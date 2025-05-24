# Strict protection rules for every route (Token + Role)
# Looks integrated, but a full audit for every route is required to confirm.

from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify, send_from_directory, Response, current_app, make_response
from flask_sqlalchemy import SQLAlchemy
import sqlalchemy.exc
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# JWT Authentication
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, JWTManager, get_jwt_identity, get_jwt
from authlib.integrations.flask_client import OAuth # For Okta/Auth0 (can be kept as an alternative auth)
from flask_migrate import Migrate

from dotenv import load_dotenv
import os
import pyotp
import qrcode
from io import BytesIO, StringIO
import base64
from datetime import timedelta, datetime, UTC
from functools import wraps
import hashlib
import uuid
import json
import csv
import re
import traceback

# Cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa, utils
from sqlalchemy.sql import text
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from werkzeug.security import generate_password_hash, check_password_hash # Added for password hashing
from werkzeug.utils import secure_filename # For handling filenames
from werkzeug.exceptions import HTTPException

# JWT Utilities
# Removed the JWT Utilities import

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secure_health_secret_key_change_this!')

def log_login_attempt(username, success):
    log_line = f"{datetime.now()}, {username}, {'SUCCESS' if success else 'FAILURE'}\n"
    os.makedirs("logs", exist_ok=True)
    with open("logs/login_attempts.log", "a") as log_file:
        log_file.write(log_line)

from sqlalchemy import text

def grant_doctor_access(username):
    with db.engine.connect() as conn:
        conn.execute(text(f"GRANT SELECT, UPDATE ON secure_health.patient_records TO '{username}';"))

def revoke_doctor_access(username):
    with db.engine.connect() as conn:
        conn.execute(text(f"REVOKE ALL PRIVILEGES ON secure_health.patient_records FROM '{username}';"))

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL').replace('mysql://', 'mysql+pymysql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['PREFERRED_URL_SCHEME'] = 'https'

# JWT Configuration
# Removed the JWT Configuration

# OAuth Configuration is initialized below

# Document upload configuration (e.g., for lab reports)
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt'} # Adjusted for medical context
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads_medical')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Master Encryption Key for sensitive data
MASTER_KEY_HEX = os.getenv('MASTER_ENCRYPTION_KEY')
if not MASTER_KEY_HEX:
    app.logger.critical("CRITICAL: MASTER_ENCRYPTION_KEY not set in .env.")
    raise ValueError("MASTER_ENCRYPTION_KEY must be set in .env and be a 64-char hex string (32 bytes)")
elif len(bytes.fromhex(MASTER_KEY_HEX)) != 32:
    raise ValueError("MASTER_ENCRYPTION_KEY must be a 64-char hex string (32 bytes) if set.")
MASTER_KEY = bytes.fromhex(MASTER_KEY_HEX)

# RSA Keys for Digital Signatures (e.g., for doctors signing prescriptions/notes)
PRIVATE_KEY_PATH = "secure_health_private_key.pem"
PUBLIC_KEY_PATH = "secure_health_public_key.pem"
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None

# Try to load keys or guide to generate them
try:
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        SERVER_PRIVATE_KEY = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    with open(PUBLIC_KEY_PATH, "rb") as key_file:
        SERVER_PUBLIC_KEY = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    app.logger.info("Secure Health RSA keys loaded successfully.")
except FileNotFoundError:
    app.logger.warning(f"RSA key files ({PRIVATE_KEY_PATH}, {PUBLIC_KEY_PATH}) not found. Digital signatures will be affected. Please generate them.")
except Exception as e:
    app.logger.error(f"Error loading Secure Health RSA keys: {e}. Digital signatures will fail.")


oauth = OAuth(app)
# Okta/Auth0 configuration remains similar, adjust if needed
okta_domain_env = os.getenv('OKTA_DOMAIN')
okta_domain_for_url = "https://example.okta.com" # Placeholder
if not okta_domain_env:
    app.logger.warning("OKTA_DOMAIN not set. Okta/Auth0 login will fail if used.")
else:
    okta_domain_for_url = okta_domain_env.strip()
    # Further validation for okta_domain_for_url as in original code

oauth.register(
    name='okta',
    client_id=os.getenv('OKTA_CLIENT_ID'),
    client_secret=os.getenv('OKTA_CLIENT_SECRET'),
    server_metadata_url=f"{okta_domain_for_url}/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid email profile', 'token_endpoint_auth_method': 'client_secret_post'}
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- Cryptography Helper Functions (largely reusable) ---
def derive_key(salt, master_key=MASTER_KEY):
    if isinstance(master_key, str): master_key = master_key.encode('utf-8')
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    key = kdf.derive(master_key)
    app.logger.debug(f"Derived key (first 8 bytes): {key[:8].hex() if key else 'None'}")
    return key

def encrypt_data(data_bytes, key):
    nonce = os.urandom(12); aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, data_bytes, None), nonce

def decrypt_data(encrypted_data_bytes, nonce, key):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_data_bytes, None)

def calculate_sha256_stream(file_stream_or_bytes):
    hash_sha256 = hashlib.sha256()
    if hasattr(file_stream_or_bytes, 'read'):
        for chunk in iter(lambda: file_stream_or_bytes.read(4096), b""): hash_sha256.update(chunk)
        file_stream_or_bytes.seek(0)
    elif isinstance(file_stream_or_bytes, bytes):
        hash_sha256.update(file_stream_or_bytes)
    else:
        if isinstance(file_stream_or_bytes, str): hash_sha256.update(file_stream_or_bytes.encode('utf-8'))
        else: app.logger.error(f"Unsupported type for hashing: {type(file_stream_or_bytes)}"); return None
    return hash_sha256.hexdigest()

# Digital Signature Functions for Doctors/System
def sign_data_rsa(data_bytes, private_key_obj=SERVER_PRIVATE_KEY):
    if not private_key_obj: app.logger.error("RSA Private key not loaded for signing."); return None
    try:
        signature = private_key_obj.sign(
            data_bytes,
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e: app.logger.error(f"Error signing data: {e}"); return None

def verify_signature_rsa(data_bytes, signature_b64, public_key_obj=SERVER_PUBLIC_KEY):
    if not public_key_obj: app.logger.error("RSA Public key not loaded for verification."); return False
    try:
        signature_bytes = base64.b64decode(signature_b64)
        public_key_obj.verify(
            signature_bytes, data_bytes,
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature: app.logger.warning("RSA signature verification failed: Invalid signature."); return False
    except Exception as e: app.logger.error(f"Error verifying RSA signature: {e}"); return False

# --- User Model ---

class DoctorPatientAssignment(db.Model):
    __tablename__ = 'doctor_patient_assignment'
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_by_admin = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)

    # علاقات ORM لسهولة الاستخدام في القوالب
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='assigned_patients')
    patient = db.relationship('User', foreign_keys=[patient_id], backref='doctor_assignments')

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=True)
    # ROLES: 'admin', 'doctor', 'patient'
    role = db.Column(db.String(50), nullable=False, default='patient')
    password_hash = db.Column(db.String(255), nullable=True)
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_uid = db.Column(db.String(255), nullable=True)
    otp_secret = db.Column(db.String(100), nullable=True) # For 2FA
    is_2fa_enabled = db.Column(db.Boolean, default=False) # For 2FA

    # Fields for user approval (kept from original, as per project description)
    is_approved = db.Column(db.Boolean, default=False) # Admins/Doctors might need approval
    approval_status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    approval_date = db.Column(db.DateTime, nullable=True)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Changed from approved_by
    rejection_reason = db.Column(db.Text, nullable=True)

    # Role-specific fields
    specialization = db.Column(db.String(100), nullable=True) # For doctors
    contact_details = db.Column(db.Text, nullable=True) # For patients (e.g., phone, address)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    approved_by_admin = db.relationship('User', remote_side=[id], backref='approved_users_list') # Renamed backref

    # For Patients
    appointments_patient = db.relationship('Appointment', foreign_keys='Appointment.patient_id', backref='patient', lazy='dynamic')
    medical_records_patient = db.relationship('MedicalRecord', foreign_keys='MedicalRecord.patient_id', backref='patient_owner', lazy='dynamic') # Changed backref name
    prescriptions_patient = db.relationship('Prescription', foreign_keys='Prescription.patient_id', backref='patient_recipient', lazy='dynamic') # Changed backref name

    # For Doctors
    appointments_doctor = db.relationship('Appointment', foreign_keys='Appointment.doctor_id', backref='doctor', lazy='dynamic')
    medical_records_doctor = db.relationship('MedicalRecord', foreign_keys='MedicalRecord.doctor_id', backref='attending_doctor', lazy='dynamic') # Changed backref name
    prescriptions_doctor = db.relationship('Prescription', foreign_keys='Prescription.doctor_id', backref='prescribing_doctor', lazy='dynamic') # Changed backref name
    
    # Audit logs related to this user
    audit_logs_actor = db.relationship('AuditLog', foreign_keys='AuditLog.user_id', backref='actor', lazy='dynamic')
    audit_logs_target = db.relationship('AuditLog', foreign_keys='AuditLog.target_user_id', backref='target_subject', lazy='dynamic')


    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        if not self.password_hash: return False
        return check_password_hash(self.password_hash, password)

    def __repr__(self): return f"<User {self.email} ({self.role})>"

# --- Appointment Model ---
class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    appointment_date = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='scheduled') # e.g., scheduled, completed, cancelled
    notes = db.Column(db.Text, nullable=True) # Notes by doctor or patient
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self): return f"<Appointment {self.id} - Patient: {self.patient_id} with Dr. {self.doctor_id} on {self.appointment_date}>"

# --- MedicalRecord Model ---
class MedicalRecord(db.Model):
    __tablename__ = 'medical_records'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Doctor who created/managed this record entry
    record_type = db.Column(db.String(100), nullable=False) # e.g., 'diagnosis', 'lab_report', 'treatment_note', 'allergy'
    description = db.Column(db.Text, nullable=True) # General description or summary

    # For encrypted sensitive data like diagnoses, detailed notes
    sensitive_data_encrypted = db.Column(db.LargeBinary, nullable=True) # Storing encrypted bytes
    encryption_salt = db.Column(db.LargeBinary(16), nullable=True)
    encryption_nonce = db.Column(db.LargeBinary(12), nullable=True)

    # If the record is an uploaded file (e.g., lab report)
    original_filename = db.Column(db.String(255), nullable=True)
    saved_filename = db.Column(db.String(255), nullable=True, unique=True) # If stored on filesystem
    filesize = db.Column(db.Integer, nullable=True)
    filetype = db.Column(db.String(50), nullable=True)
    # SHA256 hash of the original uploaded file, if applicable
    file_sha256_hash = db.Column(db.String(64), nullable=True)


    # Digital signature for the record (e.g., doctor signing off on a diagnosis)
    is_signed = db.Column(db.Boolean, default=False)
    signature_data = db.Column(db.Text, nullable=True) # Base64 encoded signature
    signed_by_doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    signed_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    signed_by_doctor = db.relationship('User', foreign_keys=[signed_by_doctor_id])


    def set_sensitive_data(self, plaintext_data_str, key):
        if not plaintext_data_str:
            self.sensitive_data_encrypted = None
            self.encryption_salt = None
            self.encryption_nonce = None
            return
        self.encryption_salt = os.urandom(16)
        derived_key = derive_key(self.encryption_salt, key)
        encrypted_bytes, nonce = encrypt_data(plaintext_data_str.encode('utf-8'), derived_key)
        self.sensitive_data_encrypted = encrypted_bytes
        self.encryption_nonce = nonce

    def get_sensitive_data(self, key):
        if not self.sensitive_data_encrypted or not self.encryption_salt or not self.encryption_nonce:
            return None
        try:
            derived_key = derive_key(self.encryption_salt, key)
            decrypted_bytes = decrypt_data(self.sensitive_data_encrypted, self.encryption_nonce, derived_key)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            app.logger.error(f"Failed to decrypt sensitive data for MedicalRecord {self.id}: {e}")
            return "Error: Could not decrypt data."

    def __repr__(self): return f"<MedicalRecord {self.id} - Patient: {self.patient_id}, Type: {self.record_type}>"

# --- Prescription Model ---
class Prescription(db.Model):
    __tablename__ = 'prescriptions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) # Doctor who wrote prescription
    medical_record_id = db.Column(db.Integer, db.ForeignKey('medical_records.id'), nullable=True) # Optional link to a specific record/diagnosis

    medication_name = db.Column(db.String(255), nullable=False)
    dosage = db.Column(db.String(100), nullable=True)
    frequency = db.Column(db.String(100), nullable=True)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=True)
    notes = db.Column(db.Text, nullable=True) # Additional instructions

    # Digital signature by the doctor
    is_signed = db.Column(db.Boolean, default=False)
    signature_data = db.Column(db.Text, nullable=True) # Base64 encoded signature
    signed_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    medical_record = db.relationship('MedicalRecord', backref='prescriptions')


    def __repr__(self): return f"<Prescription {self.id} - Patient: {self.patient_id}, Medication: {self.medication_name}>"

# --- AuditLog Model (largely reusable, ensure target_document_id is repurposed or new FKs added) ---
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True) # User performing action
    action_type = db.Column(db.String(100), nullable=False) # e.g., LOGIN_SUCCESS, PATIENT_RECORD_VIEW, PRESCRIPTION_CREATE
    
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True) # e.g., admin modified this user
    target_medical_record_id = db.Column(db.Integer, db.ForeignKey('medical_records.id', ondelete='SET NULL'), nullable=True)
    target_appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id', ondelete='SET NULL'), nullable=True)
    target_prescription_id = db.Column(db.Integer, db.ForeignKey('prescriptions.id', ondelete='SET NULL'), nullable=True)
    
    details = db.Column(db.Text, nullable=True) # JSON string with more details
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    # ... other fields from original AuditLog like request_method, resource_path, status_code etc. can be kept ...
    request_method = db.Column(db.String(10), nullable=True)
    resource_path = db.Column(db.String(255), nullable=True)
    status_code = db.Column(db.Integer, nullable=True)

    # Relationships for easy access to target objects
    medical_record_targeted = db.relationship('MedicalRecord')
    appointment_targeted = db.relationship('Appointment')
    prescription_targeted = db.relationship('Prescription')
    
    def __repr__(self): return f"<AuditLog {self.timestamp} - User: {self.user_id} - Action: {self.action_type}>"

# --- Helper function to record audit logs (adapted) ---
def record_audit_log(action_type, details=None, user_id=None,
                     target_user_id=None, target_medical_record_id=None,
                     target_appointment_id=None, target_prescription_id=None,
                     status_code=None, exception_info=None):
    try:
        log_user_id = user_id if user_id is not None else (current_user.id if current_user.is_authenticated else None)
        ip, ua_string, method, path = None, None, None, None
        if request:
            ip = request.remote_addr
            if request.user_agent: ua_string = request.user_agent.string
            method = request.method
            path = request.path
        
        details_to_store = {}
        if isinstance(details, dict): details_to_store.update(details)
        elif details is not None: details_to_store['message'] = str(details)
        if exception_info: details_to_store['exception'] = str(exception_info)

        log_entry = AuditLog(
            user_id=log_user_id, action_type=action_type,
            target_user_id=target_user_id,
            target_medical_record_id=target_medical_record_id,
            target_appointment_id=target_appointment_id,
            target_prescription_id=target_prescription_id,
            details=json.dumps(details_to_store, ensure_ascii=False, indent=2) if details_to_store else None,
            ip_address=ip, user_agent=ua_string,
            request_method=method, resource_path=path, status_code=status_code
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"CRITICAL: Error recording audit log itself for action '{action_type}': {e}")
        app.logger.error(f"Original audit details: {details_to_store if 'details_to_store' in locals() else details}")
        db.session.rollback()

# --- Role Decorators ---
def role_required(role_name):
    """Decorator for session-based authentication with role check"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in to access this page.", "warning")
                return redirect(url_for('login', next=request.url))
            if current_user.role != role_name:
                flash("You do not have permission to access this page.", "danger")
                # Potentially log this unauthorized access attempt
                record_audit_log("AUTH_ACCESS_DENIED_ROLE",
                                 details={"required_role": role_name, "user_role": current_user.role, "path": request.path},
                                 user_id=current_user.id, status_code=403)
                return redirect(url_for('dashboard')) # Or a general access denied page
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Session-based role decorators
admin_required = role_required('admin')
doctor_required = role_required('doctor')
patient_required = role_required('patient')

# --- Password Complexity Function (reusable) ---
def check_password_complexity(password):
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password): return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password): return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password): return False, "Password must contain at least one special character."
    return True, "Password meets complexity requirements."


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Route name for login page
login_manager.login_message_category = 'info'
@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))


# --- Error Handlers (reusable, ensure templates exist or are adapted) ---
@app.errorhandler(400)
def bad_request_error(e):
    # record_audit_log(...) # Consider logging errors
    return render_template("error_pages/400.html", error=str(e)), 400 # Assume error_pages/ subfolder

@app.errorhandler(401)
def unauthorized_error(e):
    return render_template("error_pages/401.html", error=str(e)), 401

@app.errorhandler(403)
def forbidden_error(e):
    return render_template("error_pages/403.html", error=str(e)), 403

@app.errorhandler(404)
def not_found_error(e):
    record_audit_log("HTTP_ERROR_404", details={"path": request.path, "error": str(e)}, status_code=404)
    return render_template("error_pages/404.html", error=str(e)), 404

@app.errorhandler(Exception) # Generic exception handler
def handle_exception(e):
    # Log the exception
    exception_trace = traceback.format_exc()
    app.logger.error(f"UNHANDLED EXCEPTION: {e}\n{exception_trace}")
    record_audit_log("UNHANDLED_EXCEPTION", details={"error": str(e)}, exception_info=exception_trace, status_code=500)

    if isinstance(e, HTTPException): # Handle specific HTTP exceptions
        return e
    return render_template("error_pages/500.html", error=str(e)), 500


# --- Template Context Processors ---
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.context_processor
def inject_oauth():
    return {'oauth': oauth}

@app.context_processor
def inject_app():
    return {'app': app, 'ALLOWED_EXTENSIONS': ALLOWED_EXTENSIONS}

@app.route('/')
def home():
    return render_template('landing_health.html') # New landing page for Secure Health

@app.route('/dashboard')
@login_required
def dashboard():
    # Dashboard logic will be role-dependent
    if current_user.role == 'admin':
        try:
            # Admin specific data
            pending_user_approvals = User.query.filter_by(approval_status='pending').count()
            # --- user_stats dictionary ---
            total_users = User.query.count()
            active_today = User.query.filter(User.updated_at >= datetime.utcnow().date()).count()
            role_distribution = {
                'admin': User.query.filter_by(role='admin').count(),
                'doctor': User.query.filter_by(role='doctor').count(),
                'patient': User.query.filter_by(role='patient').count()
            }
            user_stats = {
                'total_users': total_users,
                'active_today': active_today,
                'pending_approvals': pending_user_approvals,
                'role_distribution': role_distribution
            }
        except Exception as e:
            user_stats = {
                'total_users': 0,
                'active_today': 0,
                'pending_approvals': 0,
                'role_distribution': {'admin': 0, 'doctor': 0, 'patient': 0}
            }
        try:
            total_appointments = Appointment.query.count()
            appointment_stats = {
                'total_appointments': total_appointments
            }
        except Exception:
            appointment_stats = {
                'total_appointments': 0
            }
        return render_template('dashboard_admin.html', pending_user_approvals=pending_user_approvals, user_stats=user_stats, appointment_stats=appointment_stats)
    elif current_user.role == 'doctor':
        # Doctor specific data
        upcoming_appointments = Appointment.query.filter_by(doctor_id=current_user.id, status='scheduled') \
                                            .filter(Appointment.appointment_date >= datetime.utcnow()) \
                                            .order_by(Appointment.appointment_date.asc()).limit(5).all()
        assigned_patients = DoctorPatientAssignment.query.filter_by(doctor_id=current_user.id).all()
        return render_template('dashboard_doctor.html', upcoming_appointments=upcoming_appointments, assigned_patients=assigned_patients)
    elif current_user.role == 'patient':
        # Patient specific data
        my_upcoming_appointments = Appointment.query.filter_by(patient_id=current_user.id, status='scheduled') \
                                            .filter(Appointment.appointment_date >= datetime.utcnow()) \
                                            .order_by(Appointment.appointment_date.asc()).limit(5).all()
        my_recent_prescriptions = Prescription.query.filter_by(patient_id=current_user.id) \
                                            .order_by(Prescription.created_at.desc()).limit(3).all()
        return render_template('dashboard_patient.html',
                               my_upcoming_appointments=my_upcoming_appointments,
                               my_recent_prescriptions=my_recent_prescriptions)
    return redirect(url_for('login')) # Fallback

# --- Authentication Routes (largely reusable, adapt for 2FA requirements) ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'patient') # Default to patient, could have a select in form

        if not all([name, email, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return render_template('signup_health.html', name=name, email=email, oauth=oauth) # New signup page

        is_complex, message = check_password_complexity(password)
        if not is_complex:
            flash(message, 'danger')
            return render_template('signup_health.html', name=name, email=email)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('signup_health.html', name=name, email=email)

        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please login or use a different email.', 'warning')
            return render_template('signup_health.html', name=name, oauth=oauth)

        # Determine initial approval status (e.g., patients might be auto-approved, doctors/admins pending)
        initial_approval_status = 'pending'
        is_approved_initial = False
        if role == 'patient': # Example: Auto-approve patients
             initial_approval_status = 'approved'
             is_approved_initial = True
        
        new_user = User(email=email, name=name, role=role, approval_status=initial_approval_status, is_approved=is_approved_initial)
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            record_audit_log("USER_REGISTER", details={"email": new_user.email, "role": role, "status": initial_approval_status}, user_id=new_user.id)
            if not is_approved_initial:
                 flash(f'Account created for {email} as {role}. It is pending administrator approval.', 'info')
            else:
                 flash(f'Account created successfully for {email} as {role}. Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error creating user {email}: {e}")
            record_audit_log("USER_REGISTER_FAILED", details={"email": email, "error": str(e)}, exception_info=traceback.format_exc())
            flash('An error occurred. Please try again.', 'danger')
            return render_template('signup_health.html', name=name, email=email)
            
    return render_template('signup_health.html', oauth=oauth)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if not user.is_approved:
                flash('Your account is not yet approved. Please contact an administrator.', 'warning')
                record_audit_log("USER_LOGIN_NOT_APPROVED", user_id=user.id)
                return redirect(url_for('login'))

            if user.is_2fa_enabled and user.role in ['doctor', 'admin']: 
                session['2fa_user_id'] = user.id
                session['2fa_next_url'] = url_for('dashboard')
                session['generate_token'] = True  # Store token generation preference
                record_audit_log("USER_LOGIN_2FA_REQUIRED", user_id=user.id)
                return redirect(url_for('verify_2fa'))
            
            # Always perform session-based login
            login_user(user)
            record_audit_log("USER_LOGIN_SUCCESS", user_id=user.id)
            flash(f'Logged in successfully as {user.name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            record_audit_log("USER_LOGIN_FAILED", details={"attempted_email": email})
            flash('Invalid email or password.', 'danger')
    return render_template('login_health.html', oauth=oauth)

@app.route('/api/login', methods=['POST'])
def api_login():
    """API endpoint for login"""
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400
    
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    
    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if user and user.check_password(password):
        if not user.is_approved:
            record_audit_log("USER_LOGIN_NOT_APPROVED", user_id=user.id)
            return jsonify({"error": "Account not approved"}), 403
        
        return jsonify({
            "message": "Login successful",
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role
            }
        })
    
    record_audit_log("USER_LOGIN_FAILED", details={"attempted_email": email})
    return jsonify({"error": "Invalid email or password"}), 401

@app.route('/logout')
@login_required # Or @jwt_required if using JWT
def logout():
    user_id_before_logout = current_user.id
    logout_user() # For session-based. For JWT, this would be client-side token removal.
    session.clear()
    record_audit_log("USER_LOGOUT", user_id=user_id_before_logout)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# 2FA Routes (reusable, ensure templates are `2fa_setup_health.html`, `2fa_verify_health.html`)
@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required # Or @jwt_required
def setup_2fa():
    if current_user.role not in ['doctor', 'admin'] and not current_user.is_admin: # Allow admin to setup for any, but doctors for self
        flash("2FA setup is only available for Doctors and Administrators.", "warning")
        return redirect(url_for('dashboard'))
    if current_user.is_2fa_enabled:
        flash('2FA is already enabled for your account.', 'info')
        return redirect(url_for('profile')) # Or dashboard

    if request.method == 'POST':
        token = request.form.get('token')
        otp_secret_from_session = session.get('new_otp_secret')
        if not otp_secret_from_session:
            flash('2FA setup session expired. Please try again.', 'danger')
            return redirect(url_for('setup_2fa'))

        totp = pyotp.TOTP(otp_secret_from_session)
        if totp.verify(token):
            current_user.otp_secret = otp_secret_from_session
            current_user.is_2fa_enabled = True
            db.session.commit()
            del session['new_otp_secret']
            record_audit_log("2FA_ENABLED", user_id=current_user.id)
            flash('Two-Factor Authentication has been enabled!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA token. Please try again.', 'danger')
    
    # Generate new OTP secret for setup
    if 'new_otp_secret' not in session:
        session['new_otp_secret'] = pyotp.random_base32()
    
    otp_secret = session['new_otp_secret']
    provisioning_name = current_user.email
    totp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=provisioning_name, issuer_name="SecureHealthApp")
    
    img = qrcode.make(totp_uri)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)
    qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('2fa_setup_health.html', otp_secret=otp_secret, qr_code_b64=qr_code_b64)


@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if current_user.is_authenticated and current_user.is_2fa_enabled: # If already logged in and 2FA verified, go to dash
         return redirect(url_for('dashboard'))

    user_id_for_2fa = session.get('2fa_user_id')
    if not user_id_for_2fa:
        flash("No 2FA process started or session expired.", "warning")
        return redirect(url_for('login'))

    user = db.session.get(User, user_id_for_2fa)
    if not user or not user.is_2fa_enabled or not user.otp_secret:
        flash("2FA is not properly configured for this account or user not found.", "danger")
        session.pop('2fa_user_id', None)
        session.pop('2fa_next_url', None)
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(token):
            login_user(user) # Complete the login process
            next_url = session.pop('2fa_next_url', url_for('dashboard'))
            session.pop('2fa_user_id', None)
            record_audit_log("USER_LOGIN_2FA_SUCCESS", user_id=user.id)
            flash('2FA verification successful. Welcome!', 'success')
            return redirect(next_url)
        else:
            record_audit_log("USER_LOGIN_2FA_FAILED", user_id=user.id)
            flash('Invalid 2FA token. Please try again.', 'danger')
            
    return render_template('2fa_verify_health.html') # New 2FA verify page

# --- Patient Routes ---
@app.route('/appointments/book', methods=['GET', 'POST'])
@login_required
@patient_required
def book_appointment():
    doctors = User.query.filter_by(role='doctor', is_approved=True).all()
    if request.method == 'GET':
        return render_template('appointments/book_appointment.html', doctors=doctors)
        
    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        appointment_date_str = request.form.get('appointment_date') # Expects "YYYY-MM-DDTHH:MM"
        reason = request.form.get('reason')
        
        try:
            appointment_date = datetime.strptime(appointment_date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DDTHH:MM.", "danger")
            # Fetch doctors again for the template
            doctors = User.query.filter_by(role='doctor', is_approved=True).all()
            return render_template('appointments/book_appointment.html', doctors=doctors)

        if not doctor_id or not appointment_date:
            flash("Doctor and appointment date are required.", "danger")
        else:
            # Basic validation: appointment date must be in the future
            if appointment_date <= datetime.utcnow():
                flash("Appointment date must be in the future.", "danger")
            else:
                doctor = User.query.get(doctor_id)
                if not doctor or doctor.role != 'doctor':
                    flash("Invalid doctor selected.", "danger")
                else:
                    new_appointment = Appointment(
                        patient_id=current_user.id,
                        doctor_id=doctor_id,
                        appointment_date=appointment_date,
                        reason=reason,
                        status='scheduled'
                    )
                    db.session.add(new_appointment)
                    db.session.commit()
                    record_audit_log("APPOINTMENT_BOOKED",
                                     details={"doctor_id": doctor_id, "date": appointment_date_str},
                                     user_id=current_user.id, target_appointment_id=new_appointment.id)
                    flash('Appointment booked successfully!', 'success')
                    return redirect(url_for('list_appointments_patient'))
        # Fetch doctors again for the template if booking failed
        doctors = User.query.filter_by(role='doctor', is_approved=True).all()
        return render_template('appointments/book_appointment.html', doctors=doctors)

@app.route('/my-appointments')
@login_required
@patient_required
def list_appointments_patient():
    my_appointments = Appointment.query.filter_by(patient_id=current_user.id).order_by(Appointment.appointment_date.desc()).all()
    return render_template('appointments/patient_appointments.html', appointments=my_appointments)

@app.route('/appointments/cancel/<int:appointment_id>', methods=['POST'])
@login_required
@patient_required
def cancel_appointment_patient(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    if appointment.patient_id != current_user.id:
        flash("You do not have permission to cancel this appointment.", "danger")
        return redirect(url_for('list_appointments_patient'))
    
    # Add logic to prevent cancellation too close to appointment time if needed
    if appointment.status == 'scheduled': # Can only cancel scheduled appointments
        appointment.status = 'cancelled_by_patient'
        db.session.commit()
        record_audit_log("APPOINTMENT_CANCELLED_PATIENT", user_id=current_user.id, target_appointment_id=appointment.id)
        flash("Appointment cancelled successfully.", "success")
    else:
        flash("This appointment cannot be cancelled (it may have already occurred or been cancelled).", "warning")
    return redirect(url_for('list_appointments_patient'))

@app.route('/my-medical-records')
@login_required
@patient_required
def view_my_medical_records():
    # Fetch records, decrypt sensitive data (this needs to be done carefully)
    records = MedicalRecord.query.filter_by(patient_id=current_user.id).order_by(MedicalRecord.created_at.desc()).all()
    decrypted_records = []
    for record in records:
        # Example: Decrypting sensitive data for display
        # This is a simplified representation; in a real app, key management is critical.
        sensitive_info = record.get_sensitive_data(MASTER_KEY) # Using MASTER_KEY directly here for simplicity.
        decrypted_records.append({
            "id": record.id,
            "record_type": record.record_type,
            "description": record.description,
            "created_at": record.created_at,
            "doctor_name": record.attending_doctor.name if record.attending_doctor else "N/A",
            "sensitive_data_preview": (sensitive_info[:100] + '...' if sensitive_info and len(sensitive_info) > 100 else sensitive_info) if sensitive_info else "No sensitive details."
            # Add other fields as necessary
        })
    prescriptions = Prescription.query.filter_by(patient_id=current_user.id).order_by(Prescription.start_date.desc()).all()
    return render_template('medical_info/my_records.html', records=decrypted_records, prescriptions=prescriptions)

@app.route('/my-profile', methods=['GET', 'POST'])
@login_required
def my_profile(): # Replaces original profile page
    if request.method == 'POST':
        current_user.name = request.form.get('name', current_user.name)
        # Patients can update contact_details
        if current_user.role == 'patient':
            current_user.contact_details = request.form.get('contact_details', current_user.contact_details)

        # Password change logic (if current_password, new_password, confirm_password are provided)
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if current_password and new_password and confirm_password:
            if not current_user.check_password(current_password):
                flash('Current password incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            else:
                is_complex, message = check_password_complexity(new_password)
                if not is_complex:
                    flash(message, 'danger')
                else:
                    current_user.set_password(new_password)
                    flash('Password updated successfully.', 'success')
                    record_audit_log("USER_PASSWORD_CHANGED", user_id=current_user.id)
        
        db.session.commit()
        record_audit_log("USER_PROFILE_UPDATED", user_id=current_user.id, details={"name": current_user.name})
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('my_profile'))
        
    # Determine if 2FA setup should be shown (for doctors/admins who haven't enabled it)
    show_2fa_option = current_user.role in ['doctor', 'admin'] and not current_user.is_2fa_enabled

    return render_template('profile_health.html', user=current_user, show_2fa_option=show_2fa_option)


# --- Doctor Routes ---
@app.route('/doctor/patients')
@login_required
@doctor_required
def list_doctor_patients():
    # Doctors should only see patients assigned to them or all patients if that's the model
    # For simplicity, showing all patients here. A real system would have assignments.
    # This query assumes doctors can see all patients with 'patient' role.
    # In a real system, you'd likely have a DoctorPatientAssignment table.
    patients = User.query.filter_by(role='patient').all()
    return render_template('doctor/patients_list.html', patients=patients)

@app.route('/doctor/patient/<int:patient_id>/records')
@login_required
@doctor_required
def view_patient_records_doctor(patient_id):
    patient = User.query.filter_by(id=patient_id, role='patient').first_or_404()
    # تحقق من صلاحية الطبيب على مريض محدد
    allowed = DoctorPatientAssignment.query.filter_by(doctor_id=current_user.id, patient_id=patient.id).first()
    if not allowed:
        flash("You do not have permission to view this patient's records. Please check with the administrator.", "danger")
        return redirect(url_for('list_doctor_patients'))
    records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.created_at.desc()).all()
    decrypted_records = []
    for record in records:
        sensitive_info = record.get_sensitive_data(MASTER_KEY)
        decrypted_records.append({
            "id": record.id, "record_type": record.record_type, "description": record.description,
            "created_at": record.created_at,
            "sensitive_data": sensitive_info, # Full data for doctor
            "is_signed": record.is_signed, "signed_at": record.signed_at,
            "original_filename": record.original_filename
        })
    
    prescriptions = Prescription.query.filter_by(patient_id=patient.id).order_by(Prescription.start_date.desc()).all()
    return render_template('doctor/view_patient_records.html', patient=patient, records=decrypted_records, prescriptions=prescriptions)

@app.route('/doctor/patient/<int:patient_id>/records/add', methods=['GET', 'POST'])
@login_required
@doctor_required
def add_medical_record(patient_id):
    patient = User.query.filter_by(id=patient_id, role='patient').first_or_404()
    # Authorization check for doctor-patient relationship needed here
    if request.method == 'POST':
        record_type = request.form.get('record_type')
        description = request.form.get('description')
        sensitive_data_plain = request.form.get('sensitive_data_plain') # Diagnosis, detailed notes
        
        # File upload handling for 'lab_report' type
        uploaded_file_data = None
        original_filename_for_record = None
        saved_filename_for_record = None
        filesize_for_record = None
        filetype_for_record = None
        file_hash_for_record = None

        if record_type == 'lab_report' and 'lab_report_file' in request.files:
            file = request.files['lab_report_file']
            if file and file.filename != '':
                if '.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
                    original_filename_for_record = secure_filename(file.filename)
                    file_ext = original_filename_for_record.rsplit('.', 1)[1].lower()
                    saved_filename_for_record = f"{uuid.uuid4().hex}.{file_ext}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename_for_record)
                    
                    uploaded_file_bytes = file.read() # Read into memory
                    file.seek(0) # Reset pointer
                    filesize_for_record = len(uploaded_file_bytes)
                    filetype_for_record = file_ext
                    file_hash_for_record = calculate_sha256_stream(uploaded_file_bytes)
                    
                    # Encrypt the file before saving if required by policy (not explicitly asked for file encryption, but good practice)
                    # For now, saving as is, but encryption like other sensitive data could be applied.
                    with open(file_path, 'wb') as f_disk:
                        f_disk.write(uploaded_file_bytes)
                    app.logger.info(f"Lab report {original_filename_for_record} saved as {saved_filename_for_record}")
                else:
                    flash("Invalid file type for lab report.", "danger")
                    return render_template('doctor/add_medical_record.html', patient=patient)
            elif record_type == 'lab_report' and not file: # Lab report type selected but no file
                 flash("Please upload a file for the lab report.", "danger")
                 return render_template('doctor/add_medical_record.html', patient=patient)


        new_record = MedicalRecord(
            patient_id=patient.id,
            doctor_id=current_user.id,
            record_type=record_type,
            description=description,
            original_filename=original_filename_for_record,
            saved_filename=saved_filename_for_record,
            filesize=filesize_for_record,
            filetype=filetype_for_record,
            file_sha256_hash=file_hash_for_record
        )
        if sensitive_data_plain:
            new_record.set_sensitive_data(sensitive_data_plain, MASTER_KEY)

        # Option to sign the record upon creation
        sign_now = request.form.get('sign_now') == 'on'
        if sign_now and SERVER_PRIVATE_KEY: # Ensure server key is loaded for system/doctor signatures
            # Data to sign would be a concatenation or JSON representation of the record's key fields
            # For simplicity, let's sign a string representation. A more robust method is needed for real apps.
            data_to_sign_str = f"RecordID:{new_record.id or 'new'}|Patient:{patient.id}|Doctor:{current_user.id}|Type:{record_type}|Time:{datetime.utcnow()}"
            signature = sign_data_rsa(data_to_sign_str.encode('utf-8'))
            if signature:
                new_record.is_signed = True
                new_record.signature_data = signature
                new_record.signed_by_doctor_id = current_user.id
                new_record.signed_at = datetime.utcnow()
            else:
                flash("Failed to sign the record. Please try again or check server key configuration.", "warning")
        
        db.session.add(new_record)
        db.session.commit()
        record_audit_log("MEDICAL_RECORD_ADDED",
                         details={"patient_id": patient.id, "record_type": record_type, "signed": new_record.is_signed},
                         user_id=current_user.id, target_medical_record_id=new_record.id)
        flash('Medical record added successfully.', 'success')
        return redirect(url_for('view_patient_records_doctor', patient_id=patient.id))
    return render_template('doctor/add_medical_record.html', patient=patient)


@app.route('/doctor/prescriptions/add/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@doctor_required
def add_prescription(patient_id):
    patient = User.query.filter_by(id=patient_id, role='patient').first_or_404()
    # Authorization check
    if request.method == 'POST':
        medication_name = request.form.get('medication_name')
        dosage = request.form.get('dosage')
        frequency = request.form.get('frequency')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        notes = request.form.get('notes')

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if end_date_str else None
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
            return render_template('doctor/add_prescription.html', patient=patient)

        if not medication_name or not start_date:
            flash("Medication name and start date are required.", "danger")
        else:
            new_prescription = Prescription(
                patient_id=patient.id, doctor_id=current_user.id,
                medication_name=medication_name, dosage=dosage, frequency=frequency,
                start_date=start_date, end_date=end_date, notes=notes
            )
            # Signing prescriptions
            data_to_sign_str = f"Prescription|Patient:{patient.id}|Doctor:{current_user.id}|Med:{medication_name}|Date:{datetime.utcnow()}"
            signature = sign_data_rsa(data_to_sign_str.encode('utf-8'))
            if signature:
                new_prescription.is_signed = True
                new_prescription.signature_data = signature
                new_prescription.signed_at = datetime.utcnow()
            else:
                 flash("Failed to sign prescription. Server key may be missing.", "warning")


            db.session.add(new_prescription)
            db.session.commit()
            record_audit_log("PRESCRIPTION_ADDED",
                             details={"patient_id": patient.id, "medication": medication_name, "signed": new_prescription.is_signed},
                             user_id=current_user.id, target_prescription_id=new_prescription.id)
            flash('Prescription added successfully.', 'success')
            return redirect(url_for('view_patient_records_doctor', patient_id=patient.id))
    return render_template('doctor/add_prescription.html', patient=patient)


@app.route('/doctor/appointments')
@login_required
@doctor_required
def list_appointments_doctor():
    # Fetch appointments for the current doctor
    doctor_appointments = Appointment.query.filter_by(doctor_id=current_user.id)\
                                      .order_by(Appointment.appointment_date.asc()).all()
    return render_template('appointments/doctor_appointments.html', appointments=doctor_appointments)


# --- Admin Routes ---

@app.route('/admin/doctor-patient-permissions', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_doctor_patient_permissions():
    doctors = User.query.filter_by(role='doctor').all()
    patients = User.query.filter_by(role='patient').all()
    permission_types = ['view', 'edit', 'delete']
    message = None

    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        patient_id = request.form.get('patient_id')
        permission_type = request.form.get('permission_type')
        action = request.form.get('action')

        assignment = DoctorPatientAssignment.query.filter_by(doctor_id=doctor_id, patient_id=patient_id).first()

        if action == 'grant':
            if not assignment:
                assignment = DoctorPatientAssignment(
                    doctor_id=doctor_id,
                    patient_id=patient_id,
                    assigned_by_admin=current_user.id
                )
                db.session.add(assignment)
                db.session.commit()
                message = "Permission granted successfully."
            else:
                message = "Permission already exists."
        elif action == 'revoke':
            if assignment:
                db.session.delete(assignment)
                db.session.commit()
                message = "Permission revoked successfully."
            else:
                message = "No permission to revoke."

    # جلب كل الصلاحيات الحالية
    all_assignments = DoctorPatientAssignment.query.all()
    return render_template(
        'admin/doctor_patient_permissions.html',
        doctors=doctors,
        patients=patients,
        permission_types=permission_types,
        message=message,
        all_assignments=all_assignments
    )

@app.route('/admin/users')
@login_required
@admin_required
def admin_users_list():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users_list.html', users=users)

@app.route('/admin/users/approve/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_approve_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.approval_status == 'pending':
        user.is_approved = True
        user.approval_status = 'approved'
        user.approval_date = datetime.utcnow()
        user.approved_by_id = current_user.id
        db.session.commit()
        record_audit_log("ADMIN_USER_APPROVED", user_id=current_user.id, target_user_id=user.id)
        flash(f"User {user.email} approved.", "success")
    else:
        flash(f"User {user.email} is not pending approval.", "warning")
    return redirect(url_for('admin_users_list'))

@app.route('/admin/users/reject/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_reject_user(user_id):
    user = User.query.get_or_404(user_id)
    rejection_reason = request.form.get('rejection_reason', 'No reason provided.')
    if user.approval_status == 'pending':
        user.is_approved = False
        user.approval_status = 'rejected'
        user.rejection_reason = rejection_reason
        user.approval_date = datetime.utcnow() # Or keep null if rejection means no approval action from admin
        user.approved_by_id = current_user.id # Admin who rejected
        db.session.commit()
        record_audit_log("ADMIN_USER_REJECTED", details={"reason": rejection_reason}, user_id=current_user.id, target_user_id=user.id)
        flash(f"User {user.email} rejected.", "success")
    else:
        flash(f"User {user.email} is not pending approval.", "warning")
    return redirect(url_for('admin_users_list'))


@app.route('/admin/users/edit-role/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_edit_user_role(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role not in ['patient', 'doctor', 'admin']:
        flash("Invalid role selected.", "danger")
        return redirect(url_for('admin_users_list'))
    
    old_role = user_to_edit.role
    user_to_edit.role = new_role

    # --- تعديل صلاحيات قاعدة البيانات بناءً على الدور الجديد ---
    try:
        if old_role != 'doctor' and new_role == 'doctor':
            grant_doctor_access(user_to_edit.email)
        elif old_role == 'doctor' and new_role != 'doctor':
            revoke_doctor_access(user_to_edit.email)
    except Exception as e:
        app.logger.error(f"Failed to update DB permissions for {user_to_edit.email}: {e}")
        flash(f"Warning: Could not update database permissions for {user_to_edit.email}.", "warning")

    db.session.commit()
    record_audit_log("ADMIN_USER_ROLE_CHANGED", details={"old_role": old_role, "new_role": new_role}, user_id=current_user.id, target_user_id=user_id)
    flash(f"Role for {user_to_edit.email} changed to {new_role}.", "success")
    return redirect(url_for('admin_users_list'))

@app.route('/admin/db-permissions', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_db_permissions():
    # THIS IS A HIGHLY SENSITIVE AREA. Exercise extreme caution.
    # A real implementation would need robust validation and security.
    # For this student project, it demonstrates the concept.
    if request.method == 'POST':
        target_db_user = request.form.get('db_user') # This would map to a DB user/role name
        table_name = request.form.get('table_name')
        permission = request.form.get('permission') # SELECT, INSERT, UPDATE, DELETE
        action = request.form.get('action') # GRANT or REVOKE

        if not all([target_db_user, table_name, permission, action]):
            flash("All fields are required for DB permission changes.", "danger")
            return render_template('admin/db_permissions.html', users=User.query.all())

        # Sanitize inputs (CRITICAL FOR SECURITY, this is simplified)
        # Use a whitelist for table_name, permission, action.
        allowed_tables = ['users', 'appointments', 'medical_records', 'prescriptions', 'audit_logs']
        allowed_permissions = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'ALL PRIVILEGES']
        allowed_actions = ['GRANT', 'REVOKE']

        if table_name not in allowed_tables or permission not in allowed_permissions or action not in allowed_actions:
            flash("Invalid table, permission, or action specified.", "danger")
            return render_template('admin/db_permissions.html', users=User.query.all())

        # Construct SQL DCL statement (VERY DANGEROUS IF NOT HANDLED PERFECTLY)
        # Example: sql_command = f"{action} {permission} ON {table_name} TO {target_db_user};"
        # Or for REVOKE: sql_command = f"{action} {permission} ON {table_name} FROM {target_db_user};"
        
        # This part assumes the application's DB user has permissions to GRANT/REVOKE.
        # This is usually not recommended for web applications.
        # An alternative is to have pre-defined roles in the DB and assign users to those roles.
        
        sql_command_str = ""
        if action == 'GRANT':
            sql_command_str = f"GRANT {permission} ON {table_name} TO \"{target_db_user}\";" # Ensure db_user is quoted if it's a role name with special chars or case sensitivity
        elif action == 'REVOKE':
            sql_command_str = f"REVOKE {permission} ON {table_name} FROM \"{target_db_user}\";"
        
        try:
            db.session.execute(text(sql_command_str))
            db.session.commit()
            record_audit_log("ADMIN_DB_PERMISSION_CHANGED",
                             details={"command": sql_command_str, "target_db_user": target_db_user},
                             user_id=current_user.id)
            flash(f"Successfully executed: {sql_command_str}", "success")
        except sqlalchemy.exc.SQLAlchemyError as e: # Catch specific SQLAlchemy errors
            db.session.rollback()
            # Log full error and show it in the UI for admin
            error_msg = f"DB Permission Change Error: {e} for command: {sql_command_str}"
            app.logger.error(error_msg)
            flash(f"Error executing DB permission command: {str(e)}", "danger")
            flash(f"[DEBUG] {error_msg}", "danger")
        except Exception as e: # Catch any other unexpected errors
            db.session.rollback()
            app.logger.error(f"Unexpected error during DB Permission Change: {e} for command: {sql_command_str}")
            flash(f"An unexpected error occurred: {str(e)}", "danger")

        return redirect(url_for('admin_db_permissions'))

    users = User.query.all() # To populate a dropdown for selecting users/roles
    # You would need a mapping from application users/roles to actual DB users/roles.
    # Or, an input field for the DB role name directly.
    return render_template('admin/db_permissions.html', users=users)


@app.route('/admin/audit-logs')
@login_required
@admin_required
def admin_audit_logs_view():
    page = request.args.get('page', 1, type=int)
    logs_pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20)
    return render_template('admin/audit_logs_view.html', logs_pagination=logs_pagination)

@app.route('/admin/audit-logs/export')
@login_required
@admin_required
def export_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.asc()).all()
    si = StringIO()
    cw = csv.writer(si)
    # Adjusted header for new target IDs
    header = ['Timestamp (UTC)', 'User ID', 'User Email', 'Action Type',
              'Target User ID', 'Target Medical Record ID', 'Target Appointment ID', 'Target Prescription ID',
              'IP Address', 'User Agent', 'Request Method', 'Resource Path', 'Status Code', 'Details']
    cw.writerow(header)
    for log in logs:
        user_email = log.actor.email if log.actor else 'N/A'
        cw.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user_id if log.user_id else 'System', user_email,
            log.action_type,
            log.target_user_id if log.target_user_id else '',
            log.target_medical_record_id if log.target_medical_record_id else '',
            log.target_appointment_id if log.target_appointment_id else '',
            log.target_prescription_id if log.target_prescription_id else '',
            log.ip_address if log.ip_address else '', log.user_agent if log.user_agent else '',
            log.request_method if log.request_method else '', log.resource_path if log.resource_path else '',
            log.status_code if log.status_code is not None else '',
            log.details if log.details else ''
        ])
    output = si.getvalue()
    record_audit_log("ADMIN_EXPORT_AUDIT_LOGS_CSV", user_id=current_user.id) # Changed action type
    return Response(output, mimetype="text/csv", headers={"Content-disposition": "attachment; filename=securehealth_audit_logs.csv"})

# --- Okta/Auth0 OAuth Routes (largely reusable) ---
@app.route('/login/okta') # Renamed for clarity
def okta_login_redirect():
    redirect_uri = url_for('okta_authorize_callback', _external=True) # Renamed callback
    return oauth.okta.authorize_redirect(redirect_uri)

@app.route('/authorize/okta_callback') # Renamed for clarity
def okta_authorize_callback():
    try:
        if not oauth.okta.client_id or not oauth.okta.client_secret:
            app.logger.error("Okta client ID or client secret is missing for Secure Health.")
            record_audit_log("OAUTH_CONFIG_ERROR_OKTA", details={"error": "Missing Okta credentials"})
            return render_template("error_pages/okta_config_error.html"), 500 # Assume specific error page

        token = oauth.okta.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info and oauth.okta.server_metadata.get('userinfo_endpoint'):
            resp = oauth.okta.get(oauth.okta.server_metadata['userinfo_endpoint'])
            resp.raise_for_status()
            user_info = resp.json()
        
        if not user_info:
            app.logger.error("Could not retrieve user information from Okta.")
            record_audit_log("OAUTH_NO_USER_INFO_OKTA")
            return render_template("error_pages/okta_auth_failed.html", error_message="Could not get user info."), 500

    except Exception as e:
        app.logger.error(f"Okta OAuth error: {e}\n{traceback.format_exc()}")
        record_audit_log("OAUTH_AUTH_ERROR_OKTA", details={"error": str(e)}, exception_info=traceback.format_exc())
        return render_template("error_pages/okta_auth_failed.html", error_message=str(e)), 500

    # Create or update user from Okta info
    email = user_info.get("email")
    name = user_info.get("name") or user_info.get("preferred_username")
    oauth_id = user_info.get("sub")

    if not email or not oauth_id:
        flash("Email or User ID not provided by Okta.", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(oauth_provider='okta', oauth_uid=oauth_id).first()
    if not user: # New Okta user
        user = User.query.filter_by(email=email).first() # Check if email exists locally
        if user: # Email exists, link Okta ID if not already an OAuth user
            if user.oauth_provider and user.oauth_provider != 'okta':
                flash(f"Email {email} is already associated with a different login method.", "danger")
                return redirect(url_for('login'))
            user.oauth_provider = 'okta'
            user.oauth_uid = oauth_id
        else: # Completely new user via Okta
            user = User(email=email, name=name, oauth_provider='okta', oauth_uid=oauth_id,
                        role='patient', # Default role for Okta signups, admin can change
                        is_approved=True, # Example: auto-approve Okta users
                        approval_status='approved')
            db.session.add(user)
        db.session.commit()
        record_audit_log("USER_OAUTH_REGISTER_OKTA", user_id=user.id)
    
    # Log in the user
    if not user.is_approved:
        flash("Your Okta-linked account is pending approval.", "warning")
        record_audit_log("USER_OAUTH_LOGIN_NOT_APPROVED", user_id=user.id)
        return redirect(url_for('login'))

    # Check 2FA for Okta users (Doctors/Admins) - Note: Okta might handle its own MFA.
    # This app's 2FA is separate. If Okta provides MFA claims, those could be checked.
    # For simplicity, if it's an Okta login, we might bypass app-level 2FA if Okta guarantees MFA.
    # Or, enforce app-level 2FA ON TOP of Okta's for these roles if super high security is needed.
    # Current logic: if user.is_2fa_enabled is true (app-level), it will trigger.
    if user.is_2fa_enabled and user.role in ['doctor', 'admin']:
        session['2fa_user_id'] = user.id
        session['2fa_next_url'] = url_for('dashboard')
        record_audit_log("USER_OAUTH_LOGIN_2FA_REQUIRED", user_id=user.id)
        return redirect(url_for('verify_2fa'))

    login_user(user)
    record_audit_log("USER_OAUTH_LOGIN_SUCCESS", user_id=user.id)
    flash(f"Successfully logged in as {user.name} via Okta!", "success")
    return redirect(url_for('dashboard'))


# --- Utility Routes (e.g., for serving uploaded medical files if stored on filesystem) ---
@app.route('/medical_files/<filename>')
@login_required # Add role checks as needed
def serve_medical_file(filename):
    # Query the MedicalRecord based on saved_filename
    record = MedicalRecord.query.filter_by(saved_filename=filename).first_or_404()
    
    # Authorization: Can current_user view this file?
    # Patient can view their own. Doctor can view their patient's. Admin can view all.
    can_access = False
    if current_user.role == 'admin':
        can_access = True
    elif current_user.role == 'patient' and record.patient_id == current_user.id:
        can_access = True
    elif current_user.role == 'doctor': # Needs a doctor-patient relationship check
        # Simplified: allow if doctor is associated with the record or patient
        if record.doctor_id == current_user.id or record.patient.appointments_doctor.filter_by(doctor_id=current_user.id).first():
             can_access = True
    
    if not can_access:
        flash("You are not authorized to view this file.", "danger")
        record_audit_log("MEDICAL_FILE_ACCESS_DENIED", user_id=current_user.id, target_medical_record_id=record.id)
        return redirect(request.referrer or url_for('dashboard'))

    record_audit_log("MEDICAL_FILE_DOWNLOAD_ACCESS", user_id=current_user.id, target_medical_record_id=record.id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False) # Set as_attachment=True for download


# --- Main execution ---
if __name__ == '__main__':
    # SSL Certificate setup (reusable)
    CERT_FILE_PATH = os.getenv('CERT_FILE_PATH', 'certs/server.crt') # e.g., certs/server.crt
    KEY_FILE_PATH = os.getenv('KEY_FILE_PATH', 'certs/server.key')   # e.g., certs/server.key
    ssl_context_to_use = None
    if os.path.exists(CERT_FILE_PATH) and os.path.exists(KEY_FILE_PATH):
        ssl_context_to_use = (CERT_FILE_PATH, KEY_FILE_PATH)
        app.logger.info(f"SSL context will be used: {CERT_FILE_PATH}, {KEY_FILE_PATH}")
    else:
        app.logger.warning("SSL certificate or key not found. Server will start in HTTP mode. FOR DEVELOPMENT ONLY.")

    with app.app_context():
        try:
            db.create_all() # Creates tables if they don't exist based on models
            app.logger.info("Database tables checked/created for Secure Health.")
            
            # Seed initial admin user if none exists (example)
            if not User.query.filter_by(role='admin').first():
                admin_email = os.getenv('ADMIN_EMAIL', 'admin@securehealth.local')
                admin_password = os.getenv('ADMIN_PASSWORD', 'admin1234')
                is_complex, msg = check_password_complexity(admin_password)
                if not is_complex and admin_password == 'admin1234':
                    app.logger.warning(f"Default admin password is not complex: {msg}. Please set ADMIN_PASSWORD env var to a strong password.")
                
                admin_user = User(email=admin_email, name="Admin User", role='admin', is_approved=True, approval_status='approved')
                admin_user.set_password(admin_password)
                db.session.add(admin_user)
                db.session.commit()
                app.logger.info(f"Default admin user created: {admin_email}")
                record_audit_log("SYSTEM_ADMIN_CREATED", details={"email": admin_email})

        except Exception as e:
            app.logger.error(f"Error during initial database setup for Secure Health: {e}")

    app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
            host=os.getenv('FLASK_HOST', '0.0.0.0'),
            port=int(os.getenv('FLASK_PORT', 5001)), # Changed port to avoid conflict with original if run side-by-side
            ssl_context=ssl_context_to_use)