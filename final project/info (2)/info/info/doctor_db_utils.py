import os
from sqlalchemy import create_engine, text
from flask import current_app

def get_doctor_db_credentials(email):
    """
    Return (username, password) for the doctor, based on email.
    In real life, fetch from secure vault or user profile. For demo, use email as username and a default password.
    """
    username = email
    password = os.getenv('DOCTOR_DB_DEFAULT_PASSWORD', 'doctor123')
    return username, password

def get_doctor_db_engine(email):
    username, password = get_doctor_db_credentials(email)
    db_host = os.getenv('DB_HOST', 'localhost')
    db_name = os.getenv('DB_NAME', 'secure_health')
    return create_engine(f"mysql+pymysql://{username}:{password}@{db_host}/{db_name}")

def doctor_can_access_patient_records(email):
    engine = get_doctor_db_engine(email)
    try:
        with engine.connect() as conn:
            conn.execute(text('SELECT 1 FROM medical_records LIMIT 1'))
        return True
    except Exception as e:
        current_app.logger.warning(f"Doctor {email} cannot access medical_records: {e}")
        return False
