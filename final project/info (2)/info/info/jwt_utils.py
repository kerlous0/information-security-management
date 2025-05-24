from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import (
    verify_jwt_in_request, get_jwt_identity, get_jwt,
    create_access_token, decode_token
)
from datetime import datetime, timedelta


def jwt_required_with_roles(roles=None):
    """
    Decorator to protect routes with JWT and role-based access control.
    
    Args:
        roles (list): List of allowed roles (e.g., ['admin', 'doctor'])
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip JWT verification in debug mode if configured
            if current_app.config.get('DEBUG') and current_app.config.get('SKIP_AUTH'):
                return f(*args, **kwargs)
                
            try:
                # Verify JWT in the request
                verify_jwt_in_request()
                
                # Get JWT claims
                claims = get_jwt()
                
                # Check if token is expired
                exp_timestamp = claims['exp']
                now = datetime.utcnow()
                exp_datetime = datetime.utcfromtimestamp(exp_timestamp)
                
                if now > exp_datetime:
                    return jsonify({
                        'error': 'Token has expired',
                        'refresh_url': '/api/refresh'
                    }), 401
                
                # Check roles if specified
                if roles:
                    user_role = claims.get('role')
                    if user_role not in roles:
                        return jsonify({
                            'error': 'Insufficient permissions',
                            'required_roles': roles
                        }), 403
                
                return f(*args, **kwargs)
                
            except Exception as e:
                return jsonify({
                    'error': 'Invalid or missing token',
                    'message': str(e)
                }), 401
        
        return decorated_function
    return decorator


def create_tokens(identity, additional_claims=None):
    """
    Create access and refresh tokens with the given identity and claims.
    
    Args:
        identity: User ID or unique identifier
        additional_claims (dict): Additional claims to include in the token
        
    Returns:
        dict: Dictionary containing access_token and refresh_token
    """
    if additional_claims is None:
        additional_claims = {}
    
    # Add standard claims
    access_token = create_access_token(
        identity=identity,
        additional_claims=additional_claims
    )
    
    # Create refresh token (longer expiry)
    refresh_token = create_access_token(
        identity=identity,
        expires_delta=timedelta(days=30),
        additional_claims={
            **additional_claims,
            'refresh': True  # Mark as refresh token
        }
    )
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer',
        'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
    }


def refresh_access_token(refresh_token):
    """
    Refresh an access token using a refresh token.
    
    Args:
        refresh_token (str): The refresh token
        
    Returns:
        dict: New access token or error message
    """
    try:
        # Decode the refresh token (without verification)
        decoded = decode_token(refresh_token)
        
        # Check if it's actually a refresh token
        if not decoded.get('refresh'):
            return {'error': 'Not a refresh token'}, 400
            
        # Create new access token with same identity and claims (except 'refresh')
        identity = decoded['sub']
        claims = {k: v for k, v in decoded.items() 
                 if k not in ['exp', 'iat', 'nbf', 'jti', 'refresh']}
        
        new_access_token = create_access_token(
            identity=identity,
            additional_claims=claims
        )
        
        return {
            'access_token': new_access_token,
            'token_type': 'bearer',
            'expires_in': current_app.config['JWT_ACCESS_TOKEN_EXPIRES'].total_seconds()
        }
        
    except Exception as e:
        return {'error': str(e)}, 401
