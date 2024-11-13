import os
from datetime import timedelta

class Config:
    # Use environment variables for sensitive data
    SECRET_KEY = os.getenv('SECRET_KEY') or 'generate-a-secure-key-here'
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL') or 'sqlite:///missed_calls.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Password hashing configuration
    PASSWORD_SALT = os.getenv('PASSWORD_SALT') or 'generate-a-secure-salt'
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Sinch configuration
    SINCH_SERVICE_PLAN_ID = os.getenv('SINCH_SERVICE_PLAN_ID')
    SINCH_API_TOKEN = os.getenv('SINCH_API_TOKEN')
    SINCH_SENDER = os.getenv('SINCH_SENDER', 'MissCall')
