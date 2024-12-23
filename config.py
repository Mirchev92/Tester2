import os
from datetime import timedelta
from flask_mail import Mail, Message

class Config:
    # Existing configuration
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
    
    # Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'your-email@gmail.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'your-app-specific-password')
    
    # OAuth Configuration
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
    GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/login/google/callback')
    
    FACEBOOK_CLIENT_ID = os.getenv('FACEBOOK_CLIENT_ID')
    FACEBOOK_CLIENT_SECRET = os.getenv('FACEBOOK_CLIENT_SECRET')
    FACEBOOK_REDIRECT_URI = os.getenv('FACEBOOK_REDIRECT_URI', 'http://localhost:5000/login/facebook/callback')
    
    # OAuth General Settings
    OAUTH_PROVIDERS = {
        'google': {
            'name': 'Google',
            'icon': 'fab fa-google',
            'authorize_url': 'https://accounts.google.com/o/oauth2/v2/auth',
            'token_url': 'https://oauth2.googleapis.com/token',
            'userinfo_url': 'https://openidconnect.googleapis.com/v1/userinfo',
            'scope': 'openid email profile',
        },
        'facebook': {
            'name': 'Facebook',
            'icon': 'fab fa-facebook',
            'authorize_url': 'https://www.facebook.com/v12.0/dialog/oauth',
            'token_url': 'https://graph.facebook.com/v12.0/oauth/access_token',
            'userinfo_url': 'https://graph.facebook.com/me',
            'scope': 'email,public_profile',
        }
    }
    
    @staticmethod
    def init_app(app):
        """Initialize application with current configuration"""
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    
class ProductionConfig(Config):
    DEBUG = False
    # Add any production-specific settings here
    
class TestingConfig(Config):
    TESTING = True
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}