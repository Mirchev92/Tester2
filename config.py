import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///missed_calls.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
