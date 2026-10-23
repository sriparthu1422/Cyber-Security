import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key-for-cybersec-ai' # CHANGE THIS IN PRODUCTION!
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///cybersec_ai.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/uploads' # For uploaded log files or sample data
    ALLOWED_LOG_EXTENSIONS = {'txt', 'log', 'csv', 'json'} # Example allowed extensions
    THREAT_INTEL_API_KEY = os.environ.get('THREAT_INTEL_API_KEY') or 'your_threat_intel_api_key' # Placeholder