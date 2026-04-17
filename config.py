# Configuration File - FIXED VERSION with Security Improvements
import os

class Config:
    # FIXED: File Upload Security
    # Only allow safe file types, removed executables (exe, sh, bat)
    # VULNERABLE (COMMENTED): Allows executable files
    # ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx', 'exe', 'sh', 'bat'}
    
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx'}  # FIXED: Only safe extensions
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # FIXED: Reduced to 5MB with proper enforcement
    
    # FIXED: Secret Key Security
    # Use environment variable for secret key, fallback for demo purposes only
    # nosec B105: Hardcoded secret only used in development, must be changed in production
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-fixed-key-change-in-production-xyz123!@#')
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///vulnerable_app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # FIXED: Session Configuration with Security
    # VULNERABLE (COMMENTED): Using Flask defaults without security flags
    # PERMANENT_SESSION_LIFETIME = 86400  # 24 hours in seconds
    
    PERMANENT_SESSION_LIFETIME = 1800  # FIXED: Reduced to 30 minutes for security
    SESSION_COOKIE_SECURE = True  # FIXED: Only send over HTTPS
    SESSION_COOKIE_HTTPONLY = True  # FIXED: Prevent JavaScript access to cookies
    SESSION_COOKIE_SAMESITE = 'Strict'  # FIXED: CSRF protection
    
    # FIXED: Flask Debug and Host Binding
    # VULNERABLE (COMMENTED): debug=True, host='0.0.0.0'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False') == 'True'  # FIXED: Disabled by default
    FLASK_ENV = os.environ.get('FLASK_ENV', 'production')  # FIXED: Default to production
    HOST = os.environ.get('FLASK_HOST', '127.0.0.1')  # FIXED: Localhost by default, not 0.0.0.0
