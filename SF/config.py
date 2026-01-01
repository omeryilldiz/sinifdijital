import os
from dotenv import load_dotenv
from flask_limiter import Limiter
from sqlalchemy.pool import QueuePool, StaticPool
from datetime import timedelta

load_dotenv()  # .env dosyasını yükle
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://sfuser:1174@localhost/sfdb')
    DATABASE_URL = SQLALCHEMY_DATABASE_URI  # Alias ekle
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ✅ Session Configuration (CSRF token için gerekli)
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False') == 'True'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF koruması için
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
    # ✅ CSRF Configuration
    WTF_CSRF_TIME_LIMIT = None  # CSRF token'ının hiç expire olmamsı (session bazlı)
    WTF_CSRF_CHECK_DEFAULT = True
    WTF_CSRF_SSL_STRICT = False  # Proxy arkasında çalışması için

    # 🔐 Admin Panel Security
    ADMIN_URL_PREFIX = os.environ.get('ADMIN_URL_PREFIX', '/yonetim-panel-x9k2m')
    EMERGENCY_RECOVERY_PASSWORD = os.environ.get('EMERGENCY_RECOVERY_PASSWORD')

    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'SF/static/uploads')
    SORU_UPLOAD_FOLDER = os.environ.get('SORU_UPLOAD_FOLDER', 'SF/static/soru_uploads')
    VIDEO_UPLOAD_FOLDER = os.environ.get('VIDEO_UPLOAD_FOLDER', 'SF/static/video_uploads')
    COZUM_UPLOAD_FOLDER = os.environ.get('COZUM_UPLOAD_FOLDER', 'SF/static/cozum_uploads')
    PDF_UPLOAD_FOLDER = os.environ.get('PDF_UPLOAD_FOLDER', 'SF/static/pdf_uploads')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    ALLOWED_PDF_EXTENSIONS = {'pdf'}
    ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm'}
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    # Daha sıkı varsayılan limitler: kötüye kullanımı azaltmak için düşürüldü
    RATELIMIT_DEFAULT = os.environ.get('RATELIMIT_DEFAULT', "200 per day;20 per hour")
    
    broker_url = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
    result_backend = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # ✅ Dosya boyut limitleri
    MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB
    MAX_PDF_SIZE = 10 * 1024 * 1024    # 10MB
    MAX_IMAGE_SIZE = 2 * 1024 * 1024   # 2MB
    
    # ✅ İzin verilen MIME türleri
    ALLOWED_IMAGE_MIMES = {
        'image/jpeg', 'image/jpg', 'image/png', 'image/gif'
    }
    ALLOWED_PDF_MIMES = {'application/pdf'}
    
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.hostinger.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 465))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'False') == 'True'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'omeryildiz@sinifdijital.com')  # ✅ Ana mail (SMTP Auth)
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@sinifdijital.com')  # ✅ Sistem emailleri
    
    # ✅ Email Aliasları (hepsi omeryildiz@sinifdijital.com'un takma adları)
    MAIL_NOREPLY_SENDER = os.environ.get('MAIL_NOREPLY_SENDER', 'noreply@sinifdijital.com')
    MAIL_CONTACT_SENDER = os.environ.get('MAIL_CONTACT_SENDER', 'iletisim@sinifdijital.com')
    
    # ✅ Dosya upload limitleri
    UPLOAD_RATE_LIMIT = os.environ.get('UPLOAD_RATE_LIMIT', "15 per minute")
    MAX_FILES_PER_HOUR = 150
    
    @staticmethod
    def get_database_engine_options():
        """Database tipine göre optimize edilmiş engine options"""
        database_url = os.environ.get('DATABASE_URL', 'postgresql://sfuser:1174@localhost/sfdb')
        
        if database_url.startswith('postgresql'):
            return {
                'poolclass': QueuePool,
                'pool_size': int(os.environ.get('DATABASE_POOL_SIZE', 10)),  # Optimized from 20
                'max_overflow': int(os.environ.get('DATABASE_MAX_OVERFLOW', 10)),  # Reduced from 50
                'pool_timeout': int(os.environ.get('DATABASE_POOL_TIMEOUT', 60)),  # Increased from 30
                'pool_recycle': 1800,  # 30 minutes
                'pool_pre_ping': True,
                'pool_reset_on_return': 'commit',
                'echo': os.environ.get('FLASK_ENV') == 'development',
                'future': True,
                'connect_args': {
                    'connect_timeout': 10  # 10s connection timeout
                }
            }
        elif database_url.startswith('mysql'):
            return {
                'poolclass': QueuePool,
                'pool_size': int(os.environ.get('DATABASE_POOL_SIZE', 10)),  # Optimized from 15
                'max_overflow': int(os.environ.get('DATABASE_MAX_OVERFLOW', 10)),  # Optimized from 30
                'pool_timeout': int(os.environ.get('DATABASE_POOL_TIMEOUT', 60)),  # Increased from 20
                'pool_recycle': 3600,  # 1 hour
                'pool_pre_ping': True,
                'pool_reset_on_return': 'rollback',  # Clean transaction state for MySQL
                'echo': os.environ.get('FLASK_ENV') == 'development',
                'connect_args': {
                    'connect_timeout': 10
                }
            }
        else:  # SQLite
            return {
                'poolclass': StaticPool,
                'pool_pre_ping': True,
                'connect_args': {
                    'timeout': 60,
                    'check_same_thread': False,
                    'isolation_level': None,
                    'journal_mode': 'WAL',
                    'synchronous': 'NORMAL',
                    'cache_size': -64000,  # 64MB cache
                    'temp_store': 2
                }
            }
    
    # ✅ Sınıf tanımlandıktan sonra engine options'ı dinamik olarak ayarla
    @classmethod
    def init_engine_options(cls):
        """Sınıf başlatıldıktan sonra engine options'ı ayarla"""
        cls.SQLALCHEMY_ENGINE_OPTIONS = cls.get_database_engine_options()
    
    # ✅ QUERY PERFORMANCE SETTINGS
    SQLALCHEMY_RECORD_QUERIES = os.environ.get('FLASK_ENV') == 'development'
    
    # ✅ PERFORMANCE MONITORING
    SLOW_QUERY_THRESHOLD = float(os.environ.get('SLOW_QUERY_THRESHOLD', 0.1))
    ENABLE_QUERY_LOGGING = os.environ.get('ENABLE_QUERY_LOGGING', 'False').lower() == 'true'

# ✅ Sınıf tanımlandıktan sonra engine options'ı başlat
Config.init_engine_options()






