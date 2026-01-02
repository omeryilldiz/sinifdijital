from dotenv import load_dotenv
import os

# Production'da .env.production, development'ta .env kullan
env_file = '.env.production' if os.environ.get('FLASK_ENV') == 'production' else '.env'
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), env_file))

import secrets
import logging

# OAuth güvenlik: Sadece development modunda HTTP'ye izin ver
if os.environ.get('FLASK_ENV') != 'production':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import event
from flask_bcrypt import Bcrypt
from SF.config import Config
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from SF.config import Config
from flask_caching import Cache
import redis
import time

from werkzeug.middleware.proxy_fix import ProxyFix


app = Flask(__name__)
app.config.from_object(Config)  
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

# ✅ ProxyFix: Nginx proxy arkasında gerçek IP adresleri için
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,  # X-Forwarded-For header sayısı
    x_proto=1,  # X-Forwarded-Proto header sayısı
    x_host=1,  # X-Forwarded-Host header sayısı
    x_prefix=0
)

# Set log level from environment (default to WARNING in production)
log_level = os.getenv('LOG_LEVEL', 'WARNING')
app.logger.setLevel(log_level)

# Mail nesnesi Config yüklendikten SONRA oluşturulmalı
mail = Mail(app)  

# Diğer uzantılar
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)

# Redis ile rate limiting için storage backend ayarı
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[app.config['RATELIMIT_DEFAULT']],
    storage_uri=os.environ.get("REDIS_URL", "memory://")
)

# Redis client for monitoring/logging (used by rate-limit admin tools)
try:
    redis_client = redis.Redis.from_url(app.config.get('REDIS_URL', os.environ.get('REDIS_URL', 'redis://localhost:6379/0')), decode_responses=True)
    # quick ping to verify connection (fail quietly)
    try:
        redis_client.ping()
        app.logger.info('Redis client connected for rate-limit monitoring')
    except Exception:
        app.logger.warning('Redis client could not ping server (monitoring disabled)')
except Exception:
    redis_client = None
    app.logger.warning('Redis client not available; rate-limit monitoring disabled')

try:
    cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})
    app.logger.info('Flask-Caching SimpleCache initialized')
except Exception:
    cache = None
    app.logger.warning('Cache could not be initialized')

ALLOWED_EXTENSIONS = app.config['ALLOWED_EXTENSIONS']
ALLOWED_PDF_EXTENSIONS = app.config['ALLOWED_PDF_EXTENSIONS']

login_manager.login_view = 'login'
login_manager.login_message = 'Sayfaya ulaşmak için lütfen giriş yapın'
login_manager.login_message_category = 'info'


# Database session cleanup on request teardown
@app.teardown_appcontext
def shutdown_session(exception=None):
    """Clean up database session at end of request"""
    try:
        db.session.remove()
        if exception:
            app.logger.warning(f"Session cleanup: exception={exception.__class__.__name__}")
        else:
            app.logger.debug("Session cleanup: success")
    except Exception as e:
        app.logger.error(f"Session cleanup error: {str(e)}")


# Register connection event listeners after app is available
def _register_db_event_listeners():
    """Register database connection lifecycle event listeners"""
    @event.listens_for(db.engine, "connect")
    def receive_connect(dbapi_conn, connection_record):
        """Log when connection is created and set PostgreSQL statement timeout"""
        app.logger.debug(f"Database connection created: {id(dbapi_conn)}")
        # Set statement_timeout for PostgreSQL (30s = 30000ms)
        if 'psycopg2' in str(type(dbapi_conn)):
            try:
                dbapi_conn.cursor().execute("SET statement_timeout TO 30000")
                dbapi_conn.commit()
                app.logger.debug(f"PostgreSQL statement_timeout set to 30s on connection {id(dbapi_conn)}")
            except Exception as e:
                app.logger.warning(f"Could not set statement_timeout: {e}")

    @event.listens_for(db.engine, "checkout")
    def receive_checkout(dbapi_conn, connection_record, connection_proxy):
        """Log when connection is checked out from pool (only in debug mode)"""
        if os.getenv('DEBUG_DB_CONNECTIONS') == 'true':
            app.logger.debug(f"Database connection checked out: {id(dbapi_conn)}")

    @event.listens_for(db.engine, "checkin")
    def receive_checkin(dbapi_conn, connection_record):
        """Log when connection is returned to pool (only in debug mode)"""
        if os.getenv('DEBUG_DB_CONNECTIONS') == 'true':
            app.logger.debug(f"Database connection checked in: {id(dbapi_conn)}")

    @event.listens_for(db.engine, "close")
    def receive_close(dbapi_conn, connection_record):
        """Log when connection is closed"""
        app.logger.debug(f"Database connection closed: {id(dbapi_conn)}")


# Register event listeners with app context
with app.app_context():
    _register_db_event_listeners()




# Query Performance Logging (app context içinde register et)
from SF.services.query_logger_service import query_logger

def _register_query_logger():
    """Query logger'ı engine'e kaydet"""
    try:
        query_logger.register_listeners(db.engine)
        app.logger.info(f"Query logger initialized (threshold: {query_logger.slow_query_threshold}s)")
    except Exception as e:
        app.logger.warning(f"Query logger registration failed: {str(e)}")

# Register handler
with app.app_context():
    _register_query_logger()

from SF import routes
# Import CLI commands
try:
    import show_admin_url
except ImportError:
    pass
