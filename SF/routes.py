from flask import render_template, redirect, url_for, flash, request, abort, jsonify, session, g, current_app, send_from_directory
from SF import app, db, bcrypt, ALLOWED_EXTENSIONS, ALLOWED_PDF_EXTENSIONS, limiter, csrf
from flask_wtf.csrf import validate_csrf
from SF.forms import LoginForm, RegistrationForm, AdminLoginForm, AdminRegisterForm, AdminEditForm, SinifForm, DersForm, UniteForm, IcerikForm, SoruEkleForm, SoruEditForm, DersNotuForm, VideoForm, VideoEditForm, DersNotuEditForm, CompleteProfileForm, ProfileUpdateForm, StudentSearchForm, BulkActionForm, AdminStudentEditForm, PasswordResetRequestForm, PasswordResetForm, HomepageSlideForm, ChangePasswordForm 
from SF.services.security_service import SecurityService
from SF.models import User, Sinif, Ders, Unite, Icerik, Soru, DersNotu, VideoIcerik, Province, District, School, SchoolType, UserProgress, ActivityType, Settings, HomepageSlide, create_slug, UserLoginLog, LogActionType
from SF.services.advanced_query_optimizer import AdvancedQueryOptimizer
from SF.services.performance_monitor import performance_monitor
from SF.services.query_optimizer import QueryOptimizer
from sqlalchemy import text, select
from flask_login import login_user, current_user, logout_user, login_required
from functools import wraps
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
import re, os, traceback, time, humanize, pytz
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from werkzeug.utils import secure_filename, safe_join
from sqlalchemy import and_, distinct, func
from SF.services.statistics_service import StatisticsService
from SF.services.student_statistics_service import StudentStatisticsService
from SF.services.leaderboard_service import LeaderboardService
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from SF import mail, secrets, redis_client, cache
from flask_mail import Message as MailMessage
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_dance.contrib.google import make_google_blueprint, google


UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']
SORU_UPLOAD_FOLDER = app.config['SORU_UPLOAD_FOLDER']
VIDEO_UPLOAD_FOLDER = app.config['VIDEO_UPLOAD_FOLDER']
COZUM_UPLOAD_FOLDER = app.config['COZUM_UPLOAD_FOLDER']
PDF_UPLOAD_FOLDER = app.config['PDF_UPLOAD_FOLDER']
ALLOWED_EXTENSIONS = app.config['ALLOWED_EXTENSIONS']
ALLOWED_PDF_EXTENSIONS = app.config['ALLOWED_PDF_EXTENSIONS']



os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SORU_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PDF_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(VIDEO_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(COZUM_UPLOAD_FOLDER, exist_ok=True)

# Flask uygulaması başlatılırken gerekli dizinlerin oluşturulması

tr_tz = pytz.timezone('Europe/Istanbul')

@app.route('/ads.txt')
def ads_txt():
    return send_from_directory(app.static_folder, 'ads.txt')


# ========================================
# Health Check Endpoint (Production Monitoring)
# ========================================
@app.route('/health')
def health_check():
    """
    Production health check endpoint.
    Returns system status for load balancers and monitoring tools.
    """
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'checks': {}
    }
    
    # Database connection check
    try:
        db.session.execute(text('SELECT 1'))
        health_status['checks']['database'] = 'ok'
    except Exception as e:
        health_status['checks']['database'] = 'error'
        health_status['status'] = 'unhealthy'
        app.logger.error(f"Health check - DB error: {str(e)}")
    
    # Redis connection check
    try:
        if redis_client:
            redis_client.ping()
            health_status['checks']['redis'] = 'ok'
        else:
            health_status['checks']['redis'] = 'not_configured'
    except Exception as e:
        health_status['checks']['redis'] = 'error'
        app.logger.warning(f"Health check - Redis error: {str(e)}")
    
    # Return appropriate status code
    status_code = 200 if health_status['status'] == 'healthy' else 503
    return jsonify(health_status), status_code


@app.route('/health/ready')
def readiness_check():
    """Kubernetes readiness probe - checks if app can serve requests."""
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify({'ready': True}), 200
    except Exception:
        return jsonify({'ready': False}), 503


@app.route('/health/live')
def liveness_check():
    """Kubernetes liveness probe - checks if app is alive."""
    return jsonify({'alive': True}), 200


## Dosya uzantılarını kontrol et
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_pdf_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_PDF_EXTENSIONS

def allowed_video_file(filename):
    """Video dosya uzantısı kontrolü"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_VIDEO_EXTENSIONS']


# Caching helpers: return no-op decorators when cache is unavailable
def _cache_cached(timeout=300, key_prefix=None):
    if cache:
        return cache.cached(timeout=timeout, key_prefix=key_prefix)
    def _decorator(f):
        return f
    return _decorator

def _cache_memoize(timeout=300):
    if cache:
        return cache.memoize(timeout=timeout)
    def _decorator(f):
        return f
    return _decorator


# Path traversal koruma yardımcıları
def _abspath_join(base, *paths):
    """Base dizin ile birleştirip mutlak yolu döndürür."""
    return os.path.abspath(os.path.join(base, *paths))


def is_within_directory(base, target_path):
    """target_path'in base dizini içinde olup olmadığını kontrol eder."""
    base = os.path.abspath(base)
    target = os.path.abspath(target_path)
    try:
        return os.path.commonpath([base, target]) == base
    except ValueError:
        return False


def send_protected_file(directory, filename):
    """Güvenli şekilde dosya gönderir: `secure_filename`, yol doğrulama ve varlık kontrolü yapar."""
    secure_name = secure_filename(filename)
    fullpath = _abspath_join(directory, secure_name)
    if not is_within_directory(directory, fullpath):
        app.logger.warning(f"Path traversal denemesi: {filename}")
        abort(404)
    if not os.path.exists(fullpath):
        abort(404)
    return send_from_directory(directory, secure_name)


# Rate limit exceeded handler: log details and return JSON or template
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Kullanıcı giriş yapmış mı?
        if not current_user.is_authenticated:
            flash('Bu sayfaya erişmek için giriş yapmalısınız.', 'warning')
            return redirect(url_for('admin_login'))
        
        # Kullanıcı admin mi?
        if current_user.role != 'admin':
            flash('Bu sayfaya erişim yetkiniz yok!', 'danger')
            abort(403)  # Forbidden error
            
        return f(*args, **kwargs)
    return decorated_function


@app.errorhandler(429)
def ratelimit_handler(e):
    try:
        ip = get_client_ip()
        endpoint = request.endpoint
        method = request.method
        app.logger.warning(f"Rate limit exceeded: IP={ip} endpoint={endpoint} method={method} path={request.path} detail={str(e)}")
    except Exception:
        app.logger.warning(f"Rate limit exceeded: {str(e)}")

    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept', '').startswith('application/json'):
        return jsonify({'error': 'Too Many Requests', 'message': str(e)}), 429
    return render_template('429.html'), 429


@app.route('/admin/rate-limit-stats')
@admin_required
def rate_limit_stats():
    """Admin endpoint: Redis üzerindeki rate-limit anahtarlarını tarayıp temel istatistik döner."""
    if not redis_client:
        return jsonify({'error': 'Redis not configured for monitoring'}), 500
    try:
        # pattern param ile filtreleme imkanı
        pattern = request.args.get('pattern', '*limiter*')
        keys = list(redis_client.scan_iter(match=pattern, count=1000))
        stats = {}
        for k in keys:
            try:
                t = redis_client.type(k)
                ttl = redis_client.ttl(k)
                if t == 'string':
                    val = redis_client.get(k)
                elif t == 'hash':
                    val = redis_client.hgetall(k)
                elif t == 'set':
                    val = list(redis_client.smembers(k))
                elif t == 'zset':
                    val = redis_client.zrange(k, 0, -1, withscores=True)
                elif t == 'list':
                    val = redis_client.lrange(k, 0, 100)
                else:
                    val = None
                stats[k] = {'type': t, 'ttl': ttl, 'value': val}
            except Exception as ex:
                stats[k] = {'error': str(ex)}

        return jsonify({'keys_count': len(keys), 'stats': stats})
    except Exception as e:
        app.logger.error(f"Rate limit stats error: {str(e)}")
        return jsonify({'error': 'internal error'}), 500


@app.route('/admin/test-smtp', methods=['GET', 'POST'])
@admin_required
def test_smtp_config():
    """
    Admin endpointi: SMTP konfigürasyonunu test et ve rapor döndür.
    GET: Test sayfasını göster
    POST: SMTP testini çalıştır ve sonucu döndür
    """
    from SF.services.email_service import EmailService
    
    if request.method == 'POST':
        # SMTP testi yapıldı
        try:
            recipient = request.get_json(silent=True)
            recipient_email = recipient.get('recipient_email', '') if recipient else ''
            
            if not recipient_email:
                return jsonify({
                    'status': 'error',
                    'message': 'Alıcı email adresi gerekli'
                }), 400
            
            # Tam SMTP test akışını çalıştır
            result = EmailService.test_email_full_flow(recipient_email)
            
            return jsonify(result), 200
            
        except Exception as e:
            app.logger.error(f"SMTP test error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': f'Test sırasında hata: {str(e)}'
            }), 500
    
    else:
        # GET isteği - konfigürasyon durumunu kontrol et
        config = EmailService.get_smtp_config()
        is_valid, errors = EmailService.validate_smtp_config()
        
        return jsonify({
            'config_status': {
                'valid': is_valid,
                'errors': errors,
                'config': {
                    'server': config['server'],
                    'port': config['port'],
                    'username': config['username'][:3] + '***' if config['username'] else None,
                    'use_tls': config['use_tls'],
                    'use_ssl': config['use_ssl'],
                    'sender': config['sender']
                }
            },
            'message': 'SMTP konfigürasyonu test edilmeye hazır. POST isteği göndererek tam test yapın.'
        }), 200

@app.route('/api/test-smtp', methods=['GET', 'POST'])
@csrf.exempt  # Test amaçlı genel endpoint
def test_smtp_api():
    """
    SMTP Konfigürasyonunu test et (genel API).
    GET: Konfigürasyon durumunu kontrol et
    POST: Tam test yap ve test maili gönder
    """
    from SF.services.email_service import EmailService
    
    # Güvenlik: IP bazlı simple rate limiting (production'da daha sıkı olmalı)
    if request.method == 'POST':
        try:
            data = request.get_json(silent=True)
            recipient_email = data.get('recipient_email', '') if data else ''
            
            if not recipient_email or '@' not in recipient_email:
                return jsonify({
                    'status': 'error',
                    'message': 'Geçerli bir email adresi gerekli (örn: user@example.com)'
                }), 400
            
            app.logger.info(f"SMTP test başlatılıyor: {request.remote_addr} -> {recipient_email}")
            
            # Tam SMTP test akışını çalıştır
            result = EmailService.test_email_full_flow(recipient_email)
            
            return jsonify(result), 200
            
        except Exception as e:
            app.logger.error(f"SMTP test error: {str(e)}")
            return jsonify({
                'status': 'error',
                'message': f'Test sırasında hata oluştu'
            }), 500
    
    else:
        # GET isteği - konfigürasyon durumunu kontrol et
        with app.app_context():
            config = EmailService.get_smtp_config()
            is_valid, errors = EmailService.validate_smtp_config()
            
            return jsonify({
                'status': 'ok',
                'config_valid': is_valid,
                'config_errors': errors,
                'config': {
                    'server': config['server'],
                    'port': config['port'],
                    'username': config['username'][:3] + '***' if config['username'] else None,
                    'use_tls': config['use_tls'],
                    'use_ssl': config['use_ssl'],
                    'sender': config['sender']
                },
                'message': 'Test email göndermek için POST isteği yapın: {"recipient_email": "test@example.com"}'
            }), 200

@app.route('/api/query-performance', methods=['GET'])
@csrf.exempt
def query_performance_stats():
    """
    Sorgu performans istatistiklerini döndür.
    Query: ?type=stats|slow|frequent|slowest
    """
    from SF.services.query_logger_service import query_logger
    
    try:
        query_type = request.args.get('type', 'stats')
        limit = request.args.get('limit', 10, type=int)
        hours = request.args.get('hours', 1, type=int)
        
        if query_type == 'stats':
            # Genel istatistikler
            stats = query_logger.get_stats()
            return jsonify({
                'type': 'statistics',
                'data': stats
            }), 200
        
        elif query_type == 'slow':
            # Son saatlerdeki yavaş sorgular
            slow_queries = query_logger.get_slow_queries(limit=limit, hours=hours)
            return jsonify({
                'type': 'slow_queries',
                'hours': hours,
                'count': len(slow_queries),
                'data': slow_queries
            }), 200
        
        elif query_type == 'slowest':
            # En yavaş sorgular
            slowest = query_logger.get_slowest_queries(limit=limit)
            return jsonify({
                'type': 'slowest_queries',
                'count': len(slowest),
                'data': slowest
            }), 200
        
        elif query_type == 'frequent':
            # En sık yavaş çalışan sorgular
            frequent = query_logger.get_most_frequent_slow_queries(limit=limit)
            return jsonify({
                'type': 'most_frequent_slow_queries',
                'count': len(frequent),
                'data': frequent
            }), 200
        
        else:
            return jsonify({
                'error': 'Invalid type parameter',
                'valid_types': ['stats', 'slow', 'slowest', 'frequent']
            }), 400
    
    except Exception as e:
        app.logger.error(f"Query performance stats error: {str(e)}")
        return jsonify({'error': 'Internal error'}), 500


@app.route('/admin/query-performance', methods=['GET'])
@admin_required
def admin_query_performance():
    """Admin paneli: Sorgu performans yönetim sayfası"""
    from SF.services.query_logger_service import query_logger
    
    try:
        stats = query_logger.get_stats()
        slow_queries = query_logger.get_slow_queries(limit=20, hours=24)
        slowest = query_logger.get_slowest_queries(limit=10)
        frequent = query_logger.get_most_frequent_slow_queries(limit=10)
        
        return jsonify({
            'status': 'ok',
            'statistics': stats,
            'slow_queries_24h': {
                'count': len(slow_queries),
                'data': slow_queries
            },
            'slowest_queries': {
                'count': len(slowest),
                'data': slowest
            },
            'most_frequent_slow': {
                'count': len(frequent),
                'data': frequent
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"Admin query performance error: {str(e)}")
        return jsonify({'error': 'Internal error'}), 500

@app.route('/get_districts/<int:province_id>')
def get_districts(province_id):
    districts = District.query.filter_by(province_id=province_id).all()
    district_list = [{'id': d.id, 'name': d.name} for d in districts]
    return jsonify(district_list)

    
    
@app.route('/get_schools_filtered/<int:district_id>/<int:school_type_id>')
def get_schools_filtered(district_id, school_type_id):
    try:
        schools = School.query.filter_by(
            district_id=district_id,
            school_type_id=school_type_id
        ).order_by(School.name).all()
        
        return jsonify([{
            'id': school.id,
            'name': school.name
        } for school in schools])
    except Exception as e:
        app.logger.error(f"Okul verisi alınırken hata: {str(e)}")
        return jsonify({'error': 'Veriler alınamadı'}), 500


@_cache_cached(timeout=300, key_prefix='inject_siniflar')
@app.context_processor
def inject_siniflar():
    siniflar = Sinif.query.order_by(Sinif.id).all()
    active_sinif = getattr(g, 'active_sinif', None)
    return dict(siniflar=siniflar, active_sinif=active_sinif)

@app.before_request
def set_active_sinif():
    active_sinif = None
    if request.view_args:
        # Eğer sinif_slug varsa
        if 'sinif_slug' in request.view_args:
            sinif = Sinif.query.filter_by(slug=request.view_args['sinif_slug']).first()
            if sinif:
                active_sinif = sinif.id
        # Eğer slug varsa (ör: /<slug>)
        elif 'slug' in request.view_args:
            sinif = Sinif.query.filter_by(slug=request.view_args['slug']).first()
            if sinif:
                active_sinif = sinif.id
        # Eğer sinif_id varsa (eski rotalar için)
        elif 'sinif_id' in request.view_args:
            active_sinif = request.view_args['sinif_id']
    g.active_sinif = active_sinif


@app.route('/')
def home():
    # Aktif slaytları sıralı şekilde al
    slides = HomepageSlide.query.filter_by(is_active=True).order_by(HomepageSlide.order.asc()).all()
    return render_template('home.html', title='Ana Sayfa', slides=slides)



@app.route('/<slug>')
def sinif(slug):
    sinif = Sinif.query.filter_by(slug=slug).first_or_404()
    dersler = Ders.query.filter_by(sinif_id=sinif.id).all()
    return render_template('sinif.html', sinif=sinif, dersler=dersler)


def build_okundu_set(user_id, icerik_ids):
    """
    Belirli içerik ID listesi için kullanıcının okuduğu (okundu=True + content_reading) içerikleri set olarak döndür.
    """
    if not icerik_ids:
        return set()
    rows = (
        db.session.query(UserProgress.icerik_id)
        .filter(
            UserProgress.user_id == user_id,
            UserProgress.icerik_id.in_(icerik_ids),
            UserProgress.activity_type == ActivityType.CONTENT_READING,
            UserProgress.okundu.is_(True)
        )
        .distinct()
        .all()
    )
    return {r[0] for r in rows}


def _prepare_uniteler_with_icerikler(ders_id):
    """
    Template içinde hasattr kullanmamak için ünite + içerik listesini düzleştirir.
    Her eleman: {'id': unite.id, 'unite': unite.unite, 'icerikler': [Icerik, ...]}
    """
    result = []
    uniteler = Unite.query.filter_by(ders_id=ders_id).order_by(Unite.id.asc()).all()
    for u in uniteler:
        if hasattr(u.icerikler, 'all'):  
            icerikler = u.icerikler.all()
        else:
            icerikler = u.icerikler
        result.append({
            'id': u.id,
            'unite': u.unite,
            'unite_slug': u.slug,  
            'icerikler': icerikler
        })
    return result




def _wrap_uniteler(ders_id):
    blocks = []
    uniteler = Unite.query.filter_by(ders_id=ders_id).order_by(Unite.id.asc()).all()
    for u in uniteler:
        coll = u.icerikler.all() if hasattr(u.icerikler, 'all') else u.icerikler
        blocks.append({'id': u.id, 'unite': u.unite, 'icerikler': list(coll)})
    return blocks


def turkce_humanize(text):
    return (text
        .replace('seconds ago', 'saniye önce')
        .replace('minutes ago', 'dakika önce')
        .replace('hours ago', 'saat önce')
        .replace('days ago', 'gün önce')
        .replace('a minute ago', '1 dakika önce')
        .replace('an hour ago', '1 saat önce')
        .replace('a day ago', '1 gün önce')
    )
    

@app.route('/kvkk')
def kvkk():
    return render_template('legal/kvkk.html')

@app.route('/gizlilik')
@app.route('/gizlilik-politikasi')
def gizlilik():
    return render_template('legal/gizlilik.html')

@app.route('/kullanim-kosullari')
@app.route('/terms')
def kullanim():
    return render_template('legal/kullanim.html')




@_cache_memoize(timeout=300)
def get_user_progress_tree(user_id):
    """
    Kullanıcının sınıfına göre ilerleme ağacını döner.
    12. Sınıf → 12 + TYT + AYT
    8. Sınıf → 8 + LGS
    Diğer sınıflar → Sadece kendi sınıfı
    """
    user = User.query.get(user_id)
    
    if not user:
        app.logger.warning(f"Kullanıcı bulunamadı: {user_id}")
        return []
    
    if not user.class_no:
        flash('Profilinizde sınıf bilgisi bulunamadığı için ilerleme verisi gösterilemiyor.', 'warning')
        return []
    
    # ✅ YENİ: Kullanıcının yarışma grubundaki tüm sınıfları al
    try:
        competing_classes = user.get_competing_classes()
        app.logger.info(f"Kullanıcı {user_id} için yarışma sınıfları: {competing_classes}")
    except Exception as e:
        app.logger.error(f"get_competing_classes hatası: {str(e)}")
        competing_classes = [str(user.class_no)]
    
    # ✅ YENİ: Bu sınıflara ait tüm Sinif kayıtlarını bul
    siniflar = Sinif.query.filter(
        db.or_(
            Sinif.sinif.in_(competing_classes),
            Sinif.slug.in_([str(c).lower() for c in competing_classes])
        )
    ).all()
    
    if not siniflar:
        app.logger.warning(f"Sınıf bulunamadı: {competing_classes}")
        flash('Sınıfınıza ait içerik bulunamadı.', 'warning')
        return []
    
    app.logger.info(f"Bulunan sınıflar: {[s.sinif for s in siniflar]}")
    
    # ✅ YENİ: Tüm sınıfların derslerini topla
    sinif_ids = [s.id for s in siniflar]
    dersler = Ders.query.options(joinedload(Ders.sinif)).filter(Ders.sinif_id.in_(sinif_ids)).all()
    
    # ...existing code... (Bundan sonraki tüm kod AYNI kalacak)
    
    ders_ids = [d.id for d in dersler]
    if not ders_ids:
        return []
    
    # Toplu sorgular ile verileri çek
    uniteler = Unite.query.filter(Unite.ders_id.in_(ders_ids)).all()
    unite_ids = [u.id for u in uniteler]
    icerikler = Icerik.query.filter(Icerik.unite_id.in_(unite_ids)).all() if unite_ids else []
    icerik_ids = [i.id for i in icerikler]
    
    # Okundu durumlarını toplu çek
    okundu_set = build_okundu_set(user_id, icerik_ids) if icerik_ids else set()
    
    # Harcanan süreleri toplu çek
    spent_times = dict(db.session.query(
        UserProgress.icerik_id,
        func.coalesce(func.sum(UserProgress.harcanan_sure), 0)
    ).filter(
        UserProgress.user_id == user_id,
        UserProgress.activity_type == ActivityType.CONTENT_READING,
        UserProgress.icerik_id.in_(icerik_ids)
    ).group_by(UserProgress.icerik_id).all())
    
    # Soru istatistiklerini toplu çek
    soru_stats = {}
    if icerik_ids:
        rows = db.session.query(
            UserProgress.icerik_id,
            func.coalesce(func.sum(UserProgress.dogru_sayisi), 0),
            func.coalesce(func.sum(UserProgress.yanlis_sayisi), 0),
            func.coalesce(func.sum(UserProgress.bos_sayisi), 0)
        ).filter(
            UserProgress.user_id == user_id,
            UserProgress.activity_type == ActivityType.QUESTION_SOLVING,
            UserProgress.icerik_id.in_(icerik_ids)
        ).group_by(UserProgress.icerik_id).all()
        soru_stats = {r[0]: (int(r[1]), int(r[2]), int(r[3])) for r in rows}
    
    # Son görüntüleme tarihlerini toplu çek
    last_views = dict(db.session.query(
        UserProgress.icerik_id,
        func.max(UserProgress.tarih)
    ).filter(
        UserProgress.user_id == user_id,
        UserProgress.activity_type == ActivityType.CONTENT_READING,
        UserProgress.okundu.is_(True),
        UserProgress.icerik_id.in_(icerik_ids)
    ).group_by(UserProgress.icerik_id).all())
    
    # Aktif yanlış soru sayılarını hesapla
    aktif_yanlis_per_icerik = {}
    if icerik_ids:
        sub = db.session.query(
            UserProgress.soru_id,
            func.max(UserProgress.tarih).label('mx')
        ).filter(
            UserProgress.user_id == user_id,
            UserProgress.activity_type == ActivityType.QUESTION_SOLVING
        ).group_by(UserProgress.soru_id).subquery()
        
        latest = db.session.query(UserProgress.soru_id, UserProgress.yanlis_sayisi, Soru.icerik_id).join(
            sub, and_(UserProgress.soru_id == sub.c.soru_id, UserProgress.tarih == sub.c.mx)
        ).join(Soru, UserProgress.soru_id == Soru.id).filter(UserProgress.yanlis_sayisi > 0).all()
        
        for _soru_id, yanlis_sayisi, icerik_id in latest:
            aktif_yanlis_per_icerik[icerik_id] = aktif_yanlis_per_icerik.get(icerik_id, 0) + 1
    
    # Map yapıları oluştur
    uniteler_by_ders = {}
    for u in uniteler:
        uniteler_by_ders.setdefault(u.ders_id, []).append(u)
    
    icerikler_by_unite = {}
    for ic in icerikler:
        icerikler_by_unite.setdefault(ic.unite_id, []).append(ic)
    
    # ✅ YENİ: Sınıf sıralama önceliği (12 -> TYT -> AYT, 8 -> LGS)
    sinif_sirasi = {
        '5': 1, '6': 2, '7': 3, '8': 4, 'LGS': 5,
        '9': 6, '10': 7, '11': 8, '12': 9, 'TYT': 10, 'AYT': 11, 'Mezun': 12
    }
    
    # Dersleri sınıf sırasına göre sırala
    dersler_sorted = sorted(dersler, key=lambda d: (
        sinif_sirasi.get(d.sinif.sinif if d.sinif else '', 99),
        d.ders_adi
    ))
    
    # Ağacı oluştur
    result = []
    for ders in dersler_sorted:
        ders_data = {
            'id': ders.id, 
            'name': ders.ders_adi, 
            'slug': ders.slug, 
            'color_class': 'primary',
            'sinif_adi': ders.sinif.sinif if ders.sinif else '',  # ✅ YENİ: Sınıf adı eklendi
            'units': [], 
            'completion_percent': 0, 
            'completed_contents': 0, 
            'total_contents': 0,
            'correct_answers': 0, 
            'wrong_answers': 0, 
            'empty_answers': 0, 
            'total_questions': 0, 
            'success_rate': 0
        }
        
        for unite in uniteler_by_ders.get(ders.id, []):
            unite_data = {
                'id': unite.id, 'name': unite.unite, 'slug': unite.slug, 'color_class': 'info',
                'contents': [], 'completion_percent': 0, 'completed_contents': 0, 'total_contents': 0,
                'correct_answers': 0, 'wrong_answers': 0, 'empty_answers': 0, 'total_questions': 0, 'success_rate': 0
            }
            
            for ic in icerikler_by_unite.get(unite.id, []):
                okundu = ic.id in okundu_set
                dogru, yanlis, bos = soru_stats.get(ic.id, (0, 0, 0))
                toplam = dogru + yanlis + bos
                success_rate = int((dogru / toplam * 100) if toplam > 0 else 0)
                
                spent = int(spent_times.get(ic.id, 0))
                spent_str = None
                if spent > 0:
                    if spent < 60:
                        spent_str = f"{spent} sn"
                    elif spent < 3600:
                        spent_str = f"{spent // 60} dk"
                    else:
                        spent_str = f"{spent // 3600} sa {((spent % 3600) // 60)} dk"
                
                last_viewed = last_views.get(ic.id)
                last_viewed_humanized = None
                if last_viewed:
                    last_viewed_tr = last_viewed.replace(tzinfo=timezone.utc).astimezone(tr_tz)
                    last_viewed_humanized = turkce_humanize(humanize.naturaltime(last_viewed_tr))
                
                aktif_yanlis = aktif_yanlis_per_icerik.get(ic.id, 0)
                
                unite_data['contents'].append({
                    'id': ic.id, 'name': ic.baslik, 'status': 'completed' if okundu else 'in_progress',
                    'spent_time': spent_str, 'correct_answers': dogru, 'wrong_answers': aktif_yanlis,
                    'empty_answers': bos, 'total_questions': toplam, 'success_rate': success_rate,
                    'last_viewed': last_viewed, 'last_viewed_humanized': last_viewed_humanized,
                    'sinif_slug': ders.sinif.slug if ders.sinif else '', 'ders_slug': ders.slug,
                    'unite_slug': unite.slug, 'icerik_slug': ic.slug
                })
                
                unite_data['total_contents'] += 1
                if okundu:
                    unite_data['completed_contents'] += 1
                unite_data['correct_answers'] += dogru
                unite_data['wrong_answers'] += aktif_yanlis
                unite_data['empty_answers'] += bos
                unite_data['total_questions'] += toplam
            
            unite_data['completion_percent'] = int((unite_data['completed_contents'] / unite_data['total_contents'] * 100) if unite_data['total_contents'] > 0 else 0)
            unite_data['success_rate'] = int((unite_data['correct_answers'] / unite_data['total_questions'] * 100) if unite_data['total_questions'] > 0 else 0)
            
            ders_data['units'].append(unite_data)
            ders_data['completed_contents'] += unite_data['completed_contents']
            ders_data['total_contents'] += unite_data['total_contents']
            ders_data['correct_answers'] += unite_data['correct_answers']
            ders_data['wrong_answers'] += unite_data['wrong_answers']
            ders_data['empty_answers'] += unite_data['empty_answers']
            ders_data['total_questions'] += unite_data['total_questions']
        
        ders_data['completion_percent'] = int((ders_data['completed_contents'] / ders_data['total_contents'] * 100) if ders_data['total_contents'] > 0 else 0)
        ders_data['success_rate'] = int((ders_data['correct_answers'] / ders_data['total_questions'] * 100) if ders_data['total_questions'] > 0 else 0)
        result.append(ders_data)
    
    return result

@app.route('/<sinif_slug>/<ders_slug>')
def ders(sinif_slug, ders_slug):
    try:
        # HATA AYIKLAMA - Aranan slug'ları logla
        app.logger.info(f"Aranan slug'lar: sinif_slug={sinif_slug}, ders_slug={ders_slug}")
        
        # Önce first() ile kontrol edelim ve sonucu logla
        sinif_check = Sinif.query.filter_by(slug=sinif_slug).first()
        app.logger.info(f"Sınıf bulundu mu: {sinif_check is not None}")
        
        if sinif_check:
            ders_check = Ders.query.filter_by(slug=ders_slug, sinif_id=sinif_check.id).first()
            app.logger.info(f"Ders bulundu mu: {ders_check is not None}")
        
        # Normal first_or_404 kodu
        sinif = Sinif.query.filter_by(slug=sinif_slug).first_or_404()
        ders_obj = Ders.query.filter_by(slug=ders_slug, sinif_id=sinif.id).first_or_404()
        
        # Kullanıcının bu derse daha önce erişip erişmediğini kontrol et
        if current_user.is_authenticated:
            # ✅ Düzeltme: ders_id yerine icerik_id üzerinden sorgula, timestamp yerine tarih kullan
            # Önce dersin tüm içerik ID'lerini al
            icerik_ids = db.session.query(Icerik.id).join(Unite).filter(Unite.ders_id == ders_obj.id).all()
            icerik_ids = [id[0] for id in icerik_ids]
            
            if icerik_ids:
                last_view = UserProgress.query.filter(
                    UserProgress.user_id == current_user.id,
                    UserProgress.icerik_id.in_(icerik_ids),
                    UserProgress.activity_type == ActivityType.CONTENT_VIEWED
                ).order_by(UserProgress.tarih.desc()).first()  # ✅ tarih kullanıldı
            else:
                last_view = None
            
            if last_view:
                ic = last_view.icerik
                # İlgili unite nesnesini al
                unite = Unite.query.get_or_404(ic.unite_id)
                
                # Slug tabanlı yönlendirme
                return redirect(url_for(
                    'icerik',
                    sinif_slug=sinif.slug,
                    ders_slug=ders_obj.slug,
                    unite_slug=unite.slug,
                    icerik_slug=ic.slug
                ))
                
        # Uniteler ve içerikleri al
        uniteler_wrapped = _wrap_uniteler(ders_obj.id)
        
        # Hedef unite ve içerik ID'leri alınıyor
        target_unite_id = request.args.get('unite_id', type=int)
        target_icerik_id = request.args.get('icerik_id', type=int)
        
        # Hedeflenen içerik varsa git
        if target_unite_id and target_icerik_id:
            target_ic = Icerik.query.filter_by(id=target_icerik_id, unite_id=target_unite_id).first()
            if target_ic:
                # İlgili unite nesnesini al
                unite = Unite.query.get_or_404(target_ic.unite_id)
                
                # Slug tabanlı yönlendirme
                return redirect(url_for(
                    'icerik',
                    sinif_slug=sinif.slug,
                    ders_slug=ders_obj.slug,
                    unite_slug=unite.slug,
                    icerik_slug=target_ic.slug
                ))
        
        # İlk içeriğe yönlendirme
        if uniteler_wrapped and uniteler_wrapped[0]['icerikler']:
            ilk_icerik = uniteler_wrapped[0]['icerikler'][0]
            # İlgili unite nesnesini al
            unite = Unite.query.get_or_404(ilk_icerik.unite_id)
            
            # Slug tabanlı yönlendirme
            return redirect(url_for(
                'icerik',
                sinif_slug=sinif.slug,
                ders_slug=ders_obj.slug,
                unite_slug=unite.slug,
                icerik_slug=ilk_icerik.slug
            ))
        
        # İçerik yoksa
        flash('Bu ders için henüz içerik bulunmamaktadır.', 'info')
        return render_template(
            'ders.html', 
            sinif=sinif, 
            ders=ders_obj, 
            uniteler=uniteler_wrapped,
            siniflar=Sinif.query.all()  # Layout için gerekli
        )
    
    except Exception as e:
        app.logger.error(f"Ders sayfası hatası: {str(e)}")
        flash('Bir hata oluştu. Lütfen daha sonra tekrar deneyin.', 'error')
        return redirect(url_for('home'))
    
       
@app.route('/<sinif_slug>/<ders_slug>/<unite_slug>/<icerik_slug>')
def icerik(sinif_slug, ders_slug, unite_slug, icerik_slug):
    try:
        # İlişkili nesneleri slug'lara göre bul
        sinif = Sinif.query.filter_by(slug=sinif_slug).first_or_404()
        ders = Ders.query.filter_by(slug=ders_slug, sinif_id=sinif.id).first_or_404()
        unite = Unite.query.filter_by(slug=unite_slug, ders_id=ders.id).first_or_404()
        icerik = Icerik.query.filter_by(slug=icerik_slug, unite_id=unite.id).first_or_404()
        
        # İlişki tutarlılığı kontrolü
        if unite.ders_id != ders.id or ders.sinif_id != sinif.id or icerik.unite_id != unite.id:
            abort(404)

        icerik_id = icerik.id

        # İçerikleri ünitelerine göre grupla
        uniteler_wrapped = _prepare_uniteler_with_icerikler(ders.id)
        
        # Tüm içerik ID'lerini topla ve okundu durumlarını kontrol et
        all_icerik_ids = [ic.id for blk in uniteler_wrapped for ic in blk['icerikler']]
        okundu_set = set()
        if current_user.is_authenticated and all_icerik_ids:
            okundu_set = build_okundu_set(current_user.id, all_icerik_ids)

        # İçerikle ilgili diğer verileri çek
        videolar = VideoIcerik.query.filter_by(
            icerik_id=icerik_id, aktif=True
        ).order_by(VideoIcerik.sira.asc()).all()
        
        ders_notlari = DersNotu.query.filter_by(
            icerik_id=icerik_id
        ).order_by(DersNotu.eklenme_tarihi.desc()).all()
        
        # TÜM DERSİN İÇERİKLERİNİ ÜNİTE SIRASINA GÖRE AL
        uniteler = Unite.query.filter_by(ders_id=ders.id).order_by(Unite.id).all()
        all_contents = []
        for u in uniteler:
            unit_contents = Icerik.query.filter_by(unite_id=u.id).order_by(Icerik.id).all()
            for content in unit_contents:
                all_contents.append({
                    'id': content.id,
                    'baslik': content.baslik,
                    'unite_id': u.id,
                    'unite_adi': u.unite,
                    'slug': content.slug,
                    'unite_slug': u.slug
                })
        current_index = -1
        for i, content in enumerate(all_contents):
            if content['id'] == icerik_id:
                current_index = i
                break
        prev_content = None
        next_content = None
        prev_content_data = None
        next_content_data = None
        if current_index > 0:
            prev_item = all_contents[current_index - 1]
            prev_content = Icerik.query.get(prev_item['id'])
            prev_unite = Unite.query.get(prev_item['unite_id'])
            prev_content_data = {
                'icerik': prev_content,
                'unite_slug': prev_unite.slug
            }
        if current_index < len(all_contents) - 1:
            next_item = all_contents[current_index + 1]
            next_content = Icerik.query.get(next_item['id'])
            next_unite = Unite.query.get(next_item['unite_id'])
            next_content_data = {
                'icerik': next_content,
                'unite_slug': next_unite.slug
            }
        total_contents = len(all_contents)
        current_position = current_index + 1  # 0-tabanlı indeksi 1-tabanlı hale getir

        # İçerik görüntülendiğinde aktivite kaydı oluştur (TEK KAYIT MANTIĞI)
        if current_user.is_authenticated:
            try:
                progress = UserProgress.query.filter_by(
                    user_id=current_user.id,
                    icerik_id=icerik_id,
                    activity_type=ActivityType.CONTENT_VIEWED
                ).first()
                if not progress:
                    progress = UserProgress(
                        user_id=current_user.id,
                        icerik_id=icerik_id,
                        activity_type=ActivityType.CONTENT_VIEWED,
                        tarih=datetime.utcnow()
                    )
                    db.session.add(progress)
                else:
                    progress.tarih = datetime.utcnow()
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"İçerik görüntüleme kaydı hatası: {str(e)}")

        return render_template(
            'icerik.html',
            sinif=sinif,
            ders=ders,
            unite=unite,
            icerik=icerik,
            uniteler=uniteler_wrapped,
            videolar=videolar,
            ders_notlari=ders_notlari,
            active_icerik_id=icerik_id,
            okundu_set=okundu_set,
            prev_content=prev_content,
            next_content=next_content,
            prev_content_data=prev_content_data,
            next_content_data=next_content_data,
            current_position=current_position,
            total_contents=total_contents
        )
    
    except Exception as e:
        app.logger.error(f"İçerik görüntüleme hatası: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('İçerik yüklenirken bir hata oluştu.', 'danger')
        return redirect(url_for('home'))

    
def _limiter_key_user_or_ip():
    try:
        return str(current_user.id) if getattr(current_user, 'is_authenticated', False) else get_remote_address()
    except Exception:
        return get_remote_address()

# NOTE: Client should batch small updates into the `buffer` list
# (debounce on client-side, e.g. send every 5-30s) to reduce request frequency.
@app.route('/icerik-sure-kaydet', methods=['POST'])
@login_required
@limiter.limit("120 per minute", key_func=_limiter_key_user_or_ip)
@csrf.exempt
def icerik_sure_kaydet():
    try:
        data = request.get_json(silent=True)
        
        if not data:
            return jsonify({'status': 'error', 'message': 'Boş veri'}), 400
            
        user_id = current_user.id

        buffer = data.get('buffer')
        if buffer and isinstance(buffer, list):
            for item in buffer:
                icerik_id = item.get('icerik_id')
                harcanan_sure = item.get('harcanan_sure')
                activity_type = item.get('activity_type', 'content_reading')
                if not icerik_id or not harcanan_sure or int(harcanan_sure) <= 0:
                    continue

                # Her kullanıcı + içerik + activity_type + gün için tek kayıt!
                today = datetime.utcnow().date()
                progress = UserProgress.query.filter_by(
                    user_id=user_id,
                    icerik_id=icerik_id,
                    activity_type=activity_type
                ).filter(func.date(UserProgress.tarih) == today).first()
                if not progress:
                    progress = UserProgress(
                        user_id=user_id,
                        icerik_id=icerik_id,
                        harcanan_sure=int(harcanan_sure),
                        activity_type=activity_type,
                        tarih=datetime.utcnow()
                    )
                    db.session.add(progress)
                else:
                    progress.harcanan_sure = (progress.harcanan_sure or 0) + int(harcanan_sure)
                    progress.tarih = datetime.utcnow()
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Süre günlük olarak kaydedildi'})
        else:
            icerik_id = data.get('icerik_id')
            harcanan_sure = data.get('harcanan_sure')
            activity_type = data.get('activity_type', 'content_reading')
            if not icerik_id or not harcanan_sure or int(harcanan_sure) <= 0:
                return jsonify({'status': 'error', 'message': 'Eksik veya hatalı veri'}), 400
            today = datetime.utcnow().date()
            progress = UserProgress.query.filter_by(
                user_id=user_id,
                icerik_id=icerik_id,
                activity_type=activity_type
            ).filter(func.date(UserProgress.tarih) == today).first()
            if not progress:
                progress = UserProgress(
                    user_id=user_id,
                    icerik_id=icerik_id,
                    harcanan_sure=int(harcanan_sure),
                    activity_type=activity_type,
                    tarih=datetime.utcnow()
                )
                db.session.add(progress)
            else:
                progress.harcanan_sure = (progress.harcanan_sure or 0) + int(harcanan_sure)
                progress.tarih = datetime.utcnow()
            db.session.commit()
            return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Süre kaydı hatası: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Sistem hatası'}), 500

    
    
@app.route('/update_content_view/<int:icerik_id>', methods=['POST'])
@login_required
def update_content_view(icerik_id):
    try:
        data = request.get_json()
        harcanan_sure = data.get('harcanan_sure', 0)
        baslama_zamani = datetime.fromisoformat(data.get('baslama_zamani').replace('Z', '+00:00'))
        bitirme_zamani = datetime.fromisoformat(data.get('bitirme_zamani').replace('Z', '+00:00'))

        # İlerleme kaydını bul veya oluştur
        progress = UserProgress.query.filter_by(
            user_id=current_user.id,
            icerik_id=icerik_id
        ).order_by(UserProgress.id.desc()).first()

        if not progress:
            progress = UserProgress(
                user_id=current_user.id,
                icerik_id=icerik_id,
                baslama_zamani=baslama_zamani,
                bitirme_zamani=bitirme_zamani,
                harcanan_sure=harcanan_sure
            )
            db.session.add(progress)
        else:
            # Toplam süreyi biriktir
            progress.harcanan_sure = (progress.harcanan_sure or 0) + harcanan_sure
            progress.baslama_zamani = baslama_zamani
            progress.bitirme_zamani = bitirme_zamani

        db.session.commit()

        return jsonify({'success': True})

    except Exception as e:
        app.logger.error(f"İçerik görüntüleme hatası: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})
    
    
@app.route('/mark_content_viewed/<int:icerik_id>', methods=['POST'])
@login_required
def mark_content_viewed(icerik_id):
        # Kullanıcı kontrolünü güçlendir
    if not current_user.is_authenticated:
        return jsonify({'error': 'Oturum sonlanmış', 'redirect': url_for('login')}), 401
        

    try:
        # Yeni görüntüleme kaydı oluştur
        progress = UserProgress(
            user_id=current_user.id,
            icerik_id=icerik_id,
            activity_type='content_viewed',
            tarih=datetime.utcnow()
        )
        db.session.add(progress)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    
    
    
    
@app.route('/mark_content_read/<int:icerik_id>', methods=['POST'])
@login_required
def mark_content_read(icerik_id):
    try:
        user_id = current_user.id
        # Okundu bilgisini doğrudan UserProgress tablosuna yaz
        progress = UserProgress.query.filter_by(user_id=user_id, icerik_id=icerik_id).order_by(UserProgress.id.desc()).first()
        if not progress:
            progress = UserProgress(user_id=user_id, icerik_id=icerik_id, okundu=True, activity_type=ActivityType.CONTENT_READING)
            db.session.add(progress)
        else:
            progress.okundu = True
            progress.activity_type = ActivityType.CONTENT_READING
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Okundu kaydı hatası: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    
    
    
    
    



@app.route('/<sinif_slug>/<ders_slug>/<unite_slug>/<icerik_slug>/soru/<int:soru_id>')
def soru(sinif_slug, ders_slug, unite_slug, icerik_slug, soru_id):
    sinif = Sinif.query.filter_by(slug=sinif_slug).first_or_404()
    ders = Ders.query.filter_by(slug=ders_slug, sinif_id=sinif.id).first_or_404()
    unite = Unite.query.filter_by(slug=unite_slug, ders_id=ders.id).first_or_404()
    icerik = Icerik.query.filter_by(slug=icerik_slug, unite_id=unite.id).first_or_404()
    
    soru = Soru.query.get_or_404(soru_id)
    if soru.icerik_id != icerik.id:
        app.logger.warning(f"Soru {soru_id} içerik {icerik.id} ile uyumsuz")
        flash('Soru ile içerik uyumsuzluğu tespit edildi.', 'warning')
        return redirect(url_for('icerik', sinif_slug=sinif_slug, ders_slug=ders_slug, unite_slug=unite_slug, icerik_slug=icerik_slug))
    
    siniflar = Sinif.query.all()
    uniteler = Unite.query.filter_by(ders_id=ders.id).all()
    return render_template('soru.html', siniflar=siniflar, soru=soru, ders=ders, uniteler=uniteler, sinif=sinif)




    


@app.route('/soru/<sinif_slug>/<ders_slug>', methods=['GET', 'POST'])
def soru_filtre(sinif_slug, ders_slug):
    sinif = Sinif.query.filter_by(slug=sinif_slug).first_or_404()
    ders = Ders.query.filter_by(slug=ders_slug, sinif_id=sinif.id).first_or_404()
    siniflar = Sinif.query.all()
    uniteler = Unite.query.filter_by(ders_id=ders.id).all()
    unite_id = request.args.get('unite_id', type=int)
    icerik_id = request.args.get('icerik_id', type=int)
    adet = request.args.get('adet', type=int)

    icerikler = []
    if unite_id:
        icerikler = Icerik.query.filter_by(unite_id=unite_id).all()

    # Soru filtreleme
    query = Soru.query.join(Unite, Soru.unite_id == Unite.id).filter(Unite.ders_id == ders.id)
    if unite_id:
        query = query.filter(Soru.unite_id == unite_id)
    if icerik_id:
        query = query.filter(Soru.icerik_id == icerik_id)
    sorular = query.all()
    if adet:
        sorular = query.limit(adet).all()
    else:
        sorular = query.all()

    return render_template(
        'soru.html',
        sinif=sinif,
        ders=ders,
        uniteler=uniteler,
        icerikler=icerikler,
        unite_id=unite_id,
        icerik_id=icerik_id,
        sorular=sorular,
        siniflar=siniflar,
        adet=adet
    )
    
    
    
@app.route('/coz/<sinif_slug>/<ders_slug>', methods=['GET', 'POST'])
def soru_coz(sinif_slug, ders_slug):
    try:
        sinif = Sinif.query.filter_by(slug=sinif_slug).first_or_404()
        ders = Ders.query.filter_by(slug=ders_slug, sinif_id=sinif.id).first_or_404()
        siniflar = Sinif.query.all()
        
        unite_id = request.args.get('unite_id', type=int)
        icerik_id = request.args.get('icerik_id', type=int)
        adet = request.args.get('adet', type=int)
        yanlis_tekrar = request.args.get('yanlis_tekrar', type=int)
        if not adet or adet < 1:
            adet = 20
        elif adet > 50:
            adet = 50

        query = Soru.query.join(Icerik).join(Unite).filter(Unite.ders_id == ders.id)
        if unite_id:
            query = query.filter(Unite.id == unite_id)
        if icerik_id:
            query = query.filter(Icerik.id == icerik_id)
        if yanlis_tekrar:
            # Sadece yanlış yapılan sorular
            yanlis_soru_ids = db.session.query(UserProgress.soru_id).filter(
                UserProgress.user_id == current_user.id,
                UserProgress.icerik_id == icerik_id,
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING,
                UserProgress.yanlis_sayisi > 0
            ).all()
            yanlis_soru_ids = [row[0] for row in yanlis_soru_ids if row[0]]
            if yanlis_soru_ids:
                query = query.filter(Soru.id.in_(yanlis_soru_ids))
            else:
                flash("Tebrikler! Yanlış sorunuz kalmadı.", "success")
                return redirect(url_for('ilerleme_patikasi'))
        sorular = query.order_by(func.random()).limit(adet).all()

        sinif_adi = str(sinif.sinif).upper()
        if sinif_adi in ['5', '6', '7', '8', 'LGS']:
            secenekler = ['A', 'B', 'C', 'D']
        elif sinif_adi in ['9', '10', '11', '12', 'AYT', 'TYT']:
            secenekler = ['A', 'B', 'C', 'D', 'E']
        else:
            secenekler = ['A', 'B', 'C', 'D']

        if not sorular:
            flash('Seçilen kriterlere uygun soru bulunamadı.', 'warning')
            return redirect(url_for('soru_filtre', sinif_slug=sinif_slug, ders_slug=ders_slug))

        soru_ids = [s.id for s in sorular]
        session['aktif_sorular'] = soru_ids
        session['soru_index'] = 0
        session['dogru_sayisi'] = 0
        session['yanlis_sayisi'] = 0
        session['cevaplar'] = {}

        if request.method == 'POST':
            cevaplar = {}
            for i in range(1, len(sorular) + 1):
                cevap = request.form.get(f'cevaplar[{i}]', 'bos')
                cevaplar[i] = cevap

            harcanan_sure = request.form.get('harcanan_sure', 0, type=int)
            soru_sureleri = {}
            soru_ziyaretleri = {}
            for i in range(1, len(sorular) + 1):
                soru_sureleri[i] = request.form.get(f'soru_sureleri[{i}]', 0, type=int)
                soru_ziyaretleri[i] = request.form.get(f'soru_ziyaretleri[{i}]', 1, type=int)

            sonuclar = []
            dogru_sayisi = 0
            yanlis_sayisi = 0
            bos_sayisi = 0
            toplam_puan = 0

            for idx, soru in enumerate(sorular):
                soru_no = idx + 1
                verilen_cevap = cevaplar.get(soru_no, 'bos')
                if verilen_cevap == 'bos':
                    bos_sayisi += 1
                    puan = 0
                    sonuc = 'Boş'
                elif verilen_cevap.upper() == soru.cevap.upper():
                    dogru_sayisi += 1
                    puan = 10
                    sonuc = 'Doğru'
                else:
                    yanlis_sayisi += 1
                    puan = 0
                    sonuc = 'Yanlış'
                toplam_puan += puan
                sonuc_obj = {
                    'soru_no': soru_no,
                    'soru_id': soru.id,
                    'verilen_cevap': verilen_cevap,
                    'dogru_cevap': soru.cevap,
                    'sonuc': sonuc,
                    'puan': puan,
                    'sure': soru_sureleri.get(soru_no, 0),
                    'ziyaret_sayisi': soru_ziyaretleri.get(soru_no, 1),
                    'video_path': soru.video_path,
                    'cozum_resim': soru.cozum_resim
                }
                sonuclar.append(sonuc_obj)

            # TEKİLLEŞTİRME: Her kullanıcı + soru + activity_type için tek satır
            if current_user.is_authenticated:
                for idx, soru in enumerate(sorular):
                    soru_no = idx + 1
                    sonuc = sonuclar[idx]
                    today = datetime.utcnow().date()
                    progress = UserProgress.query.filter_by(
                        user_id=current_user.id,
                        soru_id=soru.id,
                        activity_type=ActivityType.QUESTION_SOLVING
                    ).filter(func.date(UserProgress.tarih) == today).first()
                    if not progress:
                        progress = UserProgress(
                            user_id=current_user.id,
                            soru_id=soru.id,
                            icerik_id=soru.icerik_id,
                            activity_type=ActivityType.QUESTION_SOLVING,
                            harcanan_sure=soru_sureleri.get(soru_no, 0),
                            dogru_sayisi=1 if sonuc['sonuc'] == 'Doğru' else 0,
                            yanlis_sayisi=1 if sonuc['sonuc'] == 'Yanlış' else 0,
                            bos_sayisi=1 if sonuc['sonuc'] == 'Boş' else 0,
                            puan=sonuc['puan'],
                            tarih=datetime.utcnow()
                        )
                        db.session.add(progress)
                    else:
                        # Yanlış tekrarında doğru çözülürse yanlış sayısını sıfırla
                        if sonuc['sonuc'] == 'Doğru':
                            progress.dogru_sayisi = 1
                            progress.yanlis_sayisi = 0
                            progress.bos_sayisi = 0
                        elif sonuc['sonuc'] == 'Yanlış':
                            progress.dogru_sayisi = 0
                            progress.yanlis_sayisi = 1
                            progress.bos_sayisi = 0
                        elif sonuc['sonuc'] == 'Boş':
                            progress.dogru_sayisi = 0
                            progress.yanlis_sayisi = 0
                            progress.bos_sayisi = 1
                        progress.harcanan_sure = (progress.harcanan_sure or 0) + soru_sureleri.get(soru_no, 0)
                        progress.puan = (progress.puan or 0) + sonuc['puan']
                        progress.tarih = datetime.utcnow()

                # Test özet kaydı (isteğe bağlı)
                test_ozet = UserProgress(
                    user_id=current_user.id,
                    icerik_id=icerik_id if icerik_id else None,
                    soru_id=None,
                    activity_type='test_summary',
                    harcanan_sure=harcanan_sure,
                    dogru_sayisi=dogru_sayisi,
                    yanlis_sayisi=yanlis_sayisi,
                    bos_sayisi=bos_sayisi,
                    puan=toplam_puan,
                    tarih=datetime.utcnow()
                )
                db.session.add(test_ozet)
                db.session.commit()
                app.logger.info(f"Test tamamlandı - User: {current_user.id}, Soru sayısı: {len(sorular)}, Doğru: {dogru_sayisi}, Süre: {harcanan_sure}s")

            return render_template(
                'soru_sonuc.html',
                toplam_soru=len(sorular),
                dogru_sayisi=dogru_sayisi,
                yanlis_sayisi=yanlis_sayisi,
                bos_sayisi=bos_sayisi,
                toplam_puan=toplam_puan,
                toplam_sure=harcanan_sure,
                sonuclar=sonuclar,
                sinif=sinif,
                ders=ders
            )

        # GET isteği - Soru çözüm sayfası
        return render_template(
            'soru_cozum.html',
            sorular=sorular,
            sinif=sinif,
            ders=ders,
            siniflar=siniflar,
            secenekler=secenekler,
            adet=adet,
            unite_id=unite_id,
            icerik_id=icerik_id
        )

    except Exception as e:
        app.logger.error(f"Soru çözüm hatası: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Bir hata oluştu. Lütfen tekrar deneyin.', 'error')
        return redirect(url_for('soru_filtre', sinif_slug=sinif_slug, ders_slug=ders_slug))
    
    
@app.route('/tekil-soru/<sinif_slug>/<ders_slug>/<int:soru_id>', methods=['GET', 'POST'])
def tekil_soru(sinif_slug, ders_slug, soru_id):
    sinif = Sinif.query.filter_by(slug=sinif_slug).first_or_404()
    ders = Ders.query.filter_by(slug=ders_slug, sinif_id=sinif.id).first_or_404()
    try:
        soru = Soru.query.get_or_404(soru_id)
        siniflar = Sinif.query.order_by(Sinif.id).all()
        
        # Soru ile ders/sınıf uyumluluğunu kontrol et
        if soru.icerik.unite.ders_id != ders.id or soru.icerik.unite.ders.sinif_id != sinif.id:
            flash('Soru ile seçilen ders/sınıf uyumsuz.', 'error')
            return redirect(url_for('home'))
        
        if request.method == 'POST':
            cevap = request.form.get('cevap', '').strip()
            harcanan_sure = int(request.form.get('harcanan_sure', 0))
            
            # ✅ SABİT PUANLAMA SİSTEMİ: Boş cevap kontrolü
            if not cevap:
                sonuc = 'Boş'
                puan = 0
                dogru_sayisi = 0
                yanlis_sayisi = 0
                bos_sayisi = 1
                sonuc_class = 'secondary'
                sonuc_mesaj = 'Cevap verilmedi'
            else:
                # Normal cevap kontrolü
                if cevap.upper() == soru.cevap.upper():
                    sonuc = 'Doğru'
                    puan = 10  # ✅ Sabit 10 puan
                    dogru_sayisi = 1
                    yanlis_sayisi = 0
                    bos_sayisi = 0
                    sonuc_class = 'success'
                    sonuc_mesaj = 'Tebrikler! Doğru cevap.'
                else:
                    sonuc = 'Yanlış'
                    puan = 0
                    dogru_sayisi = 0
                    yanlis_sayisi = 1
                    bos_sayisi = 0
                    sonuc_class = 'danger'
                    sonuc_mesaj = f'Yanlış! Doğru cevap: {soru.cevap}'
            
            # UserProgress kaydı
            if current_user.is_authenticated:
                today = datetime.utcnow().date()
                progress = UserProgress.query.filter_by(
                    user_id=current_user.id,
                    soru_id=soru.id,
                    activity_type=ActivityType.QUESTION_SOLVING
                ).filter(func.date(UserProgress.tarih) == today).first()

                if not progress:
                    progress = UserProgress(
                        user_id=current_user.id,
                        icerik_id=soru.icerik_id,
                        soru_id=soru.id,
                        activity_type=ActivityType.QUESTION_SOLVING,
                        harcanan_sure=harcanan_sure,
                        dogru_sayisi=dogru_sayisi,
                        yanlis_sayisi=yanlis_sayisi,
                        bos_sayisi=bos_sayisi,
                        puan=puan,
                        tarih=datetime.utcnow()
                    )
                    db.session.add(progress)
                else:
                    progress.harcanan_sure = (progress.harcanan_sure or 0) + harcanan_sure
                    progress.dogru_sayisi = dogru_sayisi
                    progress.yanlis_sayisi = yanlis_sayisi
                    progress.bos_sayisi = bos_sayisi
                    progress.puan = (progress.puan or 0) + puan
                    progress.tarih = datetime.utcnow()
                db.session.commit()
            
            return render_template('tekil_soru_sonuc.html',
                                sinif=sinif,
                                ders=ders,
                                soru=soru,
                                verilen_cevap=cevap,
                                dogru_cevap=soru.cevap,
                                sonuc=sonuc,
                                sonuc_class=sonuc_class,
                                sonuc_mesaj=sonuc_mesaj,
                                puan=puan,
                                harcanan_sure=harcanan_sure,
                                siniflar=siniflar)
        
        # GET isteği - Soruyu göster
        return render_template('tekil_soru.html',
                            sinif=sinif,
                            ders=ders,
                            soru=soru,
                            siniflar=siniflar)
                            
    except Exception as e:
        app.logger.error(f"Tekil soru hatası: {str(e)}")
        flash('Bir hata oluştu. Lütfen tekrar deneyin.', 'error')
        return redirect(url_for('home'))
    
    
    
google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ],
    redirect_url="/google_login_callback"
)
app.register_blueprint(google_bp, url_prefix="/login")


@app.route("/google_login_callback")
def google_login_callback():
    if not google.authorized:
        return redirect(url_for("google.login"))
    
    # Google'dan kullanıcı bilgilerini al
    resp = google.get("/oauth2/v2/userinfo")
    user_info = resp.json()
    email = user_info.get("email")
    
    if not email:
        flash("Google'dan e-posta bilgisi alınamadı.", "danger")
        return redirect(url_for("register"))
    
    # Kullanıcı daha önce kayıt olmuş mu?
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Kullanıcı zaten kayıtlı, giriş yap
        login_user(user)
        flash(f"Hoş geldiniz {user.first_name}! Google hesabınızla giriş yaptınız.", "success")
    else:
        # Yeni kullanıcı oluştur
        first_name = user_info.get("given_name", "")
        last_name = user_info.get("family_name", "")
        
        # Benzersiz kullanıcı adı oluştur
        base_username = email.split("@")[0]
        username = base_username
        counter = 1
        
        # Username benzersiz olmalı
        while User.query.filter_by(username=username).first():
            username = f"{base_username}{counter}"
            counter += 1
        
        # Rastgele güvenli bir şifre oluştur
        random_password = secrets.token_urlsafe(16)
        hashed_password = bcrypt.generate_password_hash(random_password).decode('utf-8')
        
        # Kullanıcıyı oluştur
        user = User(
            username=username,
            email=email,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            role="user",
            is_active=True,
            profile_completed=False,
            date_created=datetime.utcnow()
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Google hesabınızla başarıyla kayıt oldunuz! Lütfen profilinizi tamamlayın.", "success")
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Google ile kayıt hatası: {str(e)}")
            flash("Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.", "danger")
            return redirect(url_for("register"))
    
    # Profil tamamlanmamışsa profil tamamlama sayfasına yönlendir
    if not user.profile_completed:
        return redirect(url_for("complete_profile"))
    
    return redirect(url_for("home"))
    
    
    
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per minute", key_func=lambda: get_remote_address())
def register():
    """Kullanıcı Kaydı - Email Doğrulama ile Güvenli + IP Loglama"""
    try:
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        form = RegistrationForm()
        
        if request.method == 'POST':
            if form.validate_on_submit():
                try:
                    # ✅ Input sanitization
                    username = SecurityService.sanitize_input(form.username.data, 50)
                    email = SecurityService.sanitize_input(form.email.data, 100)
                    password = form.password.data.strip()
                    
                    # ✅ Güvenlik kontrolleri
                    if not username or not email or not password:
                        flash('Tüm alanlar doldurulmalıdır.', 'danger')
                        return redirect(url_for('register'))
                    
                    # ✅ Username uzunluk ve karakter kontrolü
                    if len(username) < 3 or len(username) > 50:
                        flash('Kullanıcı adı 3-50 karakter arasında olmalıdır.', 'danger')
                        return redirect(url_for('register'))
                    
                    # ✅ Email format kontrolü
                    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                    if not re.match(email_pattern, email):
                        flash('Geçersiz email formatı.', 'danger')
                        return redirect(url_for('register'))
                    
                    # ✅ Benzersizlik kontrolleri
                    existing_username = User.query.filter_by(username=username).first()
                    if existing_username:
                        flash('Bu kullanıcı adı zaten kullanılıyor.', 'danger')
                        return redirect(url_for('register'))
                    
                    existing_email = User.query.filter_by(email=email).first()
                    if existing_email:
                        flash('Bu email adresi zaten kullanılıyor.', 'danger')
                        return redirect(url_for('register'))
                    
                    # ✅ YENİ: IP ve User Agent bilgilerini al
                    registration_ip = get_client_ip()
                    
                    # ✅ YENİ: Veli onayı kontrolü (form'da varsa)
                    parental_consent = getattr(form, 'parental_consent', None)
                    parental_consent_value = parental_consent.data if parental_consent else False
                    
                    # ✅ Güvenli şifre hash'leme
                    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                    
                    # ✅ Güvenli kullanıcı oluşturma - IP bilgileri ile
                    user = User(
                        username=username, 
                        email=email, 
                        password=hashed_password,
                        role='user',
                        date_created=datetime.utcnow(),
                        profile_completed=False,
                        is_active=True,
                        email_verified=False,
                        # ✅ YENİ: IP ve veli onayı alanları
                        registration_ip=registration_ip,
                        parental_consent=parental_consent_value,
                        parental_consent_date=datetime.utcnow() if parental_consent_value else None,
                        parental_consent_ip=registration_ip if parental_consent_value else None
                    )
                    
                    # ✅ Güvenli veritabanı işlemi
                    db.session.add(user)
                    db.session.flush()  # ID almak için flush
                    
                    # ✅ YENİ: Kayıt log'u oluştur (5651 Uyumu)
                    log_user_action(
                        user_id=user.id,
                        action_type=LogActionType.REGISTER,
                        success=True,
                        details=f"Email: {email[:20]}..."
                    )
                    
                    db.session.commit()
                    
                    # ✅ Doğrulama emaili gönder
                    email_sent = send_verification_email(user)
                    
                    # ✅ Güvenli log yazma
                    app.logger.info(f"New user registered - ID: {user.id}, IP: {registration_ip}, Email sent: {email_sent}")
                    
                    if email_sent:
                        flash('🎉 Hesabınız oluşturuldu! Lütfen email adresinize gönderilen doğrulama linkine tıklayın.', 'success')
                    else:
                        flash('🎉 Hesabınız oluşturuldu! Doğrulama emaili gönderilemedi, giriş yaptıktan sonra tekrar isteyebilirsiniz.', 'warning')
                    
                    return redirect(url_for('login'))
                    
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Registration error: {str(e)}")
                    app.logger.error(traceback.format_exc())
                    flash('Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
                    return redirect(url_for('register'))
            else:
                for field, errors in form.errors.items():
                    for error in errors:
                        flash(f'{field}: {error}', 'danger')
        
        return render_template('register.html', form=form, title='Kayıt Ol')
        
    except Exception as e:
        app.logger.error(f"Register page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('home'))
    


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", key_func=lambda: get_remote_address())
def login():
    """Kullanıcı Girişi - Güvenli + Hesap Kilitleme + IP Loglama"""
    try:
        if current_user.is_authenticated:
            return redirect(url_for('home'))

        form = LoginForm()
        
        if form.validate_on_submit():
            email = SecurityService.sanitize_input(form.email.data.lower().strip(), 100)
            password = form.password.data.strip()
            remember_me = bool(form.remember_me.data)
            
            if not email or not password:
                flash('E-mail ve şifre boş olamaz.', 'danger')
                return redirect(url_for('login'))
            
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                flash('Geçersiz e-mail formatı.', 'danger')
                return redirect(url_for('login'))
            
            try:
                user = User.query.filter_by(email=email, role='user').first()
                
                # ✅ YENİ: IP bilgisini al
                client_ip = get_client_ip()
                
                if user:
                    # Hesap kilitleme kontrolü
                    if user.is_account_locked():
                        remaining = user.get_lock_remaining_time()
                        
                        # ✅ YENİ: Kilitli hesaba giriş denemesi logla
                        log_user_action(
                            user_id=user.id,
                            action_type=LogActionType.FAILED_LOGIN,
                            success=False,
                            details="Hesap kilitli - giriş denemesi"
                        )
                        db.session.commit()
                        
                        flash(f'Hesabınız çok fazla başarısız giriş denemesi nedeniyle kilitlendi. {remaining} dakika sonra tekrar deneyin.', 'danger')
                        app.logger.warning(f"Locked account login attempt - Email: {email}, IP: {client_ip}")
                        return render_template('login.html', form=form)
                    
                    # Hesap aktif kontrolü
                    if hasattr(user, 'is_active') and not user.is_active:
                        # ✅ YENİ: Pasif hesaba giriş denemesi logla
                        log_user_action(
                            user_id=user.id,
                            action_type=LogActionType.FAILED_LOGIN,
                            success=False,
                            details="Hesap pasif"
                        )
                        db.session.commit()
                        
                        flash('Hesabınız devre dışı bırakılmış. Lütfen yönetici ile iletişime geçin.', 'warning')
                        app.logger.warning(f"Inactive user login attempt - Email: {email}, IP: {client_ip}")
                        return redirect(url_for('login'))
                    
                    # Şifre kontrolü
                    if bcrypt.check_password_hash(user.password, password):
                        # ✅ Başarılı giriş
                        user.reset_failed_login()
                        user.last_login = datetime.utcnow()
                        user.last_login_ip = client_ip  # ✅ YENİ: Son giriş IP'sini kaydet
                        
                        # ✅ YENİ: Başarılı giriş logla
                        log_user_action(
                            user_id=user.id,
                            action_type=LogActionType.LOGIN,
                            success=True,
                            details=None
                        )
                        
                        db.session.commit()
                        
                        login_user(user, remember=remember_me)
                        
                        app.logger.info(f"User login successful - ID: {user.id}, IP: {client_ip}")
                        
                        if not user.first_name or not user.school_id:
                            flash('Profilinizi tamamlayarak sistemi kullanmaya başlayın!', 'info')
                            return redirect(url_for('complete_profile'))
                        
                        flash('Giriş başarılı! Hoş geldiniz.', 'success')
                        
                        next_page = request.args.get('next')
                        if next_page:
                            from urllib.parse import urlparse
                            parsed_url = urlparse(next_page)
                            if parsed_url.netloc == '' or parsed_url.netloc == request.host:
                                if not any(char in next_page for char in ['<', '>', '"', "'", '&']):
                                    return redirect(next_page)
                        
                        return redirect(url_for('home'))
                    else:
                        # ✅ Başarısız giriş - şifre yanlış
                        user.increment_failed_login()
                        
                        # ✅ YENİ: Başarısız giriş logla
                        log_user_action(
                            user_id=user.id,
                            action_type=LogActionType.FAILED_LOGIN,
                            success=False,
                            details=f"Yanlış şifre - Deneme: {user.failed_login_attempts}"
                        )
                        
                        db.session.commit()
                        
                        remaining_attempts = 5 - user.failed_login_attempts
                        if remaining_attempts > 0:
                            flash(f'Giriş başarısız. {remaining_attempts} deneme hakkınız kaldı.', 'danger')
                        else:
                            flash('Hesabınız 15 dakika süreyle kilitlendi.', 'danger')
                        
                        app.logger.warning(f"Failed login attempt - Email: {email}, Attempts: {user.failed_login_attempts}, IP: {client_ip}")
                else:
                    # Kullanıcı bulunamadı
                    app.logger.warning(f"Login attempt with non-existent email - Email: {email}, IP: {client_ip}")
                    flash('Giriş başarısız. Lütfen e-mail ve şifrenizi kontrol edin.', 'danger')
                    
            except Exception as e:
                app.logger.error(f"Login database error: {str(e)}")
                flash('Giriş sırasında bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
                return redirect(url_for('login'))
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')

        return render_template('login.html', title='Giriş Yap', form=form)
        
    except Exception as e:
        app.logger.error(f"Login page error: {str(e)}")
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('home'))




    
@app.route('/dashboard/change-password', methods=['GET', 'POST'])
@login_required
@limiter.limit("3 per minute", key_func=lambda: get_remote_address())
def change_password():
    """Kullanıcı - Şifre Değiştirme + IP Loglama"""
    try:
        form = ChangePasswordForm()
        
        if form.validate_on_submit():
            if not bcrypt.check_password_hash(current_user.password, form.current_password.data):
                flash('Mevcut şifreniz yanlış.', 'danger')
                app.logger.warning(f"Wrong current password - User: {current_user.id}, IP: {get_client_ip()}")
                return render_template('change_password.html', form=form)
            
            if bcrypt.check_password_hash(current_user.password, form.new_password.data):
                flash('Yeni şifreniz mevcut şifrenizle aynı olamaz.', 'warning')
                return render_template('change_password.html', form=form)
            
            try:
                current_user.password = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
                current_user.password_changed_at = datetime.utcnow()
                
                # ✅ YENİ: Şifre değişikliği logla
                log_user_action(
                    user_id=current_user.id,
                    action_type=LogActionType.PASSWORD_CHANGE,
                    success=True,
                    details=None
                )
                
                db.session.commit()
                
                send_password_changed_notification(current_user)
                
                app.logger.info(f"Password changed - User: {current_user.id}, IP: {get_client_ip()}")
                
                flash('Şifreniz başarıyla değiştirildi!', 'success')
                return redirect(url_for('profile'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Password change error: {str(e)}")
                flash('Şifre değiştirilirken bir hata oluştu.', 'danger')
                return render_template('change_password.html', form=form)
        
        return render_template('change_password.html', form=form, title='Şifre Değiştir')
        
    except Exception as e:
        app.logger.error(f"Change password page error: {str(e)}")
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('profile'))
    
    
def generate_password_reset_token(email):
    """E-posta için güvenli token oluştur"""
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps(email, salt='password-reset-salt')

def verify_password_reset_token(token, expiration=3600):
    """Token'ı doğrula ve e-postayı çıkar"""
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email

# Email doğrulama token oluştur
def generate_email_verification_token(email):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps(email, salt='email-verification-salt')

# Email doğrulama token kontrol
def verify_email_verification_token(token, expiration=86400):  # 24 saat
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt='email-verification-salt', max_age=expiration)
        return email
    except (SignatureExpired, BadSignature):
        return None

# Email doğrulama maili gönder
def send_verification_email(user):
    token = generate_email_verification_token(user.email)
    user.email_verification_token = token
    user.email_verification_sent_at = datetime.utcnow()
    db.session.commit()
    
    verification_url = url_for('verify_email', token=token, _external=True)
    
    subject = "Email Adresinizi Doğrulayın - SF Eğitim"
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
            <h1 style="color: white; margin: 0;">SF Eğitim</h1>
        </div>
        <div style="padding: 30px; background: #f9f9f9;">
            <h2 style="color: #333;">Merhaba {user.first_name or 'Değerli Kullanıcı'},</h2>
            <p style="color: #666; line-height: 1.6;">
                SF Eğitim platformuna hoş geldiniz! Hesabınızı aktifleştirmek için 
                aşağıdaki butona tıklayarak email adresinizi doğrulayın.
            </p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="{verification_url}" 
                   style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                          color: white; 
                          padding: 15px 40px; 
                          text-decoration: none; 
                          border-radius: 25px;
                          font-weight: bold;
                          display: inline-block;">
                    Email Adresimi Doğrula
                </a>
            </div>
            <p style="color: #999; font-size: 12px;">
                Bu link 24 saat geçerlidir. Eğer bu hesabı siz oluşturmadıysanız, 
                bu emaili görmezden gelebilirsiniz.
            </p>
            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
            <p style="color: #999; font-size: 12px;">
                Link çalışmıyorsa, aşağıdaki adresi tarayıcınıza kopyalayın:<br>
                <a href="{verification_url}" style="color: #667eea;">{verification_url}</a>
            </p>
        </div>
    </body>
    </html>
    """
    
    try:
        msg = MailMessage(
            subject=subject,
            recipients=[user.email],
            html=html_body,
            sender=app.config.get('MAIL_DEFAULT_SENDER', 'noreply@sf-egitim.com')
        )
        mail.send(msg)
        app.logger.info(f"Doğrulama emaili gönderildi: {user.email}")
        return True
    except Exception as e:
        app.logger.error(f"Email gönderme hatası: {str(e)}")
        return False
    
    
def send_password_changed_notification(user):
    """Şifre değişiklik bildirimi gönder"""
    subject = "Şifreniz Değiştirildi - SF Eğitim"
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;">
            <h1 style="color: white; margin: 0;">SF Eğitim</h1>
        </div>
        <div style="padding: 30px; background: #f9f9f9;">
            <h2 style="color: #333;">Şifreniz Değiştirildi</h2>
            <p style="color: #666; line-height: 1.6;">
                Merhaba {user.first_name or 'Değerli Kullanıcı'},<br><br>
                Hesabınızın şifresi başarıyla değiştirildi.<br><br>
                <strong>Tarih:</strong> {datetime.utcnow().strftime('%d.%m.%Y %H:%M')}<br>
                <strong>IP Adresi:</strong> {request.remote_addr if request else 'Bilinmiyor'}
            </p>
            <p style="color: #dc3545; font-weight: bold;">
                Eğer bu işlemi siz yapmadıysanız, lütfen hemen bizimle iletişime geçin!
            </p>
        </div>
    </body>
    </html>
    """
    
    try:
        msg = MailMessage(
            subject=subject,
            recipients=[user.email],
            html=html_body,
            sender=app.config.get('MAIL_DEFAULT_SENDER', 'noreply@sf-egitim.com')
        )
        mail.send(msg)
        app.logger.info(f"Şifre değişiklik bildirimi gönderildi: {user.email}")
    except Exception as e:
        app.logger.error(f"Şifre değişiklik bildirimi gönderilemedi: {str(e)}")

# Email doğrulama route
@app.route('/verify-email/<token>')
def verify_email(token):
    email = verify_email_verification_token(token)
    
    if email is None:
        flash('Doğrulama linki geçersiz veya süresi dolmuş.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    
    if user is None:
        flash('Kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('login'))
    
    if user.email_verified:
        flash('Email adresiniz zaten doğrulanmış.', 'info')
        return redirect(url_for('login'))
    
    user.email_verified = True
    user.email_verification_token = None
    
    # ✅ YENİ: Email doğrulama logla
    log_user_action(
        user_id=user.id,
        action_type=LogActionType.EMAIL_VERIFY,
        success=True,
        details=f"IP: {get_client_ip()}"
    )
    
    db.session.commit()
    
    flash('Email adresiniz başarıyla doğrulandı! Şimdi giriş yapabilirsiniz.', 'success')
    app.logger.info(f"Email doğrulandı: {user.email}, IP: {get_client_ip()}")
    return redirect(url_for('login'))

# Doğrulama emaili yeniden gönder
@app.route('/resend-verification')
@login_required
def resend_verification():
    if current_user.email_verified:
        flash('Email adresiniz zaten doğrulanmış.', 'info')
        return redirect(url_for('dashboard'))
    
    # Son gönderimden 2 dakika geçmeli
    if current_user.email_verification_sent_at:
        time_diff = datetime.utcnow() - current_user.email_verification_sent_at
        if time_diff.total_seconds() < 120:
            remaining = 120 - int(time_diff.total_seconds())
            flash(f'Lütfen {remaining} saniye bekleyin.', 'warning')
            return redirect(url_for('dashboard'))
    
    if send_verification_email(current_user):
        flash('Doğrulama emaili tekrar gönderildi.', 'success')
    else:
        flash('Email gönderilemedi, lütfen daha sonra tekrar deneyin.', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    form = PasswordResetRequestForm()
    
    if request.method == 'POST':
        app.logger.debug(f"POST request to reset_password - data: {request.form}")
        
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                try:
                    token = generate_password_reset_token(user.email)
                    
                    user.password_reset_token = token
                    user.password_reset_token_created_at = datetime.utcnow()
                    
                    # ✅ YENİ: Şifre sıfırlama talebi logla
                    log_user_action(
                        user_id=user.id,
                        action_type=LogActionType.PASSWORD_RESET_REQUEST,
                        success=True,
                        details=f"IP: {get_client_ip()}"
                    )
                    
                    db.session.commit()
                    
                    reset_url = url_for('reset_password_token', token=token, _external=True)
                    
                    msg = MailMessage(
                        subject="Şifre Sıfırlama Talebi",
                        sender="sdsendermail@gmail.com",
                        recipients=[user.email],
                        body=f"Şifrenizi sıfırlamak için aşağıdaki linke tıklayın:\n{reset_url}\n\nBu bağlantı 1 saat geçerlidir."
                    )
                    
                    mail.send(msg)
                    app.logger.info(f"Şifre sıfırlama maili gönderildi: {user.email}, IP: {get_client_ip()}")
                    flash('Şifre sıfırlama linki e-posta adresinize gönderildi.', 'info')
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Mail gönderme hatası: {str(e)}")
                    flash('Mail gönderimi başarısız. Lütfen daha sonra tekrar deneyin.', 'danger')
            else:
                flash('Eğer bu email adresi kayıtlıysa, şifre sıfırlama linki gönderildi.', 'info')
            return redirect(url_for('login'))
        else:
            app.logger.error(f"Form doğrulama hatası: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", 'danger')
    
    return render_template('reset_password_request.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    """Şifre Sıfırlama - Token ile Yeni Şifre Belirleme + IP Loglama"""
    try:
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        try:
            email = verify_password_reset_token(token)
            app.logger.info(f"Token verified for email: {email}")
        except Exception as e:
            app.logger.error(f"Token verification error: {str(e)}")
            email = None
        
        if email is None:
            flash('Geçersiz veya süresi dolmuş şifre sıfırlama linki.', 'danger')
            return redirect(url_for('reset_password_request'))
        
        user = User.query.filter_by(email=email).first()
        
        if user is None:
            flash('Kullanıcı bulunamadı.', 'danger')
            return redirect(url_for('reset_password_request'))
        
        if user.password_reset_token is None or user.password_reset_token != token:
            flash('Bu şifre sıfırlama linki zaten kullanılmış veya geçersiz.', 'danger')
            return redirect(url_for('reset_password_request'))
        
        form = PasswordResetForm()
        
        if form.validate_on_submit():
            try:
                hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user.password = hashed_password
                
                user.password_reset_token = None
                user.password_reset_token_created_at = None
                user.password_changed_at = datetime.utcnow()
                
                # ✅ YENİ: Şifre sıfırlama tamamlandı logla
                log_user_action(
                    user_id=user.id,
                    action_type=LogActionType.PASSWORD_RESET_COMPLETE,
                    success=True,
                    details=f"IP: {get_client_ip()}"
                )
                
                db.session.commit()
                
                app.logger.info(f"Password reset successful for user: {user.id}, IP: {get_client_ip()}")
                
                try:
                    send_password_changed_notification(user)
                except Exception as e:
                    app.logger.warning(f"Password change notification failed: {str(e)}")
                
                flash('Şifreniz başarıyla güncellendi! Şimdi giriş yapabilirsiniz.', 'success')
                return redirect(url_for('login'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Password reset error: {str(e)}")
                flash('Şifre güncellenirken bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
        
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{error}', 'danger')
                    app.logger.warning(f"Form validation error - {field}: {error}")
        
        return render_template('reset_password_form.html', form=form)
        
    except Exception as e:
        app.logger.error(f"Reset password token page error: {str(e)}")
        import traceback
        app.logger.error(traceback.format_exc())
        flash('Bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
        return redirect(url_for('reset_password_request'))




@app.route('/complete_profile', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute", key_func=lambda: get_remote_address())
def complete_profile():
    """Kullanıcı - Profil Tamamlama - Güvenli"""
    try:
        # ✅ Profil zaten tamamlanmış mı kontrolü
        if current_user.profile_completed:
            flash('Profiliniz zaten tamamlanmış.', 'info')
            return redirect(url_for('dashboard'))
        
        form = CompleteProfileForm()

        # ✅ Form seçeneklerini güvenli şekilde yükle
        try:
            provinces = Province.query.order_by(Province.name).all()
            form.province.choices = [(0, 'İl Seçiniz')] + [(p.id, p.name) for p in provinces]
        except Exception as e:
            app.logger.error(f"Province options loading error: {str(e)}")
            form.province.choices = [(0, 'İl Seçiniz')]
        
        try:
            school_types = SchoolType.query.order_by(SchoolType.name).all()
            form.school_type.choices = [(0, 'Okul Türü Seçiniz')] + [(s.id, s.name) for s in school_types]
        except Exception as e:
            app.logger.error(f"School type options loading error: {str(e)}")
            form.school_type.choices = [(0, 'Okul Türü Seçiniz')]
        
        form.district.choices = [(0, 'İlçe Seçiniz')]
        form.school.choices = [(0, 'Okul Seçiniz')]

        if request.method == 'POST':
            # ✅ POST isteğinde seçili değerlere göre choices'ları güvenli güncelle
            province_id = SecurityService.sanitize_input(str(form.province.data), 10) if form.province.data else None
            district_id = SecurityService.sanitize_input(str(form.district.data), 10) if form.district.data else None
            school_type_id = SecurityService.sanitize_input(str(form.school_type.data), 10) if form.school_type.data else None
            
            # ✅ İl seçimi güvenli kontrolü
            if province_id and province_id.isdigit():
                try:
                    districts = District.query.filter_by(province_id=int(province_id)).order_by(District.name).all()
                    form.district.choices = [(0, 'İlçe Seçiniz')] + [(d.id, d.name) for d in districts]
                except Exception as e:
                    app.logger.error(f"District options loading error: {str(e)}")
                    form.district.choices = [(0, 'İlçe Seçiniz')]

            # ✅ İlçe ve okul türü seçimi güvenli kontrolü
            if district_id and district_id.isdigit() and school_type_id and school_type_id.isdigit():
                try:
                    schools = School.query.filter_by(
                        district_id=int(district_id),
                        school_type_id=int(school_type_id)
                    ).order_by(School.name).all()
                    form.school.choices = [(0, 'Okul Seçiniz')] + [(s.id, s.name) for s in schools]
                except Exception as e:
                    app.logger.error(f"School options loading error: {str(e)}")
                    form.school.choices = [(0, 'Okul Seçiniz')]
            elif district_id and district_id.isdigit():
                # Sadece ilçe seçili - tüm okul türlerinden okullar
                try:
                    schools = School.query.filter_by(district_id=int(district_id)).order_by(School.name).all()
                    form.school.choices = [(0, 'Okul Seçiniz')] + [(s.id, s.name) for s in schools]
                except Exception as e:
                    app.logger.error(f"School options loading error: {str(e)}")
                    form.school.choices = [(0, 'Okul Seçiniz')]

        if form.validate_on_submit():
            try:
                # ✅ Input sanitization
                first_name = SecurityService.sanitize_input(form.first_name.data, 50)
                last_name = SecurityService.sanitize_input(form.last_name.data, 50)
                class_no = SecurityService.sanitize_input(form.class_no.data, 10) if form.class_no.data else None
                class_name = SecurityService.sanitize_input(form.class_name.data, 10) if form.class_name.data else None
                school_id = form.school.data
                
                # ✅ Güvenlik kontrolleri
                if not first_name or not last_name:
                    flash('Ad ve soyad alanları zorunludur.', 'danger')
                    return redirect(url_for('complete_profile'))
                
                # ✅ İsim doğrulama
                if len(first_name) < 2 or len(first_name) > 50:
                    flash('Ad 2-50 karakter arasında olmalıdır.', 'warning')
                    return redirect(url_for('complete_profile'))
                
                if len(last_name) < 2 or len(last_name) > 50:
                    flash('Soyad 2-50 karakter arasında olmalıdır.', 'warning')
                    return redirect(url_for('complete_profile'))
                
                # ✅ İsim format kontrolü - sadece harf ve boşluk
                import re
                name_pattern = r'^[a-zA-ZçğıöşüÇĞIİÖŞÜ\s]+$'
                if not re.match(name_pattern, first_name):
                    flash('Ad sadece harf ve boşluk içerebilir.', 'warning')
                    return redirect(url_for('complete_profile'))
                
                if not re.match(name_pattern, last_name):
                    flash('Soyad sadece harf ve boşluk içerebilir.', 'warning')
                    return redirect(url_for('complete_profile'))
                
                # ✅ Sınıf doğrulama
                allowed_classes = ['5', '6', '7', '8', '9', '10', '11', '12', 'LGS', 'TYT', 'AYT']
                if class_no and class_no not in allowed_classes:
                    flash('Geçersiz sınıf seçimi.', 'warning')
                    return redirect(url_for('complete_profile'))
                
                # ✅ Okul ID doğrulama
                if not school_id or school_id <= 0:
                    flash('Lütfen geçerli bir okul seçiniz.', 'warning')
                    return redirect(url_for('complete_profile'))
                
                # ✅ Okul varlık kontrolü
                school_check = School.query.get(school_id)
                if not school_check:
                    flash('Seçilen okul bulunamadı.', 'danger')
                    return redirect(url_for('complete_profile'))
                
                # ✅ Sınıf adı kontrolü (opsiyonel alan)
                if class_name and (len(class_name) < 1 or len(class_name) > 10):
                    flash('Sınıf adı 1-10 karakter arasında olmalıdır.', 'warning')
                    return redirect(url_for('complete_profile'))
                
                # ✅ Güvenli profil güncelleme
                old_data = {
                    'first_name': current_user.first_name,
                    'last_name': current_user.last_name,
                    'school_id': current_user.school_id,
                    'profile_completed': current_user.profile_completed
                }
                
                current_user.first_name = first_name.title()  # İlk harfleri büyük yap
                current_user.last_name = last_name.title()
                current_user.class_no = class_no
                current_user.class_name = class_name.upper() if class_name else None  # Sınıf adı büyük harf
                current_user.school_id = school_id
                current_user.profile_completed = True
                current_user.profile_completed_date = datetime.utcnow()

                db.session.commit()
                
                # ✅ Güvenli log yazma
                changes = []
                for key, old_value in old_data.items():
                    new_value = getattr(current_user, key)
                    if old_value != new_value:
                        changes.append(key)
                
                app.logger.info(f"User {current_user.id} completed profile - Changed fields: {changes}, School: {school_id}")
                
                flash('🎉 Profiliniz başarıyla tamamlandı! Artık yarışmaya katılabilirsiniz.', 'success')
                return redirect(url_for('dashboard'))

            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Profile completion error: {str(e)}")
                app.logger.error(traceback.format_exc())
                flash('Profil tamamlanırken bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
                return redirect(url_for('complete_profile'))
        else:
            # ✅ Form validation hataları
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')

        return render_template('complete_profile.html', 
                             form=form, 
                             title='Profil Tamamla')
                             
    except Exception as e:
        app.logger.error(f"Complete profile page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('dashboard'))
    




    
    
@app.route("/dashboard/profile", methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileUpdateForm()
    
    # Form seçeneklerini yükle
    form.province.choices = [(p.id, p.name) for p in Province.query.order_by(Province.name).all()]
    form.school_type.choices = [(st.id, st.name) for st in SchoolType.query.order_by(SchoolType.name).all()]
    
    current_school = School.query.get(current_user.school_id) if current_user.school_id else None

    if request.method == 'POST':
        # Province seçiliyse district'leri güncelle
        if form.province.data:
            districts = District.query.filter_by(province_id=form.province.data).all()
            form.district.choices = [(d.id, d.name) for d in districts]
        else:
            form.district.choices = [(0, 'Önce il seçin')]

        # District ve school_type seçiliyse okulları güncelle
        if form.district.data and form.school_type.data:
            schools = School.query.filter_by(
                district_id=form.district.data,
                school_type_id=form.school_type.data
            ).all()
            form.school.choices = [(s.id, s.name) for s in schools]
        else:
            form.school.choices = [(0, 'Önce ilçe ve okul türü seçin')]

    elif current_school:
        # İlçe seçeneklerini yükle
        districts = District.query.filter_by(province_id=current_school.district.province_id).all()
        form.district.choices = [(d.id, d.name) for d in districts]
        # Okul seçeneklerini yükle
        schools = School.query.filter_by(
            district_id=current_school.district_id,
            school_type_id=current_school.school_type_id
        ).all()
        form.school.choices = [(s.id, s.name) for s in schools]
    else:
        form.district.choices = [(0, 'Önce il seçin')]
        form.school.choices = [(0, 'Önce ilçe ve okul türü seçin')]

    if form.validate_on_submit():
        try:
            current_user.first_name = form.first_name.data
            current_user.last_name = form.last_name.data
            current_user.email = form.email.data
            current_user.phone = form.phone.data
            current_user.school_id = form.school.data
            current_user.class_no = form.class_no.data
            current_user.class_name = form.class_name.data
            
            if not current_user.profile_completed:
                current_user.profile_completed = True
                current_user.profile_completed_date = datetime.utcnow()
            
            db.session.commit()
            flash('Profiliniz başarıyla güncellendi!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Profil güncelleme hatası: {str(e)}")
            flash('Profil güncellenirken bir hata oluştu!', 'danger')
            
    elif request.method == 'GET':
        # Form alanlarını doldur
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.email.data = current_user.email
        form.phone.data = current_user.phone
        
        if current_school:
            form.province.data = current_school.district.province_id
            form.district.data = current_school.district_id
            form.school_type.data = current_school.school_type_id
            form.school.data = current_user.school_id
            
        form.class_no.data = current_user.class_no
        form.class_name.data = current_user.class_name
        
    # Leaderboard verilerini hesapla
    leaderboard_service = LeaderboardService()
    leaderboard = leaderboard_service.get_student_leaderboard_data(current_user.id)
    if not leaderboard or not isinstance(leaderboard, dict):
        leaderboard = {'general': {'my_rank': None, 'my_points': 0, 'top_students': []}}
    if not leaderboard.get('general'):
        leaderboard['general'] = {'my_rank': None, 'my_points': 0, 'top_students': []}
    if not leaderboard['weekly'].get('general') or not isinstance(leaderboard['weekly'].get('general'), dict):
        leaderboard['weekly']['general'] = {'my_rank': '?'}
        
    return render_template('profile.html', 
                         title='Profil', 
                         form=form,
                         leaderboard=leaderboard)
    
    
    
@app.context_processor
def inject_common_values():
    if current_user.is_authenticated:
        try:
            # Kullanıcı adı oluştur
            first_name = current_user.first_name or ""
            last_name = current_user.last_name or ""
            kullanici_adi = f"{first_name} {last_name}".strip() or current_user.username or "Kullanıcı"

            # Puanlar ve tarih aralıkları
            today = datetime.utcnow().date()
            week_start = datetime.utcnow() - timedelta(days=7)
            month_start = datetime.utcnow() - timedelta(days=30)

            daily_points = db.session.query(func.sum(UserProgress.puan)).filter(
                UserProgress.user_id == current_user.id,
                UserProgress.puan.isnot(None),
                func.date(UserProgress.tarih) == today
            ).scalar() or 0

            weekly_points = db.session.query(func.sum(UserProgress.puan)).filter(
                UserProgress.user_id == current_user.id,
                UserProgress.puan.isnot(None),
                UserProgress.tarih >= week_start
            ).scalar() or 0

            monthly_points = db.session.query(func.sum(UserProgress.puan)).filter(
                UserProgress.user_id == current_user.id,
                UserProgress.puan.isnot(None),
                UserProgress.tarih >= month_start
            ).scalar() or 0

            total_points = db.session.query(func.sum(UserProgress.puan)).filter(
                UserProgress.user_id == current_user.id,
                UserProgress.puan.isnot(None)
            ).scalar() or 0

            # Genel istatistikler
            stats_service = StatisticsService(current_user.id)
            genel_istatistikler = stats_service.get_time_based_stats() or {}

            # Leaderboard verilerini context processor'da çağırma - performans için sadece gerekli sayfalarda çağır
            # leaderboard_service = LeaderboardService()
            # leaderboard = leaderboard_service.get_student_leaderboard_data(current_user.id)

            return {
                'kullanici_adi': kullanici_adi,
                'daily_points': int(daily_points),
                'weekly_points': int(weekly_points),
                'monthly_points': int(monthly_points),
                'total_points': int(total_points),
                'genel_istatistikler': genel_istatistikler,
                # 'leaderboard': leaderboard  # Kaldırıldı - sadece gerekli sayfalarda çağır
            }
        except Exception as e:
            app.logger.error(f"Context processor hatası: {str(e)}")
            return {
                'kullanici_adi': getattr(current_user, 'username', 'Kullanıcı'),
                'daily_points': 0,
                'weekly_points': 0,
                'monthly_points': 0,
                'total_points': 0,
                'genel_istatistikler': {},
                # 'leaderboard': {'weekly': {'general': {'my_rank': '?'}}}  # Kaldırıldı
            }
    return {}





@app.route('/<int:sinif_id>')
def redirect_sinif(sinif_id):
    sinif = Sinif.query.get_or_404(sinif_id)
    return redirect(url_for('sinif', slug=sinif.slug), code=301)

@app.route('/<int:sinif_id>/<int:ders_id>')
def legacy_ders_redirect(sinif_id, ders_id):
    sinif = Sinif.query.get_or_404(sinif_id)
    ders = Ders.query.filter_by(id=ders_id, sinif_id=sinif_id).first_or_404()
    return redirect(url_for('ders', sinif_slug=sinif.slug, ders_slug=ders.slug), code=301)  

@app.route('/ders_notu_filtre/<int:sinif_id>/<int:ders_id>')
def redirect_ders_notu_filtre(sinif_id, ders_id):
    sinif = Sinif.query.get_or_404(sinif_id)
    ders = Ders.query.filter_by(id=ders_id, sinif_id=sinif_id).first_or_404()
    return redirect(url_for('ders_notu_filtre', sinif_slug=sinif.slug, ders_slug=ders.slug), code=301)

@app.route('/<int:sinif_id>/<int:ders_id>/<int:unite_id>')
def legacy_unite_redirect(sinif_id, ders_id, unite_id):
    sinif = Sinif.query.get_or_404(sinif_id)
    ders = Ders.query.filter_by(id=ders_id, sinif_id=sinif_id).first_or_404()
    unite = Unite.query.filter_by(id=unite_id, ders_id=ders_id).first_or_404()
    return redirect(url_for('unite', sinif_slug=sinif.slug, ders_slug=ders.slug, unite_slug=unite.slug), code=301)

@app.route('/<int:sinif_id>/<int:ders_id>/<int:unite_id>/<int:icerik_id>')
def legacy_icerik_redirect(sinif_id, ders_id, unite_id, icerik_id):
    sinif = Sinif.query.get_or_404(sinif_id)
    ders = Ders.query.filter_by(id=ders_id, sinif_id=sinif_id).first_or_404()
    unite = Unite.query.filter_by(id=unite_id, ders_id=ders_id).first_or_404()
    icerik = Icerik.query.filter_by(id=icerik_id, unite_id=unite_id).first_or_404()
    return redirect(url_for('icerik', sinif_slug=sinif.slug, ders_slug=ders.slug, unite_slug=unite.slug, icerik_slug=icerik.slug), code=301)





def get_recent_courses_optimized(user_id, limit=3):
    """
    Tekilleştirilmiş UserProgress yapısına uygun şekilde:
    - Son görüntülenen dersleri
    - Her ders için okunan içerik sayısını (her içerik için sadece bir kez okundu sayılır)
    - Toplam içerik sayısını
    - Son görüntülenme tarihini
    döndürür.
    """
    try:
        # 1. Kullanıcının okuduğu içeriklerin ID'lerini tekilleştir
        okunan_icerik_ids = set(
            row[0] for row in db.session.query(UserProgress.icerik_id)
            .filter(
                UserProgress.user_id == user_id,
                UserProgress.activity_type == ActivityType.CONTENT_READING,
                UserProgress.okundu.is_(True)
            ).distinct()
        )

        # 2. Son görüntülenen içeriklerin derslerini bul (en son görüntüleme tarihine göre)
        recent_progress = (
            db.session.query(
                UserProgress.icerik_id,
                func.max(UserProgress.tarih).label('son_gorulme')
            )
            .filter(
                UserProgress.user_id == user_id,
                UserProgress.activity_type == ActivityType.CONTENT_VIEWED
            )
            .group_by(UserProgress.icerik_id)
            .order_by(func.max(UserProgress.tarih).desc())
            .limit(30)  # Son 30 içerik üzerinden dersleri bul
            .all()
        )

        # 3. Bu içeriklerin derslerini sırayla bul ve tekilleştir
        ders_sirasi = []
        ders_ids_seen = set()
        for icerik_id, son_gorulme in recent_progress:
            icerik = Icerik.query.get(icerik_id)
            if not icerik:
                continue
            unite = Unite.query.get(icerik.unite_id)
            if not unite:
                continue
            ders = Ders.query.get(unite.ders_id)
            if not ders or ders.id in ders_ids_seen:
                continue
            ders_sirasi.append((ders, son_gorulme))
            ders_ids_seen.add(ders.id)
            if len(ders_sirasi) >= limit:
                break

        # 4. Her ders için okunan içerik sayısı ve toplam içerik sayısı
        course_progress = []
        for ders, son_gorulme in ders_sirasi:
            # O derse ait tüm içeriklerin ID'leri
            ders_icerik_ids = set(
                ic.id for u in ders.uniteler for ic in (u.icerikler.all() if hasattr(u.icerikler, 'all') else u.icerikler)
            )
            read_contents = len(okunan_icerik_ids & ders_icerik_ids)
            total_contents = len(ders_icerik_ids) or 1
            progress_percentage = int((read_contents / total_contents * 100)) if total_contents > 0 else 0

            course_data = {
                'ders_id': ders.id,
                'ders_adi': ders.ders_adi,
                'sinif': ders.sinif.sinif if ders.sinif else '',
                'sinif_slug': ders.sinif.slug if ders.sinif else '',
                'ders_slug': ders.slug,
                'son_gorulme': son_gorulme,
                'progress': progress_percentage,
                'total_contents': int(total_contents),
                'read_contents': int(read_contents)
            }
            course_progress.append(course_data)

        return course_progress

    except Exception as e:
        app.logger.error(f"get_recent_courses_optimized error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return []



    
    
@app.route("/dashboard")
@login_required
def dashboard():
    try:
        # Admin ise boş veri döndür
        if current_user.role == 'admin':
            return render_template(
                'dashboard.html',
                siniflar=[],
                sinif=None,
                dersler=[],
                uniteler=[],
                active_icerik_id=None,
                streak_days=0,
                daily_solved=0,
                last_progress=None,
                recent_contents=[],
                today_wrong_questions=[],
                daily_stats={},
                course_progress=[],
                is_admin=True
            )

        today = datetime.utcnow().date()
        stats_service = StatisticsService(current_user.id)
        siniflar = Sinif.query.all()

        # Kullanıcının sınıfı
        sinif = None
        if current_user.class_no:
            sinif = Sinif.query.filter_by(sinif=current_user.class_no).first()

        dersler = Ders.query.filter_by(sinif_id=sinif.id).all() if sinif else []
        ders = dersler[0] if dersler else None

        # Sidebar için ünite ve içerik verileri
        uniteler_with_icerikler = []
        if ders:
            uniteler = Unite.query.filter_by(ders_id=ders.id).all()
            for unite in uniteler:
                icerik_listesi = []
                icerikler = unite.icerikler.all()
                for icerik in icerikler:
                    progress = UserProgress.query.filter_by(
                        user_id=current_user.id,
                        icerik_id=icerik.id,
                        okundu=True
                    ).first()
                    icerik_obj = {
                        'id': icerik.id,
                        'baslik': icerik.baslik,
                        'okundu': bool(progress),
                        'unite_slug': unite.slug  # ✅ EKLE: unite_slug eklendi
                    }
                    icerik_listesi.append(icerik_obj)
                uniteler_with_icerikler.append({
                    'unite': unite.unite,
                    'id': unite.id,
                    'unite_slug': unite.slug,  # ✅ EKLE: unite_slug eklendi
                    'icerikler': icerik_listesi
                })

        # ✅ YENİ: Bugünkü istatistikler (genişletilmiş)
        today_stats = db.session.query(
            func.sum(UserProgress.dogru_sayisi).label('total_dogru'),
            func.sum(UserProgress.yanlis_sayisi).label('total_yanlis'),
            func.sum(UserProgress.bos_sayisi).label('total_bos'),
            func.sum(UserProgress.puan).label('total_puan'),
            func.count(UserProgress.id).label('total_soru')
        ).filter(
            UserProgress.user_id == current_user.id,
            func.date(UserProgress.tarih) == today,
            UserProgress.activity_type == 'question_solving'
        ).first()

        # ✅ YENİ: Genişletilmiş daily_stats
        daily_stats = {
            'total_questions': today_stats.total_soru or 0,
            'total_correct': today_stats.total_dogru or 0,      # ✅ YENİ: Doğru cevap sayısı
            'total_wrong': today_stats.total_yanlis or 0,       # ✅ YENİ: Yanlış cevap sayısı
            'total_empty': today_stats.total_bos or 0,          # ✅ YENİ: Boş cevap sayısı
            'success_rate': int((today_stats.total_dogru / today_stats.total_soru * 100) if today_stats.total_soru else 0)
        }

        # ✅ Son 5 içerik aktivitesi
        recent_contents = db.session.query(UserProgress).options(
            joinedload(UserProgress.icerik).joinedload(Icerik.unite).joinedload(Unite.ders).joinedload(Ders.sinif)
        ).filter(
            UserProgress.user_id == current_user.id,
            UserProgress.icerik_id.isnot(None),
            UserProgress.activity_type == 'content_viewed'
        ).order_by(UserProgress.tarih.desc()).limit(5).all()

        # ✅ Son ilerleme kaydı
        last_progress = db.session.query(UserProgress).options(
            joinedload(UserProgress.icerik).joinedload(Icerik.unite).joinedload(Unite.ders).joinedload(Ders.sinif)
        ).filter(
            UserProgress.user_id == current_user.id,
            UserProgress.icerik_id.isnot(None),
            UserProgress.activity_type == 'content_viewed'
        ).order_by(UserProgress.tarih.desc()).first()

        # ✅ Bugünkü yanlış sorular
        today_wrong_questions = (
            db.session.query(UserProgress, Soru, Icerik, Unite, Ders, Sinif)
            .join(Soru, UserProgress.soru_id == Soru.id)
            .join(Icerik, Soru.icerik_id == Icerik.id)
            .join(Unite, Icerik.unite_id == Unite.id)
            .join(Ders, Unite.ders_id == Ders.id)
            .join(Sinif, Ders.sinif_id == Sinif.id)
            .filter(
                UserProgress.user_id == current_user.id,
                UserProgress.soru_id.isnot(None),
                UserProgress.yanlis_sayisi > 0,
                func.date(UserProgress.tarih) == today,
                UserProgress.activity_type == 'question_solving'
            )
            .order_by(UserProgress.tarih.desc())
            .all()
        )

        # ✅ İYİLEŞTİRİLMİŞ: Son görüntülenen dersler (optimize edilmiş)
        try:
            course_progress = get_recent_courses_optimized(current_user.id, limit=3)
        except Exception as e:
            app.logger.error(f"Course progress query error: {str(e)}")
            course_progress = []

        # ✅ Zaman bazlı istatistikler
        time_stats = stats_service.get_time_based_stats()

        # ✅ Template context
        context = {
            'siniflar': siniflar,
            'sinif': sinif,
            'dersler': dersler,
            'uniteler': uniteler_with_icerikler,
            'active_icerik_id': last_progress.icerik_id if last_progress else None,
            'streak_days': time_stats.get('streak_days', 0) if time_stats else 0,
            'daily_solved': time_stats.get('daily_solved', 0) if time_stats else 0,
            'last_progress': last_progress,
            'recent_contents': recent_contents,
            'today_wrong_questions': today_wrong_questions,
            'daily_stats': daily_stats,  # ✅ Genişletilmiş istatistikler
            'course_progress': course_progress,  # ✅ Optimize edilmiş ders verileri
            'is_admin': False
        }

        return render_template('dashboard.html', **context)

    except Exception as e:
        app.logger.error(f"Dashboard hatası: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Dashboard yüklenirken bir hata oluştu.', 'error')
        return redirect(url_for('home'))



@app.route('/istatistikler')
@login_required
def istatistikler():
    try:
        stats_service = StatisticsService(current_user.id)
        time_stats = stats_service.get_time_based_stats() or {}
        performance_stats = stats_service.get_performance_stats() or {}
        course_stats = stats_service.get_course_stats() or {}

        # Leaderboard verilerini güvenli şekilde al
        leaderboard_service = LeaderboardService()
        leaderboard = leaderboard_service.get_student_leaderboard_data(current_user.id)
        
        # ✅ Güvenli fallback: None veya dict değilse boş dict ata
        if not leaderboard or not isinstance(leaderboard, dict):
            leaderboard = {}
        
        # Günlük, haftalık, toplam puanlar
        today = datetime.utcnow().date()
        week_start = today - timedelta(days=today.weekday())
        daily_points = db.session.query(func.sum(UserProgress.puan)).filter(
            UserProgress.user_id == current_user.id,
            UserProgress.activity_type == ActivityType.QUESTION_SOLVING,
            func.date(UserProgress.tarih) == today
        ).scalar() or 0
        weekly_points = db.session.query(func.sum(UserProgress.puan)).filter(
            UserProgress.user_id == current_user.id,
            UserProgress.activity_type == ActivityType.QUESTION_SOLVING,
            func.date(UserProgress.tarih) >= week_start
        ).scalar() or 0
        total_points = db.session.query(func.sum(UserProgress.puan)).filter(
            UserProgress.user_id == current_user.id,
            UserProgress.activity_type == ActivityType.QUESTION_SOLVING
        ).scalar() or 0

        return render_template(
            'statistics.html',
            overview=time_stats,
            performance=performance_stats,
            courses=course_stats,
            leaderboard=leaderboard,
            daily_points=int(daily_points),
            weekly_points=int(weekly_points),
            total_points=int(total_points),
            genel_istatistikler=time_stats  # ✅ EKLENDİ - Template için gerekli
        )
    except Exception as e:
        app.logger.error(f"İstatistikler sayfası hatası: {str(e)}")
        flash('İstatistikler yüklenirken bir hata oluştu.', 'error')
        return render_template(
            'statistics.html',
            overview=None,
            performance=None,
            courses=None,
            leaderboard={},
            daily_points=0,
            weekly_points=0,
            total_points=0,
            genel_istatistikler={}  # ✅ EKLENDİ - Fallback
        )
        
        
        
        
@app.route('/guclendirme-merkezi')
@login_required
def guclendirme_merkezi():
    try:
        stats_service = StudentStatisticsService(current_user.id)
        stats = stats_service.get_comprehensive_stats() or {}
        leaderboard_service = LeaderboardService()
        leaderboard = leaderboard_service.get_student_leaderboard_data(current_user.id) or {}
        
        # ✅ GÜVENLI FALLBACK - Önce None kontrolü
        if not leaderboard or not isinstance(leaderboard, dict):
            leaderboard = {}
        
        if not leaderboard.get('weekly') or not isinstance(leaderboard.get('weekly'), dict):
            leaderboard['weekly'] = {}
            
        if not leaderboard['weekly'].get('general') or not isinstance(leaderboard['weekly'].get('general'), dict):
            leaderboard['weekly']['general'] = {'my_rank': '?'}
        
        return render_template(
            'guclendirme_merkezi.html',
            stats=stats,
            leaderboard=leaderboard,
            title="Güçlendirme Merkezi"
        )
        
    except Exception as e:
        app.logger.error(f"Güçlendirme merkezi hatası: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Güçlendirme merkezi yüklenirken bir hata oluştu.', 'error')
        return redirect(url_for('dashboard'))
    
    
    
    
@app.route('/ilerleme-patikasi')
@login_required
def ilerleme_patikasi():
    """
    İlerleme patikası rotası — get_user_progress_tree ile kullanıcının sınıfına göre filtrelenmiş
    ilerleme verisini alır ve şablona gönderir. Hatalarda log atar ve kullanıcıyı güvenli şekilde yönlendirir.
    """
    try:
        app.logger.debug(f"ilerleme_patikasi çağrıldı - user_id={current_user.id}")
        progress_tree = get_user_progress_tree(current_user.id)
        
        if progress_tree is None:
            progress_tree = []
        
        return render_template(
            'ilerleme_patikasi.html',
            completion={'subjects': progress_tree}
        )
    except Exception as e:
        app.logger.error(f"İlerleme patikası yüklenirken hata: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('İlerleme verileri yüklenirken bir hata oluştu. Lütfen daha sonra tekrar deneyin.', 'danger')
        return redirect(url_for('dashboard'))
    
    
@app.route('/api/check-password-strength', methods=['POST'])
@csrf.exempt  # Public API endpoint for password strength checking
def check_password_strength():
    """
    Password gücünü kontrol et ve detaylı feedback sağla.
    Request: {"password": "MyP@ssw0rd123"}
    Response: {
        "valid": true/false,
        "score": 0-100,
        "strength": "weak/fair/good/strong",
        "errors": ["hata1", "hata2"],
        "feedback": "Güçlü bir şifre seçtiniz!"
    }
    """
    try:
        data = request.get_json(silent=True)
        if not data or 'password' not in data:
            return jsonify({'error': 'password parametresi gerekli'}), 400
        
        password = data.get('password', '')
        
        # Validate strength
        is_valid, errors = SecurityService.validate_password_strength(password)
        
        # Get score
        score = SecurityService.get_password_strength_score(password)
        
        # Determine strength level
        if score < 26:
            strength = 'çok-zayıf'
            feedback = 'Çok zayıf bir şifre. Daha karmaşık bir şifre seçin.'
        elif score < 51:
            strength = 'zayıf'
            feedback = 'Zayıf bir şifre. Daha uzun ve çeşitli karakterler kullanın.'
        elif score < 76:
            strength = 'orta'
            feedback = 'Orta düzey bir şifre. Biraz daha güçlendirebilir.'
        else:
            strength = 'güçlü'
            feedback = 'Güçlü bir şifre! Güvenli ve kompleks.'
        
        return jsonify({
            'valid': is_valid,
            'score': score,
            'strength': strength,
            'errors': errors,
            'feedback': feedback,
            'breached': SecurityService.check_password_breach(password)
        }), 200
        
    except Exception as e:
        app.logger.error(f"Password strength check error: {str(e)}")
        return jsonify({'error': 'Internal error'}), 500

    
    
@app.route('/api/user/weekly-progress')
@login_required
def api_user_weekly_progress():
    """Login olan kullanıcının son 7 gün doğru/yanlış istatistiklerini JSON olarak döndürür."""
    try:
        today = datetime.utcnow().date()
        days = [(today - timedelta(days=i)) for i in range(6, -1, -1)]  # 7 gün: eski->yeni
        result = []
        for day in days:
            dogru = db.session.query(func.sum(UserProgress.dogru_sayisi)).filter(
                UserProgress.user_id == current_user.id,
                func.date(UserProgress.tarih) == day,
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            ).scalar() or 0
            yanlis = db.session.query(func.sum(UserProgress.yanlis_sayisi)).filter(
                UserProgress.user_id == current_user.id,
                func.date(UserProgress.tarih) == day,
                UserProgress.activity_type == ActivityType.QUESTION_SOLVING
            ).scalar() or 0
            result.append({
                'day': day.strftime('%a'),  # 'Mon', 'Tue', ...
                'dogru': int(dogru),
                'yanlis': int(yanlis)
            })
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Weekly progress API error: {str(e)}")
        return jsonify([]), 500
    

    
    
    

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    """Kullanıcı Çıkışı - IP Loglama ile"""
    try:
        user_id = current_user.id
        
        # ✅ YENİ: Çıkış logla
        log_user_action(
            user_id=user_id,
            action_type=LogActionType.LOGOUT,
            success=True,
            details=None
        )
        db.session.commit()
        
        app.logger.info(f"User logout - ID: {user_id}, IP: {get_client_ip()}")
        
    except Exception as e:
        app.logger.error(f"Logout logging error: {str(e)}")
    
    logout_user()
    flash('Başarıyla çıkış yaptınız!', 'success')
    return redirect(url_for('home'))


@app.route('/admin/register', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def admin_register():
    if current_user.is_authenticated and current_user.role != 'admin':
        return redirect(url_for('admin'))
    
    form = AdminRegisterForm() 
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_admin = User(username=form.username.data, email=form.email.data, password=hashed_pw, role='admin',)
            
        db.session.add(new_admin)
        db.session.commit()
            
        flash(f'Yeni admin {form.username.data} başarıyla eklendi!', 'success')
        return redirect(url_for('admin'))
           
    admin_users = User.query.filter_by(role='admin').order_by(User.id).all()      
    return render_template('admin_register.html', form=form, admin_users=admin_users)


@app.route('/admin')
def admin():
    return render_template('admin.html', title='Admin Paneli')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin'))
        
    form = AdminLoginForm()
    
    if request.method == 'POST':
        app.logger.debug(f"Admin login POST - CSRF token in form: {bool(form.csrf_token.data)}")
        app.logger.debug(f"Admin login POST - Form errors: {form.errors}")
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        # Kullanıcı var mı ve admin mi kontrol et
        if user and user.role == 'admin':
            # Şifre kontrolü
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember_me.data)
                flash('Admin olarak giriş yaptınız!', 'success')
                app.logger.info(f"Admin login successful - User ID: {user.id}, IP: {request.remote_addr}")
                
                # 'next' parametresi varsa oraya, yoksa admin paneline yönlendir
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('admin'))
            else:
                flash('Şifre yanlış!', 'danger')
                app.logger.warning(f"Admin login failed - wrong password, Email: {form.email.data}, IP: {request.remote_addr}")
        else:
            flash('Bu email adresi ile kayıtlı admin bulunamadı!', 'danger')
            app.logger.warning(f"Admin login failed - user not found or not admin, Email: {form.email.data}, IP: {request.remote_addr}")
    elif request.method == 'POST' and form.errors:
        # CSRF token hatası veya diğer form hataları
        app.logger.error(f"Admin login form validation error: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f'{field}: {error}', 'danger')
    
    return render_template('admin_login.html', title='Admin Girişi', form=form)



@app.route('/admin-logout')
@admin_required
def admin_logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('admin_login'))



@app.route('/admin/delete/<int:id>', methods=['POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def admin_delete(id):
    admin = User.query.get_or_404(id)
    if admin:
        db.session.delete(admin)
        db.session.commit()
        flash(f'{admin.name} adlı admin başarıyla silindi!', 'success')
        return redirect(url_for('admin_register'))
    else:
        flash('Belirtilen ID\'ye sahip admin bulunamadı!', 'danger')
    return redirect(url_for('admin_register'))



@app.route('/admin/edit_admin/<int:id>', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def admin_edit(id):
    admin = User.query.get_or_404(id)
    form = AdminEditForm()
    if request.method == 'GET':
        form.username.data = admin.username
        form.email.data = admin.email
        form.password.data = admin.password
    elif form.validate_on_submit():
        try:
            admin.username = form.username.data
            admin.email = form.email.data
            admin.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            db.session.commit() # Değişiklikleri kaydet
            flash('Admin başarıyla güncellendi!', 'success')
            return redirect(url_for('admin_register'))
        except Exception as e:
            db.session.rollback()
            flash('Admin güncellenirken bir hata oluştu!', 'danger')
            app.logger.error(f'Admin güncelleme hatası: {str(e)}')
    return render_template('admin_edit.html', form=form, admin=admin)


## Sınıf Ekleme Bölümü

@app.route('/konu_ekleme', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def add_konu():
    form = SinifForm()
    try:
        if form.validate_on_submit():
            # Veri kontrolü
            mevcut_sinif = Sinif.query.filter_by(sinif=form.sinif.data).first()
            if mevcut_sinif:
                flash('Bu sınıf zaten mevcut!', 'warning')
                return redirect(url_for('add_konu'))
            
            # Yeni kayıt
            yeni_sinif = Sinif(sinif=form.sinif.data)
            db.session.add(yeni_sinif)
            db.session.commit()
            
            flash('Sınıf başarıyla eklendi!', 'success')
            return redirect(url_for('add_konu'))
            
    except Exception as e:
        db.session.rollback()
        flash('Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.', 'error')
        app.logger.error(f'DB Hatası: {str(e)}')
    
    siniflar = Sinif.query.order_by(Sinif.id).all()
    return render_template('add_konu.html', form=form, siniflar=siniflar)



@app.route('/konu_ekleme/<int:id>', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def update_konu(id):
    konu = Sinif.query.get_or_404(id)
    form = SinifForm()
    
    try:
        if form.validate_on_submit():
            # Aynı isimde başka sınıf var mı kontrolü
            mevcut_sinif = Sinif.query.filter(
                Sinif.sinif == form.sinif.data,
                Sinif.id != id
            ).first()
            
            if mevcut_sinif:
                flash('Bu sınıf adı zaten kullanılıyor!', 'warning')
                return redirect(url_for('update_konu', id=id))
                
            konu.sinif = form.sinif.data
            konu.slug = create_slug(form.sinif.data)
            db.session.commit()
            flash('Sınıf başarıyla güncellendi.', 'success')
            return redirect(url_for('add_konu'))
            
        elif request.method == 'GET':
            form.sinif.data = konu.sinif
            
    except Exception as e:
        db.session.rollback()
        flash('Güncelleme sırasında bir hata oluştu!', 'danger')
        app.logger.error(f'Güncelleme hatası: {str(e)}')
        
    return render_template('update_konu.html', form=form, id=id)



@app.route('/konu_ekleme/<int:id>/delete', methods=['POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def delete_konu(id):
    sinif = Sinif.query.get_or_404(id)
    try:
        db.session.delete(sinif)  # Cascade silme otomatik çalışır
        db.session.commit()
        flash('Sınıf başarıyla silindi.', 'success')
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Silme işlemi sırasında bir hata oluştu!', 'danger')
        app.logger.error(f'DB Hatası: {str(e)}')
    return redirect(url_for('add_konu'))


##Ders Ekleme Bölümü

@app.route('/konu_ekleme/<int:id>/ders_ekleme', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def add_ders(id):
    form = DersForm()
    try:
        if form.validate_on_submit():
            # Aynı isimde ders kontrolü
            mevcut_ders = Ders.query.filter_by(ders_adi=form.ders.data, sinif_id=id).first()
            
            if mevcut_ders:
                flash('Bu ders zaten mevcut!', 'warning')
                return redirect(url_for('add_ders', id=id))
            
            # Yeni ders ekle
            ders = Ders(sinif_id=id, ders_adi=form.ders.data)
            db.session.add(ders)
            db.session.commit()
            
            flash('Ders başarıyla eklendi.', 'success')
            return redirect(url_for('add_ders', id=id))
            
    except Exception as e:
        db.session.rollback()
        flash('Ders eklenirken bir hata oluştu!', 'danger')
        app.logger.error(f'Hata: {str(e)}')
    
    # Mevcut dersleri getir
    dersler = Ders.query.filter_by(sinif_id=id).order_by(Ders.id)
    sinif = Sinif.query.get_or_404(id)
    
    return render_template('add_ders.html', dersler=dersler, form=form, sinif=sinif)


@app.route('/konu_ekleme/<int:id>/<int:sub_id>', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir   
def update_ders(id, sub_id):
    ders = Ders.query.get_or_404(sub_id)
    form = DersForm()
    
    try:
        if form.validate_on_submit():
            # Aynı isimde ders kontrolü
            mevcut_ders = Ders.query.filter(
                Ders.ders_adi == form.ders.data,
                Ders.id != sub_id, Ders.sinif_id == id).first()
            
            if mevcut_ders:
                flash('Bu ders adı zaten kullanılıyor!', 'warning')
                return redirect(url_for('update_ders', id=id, sub_id=sub_id))
            
            ders.ders_adi = form.ders.data
            ders.slug = create_slug(form.ders.data) 
            db.session.commit()
            flash('Ders başarıyla güncellendi.', 'success')
            return redirect(url_for('add_ders', id=ders.sinif_id))
            
        elif request.method == 'GET':
            form.ders.data = ders.ders_adi
            
    except Exception as e:
        db.session.rollback()
        flash('Güncelleme sırasında bir hata oluştu!', 'error')
        app.logger.error(f'Güncelleme hatası: {str(e)}')
        
    return render_template('update_ders.html', form=form, ders=ders)


@app.route('/konu_ekleme/<int:id>/<int:sub_id>/delete', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir  
def delete_ders(id, sub_id):
    ders = Ders.query.get_or_404(sub_id)
    try:
        db.session.delete(ders)
        db.session.commit()
        flash('Ders başarı ile silinmiştir. ', 'success')  
        return redirect(url_for('add_ders', id=ders.sinif_id))
    except:
        flash('İşlem esnasında bir sorun ile karşılaşıldı. Tekrar deneyiniz.', 'danger')
        return redirect(url_for('add_ders', id=ders.sinif_id))
    
    

## Ünite Ekleme Bölümü


@app.route('/konu_ekleme/<int:id>/<int:sub_id>/unite_ekleme', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def add_unite(id, sub_id):
    form = UniteForm()
    ders = Ders.query.get_or_404(sub_id)
    
    try:
        if form.validate_on_submit():
            # Duplicate kontrolü
            mevcut_unite = Unite.query.filter_by(unite=form.unite.data, ders_id=sub_id).first()
            
            if mevcut_unite:
                flash('Bu ünite zaten mevcut!', 'warning')
                return redirect(url_for('add_unite', id=id, sub_id=sub_id))
            
            # Yeni ünite oluştur
            unite = Unite(unite=form.unite.data, ders_id=sub_id)
            db.session.add(unite)
            db.session.commit()
            
            flash('Ünite başarıyla eklendi!', 'success')
            return redirect(url_for('add_unite', id=id, sub_id=sub_id))
            
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Veritabanı hatası: Ünite eklenemedi!', 'error')
        app.logger.error(f'DB Hatası: {str(e)}')
    
    # Mevcut üniteleri getir ve sırala
    uniteler = Unite.query.filter_by(ders_id=sub_id).order_by(Unite.id)    
    return render_template('add_unite.html', form=form, uniteler=uniteler, ders=ders, id=id, sub_id=sub_id)


@app.route('/konu_ekleme/<int:id>/<int:sub_id>/unite_delete/<int:unite_id>', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir   
def delete_unite(id, sub_id, unite_id):
    konu = Unite.query.get_or_404(unite_id)
    try:        
        # İçeriği sil
        db.session.delete(konu)
        db.session.commit()
               
        flash('Ünite başarıyla silindi.', 'success')
        return redirect(url_for('add_unite', id=id, sub_id=sub_id))
    except Exception as e:
        app.logger.error(f"Silme hatası: {str(e)}")
        flash('İşlem sırasında bir hata oluştu.', 'danger')
        return redirect(url_for('add_unite', id=id, sub_id=sub_id))
    
    
@app.route('/konu_ekleme/<int:id>/<int:sub_id>/icerik_edit/<int:unite_id>', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def edit_unite(id, sub_id, unite_id):
    ders = Ders.query.get_or_404(sub_id)
    konu = Unite.query.get_or_404(unite_id)
    form = UniteForm()
    if form.validate_on_submit():
        try:
            konu.unite = form.unite.data
            konu.slug = create_slug(form.unite.data)
            db.session.commit()
            flash('İçerik başarı ile güncellendi.')
            return redirect(url_for('add_unite', id=id, sub_id=sub_id))
        except Exception as e:
            app.logger.error(f"Güncelleme hatası: {str(e)}")
            flash('İçerik güncellenirken bir hata oluştu.')
            return redirect(url_for('add_unite', id=id, sub_id=sub_id))
    elif request.method == 'GET':
        form.unite.data = konu.unite
    return render_template('update_unite.html',ders=ders, form=form, konu=konu, id=id, sub_id=sub_id)


def get_image_urls_from_content(content):
    """İçerikteki resim URL'lerini güvenli şekilde çıkar"""
    if not content:
        return []
    
    try:
        # Host URL'ini al
        base_url = request.host_url.rstrip('/')
        
        # Sadece uploads klasöründeki resimleri bul
        pattern = f'src=[\'"]({re.escape(base_url)}/static/uploads/[^\'"]+)[\'"]'
        
        # URL'leri bul ve filtrele  
        urls = re.findall(pattern, content)
        
        # Sadece güvenli domain'deki URL'leri döndür
        filtered_urls = []
        for url in urls:
            parsed_url = urlparse(url)
            if parsed_url.netloc == urlparse(base_url).netloc:
                filtered_urls.append(url)
                
        return filtered_urls
        
    except Exception as e:
        app.logger.error(f'URL parsing hatası: {str(e)}')
        return []
    
    
    
def delete_image_files(image_urls):
    """Belirtilen URL'lerdeki resim dosyalarını sil"""
    for url in image_urls:
        try:
            # URL'den dosya adını çıkar
            filename = url.split('/')[-1]
            fullpath = _abspath_join(app.config['UPLOAD_FOLDER'], filename)

            # Dosya varsa ve uploads klasöründeyse sil
            if is_within_directory(app.config['UPLOAD_FOLDER'], fullpath) and os.path.exists(fullpath):
                os.remove(fullpath)
                app.logger.info(f"Dosya silindi: {filename}")
            
        except Exception as e:
            app.logger.error(f"Dosya silme hatası: {str(e)}")
            
            
@app.route('/upload', methods=['POST'])
@admin_required
def upload_file():
    try:
        if 'upload' not in request.files:
            return jsonify({'error': 'Dosya yok'}), 400
            
        file = request.files['upload']
        if file.filename == '':
            return jsonify({'error': 'Dosya seçilmedi'}), 400
        
        # ✅ Dosya adını temizle
        filename = SecurityService.sanitize_input(file.filename, 255)
        
        if not allowed_file(filename):
            return jsonify({'error': 'İzin verilmeyen dosya türü'}), 400
        
        # ✅ Dosya boyutu kontrolü (5MB maksimum)
        file.seek(0, 2)  # Dosya sonuna git
        file_size = file.tell()
        file.seek(0)  # Başa dön
        
        if file_size > 5 * 1024 * 1024:  # 5MB
            return jsonify({'error': 'Dosya boyutu 5MB\'dan büyük olamaz'}), 400
        
        # ✅ MIME type kontrolü (ek güvenlik)
        import mimetypes
        mime_type, _ = mimetypes.guess_type(filename)
        allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/jpg']
        
        if mime_type not in allowed_mimes:
            return jsonify({'error': 'Geçersiz dosya türü'}), 400
        
        # ✅ Güvenli dosya adı oluştur
        secure_name = secure_filename(filename)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{secure_name}"
        
        # ✅ Dosya yolu güvenlik kontrolü
        fullpath = _abspath_join(app.config['UPLOAD_FOLDER'], unique_filename)

        # Path traversal saldırısını önle
        if not is_within_directory(app.config['UPLOAD_FOLDER'], fullpath):
            return jsonify({'error': 'Güvenlik hatası: Geçersiz dosya yolu'}), 400

        # ✅ Dosyayı kaydet
        file.save(fullpath)
        
        # ✅ URL oluştur - _external=True KALDIRILDI
        # Artık göreli URL dönecek: /static/uploads/dosya.png
        # Bu URL hem localhost'ta hem Render'da çalışır
        url = url_for('static', filename=f'uploads/{unique_filename}')
        
        # ✅ Güvenli log
        app.logger.info(f"Admin {current_user.id} uploaded file - Size: {file_size} bytes, Type: {mime_type}")
        
        return jsonify({
            'url': url, 
            'uploaded': 1, 
            'fileName': unique_filename,
            'fileSize': file_size
        })
        
    except Exception as e:
        app.logger.error(f'Upload hatası: {str(e)}')
        return jsonify({'error': 'Dosya yüklenirken hata oluştu'}), 500
    
    
def get_client_ip():
    """
    İstemcinin gerçek IP adresini güvenli şekilde alır.
    Proxy/Load Balancer arkasında da doğru çalışır.
    """
    # Öncelik sırası: X-Forwarded-For > X-Real-IP > remote_addr
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For birden fazla IP içerebilir (virgülle ayrılmış)
        # İlk IP gerçek istemci IP'sidir
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP').strip()
    else:
        ip = request.remote_addr or 'unknown'
    
    # IP uzunluk kontrolü (IPv6 için max 45 karakter)
    if ip and len(ip) > 45:
        ip = ip[:45]
    
    return ip


def get_user_agent():
    """
    İstemcinin User-Agent bilgisini güvenli şekilde alır.
    """
    user_agent = request.headers.get('User-Agent', '')
    # Max 500 karakter (veritabanı sınırı)
    if user_agent and len(user_agent) > 500:
        user_agent = user_agent[:500]
    return user_agent


def log_user_action(user_id, action_type, success=True, details=None):
    """
    Kullanıcı aksiyonunu loglar (5651 Sayılı Kanun Uyumu).
    
    Args:
        user_id: Kullanıcı ID
        action_type: LogActionType sabitlerinden biri
        success: İşlem başarılı mı
        details: Ek detaylar (opsiyonel)
    """
    try:
        ip_address = get_client_ip()
        user_agent = get_user_agent()
        
        log = UserLoginLog(
            user_id=user_id,
            action_type=action_type,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details[:255] if details and len(details) > 255 else details
        )
        db.session.add(log)
        # NOT: db.session.commit() çağırmıyoruz, ana işlemle birlikte commit edilecek
        return log
    except Exception as e:
        app.logger.error(f"Log kaydı hatası: {str(e)}")
        return None
            
            
            

@app.route('/konu_ekleme/<int:id>/<int:sub_id>/<int:unite_id>/icerik_ekleme', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def add_icerik(id, sub_id, unite_id):
    form = IcerikForm()
    unite = Unite.query.get_or_404(unite_id)
    
    try:
        if form.validate_on_submit():
            icerik = Icerik(baslik=form.baslik.data, icerik=form.icerik.data, unite_id=unite_id)
            db.session.add(icerik)
            db.session.commit()
            flash('İçerik başarıyla eklendi!', 'success')
            return redirect(url_for('add_icerik', id=id, sub_id=sub_id, unite_id=unite_id))
    
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('İçerik eklenirken hata oluştu!', 'error')
        app.logger.error(f'DB Hatası: {str(e)}')
    
    icerikler = Icerik.query.filter_by(unite_id=unite_id).order_by(Icerik.id)
    return render_template('add_icerik.html', form=form, unite=unite, icerikler=icerikler, id=id, sub_id=sub_id, unite_id=unite_id)


@app.route('/konu_ekleme/<int:id>/<int:sub_id>/<int:unite_id>/icerik_edit/<int:icerik_id>', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def edit_icerik(id, sub_id, unite_id, icerik_id):
    icerik = Icerik.query.get_or_404(icerik_id)
    unite = Unite.query.get_or_404(unite_id)
    form = IcerikForm()
    
    try:
        if form.validate_on_submit():
            
            # Eski içerikteki resimleri al
            old_images = set(get_image_urls_from_content(icerik.icerik))
            # Yeni içerikteki resimleri al
            new_images = set(get_image_urls_from_content(form.icerik.data))
            # Sadece bu içeriğe ait olup artık kullanılmayan resimleri bul
            unused_images = old_images - new_images
            
            # İçeriği güncelle
            icerik.baslik = form.baslik.data
            icerik.icerik = form.icerik.data
            icerik.updated_at = datetime.utcnow()
            icerik.slug = create_slug(form.baslik.data)
            
            # Değişiklikleri kaydet
            db.session.commit()
            
            # Kullanılmayan resimleri sil
            delete_image_files(unused_images)
            
            flash('İçerik başarıyla güncellendi!', 'success')
            return redirect(url_for('add_icerik', id=id, sub_id=sub_id, unite_id=unite_id))
            
        elif request.method == 'GET':
            form.baslik.data = icerik.baslik
            form.icerik.data = icerik.icerik
            
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Güncelleme sırasında bir hata oluştu!', 'error')
        app.logger.error(f'DB Hatası: {str(e)}')
    
    return render_template('update_icerik.html', form=form, icerik=icerik, unite=unite, id=id, sub_id=sub_id, unite_id=unite_id,kaydedilmis_icerik=icerik.icerik)


@app.route('/konu_ekleme/<int:id>/<int:sub_id>/<int:unite_id>/icerik_delete/<int:icerik_id>', methods=['GET', 'POST'])
@admin_required  # Sadece adminler yeni admin ekleyebilir
def delete_icerik(id, sub_id, unite_id, icerik_id):
    try:
        # İçeriği bul
        icerik = Icerik.query.get_or_404(icerik_id)
        
        # Önce bu içeriğe bağlı soruları bul
        bagli_sorular = Soru.query.filter_by(icerik_id=icerik_id).all()
        
        # Bağlı soruların resimlerini sil
        for soru in bagli_sorular:
            if soru.soru_resim:
                image_path = _abspath_join(app.config['SORU_UPLOAD_FOLDER'], soru.soru_resim)
                if is_within_directory(app.config['SORU_UPLOAD_FOLDER'], image_path) and os.path.exists(image_path):
                    os.remove(image_path)
            
            # Soruyu veritabanından sil
            db.session.delete(soru)
        
        # İçerikteki resimleri bul ve sil
        image_urls = get_image_urls_from_content(icerik.icerik)
        delete_image_files(image_urls)
        
        # İçeriği sil
        db.session.delete(icerik)
        db.session.commit()
        
        flash('İçerik ve bağlı tüm sorular başarıyla silindi!', 'success')
        return redirect(url_for('add_icerik', id=id, sub_id=sub_id, unite_id=unite_id))
        
    except SQLAlchemyError as e:
        db.session.rollback()
        flash('Silme sırasında bir hata oluştu!', 'danger')
        app.logger.error(f'DB Hatası: {str(e)}')
        return redirect(url_for('add_icerik', id=id, sub_id=sub_id, unite_id=unite_id))
    
    
## Soru Ekleme Bölümü


@app.route('/soru_ekleme', methods=['GET', 'POST'])
@admin_required
def add_soru():
    """Admin - Soru Ekleme"""
    try:
        form = SoruEkleForm()

        # ✅ Başlangıç seçeneklerini güvenli şekilde ayarla
        try:
            siniflar = Sinif.query.order_by(Sinif.sinif).all()
            form.sinif.choices = [(0, 'Sınıf Seçiniz')] + [(s.id, s.sinif) for s in siniflar]
        except Exception as e:
            app.logger.error(f"Sınıf seçenekleri yükleme hatası: {str(e)}")
            form.sinif.choices = [(0, 'Sınıf Seçiniz')]
            
        form.ders.choices = [(0, 'Önce Sınıf Seçiniz')]
        form.unite.choices = [(0, 'Önce Ders Seçiniz')]
        form.icerik.choices = [(0, 'Önce Ünite Seçiniz')]

        if request.method == 'POST':
            # ✅ POST isteğinde seçili değerlere göre choices'ları güvenli güncelle
            sinif_id = SecurityService.sanitize_input(str(form.sinif.data), 10) if form.sinif.data else None
            ders_id = SecurityService.sanitize_input(str(form.ders.data), 10) if form.ders.data else None
            unite_id = SecurityService.sanitize_input(str(form.unite.data), 10) if form.unite.data else None
            
            # ✅ Sınıf seçimi güvenli kontrolü
            if sinif_id and sinif_id.isdigit():
                try:
                    dersler = Ders.query.filter_by(sinif_id=int(sinif_id)).all()
                    form.ders.choices = [(0, 'Ders Seçiniz')] + [(d.id, d.ders_adi) for d in dersler]
                except Exception as e:
                    app.logger.error(f"Ders seçenekleri yükleme hatası: {str(e)}")
                    form.ders.choices = [(0, 'Ders Seçiniz')]
            
            # ✅ Ders seçimi güvenli kontrolü
            if ders_id and ders_id.isdigit():
                try:
                    uniteler = Unite.query.filter_by(ders_id=int(ders_id)).all()
                    form.unite.choices = [(0, 'Ünite Seçiniz')] + [(u.id, u.unite) for u in uniteler]
                except Exception as e:
                    app.logger.error(f"Ünite seçenekleri yükleme hatası: {str(e)}")
                    form.unite.choices = [(0, 'Ünite Seçiniz')]
            
            # ✅ Ünite seçimi güvenli kontrolü
            if unite_id and unite_id.isdigit():
                try:
                    icerikler = Icerik.query.filter_by(unite_id=int(unite_id)).all()
                    form.icerik.choices = [(0, 'İçerik Seçiniz')] + [(i.id, i.baslik) for i in icerikler]
                except Exception as e:
                    app.logger.error(f"İçerik seçenekleri yükleme hatası: {str(e)}")
                    form.icerik.choices = [(0, 'İçerik Seçiniz')]

        if form.validate_on_submit():
            try:
                # ✅ Dosya varlık kontrolü
                if 'soru' not in request.files:
                    flash('Soru resmi yüklenmedi!', 'danger')
                    return redirect(request.url)
                
                file = request.files['soru']
                if file.filename == '':
                    flash('Dosya seçilmedi!', 'danger')
                    return redirect(request.url)
                
                # ✅ Dosya güvenlik kontrolü
                if not file or not allowed_file(file.filename):
                    flash('İzin verilmeyen dosya türü! Sadece JPG, JPEG, PNG, GIF dosyaları yüklenebilir.', 'danger')
                    return redirect(request.url)
                
                # ✅ Dosya boyutu kontrolü (5MB maksimum)
                file.seek(0, 2)  # Dosya sonuna git
                file_size = file.tell()
                file.seek(0)  # Başa dön
                
                if file_size > 5 * 1024 * 1024:  # 5MB
                    flash('Dosya boyutu 5MB\'dan büyük olamaz!', 'danger')
                    return redirect(request.url)
                
                # ✅ Form verilerini güvenli şekilde al
                cevap = SecurityService.sanitize_input(form.cevap.data, 10)
                unite_id = form.unite.data
                icerik_id = form.icerik.data
                
                # ✅ Cevap doğrulama - sadece A-E harfleri
                if not cevap or cevap.upper() not in ['A', 'B', 'C', 'D', 'E']:
                    flash('Geçersiz cevap seçimi! Cevap A, B, C, D veya E olmalıdır.', 'danger')
                    return redirect(request.url)
                
                # ✅ İlişki doğrulama - unite ve icerik uyumlu mu?
                if unite_id and icerik_id:
                    icerik_check = Icerik.query.filter_by(id=icerik_id, unite_id=unite_id).first()
                    if not icerik_check:
                        flash('Seçilen ünite ve içerik uyumsuz!', 'danger')
                        return redirect(request.url)
                
                # ✅ Güvenli dosya adı oluştur
                filename = secure_filename(file.filename)
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                unique_filename = f"{timestamp}_{filename}"
                
                # ✅ Dosya kaydetme yolu kontrolü
                upload_path = _abspath_join(app.config['SORU_UPLOAD_FOLDER'], unique_filename)

                # Dosya yolu güvenlik kontrolü
                if not is_within_directory(app.config['SORU_UPLOAD_FOLDER'], upload_path):
                    flash('Güvenlik hatası: Geçersiz dosya yolu!', 'danger')
                    return redirect(request.url)

                # ✅ Dosyayı güvenli şekilde kaydet
                file.save(upload_path)
                
                # ✅ Video yükleme kontrolü (opsiyonel)
                video_path = None
                if form.video.data and form.video.data.filename:
                    video_file = form.video.data
                    if allowed_video_file(video_file.filename):
                        video_filename = secure_filename(video_file.filename)
                        # Benzersiz dosya adı oluştur
                        video_unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_video_{video_filename}"
                        video_upload_path = _abspath_join(app.config['VIDEO_UPLOAD_FOLDER'], video_unique_filename)
                        if not is_within_directory(app.config['VIDEO_UPLOAD_FOLDER'], video_upload_path):
                            flash('Güvenlik hatası: Geçersiz video yolu!', 'danger')
                            return redirect(request.url)
                        video_file.save(video_upload_path)
                        video_path = video_unique_filename
                    else:
                        flash('Geçersiz video formatı. Sadece MP4 desteklenir.', 'danger')
                        return redirect(request.url)
                
                # ✅ Çözüm resmi yükleme kontrolü (opsiyonel)
                cozum_path = None
                if form.cozum_resim.data and form.cozum_resim.data.filename:
                    cozum_file = form.cozum_resim.data
                    if allowed_file(cozum_file.filename):
                        cozum_filename = secure_filename(cozum_file.filename)
                        # Benzersiz dosya adı oluştur
                        cozum_unique_filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_cozum_{cozum_filename}"
                        cozum_upload_path = _abspath_join(app.config['COZUM_UPLOAD_FOLDER'], cozum_unique_filename)
                        if not is_within_directory(app.config['COZUM_UPLOAD_FOLDER'], cozum_upload_path):
                            flash('Güvenlik hatası: Geçersiz çözüm resmi yolu!', 'danger')
                            return redirect(request.url)
                        cozum_file.save(cozum_upload_path)
                        cozum_path = cozum_unique_filename
                    else:
                        flash('Geçersiz çözüm resmi formatı.', 'danger')
                        return redirect(request.url)
                
                # ✅ Soru nesnesini oluştur
                soru = Soru(
                    soru_resim=unique_filename,
                    cevap=cevap.upper(),  # Büyük harfe çevir
                    unite_id=unite_id,
                    icerik_id=icerik_id,
                    video_path=video_path,  # Yeni alan
                    cozum_resim=cozum_path  # Yeni alan
                )
                
                db.session.add(soru)
                db.session.commit()
                
                # ✅ Güvenli log yazma
                app.logger.info(f"Admin {current_user.id} added question - Unite: {unite_id}, Content: {icerik_id}, Answer: {cevap}")
                
                flash('Soru başarıyla eklendi!', 'success')
                return redirect(url_for('add_soru'))
                
            except Exception as e:
                db.session.rollback()

                # ✅ Hata durumunda dosyaları temizle
                if 'unique_filename' in locals():
                    try:
                        error_file_path = _abspath_join(app.config['SORU_UPLOAD_FOLDER'], unique_filename)
                        if is_within_directory(app.config['SORU_UPLOAD_FOLDER'], error_file_path) and os.path.exists(error_file_path):
                            os.remove(error_file_path)
                    except:
                        pass

                # Video ve çözüm dosyalarını da temizle
                if 'video_unique_filename' in locals():
                    try:
                        error_video_path = _abspath_join(app.config['VIDEO_UPLOAD_FOLDER'], video_unique_filename)
                        if is_within_directory(app.config['VIDEO_UPLOAD_FOLDER'], error_video_path) and os.path.exists(error_video_path):
                            os.remove(error_video_path)
                    except:
                        pass

                if 'cozum_unique_filename' in locals():
                    try:
                        error_cozum_path = _abspath_join(app.config['COZUM_UPLOAD_FOLDER'], cozum_unique_filename)
                        if is_within_directory(app.config['COZUM_UPLOAD_FOLDER'], error_cozum_path) and os.path.exists(error_cozum_path):
                            os.remove(error_cozum_path)
                    except:
                        pass

                app.logger.error(f"Question adding error: {str(e)}")
                app.logger.error(traceback.format_exc())
                flash('Soru eklenirken bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
                return redirect(request.url)

        # ✅ Form validation hataları
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')

        return render_template('add_soru.html', 
                             form=form,
                             title='Soru Ekleme')
                             
    except Exception as e:
        app.logger.error(f"Add question page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('admin'))
    
    

@app.route('/admin/homepage-slide/add', methods=['GET', 'POST'])
@admin_required
def add_homepage_slide():
    form = HomepageSlideForm()
    if form.validate_on_submit():
        image_path = None
        image_file = form.image.data
        if image_file:
            filename = secure_filename(image_file.filename)
            upload_folder = os.path.join(current_app.root_path, 'static', 'homepage_slides')
            os.makedirs(upload_folder, exist_ok=True)
            image_file.save(os.path.join(upload_folder, filename))
            image_path = filename

        # Custom URL kontrolü - Eğer 'custom' seçildiyse, custom_url'yi kullan
        if form.button_url.data == 'custom':
            button_url = form.custom_url.data
        elif form.button_url.data == 'tel':
            # Telefon formatını düzenle
            phone = form.phone_number.data.replace(" ", "").replace("-", "")
            button_url = f"tel:{phone}"
        elif form.button_url.data == 'whatsapp':
            # WhatsApp formatını düzenle
            phone = form.phone_number.data.replace(" ", "").replace("-", "")
            if not phone.startswith("90"):  # Türkiye alan kodu
                phone = "90" + phone.lstrip("0")  # Başındaki 0'ı kaldır
            button_url = f"https://wa.me/{phone}"
        else:
            button_url = form.button_url.data

        slide = HomepageSlide(
            title=form.title.data,
            description=form.description.data,
            image_path=image_path,
            button_text=form.button_text.data,
            button_url=button_url,
            badge_text=form.badge_text.data,
            badge_color=form.badge_color.data,
            slide_type=form.slide_type.data,
            order=form.order.data or 0,
            is_active=form.is_active.data
        )
        db.session.add(slide)
        db.session.commit()
        flash('Slayt başarıyla eklendi!', 'success')
        return redirect(url_for('list_homepage_slides'))
    return render_template('admin/add_homepage_slide.html', form=form)




@app.route('/admin/homepage-slides')
@admin_required
def list_homepage_slides():
    slides = HomepageSlide.query.order_by(HomepageSlide.order.asc()).all()
    return render_template('admin/list_homepage_slides.html', slides=slides)




@app.route('/admin/homepage-slide/<int:slide_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_homepage_slide(slide_id):
    slide = HomepageSlide.query.get_or_404(slide_id)
    form = HomepageSlideForm(obj=slide)
    
    if form.validate_on_submit():
        image_file = form.image.data
        if image_file:
            # Mevcut görseli sil
            if slide.image_path:
                old_image_path = os.path.join(current_app.root_path, 'static', 'homepage_slides', slide.image_path)
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
            # Yeni görseli kaydet
            filename = secure_filename(image_file.filename)
            upload_folder = os.path.join(current_app.root_path, 'static', 'homepage_slides')
            os.makedirs(upload_folder, exist_ok=True)
            image_file.save(os.path.join(upload_folder, filename))
            slide.image_path = filename
        
        # Diğer alanları güncelle
        slide.title = form.title.data
        slide.description = form.description.data
        slide.button_text = form.button_text.data
        
        # Custom URL kontrolü - Eğer 'custom' seçildiyse, custom_url'yi kullan
        if form.button_url.data == 'custom':
            slide.button_url = form.custom_url.data
        elif form.button_url.data == 'tel':
            # Telefon formatını düzenle
            phone = form.phone_number.data.replace(" ", "").replace("-", "")
            slide.button_url = f"tel:{phone}"
        elif form.button_url.data == 'whatsapp':
            # WhatsApp formatını düzenle
            phone = form.phone_number.data.replace(" ", "").replace("-", "")
            if not phone.startswith("90"):  # Türkiye alan kodu
                phone = "90" + phone.lstrip("0")  # Başındaki 0'ı kaldır
            slide.button_url = f"https://wa.me/{phone}"
        else:
            slide.button_url = form.button_url.data
            
        slide.badge_text = form.badge_text.data
        slide.badge_color = form.badge_color.data
        slide.slide_type = form.slide_type.data
        slide.order = form.order.data
        slide.is_active = form.is_active.data
        
        db.session.commit()
        flash('Slayt başarıyla güncellendi!', 'success')
        return redirect(url_for('list_homepage_slides'))
    
    # Form ilk yüklendiğinde, eğer URL özel bir URL ise, custom seçeneğini seç
    elif request.method == 'GET':
        # Buton URL'si bilinen bir seçenek değilse, custom olarak ayarla
        known_urls = [choice[0] for choice in form.button_url.choices]
        if slide.button_url and slide.button_url not in known_urls:
            form.button_url.data = 'custom'
            form.custom_url.data = slide.button_url
        
    return render_template('admin/edit_homepage_slide.html', form=form, slide=slide)


@app.route('/admin/homepage-slide/<int:slide_id>/delete', methods=['POST'])
@admin_required
def delete_homepage_slide(slide_id):
    slide = HomepageSlide.query.get_or_404(slide_id)
    # Görsel dosyasını da silmek istersen:
    if slide.image_path:
        image_path = os.path.join(current_app.root_path, 'static', 'homepage_slides', slide.image_path)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(slide)
    db.session.commit()
    flash('Slayt başarıyla silindi!', 'success')
    return redirect(url_for('list_homepage_slides'))



@app.route('/admin/student/<int:student_id>')
@admin_required
def admin_student_detail(student_id):
    """Admin - Öğrenci Detay Sayfası"""
    try:
        # ✅ Güvenli ID kontrolü
        if student_id <= 0:
            flash('Geçersiz öğrenci ID.', 'danger')
            return redirect(url_for('admin_students'))
        
        # ✅ Öğrenci varlık kontrolü - sadece 'user' rolü
        student = User.query.filter_by(id=student_id, role='user').first()
        if not student:
            flash('Öğrenci bulunamadı.', 'danger')
            app.logger.warning(f"Admin {current_user.id} attempted to access non-existent student {student_id}")
            return redirect(url_for('admin_students'))
        
        # ✅ İstatistik servisi - güvenli çağrı
        try:
            stats_service = StudentStatisticsService(student_id)
            comprehensive_stats = stats_service.get_comprehensive_stats()
        except Exception as e:
            app.logger.error(f"Statistics service error for student {student_id}: {str(e)}")
            comprehensive_stats = None
        
        # ✅ Leaderboard servisi - güvenli fallback
        student_leaderboard = None
        try:
            leaderboard_service = LeaderboardService()
            student_leaderboard = leaderboard_service.get_student_leaderboard_data(student_id)
            
            # Güvenli leaderboard yapısı kontrolü
            if not student_leaderboard or not isinstance(student_leaderboard, dict):
                student_leaderboard = None
                
        except Exception as e:
            app.logger.error(f"Leaderboard service error for student {student_id}: {str(e)}")
            student_leaderboard = None
        
        # ✅ Fallback leaderboard yapısı
        if not student_leaderboard:
            student_leaderboard = {
                'daily': {'general': {'my_rank': '?', 'my_points': 0}},
                'weekly': {'general': {'my_rank': '?', 'my_points': 0}}, 
                'monthly': {'general': {'my_rank': '?', 'my_points': 0}},
                'all_time': {'general': {'my_rank': '?', 'my_points': 0}},
                'user_info': {
                    'competition_group_name': f'{student.class_no}. Sınıf Grubu' if student.class_no else 'Standart Grup',
                    'competing_classes': [f"{student.class_no}. Sınıf"] if student.class_no else ['Sınıf Bilgisi Yok'],
                    'school_name': student.school.name if student.school else 'Belirtilmemiş',
                    'district_name': student.school.district.name if student.school and student.school.district else 'Belirtilmemiş',
                    'province_name': student.school.district.province.name if student.school and student.school.district and student.school.district.province else 'Belirtilmemiş'
                }
            }
        
        # ✅ YENİ: Kullanıcı Login Loglarını Al (Son 100 kayıt)
        login_logs = []
        try:
            login_logs = UserLoginLog.query.filter_by(user_id=student_id)\
                .order_by(UserLoginLog.action_date.desc())\
                .limit(100)\
                .all()
        except Exception as e:
            app.logger.error(f"Login logs error for student {student_id}: {str(e)}")
            login_logs = []
        
        # ✅ YENİ: Log istatistikleri
        log_stats = {
            'total_logs': len(login_logs),
            'successful_logins': len([l for l in login_logs if l.action_type == LogActionType.LOGIN and l.success]),
            'failed_logins': len([l for l in login_logs if l.action_type == LogActionType.FAILED_LOGIN]),
            'unique_ips': len(set([l.ip_address for l in login_logs if l.ip_address])),
            'last_login': None,
            'last_login_ip': None
        }
        
        # Son başarılı giriş bilgisi
        last_successful_login = next(
            (l for l in login_logs if l.action_type == LogActionType.LOGIN and l.success), 
            None
        )
        if last_successful_login:
            log_stats['last_login'] = last_successful_login.action_date
            log_stats['last_login_ip'] = last_successful_login.ip_address
        
        # ✅ Güvenli öğrenci JSON verisi
        student_json = {
            "id": student.id,
            "username": SecurityService.sanitize_input(student.username, 50),
            "first_name": SecurityService.sanitize_input(student.first_name, 50) if student.first_name else None,
            "last_name": SecurityService.sanitize_input(student.last_name, 50) if student.last_name else None,
            "class_no": SecurityService.sanitize_input(str(student.class_no), 10) if student.class_no else None,
            "class_name": SecurityService.sanitize_input(student.class_name, 10) if student.class_name else None,
            "school_name": student.school.name if student.school else None,
            "email": student.email,
            "profile_completed": student.profile_completed,
            "is_active": getattr(student, 'is_active', True),
            "date_created": student.date_created.strftime('%Y-%m-%d') if student.date_created else None,
            # ✅ YENİ: IP bilgileri
            "registration_ip": student.registration_ip,
            "last_login_ip": student.last_login_ip
        }
        
        # ✅ Son aktivite bilgileri (güvenli)
        try:
            last_login = db.session.query(UserProgress.tarih).filter_by(
                user_id=student_id
            ).order_by(UserProgress.tarih.desc()).first()
            
            if last_login:
                student_json["last_activity"] = last_login[0].strftime('%Y-%m-%d %H:%M')
            else:
                student_json["last_activity"] = "Hiç aktivite yok"
                
        except Exception as e:
            app.logger.error(f"Last activity query error: {str(e)}")
            student_json["last_activity"] = "Belirlenemedi"
        
        # ✅ Güvenli log yazma - kişisel bilgi yok
        app.logger.info(f"Admin {current_user.id} viewed student detail - Student ID: {student_id}, Has Stats: {bool(comprehensive_stats)}")
        
        return render_template('admin_student_detail.html',
                            student=student,
                            student_json=student_json,
                            stats=comprehensive_stats,
                            leaderboard=student_leaderboard,
                            login_logs=login_logs,  # ✅ YENİ
                            log_stats=log_stats,    # ✅ YENİ
                            LogActionType=LogActionType,  # ✅ YENİ: Template'de kullanmak için
                            title=f'Öğrenci Detayı - {student.username}')
                             
    except Exception as e:
        app.logger.error(f"Admin student detail error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Öğrenci detayları yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('admin_students'))
    


@app.route('/admin/students/bulk-action', methods=['POST'])
@admin_required
def admin_students_bulk_action():
    """Admin - Öğrenciler Toplu İşlem"""
    try:
        form = BulkActionForm()
        
        if form.validate_on_submit():
            # ✅ Input sanitization
            action = SecurityService.sanitize_input(form.action.data, 50)
            student_ids = request.form.getlist('student_ids')
            
            # ✅ Güvenlik kontrolleri
            if not action or action not in ['activate', 'deactivate', 'delete', 'complete_profile', 'change_class']:
                flash('Geçersiz işlem türü.', 'danger')
                return redirect(url_for('admin_students'))
            
            if not student_ids:
                flash('Lütfen işlem yapılacak öğrencileri seçin.', 'warning')
                return redirect(url_for('admin_students'))
            
            # ✅ Student ID'leri sayısal kontrolü
            try:
                student_ids = [int(sid) for sid in student_ids if str(sid).isdigit()]
            except (ValueError, TypeError):
                flash('Geçersiz öğrenci ID formatı.', 'danger')
                return redirect(url_for('admin_students'))
            
            # ✅ Maximum işlem sayısı kontrolü
            if len(student_ids) > 100:
                flash('Tek seferde en fazla 100 öğrenci seçebilirsiniz.', 'warning')
                return redirect(url_for('admin_students'))
            
            # ✅ Sadece 'user' rolündeki öğrencileri getir
            students = User.query.filter(
                User.id.in_(student_ids), 
                User.role == 'user'
            ).all()
            
            if not students:
                flash('Seçilen öğrenciler bulunamadı veya erişim yetkiniz yok.', 'warning')
                return redirect(url_for('admin_students'))
            
            # ✅ Güvenli işlem uygulaması
            processed_count = 0
            
            if action == 'activate':
                for student in students:
                    student.is_active = True
                    processed_count += 1
                flash(f'{processed_count} öğrenci aktif yapıldı.', 'success')
                
            elif action == 'deactivate':
                for student in students:
                    student.is_active = False
                    processed_count += 1
                flash(f'{processed_count} öğrenci pasif yapıldı.', 'success')
                
            elif action == 'delete':
                # ✅ Güvenlik: Admin kendini silemez
                admin_ids = [s.id for s in students if s.role == 'admin']
                if admin_ids:
                    flash('Admin hesapları silinemez.', 'danger')
                    return redirect(url_for('admin_students'))
                
                
            elif action == 'complete_profile':
                for student in students:
                    student.profile_completed = True
                    student.profile_completed_date = datetime.utcnow()
                    processed_count += 1
                flash(f'{processed_count} öğrencinin profili tamamlanmış olarak işaretlendi.', 'success')
                
            elif action == 'change_class':
                # ✅ Yeni sınıf verisi güvenli kontrolü
                new_class = SecurityService.sanitize_input(form.new_class.data, 10)
                
                # İzin verilen sınıf listesi
                allowed_classes = ['5', '6', '7', '8', '9', '10', '11', '12', 'LGS', 'TYT', 'AYT']
                
                if not new_class or new_class not in allowed_classes:
                    flash('Geçerli bir sınıf seçmelisiniz.', 'warning')
                    return redirect(url_for('admin_students'))
                
                for student in students:
                    student.class_no = new_class
                    processed_count += 1
                flash(f'{processed_count} öğrencinin sınıfı {new_class} olarak değiştirildi.', 'success')
            
            # ✅ Güvenli log yazma
            app.logger.info(f"Admin {current_user.id} performed bulk action '{action}' on {processed_count} students")
            
            db.session.commit()
        else:
            # Form validation hatası
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')
        
        return redirect(url_for('admin_students'))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Admin bulk action error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Toplu işlem sırasında hata oluştu.', 'danger')
        return redirect(url_for('admin_students'))
    
    
    


@app.route('/admin/student/<int:student_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_student_edit(student_id):
    """Admin - Öğrenci Düzenleme"""
    try:
        # ✅ Güvenli ID kontrolü
        if student_id <= 0:
            flash('Geçersiz öğrenci ID.', 'danger')
            return redirect(url_for('admin_students'))
        
        # ✅ Öğrenci varlık kontrolü - sadece 'user' rolü
        student = User.query.filter_by(id=student_id, role='user').first()
        if not student:
            flash('Öğrenci bulunamadı.', 'danger')
            app.logger.warning(f"Admin {current_user.id} attempted to edit non-existent student {student_id}")
            return redirect(url_for('admin_students'))
        
        # ✅ Form oluştur ve güvenli seçenekler ekle
        form = AdminStudentEditForm(obj=student)
        
        # ✅ Sınıf seçenekleri - izin verilen değerler
        allowed_classes = ['5', '6', '7', '8', '9', '10', '11', '12', 'LGS', 'TYT', 'AYT']
        form.class_no.choices = [('', 'Sınıf Seçiniz')] + [
            (cls, f'{cls}. Sınıf' if cls.isdigit() else f'{cls} Hazırlık') 
            for cls in allowed_classes
        ]
        
        # ✅ Okul seçenekleri - güvenli sorgu
        try:
            schools = db.session.query(School, District, Province).join(
                District, School.district_id == District.id
            ).join(
                Province, District.province_id == Province.id
            ).order_by(School.name).all()
            
            form.school_id.choices = [('', 'Okul Seçiniz')] + [
                (str(school.id), f"{school.name} - {district.name}/{province.name}") 
                for school, district, province in schools
            ]
        except Exception as e:
            app.logger.error(f"School options loading error: {str(e)}")
            form.school_id.choices = [('', 'Okul Seçiniz')]
        
        if form.validate_on_submit():
            try:
                # ✅ Input sanitization
                new_username = SecurityService.sanitize_input(form.username.data, 50)
                new_email = SecurityService.sanitize_input(form.email.data, 100)
                new_first_name = SecurityService.sanitize_input(form.first_name.data, 50)
                new_last_name = SecurityService.sanitize_input(form.last_name.data, 50)
                new_class_name = SecurityService.sanitize_input(form.class_name.data, 10)
                
                # ✅ Sınıf doğrulama
                new_class_no = form.class_no.data
                if new_class_no and new_class_no not in allowed_classes:
                    flash('Geçersiz sınıf seçimi.', 'danger')
                    return redirect(url_for('admin_student_edit', student_id=student_id))
                
                # ✅ Okul ID doğrulama
                new_school_id = None
                if form.school_id.data:
                    try:
                        new_school_id = int(form.school_id.data)
                        # Okul var mı kontrol et
                        if not School.query.get(new_school_id):
                            flash('Geçersiz okul seçimi.', 'danger')
                            return redirect(url_for('admin_student_edit', student_id=student_id))
                    except (ValueError, TypeError):
                        flash('Geçersiz okul ID formatı.', 'danger')
                        return redirect(url_for('admin_student_edit', student_id=student_id))
                
                # ✅ Username benzersizlik kontrolü
                if new_username != student.username:
                    existing_user = User.query.filter(
                        User.username == new_username,
                        User.id != student_id
                    ).first()
                    if existing_user:
                        flash('Bu kullanıcı adı zaten kullanılıyor.', 'danger')
                        return redirect(url_for('admin_student_edit', student_id=student_id))
                
                # ✅ Email benzersizlik kontrolü
                if new_email != student.email:
                    existing_email = User.query.filter(
                        User.email == new_email,
                        User.id != student_id
                    ).first()
                    if existing_email:
                        flash('Bu e-mail adresi zaten kullanılıyor.', 'danger')
                        return redirect(url_for('admin_student_edit', student_id=student_id))
                
                # ✅ Güvenli güncelleme
                old_data = {
                    'username': student.username,
                    'email': student.email,
                    'class_no': student.class_no,
                    'school_id': student.school_id
                }
                
                student.username = new_username
                student.email = new_email
                student.first_name = new_first_name
                student.last_name = new_last_name
                student.class_no = new_class_no
                student.class_name = new_class_name
                student.school_id = new_school_id
                student.profile_completed = form.profile_completed.data
                student.is_active = getattr(form, 'is_active', True)  # Form'da varsa
                
                # ✅ Şifre değişikliği - güvenli
                if form.password.data and len(form.password.data.strip()) > 0:
                    # Şifre uzunluk kontrolü
                    password = form.password.data.strip()
                    if len(password) < 6:
                        flash('Şifre en az 6 karakter olmalıdır.', 'danger')
                        return redirect(url_for('admin_student_edit', student_id=student_id))
                    
                    student.password = bcrypt.generate_password_hash(password).decode('utf-8')
                
                db.session.commit()
                
                # ✅ Güvenli log yazma
                changes = []
                for key, old_value in old_data.items():
                    new_value = getattr(student, key)
                    if old_value != new_value:
                        changes.append(key)
                
                app.logger.info(f"Admin {current_user.id} updated student {student_id} - Changed fields: {changes}")
                
                flash(f'{student.username} başarıyla güncellendi.', 'success')
                return redirect(url_for('admin_student_detail', student_id=student.id))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Student update error: {str(e)}")
                app.logger.error(traceback.format_exc())
                flash('Öğrenci güncellenirken hata oluştu.', 'danger')
        else:
            # ✅ Form validation hataları
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')
        
        return render_template('admin_student_edit.html',
                             form=form,
                             student=student,
                             title=f'Öğrenci Düzenle - {student.username}')
                             
    except Exception as e:
        app.logger.error(f"Admin student edit error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Öğrenci düzenleme sayfası yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('admin_students'))
    
    
    

@app.route('/admin/student/<int:student_id>/delete', methods=['POST'])
@admin_required
def admin_student_delete(student_id):
    """Admin - Öğrenci Silme"""
    try:
        student = User.query.filter_by(id=student_id, role='user').first()
        if not student:
            flash('Öğrenci bulunamadı.', 'danger')
            return redirect(url_for('admin_students'))
        
        username = student.username
        db.session.delete(student)
        db.session.commit()
        
        flash(f'{username} başarıyla silindi.', 'success')
        return redirect(url_for('admin_students'))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Student delete error: {str(e)}")
        flash('Öğrenci silinirken hata oluştu.', 'danger')
        return redirect(url_for('admin_students'))
    
    

    
@app.route('/admin/provinces', methods=['GET', 'POST'])
@admin_required
def admin_provinces():
    """Admin - İl Yönetimi - Güvenli"""
    try:
        provinces = Province.query.order_by(Province.name).all()
        
        if request.method == 'POST':
            # ✅ Input sanitization
            name = SecurityService.sanitize_input(request.form.get('name', '').strip(), 100)
            code = SecurityService.sanitize_input(request.form.get('code', '').strip(), 10)
            
            # ✅ Güvenlik kontrolleri
            if not name or not code:
                flash('İl adı ve kodu boş olamaz!', 'danger')
                return redirect(url_for('admin_provinces'))
            
            # ✅ Veri doğrulama
            if len(name) < 2:
                flash('İl adı en az 2 karakter olmalıdır.', 'warning')
                return redirect(url_for('admin_provinces'))
            
            if len(code) < 1 or len(code) > 3:
                flash('İl kodu 1-3 karakter arasında olmalıdır.', 'warning')
                return redirect(url_for('admin_provinces'))
            
            # ✅ Kod formatı kontrolü (sadece rakam)
            if not code.isdigit():
                flash('İl kodu sadece rakam içermelidir.', 'warning')
                return redirect(url_for('admin_provinces'))
            
            # ✅ Benzersizlik kontrolleri - güvenli sorgular
            existing_name = Province.query.filter_by(name=name).first()
            if existing_name:
                flash('Bu isimde bir il zaten mevcut!', 'warning')
                return redirect(url_for('admin_provinces'))
            
            existing_code = Province.query.filter_by(code=code).first()
            if existing_code:
                flash('Bu kodda bir il zaten mevcut!', 'warning')
                return redirect(url_for('admin_provinces'))
            
            try:
                # ✅ Güvenli il oluşturma
                province = Province(name=name, code=code)
                db.session.add(province)
                db.session.commit()
                
                # ✅ Güvenli log yazma
                app.logger.info(f"Admin {current_user.id} added province - Name: {name}, Code: {code}")
                
                flash('İl başarıyla eklendi!', 'success')
                return redirect(url_for('admin_provinces'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Province creation error: {str(e)}")
                flash('İl eklenirken bir hata oluştu.', 'danger')
                return redirect(url_for('admin_provinces'))
        
        return render_template('admin_provinces.html', 
                             provinces=provinces, 
                             title='İl Yönetimi')
                             
    except Exception as e:
        app.logger.error(f"Admin provinces error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('admin'))

@app.route('/admin/province/<int:province_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_province_edit(province_id):
    """Admin - İl Düzenleme - Güvenli"""
    try:
        # ✅ Güvenli ID kontrolü
        if province_id <= 0:
            flash('Geçersiz il ID.', 'danger')
            return redirect(url_for('admin_provinces'))
        
        # ✅ İl varlık kontrolü
        province = Province.query.get_or_404(province_id)
        
        if request.method == 'POST':
            # ✅ Input sanitization
            name = SecurityService.sanitize_input(request.form.get('name', '').strip(), 100)
            code = SecurityService.sanitize_input(request.form.get('code', '').strip(), 10)
            
            # ✅ Güvenlik kontrolleri
            if not name or not code:
                flash('İl adı ve kodu boş olamaz!', 'danger')
                return redirect(url_for('admin_province_edit', province_id=province_id))
            
            # ✅ Veri doğrulama
            if len(name) < 2:
                flash('İl adı en az 2 karakter olmalıdır.', 'warning')
                return redirect(url_for('admin_province_edit', province_id=province_id))
            
            if len(code) < 1 or len(code) > 3:
                flash('İl kodu 1-3 karakter arasında olmalıdır.', 'warning')
                return redirect(url_for('admin_province_edit', province_id=province_id))
            
            # ✅ Kod formatı kontrolü
            if not code.isdigit():
                flash('İl kodu sadece rakam içermelidir.', 'warning')
                return redirect(url_for('admin_province_edit', province_id=province_id))
            
            # ✅ Benzersizlik kontrolleri - mevcut kayıt hariç
            existing_name = Province.query.filter(
                Province.name == name,
                Province.id != province_id
            ).first()
            if existing_name:
                flash('Bu isimde başka bir il zaten mevcut!', 'warning')
                return redirect(url_for('admin_province_edit', province_id=province_id))
            
            existing_code = Province.query.filter(
                Province.code == code,
                Province.id != province_id
            ).first()
            if existing_code:
                flash('Bu kodda başka bir il zaten mevcut!', 'warning')
                return redirect(url_for('admin_province_edit', province_id=province_id))
            
            try:
                # ✅ Güvenli güncelleme
                old_name = province.name
                old_code = province.code
                
                province.name = name
                province.code = code
                db.session.commit()
                
                # ✅ Güvenli log yazma
                app.logger.info(f"Admin {current_user.id} updated province {province_id} - Old: {old_name}({old_code}), New: {name}({code})")
                
                flash('İl başarıyla güncellendi!', 'success')
                return redirect(url_for('admin_provinces'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Province update error: {str(e)}")
                flash('İl güncellenirken bir hata oluştu.', 'danger')
                return redirect(url_for('admin_province_edit', province_id=province_id))
        
        return render_template('admin_province_edit.html', 
                             province=province, 
                             title='İl Düzenle')
                             
    except Exception as e:
        app.logger.error(f"Admin province edit error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('admin_provinces'))

@app.route('/admin/province/<int:province_id>/delete', methods=['POST'])
@admin_required
def admin_province_delete(province_id):
    """Admin - İl Silme - Güvenli"""
    try:
        # ✅ Güvenli ID kontrolü
        if province_id <= 0:
            flash('Geçersiz il ID.', 'danger')
            return redirect(url_for('admin_provinces'))
        
        # ✅ İl varlık kontrolü
        province = Province.query.get_or_404(province_id)
        
        # ✅ Bağımlılık kontrolü - ilçe var mı?
        district_count = District.query.filter_by(province_id=province_id).count()
        if district_count > 0:
            flash(f'Bu ile bağlı {district_count} ilçe bulunduğu için silinemez.', 'warning')
            return redirect(url_for('admin_provinces'))
        
        # ✅ Güvenli CSRF token kontrolü
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.form.get('csrf_token'))
        except:
            flash('Güvenlik hatası. Sayfayı yenileyin.', 'danger')
            return redirect(url_for('admin_provinces'))
        
        try:
            # ✅ Güvenli silme
            province_name = province.name
            db.session.delete(province)
            db.session.commit()
            
            # ✅ Güvenli log yazma
            app.logger.info(f"Admin {current_user.id} deleted province - Name: {province_name}, ID: {province_id}")
            
            flash('İl başarıyla silindi.', 'success')
            return redirect(url_for('admin_provinces'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Province delete error: {str(e)}")
            flash('Silme sırasında hata oluştu.', 'danger')
            return redirect(url_for('admin_provinces'))
            
    except Exception as e:
        app.logger.error(f"Admin province delete error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Silme işlemi sırasında hata oluştu.', 'danger')
        return redirect(url_for('admin_provinces'))





@app.route('/admin/districts', methods=['GET', 'POST'])
@admin_required
def admin_districts():
    provinces = Province.query.order_by(Province.name).all()
    province_id = request.args.get('province_id', type=int)
    if province_id:
        districts = District.query.filter_by(province_id=province_id).order_by(District.name).all()
    else:
        districts = District.query.order_by(District.name).all()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        province_id_form = request.form.get('province_id', type=int)
        if not name or not province_id_form:
            flash('İlçe adı ve il seçimi zorunludur.', 'danger')
        else:
            # Aynı isimde ilçe var mı kontrol et (aynı ilde)
            if District.query.filter_by(name=name, province_id=province_id_form).first():
                flash('Bu ilde aynı isimde bir ilçe zaten mevcut!', 'warning')
            else:
                district = District(name=name, province_id=province_id_form)
                db.session.add(district)
                db.session.commit()
                flash('İlçe başarıyla eklendi!', 'success')
        return redirect(url_for('admin_districts', province_id=province_id_form or province_id))
    return render_template('admin_districts.html', districts=districts, provinces=provinces, province_id=province_id, title='İlçe Yönetimi')

@app.route('/admin/district/<int:district_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_district_edit(district_id):
    district = District.query.get_or_404(district_id)
    provinces = Province.query.order_by(Province.name).all()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        province_id_form = request.form.get('province_id', type=int)
        if not name or not province_id_form:
            flash('İlçe adı ve il seçimi zorunludur.', 'danger')
        else:
            # Aynı isimde ilçe var mı kontrol et (aynı ilde)
            existing = District.query.filter(
                District.name == name,
                District.province_id == province_id_form,
                District.id != district_id
            ).first()
            if existing:
                flash('Bu ilde aynı isimde başka bir ilçe zaten mevcut!', 'warning')
            else:
                district.name = name
                district.province_id = province_id_form
                db.session.commit()
                flash('İlçe başarıyla güncellendi!', 'success')
                return redirect(url_for('admin_districts', province_id=province_id_form))
    return render_template('admin_district_edit.html', district=district, provinces=provinces, title='İlçe Düzenle')

@app.route('/admin/district/<int:district_id>/delete', methods=['POST'])
@admin_required
def admin_district_delete(district_id):
    district = District.query.get_or_404(district_id)
    province_id = district.province_id
    try:
        db.session.delete(district)
        db.session.commit()
        flash('İlçe başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Silme sırasında hata oluştu.', 'danger')
    return redirect(url_for('admin_districts', province_id=province_id))




@app.route('/admin/schools', methods=['GET', 'POST'])
@admin_required
def admin_schools():
    provinces = Province.query.order_by(Province.name).all()
    districts = []
    schools = []
    province_id = request.args.get('province_id', type=int)
    district_id = request.args.get('district_id', type=int)
    school_type_id = request.args.get('school_type_id', type=int)
    school_types = SchoolType.query.order_by(SchoolType.name).all()

    # Filtreye göre ilçeleri getir
    if province_id:
        districts = District.query.filter_by(province_id=province_id).order_by(District.name).all()
    else:
        districts = []

    # Okul filtreleme: İl/ilçe seçilmeden okul listesi BOŞ gelsin
    if district_id:
        schools = School.query.filter_by(district_id=district_id).order_by(School.name).all()
    elif province_id:
        district_ids = [d.id for d in District.query.filter_by(province_id=province_id).all()]
        schools = School.query.filter(School.district_id.in_(district_ids)).order_by(School.name).all()
    else:
        schools = []  # Açılışta okul listesi boş

    # Okul türü filtresi uygula
    if school_type_id:
        schools = [s for s in schools if s.school_type_id == school_type_id]

    # Okul ekleme
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        district_id_form = request.form.get('district_id', type=int)
        school_type_id_form = request.form.get('school_type_id', type=int)
        if not name or not district_id_form or not school_type_id_form:
            flash('Okul adı, ilçe ve okul türü zorunludur.', 'danger')
        else:
            if School.query.filter_by(name=name, district_id=district_id_form).first():
                flash('Bu ilçede aynı isimde bir okul zaten mevcut!', 'warning')
            else:
                school = School(name=name, district_id=district_id_form, school_type_id=school_type_id_form)
                db.session.add(school)
                db.session.commit()
                flash('Okul başarıyla eklendi!', 'success')
        return redirect(url_for('admin_schools', province_id=province_id, district_id=district_id, school_type_id=school_type_id))

    return render_template(
        'admin_schools.html',
        schools=schools,
        provinces=provinces,
        districts=districts,
        school_types=school_types,
        province_id=province_id,
        district_id=district_id,
        school_type_id=school_type_id,
        title='Okul Yönetimi'
    )



@app.route('/admin/school/<int:school_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_school_edit(school_id):
    school = School.query.get_or_404(school_id)
    provinces = Province.query.order_by(Province.name).all()
    districts = District.query.filter_by(province_id=school.district.province_id).order_by(District.name).all()
    school_types = SchoolType.query.order_by(SchoolType.name).all()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        district_id = request.form.get('district_id', type=int)
        school_type_id = request.form.get('school_type_id', type=int)
        if not name or not district_id or not school_type_id:
            flash('Okul adı, ilçe ve okul türü zorunludur.', 'danger')
        else:
            existing = School.query.filter(
                School.name == name,
                School.district_id == district_id,
                School.id != school_id
            ).first()
            if existing:
                flash('Bu ilçede aynı isimde başka bir okul zaten mevcut!', 'warning')
            else:
                school.name = name
                school.district_id = district_id
                school.school_type_id = school_type_id
                db.session.commit()
                flash('Okul başarıyla güncellendi!', 'success')
                return redirect(url_for('admin_schools', province_id=school.district.province_id, district_id=school.district_id, school_type_id=school.school_type_id))
    return render_template('admin_school_edit.html', school=school, provinces=provinces, districts=districts, school_types=school_types, title='Okul Düzenle')

@app.route('/admin/school/<int:school_id>/delete', methods=['POST'])
@admin_required
def admin_school_delete(school_id):
    school = School.query.get_or_404(school_id)
    province_id = school.district.province_id
    district_id = school.district_id
    school_type_id = school.school_type_id
    try:
        db.session.delete(school)
        db.session.commit()
        flash('Okul başarıyla silindi.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Silme sırasında hata oluştu.', 'danger')
    return redirect(url_for('admin_schools', province_id=province_id, district_id=district_id, school_type_id=school_type_id)) 

  
@app.route('/admin/students')
@admin_required
def admin_students():
    """Admin - Öğrenci Listesi"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        # Filtreleme parametreleri
        search = request.args.get('search', '').strip()
        class_filter = request.args.get('class_no', '')
        status_filter = request.args.get('status', '')
        
        # Base query - sadece 'user' rolündeki kullanıcılar
        query = User.query.filter_by(role='user')
        
        # Arama filtresi
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                db.or_(
                    User.username.ilike(search_term),
                    User.email.ilike(search_term),
                    User.first_name.ilike(search_term),
                    User.last_name.ilike(search_term)
                )
            )
        
        # Sınıf filtresi
        if class_filter:
            query = query.filter(User.class_no == class_filter)
        
        # Durum filtresi
        if status_filter == 'active':
            query = query.filter(User.is_active == True)
        elif status_filter == 'inactive':
            query = query.filter(User.is_active == False)
        elif status_filter == 'profile_incomplete':
            query = query.filter(User.profile_completed == False)
        
        # Sıralama ve sayfalama
        pagination = query.order_by(User.date_created.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        students = pagination.items
        
        # İstatistikler
        total_students = User.query.filter_by(role='user').count()
        active_students = User.query.filter_by(role='user', is_active=True).count()
        profile_completed = User.query.filter_by(role='user', profile_completed=True).count()
        
        # Sınıf listesi (filtre için)
        class_options = ['5', '6', '7', '8', '9', '10', '11', '12', 'LGS', 'TYT', 'AYT']
        
        # Form nesnesi (toplu işlemler için)
        form = BulkActionForm()
        
        return render_template('admin_students.html',
                             students=students,
                             pagination=pagination,
                             search=search,
                             class_filter=class_filter,
                             status_filter=status_filter,
                             class_options=class_options,
                             total_students=total_students,
                             active_students=active_students,
                             profile_completed=profile_completed,
                             form=form,
                             title='Öğrenci Yönetimi')
                             
    except Exception as e:
        app.logger.error(f"Admin students list error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Öğrenci listesi yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('admin'))



@app.route('/get_dersler/<int:sinif_id>')
def get_dersler(sinif_id):
    dersler = Ders.query.filter_by(sinif_id=sinif_id).all()
    return jsonify([{'id': d.id, 'ders_adi': d.ders_adi} for d in dersler])

@app.route('/get_uniteler/<int:ders_id>')
def get_uniteler(ders_id):
    uniteler = Unite.query.filter_by(ders_id=ders_id).all()
    return jsonify([{'id': u.id, 'unite': u.unite} for u in uniteler])

@app.route('/get_icerikler/<int:unite_id>')
def get_icerikler(unite_id):
    icerikler = Icerik.query.filter_by(unite_id=unite_id).all()
    return jsonify([{'id': i.id, 'baslik': i.baslik} for i in icerikler])



@app.route('/admin/sorular', methods=['GET'])
@login_required
@admin_required
def list_sorular():
    # Form nesnesi
    form = SoruEkleForm()
    
    # Sayfalama parametresi
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Filtreleme parametreleri
    sinif_id = request.args.get('sinif_id', type=int)
    ders_id = request.args.get('ders_id', type=int)
    unite_id = request.args.get('unite_id', type=int)
    icerik_id = request.args.get('icerik_id', type=int)
    
    # Referans Kodu filtresi
    reference_code = request.args.get('reference_code', '')
    
    # Tüm sınıfları getir (filtreleme için)
    siniflar = Sinif.query.order_by(Sinif.sinif).all() 
    
    # Ders filtreleme
    dersler = []
    if sinif_id:
        dersler = Ders.query.filter_by(sinif_id=sinif_id).order_by(Ders.ders_adi).all()
    
    # Ünite filtreleme
    uniteler = []
    if ders_id:
        uniteler = Unite.query.filter_by(ders_id=ders_id).order_by(Unite.unite).all()
    
    # İçerik filtreleme
    icerikler = []
    if unite_id:
        icerikler = Icerik.query.filter_by(unite_id=unite_id).order_by(Icerik.baslik).all()
    
    # ✅ DÜZELTİLDİ: Sorgu oluştur - JOIN'ları tek seferde yap
    query = Soru.query
    
    # ✅ Eğer sinif veya ders filtresi varsa, JOIN'ları bir kez yap
    if sinif_id or ders_id:
        query = query.join(Unite, Soru.unite_id == Unite.id).join(Ders, Unite.ders_id == Ders.id)
        
        if sinif_id:
            query = query.filter(Ders.sinif_id == sinif_id)
        if ders_id:
            query = query.filter(Unite.ders_id == ders_id)
    
    # ✅ Ünite filtresi (JOIN gerekmez, Soru tablosunda unite_id var)
    if unite_id:
        query = query.filter(Soru.unite_id == unite_id)
    
    # ✅ İçerik filtresi
    if icerik_id:
        query = query.filter(Soru.icerik_id == icerik_id)
        
    # Referans kodu ile filtreleme
    if reference_code:
        query = query.filter(Soru.reference_code.ilike(f'%{reference_code}%'))
    
    # Pagination
    pagination = query.order_by(Soru.id.desc()).paginate(page=page, per_page=per_page)
    sorular = pagination.items
    
    return render_template(
        'list_sorular.html',
        sorular=sorular,
        siniflar=siniflar,
        dersler=dersler,
        uniteler=uniteler,
        icerikler=icerikler,
        sinif_id=sinif_id,
        ders_id=ders_id,
        unite_id=unite_id,
        icerik_id=icerik_id,
        pagination=pagination,
        form=form,
        reference_code=reference_code
    )
    


@app.route('/soru_edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_soru(id):
    """Admin - Soru Düzenleme - Güvenli"""
    try:
        # ✅ Güvenli ID kontrolü
        if id <= 0:
            flash('Geçersiz soru ID.', 'danger')
            return redirect(url_for('list_sorular'))
        
        # ✅ Soru varlık kontrolü
        soru = Soru.query.get_or_404(id)
        form = SoruEditForm()
        
        # ✅ Select field choices'ları güvenli şekilde ayarla
        try:
            siniflar = Sinif.query.order_by(Sinif.sinif).all()
            form.sinif.choices = [(0, 'Sınıf Seçiniz')] + [(s.id, s.sinif) for s in siniflar]
        except Exception as e:
            app.logger.error(f"Sınıf seçenekleri yükleme hatası: {str(e)}")
            form.sinif.choices = [(0, 'Sınıf Seçiniz')]
        
        # ✅ POST isteğinde seçili değerlere göre choices'ları güncelle
        if request.method == 'POST':
            sinif_id = SecurityService.sanitize_input(str(form.sinif.data), 10) if form.sinif.data else None
            ders_id = SecurityService.sanitize_input(str(form.ders.data), 10) if form.ders.data else None
            unite_id = SecurityService.sanitize_input(str(form.unite.data), 10) if form.unite.data else None
            
            # ✅ Sınıf seçimi güvenli kontrolü
            if sinif_id and sinif_id.isdigit():
                try:
                    dersler = Ders.query.filter_by(sinif_id=int(sinif_id)).all()
                    form.ders.choices = [(0, 'Ders Seçiniz')] + [(d.id, d.ders_adi) for d in dersler]
                except Exception as e:
                    app.logger.error(f"Ders seçenekleri yükleme hatası: {str(e)}")
                    form.ders.choices = [(0, 'Ders Seçiniz')]
            else:
                form.ders.choices = [(0, 'Önce Sınıf Seçiniz')]
            
            # ✅ Ders seçimi güvenli kontrolü
            if ders_id and ders_id.isdigit():
                try:
                    uniteler = Unite.query.filter_by(ders_id=int(ders_id)).all()
                    form.unite.choices = [(0, 'Ünite Seçiniz')] + [(u.id, u.unite) for u in uniteler]
                except Exception as e:
                    app.logger.error(f"Ünite seçenekleri yükleme hatası: {str(e)}")
                    form.unite.choices = [(0, 'Ünite Seçiniz')]
            else:
                form.unite.choices = [(0, 'Önce Ders Seçiniz')]
            
            # ✅ Ünite seçimi güvenli kontrolü
            if unite_id and unite_id.isdigit():
                try:
                    icerikler = Icerik.query.filter_by(unite_id=int(unite_id)).all()
                    form.icerik.choices = [(0, 'İçerik Seçiniz')] + [(i.id, i.baslik) for i in icerikler]
                except Exception as e:
                    app.logger.error(f"İçerik seçenekleri yükleme hatası: {str(e)}")
                    form.icerik.choices = [(0, 'İçerik Seçiniz')]
            else:
                form.icerik.choices = [(0, 'Önce Ünite Seçiniz')]
        else:
            # ✅ GET isteği - mevcut verilere göre seçenekleri ayarla
            try:
                icerik = Icerik.query.get(soru.icerik_id)
                unite = Unite.query.get(soru.unite_id)
                ders = Ders.query.get(unite.ders_id)
                sinif = Sinif.query.get(ders.sinif_id)
                
                dersler = Ders.query.filter_by(sinif_id=sinif.id).all()
                form.ders.choices = [(0, 'Ders Seçiniz')] + [(d.id, d.ders_adi) for d in dersler]
                
                uniteler = Unite.query.filter_by(ders_id=ders.id).all()
                form.unite.choices = [(0, 'Ünite Seçiniz')] + [(u.id, u.unite) for u in uniteler]
                
                icerikler = Icerik.query.filter_by(unite_id=unite.id).all()
                form.icerik.choices = [(0, 'İçerik Seçiniz')] + [(i.id, i.baslik) for i in icerikler]
                
                # Form alanlarını doldur
                form.sinif.data = sinif.id
                form.ders.data = ders.id
                form.unite.data = unite.id
                form.icerik.data = soru.icerik_id
                form.cevap.data = soru.cevap
                
            except Exception as e:
                app.logger.error(f"Mevcut veri yükleme hatası: {str(e)}")
                form.ders.choices = [(0, 'Önce Sınıf Seçiniz')]
                form.unite.choices = [(0, 'Önce Ders Seçiniz')]
                form.icerik.choices = [(0, 'Önce Ünite Seçiniz')]

        if form.validate_on_submit():
            try:
                # ✅ Form verilerini güvenli şekilde al
                cevap = SecurityService.sanitize_input(form.cevap.data, 10)
                unite_id = form.unite.data
                icerik_id = form.icerik.data
                
                # ✅ Cevap doğrulama - sadece A-E harfleri
                if not cevap or cevap.upper() not in ['A', 'B', 'C', 'D', 'E']:
                    flash('Geçersiz cevap seçimi! Cevap A, B, C, D veya E olmalıdır.', 'danger')
                    return redirect(url_for('edit_soru', id=id))
                
                # ✅ İlişki doğrulama - unite ve icerik uyumlu mu?
                if unite_id and icerik_id:
                    icerik_check = Icerik.query.filter_by(id=icerik_id, unite_id=unite_id).first()
                    if not icerik_check:
                        flash('Seçilen ünite ve içerik uyumsuz!', 'danger')
                        return redirect(url_for('edit_soru', id=id))
                
                # ✅ Dosya değiştirildi mi kontrol et - güvenli
                if form.soru.data and form.soru.data.filename:
                    file = form.soru.data
                    
                    # ✅ Dosya güvenlik kontrolü
                    if not allowed_file(file.filename):
                        flash('İzin verilmeyen dosya türü! Sadece JPG, JPEG, PNG, GIF dosyaları yüklenebilir.', 'danger')
                        return redirect(url_for('edit_soru', id=id))
                    
                    # ✅ Dosya boyutu kontrolü (5MB maksimum)
                    file.seek(0, 2)  # Dosya sonuna git
                    file_size = file.tell()
                    file.seek(0)  # Başa dön
                    
                    if file_size > 5 * 1024 * 1024:  # 5MB
                        flash('Dosya boyutu 5MB\'dan büyük olamaz!', 'danger')
                        return redirect(url_for('edit_soru', id=id))
                    
                    # ✅ Eski resmi güvenli şekilde sil
                    if soru.soru_resim:
                        old_image_path = _abspath_join(app.config['SORU_UPLOAD_FOLDER'], soru.soru_resim)
                        try:
                            if is_within_directory(app.config['SORU_UPLOAD_FOLDER'], old_image_path) and os.path.exists(old_image_path):
                                os.remove(old_image_path)
                        except Exception as e:
                            app.logger.error(f"Eski dosya silme hatası: {str(e)}")
                    
                    # ✅ Güvenli dosya adı oluştur
                    filename = secure_filename(file.filename)
                    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                    unique_filename = f"{timestamp}_{filename}"
                    
                    # ✅ Dosya kaydetme yolu kontrolü
                    upload_path = _abspath_join(app.config['SORU_UPLOAD_FOLDER'], unique_filename)

                    # Path traversal saldırısını önle
                    if not is_within_directory(app.config['SORU_UPLOAD_FOLDER'], upload_path):
                        flash('Güvenlik hatası: Geçersiz dosya yolu!', 'danger')
                        return redirect(url_for('edit_soru', id=id))

                    # ✅ Yeni resmi kaydet
                    file.save(upload_path)
                    soru.soru_resim = unique_filename

                # ✅ Video dosyası kontrolü ve yükleme - YENİ
                if form.video.data and form.video.data.filename:
                    video_file = form.video.data
                    
                    # ✅ Video dosyası güvenlik kontrolü
                    if not allowed_video_file(video_file.filename):
                        flash('Geçersiz video formatı. Sadece MP4 desteklenir.', 'danger')
                        return redirect(url_for('edit_soru', id=id))
                    
                    # ✅ Video boyutu kontrolü (20MB maksimum)
                    video_file.seek(0, 2)
                    video_size = video_file.tell()
                    video_file.seek(0)
                    
                    if video_size > 20 * 1024 * 1024:  # 20MB
                        flash('Video boyutu 20MB\'dan büyük olamaz!', 'danger')
                        return redirect(url_for('edit_soru', id=id))
                    
                    # ✅ Eski video dosyasını sil (eğer varsa)
                    if soru.video_path:
                        old_video_path = _abspath_join(app.config['VIDEO_UPLOAD_FOLDER'], soru.video_path)
                        try:
                            if is_within_directory(app.config['VIDEO_UPLOAD_FOLDER'], old_video_path) and os.path.exists(old_video_path):
                                os.remove(old_video_path)
                        except Exception as e:
                            app.logger.error(f"Eski video silme hatası: {str(e)}")
                    
                    # ✅ Güvenli video dosya adı oluştur
                    video_filename = secure_filename(video_file.filename)
                    video_timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                    video_unique_filename = f"{video_timestamp}_video_{video_filename}"
                    
                    # ✅ Video dosya yolu kontrolü
                    video_upload_path = _abspath_join(app.config['VIDEO_UPLOAD_FOLDER'], video_unique_filename)

                    # Path traversal saldırısını önle
                    if not is_within_directory(app.config['VIDEO_UPLOAD_FOLDER'], video_upload_path):
                        flash('Güvenlik hatası: Geçersiz video dosya yolu!', 'danger')
                        return redirect(url_for('edit_soru', id=id))

                    # ✅ Yeni videoyu kaydet
                    video_file.save(video_upload_path)
                    soru.video_path = video_unique_filename

                # ✅ Çözüm resmi kontrolü ve yükleme - YENİ
                if form.cozum_resim.data and form.cozum_resim.data.filename:
                    cozum_file = form.cozum_resim.data
                    
                    # ✅ Çözüm resmi güvenlik kontrolü
                    if not allowed_file(cozum_file.filename):
                        flash('Geçersiz çözüm resmi formatı.', 'danger')
                        return redirect(url_for('edit_soru', id=id))
                    
                    # ✅ Çözüm resmi boyutu kontrolü (5MB maksimum)
                    cozum_file.seek(0, 2)
                    cozum_size = cozum_file.tell()
                    cozum_file.seek(0)
                    
                    if cozum_size > 5 * 1024 * 1024:  # 5MB
                        flash('Çözüm resmi boyutu 5MB\'dan büyük olamaz!', 'danger')
                        return redirect(url_for('edit_soru', id=id))
                    
                    # ✅ Eski çözüm resmini sil (eğer varsa)
                    if soru.cozum_resim:
                        old_cozum_path = _abspath_join(app.config['COZUM_UPLOAD_FOLDER'], soru.cozum_resim)
                        try:
                            if is_within_directory(app.config['COZUM_UPLOAD_FOLDER'], old_cozum_path) and os.path.exists(old_cozum_path):
                                os.remove(old_cozum_path)
                        except Exception as e:
                            app.logger.error(f"Eski çözüm resmi silme hatası: {str(e)}")
                    
                    # ✅ Güvenli çözüm resmi dosya adı oluştur
                    cozum_filename = secure_filename(cozum_file.filename)
                    cozum_timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                    cozum_unique_filename = f"{cozum_timestamp}_cozum_{cozum_filename}"
                    
                    # ✅ Çözüm resmi dosya yolu kontrolü
                    cozum_upload_path = _abspath_join(app.config['COZUM_UPLOAD_FOLDER'], cozum_unique_filename)

                    # Path traversal saldırısını önle
                    if not is_within_directory(app.config['COZUM_UPLOAD_FOLDER'], cozum_upload_path):
                        flash('Güvenlik hatası: Geçersiz çözüm resmi dosya yolu!', 'danger')
                        return redirect(url_for('edit_soru', id=id))

                    # ✅ Yeni çözüm resmini kaydet
                    cozum_file.save(cozum_upload_path)
                    soru.cozum_resim = cozum_unique_filename

                # ✅ Güvenli güncelleme
                old_data = {
                    'cevap': soru.cevap,
                    'unite_id': soru.unite_id,
                    'icerik_id': soru.icerik_id
                }
                
                soru.cevap = cevap.upper()
                soru.unite_id = unite_id
                soru.icerik_id = icerik_id
                
                db.session.commit()
                
                # ✅ Güvenli log yazma
                changes = []
                for key, old_value in old_data.items():
                    new_value = getattr(soru, key)
                    if old_value != new_value:
                        changes.append(key)
                
                app.logger.info(f"Admin {current_user.id} updated question {id} - Changed fields: {changes}")
                
                flash('Soru başarıyla güncellendi!', 'success')
                return redirect(url_for('list_sorular'))
                
            except Exception as e:
                db.session.rollback()
                
                # ✅ Hata durumunda yeni yüklenen dosyaları temizle
                if 'unique_filename' in locals():
                    try:
                        error_file_path = _abspath_join(app.config['SORU_UPLOAD_FOLDER'], unique_filename)
                        if is_within_directory(app.config['SORU_UPLOAD_FOLDER'], error_file_path) and os.path.exists(error_file_path):
                            os.remove(error_file_path)
                    except:
                        pass
                        
                # ✅ Hata durumunda video ve çözüm dosyalarını da temizle - YENİ
                if 'video_unique_filename' in locals():
                    try:
                        error_video_path = _abspath_join(app.config['VIDEO_UPLOAD_FOLDER'], video_unique_filename)
                        if is_within_directory(app.config['VIDEO_UPLOAD_FOLDER'], error_video_path) and os.path.exists(error_video_path):
                            os.remove(error_video_path)
                    except:
                        pass
                
                if 'cozum_unique_filename' in locals():
                    try:
                        error_cozum_path = _abspath_join(app.config['COZUM_UPLOAD_FOLDER'], cozum_unique_filename)
                        if is_within_directory(app.config['COZUM_UPLOAD_FOLDER'], error_cozum_path) and os.path.exists(error_cozum_path):
                            os.remove(error_cozum_path)
                    except:
                        pass
                
                app.logger.error(f"Question update error: {str(e)}")
                app.logger.error(traceback.format_exc())
                flash('Soru güncellenirken bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
                return redirect(url_for('edit_soru', id=id))

        # ✅ Form validation hataları
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')

        return render_template('edit_soru.html', 
                             form=form, 
                             soru=soru,
                             title='Soru Düzenle')
                             
    except Exception as e:
        app.logger.error(f"Edit question page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('list_sorular'))


@app.route('/soru_delete/<int:id>', methods=['POST'])
@admin_required
def delete_soru(id):
    """Admin - Soru Silme - Güvenli"""
    try:
        # ✅ Güvenli ID kontrolü
        if id <= 0:
            flash('Geçersiz soru ID.', 'danger')
            return redirect(url_for('list_sorular'))
        
        # ✅ Soru varlık kontrolü
        soru = Soru.query.get_or_404(id)
        
        # ✅ Güvenli CSRF token kontrolü
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.form.get('csrf_token'))
        except:
            flash('Güvenlik hatası. Sayfayı yenileyin.', 'danger')
            return redirect(url_for('list_sorular'))
        
        # ✅ Admin yetki kontrolü (ek güvenlik)
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Bu işlem için yetkiniz yok.', 'danger')
            return redirect(url_for('list_sorular'))
        
        try:
            # ✅ İlgili UserProgress kayıtlarını temizle (veri bütünlüğü)
            related_progress = UserProgress.query.filter_by(soru_id=id).all()
            progress_count = len(related_progress)
            
            for progress in related_progress:
                db.session.delete(progress)
            
            # ✅ Soru resmini güvenli şekilde sil
            if soru.soru_resim:
                image_path = _abspath_join(app.config['SORU_UPLOAD_FOLDER'], soru.soru_resim)

                # Path traversal saldırısını önle
                if not is_within_directory(app.config['SORU_UPLOAD_FOLDER'], image_path):
                    app.logger.warning(f"Suspicious file path detected: {image_path}")
                else:
                    try:
                        if os.path.exists(image_path):
                            os.remove(image_path)
                            app.logger.info(f"Deleted image file: {soru.soru_resim}")
                    except Exception as e:
                        app.logger.error(f"Image deletion error: {str(e)}")
                        # Dosya silme hatası kritik değil, devam et
            
            # ✅ Soru bilgilerini log için sakla
            soru_info = {
                'id': soru.id,
                'unite_id': soru.unite_id,
                'icerik_id': soru.icerik_id,
                'cevap': soru.cevap,
                'image_name': soru.soru_resim
            }
            
            # ✅ Soruyu veritabanından sil
            db.session.delete(soru)
            db.session.commit()
            
            # ✅ Güvenli log yazma
            app.logger.info(f"Admin {current_user.id} deleted question {id} - Unite: {soru_info['unite_id']}, Content: {soru_info['icerik_id']}, Related progress records: {progress_count}")
            
            flash('Soru ve ilgili tüm veriler başarıyla silindi.', 'success')
            return redirect(url_for('list_sorular'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Question deletion error: {str(e)}")
            app.logger.error(traceback.format_exc())
            flash('Soru silinirken bir hata oluştu.', 'danger')
            return redirect(url_for('list_sorular'))
            
    except Exception as e:
        app.logger.error(f"Delete question page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Silme işlemi sırasında hata oluştu.', 'danger')
        return redirect(url_for('list_sorular'))
    
    


@app.route('/ders_notu_ekle', methods=['GET', 'POST'])
@admin_required
def add_ders_notu():
    """Admin - Ders Notu Ekleme - Güvenli"""
    try:
        form = DersNotuForm()

        # ✅ Başlangıç seçeneklerini güvenli şekilde ayarla
        try:
            siniflar = Sinif.query.order_by(Sinif.sinif).all()
            form.sinif.choices = [(0, 'Sınıf Seçiniz')] + [(s.id, s.sinif) for s in siniflar]
        except Exception as e:
            app.logger.error(f"Sınıf seçenekleri yükleme hatası: {str(e)}")
            form.sinif.choices = [(0, 'Sınıf Seçiniz')]
            
        form.ders.choices = [(0, 'Önce Sınıf Seçiniz')]
        form.unite.choices = [(0, 'Önce Ders Seçiniz')]
        form.icerik.choices = [(0, 'Önce Ünite Seçiniz')]

        if request.method == 'POST':
            # ✅ POST isteğinde seçili değerlere göre choices'ları güvenli güncelle
            sinif_id = SecurityService.sanitize_input(str(form.sinif.data), 10) if form.sinif.data else None
            ders_id = SecurityService.sanitize_input(str(form.ders.data), 10) if form.ders.data else None
            unite_id = SecurityService.sanitize_input(str(form.unite.data), 10) if form.unite.data else None

            # ✅ Sınıf seçimi güvenli kontrolü
            if sinif_id and sinif_id.isdigit():
                try:
                    dersler = Ders.query.filter_by(sinif_id=int(sinif_id)).all()
                    form.ders.choices = [(0, 'Ders Seçiniz')] + [(d.id, d.ders_adi) for d in dersler]
                except Exception as e:
                    app.logger.error(f"Ders seçenekleri yükleme hatası: {str(e)}")
                    form.ders.choices = [(0, 'Ders Seçiniz')]

            # ✅ Ders seçimi güvenli kontrolü
            if ders_id and ders_id.isdigit():
                try:
                    uniteler = Unite.query.filter_by(ders_id=int(ders_id)).all()
                    form.unite.choices = [(0, 'Ünite Seçiniz')] + [(u.id, u.unite) for u in uniteler]
                except Exception as e:
                    app.logger.error(f"Ünite seçenekleri yükleme hatası: {str(e)}")
                    form.unite.choices = [(0, 'Ünite Seçiniz')]

            # ✅ Ünite seçimi güvenli kontrolü
            if unite_id and unite_id.isdigit():
                try:
                    icerikler = Icerik.query.filter_by(unite_id=int(unite_id)).all()
                    form.icerik.choices = [(0, 'İçerik Seçiniz')] + [(i.id, i.baslik) for i in icerikler]
                except Exception as e:
                    app.logger.error(f"İçerik seçenekleri yükleme hatası: {str(e)}")
                    form.icerik.choices = [(0, 'İçerik Seçiniz')]

        if form.validate_on_submit():
            try:
                # ✅ Dosya varlık kontrolü
                if not form.pdf.data or form.pdf.data.filename == '':
                    flash('PDF dosyası seçilmedi!', 'danger')
                    return redirect(request.url)

                file = form.pdf.data
                
                # ✅ Dosya güvenlik kontrolü - PDF dosyası mı?
                if not allowed_pdf_file(file.filename):
                    flash('Sadece PDF dosyası yüklenebilir!', 'danger')
                    return redirect(request.url)
                
                # ✅ Dosya boyutu kontrolü (10MB maksimum)
                file.seek(0, 2)  # Dosya sonuna git
                file_size = file.tell()
                file.seek(0)  # Başa dön
                
                if file_size > 10 * 1024 * 1024:  # 10MB
                    flash('PDF dosyası 10MB\'dan büyük olamaz!', 'danger')
                    return redirect(request.url)
                
                # ✅ MIME type kontrolü (ek güvenlik)
                import mimetypes
                mime_type, _ = mimetypes.guess_type(file.filename)
                allowed_pdf_mimes = ['application/pdf']
                
                if mime_type not in allowed_pdf_mimes:
                    flash('Geçersiz dosya türü! Sadece PDF dosyaları kabul edilir.', 'danger')
                    return redirect(request.url)
                
                # ✅ Form verilerini güvenli şekilde al
                baslik = SecurityService.sanitize_input(form.baslik.data, 200)
                sinif_id = form.sinif.data
                ders_id = form.ders.data
                unite_id = form.unite.data
                icerik_id = form.icerik.data
                
                # ✅ Başlık kontrolü
                if not baslik or len(baslik.strip()) < 3:
                    flash('Başlık en az 3 karakter olmalıdır.', 'warning')
                    return redirect(request.url)
                
                # ✅ İlişki doğrulama - unite ve icerik uyumlu mu?
                if unite_id and icerik_id:
                    icerik_check = Icerik.query.filter_by(id=icerik_id, unite_id=unite_id).first()
                    if not icerik_check:
                        flash('Seçilen ünite ve içerik uyumsuz!', 'danger')
                        return redirect(request.url)
                
                # ✅ Güvenli dosya adı oluştur
                filename = secure_filename(file.filename)
                timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                unique_filename = f"{timestamp}_{filename}"
                
                # ✅ Dosya kaydetme yolu kontrolü
                upload_path = _abspath_join(app.config['PDF_UPLOAD_FOLDER'], unique_filename)

                # Path traversal saldırısını önle
                if not is_within_directory(app.config['PDF_UPLOAD_FOLDER'], upload_path):
                    flash('Güvenlik hatası: Geçersiz dosya yolu!', 'danger')
                    return redirect(request.url)
                
                # ✅ Aynı başlıkta ders notu var mı kontrol et
                existing_note = DersNotu.query.filter_by(
                    baslik=baslik,
                    icerik_id=icerik_id
                ).first()
                if existing_note:
                    flash('Aynı başlıkta bir ders notu zaten mevcut!', 'warning')
                    return redirect(request.url)
                
                # ✅ Dosyayı güvenli şekilde kaydet
                file.save(upload_path)

                # ✅ Ders notu nesnesini oluştur
                ders_notu = DersNotu(
                    baslik=baslik,
                    dosya_adi=unique_filename,
                    sinif_id=sinif_id,
                    ders_id=ders_id,
                    unite_id=unite_id,
                    icerik_id=icerik_id,
                    eklenme_tarihi=datetime.utcnow()
                )
                
                db.session.add(ders_notu)
                db.session.commit()
                
                # ✅ Güvenli log yazma
                app.logger.info(f"Admin {current_user.id} added PDF note - Title: {baslik}, Size: {file_size} bytes, Content: {icerik_id}")
                
                flash('Ders notu başarıyla yüklendi!', 'success')
                return redirect(url_for('add_ders_notu'))
                
            except Exception as e:
                db.session.rollback()
                
                # ✅ Hata durumunda dosyayı temizle
                if 'unique_filename' in locals():
                    try:
                        error_file_path = _abspath_join(app.config['PDF_UPLOAD_FOLDER'], unique_filename)
                        if is_within_directory(app.config['PDF_UPLOAD_FOLDER'], error_file_path) and os.path.exists(error_file_path):
                            os.remove(error_file_path)
                    except:
                        pass
                
                app.logger.error(f"PDF upload error: {str(e)}")
                app.logger.error(traceback.format_exc())
                flash('Ders notu eklenirken bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
                return redirect(request.url)

        # ✅ Form validation hataları
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')

        return render_template('add_ders_notu.html', 
                             form=form,
                             title='Ders Notu Ekleme')
                             
    except Exception as e:
        app.logger.error(f"Add PDF note page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('admin'))

@app.route('/ders_notlari')
@admin_required
def list_ders_notlari():
    try:
        form = DersNotuForm()
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        # Filtreleme parametrelerini al
        sinif_id = request.args.get('sinif_id', type=int)
        ders_id = request.args.get('ders_id', type=int)
        unite_id = request.args.get('unite_id', type=int)
        icerik_id = request.args.get('icerik_id', type=int)
        
        # Base query
        query = DersNotu.query

        # Filtreleri uygula
        if sinif_id:
            query = query.filter(DersNotu.sinif_id == sinif_id)
        if ders_id:
            query = query.filter(DersNotu.ders_id == ders_id)
        if unite_id:
            query = query.filter(DersNotu.unite_id == unite_id)
        if icerik_id:
            query = query.filter(DersNotu.icerik_id == icerik_id)
        
        # Sıralama ve sayfalama
        pagination = query.order_by(DersNotu.eklenme_tarihi.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        ders_notlari = pagination.items
        
        # Filtre seçeneklerini getir
        siniflar = Sinif.query.order_by(Sinif.sinif).all()
        dersler = Ders.query.filter_by(sinif_id=sinif_id).all() if sinif_id else []
        uniteler = Unite.query.filter_by(ders_id=ders_id).all() if ders_id else []
        icerikler = Icerik.query.filter_by(unite_id=unite_id).all() if unite_id else []

        return render_template(
            'list_ders_notlari.html',
            form=form,
            ders_notlari=ders_notlari,
            pagination=pagination,
            siniflar=siniflar,
            dersler=dersler,
            uniteler=uniteler,
            icerikler=icerikler,
            sinif_id=sinif_id,
            ders_id=ders_id,
            unite_id=unite_id,
            icerik_id=icerik_id
        )
                            
    except Exception as e:
        app.logger.error(f'Ders notları listeleme hatası: {str(e)}')
        app.logger.error(traceback.format_exc())
        flash('Ders notları listelenirken bir hata oluştu.', 'error')
        return redirect(url_for('admin'))
    
    


@app.route('/ders_notu_edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_ders_notu(id):
    """Admin - Ders Notu Düzenleme - Güvenli"""
    try:
        # ✅ Güvenli ID kontrolü
        if id <= 0:
            flash('Geçersiz ders notu ID.', 'danger')
            return redirect(url_for('list_ders_notlari'))
        
        # ✅ Ders notu varlık kontrolü
        ders_notu = DersNotu.query.get_or_404(id)
        form = DersNotuEditForm()

        # ✅ İçeriğin bağlı olduğu bilgileri güvenli şekilde al
        try:
            icerik = Icerik.query.get(ders_notu.icerik_id)
            unite = Unite.query.get(icerik.unite_id)
            ders = Ders.query.get(unite.ders_id)
            sinif = Sinif.query.get(ders.sinif_id)
        except Exception as e:
            app.logger.error(f"Related data loading error: {str(e)}")
            flash('İlişkili veriler yüklenirken hata oluştu.', 'danger')
            return redirect(url_for('list_ders_notlari'))

        # ✅ Select field choices'ları güvenli şekilde ayarla
        try:
            siniflar = Sinif.query.order_by(Sinif.sinif).all()
            form.sinif.choices = [(0, 'Sınıf Seçiniz')] + [(s.id, s.sinif) for s in siniflar]
        except Exception as e:
            app.logger.error(f"Sınıf seçenekleri yükleme hatası: {str(e)}")
            form.sinif.choices = [(0, 'Sınıf Seçiniz')]

        if request.method == 'POST':
            # ✅ POST isteğinde seçili değerlere göre choices'ları güvenli güncelle
            sinif_id = SecurityService.sanitize_input(str(form.sinif.data), 10) if form.sinif.data else None
            ders_id = SecurityService.sanitize_input(str(form.ders.data), 10) if form.ders.data else None
            unite_id = SecurityService.sanitize_input(str(form.unite.data), 10) if form.unite.data else None
            
            # ✅ Sınıf seçimi güvenli kontrolü
            if sinif_id and sinif_id.isdigit():
                try:
                    dersler = Ders.query.filter_by(sinif_id=int(sinif_id)).all()
                    form.ders.choices = [(0, 'Ders Seçiniz')] + [(d.id, d.ders_adi) for d in dersler]
                except Exception as e:
                    app.logger.error(f"Ders seçenekleri yükleme hatası: {str(e)}")
                    form.ders.choices = [(0, 'Ders Seçiniz')]
            
            # ✅ Ders seçimi güvenli kontrolü
            if ders_id and ders_id.isdigit():
                try:
                    uniteler = Unite.query.filter_by(ders_id=int(ders_id)).all()
                    form.unite.choices = [(0, 'Ünite Seçiniz')] + [(u.id, u.unite) for u in uniteler]
                except Exception as e:
                    app.logger.error(f"Ünite seçenekleri yükleme hatası: {str(e)}")
                    form.unite.choices = [(0, 'Ünite Seçiniz')]
            
            # ✅ Ünite seçimi güvenli kontrolü
            if unite_id and unite_id.isdigit():
                try:
                    icerikler = Icerik.query.filter_by(unite_id=int(unite_id)).all()
                    form.icerik.choices = [(0, 'İçerik Seçiniz')] + [(i.id, i.baslik) for i in icerikler]
                except Exception as e:
                    app.logger.error(f"İçerik seçenekleri yükleme hatası: {str(e)}")
                    form.icerik.choices = [(0, 'İçerik Seçiniz')]
        else:
            # ✅ GET isteği - mevcut verilere göre seçenekleri ayarla
            try:
                dersler = Ders.query.filter_by(sinif_id=sinif.id).all()
                form.ders.choices = [(0, 'Ders Seçiniz')] + [(d.id, d.ders_adi) for d in dersler]
                
                uniteler = Unite.query.filter_by(ders_id=ders.id).all()
                form.unite.choices = [(0, 'Ünite Seçiniz')] + [(u.id, u.unite) for u in uniteler]
                
                icerikler = Icerik.query.filter_by(unite_id=unite.id).all()
                form.icerik.choices = [(0, 'İçerik Seçiniz')] + [(i.id, i.baslik) for i in icerikler]

                # ✅ Form alanlarını güvenli şekilde doldur
                form.sinif.data = sinif.id
                form.ders.data = ders.id
                form.unite.data = unite.id
                form.icerik.data = ders_notu.icerik_id
                form.baslik.data = ders_notu.baslik
            except Exception as e:
                app.logger.error(f"Form initialization error: {str(e)}")
                flash('Form verileri yüklenirken hata oluştu.', 'danger')
                return redirect(url_for('list_ders_notlari'))

        if form.validate_on_submit():
            try:
                # ✅ Form verilerini güvenli şekilde al
                new_baslik = SecurityService.sanitize_input(form.baslik.data, 200)
                new_icerik_id = form.icerik.data
                
                # ✅ Başlık kontrolü
                if not new_baslik or len(new_baslik.strip()) < 3:
                    flash('Başlık en az 3 karakter olmalıdır.', 'warning')
                    return redirect(url_for('edit_ders_notu', id=id))
                
                # ✅ İçerik doğrulama
                if not new_icerik_id:
                    flash('İçerik seçimi zorunludur.', 'warning')
                    return redirect(url_for('edit_ders_notu', id=id))
                
                # ✅ Aynı başlıkta başka ders notu var mı kontrol et
                if new_baslik != ders_notu.baslik or new_icerik_id != ders_notu.icerik_id:
                    existing_note = DersNotu.query.filter(
                        DersNotu.baslik == new_baslik,
                        DersNotu.icerik_id == new_icerik_id,
                        DersNotu.id != id
                    ).first()
                    if existing_note:
                        flash('Aynı başlıkta bir ders notu zaten mevcut!', 'warning')
                        return redirect(url_for('edit_ders_notu', id=id))
                
                # ✅ PDF dosyası değiştirildi mi kontrol et - güvenli
                if form.pdf.data and form.pdf.data.filename:
                    file = form.pdf.data
                    
                    # ✅ Dosya güvenlik kontrolü
                    if not allowed_pdf_file(file.filename):
                        flash('Sadece PDF dosyası yüklenebilir!', 'danger')
                        return redirect(url_for('edit_ders_notu', id=id))
                    
                    # ✅ Dosya boyutu kontrolü (10MB maksimum)
                    file.seek(0, 2)  # Dosya sonuna git
                    file_size = file.tell()
                    file.seek(0)  # Başa dön
                    
                    if file_size > 10 * 1024 * 1024:  # 10MB
                        flash('PDF dosyası 10MB\'dan büyük olamaz!', 'danger')
                        return redirect(url_for('edit_ders_notu', id=id))
                    
                    # ✅ MIME type kontrolü (ek güvenlik)
                    import mimetypes
                    mime_type, _ = mimetypes.guess_type(file.filename)
                    allowed_pdf_mimes = ['application/pdf']
                    
                    if mime_type not in allowed_pdf_mimes:
                        flash('Geçersiz dosya türü! Sadece PDF dosyaları kabul edilir.', 'danger')
                        return redirect(url_for('edit_ders_notu', id=id))
                    
                    # ✅ Eski PDF'i güvenli şekilde sil
                    if ders_notu.dosya_adi:
                        old_pdf_path = _abspath_join(app.config['PDF_UPLOAD_FOLDER'], ders_notu.dosya_adi)
                        try:
                            if is_within_directory(app.config['PDF_UPLOAD_FOLDER'], old_pdf_path) and os.path.exists(old_pdf_path):
                                os.remove(old_pdf_path)
                                app.logger.info(f"Deleted old PDF: {ders_notu.dosya_adi}")
                        except Exception as e:
                            app.logger.error(f"Old PDF deletion error: {str(e)}")
                    
                    # ✅ Güvenli dosya adı oluştur
                    filename = secure_filename(file.filename)
                    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                    unique_filename = f"{timestamp}_{filename}"
                    
                    # ✅ Dosya kaydetme yolu kontrolü
                    upload_path = _abspath_join(app.config['PDF_UPLOAD_FOLDER'], unique_filename)

                    # Path traversal saldırısını önle
                    if not is_within_directory(app.config['PDF_UPLOAD_FOLDER'], upload_path):
                        flash('Güvenlik hatası: Geçersiz dosya yolu!', 'danger')
                        return redirect(url_for('edit_ders_notu', id=id))

                    # ✅ Yeni PDF'i kaydet
                    file.save(upload_path)
                    ders_notu.dosya_adi = unique_filename

                # ✅ Güvenli güncelleme
                old_data = {
                    'baslik': ders_notu.baslik,
                    'icerik_id': ders_notu.icerik_id
                }
                
                ders_notu.baslik = new_baslik
                ders_notu.icerik_id = new_icerik_id
                
                db.session.commit()
                
                # ✅ Güvenli log yazma
                changes = []
                for key, old_value in old_data.items():
                    new_value = getattr(ders_notu, key)
                    if old_value != new_value:
                        changes.append(key)
                
                app.logger.info(f"Admin {current_user.id} updated PDF note {id} - Changed fields: {changes}")
                
                flash('Ders notu başarıyla güncellendi!', 'success')
                return redirect(url_for('list_ders_notlari'))
                
            except Exception as e:
                db.session.rollback()
                
                # ✅ Hata durumunda yeni yüklenen dosyayı temizle
                if 'unique_filename' in locals():
                    try:
                        error_file_path = _abspath_join(app.config['PDF_UPLOAD_FOLDER'], unique_filename)
                        if is_within_directory(app.config['PDF_UPLOAD_FOLDER'], error_file_path) and os.path.exists(error_file_path):
                            os.remove(error_file_path)
                    except:
                        pass
                
                app.logger.error(f"PDF note update error: {str(e)}")
                app.logger.error(traceback.format_exc())
                flash('Ders notu güncellenirken bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
                return redirect(url_for('edit_ders_notu', id=id))

        # ✅ Form validation hataları
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')
        
        return render_template('edit_ders_notu.html', 
                             form=form, 
                             ders_notu=ders_notu,
                             title='Ders Notu Düzenle')
                             
    except Exception as e:
        app.logger.error(f"Edit PDF note page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('list_ders_notlari'))
  


@app.route('/video_ekle', methods=['GET', 'POST'])
@admin_required
def video_ekle():
    """Admin - Video Ekleme - Güvenli"""
    try:
        form = VideoForm()

        # ✅ Başlangıç seçeneklerini güvenli şekilde ayarla
        try:
            siniflar = Sinif.query.order_by(Sinif.sinif).all()
            form.sinif.choices = [(0, 'Sınıf Seçiniz')] + [(s.id, s.sinif) for s in siniflar]
        except Exception as e:
            app.logger.error(f"Sınıf seçenekleri yükleme hatası: {str(e)}")
            form.sinif.choices = [(0, 'Sınıf Seçiniz')]
            
        form.ders.choices = [(0, 'Önce Sınıf Seçiniz')]
        form.unite.choices = [(0, 'Önce Ders Seçiniz')]
        form.icerik.choices = [(0, 'Önce Ünite Seçiniz')]

        if request.method == 'POST':
            # ✅ POST isteğinde seçili değerlere göre choices'ları güvenli güncelle
            sinif_id = SecurityService.sanitize_input(str(form.sinif.data), 10) if form.sinif.data else None
            ders_id = SecurityService.sanitize_input(str(form.ders.data), 10) if form.ders.data else None
            unite_id = SecurityService.sanitize_input(str(form.unite.data), 10) if form.unite.data else None

            # ✅ Sınıf seçimi güvenli kontrolü
            if sinif_id and sinif_id.isdigit():
                try:
                    dersler = Ders.query.filter_by(sinif_id=int(sinif_id)).all()
                    form.ders.choices = [(0, 'Ders Seçiniz')] + [(d.id, d.ders_adi) for d in dersler]
                except Exception as e:
                    app.logger.error(f"Ders seçenekleri yükleme hatası: {str(e)}")
                    form.ders.choices = [(0, 'Ders Seçiniz')]

            # ✅ Ders seçimi güvenli kontrolü
            if ders_id and ders_id.isdigit():
                try:
                    uniteler = Unite.query.filter_by(ders_id=int(ders_id)).all()
                    form.unite.choices = [(0, 'Ünite Seçiniz')] + [(u.id, u.unite) for u in uniteler]
                except Exception as e:
                    app.logger.error(f"Ünite seçenekleri yükleme hatası: {str(e)}")
                    form.unite.choices = [(0, 'Ünite Seçiniz')]

            # ✅ Ünite seçimi güvenli kontrolü
            if unite_id and unite_id.isdigit():
                try:
                    icerikler = Icerik.query.filter_by(unite_id=int(unite_id)).all()
                    form.icerik.choices = [(0, 'İçerik Seçiniz')] + [(i.id, i.baslik) for i in icerikler]
                except Exception as e:
                    app.logger.error(f"İçerik seçenekleri yükleme hatası: {str(e)}")
                    form.icerik.choices = [(0, 'İçerik Seçiniz')]

        if form.validate_on_submit():
            try:
                # ✅ Form verilerini güvenli şekilde al
                video_url = SecurityService.sanitize_input(form.video_url.data, 500)
                video_title = SecurityService.sanitize_input(form.video_title.data, 200)
                icerik_id = form.icerik.data
                sira = form.sira.data
                
                # ✅ Video URL kontrolü
                if not video_url or len(video_url.strip()) < 10:
                    flash('Geçerli bir video URL\'si giriniz.', 'danger')
                    return redirect(request.url)
                
                # ✅ Video başlığı kontrolü
                if not video_title or len(video_title.strip()) < 3:
                    flash('Video başlığı en az 3 karakter olmalıdır.', 'warning')
                    return redirect(request.url)
                
                # ✅ İçerik ID kontrolü
                if not icerik_id or icerik_id <= 0:
                    flash('Lütfen geçerli bir içerik seçiniz.', 'warning')
                    return redirect(request.url)
                
                # ✅ İçerik varlık kontrolü
                icerik_check = Icerik.query.get(icerik_id)
                if not icerik_check:
                    flash('Seçilen içerik bulunamadı.', 'danger')
                    return redirect(request.url)
                
                # ✅ Video URL format kontrolü (YouTube, Vimeo vb.)
                import re
                valid_patterns = [
                    r'(https?://)?(www\.)?(youtube\.com/watch\?v=|youtu\.be/)',
                    r'(https?://)?(www\.)?vimeo\.com/',
                    r'(https?://)?(www\.)?dailymotion\.com/',
                    r'(https?://)?(www\.)?facebook\.com/.*/videos/'
                ]
                
                is_valid_url = False
                for pattern in valid_patterns:
                    if re.search(pattern, video_url.lower()):
                        is_valid_url = True
                        break
                
                if not is_valid_url:
                    flash('Desteklenmeyen video platformu! YouTube, Vimeo, DailyMotion veya Facebook videoları kabul edilir.', 'warning')
                    return redirect(request.url)
                
                # ✅ Sıra numarası kontrolü
                if sira is None or sira < 0:
                    flash('Geçerli bir sıra numarası giriniz.', 'warning')
                    return redirect(request.url)
                
                # ✅ Aynı içerikte aynı sırada video var mı kontrolü
                existing_video = VideoIcerik.query.filter_by(
                    icerik_id=icerik_id,
                    sira=sira
                ).first()
                if existing_video:
                    flash(f'Bu içerikte {sira} sıra numarasında zaten bir video bulunuyor.', 'warning')
                    return redirect(request.url)
                
                # ✅ Video nesnesini oluştur
                video = VideoIcerik(
                    icerik_id=icerik_id,
                    video_url=video_url.strip(),
                    video_title=video_title.strip(),
                    sira=sira,
                    aktif=True,  # Yeni videolar aktif
                    eklenme_tarihi=datetime.utcnow()
                )
                
                db.session.add(video)
                db.session.commit()
                
                # ✅ Güvenli log yazma
                app.logger.info(f"Admin {current_user.id} added video - Title: {video_title}, Content: {icerik_id}, Order: {sira}")
                
                flash('Video başarıyla eklendi!', 'success')
                return redirect(url_for('video_ekle'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Video adding error: {str(e)}")
                app.logger.error(traceback.format_exc())
                flash('Video eklenirken bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
                return redirect(request.url)

        # ✅ Form validation hataları
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')

        return render_template('video_ekle.html', 
                             form=form,
                             title='Video Ekleme')
                             
    except Exception as e:
        app.logger.error(f"Add video page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('admin'))
    
    
    
@app.route('/video_delete/<int:id>', methods=['POST'])
@admin_required
def delete_video(id):
    video = VideoIcerik.query.get_or_404(id)
    db.session.delete(video)
    db.session.commit()
    flash('Video başarıyla silindi.', 'success')
    return redirect(url_for('list_videolar'))




@app.route('/videolar')
@admin_required
def list_videolar():
    form = VideoForm()
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Her sayfada gösterilecek video sayısı
    
    # Filtreleme parametrelerini al
    sinif_id = request.args.get('sinif_id', type=int)
    ders_id = request.args.get('ders_id', type=int)
    unite_id = request.args.get('unite_id', type=int)
    icerik_id = request.args.get('icerik_id', type=int)
    
    # Base query - İlişkileri tek seferde yükle
    query = VideoIcerik.query.join(VideoIcerik.icerik).join(Icerik.unite).join(Unite.ders).join(Ders.sinif)
    
    # Filtreleri uygula
    if sinif_id:
        query = query.filter(Sinif.id == sinif_id)
    if ders_id:
        query = query.filter(Ders.id == ders_id)
    if unite_id:
        query = query.filter(Unite.id == unite_id)
    if icerik_id:
        query = query.filter(VideoIcerik.icerik_id == icerik_id)
    
    # Sıralama
    query = query.order_by(VideoIcerik.sira.asc())
    
    try:
        # Sayfalama
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        videolar = pagination.items
        
        # Filtre seçeneklerini getir
        siniflar = Sinif.query.order_by(Sinif.sinif).all()
        dersler = Ders.query.filter_by(sinif_id=sinif_id).all() if sinif_id else []
        uniteler = Unite.query.filter_by(ders_id=ders_id).all() if ders_id else []
        icerikler = Icerik.query.filter_by(unite_id=unite_id).all() if unite_id else []

        return render_template('list_videolar.html',
                            form=form,
                            videolar=videolar,
                            pagination=pagination,
                            siniflar=siniflar,
                            dersler=dersler,
                            uniteler=uniteler,
                            icerikler=icerikler,
                            sinif_id=sinif_id,
                            ders_id=ders_id,
                            unite_id=unite_id,
                            icerik_id=icerik_id)
                            
    except Exception as e:
        app.logger.error(f'Video listeleme hatası: {str(e)}')
        flash('Videolar listelenirken bir hata oluştu.', 'error')
        return redirect(url_for('admin'))
    
    
    

@app.route('/video_edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit_video(id):
    """Admin - Video Düzenleme - Güvenli"""
    try:
        # ✅ Güvenli ID kontrolü
        if id <= 0:
            flash('Geçersiz video ID.', 'danger')
            return redirect(url_for('list_videolar'))
        
        # ✅ Video varlık kontrolü
        video = VideoIcerik.query.get_or_404(id)
        form = VideoEditForm()

        # ✅ İçeriğin bağlı olduğu bilgileri güvenli şekilde al
        try:
            icerik = Icerik.query.get(video.icerik_id)
            unite = Unite.query.get(icerik.unite_id)
            ders = Ders.query.get(unite.ders_id)
            sinif = Sinif.query.get(ders.sinif_id)
        except Exception as e:
            app.logger.error(f"Related data loading error: {str(e)}")
            flash('İlişkili veriler yüklenirken hata oluştu.', 'danger')
            return redirect(url_for('list_videolar'))

        # ✅ Select field choices'ları güvenli şekilde ayarla
        try:
            siniflar = Sinif.query.order_by(Sinif.sinif).all()
            form.sinif.choices = [(0, 'Sınıf Seçiniz')] + [(s.id, s.sinif) for s in siniflar]
        except Exception as e:
            app.logger.error(f"Sınıf seçenekleri yükleme hatası: {str(e)}")
            form.sinif.choices = [(0, 'Sınıf Seçiniz')]

        if request.method == 'POST':
            # ✅ POST isteğinde seçili değerlere göre choices'ları güvenli güncelle
            sinif_id = SecurityService.sanitize_input(str(form.sinif.data), 10) if form.sinif.data else None
            ders_id = SecurityService.sanitize_input(str(form.ders.data), 10) if form.ders.data else None
            unite_id = SecurityService.sanitize_input(str(form.unite.data), 10) if form.unite.data else None
            
            # ✅ Sınıf seçimi güvenli kontrolü
            if sinif_id and sinif_id.isdigit():
                try:
                    dersler = Ders.query.filter_by(sinif_id=int(sinif_id)).all()
                    form.ders.choices = [(0, 'Ders Seçiniz')] + [(d.id, d.ders_adi) for d in dersler]
                except Exception as e:
                    app.logger.error(f"Ders seçenekleri yükleme hatası: {str(e)}")
                    form.ders.choices = [(0, 'Ders Seçiniz')]
            
            # ✅ Ders seçimi güvenli kontrolü
            if ders_id and ders_id.isdigit():
                try:
                    uniteler = Unite.query.filter_by(ders_id=int(ders_id)).all()
                    form.unite.choices = [(0, 'Ünite Seçiniz')] + [(u.id, u.unite) for u in uniteler]
                except Exception as e:
                    app.logger.error(f"Ünite seçenekleri yükleme hatası: {str(e)}")
                    form.unite.choices = [(0, 'Ünite Seçiniz')]
            
            # ✅ Ünite seçimi güvenli kontrolü
            if unite_id and unite_id.isdigit():
                try:
                    icerikler = Icerik.query.filter_by(unite_id=int(unite_id)).all()
                    form.icerik.choices = [(0, 'İçerik Seçiniz')] + [(i.id, i.baslik) for i in icerikler]
                except Exception as e:
                    app.logger.error(f"İçerik seçenekleri yükleme hatası: {str(e)}")
                    form.icerik.choices = [(0, 'İçerik Seçiniz')]
        else:
            # ✅ GET isteği - mevcut verilere göre seçenekleri ayarla
            try:
                dersler = Ders.query.filter_by(sinif_id=sinif.id).all()
                form.ders.choices = [(0, 'Ders Seçiniz')] + [(d.id, d.ders_adi) for d in dersler]
                
                uniteler = Unite.query.filter_by(ders_id=ders.id).all()
                form.unite.choices = [(0, 'Ünite Seçiniz')] + [(u.id, u.unite) for u in uniteler]
                
                icerikler = Icerik.query.filter_by(unite_id=unite.id).all()
                form.icerik.choices = [(0, 'İçerik Seçiniz')] + [(i.id, i.baslik) for i in icerikler]

                # ✅ Form alanlarını güvenli şekilde doldur
                form.sinif.data = sinif.id
                form.ders.data = ders.id
                form.unite.data = unite.id
                form.icerik.data = video.icerik_id
                form.video_url.data = video.video_url
                form.video_title.data = video.video_title
                form.sira.data = video.sira
            except Exception as e:
                app.logger.error(f"Form initialization error: {str(e)}")
                flash('Form verileri yüklenirken hata oluştu.', 'danger')
                return redirect(url_for('list_videolar'))

        if form.validate_on_submit():
            try:
                # ✅ Form verilerini güvenli şekilde al
                new_video_url = SecurityService.sanitize_input(form.video_url.data, 500)
                new_video_title = SecurityService.sanitize_input(form.video_title.data, 200)
                new_icerik_id = form.icerik.data
                new_sira = form.sira.data
                
                # ✅ Video URL kontrolü
                if not new_video_url or len(new_video_url.strip()) < 10:
                    flash('Geçerli bir video URL\'si giriniz.', 'danger')
                    return redirect(url_for('edit_video', id=id))
                
                # ✅ Video başlığı kontrolü
                if not new_video_title or len(new_video_title.strip()) < 3:
                    flash('Video başlığı en az 3 karakter olmalıdır.', 'warning')
                    return redirect(url_for('edit_video', id=id))
                
                # ✅ İçerik ID kontrolü
                if not new_icerik_id or new_icerik_id <= 0:
                    flash('Lütfen geçerli bir içerik seçiniz.', 'warning')
                    return redirect(url_for('edit_video', id=id))
                
                # ✅ İçerik varlık kontrolü
                icerik_check = Icerik.query.get(new_icerik_id)
                if not icerik_check:
                    flash('Seçilen içerik bulunamadı.', 'danger')
                    return redirect(url_for('edit_video', id=id))
                
                # ✅ Video URL format kontrolü (YouTube, Vimeo vb.)
                import re
                valid_patterns = [
                    r'(https?://)?(www\.)?(youtube\.com/watch\?v=|youtu\.be/)',
                    r'(https?://)?(www\.)?vimeo\.com/',
                    r'(https?://)?(www\.)?dailymotion\.com/',
                    r'(https?://)?(www\.)?facebook\.com/.*/videos/'
                ]
                
                is_valid_url = False
                for pattern in valid_patterns:
                    if re.search(pattern, new_video_url.lower()):
                        is_valid_url = True
                        break
                
                if not is_valid_url:
                    flash('Desteklenmeyen video platformu! YouTube, Vimeo, DailyMotion veya Facebook videoları kabul edilir.', 'warning')
                    return redirect(url_for('edit_video', id=id))
                
                # ✅ Sıra numarası kontrolü
                if new_sira is None or new_sira < 0:
                    flash('Geçerli bir sıra numarası giriniz.', 'warning')
                    return redirect(url_for('edit_video', id=id))
                
                # ✅ Aynı içerikte aynı sırada başka video var mı kontrolü
                if new_icerik_id != video.icerik_id or new_sira != video.sira:
                    existing_video = VideoIcerik.query.filter(
                        VideoIcerik.icerik_id == new_icerik_id,
                        VideoIcerik.sira == new_sira,
                        VideoIcerik.id != id
                    ).first()
                    if existing_video:
                        flash(f'Bu içerikte {new_sira} sıra numarasında zaten başka bir video bulunuyor.', 'warning')
                        return redirect(url_for('edit_video', id=id))
                
                # ✅ Güvenli güncelleme
                old_data = {
                    'video_url': video.video_url,
                    'video_title': video.video_title,
                    'icerik_id': video.icerik_id,
                    'sira': video.sira
                }
                
                video.icerik_id = new_icerik_id
                video.video_url = new_video_url.strip()
                video.video_title = new_video_title.strip()
                video.sira = new_sira
                
                db.session.commit()
                
                # ✅ Güvenli log yazma
                changes = []
                for key, old_value in old_data.items():
                    new_value = getattr(video, key)
                    if old_value != new_value:
                        changes.append(key)
                
                app.logger.info(f"Admin {current_user.id} updated video {id} - Changed fields: {changes}")
                
                flash('Video başarıyla güncellendi!', 'success')
                return redirect(url_for('list_videolar'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Video update error: {str(e)}")
                app.logger.error(traceback.format_exc())
                flash('Video güncellenirken bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
                return redirect(url_for('edit_video', id=id))

        # ✅ Form validation hataları
        if form.errors:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'danger')

        return render_template('edit_video.html', 
                             form=form, 
                             video=video,
                             title='Video Düzenle')
                             
    except Exception as e:
        app.logger.error(f"Edit video page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Sayfa yüklenirken hata oluştu.', 'danger')
        return redirect(url_for('list_videolar'))




@app.route('/ders_notu_delete/<int:id>', methods=['POST'])
@admin_required
def delete_ders_notu(id):
    """Admin - Ders Notu Silme - Güvenli"""
    try:
        # ✅ Güvenli ID kontrolü
        if id <= 0:
            flash('Geçersiz ders notu ID.', 'danger')
            return redirect(url_for('list_ders_notlari'))
        
        # ✅ Ders notu varlık kontrolü
        ders_notu = DersNotu.query.get_or_404(id)
        
        # ✅ Güvenli CSRF token kontrolü
        from flask_wtf.csrf import validate_csrf
        try:
            validate_csrf(request.form.get('csrf_token'))
        except:
            flash('Güvenlik hatası. Sayfayı yenileyin.', 'danger')
            return redirect(url_for('list_ders_notlari'))
        
        # ✅ Admin yetki kontrolü (ek güvenlik)
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Bu işlem için yetkiniz yok.', 'danger')
            return redirect(url_for('list_ders_notlari'))
        
        try:
            # ✅ Ders notu bilgilerini log için sakla
            note_info = {
                'id': ders_notu.id,
                'baslik': ders_notu.baslik,
                'icerik_id': ders_notu.icerik_id,
                'dosya_adi': ders_notu.dosya_adi
            }
            
            # ✅ PDF dosyasını güvenli şekilde sil
            if ders_notu.dosya_adi:
                pdf_path = _abspath_join(app.config['PDF_UPLOAD_FOLDER'], ders_notu.dosya_adi)

                # Path traversal saldırısını önle
                if not is_within_directory(app.config['PDF_UPLOAD_FOLDER'], pdf_path):
                    app.logger.warning(f"Suspicious PDF path detected: {pdf_path}")
                else:
                    try:
                        if os.path.exists(pdf_path):
                            os.remove(pdf_path)
                            app.logger.info(f"Deleted PDF file: {ders_notu.dosya_adi}")
                    except Exception as e:
                        app.logger.error(f"PDF file deletion error: {str(e)}")
                        # Dosya silme hatası kritik değil, devam et
            
            # ✅ Ders notunu veritabanından sil
            db.session.delete(ders_notu)
            db.session.commit()
            
            # ✅ Güvenli log yazma
            app.logger.info(f"Admin {current_user.id} deleted PDF note {id} - Title: {note_info['baslik']}, Content: {note_info['icerik_id']}")
            
            flash('Ders notu başarıyla silindi.', 'success')
            return redirect(url_for('list_ders_notlari'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"PDF note deletion error: {str(e)}")
            app.logger.error(traceback.format_exc())
            flash('Ders notu silinirken bir hata oluştu.', 'danger')
            return redirect(url_for('list_ders_notlari'))
            
    except Exception as e:
        app.logger.error(f"Delete PDF note page error: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash('Silme işlemi sırasında hata oluştu.', 'danger')
        return redirect(url_for('list_ders_notlari'))
    
    
    



# Admin routes bölümünün sonuna ekle:

@app.route('/admin/system/database-health')
@admin_required  
def database_health_check():
    """Admin - Database sağlık kontrolü"""
    try:
        # Performance stats
        perf_stats = performance_monitor.get_performance_stats()
        
        # Basic query test
        start_time = time.time()
        user_count = User.query.filter_by(role='user').count()
        basic_query_time = time.time() - start_time
        
        # Complex query test  
        start_time = time.time()
        if user_count > 0:
            stats = QueryOptimizer.get_user_progress_stats(1)
        else:
            stats = {}
        complex_query_time = time.time() - start_time
        
        # Connection test
        try:
            db.session.execute(text('SELECT 1'))
            connection_status = 'healthy'
        except Exception as e:
            connection_status = f'error: {str(e)}'
        
        # Health assessment
        health_score = 100
        alerts = []
        
        if basic_query_time > 0.1:
            health_score -= 20
            alerts.append(f"Yavaş temel sorgu: {basic_query_time:.3f}s")
            
        if complex_query_time > 0.2:
            health_score -= 20  
            alerts.append(f"Yavaş karmaşık sorgu: {complex_query_time:.3f}s")
            
        if connection_status != 'healthy':
            health_score -= 50
            alerts.append("Database bağlantı sorunu")
        
        health_data = {
            'overall_health': health_score,
            'health_status': 'Excellent' if health_score >= 90 else 'Good' if health_score >= 70 else 'Poor',
            'alerts': alerts,
            'connection_status': connection_status,
            'query_performance': {
                'basic_query_time': f"{basic_query_time:.3f}s",
                'complex_query_time': f"{complex_query_time:.3f}s",
                'user_count': user_count
            },
            'performance_stats': perf_stats,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Simple template için JSON response
        return jsonify(health_data)
                             
    except Exception as e:
        app.logger.error(f"Database health check error: {str(e)}")
        return jsonify({'error': str(e), 'timestamp': datetime.utcnow().isoformat()})
    
    
@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required  # Sadece admin erişebilsin
def admin_settings():
    # Ayarları veritabanından çek
    mail_sender = Settings.get('MAIL_DEFAULT_SENDER')
    mail_password = Settings.get('MAIL_PASSWORD')
    google_client_id = Settings.get('GOOGLE_CLIENT_ID')
    google_client_secret = Settings.get('GOOGLE_CLIENT_SECRET')

    if request.method == 'POST':
        # Formdan gelen verileri al
        mail_sender = request.form.get('mail_sender')
        mail_password = request.form.get('mail_password')
        google_client_id = request.form.get('google_client_id')
        google_client_secret = request.form.get('google_client_secret')

        # Ayarları güncelle
        Settings.set('MAIL_DEFAULT_SENDER', mail_sender)
        Settings.set('MAIL_PASSWORD', mail_password)
        Settings.set('GOOGLE_CLIENT_ID', google_client_id)
        Settings.set('GOOGLE_CLIENT_SECRET', google_client_secret)
        db.session.commit()
        flash('Ayarlar başarıyla güncellendi.', 'success')
        return redirect(url_for('admin_settings'))

    return render_template('admin_settings.html',
                           mail_sender=mail_sender,
                           mail_password=mail_password,
                           google_client_id=google_client_id,
                           google_client_secret=google_client_secret)  


@app.route('/admin/system/performance-test')
@admin_required
def performance_test():
    """Admin - Performance benchmark test"""
    try:
        # Benchmark testlerini çalıştır
        test_results = performance_monitor.run_performance_benchmark()
        
        # Advanced Query Optimizer testleri
        advanced_tests = []
        
        # Test: Minimal user data
        try:
            start_time = time.time()
            user = AdvancedQueryOptimizer.get_minimal_user_data(1)
            test_time = time.time() - start_time
            advanced_tests.append({
                'test': 'Minimal User Data',
                'time': f"{test_time:.4f}s",
                'result': 'Success' if user else 'No data',
                'status': 'fast' if test_time < 0.05 else 'slow'
            })
        except Exception as e:
            advanced_tests.append({
                'test': 'Minimal User Data',
                'time': '0.000s',
                'result': f'Error: {str(e)}',
                'status': 'error'
            })
        
        # Test: Content summary
        try:
            start_time = time.time()
            content = AdvancedQueryOptimizer.get_content_summary_optimized(10)
            test_time = time.time() - start_time
            advanced_tests.append({
                'test': 'Content Summary (10 items)',
                'time': f"{test_time:.4f}s",
                'result': f'{len(content)} items loaded',
                'status': 'fast' if test_time < 0.1 else 'slow'
            })
        except Exception as e:
            advanced_tests.append({
                'test': 'Content Summary',
                'time': '0.000s',
                'result': f'Error: {str(e)}',
                'status': 'error'
            })
        
        # Test: Raw SQL leaderboard
        try:
            start_time = time.time()
            leaderboard = AdvancedQueryOptimizer.get_leaderboard_raw_sql('weekly', None, 10)
            test_time = time.time() - start_time
            advanced_tests.append({
                'test': 'Raw SQL Leaderboard',
                'time': f"{test_time:.4f}s",
                'result': f'{len(leaderboard)} entries',
                'status': 'fast' if test_time < 0.1 else 'slow'
            })
        except Exception as e:
            advanced_tests.append({
                'test': 'Raw SQL Leaderboard',
                'time': '0.000s',
                'result': f'Error: {str(e)}',
                'status': 'error'
            })
        
        # Combine all results
        all_results = {
            'basic_tests': test_results,
            'advanced_tests': advanced_tests,
            'summary': {
                'total_tests': len(test_results) + len(advanced_tests),
                'fast_tests': len([t for t in test_results + advanced_tests if t['status'] == 'fast']),
                'slow_tests': len([t for t in test_results + advanced_tests if t['status'] == 'slow']),
                'error_tests': len([t for t in test_results + advanced_tests if t['status'] == 'error']),
                'timestamp': datetime.utcnow().isoformat()
            }
        }
        
        return jsonify(all_results)
                             
    except Exception as e:
        app.logger.error(f"Performance test error: {str(e)}")
        return jsonify({'error': str(e), 'timestamp': datetime.utcnow().isoformat()})

@app.route('/admin/system/query-stats')
@admin_required
def query_statistics():
    """Admin - Query istatistikleri"""
    try:
        # Performance stats
        perf_stats = performance_monitor.get_performance_stats()
        
        # Slow query report
        slow_query_report = performance_monitor.get_slow_queries_report(24)
        
        stats = {
            'performance_stats': perf_stats,
            'slow_query_report': slow_query_report,
            'system_info': {
                'python_version': f"{db.engine.dialect.server_version_info if hasattr(db.engine.dialect, 'server_version_info') else 'Unknown'}",
                'sqlalchemy_version': '2.x',
                'database_type': db.engine.dialect.name
            },
            'recommendations': [
                'Query süreleri düzenli olarak izlenir',
                'Index kullanımı optimize edilmiştir',
                'Connection pool ayarları optimize edilmiştir',
                'N+1 query problemi çözülmüştür'
            ],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return jsonify(stats)
        
    except Exception as e:
        app.logger.error(f"Query stats error: {str(e)}")
        return jsonify({'error': str(e), 'timestamp': datetime.utcnow().isoformat()})
    
    
    
@app.route('/admin/system/monitor')
@admin_required
def admin_system_monitor():
    return render_template('admin_system_monitor.html', title='Sistem İzleme')
    
    

@app.route('/ders_notu_filtre/<sinif_slug>/<ders_slug>')
def ders_notu_filtre(sinif_slug, ders_slug):
    sinif = Sinif.query.filter_by(slug=sinif_slug).first_or_404()
    ders = Ders.query.filter_by(slug=ders_slug, sinif_id=sinif.id).first_or_404()
    try:
        # Temel sorgu
        query = DersNotu.query.join(DersNotu.unite).join(Unite.ders).join(Ders.sinif)
        
        # Sınıf ve ders filtreleri
        query = query.filter(Sinif.id == sinif.id, Ders.id == ders.id)
        
        # Unite filtresi
        unite_id = request.args.get('unite_id', type=int)
        if unite_id:
            query = query.filter(Unite.id == unite_id)
            
        # İçerik filtresi
        icerik_id = request.args.get('icerik_id', type=int)
        if icerik_id:
            query = query.filter(DersNotu.icerik_id == icerik_id)
            
        # Sıralama
        query = query.order_by(Unite.id.asc(), DersNotu.eklenme_tarihi.desc())
        
        # Verileri al
        ders_notlari = query.all()
        uniteler = Unite.query.filter_by(ders_id=ders.id).all()
        
        # İçerikleri al (eğer ünite seçilmişse)
        icerikler = []
        if unite_id:
            icerikler = Icerik.query.filter_by(unite_id=unite_id).all()
        
        return render_template('ders_notu_filtre.html',
                            ders_notlari=ders_notlari,
                            sinif=sinif,
                            ders=ders,
                            uniteler=uniteler,
                            icerikler=icerikler,
                            unite_id=unite_id,
                            icerik_id=icerik_id)
                            
    except Exception as e:
        flash('Ders notları yüklenirken bir hata oluştu.', 'danger')
        app.logger.error(f'Ders notları filtreleme hatası: {str(e)}')
        return redirect(url_for('home'))
    
    



    
@app.cli.command('update-slugs')
def update_slugs_command():
    """Eksik slugları günceller."""
    count = 0
    
    # Sınıf sluglarını kontrol et ve güncelle
    for sinif in Sinif.query.all():
        if not sinif.slug:
            sinif.slug = create_slug(sinif.sinif)
            count += 1
    
    # Ders sluglarını kontrol et ve güncelle
    for ders in Ders.query.all():
        if not ders.slug:
            ders.slug = create_slug(ders.ders_adi)
            count += 1
            
    # Ünite sluglarını kontrol et ve güncelle
    for unite in Unite.query.all():
        if not unite.slug:
            unite.slug = create_slug(unite.unite)
            count += 1
            
    # İçerik sluglarını kontrol et ve güncelle
    for icerik in Icerik.query.all():
        if not icerik.slug:
            icerik.slug = create_slug(icerik.baslik)
            count += 1
    
    # Değişiklikleri kaydet
    db.session.commit()
    
    app.logger.info(f'Toplam {count} slug güncellendi.')
    
    

    
    
@app.context_processor
def inject_footer_shortcuts():
    return {'footer_shortcuts': FOOTER_SHORTCUTS}   


    
FOOTER_SHORTCUTS = {
    "5. Sınıf": [
        {"ad": "Matematik", "url": "/sinif/5/matematik"},
        {"ad": "Türkçe", "url": "/sinif/5/turkce"},
        {"ad": "Fen Bilimleri", "url": "/sinif/5/fen-bilimleri"},
    ],
    "6. Sınıf": [
        {"ad": "Matematik", "url": "/sinif/6/matematik"},
        {"ad": "Türkçe", "url": "/sinif/6/turkce"},
        {"ad": "Fen Bilimleri", "url": "/sinif/6/fen-bilimleri"},
    ],
    # ... diğer sınıflar ...
}

    
    
@app.errorhandler(404)
def page_not_found(e): 
    return render_template("404.html"), 404

#Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template("403.html"), 403

# Duplicate 429 handler removed to keep the earlier JSON-aware handler.
