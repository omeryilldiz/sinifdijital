from datetime import datetime
from SF import db, login_manager
from flask_login import UserMixin
from sqlalchemy import Index, text, event
from sqlalchemy.orm import joinedload, selectinload
import re
from unidecode import unidecode
import random
import string


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    school_id = db.Column(db.Integer, db.ForeignKey('school.id', ondelete='SET NULL'))
    
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    phone = db.Column(db.String(15), nullable=True)
    class_no = db.Column(db.String(10), nullable=True)
    class_name = db.Column(db.String(50), nullable=True)
    profile_completed = db.Column(db.Boolean, default=False)
    profile_completed_date = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Email doğrulama alanları (zaten var)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(200), nullable=True)
    email_verification_sent_at = db.Column(db.DateTime, nullable=True)
    
    # Şifre sıfırlama token alanları (zaten var)
    password_reset_token = db.Column(db.String(200), nullable=True)
    password_reset_token_created_at = db.Column(db.DateTime, nullable=True)
    
    # Hesap kilitleme alanları
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    last_failed_login = db.Column(db.DateTime, nullable=True)
    
    # Şifre değişiklik takibi
    password_changed_at = db.Column(db.DateTime, nullable=True)
    
    # ✅ YENİ: IP Kayıt Alanları (5651 Sayılı Kanun Uyumu)
    registration_ip = db.Column(db.String(45), nullable=True)  # IPv6 için 45 karakter
    last_login_ip = db.Column(db.String(45), nullable=True)
    
    # ✅ YENİ: Veli Onayı Alanları (KVKK Uyumu)
    parental_consent = db.Column(db.Boolean, default=False)
    parental_consent_date = db.Column(db.DateTime, nullable=True)
    parental_consent_ip = db.Column(db.String(45), nullable=True)
    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: Indexler eklendi
    __table_args__ = (
        Index('idx_user_email', 'email'),
        Index('idx_user_role', 'role'),
        Index('idx_user_school_class', 'school_id', 'class_no'),
        Index('idx_user_profile_completed', 'profile_completed'),
        Index('idx_user_created_date', 'date_created'),
        Index('idx_user_last_login', 'last_login'),
        Index('idx_user_registration_ip', 'registration_ip'),  # ✅ YENİ
        Index('idx_user_last_login_ip', 'last_login_ip'),  # ✅ YENİ
    )
    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişkileri optimize et
    school = db.relationship('School', lazy='select', backref='users')
    progress_records = db.relationship('UserProgress', 
                                     lazy='dynamic', 
                                     cascade='all, delete-orphan',
                                     backref='user')

    @staticmethod
    def create_slug(text):
        if not text:
            return ""
        
        text = unidecode(text)
        text = text.lower()
        text = re.sub(r'[^a-z0-9\s-]', '', text)
        text = re.sub(r'\s+', '-', text)
        text = re.sub(r'-+', '-', text)
        return text.strip('-')

    # ✅ Mevcut metodlar korundu
    def get_class_display(self):
        """Sınıf bilgisini güzel formatta döndür"""
        if not self.class_no:
            return 'Belirtilmemiş'
        
        class_display_mapping = {
            '5': '5. Sınıf', '6': '6. Sınıf', '7': '7. Sınıf', '8': '8. Sınıf',
            '9': '9. Sınıf', '10': '10. Sınıf', '11': '11. Sınıf', '12': '12. Sınıf',
            'LGS': 'LGS Hazırlık', 'TYT': 'TYT Hazırlık', 'AYT': 'AYT Hazırlık'
        }
        
        display_name = class_display_mapping.get(str(self.class_no), str(self.class_no))
        
        if self.class_name:
            return f"{display_name} - {self.class_name}"
        return display_name
    
    def get_competition_group(self):
        """Kullanıcının yarışma grubunu döndür"""
        class_mapping = {
            '5': '5_sinif',
            '6': '6_sinif',
            '7': '7_sinif',
           
            'LGS': 'lgs_grubu',
            '9': '9_sinif',
            '10': '10_sinif',
            '11': '11_sinif',
            '12': 'universite_hazirlik',
            'TYT': 'universite_hazirlik',
            'AYT': 'universite_hazirlik',
            'Mezun': 'universite_hazirlik'  # Yeni eklendi
        }
        return class_mapping.get(str(self.class_no), 'other')
    
    def get_competing_classes(self):
        """Aynı yarışma grubundaki tüm sınıfları döndür"""
        group_classes = {
            '5_sinif': ['5'],
            '6_sinif': ['6'],
            '7_sinif': ['7'],
            'lgs_grubu': ['8', 'LGS'],
            '9_sinif': ['9'],
            '10_sinif': ['10'],
            '11_sinif': ['11'],
            'universite_hazirlik': ['12', 'TYT', 'AYT', 'Mezun']  # Mezun eklendi
        }
        competition_group = self.get_competition_group()
        return group_classes.get(competition_group, [str(self.class_no)])
    
    def get_competition_display_name(self):
        """Yarışma grubunun görüntüleme adı"""
        competition_group = self.get_competition_group()
        display_names = {
            '5_sinif': '5. Sınıf', '6_sinif': '6. Sınıf', '7_sinif': '7. Sınıf',
            'lgs_grubu': 'LGS Hazırlık (8. Sınıf + LGS)',
            '9_sinif': '9. Sınıf', '10_sinif': '10. Sınıf', '11_sinif': '11. Sınıf',
            'universite_hazirlik': 'Üniversite Hazırlık (12. Sınıf + TYT + AYT)',
            'other': 'Diğer'
        }
        return display_names.get(competition_group, competition_group)
    
    def is_profile_complete(self):
        """Kullanıcı profilinin tam olup olmadığını kontrol et"""
        return bool(
            self.first_name and 
            self.last_name and 
            self.school_id and 
            self.class_no and 
            self.profile_completed
        )

    def is_account_locked(self):
        """Hesabın kilitli olup olmadığını kontrol et"""
        if self.account_locked_until is None:
            return False
        from datetime import datetime
        if datetime.utcnow() > self.account_locked_until:
            # Kilit süresi dolmuş, sıfırla
            self.failed_login_attempts = 0
            self.account_locked_until = None
            return False
        return True
    
    def get_lock_remaining_time(self):
        """Kalan kilit süresini dakika olarak döndür"""
        if not self.is_account_locked():
            return 0
        from datetime import datetime
        remaining = self.account_locked_until - datetime.utcnow()
        return max(0, int(remaining.total_seconds() / 60))
    
    def increment_failed_login(self):
        """Başarısız giriş sayısını artır ve gerekirse kilitle"""
        from datetime import datetime, timedelta
        
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        self.last_failed_login = datetime.utcnow()
        
        # 5 başarısız deneme → 15 dakika kilitle
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
    
    def reset_failed_login(self):
        """Başarılı girişte sayacı sıfırla"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.last_failed_login = None

class UserLoginLog(db.Model):
    """
    Kullanıcı giriş logları - 5651 Sayılı Kanun Uyumu
    2 yıl boyunca saklanacak, sonra otomatik silinecek
    """
    __tablename__ = 'user_login_log'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    
    # Log bilgileri
    action_type = db.Column(db.String(50), nullable=False)
    action_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500), nullable=True)
    
    # Ek bilgiler
    success = db.Column(db.Boolean, default=True)
    details = db.Column(db.String(255), nullable=True)
    
    # Kayıt oluşturma zamanı (log temizliği için)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # İlişki
    user = db.relationship('User', backref=db.backref('login_logs', lazy='dynamic', cascade='all, delete-orphan'))
    
    # Indexler
    __table_args__ = (
        Index('idx_login_log_user_date', 'user_id', 'action_date'),
        Index('idx_login_log_action_type', 'action_type'),
        Index('idx_login_log_created_at', 'created_at'),
        Index('idx_login_log_ip', 'ip_address'),
        Index('idx_login_log_user_action', 'user_id', 'action_type', 'action_date'),
    )
    
    def __repr__(self):
        return f"<UserLoginLog {self.user_id} - {self.action_type} - {self.action_date}>"
    
    @staticmethod
    def log_action(user_id, action_type, ip_address, user_agent=None, success=True, details=None):
        """Yardımcı metod: Log kaydı oluştur"""
        log = UserLoginLog(
            user_id=user_id,
            action_type=action_type,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent and len(user_agent) > 500 else user_agent,
            success=success,
            details=details
        )
        db.session.add(log)
        return log


class LogActionType:
    """Log action türleri için sabitler"""
    REGISTER = 'register'
    LOGIN = 'login'
    LOGOUT = 'logout'
    FAILED_LOGIN = 'failed_login'
    PASSWORD_RESET_REQUEST = 'password_reset_request'
    PASSWORD_RESET_COMPLETE = 'password_reset_complete'
    PASSWORD_CHANGE = 'password_change'
    EMAIL_VERIFY = 'email_verify'
    PROFILE_UPDATE = 'profile_update'
    CONSENT_GIVEN = 'consent_given'
    CONSENT_WITHDRAWN = 'consent_withdrawn'


class ConsentType:
    """Sözleşme türleri için sabitler"""
    KVKK = 'kvkk'
    PRIVACY_POLICY = 'privacy_policy'
    TERMS_OF_USE = 'terms_of_use'
    EXPLICIT_CONSENT = 'explicit_consent'
    CLARIFICATION_TEXT = 'clarification_text'
    PARENTAL_CONSENT = 'parental_consent'
    COMMERCIAL_ELECTRONIC_MESSAGE = 'commercial_electronic_message'


class UserConsent(db.Model):
    """
    Kullanıcı sözleşme onayları - KVKK/GDPR Uyumu
    2 yıl boyunca saklanacak, sonra otomatik silinecek
    """
    __tablename__ = 'user_consent'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    
    # Sözleşme bilgileri
    consent_type = db.Column(db.String(50), nullable=False)  # ConsentType sabitlerinden
    consent_version = db.Column(db.String(20), nullable=False)  # '1.0', '2.1', vb
    consent_text_hash = db.Column(db.String(64), nullable=True)  # SHA-256 hash (opsiyonel)
    
    # Onay durumu
    accepted = db.Column(db.Boolean, nullable=False, default=True)
    accepted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(500), nullable=True)
    
    # Geri çekilme (isteğe bağlı)
    withdrawn_at = db.Column(db.DateTime, nullable=True)
    withdrawn_ip = db.Column(db.String(45), nullable=True)
    
    # Kayıt oluşturma zamanı (log temizliği için)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # İlişki
    user = db.relationship('User', backref=db.backref('consents', lazy='dynamic', cascade='all, delete-orphan'))
    
    # Indexler
    __table_args__ = (
        Index('idx_consent_user_type', 'user_id', 'consent_type'),
        Index('idx_consent_user_date', 'user_id', 'accepted_at'),
        Index('idx_consent_type', 'consent_type'),
        Index('idx_consent_created_at', 'created_at'),
        Index('idx_consent_withdrawn', 'withdrawn_at'),
    )
    
    def __repr__(self):
        return f"<UserConsent {self.user_id} - {self.consent_type} - {self.accepted_at}>"
    
    @staticmethod
    def log_consent(user_id, consent_type, consent_version, ip_address, user_agent=None, accepted=True, consent_text_hash=None):
        """Yardımcı metod: Sözleşme onayı kaydı oluştur"""
        consent = UserConsent(
            user_id=user_id,
            consent_type=consent_type,
            consent_version=consent_version,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent and len(user_agent) > 500 else user_agent,
            accepted=accepted,
            consent_text_hash=consent_text_hash
        )
        db.session.add(consent)
        return consent
    
    def withdraw(self, ip_address):
        """Onayı geri çek"""
        self.withdrawn_at = datetime.utcnow()
        self.withdrawn_ip = ip_address


class UserProgress(db.Model):
    __tablename__ = 'user_progress'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    icerik_id = db.Column(db.Integer, db.ForeignKey('icerik.id', ondelete='CASCADE'), nullable=True)
    soru_id = db.Column(db.Integer, db.ForeignKey('soru.id', ondelete='CASCADE'), nullable=True)
    activity_type = db.Column(db.String(20), nullable=False)
    harcanan_sure = db.Column(db.Integer, nullable=True)
    dogru_sayisi = db.Column(db.Integer, default=0)
    yanlis_sayisi = db.Column(db.Integer, default=0)
    bos_sayisi = db.Column(db.Integer, default=0)
    puan = db.Column(db.Float, default=0.0)
    okundu = db.Column(db.Boolean, default=False)
    tarih = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: Kritik indexler
    __table_args__ = (
        Index('idx_progress_user_date', 'user_id', 'tarih'),
        Index('idx_progress_user_activity', 'user_id', 'activity_type'),
        Index('idx_progress_icerik', 'icerik_id'),
        Index('idx_progress_soru', 'soru_id'),
        Index('idx_progress_composite', 'user_id', 'icerik_id', 'activity_type'),
        Index('idx_progress_points', 'user_id', 'puan'),
    )
    
    # ✅ WARNING DÜZELTMESİ: Overlaps eklendi
    icerik = db.relationship('Icerik', lazy='select', overlaps="user_progress")
    soru = db.relationship('Soru', lazy='select', overlaps="user_progress")

class ActivityType:
    CONTENT_READING = 'content_reading'
    QUESTION_SOLVING = 'question_solving'
    VIDEO_WATCHING = 'video_watching'
    NOTE_TAKING = 'note_taking'
    PRACTICE_TEST = 'practice_test'
    CONTENT_VIEWED = 'content_viewed'
    TEST_SUMMARY = 'test_summary'
    
     

class Sinif(db.Model):
    __tablename__ = 'sinif'
    
    id = db.Column(db.Integer, primary_key=True)
    sinif = db.Column(db.String(225), nullable=False, unique=True)
    slug = db.Column(db.String(255), unique=True, nullable=False)  # ✅ Slug alanı eklendi

    # ✅ PERFORMANS İYİLEŞTİRMESİ: Cascade ve lazy loading optimize edildi
    dersler = db.relationship('Ders', 
                             lazy='dynamic',
                             cascade='all, delete-orphan',
                             order_by='Ders.id',
                             overlaps="sinif")
    
    # ✅ Index eklendi
    __table_args__ = (
        Index('idx_sinif_name', 'sinif'),
        Index('idx_sinif_slug', 'slug'),  # ✅ Slug için index eklendi
    )
    
    def __repr__(self):
        return f"<Sinif {self.sinif}>"






class Ders(db.Model):
    __tablename__ = 'ders'
    
    id = db.Column(db.Integer, primary_key=True)
    ders_adi = db.Column(db.String(225), nullable=False)
    sinif_id = db.Column(db.Integer, db.ForeignKey('sinif.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    slug = db.Column(db.String(255), unique=True, nullable=False)  # ✅ Slug alanı eklendi

    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişkiler optimize edildi
    sinif = db.relationship('Sinif', lazy='select', overlaps="dersler")
    uniteler = db.relationship('Unite', 
                              lazy='dynamic',
                              cascade='all, delete-orphan',
                              order_by='Unite.id',
                              overlaps="ders")
    
    # ✅ Index eklendi
    __table_args__ = (
        Index('idx_ders_sinif', 'sinif_id'),
        Index('idx_ders_name', 'ders_adi'),
        Index('idx_ders_slug', 'slug'),  # ✅ Slug için index eklendi

    )

class Unite(db.Model):
    __tablename__ = 'unite'
    
    id = db.Column(db.Integer, primary_key=True)
    unite = db.Column(db.String(225), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ders_id = db.Column(db.Integer, db.ForeignKey('ders.id', ondelete='CASCADE'), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False)  # ✅ Slug alanı eklendi

    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişkiler optimize edildi
    ders = db.relationship('Ders', lazy='select', overlaps="uniteler")
    icerikler = db.relationship('Icerik', 
                               lazy='dynamic',
                               cascade='all, delete-orphan',
                               order_by='Icerik.id',
                               overlaps="unite")
    sorular = db.relationship('Soru', 
                             lazy='dynamic',
                             cascade='all, delete-orphan',
                             overlaps="unite")
    ders_notlari = db.relationship('DersNotu', 
                                  lazy='dynamic',
                                  cascade='all, delete-orphan',
                                  overlaps="unite")

# ✅ PERFORMANS İYİLEŞTİRMESİ: Index eklendi
    __table_args__ = (
        Index('idx_unite_ders', 'ders_id'),
        Index('idx_unite_name', 'unite'),
        Index('idx_unite_slug', 'slug'),  # ✅ Slug için index eklendi

    )
    
    def __repr__(self):
        return f"Unite('{self.unite}')"

class Icerik(db.Model):
    __tablename__ = 'icerik'
    
    id = db.Column(db.Integer, primary_key=True)
    baslik = db.Column(db.String(255), nullable=False)
    icerik = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    unite_id = db.Column(db.Integer, db.ForeignKey('unite.id', ondelete='CASCADE'), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False)  # ✅ Slug alanı eklendi


    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişkiler optimize edildi
    unite = db.relationship('Unite', lazy='select', overlaps="icerikler")
    sorular = db.relationship('Soru', 
                             lazy='dynamic',
                             cascade='all, delete-orphan',
                             overlaps="icerik")
    ders_notlari = db.relationship('DersNotu', 
                                  lazy='dynamic',
                                  cascade='all, delete-orphan',
                                  overlaps="icerik")
    videolar = db.relationship('VideoIcerik', 
                              lazy='dynamic',
                              cascade='all, delete-orphan',
                              order_by='VideoIcerik.sira',
                              overlaps="icerik")
    user_progress = db.relationship('UserProgress', 
                                   lazy='dynamic',
                                   cascade='all, delete-orphan',
                                   overlaps="icerik")

    # ✅ PERFORMANS İYİLEŞTİRMESİ: Indexler eklendi
    __table_args__ = (
        Index('idx_icerik_unite', 'unite_id'),
        Index('idx_icerik_title', 'baslik'),
        Index('idx_icerik_created', 'created_at'),
        Index('idx_icerik_slug', 'slug'),  # ✅ Slug için index eklendi

    )

class Soru(db.Model):
    __tablename__ = 'soru'
    
    id = db.Column(db.Integer, primary_key=True)
    soru_resim = db.Column(db.String(255), nullable=False)
    cevap = db.Column(db.String(1), nullable=False)
    video_path = db.Column(db.String(255), nullable=True)  # Video dosya yolu
    cozum_resim = db.Column(db.String(255), nullable=True)  # Çözüm resmi dosya yolu
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    unite_id = db.Column(db.Integer, db.ForeignKey('unite.id', ondelete='CASCADE'), nullable=False)
    icerik_id = db.Column(db.Integer, db.ForeignKey('icerik.id', ondelete='CASCADE'), nullable=False)
    reference_code = db.Column(db.String(32), unique=True, nullable=False, index=True)  # <-- yeni alan

    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişkiler optimize edildi
    unite = db.relationship('Unite', lazy='select', overlaps="sorular")
    icerik = db.relationship('Icerik', lazy='select', overlaps="sorular")
    user_progress = db.relationship('UserProgress', 
                                   lazy='dynamic',
                                   cascade='all, delete-orphan',
                                   overlaps="soru")

    # ✅ PERFORMANS İYİLEŞTİRMESİ: Soru sorguları için indexler
    __table_args__ = (
        Index('idx_soru_unite_icerik', 'unite_id', 'icerik_id'),
        Index('idx_soru_icerik', 'icerik_id'),
        Index('idx_soru_unite', 'unite_id'),
        Index('idx_soru_created', 'created_at'),
    )
    
    # İlişki üzerinden sinif ve ders bilgilerine erişim metodları
    @property
    def sinif(self):
        return self.unite.ders.sinif if self.unite and self.unite.ders else None
        
    @property 
    def ders(self):
        return self.unite.ders if self.unite else None

    def get_image_path(self):
        return f'soru_uploads/{self.soru_resim}'

    def __repr__(self):
        return f"Soru(id={self.id}, unite_id={self.unite_id}, icerik_id={self.icerik_id})"

class DersNotu(db.Model):
    __tablename__ = 'ders_notu'
    
    id = db.Column(db.Integer, primary_key=True)
    dosya_adi = db.Column(db.String(255), nullable=False)
    baslik = db.Column(db.String(255), nullable=False)
    eklenme_tarihi = db.Column(db.DateTime, default=datetime.utcnow)
    sinif_id = db.Column(db.Integer, db.ForeignKey('sinif.id', ondelete='CASCADE'), nullable=False)
    ders_id = db.Column(db.Integer, db.ForeignKey('ders.id', ondelete='CASCADE'), nullable=False)
    unite_id = db.Column(db.Integer, db.ForeignKey('unite.id', ondelete='CASCADE'), nullable=False)
    icerik_id = db.Column(db.Integer, db.ForeignKey('icerik.id', ondelete='CASCADE'), nullable=False)

    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişkiler optimize edildi
    sinif = db.relationship('Sinif', lazy='select')
    ders = db.relationship('Ders', lazy='select')
    unite = db.relationship('Unite', lazy='select', overlaps="ders_notlari")
    icerik = db.relationship('Icerik', lazy='select', overlaps="ders_notlari")

    # ✅ PERFORMANS İYİLEŞTİRMESİ: Ders notu indexleri
    __table_args__ = (
        Index('idx_dersnotu_icerik_date', 'icerik_id', 'eklenme_tarihi'),
        Index('idx_dersnotu_composite', 'sinif_id', 'ders_id', 'unite_id'),
        Index('idx_dersnotu_title', 'baslik'),
    )

    def __repr__(self):
        return f"DersNotu('{self.baslik}')"

class VideoIcerik(db.Model):
    __tablename__ = 'video_icerik'
    
    id = db.Column(db.Integer, primary_key=True)
    icerik_id = db.Column(db.Integer, db.ForeignKey('icerik.id', ondelete='CASCADE'), nullable=False)
    video_url = db.Column(db.String(255), nullable=False)
    video_title = db.Column(db.String(255))
    sira = db.Column(db.Integer, default=0)
    aktif = db.Column(db.Boolean, default=True)
    eklenme_tarihi = db.Column(db.DateTime, default=datetime.utcnow)  # ✅ Eklendi
    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişki optimize edildi
    icerik = db.relationship('Icerik', lazy='select', overlaps="videolar")
    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: Video indexleri
    __table_args__ = (
        Index('idx_video_icerik_sira', 'icerik_id', 'sira'),
        Index('idx_video_aktif', 'aktif'),
        Index('idx_video_created', 'eklenme_tarihi'),
    )
    
    @property
    def video_id(self):
        """YouTube URL'sinden video ID'sini çıkarır"""
        import re
        patterns = [
            r'^(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/(?:watch\?v=|embed\/)|youtu\.be\/)([a-zA-Z0-9_-]+)',
            r'^(?:https?:\/\/)?(?:www\.)?youtube\.com\/.*\?.*v=([a-zA-Z0-9_-]+)',
            r'^(?:https?:\/\/)?(?:www\.)?youtu\.be\/([a-zA-Z0-9_-]+)'
        ]
        
        url = self.video_url.strip()
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None
    
    @property
    def embed_url(self):
        """Embed URL oluştur"""
        video_id = self.video_id
        return f"https://www.youtube.com/embed/{video_id}" if video_id else None

class Province(db.Model):
    __tablename__ = 'province'
    
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(10), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişki optimize edildi
    districts = db.relationship('District', 
                               lazy='dynamic',
                               cascade='all, delete-orphan',
                               order_by='District.name',
                               overlaps="province")
    
    # ✅ Index eklendi
    __table_args__ = (
        Index('idx_province_code', 'code'),
        Index('idx_province_name', 'name'),
    )

class District(db.Model):
    __tablename__ = 'district'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    province_id = db.Column(db.Integer, db.ForeignKey('province.id', ondelete='CASCADE'), nullable=False)
    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişkiler optimize edildi
    province = db.relationship('Province', lazy='select', overlaps="districts")
    schools = db.relationship('School', 
                             lazy='dynamic',
                             cascade='all, delete-orphan',
                             order_by='School.name',
                             overlaps="district")

    # ✅ Index eklendi
    __table_args__ = (
        Index('idx_district_province', 'province_id'),
        Index('idx_district_name', 'name'),
    )

class SchoolType(db.Model):
    __tablename__ = 'school_type'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişki optimize edildi
    schools = db.relationship('School', 
                             lazy='dynamic',
                             cascade='all, delete-orphan',
                             order_by='School.name',
                             overlaps="school_type")
    
    # ✅ Index eklendi
    __table_args__ = (
        Index('idx_school_type_name', 'name'),
    )

class School(db.Model):
    __tablename__ = 'school'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    district_id = db.Column(db.Integer, db.ForeignKey('district.id', ondelete='CASCADE'), nullable=False)
    school_type_id = db.Column(db.Integer, db.ForeignKey('school_type.id', ondelete='CASCADE'), nullable=False)
    
    # ✅ PERFORMANS İYİLEŞTİRMESİ: İlişkiler optimize edildi
    district = db.relationship('District', lazy='select', overlaps="schools")
    school_type = db.relationship('SchoolType', lazy='select', overlaps="schools")

    # ✅ PERFORMANS İYİLEŞTİRMESİ: Okul sorguları için indexler
    __table_args__ = (
        Index('idx_school_district_type', 'district_id', 'school_type_id'),
        Index('idx_school_name', 'name'),
    )
    
    
class HomepageSlide(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)           # Slayt başlığı
    description = db.Column(db.Text, nullable=True)              # Slayt açıklaması
    image_path = db.Column(db.String(255), nullable=True)        # Görsel yolu
    button_text = db.Column(db.String(100), nullable=True)       # Buton metni
    button_url = db.Column(db.String(255), nullable=True)        # Buton linki
    badge_text = db.Column(db.String(50), nullable=True)         # Üstteki rozet (örn: YENİ, REKLAM)
    badge_color = db.Column(db.String(30), nullable=True)        # Rozet rengi (örn: bg-danger, bg-warning)
    slide_type = db.Column(db.String(30), nullable=True)         # Slayt tipi (örn: 'normal', 'reklam')
    order = db.Column(db.Integer, default=0)                     # Carousel sırası
    is_active = db.Column(db.Boolean, default=True)              # Slayt aktif mi

    def __repr__(self):
        return f"<HomepageSlide {self.title}>"
    
    
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)

    @staticmethod
    def get(key):
        setting = Settings.query.filter_by(key=key).first()
        return setting.value if setting else ''

    @staticmethod
    def set(key, value):
        setting = Settings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = Settings(key=key, value=value)
            db.session.add(setting)


        
        
def create_slug(text):
    if not text:
        return ""
    
    text = unidecode(text)
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s-]', '', text)
    text = re.sub(r'\s+', '-', text)
    text = re.sub(r'-+', '-', text)
    return text.strip('-')

@event.listens_for(Sinif, 'before_insert')
@event.listens_for(Sinif, 'before_update')
def generate_sinif_slug(mapper, connection, target):
    if not target.slug and target.sinif:
        base_slug = create_slug(target.sinif)
        slug = base_slug
        counter = 1
        counter = 1
        
        # Benzersiz slug kontrolü
        while connection.execute(
            text("SELECT 1 FROM sinif WHERE slug = :slug AND id != :id"),
            {'slug': slug, 'id': target.id or 0}
        ).fetchone():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        target.slug = slug
        
@event.listens_for(Ders, 'before_insert')
@event.listens_for(Ders, 'before_update')
def generate_ders_slug(mapper, connection, target):
    if not target.slug and target.ders_adi:
        base_slug = create_slug(target.ders_adi)
        slug = base_slug
        counter = 1
        
        # Benzersiz slug kontrolü
        while connection.execute(
            text("SELECT 1 FROM ders WHERE slug = :slug AND id != :id"),
            {'slug': slug, 'id': target.id or 0}
        ).fetchone():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        target.slug = slug


@event.listens_for(Unite, 'before_insert')
@event.listens_for(Unite, 'before_update')
def generate_unite_slug(mapper, connection, target):
    if not target.slug and target.unite:
        base_slug = create_slug(target.unite)
        slug = base_slug
        counter = 1
        
        # Benzersiz slug kontrolü
        while connection.execute(
            text("SELECT 1 FROM unite WHERE slug = :slug AND id != :id"),
            {'slug': slug, 'id': target.id or 0}
        ).fetchone():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        target.slug = slug
        
        
@event.listens_for(Icerik, 'before_insert')
@event.listens_for(Icerik, 'before_update')
def generate_icerik_slug(mapper, connection, target):
    if not target.slug and target.baslik:
        base_slug = create_slug(target.baslik)
        slug = base_slug
        counter = 1
        
        # Benzersiz slug kontrolü
        while connection.execute(
            text("SELECT 1 FROM icerik WHERE slug = :slug AND id != :id"),
            {'slug': slug, 'id': target.id or 0}
        ).fetchone():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        target.slug = slug

def generate_reference_code(soru):
    # Ders kısa adı (ilk 3 harf, büyük harf, Türkçe karakter temizlenmiş)
    ders_adi = (soru.ders.ders_adi[:3] if soru.ders and soru.ders.ders_adi else "GEN").upper()
    ders_adi = ders_adi.replace("Ç", "C").replace("Ğ", "G").replace("İ", "I").replace("Ö", "O").replace("Ş", "S").replace("Ü", "U")
    # Sınıf (ör: 8, 10, AYT)
    sinif = (soru.ders.sinif.sinif if soru.ders and soru.ders.sinif and soru.ders.sinif.sinif else "GEN").upper()
    rand = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"{ders_adi}-{sinif}-{rand}"

@event.listens_for(Soru, 'before_insert')
def set_reference_code(mapper, connection, target):
    if not target.reference_code:
        code = generate_reference_code(target)
        # Benzersizliği kontrol et
        from SF.models import Soru as SoruModel  # Dairesel importu önlemek için
        while SoruModel.query.filter_by(reference_code=code).first():
            code = generate_reference_code(target)
        target.reference_code = code
