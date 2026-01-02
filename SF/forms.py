from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, FileField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, URL
from SF.models import User
from SF.services.security_service import SecurityService
import re

def validate_password_strength(form, field):
    """Güçlü şifre politikası kontrolü - SecurityService entegrasyonu"""
    password = field.data
    if not password:
        return
    
    # SecurityService'den validator'u kullan
    is_valid, errors = SecurityService.validate_password_strength(password)
    
    if not is_valid:
        raise ValidationError(f"Şifre gereksinimleri: {', '.join(errors)}")
    
    # Check for breached passwords
    if SecurityService.check_password_breach(password):
        raise ValidationError("Bu şifre çok yaygın. Lütfen daha güçlü bir şifre seçin.")

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message='Email gereklidir'),
        Email(message='Geçerli bir email adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(message='Şifre gereklidir')
    ])
    remember_me = BooleanField('Beni Hatırla')
    submit = SubmitField('Giriş Yap')

class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[
        DataRequired(message='Kullanıcı adı gereklidir'),
        Length(min=2, max=20, message='Kullanıcı adı 2-20 karakter arasında olmalıdır')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email gereklidir'),
        Email(message='Geçerli bir email adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(message="Şifre gereklidir"),
        # Şifre gücü kontrolü için yardımcı fonksiyon
        validate_password_strength
    ])
    confirm_password = PasswordField('Şifre Tekrar', validators=[
        DataRequired(message="Şifre tekrarı gereklidir"),
        EqualTo('password', message="Şifreler eşleşmiyor")
    ])
    
    # ✅ YENİ: Veli Onayı Checkbox'ı (KVKK ve 18 Yaş Altı Uyumu)
    parental_consent = BooleanField(
        '18 yaşından büyük olduğumu veya velimin/yasal vasimin bilgisi ve izni dahilinde siteye üye olduğumu beyan ederim.',
        validators=[DataRequired(message="Devam etmek için bu kutucuğu işaretlemelisiniz.")]
    )
    
    # ✅ YENİ: Kullanıcı Sözleşmesi Onayı
    terms_accepted = BooleanField(
        'Kullanıcı Sözleşmesi\'ni okudum ve kabul ediyorum.',
        validators=[DataRequired(message="Kullanıcı sözleşmesini kabul etmelisiniz.")]
    )
    
    # ✅ YENİ: KVKK/Gizlilik Politikası Onayı
    privacy_accepted = BooleanField(
        'Gizlilik Politikası\'nı okudum ve kişisel verilerimin işlenmesini kabul ediyorum.',
        validators=[DataRequired(message="Gizlilik politikasını kabul etmelisiniz.")]
    )
    
    submit = SubmitField('Kayıt Ol')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('E-posta', validators=[
        DataRequired(message='Email gereklidir'),
        Email(message='Geçerli bir email adresi girin')
    ])
    submit = SubmitField('Sıfırlama Linki Gönder')

    # ✅ GÜVENLİK: Email enumeration saldırılarını önlemek için
    # validate_email metodu kaldırıldı. Kullanıcı var olup olmadığı
    # kontrol edilmez. Her durumda aynı mesaj gösterilir.
        
class PasswordResetForm(FlaskForm):
    password = PasswordField('Yeni Şifre', validators=[
        DataRequired(message="Şifre gereklidir"),
        # Şifre gücü kontrolü için yardımcı fonksiyon
        validate_password_strength
    ])
    confirm_password = PasswordField('Şifre Tekrar', validators=[
        DataRequired(message="Şifre tekrarı gereklidir"),
        EqualTo('password', message="Şifreler eşleşmiyor")
    ])
    submit = SubmitField('Şifreyi Güncelle')

class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message='Email gereklidir'),
        Email(message='Geçerli bir email adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(message='Şifre gereklidir')
    ])
    remember_me = BooleanField('Beni Hatırla')
    submit = SubmitField('Giriş Yap')

class AdminRegisterForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[
        DataRequired(message='Kullanıcı adı gereklidir'),
        Length(min=2, max=20, message='Kullanıcı adı 2-20 karakter arasında olmalıdır')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email gereklidir'),
        Email(message='Geçerli bir email adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(message='Şifre gereklidir')
    ])
    confirm_password = PasswordField('Şifre Tekrar', validators=[
        DataRequired(message='Şifre tekrarı gereklidir'),
        EqualTo('password', message='Şifreler eşleşmiyor')
    ])
    submit = SubmitField('Kayıt Ol')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Bu kullanıcı adı zaten alınmış. Lütfen farklı bir kullanıcı adı seçin.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Bu email adresi zaten kullanılıyor. Lütfen farklı bir email adresi girin.')

class AdminEditForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[
        DataRequired(message='Kullanıcı adı gereklidir'),
        Length(min=2, max=20, message='Kullanıcı adı 2-20 karakter arasında olmalıdır')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email gereklidir'),
        Email(message='Geçerli bir email adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(message='Şifre gereklidir')
    ])
    confirm_password = PasswordField('Şifre Tekrar', validators=[
        DataRequired(message='Şifre tekrarı gereklidir'),
        EqualTo('password', message='Şifreler eşleşmiyor')
    ])
    submit = SubmitField('Güncelle')

class SinifForm(FlaskForm):
    sinif = StringField('Sınıf Adı', validators=[
        DataRequired(message='Sınıf adı gereklidir')
    ])
    submit = SubmitField('Kaydet')

class DersForm(FlaskForm):
    ders = StringField('Ders Adı', validators=[
        DataRequired(message='Ders adı gereklidir')
    ])
    submit = SubmitField('Kaydet')

class UniteForm(FlaskForm):
    unite = StringField('Ünite Adı', validators=[
        DataRequired(message='Ünite adı gereklidir')
    ])
    submit = SubmitField('Kaydet')

class IcerikForm(FlaskForm):
    baslik = StringField('Başlık', validators=[
        DataRequired(message='Başlık gereklidir')
    ])
    icerik = TextAreaField('İçerik', validators=[
        DataRequired(message='İçerik gereklidir')
    ])
    submit = SubmitField('Kaydet')

class SoruEkleForm(FlaskForm):
    sinif = SelectField('Sınıf', coerce=int, validators=[
        DataRequired(message='Sınıf seçimi gereklidir')
    ])
    ders = SelectField('Ders', coerce=int, validators=[
        DataRequired(message='Ders seçimi gereklidir')
    ])
    unite = SelectField('Ünite', coerce=int, validators=[
        DataRequired(message='Ünite seçimi gereklidir')
    ])
    icerik = SelectField('İçerik', coerce=int, validators=[
        DataRequired(message='İçerik seçimi gereklidir')
    ])
    soru = FileField('Soru Resmi', validators=[
        DataRequired(message='Soru resmi gereklidir')
    ])
    cevap = SelectField('Doğru Cevap', choices=[('A', 'A'), ('B', 'B'), ('C', 'C'), ('D', 'D'), ('E', 'E')], validators=[
        DataRequired(message='Doğru cevap seçimi gereklidir')
    ])
    video = FileField('Çözüm Videosu (MP4)', validators=[Optional()])
    cozum_resim = FileField('Çözüm Görseli (WebP)', validators=[Optional()])
    submit = SubmitField('Kaydet')

class SoruEditForm(FlaskForm):
    sinif = SelectField('Sınıf', coerce=int, validators=[
        DataRequired(message='Sınıf seçimi gereklidir')
    ])
    ders = SelectField('Ders', coerce=int, validators=[
        DataRequired(message='Ders seçimi gereklidir')
    ])
    unite = SelectField('Ünite', coerce=int, validators=[
        DataRequired(message='Ünite seçimi gereklidir')
    ])
    icerik = SelectField('İçerik', coerce=int, validators=[
        DataRequired(message='İçerik seçimi gereklidir')
    ])
    soru = FileField('Soru Resmi (Değiştirmek istiyorsanız)')
    cevap = SelectField('Doğru Cevap', choices=[('A', 'A'), ('B', 'B'), ('C', 'C'), ('D', 'D'), ('E', 'E')], validators=[
        DataRequired(message='Doğru cevap seçimi gereklidir')
    ])
    video = FileField('Çözüm Videosu (Değiştirmek istiyorsanız)')
    cozum_resim = FileField('Çözüm Görseli (Değiştirmek istiyorsanız)')
    submit = SubmitField('Güncelle')

class DersNotuForm(FlaskForm):
    sinif = SelectField('Sınıf', coerce=int, validators=[
        DataRequired(message='Sınıf seçimi gereklidir')
    ])
    ders = SelectField('Ders', coerce=int, validators=[
        DataRequired(message='Ders seçimi gereklidir')
    ])
    unite = SelectField('Ünite', coerce=int, validators=[
        DataRequired(message='Ünite seçimi gereklidir')
    ])
    icerik = SelectField('İçerik', coerce=int, validators=[
        DataRequired(message='İçerik seçimi gereklidir')
    ])
    baslik = StringField('Başlık', validators=[
        DataRequired(message='Başlık gereklidir')
    ])
    pdf = FileField('PDF Dosyası', validators=[
        DataRequired(message='PDF dosyası gereklidir')
    ])
    submit = SubmitField('Yükle')

class DersNotuEditForm(FlaskForm):
    sinif = SelectField('Sınıf', coerce=int, validators=[
        DataRequired(message='Sınıf seçimi gereklidir')
    ])
    ders = SelectField('Ders', coerce=int, validators=[
        DataRequired(message='Ders seçimi gereklidir')
    ])
    unite = SelectField('Ünite', coerce=int, validators=[
        DataRequired(message='Ünite seçimi gereklidir')
    ])
    icerik = SelectField('İçerik', coerce=int, validators=[
        DataRequired(message='İçerik seçimi gereklidir')
    ])
    baslik = StringField('Başlık', validators=[
        DataRequired(message='Başlık gereklidir')
    ])
    pdf = FileField('PDF Dosyası (Değiştirmek istiyorsanız)')
    submit = SubmitField('Güncelle')

class VideoForm(FlaskForm):
    sinif = SelectField('Sınıf', coerce=int, validators=[
        DataRequired(message='Sınıf seçimi gereklidir')
    ])
    ders = SelectField('Ders', coerce=int, validators=[
        DataRequired(message='Ders seçimi gereklidir')
    ])
    unite = SelectField('Ünite', coerce=int, validators=[
        DataRequired(message='Ünite seçimi gereklidir')
    ])
    icerik = SelectField('İçerik', coerce=int, validators=[
        DataRequired(message='İçerik seçimi gereklidir')
    ])
    video_url = StringField('Video URL', validators=[
        DataRequired(message='Video URL gereklidir')
    ])
    video_title = StringField('Video Başlığı', validators=[
        DataRequired(message='Video başlığı gereklidir')
    ])
    sira = IntegerField('Sıra', validators=[
        DataRequired(message='Sıra numarası gereklidir')
    ], default=1)
    submit = SubmitField('Kaydet')

class VideoEditForm(FlaskForm):
    sinif = SelectField('Sınıf', coerce=int, validators=[
        DataRequired(message='Sınıf seçimi gereklidir')
    ])
    ders = SelectField('Ders', coerce=int, validators=[
        DataRequired(message='Ders seçimi gereklidir')
    ])
    unite = SelectField('Ünite', coerce=int, validators=[
        DataRequired(message='Ünite seçimi gereklidir')
    ])
    icerik = SelectField('İçerik', coerce=int, validators=[
        DataRequired(message='İçerik seçimi gereklidir')
    ])
    video_url = StringField('Video URL', validators=[
        DataRequired(message='Video URL gereklidir')
    ])
    video_title = StringField('Video Başlığı', validators=[
        DataRequired(message='Video başlığı gereklidir')
    ])
    sira = IntegerField('Sıra', validators=[
        DataRequired(message='Sıra numarası gereklidir')
    ])
    submit = SubmitField('Güncelle')


class CompleteProfileForm(FlaskForm):
    first_name = StringField('Ad', validators=[
        DataRequired(message='Ad gereklidir'),
        Length(min=2, max=50, message='Ad 2-50 karakter arasında olmalıdır')
    ])
    last_name = StringField('Soyad', validators=[
        DataRequired(message='Soyad gereklidir'),
        Length(min=2, max=50, message='Soyad 2-50 karakter arasında olmalıdır')
    ])
    province = SelectField('İl', coerce=int, validators=[
        DataRequired(message='İl seçimi gereklidir')
    ])
    district = SelectField('İlçe', coerce=int, validators=[
        DataRequired(message='İlçe seçimi gereklidir')
    ])
    school_type = SelectField('Okul Türü', coerce=int, validators=[
        DataRequired(message='Okul türü seçimi gereklidir')
    ])
    school = SelectField('Okul', coerce=int, validators=[
        DataRequired(message='Okul seçimi gereklidir')
    ])
    
    # ✅ YENİ SINIF SEÇENEKLERİ
    class_no = SelectField('Sınıf', choices=[
        ('', 'Sınıf Seçiniz'),
        
        # ORTAOKUL
        ('5', '5. Sınıf'),
        ('6', '6. Sınıf'),
        ('7', '7. Sınıf'),
        ('8', '8. Sınıf (LGS Hazırlık dahil)'),
        
        # LİSE
        ('9', '9. Sınıf'),
        ('10', '10. Sınıf'),
        ('11', '11. Sınıf'),
        ('12', '12. Sınıf (TYT + AYT dahil)'),
        
        # MEZUN
        ('Mezun', 'Üniversite Hazırlık (TYT + AYT)')
    ], validators=[DataRequired(message='Sınıf seçimi gereklidir')])
    
    class_name = SelectField('Şube', choices=[
        ('', 'Şube Seçiniz (İsteğe Bağlı)'),
        ('A', 'A'),
        ('B', 'B'),
        ('C', 'C'),
        ('D', 'D'),
        ('E', 'E'),
        ('F', 'F')
    ], validators=[Optional()])  # İsteğe bağlı
    
    submit = SubmitField('Profili Tamamla')

class ProfileUpdateForm(FlaskForm):
    first_name = StringField('Ad', validators=[
        DataRequired(message='Ad gereklidir'),
        Length(min=2, max=50, message='Ad 2-50 karakter arasında olmalıdır')
    ])
    last_name = StringField('Soyad', validators=[
        DataRequired(message='Soyad gereklidir'),
        Length(min=2, max=50, message='Soyad 2-50 karakter arasında olmalıdır')
    ])
    email = StringField('Email', validators=[
        DataRequired(message='Email gereklidir'),
        Email(message='Geçerli bir email adresi girin')
    ])
    phone = StringField('Telefon', validators=[
        Optional(),
        Length(max=15, message='Telefon en fazla 15 karakter olabilir')
    ])
    province = SelectField('İl', coerce=int, validators=[
        DataRequired(message='İl seçimi gereklidir')
    ])
    district = SelectField('İlçe', coerce=int, validators=[
        DataRequired(message='İlçe seçimi gereklidir')
    ])
    school_type = SelectField('Okul Türü', coerce=int, validators=[
        DataRequired(message='Okul türü seçimi gereklidir')
    ])
    school = SelectField('Okul', coerce=int, validators=[
        DataRequired(message='Okul seçimi gereklidir')
    ])
    
    # ✅ YENİ SINIF SEÇENEKLERİ
    class_no = SelectField('Sınıf', choices=[
        ('', 'Sınıf Seçiniz'),
        
        # ORTAOKUL
        ('5', '5. Sınıf'),
        ('6', '6. Sınıf'),
        ('7', '7. Sınıf'),
        ('8', '8. Sınıf (LGS Hazırlık dahil)'),
        
        # LİSE
        ('9', '9. Sınıf'),
        ('10', '10. Sınıf'),
        ('11', '11. Sınıf'),
        ('12', '12. Sınıf (TYT + AYT dahil)'),
        
        # MEZUN
        ('Mezun', 'Üniversite Hazırlık (TYT + AYT)')
    ], validators=[DataRequired(message='Sınıf seçimi gereklidir')])
    
    class_name = SelectField('Şube', choices=[
        ('', 'Şube Seçiniz (İsteğe Bağlı)'),
        ('A', 'A'),
        ('B', 'B'),
        ('C', 'C'),
        ('D', 'D'),
        ('E', 'E'),
        ('F', 'F')
    ], validators=[Optional()])  # İsteğe bağlı
    
    submit = SubmitField('Profili Güncelle')

# ✅ YENİ: Yardımcı fonksiyonlar
def get_class_choices():
    """Form sınıf seçeneklerini döndür"""
    return [
        ('', 'Sınıf Seçiniz'),
        
        # ORTAOKUL
        ('5', '5. Sınıf'),
        ('6', '6. Sınıf'),
        ('7', '7. Sınıf'),
        ('8', '8. Sınıf (LGS Hazırlık dahil)'),
        
        # LİSE
        ('9', '9. Sınıf'),
        ('10', '10. Sınıf'),
        ('11', '11. Sınıf'),
        ('12', '12. Sınıf (TYT + AYT dahil)'),
        
        # MEZUN
        ('Mezun', 'Üniversite Hazırlık (TYT + AYT)')
    ]

def get_branch_choices():
    """Form şube seçeneklerini döndür"""
    return [
        ('', 'Şube Seçiniz (İsteğe Bağlı)'),
        ('A', 'A'),
        ('B', 'B'),
        ('C', 'C'),
        ('D', 'D'),
        ('E', 'E'),
        ('F', 'F')
    ]

def get_class_info(class_no):
    """Sınıf bilgilerini döndür"""
    class_info = {
        '5': {'name': '5. Sınıf', 'level': 'ortaokul', 'group': '5_sinif'},
        '6': {'name': '6. Sınıf', 'level': 'ortaokul', 'group': '6_sinif'},
        '7': {'name': '7. Sınıf', 'level': 'ortaokul', 'group': '7_sinif'},
        '8': {'name': '8. Sınıf', 'level': 'ortaokul', 'group': 'lgs_grubu'},
        '9': {'name': '9. Sınıf', 'level': 'lise', 'group': '9_sinif'},
        '10': {'name': '10. Sınıf', 'level': 'lise', 'group': '10_sinif'},
        '11': {'name': '11. Sınıf', 'level': 'lise', 'group': '11_sinif'},
        '12': {'name': '12. Sınıf', 'level': 'lise', 'group': 'universite_hazirlik'},
        'LGS': {'name': 'LGS Hazırlık', 'level': 'sinav', 'group': 'lgs_grubu'},
        'TYT': {'name': 'TYT Hazırlık', 'level': 'sinav', 'group': 'universite_hazirlik'},
        'AYT': {'name': 'AYT Hazırlık', 'level': 'sinav', 'group': 'universite_hazirlik'},
        'Mezun': {'name': 'Üniversite Hazırlık', 'level': 'mezun', 'group': 'universite_hazirlik'}
    }
    return class_info.get(str(class_no), {'name': 'Bilinmeyen', 'level': 'other', 'group': 'other'})

def get_class_level(class_no):
    """Sınıfın seviyesini döndür (ortaokul/lise/sinav)"""
    info = get_class_info(class_no)
    return info['level']

def get_class_competition_group(class_no):
    """Sınıfın yarışma grubunu döndür"""
    info = get_class_info(class_no)
    return info['group']

def validate_class_selection(class_no, class_name=None):
    """Sınıf seçiminin geçerliliğini kontrol et"""
    valid_classes = ['5', '6', '7', '8', '9', '10', '11', '12', 'LGS', 'TYT', 'AYT', 'Mezun']
    
    if class_no not in valid_classes:
        return False, "Geçersiz sınıf seçimi"
    
    # Sınav hazırlık sınıfları için şube kontrolü
    if class_no in ['LGS', 'TYT', 'AYT'] and class_name:
        # Bu sınıflar için özel şube adları olabilir
        pass
    
    return True, "Geçerli seçim"

class HomepageSlideForm(FlaskForm):
    title = StringField('Başlık', validators=[
        DataRequired(message='Başlık gereklidir')
    ])
    description = TextAreaField('Açıklama', validators=[Optional()])
    image = FileField('Görsel', validators=[Optional()])
    button_text = StringField('Buton Metni', validators=[Optional()])
    button_url = SelectField('Buton Linki', choices=[
        ('', 'Seçiniz'),
        ('/register', 'Kayıt Sayfası'),
        ('/login', 'Giriş Sayfası'),
        ('/dashboard', 'Dashboard'),
        ('tel', 'Telefon Numarası'),
        ('whatsapp', 'WhatsApp Mesaj'),
        ('custom', 'Özel URL')
    ])
    custom_url = StringField('Özel URL', validators=[Optional()])
    phone_number = StringField('Telefon Numarası', validators=[Optional()])
    badge_text = StringField('Rozet Metni', validators=[Optional()])
    badge_color = SelectField('Rozet Rengi', choices=[
        ('bg-danger', 'Kırmızı'), ('bg-warning', 'Sarı'), ('bg-primary', 'Mavi'), ('bg-success', 'Yeşil')
    ], validators=[Optional()])
    slide_type = SelectField('Slayt Tipi', choices=[
        ('normal', 'Normal'), ('reklam', 'Reklam')
    ], validators=[Optional()])
    order = IntegerField('Sıra', validators=[Optional()])
    is_active = BooleanField('Aktif mi?', default=True)



class StudentSearchForm(FlaskForm):
    search = StringField('Arama', render_kw={'placeholder': 'Ad, soyad, kullanıcı adı veya email ara...'})
    class_filter = SelectField('Sınıf', choices=[('', 'Tüm Sınıflar')], default='')
    status_filter = SelectField('Profil Durumu', choices=[
        ('', 'Tümü'),
        ('completed', 'Tamamlanmış'),
        ('incomplete', 'Eksik')
    ], default='')
    province_filter = SelectField('İl', choices=[('', 'Tüm İller')], default='')
    district_filter = SelectField('İlçe', choices=[('', 'Tüm İlçeler')], default='')
    school_filter = SelectField('Okul', choices=[('', 'Tüm Okullar')], default='')
    submit = SubmitField('Filtrele')


class BulkActionForm(FlaskForm):
    action = SelectField('Toplu İşlem', choices=[
        ('', 'İşlem Seçiniz'),
        ('activate', 'Aktif Yap'),
        ('deactivate', 'Pasif Yap'),
        ('delete', 'Sil'),
        ('reset_password', 'Şifre Sıfırla'),
        ('complete_profile', 'Profil Tamamlanmış İşaretle'),
        ('change_class', 'Sınıf Değiştir')
    ], validators=[
        DataRequired(message='İşlem seçimi gereklidir')
    ])
    
    new_class = SelectField('Yeni Sınıf', choices=[
        ('', 'Sınıf Seçiniz'),
        ('5', '5. Sınıf'),
        ('6', '6. Sınıf'),
        ('7', '7. Sınıf'),
        ('8', '8. Sınıf (LGS Hazırlık dahil)'),
        ('9', '9. Sınıf'),
        ('10', '10. Sınıf'),
        ('11', '11. Sınıf'),
        ('12', '12. Sınıf (TYT + AYT dahil)'),
        ('Mezun', 'Üniversite Hazırlık (TYT + AYT)')
    ], validators=[Optional()])
    
    submit = SubmitField('Uygula')
    
    
    

class AdminStudentEditForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[
        DataRequired(message='Kullanıcı adı gereklidir'),
        Length(min=3, max=20, message='Kullanıcı adı 3-20 karakter olmalıdır')
    ])
    
    email = StringField('Email', validators=[
        DataRequired(message='Email gereklidir'),
        Email(message='Geçerli bir email adresi girin')
    ])
    
    first_name = StringField('Ad', validators=[
        Length(max=50, message='Ad en fazla 50 karakter olabilir')
    ])
    
    last_name = StringField('Soyad', validators=[
        Length(max=50, message='Soyad en fazla 50 karakter olabilir')
    ])
    
    password = PasswordField('Yeni Şifre (Opsiyonel)', validators=[
        Optional(),
        Length(min=6, max=100, message='Şifre en az 6 karakter olmalıdır')
    ])
    
    confirm_password = PasswordField('Şifre Tekrar', validators=[
        EqualTo('password', message='Şifreler eşleşmiyor')
    ])
    
    class_no = SelectField('Sınıf', choices=[], default='')
    class_name = StringField('Sınıf Adı/Şube', validators=[
        Length(max=50, message='Sınıf adı en fazla 50 karakter olabilir')
    ])
    
    school_id = SelectField('Okul', choices=[], default='')
    
    profile_completed = BooleanField('Profil Tamamlanmış')
    is_active = BooleanField('Aktif')
    
    submit = SubmitField('Güncelle')
    
    def __init__(self, *args, **kwargs):
        super(AdminStudentEditForm, self).__init__(*args, **kwargs)
        
    def validate_username(self, username):
        # Mevcut kullanıcı hariç username kontrolü
        if hasattr(self, '_obj') and self._obj:
            existing_user = User.query.filter(
                User.username == username.data,
                User.id != self._obj.id
            ).first()
        else:
            existing_user = User.query.filter_by(username=username.data).first()
            
        if existing_user:
            raise ValidationError('Bu kullanıcı adı zaten kullanılıyor.')
    
    def validate_email(self, email):
        # Mevcut kullanıcı hariç email kontrolü
        if hasattr(self, '_obj') and self._obj:
            existing_user = User.query.filter(
                User.email == email.data,
                User.id != self._obj.id
            ).first()
        else:
            existing_user = User.query.filter_by(email=email.data).first()
            
        if existing_user:
            raise ValidationError('Bu email adresi zaten kullanılıyor.')

class ChangePasswordForm(FlaskForm):
    """Profil üzerinden şifre değiştirme formu"""
    current_password = PasswordField('Mevcut Şifre', validators=[
        DataRequired(message="Mevcut şifrenizi girmelisiniz")
    ])
    new_password = PasswordField('Yeni Şifre', validators=[
        DataRequired(message="Yeni şifre gereklidir"),
        validate_password_strength
    ])
    confirm_password = PasswordField('Yeni Şifre Tekrar', validators=[
        DataRequired(message="Şifre tekrarı gereklidir"),
        EqualTo('new_password', message="Şifreler eşleşmiyor")
    ])
    submit = SubmitField('Şifreyi Değiştir')


class ContactForm(FlaskForm):
    """İletişim formu"""
    name = StringField('Adınız', validators=[
        DataRequired(message="Ad gereklidir"),
        Length(min=2, max=50, message="Ad 2-50 karakter arasında olmalıdır")
    ])
    email = StringField('Email Adresiniz', validators=[
        DataRequired(message="Email gereklidir"),
        Email(message="Geçerli bir email adresi girin")
    ])
    subject = StringField('Konu', validators=[
        DataRequired(message="Konu gereklidir"),
        Length(min=5, max=100, message="Konu 5-100 karakter arasında olmalıdır")
    ])
    message = TextAreaField('Mesajınız', validators=[
        DataRequired(message="Mesaj gereklidir"),
        Length(min=10, max=1000, message="Mesaj 10-1000 karakter arasında olmalıdır")
    ])
    submit = SubmitField('Gönder')





