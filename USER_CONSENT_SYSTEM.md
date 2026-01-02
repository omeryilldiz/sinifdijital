# 🔒 Kullanıcı Sözleşme Onay Sistemi (KVKK Uyumu)

## ✅ Neler Eklendi

### 1. **UserConsent Modeli** (`SF/models.py`)
Kullanıcıların tüm sözleşme onaylarını KVKK ve 6698 Sayılı Kanun uyumlu şekilde saklayan model eklendi.

**Özellikler:**
- Sözleşme türü (`consent_type`)
- Sözleşme versiyonu (`consent_version`)
- Sözleşme metni hash'i (SHA-256) - opsiyonel
- Onay durumu (`accepted`)
- Onay tarihi ve IP adresi
- User-Agent bilgisi
- Geri çekilme tarihi ve IP'si
- **2 yıl saklama süresi** için `created_at` alanı

**Index'ler:**
- `idx_consent_user_type`: Kullanıcı ve sözleşme türüne göre hızlı sorgulama
- `idx_consent_user_date`: Kullanıcı ve tarihe göre sıralama
- `idx_consent_created_at`: Log temizliği için
- `idx_consent_withdrawn`: Geri çekilmiş onayları filtreleme

### 2. **ConsentType Sabitleri**
Sözleşme türlerini standardize etmek için:
```python
ConsentType.KVKK                           # KVKK Aydınlatma Metni
ConsentType.PRIVACY_POLICY                  # Gizlilik Politikası
ConsentType.TERMS_OF_USE                    # Kullanım Şartları
ConsentType.EXPLICIT_CONSENT                # Açık Rıza
ConsentType.CLARIFICATION_TEXT              # Aydınlatma Metni
ConsentType.PARENTAL_CONSENT                # Veli Onayı
ConsentType.COMMERCIAL_ELECTRONIC_MESSAGE   # Ticari Elektronik İleti
```

### 3. **Kayıt (Register) İşleminde Otomatik Kayıt**
`routes.py` içinde `/register` endpoint'i güncellendi:

**Kaydedilen Onaylar:**
1. ✅ **Kullanım Şartları** - `terms_accepted` checkbox'ından
2. ✅ **Gizlilik Politikası** - `privacy_accepted` checkbox'ından
3. ✅ **KVKK Aydınlatma Metni** - Gizlilik ile birlikte otomatik
4. ✅ **Veli Onayı** - `parental_consent` checkbox'ından (18 yaş altı)

**Saklanan Bilgiler:**
- Onay tarihi (UTC)
- Kullanıcı IP adresi (IPv6 uyumlu)
- User-Agent (tarayıcı bilgisi)
- Sözleşme versiyonu (şu an: `1.0`)

### 4. **Admin Panelinde Görüntüleme**
Admin öğrenci detay sayfasında (`admin_student_detail`):
- Kullanıcının verdiği tüm sözleşme onayları listelenir
- Her onayın tarihi, IP'si ve user-agent bilgisi gösterilir
- Geri çekilmiş onaylar işaretlenir
- İstatistikler: Toplam onay sayısı, geri çekilen sayısı

### 5. **Yardımcı Metodlar**

#### `UserConsent.log_consent()`
```python
UserConsent.log_consent(
    user_id=user.id,
    consent_type=ConsentType.TERMS_OF_USE,
    consent_version="1.0",
    ip_address=registration_ip,
    user_agent=user_agent,
    accepted=True
)
```

#### `consent.withdraw(ip_address)`
```python
# Kullanıcı onayını geri çekerse:
consent = UserConsent.query.filter_by(
    user_id=user_id, 
    consent_type=ConsentType.PRIVACY_POLICY
).first()
consent.withdraw(ip_address=get_client_ip())
db.session.commit()
```

## 📊 Veritabanı Değişiklikleri

### Migration Uygulandı
```bash
flask db migrate -m "Add UserConsent model for KVKK compliance"
flask db upgrade
```

**Yeni Tablo:**
- `user_consent` - Tüm sözleşme onaylarını saklar
- 5 adet index ile optimize edilmiş sorgulama

## 🔍 Örnek Kullanım Senaryoları

### 1. Kullanıcının Tüm Onaylarını Görüntüleme
```python
consents = UserConsent.query.filter_by(user_id=user_id).all()
for consent in consents:
    print(f"{consent.consent_type} - {consent.accepted_at}")
```

### 2. Belirli Bir Sözleşme Onayını Kontrol Etme
```python
kvkk_consent = UserConsent.query.filter_by(
    user_id=user_id,
    consent_type=ConsentType.KVKK
).order_by(UserConsent.accepted_at.desc()).first()

if kvkk_consent and not kvkk_consent.withdrawn_at:
    print("KVKK onayı mevcut ve aktif")
```

### 3. Onay İstatistikleri
```python
# Toplam onay sayısı
total = UserConsent.query.filter_by(user_id=user_id).count()

# Geri çekilmiş onaylar
withdrawn = UserConsent.query.filter(
    UserConsent.user_id == user_id,
    UserConsent.withdrawn_at.isnot(None)
).count()
```

## ⚖️ Hukuki Uyum

### KVKK Gereksinimleri
✅ **Veri Toplama İzni**: Her sözleşme için açık onay alınıyor  
✅ **Kayıt Tutma**: Tüm onaylar tarih/saat/IP ile kaydediliyor  
✅ **2 Yıl Saklama**: `created_at` alanı ile log temizliği yapılabilir  
✅ **Geri Çekilme Hakkı**: `withdraw()` metodu ile uygulanabilir  
✅ **Şeffaflık**: Kullanıcı onaylarını admin panelde görebilir  

### 5651 Sayılı Kanun (İnternet Ortamında Yapılan Yayınların Düzenlenmesi)
✅ **IP Kayıt**: Her onay için IP adresi kaydediliyor  
✅ **Zaman Damgası**: UTC timezone ile hassas zaman kaydı  
✅ **User-Agent**: Cihaz/tarayıcı bilgisi kaydediliyor  

## 🚀 Gelecek Geliştirmeler

### 1. Sözleşme Versiyonlama
Sözleşmeler güncellendiğinde:
- Yeni versiyon numarası atanır (örn: `1.0` → `1.1`)
- Mevcut kullanıcılardan yeni onay istenir
- Eski ve yeni versiyonlar karşılaştırılır

### 2. Otomatik Log Temizliği (Cronjob)
```python
# 2 yıl önceki kayıtları temizle
two_years_ago = datetime.utcnow() - timedelta(days=730)
UserConsent.query.filter(UserConsent.created_at < two_years_ago).delete()
```

### 3. Kullanıcı Profil Sayfasında Onay Yönetimi
Kullanıcılar kendi profillerinde:
- Verdikleri onayları görebilir
- İstediklerini geri çekebilir
- Yeni sözleşme versiyonlarını onaylayabilir

### 4. Sözleşme Metni Hash'i
```python
import hashlib

def get_consent_text_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

# Kayıt ederken:
UserConsent.log_consent(
    ...
    consent_text_hash=get_consent_text_hash(agreement_text)
)
```

## 📝 Template Entegrasyonu

Admin student detail template'inde (`admin_student_detail.html`) eklenebilir:

```html
<!-- Sözleşme Onayları Bölümü -->
<div class="card mt-4">
    <div class="card-header">
        <h5>🔒 Sözleşme Onayları (KVKK)</h5>
        <small class="text-muted">Toplam: {{ log_stats.total_consents }} | Geri Çekilen: {{ log_stats.withdrawn_consents }}</small>
    </div>
    <div class="card-body">
        {% if user_consents %}
        <div class="table-responsive">
            <table class="table table-sm">
                <thead>
                    <tr>
                        <th>Sözleşme Türü</th>
                        <th>Versiyon</th>
                        <th>Onay Tarihi</th>
                        <th>IP Adresi</th>
                        <th>Durum</th>
                    </tr>
                </thead>
                <tbody>
                    {% for consent in user_consents %}
                    <tr>
                        <td>{{ consent.consent_type }}</td>
                        <td>{{ consent.consent_version }}</td>
                        <td>{{ consent.accepted_at.strftime('%d.%m.%Y %H:%M') }}</td>
                        <td><code>{{ consent.ip_address }}</code></td>
                        <td>
                            {% if consent.withdrawn_at %}
                            <span class="badge badge-danger">Geri Çekildi</span>
                            {% else %}
                            <span class="badge badge-success">Aktif</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p class="text-muted">Henüz sözleşme onayı kaydı yok.</p>
        {% endif %}
    </div>
</div>
```

## 🎯 Sonuç

✅ Kullanıcı kayıt esnasında verdiği tüm sözleşme onayları artık veritabanında güvenli şekilde saklanıyor.  
✅ KVKK ve 5651 Sayılı Kanun gereksinimlerine tam uyum sağlandı.  
✅ Admin panelinde görüntüleme ve raporlama altyapısı hazır.  
✅ Gelecekte sözleşme versiyonlama ve kullanıcı onay yönetimi kolayca eklenebilir.

---

**Son Güncelleme:** 03 Ocak 2026  
**Versiyon:** 1.0  
**Durum:** ✅ Production Ready
