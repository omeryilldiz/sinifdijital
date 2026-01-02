# Google OAuth Yapılandırma Kontrol Listesi

## 🔍 Problem: Google ile Kayıt/Giriş Çalışmıyor

### ✅ Yapılması Gerekenler:

## 1. Google Cloud Console Kontrolleri

### A) Authorized Redirect URIs
Google Cloud Console'da (https://console.cloud.google.com/apis/credentials):

**Eklenmiş olması gereken URL'ler:**
```
https://sinifdijital.com/login/google/authorized
https://www.sinifdijital.com/login/google/authorized
http://localhost:5000/login/google/authorized  (development için)
```

**UYARI:** `/google_login_callback` değil, `/login/google/authorized` olmalı!

### B) Authorized JavaScript Origins
```
https://sinifdijital.com
https://www.sinifdijital.com
http://localhost:5000  (development için)
```

### C) OAuth Consent Screen
- User Type: External
- Scopes:
  - openid
  - .../auth/userinfo.email
  - .../auth/userinfo.profile
- Test Users: Ekli olmalı (eğer "Testing" modundaysa)

---

## 2. Sistem Yapılandırması Kontrolleri

### ✅ Client ID ve Secret
```bash
# Client ID kontrol
cat /root/SF/deploy/secrets/google_client_id.txt

# Client Secret kontrol  
cat /root/SF/deploy/secrets/google_client_secret.txt
```

### ✅ Environment Variables
`.env` dosyasında:
```
SERVER_NAME=sinifdijital.com
PREFERRED_URL_SCHEME=https
BASE_URL=https://sinifdijital.com
```

---

## 3. Test Etme

### A) Development Modu (Local Test)
```bash
# .env dosyasında FLASK_ENV=development yapın
FLASK_ENV=development
DEBUG=True
OAUTHLIB_INSECURE_TRANSPORT=1

# Docker compose restart
docker compose restart web
```

### B) Production Test
1. Browser'da: https://sinifdijital.com/register
2. "Google ile Kayıt Ol" butonuna tıklayın
3. Console loglarını kontrol edin:
```bash
docker compose logs web --tail=100 -f | grep -i "google\|oauth"
```

---

## 4. Yaygın Hatalar ve Çözümleri

### Hata 1: "redirect_uri_mismatch"
**Çözüm:** Google Console'da redirect URI'ları kontrol edin.
Tam URL: `https://sinifdijital.com/login/google/authorized`

### Hata 2: "access_denied"  
**Çözüm:** OAuth Consent Screen'i yayınlayın veya test user ekleyin.

### Hata 3: "unauthorized_client"
**Çözüm:** Client ID ve Secret'i kontrol edin, yeniden girin.

### Hata 4: HTTPS hatası
**Çözüm:** Production'da `OAUTHLIB_INSECURE_TRANSPORT` kapalı olmalı.
Development'ta açık olmalı.

---

## 5. Debug Logları

Güncel kodda ekli debug logları:
- `app.logger.info("Google callback triggered")`
- `app.logger.info("Fetching user info from Google...")`
- `app.logger.error("Google authorization failed")`

Logları izlemek için:
```bash
docker compose logs web -f
```

---

## 6. Hızlı Düzeltme Komutları

```bash
# Container'ları yeniden başlat
docker compose restart web nginx

# Logları izle
docker compose logs web -f | grep -i google

# Secret'ları kontrol et
cat deploy/secrets/google_client_id.txt
cat deploy/secrets/google_client_secret.txt

# Environment'ı kontrol et
docker compose exec web env | grep GOOGLE
```

---

## 📌 ÖNEMLİ NOTLAR:

1. **Redirect URI Format:** 
   - ✅ Doğru: `https://sinifdijital.com/login/google/authorized`
   - ❌ Yanlış: `https://sinifdijital.com/google_login_callback`

2. **Flask-Dance Öntanımlı Endpoint:**
   - Flask-Dance otomatik olarak `/login/google/authorized` kullanır
   - `redirect_to="google_login_callback"` ile callback fonksiyonunu belirtiyoruz

3. **HTTPS Zorunluluğu:**
   - Production'da HTTPS şart
   - Development için `OAUTHLIB_INSECURE_TRANSPORT=1` gerekli

4. **www subdomain:**
   - Hem `sinifdijital.com` hem `www.sinifdijital.com` eklenmiş olmalı

---

## 🔧 Şu An Yapılan Değişiklikler:

1. ✅ `redirect_url=None` yapıldı (Flask-Dance otomatik belirlesin)
2. ✅ `redirect_to="google_login_callback"` eklendi
3. ✅ Detaylı error logging eklendi
4. ✅ Try-catch ile hata yakalama eklendi

## 📝 Sonraki Adım:

**Google Cloud Console'da Redirect URI'ı kontrol edin ve güncelleyin:**
https://console.cloud.google.com/apis/credentials

Authorized Redirect URIs:
- https://sinifdijital.com/login/google/authorized
- https://www.sinifdijital.com/login/google/authorized
