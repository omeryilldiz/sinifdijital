# 🚀 Production Deployment Rehberi - SinifDijital.com

## 📋 İçindekiler
1. [Ön Gereksinimler](#ön-gereksinimler)
2. [Sunucu Kurulumu](#sunucu-kurulumu)
3. [DNS Ayarları](#dns-ayarları)
4. [Docker & Uygulama Kurulumu](#docker--uygulama-kurulumu)
5. [SSL Sertifikası Kurulumu](#ssl-sertifikası-kurulumu)
6. [Production'a Geçiş](#productiona-geçiş)
7. [Güvenlik Kontrolleri](#güvenlik-kontrolleri)
8. [Monitoring & Bakım](#monitoring--bakım)
9. [Troubleshooting](#troubleshooting)

---

## 🎯 Ön Gereksinimler

### Sunucu Gereksinimleri
- **İşletim Sistemi**: Ubuntu 22.04 LTS veya Debian 11+
- **RAM**: Minimum 2GB (Önerilen: 4GB+)
- **CPU**: 2 Core+
- **Disk**: 20GB+ SSD
- **Network**: Statik IP adresi

### Domain Gereksinimleri
- Domain: `sinifdijital.com` (satın alınmış)
- DNS yönetim erişimi
- Email adresi (SSL sertifikası için)

### Gerekli Bilgiler
```
DOMAIN: sinifdijital.com
EMAIL: admin@sinifdijital.com
SUNUCU_IP: [VDS IP adresiniz]
```

---

## 🖥️ Sunucu Kurulumu

### 1. Sunucuya Bağlanma
```bash
ssh root@[SUNUCU_IP]
```

### 2. Sistem Güncellemeleri
```bash
apt update && apt upgrade -y
apt install -y curl wget git vim ufw fail2ban
```

### 3. Güvenlik Duvarı Ayarları
```bash
# UFW kurulumu ve ayarları
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw enable
ufw status
```

### 4. Fail2ban Kurulumu (Brute-force koruması)
```bash
systemctl enable fail2ban
systemctl start fail2ban
```

### 5. Docker Kurulumu
```bash
# Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Docker repository
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Docker kurulumu
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Docker servisi
systemctl enable docker
systemctl start docker

# Doğrulama
docker --version
docker compose version
```

---

## 🌐 DNS Ayarları

Domain sağlayıcınızın (GoDaddy, Namecheap, vb.) DNS yönetim panelinde:

### A Kayıtları (A Records)
```
Tip     Host                Değer              TTL
A       @                   [SUNUCU_IP]        3600
A       www                 [SUNUCU_IP]        3600
```

### Doğrulama (10-15 dk sonra)
```bash
# Ana domain
dig sinifdijital.com +short

# WWW subdomain
dig www.sinifdijital.com +short

# Her ikisi de SUNUCU_IP'nizi göstermeli
```

---

## 🐳 Docker & Uygulama Kurulumu

### 1. Proje Klonlama
```bash
cd /opt
git clone https://github.com/[YOUR-REPO]/SF.git
cd SF
```

### 2. Docker Secrets Oluşturma
```bash
# Secrets dizini
mkdir -p deploy/secrets
cd deploy/secrets

# SECRET_KEY oluştur (güçlü, rastgele)
python3 -c "import secrets; print(secrets.token_hex(32))" > secret_key.txt

# PostgreSQL şifresi
echo "GÜVENLİ_POSTGRES_ŞİFRESİ_BURAYA" > postgres_password.txt

# Redis şifresi
echo "GÜVENLİ_REDIS_ŞİFRESİ_BURAYA" > redis_password.txt

# Mail şifresi
echo "MAIL_ŞİFRESİ_BURAYA" > mail_password.txt

# Google OAuth credentials
echo "GOOGLE_CLIENT_ID_BURAYA" > google_client_id.txt
echo "GOOGLE_CLIENT_SECRET_BURAYA" > google_client_secret.txt

# İzinleri kısıtla (GÜVENLİK!)
chmod 400 *.txt
cd ../..
```

### 3. Environment Dosyası (.env.production)
```bash
cat > .env.production << 'EOF'
FLASK_ENV=production
DEBUG=False

# Database
DB_HOST=db
DB_PORT=5432
DB_USER=sfuser
DB_NAME=sfdb
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=10
DATABASE_POOL_TIMEOUT=60

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0

# Mail
MAIL_SERVER=smtp.hostinger.com
MAIL_PORT=465
MAIL_USE_TLS=False
MAIL_USE_SSL=True
MAIL_USERNAME=omeryildiz@sinifdijital.com
MAIL_DEFAULT_SENDER=noreply@sinifdijital.com

# Security
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Strict

# Domain
SERVER_NAME=sinifdijital.com
PREFERRED_URL_SCHEME=https
BASE_URL=https://sinifdijital.com

# Admin Security
ADMIN_URL_PREFIX=/yonetim-panel-x9k2m
EMERGENCY_RECOVERY_PASSWORD=ultra-secret-recovery-key-2026-sf

# Performance
GUNICORN_WORKERS=1
MAX_CONTENT_LENGTH=16777216
SLOW_QUERY_THRESHOLD_MS=100
CACHE_TIMEOUT=300
EOF
```

### 4. Docker Compose ile Başlatma (İlk Kez)
```bash
# Image build
docker compose build

# Container'ları başlat (SSL olmadan)
docker compose up -d

# Logları kontrol et
docker compose logs -f web

# Health check
curl http://localhost:5000/health
# Yanıt: {"status":"healthy"}
```

### 5. Database Initialization
```bash
# Web container'a gir
docker exec -it sf-web-1 bash

# Flask shell ile tablo oluştur
python -c "from SF import app, db; app.app_context().push(); db.create_all(); print('Tables created!')"

# Admin kullanıcı oluştur
python -c "
from SF import app, db
from SF.models import User
from werkzeug.security import generate_password_hash

app.app_context().push()

admin = User(
    username='admin',
    email='admin@sinifdijital.com',
    password=generate_password_hash('GÜVENLİ_ADMIN_ŞİFRESİ'),
    role='admin',
    is_verified=True,
    email_verified=True
)
db.session.add(admin)
db.session.commit()
print('Admin user created!')
"

exit
```

---

## 🔒 SSL Sertifikası Kurulumu

### 1. Certbot Kurulumu
```bash
apt install -y certbot python3-certbot-nginx
```

### 2. Webroot Dizini Oluştur
```bash
mkdir -p /var/www/letsencrypt
chown -R www-data:www-data /var/www/letsencrypt
```

### 3. Nginx Konfigürasyonu Güncelleme
```bash
# Geçici olarak nginx container'ı durdur
docker compose stop nginx

# Host'ta nginx kur (sadece SSL için)
apt install -y nginx

# SF nginx config'i kopyala
cp /opt/SF/deploy/nginx-sf.conf /etc/nginx/sites-available/sinifdijital
ln -sf /etc/nginx/sites-available/sinifdijital /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Nginx testi ve restart
nginx -t
systemctl restart nginx
```

### 4. SSL Sertifikası Al
```bash
certbot --nginx \
  -d sinifdijital.com \
  -d www.sinifdijital.com \
  --agree-tos \
  --email admin@sinifdijital.com \
  --non-interactive \
  --redirect
```

### 5. Sertifika Yenileme Testi
```bash
certbot renew --dry-run
```

### 6. Docker Nginx'e Geri Dön
```bash
# Host nginx'i durdur
systemctl stop nginx
systemctl disable nginx

# Docker Compose'da nginx volume'ü düzenle
# /etc/letsencrypt sertifikaları nginx container'a mount et

# docker-compose.yml'de nginx service'ine ekle:
# volumes:
#   - /etc/letsencrypt:/etc/letsencrypt:ro

# Container'ları yeniden başlat
cd /opt/SF
docker compose up -d

# SSL testi
curl -I https://sinifdijital.com
```

---

## ✅ Production'a Geçiş

### 1. Final Kontroller
```bash
# Container durumları
docker compose ps

# Tüm servisler "healthy" olmalı
docker compose ps | grep -E "healthy|Up"

# Web container logları
docker compose logs web | tail -50

# Database bağlantısı
docker exec sf-web-1 python -c "from SF import app, db; app.app_context().push(); print('Users:', db.session.query(db.func.count(db.text('*'))).select_from(db.text('\"User\"')).scalar())"
```

### 2. Uygulama Testi
```bash
# Ana sayfa
curl -I https://sinifdijital.com

# Admin panel (honeypot)
curl -I https://sinifdijital.com/admin
# 404 dönmeli

# Gerçek admin panel
curl -I https://sinifdijital.com/yonetim-panel-x9k2m
# 200 OK dönmeli (login sayfası)

# Health check
curl https://sinifdijital.com/health
```

### 3. Browser Testleri
- ✅ Ana sayfa yüklenme
- ✅ HTTPS redirect çalışıyor mu
- ✅ Statik dosyalar (CSS, JS, resimler) yükleniyor mu
- ✅ Login/Register işlemleri
- ✅ Admin panel erişimi
- ✅ Honeypot logu kontrol et

### 4. Performance Testi
```bash
# Apache Bench ile yük testi
apt install -y apache2-utils

ab -n 100 -c 10 https://sinifdijital.com/
# 100 istek, 10 concurrent
```

---

## 🔐 Güvenlik Kontrolleri

### 1. SSL Güvenlik Skoru
```bash
# Qualys SSL Labs test
# https://www.ssllabs.com/ssltest/analyze.html?d=sinifdijital.com
# Hedef: A+ rating
```

### 2. Security Headers
```bash
curl -I https://sinifdijital.com | grep -E "Strict-Transport|X-Frame|X-Content"

# Olması gerekenler:
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
```

### 3. Admin Panel Güvenlik
```bash
# Honeypot test
curl -I https://sinifdijital.com/admin
# 404 dönmeli

# Gerçek admin test
curl -I https://sinifdijital.com/yonetim-panel-x9k2m
# 200 dönmeli

# Honeypot logları
docker logs sf-web-1 | grep HONEYPOT
```

### 4. Rate Limiting Test
```bash
# 10 hızlı istek gönder
for i in {1..10}; do curl -I https://sinifdijital.com/admin 2>&1 | grep HTTP; done
# 429 Too Many Requests dönmeli (rate limit)
```

### 5. File Permissions
```bash
# Secrets dosyaları
ls -la /opt/SF/deploy/secrets/
# -r-------- root root (400) olmalı

# Upload dizinleri
docker exec sf-web-1 ls -ld /app/SF/static/*uploads
# drwxr-xr-x appuser appuser olmalı
```

---

## 📊 Monitoring & Bakım

### 1. Log Yönetimi
```bash
# Container logları
docker compose logs -f --tail=100

# Sadece hata logları
docker compose logs web | grep -i error

# Nginx access logları
docker exec sf-nginx-1 cat /var/log/nginx/access.log | tail -50

# Nginx error logları
docker exec sf-nginx-1 cat /var/log/nginx/error.log | tail -50
```

### 2. Database Backup
```bash
# Manuel backup
docker exec sf-db-1 pg_dump -U sfuser -d sfdb > backup_$(date +%Y%m%d_%H%M%S).sql

# Otomatik backup script'i çalıştır
chmod +x /opt/SF/scripts/db_backup.sh
/opt/SF/scripts/db_backup.sh

# Cron job ekle (her gün gece 3'te)
crontab -e
# 0 3 * * * /opt/SF/scripts/db_backup.sh
```

### 3. Disk Kullanımı
```bash
# Genel disk durumu
df -h

# Docker disk kullanımı
docker system df

# Upload dosyaları
du -sh /opt/SF/SF/static/*uploads

# Docker cleanup (dikkatli!)
docker system prune -a --volumes  # TEHLİKELİ: Tüm kullanılmayan container/image/volume'leri siler
```

### 4. Resource Monitoring
```bash
# Container resource kullanımı
docker stats

# Top processes
docker exec sf-web-1 top -bn1

# Memory kullanımı
free -h

# CPU load
uptime
```

### 5. Güncelleme Prosedürü
```bash
cd /opt/SF

# 1. Backup al
docker exec sf-db-1 pg_dump -U sfuser -d sfdb > backup_before_update.sql

# 2. Yeni kodu çek
git pull origin main

# 3. Image'i yeniden build et
docker compose build

# 4. Container'ları güncelle (zero-downtime için rolling update)
docker compose up -d --no-deps web

# 5. Health check
sleep 30
docker compose ps
curl https://sinifdijital.com/health

# 6. Logları kontrol et
docker compose logs web --tail=50
```

---

## 🔧 Troubleshooting

### Problem: Container başlamıyor
```bash
# Logs kontrol et
docker compose logs web

# Common issues:
# - Database bağlantısı: DB_HOST, postgres_password secret
# - Port conflict: 5000 portu başka bir servis kullanıyor mu?
# - Memory: Yeterli RAM var mı?

# Manuel başlatma denemesi
docker compose down
docker compose up web
```

### Problem: SSL sertifikası yenilenmiyor
```bash
# Certbot logs
journalctl -u certbot

# Manuel yenileme
certbot renew --force-renewal

# Cron job kontrol
systemctl status certbot.timer
```

### Problem: 502 Bad Gateway
```bash
# Web container çalışıyor mu?
docker compose ps web

# Gunicorn çalışıyor mu?
docker exec sf-web-1 ps aux | grep gunicorn

# Upstream connection
docker exec sf-nginx-1 wget -O- http://web:5000/health

# Nginx config test
docker exec sf-nginx-1 nginx -t
```

### Problem: Yavaş performans
```bash
# Database query logs
docker compose logs web | grep "SLOW QUERY"

# Resource kullanımı
docker stats

# Database connection pool
docker exec sf-web-1 python -c "from SF import app; app.app_context().push(); from SF.models import db; print('Pool size:', db.engine.pool.size())"

# Gunicorn worker sayısı (şu an 1)
# Artırmak için: docker-compose.yml'de GUNICORN_WORKERS=2
```

### Problem: Database connection pool exhausted
```bash
# Pool ayarları kontrol et
docker exec sf-web-1 python -c "from SF import app; print(app.config['SQLALCHEMY_ENGINE_OPTIONS'])"

# Aktif bağlantılar
docker exec sf-db-1 psql -U sfuser -d sfdb -c "SELECT count(*) FROM pg_stat_activity;"

# Pool boyutunu artır: .env'de DATABASE_POOL_SIZE=20
```

### Problem: Admin panel erişilemiyor
```bash
# Config kontrol
docker exec sf-web-1 python -c "from SF import app; print('ADMIN_URL:', app.config.get('ADMIN_URL_PREFIX'))"

# Route kontrol
docker exec sf-web-1 python -c "from SF import app; print([rule.rule for rule in app.url_map.iter_rules() if 'admin' in rule.rule][:5])"

# Environment variable
docker exec sf-web-1 env | grep ADMIN_URL_PREFIX
```

### Emergency: Tüm sistemi resetleme
```bash
# ⚠️ DİKKAT: Tüm data silinir!

# 1. Backup al
docker exec sf-db-1 pg_dump -U sfuser -d sfdb > emergency_backup.sql

# 2. Tüm container'ları durdur ve sil
docker compose down -v

# 3. Image'leri sil
docker rmi sf-web:latest

# 4. Yeniden başlat
docker compose up -d --build

# 5. Database restore
docker exec -i sf-db-1 psql -U sfuser -d sfdb < emergency_backup.sql
```

---

## 📝 Production Checklist

### Pre-Launch
- [ ] DNS kayıtları doğru (sinifdijital.com → SUNUCU_IP)
- [ ] SSL sertifikası aktif (HTTPS çalışıyor)
- [ ] Docker secrets oluşturuldu ve güvenli (chmod 400)
- [ ] Admin kullanıcı oluşturuldu
- [ ] Database migration tamamlandı
- [ ] Tüm environment variables ayarlandı
- [ ] Gunicorn worker sayısı ayarlandı (1 worker = OK)
- [ ] Memory limit ayarlandı (1GB)

### Security
- [ ] Admin URL değiştirildi (/yonetim-panel-x9k2m)
- [ ] Honeypot aktif (/admin → 404)
- [ ] Rate limiting çalışıyor
- [ ] Security headers eklendi
- [ ] HTTPS redirect aktif
- [ ] SESSION_COOKIE_SECURE=True
- [ ] UFW firewall aktif (80, 443, SSH)
- [ ] Fail2ban aktif
- [ ] SSH key-based authentication (opsiyonel ama önerilen)

### Monitoring
- [ ] Health check endpoint çalışıyor (/health)
- [ ] Log rotation ayarlandı
- [ ] Database backup cron job aktif
- [ ] SSL auto-renewal aktif (certbot timer)
- [ ] Disk space monitoring
- [ ] Uptime monitoring (UptimeRobot, Pingdom vb.)

### Performance
- [ ] Static files cache headers eklendi (30 gün)
- [ ] Gzip compression aktif
- [ ] Database connection pool optimize edildi
- [ ] Slow query logging aktif
- [ ] CDN kullanımı (opsiyonel, ileride)

### Backup & Recovery
- [ ] Database backup script çalışıyor
- [ ] Backup retention policy belirlendi (30 gün)
- [ ] Disaster recovery planı hazır
- [ ] Restore testi yapıldı

---

## 🎯 Go-Live Steps

### 1. Final DNS Değişikliği
```bash
# Domain sağlayıcınızda A record'u güncelle
# @ → [SUNUCU_IP]
# www → [SUNUCU_IP]

# Propagation kontrolü (15-30 dakika)
watch -n 10 'dig sinifdijital.com +short'
```

### 2. SSL Force
```bash
# HTTP → HTTPS redirect kontrol
curl -I http://sinifdijital.com
# Location: https://sinifdijital.com dönmeli
```

### 3. Cache Clear
```bash
# Browser cache temizle
# Redis cache temizle
docker exec sf-redis-1 redis-cli FLUSHALL
```

### 4. Announcement
```bash
# Site canlı!
echo "🚀 SinifDijital.com is now LIVE!"
echo "URL: https://sinifdijital.com"
echo "Admin: https://sinifdijital.com/yonetim-panel-x9k2m"
```

---

## 📞 Support & Resources

### Useful Commands
```bash
# Container restart
docker compose restart web

# Full restart
docker compose down && docker compose up -d

# Logs (real-time)
docker compose logs -f

# Database access
docker exec -it sf-db-1 psql -U sfuser -d sfdb

# Web shell
docker exec -it sf-web-1 bash

# Admin URL göster
docker exec sf-web-1 flask show-admin-url
```

### Documentation
- Flask: https://flask.palletsprojects.com/
- Docker Compose: https://docs.docker.com/compose/
- Nginx: https://nginx.org/en/docs/
- PostgreSQL: https://www.postgresql.org/docs/
- Let's Encrypt: https://letsencrypt.org/docs/

### Monitoring Tools (Önerilen)
- **Uptime**: UptimeRobot, Pingdom
- **Logs**: Sentry, Papertrail
- **Performance**: New Relic, Datadog
- **Errors**: Sentry.io

---

**Son Güncelleme**: 2026-01-01  
**Versiyon**: 1.0  
**Hazırlayan**: GitHub Copilot

🎉 **Başarılar! SinifDijital.com artık production'da!** 🎉
