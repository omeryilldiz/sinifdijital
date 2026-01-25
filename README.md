# SF - Öğrenci Öğrenme Platformu

Flask tabanlı, öğrencilerin soru çözerek gelişimlerini takip edebilecekleri modern bir öğrenme platformu.

## 🚀 Özellikler

### 📚 Eğitim Sistemi
- **Çoktan Seçmeli Testler**: Sınıf, ders, ünite ve içerik bazlı filtreleme
- **Yanlış Tekrar Sistemi**: Son çözümde yanlış yapılan soruları tekrar çözme
- **Tek Soru Modu**: Sorulara odaklanmış çalışma
- **Video Çözümler**: Her soru için video ve görsel çözüm desteği
- **Canvas Çizim Aracı**: Soru üzerine çizim yapma imkanı

### 📊 İlerleme Takibi
- **Detaylı İstatistikler**: Günlük, haftalık, aylık performans analizi
- **İlerleme Patikası**: Görsel ağaç yapısında konu tamamlama durumu
- **Başarı Oranları**: Ders ve ünite bazında başarı metrikleri
- **Zaman Takibi**: Soru çözme ve içerik okuma sürelerinin kaydı

### 🏆 Liderlik Sistemi
- **Çoklu Sıralama**: Genel, il, okul ve sınıf bazında liderlik tabloları
- **Güncel/Haftalık/Aylık**: Farklı zaman aralıklarında sıralama
- **Yarışma Grupları**: Sınıf bazlı özel yarışma grupları (LGS, TYT, AYT)

### 🔐 Güvenlik
- **Rate Limiting**: API ve endpoint koruması
- **CSRF Protection**: Form güvenliği
- **Password Strength**: Güçlü şifre kontrolü
- **Honeypot Admin**: Sahte admin paneli ile güvenlik
- **User Consent System**: KVKK/GDPR uyumlu onay sistemi

### 🎨 Modern Arayüz
- **Responsive Design**: Mobil uyumlu tasarım
- **Dark Mode Ready**: Koyu tema desteği hazır
- **Bootstrap 5**: Modern component library
- **Chart.js**: İnteraktif grafikler
- **Font Awesome**: Zengin ikon seti

## 🛠️ Teknoloji Stack

### Backend
- **Flask 3.0.0**: Web framework
- **SQLAlchemy**: ORM
- **PostgreSQL 16**: Veritabanı
- **Redis 7**: Cache ve session yönetimi
- **Gunicorn**: Production WSGI server

### Frontend
- **Bootstrap 5.3**: UI framework
- **Chart.js 4.4**: Grafikler
- **Font Awesome 6.5**: İkonlar
- **jQuery 3.7**: DOM manipulation

### DevOps
- **Docker & Docker Compose**: Containerization
- **Nginx**: Reverse proxy
- **Certbot**: SSL/TLS sertifikaları
- **Systemd**: Service management

## 📦 Kurulum

### Gereksinimler
- Docker & Docker Compose
- Python 3.11+
- PostgreSQL 16
- Redis 7

### Hızlı Başlangıç

```bash
# Repository'yi klonla
git clone <repository-url>
cd SF

# Secrets klasörünü oluştur
mkdir -p deploy/secrets

# Gerekli secret dosyalarını oluştur
python scripts/generate_env.py

# Docker ile başlat
docker compose up -d

# Veritabanı migration
docker compose exec web flask db upgrade

# Test verisi yükle (opsiyonel)
./add_test_data.sh
```

### Manuel Kurulum

```bash
# Virtual environment oluştur
python3 -m venv .venv
source .venv/bin/activate

# Bağımlılıkları yükle
pip install -r requirements.txt

# Environment değişkenlerini ayarla
cp .env.example .env
# .env dosyasını düzenle

# PostgreSQL ve Redis'i başlat
# Database oluştur
createdb sfdb

# Migration
flask db upgrade

# Geliştirme sunucusunu başlat
flask run --debug
```

## 🔧 Yapılandırma

### Environment Variables

```bash
# Flask
SECRET_KEY=your-secret-key
FLASK_ENV=production
ADMIN_URL_PREFIX=/secure-admin-path

# Database
DATABASE_URL=postgresql://user:pass@localhost/dbname

# Redis
REDIS_URL=redis://localhost:6379/0

# Email (SMTP)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Google OAuth
GOOGLE_OAUTH_CLIENT_ID=your-client-id
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret

# Security
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
```

### Secrets (Production)

```bash
deploy/secrets/
├── secret_key.txt
├── postgres_password.txt
├── redis_password.txt
├── mail_password.txt
├── google_client_id.txt
└── google_client_secret.txt
```

## 🧪 Test

```bash
# Unit testler
pytest

# Performance test
python test_perf.py

# Docker içinde test
docker compose exec web python /app/SF/test_perf.py

# Integration test
./test_perf.sh
```

## 📊 Performans

### Son Optimizasyonlar (v1.1.0)
- **N+1 Query Problemi Çözüldü**: 40-50 sorgu → 5-7 sorgu
- **Batch Operations**: User ve progress verileri toplu çekiliyor
- **Dictionary Caching**: O(1) lookup performansı
- **SQL Aggregation**: Veritabanında hesaplama

### Metrikler
```
Route: /guclendirme-merkezi
Önce:  40-50 queries, ~2-3s
Sonra:  5-7 queries, ~0.5s
İyileştirme: %85-90 ↓
```

## 🐛 Bilinen Sorunlar ve Çözümler

### ✅ Çözülen Kritik Buglar

#### Test Soru Tutarsızlığı (v1.1.0)
**Sorun**: Gösterilen sorular ile değerlendirilen sorular farklıydı
**Çözüm**: Session bazlı soru yönetimi

#### N+1 Query (v1.1.0)
**Sorun**: Nested loop'larda her kayıt için ayrı sorgu
**Çözüm**: Batch queries ve dictionary caching

## 📝 API Dokümantasyonu

### Public Endpoints
```
GET  /                          # Ana sayfa
GET  /login                     # Giriş
POST /login                     # Giriş işlemi
GET  /register                  # Kayıt
POST /register                  # Kayıt işlemi
GET  /<sinif>/<ders>           # Ders detay
GET  /ilerleme-patikasi        # İlerleme takibi
```

### Authenticated Endpoints
```
GET  /dashboard                # Kullanıcı paneli
GET  /coz/<sinif>/<ders>      # Test çözme
POST /coz/<sinif>/<ders>      # Test değerlendirme
GET  /guclendirme-merkezi     # İstatistikler
GET  /dashboard/profile       # Profil düzenleme
```

### Admin Endpoints
```
GET  /secure-admin-path/             # Admin panel
GET  /secure-admin-path/students     # Öğrenci yönetimi
GET  /secure-admin-path/analytics    # Analitik
```

## 🚀 Deployment

### Production Deployment

```bash
# SSL sertifikası al
sudo ./scripts/setup_ssl.sh

# Production deployment
sudo ./scripts/deploy_production.sh

# Service olarak çalıştır
sudo systemctl enable sf-app
sudo systemctl start sf-app
```

### Docker Production

```bash
# Production compose
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Logs
docker compose logs -f web

# Backup
./scripts/db_backup.sh
```

## 📖 Dokümantasyon

Detaylı dokümantasyon için:
- [CHANGELOG.md](CHANGELOG.md) - Versiyon değişiklikleri
- [PERFORMANCE_OPTIMIZATION_COMPLETE.md](PERFORMANCE_OPTIMIZATION_COMPLETE.md) - Performans optimizasyonları
- [PRODUCTION_DEPLOYMENT_GUIDE.md](PRODUCTION_DEPLOYMENT_GUIDE.md) - Production kurulum
- [QUICKSTART.md](QUICKSTART.md) - Hızlı başlangıç

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'feat: Add amazing feature'`)
4. Push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

### Commit Convention
```
feat: Yeni özellik
fix: Bug düzeltmesi
docs: Dokümantasyon
style: Kod formatı
refactor: Kod refactor
perf: Performans iyileştirmesi
test: Test ekleme/düzenleme
chore: Bakım işleri
```

## 📄 Lisans

Bu proje özel bir projedir. Lisans bilgisi için iletişime geçiniz.

## 📧 İletişim

- Website: [Your Website]
- Email: [Your Email]
- Issues: [GitHub Issues]

## 🙏 Teşekkürler

- Flask team
- Bootstrap team
- Chart.js team
- PostgreSQL team
- Tüm katkıda bulunanlar

---

**Not**: Bu proje aktif geliştirme aşamasındadır. Önerileriniz için issue açabilirsiniz
