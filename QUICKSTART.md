# 🎯 Quick Start - Production Deployment

## 🚀 Hızlı Başlangıç (5 Adım)

### 1️⃣ Sunucu Hazırlığı
```bash
# Root kullanıcı olarak
sudo su

# Otomatik kurulum script'i çalıştır
cd /opt
git clone https://github.com/YOUR_REPO/SF.git
cd SF
chmod +x scripts/deploy_production.sh
./scripts/deploy_production.sh
```

### 2️⃣ Secrets Dosyalarını Düzenle
```bash
cd /opt/SF/deploy/secrets

# Her dosyayı düzenle ve güvenli şifreler gir
nano secret_key.txt          # Rastgele 64 karakter
nano postgres_password.txt   # Güçlü veritabanı şifresi
nano redis_password.txt      # Güçlü Redis şifresi
nano mail_password.txt       # Email şifreniz
nano google_client_id.txt    # Google OAuth Client ID
nano google_client_secret.txt # Google OAuth Client Secret
```

### 3️⃣ Environment Dosyasını Düzenle
```bash
cd /opt/SF
nano .env

# Önemli değişkenler:
# - MAIL_USERNAME
# - ADMIN_URL_PREFIX (değiştirin!)
# - EMERGENCY_RECOVERY_PASSWORD (değiştirin!)
```

### 4️⃣ Container'ları Yeniden Başlat
```bash
cd /opt/SF
docker compose down
docker compose up -d

# Logları izle
docker compose logs -f web
```

### 5️⃣ SSL Sertifikası Kur
```bash
cd /opt/SF
./scripts/setup_ssl_docker.sh sinifdijital.com admin@sinifdijital.com
```

---

## ✅ Production Checklist

### Zorunlu Adımlar
- [ ] DNS A kayıtları eklendi (@ ve www)
- [ ] Secrets dosyaları düzenlendi
- [ ] .env production değerleriyle dolduruldu
- [ ] Admin kullanıcı oluşturuldu
- [ ] SSL sertifikası kuruldu
- [ ] HTTPS çalışıyor

### Güvenlik
- [ ] ADMIN_URL_PREFIX değiştirildi
- [ ] EMERGENCY_RECOVERY_PASSWORD değiştirildi
- [ ] UFW firewall aktif
- [ ] Fail2ban aktif
- [ ] Secrets dosyaları chmod 400

### Test
- [ ] https://sinifdijital.com açılıyor
- [ ] Admin panel erişilebilir
- [ ] Login/register çalışıyor
- [ ] Static dosyalar yükleniyor
- [ ] Database bağlantısı çalışıyor

---

## 📚 Detaylı Dokümantasyon

**Komple Rehber**: [PRODUCTION_DEPLOYMENT_GUIDE.md](PRODUCTION_DEPLOYMENT_GUIDE.md)

---

## 🆘 Yardım

### Logs Kontrol
```bash
docker compose logs -f
docker compose logs web --tail=100
```

### Container Durumu
```bash
docker compose ps
docker stats
```

### Database Backup
```bash
./scripts/db_backup.sh
```

### SSL Yenileme
```bash
certbot renew --dry-run
```

---

## 📞 Troubleshooting

| Problem | Çözüm |
|---------|-------|
| 502 Bad Gateway | `docker compose restart web` |
| SSL hatası | `./scripts/setup_ssl_docker.sh DOMAIN EMAIL` |
| Admin panel 404 | Config'de ADMIN_URL_PREFIX kontrol et |
| Database bağlantı hatası | postgres_password secret'ı kontrol et |

---

**Başarılar!** 🎉
