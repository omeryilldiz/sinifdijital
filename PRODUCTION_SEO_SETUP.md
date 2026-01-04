# Production Setup Guide - Sınıf Dijital

**Tarih:** 4 Ocak 2026  
**Domain:** https://sinifdijital.com  
**Admin URL:** https://sinifdijital.com/yonetim-panel-x9k2m  

---

## 📋 Production için Tamamlanan Görevler

### ✅ 1. SEO Yapılandırması
- [x] robots.txt dosyası oluşturuldu ([`SF/static/robots.txt`](SF/static/robots.txt))
- [x] Sitemap XML dosyaları oluşturuldu:
  - Ana sitemap: [`SF/static/sitemap.xml`](SF/static/sitemap.xml)
  - Yasal sayfalar: [`SF/static/sitemap-legal.xml`](SF/static/sitemap-legal.xml)
  - Dinamik sitemaplar (backend):
    - `/sitemap-classes.xml` - Tüm sınıflar
    - `/sitemap-courses.xml` - Tüm dersler
    - `/sitemap-content.xml` - Tüm içerikler
- [x] Meta tag'ları layout.html'e eklendi:
  - SEO meta description, keywords
  - Canonical URLs
  - Open Graph (Facebook, LinkedIn)
  - Twitter Cards
  - Apple/Theme color

### ✅ 2. Nginx Konfigürasyonu
- [x] Sitemap ve robots.txt routing'i eklendi ([`deploy/nginx-sf.conf`](deploy/nginx-sf.conf))
- [x] Gzip compression ayarlandı
- [x] Security headers eklendi:
  - HSTS (Strict-Transport-Security)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy

### ✅ 3. Backend Routes
- [x] Sitemap endpoints routes.py'ye eklendi:
  - `/robots.txt` - Static file
  - `/sitemap.xml` - Static file
  - `/sitemap-legal.xml` - Static file
  - `/sitemap-classes.xml` - Dynamic (24h cache)
  - `/sitemap-courses.xml` - Dynamic (24h cache)
  - `/sitemap-content.xml` - Dynamic (24h cache)

### ✅ 4. Caching Strategy
- [x] Static sitemaplar: 1 gün cache
- [x] Dinamik sitemaplar: 24 saat cache
- [x] Static dosyalar: 30 gün cache

---

## 🚀 Production Deployment Adımları

### 1. Docker Image'ı Yeniden Build Et

```bash
cd /root/SF
docker compose build --no-cache
```

### 2. Container'ları Yeniden Başlat

```bash
docker compose down
docker compose up -d
```

### 3. Dosyaların Doğru Yerinde Olduğunu Kontrol Et

```bash
# robots.txt kontrolü
docker compose exec web test -f SF/static/robots.txt && echo "✓ robots.txt OK" || echo "✗ robots.txt MISSING"

# sitemap.xml kontrolü
docker compose exec web test -f SF/static/sitemap.xml && echo "✓ sitemap.xml OK" || echo "✗ sitemap.xml MISSING"

# sitemap-legal.xml kontrolü
docker compose exec web test -f SF/static/sitemap-legal.xml && echo "✓ sitemap-legal.xml OK" || echo "✗ sitemap-legal.xml MISSING"
```

### 4. SEO Dosyalarının Erişilebilir Olduğunu Test Et

```bash
# robots.txt'i test et
curl -I https://sinifdijital.com/robots.txt

# Ana sitemap'i test et
curl -I https://sinifdijital.com/sitemap.xml

# Dinamik sitemap'i test et (ilk çekişte generate edilecek)
curl -I https://sinifdijital.com/sitemap-classes.xml
```

**Beklenen Cevaplar:**
```
HTTP/2 200 OK
Cache-Control: public, max-age=86400
Content-Type: application/xml (sitemap için)
```

---

## 🔍 Google Search Console Kurulumu

### Adım 1: Domain'i Ekle

1. https://search.google.com adresine gidin
2. **Property ekle** → **Web sitesi** seçin
3. **Sinifdijital.com** yazın (www olmadan)
4. DNS veya HTML tag ile doğrulama yapın

### Adım 2: Sitemap'i Gönder

1. Search Console sol menüden **Sitemaplar** seçin
2. Yeni sitemap ekle:
   - `https://sinifdijital.com/sitemap.xml`
   - `https://sinifdijital.com/sitemap-classes.xml`
   - `https://sinifdijital.com/sitemap-courses.xml`
   - `https://sinifdijital.com/sitemap-content.xml`

### Adım 3: robots.txt'i Doğrula

1. **Sitemaplar** bölümünde **robots.txt** testi yapın
2. **URL Denetimi** ile test URL'leri kontrol edin

### Adım 4: İçeriğin İndekslendiğini Kontrol Et

1. **Kapsam** → **Kapsam özeti**
2. İndeksli URL sayısını takip edin
3. İndekslenmemiş sayfalar var mı kontrol edin

---

## 📊 SEO Monitoring Kontrol Listesi

```markdown
## Günlük Kontrol Listesi

- [ ] Google Search Console'dan yeni hata kontrolü
- [ ] Sitemaplar başarıyla generate ediliyor mu?
- [ ] robots.txt dosyası günceldir
- [ ] Nginx loglarında 404 yok mu?
- [ ] Dynamic sitemap'ler cache'leniyor mu?

## Haftalık Kontrol Listesi

- [ ] Google Search Console'da yeni URL'ler görülüyor mu?
- [ ] Organic traffic artıyor mu?
- [ ] Indexing durumu iyi mi?
- [ ] Mobil uyumluluk problemi var mı?

## Aylık Kontrol Listesi

- [ ] SEO ranking'de gelişme var mı?
- [ ] Backlink profili değişti mi?
- [ ] Meta description'lar optimize mi?
- [ ] Page speed score'lar iyi mi?
```

---

## 🐛 Troubleshooting

### robots.txt Erişilemiyorsa

```bash
# Nginx config'ini test et
docker compose exec nginx nginx -t

# Static dosyaların var olduğunu kontrol et
docker compose exec web ls -la SF/static/robots.txt

# Nginx loglarını kontrol et
docker compose logs nginx | tail -20
```

### Sitemap'ler Generate Olmuyorsa

```bash
# Web container'ındaki logları kontrol et
docker compose logs web | grep -i sitemap

# Database bağlantısını test et
docker compose exec web python -c "from SF import db; print('DB OK')"
```

### Cache Problemi

```bash
# Browser cache'ini temizle
# Chrome: Ctrl+Shift+Delete

# Nginx cache'ini temizle
docker compose exec nginx rm -rf /var/cache/nginx/*

# Redis cache'ini temizle
docker compose exec redis redis-cli FLUSHALL
```

---

## 📈 Performance Optimizations

### Gzip Compression Doğrulaması

```bash
# Gzip compression aktif mı?
curl -I -H "Accept-Encoding: gzip" https://sinifdijital.com/ | grep -i encoding
```

**Beklenen Çıktı:**
```
Content-Encoding: gzip
```

### Static Asset Caching

```bash
# Cache header'ları kontrol et
curl -I https://sinifdijital.com/static/style.css

# Cache-Control header'ı görmeli
Cache-Control: public, max-age=2592000, immutable
```

---

## 🔐 Security Kontrol Listesi

```markdown
- [x] robots.txt - Admin ve sensitive alanları gizliyor
- [x] HTTPS only - HTTP'den HTTPS'e redirect
- [x] HSTS enabled - Güçlü SSL politikası
- [x] X-Frame-Options - Clickjacking koruması
- [x] Security headers - Tüm güvenlik header'ları eklendi
- [x] Meta robots - Index, follow kuralları doğru
```

---

## 📝 İçerik Ekleme Sırasında Yapılması Gerekenler

### Yeni Sınıf Eklerken
1. Admin paneline girin
2. Sınıf ekle → Başlık yazın
3. Sistem otomatik olarak slug oluşturur
4. **Sitemap'ler 24 saat sonra güncellenecek**

### Yeni Ders Eklerken
1. Sınıf seçin
2. Ders ekle → Başlık yazın
3. Sistem otomatik slug oluşturur
4. **Sitemap'ler 24 saat sonra güncellenecek**

### Yeni İçerik Eklerken
1. Ders → Ünite seçin
2. İçerik ekle → Başlık ve metin yazın
3. Resimler ekleyin (Upload button)
4. Kaydet
5. **Sistem otomatik URL oluşturur:**
   ```
   /[sinif-slug]/[ders-slug]/[unite-slug]/[icerik-slug]
   ```

---

## 🌐 Domain & DNS Ayarları

### A Record
```
sinifdijital.com → Render IP adresi
```

### CNAME Record (www)
```
www.sinifdijital.com → sinifdijital.com (301 redirect)
```

### TXT Records (Verification)
```
Google Site Verification: google-site-verification=XXXXX
```

---

## 📞 Destek ve İletişim

- **Admin Panel:** `/yonetim-panel-x9k2m`
- **Error Logs:** `docker compose logs web | grep ERROR`
- **System Health:** `GET /health`
- **Database Status:** Admin → Settings → Database Health

---

## 📚 Referanslar

- [Google Search Console Guide](https://support.google.com/webmasters)
- [Sitemap Format](https://www.sitemaps.org/)
- [Robots.txt Guide](https://www.robotstxt.org/)
- [SEO Best Practices](https://developers.google.com/search/docs)

---

**Son Güncelleme:** 4 Ocak 2026
**Sorumluluk:** Admin Paneli
