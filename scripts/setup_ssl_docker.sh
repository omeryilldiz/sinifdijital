#!/usr/bin/env bash
# ========================================
# SSL Certificate Setup & Auto-Renewal
# ========================================
# Bu script Let's Encrypt SSL sertifikası kurar ve otomatik yenileme ayarlar
# Usage: sudo ./scripts/setup_ssl_docker.sh sinifdijital.com admin@sinifdijital.com

set -euo pipefail

DOMAIN=${1:-}
EMAIL=${2:-}
COMPOSE_DIR="${3:-$(pwd)}"

if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
  echo "❌ Kullanım: sudo $0 <domain> <email>"
  echo "   Örnek: sudo $0 sinifdijital.com admin@sinifdijital.com"
  exit 1
fi

echo "🔒 SSL Certificate Setup - $DOMAIN"
echo "===================================="
echo ""

# 1. Certbot kurulumu
echo "📦 1/6 - Certbot kurulumu..."
if ! command -v certbot &> /dev/null; then
    apt update
    apt install -y certbot python3-certbot-nginx
fi

# 2. Webroot dizini
echo "📁 2/6 - ACME challenge dizini oluşturuluyor..."
mkdir -p /var/www/letsencrypt
chmod -R 755 /var/www/letsencrypt

# 3. Geçici nginx kurulumu (sadece SSL için)
echo "🌐 3/6 - Geçici nginx kurulumu..."
if ! command -v nginx &> /dev/null; then
    apt install -y nginx
fi

# Docker nginx'i durdur
cd $COMPOSE_DIR
docker compose stop nginx || true

# Nginx config için geçici dosya
cat > /etc/nginx/sites-available/temp-ssl << EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;

    location /.well-known/acme-challenge/ {
        root /var/www/letsencrypt;
    }

    location / {
        return 200 "SSL setup in progress...";
        add_header Content-Type text/plain;
    }
}
EOF

ln -sf /etc/nginx/sites-available/temp-ssl /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx

# 4. SSL sertifikası al
echo "🔐 4/6 - SSL sertifikası alınıyor..."
certbot certonly \
    --webroot \
    -w /var/www/letsencrypt \
    -d $DOMAIN \
    -d www.$DOMAIN \
    --agree-tos \
    --email $EMAIL \
    --non-interactive

# 5. Host nginx'i durdur
echo "🛑 5/6 - Host nginx durduruluyor..."
systemctl stop nginx
systemctl disable nginx

# 6. Docker compose güncelle ve başlat
echo "🐳 6/6 - Docker container'ları başlatılıyor..."
cd $COMPOSE_DIR

# nginx volume'ü güncelle (eğer yoksa)
if ! grep -q "/etc/letsencrypt" docker-compose.yml; then
    echo "⚠️  docker-compose.yml'de /etc/letsencrypt volume'ü eksik!"
    echo "   Manuel olarak ekleyin:"
    echo "   volumes:"
    echo "     - /etc/letsencrypt:/etc/letsencrypt:ro"
fi

docker compose up -d

# SSL testi
echo ""
echo "✅ SSL kurulumu tamamlandı!"
echo ""
echo "🧪 Test komutları:"
echo "   curl -I https://$DOMAIN"
echo "   curl -I https://www.$DOMAIN"
echo ""
echo "🔄 Otomatik yenileme testi:"
echo "   certbot renew --dry-run"
echo ""
echo "📅 Sertifika bilgileri:"
certbot certificates

echo ""
echo "🎯 Sonraki adımlar:"
echo "1. Browser'da https://$DOMAIN adresini ziyaret edin"
echo "2. SSL Labs test: https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
echo "3. Otomatik yenileme: sudo systemctl status certbot.timer"
