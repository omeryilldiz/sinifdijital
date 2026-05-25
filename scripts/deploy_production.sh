#!/usr/bin/env bash
# ========================================
# Quick Production Deployment Script
# ========================================
# Usage: sudo ./scripts/deploy_production.sh

set -euo pipefail

DOMAIN="sinifdijital.com"
EMAIL="omeryildiz@sinifdijital.com"
PROJECT_DIR="/opt/SF"

echo "🚀 SinifDijital.com - Production Deployment"
echo "==========================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ Bu script root olarak çalıştırılmalı (sudo kullanın)" 
   exit 1
fi

# 1. System Updates
echo "📦 1/10 - Sistem güncellemeleri..."
apt update && apt upgrade -y
apt install -y curl wget git vim ufw fail2ban

# 2. Firewall Setup
echo "🔥 2/10 - Firewall ayarları..."
ufw --force default deny incoming
ufw --force default allow outgoing
ufw --force allow ssh
ufw --force allow 80/tcp
ufw --force allow 443/tcp
ufw --force enable

# 3. Fail2ban
echo "🛡️  3/10 - Fail2ban aktifleştiriliyor..."
systemctl enable fail2ban
systemctl start fail2ban

# 4. Docker Installation
echo "🐳 4/10 - Docker kurulumu..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
fi
systemctl enable docker
systemctl start docker

# 5. Project Clone
echo "📂 5/10 - Proje indiriliyor..."
if [ ! -d "$PROJECT_DIR" ]; then
    git clone https://github.com/YOUR_REPO/SF.git $PROJECT_DIR
fi
cd $PROJECT_DIR

# 6. Docker Secrets
echo "🔐 6/10 - Docker secrets oluşturuluyor..."
mkdir -p deploy/secrets
cd deploy/secrets

if [ ! -f secret_key.txt ]; then
    python3 -c "import secrets; print(secrets.token_hex(32))" > secret_key.txt
fi
if [ ! -f postgres_password.txt ]; then
    echo "CHANGE_POSTGRES_PASSWORD" > postgres_password.txt
fi
if [ ! -f redis_password.txt ]; then
    echo "CHANGE_REDIS_PASSWORD" > redis_password.txt
fi
if [ ! -f mail_password.txt ]; then
    echo "CHANGE_MAIL_PASSWORD" > mail_password.txt
fi
if [ ! -f google_client_id.txt ]; then
    echo "CHANGE_GOOGLE_CLIENT_ID" > google_client_id.txt
fi
if [ ! -f google_client_secret.txt ]; then
    echo "CHANGE_GOOGLE_CLIENT_SECRET" > google_client_secret.txt
fi

chmod 400 *.txt
cd ../..

# 7. Environment File
echo "⚙️  7/10 - Environment dosyası hazırlanıyor..."
if [ ! -f .env ]; then
    cp .env.production.example .env
    echo "⚠️  .env dosyasını düzenleyin!"
fi

# 8. Build & Start
echo "🏗️  8/10 - Docker image build ediliyor..."
docker compose build

echo "▶️  9/10 - Container'lar başlatılıyor..."
docker compose up -d

# Wait for health check
echo "⏳ Health check bekleniyor (60 saniye)..."
sleep 60

# 9. Database Init
echo "💾 10/10 - Database initialization..."
docker exec sf-web-1 python -c "from SF import app, db; app.app_context().push(); db.create_all(); print('✅ Database tables created')"

# 10. Status Check
echo ""
echo "✅ Deployment tamamlandı!"
echo ""
echo "📊 Container Durumu:"
docker compose ps

echo ""
echo "🌐 Test URL:"
echo "   http://localhost:5000/health"
echo ""
echo "⚠️  SONRAKI ADIMLAR:"
echo "1. deploy/secrets/ altındaki tüm şifreleri değiştirin"
echo "2. .env dosyasını production değerleriyle doldurun"
echo "3. Admin kullanıcı oluşturun"
echo "4. SSL sertifikası için: sudo ./scripts/setup_ssl.sh $DOMAIN $EMAIL"
echo ""
echo "📚 Detaylı rehber: PRODUCTION_DEPLOYMENT_GUIDE.md"
