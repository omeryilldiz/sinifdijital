#!/usr/bin/env bash
set -euo pipefail

# Helper to install certbot (Debian/Ubuntu) and request Let's Encrypt certificate
# Usage: sudo ./scripts/setup_ssl.sh your-domain.com you@example.com

DOMAIN=${1:-}
EMAIL=${2:-}

if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
  echo "Usage: sudo $0 <your-domain> <email-for-lets-encrypt>"
  exit 2
fi

echo "Ensure nginx is installed and running"
if ! command -v nginx >/dev/null 2>&1; then
  echo "Install nginx first (apt install nginx)" >&2
  exit 1
fi

echo "Creating webroot for ACME challenges"
mkdir -p /var/www/letsencrypt
chown -R www-data:www-data /var/www/letsencrypt

echo "Copying example nginx site to /etc/nginx/sites-available/sf"
cp deploy/nginx-sf.conf /etc/nginx/sites-available/sf
sed -i "s/YOUR_DOMAIN_HERE/$DOMAIN/g" /etc/nginx/sites-available/sf

ln -sf /etc/nginx/sites-available/sf /etc/nginx/sites-enabled/sf
nginx -t
systemctl reload nginx

if ! command -v certbot >/dev/null 2>&1; then
  echo "Installing certbot and python3-certbot-nginx"
  apt-get update
  apt-get install -y certbot python3-certbot-nginx
fi

echo "Requesting certificate for $DOMAIN"
certbot --nginx -d "$DOMAIN" --agree-tos --email "$EMAIL" --non-interactive --redirect

echo "Setup complete. certbot will auto-renew certificates. Verify with: sudo certbot certificates"
