#!/bin/bash
set -e

echo "=== Docker Entrypoint Started ==="

# Read secrets and export as environment variables
# These will be inherited by the gunicorn process
if [ -f /run/secrets/secret_key ]; then
    export SECRET_KEY=$(cat /run/secrets/secret_key)
    echo "✓ SECRET_KEY loaded from secret"
fi

if [ -f /run/secrets/postgres_password ]; then
    export POSTGRES_PASSWORD=$(cat /run/secrets/postgres_password)
    echo "✓ POSTGRES_PASSWORD loaded from secret"
fi

if [ -f /run/secrets/redis_password ]; then
    export REDIS_PASSWORD=$(cat /run/secrets/redis_password)
    echo "✓ REDIS_PASSWORD loaded from secret"
fi

if [ -f /run/secrets/mail_password ]; then
    export MAIL_PASSWORD=$(cat /run/secrets/mail_password)
    echo "✓ MAIL_PASSWORD loaded from secret"
fi

if [ -f /run/secrets/google_client_secret ]; then
    export GOOGLE_CLIENT_SECRET=$(cat /run/secrets/google_client_secret)
    echo "✓ GOOGLE_CLIENT_SECRET loaded from secret"
elif [ -f /run/secrets/google_client_secret_v2 ]; then
    export GOOGLE_CLIENT_SECRET=$(cat /run/secrets/google_client_secret_v2)
    echo "✓ GOOGLE_CLIENT_SECRET loaded from secret_v2"
fi

if [ -f /run/secrets/google_client_id ]; then
    export GOOGLE_CLIENT_ID=$(cat /run/secrets/google_client_id)
    echo "✓ GOOGLE_CLIENT_ID loaded from secret"
elif [ -f /run/secrets/google_client_id_v2 ]; then
    export GOOGLE_CLIENT_ID=$(cat /run/secrets/google_client_id_v2)
    echo "✓ GOOGLE_CLIENT_ID loaded from secret_v2"
fi

# DATABASE_URL'i oluştur veya secret varsa üzerine yaz
POSTGRES_USER=${POSTGRES_USER:-sfuser}
POSTGRES_DB=${POSTGRES_DB:-sfdb}
POSTGRES_HOST=${POSTGRES_HOST:-db}
POSTGRES_PORT=${POSTGRES_PORT:-5432}

if [ -n "$POSTGRES_PASSWORD" ] || [ -f /run/secrets/postgres_password ]; then
    export DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"
    # maskelenmiş log
    masked_pw="${POSTGRES_PASSWORD:0:1}***${POSTGRES_PASSWORD: -1}"
    echo "✓ DATABASE_URL constructed (user=${POSTGRES_USER}, host=${POSTGRES_HOST}, db=${POSTGRES_DB}, pw=${masked_pw})"
fi

# REDIS_URL'i oluştur veya secret varsa üzerine yaz
REDIS_HOST=${REDIS_HOST:-redis}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_DB=${REDIS_DB:-0}

if [ -n "$REDIS_PASSWORD" ] || [ -f /run/secrets/redis_password ]; then
    export REDIS_URL="redis://:${REDIS_PASSWORD}@${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB}"
    masked_redis_pw="${REDIS_PASSWORD:0:1}***${REDIS_PASSWORD: -1}"
    echo "✓ REDIS_URL constructed (host=${REDIS_HOST}, db=${REDIS_DB}, pw=${masked_redis_pw})"
fi

echo "=== Environment Setup Complete ==="

# If running as root and appuser exists, switch to appuser
if [ "$(id -u)" = "0" ] && id appuser &>/dev/null; then
    echo "Switching to appuser..."
    # Use gosu to switch user while preserving environment
    exec gosu appuser "$@"
else
    exec "$@"
fi
