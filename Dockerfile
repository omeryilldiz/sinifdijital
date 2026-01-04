# =========================
# 1. BUILD STAGE
# =========================
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip \
 && pip wheel --no-cache-dir --no-deps -w /wheels -r requirements.txt


# =========================
# 2. RUNTIME STAGE
# =========================
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    gosu \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /wheels /wheels
COPY requirements.txt .

RUN pip install --no-cache-dir /wheels/*

# Non-root user oluştur (güvenlik)
RUN useradd --create-home --shell /bin/bash appuser \
 && mkdir -p /app/SF/static/uploads /app/SF/static/soru_uploads \
    /app/SF/static/video_uploads /app/SF/static/cozum_uploads \
    /app/SF/static/pdf_uploads /var/log/gunicorn \
 && chown -R appuser:appuser /app /var/log/gunicorn

COPY --chown=appuser:appuser . .

# Flask için port
EXPOSE 5000

# copy entrypoint that will load Docker secrets into env (must be readable by root)
COPY docker/docker-entrypoint.sh /app/docker/docker-entrypoint.sh
RUN chmod +x /app/docker/docker-entrypoint.sh

# Don't set USER here - entrypoint will run as root to read secrets, then switch to appuser
# ENTRYPOINT script will handle user switching after loading secrets

# Projendeki WSGI entry: SF.wsgi:app
ENTRYPOINT ["/app/docker/docker-entrypoint.sh"]
CMD ["gunicorn", "-c", "gunicorn_config.py", "wsgi:app"]
