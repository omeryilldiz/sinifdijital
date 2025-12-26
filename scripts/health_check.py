#!/usr/bin/env python3
"""
Basit sağlık kontrol scripti:
 - Veritabanı (DATABASE_URL) bağlantısı: SELECT 1
 - Redis (REDIS_URL) ping
 - SMTP (MAIL_SERVER, MAIL_PORT) connect + STARTTLS check
 - Security headers check (target URL)

Kullanım:
  . venv/bin/activate
  export $(cat .env.production | grep -v '^#' | xargs)
  python scripts/health_check.py --url https://your-domain.com

Not: Eksik paketler durumunda hata verir.
"""
import argparse
import os
import socket
import smtplib

from urllib.parse import urlparse

try:
    from sqlalchemy import create_engine, text
except Exception as e:
    create_engine = None

try:
    import redis
except Exception:
    redis = None

try:
    import requests
except Exception:
    requests = None


def check_db(url):
    if create_engine is None:
        return False, "SQLAlchemy yüklü değil"
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with engine.connect() as conn:
            conn.execute(text('SELECT 1'))
        return True, "DB bağlantısı başarılı"
    except Exception as e:
        return False, str(e)


def check_redis(url):
    if redis is None:
        return False, "redis Python kütüphanesi yüklü değil"
    try:
        r = redis.from_url(url)
        r.ping()
        return True, "Redis ping başarılı"
    except Exception as e:
        return False, str(e)


def check_smtp(server, port, use_tls=True, timeout=10):
    try:
        with smtplib.SMTP(server, port, timeout=timeout) as smtp:
            smtp.ehlo()
            if use_tls:
                smtp.starttls()
                smtp.ehlo()
        return True, "SMTP bağlantısı başarılı"
    except (smtplib.SMTPException, socket.error) as e:
        return False, str(e)


def check_headers(target):
    if requests is None:
        return False, "requests kütüphanesi yüklü değil"
    try:
        r = requests.get(target, timeout=10)
        headers = r.headers
        keys = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
        ]
        present = {k: headers.get(k) for k in keys}
        return True, present
    except Exception as e:
        return False, str(e)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--url', help='Uygulama URLsi (https://domain) to check headers', required=False)
    args = p.parse_args()

    print('Reading environment variables from runtime...')
    db_url = os.getenv('DATABASE_URL')
    redis_url = os.getenv('REDIS_URL')
    mail_server = os.getenv('MAIL_SERVER')
    mail_port = int(os.getenv('MAIL_PORT', '587'))
    mail_use_tls = os.getenv('MAIL_USE_TLS', 'True').lower() in ('1','true','yes')

    if db_url:
        ok, msg = check_db(db_url)
        print('DB:', 'OK' if ok else 'FAIL', msg)
    else:
        print('DB: SKIP (DATABASE_URL bulunamadı)')

    if redis_url:
        ok, msg = check_redis(redis_url)
        print('Redis:', 'OK' if ok else 'FAIL', msg)
    else:
        print('Redis: SKIP (REDIS_URL bulunamadı)')

    if mail_server:
        ok, msg = check_smtp(mail_server, mail_port, mail_use_tls)
        print('SMTP:', 'OK' if ok else 'FAIL', msg)
    else:
        print('SMTP: SKIP (MAIL_SERVER bulunamadı)')

    if args.url:
        ok, info = check_headers(args.url)
        if ok:
            print('Headers:')
            for k, v in info.items():
                print(f'  {k}: {v}')
        else:
            print('Headers: FAIL', info)
    else:
        print('Headers: SKIP (url parametresi verilmedi)')

if __name__ == '__main__':
    main()
