#!/usr/bin/env python3
"""
Kullanım: venv aktifken çalıştır.
Bu script `.env.production.example` dosyasını okuyup `SECRET_KEY` placeholder'ını
rastgele güçlü bir anahtar ile değiştirir ve `.env.production` olarak kaydeder.
"""
import secrets
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[1] / ".env.production.example"
OUT = Path(__file__).resolve().parents[1] / ".env.production"

def main():
    if not EXAMPLE.exists():
        print(f"Hata: {EXAMPLE} bulunamadı")
        raise SystemExit(1)

    text = EXAMPLE.read_text()
    # placeholder metinleri
    placeholder = "<generate-with-secrets.token_urlsafe(32)>"
    if placeholder in text:
        secret = secrets.token_urlsafe(32)
        text = text.replace(placeholder, secret)
        OUT.write_text(text)
        print(f"Oluşturuldu: {OUT}")
        print("SECRET_KEY oluşturuldu ve .env.production içine yazıldı.")
    else:
        # Eğer zaten bir SECRET_KEY varsa, sadece kopyala
        if OUT.exists():
            print(f"{OUT} zaten var, işlem atlandı.")
            raise SystemExit(0)
        OUT.write_text(text)
        print(f"Kopyalandı: {OUT}")

if __name__ == '__main__':
    main()
