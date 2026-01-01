#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask import Flask

# .env dosyasını yükle
load_dotenv()

# Flask app oluştur
app = Flask(__name__)

# Mail ayarlarını yapılandır
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.hostinger.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 465))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'False') == 'True'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

def test_mail():
    """Mail gönderimi test et"""
    print("\n📧 Mail Gönderimi Test Ediliyor...")
    print(f"SMTP Sunucusu: {app.config['MAIL_SERVER']}")
    print(f"Port: {app.config['MAIL_PORT']}")
    print(f"Gönderen: {app.config['MAIL_USERNAME']}")
    print(f"Gönderici (noreply): noreply@sinifdijital.com")
    print(f"SSL: {app.config['MAIL_USE_SSL']}")
    print(f"TLS: {app.config['MAIL_USE_TLS']}")
    
    try:
        with app.app_context():
            msg = Message(
                subject='Test Mail - Sınıf Dijital (noreply)',
                recipients=['omeryildiz84@gmail.com'],
                sender='noreply@sinifdijital.com',
                body="""Merhaba,

Bu bir test e-postasıdır. noreply@sinifdijital.com adresinden gönderilmiştir.

Eğer bu mesajı aldıysanız, mail gönderimi başarıyla çalışıyor demektir.

Test Tarihi: """ + str(__import__('datetime').datetime.now()) + """

Sınıf Dijital
"""
            )
            mail.send(msg)
            print("\n✅ Mail başarıyla gönderildi!")
            print("📬 omeryildiz84@gmail.com adresini kontrol et")
            print("📧 Gönderici: noreply@sinifdijital.com")
            return True
    except Exception as e:
        print(f"\n❌ Mail gönderimi başarısız!")
        print(f"Hata: {str(e)}")
        return False

if __name__ == '__main__':
    test_mail()
