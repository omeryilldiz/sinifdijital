"""
Email/SMTP İşlemleri ve Test Yardımcıları
"""
from flask import current_app
from flask_mail import Message
import smtplib
import socket
from datetime import datetime

class EmailService:
    """Email gönderme ve SMTP testi için servis"""
    
    @staticmethod
    def get_smtp_config():
        """SMTP konfigürasyonunu döndür"""
        return {
            'server': current_app.config.get('MAIL_SERVER', 'smtp.gmail.com'),
            'port': current_app.config.get('MAIL_PORT', 587),
            'username': current_app.config.get('MAIL_USERNAME'),
            'password': current_app.config.get('MAIL_PASSWORD'),
            'use_tls': current_app.config.get('MAIL_USE_TLS', True),
            'use_ssl': current_app.config.get('MAIL_USE_SSL', False),
            'sender': current_app.config.get('MAIL_DEFAULT_SENDER'),
        }
    
    @staticmethod
    def validate_smtp_config() -> tuple[bool, list[str]]:
        """
        SMTP yapılandırmasını doğrula.
        
        Return: (is_valid: bool, errors: list[str])
        """
        config = EmailService.get_smtp_config()
        errors = []
        
        if not config['server']:
            errors.append("MAIL_SERVER tanımlanmamış")
        if not config['port']:
            errors.append("MAIL_PORT tanımlanmamış")
        if not config['username']:
            errors.append("MAIL_USERNAME tanımlanmamış")
        if not config['password']:
            errors.append("MAIL_PASSWORD tanımlanmamış")
        if not config['sender']:
            errors.append("MAIL_DEFAULT_SENDER tanımlanmamış")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def test_smtp_connection() -> tuple[bool, str]:
        """
        SMTP sunucusuna bağlantı testi yap.
        
        Return: (success: bool, message: str)
        """
        config = EmailService.get_smtp_config()
        
        # Konfigürasyon doğrulama
        is_valid, errors = EmailService.validate_smtp_config()
        if not is_valid:
            return False, f"Konfigürasyon hatası: {', '.join(errors)}"
        
        try:
            # SMTP bağlantısı kur
            if config['use_ssl']:
                server = smtplib.SMTP_SSL(config['server'], config['port'], timeout=10)
            else:
                server = smtplib.SMTP(config['server'], config['port'], timeout=10)
            
            # TLS başlat
            if config['use_tls']:
                server.starttls()
            
            # Giriş yap
            server.login(config['username'], config['password'])
            
            # Başarılı
            server.quit()
            return True, f"SMTP bağlantısı başarılı ({config['server']}:{config['port']})"
            
        except socket.timeout:
            return False, f"Zaman aşımı: {config['server']}:{config['port']} (10s)"
        except smtplib.SMTPAuthenticationError:
            return False, f"Kimlik doğrulama hatası: Kullanıcı adı/şifre yanlış"
        except smtplib.SMTPException as e:
            return False, f"SMTP hatası: {str(e)}"
        except Exception as e:
            return False, f"Bağlantı hatası: {str(e)}"
    
    @staticmethod
    def send_test_email(recipient_email: str) -> tuple[bool, str]:
        """
        Test email gönder.
        
        Args:
            recipient_email: Alıcı email adresi
        
        Return: (success: bool, message: str)
        """
        config = EmailService.get_smtp_config()
        
        # Konfigürasyon doğrulama
        is_valid, errors = EmailService.validate_smtp_config()
        if not is_valid:
            return False, f"Konfigürasyon hatası: {', '.join(errors)}"
        
        try:
            # Test email oluştur
            subject = "SF Eğitim - SMTP Test Maili"
            timestamp = datetime.utcnow().isoformat()
            
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                          padding: 30px; text-align: center; border-radius: 5px 5px 0 0;">
                    <h1 style="color: white; margin: 0;">SF Eğitim</h1>
                </div>
                <div style="padding: 30px; background: #f9f9f9; border-radius: 0 0 5px 5px;">
                    <h2 style="color: #333;">SMTP Test Maili</h2>
                    <p style="color: #666; line-height: 1.6;">
                        Bu mail, SF Eğitim uygulamasının SMTP/Email gönderme özelliğinin 
                        düzgün çalıştığını doğrulamak için gönderilmiştir.
                    </p>
                    <div style="background: white; padding: 15px; border-radius: 5px; 
                               border: 1px solid #ddd; margin: 20px 0;">
                        <p style="margin: 5px 0;"><strong>Gönderici:</strong> {config['sender']}</p>
                        <p style="margin: 5px 0;"><strong>Alıcı:</strong> {recipient_email}</p>
                        <p style="margin: 5px 0;"><strong>SMTP Sunucu:</strong> {config['server']}:{config['port']}</p>
                        <p style="margin: 5px 0;"><strong>TLS Kullanımı:</strong> {'Evet' if config['use_tls'] else 'Hayır'}</p>
                        <p style="margin: 5px 0;"><strong>Gönderim Zamanı:</strong> {timestamp}</p>
                    </div>
                    <p style="color: #27ae60; font-weight: bold;">
                        ✓ Email sistemi başarıyla çalışıyor!
                    </p>
                </div>
            </body>
            </html>
            """
            
            msg = Message(
                subject=subject,
                recipients=[recipient_email],
                html=html_body,
                sender=config['sender']
            )
            
            # Mail gönder (Flask-Mail kullan)
            from SF import mail
            mail.send(msg)
            
            return True, f"Test maili başarıyla gönderildi: {recipient_email}"
            
        except Exception as e:
            return False, f"Email gönderme hatası: {str(e)}"
    
    @staticmethod
    def test_email_full_flow(recipient_email: str) -> dict:
        """
        SMTP konfigürasyonundan email gönderilişine kadar 
        tüm işlemleri test et ve sonuç raporu döndür.
        
        Return: {
            'overall_status': 'success'/'partial'/'failure',
            'config_valid': bool,
            'config_errors': [str],
            'connection_test': {'success': bool, 'message': str},
            'email_sent': {'success': bool, 'message': str},
            'timestamp': str
        }
        """
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_status': 'success',
            'details': []
        }
        
        # 1. Konfigürasyon doğrulama
        is_valid, config_errors = EmailService.validate_smtp_config()
        result['config_valid'] = is_valid
        result['config_errors'] = config_errors
        
        if not is_valid:
            result['overall_status'] = 'failure'
            result['details'].append({
                'step': 'Konfigürasyon Doğrulama',
                'status': 'BAŞARISIZ',
                'message': f"Hata: {', '.join(config_errors)}"
            })
            return result
        
        result['details'].append({
            'step': 'Konfigürasyon Doğrulama',
            'status': 'BAŞARILI',
            'message': 'Tüm SMTP parametreleri tanımlanmış'
        })
        
        # 2. SMTP Bağlantı Testi
        success, conn_msg = EmailService.test_smtp_connection()
        result['connection_test'] = {'success': success, 'message': conn_msg}
        
        if not success:
            result['overall_status'] = 'failure'
            result['details'].append({
                'step': 'SMTP Bağlantı Testi',
                'status': 'BAŞARISIZ',
                'message': conn_msg
            })
            return result
        
        result['details'].append({
            'step': 'SMTP Bağlantı Testi',
            'status': 'BAŞARILI',
            'message': conn_msg
        })
        
        # 3. Test Email Gönderimi
        success, email_msg = EmailService.send_test_email(recipient_email)
        result['email_sent'] = {'success': success, 'message': email_msg}
        
        if not success:
            result['overall_status'] = 'partial'
            result['details'].append({
                'step': 'Test Email Gönderimi',
                'status': 'BAŞARISIZ',
                'message': email_msg
            })
        else:
            result['details'].append({
                'step': 'Test Email Gönderimi',
                'status': 'BAŞARILI',
                'message': email_msg
            })
        
        return result
