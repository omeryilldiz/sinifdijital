"""
Email şablonlarını yönet ve gönder
Template-based email rendering service
"""
from flask import url_for, current_app
from jinja2 import Template
from html import escape


class EmailTemplateService:
    """Email şablonlarını renderle ve yönet"""
    
    @staticmethod
    def _get_base_url():
        """
        Base URL'yi al - request context'den veya config'ten
        
        Returns:
            Base URL string (https://example.com)
        """
        try:
            # Request context varsa, url_for kullan (en doğru)
            return url_for('home', _external=True).rstrip('/')
        except RuntimeError:
            # Request context yoksa, config'ten al
            return current_app.config.get('BASE_URL', 'http://localhost:5000')
    
    @staticmethod
    def _load_template(filename):
        """
        Template dosyasını yükle
        
        Args:
            filename: Template dosya adı (emails/ klasöründe)
            
        Returns:
            Template içeriği (string)
        """
        try:
            with open(f'SF/templates/emails/{filename}', 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            current_app.logger.error(f"Email template not found: {filename}")
            return None
        except Exception as e:
            current_app.logger.error(f"Error loading email template {filename}: {str(e)}")
            return None
    
    @staticmethod
    def render_verification_email(user, verification_url):
        """
        Email doğrulama şablonunu renderle
        
        Args:
            user: User nesnesi
            verification_url: Doğrulama linki
            
        Returns:
            HTML string
        """
        try:
            # Güvenlik: Kullanıcı adını HTML escape et
            user_name = escape(user.first_name or 'Değerli Kullanıcı')
            
            # Base URL'yi al
            base_url = EmailTemplateService._get_base_url()
            
            # Template context oluştur
            context = {
                'user_name': user_name,
                'verification_url': verification_url,
                'support_url': f"{base_url}/iletisim",
                'privacy_url': f"{base_url}/gizlilik-politikasi",
                'terms_url': f"{base_url}/kullanim-sartlari",
                'home_url': base_url,
            }
            
            # Template yükle ve renderle
            template_str = EmailTemplateService._load_template('verification_email.html')
            
            if not template_str:
                # Fallback - basit HTML
                return EmailTemplateService._fallback_verification_email(user_name, verification_url)
            
            template = Template(template_str)
            html_body = template.render(context)
            
            return html_body
            
        except Exception as e:
            current_app.logger.error(f"Email template rendering error: {str(e)}")
            return EmailTemplateService._fallback_verification_email(user.first_name or 'Değerli Kullanıcı', verification_url)
    
    @staticmethod
    def render_password_reset_email(user, reset_url):
        """
        Şifre sıfırlama şablonunu renderle
        
        Args:
            user: User nesnesi
            reset_url: Sıfırlama linki
            
        Returns:
            HTML string
        """
        try:
            user_name = escape(user.first_name or 'Değerli Kullanıcı')
            
            # Base URL'yi al
            base_url = EmailTemplateService._get_base_url()
            
            context = {
                'user_name': user_name,
                'reset_url': reset_url,
                'support_url': f"{base_url}/iletisim",
                'home_url': base_url,
            }
            
            template_str = EmailTemplateService._load_template('reset_password_email.html')
            
            if not template_str:
                return EmailTemplateService._fallback_password_reset_email(user_name, reset_url)
            
            template = Template(template_str)
            html_body = template.render(context)
            
            return html_body
            
        except Exception as e:
            current_app.logger.error(f"Password reset email rendering error: {str(e)}")
            return EmailTemplateService._fallback_password_reset_email(user.first_name or 'Değerli Kullanıcı', reset_url)
    
    @staticmethod
    def render_password_changed_email(user):
        """
        Şifre değişiklik bildirimi şablonunu renderle
        
        Args:
            user: User nesnesi
            
        Returns:
            HTML string
        """
        try:
            user_name = escape(user.first_name or 'Değerli Kullanıcı')
            
            # Base URL'yi al
            base_url = EmailTemplateService._get_base_url()
            
            context = {
                'user_name': user_name,
                'login_url': f"{base_url}/login",
                'support_url': f"{base_url}/iletisim",
                'home_url': base_url,
            }
            
            template_str = EmailTemplateService._load_template('password_changed_email.html')
            
            if not template_str:
                return EmailTemplateService._fallback_password_changed_email(user_name)
            
            template = Template(template_str)
            html_body = template.render(context)
            
            return html_body
            
        except Exception as e:
            current_app.logger.error(f"Password changed email rendering error: {str(e)}")
            return EmailTemplateService._fallback_password_changed_email(user.first_name or 'Değerli Kullanıcı')
    
    # ===== FALLBACK EMAIL TEMPLATES =====
    
    @staticmethod
    def _fallback_verification_email(user_name, verification_url):
        """Fallback: Email doğrulama emaili"""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px;">
                <h2 style="color: #00457C;">Email Adresinizi Doğrulayın</h2>
                <p style="color: #666; line-height: 1.8;">Merhaba {user_name},</p>
                <p style="color: #666; line-height: 1.8;">
                    Sınıf Dijital platformuna hoş geldiniz! Hesabınızı aktifleştirmek için lütfen aşağıdaki linke tıklayın.
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verification_url}" 
                       style="background: linear-gradient(135deg, #00457C 0%, #00A5AD 100%); 
                              color: white; 
                              padding: 12px 30px; 
                              text-decoration: none; 
                              border-radius: 6px;
                              font-weight: bold;
                              display: inline-block;">
                        Email Adresimi Doğrula
                    </a>
                </div>
                <p style="color: #999; font-size: 12px;">Bu link 24 saat geçerlidir.</p>
            </div>
        </body>
        </html>
        """
    
    @staticmethod
    def _fallback_password_reset_email(user_name, reset_url):
        """Fallback: Şifre sıfırlama emaili"""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px;">
                <h2 style="color: #00457C;">Şifre Sıfırlama</h2>
                <p style="color: #666; line-height: 1.8;">Merhaba {user_name},</p>
                <p style="color: #666; line-height: 1.8;">
                    Şifrenizi sıfırlamak için bir talep aldık. Aşağıdaki linke tıklayarak yeni bir şifre oluşturabilirsiniz.
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_url}" 
                       style="background: linear-gradient(135deg, #00457C 0%, #00A5AD 100%); 
                              color: white; 
                              padding: 12px 30px; 
                              text-decoration: none; 
                              border-radius: 6px;
                              font-weight: bold;
                              display: inline-block;">
                        Şifremi Sıfırla
                    </a>
                </div>
                <p style="color: #999; font-size: 12px;">Bu link 1 saat geçerlidir.</p>
            </div>
        </body>
        </html>
        """
    
    @staticmethod
    def _fallback_password_changed_email(user_name):
        """Fallback: Şifre değişiklik bildirimi emaili"""
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px;">
                <h2 style="color: #00457C;">Şifreniz Değiştirildi</h2>
                <p style="color: #666; line-height: 1.8;">Merhaba {user_name},</p>
                <p style="color: #666; line-height: 1.8;">
                    Hesabınızın şifresi başarıyla değiştirilmiştir.
                </p>
                <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
                    <p style="color: #856404; margin: 0; font-size: 13px;">
                        <strong>⚠️ Eğer bu işlemi siz yapmadıysanız, lütfen destek ekibine bildirin!</strong>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
