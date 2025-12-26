from sqlalchemy import text
from SF import db, app
import html
import re

class SecurityService:
    
    @staticmethod
    def safe_raw_query(sql, params):
        """Güvenli raw SQL sorgusu"""
        try:
            if not sql.strip().upper().startswith('SELECT'):
                raise ValueError("Sadece SELECT sorguları izinli")
            
            return db.session.execute(text(sql), params)
        except Exception as e:
            app.logger.error(f"SQL Sorgu hatası: {str(e)}")
            raise

    @staticmethod
    def sanitize_input(value, max_length=255):
        """Kullanıcı girdilerini temizle"""
        if not value:
            return None
        
        sanitized = html.escape(str(value).strip())
        
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized

    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, list[str]]:
        """
        Password gücünü kontrol et ve detaylı hata mesajları döndür.
        
        Return: (is_valid: bool, errors: list[str])
        
        Gereksinim:
        - Minimum 8 karakter
        - En az 1 büyük harf (A-Z)
        - En az 1 küçük harf (a-z)
        - En az 1 rakam (0-9)
        - En az 1 özel karakter (!@#$%^&*(),.?":{}|<>)
        - Tahmin edilebilir dizileri içermemesi (123, abc, qwerty vb)
        """
        errors = []
        
        if not password:
            return False, ["Şifre boş olamaz"]
        
        # Length check
        if len(password) < 8:
            errors.append("en az 8 karakter olmalıdır")
        if len(password) > 128:
            errors.append("maksimum 128 karakter olabilir")
        
        # Uppercase check
        if not re.search(r'[A-Z]', password):
            errors.append("en az 1 büyük harf (A-Z) içermelidir")
        
        # Lowercase check
        if not re.search(r'[a-z]', password):
            errors.append("en az 1 küçük harf (a-z) içermelidir")
        
        # Digit check
        if not re.search(r'\d', password):
            errors.append("en az 1 rakam (0-9) içermelidir")
        
        # Special character check
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-\+=\[\]\\;:\'`~]', password):
            errors.append("en az 1 özel karakter (!@#$%^&*) içermelidir")
        
        # Common patterns check (sequential numbers or letters)
        common_patterns = [
            r'123456',      # Sequential numbers
            r'654321',      # Reverse sequential numbers
            r'abcdef',      # Sequential letters
            r'qwerty',      # Keyboard pattern
            r'123123',      # Repeated pattern
            r'aaaaaa',      # Repeated character
            r'111111',      # Repeated numbers
        ]
        
        password_lower = password.lower()
        for pattern in common_patterns:
            if re.search(pattern, password_lower):
                errors.append("tahmin edilebilir dizi içermemelidir (123, abc, qwerty vb)")
                break
        
        # No username-like patterns
        if re.search(r'^[a-z]{3,}[0-9]{3,}$', password_lower):
            errors.append("kullanıcı adı şablonuna benzememelidir")
        
        is_valid = len(errors) == 0
        return is_valid, errors

    @staticmethod
    def get_password_strength_score(password: str) -> int:
        """
        Şifrenin gücünü 0-100 arasında puanla.
        
        Scoring:
        - 0-25: Very Weak
        - 26-50: Weak  
        - 51-75: Fair
        - 76-100: Strong
        """
        if not password:
            return 0
        
        score = 0
        
        # Length scoring
        if len(password) >= 8:
            score += 10
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10
        
        # Character variety scoring
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>_\-\+=\[\]\\;:\'`~]', password):
            score += 15
        
        # Pattern variety (non-sequential)
        if not re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', password.lower()):
            score += 10
        
        # No repeated characters
        if not re.search(r'(.)\1{3,}', password):
            score += 10
        
        return min(score, 100)

    @staticmethod
    def check_password_breach(password: str) -> bool:
        """
        Şifrenin havuzlanmış veri ihlallerinde olup olmadığını kontrol et.
        (Basit yerel kontrol - gerçek uygulamada HIBP API kullanılmalı)
        """
        # Common breached passwords list (very small sample)
        common_breached = {
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'letmein', 'welcome', 'monkey', 'dragon', 'master'
        }
        
        return password.lower() in common_breached