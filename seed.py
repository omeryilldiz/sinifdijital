from SF import app, db, bcrypt
from SF.models import User

def create_admin():
    with app.app_context():
        # Admin kullanıcının var olup olmadığını kontrol et
        existing_admin = User.query.filter_by(role='admin').first()
        if existing_admin:
            print("Admin kullanıcı zaten mevcut.")
            return
        # Admin kullanıcısını oluştur
        
        hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')  # Güçlü bir şifre kullanın!
        admin_user = User(username='Patron2', email='admin1@admin.com', password=hashed_password, role='admin')
        
        if bcrypt.check_password_hash(hashed_password, 'admin123'):
            print("Admin şifresi doğru.")
        else:
            print("Admin şifresi yanlış.")

        # Veritabanına ekle
        db.session.add(admin_user)
        db.session.commit()
        print("Admin kullanıcı başarıyla oluşturuldu.")

if __name__ == '__main__':
    create_admin()
