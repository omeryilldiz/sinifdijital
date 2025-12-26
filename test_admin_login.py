from SF import app, db, bcrypt
from SF.models import User

with app.app_context():
    print("Checking admin user...")
    user = User.query.filter_by(email='admin1@admin.com').first()
    if user:
        print(f"User found: {user.email}, Role: {user.role}")
        print(f"Password hash: {user.password}")
        # Test password check (assuming password is '123456' or similar, but we don't know it)
        # We can just check if bcrypt works
        try:
            is_valid = bcrypt.check_password_hash(user.password, 'wrongpassword')
            print(f"Bcrypt check (wrong password): {is_valid}")
        except Exception as e:
            print(f"Bcrypt error: {e}")
    else:
        print("Admin user not found")
