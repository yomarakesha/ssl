"""
Run this script once to initialize the database and create the default admin user.
Usage: python init_db.py
Default login: admin / admin123
"""
from app import create_app
from models import db, User

app = create_app()

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        user = User(username='admin')
        user.set_password('admin123')
        db.session.add(user)
        db.session.commit()
        print("[OK] User 'admin' created. Password: admin123")
    else:
        print("[INFO] User 'admin' already exists.")
    print("[OK] Database initialized.")
