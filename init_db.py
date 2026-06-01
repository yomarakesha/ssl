"""
Initialize the database and create a default admin user + organization.
Usage: python init_db.py
Default login: admin / admin123  (DEV ONLY — change immediately)
"""
import os
import secrets

from app import create_app
from models import db, Organization, User

app = create_app()

with app.app_context():
    db.create_all()

    if User.query.filter_by(username='admin').first():
        print("[INFO] User 'admin' already exists. Skipping.")
    else:
        org = Organization(name='Default Organization')
        db.session.add(org)
        db.session.flush()  # get org.id without committing

        password = os.environ.get('SSL_ADMIN_PASSWORD') or 'admin123'
        user = User(username='admin', role='admin', org_id=org.id)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if password == 'admin123':
            print("[OK] User 'admin' created. Password: admin123 (CHANGE THIS)")
        else:
            print("[OK] User 'admin' created with SSL_ADMIN_PASSWORD from env.")
    print("[OK] Database initialized.")
