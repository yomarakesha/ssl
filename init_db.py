"""
Initialize the database and create a default admin user + organization.
Usage: python init_db.py
Default login: admin / admin123  (DEV ONLY — change immediately)

The default admin is also marked is_staff=True so you can access /admin.
"""
import os

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
        db.session.flush()

        password = os.environ.get('SSL_ADMIN_PASSWORD') or 'admin123'
        user = User(username='admin', role='admin', is_staff=True, org_id=org.id)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        org.owner_id = user.id
        db.session.commit()

        if password == 'admin123':
            print("[OK] User 'admin' created (owner + staff). Password: admin123 (CHANGE THIS)")
        else:
            print("[OK] User 'admin' created with SSL_ADMIN_PASSWORD from env.")
    print("[OK] Database initialized.")
