"""
Mock data seeder for SSL Manager.
Usage: python seed_data.py

Adds test records for SSL keys, servers, and accesses.
Access passwords are encrypted via Fernet.
Safe to run multiple times — idempotent for SSL/Server, re-creates accesses.
"""
from datetime import date, timedelta
from app import create_app
from models import db, SSLKey, Server, Access, encrypt_password

app = create_app()
TODAY = date.today()


def add_if_not_exists(model, filter_field, filter_value, **kwargs):
    """Add a record only if no matching record exists."""
    if not model.query.filter(getattr(model, filter_field) == filter_value).first():
        db.session.add(model(**kwargs))
        return True
    return False


with app.app_context():

    # ── SSL Ключи ──────────────────────────────────────────────────────────
    ssl_entries = [
        dict(name='Wildcard *.example.com',   domain='*.example.com',
             ip_address='185.10.20.30',        valid_until=TODAY + timedelta(days=180)),
        dict(name='Основной сайт shop.ru',     domain='shop.ru',
             ip_address='91.234.56.78',        valid_until=TODAY + timedelta(days=20)),   # warn
        dict(name='API Gateway',               domain='api.myservice.ru',
             ip_address='185.100.200.10',      valid_until=TODAY - timedelta(days=5)),    # expired
        dict(name='Корпоративный портал',      domain='portal.corp.local',
             ip_address='192.168.1.50',        valid_until=TODAY + timedelta(days=365)),
        dict(name='Мобильный бэкенд',          domain='mobile-api.example.com',
             ip_address='5.8.9.100',           valid_until=TODAY + timedelta(days=10)),   # warn
    ]
    for e in ssl_entries:
        ok = add_if_not_exists(SSLKey, 'domain', e['domain'], **e)
        print(f'  SSL  {e["name"]} — {"добавлен" if ok else "уже существует"}')

    # ── Серверы ────────────────────────────────────────────────────────────
    server_entries = [
        dict(name='Prod Web Server',    domain='web.example.com',
             ip_address='185.10.20.31', server_type='Server', provider='Hetzner',       valid_until=None),
        dict(name='VDS Базы данных',    domain='db1.example.com',
             ip_address='185.10.20.32', server_type='VDS',    provider='DigitalOcean',  valid_until=TODAY + timedelta(days=15)),  # warn
        dict(name='Staging сервер',     domain='staging.example.com',
             ip_address='10.0.0.5',     server_type='VDS',    provider='Selectel',      valid_until=TODAY + timedelta(days=90)),
        dict(name='Резервный сервер',   domain='backup.corp.local',
             ip_address='192.168.1.100',server_type='Server', provider='Собственное железо', valid_until=None),
        dict(name='VDS Очереди задач',  domain='queue.example.com',
             ip_address='78.90.11.22',  server_type='VDS',    provider='Timeweb',       valid_until=TODAY - timedelta(days=3)),   # expired
    ]
    for e in server_entries:
        ok = add_if_not_exists(Server, 'domain', e['domain'], **e)
        print(f'  SRV  {e["name"]} — {"добавлен" if ok else "уже существует"}')

    # ── Доступы — пароли шифруются Fernet ─────────────────────────────────
    # Always re-create to ensure Fernet encryption is applied correctly
    Access.query.delete()

    access_entries = [
        dict(name='SSH root Web Server',     domain='web.example.com',
             ip_address='185.10.20.31',      username='root',
             password=encrypt_password('S3cur3P@ssw0rd!'),
             public_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+devops@web',
             access_type='server',           valid_until=None),
        dict(name='Панель управления VPS',   domain='panel.vds.example.com',
             ip_address='185.10.20.32',      username='admin',
             password=encrypt_password('P@nel$ecr3t'),
             public_key=None,                access_type='server_management',
             valid_until=TODAY + timedelta(days=25)),  # warn
        dict(name='GitHub Actions CI',       domain='github.com',
             ip_address='140.82.121.4',      username='ci-bot',
             password=encrypt_password('ghp_fakeToken123456'),
             public_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA ci-bot@github',
             access_type='account',          valid_until=TODAY + timedelta(days=330)),
        dict(name='Cloudflare DNS',          domain='cloudflare.com',
             ip_address='1.1.1.1',           username='admin@example.com',
             password=encrypt_password('CF$ecretKey!'),
             public_key=None,                access_type='account',
             valid_until=None),
        dict(name='SSH Staging',             domain='staging.example.com',
             ip_address='10.0.0.5',          username='deploy',
             password=encrypt_password('D3ploy$ecret'),
             public_key='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB deploy@staging',
             access_type='server',           valid_until=TODAY - timedelta(days=1)),  # expired
    ]
    for e in access_entries:
        db.session.add(Access(**e))
        print(f'  ACC  {e["name"]} — добавлен (зашифрован)')

    db.session.commit()
    print('\n[OK] Тестовые данные загружены. Пароли зашифрованы Fernet.')
    print('     Содержит: истекшие / скоро истекает / нормальные записи.')
