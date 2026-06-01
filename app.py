import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, redirect, url_for, flash
from flask_login import LoginManager
from flask_migrate import Migrate

# Load .env if present (no-op in production where env is set by the platform)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

login_manager = LoginManager()
migrate = Migrate()

# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────
LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(formatter)
_console_handler.setLevel(logging.INFO)

_file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, 'ssl_manager.log'),
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding='utf-8',
)
_file_handler.setFormatter(formatter)
_file_handler.setLevel(logging.INFO)


def _is_production() -> bool:
    return os.environ.get('FLASK_ENV') == 'production'


def create_app():
    app = Flask(__name__)

    # ── Secrets / DB config ──
    secret_key = os.environ.get('SSL_SECRET_KEY')
    if not secret_key:
        if _is_production():
            raise RuntimeError('SSL_SECRET_KEY must be set in production')
        secret_key = 'dev-only-insecure-key-change-me'
    app.config['SECRET_KEY'] = secret_key

    database_url = os.environ.get('DATABASE_URL', 'sqlite:///ssl_manager.db')
    # Heroku/Render style postgres:// → postgresql+psycopg://
    if database_url.startswith('postgres://'):
        database_url = 'postgresql+psycopg://' + database_url[len('postgres://'):]
    elif database_url.startswith('postgresql://'):
        database_url = 'postgresql+psycopg://' + database_url[len('postgresql://'):]
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PROPAGATE_EXCEPTIONS'] = False

    # ── Mail config (used by reminders + invites) ──
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'localhost')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 25))
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'false').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get(
        'MAIL_DEFAULT_SENDER', 'noreply@ssl-manager.local'
    )

    # ── Stripe config ──
    app.config['STRIPE_API_KEY'] = os.environ.get('STRIPE_API_KEY', '')
    app.config['STRIPE_WEBHOOK_SECRET'] = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    app.config['STRIPE_PRICE_ID_PRO'] = os.environ.get('STRIPE_PRICE_ID_PRO', '')
    app.config['APP_BASE_URL'] = os.environ.get(
        'APP_BASE_URL', 'http://localhost:5000'
    )

    # Logger
    app.logger.setLevel(logging.INFO)
    if not app.logger.handlers:
        app.logger.addHandler(_console_handler)
        app.logger.addHandler(_file_handler)
    app.logger.info('SSL Manager starting up')

    # Extensions
    from models import db
    db.init_app(app)
    migrate.init_app(app, db)

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Пожалуйста, войдите в систему.'
    login_manager.login_message_category = 'warning'

    from services.mail import init_mail
    init_mail(app)

    from models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ── Error handlers ──
    @app.errorhandler(403)
    def forbidden(e):
        app.logger.warning('403 Forbidden: %s', e)
        flash('Доступ запрещён (403).', 'danger')
        return redirect(url_for('ssl.index'))

    @app.errorhandler(404)
    def not_found(e):
        app.logger.warning('404 Not Found: %s', e)
        flash('Страница не найдена (404).', 'warning')
        return redirect(url_for('ssl.index'))

    @app.errorhandler(405)
    def method_not_allowed(e):
        app.logger.warning('405 Method Not Allowed: %s', e)
        flash('Недопустимый метод запроса (405).', 'warning')
        return redirect(url_for('ssl.index'))

    @app.errorhandler(500)
    def internal_error(e):
        from models import db as _db
        _db.session.rollback()
        app.logger.error('500 Internal Server Error: %s', e, exc_info=True)
        flash('Внутренняя ошибка сервера. Попробуйте позже (500).', 'danger')
        return redirect(url_for('ssl.index'))

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        try:
            from models import db as _db
            _db.session.rollback()
        except Exception:
            pass
        app.logger.error('Unhandled exception: %s', e, exc_info=True)
        flash(f'Произошла ошибка: {e}', 'danger')
        return redirect(url_for('ssl.index'))

    # ── Blueprints ──
    from routes.auth import auth_bp
    from routes.ssl_keys import ssl_bp
    from routes.servers import servers_bp
    from routes.accesses import accesses_bp
    from routes.billing import billing_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(ssl_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(accesses_bp)
    app.register_blueprint(billing_bp)

    # In dev with SQLite, bootstrap schema directly. In production, use
    # `flask db upgrade` (Alembic) — handled by Migrate above.
    if database_url.startswith('sqlite:'):
        with app.app_context():
            db.create_all()

    # Reminders scheduler (skip when running CLI commands / migrations)
    if os.environ.get('ENABLE_SCHEDULER', '1') == '1' and not _is_production_cli():
        from services.scheduler import start_scheduler
        start_scheduler(app)

    app.logger.info('All blueprints registered and DB ready')
    return app


def _is_production_cli() -> bool:
    """Detect Flask CLI invocations (db migrate, shell, etc.) so we don't
    start the scheduler twice."""
    import sys
    return any(arg in sys.argv for arg in ('db', 'shell', 'routes'))


if __name__ == '__main__':
    app = create_app()
    app.run(debug=False)
