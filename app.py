import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager

login_manager = LoginManager()

# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────
LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

formatter = logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Console handler
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(formatter)
_console_handler.setLevel(logging.INFO)

# File handler (10 MB × 5 backups)
_file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, 'ssl_manager.log'),
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding='utf-8',
)
_file_handler.setFormatter(formatter)
_file_handler.setLevel(logging.INFO)


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'ssl-manager-secret-key-2024'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ssl_manager.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PROPAGATE_EXCEPTIONS'] = False  # don't re-raise in prod

    # Attach handlers to the app logger
    app.logger.setLevel(logging.INFO)
    if not app.logger.handlers:
        app.logger.addHandler(_console_handler)
        app.logger.addHandler(_file_handler)

    app.logger.info('SSL Manager starting up')

    from models import db
    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Пожалуйста, войдите в систему.'
    login_manager.login_message_category = 'warning'

    from models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ──────────────────────────────────────────────
    # Global error handlers — no crashes in prod
    # ──────────────────────────────────────────────
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
        _db.session.rollback()          # safety rollback on 500
        app.logger.error('500 Internal Server Error: %s', e, exc_info=True)
        flash('Внутренняя ошибка сервера. Попробуйте позже (500).', 'danger')
        return redirect(url_for('ssl.index'))

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        """Catch-all: log every unhandled exception and show a friendly warning."""
        try:
            from models import db as _db
            _db.session.rollback()
        except Exception:
            pass
        app.logger.error('Unhandled exception: %s', e, exc_info=True)
        flash(f'Произошла ошибка: {e}', 'danger')
        return redirect(url_for('ssl.index'))

    # ──────────────────────────────────────────────
    # Blueprints
    # ──────────────────────────────────────────────
    from routes.auth import auth_bp
    from routes.ssl_keys import ssl_bp
    from routes.servers import servers_bp
    from routes.accesses import accesses_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(ssl_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(accesses_bp)

    with app.app_context():
        db.create_all()

    app.logger.info('All blueprints registered and DB ready')
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=False)   # debug=False in prod — exceptions handled above
