import os
from datetime import date, datetime, timedelta

from cryptography.fernet import Fernet
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()

# ──────────────────────────────────────────────────────────────────────────────
# Fernet key for symmetric password encryption.
# In production store SSL_FERNET_KEY in an environment variable.
# On first run a key is auto-generated and saved to fernet.key (dev only).
# ──────────────────────────────────────────────────────────────────────────────
_FERNET_KEY_FILE = os.path.join(os.path.dirname(__file__), 'fernet.key')


def _get_fernet() -> Fernet:
    env_key = os.environ.get('SSL_FERNET_KEY')
    if env_key:
        return Fernet(env_key.encode())
    if os.path.exists(_FERNET_KEY_FILE):
        with open(_FERNET_KEY_FILE, 'rb') as f:
            return Fernet(f.read().strip())
    # Generate and persist a new key (dev convenience)
    key = Fernet.generate_key()
    with open(_FERNET_KEY_FILE, 'wb') as f:
        f.write(key)
    return Fernet(key)


def encrypt_password(plain: str) -> str:
    """Encrypt a plaintext password and return a UTF-8 token string."""
    return _get_fernet().encrypt(plain.encode()).decode()


def decrypt_password(token: str) -> str:
    """Decrypt a Fernet token back to plaintext. Returns '***' on failure."""
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except Exception:
        return '***'


# ──────────────────────────────────────────────────────────────────────────────
# Shared mixin: audit timestamps
# ──────────────────────────────────────────────────────────────────────────────
class TimestampMixin:
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow, onupdate=datetime.utcnow)


# ──────────────────────────────────────────────────────────────────────────────
# Shared mixin: expiry logic — only ONE of is_expired / is_expiring_soon is True
# ──────────────────────────────────────────────────────────────────────────────
class ExpiryMixin:
    @property
    def is_expired(self) -> bool:
        if self.valid_until is None:
            return False
        return self.valid_until < date.today()

    @property
    def is_expiring_soon(self) -> bool:
        """True only when NOT yet expired but expires within 30 days."""
        if self.valid_until is None:
            return False
        today = date.today()
        return today <= self.valid_until <= today + timedelta(days=30)


# ──────────────────────────────────────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class SSLKey(TimestampMixin, ExpiryMixin, db.Model):
    __tablename__ = 'ssl_keys'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    valid_until = db.Column(db.Date, nullable=False)


VALID_SERVER_TYPES = ('VDS', 'Server')


class Server(TimestampMixin, ExpiryMixin, db.Model):
    __tablename__ = 'servers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    # Enum-like: only 'VDS' or 'Server' are accepted (validated in routes)
    server_type = db.Column(db.String(20), nullable=False)
    provider = db.Column(db.String(200), nullable=False)
    # None → Всегда (only for type='Server')
    valid_until = db.Column(db.Date, nullable=True)


VALID_ACCESS_TYPES = ('account', 'server', 'server_management')


class Access(TimestampMixin, ExpiryMixin, db.Model):
    __tablename__ = 'accesses'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(200), nullable=False)
    # Stored as Fernet-encrypted ciphertext — use encrypt/decrypt_password()
    password = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=True)
    # Enum-like: 'account' | 'server' | 'server_management'
    access_type = db.Column(db.String(50), nullable=False)
    valid_until = db.Column(db.Date, nullable=True)

    @property
    def decrypted_password(self) -> str:
        return decrypt_password(self.password)
