import os
import secrets
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
# Multi-tenancy: an Organization owns all SSL keys, servers, accesses, and users.
# Users belong to exactly one org (v1). Roles: 'admin' (manage members/billing)
# or 'member' (manage resources only).
# ──────────────────────────────────────────────────────────────────────────────
VALID_ROLES = ('admin', 'member', 'viewer')
EDITOR_ROLES = ('admin', 'member')  # can create/edit/delete resources


class Organization(TimestampMixin, db.Model):
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    # The owner is special: cannot be removed/demoted; receives billing emails.
    # Nullable only because of FK chicken-and-egg at creation; always set after.
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Billing — see Subscription model below. Mirrored here for fast access.
    plan = db.Column(db.String(20), nullable=False, default='free')  # free|pro
    plan_status = db.Column(db.String(30), nullable=False, default='active')

    users = db.relationship('User', back_populates='organization',
                            lazy='dynamic', foreign_keys='User.org_id')
    owner = db.relationship('User', foreign_keys=[owner_id], post_update=True)
    ssl_keys = db.relationship('SSLKey', back_populates='organization',
                               lazy='dynamic', cascade='all, delete-orphan')
    servers = db.relationship('Server', back_populates='organization',
                              lazy='dynamic', cascade='all, delete-orphan')
    accesses = db.relationship('Access', back_populates='organization',
                               lazy='dynamic', cascade='all, delete-orphan')
    invites = db.relationship('Invite', back_populates='organization',
                              lazy='dynamic', cascade='all, delete-orphan')
    subscription = db.relationship('Subscription', back_populates='organization',
                                   uselist=False, cascade='all, delete-orphan')

    @property
    def is_paid(self) -> bool:
        return self.plan != 'free' and self.plan_status in ('active', 'trialing')

    def record_count(self) -> int:
        return (self.ssl_keys.count()
                + self.servers.count()
                + self.accesses.count())

    @property
    def record_limit(self) -> int | None:
        """Free tier: 10 records total. Paid: unlimited (None)."""
        return None if self.is_paid else 10

    @property
    def can_add_record(self) -> bool:
        limit = self.record_limit
        return limit is None or self.record_count() < limit


class Subscription(TimestampMixin, db.Model):
    """Mirror of the active Stripe subscription, for billing UI + webhook updates."""
    __tablename__ = 'subscriptions'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'),
                       nullable=False, unique=True)
    stripe_customer_id = db.Column(db.String(120), nullable=True, index=True)
    stripe_subscription_id = db.Column(db.String(120), nullable=True, index=True)
    plan = db.Column(db.String(20), nullable=False, default='free')
    status = db.Column(db.String(30), nullable=False, default='active')
    current_period_end = db.Column(db.DateTime, nullable=True)
    cancel_at_period_end = db.Column(db.Boolean, nullable=False, default=False)

    organization = db.relationship('Organization', back_populates='subscription')


# ──────────────────────────────────────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='member')
    # Platform-level flag: super-admin (sees /admin, can impersonate, set plans).
    # Independent of org role. Granted manually via DB or init_db.py.
    is_staff = db.Column(db.Boolean, nullable=False, default=False)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'),
                       nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    organization = db.relationship('Organization', back_populates='users',
                                   foreign_keys=[org_id])

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == 'admin'

    @property
    def is_editor(self) -> bool:
        """Can create/edit/delete resources (admin or member, not viewer)."""
        return self.role in EDITOR_ROLES

    @property
    def is_owner(self) -> bool:
        return self.organization is not None and self.organization.owner_id == self.id


class Invite(db.Model):
    """One-time invite token that lets a new user join an existing org."""
    __tablename__ = 'invites'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'),
                       nullable=False, index=True)
    email = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(20), nullable=False, default='member')
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False,
                           default=lambda: datetime.utcnow() + timedelta(days=7))
    used_at = db.Column(db.DateTime, nullable=True)

    organization = db.relationship('Organization', back_populates='invites')

    @staticmethod
    def new_token() -> str:
        return secrets.token_urlsafe(32)

    @property
    def is_valid(self) -> bool:
        return self.used_at is None and self.expires_at > datetime.utcnow()


class SSLKey(TimestampMixin, ExpiryMixin, db.Model):
    __tablename__ = 'ssl_keys'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'),
                       nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    valid_until = db.Column(db.Date, nullable=False)

    organization = db.relationship('Organization', back_populates='ssl_keys')


VALID_SERVER_TYPES = ('VDS', 'Server')


class Server(TimestampMixin, ExpiryMixin, db.Model):
    __tablename__ = 'servers'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'),
                       nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    domain = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    # Enum-like: only 'VDS' or 'Server' are accepted (validated in routes)
    server_type = db.Column(db.String(20), nullable=False)
    provider = db.Column(db.String(200), nullable=False)
    # None → Всегда (only for type='Server')
    valid_until = db.Column(db.Date, nullable=True)

    organization = db.relationship('Organization', back_populates='servers')


VALID_ACCESS_TYPES = ('account', 'server', 'server_management')


class Access(TimestampMixin, ExpiryMixin, db.Model):
    __tablename__ = 'accesses'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'),
                       nullable=False, index=True)
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

    organization = db.relationship('Organization', back_populates='accesses')

    @property
    def decrypted_password(self) -> str:
        return decrypt_password(self.password)


# ──────────────────────────────────────────────────────────────────────────────
# Audit log — every sensitive action gets a row here.
# ──────────────────────────────────────────────────────────────────────────────
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'),
                       nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    actor_label = db.Column(db.String(120), nullable=True)  # snapshot of username at the time
    action = db.Column(db.String(60), nullable=False, index=True)
    entity_type = db.Column(db.String(40), nullable=True)
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False,
                           default=datetime.utcnow, index=True)

    user = db.relationship('User', foreign_keys=[user_id])
