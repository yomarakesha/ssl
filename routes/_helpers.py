"""
Shared route helpers: input validation and tenant-scoped queries.

Every resource query MUST go through these helpers so we cannot accidentally
leak data across organizations.
"""
import re
from datetime import datetime
from functools import wraps

from flask import abort
from flask_login import current_user

_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')


def validate_ip(ip: str) -> bool:
    if not _IP_RE.match(ip):
        return False
    parts = ip.split('/')[0].split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def parse_date(date_str: str):
    """Return a date object or None on failure."""
    try:
        return datetime.strptime(date_str.strip(), '%Y-%m-%d').date()
    except (ValueError, AttributeError):
        return None


def org_query(model):
    """Return a query for `model` scoped to the current user's organization."""
    return model.query.filter_by(org_id=current_user.org_id)


def get_for_org_or_404(model, obj_id: int):
    """Fetch a row by id but only if it belongs to the current org. 404 otherwise."""
    obj = org_query(model).filter_by(id=obj_id).first()
    if obj is None:
        abort(404)
    return obj


def admin_required(view):
    """Decorator that 403s if the current user is not an org admin."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def editor_required(view):
    """403 if the current user is not allowed to modify resources (viewer)."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_editor:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def staff_required(view):
    """Platform-level: only super-admins (User.is_staff)."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_staff:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def enforce_record_limit():
    """Return True if a new record can be added; flash + return False otherwise.

    Call at the top of every POST handler that creates a new resource.
    """
    from flask import flash, url_for
    org = current_user.organization
    if org.can_add_record:
        return True
    flash(
        f'На бесплатном тарифе можно хранить до {org.record_limit} записей. '
        f'Обновите тариф: {url_for("billing.index")}',
        'warning',
    )
    return False
