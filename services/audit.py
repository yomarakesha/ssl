"""Audit logging — one entry per sensitive action.

Callers pass the action name + optional entity. The helper snapshots
the current user/org/IP so the log row stays meaningful even after
the user is deleted or the resource is removed.
"""
from flask import request, has_request_context
from flask_login import current_user

from models import db, AuditLog


def log_action(action: str,
               entity_type: str | None = None,
               entity_id: int | None = None,
               details: str | None = None,
               org_id: int | None = None,
               user=None):
    """Persist an audit-log row. Never raises — logging must not break the request."""
    try:
        actor = user if user is not None else (
            current_user if has_request_context() and current_user.is_authenticated else None
        )
        log = AuditLog(
            org_id=org_id if org_id is not None else (actor.org_id if actor else None),
            user_id=(actor.id if actor else None),
            actor_label=(actor.username if actor else None),
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            ip_address=(request.remote_addr if has_request_context() else None),
        )
        db.session.add(log)
        # Caller is expected to commit as part of its own transaction. We flush
        # so the log shares the same transaction boundary as the action.
        db.session.flush()
    except Exception:
        # Never let audit failures break the user-visible action.
        db.session.rollback()
