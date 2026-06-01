"""Daily expiry-reminder job.

For each organization, find SSL keys / servers / accesses that:
  - expire within the next 30 days, OR
  - have already expired within the last 7 days
…and email all admins of that org.
"""
from datetime import date, timedelta

from models import db, Organization, User, SSLKey, Server, Access
from services.mail import send_email


WINDOW_DAYS = 30
GRACE_DAYS = 7


def _format_items(label: str, items, attr='valid_until') -> list[str]:
    lines = []
    for it in items:
        when = getattr(it, attr)
        prefix = '⚠️ ' if when and when < date.today() else '  '
        lines.append(f'  {prefix}{label}: {it.name} ({it.domain}) — {when}')
    return lines


def _due_for_org(org_id: int):
    today = date.today()
    soon = today + timedelta(days=WINDOW_DAYS)
    cutoff = today - timedelta(days=GRACE_DAYS)

    def q(model):
        return (model.query
                .filter_by(org_id=org_id)
                .filter(model.valid_until.isnot(None))
                .filter(model.valid_until >= cutoff)
                .filter(model.valid_until <= soon)
                .all())

    return q(SSLKey), q(Server), q(Access)


def send_expiry_reminders(app):
    """Main entry point — called from the scheduler once per day."""
    with app.app_context():
        for org in Organization.query.all():
            ssl_due, server_due, access_due = _due_for_org(org.id)
            if not (ssl_due or server_due or access_due):
                continue

            admins = User.query.filter_by(org_id=org.id, role='admin').all()
            recipients = [a.email for a in admins if a.email]
            if not recipients:
                continue

            lines = [f'Организация: {org.name}', '']
            if ssl_due:
                lines.append('SSL-сертификаты:')
                lines.extend(_format_items('SSL', ssl_due))
                lines.append('')
            if server_due:
                lines.append('Серверы:')
                lines.extend(_format_items('Сервер', server_due))
                lines.append('')
            if access_due:
                lines.append('Доступы:')
                lines.extend(_format_items('Доступ', access_due))
                lines.append('')
            lines.append('— SSL Manager')

            send_email(
                app, recipients,
                subject=f'[{org.name}] Скоро истекают сертификаты/доступы',
                body_text='\n'.join(lines),
            )
