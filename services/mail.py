"""Email sending. No-op in dev unless MAIL_SERVER is configured."""
from flask_mail import Mail, Message

mail = Mail()


def init_mail(app):
    mail.init_app(app)


def send_email(app, recipients, subject, body_text):
    """Send a plain-text email. Silently logs failures (we don't want
    expiry-reminder failures to crash the scheduler)."""
    if not recipients:
        return
    try:
        msg = Message(
            subject=subject,
            recipients=recipients,
            body=body_text,
        )
        mail.send(msg)
        app.logger.info('Mail sent: %s → %s', subject, recipients)
    except Exception as e:
        app.logger.error('Mail send failed (%s → %s): %s', subject, recipients, e)
