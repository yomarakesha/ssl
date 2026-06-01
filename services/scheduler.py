"""Background scheduler for periodic jobs (expiry reminders).

Uses APScheduler in-process. Fine for a single-instance deployment;
for multi-instance, move to Celery beat / external cron.
"""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from services.reminders import send_expiry_reminders

_scheduler: BackgroundScheduler | None = None


def start_scheduler(app):
    global _scheduler
    if _scheduler is not None:
        return  # already running

    _scheduler = BackgroundScheduler(daemon=True, timezone='UTC')
    _scheduler.add_job(
        lambda: send_expiry_reminders(app),
        trigger=CronTrigger(hour=9, minute=0),  # 09:00 UTC daily
        id='expiry_reminders',
        replace_existing=True,
    )
    _scheduler.start()
    app.logger.info('Scheduler started: expiry_reminders @ 09:00 UTC daily')
