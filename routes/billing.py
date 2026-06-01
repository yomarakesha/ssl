"""Stripe billing — Checkout + webhooks.

Free tier: 10 records, single user. Pro: unlimited, team.
Configure via env: STRIPE_API_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID_PRO.
"""
from datetime import datetime

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, current_app, abort,
)
from flask_login import login_required, current_user

from models import db, Organization, Subscription
from routes._helpers import admin_required

billing_bp = Blueprint('billing', __name__, url_prefix='/billing')


def _stripe():
    """Lazy import — Stripe is optional in dev."""
    import stripe
    api_key = current_app.config.get('STRIPE_API_KEY')
    if not api_key:
        abort(503, description='Stripe is not configured (STRIPE_API_KEY missing)')
    stripe.api_key = api_key
    return stripe


def _ensure_subscription(org: Organization) -> Subscription:
    if org.subscription:
        return org.subscription
    sub = Subscription(org_id=org.id, plan=org.plan, status=org.plan_status)
    db.session.add(sub)
    db.session.commit()
    return sub


@billing_bp.route('/')
@login_required
def index():
    org = current_user.organization
    _ensure_subscription(org)
    return render_template('billing.html',
                           org=org,
                           is_admin=current_user.is_admin,
                           record_count=org.record_count(),
                           record_limit=org.record_limit)


@billing_bp.route('/checkout', methods=['POST'])
@login_required
@admin_required
def checkout():
    org = current_user.organization
    sub = _ensure_subscription(org)
    price_id = current_app.config.get('STRIPE_PRICE_ID_PRO')
    if not price_id:
        abort(503, description='STRIPE_PRICE_ID_PRO is not configured')

    stripe = _stripe()
    base = current_app.config['APP_BASE_URL'].rstrip('/')

    customer_id = sub.stripe_customer_id
    if not customer_id:
        cust = stripe.Customer.create(
            name=org.name,
            email=current_user.email,
            metadata={'org_id': org.id},
        )
        customer_id = cust.id
        sub.stripe_customer_id = customer_id
        db.session.commit()

    session = stripe.checkout.Session.create(
        mode='subscription',
        customer=customer_id,
        line_items=[{'price': price_id, 'quantity': 1}],
        success_url=base + url_for('billing.success') + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=base + url_for('billing.index'),
        metadata={'org_id': org.id},
    )
    return redirect(session.url, code=303)


@billing_bp.route('/success')
@login_required
def success():
    flash('Спасибо! Если оплата прошла, тариф обновится через несколько секунд.', 'success')
    return redirect(url_for('billing.index'))


@billing_bp.route('/portal', methods=['POST'])
@login_required
@admin_required
def portal():
    """Open Stripe-hosted billing portal — manage card, cancel, view invoices."""
    org = current_user.organization
    sub = _ensure_subscription(org)
    if not sub.stripe_customer_id:
        flash('Нет активной подписки.', 'warning')
        return redirect(url_for('billing.index'))

    stripe = _stripe()
    base = current_app.config['APP_BASE_URL'].rstrip('/')
    portal_session = stripe.billing_portal.Session.create(
        customer=sub.stripe_customer_id,
        return_url=base + url_for('billing.index'),
    )
    return redirect(portal_session.url, code=303)


# ──────────────────────────────────────────────
# Webhook — Stripe → us
# ──────────────────────────────────────────────
@billing_bp.route('/webhook', methods=['POST'])
def webhook():
    import stripe
    webhook_secret = current_app.config.get('STRIPE_WEBHOOK_SECRET')
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature', '')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except (ValueError, stripe.error.SignatureVerificationError) as e:
        current_app.logger.warning('Stripe webhook rejected: %s', e)
        abort(400)

    etype = event['type']
    data = event['data']['object']
    current_app.logger.info('Stripe event: %s', etype)

    if etype in (
        'customer.subscription.created',
        'customer.subscription.updated',
        'customer.subscription.deleted',
    ):
        _apply_subscription(data)
    elif etype == 'checkout.session.completed':
        # We'll get a subscription.* event right after — webhook is informational.
        pass

    return ('', 200)


def _apply_subscription(stripe_sub: dict):
    """Update the local Subscription mirror from a Stripe subscription object."""
    org_id = (stripe_sub.get('metadata') or {}).get('org_id')
    customer_id = stripe_sub.get('customer')

    sub = None
    if org_id:
        sub = Subscription.query.filter_by(org_id=int(org_id)).first()
    if sub is None and customer_id:
        sub = Subscription.query.filter_by(stripe_customer_id=customer_id).first()
    if sub is None:
        current_app.logger.warning('No Subscription found for stripe sub %s', stripe_sub.get('id'))
        return

    sub.stripe_subscription_id = stripe_sub['id']
    sub.status = stripe_sub.get('status', 'unknown')
    sub.cancel_at_period_end = bool(stripe_sub.get('cancel_at_period_end'))
    period_end = stripe_sub.get('current_period_end')
    if period_end:
        sub.current_period_end = datetime.utcfromtimestamp(period_end)

    # Derive plan from subscription status. Anything 'active'/'trialing' = pro.
    if sub.status in ('active', 'trialing'):
        sub.plan = 'pro'
    elif sub.status in ('canceled', 'unpaid', 'incomplete_expired'):
        sub.plan = 'free'
    # other states (past_due, incomplete) keep current plan

    # Mirror to Organization
    org = sub.organization
    org.plan = sub.plan
    org.plan_status = sub.status

    db.session.commit()
    current_app.logger.info(
        'Subscription updated for org=%s: plan=%s status=%s',
        org.id, sub.plan, sub.status,
    )
