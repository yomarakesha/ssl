"""Platform admin panel (User.is_staff=True).

This is the SaaS owner's view across all tenants — separate from /team
which is for an Organization's own admin.
"""
from datetime import datetime, timedelta

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    flash, abort, session,
)
from flask_login import login_required, current_user, login_user
from sqlalchemy import func, or_

from models import db, Organization, User, SSLKey, Server, Access, Subscription
from routes._helpers import staff_required
from services.audit import log_action

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

VALID_PLANS = ('free', 'pro')
VALID_PLAN_STATUSES = ('active', 'trialing', 'canceled', 'past_due', 'incomplete')


# ──────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────
@admin_bp.route('/')
@login_required
@staff_required
def dashboard():
    week_ago = datetime.utcnow() - timedelta(days=7)
    stats = {
        'orgs_total': Organization.query.count(),
        'orgs_paid': Organization.query.filter(Organization.plan != 'free').count(),
        'users_total': User.query.count(),
        'users_new_7d': User.query.filter(User.created_at >= week_ago).count(),
        'orgs_new_7d': Organization.query.filter(Organization.created_at >= week_ago).count(),
        'ssl_total': SSLKey.query.count(),
        'servers_total': Server.query.count(),
        'accesses_total': Access.query.count(),
    }
    recent_orgs = (Organization.query
                   .order_by(Organization.created_at.desc())
                   .limit(10).all())
    return render_template('admin/dashboard.html', stats=stats, recent_orgs=recent_orgs)


# ──────────────────────────────────────────────
# Organizations list / detail
# ──────────────────────────────────────────────
@admin_bp.route('/orgs')
@login_required
@staff_required
def orgs():
    q = request.args.get('q', '').strip()
    plan = request.args.get('plan', '').strip()
    query = Organization.query
    if q:
        query = query.filter(Organization.name.ilike(f'%{q}%'))
    if plan in VALID_PLANS:
        query = query.filter_by(plan=plan)
    orgs = query.order_by(Organization.created_at.desc()).limit(200).all()
    # Counts for the list view — one extra small query each, fine for <200 rows.
    org_stats = []
    for o in orgs:
        org_stats.append({
            'org': o,
            'users': o.users.count(),
            'records': o.record_count(),
        })
    return render_template('admin/orgs.html', org_stats=org_stats, q=q, plan=plan)


@admin_bp.route('/orgs/<int:org_id>')
@login_required
@staff_required
def org_detail(org_id):
    org = Organization.query.get_or_404(org_id)
    members = User.query.filter_by(org_id=org.id).order_by(User.created_at).all()
    counts = {
        'ssl': SSLKey.query.filter_by(org_id=org.id).count(),
        'servers': Server.query.filter_by(org_id=org.id).count(),
        'accesses': Access.query.filter_by(org_id=org.id).count(),
    }
    return render_template('admin/org_detail.html',
                           org=org, members=members, counts=counts)


@admin_bp.route('/orgs/<int:org_id>/set-plan', methods=['POST'])
@login_required
@staff_required
def set_plan(org_id):
    org = Organization.query.get_or_404(org_id)
    plan = request.form.get('plan', '').strip()
    status = request.form.get('status', 'active').strip()
    if plan not in VALID_PLANS or status not in VALID_PLAN_STATUSES:
        flash('Недопустимый план/статус.', 'danger')
        return redirect(url_for('admin.org_detail', org_id=org.id))

    old = f'{org.plan}/{org.plan_status}'
    org.plan = plan
    org.plan_status = status
    if org.subscription:
        org.subscription.plan = plan
        org.subscription.status = status

    log_action('admin.set_plan', 'organization', org.id,
               f'{old} → {plan}/{status}', org_id=org.id)
    db.session.commit()
    flash(f'Тариф организации обновлён: {plan}/{status}.', 'success')
    return redirect(url_for('admin.org_detail', org_id=org.id))


# ──────────────────────────────────────────────
# Users list + impersonation
# ──────────────────────────────────────────────
@admin_bp.route('/users')
@login_required
@staff_required
def users():
    q = request.args.get('q', '').strip()
    query = User.query
    if q:
        like = f'%{q}%'
        query = query.filter(or_(User.username.ilike(like), User.email.ilike(like)))
    users = query.order_by(User.created_at.desc()).limit(200).all()
    return render_template('admin/users.html', users=users, q=q)


@admin_bp.route('/users/<int:user_id>/impersonate', methods=['POST'])
@login_required
@staff_required
def impersonate(user_id):
    if session.get('impersonator_id'):
        flash('Сначала вернитесь в свою учётную запись.', 'warning')
        return redirect(url_for('admin.users'))

    target = User.query.get_or_404(user_id)
    if target.id == current_user.id:
        flash('Уже вы.', 'info')
        return redirect(url_for('admin.users'))

    log_action('admin.impersonate', 'user', target.id,
               f'{current_user.username} → {target.username}')
    db.session.commit()

    session['impersonator_id'] = current_user.id
    login_user(target)
    flash(f'Вы вошли как {target.username}. Используйте «Выйти из режима» в шапке.', 'info')
    return redirect(url_for('ssl.index'))


@admin_bp.route('/stop-impersonate', methods=['POST'])
@login_required
def stop_impersonate():
    """Available to anyone who was impersonated — uses session, not staff flag."""
    original_id = session.pop('impersonator_id', None)
    if not original_id:
        flash('Вы не в режиме impersonation.', 'warning')
        return redirect(url_for('ssl.index'))

    original = User.query.get(original_id)
    if not original:
        # Edge case: original user was deleted. Just log out.
        from flask_login import logout_user
        logout_user()
        return redirect(url_for('auth.login'))

    log_action('admin.stop_impersonate', user=original,
               details=f'was: {current_user.username}')
    db.session.commit()
    login_user(original)
    flash('Вернулись в свою учётную запись.', 'success')
    return redirect(url_for('admin.dashboard'))
