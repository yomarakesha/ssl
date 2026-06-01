from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_user, logout_user, login_required, current_user

from models import db, User, Organization, Invite, AuditLog, VALID_ROLES
from routes._helpers import admin_required
from services.audit import log_action

auth_bp = Blueprint('auth', __name__)

MIN_PASSWORD = 8


# ──────────────────────────────────────────────
# Login / Logout
# ──────────────────────────────────────────────
@auth_bp.route('/', methods=['GET', 'POST'])
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('ssl.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            log_action('auth.login', user=user)
            db.session.commit()
            return redirect(url_for('ssl.index'))
        log_action('auth.login_failed', details=f'username={username}')
        db.session.commit()
        flash('Неверное имя пользователя или пароль.', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    log_action('auth.logout')
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))


# ──────────────────────────────────────────────
# Registration: new org + first admin user
# ──────────────────────────────────────────────
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('ssl.index'))

    form = {}
    if request.method == 'POST':
        form = request.form.to_dict()
        org_name = form.get('org_name', '').strip()
        username = form.get('username', '').strip()
        email = form.get('email', '').strip() or None
        password = form.get('password', '')

        if not all([org_name, username, password]):
            flash('Пожалуйста, заполните все поля.', 'danger')
            return render_template('register.html', form=form)

        if len(password) < MIN_PASSWORD:
            flash(f'Пароль должен быть не короче {MIN_PASSWORD} символов.', 'danger')
            return render_template('register.html', form=form)

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует.', 'danger')
            return render_template('register.html', form=form)

        if email and User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует.', 'danger')
            return render_template('register.html', form=form)

        org = Organization(name=org_name)
        db.session.add(org)
        db.session.flush()

        user = User(username=username, email=email, role='admin', org_id=org.id)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()

        # First user is the owner.
        org.owner_id = user.id
        log_action('org.create', 'organization', org.id, org_name,
                   org_id=org.id, user=user)
        db.session.commit()

        login_user(user)
        flash('Организация создана. Добро пожаловать!', 'success')
        return redirect(url_for('ssl.index'))

    return render_template('register.html', form=form)


# ──────────────────────────────────────────────
# Invites: admin creates, anyone with the link can accept
# ──────────────────────────────────────────────
@auth_bp.route('/team', methods=['GET'])
@login_required
@admin_required
def team():
    members = User.query.filter_by(org_id=current_user.org_id).order_by(User.username).all()
    invites = (Invite.query
               .filter_by(org_id=current_user.org_id, used_at=None)
               .filter(Invite.expires_at > datetime.utcnow())
               .order_by(Invite.created_at.desc()).all())
    return render_template('team.html', members=members, invites=invites)


@auth_bp.route('/team/invite', methods=['POST'])
@login_required
@admin_required
def create_invite():
    email = request.form.get('email', '').strip() or None
    role = request.form.get('role', 'member').strip()
    if role not in VALID_ROLES:
        flash('Недопустимая роль.', 'danger')
        return redirect(url_for('auth.team'))

    invite = Invite(
        token=Invite.new_token(),
        org_id=current_user.org_id,
        email=email,
        role=role,
        created_by_id=current_user.id,
    )
    db.session.add(invite)
    db.session.flush()
    log_action('invite.create', 'invite', invite.id, f'role={role} email={email or "-"}')
    db.session.commit()
    flash('Инвайт создан. Скопируй ссылку и отправь сотруднику.', 'success')
    return redirect(url_for('auth.team'))


@auth_bp.route('/team/invite/<int:invite_id>/revoke', methods=['POST'])
@login_required
@admin_required
def revoke_invite(invite_id):
    invite = Invite.query.filter_by(
        id=invite_id, org_id=current_user.org_id
    ).first_or_404()
    log_action('invite.revoke', 'invite', invite.id)
    db.session.delete(invite)
    db.session.commit()
    flash('Инвайт отозван.', 'success')
    return redirect(url_for('auth.team'))


@auth_bp.route('/accept-invite/<token>', methods=['GET', 'POST'])
def accept_invite(token):
    if current_user.is_authenticated:
        flash('Сначала выйдите из текущей учётной записи, чтобы принять инвайт.', 'warning')
        return redirect(url_for('ssl.index'))

    invite = Invite.query.filter_by(token=token).first()
    if not invite or not invite.is_valid:
        abort(404)

    form = {'email': invite.email or ''}
    if request.method == 'POST':
        form = request.form.to_dict()
        username = form.get('username', '').strip()
        email = form.get('email', '').strip() or invite.email
        password = form.get('password', '')

        if not all([username, password]):
            flash('Пожалуйста, заполните все поля.', 'danger')
            return render_template('accept_invite.html', invite=invite, form=form)

        if len(password) < MIN_PASSWORD:
            flash(f'Пароль должен быть не короче {MIN_PASSWORD} символов.', 'danger')
            return render_template('accept_invite.html', invite=invite, form=form)

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует.', 'danger')
            return render_template('accept_invite.html', invite=invite, form=form)

        if email and User.query.filter_by(email=email).first():
            flash('Пользователь с таким email уже существует.', 'danger')
            return render_template('accept_invite.html', invite=invite, form=form)

        user = User(
            username=username, email=email,
            role=invite.role, org_id=invite.org_id,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        invite.used_at = datetime.utcnow()
        log_action('invite.accept', 'invite', invite.id,
                   f'username={username} role={invite.role}',
                   org_id=invite.org_id, user=user)
        db.session.commit()

        login_user(user)
        flash(f'Добро пожаловать в {invite.organization.name}!', 'success')
        return redirect(url_for('ssl.index'))

    return render_template('accept_invite.html', invite=invite, form=form)


# ──────────────────────────────────────────────
# Member management (admin only)
# ──────────────────────────────────────────────
def _get_org_member_or_404(user_id: int) -> User:
    user = User.query.filter_by(id=user_id, org_id=current_user.org_id).first()
    if user is None:
        abort(404)
    return user


@auth_bp.route('/team/<int:user_id>/role', methods=['POST'])
@login_required
@admin_required
def change_role(user_id):
    target = _get_org_member_or_404(user_id)
    new_role = request.form.get('role', '').strip()
    if new_role not in VALID_ROLES:
        flash('Недопустимая роль.', 'danger')
        return redirect(url_for('auth.team'))

    if target.is_owner:
        flash('Нельзя изменить роль владельца. Сначала передайте права.', 'warning')
        return redirect(url_for('auth.team'))

    if target.id == current_user.id and new_role != 'admin':
        flash('Нельзя понизить собственные права администратора.', 'warning')
        return redirect(url_for('auth.team'))

    old = target.role
    target.role = new_role
    log_action('member.role_change', 'user', target.id,
               f'{target.username}: {old} → {new_role}')
    db.session.commit()
    flash(f'Роль {target.username} изменена на {new_role}.', 'success')
    return redirect(url_for('auth.team'))


@auth_bp.route('/team/<int:user_id>/remove', methods=['POST'])
@login_required
@admin_required
def remove_member(user_id):
    target = _get_org_member_or_404(user_id)

    if target.is_owner:
        flash('Нельзя удалить владельца. Сначала передайте права.', 'warning')
        return redirect(url_for('auth.team'))

    if target.id == current_user.id:
        flash('Нельзя удалить самого себя.', 'warning')
        return redirect(url_for('auth.team'))

    log_action('member.remove', 'user', target.id, target.username)
    db.session.delete(target)
    db.session.commit()
    flash(f'Пользователь {target.username} удалён из организации.', 'success')
    return redirect(url_for('auth.team'))


@auth_bp.route('/team/<int:user_id>/transfer-ownership', methods=['POST'])
@login_required
@admin_required
def transfer_ownership(user_id):
    if not current_user.is_owner:
        flash('Передавать права может только владелец.', 'danger')
        return redirect(url_for('auth.team'))

    target = _get_org_member_or_404(user_id)
    if target.id == current_user.id:
        flash('Вы уже владелец.', 'info')
        return redirect(url_for('auth.team'))

    org = current_user.organization
    org.owner_id = target.id
    target.role = 'admin'
    log_action('org.transfer_ownership', 'user', target.id,
               f'owner: {current_user.username} → {target.username}')
    db.session.commit()
    flash(f'Владелец организации теперь {target.username}.', 'success')
    return redirect(url_for('auth.team'))


# ──────────────────────────────────────────────
# Audit log view (admin only)
# ──────────────────────────────────────────────
@auth_bp.route('/audit')
@login_required
@admin_required
def audit():
    entity = request.args.get('entity', '').strip() or None
    q = AuditLog.query.filter_by(org_id=current_user.org_id)
    if entity:
        q = q.filter_by(entity_type=entity)
    entries = q.order_by(AuditLog.created_at.desc()).limit(200).all()
    return render_template('audit.html', entries=entries, entity=entity)
