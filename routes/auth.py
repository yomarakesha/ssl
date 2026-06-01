from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_user, logout_user, login_required, current_user

from models import db, User, Organization, Invite, VALID_ROLES
from routes._helpers import admin_required

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
            return redirect(url_for('ssl.index'))
        flash('Неверное имя пользователя или пароль.', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
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
        invite.used_at = datetime.utcnow()
        db.session.commit()

        login_user(user)
        flash(f'Добро пожаловать в {invite.organization.name}!', 'success')
        return redirect(url_for('ssl.index'))

    return render_template('accept_invite.html', invite=invite, form=form)
