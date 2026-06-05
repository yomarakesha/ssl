from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user

from models import db, Access, VALID_ACCESS_TYPES, encrypt_password
from routes._helpers import (
    validate_ip, parse_date, org_query, get_for_org_or_404,
    enforce_record_limit, editor_required,
)
from services.audit import log_action

accesses_bp = Blueprint('accesses', __name__, url_prefix='/accesses')

ACCESS_TYPE_LABELS = {
    'account': 'Аккаунт',
    'server': 'Сервер',
    'server_management': 'Управление серверами',
}


@accesses_bp.route('/')
@login_required
def index():
    accesses = org_query(Access).order_by(Access.name).all()
    return render_template('accesses/index.html', accesses=accesses,
                           access_types=ACCESS_TYPE_LABELS)


@accesses_bp.route('/add', methods=['GET', 'POST'])
@login_required
@editor_required
def add():
    form = {}
    if request.method == 'POST':
        if not enforce_record_limit():
            return redirect(url_for('billing.index'))
        form = request.form.to_dict()
        name = form.get('name', '').strip()
        domain = form.get('domain', '').strip()
        ip_address = form.get('ip_address', '').strip()
        username = form.get('username', '').strip()
        password = form.get('password', '').strip()
        public_key = form.get('public_key', '').strip()
        access_type = form.get('access_type', '').strip()
        valid_until_str = form.get('valid_until', '').strip()

        if not all([name, domain, ip_address, username, password, access_type]):
            flash('Пожалуйста, заполните все обязательные поля.', 'danger')
            return render_template('accesses/form.html', action='add', item=None,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        if access_type not in VALID_ACCESS_TYPES:
            flash('Недопустимый тип доступа.', 'danger')
            return render_template('accesses/form.html', action='add', item=None,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        if not validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('accesses/form.html', action='add', item=None,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        valid_until = None
        if valid_until_str:
            valid_until = parse_date(valid_until_str)
            if not valid_until:
                flash('Неверный формат даты.', 'danger')
                return render_template('accesses/form.html', action='add', item=None,
                                       access_types=ACCESS_TYPE_LABELS, form=form)

        access = Access(
            org_id=current_user.org_id,
            name=name, domain=domain, ip_address=ip_address,
            username=username,
            password=encrypt_password(password),
            public_key=public_key or None,
            access_type=access_type,
            valid_until=valid_until,
        )
        db.session.add(access)
        db.session.flush()
        log_action('access.create', 'access', access.id, f'{name} ({domain})')
        db.session.commit()
        flash('Доступ успешно добавлен.', 'success')
        return redirect(url_for('accesses.index'))

    return render_template('accesses/form.html', action='add', item=None,
                           access_types=ACCESS_TYPE_LABELS, form=form)


@accesses_bp.route('/edit/<int:access_id>', methods=['GET', 'POST'])
@login_required
@editor_required
def edit(access_id):
    access = get_for_org_or_404(Access, access_id)
    form = {}
    if request.method == 'POST':
        form = request.form.to_dict()
        name = form.get('name', '').strip()
        domain = form.get('domain', '').strip()
        ip_address = form.get('ip_address', '').strip()
        username = form.get('username', '').strip()
        password = form.get('password', '').strip()
        public_key = form.get('public_key', '').strip()
        access_type = form.get('access_type', '').strip()
        valid_until_str = form.get('valid_until', '').strip()

        if not all([name, domain, ip_address, username, access_type]):
            flash('Пожалуйста, заполните все обязательные поля.', 'danger')
            return render_template('accesses/form.html', action='edit', item=access,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        if access_type not in VALID_ACCESS_TYPES:
            flash('Недопустимый тип доступа.', 'danger')
            return render_template('accesses/form.html', action='edit', item=access,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        if not validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('accesses/form.html', action='edit', item=access,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        valid_until = None
        if valid_until_str:
            valid_until = parse_date(valid_until_str)
            if not valid_until:
                flash('Неверный формат даты.', 'danger')
                return render_template('accesses/form.html', action='edit', item=access,
                                       access_types=ACCESS_TYPE_LABELS, form=form)

        access.name = name
        access.domain = domain
        access.ip_address = ip_address
        access.username = username
        # Only re-encrypt if the user actually changed the password field
        if password:
            access.password = encrypt_password(password)
        access.public_key = public_key or None
        access.access_type = access_type
        access.valid_until = valid_until
        log_action('access.update', 'access', access.id, f'{name} ({domain})')
        db.session.commit()
        flash('Доступ успешно обновлён.', 'success')
        return redirect(url_for('accesses.index'))

    return render_template('accesses/form.html', action='edit', item=access,
                           access_types=ACCESS_TYPE_LABELS, form=form)


@accesses_bp.route('/delete/<int:access_id>', methods=['POST'])
@login_required
@editor_required
def delete(access_id):
    access = get_for_org_or_404(Access, access_id)
    log_action('access.delete', 'access', access.id, f'{access.name} ({access.domain})')
    db.session.delete(access)
    db.session.commit()
    flash('Доступ удалён.', 'success')
    return redirect(url_for('accesses.index'))


@accesses_bp.route('/<int:access_id>/reveal', methods=['POST'])
@login_required
def reveal(access_id):
    """Return the plaintext password and write an audit entry. Viewer ok —
    they can read but cannot edit."""
    access = get_for_org_or_404(Access, access_id)
    log_action('access.reveal', 'access', access.id, f'{access.name} ({access.domain})')
    db.session.commit()
    return jsonify({'password': access.decrypted_password})
