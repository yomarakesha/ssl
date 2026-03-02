import re
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required

from models import db, Access, VALID_ACCESS_TYPES, encrypt_password

accesses_bp = Blueprint('accesses', __name__, url_prefix='/accesses')

ACCESS_TYPE_LABELS = {
    'account': 'Аккаунт',
    'server': 'Сервер',
    'server_management': 'Управление серверами',
}

_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')


def _validate_ip(ip: str) -> bool:
    if not _IP_RE.match(ip):
        return False
    parts = ip.split('/')[0].split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def _parse_date(date_str: str):
    try:
        return datetime.strptime(date_str.strip(), '%Y-%m-%d').date()
    except (ValueError, AttributeError):
        return None


@accesses_bp.route('/')
@login_required
def index():
    accesses = Access.query.order_by(Access.name).all()
    return render_template('accesses/index.html', accesses=accesses,
                           access_types=ACCESS_TYPE_LABELS)


@accesses_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add():
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

        if not all([name, domain, ip_address, username, password, access_type]):
            flash('Пожалуйста, заполните все обязательные поля.', 'danger')
            return render_template('accesses/form.html', action='add', item=None,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        if access_type not in VALID_ACCESS_TYPES:
            flash('Недопустимый тип доступа.', 'danger')
            return render_template('accesses/form.html', action='add', item=None,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        if not _validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('accesses/form.html', action='add', item=None,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        valid_until = None
        if valid_until_str:
            valid_until = _parse_date(valid_until_str)
            if not valid_until:
                flash('Неверный формат даты.', 'danger')
                return render_template('accesses/form.html', action='add', item=None,
                                       access_types=ACCESS_TYPE_LABELS, form=form)

        access = Access(
            name=name, domain=domain, ip_address=ip_address,
            username=username,
            password=encrypt_password(password),
            public_key=public_key or None,
            access_type=access_type,
            valid_until=valid_until,
        )
        db.session.add(access)
        db.session.commit()
        flash('Доступ успешно добавлен.', 'success')
        return redirect(url_for('accesses.index'))

    return render_template('accesses/form.html', action='add', item=None,
                           access_types=ACCESS_TYPE_LABELS, form=form)


@accesses_bp.route('/edit/<int:access_id>', methods=['GET', 'POST'])
@login_required
def edit(access_id):
    access = Access.query.get_or_404(access_id)
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

        if not _validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('accesses/form.html', action='edit', item=access,
                                   access_types=ACCESS_TYPE_LABELS, form=form)

        valid_until = None
        if valid_until_str:
            valid_until = _parse_date(valid_until_str)
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
        db.session.commit()
        flash('Доступ успешно обновлён.', 'success')
        return redirect(url_for('accesses.index'))

    return render_template('accesses/form.html', action='edit', item=access,
                           access_types=ACCESS_TYPE_LABELS, form=form)


@accesses_bp.route('/delete/<int:access_id>', methods=['POST'])
@login_required
def delete(access_id):
    access = Access.query.get_or_404(access_id)
    db.session.delete(access)
    db.session.commit()
    flash('Доступ удалён.', 'success')
    return redirect(url_for('accesses.index'))
