from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from models import db, SSLKey
from routes._helpers import (
    validate_ip, parse_date, org_query, get_for_org_or_404,
    enforce_record_limit, editor_required,
)
from services.audit import log_action

ssl_bp = Blueprint('ssl', __name__, url_prefix='/ssl')


@ssl_bp.route('/')
@login_required
def index():
    keys = org_query(SSLKey).order_by(SSLKey.valid_until).all()
    return render_template('ssl/index.html', keys=keys)


@ssl_bp.route('/add', methods=['GET', 'POST'])
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
        valid_until_str = form.get('valid_until', '').strip()

        if not all([name, domain, ip_address, valid_until_str]):
            flash('Пожалуйста, заполните все поля.', 'danger')
            return render_template('ssl/form.html', action='add', item=None, form=form)

        if not validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('ssl/form.html', action='add', item=None, form=form)

        valid_until = parse_date(valid_until_str)
        if not valid_until:
            flash('Неверный формат даты.', 'danger')
            return render_template('ssl/form.html', action='add', item=None, form=form)

        key = SSLKey(
            org_id=current_user.org_id,
            name=name, domain=domain, ip_address=ip_address,
            valid_until=valid_until,
        )
        db.session.add(key)
        db.session.flush()
        log_action('ssl.create', 'ssl_key', key.id, f'{name} ({domain})')
        db.session.commit()
        flash('SSL ключ успешно добавлен.', 'success')
        return redirect(url_for('ssl.index'))

    return render_template('ssl/form.html', action='add', item=None, form=form)


@ssl_bp.route('/edit/<int:key_id>', methods=['GET', 'POST'])
@login_required
@editor_required
def edit(key_id):
    key = get_for_org_or_404(SSLKey, key_id)
    form = {}
    if request.method == 'POST':
        form = request.form.to_dict()
        name = form.get('name', '').strip()
        domain = form.get('domain', '').strip()
        ip_address = form.get('ip_address', '').strip()
        valid_until_str = form.get('valid_until', '').strip()

        if not all([name, domain, ip_address, valid_until_str]):
            flash('Пожалуйста, заполните все поля.', 'danger')
            return render_template('ssl/form.html', action='edit', item=key, form=form)

        if not validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('ssl/form.html', action='edit', item=key, form=form)

        valid_until = parse_date(valid_until_str)
        if not valid_until:
            flash('Неверный формат даты.', 'danger')
            return render_template('ssl/form.html', action='edit', item=key, form=form)

        key.name = name
        key.domain = domain
        key.ip_address = ip_address
        key.valid_until = valid_until
        log_action('ssl.update', 'ssl_key', key.id, f'{name} ({domain})')
        db.session.commit()
        flash('SSL ключ успешно обновлён.', 'success')
        return redirect(url_for('ssl.index'))

    return render_template('ssl/form.html', action='edit', item=key, form=form)


@ssl_bp.route('/delete/<int:key_id>', methods=['POST'])
@login_required
@editor_required
def delete(key_id):
    key = get_for_org_or_404(SSLKey, key_id)
    log_action('ssl.delete', 'ssl_key', key.id, f'{key.name} ({key.domain})')
    db.session.delete(key)
    db.session.commit()
    flash('SSL ключ удалён.', 'success')
    return redirect(url_for('ssl.index'))
