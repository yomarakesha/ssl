import re
from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required

from models import db, SSLKey

ssl_bp = Blueprint('ssl', __name__, url_prefix='/ssl')

# Simple IPv4 pattern (also allows single IPs and ranges like 192.168.1.0/24)
_IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
)


def _validate_ip(ip: str) -> bool:
    if not _IP_RE.match(ip):
        return False
    parts = ip.split('/')[0].split('.')
    return all(0 <= int(p) <= 255 for p in parts)


def _parse_date(date_str: str):
    """Return a date object or None on failure."""
    try:
        return datetime.strptime(date_str.strip(), '%Y-%m-%d').date()
    except (ValueError, AttributeError):
        return None


@ssl_bp.route('/')
@login_required
def index():
    keys = SSLKey.query.order_by(SSLKey.valid_until).all()
    return render_template('ssl/index.html', keys=keys)


@ssl_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = {}
    if request.method == 'POST':
        form = request.form.to_dict()
        name = form.get('name', '').strip()
        domain = form.get('domain', '').strip()
        ip_address = form.get('ip_address', '').strip()
        valid_until_str = form.get('valid_until', '').strip()

        if not all([name, domain, ip_address, valid_until_str]):
            flash('Пожалуйста, заполните все поля.', 'danger')
            return render_template('ssl/form.html', action='add', item=None, form=form)

        if not _validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('ssl/form.html', action='add', item=None, form=form)

        valid_until = _parse_date(valid_until_str)
        if not valid_until:
            flash('Неверный формат даты.', 'danger')
            return render_template('ssl/form.html', action='add', item=None, form=form)

        key = SSLKey(name=name, domain=domain, ip_address=ip_address, valid_until=valid_until)
        db.session.add(key)
        db.session.commit()
        flash('SSL ключ успешно добавлен.', 'success')
        return redirect(url_for('ssl.index'))

    return render_template('ssl/form.html', action='add', item=None, form=form)


@ssl_bp.route('/edit/<int:key_id>', methods=['GET', 'POST'])
@login_required
def edit(key_id):
    key = SSLKey.query.get_or_404(key_id)
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

        if not _validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('ssl/form.html', action='edit', item=key, form=form)

        valid_until = _parse_date(valid_until_str)
        if not valid_until:
            flash('Неверный формат даты.', 'danger')
            return render_template('ssl/form.html', action='edit', item=key, form=form)

        key.name = name
        key.domain = domain
        key.ip_address = ip_address
        key.valid_until = valid_until
        db.session.commit()
        flash('SSL ключ успешно обновлён.', 'success')
        return redirect(url_for('ssl.index'))

    return render_template('ssl/form.html', action='edit', item=key, form=form)


@ssl_bp.route('/delete/<int:key_id>', methods=['POST'])
@login_required
def delete(key_id):
    key = SSLKey.query.get_or_404(key_id)
    db.session.delete(key)
    db.session.commit()
    flash('SSL ключ удалён.', 'success')
    return redirect(url_for('ssl.index'))
