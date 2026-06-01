from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

from models import db, Server, VALID_SERVER_TYPES
from routes._helpers import (
    validate_ip, parse_date, org_query, get_for_org_or_404,
    enforce_record_limit,
)

servers_bp = Blueprint('servers', __name__, url_prefix='/servers')


@servers_bp.route('/')
@login_required
def index():
    servers = org_query(Server).order_by(Server.name).all()
    return render_template('servers/index.html', servers=servers)


@servers_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = {}
    if request.method == 'POST':
        if not enforce_record_limit():
            return redirect(url_for('billing.index'))
        form = request.form.to_dict()
        name = form.get('name', '').strip()
        domain = form.get('domain', '').strip()
        ip_address = form.get('ip_address', '').strip()
        server_type = form.get('server_type', '').strip()
        provider = form.get('provider', '').strip()
        valid_until_str = form.get('valid_until', '').strip()

        if not all([name, domain, ip_address, server_type, provider]):
            flash('Пожалуйста, заполните все обязательные поля.', 'danger')
            return render_template('servers/form.html', action='add', item=None, form=form)

        if server_type not in VALID_SERVER_TYPES:
            flash('Недопустимый тип сервера.', 'danger')
            return render_template('servers/form.html', action='add', item=None, form=form)

        if not validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('servers/form.html', action='add', item=None, form=form)

        valid_until = None
        if server_type == 'VDS':
            if not valid_until_str:
                flash('Для типа VDS необходимо указать дату окончания.', 'danger')
                return render_template('servers/form.html', action='add', item=None, form=form)
            valid_until = parse_date(valid_until_str)
            if not valid_until:
                flash('Неверный формат даты.', 'danger')
                return render_template('servers/form.html', action='add', item=None, form=form)

        server = Server(
            org_id=current_user.org_id,
            name=name, domain=domain, ip_address=ip_address,
            server_type=server_type, provider=provider, valid_until=valid_until,
        )
        db.session.add(server)
        db.session.commit()
        flash('Сервер успешно добавлен.', 'success')
        return redirect(url_for('servers.index'))

    return render_template('servers/form.html', action='add', item=None, form=form)


@servers_bp.route('/edit/<int:server_id>', methods=['GET', 'POST'])
@login_required
def edit(server_id):
    server = get_for_org_or_404(Server, server_id)
    form = {}
    if request.method == 'POST':
        form = request.form.to_dict()
        name = form.get('name', '').strip()
        domain = form.get('domain', '').strip()
        ip_address = form.get('ip_address', '').strip()
        server_type = form.get('server_type', '').strip()
        provider = form.get('provider', '').strip()
        valid_until_str = form.get('valid_until', '').strip()

        if not all([name, domain, ip_address, server_type, provider]):
            flash('Пожалуйста, заполните все обязательные поля.', 'danger')
            return render_template('servers/form.html', action='edit', item=server, form=form)

        if server_type not in VALID_SERVER_TYPES:
            flash('Недопустимый тип сервера.', 'danger')
            return render_template('servers/form.html', action='edit', item=server, form=form)

        if not validate_ip(ip_address):
            flash('Некорректный IP-адрес.', 'danger')
            return render_template('servers/form.html', action='edit', item=server, form=form)

        valid_until = None
        if server_type == 'VDS':
            if not valid_until_str:
                flash('Для типа VDS необходимо указать дату окончания.', 'danger')
                return render_template('servers/form.html', action='edit', item=server, form=form)
            valid_until = parse_date(valid_until_str)
            if not valid_until:
                flash('Неверный формат даты.', 'danger')
                return render_template('servers/form.html', action='edit', item=server, form=form)

        server.name = name
        server.domain = domain
        server.ip_address = ip_address
        server.server_type = server_type
        server.provider = provider
        server.valid_until = valid_until
        db.session.commit()
        flash('Сервер успешно обновлён.', 'success')
        return redirect(url_for('servers.index'))

    return render_template('servers/form.html', action='edit', item=server, form=form)


@servers_bp.route('/delete/<int:server_id>', methods=['POST'])
@login_required
def delete(server_id):
    server = get_for_org_or_404(Server, server_id)
    db.session.delete(server)
    db.session.commit()
    flash('Сервер удалён.', 'success')
    return redirect(url_for('servers.index'))
