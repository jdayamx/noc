from flask import Blueprint, render_template, request, flash, redirect, url_for
from math import ceil
from ipaddress import ip_address
import os
import re
import sqlite3

network_bp = Blueprint('network', __name__)

DB_FOLDER = 'db'
DATABASE_NET = os.path.join(DB_FOLDER, 'network.db')

@network_bp.route('/network')
def network_list():
    per_page = 15
    page = request.args.get('page', 1, type=int)
    offset = (page - 1) * per_page

    with sqlite3.connect(DATABASE_NET) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM network")
        total_rows = cursor.fetchone()[0]

        cursor.execute("SELECT * FROM network LIMIT ? OFFSET ?", (per_page, offset))
        rows = [dict(row) for row in cursor.fetchall()]

    total_pages = ceil(total_rows / per_page)
    return render_template('network/list.html', rows=rows, page=page, total_pages=total_pages)

def is_valid_ip(ip):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split('.'))

@network_bp.route('/network/add', methods=['GET', 'POST'])
def network_add():
    if request.method == 'POST':
        new_ip_min = request.form['ip_min']
        new_ip_max = request.form['ip_max']

        if not is_valid_ip(new_ip_min):
            flash('Invalid Min IP address format.', 'danger')
            return redirect(url_for('network.network_add'))

        if not is_valid_ip(new_ip_max):
            flash('Invalid Max IP address format.', 'danger')
            return redirect(url_for('network.network_add'))

        with sqlite3.connect(DATABASE_NET) as conn:
            conn.execute('INSERT INTO network (ip_min, ip_max) VALUES (?, ?)', 
                         (new_ip_min, new_ip_max))
            conn.commit()

        flash(f'Network {new_ip_min}-{new_ip_max} added successfully!', 'success')
        return redirect(url_for('network.network_list'))

    return render_template('network/form.html', request=request)

@network_bp.route('/network/edit/<id>', methods=['GET', 'POST'])
def network_edit(id):
    with sqlite3.connect(DATABASE_NET) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM network WHERE id = ?", (id,))
        row = cursor.fetchone()
    if request.method == 'POST':
        new_ip_min = request.form['ip_min']
        new_ip_max = request.form['ip_max']
        row_dict = dict(row)
        row_dict['ip_min'] = new_ip_min
        row_dict['ip_max'] = new_ip_max

        if not is_valid_ip(new_ip_min):
            flash('Invalid Min IP address format.', 'danger')
            return render_template('network/form.html', row=row_dict, request=request)

        if not is_valid_ip(new_ip_max):
            flash('Invalid Max IP address format.', 'danger')
            return render_template('network/form.html', row=row, request=request)

        with sqlite3.connect(DATABASE_NET) as conn:
            conn.execute('UPDATE network SET ip_min = ?, ip_max = ? WHERE id = ?', 
                         (new_ip_min, new_ip_max, id))
            conn.commit()

        flash(f'Network {new_ip_min}-{new_ip_max} added successfully!', 'success')
        return redirect(url_for('network.network_list'))

    return render_template('network/form.html', row=row, request=request)

def get_arp_table():
    from noc import get_arp_table  # Відкладений імпорт
    arp_table = get_arp_table()
    return arp_table

@network_bp.route('/network/<int:id>')
def network_view(id):
    with sqlite3.connect(DATABASE_NET) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM network WHERE id = ?", (id,))
        row = cursor.fetchone()
        ip_min = ip_address(row['ip_min'])
        ip_max = ip_address(row['ip_max'])

        cursor.execute("SELECT * FROM ip WHERE ip >= ? AND ip <= ?", (row['ip_min'], row['ip_max']))
        db_rows = cursor.fetchall()
        db_ips = {row['ip'] for row in db_rows}
        db_dict = {row['ip']: row['mac'] for row in db_rows}
    arp_table = get_arp_table()
    arp_ips = {row['ip'] for row in arp_table}
    ip_list = []
    current_ip = ip_min
    while current_ip <= ip_max:
        ip_last_digit = int(str(current_ip).split('.')[-1])
        color = 'lightgray'
        if ip_last_digit in [0, 255]:
            color = 'yellow'
        if str(current_ip) in db_ips:
            color = 'red'
        if str(current_ip) in arp_ips:
            color = 'green'
        ip_entry = {
            'ip': str(current_ip),
            'number': ip_last_digit,
            'color': color,
            'mac': db_dict.get(str(current_ip), '')
        }
        ip_list.append(ip_entry)

        current_ip = ip_address(int(current_ip) + 1)
    return render_template('network/view.html', row=row, ip_list=ip_list)

@network_bp.route('/network/delete/<id>', methods=['GET'])
def network_delete(id):
    with sqlite3.connect(DATABASE_NET) as conn:
        conn.execute('DELETE FROM network WHERE id = ?', (id,))
        conn.commit()

    flash(f'Network deleted successfully!', 'success')
    return redirect(url_for('network.network_list'))