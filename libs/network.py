from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, session, abort
from math import ceil
from ipaddress import ip_address
import subprocess
import os
import re
import sqlite3
import xml.etree.ElementTree as ET
from contextlib import closing
from datetime import datetime
from functools import wraps
from libs.security import admin_required

network_bp = Blueprint('network', __name__)

DB_FOLDER = 'db'
DATABASE_NET = os.path.join(DB_FOLDER, 'network.db')

def ensure_description_column(conn):
    columns = {row[1] for row in conn.execute('PRAGMA table_info(ip)')}
    if 'description' not in columns:
        conn.execute("ALTER TABLE ip ADD COLUMN description TEXT NOT NULL DEFAULT ''")


def ensure_presence_column(conn):
    columns = {row[1] for row in conn.execute('PRAGMA table_info(ip)')}
    if 'ever_seen' not in columns:
        conn.execute('ALTER TABLE ip ADD COLUMN ever_seen INTEGER NOT NULL DEFAULT 0')
    if {'mac', 'status'} <= columns:
        conn.execute("""UPDATE ip SET ever_seen = 1 WHERE ever_seen = 0 AND
                     (status = 'online' OR (mac IS NOT NULL AND mac NOT IN ('', 'N/A'))
                      OR EXISTS (SELECT 1 FROM service WHERE service.ip_id = ip.id))""")


def ip_color(ip, status, ever_seen):
    if status == 'online':
        return 'green'
    if ever_seen:
        return 'red'
    return 'yellow' if int(ip.split('.')[-1]) in (0, 255) else 'lightgray'


@network_bp.route('/network/description/<ip>', methods=['POST'])
@admin_required
def save_description(ip):
    data = request.get_json(silent=True)
    if not is_valid_ip(ip) or not isinstance(data, dict):
        return jsonify({'error': 'Invalid request'}), 400
    description = data.get('description')
    if not isinstance(description, str) or len(description) > 4000:
        return jsonify({'error': 'Description must be text up to 4000 characters.'}), 400
    try:
        with closing(sqlite3.connect(DATABASE_NET)) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            ensure_description_column(conn)
            conn.execute('INSERT OR IGNORE INTO ip (ip) VALUES (?)', (ip,))
            conn.execute('UPDATE ip SET description = ? WHERE ip = ?', (description, ip))
        return jsonify({'ip': ip, 'description': description})
    except sqlite3.Error:
        return jsonify({'error': 'Could not save description.'}), 500

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@network_bp.route('/network')
@admin_required
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
@admin_required
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
@admin_required
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
@admin_required
def network_view(id):
    with closing(sqlite3.connect(DATABASE_NET)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        ensure_description_column(conn)
        ensure_presence_column(conn)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM network WHERE id = ?", (id,))
        row = cursor.fetchone()
        if row is None:
            abort(404)
        ip_min = ip_address(row['ip_min'])
        ip_max = ip_address(row['ip_max'])

        # IP text ordering is not numeric ordering (e.g. .100 sorts before .20).
        cursor.execute("SELECT ip, mac, status, description, ever_seen FROM ip")
        db_rows = [entry for entry in cursor.fetchall()
                   if ip_min <= ip_address(entry['ip']) <= ip_max]
        db_seen = {row['ip']: row['ever_seen'] for row in db_rows}
        db_dict = {row['ip']: row['mac'] for row in db_rows}
        db_status = {row['ip']: row['status'] for row in db_rows}
        db_descriptions = {row['ip']: row['description'] for row in db_rows}

        cursor.execute("SELECT ip.ip, GROUP_CONCAT(service.number, ',') AS ports FROM ip LEFT JOIN service ON service.ip_id = ip.id GROUP BY ip.ip;")
        db_rows_p = cursor.fetchall()
        db_ports = {row['ip']: row['ports'] for row in db_rows_p}

    ip_list = []
    current_ip = ip_min
    while current_ip <= ip_max:
        ip_last_digit = int(str(current_ip).split('.')[-1])
        status = db_status.get(str(current_ip))
        color = ip_color(str(current_ip), status, db_seen.get(str(current_ip), False))
        ip_entry = {
            'ip': str(current_ip),
            'number': ip_last_digit,
            'color': color,
            'mac': db_dict.get(str(current_ip), ''),
            'description': db_descriptions.get(str(current_ip), '') or '',
            'ports': db_ports.get(str(current_ip), '')
        }
        ip_list.append(ip_entry)

        current_ip = ip_address(int(current_ip) + 1)
    return render_template('network/view.html', row=row, ip_list=ip_list)


@network_bp.route('/network/status/<int:id>')
@admin_required
def network_status(id):
    with closing(sqlite3.connect(DATABASE_NET)) as conn:
        bounds = conn.execute('SELECT ip_min, ip_max FROM network WHERE id=?', (id,)).fetchone()
        if bounds is None:
            abort(404)
        low, high = map(ip_address, bounds)
        entries = [{'ip': ip, 'color': ip_color(ip, status, seen)}
                   for ip, status, seen in conn.execute('SELECT ip, status, ever_seen FROM ip')
                   if low <= ip_address(ip) <= high]
    return jsonify({'entries': entries})

@network_bp.route('/network/delete/<id>', methods=['POST'])
@admin_required
def network_delete(id):
    with sqlite3.connect(DATABASE_NET) as conn:
        conn.execute('DELETE FROM network WHERE id = ?', (id,))
        conn.commit()

    flash(f'Network deleted successfully!', 'success')
    return redirect(url_for('network.network_list'))

@network_bp.route('/network/ping', methods=['POST'])
@login_required
def ping():
    data = request.get_json(silent=True)
    ip = data.get('ip') if isinstance(data, dict) else None
    if not isinstance(ip, str) or not is_valid_ip(ip):
        return jsonify({'error': 'No IP provided'}), 400

    try:
        from libs.monitor import probe, ensure_monitor_columns
        import time
        online = probe(ip)
        status = 'online' if online else 'offline'
        now = datetime.utcnow().isoformat(sep=' ', timespec='seconds')

        with closing(sqlite3.connect(DATABASE_NET)) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            ensure_monitor_columns(conn)
            conn.execute('INSERT OR IGNORE INTO ip (ip) VALUES (?)', (ip,))
            conn.execute("""UPDATE ip SET status = ?, updated_at = ?,
                         ever_seen = CASE WHEN ? THEN 1 ELSE ever_seen END WHERE ip = ?""",
                         (status, now, online, ip))
            conn.execute('UPDATE ip SET checked_at=?, ping_failures=? WHERE ip=?',
                         (time.time(), 0 if online else 3, ip))
            ever_seen = bool(conn.execute('SELECT ever_seen FROM ip WHERE ip = ?', (ip,)).fetchone()[0])
        return jsonify({'status': status, 'ever_seen': ever_seen,
                        'color': ip_color(ip, status, ever_seen)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# def get_mac_from_ip(ip):
#     output = subprocess.check_output(['ip', 'neigh', 'show', ip]).decode()
#     match = re.search(r'(?P<mac>([0-9a-f]{2}:){5}[0-9a-f]{2})', output, re.I)
#     return match.group('mac') if match else None

@network_bp.route('/network/ports/<ip>', methods=['POST'])
@admin_required
def ports(ip):
    if not is_valid_ip(ip):
        return jsonify({'error': 'Invalid IPv4 address'}), 400
    try:
        result = subprocess.run(
            ['nmap', '-sT', '-Pn', '-n', '-p-', '-T4',
             '--host-timeout', '60s', '-oX', '-', ip],
            capture_output=True, text=True, timeout=75)
        if result.returncode != 0:
            return jsonify({'error': 'Nmap failed; previous ports were preserved.'}), 502
        report = ET.fromstring(result.stdout)
        finished = report.find('runstats/finished')
        host = next((host for host in report.findall('host')
                     if any(address.get('addr') == ip for address in host.findall('address'))), None)
        if (finished is None or finished.get('exit') != 'success' or host is None
                or host.get('timedout') == 'true' or host.find('ports') is None):
            return jsonify({'error': 'Scan incomplete or host timed out; previous ports were preserved.'}), 502
        open_ports = sorted({int(port.get('portid'))
                             for port in host.findall('ports/port')
                             if port.get('protocol') == 'tcp'
                             and port.find('state') is not None
                             and port.find('state').get('state') == 'open'})
        now = datetime.utcnow().isoformat()
        with closing(sqlite3.connect(DATABASE_NET)) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            ensure_presence_column(conn)
            conn.execute('INSERT OR IGNORE INTO ip (ip) VALUES (?)', (ip,))
            if open_ports:
                conn.execute('UPDATE ip SET ever_seen = 1 WHERE ip = ?', (ip,))
            ip_id = conn.execute('SELECT id FROM ip WHERE ip = ?', (ip,)).fetchone()[0]
            conn.execute('DELETE FROM service WHERE ip_id = ?', (ip_id,))
            conn.executemany(
                'INSERT INTO service (ip_id, number, updated_at) VALUES (?, ?, ?)',
                [(ip_id, port, now) for port in open_ports])
        return jsonify({'ip': ip, 'ports': open_ports})
    except FileNotFoundError:
        return jsonify({'error': 'Nmap is not installed on the NOC server.'}), 503
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Scan timed out; previous ports were preserved.'}), 504
    except (ET.ParseError, ValueError, TypeError):
        return jsonify({'error': 'Invalid Nmap output; previous ports were preserved.'}), 502
    except sqlite3.Error:
        return jsonify({'error': 'Could not save scan results.'}), 500
