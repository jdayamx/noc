import psutil
import subprocess
import secrets
from flask import jsonify, flash, Flask, render_template, request, redirect, url_for, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps
import sqlite3
import json
import os
import time
import threading
import shutil
import platform
import csv
import io
from pathlib import Path
if platform.system() == "Linux":
    import pyudev
else:
    import wmi
import re
from datetime import datetime
import glob
import gzip
from math import ceil
import socket
from libs import firewall
from libs.network import network_bp
from libs.systemd import systemd_bp
from libs.security import admin_required, csrf_token, get_admin_usernames, is_admin_user, validate_csrf
from collections import Counter
from collections import deque

previous_traffic = {}
APP_VERSION = "1.0.0.26"
WEB_PORTS = {80, 81, 443, 5000, 1983, 3000, 3010, 3335, 8000, 8080, 8443, 9001}
_hostname_cache = {}

app = Flask(__name__, template_folder='html')
app.register_blueprint(network_bp)
app.register_blueprint(systemd_bp)

DB_FOLDER = 'db'
DATABASE = os.path.join(DB_FOLDER, 'users.db')
DATABASE_NET = os.path.join(DB_FOLDER, 'network.db')
SECRET_KEY_FILE = os.path.join(DB_FOLDER, 'secret_key.txt')

LOG_FILE = "/var/log/nginx/access.json"

def get_secret_key():
    os.makedirs(DB_FOLDER, exist_ok=True)

    env_key = os.environ.get("NOC_SECRET_KEY")
    if env_key:
        return env_key

    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key

    key = secrets.token_urlsafe(48)
    with open(SECRET_KEY_FILE, "w", encoding="utf-8") as f:
        f.write(key)
    return key

app.secret_key = get_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("NOC_COOKIE_SECURE", "0") == "1",
)

# Create the db directory if it doesn't exist
if not os.path.exists(DB_FOLDER):
    os.makedirs(DB_FOLDER)


@app.context_processor
def inject_security_helpers():
    return {
        "csrf_token": csrf_token,
        "is_admin_user": is_admin_user,
        "app_version": APP_VERSION,
        "firewall_type": firewall.get_firewall_type(),
    }


app.jinja_env.globals["csrf_token"] = csrf_token
app.jinja_env.globals["is_admin_user"] = is_admin_user
app.jinja_env.globals["app_version"] = APP_VERSION


@app.before_request
def enforce_csrf():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not validate_csrf():
        if request.is_json or request.path == "/update_project":
            return jsonify({"message": "Invalid CSRF token."}), 400

        flash("Invalid CSRF token.", "danger")
        if request.path == "/login":
            return redirect(url_for("login"))
        return redirect(url_for("dashboard"))

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            username TEXT PRIMARY KEY,
                            password TEXT
                        )''')
        conn.commit()
    with sqlite3.connect(DATABASE_NET) as conn_net:
         conn_net.execute('''CREATE TABLE IF NOT EXISTS network (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip_min TEXT NOT NULL,
                            ip_max TEXT NOT NULL
                        )''')
         conn_net.execute('''CREATE TABLE IF NOT EXISTS ip (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip TEXT UNIQUE NOT NULL,
                            mac TEXT,
                            status TEXT DEFAULT 'Unknown',
                            updated_at TEXT
                        )''')
         conn_net.execute('''CREATE TABLE IF NOT EXISTS service (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ip_id INTEGER NOT NULL,
                            number INTEGER NOT NULL,
                            updated_at TEXT,
                            FOREIGN KEY (ip_id) REFERENCES ip (id)
                        )''')
         conn_net.execute('''CREATE TABLE IF NOT EXISTS device (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            description TEXT
                        )''')
         conn_net.execute('''CREATE TABLE IF NOT EXISTS device_ip_link (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            device_id INTEGER NOT NULL,
                            ip_id INTEGER NOT NULL,
                            port_id INTEGER,
                            FOREIGN KEY (device_id) REFERENCES device (id),
                            FOREIGN KEY (ip_id) REFERENCES ip (id),
                            FOREIGN KEY (port_id) REFERENCES port (id)
                        )''')
         conn_net.execute('''CREATE TABLE IF NOT EXISTS port (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            device_id INTEGER NOT NULL,
                            type TEXT NOT NULL,
                            name TEXT NOT NULL,
                            speed TEXT,
                            FOREIGN KEY (device_id) REFERENCES device (id)
                        )''')
         conn_net.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def add_default_users():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        if cursor.fetchone()[0] > 0:
            return

        admin_username = sorted(get_admin_usernames())[0]
        admin_password = os.environ.get('NOC_ADMIN_PASSWORD')
        if not admin_password:
            admin_password = secrets.token_urlsafe(16)
            bootstrap_file = os.path.join(DB_FOLDER, 'bootstrap_credentials.txt')
            with open(bootstrap_file, 'w', encoding='utf-8') as f:
                f.write(f'username={admin_username}\n')
                f.write(f'password={admin_password}\n')
            print(f'Bootstrap admin credentials written to {bootstrap_file}')

        cursor.execute(
            'INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)',
            (admin_username, generate_password_hash(admin_password))
        )
        conn.commit()

def get_cpu_name():
    system = platform.system()

    if system == "Linux":
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "model name" in line:
                        return line.strip().split(":")[1].strip()
        except Exception:
            pass

    elif system == "Windows":
        try:
            output = subprocess.check_output("wmic cpu get name", shell=True).decode()
            lines = output.strip().split("\n")
            if len(lines) > 1:
                return lines[1].strip()
        except Exception:
            pass

    elif system == "Darwin":  # macOS
        try:
            output = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"]).decode().strip()
            return output
        except Exception:
            pass

    # Fallback
    return platform.processor() or "Unknown CPU"

def get_cpu_info():
    usage = psutil.cpu_percent(interval=0.1, percpu=True)
    freq_list = psutil.cpu_freq(percpu=True)

    cores_info = []
    for i, (core_usage, freq) in enumerate(zip(usage, freq_list)):
        cores_info.append({
            "core": i,
            "usage": core_usage,
            "frequency": round(freq.current, 2) if freq else None,
            "min_freq": round(freq.min, 2) if freq else None,
            "max_freq": round(freq.max, 2) if freq else None
        })

    cpu_info = {
        "cpu_name": get_cpu_name(),
        "architecture": platform.machine(),
        "physical_cores": psutil.cpu_count(logical=False),
        "total_cores": psutil.cpu_count(logical=True),
        "cpu_usage_total": psutil.cpu_percent(interval=0),
        "cores": cores_info
    }

    return cpu_info

def get_ram_info():
    mem = psutil.virtual_memory()

    ram_info = []
    dmidecode_path = shutil.which("dmidecode")
    if dmidecode_path:
        try:
            result = subprocess.run(
                [dmidecode_path, "--type", "17"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
                check=False,
            )
            current_ram = {}
            for line in result.stdout.splitlines():
                if "Size" in line:
                    if "No Module Installed" not in line:
                        size = line.split(":", 1)[1].strip()
                        current_ram["size"] = size
                elif "Speed" in line:
                    speed = line.split(":", 1)[1].strip()
                    current_ram["speed"] = speed
                elif "Locator" in line:
                    if current_ram:
                        ram_info.append(current_ram)
                    current_ram = {}

            if current_ram:
                ram_info.append(current_ram)
        except (OSError, subprocess.SubprocessError):
            pass

    return {
        "total": mem.total,
        "available": mem.available,
        "used": mem.used,
        "percent": mem.percent,
        "ram_modules": ram_info,
    }
def get_interface_type(iface):
    try:
        result = subprocess.run(['ethtool', iface], stdout=subprocess.PIPE, text=True)
        if "Speed" in result.stdout:
            return "Ethernet"
    except FileNotFoundError:
        pass

    try:
        result = subprocess.run(['iwconfig', iface], stdout=subprocess.PIPE, text=True)
        if "ESSID" in result.stdout:
            return "Wi-Fi"
    except FileNotFoundError:
        pass

    if iface.startswith("lo"):
        return "Loopback"
    
    return "Unknown"

def get_network_info():
    global previous_traffic

    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    current_traffic = psutil.net_io_counters(pernic=True)

    network_info = []
    current_time = time.time()

    for iface, addrs in interfaces.items():
        ips = []
        conn_type = get_interface_type(iface)

        for addr in addrs:
            if addr.family == 2:  # AF_INET (IPv4)
                ips.append(addr.address)

        speed = stats[iface].speed if iface in stats else 0  # Мбіт/с
        net_stats = current_traffic.get(iface, None)

        # Ініціалізація значень
        bytes_sent = 0
        bytes_received = 0
        utilization = 0

        if net_stats:
            prev_data = previous_traffic.get(iface, {"bytes_sent": net_stats.bytes_sent, "bytes_received": net_stats.bytes_recv, "time": current_time})
            time_diff = current_time - prev_data["time"]

            if time_diff > 0:  # Уникаємо ділення на 0
                bytes_sent = net_stats.bytes_sent - prev_data["bytes_sent"]
                bytes_received = net_stats.bytes_recv - prev_data["bytes_received"]

                # Обчислюємо швидкість за секунду
                sent_per_sec = bytes_sent / time_diff
                recv_per_sec = bytes_received / time_diff

                # Перетворюємо швидкість у байти за секунду
                max_speed_bps = speed * 1_000_000  # у бітах/с
                max_speed_Bps = max_speed_bps / 8  # у байтах/с

                # Розраховуємо завантаженість
                utilization = ((sent_per_sec + recv_per_sec) / max_speed_Bps) * 100 if max_speed_Bps > 0 else 0
                utilization = round(min(utilization, 100), 2)  # Округлюємо до 2 знаків після коми
            else:
                utilization = 0
        else:
            # Якщо немає статистики, значення залишаються 0
            bytes_sent = 0
            bytes_received = 0
            utilization = 0

        # Оновлюємо попередні значення
        previous_traffic[iface] = {
            "bytes_sent": net_stats.bytes_sent if net_stats else 0,
            "bytes_received": net_stats.bytes_recv if net_stats else 0,
            "time": current_time
        }

        network_info.append({
            "interface": iface,
            "ips": ips,  
            "type": conn_type,
            "speed": speed,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "utilization": utilization
        })

    return network_info

def get_arp_table():
    arp_table = []

    try:
        result = subprocess.run(['ip', 'neigh'], stdout=subprocess.PIPE, text=True)
        lines = result.stdout.strip().split("\n")

        # Отримуємо список мережевих інтерфейсів
        interfaces = {iface: psutil.net_if_addrs().get(iface, []) for iface in psutil.net_if_addrs()}

        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                ip_address = parts[0]
                mac_address = parts[4] if parts[4] != "FAILED" else "N/A"
                interface = parts[-1]

                # Шукаємо інтерфейс, який використовує цей MAC
                iface_name = next((iface for iface, addrs in interfaces.items() 
                                   if any(addr.address.lower() == mac_address.lower() for addr in addrs)), interface)

                arp_table.append({
                    "ip": ip_address,
                    "mac": mac_address,
                    "interface": iface_name
                })
    except FileNotFoundError:
        pass

    return arp_table

def get_disk_info():
    disk_info = []
    partitions = psutil.disk_partitions()

    for partition in partitions:
        if partition.mountpoint and partition.mountpoint != "":
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                mountpoint = partition.mountpoint
                if platform.system() == "Linux":
                    mountpoint = partition.mountpoint.replace("\\", "/")
                disk_info.append({
                    "device": partition.device,
                    "mountpoint": mountpoint,
                    "fstype": partition.fstype,
                    "size": usage.total,
                    "free": usage.free,
                    "used": usage.used,
                    "percent": usage.percent,
                })
            except Exception:
                pass
    return disk_info
def get_network_connections():
    connections = []
    
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
            connections.append({
                "local_ip": conn.laddr.ip,
                "local_port": conn.laddr.port,
                "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port,
                "pid": conn.pid
            })
    
    return connections

def _resolve_hostname(ip_address):
    if not ip_address:
        return "Unknown"

    if ip_address in {"127.0.0.1", "::1"}:
        return "localhost"

    cached = _hostname_cache.get(ip_address)
    if cached is not None:
        return cached

    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except Exception:
        hostname = ip_address

    _hostname_cache[ip_address] = hostname
    return hostname

def _get_process_name(pid):
    if not pid:
        return "Unknown"

    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, psutil.Error):
        return "Unknown"

def _is_web_port(port):
    return port in WEB_PORTS

def get_web_connections():
    inbound_connections = []
    outbound_connections = []
    recent_http_by_ip = get_recent_http_activity_by_ip(limit=300)

    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.laddr:
            continue

        local_port = getattr(conn.laddr, "port", None)
        remote_port = getattr(conn.raddr, "port", None)
        local_ip = getattr(conn.laddr, "ip", "")
        remote_ip = getattr(conn.raddr, "ip", "")

        if local_port is None or remote_port is None:
            continue

        if not _is_web_port(local_port) and not _is_web_port(remote_port):
            continue

        record = {
            "pid": conn.pid or 0,
            "process": _get_process_name(conn.pid),
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "remote_host": _resolve_hostname(remote_ip),
            "last_http_host": recent_http_by_ip.get(remote_ip, {}).get("host", ""),
            "last_http_request": recent_http_by_ip.get(remote_ip, {}).get("request", ""),
            "last_http_status": recent_http_by_ip.get(remote_ip, {}).get("status", ""),
        }

        if _is_web_port(local_port):
            record["service"] = f"{local_ip}:{local_port}"
            inbound_connections.append(record)
        else:
            record["service"] = f"{remote_ip}:{remote_port}"
            outbound_connections.append(record)

    inbound_connections.sort(key=lambda item: (item["local_port"], item["remote_ip"], item["remote_port"]))
    outbound_connections.sort(key=lambda item: (item["remote_ip"], item["remote_port"], item["local_port"]))

    return inbound_connections, outbound_connections

def get_recent_http_activity_by_ip(limit=300):
    activity = {}
    for log_entry in _read_recent_access_log_entries(limit):
        ip = log_entry.get("remote_addr", "")
        if not ip:
            continue
        activity[ip] = {
            "time": log_entry.get("time_local", ""),
            "host": log_entry.get("host", ""),
            "request": log_entry.get("request", ""),
            "status": log_entry.get("status", ""),
        }
    return activity

def _read_recent_access_log_entries(limit=2000):
    if not os.path.exists(LOG_FILE):
        return []

    if platform.system() == "Linux":
        try:
            output = subprocess.check_output(
                ["tail", "-n", str(limit), LOG_FILE],
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            output = ""
        if output:
            lines = output.splitlines()
        else:
            lines = []
    else:
        lines = deque(maxlen=limit)
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    lines.append(line.rstrip("\n"))
        except OSError:
            return []
        lines = list(lines)

    entries = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            log_entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries.append(log_entry)

    return entries

def get_summarize_connections():
    from collections import Counter

    conns = get_network_connections()
    counter = Counter()

    for c in conns:
        remote_ip = c["remote_ip"]

        # Пропускаємо локальні підключення
        if remote_ip.startswith("127.") or remote_ip == "::1":
            continue

        key = (remote_ip, c["local_port"])
        counter[key] += 1

    result = [
        {"ip": ip, "port": port, "connections": count}
        for (ip, port), count in counter.items()
    ]

    # Сортування за кількістю підключень (спадання)
    result.sort(key=lambda x: x["connections"], reverse=True)

    return result

def get_usb_devices():
    devices = []
    if platform.system() == "Linux":
        context = pyudev.Context()

        for device in context.list_devices(subsystem='usb', DEVTYPE='usb_device'):
            vendor = device.get('ID_VENDOR', 'Unknown Vendor')
            product = device.get('ID_MODEL', 'Unknown Device')
            busnum = device.get('BUSNUM', 'N/A')
            devnum = device.get('DEVNUM', 'N/A')

            devices.append({
                "bus": busnum,
                "device": devnum,
                "name": f"{vendor} {product}"
            })
    else:
        pythoncom = None
        try:
            import pythoncom  # type: ignore
            pythoncom.CoInitialize()
        except Exception:
            pythoncom = None

        try:
            c = wmi.WMI()
            for usb in c.Win32_PnPEntity():
                caption = getattr(usb, "Caption", "") or ""
                if "USB" in caption:
                    devices.append({
                        "bus": "N/A",
                        "device": usb.DeviceID,
                        "name": caption
                    })
        except Exception:
            return []
        finally:
            if pythoncom is not None:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

    return devices

def get_processes():
    processes = []
    
    for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            processes.append({
                "pid": info["pid"],
                "name": info["name"],
                "cpu_usage": round(info["cpu_percent"], 2),
                "ram_usage": round(info["memory_percent"], 2)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Спочатку сортуємо за CPU, якщо рівне – сортуємо за RAM
    return sorted(processes, key=lambda x: (x["cpu_usage"], x["ram_usage"]), reverse=True)

def scan_bluetooth_devices():
    #try:
        #nearby_devices = bluetooth.discover_devices(duration=5, lookup_names=True)
        #return nearby_devices if nearby_devices else []
    #except Exception as e:
    #    return str(e)
    return []

@app.route('/get_dashboard_data')
@login_required
def get_dashboard_data():
    cpu_info = get_cpu_info()
    disk_info = get_disk_info()
    ram_info = get_ram_info()
    network_info = get_network_info()
    arp_table = get_arp_table()

    return jsonify({
        'cpu_info': cpu_info,
        'disk_info': disk_info,
        'ram_info': ram_info,
        'network_info': network_info,
        'arp_table': arp_table
    })

@app.route('/lan')
@login_required
def lan():
    network_info = get_network_info()
    arp_table = get_arp_table()
    network_connections = get_network_connections()
    summarize_connections = get_summarize_connections()
    return render_template('lan.html', network_info=network_info, 
                           arp_table=arp_table, network_connections=network_connections,
                           summarize_connections=summarize_connections)

@app.route('/web-connections')
@login_required
def web_connections():
    inbound_connections, outbound_connections = get_web_connections()
    return render_template(
        'web_connections.html',
        inbound_connections=inbound_connections,
        outbound_connections=outbound_connections,
        inbound_total=len(inbound_connections),
        outbound_total=len(outbound_connections),
    )

@app.route('/', methods=['GET'])
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()

            if row and check_password_hash(row[0], password):
                session['username'] = username
                return redirect(url_for('dashboard'))
        
    return render_template('login.html')

@app.route('/user/list')
@admin_required
def user_list():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users")
        users = cursor.fetchall()

    return render_template('user_list.html', users=users)

@app.route('/ip/list')
@admin_required
def ip_list():
    # Кількість елементів на сторінці
    per_page = 15
    
    # Отримуємо поточну сторінку з параметрів запиту, якщо вона є
    page = request.args.get('page', 1, type=int)

    # Обчислюємо зсув для запиту
    offset = (page - 1) * per_page

    with sqlite3.connect(DATABASE_NET) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Загальний запит для отримання кількості IP-адрес
        cursor.execute("SELECT COUNT(*) FROM ip")
        total_ips = cursor.fetchone()[0]
        
        # Запит для отримання IP-адрес на поточній сторінці
        cursor.execute("SELECT * FROM ip LIMIT ? OFFSET ?", (per_page, offset))
        ips = [dict(row) for row in cursor.fetchall()]

    # Обчислюємо загальну кількість сторінок
    total_pages = ceil(total_ips / per_page)

    return render_template('ip_list.html', ips=ips, page=page, total_pages=total_pages)

def is_valid_ip(ip):
    """Перевіряє, чи є рядок коректною IP-адресою (IPv4)."""
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split('.'))

def is_valid_mac(mac):
    """Перевіряє, чи є рядок коректною MAC-адресою."""
    pattern = r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$"
    return bool(re.match(pattern, mac))

@app.route('/ip/add', methods=['GET', 'POST'])
@admin_required
def ip_add():
    if request.method == 'POST':
        new_ip = request.form['ip']
        new_mac = request.form['mac']

        if not is_valid_ip(new_ip):
            flash('Invalid IP address format.', 'danger')
            return redirect(url_for('ip_add'))

        if not is_valid_mac(new_mac):
            flash('Invalid MAC address format.', 'danger')
            return redirect(url_for('ip_add'))
        
        # Додавання нового користувача в базу даних
        with sqlite3.connect(DATABASE_NET) as conn:
            conn.execute('INSERT INTO ip (ip, mac) VALUES (?, ?)', 
                         (new_ip, new_mac))
            conn.commit()

        flash(f'IP {new_ip} added successfully!', 'success')
        return redirect(url_for('ip_list'))

    return render_template('ip_edit.html')
@app.route('/ip/edit/<id>', methods=['GET', 'POST'])
@admin_required
def ip_edit(id):
    with sqlite3.connect(DATABASE_NET) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ip WHERE id = ?", (id,))
        ip = cursor.fetchone()

        if request.method == 'POST':
            new_ip = request.form.get('ip', '').strip()
            new_mac = request.form.get('mac', '').strip()

            if not is_valid_ip(new_ip):
                flash('Invalid IP address format.', 'danger')
                return render_template('ip_edit.html', ip=ip)

            if not is_valid_mac(new_mac):
                flash('Invalid MAC address format.', 'danger')
                return render_template('ip_edit.html', ip=ip)

            cursor.execute('''
                UPDATE ip
                SET ip = ?, mac = ?, updated_at = datetime('now')
                WHERE id = ?
            ''', (new_ip, new_mac, id))
            conn.commit()
            return redirect('/ip/list')

        return render_template('ip_edit.html', ip=ip, request=request)

@app.route('/ip/delete/<id>', methods=['POST'])
@admin_required
def ip_delete(id):
    with sqlite3.connect(DATABASE_NET) as conn:
        conn.execute('DELETE FROM ip WHERE id = ?', (id,))
        conn.commit()

    flash(f'IP deleted successfully!', 'success')
    return redirect(url_for('ip_list'))

@app.route('/user/edit/<username>', methods=['GET', 'POST'])
@admin_required
def edit_user(username):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if request.method == 'POST':
            updated_username = request.form['username']
            change_password = request.form.get('change_password')

            # Якщо обрано змінити пароль
            if change_password:
                new_password = request.form['password']
                confirm_password = request.form['confirm_password']

                if len(updated_username) < 3:
                    flash('Username must be at least 3 characters long.', 'danger')
                    return render_template('edit_user.html', user=user)
                
                # Перевіряємо, чи співпадають паролі
                if new_password != confirm_password:
                    flash("Passwords do not match!", "danger")
                    return render_template('edit_user.html', user=user)
                
                # Хешуємо новий пароль
                hashed_password = generate_password_hash(new_password)
            else:
                # Якщо пароль не змінюється, залишаємо старий хешований пароль
                hashed_password = user[1]  # Візьмемо пароль з БД, який вже хешований

            cursor.execute('''
                UPDATE users
                SET username = ?, password = ?
                WHERE username = ?
            ''', (updated_username, hashed_password, username))
            conn.commit()
            return redirect('/user/list')

        return render_template('edit_user.html', user=user, request=request)
@app.route('/user/add', methods=['GET', 'POST'])
@admin_required
def user_add():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if len(username) < 3:
            flash('Username must be at least 3 characters long.', 'danger')
            return redirect(url_for('user_add'))
        
        # Додавання нового користувача в базу даних
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', 
                         (username, generate_password_hash(password)))
            conn.commit()

        flash('User added successfully!', 'success')
        return redirect(url_for('user_list'))

    return render_template('user_add.html')

@app.route('/user/delete/<username>', methods=['POST'])
@admin_required
def delete_user(username):
    if is_admin_user(username):
        flash('Cannot delete an admin user.', 'danger')
        return redirect(url_for('user_list'))

    with sqlite3.connect(DATABASE) as conn:
        conn.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()

    flash(f'User {username} deleted successfully!', 'success')
    return redirect(url_for('user_list'))  # Переходимо до списку користувачів

@app.route('/dashboard')
@login_required
def dashboard():
    disk_info = get_disk_info()
    cpu_info = get_cpu_info()
    ram_info = get_ram_info()
    network_info = get_network_info()
    arp_table = get_arp_table()
    processes = get_processes()
    usb_devices = get_usb_devices()
    firewalls = firewall.check_firewall()
    per_page = 15
    page = request.args.get('process_page', 1, type=int)
    total_processes = len(processes)
    total_pages = max(1, ceil(total_processes / per_page))
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    paginated_processes = processes[start:start + per_page]
    
    return render_template('dashboard.html', username=session['username'], 
                           cpu_info=cpu_info, disk_info=disk_info, 
                           ram_info=ram_info, network_info=network_info, 
                           arp_table=arp_table, processes=paginated_processes,
                           usb_devices=usb_devices, firewalls=firewalls,
                           process_page=page, process_total_pages=total_pages,
                           process_total=total_processes, process_per_page=per_page)

def get_project_path():
    return os.path.dirname(os.path.abspath(__file__))

# Функція для додавання репозиторію до safe.directory, якщо його ще немає
def add_safe_directory(project_path):
    try:
        # Перевіряємо, чи вже є цей каталог в safe.directory
        result = subprocess.run(['git', 'config', '--global', '--get', 'safe.directory'], capture_output=True, text=True)
        safe_directories = result.stdout.splitlines()

        # Якщо каталогу ще немає в safe.directory, додаємо його
        if project_path not in safe_directories:
            subprocess.run(['git', 'config', '--global', '--add', 'safe.directory', project_path], check=True)
    except subprocess.CalledProcessError as e:
        raise Exception(f"Помилка при перевірці safe.directory: {e.stderr}")

UPDATE_LOCK_DIR = "/tmp/noc_update.lockdir"
UPDATE_LOG_FILE = "/tmp/noc_update.log"


def _release_update_lock():
    try:
        os.rmdir(UPDATE_LOCK_DIR)
    except OSError:
        pass


def _launch_update_worker(project_path):
    script = """#!/bin/sh
set -eu
lock_dir="{lock_dir}"
project_path="{project_path}"
log_file="{log_file}"
trap 'rmdir "$lock_dir"' EXIT INT TERM
{{
    echo "[$(date -Iseconds)] Starting project update"
    cd "$project_path"
    git -c safe.directory="$project_path" fetch --prune origin
    git -c safe.directory="$project_path" reset --hard origin/master
    systemctl restart noc.service
    echo "[$(date -Iseconds)] Project update finished"
}} >> "$log_file" 2>&1
""".format(
        lock_dir=UPDATE_LOCK_DIR,
        project_path=project_path,
        log_file=UPDATE_LOG_FILE,
    )
    subprocess.Popen(['/bin/sh', '-c', script], start_new_session=True)

SSH_AUTH_LOG_PATTERNS = ["/var/log/secure*", "/var/log/auth.log*"]
SSH_AUTH_FAIL_PATTERN = re.compile(r'(?:Failed password for(?: invalid user)?|Invalid user) (?P<login>\S+) from (?P<ip>\S+)')


def _read_failed_ssh_auth_entries(limit=250):
    entries = []
    current_year = datetime.now().year
    paths = []

    for pattern in SSH_AUTH_LOG_PATTERNS:
        paths.extend(glob.glob(pattern))

    for path in sorted({p for p in paths if os.path.isfile(p)}, key=os.path.getmtime):
        opener = gzip.open if path.endswith('.gz') else open
        try:
            with opener(path, 'rt', encoding='utf-8', errors='ignore') as handle:
                for line in handle:
                    if 'Failed password' not in line and 'Invalid user' not in line:
                        continue
                    match = SSH_AUTH_FAIL_PATTERN.search(line)
                    if not match:
                        continue
                    try:
                        dt = datetime.strptime(line[:15], '%b %d %H:%M:%S').replace(year=current_year)
                    except ValueError:
                        continue
                    entries.append({
                        'date': dt.strftime('%Y-%m-%d %H:%M:%S'),
                        'ip': match.group('ip'),
                        'login': match.group('login'),
                        '_sort': dt.timestamp(),
                    })
        except OSError:
            continue

    entries.sort(key=lambda item: item['_sort'], reverse=True)
    for item in entries:
        item.pop('_sort', None)
    return entries[:limit]


def _filter_failed_ssh_auth_entries(limit=250, ip_filter="", login_filter=""):
    entries = _read_failed_ssh_auth_entries(limit=limit)

    if ip_filter:
        needle = ip_filter.casefold()
        entries = [entry for entry in entries if needle in entry['ip'].casefold()]
    if login_filter:
        needle = login_filter.casefold()
        entries = [entry for entry in entries if needle in entry['login'].casefold()]

    return entries


@app.route('/tool/fail-ssh-auth')
@login_required
def fail_ssh_auth():
    ip_filter = (request.args.get('ip') or '').strip()
    login_filter = (request.args.get('login') or '').strip()
    entries = _filter_failed_ssh_auth_entries(limit=2000, ip_filter=ip_filter, login_filter=login_filter)

    per_page = 25
    page = request.args.get('page', 1, type=int)
    total_entries = len(entries)
    total_pages = max(1, ceil(total_entries / per_page))
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    paginated_entries = entries[start:start + per_page]

    return render_template(
        'fail_ssh_auth.html',
        entries=paginated_entries,
        ip_filter=ip_filter,
        login_filter=login_filter,
        page=page,
        total_pages=total_pages,
        total_entries=total_entries,
        per_page=per_page,
    )


@app.route('/tool/fail-ssh-auth/export')
@login_required
def fail_ssh_auth_export():
    ip_filter = (request.args.get('ip') or '').strip()
    login_filter = (request.args.get('login') or '').strip()
    entries = _filter_failed_ssh_auth_entries(limit=5000, ip_filter=ip_filter, login_filter=login_filter)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(['date', 'ip', 'login'])
    for row in entries:
        writer.writerow([row['date'], row['ip'], row['login']])

    response = Response(buffer.getvalue(), mimetype='text/csv; charset=utf-8')
    response.headers['Content-Disposition'] = 'attachment; filename=fail_ssh_auth.csv'
    return response


DHCP_LEASE_FILE = "/var/lib/dhcpd/dhcpd.leases"
DHCP_HOSTNAME_PATTERNS = [
    re.compile(r'client-hostname "([^"]+)"'),
    re.compile(r'set host-name = "([^"]+)"'),
    re.compile(r'set ddns-hostname = "([^"]+)"'),
]
DHCP_TIMESTAMP_RE = re.compile(r'^(starts|ends|cltt|tstp)\s+\d+\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2});$')


def _format_dhcp_timestamp(value):
    if not value:
        return ""
    try:
        return datetime.strptime(value, '%Y/%m/%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return value


def _parse_dhcp_timestamp(value):
    if not value:
        return 0
    try:
        return datetime.strptime(value, '%Y/%m/%d %H:%M:%S').timestamp()
    except ValueError:
        return 0


def _read_dhcp_leases():
    active = []
    history = []
    if not os.path.exists(DHCP_LEASE_FILE):
        return active, history

    current = None
    with open(DHCP_LEASE_FILE, 'r', encoding='utf-8', errors='ignore') as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith('#') or line.startswith('authoring-byte-order'):
                continue

            if line.startswith('lease ') and line.endswith('{'):
                current = {
                    'ip': line.split()[1],
                    'state': '',
                    'mac': '',
                    'hostname': '',
                    'starts': '',
                    'ends': '',
                    'cltt': '',
                    'tstp': '',
                }
                continue

            if line == '}':
                if current:
                    date_source = current['cltt'] or current['starts'] or current['ends'] or current['tstp'] or ''
                    row = {
                        'ip': current['ip'],
                        'mac': current['mac'] or 'Unknown',
                        'hostname': current['hostname'] or 'Unknown',
                        'starts': _format_dhcp_timestamp(current['starts']),
                        'ends': _format_dhcp_timestamp(current['ends']),
                        'date': _format_dhcp_timestamp(date_source),
                        '_sort': _parse_dhcp_timestamp(date_source),
                    }
                    history.append(row)
                    if current['state'] == 'active':
                        active.append(row.copy())
                current = None
                continue

            if current is None:
                continue

            if line.startswith('binding state '):
                current['state'] = line.split()[2].rstrip(';')
                continue

            if line.startswith('hardware ethernet '):
                current['mac'] = line.split()[2].rstrip(';')
                continue

            match = DHCP_TIMESTAMP_RE.match(line)
            if match:
                current[match.group(1)] = match.group(2)
                continue

            for hostname_pattern in DHCP_HOSTNAME_PATTERNS:
                hostname_match = hostname_pattern.search(line)
                if hostname_match:
                    current['hostname'] = hostname_match.group(1)
                    break

    history.sort(key=lambda item: item['_sort'], reverse=True)
    active.sort(key=lambda item: item['_sort'], reverse=True)

    dedup_active = []
    seen_ips = set()
    for item in active:
        if item['ip'] in seen_ips:
            continue
        seen_ips.add(item['ip'])
        dedup_active.append(item)

    for item in history:
        item.pop('_sort', None)
    for item in dedup_active:
        item.pop('_sort', None)

    return dedup_active, history


@app.route('/dhcp')
@login_required
def dhcp():
    active_leases, history_leases = _read_dhcp_leases()
    per_page = 25
    page = request.args.get('page', 1, type=int)
    total_history = len(history_leases)
    total_pages = max(1, ceil(total_history / per_page))
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    paginated_history = history_leases[start:start + per_page]

    return render_template(
        'dhcp.html',
        active_leases=active_leases,
        history_leases=paginated_history,
        active_total=len(active_leases),
        total_history=total_history,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
    )


@app.route('/dhcp/kick', methods=['POST'])
@admin_required
def dhcp_kick():
    ip_address = (request.form.get('ip') or '').strip()
    if not ip_address:
        flash('Missing DHCP lease IP.', 'danger')
        return redirect(url_for('dhcp'))

    lease_path = Path(DHCP_LEASE_FILE)
    if not lease_path.exists():
        flash('DHCP lease file not found.', 'danger')
        return redirect(url_for('dhcp'))

    lines = lease_path.read_text(encoding='utf-8', errors='ignore').splitlines(True)
    blocks = []
    current = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('lease ') and stripped.endswith('{'):
            current = {'start': index, 'ip': stripped.split()[1], 'state_idx': None, 'state': None}
            continue
        if current is not None:
            if stripped.startswith('binding state '):
                current['state_idx'] = index
                current['state'] = stripped.split()[2].rstrip(';')
            if stripped == '}':
                current['end'] = index
                blocks.append(current)
                current = None

    target = None
    for block in reversed(blocks):
        if block.get('ip') == ip_address and block.get('state') == 'active' and block.get('state_idx') is not None:
            target = block
            break

    if target is None:
        flash(f'Active DHCP lease for {ip_address} was not found.', 'warning')
        return redirect(url_for('dhcp'))

    old_mode = lease_path.stat().st_mode
    tmp_path = lease_path.with_name(lease_path.name + '.tmp')
    lines[target['state_idx']] = lines[target['state_idx']].replace('binding state active;', 'binding state free;')
    tmp_path.write_text(''.join(lines), encoding='utf-8')
    try:
        os.chmod(tmp_path, old_mode & 0o777)
    except OSError:
        pass

    try:
        shutil.copystat(lease_path, tmp_path)
    except OSError:
        pass

    os.replace(tmp_path, lease_path)
    subprocess.run(['systemctl', 'restart', 'dhcpd.service'], check=True)
    flash(f'DHCP lease {ip_address} was kicked.', 'success')
    return redirect(url_for('dhcp'))


@app.route('/firewall')
@login_required
def firewall_page():
    if firewall.get_firewall_type() != 'iptables':
        flash('iptables firewall is not detected on this host.', 'warning')
        return redirect(url_for('lan'))

    firewall_tables = firewall.get_iptables_tables()
    total_rules = sum(len(chain['rules']) for table in firewall_tables for chain in table['chains'])
    total_chains = sum(len(table['chains']) for table in firewall_tables)

    return render_template(
        'firewall.html',
        firewall_tables=firewall_tables,
        total_rules=total_rules,
        total_chains=total_chains,
        firewall_type=firewall.get_firewall_type(),
    )


@app.route('/firewall/export')
@login_required
def firewall_export():
    if firewall.get_firewall_type() != 'iptables':
        flash('iptables firewall is not detected on this host.', 'warning')
        return redirect(url_for('lan'))

    export_script = firewall.get_iptables_command_script()
    filename = f'iptables-firewall-rules-{datetime.now().strftime("%Y%m%d-%H%M%S")}.sh'
    return Response(
        export_script,
        mimetype='text/x-sh',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
        },
    )


@app.route("/logs")
@login_required
def logs():
    logs = _read_recent_access_log_entries(limit=2000)

    # ?????????? ?????, ??? ??????? ?????? ???? ???????
    logs.reverse()

    # ----------------- ????????? URL -----------------
    url_counter = Counter()
    for l in logs:
        req = l.get("request", "")
        url_counter[req] += 1

    # ----------------- ????????? IP -----------------
    ip_counter = Counter()
    for l in logs:
        ip = l.get("remote_addr", "")
        ip_counter[ip] += 1

    # ----------------- ????????? User-Agent -----------------
    ua_counter = Counter()
    for l in logs:
        ua = l.get("http_user_agent", "")
        ua_counter[ua] += 1

    # ----------------- ??????? -----------------
    errors = []
    for l in logs:
        try:
            status = int(l.get("status", 0))
        except ValueError:
            continue
        if status >= 400:
            errors.append({
                "time": l.get("time_local"),
                "status": status,
                "request": l.get("request"),
                "ip": l.get("remote_addr"),
            })

    return render_template(
        "nginx/logs.html",
        logs=logs,
        urls=url_counter.most_common(),
        ips=ip_counter.most_common(),
        user_agents=ua_counter.most_common(),
        errors=errors
    )

@app.route('/update_project', methods=['POST'])
@admin_required
def update_project():
    try:
        project_path = get_project_path()
        add_safe_directory(project_path)

        try:
            os.mkdir(UPDATE_LOCK_DIR)
        except FileExistsError:
            return jsonify({'message': 'Update already in progress'}), 409

        try:
            _launch_update_worker(project_path)
        except Exception:
            _release_update_lock()
            raise

        return jsonify({'message': 'Update queued. NOC will restart after git pull.'}), 202

    except Exception as e:
        return jsonify({'message': f'Unexpected error: {str(e)}'}), 500

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('_csrf_token', None)
    return redirect(url_for('login'))

@app.route('/reset', methods=['POST'])
@admin_required
def reset_users():
    with sqlite3.connect(DATABASE) as conn:
        admin_usernames = tuple(sorted(get_admin_usernames()))
        placeholders = ", ".join("?" for _ in admin_usernames)
        conn.execute(
            f'DELETE FROM users WHERE username NOT IN ({placeholders})',
            admin_usernames,
        )
        conn.commit()

        add_default_users()
    return redirect(url_for('dashboard'))

def update_arp_table():
    arp_entries = get_arp_table()
    with sqlite3.connect(DATABASE_NET) as conn:
        cursor = conn.cursor()
        # Спочатку всім ставимо offline
        cursor.execute("UPDATE ip SET status = 'offline'")
        # Потім оновлюємо або вставляємо активні (online)
        for entry in arp_entries:
            # Оновити, якщо існує
            cursor.execute('''
                UPDATE ip
                SET mac = ?, status = 'online', updated_at = datetime('now')
                WHERE ip = ?
            ''', (entry["mac"], entry["ip"]))

            # Вставити, якщо ще нема такого IP
            cursor.execute('''
                INSERT INTO ip (ip, mac, status, updated_at)
                SELECT ?, ?, 'online', datetime('now')
                WHERE NOT EXISTS (
                    SELECT 1 FROM ip WHERE ip = ?
                )
            ''', (entry["ip"], entry["mac"], entry["ip"]))

        conn.commit()

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(update_arp_table, 'interval', minutes=15)
    scheduler.start()
    # Додаємо шедулер до окремого потоку
    def scheduler_thread():
        while True:
            time.sleep(1)  # Не даємо потоку зупинитись
    thread = threading.Thread(target=scheduler_thread)
    thread.start()

if __name__ == '__main__':
    init_db()
    add_default_users()
    #if not os.environ.get("WERKZEUG_RUN_MAIN"):
    start_scheduler()
    app.run(
        host='0.0.0.0',
        port=1983,
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
