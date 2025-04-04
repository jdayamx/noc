import psutil
import subprocess
from flask import  jsonify, flash, Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import sqlite3
import os
import time
import threading
import platform
if platform.system() == "Linux":
    import pyudev
else:
    import wmi
import re
from math import ceil

previous_traffic = {}

app = Flask(__name__, template_folder='html')
app.secret_key = 'your_secret_key'

DB_FOLDER = 'db'
DATABASE = os.path.join(DB_FOLDER, 'users.db')
DATABASE_NET = os.path.join(DB_FOLDER, 'network.db')

# Create the db directory if it doesn't exist
if not os.path.exists(DB_FOLDER):
    os.makedirs(DB_FOLDER)

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

def add_default_users():
    users = [
        ('admin', generate_password_hash('admin')),
        ('user', generate_password_hash('user'))
    ]
    with sqlite3.connect(DATABASE) as conn:
        conn.executemany('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', users)
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
    # Отримуємо основну інформацію про пам'ять
    mem = psutil.virtual_memory()
    
    # Використовуємо dmidecode для детальної інформації про модулі пам'яті
    result = subprocess.run(['sudo', 'dmidecode', '--type', '17'], stdout=subprocess.PIPE)
    output = result.stdout.decode()

    ram_info = []
    current_ram = {}
    
    for line in output.splitlines():
        # Шукаємо розмір планки
        if "Size" in line:
            if "No Module Installed" not in line:
                size = line.split(":")[1].strip()
                current_ram['size'] = size
        # Шукаємо швидкість планки
        elif "Speed" in line:
            speed = line.split(":")[1].strip()
            current_ram['speed'] = speed
        # Коли знаходимо нову планку пам'яті
        elif "Locator" in line:
            if current_ram:
                ram_info.append(current_ram)  # додаємо попередню планку
            current_ram = {}  # очищуємо поточну інформацію для нової планки

    if current_ram:
        ram_info.append(current_ram)  # додаємо останню планку, якщо є

    # Повертати загальну інформацію про пам'ять разом з деталями про планки
    return {
        "total": mem.total,
        "available": mem.available,
        "used": mem.used,
        "percent": mem.percent,
        "ram_modules": ram_info  # додано деталі про планки пам'яті
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
        print(f"Перевіряємо розділ: {partition.device}, mountpoint: {partition.mountpoint}")
        # Перевіряємо, чи правильний формат шляху
        
        if partition.mountpoint and partition.mountpoint != '':  # Перевірка на наявність шляху
            try:
                # Отримуємо інформацію про використання кожного розділу
                usage = psutil.disk_usage(partition.mountpoint)
                mountpoint = partition.mountpoint
                if platform.system() == "Linux":
                    mountpoint = partition.mountpoint.replace('\\', '/')
                # Додаємо інформацію в список
                disk_info.append({
                    "device": partition.device,
                    "mountpoint": mountpoint,
                    "fstype": partition.fstype,
                    "size": usage.total,
                    "free": usage.free,
                    "used": usage.used,
                    "percent": usage.percent
                })
            except Exception as e:
                print(f"Не вдалося отримати інформацію для {partition.device}: {str(e)}")
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
        c = wmi.WMI()
        for usb in c.Win32_PnPEntity():
            if "USB" in usb.Caption:
                devices.append({
                    "bus": "N/A",
                    "device": usb.DeviceID,
                    "name": usb.Caption
                })

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
    try:
        nearby_devices = bluetooth.discover_devices(duration=5, lookup_names=True)
        return nearby_devices if nearby_devices else []
    except Exception as e:
        return str(e)

@app.route('/get_dashboard_data')
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
def lan():
    network_info = get_network_info()
    arp_table = get_arp_table()
    network_connections = get_network_connections()
    return render_template('lan.html', network_info=network_info, 
                           arp_table=arp_table, network_connections=network_connections)

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
def user_list():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users")
        users = cursor.fetchall()

    return render_template('user_list.html', users=users)

@app.route('/ip/list')
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
def ip_add():
    if request.method == 'POST':
        new_ip = request.form['username']
        new_mac = request.form['password']

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

@app.route('/ip/delete/<id>', methods=['GET'])
def ip_delete(id):
    with sqlite3.connect(DATABASE_NET) as conn:
        conn.execute('DELETE FROM ip WHERE id = ?', (id,))
        conn.commit()

    flash(f'IP deleted successfully!', 'success')
    return redirect(url_for('ip_list'))  # Переходимо до списку користувачів

@app.route('/user/edit/<username>', methods=['GET', 'POST'])
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

@app.route('/user/delete/<username>', methods=['GET'])
def delete_user(username):
    if username == 'admin':
        flash('Cannot delete the admin user.', 'danger')
        return redirect(url_for('user_list'))

    with sqlite3.connect(DATABASE) as conn:
        conn.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()

    flash(f'User {username} deleted successfully!', 'success')
    return redirect(url_for('user_list'))  # Переходимо до списку користувачів

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    disk_info = get_disk_info()
    cpu_info = get_cpu_info()
    ram_info = get_ram_info()
    network_info = get_network_info()
    arp_table = get_arp_table()
    processes = get_processes()
    usb_devices = get_usb_devices()
    
    return render_template('dashboard.html', username=session['username'], 
                           cpu_info=cpu_info, disk_info=disk_info, 
                           ram_info=ram_info, network_info=network_info, 
                           arp_table=arp_table, processes=processes,
                           usb_devices=usb_devices)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/reset', methods=['POST'])
def reset_users():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('DELETE FROM users WHERE username NOT IN ("admin", "user")')
        conn.commit()

        add_default_users()
    return redirect(url_for('dashboard'))

def update_arp_table():
    arp_entries = get_arp_table()
    with sqlite3.connect(DATABASE_NET) as conn:
        for entry in arp_entries:
            conn.execute('''INSERT OR REPLACE INTO ip (ip, mac, status, updated_at) 
                            VALUES (?, ?, ?, datetime('now'))''',
                         (entry["ip"], entry["mac"], 'Active'))
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
    if not os.environ.get("WERKZEUG_RUN_MAIN"):
        start_scheduler()
    app.run(host='0.0.0.0', port=1983, debug=True)
