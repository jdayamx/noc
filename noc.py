import psutil
import subprocess
from flask import Flask, render_template, request, redirect, url_for, session
from flask import jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import sqlite3
import os
import time

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

def get_cpu_info():
    cpu_info = {
        "physical_cores": psutil.cpu_count(logical=False),
        "total_cores": psutil.cpu_count(logical=True),
        "cpu_usage": psutil.cpu_percent(interval=0),  # Використовує останнє значення без очікування
        "per_core_usage": psutil.cpu_percent(interval=0, percpu=True)
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
            utilization = 0
            bytes_sent = 0
            bytes_received = 0

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
        usage = psutil.disk_usage(partition.mountpoint)
        disk_info.append({
            "device": partition.device,

            "mountpoint": partition.mountpoint,
            "fstype": partition.fstype,
            "size": usage.total,
            "free": usage.free,
            "used": usage.used,
            "percent": usage.percent
        })
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
    return render_template('dashboard.html', username=session['username'], 
                           cpu_info=cpu_info, disk_info=disk_info, 
                           ram_info=ram_info, network_info=network_info, 
                           arp_table=arp_table, processes=processes)

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
            conn.execute('''INSERT OR REPLACE INTO ip (ip, mac, interface, status, updated_at) 
                            VALUES (?, ?, ?, ?, datetime('now'))''',
                         (entry["ip"], entry["mac"], entry["interface"], 'Active'))
        conn.commit()

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(update_arp_table, 'interval', minutes=15)
    scheduler.start()

if __name__ == '__main__':
    init_db()
    add_default_users()
    app.run(host='0.0.0.0', port=1983, debug=True)
