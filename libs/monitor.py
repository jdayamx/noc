"""Bounded ICMP monitoring; ARP is identity evidence, not an offline test."""
import logging
import os
import sqlite3
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from ipaddress import ip_address
from libs.network import ensure_presence_column

log = logging.getLogger(__name__)
_cursors = {}


def ensure_monitor_columns(conn):
    ensure_presence_column(conn)
    columns = {row[1] for row in conn.execute('PRAGMA table_info(ip)')}
    for name, definition in [('checked_at', 'REAL NOT NULL DEFAULT 0'),
                             ('ping_failures', 'INTEGER NOT NULL DEFAULT 0')]:
        if name not in columns:
            conn.execute(f'ALTER TABLE ip ADD COLUMN {name} {definition}')


def probe(ip):
    args = ['ping', '-n', '1', '-w', '1000', ip] if os.name == 'nt' else ['ping', '-n', '-c', '1', '-W', '1', ip]
    try:
        result = subprocess.run(args, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=3)
    except subprocess.TimeoutExpired:
        return False
    if result.returncode not in (0, 1):
        raise RuntimeError('Ping execution failed')
    return result.returncode == 0


def monitor_tick(database, arp_reader):
    now = time.time()
    with closing(sqlite3.connect(database, timeout=10)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        ensure_monitor_columns(conn)
        ranges = []
        for key, low, high in conn.execute('SELECT id, ip_min, ip_max FROM network'):
            try:
                low, high = ip_address(low), ip_address(high)
                if low.version == high.version == 4 and low <= high:
                    ranges.append((key, int(low), int(high)))
            except ValueError:
                continue
        def in_scope(ip):
            try:
                number = int(ip_address(ip))
                return any(low <= number <= high for _, low, high in ranges)
            except ValueError:
                return False
        # Preserve MAC identities without treating a cached neighbour as live.
        for entry in arp_reader():
            ip, mac = entry.get('ip', ''), entry.get('mac', '')
            if in_scope(ip) and mac and mac != 'N/A':
                conn.execute('INSERT OR IGNORE INTO ip (ip) VALUES (?)', (ip,))
                conn.execute('UPDATE ip SET mac=?, ever_seen=1 WHERE ip=?', (mac, ip))
        rows = {row[0]: row[1:] for row in conn.execute('SELECT ip, ever_seen, checked_at FROM ip')}
        known = sorted((ip for ip, (seen, checked) in rows.items()
                        if seen and checked <= now - 180 and in_scope(ip)),
                       key=lambda ip: rows[ip][1])[:24]
        unknown = []
        # Round-robin address discovery; never materialize an entire subnet.
        for step in range(256):
            if not ranges or len(unknown) >= 8:
                break
            key, low, high = ranges[step % len(ranges)]
            number = _cursors.get(key, low)
            if not low <= number <= high:
                number = low
            _cursors[key] = low if number == high else number + 1
            ip = str(ip_address(number))
            seen, checked = rows.get(ip, (0, 0))
            if not seen and checked <= now - 900 and ip not in unknown and number % 256 not in (0, 255):
                unknown.append(ip)
    # No database transaction stays open while waiting for network replies.
    targets = known + unknown
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [(ip, pool.submit(probe, ip)) for ip in targets]
        results = []
        for ip, future in futures:
            try:
                results.append((ip, future.result()))
            except Exception:
                log.exception('Could not probe %s; preserving previous status', ip)
    with closing(sqlite3.connect(database, timeout=10)) as conn, conn:
        for ip, online in results:
            conn.execute('INSERT OR IGNORE INTO ip (ip) VALUES (?)', (ip,))
            # A manual check completed after this tick began takes precedence.
            conn.execute("""UPDATE ip SET checked_at=?, updated_at=datetime('now'),
                ping_failures=CASE WHEN ? THEN 0 ELSE ping_failures+1 END,
                status=CASE WHEN ? THEN 'online' WHEN ping_failures>=2 OR ever_seen=0
                            THEN 'offline' ELSE status END,
                ever_seen=CASE WHEN ? THEN 1 ELSE ever_seen END
                WHERE ip=? AND checked_at<=?""", (now, online, online, online, ip, now))
