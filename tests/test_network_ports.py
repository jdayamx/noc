import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch
from flask import Flask
from libs import network


class PortScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.temp.name, 'network.db')
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.executescript('CREATE TABLE ip(id INTEGER PRIMARY KEY, ip TEXT UNIQUE); CREATE TABLE service(ip_id INTEGER, number INTEGER, updated_at TEXT);')
        self.app = Flask(__name__)
        self.app.secret_key = 'test'
        self.app.register_blueprint(network.network_bp)
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session['username'] = 'admin'
        self.db_patch = patch.object(network, 'DATABASE_NET', self.db)
        self.db_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def scan(self, xml, returncode=0):
        with patch.object(network.subprocess, 'run') as run:
            run.return_value.stdout = xml
            run.return_value.returncode = returncode
            return self.client.post('/network/ports/10.1.1.99')

    def report(self, ports):
        return '<nmaprun><host><address addr="10.1.1.99"/><ports>' + ports + '</ports></host><runstats><finished exit="success"/></runstats></nmaprun>'

    def saved(self):
        with closing(sqlite3.connect(self.db)) as conn:
            return conn.execute('SELECT number FROM service ORDER BY number').fetchall()

    def test_new_ip_exact_open_tcp_and_replacement(self):
        response = self.scan(self.report('<port protocol="tcp" portid="80"><state state="open"/></port><port protocol="tcp" portid="443"><state state="open|filtered"/></port><port protocol="udp" portid="53"><state state="open"/></port>'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['ports'], [80])
        self.assertEqual(self.saved(), [(80,)])
        self.assertEqual(self.scan(self.report('')).json['ports'], [])
        self.assertEqual(self.saved(), [])

    def test_failures_preserve_results(self):
        self.scan(self.report('<port protocol="tcp" portid="80"><state state="open"/></port>'))
        for xml, code in [('broken', 0), ('', 1), ('<nmaprun><host timedout="true"><address addr="10.1.1.99"/></host><runstats><finished exit="success"/></runstats></nmaprun>', 0)]:
            self.assertEqual(self.scan(xml, code).status_code, 502)
            self.assertEqual(self.saved(), [(80,)])
        for error, status in [(FileNotFoundError(), 503), (subprocess.TimeoutExpired('nmap', 75), 504)]:
            with patch.object(network.subprocess, 'run', side_effect=error):
                self.assertEqual(self.client.post('/network/ports/10.1.1.99').status_code, status)
            self.assertEqual(self.saved(), [(80,)])

    def test_description_migrates_persists_and_preserves_ports(self):
        text = 'Сервер <b>резервний</b> "офіс"\nДругий рядок'
        response = self.client.post('/network/description/10.1.1.99', json={'description': text})
        self.assertEqual(response.status_code, 200)
        self.scan(self.report('<port protocol="tcp" portid="80"><state state="open"/></port>'))
        with closing(sqlite3.connect(self.db)) as conn, conn:
            self.assertEqual(conn.execute('SELECT description FROM ip').fetchone()[0], text)
            conn.executescript("ALTER TABLE ip ADD COLUMN mac TEXT; ALTER TABLE ip ADD COLUMN status TEXT; CREATE TABLE network(id INTEGER, ip_min TEXT, ip_max TEXT); INSERT INTO network VALUES(1,'10.1.1.99','10.1.1.99');")
        from jinja2 import ChoiceLoader, DictLoader, FileSystemLoader
        self.app.jinja_loader = ChoiceLoader([DictLoader({'main.html': '{% block content %}{% endblock %}{% block scripts %}{% endblock %}'}), FileSystemLoader('html')])
        with patch.object(network, 'get_arp_table', return_value=[]):
            page = self.client.get('/network/1')
        self.assertEqual(page.status_code, 200)
        self.assertIn('Ports: 80', page.text)
        self.assertIn('&lt;b&gt;', page.text)
        self.assertIn('data-bs-html="false"', page.text)
        self.assertIn('Другий рядок', page.text)
        self.assertEqual(self.client.post('/network/description/10.1.1.99', json={'description': ''}).status_code, 200)
        self.assertEqual(self.saved(), [(80,)])
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('SELECT description FROM ip').fetchone()[0], '')

    def test_description_validation(self):
        for payload in [{'description': None}, {'description': 'x' * 4001}, [], {}]:
            self.assertEqual(self.client.post('/network/description/10.1.1.99', json=payload).status_code, 400)
        self.assertEqual(self.client.post('/network/description/invalid', json={'description': 'test'}).status_code, 400)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM ip').fetchone()[0], 0)

    def test_invalid_target_and_get_do_not_scan(self):
        with patch.object(network.subprocess, 'run') as run:
            self.assertEqual(self.client.post('/network/ports/--help').status_code, 400)
            self.assertEqual(self.client.get('/network/ports/10.1.1.99').status_code, 405)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
