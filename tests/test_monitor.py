import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch
from libs import monitor

class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.temp.name, 'network.db')
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.executescript("CREATE TABLE network(id INTEGER,ip_min TEXT,ip_max TEXT); INSERT INTO network VALUES(1,'10.0.0.1','10.0.0.254'); CREATE TABLE ip(id INTEGER PRIMARY KEY,ip TEXT UNIQUE,mac TEXT,status TEXT,updated_at TEXT); CREATE TABLE service(ip_id INTEGER,number INTEGER); INSERT INTO ip(ip,status) VALUES('10.0.0.1','online');")
        monitor._cursors.clear()
    def tearDown(self):
        self.temp.cleanup()
    def tick(self, now, result=False):
        with patch.object(monitor.time, 'time', return_value=now), patch.object(monitor,'probe',return_value=result) as probe:
            monitor.monitor_tick(self.db, lambda: [])
            return probe.call_count
    def state(self):
        with closing(sqlite3.connect(self.db)) as conn:
            return conn.execute("SELECT status,ever_seen,ping_failures FROM ip WHERE ip='10.0.0.1'").fetchone()
    def test_failure_threshold_and_recovery(self):
        for index in range(3):
            self.tick(10000 + index*181)
            self.assertEqual(self.state(), ('offline' if index==2 else 'online',1,index+1))
        self.tick(11000,True)
        self.assertEqual(self.state(),('online',1,0))
    def test_bounded_work_and_unknowns_stay_unseen(self):
        self.assertLessEqual(self.tick(10000),32)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM ip WHERE ip!='10.0.0.1' AND ever_seen!=0").fetchone()[0],0)
        with patch.object(monitor,'probe',side_effect=FileNotFoundError()), self.assertLogs('libs.monitor',level='ERROR'):
            monitor.monitor_tick(self.db,lambda: [])
        self.assertEqual(self.state(),('online',1,1))
    def test_absent_arp_does_not_mark_offline_or_ignore_interval(self):
        self.tick(10000,True)
        with patch.object(monitor.time,'time',return_value=10030), patch.object(monitor,'probe',return_value=False) as probe:
            monitor.monitor_tick(self.db,lambda: [])
            self.assertNotIn(('10.0.0.1',), [call.args for call in probe.call_args_list])
        self.assertEqual(self.state(),('online',1,0))

if __name__ == '__main__': unittest.main()
