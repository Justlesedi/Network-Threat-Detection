import sqlite3
from datetime import datetime
from typing import List, Optional

class Device:
    def __init__(self, device_id: int, mac_address: str, ip_address: str, hostname: str, first_seen: str, last_seen: str, is_suspicious: bool=False):
        self.device_id = device_id
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.hostname = hostname
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.is_suspicious = is_suspicious

class Alert:
    def __init__(self, id: int,alert_type: str, device_id: int, timestamp: str, severity: str, message: str):
        self.id = id
        self.alert_type = alert_type
        self.device_id = device_id
        self.timestamp = timestamp
        self.severity = severity
        self.message = message

class Database:
    def __init__(self, db_path: str="krypt.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.create_tables()

    def connect(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                device_id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT UNIQUE,
                ip_address TEXT,
                hostname TEXT,
                first_seen TEXT,
                last_seen TEXT,
                is_suspicious INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                device_id INTEGER,
                timestamp TEXT,
                severity TEXT,
                message TEXT,
                FOREIGN KEY (device_id) REFERENCES devices (device_id)
            )
        ''')
        self.conn.commit()

    def add_device(self, mac_address: str, ip_address: str, hostname: str = None) -> Optional[Device]:
        cursor = self.connection.cursor()
        try:
            cursor.execute("""
                INSERT INTO devices (mac_address, ip_address, hostname)
                VALUES (?, ?, ?)
            """, (mac_address, ip_address, hostname))
            self.connection.commit()
            device_id = cursor.lastrowid
            return self.get_device_by_id(device_id)
        except sqlite3.IntegrityError:
            return None

    def get_device_by_mac(self, mac_address: str) -> Optional[Device]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac_address,))
        row = cursor.fetchone()
        return self._row_to_device(row) if row else None

    def get_device_by_id(self, device_id: int) -> Optional[Device]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        row = cursor.fetchone()
        return self._row_to_device(row) if row else None

    def get_all_devices(self) -> List[Device]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
        rows = cursor.fetchall()
        return [self._row_to_device(row) for row in rows]

    def update_device_last_seen(self, mac_address: str):
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE devices SET last_seen = CURRENT_TIMESTAMP
            WHERE mac_address = ?
        """, (mac_address,))
        self.conn.commit()

    def mark_device_suspicious(self, device_id: int):
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE devices SET is_suspicious = 1
            WHERE id = ?
        """, (device_id,))
        self.conn.commit()

    def add_alert(self, device_id: int, alert_type: str, severity: str, message: str) -> Alert:
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (device_id, alert_type, severity, message)
            VALUES (?, ?, ?, ?)
        """, (device_id, alert_type, severity, message))
        self.connection.commit()
        alert_id = cursor.lastrowid
        return self.get_alert_by_id(alert_id)

    def get_alert_by_id(self, alert_id: int) -> Optional[Alert]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        return self._row_to_alert(row) if row else None

    def get_recent_alerts(self, limit: int = 10) -> List[Alert]:
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [self._row_to_alert(row) for row in rows]

    def get_alerts_by_device(self, device_id: int, limit: int = 10) -> List[Alert]:
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM alerts WHERE device_id = ?
            ORDER BY timestamp DESC LIMIT ?
        """, (device_id, limit))
        rows = cursor.fetchall()
        return [self._row_to_alert(row) for row in rows]

    def _row_to_device(self, row) -> Device:
        return Device(
            id=row["id"],
            mac_address=row["mac_address"],
            ip_address=row["ip_address"],
            hostname=row["hostname"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            is_suspicious=bool(row["is_suspicious"])
        )

    def _row_to_alert(self, row) -> Alert:
        return Alert(
            id=row["id"],
            device_id=row["device_id"],
            alert_type=row["alert_type"],
            severity=row["severity"],
            message=row["message"],
            timestamp=row["timestamp"]
        )

    def close(self):
        if self.conn:
            self.conn.close()


