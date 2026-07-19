import sqlite3
import json
from datetime import datetime
import os

DB_PATH = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_name TEXT DEFAULT 'Unnamed Scan',
            target_ip TEXT,
            target_port INTEGER,
            target_url TEXT NOT NULL,
            status TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            total_vulns INTEGER DEFAULT 0,
            progress INTEGER DEFAULT 0
        )
    ''')
    
    # Try to alter the table for existing databases
    try:
        cursor.execute("ALTER TABLE scans ADD COLUMN scan_name TEXT DEFAULT 'Unnamed Scan'")
        cursor.execute("ALTER TABLE scans ADD COLUMN target_ip TEXT")
        cursor.execute("ALTER TABLE scans ADD COLUMN target_port INTEGER")
    except sqlite3.OperationalError:
        pass # Columns already exist
    
    # Create findings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            vulnerability TEXT,
            severity TEXT,
            url TEXT,
            parameter TEXT,
            payload TEXT,
            description TEXT,
            impact TEXT,
            reproduction TEXT,
            remediation TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
    ''')
    
    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            timestamp TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
    ''')
    
    # Create open_ports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS open_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            port INTEGER,
            service TEXT,
            version TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

def create_scan(scan_name, target_ip, target_port, target_url):
    conn = get_db_connection()
    cursor = conn.cursor()
    start_time = datetime.now().isoformat()
    cursor.execute(
        'INSERT INTO scans (scan_name, target_ip, target_port, target_url, status, start_time) VALUES (?, ?, ?, ?, ?, ?)',
        (scan_name, target_ip, target_port, target_url, 'RUNNING', start_time)
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def update_scan_status(scan_id, status, progress=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if progress is not None:
        cursor.execute(
            'UPDATE scans SET status = ?, progress = ? WHERE id = ?',
            (status, progress, scan_id)
        )
    else:
        cursor.execute(
            'UPDATE scans SET status = ? WHERE id = ?',
            (status, scan_id)
        )
    
    if status in ('COMPLETED', 'FAILED', 'ERROR'):
        end_time = datetime.now().isoformat()
        cursor.execute(
            'UPDATE scans SET end_time = ? WHERE id = ?',
            (end_time, scan_id)
        )
    conn.commit()
    conn.close()

def add_finding(scan_id, finding_dict):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO findings (
            scan_id, vulnerability, severity, url, parameter, payload, 
            description, impact, reproduction, remediation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_id,
        finding_dict.get('vulnerability'),
        finding_dict.get('severity'),
        finding_dict.get('url'),
        finding_dict.get('parameter'),
        finding_dict.get('payload'),
        finding_dict.get('description'),
        finding_dict.get('impact'),
        finding_dict.get('reproduction'),
        finding_dict.get('remediation')
    ))
    
    # Update total vulns logic
    cursor.execute('UPDATE scans SET total_vulns = total_vulns + 1 WHERE id = ?', (scan_id,))
    
    conn.commit()
    conn.close()

def add_log(scan_id, level, message):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO logs (scan_id, timestamp, level, message) VALUES (?, ?, ?, ?)',
        (scan_id, datetime.now().isoformat(), level, message)
    )
    conn.commit()
    conn.close()

def get_logs():
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM logs ORDER BY id DESC LIMIT 500').fetchall()
    conn.close()
    return [dict(l) for l in logs]

def get_all_scans():
    conn = get_db_connection()
    scans = conn.execute('SELECT * FROM scans ORDER BY id DESC').fetchall()
    conn.close()
    return [dict(s) for s in scans]

def add_open_port(scan_id, port, service, version):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO open_ports (scan_id, port, service, version) VALUES (?, ?, ?, ?)',
        (scan_id, port, service, version)
    )
    conn.commit()
    conn.close()

def get_open_ports(scan_id):
    conn = get_db_connection()
    ports = conn.execute('SELECT * FROM open_ports WHERE scan_id = ? ORDER BY port ASC', (scan_id,)).fetchall()
    conn.close()
    return [dict(p) for p in ports]

def get_scan(scan_id):
    conn = get_db_connection()
    scan = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    return dict(scan) if scan else None

def get_findings(scan_id):
    conn = get_db_connection()
    findings = conn.execute('SELECT * FROM findings WHERE scan_id = ?', (scan_id,)).fetchall()
    conn.close()
    return [dict(f) for f in findings]

if __name__ == '__main__':
    init_db()
    print("Database initialized.")
