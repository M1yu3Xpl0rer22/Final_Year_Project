import sqlite3
import json
from datetime import datetime
import os

DB_NAME = "scans.db"

def init_db():
    """Initialize the database with the scans table."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            risk_level TEXT,
            zap_results TEXT,
            nmap_results TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_scan(data):
    """Save a scan result to the database."""
    init_db() # Ensure table exists
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Serialize dicts to JSON for storage
    zap_json = json.dumps(data.get('zap', {}))
    nmap_json = json.dumps(data.get('nmap', {}))
    
    c.execute('''
        INSERT INTO scans (url, timestamp, risk_level, zap_results, nmap_results)
        VALUES (?, ?, ?, ?, ?)
    ''', (data['target'], timestamp, data.get('riskLevel', 'Unknown'), zap_json, nmap_json))
    
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id

def get_recent_scans(limit=5):
    """Retrieve recent scans."""
    init_db()
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    
    scans = []
    for row in rows:
        scans.append({
            'id': row['id'],
            'url': row['url'],
            'timestamp': row['timestamp'],
            'risk_level': row['risk_level']
        })
    return scans

def get_next_scan_id():
    """Predicts the next auto-increment ID."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Check if table has data
    try:
        c.execute("SELECT seq FROM sqlite_sequence WHERE name='scans'")
        row = c.fetchone()
        next_id = (row[0] + 1) if row else 1
    except:
        next_id = 1
        
    conn.close()
    return f"{datetime.now().year}_{next_id:03d}"
