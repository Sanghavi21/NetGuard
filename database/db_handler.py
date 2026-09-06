import sqlite3
from werkzeug.security import generate_password_hash
from config import Config

def get_db_connection():
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            event_type TEXT,
            severity TEXT,
            description TEXT,
            location TEXT DEFAULT 'Unknown',
            status TEXT DEFAULT 'DETECTED'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blacklisted_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # --- NEW TABLE: ADMIN AUDIT TRAIL ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            action TEXT,
            ip_address TEXT
        )
    ''')
    
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        hashed_pw = generate_password_hash('admin123')
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ('admin', hashed_pw))

    conn.commit()
    conn.close()