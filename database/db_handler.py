import sqlite3
from werkzeug.security import generate_password_hash
from config import Config

def get_db_connection():
    # The live monitor writes every second; wait briefly for other requests and
    # use WAL so reads such as alert pages don't block that collector.
    conn = sqlite3.connect(Config.DB_PATH, timeout=30)
    conn.execute('PRAGMA busy_timeout = 30000')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('PRAGMA journal_mode = WAL')
    conn.execute('PRAGMA synchronous = NORMAL')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            email TEXT,
            job_title TEXT,
            department TEXT,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    user_columns = {row['name'] for row in cursor.execute('PRAGMA table_info(users)').fetchall()}
    if 'display_name' not in user_columns:
        cursor.execute('ALTER TABLE users ADD COLUMN display_name TEXT')
    if 'email' not in user_columns:
        cursor.execute('ALTER TABLE users ADD COLUMN email TEXT')
    if 'job_title' not in user_columns:
        cursor.execute('ALTER TABLE users ADD COLUMN job_title TEXT')
    if 'department' not in user_columns:
        cursor.execute('ALTER TABLE users ADD COLUMN department TEXT')
    if 'phone' not in user_columns:
        cursor.execute('ALTER TABLE users ADD COLUMN phone TEXT')
    
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
            status TEXT DEFAULT 'DETECTED',
            source_kind TEXT NOT NULL DEFAULT 'LEGACY'
        )
    ''')

    event_columns = {row['name'] for row in cursor.execute('PRAGMA table_info(security_events)').fetchall()}
    if 'source_kind' not in event_columns:
        cursor.execute("ALTER TABLE security_events ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'LEGACY'")
    
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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incident_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT NOT NULL,
            status TEXT NOT NULL,
            note TEXT,
            FOREIGN KEY (event_id) REFERENCES security_events(id) ON DELETE CASCADE
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS data_usage_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            app_name TEXT NOT NULL,
            usage_mb REAL NOT NULL CHECK(usage_mb > 0),
            usage_date TEXT NOT NULL,
            network_name TEXT NOT NULL DEFAULT 'Wi-Fi',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS data_usage_settings (
            username TEXT PRIMARY KEY,
            monthly_quota_gb REAL NOT NULL DEFAULT 10
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_data_usage_user_date ON data_usage_entries(username, usage_date)')

    # Automatically sampled network-interface counters. These are system-wide
    # adapter totals, not per-application attribution.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_interface_state (
            interface_name TEXT PRIMARY KEY,
            bytes_sent INTEGER NOT NULL,
            bytes_recv INTEGER NOT NULL,
            sampled_at TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_usage_daily (
            usage_date TEXT NOT NULL,
            interface_name TEXT NOT NULL,
            upload_bytes INTEGER NOT NULL DEFAULT 0,
            download_bytes INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (usage_date, interface_name)
        )
    ''')
    
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        hashed_pw = generate_password_hash('admin123')
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ('admin', hashed_pw))

    conn.commit()
    conn.close()
