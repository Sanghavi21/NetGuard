import os

class Config:
    # Secret key for session management (logging in/out securely)
    SECRET_KEY = 'super-secret-netguard-key'
    # Path to the SQLite database file
    DB_PATH = os.path.join(os.path.dirname(__file__), 'database', 'netguard.db')