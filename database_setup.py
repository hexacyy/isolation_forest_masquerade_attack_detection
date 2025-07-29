import sqlite3
import os
from werkzeug.security import generate_password_hash
from config import DB_FILE

def init_user_database():
    """Initialize the user database with default admin user"""
    if not os.path.exists(DB_FILE):
        print(f"Creating user database: {DB_FILE}")
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # Create users table
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default admin user
        admin_password = "admin123456789!"  # Change this in production
        c.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash(admin_password), "admin")
        )
        
        # Create default viewer user for testing
        viewer_password = "viewer123456789!"  # Change this in production
        c.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",  
            ("viewer", generate_password_hash(viewer_password), "viewer")
        )
        
        conn.commit()
        conn.close()
        
        print("✅ User database initialized successfully!")
        print("Default users created:")
        print("  - Admin: username=admin, password=admin123456789!")
        print("  - Viewer: username=viewer, password=viewer123456789!")
        print("⚠️  Please change these passwords immediately in production!")
    else:
        print(f"User database already exists: {DB_FILE}")

def init_prediction_database():
    """Initialize the prediction logs database"""
    from utils import get_monthly_db_path
    
    db_path = get_monthly_db_path()
    
    if not os.path.exists(db_path):
        print(f"Creating prediction database: {db_path}")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        c.execute('''
            CREATE TABLE IF NOT EXISTS prediction_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                log_month TEXT NOT NULL,
                anomaly INTEGER NOT NULL,
                explanation TEXT,
                network_packet_size INTEGER,
                login_attempts INTEGER,
                session_duration REAL,
                ip_reputation_score REAL,
                failed_logins INTEGER,
                unusual_time_access INTEGER,
                protocol_type_ICMP INTEGER,
                protocol_type_TCP INTEGER,
                protocol_type_UDP INTEGER,
                encryption_used_AES INTEGER,
                encryption_used_DES INTEGER,
                browser_type_Chrome INTEGER,
                browser_type_Edge INTEGER,
                browser_type_Firefox INTEGER,
                browser_type_Safari INTEGER,
                browser_type_Unknown INTEGER,
                risk_score REAL,
                anomaly_score REAL,
                profile_used TEXT,
                user_role TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better performance
        c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON prediction_logs(timestamp)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_anomaly ON prediction_logs(anomaly)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_log_month ON prediction_logs(log_month)')
        
        conn.commit()
        conn.close()
        
        print("✅ Prediction database initialized successfully!")
    else:
        print(f"Prediction database already exists: {db_path}")

def create_required_directories():
    """Create required directories if they don't exist"""
    directories = ['backup', 'archives', 'static/css', 'static/js', 'static/images', 'templates', 'test']
    
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

if __name__ == '__main__':
    print("Initializing database setup...")
    
    # Create required directories
    create_required_directories()
    
    # Initialize databases
    init_user_database()
    init_prediction_database()
    
    print("\n✅ Database setup completed successfully!")
    print("\nTo run the application:")
    print("1. Ensure all required files are in place (models, templates, etc.)")
    print("2. Update webhook.env with your configuration")
    print("3. Run: python app.py")