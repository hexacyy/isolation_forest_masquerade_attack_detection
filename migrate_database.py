# migrate_database.py
"""
Database Migration Script for Behavioral Analysis Support
Run this script to add behavioral analysis tracking capabilities to your existing database
"""

import sqlite3
import os
import json
from datetime import datetime
import glob

def find_database_files():
    """Find all database files in the current directory"""
    db_files = []
    
    # Common database file patterns
    patterns = [
        "*.db",
        "users_v2.db",
        "prediction_logs*.db",
        "database.db"
    ]
    
    for pattern in patterns:
        db_files.extend(glob.glob(pattern))
    
    # Remove duplicates
    db_files = list(set(db_files))
    
    print(f"Found database files: {db_files}")
    return db_files

def backup_database(db_path):
    """Create a backup of the database before migration"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{db_path}.backup_{timestamp}"
    
    try:
        # Simple file copy for SQLite
        import shutil
        shutil.copy2(db_path, backup_path)
        print(f"✅ Backup created: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"⚠️ Backup failed for {db_path}: {e}")
        return None

def check_existing_columns(cursor, table_name):
    """Check what columns already exist in a table"""
    try:
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [row[1] for row in cursor.fetchall()]
        return columns
    except:
        return []

def migrate_predictions_table(cursor):
    """Add behavioral analysis columns to predictions table"""
    print("🔧 Migrating predictions table...")
    
    # Check existing columns
    existing_columns = check_existing_columns(cursor, 'predictions')
    print(f"   Existing columns: {existing_columns}")
    
    # Add new behavioral analysis columns
    new_columns = [
        ('behavioral_risk', 'TEXT DEFAULT "UNKNOWN"'),
        ('profile_used', 'TEXT DEFAULT "Unknown"'),
        ('deviation_score', 'REAL DEFAULT 0.0'),
        ('individual_deviations', 'TEXT DEFAULT "{}"'),
        ('composite_confidence', 'REAL DEFAULT 0.0'),
        ('detection_method_details', 'TEXT DEFAULT ""')
    ]
    
    for column_name, column_def in new_columns:
        if column_name not in existing_columns:
            try:
                cursor.execute(f"ALTER TABLE predictions ADD COLUMN {column_name} {column_def}")
                print(f"   ✅ Added column: {column_name}")
            except Exception as e:
                print(f"   ❌ Failed to add {column_name}: {e}")
        else:
            print(f"   ⏩ Column {column_name} already exists")

def create_behavioral_profiles_table(cursor):
    """Create table for storing user behavioral profiles"""
    print("🔧 Creating behavioral_profiles table...")
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            user_role TEXT NOT NULL,
            profile_type TEXT NOT NULL, -- 'learned', 'baseline', 'combined'
            
            -- Statistical parameters for each feature
            network_packet_size_mean REAL DEFAULT 0,
            network_packet_size_std REAL DEFAULT 1,
            session_duration_mean REAL DEFAULT 0,
            session_duration_std REAL DEFAULT 1,
            login_attempts_mean REAL DEFAULT 1,
            login_attempts_std REAL DEFAULT 0.5,
            failed_logins_mean REAL DEFAULT 0,
            failed_logins_std REAL DEFAULT 0.5,
            ip_reputation_score_mean REAL DEFAULT 0.1,
            ip_reputation_score_std REAL DEFAULT 0.1,
            unusual_time_access_mean REAL DEFAULT 0.1,
            unusual_time_access_std REAL DEFAULT 0.3,
            
            -- Metadata
            sample_count INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            
            UNIQUE(username, profile_type)
        )
    """)
    print("   ✅ behavioral_profiles table created")

def create_behavioral_alerts_table(cursor):
    """Create table for tracking high-risk behavioral anomalies"""
    print("🔧 Creating behavioral_alerts table...")
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            user_role TEXT NOT NULL,
            
            -- Alert details
            risk_level TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW
            deviation_score REAL NOT NULL,
            profile_used TEXT NOT NULL,
            
            -- Session context
            source_ip TEXT,
            session_duration INTEGER,
            network_packet_size INTEGER,
            failed_logins INTEGER,
            
            -- Detection details
            explanation TEXT,
            individual_deviations TEXT, -- JSON of feature deviations
            
            -- Status tracking
            status TEXT DEFAULT 'NEW', -- NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE
            assigned_to TEXT,
            resolution_notes TEXT,
            
            -- Timestamps
            alert_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_timestamp TIMESTAMP
        )
    """)
    print("   ✅ behavioral_alerts table created")

def create_indexes(cursor):
    """Create indexes for better performance"""
    print("🔧 Creating database indexes...")
    
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_predictions_behavioral ON predictions(behavioral_risk, deviation_score)",
        "CREATE INDEX IF NOT EXISTS idx_predictions_profile ON predictions(profile_used)",
        "CREATE INDEX IF NOT EXISTS idx_behavioral_alerts_username ON behavioral_alerts(username)",
        "CREATE INDEX IF NOT EXISTS idx_behavioral_alerts_risk_level ON behavioral_alerts(risk_level)",
        "CREATE INDEX IF NOT EXISTS idx_behavioral_alerts_timestamp ON behavioral_alerts(alert_timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_behavioral_alerts_status ON behavioral_alerts(status)",
        "CREATE INDEX IF NOT EXISTS idx_behavioral_profiles_user ON behavioral_profiles(username, user_role)"
    ]
    
    for index_sql in indexes:
        try:
            cursor.execute(index_sql)
            index_name = index_sql.split('IF NOT EXISTS ')[1].split(' ON')[0]
            print(f"   ✅ Created index: {index_name}")
        except Exception as e:
            print(f"   ❌ Index creation failed: {e}")

def create_dashboard_views(cursor):
    """Create views for behavioral analysis dashboard"""
    print("🔧 Creating dashboard views...")
    
    # Behavioral analysis summary view
    cursor.execute("""
        CREATE VIEW IF NOT EXISTS behavioral_analysis_summary AS
        SELECT 
            DATE(alert_timestamp) as alert_date,
            risk_level,
            COUNT(*) as alert_count,
            COUNT(DISTINCT username) as affected_users,
            AVG(deviation_score) as avg_deviation,
            COUNT(CASE WHEN status = 'RESOLVED' THEN 1 END) as resolved_count,
            COUNT(CASE WHEN status = 'FALSE_POSITIVE' THEN 1 END) as false_positive_count
        FROM behavioral_alerts 
        GROUP BY DATE(alert_timestamp), risk_level
        ORDER BY alert_date DESC, risk_level DESC
    """)
    print("   ✅ Created behavioral_analysis_summary view")
    
    # User behavioral trends view
    cursor.execute("""
        CREATE VIEW IF NOT EXISTS user_behavioral_trends AS
        SELECT 
            p.profile_used,
            COUNT(*) as total_sessions,
            AVG(p.deviation_score) as avg_deviation,
            MAX(p.deviation_score) as max_deviation,
            COUNT(CASE WHEN p.behavioral_risk IN ('HIGH', 'CRITICAL') THEN 1 END) as high_risk_sessions,
            COUNT(CASE WHEN p.prediction = 1 THEN 1 END) as flagged_sessions,
            MAX(p.timestamp) as last_activity
        FROM predictions p
        WHERE p.deviation_score > 0 AND p.profile_used != 'Unknown'
        GROUP BY p.profile_used
        HAVING COUNT(*) >= 5  -- Profiles with at least 5 sessions
        ORDER BY avg_deviation DESC
    """)
    print("   ✅ Created user_behavioral_trends view")

def insert_baseline_profiles(cursor):
    """Insert sample behavioral profiles based on baseline data"""
    print("🔧 Inserting baseline profiles...")
    
    baseline_profiles = [
        # Admin baseline profile
        ('BASELINE_ADMIN', 'Admin', 'baseline', 1000, 100, 1500, 200, 2, 1, 0.5, 0.5, 0.2, 0.1, 0.05, 0.1, 1000),
        # Viewer baseline profile  
        ('BASELINE_VIEWER', 'Viewer', 'baseline', 200, 50, 300, 100, 1, 0.5, 0.3, 0.3, 0.1, 0.05, 0.2, 0.3, 1000),
        # Staff baseline profile
        ('BASELINE_STAFF', 'Staff', 'baseline', 600, 80, 800, 150, 4, 1, 2, 1, 0.4, 0.15, 0.1, 0.2, 1000)
    ]
    
    for profile in baseline_profiles:
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO behavioral_profiles 
                (username, user_role, profile_type, network_packet_size_mean, network_packet_size_std,
                 session_duration_mean, session_duration_std, login_attempts_mean, login_attempts_std,
                 failed_logins_mean, failed_logins_std, ip_reputation_score_mean, ip_reputation_score_std,
                 unusual_time_access_mean, unusual_time_access_std, sample_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, profile)
            print(f"   ✅ Inserted baseline profile: {profile[0]}")
        except Exception as e:
            print(f"   ❌ Failed to insert {profile[0]}: {e}")

def migrate_single_database(db_path):
    """Migrate a single database file"""
    print(f"\n🔄 Migrating database: {db_path}")
    
    if not os.path.exists(db_path):
        print(f"   ❌ Database file not found: {db_path}")
        return False
    
    # Create backup
    backup_path = backup_database(db_path)
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Check if this is a predictions database
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            if 'predictions' in tables:
                print("   📊 Found predictions table - applying behavioral analysis migration")
                migrate_predictions_table(cursor)
            
            # Create new behavioral analysis tables
            create_behavioral_profiles_table(cursor)
            create_behavioral_alerts_table(cursor)
            create_indexes(cursor)
            create_dashboard_views(cursor)
            insert_baseline_profiles(cursor)
            
            conn.commit()
            print(f"   ✅ Successfully migrated: {db_path}")
            return True
            
    except Exception as e:
        print(f"   ❌ Migration failed for {db_path}: {e}")
        if backup_path and os.path.exists(backup_path):
            print(f"   🔄 Backup available at: {backup_path}")
        return False

def verify_migration(db_path):
    """Verify that migration was successful"""
    print(f"\n🔍 Verifying migration for: {db_path}")
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Check tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            expected_tables = ['behavioral_profiles', 'behavioral_alerts']
            for table in expected_tables:
                if table in tables:
                    print(f"   ✅ Table {table} exists")
                    
                    # Check row count
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0]
                    print(f"      Records: {count}")
                else:
                    print(f"   ❌ Table {table} missing")
            
            # Check if predictions table has new columns (if it exists)
            if 'predictions' in tables:
                cursor.execute("PRAGMA table_info(predictions)")
                columns = [row[1] for row in cursor.fetchall()]
                
                expected_columns = ['behavioral_risk', 'profile_used', 'deviation_score']
                for col in expected_columns:
                    if col in columns:
                        print(f"   ✅ Column predictions.{col} exists")
                    else:
                        print(f"   ❌ Column predictions.{col} missing")
            
            # Check views exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='view'")
            views = [row[0] for row in cursor.fetchall()]
            
            expected_views = ['behavioral_analysis_summary', 'user_behavioral_trends']
            for view in expected_views:
                if view in views:
                    print(f"   ✅ View {view} exists")
                else:
                    print(f"   ❌ View {view} missing")
                    
    except Exception as e:
        print(f"   ❌ Verification failed: {e}")

def main():
    """Run the complete database migration"""
    print("🚀 Starting Behavioral Analysis Database Migration")
    print("=" * 60)
    
    # Find all database files
    db_files = find_database_files()
    
    if not db_files:
        print("❌ No database files found!")
        print("Make sure you're running this script in the directory containing your .db files")
        return
    
    # Migrate each database
    successful_migrations = 0
    for db_file in db_files:
        if migrate_single_database(db_file):
            successful_migrations += 1
            verify_migration(db_file)
    
    print("\n" + "=" * 60)
    print(f"🎉 Migration Complete!")
    print(f"   Successfully migrated: {successful_migrations}/{len(db_files)} databases")
    
    if successful_migrations > 0:
        print("\n✅ Your databases now support:")
        print("   • Behavioral risk level tracking")
        print("   • User profile matching")
        print("   • Deviation score analytics")
        print("   • Individual feature deviation storage")
        print("   • Behavioral alerts management")
        print("   • Dashboard views for analysis")
        
        print("\n🔧 Next steps:")
        print("   1. Restart your application")
        print("   2. Test predictions with behavioral analysis")
        print("   3. Monitor /behavioral-profiles endpoint")
        print("   4. Check behavioral alerts in database")
    else:
        print("\n❌ Migration failed - check error messages above")

if __name__ == "__main__":
    main()