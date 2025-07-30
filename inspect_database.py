# inspect_database.py
"""
Database Structure Inspector
Shows current database structure before migration
"""

import sqlite3
import os
import glob

def inspect_database(db_path):
    """Inspect a single database file"""
    print(f"\n📊 Database: {db_path}")
    print("-" * 50)
    
    if not os.path.exists(db_path):
        print("   ❌ File not found")
        return
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            print(f"   Tables found: {len(tables)}")
            
            for table in tables:
                print(f"\n   📋 Table: {table}")
                
                # Get table schema
                cursor.execute(f"PRAGMA table_info({table})")
                columns = cursor.fetchall()
                
                print("      Columns:")
                for col in columns:
                    col_name = col[1]
                    col_type = col[2]
                    not_null = "NOT NULL" if col[3] else ""
                    default = f"DEFAULT {col[4]}" if col[4] else ""
                    print(f"        • {col_name} ({col_type}) {not_null} {default}".strip())
                
                # Get row count
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                print(f"      Records: {count}")
                
                # Show sample data for predictions table
                if table == 'predictions' and count > 0:
                    cursor.execute(f"SELECT * FROM {table} LIMIT 1")
                    sample = cursor.fetchone()
                    if sample:
                        print("      Sample record structure:")
                        for i, col in enumerate(columns):
                            col_name = col[1]
                            value = sample[i] if i < len(sample) else "NULL"
                            print(f"        {col_name}: {value}")
            
            # Get views
            cursor.execute("SELECT name FROM sqlite_master WHERE type='view'")
            views = [row[0] for row in cursor.fetchall()]
            
            if views:
                print(f"\n   Views found: {views}")
            
            # Get indexes
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
            indexes = [row[0] for row in cursor.fetchall()]
            
            if indexes:
                print(f"   Indexes found: {indexes}")
                
    except Exception as e:
        print(f"   ❌ Error inspecting database: {e}")

def main():
    """Inspect all database files"""
    print("🔍 Database Structure Inspector")
    print("=" * 60)
    
    # Find database files
    db_patterns = ["*.db", "users_v2.db", "prediction_logs*.db"]
    db_files = []
    
    for pattern in db_patterns:
        db_files.extend(glob.glob(pattern))
    
    db_files = list(set(db_files))  # Remove duplicates
    
    if not db_files:
        print("❌ No database files found in current directory")
        return
    
    print(f"Found {len(db_files)} database files:")
    for db in db_files:
        print(f"  • {db}")
    
    # Inspect each database
    for db_file in db_files:
        inspect_database(db_file)
    
    print("\n" + "=" * 60)
    print("🔧 Ready for migration!")
    print("Run: python migrate_database.py")

if __name__ == "__main__":
    main()