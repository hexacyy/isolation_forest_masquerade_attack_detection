from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file
from werkzeug.security import generate_password_hash
import pandas as pd
import sqlite3
import os
import csv
from datetime import datetime, timezone, timedelta
from utils import login_required, is_strong_password, get_monthly_db_path
from config import DB_FILE
from routes.dashboard import generate_summary_internal

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/manage_users', methods=['GET', 'POST'])
@login_required(role='admin')
def manage_users():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    if request.method == 'POST':
        # Handle adding user
        new_username = request.form['username']
        new_password = request.form['password']
        new_role = request.form['role']
        try:
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (
                new_username, generate_password_hash(new_password), new_role))
            conn.commit()
            flash(f"✅ User '{new_username}' added successfully.", "success")
        except sqlite3.IntegrityError:
            flash(f"❌ Username '{new_username}' already exists.", "danger")

    # Always show updated user list
    c.execute("SELECT id, username, role FROM users ORDER BY id ASC")
    users = c.fetchall()
    conn.close()

    return render_template("manage_users_v2.html", users=users, active_page='manage_users')

@admin_bp.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def delete_user(user_id):
    print(f"[ROUTE] DELETE user {user_id}")
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        flash(f"✅ User ID {user_id} deleted successfully.", "info")
    except Exception as e:
        print(f"[ERROR] Failed to delete user: {e}")
        flash("❌ Failed to delete user.", "danger")
    
    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/reset_password/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def reset_password(user_id):
    print(f"[ROUTE] DELETE user {user_id}")
    new_password = request.form['new_password']
    if not new_password or not is_strong_password(new_password):
        flash("❌ Password must be at least 12 characters and include uppercase, lowercase, numbers, and symbols.", "danger")
        return redirect(url_for('admin.manage_users'))
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (
        generate_password_hash(new_password), user_id))
    conn.commit()
    conn.close()
    flash("✅ Password reset successfully.", "info")
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/clear_predictions', methods=['POST'])
@login_required(role='admin')
def clear_predictions():
    try:
        # Use the current month's database
        db_path = get_monthly_db_path()
        print(f"[DEBUG] Clearing data from: {db_path}")

        # Connect to SQLite
        conn = sqlite3.connect(db_path)
        c = conn.cursor()

        # Optional backup
        backup_df = pd.read_sql_query("SELECT * FROM prediction_logs", conn)
        if not backup_df.empty:
            # Create backup folder if it doesn't exist
            backup_folder = "backup"
            if not os.path.exists(backup_folder):
                os.makedirs(backup_folder)
                print(f"[INFO] Created backup folder: {backup_folder}")
            
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"prediction_logs_backup_{timestamp}.csv"
            backup_path = os.path.join(backup_folder, backup_filename)
            
            backup_df.to_csv(backup_path, index=False)
            print(f"[INFO] Backup saved to {backup_path}")

        # Clear the table
        c.execute("DELETE FROM prediction_logs")
        # Optionally drop and recreate the table if you want to reset the structure
        c.execute("DROP TABLE IF EXISTS prediction_logs")
        c.execute("""
            CREATE TABLE prediction_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                log_month TEXT,
                anomaly INTEGER,
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
                user_role TEXT
            )
        """)

        # Reset AUTOINCREMENT counter
        c.execute("DELETE FROM sqlite_sequence WHERE name='prediction_logs'")
        conn.commit()
        conn.close()

        # Regenerate summary to reflect the cleared state
        generate_summary_internal()

        flash("✅ Prediction logs have been cleared and backed up.", "info")
        return redirect(url_for('dashboard.dashboard'))

    except Exception as e:
        print(f"[ERROR] Failed to clear predictions: {str(e)}")
        flash(f"❌ Failed to clear predictions: {str(e)}", "danger")
        return redirect(url_for('dashboard.dashboard'))

@admin_bp.route('/restore_backup', methods=['GET', 'POST'])
@login_required(role='admin')
def restore_backup():
    if request.method == 'POST':
        file = request.files.get('backup_file')
        if not file or not file.filename.endswith('.csv'):
            flash("❌ Invalid file format. Please upload a .csv file.", "danger")
            return redirect(request.url)

        try:
            print(f"[DEBUG] Received backup file: {file.filename}")
            
            # Read CSV with better error handling
            try:
                df = pd.read_csv(file, encoding='utf-8')
            except UnicodeDecodeError:
                file.seek(0)  # Reset file pointer
                df = pd.read_csv(file, encoding='latin-1')
                print("[DEBUG] Used latin-1 encoding")
            
            print(f"[DEBUG] CSV loaded: {len(df)} rows, {len(df.columns)} columns")
            print(f"[DEBUG] Columns in CSV: {df.columns.tolist()}")
            print(f"[DEBUG] First 2 rows:\n{df.head(2).to_string(index=False)}")

            if df.empty:
                flash("⚠️ Uploaded file is empty.", "warning")
                return redirect(request.url)

            # Remove any unnamed columns
            df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
            
            # Add missing explanation column if it doesn't exist
            if 'explanation' not in df.columns:
                df['explanation'] = "Restored from legacy CSV (no explanation)"
                print("[INFO] Added missing explanation column.")

            # Define expected columns in the correct order
            expected_columns = [
                'timestamp', 'anomaly', 'explanation', 'network_packet_size',
                'login_attempts', 'session_duration', 'ip_reputation_score',
                'failed_logins', 'unusual_time_access', 'protocol_type_ICMP',
                'protocol_type_TCP', 'protocol_type_UDP', 'encryption_used_AES',
                'encryption_used_DES', 'browser_type_Chrome', 'browser_type_Edge',
                'browser_type_Firefox', 'browser_type_Safari', 'browser_type_Unknown',
                'risk_score', 'profile_used'
            ]

            # Add any missing columns with default values
            for col in expected_columns:
                if col not in df.columns:
                    if col in ['anomaly', 'network_packet_size', 'login_attempts', 'failed_logins',
                              'unusual_time_access', 'protocol_type_ICMP', 'protocol_type_TCP',
                              'protocol_type_UDP', 'encryption_used_AES', 'encryption_used_DES',
                              'browser_type_Chrome', 'browser_type_Edge', 'browser_type_Firefox',
                              'browser_type_Safari', 'browser_type_Unknown']:
                        df[col] = 0
                    elif col in ['session_duration', 'ip_reputation_score', 'risk_score']:
                        df[col] = 0.0
                    else:
                        df[col] = ""
                    print(f"[INFO] Added missing column '{col}' with default values")

            # Drop the 'id' column if it exists
            if 'id' in df.columns:
                df = df.drop(columns=['id'])
                print("[INFO] Dropped 'id' column - SQLite will auto-increment")

            # Enhanced timestamp parsing
            if 'timestamp' in df.columns:
                print(f"[DEBUG] Original timestamp sample: {df['timestamp'].iloc[0] if len(df) > 0 else 'Empty'}")
                df['timestamp'] = df['timestamp'].astype(str)
                timestamp_formats = [
                    '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S.%f',
                    '%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M:%S', '%d/%m/%Y %H:%M:%S',
                    '%Y/%m/%d %H:%M:%S', '%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y'
                ]
                parsed_timestamps = None
                successful_format = None
                for fmt in timestamp_formats:
                    try:
                        parsed_timestamps = pd.to_datetime(df['timestamp'], format=fmt, errors='raise')
                        successful_format = fmt
                        print(f"[SUCCESS] Timestamps parsed using format: {fmt}")
                        break
                    except (ValueError, TypeError):
                        continue
                if parsed_timestamps is None:
                    try:
                        print("[DEBUG] Trying pandas automatic date parsing...")
                        parsed_timestamps = pd.to_datetime(df['timestamp'], errors='coerce')
                        successful_format = "automatic"
                        print("[SUCCESS] Timestamps parsed using automatic detection")
                    except Exception as e:
                        print(f"[ERROR] All timestamp parsing attempts failed: {e}")
                        parsed_timestamps = pd.to_datetime([datetime.utcnow()] * len(df))
                        print("[WARN] Using current timestamp as fallback for all entries")
                df['timestamp'] = parsed_timestamps
                valid_timestamps = df['timestamp'].notna().sum()
                total_timestamps = len(df)
                print(f"[INFO] Successfully parsed {valid_timestamps}/{total_timestamps} timestamps")
                if valid_timestamps == 0:
                    flash("❌ No valid timestamps found in the backup file.", "danger")
                    return redirect(request.url)
                elif valid_timestamps < total_timestamps:
                    print(f"[WARN] {total_timestamps - valid_timestamps} rows had invalid timestamps")
                    df.loc[df['timestamp'].isna(), 'timestamp'] = datetime.utcnow()
                df['timestamp'] = df['timestamp'].dt.strftime('%Y-%m-%dT%H:%M:%S')

            # Data type conversions
            int_cols = ['anomaly', 'network_packet_size', 'login_attempts', 'failed_logins',
                       'unusual_time_access', 'protocol_type_ICMP', 'protocol_type_TCP',
                       'protocol_type_UDP', 'encryption_used_AES', 'encryption_used_DES',
                       'browser_type_Chrome', 'browser_type_Edge', 'browser_type_Firefox',
                       'browser_type_Safari', 'browser_type_Unknown']
            float_cols = ['session_duration', 'ip_reputation_score', 'risk_score']
            for col in int_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
            for col in float_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0.0)

            # Reindex to ensure correct column order
            df = df.reindex(columns=expected_columns, fill_value=0)

            # Remove duplicates
            before_dedup = len(df)
            df = df.drop_duplicates(subset=['timestamp', 'anomaly', 'network_packet_size', 'ip_reputation_score'], keep='first')
            after_dedup = len(df)
            if before_dedup != after_dedup:
                print(f"[INFO] Removed {before_dedup - after_dedup} duplicate rows")

            print(f"[INFO] Final dataset: {len(df)} rows ready for import")
            print(f"[DEBUG] Final columns: {df.columns.tolist()}")
            print(f"[DEBUG] Sample final row:\n{df.iloc[0].to_dict() if len(df) > 0 else 'Empty'}")

            # Connect to the current month's database
            db_path = get_monthly_db_path()
            print(f"[DEBUG] Using database: {db_path}")

            # Ensure the database and table exist
            with sqlite3.connect(db_path) as conn:
                c = conn.cursor()
                c.execute("""
                    CREATE TABLE IF NOT EXISTS prediction_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        anomaly INTEGER,
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
                        profile_used TEXT
                    )
                """)
                conn.commit()

                # Check current row count
                c.execute("SELECT COUNT(*) FROM prediction_logs")
                rows_before = c.fetchone()[0]
                print(f"[DEBUG] Database rows before import: {rows_before}")

                # Insert data in chunks
                chunk_size = 1000
                total_inserted = 0
                for i in range(0, len(df), chunk_size):
                    chunk = df.iloc[i:i+chunk_size].to_dict(orient='records')
                    c.executemany("""
                        INSERT INTO prediction_logs (timestamp, anomaly, explanation, network_packet_size,
                                                    login_attempts, session_duration, ip_reputation_score,
                                                    failed_logins, unusual_time_access, protocol_type_ICMP,
                                                    protocol_type_TCP, protocol_type_UDP, encryption_used_AES,
                                                    encryption_used_DES, browser_type_Chrome, browser_type_Edge,
                                                    browser_type_Firefox, browser_type_Safari, browser_type_Unknown,
                                                    risk_score, profile_used)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, [tuple(row[col] for col in expected_columns) for row in chunk])
                    conn.commit()
                    total_inserted += len(chunk)
                    print(f"[DEBUG] Inserted chunk {i//chunk_size + 1}: {len(chunk)} rows")

                # Verify final row count
                c.execute("SELECT COUNT(*) FROM prediction_logs")
                rows_after = c.fetchone()[0]
                actually_inserted = rows_after - rows_before
                print(f"[DEBUG] Database rows after import: {rows_after}")
                print(f"[DEBUG] Actually inserted: {actually_inserted} rows")

            if actually_inserted > 0:
                generate_summary_internal()  # Refresh summary
                flash(f"✅ Backup restored successfully! {actually_inserted} records imported.", "success")
                print(f"[INFO] Backup restore completed: {actually_inserted} records")
            else:
                flash("⚠️ No new records were imported. Data may already exist or have issues.", "warning")

        except Exception as e:
            print(f"[ERROR] Restore failed: {e}")
            import traceback
            traceback.print_exc()
            flash(f"❌ Restore failed: {str(e)}", "danger")

        return redirect(url_for('dashboard.dashboard'))

    return render_template("restore_backup.html")

@admin_bp.route('/archive', methods=['POST'])
@login_required(role='admin')
def archive_last_month():
    try:
        # Get current and previous month
        now = datetime.utcnow()
        prev_month = (now.replace(day=1) - timedelta(days=1)).strftime('%Y-%m')

        conn = sqlite3.connect("prediction_logs.db")
        df = pd.read_sql_query("SELECT * FROM prediction_logs WHERE log_month = ?", conn, params=(prev_month,))
        conn.close()

        if df.empty:
            flash(f"No logs found for {prev_month}.", "warning")
            return redirect(url_for('dashboard.report'))

        # Save logs as CSV
        log_path = f"archives/prediction_log_{prev_month}.csv"
        df.to_csv(log_path, index=False)

        # Generate summary
        total = len(df)
        anomalies = df['anomaly'].sum()
        normal = total - anomalies
        anomaly_rate = round((anomalies / total) * 100, 2)

        summary = {
            "total_sessions": total,
            "anomalies_detected": int(anomalies),
            "normal_sessions": int(normal),
            "anomaly_rate_percent": anomaly_rate,
            "first_entry_time": df['timestamp'].min(),
            "last_entry_time": df['timestamp'].max(),
            "archived_at": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }

        with open(f"archives/summary_report_{prev_month}.csv", "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=summary.keys())
            writer.writeheader()
            writer.writerow(summary)

        flash(f"Archived logs for {prev_month} successfully.", "success")
        return redirect(url_for('dashboard.report'))

    except Exception as e:
        flash(f"Archiving failed: {str(e)}", "danger")
        return redirect(url_for('dashboard.report'))