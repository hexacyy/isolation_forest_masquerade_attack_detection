from flask import Blueprint, render_template, request, send_file, jsonify
import pandas as pd
import sqlite3
import os
import csv
from datetime import datetime, timezone
from utils import login_required, get_monthly_db_path
import numpy as np

dashboard_bp = Blueprint('dashboard', __name__)

def clean_dataframe_for_json(df):
    """Clean DataFrame to make it JSON serializable"""
    if df is None or df.empty:
        return []
    
    df_clean = df.copy()
    
    # Handle datetime columns and NaT values
    for col in df_clean.columns:
        if df_clean[col].dtype == 'datetime64[ns]':
            # Convert datetime to string, handling NaT values
            df_clean[col] = df_clean[col].dt.strftime('%Y-%m-%d %H:%M:%S').where(
                pd.notna(df_clean[col]), None
            )
    
    # Replace NaN with None (which becomes null in JSON)
    df_clean = df_clean.where(pd.notna(df_clean), None)
    
    # Convert to records (list of dictionaries)
    return df_clean.to_dict(orient='records')

def generate_summary_internal(selected_month=None):
    try:
        if selected_month:
            db_path = f"prediction_logs_{selected_month.replace('-', '')}.db"
        else:
            db_path = get_monthly_db_path()
        print(f"[DEBUG] Using database: {db_path}")

        df = pd.DataFrame()
        if os.path.exists(db_path):
            with sqlite3.connect(db_path) as conn:
                df = pd.read_sql_query("SELECT * FROM prediction_logs", conn)
                print(f"[DEBUG] Total rows in {db_path}: {len(df)}")

        available_months = sorted([f.replace('prediction_logs_', '').replace('.db', '-01')[:-3] 
                                 for f in os.listdir('.') 
                                 if f.startswith('prediction_logs_') and f.endswith('.db')], reverse=True)
        print(f"[DEBUG] Available months: {available_months}")

        if df.empty:
            print("[INFO] No data in selected database to summarize.")
            return {
                'total': 0,
                'anomalies': 0,
                'normal': 0,
                'anomaly_rate': 0.0,
                'last_updated': 'N/A',
                'df_tail': [],
                'timestamps': [],
                'anomaly_flags': [],
                'available_months': available_months
            }

        # Ensure timestamp is in datetime format
        if 'timestamp' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            print("[DEBUG] Converted timestamp to datetime")

        total = len(df)
        anomalies = df['anomaly'].sum() if not df.empty else 0
        normal = total - anomalies if total > 0 else 0
        anomaly_rate = (anomalies / total * 100) if total > 0 else 0.0

        # Handle last_updated properly
        last_updated = 'N/A'
        if not df.empty and 'timestamp' in df.columns:
            max_timestamp = df['timestamp'].max()
            if pd.notna(max_timestamp):
                last_updated = max_timestamp.strftime('%Y-%m-%d %H:%M:%S')
        print(f"[DEBUG] Last updated: {last_updated}")

        # Clean df_tail for JSON serialization
        df_tail_clean = clean_dataframe_for_json(df)

        # Handle timestamps and anomaly flags
        timestamps = []
        anomaly_flags = []
        if not df.empty and 'timestamp' in df.columns:
            # Convert timestamps to strings, handling NaT values
            timestamps = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S').where(
                pd.notna(df['timestamp']), 'N/A'
            ).tolist()
            anomaly_flags = df['anomaly'].tolist()

        return {
            'total': total,
            'anomalies': int(anomalies),
            'normal': normal,
            'anomaly_rate': round(anomaly_rate, 2),
            'last_updated': last_updated,
            'df_tail': df_tail_clean,
            'timestamps': timestamps,
            'anomaly_flags': anomaly_flags,
            'available_months': available_months
        }

    except Exception as e:
        print(f"[ERROR] Failed to generate summary: {e}")
        import traceback
        traceback.print_exc()
        return {
            'total': 0,
            'anomalies': 0,
            'normal': 0,
            'anomaly_rate': 0.0,
            'last_updated': 'N/A',
            'df_tail': [],
            'timestamps': [],
            'anomaly_flags': [],
            'available_months': []
        }

@dashboard_bp.route('/dashboard')
@login_required()
def dashboard():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    summary = generate_summary_internal()
    
    # Handle date filtering
    if start_date or end_date:
        try:
            with sqlite3.connect(get_monthly_db_path()) as conn:
                df = pd.read_sql_query("SELECT * FROM prediction_logs", conn)
                
                if not df.empty:
                    # Ensure timestamp is datetime
                    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                    
                    # Apply filters
                    if start_date:
                        df = df[df['timestamp'] >= start_date]
                    if end_date:
                        df = df[df['timestamp'] <= end_date]
                    
                    # Update summary with filtered data
                    summary['df_tail'] = clean_dataframe_for_json(df)
                    summary['total'] = len(df)
                    summary['anomalies'] = int(df['anomaly'].sum()) if not df.empty else 0
                    summary['normal'] = summary['total'] - summary['anomalies']
                    summary['anomaly_rate'] = (summary['anomalies'] / summary['total'] * 100) if summary['total'] > 0 else 0
                    
                    # Handle last_updated for filtered data
                    if not df.empty and 'timestamp' in df.columns:
                        max_timestamp = df['timestamp'].max()
                        summary['last_updated'] = max_timestamp.strftime('%Y-%m-%d %H:%M:%S') if pd.notna(max_timestamp) else 'N/A'
                    else:
                        summary['last_updated'] = 'N/A'
                    
                    # Handle timestamps and anomaly flags for filtered data
                    if not df.empty:
                        summary['timestamps'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S').where(
                            pd.notna(df['timestamp']), 'N/A'
                        ).tolist()
                        summary['anomaly_flags'] = df['anomaly'].tolist()
                    else:
                        summary['timestamps'] = []
                        summary['anomaly_flags'] = []
        except Exception as e:
            print(f"[ERROR] Error filtering data: {e}")
            # Keep original summary data if filtering fails
    
    return render_template("dashboard_v5.html", summary=summary, start_date=start_date, end_date=end_date, active_page='dashboard')

@dashboard_bp.route('/report')
@login_required()
def report():
    selected_month = request.args.get('month')
    summary = generate_summary_internal(selected_month)
    return render_template("report.html", summary=summary, selected_month=selected_month)

@dashboard_bp.route('/generate_summary')
@login_required(role='admin')
def generate_summary():
    try:
        selected_month = request.args.get("month")
        summary_data = generate_summary_internal(selected_month)

        # Convert numpy types to Python types
        summary_data = {
            k: int(v) if isinstance(v, (np.int64, np.int32))
            else float(v) if isinstance(v, (np.float64, np.float32))
            else v for k, v in summary_data.items()
        }

        return jsonify({"message": "Summary generated successfully.", "summary": summary_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/download/log')
@login_required()
def download_log():
    selected_month = request.args.get("month")
    db_path = f"prediction_logs_{selected_month.replace('-', '')}.db" if selected_month else get_monthly_db_path()
    try:
        with sqlite3.connect(db_path) as conn:
            df = pd.read_sql_query("SELECT * FROM prediction_logs", conn)
        if df.empty:
            return "No data available for download.", 404
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        csv_path = f"prediction_logs_backup_{selected_month or 'current'}_{timestamp}.csv"
        df.to_csv(csv_path, index=False)
        return send_file(csv_path, as_attachment=True)
    except Exception as e:
        return f"Failed to generate download: {str(e)}", 500

@dashboard_bp.route('/download/summary')
@login_required()
def download_summary():
    selected_month = request.args.get("month")
    summary = generate_summary_internal(selected_month)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    csv_path = f"prediction_summary_report_{selected_month or 'current'}_{timestamp}.csv"
    with open(csv_path, "w", newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=summary.keys())
        writer.writeheader()
        writer.writerow(summary)
    return send_file(csv_path, as_attachment=True)