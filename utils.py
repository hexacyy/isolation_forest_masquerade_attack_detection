import sqlite3
import pandas as pd
import requests
import json
import sys
import os
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import session, redirect, url_for, flash, request, jsonify
from config import (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, TELEGRAM_GROUPCHAT_ID, 
                   baseline_stats, API_KEY)

def is_strong_password(pw):
    return (
        len(pw) >= 12 and
        any(c.islower() for c in pw) and
        any(c.isupper() for c in pw) and
        any(c.isdigit() for c in pw) and
        any(c in r"!@#$%^&*()-_=+[{]}\|;:'\",<.>/?`~" for c in pw)
    )

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'username' not in session:
                flash("⚠️ Please log in to continue.", "warning")
                return redirect(url_for('auth.login'))
            if role and session.get('role') != role:
                flash("⛔ You do not have permission to access this page.", "danger")
                return redirect(url_for('dashboard.dashboard'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth_header.split(" ")[1]
        if token != API_KEY:
            return jsonify({"error": "Invalid API key"}), 401
        return f(*args, **kwargs)
    return decorated

def get_monthly_db_path():
    now = datetime.now(timezone.utc)
    return f"prediction_logs_{now.strftime('%Y%m')}.db"

def send_telegram_alert(session_data):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or not TELEGRAM_GROUPCHAT_ID:
        print("[ALERT ERROR] Missing TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID or TELEGRAM_GROUPCHAT_ID.")
        return

    protocol = (
        ("ICMP " if session_data.get('protocol_type_ICMP') else '') +
        ("TCP " if session_data.get('protocol_type_TCP') else '') +
        ("UDP " if session_data.get('protocol_type_UDP') else '')
    ).strip() or "Unknown"

    # Final combined alert message
    text = (
        f"🚨 *Masquerade Attack Detected!*\n\n"
        f"🕒 *Time:* `{session_data['timestamp']}`\n"
        f"🎯 *Risk Score:* `{session_data['risk_score']:.2f}`\n"
        f"📌 *IP Reputation Score:* `{session_data['ip_reputation_score']}`\n"
        f"❗ *Failed Logins:* `{session_data['failed_logins']}`\n"
        f"⏰ *Unusual Access:* `{session_data['unusual_time_access']}`\n"
        f"💻 *Protocol:* `{protocol}`\n\n"
        f"```json\n{json.dumps(session_data, indent=2)}\n```"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    # Send to personal chat
    payload_personal = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "Markdown"
    }
    
    # Send to group chat
    payload_group = {
        "chat_id": TELEGRAM_GROUPCHAT_ID,
        "text": text,
        "parse_mode": "Markdown"
    }
    
    # Send both alerts
    success_count = 0
    
    try:
        # Send to personal chat
        response_personal = requests.post(url, json=payload_personal)
        if response_personal.status_code == 200:
            print("[ALERT] Telegram alert sent successfully to personal chat.")
            success_count += 1
        else:
            print(f"[ALERT ERROR] Personal chat - Telegram returned status {response_personal.status_code}: {response_personal.text}")
    except Exception as e:
        print(f"[ALERT ERROR] Failed to send Telegram alert to personal chat: {e}")
    
    try:
        # Send to group chat
        response_group = requests.post(url, json=payload_group)
        if response_group.status_code == 200:
            print("[ALERT] Telegram alert sent successfully to group chat.")
            success_count += 1
        else:
            print(f"[ALERT ERROR] Group chat - Telegram returned status {response_group.status_code}: {response_group.text}")
    except Exception as e:
        print(f"[ALERT ERROR] Failed to send Telegram alert to group chat: {e}")
    
    if success_count > 0:
        print(f"[ALERT] Successfully sent {success_count}/2 Telegram alerts.")
        sys.stdout.flush()
    else:
        print("[ALERT ERROR] Failed to send any Telegram alerts.")
        sys.stdout.flush()

def get_explanation(data, anomaly_score=None, profile="Medium"):
    reasons = []

    # Use fallback profile if invalid
    stats = baseline_stats.get(profile, baseline_stats.get("Medium"))

    # Check deviation from profile means
    for key in ["network_packet_size", "login_attempts", "session_duration", "ip_reputation_score", "failed_logins"]:
        try:
            value = float(data.get(key, 0))
            mean = stats[key]["mean"]
            std = stats[key]["std"]
            if value > mean + std:
                reasons.append(f"{key} is above normal ({value} > {mean + std:.1f})")
            elif value < mean - std:
                reasons.append(f"{key} is below normal ({value} < {mean - std:.1f})")
        except:
            continue

    # Rule-based indicators
    if data.get("failed_logins", 0) > 3:
        reasons.append("Multiple Failed Logins")
    if data.get("ip_reputation_score", 0) > 0.8:
        reasons.append("High IP Reputation Score")
    if data.get("risk_score", 0) >= 1.0:
        reasons.append("Overall High Risk Score")
    if anomaly_score is not None and anomaly_score < -0.25:
        reasons.append(f"Anomaly Score indicates outlier ({anomaly_score:.2f})")
    if data.get("unusual_time_access", 0) == 1:
        reasons.append("Access occurred outside normal hours (9AM to 5PM)")
    role = data.get("user_role", "Unknown")
    profile = profile or "Unknown"
    reasons.append(f"Session deviated from expected behaviour for {role} during {profile} traffic.")

    return "No significant anomalies detected. Session is within expected bounds." if not reasons else " | ".join(reasons)

def archive_previous_month():
    now = datetime.now(timezone.utc)
    current_month = now.strftime('%Y%m')
    prev_month = (now.replace(day=1) - timedelta(days=1)).strftime('%Y%m')
    if os.path.exists(f"prediction_logs_{current_month}.db"):
        # No action needed for current month
        pass
    if os.path.exists(f"prediction_logs_{prev_month}.db"):
        # Previous month already archived
        return
    with sqlite3.connect(f"prediction_logs_{current_month}.db") as conn:
        df = pd.read_sql_query("SELECT * FROM prediction_logs WHERE log_month != ?", (now.strftime('%Y-%m'),))
        if not df.empty:
            prev_db_path = f"prediction_logs_{prev_month}.db"
            with sqlite3.connect(prev_db_path) as prev_conn:
                c = prev_conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS prediction_logs (
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
                )''')
                for _, row in df.iterrows():
                    c.execute("INSERT INTO prediction_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", tuple(row))
                prev_conn.commit()
            with sqlite3.connect(f"prediction_logs_{current_month}.db") as conn:
                c = conn.cursor()
                c.execute("DELETE FROM prediction_logs WHERE log_month != ?", (now.strftime('%Y-%m'),))
                conn.commit()