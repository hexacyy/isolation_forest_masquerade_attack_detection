from flask import Blueprint, request, jsonify, render_template, current_app
import pandas as pd
import sqlite3
import json
import os
from datetime import datetime, timezone
from random import gauss
from config import model, scaler, expected_columns, baseline_stats
from utils import require_api_key, login_required, get_monthly_db_path, send_telegram_alert, get_explanation

prediction_bp = Blueprint('prediction', __name__)

@prediction_bp.route('/predict', methods=['POST'])
@require_api_key
def predict():
    data = request.get_json(force=True)
    input_df = pd.DataFrame([data])

    # Compute risk score and other logic
    input_df['risk_score'] = (
        input_df['ip_reputation_score'] * 0.5 +
        input_df['failed_logins'] * 0.2 +
        input_df['unusual_time_access'] * 0.3
    )

    profile = data.get("profile_used", "Unknown")
    user_role = data.get("user_role", "Viewer")

    for col in expected_columns:
        if col not in input_df.columns:
            input_df[col] = 0
    input_df = input_df[expected_columns]

    scaled_input = scaler.transform(input_df)
    prediction = model.predict(scaled_input)
    anomaly_score = model.decision_function(scaled_input)[0]
    anomaly_flag = int(prediction[0] == -1)

    explanation = get_explanation({
        **data,
        "risk_score": input_df["risk_score"].iloc[0],
        "unusual_time_access": int(data.get("unusual_time_access", 0)),
    }, anomaly_score, profile)

    if user_role:
        explanation += f" | Role: {user_role}"

    if anomaly_flag == 0 and input_df['risk_score'].iloc[0] >= 0.8:
        anomaly_flag = 1
        explanation += " | Overridden due to high calculated risk score"

    now = datetime.now(timezone.utc)
    log_entry = {
        "timestamp": now.isoformat(),
        "log_month": now.strftime("%Y-%m"),
        "anomaly": anomaly_flag,
        "anomaly_score": round(anomaly_score, 4),
        "explanation": explanation,
        "profile_used": profile,
        "user_role": user_role
    }
    
    for col in expected_columns:
        value = data.get(col, 0)
        try:
            if col == "risk_score":
                log_entry[col] = float(input_df["risk_score"].iloc[0])
            elif col in [
                "network_packet_size", "login_attempts", "failed_logins",
                "unusual_time_access", "protocol_type_ICMP", "protocol_type_TCP",
                "protocol_type_UDP", "encryption_used_AES", "encryption_used_DES",
                "browser_type_Chrome", "browser_type_Edge", "browser_type_Firefox",
                "browser_type_Safari", "browser_type_Unknown"
            ]:
                log_entry[col] = int(value)
            else:
                log_entry[col] = float(value)
        except (ValueError, TypeError):
            log_entry[col] = 0

    db_path = get_monthly_db_path()
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
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
        columns = ", ".join(log_entry.keys())
        placeholders = ", ".join("?" for _ in log_entry)
        c.execute(f"INSERT INTO prediction_logs ({columns}) VALUES ({placeholders})", tuple(log_entry.values()))
        conn.commit()

    if anomaly_flag:
        send_telegram_alert(log_entry)

    return jsonify({
        "anomaly": anomaly_flag,
        "message": "Anomaly detected!" if anomaly_flag else "Session is normal.",
        "explanation": explanation if explanation else "No explanation available.",
        "risk_score": input_df["risk_score"].iloc[0]
    })

@prediction_bp.route('/submit', methods=['GET', 'POST'])
@login_required()
def submit():
    from config import API_KEY
    
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(BASE_DIR, "..", "test", "combined_baseline_profiles.json")

    with open(json_path, "r") as f:
        profile_data = json.load(f)

    def generate_prefill(role='Viewer', profile='Medium'):
        hybrid_key = f"{role}-{profile}"
        if hybrid_key in profile_data:
            stats = profile_data[hybrid_key]
            print(f"[DEBUG] Using hybrid baseline: {hybrid_key}")
        elif role in profile_data.get("role_profiles", {}):
            stats = profile_data["role_profiles"][role]
            print(f"[DEBUG] Using role-only baseline: {role}")
        elif profile in profile_data.get("traffic_profiles", {}):
            stats = profile_data["traffic_profiles"][profile]
            print(f"[DEBUG] Using traffic-only baseline: {profile}")
        else:
            stats = profile_data["traffic_profiles"]["Medium"]
            print("[DEBUG] Using default fallback baseline: Medium")

        sample = {}
        for feature, values in stats.items():
            mean = values['mean']
            std = values['std']
            sample[feature] = max(0, round(gauss(mean, std), 2))

        sample.update({
            'protocol_type_TCP': 1, 'encryption_used_AES': 1, 'browser_type_Chrome': 1,
            'protocol_type_UDP': 0, 'protocol_type_ICMP': 0, 'encryption_used_DES': 0,
            'browser_type_Edge': 0, 'browser_type_Firefox': 0, 'browser_type_Safari': 0,
            'browser_type_Unknown': 0, 'user_role': role, 'access_time': "12:00"
        })

        int_fields = [
            'login_attempts', 'failed_logins', 'protocol_type_TCP', 'protocol_type_UDP',
            'protocol_type_ICMP', 'encryption_used_AES', 'encryption_used_DES',
            'browser_type_Chrome', 'browser_type_Edge', 'browser_type_Firefox',
            'browser_type_Safari', 'browser_type_Unknown'
        ]
        for key in int_fields:
            sample[key] = int(round(sample.get(key, 0)))

        return sample

    def generate_profile_guide():
        selected_features = ['network_packet_size', 'login_attempts', 'session_duration', 'ip_reputation_score']
        guide = {}
        if "traffic_profiles" in profile_data:
            for level, stats in profile_data["traffic_profiles"].items():
                guide[f"{level} (traffic)"] = {feat: f"{round(stats[feat]['mean'], 2)} ± {round(stats[feat]['std'], 2)}"
                                                for feat in selected_features if feat in stats}
        if "role_profiles" in profile_data:
            for role, stats in profile_data["role_profiles"].items():
                guide[f"{role} (role)"] = {feat: f"{round(stats[feat]['mean'], 2)} ± {round(stats[feat]['std'], 2)}"
                                           for feat in selected_features if feat in stats}
        for key, stats in profile_data.items():
            if "-" in key and not key.startswith(("role_", "traffic_")):
                guide[f"{key} (hybrid)"] = {feat: f"{round(stats[feat]['mean'], 2)} ± {round(stats[feat]['std'], 2)}"
                                            for feat in selected_features if feat in stats}
        return guide

    if request.method == 'POST':
        form = request.form
        selected_profile = form.get("selected_profile", "Medium")
        access_time = form.get("access_time", "12:00")
        user_role = form.get("user_role", "Viewer")

        try:
            try:
                hour = datetime.strptime(access_time, "%H:%M").hour
                unusual_time = int(hour < 9 or hour >= 17)
            except:
                unusual_time = 0

            data = {
                "network_packet_size": float(form["network_packet_size"]),
                "login_attempts": int(form["login_attempts"]),
                "session_duration": float(form["session_duration"]),
                "ip_reputation_score": float(form["ip_reputation_score"]),
                "failed_logins": int(form["failed_logins"]),
                "unusual_time_access": unusual_time,
                "protocol_type_TCP": int(form.get("protocol_type_TCP", 0) or 0),
                "encryption_used_AES": int(form.get("encryption_used_AES", 0) or 0),
                "browser_type_Chrome": int(form.get("browser_type_Chrome", 0) or 0),
                "protocol_type_ICMP": int(form.get("protocol_type_ICMP", 0) or 0),
                "protocol_type_UDP": int(form.get("protocol_type_UDP", 0) or 0),
                "encryption_used_DES": int(form.get("encryption_used_DES", 0) or 0),
                "browser_type_Edge": int(form.get("browser_type_Edge", 0) or 0),
                "browser_type_Firefox": int(form.get("browser_type_Firefox", 0) or 0),
                "browser_type_Safari": int(form.get("browser_type_Safari", 0) or 0),
                "browser_type_Unknown": int(form.get("browser_type_Unknown", 0) or 0),
                "selected_profile": selected_profile,
                "profile_used": f"{user_role}-{selected_profile}",
                "user_role": user_role
            }

            # Call predict function directly
            with current_app.test_request_context(json=data, headers={"Authorization": f"Bearer {API_KEY}"}):
                result = predict()

            result = result.get_json() if hasattr(result, 'get_json') else result
            print("[DEBUG] /predict response body:", result)

            if not result:
                result = {
                    "message": "⚠️ No response from prediction engine.",
                    "explanation": "Please verify model routing or response format.",
                    "anomaly": 0,
                    "risk_score": 0.0
                }
            else:
                result.setdefault("message", "Session is normal." if result.get("anomaly") == 0 else "Anomaly detected.")
                result.setdefault("explanation", "No explanation provided by model.")

            return render_template(
                "predict_form_v3.html",
                result=result,
                form_data=form.to_dict(),
                selected_profile=selected_profile,
                profile_guide=generate_profile_guide()
            )

        except Exception as e:
            print("[ERROR] Exception during submit:", str(e))
            return render_template(
                "predict_form_v3.html",
                result={"error": str(e)},
                form_data=form.to_dict(),
                selected_profile=selected_profile,
                profile_guide=generate_profile_guide()
            )

    selected_profile = request.args.get("profile", "Medium")
    selected_role = request.args.get("role", "Viewer")
    prefill_data = generate_prefill(role=selected_role, profile=selected_profile)

    if request.args.get("fail", type=int) is not None:
        prefill_data["failed_logins"] = request.args.get("fail", type=int)
    if request.args.get("time"):
        prefill_data["access_time"] = request.args.get("time")

    return render_template(
        "predict_form_v3.html",
        result=None,
        form_data=prefill_data.copy(),
        selected_profile=selected_profile,
        profile_guide=generate_profile_guide()
    )