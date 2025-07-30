# REPLACE your entire routes/prediction.py with this clean version

from flask import Blueprint, request, jsonify, render_template, current_app
import pandas as pd
import sqlite3
import json
import os
from datetime import datetime, timezone
from random import gauss, uniform, choice
import numpy as np
from config import model, scaler, expected_columns, baseline_stats
from utils import require_api_key, login_required, get_monthly_db_path, send_telegram_alert

prediction_bp = Blueprint('prediction', __name__)

def detect_obvious_attacks(data):
    """Rule-based detection for obvious masquerade attacks"""
    attack_indicators = []
    confidence_score = 0
    
    # Check IP reputation (strongest indicator)
    ip_score = data.get('ip_reputation_score', 0)
    if ip_score >= 0.8:
        attack_indicators.append("🚨 MALICIOUS IP: Known threat actor source")
        confidence_score += 0.5
    elif ip_score >= 0.6:
        attack_indicators.append("⚠️ SUSPICIOUS IP: Elevated risk reputation")
        confidence_score += 0.3
    
    # Check failed login patterns
    failed_logins = data.get('failed_logins', 0)
    if failed_logins >= 4:
        attack_indicators.append("🔐 CREDENTIAL STUFFING: Multiple authentication failures")
        confidence_score += 0.4
    elif failed_logins >= 2:
        attack_indicators.append("🔑 AUTH ANOMALY: Repeated login failures")
        confidence_score += 0.2
    
    # Check timing anomaly
    if data.get('unusual_time_access', 0) == 1:
        attack_indicators.append("🕐 TIMING ATTACK: Access outside business hours")
        confidence_score += 0.2
    
    # Check session behavior anomalies
    session_duration = data.get('session_duration', 1800)
    packet_size = data.get('network_packet_size', 500)
    
    if session_duration < 180:  # Very short session (< 3 minutes)
        attack_indicators.append("⏱️ HIT-AND-RUN: Abnormally short session duration")
        confidence_score += 0.1
    
    if packet_size < 100 or packet_size > 1400:  # Unusual packet sizes
        attack_indicators.append("📊 TRAFFIC ANOMALY: Unusual network packet patterns")
        confidence_score += 0.1
    
    # Calculate overall attack probability
    attack_detected = confidence_score >= 0.4  # Lower threshold for rule-based detection
    
    return {
        'is_attack': attack_detected,
        'indicators': attack_indicators,
        'confidence': min(confidence_score, 1.0),
        'rule_based': True
    }

def ensure_database_logging(log_entry):
    """Ensure prediction gets logged to the correct database that dashboard reads"""
    databases_to_update = []
    
    # Add monthly database
    current_month = datetime.now().strftime("%Y%m")
    monthly_db = f"prediction_logs_{current_month}.db"
    databases_to_update.append(monthly_db)
    
    # Add main database (in case dashboard reads from this)
    main_db = "prediction_logs.db"
    databases_to_update.append(main_db)
    
    # Update all relevant databases
    for db_path in databases_to_update:
        try:
            with sqlite3.connect(db_path) as conn:
                c = conn.cursor()
                
                # Create table if it doesn't exist
                c.execute('''CREATE TABLE IF NOT EXISTS prediction_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    log_month TEXT,
                    anomaly INTEGER,
                    anomaly_score REAL,
                    explanation TEXT,
                    profile_used TEXT,
                    user_role TEXT,
                    confidence TEXT,
                    business_impact TEXT,
                    estimated_cost INTEGER,
                    rule_based_detection INTEGER,
                    ml_detection INTEGER,
                    risk_score REAL,
                    detection_method TEXT,
                    network_packet_size REAL,
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
                    browser_type_Unknown INTEGER
                )''')
                
                # Insert the log entry
                columns = ', '.join(log_entry.keys())
                placeholders = ', '.join('?' for _ in log_entry)
                c.execute(f"INSERT INTO prediction_logs ({columns}) VALUES ({placeholders})", 
                         tuple(log_entry.values()))
                conn.commit()
                print(f"[SUCCESS] Logged to {db_path}: Anomaly={log_entry.get('anomaly')}")
                
        except Exception as e:
            print(f"[ERROR] Failed to log to {db_path}: {e}")

def debug_database_issue():
    """Debug function to check database files and connections"""
    print("=== DATABASE DEBUG INFO ===")
    
    # Check what database files exist
    db_files = [f for f in os.listdir('.') if f.endswith('.db')]
    print(f"Database files found: {db_files}")
    
    # Check the current month database path
    current_month = datetime.now().strftime("%Y%m")
    monthly_db = f"prediction_logs_{current_month}.db"
    print(f"Expected monthly DB: {monthly_db}")
    
    # Check if monthly DB exists and has data
    if os.path.exists(monthly_db):
        with sqlite3.connect(monthly_db) as conn:
            c = conn.cursor()
            try:
                c.execute("SELECT COUNT(*) FROM prediction_logs")
                count = c.fetchone()[0]
                print(f"Records in {monthly_db}: {count}")
                
                if count > 0:
                    c.execute("SELECT timestamp, anomaly, user_role, risk_score FROM prediction_logs ORDER BY timestamp DESC LIMIT 3")
                    recent = c.fetchall()
                    print("Recent records:")
                    for record in recent:
                        print(f"  - {record}")
            except Exception as e:
                print(f"Error reading {monthly_db}: {e}")
    else:
        print(f"Monthly DB {monthly_db} does not exist!")

@prediction_bp.route('/predict', methods=['POST'])
@require_api_key
def predict():
    """Enhanced prediction with rule-based attack detection"""
    data = request.get_json(force=True)
    input_df = pd.DataFrame([data])

    # Calculate risk score
    input_df['risk_score'] = (
        input_df['ip_reputation_score'] * 0.5 +
        input_df['failed_logins'] * 0.2 +
        input_df['unusual_time_access'] * 0.3
    )

    profile = data.get("profile_used", "Unknown")
    user_role = data.get("user_role", "Viewer")

    # Prepare features for ML model
    for col in expected_columns:
        if col not in input_df.columns:
            input_df[col] = 0
    input_df = input_df[expected_columns]

    # Get ML model prediction
    scaled_input = scaler.transform(input_df)
    ml_prediction = model.predict(scaled_input)
    anomaly_score = model.decision_function(scaled_input)[0]
    ml_anomaly_flag = int(ml_prediction[0] == -1)

    # Get rule-based detection
    rule_detection = detect_obvious_attacks(data)
    
    # COMBINE ML + RULES for final decision
    final_anomaly_flag = ml_anomaly_flag or rule_detection['is_attack']
    
    # Risk score override (your existing logic)
    risk_score = float(input_df['risk_score'].iloc[0])
    if not final_anomaly_flag and risk_score >= 0.8:
        final_anomaly_flag = 1
        override_reason = "High risk score override"
    else:
        override_reason = None

    # Generate comprehensive explanation
    explanation_parts = []
    
    if final_anomaly_flag:
        explanation_parts.append("🚨 MASQUERADE ATTACK DETECTED")
        
        # Add rule-based indicators
        if rule_detection['indicators']:
            explanation_parts.extend(rule_detection['indicators'])
        
        # Add ML reasoning
        if ml_anomaly_flag:
            explanation_parts.append(f"🤖 ML MODEL: Behavioral anomaly detected (score: {anomaly_score:.3f})")
        
        # Add override reasoning
        if override_reason:
            explanation_parts.append(f"📊 RISK OVERRIDE: {override_reason}")
            
    else:
        explanation_parts.append("✅ LEGITIMATE SESSION CONFIRMED")
        explanation_parts.append("🔍 All security indicators within acceptable ranges")
        explanation_parts.append(f"🤖 ML MODEL: Normal behavior pattern (score: {anomaly_score:.3f})")

    explanation = " | ".join(explanation_parts)

    # Determine confidence level
    if rule_detection['confidence'] >= 0.7 or abs(anomaly_score) > 0.1:
        confidence = "HIGH"
    elif rule_detection['confidence'] >= 0.4 or abs(anomaly_score) > 0.05:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # Business impact assessment
    if final_anomaly_flag:
        if user_role == 'Admin':
            business_impact = "🚨 CRITICAL: Admin account compromise - immediate response required"
            estimated_cost = 50000  # $50K potential damage
        else:
            business_impact = "⚠️ HIGH: User account breach - investigate immediately"
            estimated_cost = 15000  # $15K potential damage
    else:
        business_impact = "✅ LOW: Normal operations - continue monitoring"
        estimated_cost = 0

    # Log the prediction with enhanced details
    now = datetime.now(timezone.utc)
    log_entry = {
        "timestamp": now.isoformat(),
        "log_month": now.strftime("%Y-%m"),
        "anomaly": final_anomaly_flag,
        "anomaly_score": round(anomaly_score, 4),
        "explanation": explanation,
        "profile_used": profile,
        "user_role": user_role,
        "confidence": confidence,
        "business_impact": business_impact,
        "estimated_cost": estimated_cost,
        "rule_based_detection": rule_detection['is_attack'],
        "ml_detection": ml_anomaly_flag,
        "risk_score": risk_score,
        "detection_method": "Combined ML + Rules" if (ml_anomaly_flag and rule_detection['is_attack']) else 
                           "Rule-based" if rule_detection['is_attack'] else 
                           "ML Model" if ml_anomaly_flag else "Normal"
    }
    
    # Add all feature values to log
    for col in expected_columns:
        value = data.get(col, 0)
        if col == "risk_score":
            log_entry[col] = risk_score
        else:
            log_entry[col] = float(value) if isinstance(value, (int, float)) else 0

    # Save to database with enhanced logging
    try:
        ensure_database_logging(log_entry)
        
        # Also try the original method for compatibility
        db_path = get_monthly_db_path()
        with sqlite3.connect(db_path) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS prediction_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                anomaly INTEGER,
                anomaly_score REAL,
                explanation TEXT,
                profile_used TEXT,
                user_role TEXT,
                log_month TEXT,
                network_packet_size REAL,
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
                risk_score REAL
            )''')
            
            # Create a simplified entry for compatibility
            simple_entry = {
                'timestamp': log_entry['timestamp'],
                'anomaly': log_entry['anomaly'],
                'anomaly_score': log_entry['anomaly_score'],
                'explanation': log_entry['explanation'],
                'profile_used': log_entry['profile_used'],
                'user_role': log_entry['user_role'],
                'log_month': log_entry['log_month'],
                'risk_score': log_entry['risk_score'],
                'network_packet_size': log_entry['network_packet_size'],
                'login_attempts': log_entry['login_attempts'],
                'session_duration': log_entry['session_duration'],
                'ip_reputation_score': log_entry['ip_reputation_score'],
                'failed_logins': log_entry['failed_logins'],
                'unusual_time_access': log_entry['unusual_time_access'],
                'protocol_type_ICMP': log_entry['protocol_type_ICMP'],
                'protocol_type_TCP': log_entry['protocol_type_TCP'],
                'protocol_type_UDP': log_entry['protocol_type_UDP'],
                'encryption_used_AES': log_entry['encryption_used_AES'],
                'encryption_used_DES': log_entry['encryption_used_DES'],
                'browser_type_Chrome': log_entry['browser_type_Chrome'],
                'browser_type_Edge': log_entry['browser_type_Edge'],
                'browser_type_Firefox': log_entry['browser_type_Firefox'],
                'browser_type_Safari': log_entry['browser_type_Safari'],
                'browser_type_Unknown': log_entry['browser_type_Unknown']
            }
            
            columns = ', '.join(simple_entry.keys())
            placeholders = ', '.join('?' for _ in simple_entry)
            c.execute(f"INSERT INTO prediction_logs ({columns}) VALUES ({placeholders})", 
                     tuple(simple_entry.values()))
            conn.commit()
            print(f"[SUCCESS] Also logged to original DB format")
            
    except Exception as e:
        print(f"[ERROR] Database logging failed: {e}")
        print(f"[FALLBACK] Prediction result: Anomaly={log_entry['anomaly']}, Risk={log_entry['risk_score']}")

    # Send alert if attack detected
    if final_anomaly_flag:
        try:
            send_telegram_alert(log_entry)
        except Exception as e:
            print(f"[WARNING] Failed to send Telegram alert: {e}")

    # Debug database after logging
    debug_database_issue()

    # Return enhanced response
    return jsonify({
        "anomaly": final_anomaly_flag,
        "message": "🚨 MASQUERADE ATTACK DETECTED!" if final_anomaly_flag else "✅ Legitimate session",
        "explanation": explanation,
        "risk_score": risk_score,
        "confidence": confidence,
        "business_impact": business_impact,
        "estimated_cost": estimated_cost,
        "detection_details": {
            "ml_model_result": ml_anomaly_flag,
            "rule_based_result": rule_detection['is_attack'],
            "final_decision": final_anomaly_flag,
            "method_used": log_entry['detection_method'],
            "anomaly_score": round(anomaly_score, 4)
        },
        "data_sources": {
            "threat_intelligence": "IP reputation analysis",
            "authentication_logs": "Login pattern analysis", 
            "behavioral_baselines": "User profile comparison",
            "ml_model": "Isolation Forest anomaly detection",
            "business_rules": "Security policy enforcement"
        }
    })

@prediction_bp.route('/submit', methods=['GET', 'POST'])
@login_required()
def submit():
    """Enhanced submission form with realistic context"""
    
    def generate_realistic_prefill(role='Viewer', profile='Medium'):
        """Generate realistic prefill data"""
        
        # Base values for different roles and profiles
        role_defaults = {
            'Admin': {
                'network_packet_size': 900,
                'login_attempts': 1,
                'session_duration': 3600,
                'ip_reputation_score': 0.05,
                'failed_logins': 0,
                'access_time': '14:00'
            },
            'Viewer': {
                'network_packet_size': 400,
                'login_attempts': 1,
                'session_duration': 1800,
                'ip_reputation_score': 0.1,
                'failed_logins': 0,
                'access_time': '10:30'
            }
        }
        
        profile_multipliers = {
            'Low': 0.7,
            'Medium': 1.0,
            'High': 1.4
        }
        
        base = role_defaults.get(role, role_defaults['Viewer']).copy()
        multiplier = profile_multipliers.get(profile, 1.0)
        
        # Apply profile multiplier with some randomness
        base['network_packet_size'] = int(base['network_packet_size'] * multiplier * uniform(0.8, 1.2))
        base['session_duration'] = int(base['session_duration'] * multiplier * uniform(0.7, 1.3))
        
        # Add technical defaults
        base.update({
            'user_role': role,
            'selected_profile': profile,
            'protocol_type_TCP': 1,
            'protocol_type_UDP': 0,
            'protocol_type_ICMP': 0,
            'encryption_used_AES': 1,
            'encryption_used_DES': 0,
            'browser_type_Chrome': 1,
            'browser_type_Firefox': 0,
            'browser_type_Safari': 0,
            'browser_type_Edge': 0,
            'browser_type_Unknown': 0
        })
        
        return base

    if request.method == 'POST':
        form = request.form
        selected_profile = form.get("selected_profile", "Medium")
        access_time = form.get("access_time", "14:00")
        user_role = form.get("user_role", "Viewer")

        try:
            # Calculate unusual time access
            try:
                hour = datetime.strptime(access_time, "%H:%M").hour
                unusual_time = int(hour < 9 or hour >= 17)
            except:
                unusual_time = 0

            # Prepare data for prediction
            data = {
                "network_packet_size": float(form.get("network_packet_size", 500)),
                "login_attempts": int(form.get("login_attempts", 1)),
                "session_duration": float(form.get("session_duration", 1800)),
                "ip_reputation_score": float(form.get("ip_reputation_score", 0.1)),
                "failed_logins": int(form.get("failed_logins", 0)),
                "unusual_time_access": unusual_time,
                "protocol_type_TCP": int(form.get("protocol_type_TCP", 1)),
                "protocol_type_UDP": int(form.get("protocol_type_UDP", 0)),
                "protocol_type_ICMP": int(form.get("protocol_type_ICMP", 0)),
                "encryption_used_AES": int(form.get("encryption_used_AES", 1)),
                "encryption_used_DES": int(form.get("encryption_used_DES", 0)),
                "browser_type_Chrome": int(form.get("browser_type_Chrome", 1)),
                "browser_type_Edge": int(form.get("browser_type_Edge", 0)),
                "browser_type_Firefox": int(form.get("browser_type_Firefox", 0)),
                "browser_type_Safari": int(form.get("browser_type_Safari", 0)),
                "browser_type_Unknown": int(form.get("browser_type_Unknown", 0)),
                "profile_used": f"{user_role}-{selected_profile}",
                "user_role": user_role
            }

            # Call prediction using your existing logic
            from config import API_KEY
            with current_app.test_request_context(json=data, headers={"Authorization": f"Bearer {API_KEY}"}):
                result = predict()

            result_data = result.get_json() if hasattr(result, 'get_json') else result
            
            if not result_data:
                result_data = {
                    "message": "⚠️ No response from prediction engine.",
                    "explanation": "Model analysis complete.",
                    "anomaly": 0,
                    "risk_score": 0.0,
                    "confidence": "Medium"
                }

            # Try enhanced template first, fallback to simple one
            try:
                return render_template(
                    "enhanced_predict_form_v4.html",
                    result=result_data,
                    form_data=form.to_dict(),
                    selected_profile=selected_profile
                )
            except:
                # Fallback to original template
                return render_template(
                    "predict_form_v3.html",
                    result=result_data,
                    form_data=form.to_dict(),
                    selected_profile=selected_profile,
                    profile_guide={}
                )

        except Exception as e:
            print(f"[ERROR] Exception during submit: {str(e)}")
            error_result = {
                "error": str(e), 
                "anomaly": 0,
                "message": "Error processing request",
                "explanation": "Please check your input values"
            }
            
            try:
                return render_template(
                    "enhanced_predict_form_v4.html",
                    result=error_result,
                    form_data=form.to_dict(),
                    selected_profile=selected_profile
                )
            except:
                return render_template(
                    "predict_form_v3.html",
                    result=error_result,
                    form_data=form.to_dict(),
                    selected_profile=selected_profile,
                    profile_guide={}
                )

    # GET request - show form
    selected_profile = request.args.get("profile", "Medium")
    selected_role = request.args.get("role", "Viewer")
    
    # Generate prefill data
    prefill_data = generate_realistic_prefill(role=selected_role, profile=selected_profile)

    # Handle quick scenario parameters
    if request.args.get("fail", type=int) is not None:
        prefill_data["failed_logins"] = request.args.get("fail", type=int)
    if request.args.get("time"):
        prefill_data["access_time"] = request.args.get("time")

    try:
        return render_template(
            "enhanced_predict_form_v4.html",
            result=None,
            form_data=prefill_data,
            selected_profile=selected_profile
        )
    except:
        # Fallback to original template if new one doesn't exist
        return render_template(
            "predict_form_v3.html",
            result=None,
            form_data=prefill_data,
            selected_profile=selected_profile,
            profile_guide={}
        )