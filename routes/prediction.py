# routes/prediction.py
"""
Enhanced prediction endpoint with integrated behavioral analysis
Combines ML model + rule-based detection + behavioral baselines
"""

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
from behavioral_analyzer import BehavioralAnalyzer

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
    
    # Check session duration anomalies
    duration = data.get('session_duration', 0)
    if duration < 60:  # Very short sessions
        attack_indicators.append("⚡ HIT-AND-RUN: Abnormally short session duration")
        confidence_score += 0.3
    
    # Check packet size anomalies
    packet_size = data.get('network_packet_size', 0)
    if packet_size in [64, 128, 1400, 1500]:  # Known attack signatures
        attack_indicators.append("📡 TRAFFIC ANOMALY: Unusual network packet patterns")
        confidence_score += 0.2
    
    return {
        'is_attack': confidence_score >= 0.5,
        'confidence_score': min(confidence_score, 1.0),
        'indicators': attack_indicators
    }

@prediction_bp.route('/predict', methods=['POST'])
@require_api_key
def predict():
    """Enhanced prediction with ML + Rules + Behavioral Analysis"""
    data = request.get_json(force=True)
    input_df = pd.DataFrame([data])

    # Calculate basic risk score
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

    # === STEP 1: ML MODEL PREDICTION ===
    scaled_input = scaler.transform(input_df)
    ml_prediction = model.predict(scaled_input)
    anomaly_score = model.decision_function(scaled_input)[0]
    ml_anomaly_flag = int(ml_prediction[0] == -1)

    # === STEP 2: RULE-BASED DETECTION ===
    rule_detection = detect_obvious_attacks(data)
    
    # === STEP 3: BEHAVIORAL ANALYSIS ===
    try:
        analyzer = BehavioralAnalyzer()
        behavioral_score = analyzer.analyze_behavior(data)
        behavioral_analysis_success = True
    except Exception as e:
        print(f"[WARNING] Behavioral analysis failed: {e}")
        # Fallback behavioral score
        behavioral_score = type('obj', (object,), {
            'risk_level': 'UNKNOWN',
            'overall_deviation': 0.0,
            'individual_deviations': {},
            'profile_used': 'Unknown',
            'explanation': ['⚠️ Behavioral analysis unavailable']
        })()
        behavioral_analysis_success = False
    
    # Map behavioral risk to numeric values for combination
    behavioral_weights = {
        'NORMAL': 0.0,
        'LOW': 0.2, 
        'MEDIUM': 0.5,
        'HIGH': 0.8,
        'CRITICAL': 1.0,
        'UNKNOWN': 0.0
    }
    
    behavioral_risk_score = behavioral_weights.get(behavioral_score.risk_level, 0.0)
    
    # === STEP 4: INTELLIGENT DECISION FUSION ===
    # Weight different detection methods
    ml_weight = 0.4
    rule_weight = 0.3  
    behavioral_weight = 0.3 if behavioral_analysis_success else 0.0
    
    # Adjust weights if behavioral analysis failed
    if not behavioral_analysis_success:
        ml_weight = 0.6
        rule_weight = 0.4
    
    # Calculate composite confidence score
    composite_confidence = (
        ml_anomaly_flag * ml_weight +
        rule_detection['confidence_score'] * rule_weight +
        behavioral_risk_score * behavioral_weight
    )
    
    # Final decision with enhanced logic
    if behavioral_score.risk_level == 'CRITICAL':
        final_anomaly_flag = 1
        method_used = "Behavioral Analysis (Critical)"
        confidence = "HIGH"
    elif composite_confidence >= 0.7:
        final_anomaly_flag = 1  
        method_used = "Combined ML + Rules + Behavioral"
        confidence = "HIGH"
    elif composite_confidence >= 0.5:
        final_anomaly_flag = 1
        method_used = "Combined ML + Rules + Behavioral" 
        confidence = "MEDIUM"
    elif ml_anomaly_flag and behavioral_risk_score >= 0.5:
        final_anomaly_flag = 1
        method_used = "ML + Behavioral Confirmation"
        confidence = "MEDIUM"
    elif rule_detection['is_attack'] and behavioral_risk_score >= 0.2:
        final_anomaly_flag = 1
        method_used = "Rules + Behavioral Confirmation"
        confidence = "MEDIUM"
    else:
        final_anomaly_flag = 0
        method_used = "All Methods Agree (Normal)" if behavioral_analysis_success else "ML + Rules (Normal)"
        confidence = "HIGH"
    
    # Risk score override (maintain existing logic)
    risk_score = float(input_df['risk_score'].iloc[0])
    if not final_anomaly_flag and risk_score >= 0.8:
        final_anomaly_flag = 1
        method_used = "High Risk Score Override"
        confidence = "MEDIUM"

    # === STEP 5: GENERATE COMPREHENSIVE EXPLANATION ===
    explanation_parts = []
    
    if final_anomaly_flag:
        explanation_parts.append("🚨 MASQUERADE ATTACK DETECTED")
        
        # Add behavioral analysis details
        if behavioral_score.risk_level in ['HIGH', 'CRITICAL'] and behavioral_analysis_success:
            explanation_parts.extend(behavioral_score.explanation)
        
        # Add rule-based indicators
        if rule_detection['indicators']:
            explanation_parts.extend(rule_detection['indicators'])
        
        # Add ML reasoning
        if ml_anomaly_flag:
            explanation_parts.append(f"🤖 ML MODEL: Behavioral anomaly detected (score: {anomaly_score:.3f})")
    else:
        # Normal session explanation
        if behavioral_analysis_success:
            explanation_parts.extend(behavioral_score.explanation)
        else:
            explanation_parts.append("✅ LEGITIMATE SESSION CONFIRMED")
        
        if not ml_anomaly_flag:
            explanation_parts.append("🤖 ML MODEL: Session patterns within normal range")

    # === STEP 6: BUSINESS IMPACT ASSESSMENT ===
    if final_anomaly_flag:
        if behavioral_score.risk_level == 'CRITICAL':
            business_impact = "🔴 CRITICAL: Immediate security response required"
            estimated_cost = 50000
        elif behavioral_score.risk_level == 'HIGH' or composite_confidence >= 0.8:
            business_impact = "⚠️ HIGH: User account breach - investigate immediately" 
            estimated_cost = 15000
        else:
            business_impact = "🟡 MEDIUM: Potential security incident - monitor closely"
            estimated_cost = 5000
    else:
        business_impact = "✅ LOW: Normal user behavior detected"
        estimated_cost = 0

    # === STEP 7: BUILD RESPONSE ===
    response = {
        'anomaly': final_anomaly_flag,
        'risk_score': risk_score + behavioral_risk_score,  # Enhanced risk score
        'confidence': confidence,
        'message': "🚨 MASQUERADE ATTACK DETECTED!" if final_anomaly_flag else "✅ Normal user behavior",
        'explanation': ' | '.join(explanation_parts),
        'business_impact': business_impact,
        'estimated_cost': estimated_cost,
        
        # Detailed analysis breakdown
        'detection_details': {
            'method_used': method_used,
            'ml_model_result': ml_anomaly_flag,
            'rule_based_result': rule_detection['is_attack'],
            'behavioral_risk_level': behavioral_score.risk_level,
            'composite_confidence': composite_confidence,
            'anomaly_score': anomaly_score,
            'final_decision': final_anomaly_flag
        },
        
        # Behavioral analysis details
        'behavioral_analysis': {
            'profile_used': behavioral_score.profile_used,
            'deviation_score': behavioral_score.overall_deviation,
            'individual_deviations': behavioral_score.individual_deviations if hasattr(behavioral_score, 'individual_deviations') else {},
            'risk_level': behavioral_score.risk_level,
            'analysis_success': behavioral_analysis_success
        },
        
        # Data sources used
        'data_sources': {
            'ml_model': 'Isolation Forest anomaly detection',
            'behavioral_baselines': 'User profile comparison',
            'business_rules': 'Security policy enforcement', 
            'threat_intelligence': 'IP reputation analysis',
            'authentication_logs': 'Login pattern analysis'
        }
    }

    # === STEP 8: LOG TO DATABASE ===
    try:
        db_path = get_monthly_db_path()
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Create table with enhanced columns (add IF NOT EXISTS to prevent errors)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS predictions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    input_data TEXT,
                    prediction INTEGER,
                    confidence TEXT,
                    risk_score REAL,
                    method_used TEXT,
                    behavioral_risk TEXT DEFAULT 'UNKNOWN',
                    profile_used TEXT DEFAULT 'Unknown',
                    deviation_score REAL DEFAULT 0.0
                )
            """)
            
            # Insert prediction record
            cursor.execute("""
                INSERT INTO predictions 
                (timestamp, input_data, prediction, confidence, risk_score, method_used, behavioral_risk, profile_used, deviation_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now(timezone.utc).isoformat(),
                json.dumps(data),
                final_anomaly_flag,
                confidence,  
                response['risk_score'],
                method_used,
                behavioral_score.risk_level,
                behavioral_score.profile_used,
                behavioral_score.overall_deviation
            ))
            conn.commit()
            print(f"[SUCCESS] Logged prediction: Anomaly={final_anomaly_flag}, Profile={behavioral_score.profile_used}")
    
    except Exception as e:
        print(f"[ERROR] Database logging failed: {e}")

    # === STEP 9: SEND ALERTS ===
    if final_anomaly_flag and behavioral_score.risk_level in ['HIGH', 'CRITICAL']:
        try:
            alert_message = f"""
🚨 MASQUERADE ATTACK DETECTED

User: {data.get('username', 'Unknown')}
Risk Level: {behavioral_score.risk_level}
Confidence: {confidence}
Profile: {behavioral_score.profile_used}

Behavioral Analysis:
{chr(10).join(f"• {exp}" for exp in behavioral_score.explanation)}

IP: {data.get('source_ip', 'Unknown')}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            send_telegram_alert(alert_message)
        except Exception as e:
            print(f"[WARNING] Alert sending failed: {e}")

    return jsonify(response)

@prediction_bp.route('/behavioral-test', methods=['POST'])
@require_api_key  
def test_behavioral_analysis():
    """Test endpoint for behavioral analysis only"""
    data = request.get_json(force=True)
    
    try:
        analyzer = BehavioralAnalyzer()
        result = analyzer.analyze_behavior(data)
        
        return jsonify({
            'success': True,
            'profile_used': result.profile_used,
            'deviation_score': result.overall_deviation,
            'risk_level': result.risk_level,
            'confidence': result.confidence,
            'individual_deviations': result.individual_deviations,
            'explanation': result.explanation
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Behavioral analysis failed'
        }), 500

@prediction_bp.route('/behavioral-profiles', methods=['GET'])
@login_required(role='admin')
def view_behavioral_profiles():
    """Admin endpoint to view available behavioral profiles"""
    return jsonify({
        'traffic_profiles': list(baseline_stats.get('traffic_profiles', {}).keys()),
        'role_profiles': list(baseline_stats.get('role_profiles', {}).keys()),
        'combined_profiles': list(baseline_stats.get('role-traffic', {}).keys()),
        'profile_details': baseline_stats
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