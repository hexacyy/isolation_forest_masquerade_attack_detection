# routes/data_feeds.py
"""
Real-World Data Feed Controller for Masquerade Detection
Manages simulation of enterprise data sources: SIEM, VPN, Honeypot, Network Monitor
"""

from flask import Blueprint, render_template, jsonify, request
from datetime import datetime
import threading
import os
import sys
import sqlite3

# Add the data_feeds directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'data_feeds'))

try:
    from session_generator import DataFeedSimulator
except ImportError:
    print("[WARNING] Data feed simulator not found. Please create data_feeds/session_generator.py")
    DataFeedSimulator = None

from utils import login_required, get_monthly_db_path

# Create blueprint
data_feeds_bp = Blueprint('data_feeds', __name__)

# Global simulator instance
simulator_instance = None

@data_feeds_bp.route('/data-feeds')
@login_required(role='admin')
def data_feeds_dashboard():
    """Data feed control dashboard"""
    return render_template('data_feeds_dashboard.html')

@data_feeds_bp.route('/api/feeds/start', methods=['POST'])
@login_required(role='admin')
def start_data_feeds():
    """Start all data feed simulations"""
    global simulator_instance
    
    try:
        if DataFeedSimulator is None:
            return jsonify({
                'error': 'Data feed simulator not available. Please check data_feeds/session_generator.py'
            }), 500
        
        if simulator_instance and simulator_instance.running:
            return jsonify({'error': 'Data feeds already running'}), 400
        
        # Get API key from config
        try:
            from config import API_KEY
        except ImportError:
            return jsonify({'error': 'API_KEY not found in config'}), 500
        
        API_ENDPOINT = "http://localhost:5000/predict"
        
        # Create and start simulator
        simulator_instance = DataFeedSimulator(API_KEY, API_ENDPOINT)
        simulator_instance.start_all_feeds()
        
        return jsonify({
            'status': 'success',
            'message': 'All data feeds started successfully',
            'feeds': ['SIEM', 'VPN', 'Honeypot', 'Network Monitor'],
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[ERROR] Failed to start data feeds: {e}")
        return jsonify({'error': str(e)}), 500

@data_feeds_bp.route('/api/feeds/stop', methods=['POST'])
@login_required(role='admin')
def stop_data_feeds():
    """Stop all data feed simulations"""
    global simulator_instance
    
    try:
        if simulator_instance:
            simulator_instance.stop_all_feeds()
            simulator_instance = None
        
        return jsonify({
            'status': 'success',
            'message': 'All data feeds stopped',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[ERROR] Failed to stop data feeds: {e}")
        return jsonify({'error': str(e)}), 500

@data_feeds_bp.route('/api/feeds/status')
@login_required(role='admin')
def get_feeds_status():
    """Get current status of data feeds"""
    global simulator_instance
    
    if simulator_instance and simulator_instance.running:
        return jsonify({
            'running': True,
            'feeds': {
                'siem': 'Active - Corporate sessions every 25s',
                'vpn': 'Active - VPN sessions every 35s', 
                'honeypot': 'Active - Attack detection every 90s',
                'network': 'Active - Network monitoring every 50s'
            },
            'uptime': 'Running since startup',
            'timestamp': datetime.now().isoformat()
        })
    else:
        return jsonify({
            'running': False,
            'feeds': {},
            'uptime': 'Not running',
            'timestamp': datetime.now().isoformat()
        })

@data_feeds_bp.route('/api/feeds/generate-sample', methods=['POST'])
@login_required(role='admin')
def generate_sample_session():
    """Generate a single sample session for testing"""
    try:
        if DataFeedSimulator is None:
            return jsonify({
                'error': 'Data feed simulator not available'
            }), 500
        
        # Get session type from request
        data = request.get_json() or {}
        session_type = data.get('type', 'legitimate')
        
        # Get API key from config
        try:
            from config import API_KEY
        except ImportError:
            return jsonify({'error': 'API_KEY not found in config'}), 500
        
        temp_simulator = DataFeedSimulator(API_KEY, "http://localhost:5000/predict")
        
        if session_type == 'attack':
            attack_type = data.get('attack_type', 'external_attacker')
            session = temp_simulator.session_generator.generate_attack_session(attack_type)
        else:
            session = temp_simulator.session_generator.generate_legitimate_session()
        
        if session:
            # Send to detection engine
            temp_simulator._send_to_detection_engine(session, source="MANUAL_TEST")
            
            return jsonify({
                'status': 'success',
                'message': f'Generated {session_type} session',
                'session': {
                    'username': session['username'],
                    'source_ip': session['source_ip'],
                    'risk_score': session['ip_reputation_score'],
                    'failed_logins': session['failed_logins'],
                    'session_type': session.get('session_type', session_type)
                },
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'error': 'Failed to generate session - user might not be active at this time'
            }), 500
            
    except Exception as e:
        print(f"[ERROR] Failed to generate sample session: {e}")
        return jsonify({'error': str(e)}), 500

@data_feeds_bp.route('/api/feeds/stats')
@login_required(role='admin')  
def get_feed_statistics():
    """Get real-time statistics about data feeds"""
    try:
        # Read recent alert logs
        alerts_today = 0
        sessions_today = 0
        
        date_str = datetime.now().strftime('%Y-%m-%d')
        alert_file = f'logs/security_alerts/alerts_{date_str}.json'
        
        if os.path.exists(alert_file):
            try:
                with open(alert_file, 'r') as f:
                    alerts_today = len(f.readlines())
            except Exception as e:
                print(f"[WARNING] Could not read alert file: {e}")
        
        # Get database statistics  
        db_path = get_monthly_db_path()
        if os.path.exists(db_path):
            try:
                with sqlite3.connect(db_path) as conn:
                    c = conn.cursor()
                    
                    # Count today's sessions
                    today = datetime.now().strftime('%Y-%m-%d')
                    c.execute("SELECT COUNT(*) FROM prediction_logs WHERE date(timestamp) = ?", (today,))
                    result = c.fetchone()
                    sessions_today = result[0] if result else 0
            except Exception as e:
                print(f"[WARNING] Could not read database: {e}")
        
        # Check if feeds are running
        feeds_active = 4 if simulator_instance and simulator_instance.running else 0
        
        return jsonify({
            'sessions_processed_today': sessions_today,
            'alerts_generated_today': alerts_today,
            'feeds_active': feeds_active,
            'total_feed_types': 4,
            'last_updated': datetime.now().isoformat(),
            'status': 'active' if feeds_active > 0 else 'inactive'
        })
        
    except Exception as e:
        print(f"[ERROR] Failed to get feed statistics: {e}")
        return jsonify({
            'error': str(e),
            'sessions_processed_today': 0,
            'alerts_generated_today': 0,
            'feeds_active': 0,
            'total_feed_types': 4,
            'last_updated': datetime.now().isoformat(),
            'status': 'error'
        }), 500

@data_feeds_bp.route('/api/feeds/recent-activity')
@login_required(role='admin')
def get_recent_activity():
    """Get recent detection activity for live log display"""
    try:
        # Read recent sessions from database
        db_path = get_monthly_db_path()
        activities = []
        
        if os.path.exists(db_path):
            with sqlite3.connect(db_path) as conn:
                c = conn.cursor()
                
                # Get last 10 sessions
                c.execute("""
                    SELECT timestamp, user_role, anomaly, explanation, risk_score 
                    FROM prediction_logs 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                """)
                
                rows = c.fetchall()
                for row in rows:
                    timestamp, user_role, anomaly, explanation, risk_score = row
                    
                    # Parse timestamp
                    try:
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        time_str = dt.strftime('%H:%M:%S')
                    except:
                        time_str = timestamp[:8] if len(timestamp) > 8 else timestamp
                    
                    activities.append({
                        'timestamp': time_str,
                        'type': 'ATTACK' if anomaly else 'NORMAL',
                        'message': f"User: {user_role} | Risk: {risk_score:.2f} | {explanation[:50]}...",
                        'severity': 'danger' if anomaly else 'success'
                    })
        
        return jsonify({
            'activities': activities,
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"[ERROR] Failed to get recent activity: {e}")
        return jsonify({
            'activities': [],
            'error': str(e),
            'last_updated': datetime.now().isoformat()
        }), 500

# Debug endpoint for troubleshooting
@data_feeds_bp.route('/api/feeds/debug')
@login_required(role='admin')
def debug_feeds():
    """Debug endpoint to check feed setup"""
    debug_info = {
        'timestamp': datetime.now().isoformat(),
        'simulator_available': DataFeedSimulator is not None,
        'simulator_running': simulator_instance and simulator_instance.running if simulator_instance else False,
        'data_feeds_dir_exists': os.path.exists('data_feeds'),
        'session_generator_exists': os.path.exists('data_feeds/session_generator.py'),
        'logs_dir_exists': os.path.exists('logs/security_alerts'),
        'monthly_db_exists': os.path.exists(get_monthly_db_path()),
        'monthly_db_path': get_monthly_db_path()
    }
    
    # Check if API key is available
    try:
        from config import API_KEY
        debug_info['api_key_available'] = bool(API_KEY)
    except ImportError:
        debug_info['api_key_available'] = False
        debug_info['api_key_error'] = 'API_KEY not found in config'
    
    # Check recent database activity
    try:
        db_path = get_monthly_db_path()
        if os.path.exists(db_path):
            with sqlite3.connect(db_path) as conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM prediction_logs")
                debug_info['total_sessions_in_db'] = c.fetchone()[0]
        else:
            debug_info['total_sessions_in_db'] = 0
    except Exception as e:
        debug_info['db_error'] = str(e)
        debug_info['total_sessions_in_db'] = 0
    
    return jsonify(debug_info)