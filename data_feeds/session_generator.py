# data_feeds/session_generator.py
"""
Real-World Data Feed Simulator for Masquerade Detection
Simulates actual data sources: SIEM logs, network captures, SSH logs, VPN sessions
"""

import random
import json
import time
import threading
from datetime import datetime, timedelta
import requests
import pandas as pd
from faker import Faker
import numpy as np
import os

fake = Faker()

class CorporateSessionGenerator:
    """Simulates real corporate user sessions based on realistic patterns"""
    
    def __init__(self):
        self.users = self._create_user_profiles()
        self.threat_actors = self._create_threat_profiles()
        self.corporate_ips = self._generate_corporate_network()
        self.external_ips = self._generate_external_ips()
        self.active_sessions = {}
        
    def _create_user_profiles(self):
        """Create realistic user profiles based on real corporate patterns"""
        profiles = []
        
        # IT Admins (5% of users, high privilege)
        for i in range(5):
            profiles.append({
                'username': f'admin.{fake.first_name().lower()}',
                'role': 'Admin',
                'department': 'IT',
                'work_hours': (7, 19),  # Early/late workers
                'typical_duration': (3600, 14400),  # 1-4 hours
                'failure_rate': 0.05,  # Very low failures
                'preferred_locations': ['office_main', 'datacenter'],
                'packet_size_range': (800, 1200),
                'weekend_access': 0.3,  # Sometimes work weekends
                'vpn_usage': 0.8
            })
        
        # Regular Staff (80% of users)
        for i in range(80):
            profiles.append({
                'username': f'{fake.first_name().lower()}.{fake.last_name().lower()}',
                'role': 'Viewer',
                'department': random.choice(['Sales', 'Marketing', 'HR', 'Finance']),
                'work_hours': (9, 17),  # Standard 9-5
                'typical_duration': (1800, 7200),  # 30min-2hours
                'failure_rate': 0.1,  # Occasional password mistakes
                'preferred_locations': ['office_main', 'home'],
                'packet_size_range': (200, 600),
                'weekend_access': 0.05,  # Rarely work weekends
                'vpn_usage': 0.4
            })
        
        # Contractors/External (15% of users, limited access)
        for i in range(15):
            profiles.append({
                'username': f'contractor.{fake.last_name().lower()}',
                'role': 'Viewer',
                'department': 'External',
                'work_hours': (10, 16),  # Limited hours
                'typical_duration': (900, 3600),  # 15min-1hour
                'failure_rate': 0.2,  # Higher failure rate
                'preferred_locations': ['remote'],
                'packet_size_range': (150, 400),
                'weekend_access': 0.0,  # No weekend access
                'vpn_usage': 0.9  # Always use VPN
            })
            
        return profiles
    
    def _create_threat_profiles(self):
        """Create realistic threat actor patterns"""
        return {
            'insider_threat': {
                'username_patterns': ['(.+)_backup', '(.+)_admin', '(.+)_temp'],
                'timing': 'off_hours',
                'duration_range': (300, 1800),  # Quick sessions
                'failure_rate': 0.3,
                'packet_anomalies': True,
                'ip_reputation': (0.4, 0.7)
            },
            'external_attacker': {
                'username_patterns': ['admin', 'administrator', 'root', 'test'],
                'timing': 'random',
                'duration_range': (60, 600),  # Very quick
                'failure_rate': 0.8,  # Many failures
                'packet_anomalies': True,
                'ip_reputation': (0.7, 1.0)
            },
            'credential_stuffing': {
                'username_patterns': ['.*'],  # Any username
                'timing': 'batch',
                'duration_range': (10, 120),  # Automated
                'failure_rate': 0.95,  # Almost all fail
                'packet_anomalies': True,
                'ip_reputation': (0.8, 1.0)
            }
        }
    
    def _generate_corporate_network(self):
        """Generate realistic corporate IP ranges"""
        return {
            'office_main': [f'10.0.{i}.{j}' for i in range(1, 5) for j in range(1, 255, 10)],
            'office_branch': [f'10.1.{i}.{j}' for i in range(1, 3) for j in range(1, 100, 5)],
            'datacenter': [f'10.10.{i}.{j}' for i in range(1, 2) for j in range(1, 50, 2)],
            'vpn_pool': [f'192.168.100.{i}' for i in range(1, 200, 3)]
        }
    
    def _generate_external_ips(self):
        """Generate external IP addresses with reputation scores"""
        return {
            'clean_residential': {
                'ips': [f"203.0.113.{i}" for i in range(1, 50)],
                'reputation_range': (0.0, 0.2)
            },
            'cloud_providers': {
                'ips': [f"198.51.100.{i}" for i in range(1, 50)],
                'reputation_range': (0.1, 0.4)
            },
            'suspicious_ranges': {
                'ips': [f"185.220.101.{i}" for i in range(1, 50)],
                'reputation_range': (0.5, 0.8)
            },
            'known_malicious': {
                'ips': [f"45.33.32.{i}" for i in range(1, 30)],
                'reputation_range': (0.8, 1.0)
            }
        }
    
    def generate_legitimate_session(self):
        """Generate a realistic legitimate user session"""
        user = random.choice(self.users)
        now = datetime.now()
        
        # Determine if this is during work hours
        current_hour = now.hour
        is_weekend = now.weekday() >= 5
        
        # Check if user would typically be working now
        work_start, work_end = user['work_hours']
        in_work_hours = work_start <= current_hour <= work_end and not is_weekend
        
        # Weekend/off-hours access based on user profile
        if not in_work_hours:
            if random.random() > user['weekend_access']:
                return None  # User wouldn't access now
        
        # Choose access location and IP
        if user['vpn_usage'] > random.random():
            location = 'vpn_pool'
            source_ip = random.choice(self.corporate_ips['vpn_pool'])
            ip_category = 'clean_residential'
        else:
            location = random.choice(user['preferred_locations'])
            if location in self.corporate_ips:
                source_ip = random.choice(self.corporate_ips[location])
                ip_category = 'clean_residential'
            else:
                ip_category = 'clean_residential'
                source_ip = random.choice(self.external_ips[ip_category]['ips'])
        
        # Generate session characteristics
        duration_min, duration_max = user['typical_duration']
        packet_min, packet_max = user['packet_size_range']
        
        # Small chance of authentication failure even for legitimate users
        will_fail = random.random() < user['failure_rate']
        failed_attempts = random.randint(1, 3) if will_fail else 0
        
        session = {
            'timestamp': now.isoformat(),
            'username': user['username'],
            'user_role': user['role'],
            'source_ip': source_ip,
            'ip_reputation_score': random.uniform(*self.external_ips[ip_category]['reputation_range']),
            'network_packet_size': random.randint(packet_min, packet_max),
            'session_duration': random.randint(duration_min, duration_max),
            'login_attempts': failed_attempts + 1,
            'failed_logins': failed_attempts,
            'unusual_time_access': 0 if in_work_hours else 1,
            'protocol_type': 'TCP',
            'encryption_used': 'AES',
            'browser_type': random.choice(['Chrome', 'Firefox', 'Safari', 'Edge']),
            'session_type': 'legitimate',
            'location': location,
            'department': user['department'],
            'data_source': 'corporate_vpn_logs'
        }
        
        return session
    
    def generate_attack_session(self, attack_type='external_attacker'):
        """Generate a realistic attack session"""
        threat = self.threat_actors[attack_type]
        now = datetime.now()
        
        # Choose target username
        if attack_type == 'insider_threat':
            # Target real user account
            target_user = random.choice(self.users)
            username = target_user['username'] + '_backup'
        elif attack_type == 'credential_stuffing':
            # Try common usernames
            username = random.choice(['admin', 'administrator', 'user', 'test', 'guest'])
        else:
            # External attacker trying to guess
            username = random.choice(['admin', 'root', 'administrator', 'sysadmin'])
        
        # Choose malicious IP
        if attack_type == 'insider_threat':
            # Might come from corporate network
            if random.random() < 0.3:
                source_ip = random.choice(self.corporate_ips['office_main'])
                ip_category = 'clean_residential'
            else:
                ip_category = 'suspicious_ranges'
                source_ip = random.choice(self.external_ips[ip_category]['ips'])
        else:
            ip_category = random.choice(['suspicious_ranges', 'known_malicious'])
            source_ip = random.choice(self.external_ips[ip_category]['ips'])
        
        # Attack characteristics
        duration_min, duration_max = threat['duration_range']
        failure_rate = threat['failure_rate']
        
        # High failure rate for attacks
        total_attempts = random.randint(3, 15)
        failed_attempts = int(total_attempts * failure_rate)
        successful_attempts = total_attempts - failed_attempts
        
        # Unusual packet sizes for attacks
        if threat['packet_anomalies']:
            packet_size = random.choice([64, 128, 1400, 1500])  # Suspicious sizes
        else:
            packet_size = random.randint(200, 800)
        
        session = {
            'timestamp': now.isoformat(),
            'username': username,
            'user_role': 'Unknown',
            'source_ip': source_ip,
            'ip_reputation_score': random.uniform(*self.external_ips[ip_category]['reputation_range']),
            'network_packet_size': packet_size,
            'session_duration': random.randint(duration_min, duration_max),
            'login_attempts': total_attempts,
            'failed_logins': failed_attempts,
            'unusual_time_access': 1 if now.hour < 6 or now.hour > 22 else random.randint(0, 1),
            'protocol_type': random.choice(['TCP', 'UDP']),
            'encryption_used': random.choice(['DES', 'None', 'AES']),
            'browser_type': random.choice(['Unknown', 'Chrome', 'Firefox']),
            'session_type': 'attack',
            'attack_type': attack_type,
            'location': 'external',
            'data_source': f'{attack_type}_detection'
        }
        
        return session

class DataFeedSimulator:
    """Simulates multiple data sources feeding into the detection system"""
    
    def __init__(self, api_key, api_endpoint="http://localhost:5000/predict"):
        self.session_generator = CorporateSessionGenerator()
        self.api_key = api_key
        self.api_endpoint = api_endpoint
        self.running = False
        self.feeds = {}
        
    def start_siem_feed(self, interval_seconds=30):
        """Simulate SIEM log feed - regular corporate sessions"""
        def siem_worker():
            while self.running:
                try:
                    # Generate 1-3 legitimate sessions
                    for _ in range(random.randint(1, 3)):
                        session = self.session_generator.generate_legitimate_session()
                        if session:
                            self._send_to_detection_engine(session, source="SIEM")
                    
                    time.sleep(interval_seconds + random.uniform(-5, 5))  # Add jitter
                    
                except Exception as e:
                    print(f"[SIEM_FEED_ERROR] {e}")
                    time.sleep(interval_seconds)
        
        self.feeds['siem'] = threading.Thread(target=siem_worker, daemon=True)
        self.feeds['siem'].start()
        print(f"[SIEM_FEED] Started - generating sessions every {interval_seconds}s")
    
    def start_honeypot_feed(self, interval_seconds=120):
        """Simulate honeypot detecting attacks"""
        def honeypot_worker():
            while self.running:
                try:
                    # Generate attack sessions
                    attack_type = random.choice(['external_attacker', 'credential_stuffing'])
                    session = self.session_generator.generate_attack_session(attack_type)
                    self._send_to_detection_engine(session, source="HONEYPOT")
                    
                    time.sleep(interval_seconds + random.uniform(-30, 30))
                    
                except Exception as e:
                    print(f"[HONEYPOT_FEED_ERROR] {e}")
                    time.sleep(interval_seconds)
        
        self.feeds['honeypot'] = threading.Thread(target=honeypot_worker, daemon=True)
        self.feeds['honeypot'].start()
        print(f"[HONEYPOT_FEED] Started - generating attacks every {interval_seconds}s")
    
    def start_vpn_feed(self, interval_seconds=45):
        """Simulate VPN server logs"""
        def vpn_worker():
            while self.running:
                try:
                    # VPN sessions tend to be longer, more remote
                    session = self.session_generator.generate_legitimate_session()
                    if session and random.random() < 0.8:  # 80% are VPN sessions
                        session['data_source'] = 'vpn_server_logs'
                        session['encryption_used'] = 'AES'  # VPN always encrypted
                        self._send_to_detection_engine(session, source="VPN")
                    
                    time.sleep(interval_seconds + random.uniform(-10, 10))
                    
                except Exception as e:
                    print(f"[VPN_FEED_ERROR] {e}")
                    time.sleep(interval_seconds)
        
        self.feeds['vpn'] = threading.Thread(target=vpn_worker, daemon=True)
        self.feeds['vpn'].start()
        print(f"[VPN_FEED] Started - generating VPN sessions every {interval_seconds}s")
    
    def start_network_monitor_feed(self, interval_seconds=60):
        """Simulate network monitoring detecting unusual traffic"""
        def network_worker():
            while self.running:
                try:
                    # Occasionally detect suspicious network patterns
                    if random.random() < 0.3:  # 30% chance of suspicious activity
                        session = self.session_generator.generate_attack_session('insider_threat')
                        session['data_source'] = 'network_monitoring'
                        self._send_to_detection_engine(session, source="NETWORK_MONITOR")
                    else:
                        # Normal network session
                        session = self.session_generator.generate_legitimate_session()
                        if session:
                            session['data_source'] = 'network_monitoring'
                            self._send_to_detection_engine(session, source="NETWORK_MONITOR")
                    
                    time.sleep(interval_seconds + random.uniform(-15, 15))
                    
                except Exception as e:
                    print(f"[NETWORK_MONITOR_ERROR] {e}")
                    time.sleep(interval_seconds)
        
        self.feeds['network'] = threading.Thread(target=network_worker, daemon=True)
        self.feeds['network'].start()
        print(f"[NETWORK_MONITOR] Started - analyzing traffic every {interval_seconds}s")
    
    def _send_to_detection_engine(self, session_data, source="UNKNOWN"):
        """Send session data to the ML detection engine"""
        try:
            # Convert to format expected by detection API
            payload = self._format_for_api(session_data)
            
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(self.api_endpoint, json=payload, headers=headers, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                anomaly_detected = result.get('anomaly', 0)
                risk_score = result.get('risk_score', 0)
                
                status = "🚨 ATTACK" if anomaly_detected else "✅ NORMAL"
                print(f"[{source}] {status} | User: {session_data['username']} | IP: {session_data['source_ip']} | Risk: {risk_score:.2f}")
                
                # Log high-risk detections
                if anomaly_detected:
                    self._log_security_alert(session_data, result, source)
                    
            else:
                print(f"[{source}_ERROR] API returned {response.status_code}: {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"[{source}_NETWORK_ERROR] Failed to send data: {e}")
        except Exception as e:
            print(f"[{source}_ERROR] Unexpected error: {e}")
    
    def _format_for_api(self, session_data):
        """Convert session data to API format"""
        # Map browser types to one-hot encoding
        browser_mapping = {
            'Chrome': {'browser_type_Chrome': 1, 'browser_type_Firefox': 0, 'browser_type_Safari': 0, 'browser_type_Edge': 0, 'browser_type_Unknown': 0},
            'Firefox': {'browser_type_Chrome': 0, 'browser_type_Firefox': 1, 'browser_type_Safari': 0, 'browser_type_Edge': 0, 'browser_type_Unknown': 0},
            'Safari': {'browser_type_Chrome': 0, 'browser_type_Firefox': 0, 'browser_type_Safari': 1, 'browser_type_Edge': 0, 'browser_type_Unknown': 0},
            'Edge': {'browser_type_Chrome': 0, 'browser_type_Firefox': 0, 'browser_type_Safari': 0, 'browser_type_Edge': 1, 'browser_type_Unknown': 0},
            'Unknown': {'browser_type_Chrome': 0, 'browser_type_Firefox': 0, 'browser_type_Safari': 0, 'browser_type_Edge': 0, 'browser_type_Unknown': 1}
        }
        
        # Map protocol types
        protocol_mapping = {
            'TCP': {'protocol_type_TCP': 1, 'protocol_type_UDP': 0, 'protocol_type_ICMP': 0},
            'UDP': {'protocol_type_TCP': 0, 'protocol_type_UDP': 1, 'protocol_type_ICMP': 0},
            'ICMP': {'protocol_type_TCP': 0, 'protocol_type_UDP': 0, 'protocol_type_ICMP': 1}
        }
        
        # Map encryption
        encryption_mapping = {
            'AES': {'encryption_used_AES': 1, 'encryption_used_DES': 0},
            'DES': {'encryption_used_AES': 0, 'encryption_used_DES': 1},
            'None': {'encryption_used_AES': 0, 'encryption_used_DES': 0}
        }
        
        # Build API payload
        payload = {
            'network_packet_size': session_data['network_packet_size'],
            'login_attempts': session_data['login_attempts'],
            'session_duration': session_data['session_duration'],
            'ip_reputation_score': session_data['ip_reputation_score'],
            'failed_logins': session_data['failed_logins'],
            'unusual_time_access': session_data['unusual_time_access'],
            'user_role': session_data.get('user_role', 'Viewer'),
            'profile_used': f"{session_data.get('user_role', 'Viewer')}-Medium"
        }
        
        # Add one-hot encodings
        payload.update(browser_mapping.get(session_data['browser_type'], browser_mapping['Unknown']))
        payload.update(protocol_mapping.get(session_data['protocol_type'], protocol_mapping['TCP']))
        payload.update(encryption_mapping.get(session_data['encryption_used'], encryption_mapping['AES']))
        
        return payload
    
    def _log_security_alert(self, session_data, detection_result, source):
        """Log security alerts to file"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'source_feed': source,
            'session_data': session_data,
            'detection_result': detection_result,
            'severity': 'HIGH' if detection_result.get('risk_score', 0) > 0.8 else 'MEDIUM'
        }
        
        # Ensure alerts directory exists
        os.makedirs('logs/security_alerts', exist_ok=True)
        
        # Write to daily alert log
        date_str = datetime.now().strftime('%Y-%m-%d')
        alert_file = f'logs/security_alerts/alerts_{date_str}.json'
        
        with open(alert_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def start_all_feeds(self):
        """Start all data feeds to simulate a real environment"""
        self.running = True
        
        print("🚀 Starting Real-World Data Feed Simulation...")
        print("=" * 60)
        
        # Start different data sources
        self.start_siem_feed(interval_seconds=25)      # Corporate sessions
        self.start_vpn_feed(interval_seconds=35)       # VPN access
        self.start_honeypot_feed(interval_seconds=90)  # Attack detection
        self.start_network_monitor_feed(interval_seconds=50)  # Network monitoring
        
        print("=" * 60)
        print("📡 All data feeds active! Sessions will be automatically sent to ML engine.")
        print("📊 Monitor /dashboard and /ml-performance to see real-time results.")
        print("🛑 Press Ctrl+C to stop all feeds.")
        
    def stop_all_feeds(self):
        """Stop all data feeds"""
        self.running = False
        print("\n🛑 Stopping all data feeds...")
        
        for feed_name, thread in self.feeds.items():
            if thread.is_alive():
                print(f"   Stopping {feed_name} feed...")
        
        print("✅ All data feeds stopped.")