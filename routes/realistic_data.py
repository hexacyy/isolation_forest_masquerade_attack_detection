"""
Integration plan for realistic data sources in your Flask app
Add these routes to make data meaningful instead of random numbers
"""

from flask import Blueprint, jsonify, request
import pandas as pd
import random
from datetime import datetime, timedelta
import ipaddress
import requests

# Create new blueprint for realistic data
realistic_data_bp = Blueprint('realistic_data', __name__, url_prefix='/api')

class RealisticDataProvider:
    def __init__(self):
        # Simulated threat intelligence feeds
        self.known_malicious_ips = [
            "45.33.32.156", "87.120.37.155", "185.220.101.32",
            "192.42.116.16", "198.98.51.189", "104.248.48.1"
        ]
        
        self.corporate_ips = [
            "203.0.113.1", "198.51.100.5", "192.0.2.146",
            "10.0.0.100", "172.16.0.50", "192.168.1.100"
        ]
        
        # User behavior baselines (from your existing profiles)
        self.user_baselines = {
            "john.admin@company.com": {
                "role": "Admin",
                "typical_hours": (8, 18),  # 8 AM to 6 PM
                "avg_session_duration": 3600,  # 1 hour
                "typical_packet_size": 1000,
                "failed_login_baseline": 0.5,
                "preferred_browser": "Chrome"
            },
            "mary.user@company.com": {
                "role": "Viewer", 
                "typical_hours": (9, 17),  # 9 AM to 5 PM
                "avg_session_duration": 1800,  # 30 minutes
                "typical_packet_size": 400,
                "failed_login_baseline": 0.2,
                "preferred_browser": "Firefox"
            }
        }

    def get_ip_reputation(self, ip_address):
        """Simulate real IP reputation lookup"""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Check against known lists
            if ip_address in self.known_malicious_ips:
                return {
                    "score": random.uniform(0.8, 1.0),
                    "category": "malicious",
                    "source": "Threat Intelligence Feed",
                    "last_seen": "2025-07-29",
                    "threat_types": ["botnet", "scanning"]
                }
            elif ip_address in self.corporate_ips or ip_obj.is_private:
                return {
                    "score": random.uniform(0.0, 0.1),
                    "category": "trusted",
                    "source": "Corporate IP Range",
                    "last_seen": None,
                    "threat_types": []
                }
            else:
                # Simulate external lookup
                return {
                    "score": random.uniform(0.2, 0.6),
                    "category": "unknown",
                    "source": "External WHOIS",
                    "last_seen": None,
                    "threat_types": []
                }
        except:
            return {"score": 0.5, "category": "invalid", "source": "error", "last_seen": None, "threat_types": []}

    def simulate_network_capture(self, duration_minutes=5):
        """Simulate real network packet capture data"""
        packets = []
        for _ in range(random.randint(50, 200)):  # Random number of packets
            packets.append({
                "timestamp": datetime.now() - timedelta(minutes=random.randint(0, duration_minutes)),
                "source_ip": random.choice(self.corporate_ips + ["203.0.113.10", "198.51.100.15"]),
                "dest_ip": "10.0.0.1",  # Corporate server
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                "size": random.randint(64, 1518),
                "flags": random.choice(["SYN", "ACK", "FIN", "PSH"])
            })
        
        # Calculate statistics
        avg_packet_size = sum(p["size"] for p in packets) / len(packets)
        protocol_dist = {}
        for p in packets:
            protocol_dist[p["protocol"]] = protocol_dist.get(p["protocol"], 0) + 1
        
        return {
            "total_packets": len(packets),
            "avg_packet_size": round(avg_packet_size, 2),
            "protocol_distribution": protocol_dist,
            "capture_duration": duration_minutes,
            "suspicious_patterns": self._detect_suspicious_patterns(packets)
        }
    
    def _detect_suspicious_patterns(self, packets):
        """Detect suspicious patterns in packet data"""
        patterns = []
        
        # Check for port scanning (many different destinations)
        unique_ports = len(set(p.get("dest_port", 80) for p in packets))
        if unique_ports > 10:
            patterns.append("port_scanning")
        
        # Check for unusual packet sizes
        large_packets = [p for p in packets if p["size"] > 1400]
        if len(large_packets) / len(packets) > 0.3:
            patterns.append("large_payload_transfer")
        
        return patterns

    def get_authentication_logs(self, username, hours_back=24):
        """Simulate authentication server logs"""
        logs = []
        start_time = datetime.now() - timedelta(hours=hours_back)
        
        baseline = self.user_baselines.get(username, self.user_baselines["mary.user@company.com"])
        
        # Generate realistic login attempts
        for hour in range(hours_back):
            current_time = start_time + timedelta(hours=hour)
            
            # Users typically log in during their work hours
            if baseline["typical_hours"][0] <= current_time.hour <= baseline["typical_hours"][1]:
                if random.random() < 0.7:  # 70% chance of login during work hours
                    success = random.random() > baseline["failed_login_baseline"]
                    logs.append({
                        "timestamp": current_time.isoformat(),
                        "username": username,
                        "success": success,
                        "source_ip": random.choice(self.corporate_ips),
                        "user_agent": f"{baseline['preferred_browser']}/91.0.4472.124",
                        "session_duration": baseline["avg_session_duration"] + random.randint(-600, 600)
                    })
        
        return logs

# API Routes
@realistic_data_bp.route('/ip-reputation/<ip_address>')
def ip_reputation_lookup(ip_address):
    """API endpoint for IP reputation lookup"""
    provider = RealisticDataProvider()
    reputation = provider.get_ip_reputation(ip_address)
    return jsonify(reputation)

@realistic_data_bp.route('/network-capture')
def network_capture():
    """API endpoint for network packet analysis"""
    duration = request.args.get('duration', 5, type=int)
    provider = RealisticDataProvider()
    capture_data = provider.simulate_network_capture(duration)
    return jsonify(capture_data)

@realistic_data_bp.route('/auth-logs/<username>')
def authentication_logs(username):
    """API endpoint for authentication log analysis"""
    hours = request.args.get('hours', 24, type=int)
    provider = RealisticDataProvider()
    logs = provider.get_authentication_logs(username, hours)
    return jsonify(logs)

@realistic_data_bp.route('/user-baseline/<username>')
def user_baseline(username):
    """API endpoint to get user behavioral baseline"""
    provider = RealisticDataProvider()
    baseline = provider.user_baselines.get(username)
    if baseline:
        return jsonify(baseline)
    else:
        return jsonify({"error": "User not found"}), 404

@realistic_data_bp.route('/simulate-session')
def simulate_realistic_session():
    """Generate a complete realistic session for testing"""
    provider = RealisticDataProvider()
    
    # Pick random user and scenario
    username = random.choice(list(provider.user_baselines.keys()))
    baseline = provider.user_baselines[username]
    
    # Determine if this should be an attack (30% chance)
    is_attack = random.random() < 0.3
    
    if is_attack:
        # Generate masquerade attack
        source_ip = random.choice(provider.known_malicious_ips)
        failed_logins = random.randint(2, 6)
        login_attempts = failed_logins + random.randint(1, 2)
        
        # Unusual timing
        hour = random.choice([2, 3, 22, 23])
        timestamp = datetime.now().replace(hour=hour)
        
        session_duration = random.randint(60, 300)  # Short session
        packet_size = baseline["typical_packet_size"] * random.uniform(0.3, 2.5)  # Deviation
        
    else:
        # Generate legitimate session
        source_ip = random.choice(provider.corporate_ips)
        failed_logins = 0 if random.random() > baseline["failed_login_baseline"] else 1
        login_attempts = failed_logins + 1
        
        # Normal work hours
        hour = random.randint(baseline["typical_hours"][0], baseline["typical_hours"][1])
        timestamp = datetime.now().replace(hour=hour)
        
        session_duration = baseline["avg_session_duration"] + random.randint(-300, 300)
        packet_size = baseline["typical_packet_size"] + random.randint(-100, 100)
    
    # Get IP reputation
    ip_reputation = provider.get_ip_reputation(source_ip)
    
    session_data = {
        "username": username,
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "ip_reputation_score": ip_reputation["score"],
        "ip_reputation_details": ip_reputation,
        "login_attempts": login_attempts,
        "failed_logins": failed_logins,
        "session_duration": session_duration,
        "network_packet_size": int(packet_size),
        "protocol_type": "TCP",  # Most common
        "encryption_used": "AES" if not is_attack else random.choice(["DES", "None"]),
        "browser_type": baseline["preferred_browser"] if not is_attack else "Unknown",
        "unusual_time_access": 1 if (hour < 9 or hour > 17) else 0,
        "is_masquerade": 1 if is_attack else 0,  # Ground truth
        "scenario_type": "masquerade_attack" if is_attack else "legitimate_session",
        "data_sources": {
            "ip_reputation": "Threat Intelligence API",
            "auth_logs": "Corporate Authentication Server", 
            "network_data": "Packet Capture Analysis",
            "user_profile": "Behavioral Baseline Database"
        }
    }
    
    return jsonify(session_data)

