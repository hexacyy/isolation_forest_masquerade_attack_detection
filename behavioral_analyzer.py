# behavioral_analyzer.py
"""
Behavioral Deviation Analysis for Masquerade Detection
Integrates with combined_baseline_profiles.json to provide context-aware anomaly detection
"""

import json
import numpy as np
from typing import Dict, Tuple, List
from dataclasses import dataclass
from config import baseline_stats

@dataclass
class BehavioralScore:
    """Container for behavioral analysis results"""
    overall_deviation: float
    individual_deviations: Dict[str, float]
    risk_level: str
    confidence: str
    explanation: List[str]
    profile_used: str

class BehavioralAnalyzer:
    """Advanced behavioral analysis using statistical baselines"""
    
    def __init__(self):
        self.baselines = baseline_stats
        self.features = [
            'network_packet_size',
            'login_attempts', 
            'session_duration',
            'ip_reputation_score',
            'failed_logins',
            'unusual_time_access'
        ]
        
        # Deviation thresholds (in standard deviations)
        self.thresholds = {
            'LOW': 1.0,      # Within 1 standard deviation = normal
            'MEDIUM': 2.0,   # 1-2 std dev = mild anomaly  
            'HIGH': 3.0,     # 2-3 std dev = significant anomaly
            'CRITICAL': 4.0  # >3 std dev = severe anomaly
        }
    
    def determine_user_profile(self, session_data: Dict) -> str:
        """
        Determine the most appropriate baseline profile for a user
        Uses role + traffic level for maximum precision
        """
        user_role = session_data.get('user_role', 'Viewer')
        packet_size = session_data.get('network_packet_size', 500)
        
        # Classify traffic level based on packet size
        if packet_size < 400:
            traffic_level = 'Low'
        elif packet_size < 650:
            traffic_level = 'Medium'  
        else:
            traffic_level = 'High'
        
        # Try combined profile first (most specific)
        combined_profile = f"{user_role}-{traffic_level}"
        if combined_profile in self.baselines.get('role-traffic', {}):
            return combined_profile
        
        # Fallback to role profile
        if user_role in self.baselines.get('role_profiles', {}):
            return user_role
            
        # Final fallback to traffic profile
        if traffic_level in self.baselines.get('traffic_profiles', {}):
            return traffic_level
            
        return 'Medium'  # Default fallback
    
    def calculate_z_score(self, value: float, mean: float, std: float) -> float:
        """Calculate standardized z-score (how many std devs from mean)"""
        if std == 0:
            return 0.0
        return abs(value - mean) / std
    
    def calculate_feature_deviation(self, session_data: Dict, profile_data: Dict) -> Dict[str, float]:
        """Calculate deviation for each behavioral feature"""
        deviations = {}
        
        for feature in self.features:
            if feature in session_data and feature in profile_data:
                value = float(session_data[feature])
                baseline = profile_data[feature]
                
                mean = baseline['mean']
                std = baseline['std']
                
                z_score = self.calculate_z_score(value, mean, std)
                deviations[feature] = z_score
        
        return deviations
    
    def calculate_composite_score(self, deviations: Dict[str, float]) -> float:
        """
        Calculate weighted composite behavioral deviation score
        Higher weights for more indicative features
        """
        feature_weights = {
            'network_packet_size': 0.15,    # Moderate indicator
            'login_attempts': 0.10,         # Low weight (noisy)
            'session_duration': 0.25,       # High weight (very indicative)  
            'ip_reputation_score': 0.20,    # High weight (external threat)
            'failed_logins': 0.20,          # High weight (direct attack sign)
            'unusual_time_access': 0.10     # Moderate weight (context dependent)
        }
        
        weighted_score = 0.0
        total_weight = 0.0
        
        for feature, deviation in deviations.items():
            weight = feature_weights.get(feature, 0.1)
            weighted_score += deviation * weight
            total_weight += weight
        
        return weighted_score / total_weight if total_weight > 0 else 0.0
    
    def determine_risk_level(self, composite_score: float) -> Tuple[str, str]:
        """Determine risk level and confidence based on composite score"""
        
        if composite_score >= self.thresholds['CRITICAL']:
            return 'CRITICAL', 'HIGH'
        elif composite_score >= self.thresholds['HIGH']:
            return 'HIGH', 'HIGH'  
        elif composite_score >= self.thresholds['MEDIUM']:
            return 'MEDIUM', 'MEDIUM'
        elif composite_score >= self.thresholds['LOW']:
            return 'LOW', 'LOW'
        else:
            return 'NORMAL', 'HIGH'
    
    def generate_explanation(self, deviations: Dict[str, float], profile_used: str, 
                           risk_level: str) -> List[str]:
        """Generate human-readable explanation of behavioral anomalies"""
        explanations = []
        
        # Add profile context
        explanations.append(f"📊 BEHAVIORAL ANALYSIS: Using {profile_used} profile")
        
        # Analyze significant deviations
        significant_deviations = {k: v for k, v in deviations.items() if v >= 1.5}
        
        if not significant_deviations:
            explanations.append("✅ NORMAL BEHAVIOR: All metrics within expected range")
            return explanations
        
        # Sort by severity
        sorted_deviations = sorted(significant_deviations.items(), 
                                 key=lambda x: x[1], reverse=True)
        
        for feature, deviation in sorted_deviations[:3]:  # Top 3 anomalies
            severity = self._get_deviation_severity(deviation)
            explanation = self._get_feature_explanation(feature, deviation, severity)
            explanations.append(explanation)
        
        # Overall assessment
        if risk_level in ['HIGH', 'CRITICAL']:
            explanations.append(f"⚠️ MASQUERADE RISK: {len(significant_deviations)} behavioral anomalies detected")
        
        return explanations
    
    def _get_deviation_severity(self, deviation: float) -> str:
        """Get severity level for a deviation score"""
        if deviation >= 3.0:
            return 'SEVERE'
        elif deviation >= 2.0:
            return 'SIGNIFICANT'  
        elif deviation >= 1.5:
            return 'MODERATE'
        else:
            return 'MILD'
    
    def _get_feature_explanation(self, feature: str, deviation: float, severity: str) -> str:
        """Generate feature-specific explanation"""
        feature_messages = {
            'network_packet_size': f"📡 {severity} TRAFFIC ANOMALY: Packet size deviates {deviation:.1f}σ from normal",
            'session_duration': f"⏱️ {severity} SESSION ANOMALY: Duration deviates {deviation:.1f}σ from expected",
            'login_attempts': f"🔐 {severity} AUTH ANOMALY: Login pattern deviates {deviation:.1f}σ from baseline",
            'ip_reputation_score': f"🌐 {severity} IP ANOMALY: Reputation score deviates {deviation:.1f}σ from normal",
            'failed_logins': f"❌ {severity} LOGIN ANOMALY: Failure rate deviates {deviation:.1f}σ from expected",
            'unusual_time_access': f"🕐 {severity} TIMING ANOMALY: Access pattern deviates {deviation:.1f}σ from routine"
        }
        
        return feature_messages.get(feature, f"🔍 {severity} ANOMALY: {feature} deviates {deviation:.1f}σ")
    
    def analyze_behavior(self, session_data: Dict) -> BehavioralScore:
        """Main analysis function - returns comprehensive behavioral assessment"""
        
        # Step 1: Determine appropriate baseline profile
        profile_key = self.determine_user_profile(session_data)
        
        # Step 2: Get baseline data for the profile
        profile_data = None
        for profile_type in ['role-traffic', 'role_profiles', 'traffic_profiles']:
            if profile_key in self.baselines.get(profile_type, {}):
                profile_data = self.baselines[profile_type][profile_key]
                break
        
        if not profile_data:
            # Fallback to Medium traffic profile
            profile_data = self.baselines['traffic_profiles']['Medium']
            profile_key = 'Medium'
        
        # Step 3: Calculate individual feature deviations
        deviations = self.calculate_feature_deviation(session_data, profile_data)
        
        # Step 4: Calculate composite behavioral score
        composite_score = self.calculate_composite_score(deviations)
        
        # Step 5: Determine risk level and confidence
        risk_level, confidence = self.determine_risk_level(composite_score)
        
        # Step 6: Generate explanations
        explanations = self.generate_explanation(deviations, profile_key, risk_level)
        
        return BehavioralScore(
            overall_deviation=composite_score,
            individual_deviations=deviations,
            risk_level=risk_level,
            confidence=confidence,
            explanation=explanations,
            profile_used=profile_key
        )

# Integration helper functions
def enhance_prediction_with_behavioral_analysis(session_data: Dict, ml_result: Dict) -> Dict:
    """
    Enhance existing ML prediction with behavioral analysis
    To be integrated into routes/prediction.py
    """
    analyzer = BehavioralAnalyzer()
    behavioral_score = analyzer.analyze_behavior(session_data)
    
    # Combine ML and behavioral analysis
    ml_anomaly = ml_result.get('anomaly', 0)
    behavioral_risk = behavioral_score.risk_level
    
    # Enhanced decision logic
    if behavioral_risk in ['CRITICAL', 'HIGH'] or ml_anomaly == 1:
        final_decision = 1
        confidence = 'HIGH' if behavioral_risk in ['CRITICAL', 'HIGH'] else 'MEDIUM'
    elif behavioral_risk == 'MEDIUM':
        final_decision = 1 if ml_anomaly == 1 else 0
        confidence = 'MEDIUM'
    else:
        final_decision = ml_anomaly
        confidence = 'LOW' if ml_anomaly == 1 else 'HIGH'
    
    # Enhanced explanation
    enhanced_explanation = []
    
    if final_decision == 1:
        enhanced_explanation.append("🚨 MASQUERADE ATTACK DETECTED")
        enhanced_explanation.extend(behavioral_score.explanation)
        
        if ml_anomaly == 1:
            enhanced_explanation.append(f"🤖 ML MODEL: Isolation Forest confirms anomaly")
    else:
        enhanced_explanation.extend(behavioral_score.explanation)
    
    # Return enhanced result
    return {
        **ml_result,
        'final_decision': final_decision,
        'confidence': confidence,
        'behavioral_analysis': {
            'deviation_score': behavioral_score.overall_deviation,
            'risk_level': behavioral_score.risk_level,
            'profile_used': behavioral_score.profile_used,
            'individual_deviations': behavioral_score.individual_deviations
        },
        'explanation': ' | '.join(enhanced_explanation),
        'method_used': 'Enhanced ML + Behavioral Analysis'
    }

# Example usage and testing
if __name__ == "__main__":
    # Test with sample data
    analyzer = BehavioralAnalyzer()
    
    # Test case 1: Normal Viewer behavior
    normal_session = {
        'user_role': 'Viewer',
        'network_packet_size': 320,
        'session_duration': 800,
        'login_attempts': 1,
        'failed_logins': 0,
        'ip_reputation_score': 0.1,
        'unusual_time_access': 0
    }
    
    result = analyzer.analyze_behavior(normal_session)
    print("Normal Session Analysis:")
    print(f"Risk Level: {result.risk_level}")
    print(f"Deviation Score: {result.overall_deviation:.2f}")
    print("Explanations:")
    for exp in result.explanation:
        print(f"  - {exp}")
    print()
    
    # Test case 2: Suspicious Admin behavior (too short session)
    suspicious_session = {
        'user_role': 'Admin', 
        'network_packet_size': 1200,
        'session_duration': 120,  # Way too short for Admin
        'login_attempts': 5,      # Too many attempts
        'failed_logins': 3,       # Too many failures
        'ip_reputation_score': 0.7,  # Suspicious IP
        'unusual_time_access': 1
    }
    
    result = analyzer.analyze_behavior(suspicious_session)
    print("Suspicious Session Analysis:")
    print(f"Risk Level: {result.risk_level}")
    print(f"Deviation Score: {result.overall_deviation:.2f}")
    print("Explanations:")
    for exp in result.explanation:
        print(f"  - {exp}")