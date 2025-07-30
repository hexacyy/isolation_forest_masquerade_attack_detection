# fix_data_feeds_integration.py
"""
Script to fix data feeds integration with behavioral analysis
"""

import os
import sys
import subprocess

def check_integration_status():
    """Check current integration status"""
    print("🔍 Checking Data Feeds Integration Status")
    print("=" * 50)
    
    # Check if data feeds are sending to correct endpoint
    try:
        with open('data_feeds/session_generator.py', 'r') as f:
            content = f.read()
            
        issues = []
        fixes = []
        
        # Check if _format_for_api includes user_role
        if "'user_role':" not in content:
            issues.append("❌ Data feeds not sending user_role (required for behavioral analysis)")
            fixes.append("Add user_role to API payload")
        else:
            print("✅ Data feeds include user_role")
        
        # Check if behavioral results are displayed
        if "behavioral_analysis" not in content:
            issues.append("❌ Data feeds not displaying behavioral analysis results")
            fixes.append("Update logging to show behavioral context")
        else:
            print("✅ Data feeds show behavioral results")
        
        # Check API endpoint
        if "http://localhost:5000/predict" in content:
            print("✅ Data feeds calling correct prediction endpoint")
        else:
            issues.append("❌ Data feeds might be calling wrong endpoint")
            fixes.append("Verify API endpoint is /predict")
        
        return issues, fixes
        
    except FileNotFoundError:
        print("❌ data_feeds/session_generator.py not found")
        return ["Missing session generator"], ["Create session generator file"]

def test_prediction_endpoint():
    """Test if prediction endpoint works with behavioral analysis"""
    print("\n🧪 Testing Prediction Endpoint")
    print("-" * 30)
    
    test_data = {
        'user_role': 'Viewer',
        'network_packet_size': 400,
        'session_duration': 1800,
        'login_attempts': 1,
        'failed_logins': 0,
        'ip_reputation_score': 0.1,
        'unusual_time_access': 0,
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
    }
    
    import json
    import requests
    
    try:
        # Get API key
        sys.path.append(os.getcwd())
        from config import API_KEY
        
        headers = {
            'Authorization': f'Bearer {API_KEY}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post('http://localhost:5000/predict', 
                               json=test_data, 
                               headers=headers, 
                               timeout=5)
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Prediction endpoint responding")
            
            # Check if behavioral analysis is included
            if 'behavioral_analysis' in result:
                behavioral = result['behavioral_analysis']
                print(f"✅ Behavioral analysis working:")
                print(f"    Profile: {behavioral.get('profile_used', 'Unknown')}")
                print(f"    Risk Level: {behavioral.get('risk_level', 'Unknown')}")
                print(f"    Deviation: {behavioral.get('deviation_score', 0):.2f}")
                return True
            else:
                print("❌ No behavioral analysis in response")
                return False
                
        else:
            print(f"❌ Prediction endpoint error: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def check_database_records():
    """Check if predictions are being saved to database"""
    print("\n🗄️ Checking Database Records")
    print("-" * 30)
    
    import sqlite3
    from datetime import datetime
    
    # Check recent predictions
    current_month = datetime.now().strftime("%Y%m")
    db_path = f"prediction_logs_{current_month}.db"
    
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} not found")
        return False
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Check predictions table
            cursor.execute("SELECT COUNT(*) FROM predictions")
            prediction_count = cursor.fetchone()[0]
            print(f"📊 Total predictions in database: {prediction_count}")
            
            # Check recent behavioral predictions
            cursor.execute("""
                SELECT COUNT(*) FROM predictions 
                WHERE behavioral_risk IS NOT NULL 
                AND behavioral_risk != 'UNKNOWN'
                AND profile_used IS NOT NULL
                AND profile_used != 'Unknown'
            """)
            behavioral_count = cursor.fetchone()[0]
            print(f"🧠 Predictions with behavioral analysis: {behavioral_count}")
            
            if behavioral_count > 0:
                # Show recent behavioral predictions
                cursor.execute("""
                    SELECT timestamp, behavioral_risk, profile_used, deviation_score 
                    FROM predictions 
                    WHERE behavioral_risk IS NOT NULL 
                    ORDER BY timestamp DESC 
                    LIMIT 3
                """)
                
                print("📋 Recent predictions with behavioral analysis:")
                for row in cursor.fetchall():
                    timestamp, risk, profile, deviation = row
                    print(f"    {timestamp[:19]} | {risk} | {profile} | {deviation:.2f}σ")
                
                return True
            else:
                print("❌ No behavioral analysis data found in database")
                return False
                
    except Exception as e:
        print(f"❌ Database check failed: {e}")
        return False

def start_test_data_feed():
    """Start a test data feed to verify integration"""
    print("\n🚀 Starting Test Data Feed")
    print("-" * 30)
    
    try:
        sys.path.append(os.getcwd())
        sys.path.append('data_feeds')
        
        from session_generator import DataFeedSimulator
        from config import API_KEY
        
        # Create test simulator
        simulator = DataFeedSimulator(API_KEY, "http://localhost:5000/predict")
        
        print("✅ Data feed simulator created")
        
        # Generate and send test sessions
        print("📡 Generating test sessions...")
        
        # Test legitimate session
        legit_session = simulator.session_generator.generate_legitimate_session()
        if legit_session:
            print("  🟢 Sending legitimate session...")
            simulator._send_to_detection_engine(legit_session, source="TEST_LEGIT")
        
        # Test attack session
        attack_session = simulator.session_generator.generate_attack_session('external_attacker')
        if attack_session:
            print("  🔴 Sending attack session...")
            simulator._send_to_detection_engine(attack_session, source="TEST_ATTACK")
        
        print("✅ Test sessions sent - check console output and database")
        return True
        
    except Exception as e:
        print(f"❌ Test data feed failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main diagnostic and fix function"""
    print("🔧 Data Feeds Integration Diagnostic & Fix")
    print("=" * 60)
    
    # Step 1: Check integration status
    issues, fixes = check_integration_status()
    
    if issues:
        print(f"\n⚠️ Found {len(issues)} integration issues:")
        for issue in issues:
            print(f"  {issue}")
        
        print(f"\n🔧 Recommended fixes:")
        for fix in fixes:
            print(f"  • {fix}")
    
    # Step 2: Test prediction endpoint
    print("\n" + "=" * 60)
    endpoint_works = test_prediction_endpoint()
    
    # Step 3: Check database
    print("\n" + "=" * 60)
    db_has_data = check_database_records()
    
    # Step 4: Run test data feed
    print("\n" + "=" * 60)
    test_feed_works = start_test_data_feed()
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 Integration Status Summary:")
    print(f"  Prediction Endpoint: {'✅ Working' if endpoint_works else '❌ Issues'}")
    print(f"  Database Recording: {'✅ Working' if db_has_data else '❌ Issues'}")  
    print(f"  Data Feed Test: {'✅ Working' if test_feed_works else '❌ Issues'}")
    
    if endpoint_works and test_feed_works:
        print("\n🎉 Integration is working! Data feeds should be recording behavioral analysis.")
        print("\n📝 To verify continuous operation:")
        print("  1. Start your Flask app: python app.py")
        print("  2. Start data feeds: python -c 'from data_feeds.session_generator import *; # start feeds'")
        print("  3. Monitor database: watch -n 5 'sqlite3 prediction_logs_202507.db \"SELECT COUNT(*) FROM predictions\"'")
    else:
        print("\n❌ Integration issues detected. Please check the error messages above.")
        
        if not endpoint_works:
            print("\n🔧 Fix prediction endpoint:")
            print("  1. Ensure Flask app is running: python app.py")
            print("  2. Check behavioral_analyzer.py is in project root")
            print("  3. Verify prediction route uses behavioral analysis")
        
        if not test_feed_works:
            print("\n🔧 Fix data feeds:")
            print("  1. Check data_feeds/session_generator.py exists")
            print("  2. Verify API_KEY in config.py")
            print("  3. Update _format_for_api to include user_role")

if __name__ == "__main__":
    main()