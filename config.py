import os
import joblib
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv("webhook.env")

# Database settings
APP_ROOT = os.getcwd()
DB_FILE = "users_v2.db"

# API settings
API_KEY = os.environ.get("API_KEY")

# Telegram settings  
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TELEGRAM_GROUPCHAT_ID = os.environ.get("TELEGRAM_GROUPCHAT_ID")

# Model settings
model = joblib.load("iso_forest_model_tuned.pkl")
scaler = joblib.load("scaler_tuned.pkl")

# Load baseline profiles
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
json_path = os.path.join(BASE_DIR, "test", "combined_baseline_profiles.json")

with open("test/combined_baseline_profiles.json", "r") as f:
    baseline_stats = json.load(f)

# Expected columns for the model
expected_columns = [
    'network_packet_size', 'login_attempts', 'session_duration',
    'ip_reputation_score', 'failed_logins', 'unusual_time_access',
    'protocol_type_ICMP', 'protocol_type_TCP', 'protocol_type_UDP',
    'encryption_used_AES', 'encryption_used_DES',
    'browser_type_Chrome', 'browser_type_Edge', 'browser_type_Firefox',
    'browser_type_Safari', 'browser_type_Unknown',
    'risk_score'
]

# Debug prints
print(f"[DEBUG] Loaded TELEGRAM_BOT_TOKEN: {bool(TELEGRAM_BOT_TOKEN)}")
print(f"[DEBUG] Loaded TELEGRAM_CHAT_ID: {TELEGRAM_CHAT_ID}")
print(f"[DEBUG] Loaded TELEGRAM_GROUPCHAT_ID: {TELEGRAM_GROUPCHAT_ID}")