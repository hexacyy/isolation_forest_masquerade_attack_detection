import pandas as pd
import numpy as np
import json

# Load dataset
df = pd.read_csv("cybersecurity_intrusion_data.csv")

# Drop non-feature columns if they exist
drop_cols = ['session_id', 'attack_detected']
for col in drop_cols:
    if col in df.columns:
        df = df.drop(columns=col)

# One-hot encode categorical features
categorical_cols = ['protocol_type', 'encryption_used', 'browser_type']
df_encoded = pd.get_dummies(df, columns=categorical_cols)

# Fill or drop missing values (if any)
df_encoded = df_encoded.dropna()

# Define behavioural features to baseline
profile_features = [
    'network_packet_size',
    'login_attempts',
    'session_duration',
    'ip_reputation_score',
    'failed_logins',
    'unusual_time_access'
]

# Categorize sessions by traffic level using quantiles
df_encoded['traffic_level'] = pd.qcut(
    df_encoded['network_packet_size'],
    q=3,
    labels=['Low', 'Medium', 'High']
)

# Build baseline profile for each traffic level
baseline_profiles = {}
for level in ['Low', 'Medium', 'High']:
    group_df = df_encoded[df_encoded['traffic_level'] == level]
    stats = group_df[profile_features].describe().loc[['mean', 'std']].T
    baseline_profiles[level] = stats.to_dict(orient='index')

# Save to JSON
with open("baseline_profiles.json", "w") as f:
    json.dump(baseline_profiles, f, indent=4)

print("✅ Baseline profiles saved to baseline_profiles.json")
