import pandas as pd
import random
import json

# Load data and profiles
df = pd.read_csv("cybersecurity_intrusion_data.csv")

# Load baseline profiles
with open("baseline_profiles.json", "r") as f:
    baseline_profiles = json.load(f)

# Drop irrelevant columns if they exist
drop_cols = ['session_id', 'attack_detected']
for col in drop_cols:
    if col in df.columns:
        df = df.drop(columns=col)

# One-hot encode for internal use
categorical_cols = ['protocol_type', 'encryption_used', 'browser_type']
df_encoded = pd.get_dummies(df, columns=categorical_cols)
df_encoded = df_encoded.dropna()

# Sample function: generate example input based on traffic profile
def generate_sample_input(profile='Medium'):
    if profile not in baseline_profiles:
        profile = 'Medium'
    stats = baseline_profiles[profile]
    sample = {}
    for feature, values in stats.items():
        mean = values['mean']
        std = values['std']
        val = max(0, round(random.gauss(mean, std), 2))  # prevent negatives
        sample[feature] = val

    # Add some default one-hot fields
    sample.update({
        'protocol_type_TCP': 1,
        'protocol_type_UDP': 0,
        'protocol_type_ICMP': 0,
        'encryption_used_AES': 1,
        'encryption_used_DES': 0,
        'browser_type_Chrome': 1,
        'browser_type_Edge': 0,
        'browser_type_Firefox': 0,
        'browser_type_Safari': 0,
        'browser_type_Unknown': 0
    })

    # Calculate risk score
    sample['risk_score'] = (
        sample['ip_reputation_score'] * 0.5 +
        sample['failed_logins'] * 0.2 +
        sample['unusual_time_access'] * 0.3
    )

    return sample

# Generate example inputs for all three profiles
low_input = generate_sample_input('Low')
medium_input = generate_sample_input('Medium')
high_input = generate_sample_input('High')

# Create a dataframe to display
example_inputs_df = pd.DataFrame([low_input, medium_input, high_input], index=['Low', 'Medium', 'High'])

example_inputs_df.to_csv("submit_form_prefill_examples.csv", index=True)
print("✅ Sample prefill values saved to submit_form_prefill_examples.csv")

example_inputs_df.to_dict(orient='index')
