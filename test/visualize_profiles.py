import json
import matplotlib.pyplot as plt
import numpy as np
import os

# === Load baseline_profiles.json ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# json_path = os.path.join(BASE_DIR, "test", "baseline_profiles.json")
json_path = os.path.join(os.path.dirname(__file__), "baseline_profiles.json")


with open(json_path, "r") as f:
    profiles = json.load(f)

# === Features to visualize ===
features_to_plot = [
    'network_packet_size',
    'login_attempts',
    'session_duration',
    'ip_reputation_score'
]

# === Setup matplotlib grid ===
fig, axs = plt.subplots(nrows=2, ncols=2, figsize=(12, 8))
axs = axs.flatten()

# === Plot each feature ===
for idx, feature in enumerate(features_to_plot):
    means = []
    stds = []
    labels = []

    for profile in ['Low', 'Medium', 'High']:
        stats = profiles.get(profile, {})
        if feature in stats:
            labels.append(profile)
            means.append(stats[feature]['mean'])
            stds.append(stats[feature]['std'])

    x = np.arange(len(labels))
    axs[idx].bar(x, means, yerr=stds, capsize=8, color=['#85C1E9', '#73C6B6', '#F7DC6F'])
    axs[idx].set_title(f"{feature.replace('_', ' ').title()} (Mean ± Std Dev)", fontsize=11)
    axs[idx].set_xticks(x)
    axs[idx].set_xticklabels(labels)
    axs[idx].set_ylabel("Value")

# === Finalize ===
plt.tight_layout()
output_path = os.path.join(BASE_DIR, "profile_feature_distributions.png")
plt.savefig(output_path)
plt.show()

print(f"✅ Visualization saved as: {output_path}")
