"""
SecureAudit-AI — Session Data Generator (for Module 3)
Simulates many "audit sessions" - each session represents one
audit event on the file at some point in time, under some
modification/corruption/attack conditions. Most sessions are
"normal" (low tampering rates); a few are deliberately
"anomalous" (a simulated compromised node under heavy attack).

Only OBSERVABLE aggregate features (things a real auditor could
actually measure, without ground truth) are used as model input.
The true_anomaly label is kept ONLY for validation/reporting -
never fed into the unsupervised model itself.
"""

import os
import sys
import random
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from partition.partition import FilePartitionManager
from features.metadata_tracker import MetadataTracker
from simulation.modification_simulator import ModificationSimulator
from simulation.corruption_simulator import CorruptionSimulator
from simulation.attack_simulator import AttackSimulator


def run_one_session(file_path, mod_rate, corrupt_rate, attack_rate, seed, is_anomalous):
    """Runs one audit session, returns an aggregate observable feature row."""
    manager = FilePartitionManager()
    info = manager.partition_file(file_path)
    info = MetadataTracker.initialize(info)

    ModificationSimulator.simulate(info, rate=mod_rate, seed=seed)
    CorruptionSimulator.simulate(info, rate=corrupt_rate, seed=seed + 1)
    AttackSimulator.simulate(info, rate=attack_rate)

    trust_scores = []
    stability_scores = []
    modified_flags = []
    challenge_counts = []

    for block in info["blocks"]:
        for sub in block["sub_blocks"]:
            trust_scores.append(sub["trust_score"])
            stability_scores.append(MetadataTracker.calculate_stability(sub))
            modified_flags.append(sub["modified"])
            challenge_counts.append(sub["challenge_count"])

    n = len(trust_scores)

    return {
        "avg_trust_score": sum(trust_scores) / n,
        "avg_stability_index": sum(stability_scores) / n,
        "fraction_modified": sum(modified_flags) / n,
        "avg_challenge_count": sum(challenge_counts) / n,
        "pct_low_trust": sum(1 for t in trust_scores if t < 80) / n,
        "true_anomaly": int(is_anomalous),   # kept for validation only
        "mod_rate_used": mod_rate,
        "corrupt_rate_used": corrupt_rate,
        "attack_rate_used": attack_rate,
    }


def generate_session_dataset(file_path, num_normal=45, num_anomalous=5, seed=config.RANDOM_SEED):
    """
    Generates a mix of normal and anomalous audit sessions.
    Normal sessions: low tampering rates (typical day-to-day).
    Anomalous sessions: high tampering rates (e.g. compromised
    node, coordinated attack, storage failure event).
    """
    rng = random.Random(seed)
    sessions = []

    for i in range(num_normal):
        mod_rate = rng.uniform(0.01, 0.08)
        corrupt_rate = rng.uniform(0.001, 0.01)
        attack_rate = rng.uniform(0.001, 0.01)
        row = run_one_session(file_path, mod_rate, corrupt_rate, attack_rate,
                               seed=seed + i * 3, is_anomalous=False)
        sessions.append(row)
        print(f"Normal session {i+1}/{num_normal}: "
              f"mod={mod_rate:.3f} corrupt={corrupt_rate:.3f} attack={attack_rate:.3f}")

    for i in range(num_anomalous):
        mod_rate = rng.uniform(0.25, 0.45)
        corrupt_rate = rng.uniform(0.10, 0.25)
        attack_rate = rng.uniform(0.10, 0.25)
        row = run_one_session(file_path, mod_rate, corrupt_rate, attack_rate,
                               seed=seed + 1000 + i * 3, is_anomalous=True)
        sessions.append(row)
        print(f"ANOMALOUS session {i+1}/{num_anomalous}: "
              f"mod={mod_rate:.3f} corrupt={corrupt_rate:.3f} attack={attack_rate:.3f}")

    df = pd.DataFrame(sessions)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)  # shuffle
    return df


if __name__ == "__main__":
    file_path = os.path.join(config.DATASET_DIR, "sample.pdf")

    print("Generating audit session dataset (this will take a few minutes)...\n")
    dataset = generate_session_dataset(file_path, num_normal=45, num_anomalous=5)

    output_path = os.path.join(config.RESULTS_RAW_DIR, "session_data.csv")
    os.makedirs(config.RESULTS_RAW_DIR, exist_ok=True)
    dataset.to_csv(output_path, index=False)

    print(f"\nTotal sessions: {len(dataset)}")
    print(f"Normal: {(dataset['true_anomaly'] == 0).sum()}")
    print(f"Anomalous: {(dataset['true_anomaly'] == 1).sum()}")
    print(f"Saved to: {output_path}")