"""
SecureAudit-AI — Training Data Generator
Runs multiple simulation rounds (different rates, different
seeds) on the sample file to build a larger, more varied
labeled dataset than a single run would produce. This is
what Module 1 (risk scorer) actually trains on.

Each row is also tagged with "tamper_type" (modification,
corruption, attack, or none) so we can analyze detection
performance separately per tamper type later.
"""

import os
import sys
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from partition.partition import FilePartitionManager
from features.metadata_tracker import MetadataTracker
from features.feature_extractor import FeatureExtractor
from simulation.modification_simulator import ModificationSimulator
from simulation.corruption_simulator import CorruptionSimulator
from simulation.attack_simulator import AttackSimulator


def generate_one_round(file_path, mod_rate, corrupt_rate, attack_rate, seed):
    """Runs one full partition -> simulate -> extract round, returns a DataFrame."""
    manager = FilePartitionManager()
    info = manager.partition_file(file_path)
    info = MetadataTracker.initialize(info)

    modified = ModificationSimulator.simulate(info, rate=mod_rate, seed=seed)
    corrupted = CorruptionSimulator.simulate(info, rate=corrupt_rate, seed=seed + 1)
    attacked = AttackSimulator.simulate(info, rate=attack_rate)

    all_tampered = set(modified) | set(corrupted) | set(attacked)

    df = FeatureExtractor.extract(info, all_tampered)

    modified_set = set(modified)
    corrupted_set = set(corrupted)
    attacked_set = set(attacked)

    def get_type(row):
        key = (row["block_id"], row["sub_block_id"])
        if key in modified_set:
            return "modification"
        elif key in corrupted_set:
            return "corruption"
        elif key in attacked_set:
            return "attack"
        else:
            return "none"

    df["tamper_type"] = df.apply(get_type, axis=1)

    return df


def generate_training_dataset(file_path, num_rounds=10):
    """
    Runs several rounds with varying rates/seeds and combines
    them into one larger training dataset.
    """
    all_dfs = []

    rate_combinations = [
        (0.01, 0.005, 0.005),
        (0.05, 0.02, 0.02),
        (0.10, 0.03, 0.02),
        (0.20, 0.05, 0.03),
    ]

    for round_num in range(num_rounds):
        mod_rate, corrupt_rate, attack_rate = rate_combinations[round_num % len(rate_combinations)]
        seed = config.RANDOM_SEED + round_num * 10

        df = generate_one_round(file_path, mod_rate, corrupt_rate, attack_rate, seed)
        df["round"] = round_num
        all_dfs.append(df)

        print(f"Round {round_num + 1}/{num_rounds}: mod={mod_rate}, corrupt={corrupt_rate}, "
              f"attack={attack_rate} -> {df['true_label'].sum()} tampered / {len(df)} total")

    combined = pd.concat(all_dfs, ignore_index=True)
    return combined


if __name__ == "__main__":
    file_path = os.path.join(config.DATASET_DIR, "sample.pdf")

    dataset = generate_training_dataset(file_path, num_rounds=10)

    output_path = os.path.join(config.RESULTS_RAW_DIR, "training_dataset.csv")
    os.makedirs(config.RESULTS_RAW_DIR, exist_ok=True)
    dataset.to_csv(output_path, index=False)

    print(f"\nTotal rows: {len(dataset)}")
    print(f"Total tampered: {dataset['true_label'].sum()}")
    print(f"Total untouched: {(dataset['true_label'] == 0).sum()}")
    print(f"\nBreakdown by tamper_type:")
    print(dataset["tamper_type"].value_counts())
    print(f"\nSaved to: {output_path}")