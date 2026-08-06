"""
SecureAudit-AI — Feature Extractor
Builds a (features, true_label) dataset from a partitioned,
simulated file. Each row represents one sub-block's state at
the time of "audit" - the features an ML model would see, and
the ground-truth label (was this sub-block actually tampered
with, from any of the three simulators?).
"""

import sys
import os
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from features.metadata_tracker import MetadataTracker


class FeatureExtractor:
    """Extracts ML-ready feature rows from a partitioned file."""

    @staticmethod
    def extract(partition_info, tampered_ids):
        """
        Args:
            partition_info: partitioned + metadata-initialized dict.
            tampered_ids: set/list of (block_id, sub_block_id) tuples that
                were genuinely tampered with (from any simulator combined).
                Used to assign the TRUE label - this is our ground truth,
                only available because WE ran the simulation.

        Returns:
            pandas.DataFrame with columns:
            block_id, sub_block_id, trust_score, stability_index,
            version, modified, challenge_count, verification_count,
            true_label (1 = tampered, 0 = untouched)
        """
        tampered_set = set(tampered_ids)
        rows = []

        for block in partition_info["blocks"]:
            for sub in block["sub_blocks"]:
                stability = MetadataTracker.calculate_stability(sub)
                key = (block["block_id"], sub["sub_block_id"])

                rows.append({
                    "block_id": block["block_id"],
                    "sub_block_id": sub["sub_block_id"],
                    "trust_score": sub["trust_score"],
                    "stability_index": stability,
                    "version": sub["version"],
                    "modified": int(sub["modified"]),
                    "challenge_count": sub["challenge_count"],
                    "verification_count": sub["verification_count"],
                    "true_label": 1 if key in tampered_set else 0,
                })

        return pd.DataFrame(rows)


if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager
    from simulation.modification_simulator import ModificationSimulator
    from simulation.corruption_simulator import CorruptionSimulator
    from simulation.attack_simulator import AttackSimulator
    import config

    test_file = sys.argv[1] if len(sys.argv) > 1 else None

    if test_file is None:
        print("Usage: python feature_extractor.py <path_to_file>")
    else:
        manager = FilePartitionManager()
        info = manager.partition_file(test_file)
        info = MetadataTracker.initialize(info)

        # Run all three simulators together, combine tampered IDs
        modified = ModificationSimulator.simulate(info, rate=0.05, seed=config.RANDOM_SEED)
        corrupted = CorruptionSimulator.simulate(info, rate=0.02, seed=config.RANDOM_SEED + 1)
        attacked = AttackSimulator.simulate(info, rate=0.02)

        all_tampered = set(modified) | set(corrupted) | set(attacked)

        df = FeatureExtractor.extract(info, all_tampered)

        print(f"Total rows: {len(df)}")
        print(f"Tampered (true_label=1): {df['true_label'].sum()}")
        print(f"Untouched (true_label=0): {(df['true_label'] == 0).sum()}")
        print(f"\nFirst 5 rows:\n{df.head()}")

        print(f"\nFeature summary:\n{df.describe()}")
        output_path = os.path.join(config.RESULTS_RAW_DIR, "sample_features.csv")
        os.makedirs(config.RESULTS_RAW_DIR, exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"\nSaved dataset to: {output_path}")