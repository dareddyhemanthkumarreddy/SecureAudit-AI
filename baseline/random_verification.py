"""
SecureAudit-AI — Baseline: Random Verification
Randomly selects a fixed percentage of signed subsets for
verification, regardless of any risk signal. Classic PDP-style
sampling approach used as a comparison baseline.
"""

import random
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config


class RandomVerification:

    @staticmethod
    def select(partition_info, percentage=config.RANDOM_VERIFICATION_PERCENTAGE, seed=config.RANDOM_SEED):
        """Returns a random subset_ids sample, `percentage`% of all subsets."""
        rng = random.Random(seed)
        all_ids = [s["subset_id"] for s in partition_info["subsets"]]

        num_to_select = max(1, int(len(all_ids) * percentage / 100))
        return set(rng.sample(all_ids, num_to_select))


if __name__ == "__main__":
    from partition.partition import FilePartitionManager
    from signature.subset_signature import SubsetSignature
    from signature.key_manager import KeyManager

    file_path = os.path.join(config.DATASET_DIR, "sample.pdf")

    if not KeyManager.keys_exist():
        KeyManager.generate_keys()

    manager = FilePartitionManager()
    info = manager.partition_file(file_path)
    info = SubsetSignature.sign_partition(info)

    selected = RandomVerification.select(info)
    print(f"Total subsets: {len(info['subsets'])}")
    print(f"Selected for verification: {len(selected)} ({config.RANDOM_VERIFICATION_PERCENTAGE}%)")