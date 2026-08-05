"""
SecureAudit-AI — Challenge Generator (TPA side)
Simulates the Third-Party Auditor randomly selecting which
signed subsets to challenge the cloud server to prove
possession of, instead of checking everything every time.
"""

import random
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config


class ChallengeGenerator:
    """Generates random challenges over signed subsets."""

    @staticmethod
    def generate_challenge(partition_info, num_subsets=None, seed=config.RANDOM_SEED):
        """
        Randomly selects subset_ids to challenge.

        Args:
            partition_info: dict containing "subsets" (from SubsetSignature.sign_partition).
            num_subsets: how many subsets to challenge. Defaults to 10% of total.
            seed: random seed for reproducibility.

        Returns:
            list of subset_id integers to challenge.
        """
        if "subsets" not in partition_info:
            raise ValueError(
                "partition_info has no 'subsets' — run SubsetSignature.sign_partition() first."
            )

        total_subsets = len(partition_info["subsets"])

        if num_subsets is None:
            num_subsets = max(1, int(total_subsets * 0.10))

        rng = random.Random(seed)
        all_ids = [s["subset_id"] for s in partition_info["subsets"]]

        return rng.sample(all_ids, min(num_subsets, total_subsets))


if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager
    from signature.subset_signature import SubsetSignature
    from signature.key_manager import KeyManager

    test_file = sys.argv[1] if len(sys.argv) > 1 else None

    if test_file is None:
        print("Usage: python challenge.py <path_to_file>")
    else:
        if not KeyManager.keys_exist():
            KeyManager.generate_keys()

        manager = FilePartitionManager()
        info = manager.partition_file(test_file)
        info = SubsetSignature.sign_partition(info)

        challenge = ChallengeGenerator.generate_challenge(info)
        print(f"Total subsets available: {len(info['subsets'])}")
        print(f"Subsets challenged: {len(challenge)}")
        print(f"Challenge (subset_ids): {challenge}")