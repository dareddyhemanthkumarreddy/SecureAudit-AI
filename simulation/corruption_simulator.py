"""
SecureAudit-AI — Corruption Simulator
Simulates silent data corruption (e.g., bit-rot, storage
failure, or a dishonest cloud server) — data changes WITHOUT
going through proper tracking. No version bump, no modified
flag, no trust penalty. This tests whether the system can
still detect tampering that doesn't announce itself.
"""

import random
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from features.metadata_tracker import MetadataTracker


class CorruptionSimulator:
    """Randomly corrupts a percentage of sub-blocks WITHOUT proper tracking."""

    @staticmethod
    def simulate(partition_info, rate, seed=None):
        """
        Args:
            partition_info: partition dict (must already have metadata initialized).
            rate: float between 0 and 1, e.g. 0.02 for 2%.
            seed: random seed for reproducibility.

        Returns:
            list of (block_id, sub_block_id) tuples that were silently corrupted.
        """
        rng = random.Random(seed)

        all_refs = []
        for block in partition_info["blocks"]:
            for sub in block["sub_blocks"]:
                all_refs.append((block["block_id"], sub["sub_block_id"], sub))

        num_to_corrupt = max(1, int(len(all_refs) * rate))
        chosen = rng.sample(all_refs, num_to_corrupt)

        corrupted_ids = []

        for block_id, sub_block_id, sub in chosen:
            new_data = os.urandom(len(sub["data"]))
            # track_properly=False -> silent, no metadata/trust update
            MetadataTracker.apply_modification(sub, new_data, track_properly=False)
            corrupted_ids.append((block_id, sub_block_id))

        return corrupted_ids


if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager
    import config

    test_file = sys.argv[1] if len(sys.argv) > 1 else None
    rate = float(sys.argv[2]) if len(sys.argv) > 2 else 0.02

    if test_file is None:
        print("Usage: python corruption_simulator.py <path_to_file> [rate]")
    else:
        manager = FilePartitionManager()
        info = manager.partition_file(test_file)
        info = MetadataTracker.initialize(info)

        corrupted = CorruptionSimulator.simulate(info, rate=rate, seed=config.RANDOM_SEED)

        print(f"Total sub-blocks: {info['total_sub_blocks']}")
        print(f"Corruption rate requested: {rate * 100}%")
        print(f"Sub-blocks actually corrupted: {len(corrupted)}")

        # Prove it's silent: check that a corrupted sub-block's metadata looks untouched
        sample_block_id, sample_sub_id = corrupted[0]
        for block in info["blocks"]:
            if block["block_id"] == sample_block_id:
                for sub in block["sub_blocks"]:
                    if sub["sub_block_id"] == sample_sub_id:
                        print(f"\nSample corrupted sub-block metadata (should look 'normal'):")
                        print(f"  version={sub['version']}, modified={sub['modified']}, "
                              f"trust_score={sub['trust_score']}")
                        print("  (data was changed, but no metadata trace of it)")