"""
SecureAudit-AI — Modification Simulator
Simulates legitimate, properly-tracked edits to a configurable
percentage of sub-blocks. This represents normal, expected file
changes over time (not corruption or attacks).
"""

import random
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from features.metadata_tracker import MetadataTracker


class ModificationSimulator:
    """Randomly modifies a percentage of sub-blocks, properly tracked."""

    @staticmethod
    def simulate(partition_info, rate, seed=None):
        """
        Args:
            partition_info: partition dict (must already have metadata initialized).
            rate: float between 0 and 1, e.g. 0.05 for 5%.
            seed: random seed for reproducibility.

        Returns:
            list of (block_id, sub_block_id) tuples that were modified.
        """
        rng = random.Random(seed)

        all_refs = []
        for block in partition_info["blocks"]:
            for sub in block["sub_blocks"]:
                all_refs.append((block["block_id"], sub["sub_block_id"], sub))

        num_to_modify = max(1, int(len(all_refs) * rate))
        chosen = rng.sample(all_refs, num_to_modify)

        modified_ids = []

        for block_id, sub_block_id, sub in chosen:
            new_data = os.urandom(len(sub["data"]))
            MetadataTracker.apply_modification(sub, new_data, track_properly=True)
            modified_ids.append((block_id, sub_block_id))

        return modified_ids


if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager
    import config

    test_file = sys.argv[1] if len(sys.argv) > 1 else None
    rate = float(sys.argv[2]) if len(sys.argv) > 2 else 0.05

    if test_file is None:
        print("Usage: python modification_simulator.py <path_to_file> [rate]")
    else:
        manager = FilePartitionManager()
        info = manager.partition_file(test_file)
        info = MetadataTracker.initialize(info)

        modified = ModificationSimulator.simulate(info, rate=rate, seed=config.RANDOM_SEED)

        print(f"Total sub-blocks: {info['total_sub_blocks']}")
        print(f"Modification rate requested: {rate * 100}%")
        print(f"Sub-blocks actually modified: {len(modified)}")
        print(f"First few modified (block_id, sub_block_id): {modified[:5]}")