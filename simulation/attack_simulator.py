"""
SecureAudit-AI — Adversarial Attack Simulator
Simulates an attacker who deliberately targets sub-blocks
that currently LOOK safe (high trust, high stability, never
modified) — the sub-blocks a naive risk system is most likely
to skip. Tests whether the risk system can be gamed.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from features.metadata_tracker import MetadataTracker


class AttackSimulator:
    """Targets the 'safest-looking' sub-blocks and corrupts them silently."""

    @staticmethod
    def simulate(partition_info, rate, seed=None):
        """
        Args:
            partition_info: partition dict (must already have metadata initialized).
            rate: float between 0 and 1, e.g. 0.02 for 2%.
            seed: unused here (selection is deterministic by trust ranking,
                  kept for interface consistency with other simulators).

        Returns:
            list of (block_id, sub_block_id) tuples that were attacked.
        """
        all_refs = []
        for block in partition_info["blocks"]:
            for sub in block["sub_blocks"]:
                stability = MetadataTracker.calculate_stability(sub)
                # "Safety score" - higher trust + higher stability = looks safer
                safety_score = sub["trust_score"] + (stability * 100)
                all_refs.append((safety_score, block["block_id"], sub["sub_block_id"], sub))

        # Sort by safety_score descending - attacker picks the SAFEST-looking ones first
        all_refs.sort(key=lambda x: x[0], reverse=True)

        num_to_attack = max(1, int(len(all_refs) * rate))
        chosen = all_refs[:num_to_attack]

        attacked_ids = []

        for safety_score, block_id, sub_block_id, sub in chosen:
            new_data = os.urandom(len(sub["data"]))
            # Silent, untracked - just like a real attacker would do
            MetadataTracker.apply_modification(sub, new_data, track_properly=False)
            attacked_ids.append((block_id, sub_block_id))

        return attacked_ids


if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager
    import config

    test_file = sys.argv[1] if len(sys.argv) > 1 else None
    rate = float(sys.argv[2]) if len(sys.argv) > 2 else 0.02

    if test_file is None:
        print("Usage: python attack_simulator.py <path_to_file> [rate]")
    else:
        manager = FilePartitionManager()
        info = manager.partition_file(test_file)
        info = MetadataTracker.initialize(info)

        attacked = AttackSimulator.simulate(info, rate=rate)

        print(f"Total sub-blocks: {info['total_sub_blocks']}")
        print(f"Attack rate requested: {rate * 100}%")
        print(f"Sub-blocks attacked: {len(attacked)}")
        print("These were the highest trust_score + stability sub-blocks -")
        print("exactly the ones a naive risk system would skip as 'LOW risk'.")