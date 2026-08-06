"""
SecureAudit-AI — Metadata & Trust Tracker
Attaches tracking fields to every sub-block (version, modified
flag, trust score, challenge/verification counts) and provides
methods to update trust based on events. Kept as one module,
unlike the professor's original project which split this logic
across two separate files.
"""

import time
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config


class MetadataTracker:
    """Initializes and updates per-sub-block metadata and trust scores."""

    @staticmethod
    def initialize(partition_info):
        """Adds fresh metadata + trust fields to every sub-block."""
        start = time.perf_counter()
        total = 0

        for block in partition_info["blocks"]:
            for sub in block["sub_blocks"]:
                sub["version"] = 1
                sub["modified"] = False
                sub["last_verified"] = None
                sub["verification_count"] = 0
                sub["challenge_count"] = 0
                sub["status"] = "ACTIVE"

                sub["trust_score"] = config.INITIAL_TRUST
                sub["trust_history"] = [
                    {"version": 1, "trust": config.INITIAL_TRUST, "event": "INITIAL"}
                ]
                total += 1

        end = time.perf_counter()

        partition_info["metadata_statistics"] = {
            "total_initialized": total,
            "execution_time": round(end - start, 6),
        }

        return partition_info

    @staticmethod
    def calculate_stability(sub):
        """Returns a stability index (1.0 = never edited, closer to 0 = edited often)."""
        updates = sub["version"] - 1
        return round(1 / (1 + updates), 3)

    @staticmethod
    def apply_modification(sub, new_data, track_properly=True):
        """
        Applies a data change to a sub-block.

        Args:
            sub: the sub-block dict to modify.
            new_data: new raw bytes to replace sub["data"] with.
            track_properly: if True (legitimate edit), updates version,
                modified flag, challenge_count, and applies trust penalty
                — this is a normal, tracked edit.
                If False (silent corruption), only the data changes —
                nothing else updates, simulating an attacker or corruption
                event that bypasses proper tracking. This is important for
                testing whether the risk system can still catch untracked
                tampering.
        """
        sub["data"] = new_data

        if track_properly:
            sub["version"] += 1
            sub["modified"] = True
            sub["challenge_count"] += 1
            sub["status"] = "UPDATED"

            sub["trust_score"] = max(0, sub["trust_score"] - config.TRUST_PENALTY_MODIFIED)
            sub["trust_history"].append({
                "version": sub["version"],
                "trust": sub["trust_score"],
                "event": "MODIFIED",
            })

        return sub

    @staticmethod
    def reward_verification_pass(sub):
        """Call after a sub-block passes verification: small trust reward."""
        sub["verification_count"] += 1
        sub["trust_score"] = min(100, sub["trust_score"] + config.TRUST_REWARD)
        sub["trust_history"].append({
            "version": sub["version"],
            "trust": sub["trust_score"],
            "event": "VERIFIED_PASS",
        })
        return sub

    @staticmethod
    def penalize_verification_fail(sub):
        """Call after a sub-block fails verification: larger trust penalty."""
        sub["trust_score"] = max(0, sub["trust_score"] - config.TRUST_PENALTY_FAILED)
        sub["trust_history"].append({
            "version": sub["version"],
            "trust": sub["trust_score"],
            "event": "VERIFIED_FAIL",
        })
        return sub


if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager

    test_file = sys.argv[1] if len(sys.argv) > 1 else None

    if test_file is None:
        print("Usage: python metadata_tracker.py <path_to_file>")
    else:
        manager = FilePartitionManager()
        info = manager.partition_file(test_file)
        info = MetadataTracker.initialize(info)

        stats = info["metadata_statistics"]
        print(f"Sub-blocks initialized: {stats['total_initialized']}")
        print(f"Time: {stats['execution_time']} seconds")

        sample = info["blocks"][0]["sub_blocks"][0]
        print(f"\nSample sub-block metadata: version={sample['version']}, "
              f"modified={sample['modified']}, trust_score={sample['trust_score']}, "
              f"stability={MetadataTracker.calculate_stability(sample)}")