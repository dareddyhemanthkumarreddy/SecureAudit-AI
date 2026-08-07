"""
SecureAudit-AI — Baseline: Metadata-Based Verification
Selects a subset for verification only if at least one of its
member sub-blocks has been flagged as modified. Represents
traditional metadata-driven integrity checking - smarter than
random, but relies on a single simple signal (no trust/stability
reasoning).
"""

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


class MetadataVerification:

    @staticmethod
    def select(partition_info):
        """
        Returns subset_ids where at least one member sub-block has
        modified == True.
        """
        # Build lookup: block_id -> {sub_block_id: sub_block}
        block_lookup = {
            block["block_id"]: {sb["sub_block_id"]: sb for sb in block["sub_blocks"]}
            for block in partition_info["blocks"]
        }

        selected = set()

        for subset in partition_info["subsets"]:
            for member in subset["members"]:
                sub = block_lookup[member["block_id"]][member["sub_block_id"]]
                if sub.get("modified", False):
                    selected.add(subset["subset_id"])
                    break

        return selected


if __name__ == "__main__":
    from partition.partition import FilePartitionManager
    from signature.subset_signature import SubsetSignature
    from signature.key_manager import KeyManager
    from features.metadata_tracker import MetadataTracker
    from simulation.modification_simulator import ModificationSimulator
    import config

    file_path = os.path.join(config.DATASET_DIR, "sample.pdf")

    if not KeyManager.keys_exist():
        KeyManager.generate_keys()

    manager = FilePartitionManager()
    info = manager.partition_file(file_path)
    info = SubsetSignature.sign_partition(info)
    info = MetadataTracker.initialize(info)

    ModificationSimulator.simulate(info, rate=0.05, seed=config.RANDOM_SEED)

    selected = MetadataVerification.select(info)
    print(f"Total subsets: {len(info['subsets'])}")
    print(f"Selected for verification: {len(selected)} (contain at least 1 modified sub-block)")