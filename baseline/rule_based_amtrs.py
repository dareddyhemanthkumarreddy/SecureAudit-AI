"""
SecureAudit-AI — Baseline: Rule-Based AMTRS (professor's original approach)
Reimplements the professor's original rule-based HIGH/MEDIUM/LOW
risk categorization (trust + stability + modified + challenge
count based if/elif rules), translated to select SUBSETS instead
of individual sub-blocks. Kept as an explicit baseline so we can
directly compare "rule-based" vs "our learned Random Forest/
Gradient Boosting" approach in the paper.
"""

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from features.metadata_tracker import MetadataTracker


class RuleBasedAMTRS:

    @staticmethod
    def classify_sub_block(sub):
        """
        Same rule-based logic as the professor's original
        adaptive_risk_analyzer.py: HIGH/MEDIUM/LOW based on
        modified flag, trust_score, stability, challenge_count.
        """
        stability = MetadataTracker.calculate_stability(sub)
        trust = sub["trust_score"]

        if sub["modified"]:
            return "HIGH"
        elif trust < 60:
            return "HIGH"
        elif stability < 0.30:
            return "HIGH"
        elif trust < 80:
            return "MEDIUM"
        elif sub["challenge_count"] >= 3:
            return "MEDIUM"
        elif stability < 0.70:
            return "MEDIUM"
        else:
            return "LOW"

    @staticmethod
    def select(partition_info):
        """
        Returns subset_ids where at least one member sub-block is
        classified as HIGH or MEDIUM risk (i.e. not LOW).
        """
        block_lookup = {
            block["block_id"]: {sb["sub_block_id"]: sb for sb in block["sub_blocks"]}
            for block in partition_info["blocks"]
        }

        selected = set()

        for subset in partition_info["subsets"]:
            for member in subset["members"]:
                sub = block_lookup[member["block_id"]][member["sub_block_id"]]
                category = RuleBasedAMTRS.classify_sub_block(sub)
                if category != "LOW":
                    selected.add(subset["subset_id"])
                    break

        return selected


if __name__ == "__main__":
    from partition.partition import FilePartitionManager
    from signature.subset_signature import SubsetSignature
    from signature.key_manager import KeyManager
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

    selected = RuleBasedAMTRS.select(info)
    print(f"Total subsets: {len(info['subsets'])}")
    print(f"Selected for verification: {len(selected)} (rule-based HIGH/MEDIUM)")