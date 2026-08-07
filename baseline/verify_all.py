"""
SecureAudit-AI — Baseline: Verify-All
Selects every signed subset for verification. Safest possible
baseline (catches everything), but most expensive - the
reference point every smarter strategy should be compared against.
"""


class VerifyAll:

    @staticmethod
    def select(partition_info):
        """Returns the set of ALL subset_ids in the partition."""
        return {s["subset_id"] for s in partition_info["subsets"]}


if __name__ == "__main__":
    import sys
    import os

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager
    from signature.subset_signature import SubsetSignature
    from signature.key_manager import KeyManager
    import config

    file_path = os.path.join(config.DATASET_DIR, "sample.pdf")

    if not KeyManager.keys_exist():
        KeyManager.generate_keys()

    manager = FilePartitionManager()
    info = manager.partition_file(file_path)
    info = SubsetSignature.sign_partition(info)

    selected = VerifyAll.select(info)
    print(f"Total subsets: {len(info['subsets'])}")
    print(f"Selected for verification: {len(selected)}")