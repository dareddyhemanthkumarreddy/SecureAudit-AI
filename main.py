"""
SecureAudit-AI — Main Entry Point
Runs the pipeline end-to-end. More stages get added here
as each phase is built.
"""

import os
import config
from partition.partition import FilePartitionManager
from storage.cloud_storage import CloudStorage
from signature.key_manager import KeyManager
from signature.subset_signature import SubsetSignature
from auditor.challenge import ChallengeGenerator
from auditor.verification_engine import VerificationEngine

FILE_PATH = os.path.join(config.DATASET_DIR, "sample.pdf")


def main():
    print("=" * 60)
    print("SecureAudit-AI")
    print("=" * 60)

    # Phase 1.1 — Partition
    manager = FilePartitionManager()
    partition_info = manager.partition_file(FILE_PATH)

    print(f"\nFile: {partition_info['file_name']} ({partition_info['file_size']} bytes)")
    print(f"Total blocks: {partition_info['total_blocks']}")
    print(f"Total sub-blocks: {partition_info['total_sub_blocks']}")

    # Phase 2 — Keys + Subset Signing
    if not KeyManager.keys_exist():
        KeyManager.generate_keys()

    partition_info = SubsetSignature.sign_partition(partition_info)
    sig_stats = partition_info["signature_statistics"]
    print(f"\nSubsets signed: {sig_stats['total_subsets']} (size {sig_stats['subset_size']} each)")
    print(f"Signing time: {sig_stats['execution_time']} seconds")

    # Phase 1.2 — Upload to simulated cloud
    storage_info = CloudStorage.upload(partition_info)
    print(f"\nUploaded to: {storage_info['storage_file']}")
    print(f"Upload time: {storage_info['upload_time']} seconds")

    # Phase 2 — TPA Challenge + Verification
    challenge = ChallengeGenerator.generate_challenge(partition_info)
    verification_result = VerificationEngine.verify_challenge(partition_info, challenge)

    print(f"\nTPA challenged {len(challenge)} subsets")
    print(f"Verified: {verification_result['verified']}")
    print(f"Failed:   {verification_result['failed']}")
    print(f"Verification time: {verification_result['execution_time']} seconds")

    print("\n" + "=" * 60)
    print("Phase 1 + Phase 2 complete")
    print("=" * 60)


if __name__ == "__main__":
    main()