"""
SecureAudit-AI — Main Entry Point
Runs the pipeline end-to-end. More stages get added here
as each phase is built.
"""

import os
import config
from partition.partition import FilePartitionManager
from storage.cloud_storage import CloudStorage

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

    # Phase 1.2 — Upload to simulated cloud
    storage_info = CloudStorage.upload(partition_info)

    print(f"\nUploaded to: {storage_info['storage_file']}")
    print(f"Upload time: {storage_info['upload_time']} seconds")

    print("\n" + "=" * 60)
    print("Phase 1 complete")
    print("=" * 60)


if __name__ == "__main__":
    main()