"""
SecureAudit-AI — Cloud Storage Simulator
Simulates uploading partitioned file data to a cloud server
by saving it as a local JSON file. Binary sub-block data is
converted to Base64 text since JSON can't store raw bytes.
"""

import json
import os
import base64
import time
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config


class CloudStorage:
    """Simulates a cloud storage server using local JSON files."""

    @staticmethod
    def initialize():
        """Create the cloud storage folder if it doesn't exist."""
        os.makedirs(config.CLOUD_STORAGE_DIR, exist_ok=True)

    @staticmethod
    def upload(partition_info):
        """
        Uploads (saves) partitioned file data to simulated cloud storage.
        Returns dict with storage_file path and upload_time.
        """
        CloudStorage.initialize()

        start_time = time.perf_counter()

        serializable = {
            "file_name": partition_info["file_name"],
            "file_size": partition_info["file_size"],
            "block_size": partition_info["block_size"],
            "sub_block_size": partition_info["sub_block_size"],
            "total_blocks": partition_info["total_blocks"],
            "total_sub_blocks": partition_info["total_sub_blocks"],
            "blocks": [],
        }

        for block in partition_info["blocks"]:
            block_copy = {
                "block_id": block["block_id"],
                "block_size": block["block_size"],
                "sub_blocks": [],
            }

            for sub in block["sub_blocks"]:
                sub_copy = sub.copy()
                sub_copy["data"] = base64.b64encode(sub_copy["data"]).decode("utf-8")
                block_copy["sub_blocks"].append(sub_copy)

            serializable["blocks"].append(block_copy)

        filename = os.path.join(
            config.CLOUD_STORAGE_DIR,
            partition_info["file_name"] + ".json"
        )

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=4)

        end_time = time.perf_counter()

        return {
            "storage_file": filename,
            "upload_time": round(end_time - start_time, 6),
        }


if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager

    test_file = sys.argv[1] if len(sys.argv) > 1 else None

    if test_file is None:
        print("Usage: python cloud_storage.py <path_to_file>")
    else:
        manager = FilePartitionManager()
        info = manager.partition_file(test_file)

        result = CloudStorage.upload(info)
        print(f"Uploaded to: {result['storage_file']}")
        print(f"Upload time: {result['upload_time']} seconds")