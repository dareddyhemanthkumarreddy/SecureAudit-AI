"""
SecureAudit-AI — File Partition Manager
Splits a file into fixed-size blocks, and each block into
fixed-size sub-blocks. Every later stage (signing, risk
scoring, verification) operates on these sub-blocks.
"""

from pathlib import Path
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config


class FilePartitionManager:
    """Partitions a file into blocks and sub-blocks of configurable size."""

    def __init__(self, block_size=config.BLOCK_SIZE, sub_block_size=config.SUB_BLOCK_SIZE):
        if block_size % sub_block_size != 0:
            raise ValueError("block_size must be a multiple of sub_block_size")

        self.block_size = block_size
        self.sub_block_size = sub_block_size

    def partition_file(self, file_path):
        """Reads a file and splits it into blocks/sub-blocks. Returns partition_info dict."""
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"{file_path} not found.")

        blocks = []
        total_sub_blocks = 0
        block_id = 0

        with open(path, "rb") as file:
            while True:
                block_data = file.read(self.block_size)

                if not block_data:
                    break

                block_id += 1
                sub_blocks = []
                sub_block_id = 0

                for i in range(0, len(block_data), self.sub_block_size):
                    sub_block_id += 1
                    total_sub_blocks += 1
                    sub_blocks.append({
                        "sub_block_id": sub_block_id,
                        "data": block_data[i:i + self.sub_block_size],
                    })

                blocks.append({
                    "block_id": block_id,
                    "block_size": len(block_data),
                    "sub_blocks": sub_blocks,
                })

        return {
            "file_name": path.name,
            "file_size": path.stat().st_size,
            "block_size": self.block_size,
            "sub_block_size": self.sub_block_size,
            "total_blocks": len(blocks),
            "total_sub_blocks": total_sub_blocks,
            "blocks": blocks,
        }


if __name__ == "__main__":
    test_file = sys.argv[1] if len(sys.argv) > 1 else None

    if test_file is None:
        print("Usage: python partition.py <path_to_file>")
    else:
        manager = FilePartitionManager()
        info = manager.partition_file(test_file)
        print(f"File: {info['file_name']} ({info['file_size']} bytes)")
        print(f"Total blocks: {info['total_blocks']}")
        print(f"Total sub-blocks: {info['total_sub_blocks']}")