"""
Tests for partition/partition.py - confirms file partitioning
produces correct, consistent block/sub-block structure.
"""

import os
import sys
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from partition.partition import FilePartitionManager


@pytest.fixture
def test_file(tmp_path):
    """Creates a small, deterministic test file of EXACTLY 10000 bytes."""
    file_path = tmp_path / "test_file.bin"
    data = bytes([i % 256 for i in range(10000)])
    file_path.write_bytes(data)
    return str(file_path)


def test_partition_file_not_found():
    manager = FilePartitionManager()
    with pytest.raises(FileNotFoundError):
        manager.partition_file("this_file_does_not_exist.bin")


def test_partition_basic_structure(test_file):
    manager = FilePartitionManager(block_size=4096, sub_block_size=512)
    info = manager.partition_file(test_file)

    assert info["file_size"] == 10000
    assert info["block_size"] == 4096
    assert info["sub_block_size"] == 512
    # 10000 bytes / 4096 per block = 2 full blocks + 1 partial block (1808 bytes) = 3 blocks
    assert info["total_blocks"] == 3
    # Each sub-block is 512 bytes: 4096/512 = 8 sub-blocks per full block
    assert info["blocks"][0]["block_size"] == 4096
    assert len(info["blocks"][0]["sub_blocks"]) == 8


def test_partition_preserves_total_bytes(test_file):
    """Reassembling all sub-block data should reproduce the original file exactly."""
    manager = FilePartitionManager(block_size=4096, sub_block_size=512)
    info = manager.partition_file(test_file)

    reassembled = b""
    for block in info["blocks"]:
        for sub in block["sub_blocks"]:
            reassembled += sub["data"]

    with open(test_file, "rb") as f:
        original = f.read()

    assert reassembled == original


def test_invalid_block_sub_block_size_ratio():
    """block_size must be evenly divisible by sub_block_size."""
    with pytest.raises(ValueError):
        FilePartitionManager(block_size=4096, sub_block_size=500)


def test_sub_block_ids_are_sequential(test_file):
    manager = FilePartitionManager(block_size=4096, sub_block_size=512)
    info = manager.partition_file(test_file)

    for block in info["blocks"]:
        expected_id = 1
        for sub in block["sub_blocks"]:
            assert sub["sub_block_id"] == expected_id
            expected_id += 1