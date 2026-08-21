"""
Tests for signature/subset_signature.py and auditor/verification_engine.py
- confirms the core cryptographic guarantee: untampered data passes
verification, tampered data fails.
"""

import os
import sys
import shutil
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from partition.partition import FilePartitionManager
from signature.key_manager import KeyManager
from signature.subset_signature import SubsetSignature
from auditor.verification_engine import VerificationEngine


TEST_KEYS_DIR = os.path.join(config.BASE_DIR, "signature", "keys_test")


@pytest.fixture(scope="module", autouse=True)
def isolated_test_keys():
    """
    Uses a SEPARATE test keys directory so running tests never
    touches your real production keypair in signature/keys/.
    """
    original_keys_dir = config.KEYS_DIR
    original_private = KeyManager.PRIVATE_KEY_PATH
    original_public = KeyManager.PUBLIC_KEY_PATH

    config.KEYS_DIR = TEST_KEYS_DIR
    KeyManager.PRIVATE_KEY_PATH = os.path.join(TEST_KEYS_DIR, "private_key.pem")
    KeyManager.PUBLIC_KEY_PATH = os.path.join(TEST_KEYS_DIR, "public_key.pem")

    if not KeyManager.keys_exist():
        KeyManager.generate_keys()

    yield

    config.KEYS_DIR = original_keys_dir
    KeyManager.PRIVATE_KEY_PATH = original_private
    KeyManager.PUBLIC_KEY_PATH = original_public

    if os.path.exists(TEST_KEYS_DIR):
        shutil.rmtree(TEST_KEYS_DIR)


@pytest.fixture
def test_file(tmp_path):
    file_path = tmp_path / "test_file.bin"
    file_path.write_bytes(os.urandom(20000))
    return str(file_path)


@pytest.fixture
def signed_partition(test_file):
    manager = FilePartitionManager(block_size=4096, sub_block_size=512)
    info = manager.partition_file(test_file)
    info = SubsetSignature.sign_partition(info, subset_size=4)
    return info


def test_signing_produces_subsets(signed_partition):
    assert len(signed_partition["subsets"]) > 0
    for subset in signed_partition["subsets"]:
        assert "signature" in subset
        assert "combined_hash" in subset
        assert len(subset["members"]) > 0


def test_untampered_subset_verifies_successfully(signed_partition):
    all_subset_ids = [s["subset_id"] for s in signed_partition["subsets"]]
    result = VerificationEngine.verify_challenge(signed_partition, all_subset_ids)

    assert result["failed"] == 0
    assert result["verified"] == len(all_subset_ids)


def test_tampered_subset_fails_verification(signed_partition):
    """The core security guarantee: any data change must be detected."""
    target_block = signed_partition["blocks"][0]
    target_sub = target_block["sub_blocks"][0]

    # Tamper with the data directly
    target_sub["data"] = b"TAMPERED" + target_sub["data"][8:]

    all_subset_ids = [s["subset_id"] for s in signed_partition["subsets"]]
    result = VerificationEngine.verify_challenge(signed_partition, all_subset_ids)

    assert result["failed"] >= 1

    failed_ids = {e["subset_id"] for e in result["verification_log"] if e["result"] == "FAIL"}
    assert len(failed_ids) >= 1


def test_single_byte_change_is_detected(signed_partition):
    """Even a 1-byte change must flip the hash and fail verification."""
    target_block = signed_partition["blocks"][0]
    target_sub = target_block["sub_blocks"][0]

    original_first_byte = target_sub["data"][0:1]
    flipped_byte = bytes([original_first_byte[0] ^ 0xFF])  # flip all bits of 1 byte
    target_sub["data"] = flipped_byte + target_sub["data"][1:]

    all_subset_ids = [s["subset_id"] for s in signed_partition["subsets"]]
    result = VerificationEngine.verify_challenge(signed_partition, all_subset_ids)

    assert result["failed"] >= 1