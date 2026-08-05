"""
SecureAudit-AI — Subset-Based Signature Generator
Groups sub-blocks into subsets and signs each subset as
one unit, instead of signing every sub-block individually.
More efficient, and the standard approach in PDP-style schemes.
"""

import hashlib
import time
import os
import sys

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from signature.key_manager import KeyManager


class SubsetSignature:
    """Generates and verifies signatures over subsets of sub-blocks."""

    @staticmethod
    def _combined_hash(sub_blocks):
        """
        Computes one combined SHA-256 hash representing an entire
        subset of sub-blocks, by hashing their concatenated data.
        """
        hasher = hashlib.sha256()
        for sub in sub_blocks:
            hasher.update(sub["data"])
        return hasher.digest()

    @staticmethod
    def sign_partition(partition_info, subset_size=config.SUBSET_SIZE):
        """
        Groups all sub-blocks (across all blocks) into subsets of
        `subset_size`, computes a combined hash per subset, and
        signs each hash with the private key.

        Adds a "subsets" list to partition_info with signature info,
        and tags each sub-block with which subset_id it belongs to.

        Returns partition_info (modified in place) with added
        "signature_statistics".
        """
        start = time.perf_counter()

        private_key = KeyManager.load_private_key()

        # Flatten all sub-blocks into one list, remembering their location
        flat_sub_blocks = []
        for block in partition_info["blocks"]:
            for sub in block["sub_blocks"]:
                flat_sub_blocks.append({
                    "block_id": block["block_id"],
                    "sub_block_ref": sub,
                })

        subsets = []
        subset_id = 0

        for i in range(0, len(flat_sub_blocks), subset_size):
            subset_id += 1
            chunk = flat_sub_blocks[i:i + subset_size]

            sub_blocks_only = [item["sub_block_ref"] for item in chunk]
            combined_hash = SubsetSignature._combined_hash(sub_blocks_only)

            signature = private_key.sign(
                combined_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            members = []
            for item in chunk:
                item["sub_block_ref"]["subset_id"] = subset_id
                members.append({
                    "block_id": item["block_id"],
                    "sub_block_id": item["sub_block_ref"]["sub_block_id"],
                })

            subsets.append({
                "subset_id": subset_id,
                "members": members,
                "combined_hash": combined_hash.hex(),
                "signature": signature.hex(),
            })

        partition_info["subsets"] = subsets

        end = time.perf_counter()

        partition_info["signature_statistics"] = {
            "total_subsets": len(subsets),
            "subset_size": subset_size,
            "execution_time": round(end - start, 6),
        }

        return partition_info

    @staticmethod
    def verify_subset(subset, sub_blocks):
        """
        Verifies a subset's signature against its current sub-block data.
        Returns True if valid (untampered), False if invalid (tampered
        or corrupted).
        """
        public_key = KeyManager.load_public_key()

        combined_hash = SubsetSignature._combined_hash(sub_blocks)
        signature = bytes.fromhex(subset["signature"])

        try:
            public_key.verify(
                signature,
                combined_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager

    test_file = sys.argv[1] if len(sys.argv) > 1 else None

    if test_file is None:
        print("Usage: python subset_signature.py <path_to_file>")
    else:
        if not KeyManager.keys_exist():
            print("No keys found — generating new keypair first...")
            KeyManager.generate_keys()

        manager = FilePartitionManager()
        info = manager.partition_file(test_file)

        info = SubsetSignature.sign_partition(info)

        stats = info["signature_statistics"]
        print(f"Total subsets signed: {stats['total_subsets']}")
        print(f"Subset size: {stats['subset_size']} sub-blocks each")
        print(f"Signing time: {stats['execution_time']} seconds")

        # Build a lookup: block_id -> {sub_block_id: sub_block}
        block_lookup = {
            block["block_id"]: {sb["sub_block_id"]: sb for sb in block["sub_blocks"]}
            for block in info["blocks"]
        }

        def get_members_data(subset):
            return [
                block_lookup[m["block_id"]][m["sub_block_id"]]
                for m in subset["members"]
            ]

        # Quick correctness test: verify the first subset as-is (should PASS)
        first_subset = info["subsets"][0]
        first_members_data = get_members_data(first_subset)
        is_valid = SubsetSignature.verify_subset(first_subset, first_members_data)
        print(f"\nVerification test (untampered): {'PASS' if is_valid else 'FAIL'}")

        # Tamper test: corrupt one byte and verify again (should FAIL)
        tampered_data = [dict(s, data=b"X" + s["data"][1:]) for s in first_members_data]
        is_valid_tampered = SubsetSignature.verify_subset(first_subset, tampered_data)
        print(f"Verification test (tampered):    {'PASS' if is_valid_tampered else 'FAIL'} (should be FAIL)")