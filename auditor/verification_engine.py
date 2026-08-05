"""
SecureAudit-AI — TPA Verification Engine
The Third-Party Auditor verifies challenged subsets using
only the public key and the current sub-block data. Never
needs the private key or any separately-trusted source.
"""

import time
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from signature.subset_signature import SubsetSignature


class VerificationEngine:
    """Verifies a list of challenged subsets against their signatures."""

    @staticmethod
    def verify_challenge(partition_info, challenged_subset_ids):
        """
        Verifies each challenged subset's signature against its
        current sub-block data.

        Returns:
            {
                "verified": int,   # passed
                "failed": int,     # failed (tampered/corrupted)
                "execution_time": float,
                "verification_log": [
                    {"subset_id": int, "result": "PASS"/"FAIL"}, ...
                ]
            }
        """
        start = time.perf_counter()

        # Build lookup: block_id -> {sub_block_id: sub_block}
        block_lookup = {
            block["block_id"]: {sb["sub_block_id"]: sb for sb in block["sub_blocks"]}
            for block in partition_info["blocks"]
        }

        subset_lookup = {s["subset_id"]: s for s in partition_info["subsets"]}

        verified = 0
        failed = 0
        verification_log = []

        for subset_id in challenged_subset_ids:
            subset = subset_lookup.get(subset_id)

            if subset is None:
                failed += 1
                verification_log.append({"subset_id": subset_id, "result": "FAIL (not found)"})
                continue

            members_data = [
                block_lookup[m["block_id"]][m["sub_block_id"]]
                for m in subset["members"]
            ]

            is_valid = SubsetSignature.verify_subset(subset, members_data)

            if is_valid:
                verified += 1
                verification_log.append({"subset_id": subset_id, "result": "PASS"})
            else:
                failed += 1
                verification_log.append({"subset_id": subset_id, "result": "FAIL"})

        end = time.perf_counter()

        return {
            "verified": verified,
            "failed": failed,
            "execution_time": round(end - start, 6),
            "verification_log": verification_log,
        }


if __name__ == "__main__":
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from partition.partition import FilePartitionManager
    from signature.key_manager import KeyManager
    from auditor.challenge import ChallengeGenerator

    test_file = sys.argv[1] if len(sys.argv) > 1 else None

    if test_file is None:
        print("Usage: python verification_engine.py <path_to_file>")
    else:
        if not KeyManager.keys_exist():
            KeyManager.generate_keys()

        manager = FilePartitionManager()
        info = manager.partition_file(test_file)
        info = SubsetSignature.sign_partition(info)

        challenge = ChallengeGenerator.generate_challenge(info)

        result = VerificationEngine.verify_challenge(info, challenge)

        print(f"Challenged: {len(challenge)} subsets")
        print(f"Verified (PASS): {result['verified']}")
        print(f"Failed:          {result['failed']}")
        print(f"Verification time: {result['execution_time']} seconds")

        # Now simulate real tampering on one challenged subset and re-verify
        print("\n--- Simulating tampering on one subset ---")
        tampered_subset_id = challenge[0]
        subset = next(s for s in info["subsets"] if s["subset_id"] == tampered_subset_id)
        first_member = subset["members"][0]

        for block in info["blocks"]:
            if block["block_id"] == first_member["block_id"]:
                for sub in block["sub_blocks"]:
                    if sub["sub_block_id"] == first_member["sub_block_id"]:
                        sub["data"] = b"TAMPERED" + sub["data"][8:]

        result2 = VerificationEngine.verify_challenge(info, challenge)
        print(f"Verified (PASS): {result2['verified']}")
        print(f"Failed:          {result2['failed']} (should be 1, since we tampered subset {tampered_subset_id})")