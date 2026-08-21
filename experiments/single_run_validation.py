"""
SecureAudit-AI — Single Run Validation
Runs ONE file at ONE modification rate per invocation, prints the
result, and APPENDS it to results/processed/manual_validation_log.csv
so every run you do builds up one combined results file over time -
useful for working through files/rates one at a time and reviewing
each result before moving to the next.

Usage:
    python experiments/single_run_validation.py <filename> <mod_rate>

Examples:
    python experiments/single_run_validation.py wallpaper.jpg 0
    python experiments/single_run_validation.py wallpaper.jpg 0.05
    python experiments/single_run_validation.py wallpaper.jpg 0.10
    python experiments/single_run_validation.py music.m4a 0
    ... and so on for each file / rate combination.

mod_rate = 0 runs the CLEAN BASELINE check (no tampering at all,
should show 0 false positives). Any other value (e.g. 0.05, 0.10,
0.15, 0.20) runs the tampering sweep at that rate (corruption and
attack are fixed at 2% each, same as the rest of the project).
"""

import os
import sys
import csv
import random
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from partition.partition import FilePartitionManager
from signature.subset_signature import SubsetSignature
from signature.key_manager import KeyManager
from auditor.challenge import ChallengeGenerator
from auditor.verification_engine import VerificationEngine
from features.metadata_tracker import MetadataTracker
from simulation.modification_simulator import ModificationSimulator
from simulation.corruption_simulator import CorruptionSimulator
from simulation.attack_simulator import AttackSimulator
from ai_agent.risk_scorer import RiskScorer

LOG_PATH = os.path.join(config.RESULTS_PROCESSED_DIR, "manual_validation_log.csv")

LOG_FIELDS = [
    "file", "file_size_bytes", "mod_rate", "total_blocks", "total_sub_blocks",
    "total_subsets", "tampered_subsets", "subsets_selected", "recall",
    "efficiency_pct", "false_positives",
]


def get_tampered_subset_ids(partition_info, tampered_sub_block_ids):
    tampered_set = set(tampered_sub_block_ids)
    tampered_subsets = set()
    for subset in partition_info["subsets"]:
        for member in subset["members"]:
            key = (member["block_id"], member["sub_block_id"])
            if key in tampered_set:
                tampered_subsets.add(subset["subset_id"])
                break
    return tampered_subsets


def ai_plus_safety_net_selection(partition_info, scorer, seed, threshold=0.5,
                                   safety_net_pct=config.SAFETY_NET_PERCENTAGE):
    block_lookup = {
        block["block_id"]: {sb["sub_block_id"]: sb for sb in block["sub_blocks"]}
        for block in partition_info["blocks"]
    }

    rows = []
    for subset in partition_info["subsets"]:
        for member in subset["members"]:
            sub = block_lookup[member["block_id"]][member["sub_block_id"]]
            stability = MetadataTracker.calculate_stability(sub)
            rows.append({
                "subset_id": subset["subset_id"],
                "trust_score": sub["trust_score"],
                "stability_index": stability,
                "version": sub["version"],
                "modified": int(sub["modified"]),
                "challenge_count": sub["challenge_count"],
            })

    df = pd.DataFrame(rows)
    df["risk_score"] = scorer.score(df)

    max_risk_per_subset = df.groupby("subset_id")["risk_score"].max()
    ai_selected = set(max_risk_per_subset[max_risk_per_subset >= threshold].index)

    all_subset_ids = set(max_risk_per_subset.index)
    remaining = list(all_subset_ids - ai_selected)

    rng = random.Random(seed)
    num_safety_net = max(1, int(len(remaining) * safety_net_pct / 100))
    safety_net = set(rng.sample(remaining, min(num_safety_net, len(remaining))))

    return ai_selected | safety_net


def append_to_log(row):
    file_exists = os.path.exists(LOG_PATH)
    os.makedirs(config.RESULTS_PROCESSED_DIR, exist_ok=True)

    with open(LOG_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def run_clean_baseline(file_path, file_name, seed=config.RANDOM_SEED):
    manager = FilePartitionManager()
    info = manager.partition_file(file_path)
    info = SubsetSignature.sign_partition(info)
    info = MetadataTracker.initialize(info)

    challenge = ChallengeGenerator.generate_challenge(info, seed=seed)
    result = VerificationEngine.verify_challenge(info, challenge)

    row = {
        "file": file_name,
        "file_size_bytes": os.path.getsize(file_path),
        "mod_rate": 0.0,
        "total_blocks": info["total_blocks"],
        "total_sub_blocks": info["total_sub_blocks"],
        "total_subsets": len(info["subsets"]),
        "tampered_subsets": 0,
        "subsets_selected": len(challenge),
        "recall": "",
        "efficiency_pct": "",
        "false_positives": result["failed"],
    }

    print(f"\n=== CLEAN BASELINE: {file_name} ===")
    print(f"  File size: {row['file_size_bytes']:,} bytes")
    print(f"  Blocks: {row['total_blocks']}, Sub-blocks: {row['total_sub_blocks']}, Subsets: {row['total_subsets']}")
    print(f"  Challenged: {len(challenge)} subsets")
    print(f"  Verified: {result['verified']}, Failed: {result['failed']} (should be 0)")

    return row


def run_tampering_test(file_path, file_name, mod_rate, scorer, seed=config.RANDOM_SEED):
    manager = FilePartitionManager()
    info = manager.partition_file(file_path)
    info = SubsetSignature.sign_partition(info)
    info = MetadataTracker.initialize(info)

    modified = ModificationSimulator.simulate(info, rate=mod_rate, seed=seed)
    corrupted = CorruptionSimulator.simulate(info, rate=0.02, seed=seed + 1)
    attacked = AttackSimulator.simulate(info, rate=0.02)

    all_tampered = set(modified) | set(corrupted) | set(attacked)
    tampered_subsets = get_tampered_subset_ids(info, all_tampered)
    total_subsets = len(info["subsets"])

    selected = ai_plus_safety_net_selection(info, scorer, seed=seed)

    verification_result = VerificationEngine.verify_challenge(info, list(selected))
    detected = {e["subset_id"] for e in verification_result["verification_log"] if e["result"] == "FAIL"}

    recall = len(detected) / len(tampered_subsets) if tampered_subsets else 0
    efficiency = 1 - (len(selected) / total_subsets)

    row = {
        "file": file_name,
        "file_size_bytes": os.path.getsize(file_path),
        "mod_rate": mod_rate,
        "total_blocks": info["total_blocks"],
        "total_sub_blocks": info["total_sub_blocks"],
        "total_subsets": total_subsets,
        "tampered_subsets": len(tampered_subsets),
        "subsets_selected": len(selected),
        "recall": round(recall, 4),
        "efficiency_pct": round(efficiency * 100, 2),
        "false_positives": "",
    }

    print(f"\n=== {file_name} @ mod_rate={mod_rate} ===")
    print(f"  File size: {row['file_size_bytes']:,} bytes")
    print(f"  Blocks: {row['total_blocks']}, Sub-blocks: {row['total_sub_blocks']}, Subsets: {row['total_subsets']}")
    print(f"  Modified: {len(modified)}, Corrupted: {len(corrupted)}, Attacked: {len(attacked)}")
    print(f"  Truly tampered subsets: {len(tampered_subsets)}")
    print(f"  Selected for verification: {len(selected)}")
    print(f"  Recall: {row['recall']}")
    print(f"  Efficiency: {row['efficiency_pct']}%")

    return row


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python experiments/single_run_validation.py <filename> <mod_rate>")
        print("Example: python experiments/single_run_validation.py wallpaper.jpg 0.05")
        print("Use mod_rate=0 for the clean baseline check.")
        sys.exit(1)

    file_name = sys.argv[1]
    mod_rate = float(sys.argv[2])

    file_path = os.path.join(config.DATASET_DIR, file_name)

    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)

    if not KeyManager.keys_exist():
        KeyManager.generate_keys()

    if mod_rate == 0:
        row = run_clean_baseline(file_path, file_name)
    else:
        scorer = RiskScorer(model_type=config.RISK_MODEL)
        scorer.load()
        row = run_tampering_test(file_path, file_name, mod_rate, scorer)

    append_to_log(row)
    print(f"\nAppended to: {LOG_PATH}")