"""
SecureAudit-AI — Multi-File Validation (generalization test)
For each test file, first confirms a CLEAN baseline (0% tampering,
should produce zero false positives), then sweeps modification
rates (5%, 10%, 15%, 20%, corruption/attack fixed at 2% each) using
the same AI + safety-net + real signature verification methodology
as Phase 11's full_pipeline_sweep.py, but across multiple file
types and sizes instead of just sample.pdf.

This directly tests whether Module 1's features (trust_score,
stability_index, version, modified, challenge_count) - which are
about SUB-BLOCK BEHAVIOR, not file content - generalize across
completely different file types (PDF, image, audio, video).
"""

import os
import sys
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

TEST_FILES = ["wallpaper.jpg", "music.m4a", "sample.pdf", "video.mp4"]
MODIFICATION_RATES = [0.05, 0.10, 0.15, 0.20]


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


def setup_file(file_path):
    """Partition, sign, and initialize metadata for a file."""
    manager = FilePartitionManager()
    info = manager.partition_file(file_path)
    info = SubsetSignature.sign_partition(info)
    info = MetadataTracker.initialize(info)
    return info


def clean_baseline_check(info, file_name):
    """
    Step 1 (as planned): confirm a clean, untouched file produces
    ZERO verification failures - a false-positive sanity check.
    """
    challenge = ChallengeGenerator.generate_challenge(info, seed=config.RANDOM_SEED)
    result = VerificationEngine.verify_challenge(info, challenge)

    print(f"  Clean baseline: challenged {len(challenge)} subsets, "
          f"verified {result['verified']}, failed {result['failed']} "
          f"(should be 0)")

    return {
        "file": file_name,
        "test": "clean_baseline",
        "mod_rate": 0.0,
        "subsets_challenged": len(challenge),
        "false_positives": result["failed"],
    }


def run_tampering_sweep(file_path, file_name, scorer):
    """Step 2: sweep modification rates, measure recall/efficiency."""
    results = []

    for mod_rate in MODIFICATION_RATES:
        seed = config.RANDOM_SEED

        info = setup_file(file_path)

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

        print(f"  mod_rate={mod_rate}: total_subsets={total_subsets}, "
              f"tampered={len(tampered_subsets)}, recall={round(recall, 4)}, "
              f"efficiency={round(efficiency * 100, 2)}%")

        results.append({
            "file": file_name,
            "test": "tampering_sweep",
            "mod_rate": mod_rate,
            "total_subsets": total_subsets,
            "tampered_subsets": len(tampered_subsets),
            "recall": round(recall, 4),
            "efficiency_pct": round(efficiency * 100, 2),
        })

    return results


if __name__ == "__main__":
    if not KeyManager.keys_exist():
        KeyManager.generate_keys()

    scorer = RiskScorer(model_type=config.RISK_MODEL)
    scorer.load()

    all_results = []

    for file_name in TEST_FILES:
        file_path = os.path.join(config.DATASET_DIR, file_name)

        if not os.path.exists(file_path):
            print(f"\nSkipping {file_name} - not found at {file_path}")
            continue

        file_size = os.path.getsize(file_path)
        print(f"\n=== {file_name} ({file_size:,} bytes) ===")

        info = setup_file(file_path)
        print(f"  Partitioned: {info['total_blocks']} blocks, "
              f"{info['total_sub_blocks']} sub-blocks, {len(info['subsets'])} subsets")

        baseline_result = clean_baseline_check(info, file_name)
        all_results.append(baseline_result)

        sweep_results = run_tampering_sweep(file_path, file_name, scorer)
        all_results.extend(sweep_results)

    results_df = pd.DataFrame(all_results)

    output_path = os.path.join(config.RESULTS_PROCESSED_DIR, "multi_file_validation.csv")
    os.makedirs(config.RESULTS_PROCESSED_DIR, exist_ok=True)
    results_df.to_csv(output_path, index=False)

    print(f"\n\nSaved: {output_path}")

    print("\n--- Clean Baseline Summary (false positives should all be 0) ---")
    baseline_df = results_df[results_df["test"] == "clean_baseline"]
    print(baseline_df[["file", "subsets_challenged", "false_positives"]].to_string(index=False))

    print("\n--- Tampering Sweep Summary ---")
    sweep_df = results_df[results_df["test"] == "tampering_sweep"]
    print(sweep_df[["file", "mod_rate", "total_subsets", "tampered_subsets",
                     "recall", "efficiency_pct"]].to_string(index=False))