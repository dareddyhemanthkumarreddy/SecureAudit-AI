"""
SecureAudit-AI — Full Pipeline Sweep (Phase 11)
Runs our COMPLETE system: partition -> sign -> simulate tampering
-> Module 1 selects likely-modified subsets -> a random safety-net
also verifies a small percentage of Module-1-LOW subsets (catches
corruption/attack that Module 1 structurally cannot see) -> actual
cryptographic signature verification runs on the combined selection.

Swept across multiple modification rates and multiple runs, and
compared against Verify-All and the Phase 10 baselines, using REAL
verification results (not ground-truth cheating) to measure recall.
"""

import os
import sys
import pandas as pd
import random

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from partition.partition import FilePartitionManager
from signature.subset_signature import SubsetSignature
from signature.key_manager import KeyManager
from auditor.verification_engine import VerificationEngine
from features.metadata_tracker import MetadataTracker
from simulation.modification_simulator import ModificationSimulator
from simulation.corruption_simulator import CorruptionSimulator
from simulation.attack_simulator import AttackSimulator
from baseline.verify_all import VerifyAll
from baseline.random_verification import RandomVerification
from baseline.metadata_verification import MetadataVerification
from baseline.rule_based_amtrs import RuleBasedAMTRS
from ai_agent.risk_scorer import RiskScorer


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
    """
    Our full system's selection strategy: Module 1 flags likely-
    modified subsets, PLUS a random safety-net sample of the
    remaining (Module-1-LOW) subsets, so corruption/attack tampering
    (invisible to Module 1) still has a chance of being caught via
    actual signature verification.
    """
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


def evaluate_with_real_verification(name, selected, partition_info, tampered_subsets, total_subsets):
    """
    Actually RUNS signature verification on the selected subsets
    (not just checking ground truth) - this is the honest way to
    measure real detected recall, using Phase 2's crypto layer.
    """
    verification_result = VerificationEngine.verify_challenge(partition_info, list(selected))

    detected_tampered = set()
    for entry in verification_result["verification_log"]:
        if entry["result"] == "FAIL":
            detected_tampered.add(entry["subset_id"])

    recall = len(detected_tampered) / len(tampered_subsets) if tampered_subsets else 0
    efficiency = 1 - (len(selected) / total_subsets)

    return {
        "strategy": name,
        "subsets_selected": len(selected),
        "efficiency_pct": round(efficiency * 100, 2),
        "recall": round(recall, 4),
        "tampered_caught": len(detected_tampered),
        "tampered_total": len(tampered_subsets),
    }


def run_one_sweep_point(file_path, mod_rate, seed, scorer):
    if not KeyManager.keys_exist():
        KeyManager.generate_keys()

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

    strategies = {
        "Verify-All": VerifyAll.select(info),
        "Random (10%)": RandomVerification.select(info, seed=seed),
        "Metadata-Only": MetadataVerification.select(info),
        "Rule-Based AMTRS": RuleBasedAMTRS.select(info),
        "Our Full System (AI + Safety Net)": ai_plus_safety_net_selection(info, scorer, seed=seed),
    }

    rows = []
    for name, selected in strategies.items():
        result = evaluate_with_real_verification(name, selected, info, tampered_subsets, total_subsets)
        result["mod_rate"] = mod_rate
        result["seed"] = seed
        rows.append(result)

    return rows


if __name__ == "__main__":
    file_path = os.path.join(config.DATASET_DIR, "sample.pdf")

    scorer = RiskScorer(model_type="random_forest")
    scorer.load()

    all_results = []

    for mod_rate in config.MODIFICATION_RATES:
        for run in range(config.NUMBER_OF_RUNS):
            seed = config.RANDOM_SEED + run * 100
            print(f"Running mod_rate={mod_rate}, run={run+1}/{config.NUMBER_OF_RUNS}...")
            rows = run_one_sweep_point(file_path, mod_rate, seed, scorer)
            all_results.extend(rows)

    results_df = pd.DataFrame(all_results)

    output_path = os.path.join(config.RESULTS_RAW_DIR, "full_pipeline_sweep.csv")
    os.makedirs(config.RESULTS_RAW_DIR, exist_ok=True)
    results_df.to_csv(output_path, index=False)

    print(f"\nSaved raw results: {output_path}")

    print("\n--- Averaged Results (across all runs, by strategy and mod_rate) ---")
    summary = results_df.groupby(["strategy", "mod_rate"]).agg(
        avg_efficiency_pct=("efficiency_pct", "mean"),
        avg_recall=("recall", "mean"),
    ).round(4).reset_index()

    print(summary.to_string(index=False))

    summary_path = os.path.join(config.RESULTS_PROCESSED_DIR, "full_pipeline_summary.csv")
    os.makedirs(config.RESULTS_PROCESSED_DIR, exist_ok=True)
    summary.to_csv(summary_path, index=False)
    print(f"\nSaved summary: {summary_path}")