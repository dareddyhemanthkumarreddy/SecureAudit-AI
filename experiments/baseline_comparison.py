"""
SecureAudit-AI — Baseline Comparison (Phase 10 conclusion)
Runs all 4 baseline strategies (Verify-All, Random, Metadata,
Rule-Based AMTRS) PLUS our AI risk-scorer approach, against the
same realistic mixed-tampering scenario (modification + silent
corruption + adversarial attack combined). Measures recall
(fraction of truly-tampered subsets caught) and efficiency
(% of subsets skipped) for each.

This deliberately reuses the Phase 5 finding: metadata-based
methods (including our own Module 1 in isolation) cannot catch
corruption/attack-type tampering. The comparison table makes
this limitation visible for ALL non-cryptographic methods, and
sets up why signature-based verification (Phase 2) is a
necessary second layer, not an optional add-on.
"""

import os
import sys
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from partition.partition import FilePartitionManager
from signature.subset_signature import SubsetSignature
from signature.key_manager import KeyManager
from features.metadata_tracker import MetadataTracker
from simulation.modification_simulator import ModificationSimulator
from simulation.corruption_simulator import CorruptionSimulator
from simulation.attack_simulator import AttackSimulator
from baseline.verify_all import VerifyAll
from baseline.random_verification import RandomVerification
from baseline.metadata_verification import MetadataVerification
from baseline.rule_based_amtrs import RuleBasedAMTRS
from ai_agent.risk_scorer import RiskScorer, FEATURE_COLUMNS


def get_tampered_subset_ids(partition_info, tampered_sub_block_ids):
    """A subset counts as 'truly tampered' if ANY of its member
    sub-blocks were touched by any simulator."""
    tampered_set = set(tampered_sub_block_ids)
    tampered_subsets = set()

    for subset in partition_info["subsets"]:
        for member in subset["members"]:
            key = (member["block_id"], member["sub_block_id"])
            if key in tampered_set:
                tampered_subsets.add(subset["subset_id"])
                break

    return tampered_subsets


def ai_based_selection(partition_info, scorer, threshold=0.5):
    """
    Our Module 1 approach: score every sub-block, aggregate to
    subset level by taking the MAX risk score among a subset's
    members, select subsets above threshold.
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
    selected = set(max_risk_per_subset[max_risk_per_subset >= threshold].index)

    return selected


def evaluate_strategy(name, selected, tampered_subsets, total_subsets):
    recall = len(selected & tampered_subsets) / len(tampered_subsets) if tampered_subsets else 0
    efficiency = 1 - (len(selected) / total_subsets)

    return {
        "strategy": name,
        "subsets_selected": len(selected),
        "subsets_skipped": total_subsets - len(selected),
        "efficiency_pct": round(efficiency * 100, 2),
        "recall": round(recall, 4),
        "tampered_caught": len(selected & tampered_subsets),
        "tampered_missed": len(tampered_subsets - selected),
    }


if __name__ == "__main__":
    file_path = os.path.join(config.DATASET_DIR, "sample.pdf")

    if not KeyManager.keys_exist():
        KeyManager.generate_keys()

    print("Setting up: partition -> sign -> initialize metadata...")
    manager = FilePartitionManager()
    info = manager.partition_file(file_path)
    info = SubsetSignature.sign_partition(info)
    info = MetadataTracker.initialize(info)

    print("Applying realistic mixed tampering (5% mod, 2% corruption, 2% attack)...")
    modified = ModificationSimulator.simulate(info, rate=0.05, seed=config.RANDOM_SEED)
    corrupted = CorruptionSimulator.simulate(info, rate=0.02, seed=config.RANDOM_SEED + 1)
    attacked = AttackSimulator.simulate(info, rate=0.02)

    all_tampered_sub_blocks = set(modified) | set(corrupted) | set(attacked)
    tampered_subsets = get_tampered_subset_ids(info, all_tampered_sub_blocks)

    total_subsets = len(info["subsets"])
    print(f"\nTotal subsets: {total_subsets}")
    print(f"Truly tampered subsets (contain >=1 modified/corrupted/attacked sub-block): {len(tampered_subsets)}")

    scorer = RiskScorer(model_type="random_forest")
    scorer.load()

    strategies = {
        "Verify-All": VerifyAll.select(info),
        "Random (10%)": RandomVerification.select(info),
        "Metadata-Only": MetadataVerification.select(info),
        "Rule-Based AMTRS": RuleBasedAMTRS.select(info),
        "Our AI (Module 1)": ai_based_selection(info, scorer),
    }

    print("\n--- Comparison ---")
    results = []
    for name, selected in strategies.items():
        result = evaluate_strategy(name, selected, tampered_subsets, total_subsets)
        results.append(result)

    results_df = pd.DataFrame(results)
    print(results_df.to_string(index=False))

    output_path = os.path.join(config.RESULTS_PROCESSED_DIR, "baseline_comparison.csv")
    os.makedirs(config.RESULTS_PROCESSED_DIR, exist_ok=True)
    results_df.to_csv(output_path, index=False)
    print(f"\nSaved to: {output_path}")

    print("\nNote: 'Metadata-Only', 'Rule-Based AMTRS', and 'Our AI (Module 1)' all rely")
    print("on metadata signals and will show the SAME structural gap: they catch")
    print("modification-type tampering but miss corruption/attack-type tampering,")
    print("which leaves no metadata trace. This is expected (see Phase 5 finding) -")
    print("Phase 2's signature verification is what closes this specific gap.")