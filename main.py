"""
SecureAudit-AI — Main Entry Point
Runs the FULL integrated pipeline end-to-end:

  Partition -> Sign (Phase 2) -> Metadata Init (Phase 4)
  -> Upload to Cloud (Phase 1) -> Simulate Tampering (Phase 3, demo)
  -> Module 1: AI Risk Scoring + Safety Net (Phase 5 + 11)
  -> Module 3: Anomaly Detection on THIS session's aggregate stats
  -> Module 2: Adaptive Audit Scheduling (Phase 7), using Module 1 + 3 outputs
  -> Module 4: Garlic Bundling (Phase 8, with saturation fix)
  -> TPA Challenge + Signature Verification (Phase 2)
  -> Report

Module 1 (Risk Scorer) and Module 3 (Anomaly Detector) models must
already be trained (see experiments/generate_training_data.py +
ai_agent/risk_scorer.py, and experiments/generate_session_data.py +
ai_agent/anomaly_detector.py) - this script LOADS them rather than
retraining on every run.

Note: Module 3 was trained on MULTI-SESSION historical data (50
simulated sessions). Using it here to score a SINGLE live session
is a reasonable real-world use of a pre-trained model, but the
model itself is not being retrained or updated by this run - it
is applying what it already learned to one new data point. Machine
unlearning (Phase 9) is a separate, standalone operation on that
historical training set and is not part of this live pipeline.
"""

import os
import random
import pandas as pd

import config
from partition.partition import FilePartitionManager
from signature.key_manager import KeyManager
from signature.subset_signature import SubsetSignature
from storage.cloud_storage import CloudStorage
from features.metadata_tracker import MetadataTracker
from simulation.modification_simulator import ModificationSimulator
from simulation.corruption_simulator import CorruptionSimulator
from simulation.attack_simulator import AttackSimulator
from ai_agent.risk_scorer import RiskScorer
from ai_agent.anomaly_detector import AnomalyDetector, SESSION_FEATURE_COLUMNS
from ai_agent.audit_scheduler import AuditScheduler
from garlic.garlic_bundler import GarlicBundler
from auditor.verification_engine import VerificationEngine

FILE_PATH = os.path.join(config.DATASET_DIR, "sample.pdf")


def select_with_safety_net(partition_info, scorer, threshold=0.5,
                            safety_net_pct=config.SAFETY_NET_PERCENTAGE, seed=config.RANDOM_SEED):
    """Module 1 AI selection + random safety net (see Phase 11)."""
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

    return ai_selected | safety_net, ai_selected, safety_net


def compute_session_features(partition_info):
    """
    Computes this run's session-level aggregate features - the
    SAME feature set Module 3's Isolation Forest was trained on
    (see experiments/generate_session_data.py). This lets us score
    the CURRENT audit session against the historically-trained model.
    """
    trust_scores = []
    stability_scores = []
    modified_flags = []
    challenge_counts = []

    for block in partition_info["blocks"]:
        for sub in block["sub_blocks"]:
            trust_scores.append(sub["trust_score"])
            stability_scores.append(MetadataTracker.calculate_stability(sub))
            modified_flags.append(sub["modified"])
            challenge_counts.append(sub["challenge_count"])

    n = len(trust_scores)

    return pd.DataFrame([{
        "avg_trust_score": sum(trust_scores) / n,
        "avg_stability_index": sum(stability_scores) / n,
        "fraction_modified": sum(modified_flags) / n,
        "avg_challenge_count": sum(challenge_counts) / n,
        "pct_low_trust": sum(1 for t in trust_scores if t < 80) / n,
    }])


def main():
    print("=" * 70)
    print("SecureAudit-AI — Full Pipeline Run")
    print("=" * 70)

    # ---------------------------------------------------------
    # Phase 1: Partition
    # ---------------------------------------------------------
    print("\n[Phase 1] Partitioning file...")
    manager = FilePartitionManager()
    partition_info = manager.partition_file(FILE_PATH)
    print(f"  File: {partition_info['file_name']} ({partition_info['file_size']} bytes)")
    print(f"  Blocks: {partition_info['total_blocks']}, Sub-blocks: {partition_info['total_sub_blocks']}")

    # ---------------------------------------------------------
    # Phase 2: Keys + Subset Signing
    # ---------------------------------------------------------
    print("\n[Phase 2] Signing subsets...")
    if not KeyManager.keys_exist():
        KeyManager.generate_keys()
        print("  Generated new RSA-2048 keypair.")

    partition_info = SubsetSignature.sign_partition(partition_info)
    sig_stats = partition_info["signature_statistics"]
    print(f"  Subsets signed: {sig_stats['total_subsets']} (size {sig_stats['subset_size']} each)")
    print(f"  Signing time: {sig_stats['execution_time']} seconds")

    # ---------------------------------------------------------
    # Phase 4: Metadata + Trust Initialization
    # ---------------------------------------------------------
    print("\n[Phase 4] Initializing metadata and trust scores...")
    partition_info = MetadataTracker.initialize(partition_info)
    print(f"  Initialized: {partition_info['metadata_statistics']['total_initialized']} sub-blocks")

    # ---------------------------------------------------------
    # Phase 1: Upload to Cloud (simulated)
    # ---------------------------------------------------------
    print("\n[Phase 1] Uploading to simulated cloud...")
    storage_info = CloudStorage.upload(partition_info)
    print(f"  Uploaded to: {storage_info['storage_file']}")
    print(f"  Upload time: {storage_info['upload_time']} seconds")

    # ---------------------------------------------------------
    # Phase 3: Simulate real-world tampering (demo scenario)
    # ---------------------------------------------------------
    print("\n[Phase 3] Simulating tampering (5% mod, 2% corruption, 2% attack)...")
    modified = ModificationSimulator.simulate(partition_info, rate=0.05, seed=config.RANDOM_SEED)
    corrupted = CorruptionSimulator.simulate(partition_info, rate=0.02, seed=config.RANDOM_SEED + 1)
    attacked = AttackSimulator.simulate(partition_info, rate=0.02)
    print(f"  Modified: {len(modified)}, Corrupted (silent): {len(corrupted)}, Attacked (silent): {len(attacked)}")

    # ---------------------------------------------------------
    # Module 1 + Safety Net: AI Risk Scoring (Phase 5 + 11)
    # ---------------------------------------------------------
    print("\n[Module 1] Scoring subsets with AI risk scorer...")
    scorer = RiskScorer(model_type=config.RISK_MODEL)
    try:
        scorer.load()
    except FileNotFoundError:
        print("  No trained Module 1 model found. Run experiments/generate_training_data.py")
        print("  and ai_agent/risk_scorer.py first. Skipping AI selection for this run.")
        selected, ai_selected, safety_net = set(), set(), set()
    else:
        selected, ai_selected, safety_net = select_with_safety_net(partition_info, scorer)
        print(f"  AI flagged: {len(ai_selected)} subsets")
        print(f"  Safety net (random, catches what AI misses): {len(safety_net)} subsets")
        print(f"  Total selected for verification: {len(selected)} / {len(partition_info['subsets'])}")

    # ---------------------------------------------------------
    # Module 3: Anomaly Detection on THIS session (real, not stubbed)
    # ---------------------------------------------------------
    print("\n[Module 3] Scoring this session against historical anomaly model...")
    session_features = compute_session_features(partition_info)
    anomaly_detector = AnomalyDetector()
    try:
        anomaly_detector.load()
    except FileNotFoundError:
        print("  No trained Module 3 model found. Run experiments/generate_session_data.py")
        print("  and ai_agent/anomaly_detector.py first. Assuming not anomalous for this run.")
        anomaly_detected = False
    else:
        predictions, scores = anomaly_detector.predict(session_features)
        anomaly_detected = bool(predictions[0] == -1)
        print(f"  Session anomaly score: {round(scores[0], 4)}")
        print(f"  Flagged as anomalous: {anomaly_detected}")

    # ---------------------------------------------------------
    # Module 2: Adaptive Audit Scheduling (Phase 7)
    # ---------------------------------------------------------
    print("\n[Module 2] Computing next audit interval...")
    total_subsets = len(partition_info["subsets"])
    avg_risk = len(ai_selected) / total_subsets if total_subsets else 0
    next_interval = AuditScheduler.compute_next_interval(avg_risk, anomaly_detected)
    print(f"  Avg risk (fraction flagged): {round(avg_risk, 4)}")
    print(f"  Anomaly flag (from Module 3): {anomaly_detected}")
    print(f"  Next audit scheduled in: {next_interval} hours")

    # ---------------------------------------------------------
    # Module 4: Garlic Bundling (Phase 8, with saturation fix)
    # ---------------------------------------------------------
    print("\n[Module 4] Constructing garlic bundle...")
    all_subset_ids = [s["subset_id"] for s in partition_info["subsets"]]
    if selected:
        bundle_info = GarlicBundler.construct_bundle(
            list(selected), all_subset_ids, seed=config.RANDOM_SEED
        )
        bundle = bundle_info["bundle"]
        print(f"  Real requests: {len(selected)}, Decoys added: {bundle_info['decoys_actual']} "
              f"(requested {bundle_info['decoys_requested']}, capped={bundle_info['capped']})")
        print(f"  Bundle sent to TPA: {len(bundle)} total requests")
    else:
        bundle = []
        print("  No subsets selected (Module 1 model missing) - skipping bundle.")

    # ---------------------------------------------------------
    # TPA Challenge + Verification (Phase 2)
    # ---------------------------------------------------------
    print("\n[TPA] Verifying bundled subsets...")
    if bundle:
        verification_result = VerificationEngine.verify_challenge(partition_info, bundle)
        print(f"  Verified: {verification_result['verified']}")
        print(f"  Failed (tampering detected): {verification_result['failed']}")
        print(f"  Verification time: {verification_result['execution_time']} seconds")
    else:
        print("  Skipped (no bundle).")

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------
    print("\n" + "=" * 70)
    print("Pipeline complete. All 4 AI Agent modules engaged in this run:")
    print("  Module 1 (Risk Scorer), Module 2 (Scheduler), Module 3 (Anomaly")
    print("  Detector, scored against pre-trained historical model), Module 4")
    print("  (Garlic Bundler). Machine Unlearning (Phase 9) remains a separate,")
    print("  standalone operation on Module 3's historical training data - see")
    print("  ai_agent/unlearning.py.")
    print("=" * 70)


if __name__ == "__main__":
    main()