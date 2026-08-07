"""
SecureAudit-AI — Threshold Sweep
Tests multiple risk-score thresholds and measures the
trade-off between detection rate (recall) and verification
work saved (efficiency). Since Module 1 only reliably
detects "modification"-type tampering (see Phase 5 findings),
this sweep evaluates against modification-type tampering,
which is the fair, honest scope for this module.
"""

import os
import sys
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from ai_agent.risk_scorer import RiskScorer, FEATURE_COLUMNS


def run_threshold_sweep(df, model, thresholds=None):
    """
    For each threshold, computes:
      - overall recall (against ALL true_label==1, for context)
      - modification-only recall (the fair metric for this module)
      - false positive rate on untouched data
      - efficiency = % of sub-blocks skipped (predicted as safe)
    """
    if thresholds is None:
        thresholds = [round(t, 2) for t in [0.50, 0.55, 0.60, 0.65, 0.70,
                                              0.75, 0.80, 0.85, 0.90, 0.95]]

    X = df[FEATURE_COLUMNS]
    probs = model.predict_proba(X)[:, 1]
    df = df.copy()
    df["predicted_prob"] = probs

    results = []

    modification_rows = df[df["tamper_type"] == "modification"]
    untouched_rows = df[df["tamper_type"] == "none"]

    for t in thresholds:
        preds = (df["predicted_prob"] >= t).astype(int)

        overall_detected = ((preds == 1) & (df["true_label"] == 1)).sum()
        overall_total_tampered = (df["true_label"] == 1).sum()
        overall_recall = overall_detected / overall_total_tampered if overall_total_tampered else 0

        mod_preds = (modification_rows["predicted_prob"] >= t).astype(int)
        mod_recall = mod_preds.sum() / len(modification_rows) if len(modification_rows) else 0

        untouched_preds = (untouched_rows["predicted_prob"] >= t).astype(int)
        false_positive_rate = untouched_preds.sum() / len(untouched_rows) if len(untouched_rows) else 0

        skipped = (preds == 0).sum()
        efficiency = skipped / len(df)

        results.append({
            "threshold": t,
            "overall_recall": round(overall_recall, 4),
            "modification_recall": round(mod_recall, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "efficiency_pct_skipped": round(efficiency * 100, 2),
        })

    return pd.DataFrame(results)


if __name__ == "__main__":
    dataset_path = os.path.join(config.RESULTS_RAW_DIR, "training_dataset.csv")

    if not os.path.exists(dataset_path):
        print("No training dataset found. Run experiments/generate_training_data.py first.")
    else:
        df = pd.read_csv(dataset_path)

        # Train fresh (or load if already saved)
        scorer = RiskScorer(model_type="random_forest")
        scorer.load()

        sweep_results = run_threshold_sweep(df, scorer.model)

        print(sweep_results.to_string(index=False))

        output_path = os.path.join(config.RESULTS_PROCESSED_DIR, "threshold_sweep.csv")
        os.makedirs(config.RESULTS_PROCESSED_DIR, exist_ok=True)
        sweep_results.to_csv(output_path, index=False)
        print(f"\nSaved to: {output_path}")

        # Suggest best threshold: highest modification_recall while
        # keeping false_positive_rate reasonably low (<= 5%)
        candidates = sweep_results[sweep_results["false_positive_rate"] <= 0.05]
        if len(candidates) > 0:
            best = candidates.loc[candidates["modification_recall"].idxmax()]
            print(f"\nSuggested threshold: {best['threshold']} "
                  f"(modification_recall={best['modification_recall']}, "
                  f"false_positive_rate={best['false_positive_rate']}, "
                  f"efficiency={best['efficiency_pct_skipped']}% skipped)")
        else:
            print("\nNo threshold met the false_positive_rate <= 5% criterion. "
                  "Consider adjusting the model or criterion.")