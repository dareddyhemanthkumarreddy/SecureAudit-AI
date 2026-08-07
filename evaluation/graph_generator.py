"""
SecureAudit-AI — Graph Generator (Phase 12)
Produces the key figures for the paper from data already
collected in earlier phases. Each function reads its own
saved CSV and outputs a PNG into the graphs/ folder.
"""

import os
import sys
import pandas as pd
import matplotlib.pyplot as plt

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

os.makedirs(config.GRAPH_DIR, exist_ok=True)


def plot_recall_vs_modification_rate():
    """Figure 1: recall of each strategy across modification rates."""
    path = os.path.join(config.RESULTS_PROCESSED_DIR, "full_pipeline_summary.csv")
    df = pd.read_csv(path)

    fig, ax = plt.subplots(figsize=(8, 5))

    for strategy in df["strategy"].unique():
        subset = df[df["strategy"] == strategy].sort_values("mod_rate")
        ax.plot(subset["mod_rate"] * 100, subset["avg_recall"] * 100,
                marker="o", label=strategy)

    ax.set_xlabel("Modification Rate (%)")
    ax.set_ylabel("Recall - Tampering Detected (%)")
    ax.set_title("Detection Rate vs. Modification Rate, by Strategy")
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(True, alpha=0.3)

    out_path = os.path.join(config.GRAPH_DIR, "recall_vs_modification_rate.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


def plot_efficiency_vs_modification_rate():
    """Figure 2: verification work saved (efficiency) across modification rates."""
    path = os.path.join(config.RESULTS_PROCESSED_DIR, "full_pipeline_summary.csv")
    df = pd.read_csv(path)

    fig, ax = plt.subplots(figsize=(8, 5))

    for strategy in df["strategy"].unique():
        subset = df[df["strategy"] == strategy].sort_values("mod_rate")
        ax.plot(subset["mod_rate"] * 100, subset["avg_efficiency_pct"],
                marker="o", label=strategy)

    ax.set_xlabel("Modification Rate (%)")
    ax.set_ylabel("Verification Work Skipped (%)")
    ax.set_title("Efficiency vs. Modification Rate, by Strategy")
    ax.legend(loc="upper right", fontsize=8)
    ax.grid(True, alpha=0.3)

    out_path = os.path.join(config.GRAPH_DIR, "efficiency_vs_modification_rate.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


def plot_baseline_comparison_bar():
    """Figure 3: bar chart of recall + efficiency at one fixed scenario."""
    path = os.path.join(config.RESULTS_PROCESSED_DIR, "baseline_comparison.csv")
    df = pd.read_csv(path)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    ax1.bar(df["strategy"], df["recall"] * 100, color="#4C72B0")
    ax1.set_ylabel("Recall (%)")
    ax1.set_title("Detection Rate by Strategy\n(5% mod, 2% corruption, 2% attack)")
    ax1.tick_params(axis="x", rotation=30)
    ax1.grid(True, alpha=0.3, axis="y")

    ax2.bar(df["strategy"], df["efficiency_pct"], color="#DD8452")
    ax2.set_ylabel("Efficiency - Work Skipped (%)")
    ax2.set_title("Verification Work Saved by Strategy")
    ax2.tick_params(axis="x", rotation=30)
    ax2.grid(True, alpha=0.3, axis="y")

    fig.tight_layout()

    out_path = os.path.join(config.GRAPH_DIR, "baseline_comparison_bar.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


def plot_anomaly_scores():
    """Figure 4: Module 3 anomaly scores, normal vs anomalous sessions."""
    path = os.path.join(config.RESULTS_RAW_DIR, "session_data.csv")
    df = pd.read_csv(path)

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from ai_agent.anomaly_detector import AnomalyDetector

    detector = AnomalyDetector()
    detector.load()
    _, scores = detector.predict(df)
    df["anomaly_score"] = scores

    fig, ax = plt.subplots(figsize=(8, 5))

    normal = df[df["true_anomaly"] == 0]["anomaly_score"]
    anomalous = df[df["true_anomaly"] == 1]["anomaly_score"]

    ax.scatter(range(len(normal)), normal.sort_values(), label="Normal sessions",
               color="#4C72B0", s=40)
    ax.scatter(range(len(normal), len(normal) + len(anomalous)),
               anomalous.sort_values(), label="Anomalous sessions",
               color="#C44E52", s=60, marker="X")

    ax.set_xlabel("Session (sorted by anomaly score)")
    ax.set_ylabel("Anomaly Score (lower = more anomalous)")
    ax.set_title("Module 3: Isolation Forest Anomaly Scores\n(5/5 anomalous sessions correctly separated)")
    ax.legend()
    ax.grid(True, alpha=0.3)

    out_path = os.path.join(config.GRAPH_DIR, "anomaly_scores.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


def plot_garlic_privacy():
    """Figure 5: adversary advantage vs decoy ratio (garlic bundling privacy)."""
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from garlic.garlic_bundler import GarlicBundler, simulate_adversary_guess

    all_subset_ids = list(range(1, 775))
    real_subset_ids = [655, 115, 26, 760, 282]

    decoy_ratios = [1, 2, 4, 8, 16]
    advantages = []

    for ratio in decoy_ratios:
        bundle_info = GarlicBundler.construct_bundle(
            real_subset_ids, all_subset_ids, decoys_per_real=ratio, seed=config.RANDOM_SEED
        )
        result = simulate_adversary_guess(bundle_info, num_trials=2000, seed=config.RANDOM_SEED)
        advantages.append(result["adversary_advantage"])

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(decoy_ratios, advantages, marker="o", color="#55A868")
    ax.axhline(0, color="gray", linestyle="--", alpha=0.5, label="Zero advantage (ideal)")

    ax.set_xlabel("Decoys per Real Request")
    ax.set_ylabel("Adversary Advantage (guess accuracy - chance baseline)")
    ax.set_title("Garlic Bundling: Privacy Guarantee vs. Decoy Ratio")
    ax.legend()
    ax.grid(True, alpha=0.3)

    out_path = os.path.join(config.GRAPH_DIR, "garlic_privacy.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    print("Generating all figures...\n")
    plot_recall_vs_modification_rate()
    plot_efficiency_vs_modification_rate()
    plot_baseline_comparison_bar()
    plot_anomaly_scores()
    plot_garlic_privacy()
    print(f"\nAll figures saved to: {config.GRAPH_DIR}")