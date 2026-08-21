"""
SecureAudit-AI — Manual Validation Log Graph Generator
Reads results/processed/manual_validation_log.csv (built up run by
run via experiments/single_run_validation.py) and produces the
recall/efficiency-vs-modification-rate figures, broken down by file,
plus a combined trade-off view.
"""

import os
import sys
import pandas as pd
import matplotlib.pyplot as plt

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

LOG_PATH = os.path.join(config.RESULTS_PROCESSED_DIR, "manual_validation_log.csv")
os.makedirs(config.GRAPH_DIR, exist_ok=True)


def load_data():
    df = pd.read_csv(LOG_PATH)
    # Clean baseline rows have mod_rate=0 and blank recall/efficiency - drop
    # them from the tampering-rate plots, but keep for the summary printout.
    tampering_df = df[df["mod_rate"] > 0].copy()
    baseline_df = df[df["mod_rate"] == 0].copy()
    return df, tampering_df, baseline_df


def print_completeness_check(df):
    """Confirms all expected file/rate combinations are present before plotting."""
    expected_files = ["wallpaper.jpg", "music.m4a", "sample.pdf", "video.mp4"]
    expected_rates = [0.0, 0.05, 0.10, 0.15, 0.20]

    print("--- Completeness Check ---")
    missing = []
    for f in expected_files:
        for r in expected_rates:
            match = df[(df["file"] == f) & (abs(df["mod_rate"] - r) < 0.001)]
            if len(match) == 0:
                missing.append((f, r))

    if missing:
        print(f"MISSING {len(missing)} run(s):")
        for f, r in missing:
            print(f"  {f} @ mod_rate={r}")
    else:
        print(f"All {len(expected_files) * len(expected_rates)} expected runs present. Proceeding.")
    print()
    return len(missing) == 0


def plot_recall_by_file(tampering_df):
    fig, ax = plt.subplots(figsize=(8, 5))

    for file_name in tampering_df["file"].unique():
        subset = tampering_df[tampering_df["file"] == file_name].sort_values("mod_rate")
        ax.plot(subset["mod_rate"] * 100, subset["recall"] * 100, marker="o", label=file_name)

    ax.set_xlabel("Modification Rate (%)")
    ax.set_ylabel("Recall - Tampering Detected (%)")
    ax.set_title("Recall vs. Modification Rate, by File\n(4 file types, 160KB-16.9MB)")
    ax.legend()
    ax.grid(True, alpha=0.3)

    out_path = os.path.join(config.GRAPH_DIR, "manual_recall_by_file.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


def plot_efficiency_by_file(tampering_df):
    fig, ax = plt.subplots(figsize=(8, 5))

    for file_name in tampering_df["file"].unique():
        subset = tampering_df[tampering_df["file"] == file_name].sort_values("mod_rate")
        ax.plot(subset["mod_rate"] * 100, subset["efficiency_pct"], marker="o", label=file_name)

    ax.set_xlabel("Modification Rate (%)")
    ax.set_ylabel("Verification Work Skipped (%)")
    ax.set_title("Efficiency vs. Modification Rate, by File\n(4 file types, 160KB-16.9MB)")
    ax.legend()
    ax.grid(True, alpha=0.3)

    out_path = os.path.join(config.GRAPH_DIR, "manual_efficiency_by_file.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


def plot_recall_efficiency_tradeoff(tampering_df):
    """Scatter showing the recall-vs-efficiency trade-off directly, colored by mod_rate."""
    fig, ax = plt.subplots(figsize=(8, 6))

    markers = {"wallpaper.jpg": "o", "music.m4a": "s", "sample.pdf": "^", "video.mp4": "D"}

    scatter = None
    for file_name in tampering_df["file"].unique():
        subset = tampering_df[tampering_df["file"] == file_name].sort_values("mod_rate")
        scatter = ax.scatter(subset["efficiency_pct"], subset["recall"] * 100,
                              c=subset["mod_rate"] * 100, cmap="viridis",
                              marker=markers.get(file_name, "o"), s=100,
                              label=file_name, edgecolors="black", linewidths=0.5)

    cbar = fig.colorbar(scatter, ax=ax)
    cbar.set_label("Modification Rate (%)")

    ax.set_xlabel("Efficiency - Work Skipped (%)")
    ax.set_ylabel("Recall - Tampering Detected (%)")
    ax.set_title("Recall vs. Efficiency Trade-off\n(color = modification rate, shape = file)")
    ax.legend(loc="lower left")
    ax.grid(True, alpha=0.3)

    out_path = os.path.join(config.GRAPH_DIR, "manual_recall_efficiency_tradeoff.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


def plot_false_positive_summary(baseline_df):
    fig, ax = plt.subplots(figsize=(7, 4))

    ax.bar(baseline_df["file"], baseline_df["false_positives"], color="#55A868")
    ax.set_ylabel("False Positives (clean baseline)")
    ax.set_title("Clean Baseline: False Positives by File\n(all should be 0)")
    ax.set_ylim(0, max(1, baseline_df["false_positives"].max() + 1))
    ax.grid(True, alpha=0.3, axis="y")

    out_path = os.path.join(config.GRAPH_DIR, "manual_false_positive_check.png")
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    if not os.path.exists(LOG_PATH):
        print(f"No log found at {LOG_PATH}. Run experiments/single_run_validation.py first.")
        sys.exit(1)

    df, tampering_df, baseline_df = load_data()

    complete = print_completeness_check(df)

    print("Generating figures from available data...\n")
    plot_recall_by_file(tampering_df)
    plot_efficiency_by_file(tampering_df)
    plot_recall_efficiency_tradeoff(tampering_df)
    plot_false_positive_summary(baseline_df)

    print(f"\nAll figures saved to: {config.GRAPH_DIR}")

    if not complete:
        print("\nNOTE: some expected runs were missing (see above) - figures")
        print("were still generated from whatever data IS present. Run the")
        print("missing single_run_validation.py commands and re-run this script.")