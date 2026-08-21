"""
Standalone fix for the false-positive chart, which was broken
(all-zero bars render as an empty plot). This replaces it with a
clear table-style visualization showing exact numbers per file.

Run this after evaluation/graph_generator_manual.py to regenerate
just this one figure with the fix.
"""

import os
import sys
import pandas as pd
import matplotlib.pyplot as plt

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

LOG_PATH = os.path.join(config.RESULTS_PROCESSED_DIR, "manual_validation_log.csv")

df = pd.read_csv(LOG_PATH)
baseline_df = df[df["mod_rate"] == 0].copy()

fig, ax = plt.subplots(figsize=(8, 4))
ax.axis("off")

table_data = []
for _, row in baseline_df.iterrows():
    status = "PASS (0 false positives)" if row["false_positives"] == 0 else f"FAIL ({int(row['false_positives'])} false positives)"
    table_data.append([
        row["file"],
        f"{int(row['file_size_bytes']):,} bytes",
        f"{int(row['subsets_selected'])} subsets challenged",
        status,
    ])

table = ax.table(
    cellText=table_data,
    colLabels=["File", "Size", "Subsets Challenged", "Result"],
    cellLoc="center",
    loc="center",
    colWidths=[0.22, 0.22, 0.28, 0.35],
)
table.auto_set_font_size(False)
table.set_fontsize(11)
table.scale(1, 2.2)

# Color the "Result" column green since all pass
for i in range(1, len(table_data) + 1):
    table[(i, 3)].set_facecolor("#d4edda")

for j in range(4):
    table[(0, j)].set_facecolor("#4C72B0")
    table[(0, j)].set_text_props(color="white", weight="bold")

ax.set_title("Clean Baseline Check: Zero False Positives Across All File Types",
              fontsize=13, pad=20)

out_path = os.path.join(config.GRAPH_DIR, "manual_false_positive_check.png")
fig.savefig(out_path, dpi=150, bbox_inches="tight")
plt.close(fig)
print(f"Fixed and saved: {out_path}")