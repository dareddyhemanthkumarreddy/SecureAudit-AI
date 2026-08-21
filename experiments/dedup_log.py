"""
One-time cleanup: removes duplicate rows from
results/processed/manual_validation_log.csv, keeping the first
occurrence of each (file, mod_rate) combination. Prints what was
removed so you can see exactly what changed.
"""

import os
import sys
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

LOG_PATH = os.path.join(config.RESULTS_PROCESSED_DIR, "manual_validation_log.csv")

df = pd.read_csv(LOG_PATH)
print(f"Rows before dedup: {len(df)}")

duplicates = df[df.duplicated(subset=["file", "mod_rate"], keep="first")]
if len(duplicates) > 0:
    print(f"\nFound {len(duplicates)} duplicate row(s):")
    print(duplicates[["file", "mod_rate"]].to_string(index=False))
else:
    print("\nNo duplicates found.")

df_clean = df.drop_duplicates(subset=["file", "mod_rate"], keep="first")
print(f"\nRows after dedup: {len(df_clean)}")

df_clean.to_csv(LOG_PATH, index=False)
print(f"\nSaved cleaned log to: {LOG_PATH}")