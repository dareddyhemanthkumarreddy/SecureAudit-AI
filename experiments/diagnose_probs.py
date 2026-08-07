"""
Quick diagnostic: check the distribution of predicted probabilities
to understand why threshold sweep results are identical across
0.50-0.95.
"""

import os
import sys
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from ai_agent.risk_scorer import RiskScorer, FEATURE_COLUMNS

dataset_path = os.path.join(config.RESULTS_RAW_DIR, "training_dataset.csv")
df = pd.read_csv(dataset_path)

scorer = RiskScorer(model_type="random_forest")
scorer.load()

X = df[FEATURE_COLUMNS]
probs = scorer.model.predict_proba(X)[:, 1]

df["predicted_prob"] = probs

print("Overall probability distribution:")
print(df["predicted_prob"].describe())

print("\nValue counts (rounded to 2 decimals), top 15:")
print(df["predicted_prob"].round(2).value_counts().head(15))

print("\nProbability distribution BY tamper_type:")
for t_type in ["modification", "corruption", "attack", "none"]:
    subset = df[df["tamper_type"] == t_type]["predicted_prob"]
    print(f"\n{t_type}:")
    print(subset.describe())