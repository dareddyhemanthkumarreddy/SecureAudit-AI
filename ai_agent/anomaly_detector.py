"""
SecureAudit-AI — Anomaly Pattern Detector (AI Agent Module 3)
Uses Isolation Forest to detect audit sessions that behave
unusually compared to normal, historical patterns - e.g. a
compromised node showing abnormally high tampering signs.

Unlike Module 1 (per-sub-block, supervised), this operates at
the SESSION level (cross-file/cross-time) and is UNSUPERVISED -
it never sees true_anomaly during training, since in a real
deployment we would not know in advance which sessions are
compromised.
"""

import os
import sys
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

# Only OBSERVABLE features - things a real auditor could measure
# without knowing ground truth about what caused them.
SESSION_FEATURE_COLUMNS = [
    "avg_trust_score", "avg_stability_index",
    "fraction_modified", "avg_challenge_count", "pct_low_trust",
]


class AnomalyDetector:
    """Trains and applies an Isolation Forest over audit session features."""

    def __init__(self, contamination="auto"):
        """
        Args:
            contamination: expected proportion of anomalies in the data.
                "auto" lets sklearn decide; or set a float like 0.1 if
                you have a rough estimate (we know it's ~10% here, but
                using "auto" is more realistic for deployment where
                this isn't known in advance).
        """
        self.contamination = contamination
        self.model = None

    def train(self, df):
        """Trains Isolation Forest on session features (unsupervised)."""
        X = df[SESSION_FEATURE_COLUMNS]

        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=config.RANDOM_SEED,
        )
        self.model.fit(X)

        return self.model

    def predict(self, df):
        """
        Returns:
            predictions: array of 1 (normal) / -1 (anomaly) per sklearn convention
            anomaly_scores: lower (more negative) = more anomalous
        """
        X = df[SESSION_FEATURE_COLUMNS]
        predictions = self.model.predict(X)
        anomaly_scores = self.model.score_samples(X)
        return predictions, anomaly_scores

    def save(self, filename="anomaly_detector.pkl"):
        os.makedirs(config.MODEL_STORE_DIR, exist_ok=True)
        path = os.path.join(config.MODEL_STORE_DIR, filename)
        joblib.dump(self.model, path)
        return path

    def load(self, filename="anomaly_detector.pkl"):
        path = os.path.join(config.MODEL_STORE_DIR, filename)
        self.model = joblib.load(path)
        return self


def evaluate_against_ground_truth(df, predictions):
    """
    Compares Isolation Forest's flags against true_anomaly - for
    VALIDATION/REPORTING ONLY. This ground truth was never used
    during training.
    """
    df = df.copy()
    df["predicted_anomaly"] = (predictions == -1).astype(int)

    true_positives = ((df["predicted_anomaly"] == 1) & (df["true_anomaly"] == 1)).sum()
    false_positives = ((df["predicted_anomaly"] == 1) & (df["true_anomaly"] == 0)).sum()
    false_negatives = ((df["predicted_anomaly"] == 0) & (df["true_anomaly"] == 1)).sum()
    true_negatives = ((df["predicted_anomaly"] == 0) & (df["true_anomaly"] == 0)).sum()

    total_anomalies = df["true_anomaly"].sum()
    detected = true_positives

    print(f"\nTrue anomalous sessions: {total_anomalies}")
    print(f"Correctly detected (true positives): {true_positives}")
    print(f"Missed (false negatives): {false_negatives}")
    print(f"Normal sessions incorrectly flagged (false positives): {false_positives}")
    print(f"Normal sessions correctly left alone (true negatives): {true_negatives}")

    return {
        "true_positives": int(true_positives),
        "false_positives": int(false_positives),
        "false_negatives": int(false_negatives),
        "true_negatives": int(true_negatives),
    }


if __name__ == "__main__":
    dataset_path = os.path.join(config.RESULTS_RAW_DIR, "session_data.csv")

    if not os.path.exists(dataset_path):
        print("No session dataset found. Run experiments/generate_session_data.py first.")
    else:
        df = pd.read_csv(dataset_path)
        print(f"Loaded {len(df)} sessions ({df['true_anomaly'].sum()} truly anomalous)")

        detector = AnomalyDetector(contamination=0.1)
        detector.train(df)

        predictions, scores = detector.predict(df)
        df["anomaly_score"] = scores

        print("\n--- Evaluation (ground truth used for reporting only) ---")
        results = evaluate_against_ground_truth(df, predictions)

        path = detector.save()
        print(f"\nSaved model: {path}")

        print("\n--- Sessions sorted by anomaly score (most anomalous first) ---")
        df_sorted = df.sort_values("anomaly_score")
        print(df_sorted[["avg_trust_score", "fraction_modified", "pct_low_trust",
                          "anomaly_score", "true_anomaly"]].head(10).to_string(index=False))