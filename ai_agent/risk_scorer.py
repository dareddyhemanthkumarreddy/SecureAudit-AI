"""
SecureAudit-AI — Risk Scorer (AI Agent Module 1)
Trains Random Forest and Gradient Boosting classifiers to
output a continuous risk score (0.0-1.0) per sub-block, based
on its metadata features. Replaces the old rule-based HIGH/
MEDIUM/LOW system with a learned, threshold-tunable score.

NOTE: verification_count was removed from features - it was
always 0 in our current training data (no TPA challenge runs
during simulation), so it added no signal and only wasted
model capacity. Re-add once Phase 2 challenge data is wired
into the training generator.
"""

import os
import sys
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import roc_auc_score, precision_score, recall_score, f1_score

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config

FEATURE_COLUMNS = [
    "trust_score", "stability_index", "version",
    "modified", "challenge_count",
]


class RiskScorer:
    """Trains and applies ML models that output a risk score per sub-block."""

    def __init__(self, model_type=config.RISK_MODEL):
        self.model_type = model_type
        self.model = None

    def _build_model(self):
        if self.model_type == "random_forest":
            return RandomForestClassifier(
                n_estimators=150,
                max_depth=10,
                min_samples_leaf=5,
                random_state=config.RANDOM_SEED,
                class_weight="balanced",
                n_jobs=-1,
            )
        elif self.model_type == "gradient_boosting":
            return GradientBoostingClassifier(
                n_estimators=150,
                max_depth=3,
                learning_rate=0.1,
                random_state=config.RANDOM_SEED,
            )
        else:
            raise ValueError(f"Unknown model_type: {self.model_type}")

    def train(self, df, run_cross_validation=True):
        """
        Trains the model on a labeled DataFrame (must have FEATURE_COLUMNS
        and a 'true_label' column). Splits into train/test, reports metrics.
        Returns metrics dict AND the test set (with predictions attached)
        so callers can do further analysis, e.g. per-tamper-type breakdown.
        """
        X = df[FEATURE_COLUMNS]
        y = df["true_label"]

        X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
            X, y, df.index, test_size=0.2, random_state=config.RANDOM_SEED, stratify=y
        )

        self.model = self._build_model()
        self.model.fit(X_train, y_train)

        probs = self.model.predict_proba(X_test)[:, 1]
        preds = (probs >= config.RISK_THRESHOLD).astype(int)

        metrics = {
            "model_type": self.model_type,
            "auc": round(roc_auc_score(y_test, probs), 4),
            "precision": round(precision_score(y_test, preds, zero_division=0), 4),
            "recall": round(recall_score(y_test, preds, zero_division=0), 4),
            "f1": round(f1_score(y_test, preds, zero_division=0), 4),
            "threshold_used": config.RISK_THRESHOLD,
        }

        if run_cross_validation:
            # 5-fold CV on AUC - more robust than a single train/test split,
            # tells us how much the score varies across different data slices.
            cv_scores = cross_val_score(
                self._build_model(), X, y, cv=5, scoring="roc_auc", n_jobs=-1
            )
            metrics["cv_auc_mean"] = round(cv_scores.mean(), 4)
            metrics["cv_auc_std"] = round(cv_scores.std(), 4)

        # Build a results DataFrame for further analysis (e.g. per tamper_type)
        test_results = df.loc[idx_test].copy()
        test_results["predicted_prob"] = probs
        test_results["predicted_label"] = preds

        return metrics, test_results

    def score(self, df):
        """Returns risk scores (0.0-1.0) for each row in df."""
        if self.model is None:
            raise RuntimeError("Model not trained yet. Call train() first.")

        X = df[FEATURE_COLUMNS]
        return self.model.predict_proba(X)[:, 1]

    def save(self, filename=None):
        """Saves the trained model to disk."""
        os.makedirs(config.MODEL_STORE_DIR, exist_ok=True)
        filename = filename or f"risk_scorer_{self.model_type}.pkl"
        path = os.path.join(config.MODEL_STORE_DIR, filename)
        joblib.dump(self.model, path)
        return path

    def load(self, filename=None):
        """Loads a previously trained model from disk."""
        filename = filename or f"risk_scorer_{self.model_type}.pkl"
        path = os.path.join(config.MODEL_STORE_DIR, filename)
        self.model = joblib.load(path)
        return self


def analyze_recall_by_tamper_type(test_results):
    """
    Breaks down recall (detection rate) separately for each
    tamper_type, to see which kinds of tampering the model
    catches vs misses.
    """
    print("\n--- Recall by Tamper Type ---")
    for tamper_type in ["modification", "corruption", "attack"]:
        subset = test_results[test_results["tamper_type"] == tamper_type]
        if len(subset) == 0:
            continue
        detected = subset["predicted_label"].sum()
        total = len(subset)
        rate = detected / total if total > 0 else 0
        print(f"{tamper_type:<15}: {detected}/{total} detected ({rate*100:.1f}%)")


if __name__ == "__main__":
    dataset_path = os.path.join(config.RESULTS_RAW_DIR, "training_dataset.csv")

    if not os.path.exists(dataset_path):
        print("No training dataset found. Run experiments/generate_training_data.py first.")
    else:
        df = pd.read_csv(dataset_path)
        print(f"Loaded dataset: {len(df)} rows, {df['true_label'].sum()} tampered")
        print(f"Features used: {FEATURE_COLUMNS}")

        print("\n--- Training Random Forest ---")
        rf_scorer = RiskScorer(model_type="random_forest")
        rf_metrics, rf_test_results = rf_scorer.train(df)
        print(rf_metrics)
        rf_path = rf_scorer.save()
        print(f"Saved: {rf_path}")

        print("\n--- Training Gradient Boosting ---")
        gb_scorer = RiskScorer(model_type="gradient_boosting")
        gb_metrics, gb_test_results = gb_scorer.train(df)
        print(gb_metrics)
        gb_path = gb_scorer.save()
        print(f"Saved: {gb_path}")

        print("\n--- Comparison (single split + 5-fold CV) ---")
        print(f"{'Metric':<15} {'Random Forest':<15} {'Gradient Boosting':<15}")
        for key in ["auc", "precision", "recall", "f1", "cv_auc_mean", "cv_auc_std"]:
            print(f"{key:<15} {rf_metrics[key]:<15} {gb_metrics[key]:<15}")

        print("\n--- Random Forest Feature Importance ---")
        for feature, importance in zip(FEATURE_COLUMNS, rf_scorer.model.feature_importances_):
            print(f"{feature:<22}: {importance:.4f}")

        analyze_recall_by_tamper_type(rf_test_results)