"""
SecureAudit-AI — Machine Unlearning (for Module 3's Anomaly Detector)
Implements EXACT unlearning via retraining: when a user requests
their data be forgotten, we remove their sessions from the
training set and retrain Isolation Forest from scratch. This is
mathematically exact - the resulting model is identical to what
you'd get if that user's data had never been included, unlike
approximate unlearning techniques that only try to reduce a
model's influence.

Trade-off: retraining-based unlearning is exact but costs a full
retrain each time. For Isolation Forest on modest dataset sizes
(as used here), this is cheap enough to be practical.
"""

import os
import sys
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config
from ai_agent.anomaly_detector import AnomalyDetector, SESSION_FEATURE_COLUMNS


class MachineUnlearning:
    """Handles forgetting a specific user's data from Module 3's model."""

    @staticmethod
    def forget_user(df, user_id):
        """
        Removes all sessions belonging to user_id, retrains a fresh
        Isolation Forest on the remaining data.

        Args:
            df: full session DataFrame (must have 'user_id' column).
            user_id: the user whose data should be forgotten.

        Returns:
            {
                "new_model": trained AnomalyDetector,
                "removed_rows": DataFrame of the user's removed sessions,
                "remaining_df": DataFrame after removal,
            }
        """
        removed_rows = df[df["user_id"] == user_id].copy()
        remaining_df = df[df["user_id"] != user_id].copy()

        if len(removed_rows) == 0:
            raise ValueError(f"No sessions found for user_id={user_id}")

        new_detector = AnomalyDetector(contamination=0.1)
        new_detector.train(remaining_df)

        return {
            "new_model": new_detector,
            "removed_rows": removed_rows,
            "remaining_df": remaining_df,
        }


def verify_unlearning(old_detector, new_detector, removed_rows):
    """
    Compares how the OLD model (trained WITH the user's data) vs
    the NEW model (trained WITHOUT it) score that user's own
    session points. Since Isolation Forest builds trees based on
    how easily a point is isolated, a point that was part of
    training generally gets scored differently than the same
    point evaluated by a model that never saw it.

    This is a diagnostic comparison, not a formal privacy proof -
    reported honestly as such.
    """
    X = removed_rows[SESSION_FEATURE_COLUMNS]

    old_scores = old_detector.model.score_samples(X)
    new_scores = new_detector.model.score_samples(X)

    removed_rows = removed_rows.copy()
    removed_rows["score_with_user_in_training"] = old_scores
    removed_rows["score_after_unlearning"] = new_scores
    removed_rows["score_shift"] = new_scores - old_scores

    return removed_rows


if __name__ == "__main__":
    dataset_path = os.path.join(config.RESULTS_RAW_DIR, "session_data.csv")

    if not os.path.exists(dataset_path):
        print("No session dataset found. Run experiments/generate_session_data.py first.")
    else:
        df = pd.read_csv(dataset_path)
        print(f"Loaded {len(df)} sessions across {df['user_id'].nunique()} users")

        # Train the ORIGINAL model (with everyone's data, including user 10)
        original_detector = AnomalyDetector(contamination=0.1)
        original_detector.train(df)
        print("\nOriginal model trained on all users (including user 10).")

        # Now: user 10 requests their data be forgotten
        print("\n--- User 10 requests their data be forgotten ---")
        result = MachineUnlearning.forget_user(df, user_id=10)

        new_detector = result["new_model"]
        removed_rows = result["removed_rows"]
        remaining_df = result["remaining_df"]

        print(f"Removed {len(removed_rows)} sessions belonging to user 10")
        print(f"Retrained on remaining {len(remaining_df)} sessions "
              f"from {remaining_df['user_id'].nunique()} users")

        # Structural proof: user 10's data is verifiably absent from the
        # new model's training set
        assert 10 not in remaining_df["user_id"].values
        print("\nStructural check PASSED: user 10 has zero rows in the retrained model's training data.")

        # Diagnostic comparison: how does the new model score user 10's
        # (now-removed) sessions, compared to the old model?
        comparison = verify_unlearning(original_detector, new_detector, removed_rows)
        print("\n--- Score comparison for user 10's removed sessions ---")
        print(comparison[["avg_trust_score", "fraction_modified",
                           "score_with_user_in_training", "score_after_unlearning",
                           "score_shift"]].to_string(index=False))

        # Save the unlearned model
        path = new_detector.save(filename="anomaly_detector_after_unlearning.pkl")
        print(f"\nSaved unlearned model: {path}")