"""
SecureAudit-AI — Audit Scheduler (AI Agent Module 2)
Decides WHEN to trigger the next audit for a file/node, instead
of using a fixed interval. Higher recent risk (from Module 1)
or a flagged anomaly (from Module 3) shortens the interval -
audit more often when things look suspicious. Low risk and no
anomalies lengthen the interval - save resources when things
look stable.
"""

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config


class AuditScheduler:
    """Computes the next audit interval based on recent risk/anomaly signals."""

    @staticmethod
    def compute_next_interval(avg_risk_score, anomaly_detected):
        """
        Args:
            avg_risk_score: float 0.0-1.0, e.g. average Module 1 risk score
                or fraction_modified from recent audit(s).
            anomaly_detected: bool, whether Module 3 flagged this session
                as anomalous.

        Returns:
            next_interval_hours: float, how long until the next audit
                should be triggered. Bounded between SCHEDULER_MIN and
                SCHEDULER_MAX.
        """
        base = config.SCHEDULER_BASE_INTERVAL_HOURS

        risk_penalty = avg_risk_score * config.SCHEDULER_RISK_WEIGHT
        anomaly_penalty = config.SCHEDULER_ANOMALY_WEIGHT if anomaly_detected else 0

        divisor = 1 + risk_penalty + anomaly_penalty
        interval = base / divisor

        interval = max(config.SCHEDULER_MIN_INTERVAL_HOURS, interval)
        interval = min(config.SCHEDULER_MAX_INTERVAL_HOURS, interval)

        return round(interval, 2)


if __name__ == "__main__":
    import pandas as pd
    from ai_agent.anomaly_detector import AnomalyDetector, SESSION_FEATURE_COLUMNS

    dataset_path = os.path.join(config.RESULTS_RAW_DIR, "session_data.csv")

    if not os.path.exists(dataset_path):
        print("No session dataset found. Run experiments/generate_session_data.py first.")
    else:
        df = pd.read_csv(dataset_path)

        detector = AnomalyDetector()
        detector.load()
        predictions, scores = detector.predict(df)
        df["predicted_anomaly"] = (predictions == -1)

        print(f"{'Session':<10}{'fraction_mod':<15}{'anomaly?':<12}{'next_audit_in (hrs)':<20}{'fixed_baseline (hrs)'}")

        for i, row in df.head(15).iterrows():
            interval = AuditScheduler.compute_next_interval(
                avg_risk_score=row["fraction_modified"],
                anomaly_detected=bool(row["predicted_anomaly"]),
            )
            print(f"{i:<10}{row['fraction_modified']:<15.3f}"
                  f"{str(bool(row['predicted_anomaly'])):<12}{interval:<20}"
                  f"{config.SCHEDULER_BASE_INTERVAL_HOURS}")

        print("\n--- Summary ---")
        df["scheduled_interval"] = df.apply(
            lambda r: AuditScheduler.compute_next_interval(
                r["fraction_modified"], bool(r["predicted_anomaly"])
            ), axis=1
        )
        print(f"Avg interval for NORMAL sessions:    "
              f"{df[~df['predicted_anomaly']]['scheduled_interval'].mean():.2f} hours")
        print(f"Avg interval for ANOMALOUS sessions: "
              f"{df[df['predicted_anomaly']]['scheduled_interval'].mean():.2f} hours")
        print(f"Fixed baseline (no adaptation):      {config.SCHEDULER_BASE_INTERVAL_HOURS} hours")