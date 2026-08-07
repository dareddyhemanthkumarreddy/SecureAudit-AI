"""
SecureAudit-AI — Central Configuration
Every tunable value in the project should be read from here.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATASET_DIR = os.path.join(BASE_DIR, "datasets", "sample_files")
CLOUD_STORAGE_DIR = os.path.join(BASE_DIR, "storage", "cloud")
RESULTS_RAW_DIR = os.path.join(BASE_DIR, "results", "raw")
RESULTS_PROCESSED_DIR = os.path.join(BASE_DIR, "results", "processed")
GRAPH_DIR = os.path.join(BASE_DIR, "graphs")
MODEL_STORE_DIR = os.path.join(BASE_DIR, "ai_agent", "model_store")
KEYS_DIR = os.path.join(BASE_DIR, "signature", "keys")

# Partition settings
BLOCK_SIZE = 4096
SUB_BLOCK_SIZE = 512
SUBSET_SIZE = 16          # sub-blocks grouped per signature

# Trust settings
INITIAL_TRUST = 100
TRUST_REWARD = 2
TRUST_PENALTY_MODIFIED = 10
TRUST_PENALTY_FAILED = 20

# Risk scorer (Module 1)
RISK_MODEL = "random_forest"
RISK_THRESHOLD = 0.75
RANDOM_SEED = 42

# Simulation settings
MODIFICATION_RATES = [0.01, 0.05, 0.10, 0.20]
NUMBER_OF_RUNS = 5

# Garlic bundling
DECOYS_PER_REAL_REQUEST = 4

# Baseline
RANDOM_VERIFICATION_PERCENTAGE = 10

# Audit Scheduler (Module 2)
SCHEDULER_BASE_INTERVAL_HOURS = 24
SCHEDULER_MIN_INTERVAL_HOURS = 1
SCHEDULER_MAX_INTERVAL_HOURS = 72
SCHEDULER_RISK_WEIGHT = 3.0
SCHEDULER_ANOMALY_WEIGHT = 5.0