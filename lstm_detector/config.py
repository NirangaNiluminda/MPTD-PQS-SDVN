import os

# --- Paths ---
ML_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ML_DIR, "data")
CHECKPOINT_DIR = os.path.join(ML_DIR, "checkpoints")

# --- Model & Sequence Parameters (defaults; overridden during arch. search) ---
WINDOW_SIZE = 20
FEATURE_DIM = 6
HIDDEN_DIM = 64
LATENT_DIM = 32
NUM_LAYERS = 2
KAPPA = 3.0  # Threshold calibration factor (99.7% confidence interval bound)

# --- Scenario Configs ---
SCENARIOS = ["urban", "rural", "highway"]
BETA_CANDIDATES = [0.01, 0.05, 0.1, 0.5]
SCENARIO_BETA_DEFAULTS = {
    "urban": 0.01,
    "rural": 0.05,
    "highway": 0.1,
}

# --- Architecture search candidates (Table 4.17) ---
# Each tuple: (candidate_id, window_size L, hidden, latent, beta)
# FPR_CONSTRAINT: candidates with FPR > this on clean held-out data are
# disqualified even if their reconstruction error is lower.
FPR_CONSTRAINT = 0.05
N_SEEDS = 3

ARCH_CANDIDATES = {
    "urban": [
        {"id": "T1", "window": 10, "hidden": 32, "latent": 16, "beta": 0.01},
        {"id": "T2", "window": 20, "hidden": 64, "latent": 32, "beta": 0.05},
        {"id": "T3", "window": 20, "hidden": 64, "latent": 32, "beta": 0.10},
    ],
    "rural": [
        {"id": "T4", "window": 10, "hidden": 32, "latent": 16, "beta": 0.05},
        {"id": "T5", "window": 10, "hidden": 32, "latent": 16, "beta": 0.10},
        {"id": "T6", "window": 20, "hidden": 32, "latent": 16, "beta": 0.10},
    ],
    "highway": [
        {"id": "T7", "window": 5,  "hidden": 16, "latent": 8,  "beta": 0.10},
        {"id": "T8", "window": 10, "hidden": 16, "latent": 8,  "beta": 0.50},
        {"id": "T9", "window": 10, "hidden": 32, "latent": 16, "beta": 0.50},
    ],
}

# --- Edge angle threshold per scenario (Table 4.18, unrelated to LSTM but
# kept here for reference since it travels with the same selected config) ---
PHI_MAX_DEGREES = {
    "urban": 45,
    "rural": 30,
    "highway": 15,
}

# --- Training Details ---
EPOCHS = 50
BATCH_SIZE = 32
LR = 0.001
DT = 0.1