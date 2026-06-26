import os

# --- Paths ---
ML_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(ML_DIR, "data")
CHECKPOINT_DIR = os.path.join(ML_DIR, "checkpoints")

# --- Model & Sequence Parameters ---
WINDOW_SIZE = 20
FEATURE_DIM = 6
HIDDEN_DIM = 64
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

# --- Training Details ---
EPOCHS = 50
BATCH_SIZE = 32
LR = 0.001
DT = 0.1
