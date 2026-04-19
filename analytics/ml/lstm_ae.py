"""
lstm_ae.py — LSTM Autoencoder Temporal Anomaly Detector
MPTD-PQS Stage 5: paper §3.4.3, Eq. 3.43-3.45

Architecture:
  Encoder: LSTM(5 → 64, 2 layers)
  Decoder: LSTM(64 → 64, 2 layers) → Linear(64 → 5)
Input  : sliding window of k=20 consecutive beacons per vehicle  (k, 5)
Output : reconstruction error ε_i(t) = MSE(x̂, x)
Threshold: θ_ae = μ_ε + κ·σ_ε  (95th-pct on clean training data, κ ≈ 1.645)
"""

import torch
import torch.nn as nn
import numpy as np

WINDOW_SIZE  = 20   # k — consecutive beacons per vehicle
FEATURE_DIM  = 5    # [pos_x, pos_y, speed, heading, accel]
HIDDEN_DIM   = 64
NUM_LAYERS   = 2
KAPPA        = 1.645  # 95th-percentile z-score for threshold


class LSTMAEDetector(nn.Module):
    """
    Sequence-to-sequence LSTM autoencoder.
    Input  shape: (batch, k, 5)
    Output shape: (batch, k, 5)  — reconstructed sequence
    """

    def __init__(self, feat_dim: int = FEATURE_DIM,
                 hidden: int = HIDDEN_DIM, num_layers: int = NUM_LAYERS):
        super().__init__()
        self.feat_dim   = feat_dim
        self.hidden     = hidden
        self.num_layers = num_layers

        # Encoder: compress sequence to hidden state
        self.encoder = nn.LSTM(
            input_size=feat_dim, hidden_size=hidden,
            num_layers=num_layers, batch_first=True
        )

        # Decoder: reproduce sequence from hidden state
        self.decoder = nn.LSTM(
            input_size=hidden, hidden_size=hidden,
            num_layers=num_layers, batch_first=True
        )
        self.output_layer = nn.Linear(hidden, feat_dim)

    def forward(self, x: torch.Tensor):
        """
        x: (B, k, feat_dim)
        returns: reconstructed (B, k, feat_dim)
        """
        B, k, _ = x.shape

        # Encode — use final hidden state as bottleneck
        _, (h_n, c_n) = self.encoder(x)

        # Repeat the bottleneck hidden state as decoder input at each step
        decoder_input = h_n[-1].unsqueeze(1).repeat(1, k, 1)  # (B, k, hidden)
        decoded, _    = self.decoder(decoder_input, (h_n, c_n))
        reconstructed = self.output_layer(decoded)              # (B, k, feat_dim)
        return reconstructed


# ---------------------------------------------------------------------------
# Threshold calibration (call once on clean validation windows)
# ---------------------------------------------------------------------------

def calibrate_threshold(model: nn.Module,
                        clean_windows: torch.Tensor,
                        kappa: float = KAPPA,
                        device: torch.device = torch.device("cpu")) -> float:
    """
    Compute θ_ae = μ_ε + κ·σ_ε on clean (non-poisoned) windows.
    clean_windows: (N, k, 5)
    Returns       : float threshold
    """
    model.eval()
    errors = []
    with torch.no_grad():
        for i in range(0, len(clean_windows), 64):
            batch = clean_windows[i:i+64].to(device)
            recon = model(batch)
            mse   = ((recon - batch) ** 2).mean(dim=(1, 2))  # (B,)
            errors.extend(mse.cpu().numpy().tolist())
    errors = np.array(errors)
    theta  = float(errors.mean() + kappa * errors.std())
    return theta


# ---------------------------------------------------------------------------
# Sliding window builder from per-vehicle beacon history
# ---------------------------------------------------------------------------

def build_windows(beacon_df, vehicle_id: int,
                  window: int = WINDOW_SIZE) -> np.ndarray:
    """
    Extract sliding windows of length `window` for a single vehicle.
    beacon_df columns: sim_time, vehicle_id, pos_x, pos_y, speed, heading, accel, ...
    Returns: (N_windows, window, 5)  or empty array if too few beacons
    """
    cols = ["pos_x", "pos_y", "speed", "heading", "accel"]
    vdf  = beacon_df[beacon_df["vehicle_id"] == vehicle_id].sort_values("sim_time")
    feats = vdf[cols].values.astype(np.float32)
    if len(feats) < window:
        return np.empty((0, window, FEATURE_DIM), dtype=np.float32)
    windows = np.stack([feats[i:i+window] for i in range(len(feats) - window + 1)])
    return windows


# ---------------------------------------------------------------------------
# Per-vehicle reconstruction error (used by prediction_server.py)
# ---------------------------------------------------------------------------

def score_window(model: nn.Module,
                 window_seq: np.ndarray,
                 device: torch.device = torch.device("cpu")) -> float:
    """
    Compute ε_i(t) for a single window.
    window_seq: (k, 5)
    Returns   : float MSE
    """
    model.eval()
    x = torch.tensor(window_seq, dtype=torch.float).unsqueeze(0).to(device)
    with torch.no_grad():
        recon = model(x)
    return float(((recon - x) ** 2).mean().cpu())
