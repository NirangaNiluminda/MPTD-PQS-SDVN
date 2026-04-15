"""
LSTM Temporal Autoencoder — Controller-side sequential anomaly detection
=========================================================================
Implements Equations 3.43–3.53 from Section 3.4.3 of the paper.

Architecture:
  - LSTM encoder: h_t = LSTM(x_t, h_{t-1})                (Eq 3.43–3.44)
  - Context vector: c = h_T                                (Eq 3.45)
  - LSTM decoder: ĥ_t = LSTM(c, ĥ_{t-1})                 (Eq 3.46–3.47)
  - Reconstruction: x̂_t = W_dec · ĥ_t + b_dec            (Eq 3.48)
  - Mobility-constrained loss (Eq 3.49–3.51):
      L_total = L_recon + λ_k · L_kinematic
      L_kinematic = Σ max(0, |Δpos_t| - (v_max·Δt + ½a_max·Δt²))²
  - Temporal anomaly score ε_i(t) = ||x_t - x̂_t||²       (Eq 3.52)
  - Detection: ε_i(t) > θ_ae                               (Eq 3.53)

Fallback: numpy-based rolling mean reconstruction when PyTorch unavailable.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


# ── Constants ─────────────────────────────────────────────────────────────────
SEQ_LEN        = 10    # trajectory window length T
INPUT_DIM      = 6     # [px, py, vx, vy, ax, ay]
HIDDEN_DIM     = 64    # LSTM hidden units
N_LAYERS       = 2     # LSTM depth
LAMBDA_K       = 0.1   # kinematic constraint weight
V_MAX          = 33.0  # m/s
A_MAX          = 4.0   # m/s²
THETA_AE       = 5.0   # reconstruction error threshold (m² equivalent)
AE_TRAIN_EPOCHS = 50
AE_LR          = 1e-3


# ── PyTorch LSTM Autoencoder ──────────────────────────────────────────────────
if TORCH_AVAILABLE:

    class LSTMEncoder(nn.Module):
        """LSTM encoder (Eq 3.43–3.45)."""
        def __init__(self, input_dim: int = INPUT_DIM,
                     hidden: int = HIDDEN_DIM, n_layers: int = N_LAYERS):
            super().__init__()
            self.lstm = nn.LSTM(input_dim, hidden, n_layers,
                                batch_first=True, dropout=0.1)

        def forward(self, x: torch.Tensor) -> Tuple[torch.Tensor, Tuple]:
            """x: [B, T, input_dim] → context [B, hidden], hidden state."""
            out, (hn, cn) = self.lstm(x)
            return hn[-1], (hn, cn)  # last layer hidden state as context


    class LSTMDecoder(nn.Module):
        """LSTM decoder with linear reconstruction head (Eq 3.46–3.48)."""
        def __init__(self, input_dim: int = INPUT_DIM,
                     hidden: int = HIDDEN_DIM, n_layers: int = N_LAYERS,
                     seq_len: int = SEQ_LEN):
            super().__init__()
            self.seq_len = seq_len
            self.hidden = hidden
            self.lstm = nn.LSTM(hidden, hidden, n_layers,
                                batch_first=True, dropout=0.1)
            self.linear = nn.Linear(hidden, input_dim)

        def forward(self, context: torch.Tensor, hidden: Tuple) -> torch.Tensor:
            """context: [B, hidden] → reconstructed sequence [B, T, input_dim]."""
            # Repeat context as input for each time step
            dec_in = context.unsqueeze(1).expand(-1, self.seq_len, -1)
            out, _ = self.lstm(dec_in, hidden)
            recon = self.linear(out)
            return recon


    class LSTMTemporalAE(nn.Module):
        """Full LSTM autoencoder (Eq 3.43–3.51)."""
        def __init__(self, input_dim: int = INPUT_DIM,
                     hidden: int = HIDDEN_DIM, n_layers: int = N_LAYERS,
                     seq_len: int = SEQ_LEN, lambda_k: float = LAMBDA_K):
            super().__init__()
            self.encoder = LSTMEncoder(input_dim, hidden, n_layers)
            self.decoder = LSTMDecoder(input_dim, hidden, n_layers, seq_len)
            self.lambda_k = lambda_k

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            """x: [B, T, 6] → reconstructed x̂: [B, T, 6]."""
            context, hidden = self.encoder(x)
            return self.decoder(context, hidden)

        def mobility_loss(self, x: torch.Tensor, dt: float = 0.3) -> torch.Tensor:
            """
            Kinematic constraint loss L_kinematic (Eq 3.49–3.51).
            Penalises position jumps exceeding physical limits.
            dt: time step between trajectory points (seconds)
            """
            pos = x[:, :, :2]           # [B, T, 2] — x,y positions
            delta_pos = pos[:, 1:, :] - pos[:, :-1, :]  # [B, T-1, 2]
            displ = torch.norm(delta_pos, dim=-1)         # [B, T-1]
            max_allowed = V_MAX * dt + 0.5 * A_MAX * dt * dt
            violation = F.relu(displ - max_allowed)
            return (violation ** 2).mean()

        def loss(self, x: torch.Tensor, x_hat: torch.Tensor) -> torch.Tensor:
            """Total loss = L_recon + λ_k · L_kinematic."""
            l_recon = F.mse_loss(x_hat, x)
            l_kin = self.mobility_loss(x)
            return l_recon + self.lambda_k * l_kin


class TemporalAEDetector:
    """
    Controller-side LSTM temporal autoencoder-based anomaly detector.
    Maintains per-vehicle sliding windows of trajectory sequences.
    """

    def __init__(self, seq_len: int = SEQ_LEN, theta_ae: float = THETA_AE,
                 train_epochs: int = AE_TRAIN_EPOCHS, lr: float = AE_LR):
        self.seq_len = seq_len
        self.theta_ae = theta_ae
        self.train_epochs = train_epochs

        if TORCH_AVAILABLE:
            self.model = LSTMTemporalAE(seq_len=seq_len)
            self.optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        else:
            self.model = None

        # Per-vehicle sliding window of [px, py, vx, vy, ax, ay] tuples
        self._windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=seq_len))
        # Training sequences (list of [T, 6] arrays)
        self._train_seqs: List = []
        self._trained = False

        self.scores: List[Dict] = []

    def _extract_features(self, state) -> List[float]:
        """Extract [px, py, vx, vy, ax, ay] from a state object or dict."""
        if hasattr(state, 'pos_x'):
            return [state.pos_x, state.pos_y, state.vel_x, state.vel_y,
                    state.acc_x, state.acc_y]
        else:
            return [state.get('pos_x', 0), state.get('pos_y', 0),
                    state.get('vel_x', 0), state.get('vel_y', 0),
                    state.get('acc_x', 0), state.get('acc_y', 0)]

    # ── Training ──────────────────────────────────────────────────────────────
    def add_training_point(self, state):
        """Accumulate a clean state point for training."""
        vid = state.vehicle_id if hasattr(state, 'vehicle_id') else state.get('vehicle_id', 'V0')
        feats = self._extract_features(state)
        self._windows[vid].append(feats)
        if len(self._windows[vid]) == self.seq_len:
            self._train_seqs.append(list(self._windows[vid]))

    def finalize_training(self):
        """Train the model on accumulated sequences."""
        if not TORCH_AVAILABLE or len(self._train_seqs) < 2:
            self._trained = True
            return

        self.model.train()
        seqs = torch.tensor(self._train_seqs, dtype=torch.float32)

        for epoch in range(self.train_epochs):
            self.optimizer.zero_grad()
            x_hat = self.model(seqs)
            loss = self.model.loss(seqs, x_hat)
            loss.backward()
            self.optimizer.step()

        self._trained = True

    # ── Scoring ───────────────────────────────────────────────────────────────
    def process(self, state) -> Optional[Dict]:
        """
        Process one trajectory point for vehicle.
        Returns anomaly score dict when enough history is accumulated, else None.
        """
        vid = state.vehicle_id if hasattr(state, 'vehicle_id') else state.get('vehicle_id', 'V0')
        rid = state.rsu_id if hasattr(state, 'rsu_id') else state.get('rsu_id', 'RSU0')
        t   = state.timestamp if hasattr(state, 'timestamp') else state.get('timestamp', 0)
        is_poisoned = state.is_poisoned if hasattr(state, 'is_poisoned') else state.get('is_poisoned', False)

        feats = self._extract_features(state)
        self._windows[vid].append(feats)

        if len(self._windows[vid]) < self.seq_len:
            return None  # not enough history yet

        window = list(self._windows[vid])

        if TORCH_AVAILABLE and self._trained:
            score = self._score_torch(window)
        else:
            score = self._score_heuristic(window)

        flagged = score > self.theta_ae
        result = {
            "vehicle_id": vid,
            "rsu_id": rid,
            "timestamp": t,
            "ae_score": score,
            "flagged": flagged,
            "ground_truth_poisoned": is_poisoned,
        }
        self.scores.append(result)
        return result

    def _score_torch(self, window: List[List[float]]) -> float:
        """Compute reconstruction error ε_i(t) = ||x_t - x̂_t||²."""
        self.model.eval()
        x = torch.tensor([window], dtype=torch.float32)  # [1, T, 6]
        with torch.no_grad():
            x_hat = self.model(x)
        # Per-step errors, return mean squared error
        err = ((x_hat - x) ** 2).mean().item()
        return err

    def _score_heuristic(self, window: List[List[float]]) -> float:
        """
        Fallback: dead-reckoning residual over the window.
        Predicts next position using constant-velocity model and measures error.
        """
        if not NUMPY_AVAILABLE:
            return self._score_pure_python(window)

        w = np.array(window)  # [T, 6]
        errors = []
        for i in range(1, len(w)):
            prev = w[i-1]
            curr = w[i]
            dt = 0.3  # assumed time step
            pred_px = prev[0] + prev[2] * dt + 0.5 * prev[4] * dt * dt
            pred_py = prev[1] + prev[3] * dt + 0.5 * prev[5] * dt * dt
            err = (curr[0] - pred_px) ** 2 + (curr[1] - pred_py) ** 2
            errors.append(err)
        return float(np.mean(errors)) if errors else 0.0

    def _score_pure_python(self, window: List[List[float]]) -> float:
        errors = []
        for i in range(1, len(window)):
            prev = window[i-1]
            curr = window[i]
            dt = 0.3
            pred_px = prev[0] + prev[2] * dt + 0.5 * prev[4] * dt * dt
            pred_py = prev[1] + prev[3] * dt + 0.5 * prev[5] * dt * dt
            err = (curr[0] - pred_px) ** 2 + (curr[1] - pred_py) ** 2
            errors.append(err)
        return sum(errors) / len(errors) if errors else 0.0

    def process_batch(self, states: List) -> List[Dict]:
        """Process multiple states, returning only non-None results."""
        results = []
        for s in states:
            r = self.process(s)
            if r is not None:
                results.append(r)
        return results

    def reset(self):
        self._windows.clear()
        self._train_seqs.clear()
        self.scores.clear()
        self._trained = False


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    from mptd_pqs.lightweight_detector import TrajectoryPoint

    # Build a short sequence for one vehicle
    pts = []
    for i in range(15):
        t = 9.0 + i * 0.3
        x = 800.0 + i * 3.0  # steady movement
        is_p = (i > 10)       # poisoned in last 4 points
        jump = 200.0 if is_p else 0.0
        pts.append(TrajectoryPoint(
            vehicle_id="V0", rsu_id="RSU0",
            timestamp=t, pos_x=x + jump, pos_y=1200.0,
            vel_x=10.0, vel_y=0.0, acc_x=0.0, acc_y=0.0,
            is_poisoned=is_p
        ))

    det = TemporalAEDetector(seq_len=5, theta_ae=10.0, train_epochs=20)

    # Train on first 10 points
    for p in pts[:10]:
        det.add_training_point(p)
    det.finalize_training()

    # Score all
    print("Temporal AE Results:")
    for p in pts:
        r = det.process(p)
        if r:
            gt = "POISONED" if r["ground_truth_poisoned"] else "clean"
            print(f"  t={p.timestamp:.1f} {gt} -> score={r['ae_score']:.3f} flagged={r['flagged']}")
