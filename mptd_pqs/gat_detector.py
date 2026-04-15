"""
GAT Spatial Anomaly Detector — Controller-side detection
=========================================================
Implements Equations 3.21–3.42 from Section 3.4.3 of the paper.

Architecture:
  - Dynamic vehicle-RSU graph G_t = (V_t, E_t)
  - Node features h_i = [pos_x, pos_y, vel_x, vel_y, acc_x, acc_y, speed, heading]
  - Multi-head attention aggregation (Eq 3.21–3.30)
  - Reconstruction-based anomaly scoring (Eq 3.31–3.38)
  - Spatial anomaly score S_i(t) ∈ [0, 1] (Eq 3.39–3.42)

When PyTorch is available: uses real GATConv layers.
When PyTorch is not available: falls back to a numpy-based approximation.
"""

import math
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

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


# ── Constants (from Table 3.2 of paper) ───────────────────────────────────────
GAT_HIDDEN_DIM = 64
GAT_HEADS      = 4
GAT_LAYERS     = 2
NODE_FEAT_DIM  = 8      # [px, py, vx, vy, ax, ay, speed, heading]
EDGE_RADIUS    = 500.0  # m — RSU communication range (R_rsu from Table 3.1)
ANOMALY_THRESHOLD_GAT = 0.5   # S_i > this → spatial anomaly


@dataclass
class VehicleState:
    vehicle_id: str
    rsu_id: str
    timestamp: float
    pos_x: float
    pos_y: float
    vel_x: float
    vel_y: float
    acc_x: float
    acc_y: float
    is_poisoned: bool = False

    @property
    def speed(self) -> float:
        return math.sqrt(self.vel_x ** 2 + self.vel_y ** 2)

    @property
    def heading(self) -> float:
        return math.atan2(self.vel_y, self.vel_x)

    def feature_vector(self) -> List[float]:
        """8-dim feature vector for GAT node."""
        return [self.pos_x, self.pos_y, self.vel_x, self.vel_y,
                self.acc_x, self.acc_y, self.speed, self.heading]


# ── PyTorch GAT implementation ─────────────────────────────────────────────────
if TORCH_AVAILABLE:

    class GATLayer(nn.Module):
        """Single Graph Attention layer (Eq 3.21–3.30)."""

        def __init__(self, in_features: int, out_features: int, n_heads: int, dropout: float = 0.1):
            super().__init__()
            self.n_heads = n_heads
            self.head_dim = out_features // n_heads
            self.W = nn.Linear(in_features, out_features, bias=False)
            self.a = nn.Parameter(torch.zeros(n_heads, 2 * self.head_dim))
            nn.init.xavier_uniform_(self.a.unsqueeze(0))
            self.leaky = nn.LeakyReLU(0.2)
            self.dropout = nn.Dropout(dropout)

        def forward(self, h: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
            """
            h   : [N, in_features]
            adj : [N, N] adjacency (1 = edge exists)
            returns: [N, n_heads * head_dim]
            """
            N = h.size(0)
            Wh = self.W(h)                               # [N, out]
            Wh = Wh.view(N, self.n_heads, self.head_dim) # [N, H, d]

            # Attention coefficients (Eq 3.24)
            Wh_i = Wh.unsqueeze(1).expand(-1, N, -1, -1)  # [N, N, H, d]
            Wh_j = Wh.unsqueeze(0).expand(N, -1, -1, -1)  # [N, N, H, d]
            concat = torch.cat([Wh_i, Wh_j], dim=-1)       # [N, N, H, 2d]

            e = self.leaky((concat * self.a).sum(-1))      # [N, N, H]

            # Mask non-edges
            mask = (adj == 0).unsqueeze(-1).expand_as(e)
            e = e.masked_fill(mask, float('-inf'))

            alpha = F.softmax(e, dim=1)                    # [N, N, H]
            alpha = self.dropout(alpha)

            # Aggregate (Eq 3.29)
            out = (alpha.unsqueeze(-1) * Wh_j).sum(1)     # [N, H, d]
            return F.elu(out.view(N, -1))                  # [N, H*d]


    class GATEncoder(nn.Module):
        """Stack of GAT layers → node embeddings (Eq 3.31–3.35)."""

        def __init__(self, in_dim: int = NODE_FEAT_DIM,
                     hidden: int = GAT_HIDDEN_DIM,
                     n_heads: int = GAT_HEADS,
                     n_layers: int = GAT_LAYERS):
            super().__init__()
            dims = [in_dim] + [hidden] * n_layers
            self.layers = nn.ModuleList([
                GATLayer(dims[i], dims[i+1], n_heads) for i in range(n_layers)
            ])
            self.decode = nn.Linear(hidden, in_dim)  # reconstruction head

        def forward(self, h: torch.Tensor, adj: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
            """Returns (embedding, reconstruction)."""
            z = h
            for layer in self.layers:
                z = layer(z, adj)
            recon = self.decode(z)
            return z, recon


class GATDetector:
    """
    Controller-side GAT spatial anomaly detector.
    Scores each vehicle node based on reconstruction error in the vehicle-RSU graph.
    """

    def __init__(self, threshold: float = ANOMALY_THRESHOLD_GAT,
                 train_epochs: int = 50, lr: float = 1e-3):
        self.threshold = threshold
        self.train_epochs = train_epochs
        self.lr = lr

        if TORCH_AVAILABLE:
            self.model = GATEncoder()
            self.optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        else:
            self.model = None

        self._snapshots: List[List[VehicleState]] = []
        self.scores: List[Dict] = []
        self._trained = False

    # ── Graph construction ─────────────────────────────────────────────────────
    @staticmethod
    def build_graph(states: List[VehicleState]) -> Tuple:
        """
        Build adjacency matrix and feature matrix from vehicle states.
        Edges: vehicle-to-RSU within EDGE_RADIUS, and RSU-to-RSU always.
        """
        N = len(states)
        if NUMPY_AVAILABLE:
            adj = np.zeros((N, N), dtype=np.float32)
            feat = np.array([s.feature_vector() for s in states], dtype=np.float32)
        else:
            adj = [[0.0] * N for _ in range(N)]
            feat = [s.feature_vector() for s in states]

        # Connect nodes within communication range
        for i in range(N):
            for j in range(N):
                if i == j:
                    if NUMPY_AVAILABLE:
                        adj[i, j] = 1.0
                    else:
                        adj[i][j] = 1.0
                    continue
                si, sj = states[i], states[j]
                dist = math.sqrt((si.pos_x - sj.pos_x) ** 2 + (si.pos_y - sj.pos_y) ** 2)
                if dist <= EDGE_RADIUS:
                    if NUMPY_AVAILABLE:
                        adj[i, j] = 1.0
                    else:
                        adj[i][j] = 1.0

        return feat, adj

    # ── Training (unsupervised autoencoder) ───────────────────────────────────
    def train_on_snapshots(self, snapshots: List[List[VehicleState]]):
        """Train GAT encoder on clean trajectory snapshots (Eq 3.36–3.38)."""
        if not TORCH_AVAILABLE or not snapshots:
            self._trained = True
            return

        self.model.train()
        for epoch in range(self.train_epochs):
            total_loss = 0.0
            for states in snapshots:
                if len(states) < 2:
                    continue
                feat, adj = self.build_graph(states)
                h = torch.tensor(feat, dtype=torch.float32)
                A = torch.tensor(np.array(adj) if NUMPY_AVAILABLE else adj, dtype=torch.float32)

                self.optimizer.zero_grad()
                _, recon = self.model(h, A)
                loss = F.mse_loss(recon, h)
                loss.backward()
                self.optimizer.step()
                total_loss += loss.item()

            if (epoch + 1) % 10 == 0:
                avg = total_loss / max(len(snapshots), 1)

        self._trained = True

    # ── Scoring ───────────────────────────────────────────────────────────────
    def score_snapshot(self, states: List[VehicleState]) -> List[Dict]:
        """
        Score a snapshot of vehicle states.
        Returns list of {vehicle_id, rsu_id, score S_i, flagged, ground_truth}.
        """
        if not states:
            return []

        if TORCH_AVAILABLE and self._trained:
            return self._score_torch(states)
        else:
            return self._score_heuristic(states)

    def _score_torch(self, states: List[VehicleState]) -> List[Dict]:
        self.model.eval()
        feat, adj = self.build_graph(states)
        h = torch.tensor(feat, dtype=torch.float32)
        A = torch.tensor(np.array(adj) if NUMPY_AVAILABLE else adj, dtype=torch.float32)

        with torch.no_grad():
            _, recon = self.model(h, A)
            errors = ((recon - h) ** 2).mean(dim=1)  # per-node MSE

        # Normalize to [0, 1] (Eq 3.39–3.42)
        err_np = errors.numpy()
        max_err = err_np.max() if err_np.max() > 0 else 1.0
        scores_norm = err_np / max_err

        results = []
        for i, (state, score) in enumerate(zip(states, scores_norm)):
            flagged = float(score) > self.threshold
            results.append({
                "vehicle_id": state.vehicle_id,
                "rsu_id": state.rsu_id,
                "timestamp": state.timestamp,
                "gat_score": float(score),
                "flagged": flagged,
                "ground_truth_poisoned": state.is_poisoned,
            })
        self.scores.extend(results)
        return results

    def _score_heuristic(self, states: List[VehicleState]) -> List[Dict]:
        """
        Numpy/pure-Python fallback when PyTorch is unavailable.
        Uses inter-vehicle position consistency as a proxy for reconstruction error.
        """
        N = len(states)
        results = []

        for i, state in enumerate(states):
            # Anomaly score: deviation of this vehicle from its neighbors' predicted motion
            neighbors = [s for j, s in enumerate(states) if j != i]
            if not neighbors:
                score = 0.0
            else:
                # Compare speed against neighbor average (simplified S_i proxy)
                own_speed = state.speed
                neighbor_speeds = [s.speed for s in neighbors]
                mean_ns = sum(neighbor_speeds) / len(neighbor_speeds)
                std_ns = math.sqrt(sum((s - mean_ns) ** 2 for s in neighbor_speeds) / len(neighbor_speeds)) + 0.1
                z = abs(own_speed - mean_ns) / std_ns
                score = min(1.0, z / 5.0)  # normalize to [0,1]

            flagged = score > self.threshold
            results.append({
                "vehicle_id": state.vehicle_id,
                "rsu_id": state.rsu_id,
                "timestamp": state.timestamp,
                "gat_score": score,
                "flagged": flagged,
                "ground_truth_poisoned": state.is_poisoned,
            })

        self.scores.extend(results)
        return results

    def add_training_snapshot(self, states: List[VehicleState]):
        """Accumulate clean snapshots for training."""
        self._snapshots.append(states)

    def finalize_training(self):
        """Run training on accumulated snapshots."""
        self.train_on_snapshots(self._snapshots)

    def reset(self):
        self._snapshots.clear()
        self.scores.clear()
        self._trained = False


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    # Synthetic snapshot with 5 vehicles
    snap = [
        VehicleState("V0", "RSU0", 9.0, 800.0, 1200.0, 10.0, 0.0, 0.5, 0.0, False),
        VehicleState("V1", "RSU0", 9.0, 1200.0, 1200.0, 10.0, 0.0, 0.5, 0.0, False),
        VehicleState("V2", "RSU1", 9.0, 1550.0, 1150.0, 12.0, 0.0, 0.3, 0.0, False),
        VehicleState("V3", "RSU1", 9.0, 1700.0, 1200.0, 11.0, 0.0, 0.4, 0.0, False),
        # Poisoned: position far outside expected range
        VehicleState("V4", "RSU2", 9.0, 5000.0, 5000.0, 50.0, 0.0, 8.0, 0.0, True),
    ]

    det = GATDetector(train_epochs=20)
    # Train on first 4 normal vehicles
    det.add_training_snapshot(snap[:4])
    det.finalize_training()

    results = det.score_snapshot(snap)
    print("GAT Detector Results:")
    for r in results:
        gt = "POISONED" if r["ground_truth_poisoned"] else "clean"
        print(f"  {r['vehicle_id']}: score={r['gat_score']:.3f} flagged={r['flagged']} gt={gt}")
