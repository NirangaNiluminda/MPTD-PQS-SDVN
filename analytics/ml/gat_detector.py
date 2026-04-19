"""
gat_detector.py — GAT Spatial Anomaly Detector
MPTD-PQS Stage 5: paper §3.4.3, Eq. 3.42

Architecture: GATConv(5→32, heads=4) → GATConv(128→16) → Linear(16→1) → Sigmoid
Node features: [pos_x, pos_y, speed, heading, accel]  (5-dim)
Edge condition: Euclidean distance ≤ R_max = 300 m
Output:         S_i(t) ∈ [0,1] — spatial anomaly score per vehicle
"""

import torch
import torch.nn as nn
from torch_geometric.nn import GATConv
from torch_geometric.data import Data
import numpy as np

R_MAX = 300.0   # maximum communication range (metres)
FEATURE_DIM = 5 # [pos_x, pos_y, speed, heading, accel]


class GATDetector(nn.Module):
    """
    Two-layer GAT followed by a per-node linear classifier.
    Input shape : (N, 5)   where N = number of vehicles in snapshot
    Output shape: (N, 1)   spatial anomaly score S_i ∈ [0,1]
    """

    def __init__(self, in_dim: int = FEATURE_DIM, hidden: int = 32, heads: int = 4):
        super().__init__()
        self.conv1 = GATConv(in_dim, hidden, heads=heads, dropout=0.1)
        # concat=True → output dim = hidden * heads = 128
        self.conv2 = GATConv(hidden * heads, 16, heads=1, concat=False, dropout=0.1)
        self.out   = nn.Linear(16, 1)
        self.act   = nn.ELU()

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        x = self.act(self.conv1(x, edge_index))
        x = self.act(self.conv2(x, edge_index))
        return torch.sigmoid(self.out(x))   # (N, 1)


# ---------------------------------------------------------------------------
# Graph construction helpers
# ---------------------------------------------------------------------------

def build_edge_index(positions: np.ndarray, r_max: float = R_MAX) -> torch.Tensor:
    """
    Build edge_index (COO format) for vehicles within r_max of each other.
    positions: (N, 2)  numpy array of [pos_x, pos_y]
    Returns  : (2, E)  LongTensor
    """
    N = len(positions)
    src, dst = [], []
    for i in range(N):
        for j in range(N):
            if i != j:
                d = np.linalg.norm(positions[i] - positions[j])
                if d <= r_max:
                    src.append(i)
                    dst.append(j)
    if not src:
        # fully isolated: self-loops to avoid empty graph
        src = list(range(N))
        dst = list(range(N))
    return torch.tensor([src, dst], dtype=torch.long)


def snapshot_to_graph(features: np.ndarray) -> Data:
    """
    Convert a per-snapshot feature matrix to a PyG Data object.
    features: (N, 5)  [pos_x, pos_y, speed, heading, accel]
    """
    positions  = features[:, :2]
    edge_index = build_edge_index(positions)
    x          = torch.tensor(features, dtype=torch.float)
    return Data(x=x, edge_index=edge_index)


# ---------------------------------------------------------------------------
# Inference helper (stateless, used by prediction_server.py)
# ---------------------------------------------------------------------------

def score_snapshot(model: GATDetector, features: np.ndarray,
                   device: torch.device = torch.device("cpu")) -> np.ndarray:
    """
    Run forward pass on a single snapshot.
    features: (N, 5)
    Returns : (N,)  numpy array of S_i scores
    """
    model.eval()
    data = snapshot_to_graph(features)
    data = data.to(device)
    with torch.no_grad():
        scores = model(data.x, data.edge_index)  # (N, 1)
    return scores.cpu().squeeze(-1).numpy()
