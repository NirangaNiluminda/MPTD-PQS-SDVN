"""
gat_detector.py — GAT Spatial Anomaly Detector
MPTD-PQS Stage 5: paper §3.4.3, Eq. 3.21, 3.38, 3.42

Architecture: GATConv(6→32, heads=4) → GATConv(128→16) → Linear(16→1) → Sigmoid

Node features (paper Eq. 3.21, 6-dim):
  [pos_x, pos_y, speed, heading, accel, tau_i]
  where tau_i = on-chain SC-Trust score ∈ [0,1] (initialised to 1.0 if unavailable)

Edge condition (paper Eq. 3.21, 3.38): BOTH must hold:
  (a) distance:         ||p_i(t) − p_j(t)|| ≤ R_max = 300 m
  (b) heading alignment: arccos(v_i·v_j / (||v_i||·||v_j||)) ≤ PHI_MAX = π/2 rad (90°)
      Vehicles moving in opposite directions are NOT connected.
      (Use PHI_MAX = π/4 = 45° for platoon; π/2 for urban cross-traffic VANET)

Output:  S_i(t) ∈ [0,1] — spatial anomaly score per vehicle (Eq. 3.42)
"""

import torch
import torch.nn as nn
from torch_geometric.nn import GATConv
from torch_geometric.data import Data
import numpy as np

R_MAX       = 300.0         # maximum communication range (metres)
PHI_MAX     = np.pi / 2     # max heading divergence for edge (90° — urban VANET)
FEATURE_DIM = 6             # [pos_x, pos_y, speed, heading, accel, tau_i]
TAU_INIT    = 1.0           # default trust score when blockchain unavailable


class GATDetector(nn.Module):
    """
    Two-layer GAT.  Output: S_i(t) = ‖(x'_i − x̄') / σ'‖₂  (Eq. 3.42)
    where x'_i is the 16-dim GAT embedding of node i, and x̄'/σ' are the
    snapshot-level mean and std across all nodes.

    Input shape : (N, 6)   where N = number of vehicles in snapshot
                           features = [pos_x, pos_y, speed, heading, accel, tau_i]
    Output shape: (N, 1)   spatial anomaly score S_i ∈ [0,1]
    """

    def __init__(self, in_dim: int = FEATURE_DIM, hidden: int = 32, heads: int = 4):
        super().__init__()
        self.conv1 = GATConv(in_dim, hidden, heads=heads, dropout=0.1)
        # concat=True → output dim = hidden * heads = 128
        self.conv2 = GATConv(hidden * heads, 16, heads=1, concat=False, dropout=0.1)
        self.act   = nn.ELU()
        # Learnable score head: linear projection of the raw z-score L2 norm
        # into the sigmoid's "useful" range. Without these, the bare
        # sigmoid(L2-norm-of-16-dim-z-score) saturates near 1.0 for ALL nodes
        # because the L2 norm of a 16-dim unit-variance z-score is ~√16 ≈ 4
        # by construction, regardless of anomaly status. With a learnable
        # scale and bias the model can pick a discriminative operating point
        # during training instead of being clamped at the saturated tail.
        self.score_scale = nn.Parameter(torch.tensor(1.0))
        self.score_bias  = nn.Parameter(torch.tensor(-4.0))  # init near sigmoid origin

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Returns S_i ∈ [0,1] per node: sigmoid-mapped L2-norm of z-score of
        the GAT embedding (paper Eq. 3.42, with a learnable affine to keep
        the sigmoid out of its saturated tail).
        """
        emb = self.act(self.conv1(x, edge_index))   # (N, hidden*heads)
        emb = self.act(self.conv2(emb, edge_index)) # (N, 16) — x'_i

        # Snapshot-level mean and std across nodes  (Eq. 3.42)
        mu  = emb.mean(dim=0, keepdim=True)         # (1, 16)
        sig = emb.std(dim=0, keepdim=True) + 1e-6   # (1, 16)
        z   = (emb - mu) / sig                      # (N, 16)
        s_i = z.norm(dim=1, keepdim=True)           # (N, 1) — L2 z-score norm

        # Affine + sigmoid — learnable shift/scale keeps the output away from
        # the saturated tail of sigmoid where gradients vanish.
        logit = self.score_scale * s_i + self.score_bias
        return torch.sigmoid(logit)                 # (N, 1)


# ---------------------------------------------------------------------------
# Graph construction helpers
# ---------------------------------------------------------------------------

def _heading_to_velocity(heading_rad: np.ndarray, speed: np.ndarray) -> np.ndarray:
    """
    Convert heading angle + speed to 2-D velocity vector.
    heading_rad: (N,)  radians  (0 = East, increases counter-clockwise)
    speed      : (N,)  m/s
    Returns    : (N, 2)  [vx, vy]
    """
    vx = speed * np.cos(heading_rad)
    vy = speed * np.sin(heading_rad)
    return np.stack([vx, vy], axis=1)


def _heading_aligned(vi: np.ndarray, vj: np.ndarray, phi_max: float) -> bool:
    """
    Returns True if the angle between velocity vectors vi and vj ≤ phi_max.
    Handles zero-speed vehicles (parked): always considered aligned to avoid
    isolating stationary vehicles from their neighbours.
    (Paper Eq. 3.38: cos⁻¹(v_i·v_j / (||v_i||·||v_j||)) ≤ φ_max)
    """
    ni = np.linalg.norm(vi)
    nj = np.linalg.norm(vj)
    if ni < 1e-6 or nj < 1e-6:
        return True          # parked vehicle — do not isolate
    cos_angle = np.dot(vi, vj) / (ni * nj)
    cos_angle = float(np.clip(cos_angle, -1.0, 1.0))
    return np.arccos(cos_angle) <= phi_max


def build_edge_index(positions: np.ndarray,
                     headings:  np.ndarray,
                     speeds:    np.ndarray,
                     r_max:     float = R_MAX,
                     phi_max:   float = PHI_MAX) -> torch.Tensor:
    """
    Build edge_index (COO format) for the VANET graph.

    Edge exists between i and j iff BOTH hold (paper Eq. 3.21, 3.38):
      (a) ||p_i − p_j|| ≤ r_max              (communication range)
      (b) angle(v_i, v_j)   ≤ phi_max        (heading alignment)

    positions : (N, 2)  numpy [pos_x, pos_y]
    headings  : (N,)    numpy heading angles in radians
    speeds    : (N,)    numpy speed in m/s
    Returns   : (2, E)  LongTensor
    """
    N        = len(positions)
    velocities = _heading_to_velocity(headings, speeds)  # (N, 2)
    src, dst = [], []

    for i in range(N):
        for j in range(N):
            if i == j:
                continue
            # (a) distance condition
            d = np.linalg.norm(positions[i] - positions[j])
            if d > r_max:
                continue
            # (b) heading alignment condition (paper Eq. 3.38)
            if not _heading_aligned(velocities[i], velocities[j], phi_max):
                continue
            src.append(i)
            dst.append(j)

    if not src:
        # fully isolated snapshot: self-loops to avoid empty graph
        src = list(range(N))
        dst = list(range(N))

    return torch.tensor([src, dst], dtype=torch.long)


def snapshot_to_graph(features: np.ndarray,
                      phi_max:  float = PHI_MAX) -> Data:
    """
    Convert a per-snapshot feature matrix to a PyG Data object.

    features: (N, 6)  [pos_x, pos_y, speed, heading, accel, tau_i]
              Column order must match FEATURE_DIM definition above.
    """
    positions = features[:, :2]          # pos_x, pos_y
    speeds    = features[:, 2]           # speed
    headings  = features[:, 3]           # heading (radians)
    edge_index = build_edge_index(positions, headings, speeds, phi_max=phi_max)
    x          = torch.tensor(features, dtype=torch.float)
    return Data(x=x, edge_index=edge_index)


# ---------------------------------------------------------------------------
# Inference helper (stateless, used by prediction_server.py)
# ---------------------------------------------------------------------------

def score_snapshot(model: GATDetector, features: np.ndarray,
                   device: torch.device = torch.device("cpu")) -> np.ndarray:
    """
    Run forward pass on a single snapshot.

    features: (N, 6)  [pos_x, pos_y, speed, heading, accel, tau_i]
              If tau_i column is absent (legacy 5-col data), it is appended
              as TAU_INIT = 1.0 so that old beacon_log.csv still works.
    Returns : (N,)  numpy array of S_i scores ∈ [0,1]
    """
    if features.shape[1] == 5:
        # Backward compatibility: append tau_i = TAU_INIT
        tau_col  = np.full((len(features), 1), TAU_INIT, dtype=np.float32)
        features = np.hstack([features, tau_col])

    # Snapshot-level z-score in the model head needs N≥2 (otherwise std()
    # returns NaN, scores become NaN, downstream fusion breaks). On a
    # 1-vehicle snapshot the spatial-anomaly signal is undefined: emit a
    # below-threshold neutral score so the lone vehicle isn't auto-flagged
    # by GAT, letting the temporal AE branch carry the decision.
    # R7f.followup-1c: was 0.5 — equal to GAT_THRESH=0.5 in evaluate_all.py,
    # so every 1-vehicle snapshot triggered A2 (FPR=1.0). Now 0.0.
    if features.shape[0] < 2:
        return np.zeros((features.shape[0],), dtype=np.float32)

    model.eval()
    data = snapshot_to_graph(features)
    data = data.to(device)
    with torch.no_grad():
        scores = model(data.x, data.edge_index)  # (N, 1)
    return scores.cpu().squeeze(-1).numpy()
