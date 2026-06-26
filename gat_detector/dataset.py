"""
dataset.py
==========
Turns a flat beacon CSV into a list of PyTorch-Geometric graphs, one graph per
timestep. Implements:

  * Eq. 3.26  mobility-aware edge definition:
        (i,j) in E(t)  <=>  ||p_i - p_j|| <= R_max
                            AND  angle(v_i, v_j) <= phi_max
  * Eq. 3.27  per-graph (per-RSU-zone) rolling z-score feature normalisation.

Each graph node = one vehicle present at that timestep. Node label y in {0,1}.
"""
import math
import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data

EPS = 1e-8  # Eq. 3.27 epsilon


def _heading_features(df):
    """Add sin/cos heading columns so the model never sees a ±pi discontinuity."""
    df = df.copy()
    df["head_sin"] = np.sin(df["heading"].values)
    df["head_cos"] = np.cos(df["heading"].values)
    return df


def _build_edges(pos, vel, r_max, phi_max_rad):
    """
    Vectorised Eq. 3.26. pos:(N,2) vel:(N,2) -> edge_index (2,E) undirected.
    Returns torch.long tensor.
    """
    n = pos.shape[0]
    if n <= 1:
        return torch.empty((2, 0), dtype=torch.long)

    # pairwise distance
    diff = pos[:, None, :] - pos[None, :, :]          # (N,N,2)
    dist = np.linalg.norm(diff, axis=-1)              # (N,N)

    # pairwise heading divergence via cosine of velocity vectors
    speed = np.linalg.norm(vel, axis=-1)              # (N,)
    safe = np.clip(speed, 1e-6, None)
    unit = vel / safe[:, None]                        # (N,2)
    cos_ang = np.clip(unit @ unit.T, -1.0, 1.0)       # (N,N)
    ang = np.arccos(cos_ang)                          # (N,N) in [0,pi]

    mask = (dist <= r_max) & (ang <= phi_max_rad)
    np.fill_diagonal(mask, False)                     # no self loops here
    src, dst = np.where(mask)
    if src.size == 0:
        return torch.empty((2, 0), dtype=torch.long)
    edge_index = np.vstack([src, dst])
    return torch.tensor(edge_index, dtype=torch.long)


def build_graph(df_t, cfg):
    """
    df_t : rows for ONE (scenario, seed, t). cfg : ScenarioConfig.
    Returns a PyG Data with:
        x         (N,F) per-graph z-scored features (Eq. 3.27)
        edge_index(2,E) Eq. 3.26
        y         (N,)  labels
        vid       (N,)  vehicle ids (for traceability)
    """
    df_t = _heading_features(df_t)

    pos = df_t[["x", "y"]].values.astype(np.float64)
    speed = df_t["speed"].values.astype(np.float64)
    heading = df_t["heading"].values.astype(np.float64)
    vel = np.stack([speed * np.cos(heading), speed * np.sin(heading)], axis=1)

    feats = df_t[cfg.feature_cols].values.astype(np.float64)
    # Eq. 3.27 — z-score per feature across vehicles present in the zone now
    mu = feats.mean(axis=0, keepdims=True)
    sd = feats.std(axis=0, keepdims=True)
    feats_norm = (feats - mu) / (sd + EPS)

    edge_index = _build_edges(pos, vel, cfg.r_max, cfg.phi_max_rad)

    data = Data(
        x=torch.tensor(feats_norm, dtype=torch.float32),
        edge_index=edge_index,
        y=torch.tensor(df_t["label"].values, dtype=torch.float32),
    )
    data.vid = torch.tensor(df_t["vehicle_id"].astype("category").cat.codes.values,
                            dtype=torch.long)
    # RSU EXTENSION POINT:
    #   add vehicle-RSU edges here and a node-type mask so RSU nodes are
    #   excluded from the loss in train.py.
    return data


def load_graphs(csv_path, cfg):
    """Read a CSV and return a list[Data], one per timestep, for this scenario."""
    df = pd.read_csv(csv_path)
    df = df[df["scenario"] == cfg.name]
    if df.empty:
        raise ValueError(f"No rows for scenario '{cfg.name}' in {csv_path}")
    graphs = []
    for (_seed, _t), df_t in df.groupby(["seed", "t"], sort=True):
        if len(df_t) == 0:
            continue
        graphs.append(build_graph(df_t.reset_index(drop=True), cfg))
    return graphs
