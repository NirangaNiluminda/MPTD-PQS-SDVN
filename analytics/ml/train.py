"""
train.py — MPTD-PQS ML Training Pipeline  (Stage 5)
Reads analytics/results/beacon_log.csv produced by NS-3 simulation.
Falls back to synthetic VANET data if CSV is absent (for offline testing).

Outputs (saved to analytics/ml/models/):
  gat_model.pt     — trained GATDetector weights
  lstm_ae_model.pt — trained LSTMAEDetector weights
  theta_ae.txt     — adaptive AE threshold θ_ae
  scaler.pkl       — sklearn StandardScaler for feature normalisation
"""

import os, sys, json, pickle
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch_geometric.loader import DataLoader as GeoLoader
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# --- path setup so we can import sibling modules
sys.path.insert(0, os.path.dirname(__file__))
from gat_detector   import GATDetector, snapshot_to_graph
from lstm_ae        import LSTMAEDetector, build_windows, calibrate_threshold, WINDOW_SIZE

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ML_DIR      = os.path.dirname(__file__)
MODEL_DIR   = os.path.join(ML_DIR, "models")
BEACON_CSV  = os.path.join(ML_DIR, "..", "results", "beacon_log.csv")
BEACON_CSV  = os.path.normpath(BEACON_CSV)

DEVICE      = torch.device("cuda" if torch.cuda.is_available() else "cpu")
EPOCHS_GAT  = 30
EPOCHS_AE   = 40
BATCH_SIZE  = 32
LR          = 1e-3

# ---------------------------------------------------------------------------
# Synthetic data generator (when beacon_log.csv is absent)
# ---------------------------------------------------------------------------

def _generate_synthetic_beacons(n_vehicles: int = 16,
                                 n_steps: int = 400,
                                 attack_frac: float = 0.2,
                                 seed: int = 42) -> pd.DataFrame:
    """
    Simulate `n_vehicles` vehicles broadcasting beacons at 100ms intervals.
    Poisoned vehicles (attack_frac of them) add trajectory noise.
    Returns DataFrame with same schema as beacon_log.csv.
    """
    rng = np.random.default_rng(seed)
    rows = []
    # random initial positions
    pos   = rng.uniform(0, 1000, (n_vehicles, 2))
    speed = rng.uniform(5, 20, n_vehicles)
    head  = rng.uniform(0, 2 * np.pi, n_vehicles)
    accel = rng.uniform(-1, 1, n_vehicles)
    is_poisoned = np.zeros(n_vehicles, dtype=bool)
    n_mal = max(1, int(n_vehicles * attack_frac))
    is_poisoned[:n_mal] = True

    for t in range(n_steps):
        sim_time = t * 0.1
        for vid in range(n_vehicles):
            # simple kinematic update
            pos[vid, 0] += speed[vid] * np.cos(head[vid]) * 0.1
            pos[vid, 1] += speed[vid] * np.sin(head[vid]) * 0.1
            speed[vid]   = np.clip(speed[vid] + accel[vid] * 0.1 + rng.normal(0, 0.1), 1, 33)
            head[vid]   += rng.normal(0, 0.02)
            accel[vid]   = np.clip(accel[vid] + rng.normal(0, 0.05), -4, 4)

            px, py = pos[vid]
            if is_poisoned[vid]:
                # inject trajectory poisoning noise (θ=0.5)
                px += 0.5 * 50 * np.sin(sim_time * 0.7)
                py += 0.5 * 50 * np.cos(sim_time * 0.5)

            rsu_id   = vid % 4
            detected = is_poisoned[vid] and rng.random() < 0.85
            rows.append(dict(
                sim_time   = sim_time,
                vehicle_id = vid,
                rsu_id     = rsu_id,
                pos_x      = px,
                pos_y      = py,
                speed      = speed[vid],
                heading    = head[vid],
                accel      = accel[vid],
                is_poisoned= int(is_poisoned[vid]),
                detected   = int(detected),
                sig_mask   = 0,
                psi_score  = float(detected) * rng.uniform(0.5, 1.0)
            ))
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_beacons() -> pd.DataFrame:
    if os.path.exists(BEACON_CSV) and os.path.getsize(BEACON_CSV) > 10:
        print(f"[train] Loading beacon data from {BEACON_CSV}")
        df = pd.read_csv(BEACON_CSV)
    else:
        print(f"[train] beacon_log.csv not found — using synthetic VANET data")
        df = _generate_synthetic_beacons()
    return df


def normalise(df: pd.DataFrame, scaler: StandardScaler = None):
    feat_cols = ["pos_x", "pos_y", "speed", "heading", "accel"]
    if scaler is None:
        scaler = StandardScaler()
        df[feat_cols] = scaler.fit_transform(df[feat_cols])
    else:
        df[feat_cols] = scaler.transform(df[feat_cols])
    return df, scaler


# ---------------------------------------------------------------------------
# GAT training
# ---------------------------------------------------------------------------

def build_gat_dataset(df: pd.DataFrame):
    """
    One PyG Data object per time-step snapshot (all vehicles at that timestamp).
    Label y_i = is_poisoned for each node.
    """
    feat_cols = ["pos_x", "pos_y", "speed", "heading", "accel"]
    graphs = []
    for t, grp in df.groupby("sim_time"):
        feats  = grp[feat_cols].values.astype(np.float32)
        labels = grp["is_poisoned"].values.astype(np.float32)
        data   = snapshot_to_graph(feats)
        data.y = torch.tensor(labels, dtype=torch.float)
        graphs.append(data)
    return graphs


def train_gat(df: pd.DataFrame) -> GATDetector:
    print("[train] Training GAT detector …")
    graphs = build_gat_dataset(df)
    train_g, val_g = train_test_split(graphs, test_size=0.2, random_state=42)

    model = GATDetector().to(DEVICE)
    opt   = torch.optim.Adam(model.parameters(), lr=LR)
    loss_fn = nn.BCELoss()

    for epoch in range(EPOCHS_GAT):
        model.train()
        total_loss = 0.0
        for data in train_g:
            data = data.to(DEVICE)
            opt.zero_grad()
            pred = model(data.x, data.edge_index).squeeze(-1)
            loss = loss_fn(pred, data.y)
            loss.backward()
            opt.step()
            total_loss += loss.item()

        if (epoch + 1) % 10 == 0:
            model.eval()
            val_loss = 0.0
            with torch.no_grad():
                for data in val_g:
                    data = data.to(DEVICE)
                    pred = model(data.x, data.edge_index).squeeze(-1)
                    val_loss += loss_fn(pred, data.y).item()
            print(f"  Epoch {epoch+1:3d}  train_loss={total_loss/len(train_g):.4f}"
                  f"  val_loss={val_loss/len(val_g):.4f}")

    return model


# ---------------------------------------------------------------------------
# LSTM-AE training
# ---------------------------------------------------------------------------

def train_lstm_ae(df: pd.DataFrame):
    print("[train] Training LSTM-AE detector …")
    vehicle_ids = df["vehicle_id"].unique()
    all_windows, all_labels = [], []

    for vid in vehicle_ids:
        wins = build_windows(df, vid)
        if len(wins) == 0:
            continue
        # labels: window is poisoned if any step in it is poisoned
        vdf = df[df["vehicle_id"] == vid].sort_values("sim_time")
        poi = vdf["is_poisoned"].values
        for i in range(len(wins)):
            lbl = int(poi[i:i+WINDOW_SIZE].any())
            all_windows.append(wins[i])
            all_labels.append(lbl)

    windows = np.stack(all_windows).astype(np.float32)
    labels  = np.array(all_labels)

    # Train AE only on clean windows; evaluate threshold on them too
    clean_idx = np.where(labels == 0)[0]
    if len(clean_idx) < 2:
        clean_idx = np.arange(len(windows))  # fallback

    train_idx, val_idx = train_test_split(clean_idx, test_size=0.2, random_state=42)
    train_t = torch.tensor(windows[train_idx])
    val_t   = torch.tensor(windows[val_idx])

    model   = LSTMAEDetector().to(DEVICE)
    opt     = torch.optim.Adam(model.parameters(), lr=LR)
    loss_fn = nn.MSELoss()

    for epoch in range(EPOCHS_AE):
        model.train()
        total_loss = 0.0
        for i in range(0, len(train_t), BATCH_SIZE):
            batch = train_t[i:i+BATCH_SIZE].to(DEVICE)
            opt.zero_grad()
            recon = model(batch)
            loss  = loss_fn(recon, batch)
            loss.backward()
            opt.step()
            total_loss += loss.item()

        if (epoch + 1) % 10 == 0:
            model.eval()
            with torch.no_grad():
                val_recon = model(val_t.to(DEVICE))
                val_loss  = loss_fn(val_recon, val_t.to(DEVICE)).item()
            print(f"  Epoch {epoch+1:3d}  train_loss={total_loss/(len(train_t)//BATCH_SIZE+1):.6f}"
                  f"  val_loss={val_loss:.6f}")

    # Calibrate θ_ae on validation clean windows
    theta_ae = calibrate_threshold(model, val_t, device=DEVICE)
    print(f"[train] θ_ae (adaptive threshold) = {theta_ae:.6f}")
    return model, theta_ae


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    df = load_beacons()
    df, scaler = normalise(df)

    # --- GAT
    gat_model = train_gat(df)
    torch.save(gat_model.state_dict(), os.path.join(MODEL_DIR, "gat_model.pt"))
    print(f"[train] GAT model saved → {MODEL_DIR}/gat_model.pt")

    # --- LSTM-AE
    ae_model, theta_ae = train_lstm_ae(df)
    torch.save(ae_model.state_dict(), os.path.join(MODEL_DIR, "lstm_ae_model.pt"))
    with open(os.path.join(MODEL_DIR, "theta_ae.txt"), "w") as f:
        f.write(str(theta_ae))
    print(f"[train] LSTM-AE model saved → {MODEL_DIR}/lstm_ae_model.pt")

    # --- Scaler
    with open(os.path.join(MODEL_DIR, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    print(f"[train] Scaler saved → {MODEL_DIR}/scaler.pkl")
    print("[train] Done.")


if __name__ == "__main__":
    main()
