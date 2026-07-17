"""
train.py — MPTD-PQS ML Training Pipeline  (Stage 5 + R7c ONNX export)
Reads analytics/results/beacon_log.csv produced by NS-3 simulation.
Falls back to synthetic VANET data if CSV is absent (for offline testing).

Outputs (saved to analytics/ml/models/):
  gat_model.pt      — trained GATDetector PyTorch weights
  gat_model.onnx    — GATDetector exported to ONNX  (R7c, for C++ inference)
  lstm_ae_model.pt  — trained LSTMAEDetector PyTorch weights
  lstm_ae_model.onnx — LSTMAEDetector exported to ONNX  (R7c, for C++ inference)
  theta_ae.txt      — adaptive AE threshold θ_ae
  scaler.pkl        — sklearn StandardScaler (Python only)
  scaler.json       — scaler mean/scale arrays (R7c, for C++ — same numbers as pkl)
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
ML_DIR        = os.path.dirname(__file__)
MODEL_DIR     = os.path.join(ML_DIR, "models")
# R7c: prefer the sweep-built master training file when present; fall back to
# the per-run beacon_log.csv (overwritten by the sim) so single-run debug works.
MASTER_CSV    = os.path.normpath(os.path.join(ML_DIR, "data", "beacon_train_master.csv"))
PER_RUN_CSV   = os.path.normpath(os.path.join(ML_DIR, "..", "results", "beacon_log.csv"))
BEACON_CSV    = MASTER_CSV if os.path.exists(MASTER_CSV) else PER_RUN_CSV

DEVICE      = torch.device("cuda" if torch.cuda.is_available() else "cpu")
EPOCHS_GAT  = int(os.environ.get("MPTD_GAT_EPOCHS", "30"))
EPOCHS_AE   = 40
BATCH_SIZE  = 32
LR          = float(os.environ.get("MPTD_GAT_LR", "1e-3"))          # #16 sensitivity
WEIGHT_DECAY = float(os.environ.get("MPTD_GAT_WD", "0.0"))          # #17 (paper 5e-4, was unapplied)

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
    # CRITICAL: when BEACON_CSV is the sweep-built master file, it concatenates
    # ~28 independent NS-3 runs. Without distinguishing them, group-by('sim_time')
    # merges vehicles from different runs into one impossible GAT snapshot, and
    # per-vehicle sort-by-sim_time splices beacons from different runs into one
    # fake LSTM-AE trajectory.
    #
    # Detect run boundaries via large sim_time DROPS (each appended per-run
    # CSV restarts at sim_time≈begin which is much earlier than the previous
    # run's end). Within one run sim_time mostly increases but small
    # reorderings of ~0.01–1.0 s occur because beacons from different vehicles
    # at the same timestep are emitted in interleaved scheduler order. A
    # threshold of |Δ| > 2 s cleanly separates inter-run boundaries (typically
    # several seconds backward) from intra-run jitter.
    if "run_id" not in df.columns:
        BOUNDARY_DROP = 2.0  # seconds — bigger than any plausible intra-run reorder
        prev = df["sim_time"].shift(1)
        new_run = (prev.notna() & ((prev - df["sim_time"]) > BOUNDARY_DROP))
        df["run_id"] = new_run.cumsum().astype(int)
    n_runs = int(df["run_id"].nunique())
    print(f"[train] Detected {n_runs} distinct run(s) in CSV (run_id 0..{n_runs - 1})")
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
    One PyG Data object per (run_id, beacon_tick) snapshot — i.e. all vehicles
    observed by RSU during one 100 ms tick WITHIN ONE RUN.

    Grouping by run_id prevents merging vehicles from independent sweep runs
    into the same graph (would create impossible 28×16=448-node snapshots).
    Bucketing sim_time at the beacon period T_b=0.1 s collapses interleaved
    per-vehicle scheduler offsets (e.g. 7.0, 7.00625, 7.0125 are all the same
    100 ms tick) into a single snapshot — without this, each "snapshot" would
    contain only 1 vehicle, the snapshot-level std() in the GAT head would
    return NaN, and BCELoss would fail on out-of-range NaN inputs.

    Label y_i = is_poisoned for each node.

    Node features (paper Eq. 3.21, 6-dim):
      [pos_x, pos_y, speed, heading, accel, tau_i]
    tau_i (SC-Trust score) defaults to 1.0 for training data because
    beacon_log.csv does not include blockchain trust queries.
    When real tau_i values are available (from /api/sctrust calls),
    they should be merged into the DataFrame before calling this function.
    """
    feat_cols = ["pos_x", "pos_y", "speed", "heading", "accel"]
    T_B = 0.1  # beacon interval (s) — paper §3.3, Eq. 3.21
    # Bucket to nearest beacon tick. Use floor so a beacon arriving at 7.005s
    # and another at 7.095s both land in bucket 7.0 (start of that tick).
    df = df.copy()
    df["_tick"] = (df["sim_time"] / T_B).round().astype(int)
    group_keys = ["run_id", "_tick"] if "run_id" in df.columns else ["_tick"]
    graphs = []
    for _key, grp in df.groupby(group_keys):
        if len(grp) < 2:
            # Snapshot-level z-score in GATDetector forward needs N≥2 for
            # std() to be defined. Single-vehicle snapshots are rare; skip
            # them rather than emit NaN losses.
            continue
        feats_5  = grp[feat_cols].values.astype(np.float32)
        # Append tau_i column: default 1.0 (fully trusted) — Eq. 3.21
        tau_col  = np.ones((len(feats_5), 1), dtype=np.float32)
        feats_6  = np.hstack([feats_5, tau_col])   # (N, 6)
        labels   = grp["is_poisoned"].values.astype(np.float32)
        data     = snapshot_to_graph(feats_6)
        data.y   = torch.tensor(labels, dtype=torch.float)
        graphs.append(data)
    return graphs


def train_gat(df: pd.DataFrame) -> GATDetector:
    print("[train] Training GAT detector …")
    # Deterministic init + training so hyperparameter sweeps isolate the knob
    # (not random-init noise). Fixed seed → 1 run per value is a fair comparison.
    _seed = int(os.environ.get("MPTD_SEED", "42"))
    torch.manual_seed(_seed); np.random.seed(_seed)
    graphs = build_gat_dataset(df)
    train_g, val_g = train_test_split(graphs, test_size=0.2, random_state=42)

    model = GATDetector().to(DEVICE)
    opt   = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)  # #17
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
    # Per (run_id, vehicle_id) windowing — see load_beacons() for why we MUST
    # NOT cross run boundaries. Sliding windows that splice beacons from
    # different runs would learn to reconstruct interleaved random walks and
    # then fail catastrophically on real coherent trajectories at inference.
    if "run_id" in df.columns:
        group_keys = ["run_id", "vehicle_id"]
    else:
        group_keys = ["vehicle_id"]
    all_windows, all_labels = [], []

    for _key, vdf in df.groupby(group_keys):
        vdf = vdf.sort_values("sim_time").reset_index(drop=True)
        wins = build_windows(vdf, vehicle_id=vdf["vehicle_id"].iloc[0])
        if len(wins) == 0:
            continue
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
    BETA    = 0.1  # kinematic penalty weight β (Eq. 3.51)
    DT      = 0.1  # beacon interval T_b = 100 ms

    def kinematic_loss(recon: torch.Tensor) -> torch.Tensor:
        """
        Mobility-Constrained Reconstruction Loss — Eq. 3.31 / 3.51
        L_kinematic = (1/L) Σ max(0, r_i(t_l) − δ_th)²
        where r_i(t_l) = ‖ p_i(t) − p̂_i(t) ‖  (dead-reckoning residual, Eq. 3.13)
        and δ_th is the tolerance threshold (default 10.0 m, from §3.3.2).
        Only residuals EXCEEDING δ_th are penalised (hinge form).
        recon: (B, k, 5)  cols: [pos_x, pos_y, speed, heading, accel]
        """
        DELTA_TH = 10.0   # δ_th — dead-reckoning tolerance (metres), Eq. 3.13
        pos_x   = recon[:, :, 0]   # (B, k)
        pos_y   = recon[:, :, 1]
        speed   = recon[:, :, 2]
        heading = recon[:, :, 3]
        # Predicted positions using prev step kinematics (cols 1..k-1 depend on 0..k-2)
        pred_x = pos_x[:, :-1] + speed[:, :-1] * torch.cos(heading[:, :-1]) * DT
        pred_y = pos_y[:, :-1] + speed[:, :-1] * torch.sin(heading[:, :-1]) * DT
        # r_i(t) = Euclidean dead-reckoning residual  (Eq. 3.13/3.14)
        r = torch.sqrt((pos_x[:, 1:] - pred_x) ** 2 +
                       (pos_y[:, 1:] - pred_y) ** 2 + 1e-8)  # (B, k-1)
        # Hinge: only penalise residuals beyond δ_th  (Eq. 3.31/3.51)
        hinge = torch.clamp(r - DELTA_TH, min=0.0) ** 2
        return hinge.mean()

    for epoch in range(EPOCHS_AE):
        model.train()
        total_loss = 0.0
        for i in range(0, len(train_t), BATCH_SIZE):
            batch = train_t[i:i+BATCH_SIZE].to(DEVICE)
            opt.zero_grad()
            recon = model(batch)
            l_recon    = loss_fn(recon, batch)
            l_kinematic = kinematic_loss(recon)
            loss = l_recon + BETA * l_kinematic   # Eq. 3.51: L_total = L_recon + β·L_kinematic
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

def export_gat_onnx(model: GATDetector, path: str, n_nodes: int = 16):
    """
    Export GAT to ONNX via the legacy TorchScript exporter (dynamo=False).
    The PyTorch 2.x dynamo exporter cannot handle PyG GATConv's data-dependent
    edge attention masking — it raises GuardOnDataDependentSymNode in
    torch_geometric/nn/conv/gat_conv.py:398. Legacy tracer + opset 16 works.

    Inputs:
      x          (N, 6)  float32 node features
      edge_index (2, E)  int64   COO edges
    Output:
      scores     (N, 1)  float32 spatial anomaly S_i ∈ [0,1]
    """
    model.eval()
    dummy_x  = torch.randn(n_nodes, 6, dtype=torch.float32)
    # Self-loop edges so the trace always has at least one edge per node.
    dummy_ei = torch.tensor([[i for i in range(n_nodes)],
                             [i for i in range(n_nodes)]], dtype=torch.long)
    torch.onnx.export(
        model,
        (dummy_x, dummy_ei),
        path,
        input_names  = ["x", "edge_index"],
        output_names = ["scores"],
        dynamic_axes = {
            "x":          {0: "N"},
            "edge_index": {1: "E"},
            "scores":     {0: "N"},
        },
        opset_version = 16,
        dynamo        = False,   # legacy tracer; required for PyG GATConv
    )
    print(f"[train] GAT ONNX exported → {path}")


def export_lstm_ae_onnx(model: LSTMAEDetector, path: str,
                         window: int = WINDOW_SIZE):
    """
    Export LSTM-AE to ONNX with dynamic batch axis. Input:
      x      (B, k, 5)  float32  (k=WINDOW_SIZE; feature_dim=5)
    Output:
      recon  (B, k, 5)  float32  reconstructed sequence
    The C++ side computes the per-window reconstruction MSE and compares against
    theta_ae from theta_ae.txt. Uses legacy exporter for consistency with GAT.
    """
    model.eval()
    dummy = torch.randn(1, window, 5, dtype=torch.float32)
    torch.onnx.export(
        model,
        dummy,
        path,
        input_names  = ["x"],
        output_names = ["recon"],
        dynamic_axes = {
            "x":     {0: "B"},
            "recon": {0: "B"},
        },
        opset_version = 16,
        dynamo        = False,
    )
    print(f"[train] LSTM-AE ONNX exported → {path}")


def export_scaler_json(scaler: StandardScaler, path: str):
    """
    Serialize the StandardScaler so the C++ side can apply the same
    normalisation. Columns are [pos_x, pos_y, speed, heading, accel] (order
    matches normalise() above).
    """
    blob = {
        "feature_names": ["pos_x", "pos_y", "speed", "heading", "accel"],
        "mean":          scaler.mean_.tolist(),
        "scale":         scaler.scale_.tolist(),
    }
    with open(path, "w") as f:
        json.dump(blob, f, indent=2)
    print(f"[train] Scaler JSON saved → {path}")


def main():
    os.makedirs(MODEL_DIR, exist_ok=True)

    df = load_beacons()
    df, scaler = normalise(df)

    # --- GAT
    gat_model = train_gat(df)
    torch.save(gat_model.state_dict(), os.path.join(MODEL_DIR, "gat_model.pt"))
    print(f"[train] GAT model saved → {MODEL_DIR}/gat_model.pt")
    export_gat_onnx(gat_model.cpu(), os.path.join(MODEL_DIR, "gat_model.onnx"))

    # --- LSTM-AE
    ae_model, theta_ae = train_lstm_ae(df)
    torch.save(ae_model.state_dict(), os.path.join(MODEL_DIR, "lstm_ae_model.pt"))
    with open(os.path.join(MODEL_DIR, "theta_ae.txt"), "w") as f:
        f.write(str(theta_ae))
    print(f"[train] LSTM-AE model saved → {MODEL_DIR}/lstm_ae_model.pt")
    export_lstm_ae_onnx(ae_model.cpu(), os.path.join(MODEL_DIR, "lstm_ae_model.onnx"))

    # --- Scaler (pkl for Python eval scripts, json for C++ inference)
    with open(os.path.join(MODEL_DIR, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    print(f"[train] Scaler saved → {MODEL_DIR}/scaler.pkl")
    export_scaler_json(scaler, os.path.join(MODEL_DIR, "scaler.json"))
    print("[train] Done.")


if __name__ == "__main__":
    main()
