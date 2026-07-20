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
from gat_detector   import GATDetector, snapshot_to_graph, ATTACK_CLASSES, SIG_BITS, FEATURE_DIM
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
        # Richer identity features (raw, unscaled): composite ψ + 9 sig_mask bits
        # (the ψ sub-scores = which LW rule-checks fired). These carry the
        # per-attack signature the kinematics lack. Absent (legacy CSV) → zeros.
        n = len(feats_5)
        psi_col = (grp["psi_score"].fillna(0).values.astype(np.float32).reshape(-1, 1)
                   if "psi_score" in grp.columns else np.zeros((n, 1), np.float32))
        if "sig_mask" in grp.columns:
            sm = grp["sig_mask"].fillna(0).values.astype(np.int64)
            sig_bits = np.stack([((sm >> b) & 1) for b in range(SIG_BITS)],
                                axis=1).astype(np.float32)          # (N, SIG_BITS)
        else:
            sig_bits = np.zeros((n, SIG_BITS), np.float32)
        feats_6  = np.hstack([feats_5, tau_col, psi_col, sig_bits]) # (N, FEATURE_DIM)
        labels   = grp["is_poisoned"].values.astype(np.float32)
        data     = snapshot_to_graph(feats_6)
        data.y   = torch.tensor(labels, dtype=torch.float)

        # Multi-task per-attack labels y_i^(k) (revised eq:gat_loss): one-hot on
        # the attacking class. y_i^(k)=1 iff vehicle i is poisoned AND executing
        # attack type k (attack_number = k+1, k∈[0,K-1]); clean vehicles are all
        # zeros. attack_number is the ground-truth NS-3 attack config.
        y_multi = np.zeros((len(grp), ATTACK_CLASSES), dtype=np.float32)
        if "attack_number" in grp.columns:
            atk_num = grp["attack_number"].fillna(0).values.astype(int)
            is_pois = labels.astype(int)
            for r in range(len(grp)):
                k = atk_num[r] - 1
                if is_pois[r] == 1 and 0 <= k < ATTACK_CLASSES:
                    y_multi[r, k] = 1.0
        data.y_multi = torch.tensor(y_multi, dtype=torch.float)
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

    # Per-class inverse-frequency weights (revised eq:gat_loss):
    #   w_k^+ = |V_train| / (2|V_k^+|),  w_k^- = |V_train| / (2|V_k^-|)
    # computed once over the whole training set so rare attack classes are not
    # dominated by frequent ones. Guard divide-by-zero for empty classes.
    tot = 0
    pos = np.zeros(ATTACK_CLASSES, dtype=np.float64)
    for data in train_g:
        ym = data.y_multi.numpy()
        tot += ym.shape[0]
        pos += ym.sum(axis=0)
    neg = np.maximum(tot - pos, 0.0)
    w_pos = np.where(pos > 0, tot / (2.0 * np.maximum(pos, 1.0)), 1.0)
    w_neg = np.where(neg > 0, tot / (2.0 * np.maximum(neg, 1.0)), 1.0)
    # Cap the positive-class weight: uncapped inverse-frequency (up to ~14×)
    # heavily over-weights positives → the head sigmoids saturate high even on
    # CLEAN nodes, so max_k ŷ^(k) stops being a valid detection score (it was
    # inverted for control-plane attacks). A modest cap keeps the probabilities
    # calibrated so the head-detection fusion tier is discriminative, while still
    # up-weighting rare classes for routing. (MPTD_GAT_WPOS_CAP; default uncapped.)
    _wpos_cap = float(os.environ.get("MPTD_GAT_WPOS_CAP", "1e9"))
    w_pos = np.minimum(w_pos, _wpos_cap)
    w_pos_t = torch.tensor(w_pos, dtype=torch.float, device=DEVICE)   # (K,)
    w_neg_t = torch.tensor(w_neg, dtype=torch.float, device=DEVICE)   # (K,)
    print(f"[train] GAT multi-task: K={ATTACK_CLASSES} heads, "
          f"pos/class={pos.astype(int).tolist()}, w_pos={np.round(w_pos,2).tolist()}")

    # Gradient clipping + best-checkpoint (early-stopping) guard against the
    # multi-task loss diverging: the summed 7-head class-weighted BCE has a large
    # gradient scale, so a plain last-epoch save can land on a worse model.
    import copy
    GRAD_CLIP = float(os.environ.get("MPTD_GAT_GRAD_CLIP", "5.0"))
    best_val   = float("inf")
    best_state = copy.deepcopy(model.state_dict())

    def _val_loss():
        model.eval()
        vl = 0.0
        with torch.no_grad():
            for data in val_g:
                data = data.to(DEVICE)
                score, atk = model(data.x, data.edge_index)
                score = score.squeeze(-1)
                ym = data.y_multi
                w = ym * w_pos_t + (1.0 - ym) * w_neg_t
                vl += (loss_fn(score, data.y).item() +
                       nn.functional.binary_cross_entropy(atk, ym, weight=w).item() * ATTACK_CLASSES)
        return vl / max(1, len(val_g))

    for epoch in range(EPOCHS_GAT):
        model.train()
        total_loss = 0.0
        for data in train_g:
            data = data.to(DEVICE)
            opt.zero_grad()
            score, atk = model(data.x, data.edge_index)   # (N,1), (N,K)
            score = score.squeeze(-1)
            ym = data.y_multi                              # (N,K)
            # Spatial-score BCE keeps S_i (fusion GAT term) calibrated on the
            # binary is_poisoned label, exactly as before the multi-task patch.
            loss_s = loss_fn(score, data.y)
            # Summed per-head class-weighted BCE (revised eq:gat_loss).
            w = ym * w_pos_t + (1.0 - ym) * w_neg_t        # (N,K) per-element weight
            loss_k = nn.functional.binary_cross_entropy(atk, ym, weight=w, reduction="mean") * ATTACK_CLASSES
            loss = loss_s + loss_k
            loss.backward()
            if GRAD_CLIP > 0:
                torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
            opt.step()
            total_loss += loss.item()

        vl = _val_loss()
        if vl < best_val:
            best_val   = vl
            best_state = copy.deepcopy(model.state_dict())
        if (epoch + 1) % 5 == 0 or epoch == 0:
            print(f"  Epoch {epoch+1:3d}  train_loss={total_loss/len(train_g):.4f}"
                  f"  val_loss={vl:.4f}  best_val={best_val:.4f}")

    # Restore the best-validation checkpoint (not the possibly-diverged last one).
    model.load_state_dict(best_state)
    print(f"[train] GAT restored best-val checkpoint (val_loss={best_val:.4f})")
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
    Outputs:
      scores        (N, 1)  float32 spatial anomaly S_i ∈ [0,1]
      attack_probs  (N, K)  float32 per-attack detection probs ŷ_i^(k)
                            (argmax_k → predicted attack type k̂_i)
    """
    model.eval()
    dummy_x  = torch.randn(n_nodes, FEATURE_DIM, dtype=torch.float32)
    # Self-loop edges so the trace always has at least one edge per node.
    dummy_ei = torch.tensor([[i for i in range(n_nodes)],
                             [i for i in range(n_nodes)]], dtype=torch.long)
    torch.onnx.export(
        model,
        (dummy_x, dummy_ei),
        path,
        input_names  = ["x", "edge_index"],
        output_names = ["scores", "attack_probs"],
        dynamic_axes = {
            "x":            {0: "N"},
            "edge_index":   {1: "E"},
            "scores":       {0: "N"},
            "attack_probs": {0: "N"},
        },
        opset_version = 16,
        dynamo        = False,   # legacy tracer; required for PyG GATConv
    )
    print(f"[train] GAT ONNX exported → {path} (2 outputs: scores, attack_probs[K={ATTACK_CLASSES}])")


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
