"""
baseline_eval.py — MPTD-PQS Baseline Comparison  (Stage 5)
Paper §4 — Compares 4 detection modes on beacon_log.csv (or synthetic data):
  B1 — Rule-based only (ψ_score threshold)
  B2 — GAT only (S_i threshold)
  B3 — LSTM-AE only (ε_i > θ_ae)
  MPTD-PQS — Full fusion (Φ > 0.5)

Outputs: analytics/results/baseline_comparison.csv
         Columns: mode, attack_number, attack_percentage, TP, FP, TN, FN,
                  MCC, FPR, PARR, CDER, TDEE, TPE
"""

import os, sys, json, pickle
import numpy as np
import pandas as pd
import torch

sys.path.insert(0, os.path.dirname(__file__))
from gat_detector  import GATDetector, score_snapshot, snapshot_to_graph
from lstm_ae       import LSTMAEDetector, score_window, build_windows, WINDOW_SIZE
from score_fusion  import fuse

ML_DIR     = os.path.dirname(__file__)
MODEL_DIR  = os.path.join(ML_DIR, "models")
BEACON_CSV = os.path.normpath(os.path.join(ML_DIR, "..", "results", "beacon_log.csv"))
OUT_CSV    = os.path.normpath(os.path.join(ML_DIR, "..", "results", "baseline_comparison.csv"))

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ψ threshold for B1
PSI_THRESH = 0.5
# S_i threshold for B2
GAT_THRESH = 0.5

# ---------------------------------------------------------------------------
# Metric helpers
# ---------------------------------------------------------------------------

def _safe(num, den):
    return num / den if den else 0.0


def compute_metrics(tp, fp, tn, fn):
    total = tp + fp + tn + fn
    denom_mcc = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    mcc   = (tp * tn - fp * fn) / (denom_mcc ** 0.5 + 1e-9) if denom_mcc else 0.0
    fpr   = _safe(fp, fp + tn)
    parr  = _safe(tp, tp + fn)         # Poisoning Attack Rejection Rate
    cder  = _safe(tp, tp + fp + fn)    # Correct Detection-to-Error Ratio
    tdee  = _safe(fn, total)           # Trajectory Data Error Exposure
    tpe   = _safe(tp + fn, total)      # Trajectory Poisoning Exposure
    return dict(MCC=mcc, FPR=fpr, PARR=parr, CDER=cder, TDEE=tdee, TPE=tpe)


# ---------------------------------------------------------------------------
# Load models
# ---------------------------------------------------------------------------

def load_models():
    gat = GATDetector().to(DEVICE)
    ae  = LSTMAEDetector().to(DEVICE)
    theta_ae = 0.05
    scaler   = None

    gat_ckpt = os.path.join(MODEL_DIR, "gat_model.pt")
    ae_ckpt  = os.path.join(MODEL_DIR, "lstm_ae_model.pt")
    th_path  = os.path.join(MODEL_DIR, "theta_ae.txt")
    sc_path  = os.path.join(MODEL_DIR, "scaler.pkl")

    if os.path.exists(gat_ckpt):
        gat.load_state_dict(torch.load(gat_ckpt, map_location=DEVICE))
    if os.path.exists(ae_ckpt):
        ae.load_state_dict(torch.load(ae_ckpt, map_location=DEVICE))
    if os.path.exists(th_path):
        theta_ae = float(open(th_path).read())
    if os.path.exists(sc_path):
        with open(sc_path, "rb") as f:
            scaler = pickle.load(f)

    gat.eval(); ae.eval()
    return gat, ae, theta_ae, scaler


# ---------------------------------------------------------------------------
# Evaluate all beacons in a dataframe
# ---------------------------------------------------------------------------

def evaluate(df: pd.DataFrame, gat, ae, theta_ae, scaler):
    """
    Returns per-beacon rows with columns: vehicle_id, is_poisoned,
    b1_det, b2_det, b3_det, mptd_det
    """
    feat_cols = ["pos_x", "pos_y", "speed", "heading", "accel"]

    if scaler is not None:
        df = df.copy()
        df[feat_cols] = scaler.transform(df[feat_cols])

    results = []
    ae_windows: dict[int, list] = {}

    for t, grp in df.groupby("sim_time"):
        vids   = grp["vehicle_id"].values
        feats  = grp[feat_cols].values.astype(np.float32)
        poisoned = grp["is_poisoned"].values
        psi_scores = grp["psi_score"].values if "psi_score" in grp.columns else np.zeros(len(grp))

        # GAT scores for all vehicles in snapshot
        gat_scores = score_snapshot(gat, feats, device=DEVICE)

        for i, vid in enumerate(vids):
            # Maintain AE window
            if vid not in ae_windows:
                ae_windows[vid] = []
            ae_windows[vid].append(feats[i])
            if len(ae_windows[vid]) > WINDOW_SIZE:
                ae_windows[vid].pop(0)

            if len(ae_windows[vid]) == WINDOW_SIZE:
                window_arr = np.array(ae_windows[vid], dtype=np.float32)
                ae_error   = score_window(ae, window_arr, device=DEVICE)
            else:
                ae_error = 0.0

            psi = float(psi_scores[i])
            g   = float(gat_scores[i])
            res = fuse(psi, g, ae_error, theta_ae)

            results.append(dict(
                vehicle_id  = int(vid),
                is_poisoned = int(poisoned[i]),
                b1_det      = int(psi >= PSI_THRESH),
                b2_det      = int(g >= GAT_THRESH),
                b3_det      = int(ae_error >= theta_ae),
                mptd_det    = int(res.is_anomalous),
            ))

    return pd.DataFrame(results)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Load data
    if os.path.exists(BEACON_CSV) and os.path.getsize(BEACON_CSV) > 10:
        df = pd.read_csv(BEACON_CSV)
        print(f"[eval] Loaded {len(df)} beacons from {BEACON_CSV}")
    else:
        from train import _generate_synthetic_beacons
        df = _generate_synthetic_beacons()
        print(f"[eval] Using synthetic data ({len(df)} beacons)")

    # Determine group columns available
    has_attack   = "attack_number"     in df.columns
    has_pct      = "attack_percentage" in df.columns

    gat, ae, theta_ae, scaler = load_models()
    print(f"[eval] θ_ae = {theta_ae:.6f}")

    det_df = evaluate(df, gat, ae, theta_ae, scaler)

    # Merge back group info
    if has_attack or has_pct:
        merge_cols = ["attack_number", "attack_percentage"]
        available  = [c for c in merge_cols if c in df.columns]
        meta = df.groupby("vehicle_id")[available].first().reset_index()
        det_df = det_df.merge(meta, on="vehicle_id", how="left")

    # Compute metrics per mode
    modes = {
        "B1_rule_based" : "b1_det",
        "B2_GAT_only"   : "b2_det",
        "B3_AE_only"    : "b3_det",
        "MPTD-PQS"      : "mptd_det",
    }

    rows = []
    for mode_name, det_col in modes.items():
        tp = ((det_df["is_poisoned"] == 1) & (det_df[det_col] == 1)).sum()
        fp = ((det_df["is_poisoned"] == 0) & (det_df[det_col] == 1)).sum()
        tn = ((det_df["is_poisoned"] == 0) & (det_df[det_col] == 0)).sum()
        fn = ((det_df["is_poisoned"] == 1) & (det_df[det_col] == 0)).sum()
        m  = compute_metrics(tp, fp, tn, fn)
        row = dict(mode=mode_name, TP=tp, FP=fp, TN=tn, FN=fn, **m)
        rows.append(row)
        print(f"  {mode_name:20s}  MCC={m['MCC']:.4f}  FPR={m['FPR']:.4f}"
              f"  PARR={m['PARR']:.4f}  CDER={m['CDER']:.4f}")

    out_df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    out_df.to_csv(OUT_CSV, index=False)
    print(f"[eval] Results saved → {OUT_CSV}")


if __name__ == "__main__":
    main()
