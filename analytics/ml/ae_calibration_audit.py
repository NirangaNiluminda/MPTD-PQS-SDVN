#!/usr/bin/env python3
"""
ae_calibration_audit.py — replays actual training-CSV clean windows through
the exported LSTM-AE ONNX to see if MSE matches the saved theta_ae.

If MSE_replayed >> theta_ae, the calibration is broken (model under-trained,
or theta_ae written before final epoch, etc.).
"""
import json
import os
import sys
import numpy as np
import pandas as pd
import onnxruntime as ort

ML_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(ML_DIR, "models")
DATA_DIR  = os.path.join(ML_DIR, "data")
CSV       = os.path.join(DATA_DIR, "beacon_train_master.csv")
ONNX_PATH = os.path.join(MODEL_DIR, "lstm_ae_model.onnx")
SCAL_JSON = os.path.join(MODEL_DIR, "scaler.json")
THETA_PTH = os.path.join(MODEL_DIR, "theta_ae.txt")

WINDOW   = 20
FEAT     = ["pos_x", "pos_y", "speed", "heading", "accel"]

def main() -> int:
    with open(SCAL_JSON) as f:
        s = json.load(f)
    mean  = np.asarray(s["mean"],  dtype=np.float32)
    scale = np.asarray(s["scale"], dtype=np.float32)
    safe  = np.where(scale == 0.0, 1.0, scale)

    with open(THETA_PTH) as f:
        theta = float(f.read().strip())

    df = pd.read_csv(CSV)
    sess = ort.InferenceSession(ONNX_PATH, providers=["CPUExecutionProvider"])

    print(f"theta_ae = {theta:.6f}")

    # Detect run boundaries (same logic as train.py load_beacons) so windows
    # never cross independent sweep runs concatenated into the master CSV.
    # |Δsim_time| > 2 s separates inter-run drops from intra-run jitter.
    if "run_id" not in df.columns:
        BOUNDARY_DROP = 2.0
        prev = df["sim_time"].shift(1)
        new_run = (prev.notna() & ((prev - df["sim_time"]) > BOUNDARY_DROP))
        df["run_id"] = new_run.cumsum().astype(int)
    n_runs = int(df["run_id"].nunique())
    print(f"runs in CSV : {n_runs}")

    # Build clean windows per (run_id, vehicle_id), normalize, run AE, report MSE
    clean_mses = []
    poisoned_mses = []
    n_pairs_used = 0
    for _key, grp in df.groupby(["run_id", "vehicle_id"]):
        grp = grp.sort_values("sim_time").reset_index(drop=True)
        if len(grp) < WINDOW:
            continue
        n_pairs_used += 1
        feats = grp[FEAT].values.astype(np.float32)
        feats_n = (feats - mean) / safe
        poi     = grp["is_poisoned"].values
        for i in range(0, len(grp) - WINDOW + 1, WINDOW):  # non-overlapping for speed
            win = feats_n[i:i+WINDOW][None, :, :].astype(np.float32)
            recon = sess.run(None, {"x": win})[0]
            mse = float(np.mean((recon - win) ** 2))
            window_poisoned = bool(poi[i:i+WINDOW].any())
            (poisoned_mses if window_poisoned else clean_mses).append(mse)

    clean_mses    = np.asarray(clean_mses)
    poisoned_mses = np.asarray(poisoned_mses)
    print(f"(run,vehicle) pairs used : {n_pairs_used}")
    print(f"Clean windows  : n={len(clean_mses)}   mean MSE={clean_mses.mean():.6f}   "
          f"median={np.median(clean_mses):.6f}   min={clean_mses.min():.6f}   "
          f"max={clean_mses.max():.6f}   p95={np.percentile(clean_mses, 95):.6f}")
    if len(poisoned_mses):
        print(f"Poison windows : n={len(poisoned_mses)} mean MSE={poisoned_mses.mean():.6f}   "
              f"median={np.median(poisoned_mses):.6f} min={poisoned_mses.min():.6f}   "
              f"max={poisoned_mses.max():.6f} p95={np.percentile(poisoned_mses, 95):.6f}")

    print()
    print(f"Ratio clean_median / theta_ae = {np.median(clean_mses)/theta:.2f}x")
    if len(poisoned_mses):
        print(f"Separation poisoned_median - clean_median = "
              f"{np.median(poisoned_mses) - np.median(clean_mses):+.6f}")
        # ROC quick check
        thresholds = np.linspace(0, max(clean_mses.max(), poisoned_mses.max()), 200)
        best_mcc = -1.0; best_th = 0.0
        for th in thresholds:
            TP = (poisoned_mses > th).sum()
            FN = (poisoned_mses <= th).sum()
            FP = (clean_mses    > th).sum()
            TN = (clean_mses    <= th).sum()
            denom = np.sqrt(float((TP+FP)*(TP+FN)*(TN+FP)*(TN+FN)))
            if denom < 1: continue
            mcc = (TP*TN - FP*FN) / denom
            if mcc > best_mcc:
                best_mcc = mcc; best_th = th
        print(f"Best MCC over swept theta = {best_mcc:.4f} at theta={best_th:.6f}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
