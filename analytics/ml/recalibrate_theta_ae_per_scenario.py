#!/usr/bin/env python3
"""
Per-scenario LSTM-AE threshold (θ_ae) recalibration — matches C++ inference
(06d_ai_inference.h::score_lstm_ae) EXACTLY:
  window = 10 beacons, 6 features [pos_x,pos_y,speed,heading,accel,tau=1.0],
  ALL 6 z-scored with models/<scen>/scaler.json, recon_mse = mean over 60 cells
  of (normed - recon)^2 in NORMALIZED space.

θ_ae = mean(clean recon_mse) + KAPPA·std  (train_lstm_ae.py convention, KAPPA=3.0).
Reports the full clean distribution so we can see if the deployed value is wrong
(rural currently 0.001248, ~200x smaller than urban/highway → degenerate).

Run (system python3 has onnxruntime): python3 recalibrate_theta_ae_per_scenario.py <urban|rural|highway|all> [--write]
"""
import os, sys, json
import numpy as np, pandas as pd
import onnxruntime as ort

ML = os.path.dirname(os.path.abspath(__file__))
L, D, KAPPA = 10, 6, 3.0
COLS = ["pos_x", "pos_y", "speed", "heading", "accel"]


def scaler6(scen):
    j = json.load(open(os.path.join(ML, "models", scen, "scaler.json")))
    return np.array(j["mean"], np.float32), np.array(j["scale"], np.float32)


def windows(df):
    """Sliding L-windows per (run_id, vehicle_id), 6-dim (5 kinematic + tau=1.0)."""
    keys = ["run_id", "vehicle_id"] if "run_id" in df.columns else ["vehicle_id"]
    out = []
    for _, vdf in df.groupby(keys):
        vdf = vdf.sort_values("sim_time")
        f5 = vdf[COLS].values.astype(np.float32)
        if len(f5) < L:
            continue
        tau = np.ones((len(f5), 1), np.float32)
        f6 = np.hstack([f5, tau])
        for i in range(len(f6) - L + 1):
            out.append(f6[i:i + L])
    return np.asarray(out, np.float32) if out else np.empty((0, L, D), np.float32)


def recon_mse(scen, wins):
    mean, scale = scaler6(scen)
    scale = np.where(scale == 0, 1.0, scale)
    normed = (wins - mean) / scale                      # (N,L,6) all 6 z-scored
    sess = ort.InferenceSession(os.path.join(ML, "models", scen, "lstm_ae_model.onnx"),
                                providers=["CPUExecutionProvider"])
    iname = sess.get_inputs()[0].name
    oname = sess.get_outputs()[0].name
    errs = []
    for i in range(0, len(normed), 256):
        b = normed[i:i + 256]
        r = sess.run([oname], {iname: b})[0]
        errs.extend(((b - r) ** 2).reshape(len(b), -1).mean(axis=1).tolist())
    return np.asarray(errs)


def run(scen, write):
    csv = os.path.join(ML, "data", f"beacon_clean_{scen}.csv")
    if not os.path.isfile(csv):
        print(f"[{scen}] SKIP no {csv}"); return
    wins = windows(pd.read_csv(csv))
    if len(wins) == 0:
        print(f"[{scen}] no windows"); return
    e = recon_mse(scen, wins)
    cur = open(os.path.join(ML, "models", scen, "theta_ae.txt")).read().strip()
    theta = float(e.mean() + KAPPA * e.std())
    p = lambda q: np.percentile(e, q)
    print(f"[{scen}] N_win={len(e)}  recon_mse: mean={e.mean():.5f} std={e.std():.5f} "
          f"p50={p(50):.5f} p95={p(95):.5f} p99={p(99):.5f} max={e.max():.5f}")
    print(f"[{scen}]   deployed θ_ae={cur}   proposed θ_ae(mean+3σ)={theta:.6f}   "
          f"(clean frac above deployed = {(e > float(cur)).mean()*100:.1f}%)")
    if write:
        open(os.path.join(ML, "models", scen, "theta_ae.txt"), "w").write(f"{theta:.6f}\n")
        print(f"[{scen}]   WROTE θ_ae={theta:.6f}")


if __name__ == "__main__":
    args = sys.argv[1:]
    write = "--write" in args
    args = [a for a in args if a != "--write"]
    which = args[0] if args else "all"
    scens = ["urban", "rural", "highway"] if which == "all" else [which]
    for s in scens:
        run(s, write)
