#!/usr/bin/env python3
"""
deploy_ae_resid.py — deploy the urban LSTM-AE retrained on DEAD-RECKONING RESIDUAL
features (AB4 fix).

Feature vector (6-dim, L=50; same tensor shape as before so the ONNX/C++ path is
unchanged — only the MEANING of the channels changes):

  0 res_x   = (pos_x[t]-pos_x[t-1]) - speed[t]*T_b*cos(heading[t])
  1 res_y   = (pos_y[t]-pos_y[t-1]) - speed[t]*T_b*sin(heading[t])
  2 dspeed  = speed[t]-speed[t-1]
  3 dheading= wrap(heading[t]-heading[t-1])
  4 accel
  5 tau_i   (=1.0)

Rationale: absolute position is normalised by ~545 m, so the 0.6-3.2 m TP-S1 stealth
drift is ~0.005 normalised — below the reconstruction noise floor (in-sim AUC 0.463).
TP-S1 modifies POSITION ONLY, leaving reported speed/heading honest, so the residual
isolates the injected increment. Held-out (disjoint vehicles): eMCC 0.546 vs 0.160
and FPR 0.003 vs 0.852 against the absolute-position baseline.

Trains on ALL-HONEST windows only, built on the CONTIGUOUS per-(run,vehicle) series
(never filter before differencing — TP-S1 vehicles alternate honest/poisoned).
Backs up the previous model/scaler/theta.

Usage: python3 deploy_ae_resid.py
"""
import os, sys, json, math, glob, shutil
import numpy as np, pandas as pd, torch

ROOT = os.path.dirname(os.path.abspath(__file__))
ML   = os.path.join(ROOT, "analytics", "ml")
NS3  = "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35"
sys.path.insert(0, ML)
from lstm_ae import LSTMAEDetector

SCEN, L, T_B, EPOCHS, KAPPA = "urban", 50, 0.1, 60, 1.645
DEV     = "cuda" if torch.cuda.is_available() else "cpu"
MODELS  = f"{ML}/models/{SCEN}"
NS3_MOD = f"{NS3}/analytics/ml/models/{SCEN}"
STAMP   = "bak_pre_resid"


def feats(g):
    px = g["pos_x"].values.astype(np.float64); py = g["pos_y"].values.astype(np.float64)
    sp = g["speed"].values.astype(np.float64); hd = g["heading"].values.astype(np.float64)
    ac = g["accel"].values.astype(np.float64); n = len(px)
    dx = np.zeros(n); dy = np.zeros(n)
    dx[1:] = np.diff(px); dy[1:] = np.diff(py)
    rx = dx - sp * T_B * np.cos(hd); ry = dy - sp * T_B * np.sin(hd)
    rx[0] = ry[0] = 0.0
    dsp = np.zeros(n); dsp[1:] = np.diff(sp)
    dhd = np.zeros(n); dhd[1:] = (np.diff(hd) + np.pi) % (2 * np.pi) - np.pi
    return np.hstack([np.stack([rx, ry, dsp, dhd, ac], 1),
                      np.ones((n, 1))]).astype(np.float32)


def windows(df):
    keys = ["run", "vehicle_id"] if "run" in df.columns else ["vehicle_id"]
    df = df.sort_values(keys + ["sim_time"])
    Xs, ys = [], []
    for _, g in df.groupby(keys):
        if len(g) < L: continue
        f = feats(g)
        poi = g["is_poisoned"].values.astype(int)
        Xs.append(np.stack([f[i:i+L] for i in range(len(f)-L+1)]))
        ys.append(np.array([poi[i:i+L].max() for i in range(len(f)-L+1)]))
    if not Xs: return np.zeros((0, L, 6), np.float32), np.zeros((0,), int)
    return np.concatenate(Xs).astype(np.float32), np.concatenate(ys)


# ── training data: fixed-binary runs (map bounds derived, no 2000-clamp) ──────
frames = []
for p in sorted(glob.glob(f"{NS3}/analytics/results/urban_pid*/beacon_log.csv"),
                key=os.path.getmtime, reverse=True)[:16]:
    try:
        d = pd.read_csv(p)
        if len(d) and (d.pos_x > 2000).any():
            d["run"] = os.path.basename(os.path.dirname(p)); frames.append(d)
    except Exception:
        pass
clean_csv = f"{ML}/data/beacon_clean_{SCEN}.csv"
if os.path.isfile(clean_csv):
    c = pd.read_csv(clean_csv)
    if (c.pos_x > 2000).any():          # only if it predates the clamp bug
        c["run"] = "clean_csv"; frames.append(c)
all_df = pd.concat(frames, ignore_index=True)
print(f"[deploy-resid] fixed-binary data: {len(all_df)} rows, {all_df.run.nunique()} runs, "
      f"{int(all_df.is_poisoned.sum())} poisoned")

X, y = windows(all_df)
Xc = X[y == 0]                                    # train on ALL-HONEST windows only
print(f"[deploy-resid] windows total={len(X)}  all-honest (training)={len(Xc)}")
flat = Xc.reshape(-1, 6)
mean = flat.mean(0); scale = flat.std(0); scale[scale < 1e-9] = 1.0
print(f"[deploy-resid] scaler mean={np.round(mean,5).tolist()}")
print(f"[deploy-resid] scaler scale={np.round(scale,5).tolist()}")
Xn = ((Xc - mean) / scale).astype(np.float32)

torch.manual_seed(42)
m = LSTMAEDetector(feat_dim=6).to(DEV)
opt = torch.optim.Adam(m.parameters(), lr=1e-3)
vi = int(len(Xn) * 0.8); Xt, Xv = torch.tensor(Xn[:vi]), torch.tensor(Xn[vi:])
for ep in range(EPOCHS):
    m.train(); perm = torch.randperm(len(Xt))
    for i in range(0, len(Xt), 128):
        b = Xt[perm[i:i+128]].to(DEV); opt.zero_grad()
        ((m(b) - b) ** 2).mean().backward(); opt.step()
m.eval()
with torch.no_grad():
    err = ((m(Xv.to(DEV)) - Xv.to(DEV)) ** 2).mean(dim=(1, 2)).cpu().numpy()
theta = float(err.mean() + KAPPA * err.std())
print(f"[deploy-resid] theta_ae = {theta:.6f}  (clean val err mean={err.mean():.5f} std={err.std():.5f})")

# quick separation sanity on poisoned windows
Xp = ((X[y == 1] - mean) / scale).astype(np.float32)
if len(Xp):
    with torch.no_grad():
        ep_ = ((m(torch.tensor(Xp).to(DEV)) - torch.tensor(Xp).to(DEV)) ** 2).mean(dim=(1, 2)).cpu().numpy()
    print(f"[deploy-resid] poisoned err mean={ep_.mean():.5f}  >theta rate={np.mean(ep_>theta):.3f} "
          f"| honest >theta rate={np.mean(err>theta):.3f}")

# ── export to BOTH model dirs (repo + ns-3 tree) ─────────────────────────────
for MD in (MODELS, NS3_MOD):
    if not os.path.isdir(MD): continue
    for fn in ("lstm_ae_model.onnx", "theta_ae.txt", "scaler.json"):
        src = os.path.join(MD, fn)
        if os.path.isfile(src) and not os.path.isfile(f"{src}.{STAMP}"):
            shutil.copy(src, f"{src}.{STAMP}")
    dummy = torch.randn(1, L, 6, dtype=torch.float32).to(DEV)
    torch.onnx.export(m, dummy, os.path.join(MD, "lstm_ae_model.onnx"),
                      input_names=["x"], output_names=["recon"],
                      dynamic_axes={"x": {0: "batch"}, "recon": {0: "batch"}},
                      opset_version=11)
    open(os.path.join(MD, "theta_ae.txt"), "w").write(f"{theta:.6f}\n")
    json.dump({"feature_names": ["res_x", "res_y", "dspeed", "dheading", "accel", "tau_i"],
               "mean": mean.tolist(), "scale": scale.tolist(),
               "_note": "AB4 fix: dead-reckoning RESIDUAL features (was absolute position). "
                        "res = dpos - v*T_b*(cos h, sin h). C++ lstm_ring_push must feed "
                        "these channels, not absolute pos."},
              open(os.path.join(MD, "scaler.json"), "w"), indent=1)
    print(f"[deploy-resid] wrote model+theta+scaler -> {MD}  (backups .{STAMP})")

import onnxruntime as ort
s = ort.InferenceSession(os.path.join(MODELS, "lstm_ae_model.onnx"))
print("[deploy-resid] onnx input shape:", s.get_inputs()[0].shape)
