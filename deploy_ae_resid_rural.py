#!/usr/bin/env python3
"""
deploy_ae_resid_rural.py — deploy the RURAL LSTM-AE retrained on DEAD-RECKONING
RESIDUAL features (AB4 fix, ported to rural 2026-07-31).

Adapted from deploy_ae_resid.py (SCEN="urban") -- see that file for the full
rationale on why residual features matter (TP-S1 stealth drift is invisible
in absolute-position units). Rural's deployed scaler.json/lstm_ae_model.onnx
were still on the OLD absolute-position scheme (dated 2026-07-05, predating
the AB4 fix), which corrupted MCC_full on the first rural R3 run -- this
script brings rural into parity with urban's already-fixed pipeline.

Reads from analytics/ml/data/rural_training_runs/ (archived copies of 6 rural
beacon logs, 2 seed=1 smoke-test runs + 4 fresh seed=2..5 runs, 30s each,
skip_blockchain=true, --mobility_scenario=1 --N_RSUs=169 --N_Vehicles=200),
NOT analytics/results/rural_pid*/ directly -- those are transient scratch
dirs that could get cleaned up; the archive is the permanent copy.

Exports to models/rural/* (both repo + ns-3 tree, urban untouched -- entirely
separate scenario directory) AND additionally to lstm_detector/checkpoints/
(*_rural.*) so train_fusion.py's per-scenario SLSQP refit can use the same
updated model (bridges the ONNX-only vs .pt-checkpoint format gap between
the two pipelines).

Usage: python3 deploy_ae_resid_rural.py
"""
import os, sys, json, math, glob, shutil
import numpy as np, pandas as pd, torch

ROOT = os.path.dirname(os.path.abspath(__file__))
ML   = os.path.join(ROOT, "analytics", "ml")
NS3  = "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35"
sys.path.insert(0, ML)
from lstm_ae import LSTMAEDetector

SCEN, L, T_B, EPOCHS, KAPPA = "rural", 50, 0.1, 60, 1.645
DEV     = "cuda" if torch.cuda.is_available() else "cpu"
MODELS  = f"{ML}/models/{SCEN}"
NS3_MOD = f"{NS3}/analytics/ml/models/{SCEN}"
CKPT_DIR = os.path.join(ROOT, "lstm_detector", "checkpoints")
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


# ── training data: archived rural runs (permanent copy) ──────────────────────
frames = []
for p in sorted(glob.glob(f"{ML}/data/rural_training_runs/beacon_log_*.csv")):
    try:
        d = pd.read_csv(p)
        if len(d):
            d["run"] = os.path.basename(p); frames.append(d)
    except Exception:
        pass
clean_csv = f"{ML}/data/beacon_clean_{SCEN}.csv"
if os.path.isfile(clean_csv):
    c = pd.read_csv(clean_csv)
    c["run"] = "clean_csv"; frames.append(c)
all_df = pd.concat(frames, ignore_index=True)
print(f"[deploy-resid-rural] training data: {len(all_df)} rows, {all_df.run.nunique()} runs, "
      f"{int(all_df.is_poisoned.sum())} poisoned, {all_df.vehicle_id.nunique()} distinct vehicle ids")

X, y = windows(all_df)
Xc = X[y == 0]                                    # train on ALL-HONEST windows only
print(f"[deploy-resid-rural] windows total={len(X)}  all-honest (training)={len(Xc)}")
if len(Xc) < 50:
    sys.exit(f"[deploy-resid-rural] ABORT: only {len(Xc)} honest windows -- too few to train "
             f"(need more honest vehicle-seconds; generate more seeds and re-run)")
flat = Xc.reshape(-1, 6)
mean = flat.mean(0); scale = flat.std(0); scale[scale < 1e-9] = 1.0
print(f"[deploy-resid-rural] scaler mean={np.round(mean,5).tolist()}")
print(f"[deploy-resid-rural] scaler scale={np.round(scale,5).tolist()}")
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
print(f"[deploy-resid-rural] theta_ae = {theta:.6f}  (clean val err mean={err.mean():.5f} std={err.std():.5f})")

Xp = ((X[y == 1] - mean) / scale).astype(np.float32)
if len(Xp):
    with torch.no_grad():
        ep_ = ((m(torch.tensor(Xp).to(DEV)) - torch.tensor(Xp).to(DEV)) ** 2).mean(dim=(1, 2)).cpu().numpy()
    print(f"[deploy-resid-rural] poisoned err mean={ep_.mean():.5f}  >theta rate={np.mean(ep_>theta):.3f} "
          f"| honest >theta rate={np.mean(err>theta):.3f}")

scaler_json = {"feature_names": ["res_x", "res_y", "dspeed", "dheading", "accel", "tau_i"],
               "mean": mean.tolist(), "scale": scale.tolist(),
               "_note": "AB4 fix ported to rural 2026-07-31: dead-reckoning RESIDUAL features "
                        "(was absolute position). res = dpos - v*T_b*(cos h, sin h)."}

# ── export ONNX to both model dirs (repo + ns-3 tree) — C++ deployment path ──
for MD in (MODELS, NS3_MOD):
    if not os.path.isdir(MD):
        os.makedirs(MD, exist_ok=True)
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
    json.dump(scaler_json, open(os.path.join(MD, "scaler.json"), "w"), indent=1)
    print(f"[deploy-resid-rural] wrote model+theta+scaler -> {MD}  (backups .{STAMP})")

# ── export .pt checkpoint + matching scaler/theta -- train_fusion.py path ────
for fn in ("lstm_ae_rural.pt", "scaler_rural.json", "theta_ae_rural.txt"):
    src = os.path.join(CKPT_DIR, fn)
    if os.path.isfile(src) and not os.path.isfile(f"{src}.{STAMP}"):
        shutil.copy(src, f"{src}.{STAMP}")
torch.save(m.state_dict(), os.path.join(CKPT_DIR, "lstm_ae_rural.pt"))
json.dump(scaler_json, open(os.path.join(CKPT_DIR, "scaler_rural.json"), "w"), indent=1)
open(os.path.join(CKPT_DIR, "theta_ae_rural.txt"), "w").write(f"{theta:.6f}\n")
print(f"[deploy-resid-rural] wrote .pt checkpoint + scaler + theta -> {CKPT_DIR} "
      f"(backups .{STAMP}) -- bridges the format gap for train_fusion.py")

import onnxruntime as ort
s = ort.InferenceSession(os.path.join(MODELS, "lstm_ae_model.onnx"))
print("[deploy-resid-rural] onnx input shape:", s.get_inputs()[0].shape)
