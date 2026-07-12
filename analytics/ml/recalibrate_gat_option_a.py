#!/usr/bin/env python3
"""
Option A (paper Eq 3.39/3.46) — re-derive the GAT spatial detector so it emits
the RAW spatial anomaly score S_i = ||(x'_i - x̄'_clean)/σ'_clean||₂ using
CLEAN-LOCKED Phase-1b statistics (not per-snapshot), and calibrate θ_S.

Steps 1-3 (offline, no C++ rebuild):
  1. Load the trained GAT (gat_model.pt), run its conv layers on CLEAN beacons
     to get embeddings, compute locked x̄'_clean, σ'_clean (16-dim) and
     θ_S = high percentile of the resulting S_i on clean data.
  2. Build a GATDetectorSI variant: same conv weights, locked clean stats as
     buffers, forward returns RAW s_i (drops the learnable affine + sigmoid).
  3. Export to a SEPARATE onnx (gat_model_sI.onnx) — does NOT overwrite the
     deployed gat_model.onnx (a running sim would otherwise load a mismatched
     model). Save θ_S to theta_s.txt. The C++ swap is step 4 (after rebuild).

Run:  cd analytics/ml && ../../gat_detector/.venv/bin/python recalibrate_gat_option_a.py
"""
import os, sys, glob, json
import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

ML  = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ML)
from gat_detector import GATDetector, snapshot_to_graph          # noqa: E402
from train import load_beacons, build_gat_dataset, normalise     # noqa: E402

THETA_S_PCTL = 95.0   # "high percentile of S_i on clean data" (paper §GAT)
OUT_ONNX  = os.path.join(ML, "models", "shared", "gat_model_sI.onnx")
OUT_THETA = os.path.join(ML, "models", "shared", "theta_s.txt")
PT        = os.path.join(ML, "models", "gat_model.pt")

def load_scaler():
    """Reuse the exact training scaler so embeddings match the trained model."""
    for p in [os.path.join(ML,"models","scaler.json"),
              os.path.join(ML,"models","shared","scaler.json"),
              os.path.join(ML,"models","urban","scaler.json")]:
        if os.path.isfile(p):
            j = json.load(open(p)); sc = StandardScaler()
            sc.mean_  = np.array(j["mean"],  dtype=np.float64)
            sc.scale_ = np.array(j["scale"], dtype=np.float64)
            sc.var_   = sc.scale_**2; sc.n_features_in_ = len(sc.mean_)
            print(f"[optA] loaded training scaler: {p}")
            return sc
    print("[optA] WARNING: no scaler.json found — fitting fresh (embeddings may differ from deployed)")
    return None

# ── 1. clean embeddings ─────────────────────────────────────────────────────
df = load_beacons()
scaler = load_scaler()
df, scaler = normalise(df, scaler)
graphs = build_gat_dataset(df)
print(f"[optA] {len(graphs)} snapshot graphs")

model = GATDetector()
model.load_state_dict(torch.load(PT, map_location="cpu"))
model.eval()

def embed(m, x, ei):
    e = m.act(m.conv1(x, ei)); e = m.act(m.conv2(e, ei)); return e   # (N,16)

clean_embs = []
with torch.no_grad():
    for g in graphs:
        e = embed(model, g.x, g.edge_index)          # (N,16)
        clean_embs.append(e[g.y == 0])               # keep CLEAN nodes only
clean = torch.cat(clean_embs, 0)                     # (Nclean,16)
print(f"[optA] clean embedding rows: {clean.shape[0]}")

mu_clean  = clean.mean(0)                             # (16,) locked Phase-1b mean
sig_clean = clean.std(0) + 1e-6                       # (16,) locked std
s_clean   = ((clean - mu_clean) / sig_clean).norm(dim=1)   # S_i on clean data
theta_s   = float(np.percentile(s_clean.numpy(), THETA_S_PCTL))
print(f"[optA] S_i clean: mean={s_clean.mean():.3f} p50={np.percentile(s_clean,50):.3f} "
      f"p95={theta_s:.3f} max={s_clean.max():.3f}")

# ── 2. GATDetectorSI: locked stats, raw S_i output (no affine/sigmoid) ───────
class GATDetectorSI(nn.Module):
    def __init__(self, base, mu, sig):
        super().__init__()
        self.conv1, self.conv2, self.act = base.conv1, base.conv2, base.act
        self.register_buffer("mu_clean",  mu.view(1, -1))
        self.register_buffer("sig_clean", sig.view(1, -1))
    def forward(self, x, edge_index):
        e = self.act(self.conv1(x, edge_index))
        e = self.act(self.conv2(e, edge_index))          # (N,16) = x'_i
        z = (e - self.mu_clean) / self.sig_clean         # locked clean z-score
        return z.norm(dim=1, keepdim=True)               # (N,1) RAW S_i (Eq 3.39)

si_model = GATDetectorSI(model, mu_clean, sig_clean).eval()

# sanity: raw S_i on a clean graph should mostly fall below θ_S
with torch.no_grad():
    g = graphs[0]; out = si_model(g.x, g.edge_index).squeeze(-1)
print(f"[optA] sanity S_i (graph0): {out.numpy().round(3)[:6]} ...  (θ_S={theta_s:.3f})")

# ── 3. export to SEPARATE onnx + save θ_S ───────────────────────────────────
n = 16
dummy_x  = torch.randn(n, 6)
dummy_ei = torch.tensor([[i for i in range(n)], [i for i in range(n)]], dtype=torch.long)
torch.onnx.export(si_model, (dummy_x, dummy_ei), OUT_ONNX,
    input_names=["x","edge_index"], output_names=["scores"],
    dynamic_axes={"x":{0:"N"}, "edge_index":{1:"E"}, "scores":{0:"N"}},
    opset_version=16, dynamo=False)
open(OUT_THETA, "w").write(f"{theta_s:.6f}\n")
print(f"[optA] exported RAW-S_i model  -> {OUT_ONNX}")
print(f"[optA] θ_S ({THETA_S_PCTL:.0f}th pctl) = {theta_s:.6f}  -> {OUT_THETA}")
print("[optA] DONE (steps 1-3). C++ swap + rebuild = step 4-5 after s_max sweep.")
