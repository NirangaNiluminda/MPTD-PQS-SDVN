#!/usr/bin/env python3
"""
ISOLATED retrain experiment for Critical Issue 3 (cls_heads collapse to ~0
confidence). Copy of train_ab3_gat.py with two changes:
  1. Output goes to models/urban_a3_retrain_test/ — a brand-new directory
     nothing in the sim or fusion_weights.json points at. The live
     models/urban_a3/ (symlinked to models/urban_a3_trained/) is never
     touched by this script, so nothing deployed changes just by running it.
  2. MPTD_GAT_LOSS_K_WEIGHT raises the classification-head loss weight
     (default 1.0 in train.py, unchanged for every other caller) to test
     whether the 0.71%-positive-rate class-imbalance collapse is fixable
     with more gradient signal on loss_k.
Promotion to models/urban_a3_trained/ (i.e. actually affecting the deployed
model) is a separate, manual, explicit step — not part of this script.
"""
import os, sys, json
import numpy as np, torch
ML = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, ML)
os.environ.setdefault("MPTD_GAT_EPOCHS", "150")
os.environ.setdefault("MPTD_GAT_LOSS_K_WEIGHT", "4.0")
from sklearn.preprocessing import StandardScaler
import train as T
from gat_detector import GATDetector

STAGE = os.path.join(ML, "models", "urban_a3_retrain_test")
os.makedirs(STAGE, exist_ok=True)

df = T.load_beacons()
npos = int((df["is_poisoned"] == 1).sum()) if "is_poisoned" in df.columns else -1
print(f"[ab3-gat-v2] rows={len(df)} poisoned={npos} loss_k_weight={os.environ['MPTD_GAT_LOSS_K_WEIGHT']} epochs={os.environ['MPTD_GAT_EPOCHS']}")

scj = json.load(open(os.path.join(ML, "models", "urban_a3", "gat_scaler.json")))
scaler = StandardScaler()
scaler.mean_ = np.array(scj["mean"], float)[:5]; scaler.scale_ = np.array(scj["scale"], float)[:5]
scaler.var_ = scaler.scale_ ** 2; scaler.n_features_in_ = 5
df, _ = T.normalise(df, scaler)

model = T.train_gat(df)

import torch.nn as nn
torch.save(model.state_dict(), os.path.join(STAGE, "gat_model.pt"))
class GATRawS(nn.Module):
    def __init__(self, base):
        super().__init__()
        self.conv1, self.conv2, self.act, self.cls_heads = base.conv1, base.conv2, base.act, base.cls_heads
    def forward(self, x, edge_index):
        e = self.act(self.conv1(x, edge_index)); e = self.act(self.conv2(e, edge_index))
        mu = e.mean(0, keepdim=True); sig = e.std(0, keepdim=True) + 1e-6
        s_i = ((e - mu) / sig).norm(dim=1, keepdim=True)
        atk = torch.sigmoid(self.cls_heads(e))
        return s_i, atk
raw = GATRawS(model.cpu()).eval()
n = 16; dx = torch.randn(n, 16); dei = torch.tensor([[i for i in range(n)],[i for i in range(n)]], dtype=torch.long)
torch.onnx.export(raw, (dx, dei), os.path.join(STAGE, "gat_model.onnx"),
    input_names=["x","edge_index"], output_names=["scores","attack_probs"],
    dynamic_axes={"x":{0:"N"},"edge_index":{1:"E"},"scores":{0:"N"},"attack_probs":{0:"N"}},
    opset_version=16, dynamo=False)
print(f"[ab3-gat-v2] exported to {STAGE} (isolated, not deployed)")

model.eval()
graphs = T.build_gat_dataset(df)
pS, cS = [], []
p_conf, c_conf = [], []
with torch.no_grad():
    for g in graphs:
        emb = model.act(model.conv1(g.x, g.edge_index))
        emb = model.act(model.conv2(emb, g.edge_index))
        mu = emb.mean(0, keepdim=True); sig = emb.std(0, keepdim=True) + 1e-6
        s = ((emb - mu) / sig).norm(dim=1).numpy()
        atk = torch.sigmoid(model.cls_heads(emb)).numpy()
        bv = atk.max(axis=1)
        y = g.y.numpy().ravel()
        pS += list(s[y == 1]); cS += list(s[y == 0])
        p_conf += list(bv[y == 1]); c_conf += list(bv[y == 0])
pS, cS = np.array(pS), np.array(cS)
p_conf, c_conf = np.array(p_conf), np.array(c_conf)
theta_s = float(np.percentile(cS, 95))
open(os.path.join(STAGE, "theta_s.txt"), "w").write(f"{theta_s:.6f}\n")
print("\n[ab3-gat-v2] ===== S SEPARATION =====")
print(f"  clean  S: p50={np.percentile(cS,50):.2f} p95={theta_s:.2f}")
print(f"  poison S: p50={np.percentile(pS,50):.2f} mean={pS.mean():.2f}  (n={len(pS)})")
print("\n[ab3-gat-v2] ===== CLASSIFICATION-HEAD CONFIDENCE (bv = max_k head) =====")
print(f"  clean  bv: mean={c_conf.mean():.5f} p50={np.percentile(c_conf,50):.5f} p95={np.percentile(c_conf,95):.5f} max={c_conf.max():.5f}")
print(f"  poison bv: mean={p_conf.mean():.5f} p50={np.percentile(p_conf,50):.5f} p95={np.percentile(p_conf,95):.5f} max={p_conf.max():.5f}  (n={len(p_conf)})")
for th in [0.1, 0.3, 0.5, 0.8]:
    print(f"  poison bv >= {th}: {100.0*(p_conf>=th).mean():.1f}%   clean bv >= {th}: {100.0*(c_conf>=th).mean():.1f}%")
print("\n[ab3-gat-v2] VERDICT: fixed if poison bv routinely clears theta_conf=0.8 while clean stays low.")
