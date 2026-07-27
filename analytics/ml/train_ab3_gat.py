#!/usr/bin/env python3
"""
Dedicated AB3 GAT: retrain the 16-feature GATDetector on the Option-A (attack-3)
trajectory-poisoning data so the encoder LEARNS the systematic lateral offset the
generic urban/ model is blind to. Output goes to models/urban_a3_trained/ (staging)
— NOTHING global is touched. Uses urban/'s scaler so the shared AE stays valid.
Reports poison-vs-clean S separation; deploy only if it separates.
"""
import os, sys, json
import numpy as np, torch
ML = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, ML)
os.environ.setdefault("MPTD_GAT_EPOCHS", "50")
from sklearn.preprocessing import StandardScaler
import train as T
from gat_detector import GATDetector

STAGE = os.path.join(ML, "models", "urban_a3_trained")
os.makedirs(STAGE, exist_ok=True)

# 1) load Option-A data (clean + poisoned, labelled by is_poisoned)
df = T.load_beacons()
npos = int((df["is_poisoned"] == 1).sum()) if "is_poisoned" in df.columns else -1
print(f"[ab3-gat] rows={len(df)} poisoned={npos}")

# 2) reuse urban/'s scaler (keep kinematic scaling identical → shared AE unaffected)
scj = json.load(open(os.path.join(ML, "models", "urban", "scaler.json")))
scaler = StandardScaler()
# normalise() scales only the 5 kinematic cols; urban scaler.json carries 6 (incl tau,
# which is identity mean=1/scale=1) — take the first 5 to match feat_cols.
scaler.mean_ = np.array(scj["mean"], float)[:5]; scaler.scale_ = np.array(scj["scale"], float)[:5]
scaler.var_ = scaler.scale_ ** 2; scaler.n_features_in_ = 5
df, _ = T.normalise(df, scaler)

# 3) train the dedicated GAT
model = T.train_gat(df)

# 4) export ONNX. CRITICAL: the deployed urban/ model outputs the RAW L2-norm s_i
# (range ~40-1600), NOT the sigmoid score in [0,1]. The sim's theta_s and fusion
# min(S/theta_s,1) assume that raw scale. train.export_gat_onnx exports the sigmoid
# head — wrong for deployment. Export a wrapper whose 'scores' output = raw s_i
# (per-snapshot z-norm, identical to the training separation computation).
import torch.nn as nn
torch.save(model.state_dict(), os.path.join(STAGE, "gat_model.pt"))
class GATRawS(nn.Module):
    def __init__(self, base):
        super().__init__()
        self.conv1, self.conv2, self.act, self.cls_heads = base.conv1, base.conv2, base.act, base.cls_heads
    def forward(self, x, edge_index):
        e = self.act(self.conv1(x, edge_index)); e = self.act(self.conv2(e, edge_index))
        mu = e.mean(0, keepdim=True); sig = e.std(0, keepdim=True) + 1e-6
        s_i = ((e - mu) / sig).norm(dim=1, keepdim=True)      # RAW s_i (matches urban/)
        atk = torch.sigmoid(self.cls_heads(e))
        return s_i, atk
raw = GATRawS(model.cpu()).eval()
n = 16; dx = torch.randn(n, 16); dei = torch.tensor([[i for i in range(n)],[i for i in range(n)]], dtype=torch.long)
torch.onnx.export(raw, (dx, dei), os.path.join(STAGE, "gat_model.onnx"),
    input_names=["x","edge_index"], output_names=["scores","attack_probs"],
    dynamic_axes={"x":{0:"N"},"edge_index":{1:"E"},"scores":{0:"N"},"attack_probs":{0:"N"}},
    opset_version=16, dynamo=False)
print("[ab3-gat] exported RAW-s_i onnx (scores = raw L2-norm, matches urban/ interface)")

# 5) raw per-snapshot S_i (matches the sim's 'scores' output) → separation + theta_s
model.eval()
graphs = T.build_gat_dataset(df)
pS, cS = [], []
with torch.no_grad():
    for g in graphs:
        emb = model.act(model.conv1(g.x, g.edge_index))
        emb = model.act(model.conv2(emb, g.edge_index))
        mu = emb.mean(0, keepdim=True); sig = emb.std(0, keepdim=True) + 1e-6
        s = ((emb - mu) / sig).norm(dim=1).numpy()
        y = g.y.numpy().ravel()
        pS += list(s[y == 1]); cS += list(s[y == 0])
pS, cS = np.array(pS), np.array(cS)
theta_s = float(np.percentile(cS, 95))
open(os.path.join(STAGE, "theta_s.txt"), "w").write(f"{theta_s:.6f}\n")
print("\n[ab3-gat] ===== SEPARATION (retrained) =====")
print(f"  clean  S: p50={np.percentile(cS,50):.2f} p95={theta_s:.2f} p99={np.percentile(cS,99):.2f}")
print(f"  poison S: p50={np.percentile(pS,50):.2f} p75={np.percentile(pS,75):.2f} "
      f"p90={np.percentile(pS,90):.2f} mean={pS.mean():.2f}  (n={len(pS)})")
above = 100.0 * (pS > theta_s).mean()
print(f"  poison beacons with S>theta_s: {above:.1f}%   (generic model was ~10%)")
print(f"  theta_s(95th clean) = {theta_s:.3f}  -> {STAGE}/theta_s.txt")
print("  VERDICT: retrain worked if poison p50 >> clean p95 (i.e. GAT now sees the 60m offset)")
