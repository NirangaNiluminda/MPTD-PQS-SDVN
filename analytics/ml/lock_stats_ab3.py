#!/usr/bin/env python3
"""AB3 locked-stats GAT: take the retrained Option-A encoder and export an ONNX
whose S = ||(emb - mu_clean_LOCKED)/sig_clean_LOCKED||  — GLOBAL clean stats baked
in as buffers, NOT per-snapshot. This makes S graph-composition-independent, so the
training separation transfers to the sim's per-RSU graphs. Fixes the transfer failure.
Outputs to models/urban_a3_trained/ (gat_model.onnx + theta_s.txt)."""
import os, sys, json, numpy as np, torch, torch.nn as nn
ML = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, ML)
from sklearn.preprocessing import StandardScaler
import train as T
from gat_detector import GATDetector

STAGE = os.path.join(ML, "models", "urban_a3_trained")
PT    = os.path.join(STAGE, "gat_model.pt")

# 1) load retrained encoder
model = GATDetector(); model.load_state_dict(torch.load(PT, map_location="cpu")); model.eval()

# 2) same data prep as train_ab3_gat.py (urban scaler, 5 kinematic cols)
df = T.load_beacons()
scj = json.load(open(os.path.join(ML, "models", "urban", "scaler.json")))
sc = StandardScaler(); sc.mean_ = np.array(scj["mean"], float)[:5]
sc.scale_ = np.array(scj["scale"], float)[:5]; sc.var_ = sc.scale_**2; sc.n_features_in_ = 5
df, _ = T.normalise(df, sc)
graphs = T.build_gat_dataset(df)
print(f"[lock] {len(graphs)} snapshot graphs")

def embed(m, x, ei):
    e = m.act(m.conv1(x, ei)); return m.act(m.conv2(e, ei))       # (N,16)

# 3) LOCKED global clean stats over ALL clean embeddings
clean, poison = [], []
with torch.no_grad():
    for g in graphs:
        e = embed(model, g.x, g.edge_index); y = g.y.numpy().ravel()
        clean.append(e[g.y == 0]); poison.append(e[g.y == 1])
clean = torch.cat(clean, 0); poison = torch.cat([p for p in poison if len(p)], 0)
mu = clean.mean(0); sig = clean.std(0) + 1e-6
print(f"[lock] clean embed rows={clean.shape[0]} poison rows={poison.shape[0]}")

# 4) locked-stats S (this is what the sim will compute per beacon)
sc_clean  = ((clean  - mu) / sig).norm(dim=1).numpy()
sc_poison = ((poison - mu) / sig).norm(dim=1).numpy()
theta_s = float(np.percentile(sc_clean, 95))
print("\n[lock] ===== LOCKED-STATS SEPARATION =====")
print(f"  clean  S: p50={np.percentile(sc_clean,50):.2f} p95={theta_s:.2f} p99={np.percentile(sc_clean,99):.2f}")
print(f"  poison S: p50={np.percentile(sc_poison,50):.2f} p90={np.percentile(sc_poison,90):.2f} mean={sc_poison.mean():.2f}")
print(f"  poison>theta_s: {100.0*(sc_poison>theta_s).mean():.1f}%   theta_s={theta_s:.3f}")

# 5) wrapper with LOCKED buffers → export (scores + attack_probs, matches sim interface)
class GATLockedS(nn.Module):
    def __init__(self, base, mu, sig):
        super().__init__()
        self.conv1, self.conv2, self.act, self.cls_heads = base.conv1, base.conv2, base.act, base.cls_heads
        self.register_buffer("mu",  mu.view(1, -1)); self.register_buffer("sig", sig.view(1, -1))
    def forward(self, x, edge_index):
        e = self.act(self.conv1(x, edge_index)); e = self.act(self.conv2(e, edge_index))
        s = ((e - self.mu) / self.sig).norm(dim=1, keepdim=True)     # LOCKED raw S
        return s, torch.sigmoid(self.cls_heads(e))
w = GATLockedS(model, mu, sig).eval()
n = 16; dx = torch.randn(n, 16); dei = torch.tensor([[i for i in range(n)],[i for i in range(n)]], dtype=torch.long)
torch.onnx.export(w, (dx, dei), os.path.join(STAGE, "gat_model.onnx"),
    input_names=["x","edge_index"], output_names=["scores","attack_probs"],
    dynamic_axes={"x":{0:"N"},"edge_index":{1:"E"},"scores":{0:"N"},"attack_probs":{0:"N"}},
    opset_version=16, dynamo=False)
open(os.path.join(STAGE, "theta_s.txt"), "w").write(f"{theta_s:.6f}\n")
print(f"\n[lock] exported LOCKED-stats onnx + theta_s={theta_s:.3f} -> {STAGE}")
print("  VERDICT: transfers if poison p50 > clean p95 (same as training) AND onnx S scale is raw")
