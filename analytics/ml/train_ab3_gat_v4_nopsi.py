#!/usr/bin/env python3
"""
ISOLATED retrain experiment v4 for Critical Issue 3, attempt 3.

v3 matched the live RSU-windowed graph structure exactly and still failed
live: bv=0.000 for 100% of real evaluations. Traced why: psi/sig_mask (10 of
16 input dims) are consistently zero across the ENTIRE live run (sampled 55
windows spanning the full 30s, every one psi=0/sig=0 — not a warm-up effect).
This matches the codebase's own --sybil_gat_evasive documentation
(02_config_globals.h:313-324): Sybil ghosts are deliberately crafted to never
trip rule-signatures, so GAT's spatial score can be isolated and tested on
its own. But cls_heads was trained on data where sig_mask was nonzero for
17.1% of poisoned rows (a genuine, if sparse, signal in that CSV) — so it
learned to partially lean on a feature that structurally doesn't exist for
this attack type in practice, and defaults to near-zero confidence whenever
that crutch is absent (i.e. always, live).

v4 fix: zero psi_col + sig_bits during TRAINING too, forcing cls_heads to
learn purely from the 5 kinematic features + graph structure (exactly what
GAT's attention mechanism is meant to exploit for spatial-relational Sybil
detection, and exactly what's actually available live).

Output: models/urban_a3_retrain_test_v4/ — isolated, nothing deployed reads
this. Promotion is a separate, explicit, manual step.
"""
import os, sys, json
import numpy as np, pandas as pd, torch
import torch.nn as nn
ML = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, ML)
os.environ.setdefault("MPTD_GAT_EPOCHS", "150")
os.environ.setdefault("MPTD_GAT_LOSS_K_WEIGHT", "4.0")
from sklearn.preprocessing import StandardScaler
import train as T
from gat_detector import GATDetector, ATTACK_CLASSES

IPFS_WINDOW_L = 10
R_MAX_GRAPH = 300.0

STAGE = os.path.join(ML, "models", "urban_a3_retrain_test_v4")
os.makedirs(STAGE, exist_ok=True)

df = T.load_beacons()
npos = int((df["is_poisoned"] == 1).sum())
print(f"[ab3-v4] rows={len(df)} poisoned={npos}")

scj = json.load(open(os.path.join(ML, "models", "urban_a3", "gat_scaler.json")))
scaler = StandardScaler()
scaler.mean_ = np.array(scj["mean"], float)[:5]; scaler.scale_ = np.array(scj["scale"], float)[:5]
scaler.var_ = scaler.scale_ ** 2; scaler.n_features_in_ = 5
df, _ = T.normalise(df, scaler)

def build_rsu_window_dataset(df, zero_psi_sig=True):
    feat_cols = ["pos_x", "pos_y", "speed", "heading", "accel"]
    group_keys = ["run_id", "rsu_id"] if "run_id" in df.columns else ["rsu_id"]
    graphs = []
    for _key, grp in df.groupby(group_keys):
        grp = grp.sort_values("sim_time")
        n = len(grp)
        for start in range(0, n - n % IPFS_WINDOW_L, IPFS_WINDOW_L):
            w = grp.iloc[start:start + IPFS_WINDOW_L]
            if len(w) < 2:
                continue
            feats_5 = w[feat_cols].values.astype(np.float32)
            tau_col = np.ones((len(feats_5), 1), dtype=np.float32)
            if zero_psi_sig:
                psi_col = np.zeros((len(feats_5), 1), dtype=np.float32)
                sig_bits = np.zeros((len(feats_5), 9), dtype=np.float32)
            else:
                psi_col = (w["psi_score"].values.astype(np.float32).reshape(-1, 1)
                           if "psi_score" in w.columns else np.zeros((len(feats_5), 1), dtype=np.float32))
                if "sig_mask" in w.columns:
                    sm = w["sig_mask"].fillna(0).values.astype(np.uint32)
                    sig_bits = np.stack([((sm >> b) & 1).astype(np.float32) for b in range(9)], axis=1)
                else:
                    sig_bits = np.zeros((len(feats_5), 9), dtype=np.float32)
            x = np.concatenate([feats_5, tau_col, psi_col, sig_bits], axis=1)

            raw_pos = w[["pos_x", "pos_y", "speed", "heading"]].values.astype(np.float32)
            n_i = len(w)
            src, dst = [], []
            for i in range(n_i):
                px_i, py_i, sp_i, hd_i = raw_pos[i]
                vx_i, vy_i = sp_i * np.cos(hd_i), sp_i * np.sin(hd_i)
                for j in range(n_i):
                    if i == j: continue
                    px_j, py_j, sp_j, hd_j = raw_pos[j]
                    if np.hypot(px_i - px_j, py_i - py_j) > R_MAX_GRAPH: continue
                    vx_j, vy_j = sp_j * np.cos(hd_j), sp_j * np.sin(hd_j)
                    denom = (np.hypot(vx_i, vy_i) * np.hypot(vx_j, vy_j)) + 1e-9
                    cos_ang = (vx_i * vx_j + vy_i * vy_j) / denom
                    if cos_ang < 0: continue
                    src.append(i); dst.append(j)
            if not src:
                continue
            y = torch.tensor(w["is_poisoned"].values.astype(np.float32))
            ym = np.zeros((n_i, ATTACK_CLASSES), dtype=np.float32)
            if "attack_number" in w.columns:
                atk_num = w["attack_number"].fillna(0).values.astype(int)
                is_pois = w["is_poisoned"].values
                for r in range(n_i):
                    k = atk_num[r] - 1
                    if is_pois[r] == 1 and 0 <= k < ATTACK_CLASSES:
                        ym[r, k] = 1.0
            from torch_geometric.data import Data
            data = Data(x=torch.tensor(x, dtype=torch.float),
                        edge_index=torch.tensor([src, dst], dtype=torch.long), y=y)
            data.y_multi = torch.tensor(ym, dtype=torch.float)
            graphs.append(data)
    return graphs

print("[ab3-v4] building RSU-windowed graphs with psi/sig_mask ZEROED (train==live condition) …")
graphs = build_rsu_window_dataset(df, zero_psi_sig=True)
print(f"[ab3-v4] built {len(graphs)} graphs")
npos_graphs = sum(int(g.y_multi.sum().item() > 0) for g in graphs)
print(f"[ab3-v4] graphs containing >=1 poisoned node: {npos_graphs}/{len(graphs)}")

_orig_build = T.build_gat_dataset
T.build_gat_dataset = lambda _df: graphs
model = T.train_gat(df)
T.build_gat_dataset = _orig_build

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
n = 16; dx = torch.randn(n, 16); dei = torch.tensor([[i for i in range(n)], [i for i in range(n)]], dtype=torch.long)
torch.onnx.export(raw, (dx, dei), os.path.join(STAGE, "gat_model.onnx"),
    input_names=["x", "edge_index"], output_names=["scores", "attack_probs"],
    dynamic_axes={"x": {0: "N"}, "edge_index": {1: "E"}, "scores": {0: "N"}, "attack_probs": {0: "N"}},
    opset_version=16, dynamo=False)
print(f"[ab3-v4] exported to {STAGE} (isolated, not deployed)")

model.eval()
pS, cS, p_conf, c_conf = [], [], [], []
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
theta_s = float(np.percentile(cS, 95)) if len(cS) else 0.0
open(os.path.join(STAGE, "theta_s.txt"), "w").write(f"{theta_s:.6f}\n")
print("\n[ab3-v4] ===== S SEPARATION =====")
print(f"  clean  S: p50={np.percentile(cS,50):.2f} p95={theta_s:.2f}  (n={len(cS)})")
print(f"  poison S: p50={np.percentile(pS,50):.2f} mean={pS.mean():.2f}  (n={len(pS)})")
print("\n[ab3-v4] ===== CLASSIFICATION-HEAD CONFIDENCE (bv = max_k head, psi/sig ZEROED like live) =====")
print(f"  clean  bv: mean={c_conf.mean():.5f} p50={np.percentile(c_conf,50):.5f} p95={np.percentile(c_conf,95):.5f} max={c_conf.max():.5f}")
print(f"  poison bv: mean={p_conf.mean():.5f} p50={np.percentile(p_conf,50):.5f} p95={np.percentile(p_conf,95):.5f} max={p_conf.max():.5f}  (n={len(p_conf)})")
for th in [0.1, 0.3, 0.5, 0.8]:
    print(f"  poison bv >= {th}: {100.0*(p_conf>=th).mean():.1f}%   clean bv >= {th}: {100.0*(c_conf>=th).mean():.1f}%")
print("\n[ab3-v4] VERDICT: fixed if poison bv routinely clears theta_conf=0.8 with psi/sig zeroed, matching live reality.")
