#!/usr/bin/env python3
"""Compare .pt (PyTorch, direct) vs .onnx (exported) output on the SAME real
malicious graph, to check whether the ONNX export itself is where confidence
collapses to zero (as opposed to a training/data problem)."""
import os, sys, json
import numpy as np, torch
ML = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, ML)
from sklearn.preprocessing import StandardScaler
import train as T
from gat_detector import GATDetector, ATTACK_CLASSES
import onnxruntime as ort

IPFS_WINDOW_L = 10
R_MAX_GRAPH = 300.0
STAGE = os.path.join(ML, "models", "urban_a3_retrain_test_v3")

df = T.load_beacons()
scj = json.load(open(os.path.join(ML, "models", "urban_a3", "gat_scaler.json")))
scaler = StandardScaler()
scaler.mean_ = np.array(scj["mean"], float)[:5]; scaler.scale_ = np.array(scj["scale"], float)[:5]
scaler.var_ = scaler.scale_ ** 2; scaler.n_features_in_ = 5
df, _ = T.normalise(df, scaler)

feat_cols = ["pos_x", "pos_y", "speed", "heading", "accel"]
group_keys = ["run_id", "rsu_id"] if "run_id" in df.columns else ["rsu_id"]
found = None
for _key, grp in df.groupby(group_keys):
    grp = grp.sort_values("sim_time")
    n = len(grp)
    for start in range(0, n - n % IPFS_WINDOW_L, IPFS_WINDOW_L):
        w = grp.iloc[start:start + IPFS_WINDOW_L]
        if len(w) == IPFS_WINDOW_L and w["is_poisoned"].sum() > 0:
            found = w
            break
    if found is not None:
        break

w = found
print("[cmp] found a real malicious 10-beacon window, poisoned rows:", int(w["is_poisoned"].sum()))
feats_5 = w[feat_cols].values.astype(np.float32)
tau_col = np.ones((len(feats_5), 1), dtype=np.float32)
psi_col = (w["psi_score"].values.astype(np.float32).reshape(-1, 1)
           if "psi_score" in w.columns else np.zeros((len(feats_5), 1), dtype=np.float32))
if "sig_mask" in w.columns:
    sm = w["sig_mask"].fillna(0).values.astype(np.uint32)
    sig_bits = np.stack([((sm >> b) & 1).astype(np.float32) for b in range(9)], axis=1)
else:
    sig_bits = np.zeros((len(feats_5), 9), dtype=np.float32)
x_np = np.concatenate([feats_5, tau_col, psi_col, sig_bits], axis=1)
print("[cmp] psi_score present:", "psi_score" in w.columns, " sig_mask present:", "sig_mask" in w.columns)
print("[cmp] x sample row0:", x_np[0])

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
print("[cmp] edges:", len(src))

x_t = torch.tensor(x_np, dtype=torch.float)
ei_t = torch.tensor([src, dst], dtype=torch.long)

model = GATDetector()
model.load_state_dict(torch.load(os.path.join(STAGE, "gat_model.pt"), map_location="cpu"))
model = model.cpu().eval()
with torch.no_grad():
    emb = model.act(model.conv1(x_t, ei_t))
    emb = model.act(model.conv2(emb, ei_t))
    atk_pt = torch.sigmoid(model.cls_heads(emb)).numpy()
print("\n[cmp] PyTorch .pt attack_probs (per node, max):")
print(atk_pt.max(axis=1))

sess = ort.InferenceSession(os.path.join(STAGE, "gat_model.onnx"))
out = sess.run(None, {"x": x_np, "edge_index": np.array([src, dst], dtype=np.int64)})
names = [o.name for o in sess.get_outputs()]
d = dict(zip(names, out))
print("\n[cmp] ONNX attack_probs (per node, max):")
print(d["attack_probs"].max(axis=1))
print("\n[cmp] ONNX scores (S):", d["scores"].ravel())
print("[cmp] is_poisoned per row:", w["is_poisoned"].values)

print("\n[cmp] === same window, psi_score + sig_mask ZEROED (simulating early-in-run live query) ===")
x_np_zeroed = x_np.copy()
x_np_zeroed[:, 6:16] = 0.0   # zero psi (col6) + 9 sig_mask bits (col7-15)
out2 = sess.run(None, {"x": x_np_zeroed, "edge_index": np.array([src, dst], dtype=np.int64)})
d2 = dict(zip(names, out2))
print("[cmp] ONNX attack_probs (psi/sig zeroed):", d2["attack_probs"].max(axis=1))
