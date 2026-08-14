#!/usr/bin/env python3
"""Re-evaluate v4 on ONLY the held-out val split (never seen during training),
reproducing train.py's exact train_test_split(graphs, test_size=0.2,
random_state=42) call, to check whether the earlier 99.2% offline separation
was genuine generalization or memorization of the training set."""
import os, sys, json
import numpy as np, torch
ML = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, ML)
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import train as T
from gat_detector import GATDetector, ATTACK_CLASSES

IPFS_WINDOW_L = 10
R_MAX_GRAPH = 300.0
STAGE = os.path.join(ML, "models", "urban_a3_retrain_test_v4")

df = T.load_beacons()
scj = json.load(open(os.path.join(ML, "models", "urban_a3", "gat_scaler.json")))
scaler = StandardScaler()
scaler.mean_ = np.array(scj["mean"], float)[:5]; scaler.scale_ = np.array(scj["scale"], float)[:5]
scaler.var_ = scaler.scale_ ** 2; scaler.n_features_in_ = 5
df, _ = T.normalise(df, scaler)

def build_rsu_window_dataset(df):
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
            psi_col = np.zeros((len(feats_5), 1), dtype=np.float32)
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

print("[heldout] building RSU-windowed graphs …")
graphs = build_rsu_window_dataset(df)
print(f"[heldout] {len(graphs)} total graphs")

# Reproduce train.py's EXACT split
train_g, val_g = train_test_split(graphs, test_size=0.2, random_state=42)
print(f"[heldout] train_g={len(train_g)} val_g={len(val_g)}  (val_g is what the model NEVER saw during training)")

model = GATDetector()
model.load_state_dict(torch.load(os.path.join(STAGE, "gat_model.pt"), map_location="cpu"))
model = model.cpu().eval()

def evaluate(graphs, label):
    pS, cS, p_conf, c_conf = [], [], [], []
    with torch.no_grad():
        for g in graphs:
            x = g.x.cpu(); ei = g.edge_index.cpu()
            emb = model.act(model.conv1(x, ei))
            emb = model.act(model.conv2(emb, ei))
            mu = emb.mean(0, keepdim=True); sig = emb.std(0, keepdim=True) + 1e-6
            s = ((emb - mu) / sig).norm(dim=1).numpy()
            atk = torch.sigmoid(model.cls_heads(emb)).numpy()
            bv = atk.max(axis=1)
            y = g.y.numpy().ravel()
            pS += list(s[y == 1]); cS += list(s[y == 0])
            p_conf += list(bv[y == 1]); c_conf += list(bv[y == 0])
    p_conf, c_conf = np.array(p_conf), np.array(c_conf)
    print(f"\n[heldout] ===== {label} (n_poison={len(p_conf)}, n_clean={len(c_conf)}) =====")
    if len(p_conf):
        print(f"  poison bv: mean={p_conf.mean():.5f} p50={np.percentile(p_conf,50):.5f} max={p_conf.max():.5f}")
        for th in [0.1, 0.3, 0.5, 0.8]:
            print(f"  poison bv >= {th}: {100.0*(p_conf>=th).mean():.1f}%   clean bv >= {th}: {100.0*(c_conf>=th).mean():.1f}%")
    else:
        print("  (no poisoned nodes in this split)")

evaluate(train_g, "TRAIN split (model has seen this)")
evaluate(val_g, "VAL split (model has NEVER seen this — true generalization test)")
