"""
score.py  —  INFERENCE  (per-node Eq. 3.38)
==========================================
Loads the locked encoder (Phase 1a) + locked PER-NODE stats (Phase 1b) and scores
a beacon CSV. The spatial anomaly score uses each node's OWN locked statistics:

  S_i(t) = || (x'_i(t) - x̄'_i) / sigma'_i ||^2        (Eq. 3.38)

where x̄'_i and sigma'_i are this vehicle's mean/std from the clean calibration.
If a vehicle id was not seen during calibration, the locked GLOBAL fallback
(pooled clean mean/std) is used instead.

Scoring modes (compare honestly):
  --mode zscore        Eq. 3.38 per-node z-score, flag = 1[S_i > theta_S]
  --mode zscore_bestT  same S_i, threshold tuned on THIS file (analysis only)
  --mode head          trained head probability, flag = 1[sigmoid(logit) > 0.5]
  --mode all           all three (default)

Run:
  python score.py --scenario urban --attack_csv data/urban_attack.csv
"""
import argparse
import os
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import matthews_corrcoef, f1_score, confusion_matrix

from config import get_config
from dataset import load_graphs
from model import build_encoder

EPS = 1e-8


def load_assets(cfg, ckpt_dir):
    ckpt = torch.load(os.path.join(ckpt_dir, f"{cfg.name}_encoder.pt"),
                      map_location="cpu")
    if ckpt.get("cfg_name", cfg.name) != cfg.name:
        raise ValueError(f"Checkpoint is for '{ckpt['cfg_name']}' but you asked "
                         f"for '{cfg.name}'. Use the matching scenario.")
    enc = build_encoder(cfg, ckpt["in_dim"])     # scenario-specific architecture
    enc.load_state_dict(ckpt["encoder_state"])
    enc.eval()
    head = nn.Linear(cfg.emb_dim, 1)
    head.load_state_dict(ckpt["head_state"])
    head.eval()

    stats = np.load(os.path.join(ckpt_dir, f"{cfg.name}_stats.npz"),
                    allow_pickle=True)
    vids = [str(v) for v in stats["vids"].tolist()]
    id_to_row = {vid: r for r, vid in enumerate(vids)}
    locked = dict(
        id_to_row=id_to_row,
        mu_per_node=stats["mu_per_node"],
        sd_per_node=stats["sd_per_node"],
        mu_global=stats["mu_global"],
        sd_global=stats["sd_global"],
        theta_S=float(stats["theta_S"]),
    )
    return enc, head, locked


@torch.no_grad()
def forward_all(enc, head, graphs, locked):
    mu_node = locked["mu_per_node"]
    sd_node = locked["sd_per_node"]
    mu_g = locked["mu_global"]
    sd_g = locked["sd_global"]
    id_to_row = locked["id_to_row"]

    S_list, p_list, y_list = [], [], []
    n_seen, n_fallback = 0, 0
    for g in graphs:
        x_prime = enc(g.x, g.edge_index).cpu().numpy()        # (N, emb_dim)
        # per-node x̄'_i and sigma'_i looked up by THIS node's vehicle id
        mu_rows = np.empty_like(x_prime)
        sd_rows = np.empty_like(x_prime)
        for k, vid in enumerate(g.node_ids):
            r = id_to_row.get(vid)
            if r is None:                                     # unseen -> fallback
                mu_rows[k], sd_rows[k] = mu_g, sd_g
                n_fallback += 1
            else:
                mu_rows[k], sd_rows[k] = mu_node[r], sd_node[r]
                n_seen += 1
        z = (x_prime - mu_rows) / (sd_rows + EPS)
        S_list.append((z ** 2).sum(axis=1))                   # Eq. 3.38, per node
        logit = head(torch.tensor(x_prime, dtype=torch.float32)).squeeze(-1)
        p_list.append(torch.sigmoid(logit).numpy())
        y_list.append(g.y.numpy())

    return (np.concatenate(S_list), np.concatenate(p_list),
            np.concatenate(y_list), n_seen, n_fallback)


def metrics(y, flag):
    if len(np.unique(y)) < 2:
        return None
    mcc = matthews_corrcoef(y, flag)
    f1 = f1_score(y, flag, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, flag).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return dict(mcc=mcc, f1=f1, fpr=fpr, tp=tp, fp=fp, fn=fn, tn=tn)


def best_threshold(score, y):
    cand = np.quantile(score, np.linspace(0.01, 0.99, 99))
    best_t, best_mcc = cand[0], -2
    for t in cand:
        m = matthews_corrcoef(y, (score > t).astype(int))
        if m > best_mcc:
            best_mcc, best_t = m, t
    return best_t


def report(name, y, flag, extra=""):
    m = metrics(y, flag)
    if m is None:
        print(f"[{name}] no positive labels — skipped")
        return
    print(f"[{name}] MCC={m['mcc']:.3f}  F1={m['f1']:.3f}  FPR={m['fpr']:.3f}  "
          f"(TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}) {extra}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--attack_csv", required=True)
    ap.add_argument("--ckpt_dir", default="checkpoints")
    ap.add_argument("--out_dir", default="outputs")
    ap.add_argument("--mode", default="all",
                    choices=["zscore", "zscore_bestT", "head", "all"])
    args = ap.parse_args()

    cfg = get_config(args.scenario)
    enc, head, locked = load_assets(cfg, args.ckpt_dir)
    graphs = load_graphs(args.attack_csv, cfg)
    S, p, y, n_seen, n_fallback = forward_all(enc, head, graphs, locked)

    os.makedirs(args.out_dir, exist_ok=True)
    pd.DataFrame({"S_i": S, "head_prob": p, "label": y}).to_csv(
        os.path.join(args.out_dir, f"{cfg.name}_scores.csv"), index=False)

    theta_S = locked["theta_S"]
    total = n_seen + n_fallback
    print(f"Scored {len(S)} vehicle-nodes for '{cfg.name}'.  "
          f"locked theta_S={theta_S:.3f}")
    print(f"  per-node stats used for {n_seen}/{total} nodes "
          f"({100*n_seen/max(total,1):.1f}%); global fallback for {n_fallback}.")

    if args.mode in ("zscore", "all"):
        report("Eq.3.38 per-node z-score (locked theta_S)", y,
               (S > theta_S).astype(int))
    if args.mode in ("zscore_bestT", "all") and len(np.unique(y)) > 1:
        t = best_threshold(S, y)
        report("per-node z-score (tuned threshold)", y, (S > t).astype(int),
               extra=f"theta*={t:.2f}")
    if args.mode in ("head", "all"):
        report("Supervised head prob (>0.5)", y, (p > 0.5).astype(int))

    print(f"Per-node scores -> {os.path.join(args.out_dir, cfg.name+'_scores.csv')}")


if __name__ == "__main__":
    main()
