"""
score.py  —  INFERENCE
======================
Loads the locked encoder (Phase 1a) + locked stats (Phase 1b) and scores a
beacon CSV. Supports three scoring modes so you can compare them honestly:

  --mode zscore   Eq. 3.38 exactly as in the report / modeling update:
                    S_i = || (x'_i - mu) / sd ||^2 ,  flag = 1[S_i > theta_S]
                  theta_S is the locked clean-percentile threshold from Phase 1b.

  --mode zscore_bestT
                  Same S_i, but the decision threshold is chosen on THIS file
                  to maximise MCC (a fair operating point for the z-score path).
                  Use only for analysis; report it as "z-score, tuned threshold".

  --mode head     Uses the trained classification head probability
                    ŷ_i = sigmoid(w_cls^T x'_i + b_cls) ,  flag = 1[ŷ_i > 0.5]
                  This is the supervised detector the loss actually optimised.

  --mode all      Runs and reports all three (default).

S_i is the GAT's contribution to the fusion Φ_i (Eq. 3.43). Fusion weights
λ1,λ2,λ3 are learned later (Phase 2) with GAT + LSTM-AE frozen.

Run:
  python score.py --scenario urban --attack_csv data/urban_attack.csv
"""
import argparse
import os
import numpy as np
import pandas as pd
import torch
from sklearn.metrics import matthews_corrcoef, f1_score, confusion_matrix

from config import get_config
from dataset import load_graphs
from model import build_encoder
import torch.nn as nn

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
    stats = np.load(os.path.join(ckpt_dir, f"{cfg.name}_stats.npz"))
    return enc, head, stats["mu"], stats["sd"], float(stats["theta_S"])


@torch.no_grad()
def forward_all(enc, head, graphs, mu, sd):
    mu_t = torch.tensor(mu, dtype=torch.float32)
    sd_t = torch.tensor(sd, dtype=torch.float32)
    S_list, p_list, y_list = [], [], []
    for g in graphs:
        x_prime = enc(g.x, g.edge_index)
        z = (x_prime - mu_t) / (sd_t + EPS)
        S_list.append((z ** 2).sum(dim=1).numpy())          # Eq. 3.38
        p_list.append(torch.sigmoid(head(x_prime).squeeze(-1)).numpy())
        y_list.append(g.y.numpy())
    return (np.concatenate(S_list), np.concatenate(p_list),
            np.concatenate(y_list))


def metrics(y, flag):
    if len(np.unique(y)) < 2:
        return None
    mcc = matthews_corrcoef(y, flag)
    f1 = f1_score(y, flag, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, flag).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return dict(mcc=mcc, f1=f1, fpr=fpr, tp=tp, fp=fp, fn=fn, tn=tn)


def best_threshold(score, y):
    """Threshold on `score` that maximises MCC (scanned over score quantiles)."""
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
    enc, head, mu, sd, theta_S = load_assets(cfg, args.ckpt_dir)
    graphs = load_graphs(args.attack_csv, cfg)
    S, p, y = forward_all(enc, head, graphs, mu, sd)

    os.makedirs(args.out_dir, exist_ok=True)
    pd.DataFrame({"S_i": S, "head_prob": p, "label": y}).to_csv(
        os.path.join(args.out_dir, f"{cfg.name}_scores.csv"), index=False)

    print(f"Scored {len(S)} vehicle-nodes for '{cfg.name}'.  "
          f"locked theta_S={theta_S:.3f}")

    if args.mode in ("zscore", "all"):
        report("Eq.3.38 z-score (locked theta_S)", y, (S > theta_S).astype(int))
    if args.mode in ("zscore_bestT", "all") and len(np.unique(y)) > 1:
        t = best_threshold(S, y)
        report("z-score (tuned threshold)", y, (S > t).astype(int),
               extra=f"theta*={t:.2f}")
    if args.mode in ("head", "all"):
        report("Supervised head prob (>0.5)", y, (p > 0.5).astype(int))

    print(f"Per-node scores -> {os.path.join(args.out_dir, cfg.name+'_scores.csv')}")


if __name__ == "__main__":
    main()
