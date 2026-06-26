"""
calibrate.py  —  PHASE 1b  (GAT statistics calibration)
=======================================================
Loads the LOCKED encoder from Phase 1a, runs it forward on the CLEAN file
(no attacks), collects all clean embeddings x'_i, and computes:

  mu  = mean over clean embeddings          ( x̄'_i in Eq. 3.38 )
  sd  = std  over clean embeddings          ( σ'_i  in Eq. 3.38 )

then the clean spatial anomaly score distribution
  S_i = || (x'_i - mu) / sd ||^2            (Eq. 3.38)
and a default threshold theta_S = percentile(clean S_i, cfg.score_percentile).

These are LOCKED and never updated at inference (matches the corrected sentence
after Eq. gat_score in the modeling update).

Run:
  python calibrate.py --scenario urban --clean_csv data/urban_clean.csv
"""
import argparse
import os
import numpy as np
import torch

from config import get_config
from dataset import load_graphs
from model import build_encoder

EPS = 1e-8


def load_encoder(cfg, ckpt_path):
    ckpt = torch.load(ckpt_path, map_location="cpu")
    if ckpt.get("cfg_name", cfg.name) != cfg.name:
        raise ValueError(f"Checkpoint is for '{ckpt['cfg_name']}' but you asked "
                         f"for '{cfg.name}'. Use the matching scenario.")
    enc = build_encoder(cfg, ckpt["in_dim"])     # scenario-specific architecture
    enc.load_state_dict(ckpt["encoder_state"])
    enc.eval()
    return enc, ckpt["in_dim"]


@torch.no_grad()
def collect_embeddings(enc, graphs):
    embs = []
    for g in graphs:
        x_prime = enc(g.x, g.edge_index)
        embs.append(x_prime.cpu().numpy())
    return np.concatenate(embs, axis=0)   # (total_nodes, emb_dim)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--clean_csv", required=True)
    ap.add_argument("--ckpt_dir", default="checkpoints")
    args = ap.parse_args()

    cfg = get_config(args.scenario)
    enc_path = os.path.join(args.ckpt_dir, f"{cfg.name}_encoder.pt")
    enc, in_dim = load_encoder(cfg, enc_path)

    print(f"Loading CLEAN graphs for '{cfg.name}' ...")
    graphs = load_graphs(args.clean_csv, cfg)
    print(f"  {len(graphs)} clean timestep-graphs")

    emb = collect_embeddings(enc, graphs)
    mu = emb.mean(axis=0)
    sd = emb.std(axis=0)

    # clean S_i distribution (Eq. 3.38)
    z = (emb - mu) / (sd + EPS)
    S_clean = (z ** 2).sum(axis=1)
    theta_S = float(np.percentile(S_clean, cfg.score_percentile))

    stats_path = os.path.join(args.ckpt_dir, f"{cfg.name}_stats.npz")
    np.savez(stats_path, mu=mu, sd=sd, theta_S=theta_S,
             score_percentile=cfg.score_percentile,
             clean_S_mean=float(S_clean.mean()),
             clean_S_p99=float(np.percentile(S_clean, 99)))
    print(f"  clean S_i: mean={S_clean.mean():.3f}  "
          f"p{cfg.score_percentile:.0f}={theta_S:.3f}")
    print(f"Stats locked -> {stats_path}")
    print("Next: python score.py --scenario "
          f"{cfg.name} --attack_csv data/{cfg.name}_attack.csv")


if __name__ == "__main__":
    main()
