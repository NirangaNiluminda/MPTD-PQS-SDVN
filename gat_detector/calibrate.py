"""
calibrate.py  —  PHASE 1b  (GAT statistics calibration, PER-NODE)
================================================================
Loads the LOCKED encoder from Phase 1a (weights frozen, eval mode) and runs it
forward on the CLEAN file (no attacks). It then computes, EXACTLY as required:

  for each vehicle node v_i:
    collect every embedding x'_i this node produced across ALL clean timesteps
    x̄'_i = mean of that node's embeddings        ( per-node, Eq. 3.38 )
    sigma'_i = std of that node's embeddings      ( per-node, Eq. 3.38 )

Both x̄'_i and sigma'_i are stored PER NODE and LOCKED. They are never updated
again during evaluation. At inference (score.py) the spatial anomaly score
divides the node's current embedding deviation by its OWN sigma'_i and measures
distance from its OWN x̄'_i:

  S_i(t) = || (x'_i(t) - x̄'_i) / sigma'_i ||^2       (Eq. 3.38)

We also store a global fallback (pooled mean/std) for any vehicle id that appears
at inference but was not seen during clean calibration (e.g. pseudonym rotation,
different seeds), and a locked threshold theta_S = percentile of the clean
per-node S_i distribution.

Run:
  python calibrate.py --scenario urban --clean_csv data/urban_clean.csv
"""
import argparse
import os
from collections import defaultdict

import numpy as np
import torch

from config import get_config
from dataset import load_graphs
from model import build_encoder

EPS = 1e-8
SD_FLOOR = 1e-6     # floor on per-node std so a near-constant dim can't blow up S_i


def load_encoder(cfg, ckpt_path):
    ckpt = torch.load(ckpt_path, map_location="cpu")
    if ckpt.get("cfg_name", cfg.name) != cfg.name:
        raise ValueError(f"Checkpoint is for '{ckpt['cfg_name']}' but you asked "
                         f"for '{cfg.name}'. Use the matching scenario.")
    enc = build_encoder(cfg, ckpt["in_dim"])     # scenario-specific architecture
    enc.load_state_dict(ckpt["encoder_state"])
    enc.eval()                                   # FROZEN
    return enc, ckpt["in_dim"]


@torch.no_grad()
def collect_per_node_embeddings(enc, graphs):
    """Frozen forward pass over every clean timestep.

    Returns {vehicle_id -> list of embedding vectors across timesteps}.
    """
    per_node = defaultdict(list)
    for g in graphs:
        x_prime = enc(g.x, g.edge_index).cpu().numpy()   # (N, emb_dim)
        for node_idx, vid in enumerate(g.node_ids):
            per_node[vid].append(x_prime[node_idx])
    return per_node


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

    # ── frozen forward pass -> per-node embedding collections ──
    per_node = collect_per_node_embeddings(enc, graphs)

    # ── per-node mean x̄'_i and std sigma'_i across that node's clean timesteps ──
    vids = sorted(per_node.keys(), key=lambda s: (len(s), s))
    mu_rows, sd_rows, counts = [], [], []
    for vid in vids:
        stack = np.stack(per_node[vid], axis=0)          # (T_i, emb_dim)
        mu_rows.append(stack.mean(axis=0))
        # population std, floored so single/near-constant nodes are safe
        sd_rows.append(np.maximum(stack.std(axis=0), SD_FLOOR))
        counts.append(stack.shape[0])
    mu_per_node = np.stack(mu_rows, axis=0)              # (n_nodes, emb_dim)
    sd_per_node = np.stack(sd_rows, axis=0)              # (n_nodes, emb_dim)
    counts = np.asarray(counts, dtype=np.int64)

    # ── global fallback (pooled over ALL clean embeddings) for unseen ids ──
    all_emb = np.concatenate([np.stack(v) for v in per_node.values()], axis=0)
    mu_global = all_emb.mean(axis=0)
    sd_global = np.maximum(all_emb.std(axis=0), SD_FLOOR)

    # ── clean per-node S_i distribution -> locked threshold theta_S ──
    id_to_row = {vid: r for r, vid in enumerate(vids)}
    S_clean = []
    for vid, vecs in per_node.items():
        r = id_to_row[vid]
        z = (np.stack(vecs) - mu_per_node[r]) / (sd_per_node[r] + EPS)
        S_clean.append((z ** 2).sum(axis=1))
    S_clean = np.concatenate(S_clean)
    theta_S = float(np.percentile(S_clean, cfg.score_percentile))

    # ── save & lock ──
    stats_path = os.path.join(args.ckpt_dir, f"{cfg.name}_stats.npz")
    np.savez(
        stats_path,
        vids=np.array(vids, dtype=object),     # raw vehicle ids (strings)
        mu_per_node=mu_per_node,               # x̄'_i   (n_nodes, emb_dim)
        sd_per_node=sd_per_node,               # sigma'_i(n_nodes, emb_dim)
        counts=counts,                         # #timesteps each node contributed
        mu_global=mu_global,                   # fallback x̄'  (emb_dim,)
        sd_global=sd_global,                   # fallback sigma' (emb_dim,)
        theta_S=theta_S,
        score_percentile=cfg.score_percentile,
        clean_S_mean=float(S_clean.mean()),
        clean_S_p99=float(np.percentile(S_clean, 99)),
    )

    print(f"  per-node stats: {len(vids)} vehicle nodes "
          f"(median {int(np.median(counts))} clean timesteps/node)")
    print(f"  clean per-node S_i: mean={S_clean.mean():.3f}  "
          f"p{cfg.score_percentile:.0f}={theta_S:.3f}")
    print(f"Stats locked -> {stats_path}")
    print("Next: python score.py --scenario "
          f"{cfg.name} --attack_csv data/{cfg.name}_attack.csv")


if __name__ == "__main__":
    main()
