# """
# calibrate.py  —  PHASE 1b  (GAT statistics calibration, PER-NODE)
# ================================================================
# Loads the LOCKED encoder from Phase 1a (weights frozen, eval mode) and runs it
# forward on the CLEAN file (no attacks). It then computes, EXACTLY as required:

#   for each vehicle node v_i:
#     collect every embedding x'_i this node produced across ALL clean timesteps
#     x̄'_i = mean of that node's embeddings        ( per-node, Eq. 3.38 )
#     sigma'_i = std of that node's embeddings      ( per-node, Eq. 3.38 )

# Both x̄'_i and sigma'_i are stored PER NODE and LOCKED. They are never updated
# again during evaluation. At inference (score.py) the spatial anomaly score
# divides the node's current embedding deviation by its OWN sigma'_i and measures
# distance from its OWN x̄'_i:

#   S_i(t) = || (x'_i(t) - x̄'_i) / sigma'_i ||_2        (Eq. gat_score)

# We also store a global fallback (pooled mean/std) for any vehicle id that appears
# at inference but was not seen during clean calibration (e.g. pseudonym rotation,
# different seeds), and a locked threshold theta_S = percentile of the clean
# per-node S_i distribution.

# Run:
#   python calibrate.py --scenario urban --clean_csv data/urban_clean.csv
# """
# import argparse
# import os
# from collections import defaultdict

# import numpy as np
# import torch

# from config import get_config
# from dataset import load_graphs
# from model import build_encoder

# EPS = 1e-8
# SD_FLOOR = 1e-6     # floor on per-node std so a near-constant dim can't blow up S_i


# def load_encoder(cfg, ckpt_path):
#     ckpt = torch.load(ckpt_path, map_location="cpu")
#     if ckpt.get("cfg_name", cfg.name) != cfg.name:
#         raise ValueError(f"Checkpoint is for '{ckpt['cfg_name']}' but you asked "
#                          f"for '{cfg.name}'. Use the matching scenario.")
#     enc = build_encoder(cfg, ckpt["in_dim"])     # scenario-specific architecture
#     enc.load_state_dict(ckpt["encoder_state"])
#     enc.eval()                                   # FROZEN
#     return enc, ckpt["in_dim"]


# @torch.no_grad()
# def collect_per_node_embeddings(enc, graphs):
#     """Frozen forward pass over every clean timestep.

#     Returns {vehicle_id -> list of embedding vectors across timesteps}.
#     """
#     per_node = defaultdict(list)
#     for g in graphs:
#         x_prime = enc(g.x, g.edge_index).cpu().numpy()   # (N, emb_dim)
#         for node_idx, vid in enumerate(g.node_ids):
#             per_node[vid].append(x_prime[node_idx])
#     return per_node


# def main():
#     ap = argparse.ArgumentParser()
#     ap.add_argument("--scenario", required=True)
#     ap.add_argument("--clean_csv", required=True)
#     ap.add_argument("--ckpt_dir", default="checkpoints")
#     args = ap.parse_args()

#     cfg = get_config(args.scenario)
#     enc_path = os.path.join(args.ckpt_dir, f"{cfg.name}_encoder.pt")
#     enc, in_dim = load_encoder(cfg, enc_path)

#     print(f"Loading CLEAN graphs for '{cfg.name}' ...")
#     graphs = load_graphs(args.clean_csv, cfg)
#     print(f"  {len(graphs)} clean timestep-graphs")

#     # ── frozen forward pass -> per-node embedding collections ──
#     per_node = collect_per_node_embeddings(enc, graphs)

#     # ── per-node mean x̄'_i and std sigma'_i across that node's clean timesteps ──
#     vids = sorted(per_node.keys(), key=lambda s: (len(s), s))
#     mu_rows, sd_rows, counts = [], [], []
#     for vid in vids:
#         stack = np.stack(per_node[vid], axis=0)          # (T_i, emb_dim)
#         mu_rows.append(stack.mean(axis=0))
#         # population std, floored so single/near-constant nodes are safe
#         sd_rows.append(np.maximum(stack.std(axis=0), SD_FLOOR))
#         counts.append(stack.shape[0])
#     mu_per_node = np.stack(mu_rows, axis=0)              # (n_nodes, emb_dim)
#     sd_per_node = np.stack(sd_rows, axis=0)              # (n_nodes, emb_dim)
#     counts = np.asarray(counts, dtype=np.int64)

#     # ── global fallback (pooled over ALL clean embeddings) for unseen ids ──
#     all_emb = np.concatenate([np.stack(v) for v in per_node.values()], axis=0)
#     mu_global = all_emb.mean(axis=0)
#     sd_global = np.maximum(all_emb.std(axis=0), SD_FLOOR)

#     # ── clean per-node S_i distribution -> locked threshold theta_S ──
#     id_to_row = {vid: r for r, vid in enumerate(vids)}
#     S_clean = []
#     for vid, vecs in per_node.items():
#         r = id_to_row[vid]
#         z = (np.stack(vecs) - mu_per_node[r]) / (sd_per_node[r] + EPS)
#         S_clean.append(np.sqrt((z ** 2).sum(axis=1)))  # Eq. gat_score: S_i = ||z||_2
#     S_clean = np.concatenate(S_clean)
#     theta_S = float(np.percentile(S_clean, cfg.score_percentile))

#     # ── save & lock ──
#     stats_path = os.path.join(args.ckpt_dir, f"{cfg.name}_stats.npz")
#     np.savez(
#         stats_path,
#         vids=np.array(vids, dtype=object),     # raw vehicle ids (strings)
#         mu_per_node=mu_per_node,               # x̄'_i   (n_nodes, emb_dim)
#         sd_per_node=sd_per_node,               # sigma'_i(n_nodes, emb_dim)
#         counts=counts,                         # #timesteps each node contributed
#         mu_global=mu_global,                   # fallback x̄'  (emb_dim,)
#         sd_global=sd_global,                   # fallback sigma' (emb_dim,)
#         theta_S=theta_S,
#         score_percentile=cfg.score_percentile,
#         clean_S_mean=float(S_clean.mean()),
#         clean_S_p99=float(np.percentile(S_clean, 99)),
#     )

#     print(f"  per-node stats: {len(vids)} vehicle nodes "
#           f"(median {int(np.median(counts))} clean timesteps/node)")
#     print(f"  clean per-node S_i: mean={S_clean.mean():.3f}  "
#           f"p{cfg.score_percentile:.0f}={theta_S:.3f}")
#     print(f"Stats locked -> {stats_path}")
#     print("Next: python score.py --scenario "
#           f"{cfg.name} --attack_csv data/{cfg.name}_attack.csv")


# if __name__ == "__main__":
#     main()


"""
calibrate.py  --  Phase 1b: lock the normal baseline from CLEAN runs.

Loads the trained encoder, runs it over the CLEAN data
(data/<scenario>/a*_p0/beacon_log.csv), and computes per-node statistics
x_bar'_i and sigma'_i used by the Eq. 3.41 spatial score. Also locks the
threshold theta_S at a high percentile of clean S_i. Saves everything to
checkpoints/<scenario>_stats.npz.

Per-node stats are keyed by vehicle_id. A GLOBAL mean/std is also stored as a
fallback for vehicles never seen in the clean run (or seen too few times).

Run:
  python calibrate.py --scenario urban   --data_root data
  python calibrate.py --scenario rural   --data_root data
  # highway: needs an attack-free (p0) run first; see README.
"""
import os, argparse
import numpy as np
import torch

from config import get_config
import dataset as D
from model import build_encoder

MIN_COUNT = 5   # per-node samples needed before trusting a per-node stat


@torch.no_grad()
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True, choices=["urban", "rural", "highway"])
    ap.add_argument("--data_root", default="data")
    ap.add_argument("--ckpt_dir", default="checkpoints")
    args = ap.parse_args()

    cfg = get_config(args.scenario)
    device = torch.device("cpu")
    enc_path = os.path.join(args.ckpt_dir, f"{cfg.name}_encoder.pt")
    if not os.path.exists(enc_path):
        raise FileNotFoundError(f"{enc_path} not found. Run train.py first.")

    ckpt = torch.load(enc_path, map_location=device)
    enc = build_encoder(cfg, D.in_dim(cfg)).to(device)
    enc.load_state_dict(ckpt["encoder"])
    enc.eval()

    print(f"[calibrate] scenario={cfg.name}: loading CLEAN graphs ...")
    graphs = D.load_clean_graphs(args.data_root, cfg)
    print(f"[calibrate] {len(graphs)} clean timestep-graphs")

    # accumulate embeddings per vehicle id
    sums, sqs, cnts = {}, {}, {}
    all_emb = []
    for g in graphs:
        emb = enc(g.x.to(device), g.edge_index.to(device)).cpu().numpy()
        ids = g.node_ids.numpy()
        all_emb.append(emb)
        for vid, e in zip(ids, emb):
            sums[vid] = sums.get(vid, 0.0) + e
            sqs[vid] = sqs.get(vid, 0.0) + e * e
            cnts[vid] = cnts.get(vid, 0) + 1

    all_emb = np.concatenate(all_emb, axis=0)
    g_mean = all_emb.mean(axis=0)
    g_std = all_emb.std(axis=0) + 1e-8

    vids = sorted(sums.keys())
    node_mean, node_std = {}, {}
    for vid in vids:
        c = cnts[vid]
        if c >= MIN_COUNT:
            m = sums[vid] / c
            v = sqs[vid] / c - m * m
            node_mean[vid] = m
            node_std[vid] = np.sqrt(np.maximum(v, 0.0)) + 1e-8
        else:
            node_mean[vid] = g_mean
            node_std[vid] = g_std

    # locked threshold theta_S from clean S_i (Eq. 3.41 deviation, L2 norm)
    s_vals = []
    for g in graphs:
        emb = enc(g.x.to(device), g.edge_index.to(device)).cpu().numpy()
        for vid, e in zip(g.node_ids.numpy(), emb):
            m = node_mean.get(vid, g_mean); s = node_std.get(vid, g_std)
            z = (e - m) / s
            s_vals.append(np.sqrt((z * z).sum()))   # ||.||_2
    theta_S = float(np.percentile(s_vals, cfg.score_percentile))

    os.makedirs(args.ckpt_dir, exist_ok=True)
    out = os.path.join(args.ckpt_dir, f"{cfg.name}_stats.npz")
    np.savez(out,
             vids=np.array(vids, dtype=np.int64),
             node_mean=np.stack([node_mean[v] for v in vids]),
             node_std=np.stack([node_std[v] for v in vids]),
             global_mean=g_mean, global_std=g_std,
             theta_S=theta_S, percentile=cfg.score_percentile)
    print(f"[calibrate] per-node stats for {len(vids)} vehicles "
          f"(global fallback for <{MIN_COUNT} samples)")
    print(f"[calibrate] theta_S (p{cfg.score_percentile:g}) = {theta_S:.4f}")
    print(f"[calibrate] saved -> {out}")


if __name__ == "__main__":
    main()
