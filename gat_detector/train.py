"""
train.py  —  PHASE 1a  (GAT supervised training)
================================================
Trains W_h and a_h by class-weighted binary cross-entropy on the ATTACK file
(labels from NS-3 ground truth). Implements the modeling-update loss:

  L_GAT = -(1/|V|) Σ [ w+ y log ŷ + w- (1-y) log(1-ŷ) ]        (Eq. gat_loss)
  w+ = |V| / (2|V+|) ,  w- = |V| / (2|V-|)

Class weighting is essential: at low penetration rates the malicious nodes are
a small minority and an unweighted loss collapses to "predict all normal".

After training, ONLY the encoder weights are saved (the head is discarded, per
the modeling update). Phase 1b (calibrate.py) consumes those encoder weights.

Run:
  python train.py --scenario urban --attack_csv data/urban_attack.csv
"""
import argparse
import os
import numpy as np
import torch
from torch_geometric.loader import DataLoader
from sklearn.metrics import matthews_corrcoef, f1_score

from config import get_config
from dataset import load_graphs
from model import build_model


def compute_class_weights(graphs):
    y = torch.cat([g.y for g in graphs])
    n = y.numel()
    n_pos = float((y == 1).sum())
    n_neg = float((y == 0).sum())
    # guard against a split with zero of one class
    w_pos = n / (2 * n_pos) if n_pos > 0 else 0.0
    w_neg = n / (2 * n_neg) if n_neg > 0 else 0.0
    return w_pos, w_neg, int(n_pos), int(n_neg)


def weighted_bce(logits, y, w_pos, w_neg):
    # per-node weight: w+ where y=1, w- where y=0
    w = torch.where(y > 0.5, torch.full_like(y, w_pos), torch.full_like(y, w_neg))
    return torch.nn.functional.binary_cross_entropy_with_logits(
        logits, y, weight=w)


def split_graphs(graphs, val_frac=0.2, seed=0):
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(graphs))
    n_val = max(1, int(len(graphs) * val_frac))
    val_idx, train_idx = idx[:n_val], idx[n_val:]
    return [graphs[i] for i in train_idx], [graphs[i] for i in val_idx]


@torch.no_grad()
def evaluate(model, loader, device):
    model.eval()
    ys, ps = [], []
    for batch in loader:
        batch = batch.to(device)
        logit, _ = model(batch.x, batch.edge_index)
        ys.append(batch.y.cpu().numpy())
        ps.append((torch.sigmoid(logit) > 0.5).cpu().numpy().astype(int))
    y = np.concatenate(ys)
    p = np.concatenate(ps)
    mcc = matthews_corrcoef(y, p) if len(np.unique(y)) > 1 else 0.0
    f1 = f1_score(y, p, zero_division=0)
    return mcc, f1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--attack_csv", required=True)
    ap.add_argument("--ckpt_dir", default="checkpoints")
    args = ap.parse_args()

    cfg = get_config(args.scenario)
    device = torch.device("cpu")
    torch.manual_seed(0)

    print(f"Loading attack graphs for '{cfg.name}' ...")
    graphs = load_graphs(args.attack_csv, cfg)
    print(f"  {len(graphs)} timestep-graphs")
    train_g, val_g = split_graphs(graphs)

    w_pos, w_neg, n_pos, n_neg = compute_class_weights(train_g)
    print(f"  train nodes: {n_pos} malicious / {n_neg} normal "
          f"-> w+={w_pos:.3f} w-={w_neg:.3f}")

    in_dim = train_g[0].x.shape[1]
    model = build_model(cfg, in_dim).to(device)
    print(f"  model: {type(model).__name__}  "
          f"(heads={cfg.heads}, hidden={cfg.hidden_dim}, emb={cfg.emb_dim}, "
          f"params={sum(p.numel() for p in model.parameters())})")
    opt = torch.optim.Adam(model.parameters(), lr=cfg.lr,
                           weight_decay=cfg.weight_decay)

    train_loader = DataLoader(train_g, batch_size=cfg.batch_graphs, shuffle=True)
    val_loader = DataLoader(val_g, batch_size=cfg.batch_graphs)

    best_mcc = -2.0
    os.makedirs(args.ckpt_dir, exist_ok=True)
    enc_path = os.path.join(args.ckpt_dir, f"{cfg.name}_encoder.pt")

    for epoch in range(1, cfg.epochs + 1):
        model.train()
        total = 0.0
        for batch in train_loader:
            batch = batch.to(device)
            opt.zero_grad()
            logit, _ = model(batch.x, batch.edge_index)
            loss = weighted_bce(logit, batch.y, w_pos, w_neg)
            loss.backward()
            opt.step()
            total += loss.item() * batch.num_graphs
        mcc, f1 = evaluate(model, val_loader, device)
        if epoch % 5 == 0 or epoch == 1:
            print(f"epoch {epoch:3d} | loss {total/len(train_g):.4f} "
                  f"| val MCC {mcc:.3f} F1 {f1:.3f}")
        if mcc > best_mcc:
            best_mcc = mcc
            # SAVE ENCODER (+ head, for the alternative supervised-scoring path).
            # The modeling update discards the head and scores via Eq. 3.38;
            # we persist it too so you can empirically compare both at inference.
            torch.save({
                "encoder_state": model.encoder.state_dict(),
                "head_state": model.head.state_dict(),
                "in_dim": in_dim,
                "cfg_name": cfg.name,
                "model_class": type(model).__name__,
                "arch": {"hidden_dim": cfg.hidden_dim, "emb_dim": cfg.emb_dim,
                         "heads": cfg.heads, "dropout": cfg.dropout},
                "feature_cols": cfg.feature_cols,
            }, enc_path)

    print(f"\nBest val MCC {best_mcc:.3f}. Encoder saved -> {enc_path}")
    print("Next: python calibrate.py --scenario "
          f"{cfg.name} --clean_csv data/{cfg.name}_clean.csv")


if __name__ == "__main__":
    main()
