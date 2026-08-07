#!/usr/bin/env python3
"""Step 3: retrain the GAT so the k=2 (Sybil ring) head actually learns the ring.

ISOLATED. Writes models/urban_ghostk2_test/ only. Nothing deployed reads that
directory; promotion is a separate explicit step after sir's Step 4/5 gates.

What this does differently from train_ab3_gat_v3/v4
---------------------------------------------------
1. CORPUS: beacon_train_corpus_v3_ghostk2.csv -- ghost rings 100% complete and
   ghosts labelled k=2. Built by build_corpus_v3.py behind an integrity gate
   that rejected 117 corrupt files (clamp / duplicate / unsorted).

2. WINDOWS: ghost_window_builder mirrors the LIVE ghost flush (N=5 typical)
   instead of tumbling-10. S_i is a PER-GRAPH z-score, so graph size changes
   the statistic; training on N=10 and deploying on N=5 is a real mismatch.

3. MASKED CLASS LOSS (new, required by the data): 88287 poisoned rows come from
   combined-attack runs where attack_number=0 -> k=-1, so no class label is set.
   Unmasked they would train all 7 heads with an all-zero target on genuine
   attacks -- i.e. "this attack is none of the 7 classes" -- which is exactly
   what would trip the per-variant regression gate. class_label_valid=0 rows are
   kept as GRAPH NODES (the GAT is relational; dropping them would distort
   window composition away from deployment) but excluded from the class loss.
   They still contribute to the binary is_poisoned loss.

4. psi/sig_mask ZEROED (inherited from v4, and it closes a leak): sig_mask==0 for
   100.0% of ghosts vs 77.9% of real rows, so a head given sig_mask learns
   "no rule signature => ghost" -- a detector-pipeline artifact, not the attack.
   Same class of error as the Fix-2-verbatim label leakage. Also matches deploy,
   where those 10 dims are zero anyway.

Env knobs: MPTD_GAT_EPOCHS (default 60), MPTD_GK2_NEG_SAMPLE (default 12000),
MPTD_GAT_LOSS_K_WEIGHT, MPTD_SEED.
"""
import os, sys, json, copy
import numpy as np, pandas as pd, torch
import torch.nn as nn

ML = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, ML)
os.environ.setdefault("MPTD_GAT_EPOCHS", "60")
from torch_geometric.data import Data
from gat_detector import GATDetector, ATTACK_CLASSES
from ghost_window_builder import build_windows, GHOST_VID_BASE

R_MAX_GRAPH = 300.0
STAGE = os.path.join(ML, "models", os.environ.get("MPTD_GK2_STAGE","urban_ghostk2_posfix"))
os.makedirs(STAGE, exist_ok=True)
CORPUS = os.path.join(ML, "data", "beacon_train_corpus_v3_ghostk2.csv")
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
SEED = int(os.environ.get("MPTD_SEED", "42"))
EPOCHS = int(os.environ.get("MPTD_GAT_EPOCHS", "60"))
NEG_SAMPLE = int(os.environ.get("MPTD_GK2_NEG_SAMPLE", "12000"))
LOSS_K_W = float(os.environ.get("MPTD_GAT_LOSS_K_WEIGHT", "1.0"))
# FIX A: constrain score_scale > 0 so raw-s_i export and fusion agree on polarity.
GK2_POSITIVE_SCALE = os.environ.get("MPTD_GK2_POSITIVE_SCALE", "1") == "1"
torch.manual_seed(SEED); np.random.seed(SEED)

FEAT = ["pos_x", "pos_y", "speed", "heading", "accel"]

# ── 1. load corpus + the DEPLOYED scaler ──────────────────────────────────
df = pd.read_csv(CORPUS)
scj = json.load(open(os.path.join(ML, "models", "urban_combined", "gat_scaler.json")))
mean = np.array(scj["mean"], float)[:5]; scale = np.array(scj["scale"], float)[:5]
print(f"[gk2] corpus rows={len(df)} ghosts={int((df.vehicle_id>=GHOST_VID_BASE).sum())} "
      f"runs={df.run_id.nunique()}")

# ── 2. build windows mirroring the live ghost flush ───────────────────────
wins = build_windows(df, mirror_ghost_flush=True)
gw = [w for w in wins if (w.vehicle_id >= GHOST_VID_BASE).any()]
nw = [w for w in wins if not (w.vehicle_id >= GHOST_VID_BASE).any()]
rng = np.random.default_rng(SEED)

# STRATIFIED sampling of non-ghost windows. Sampling them uniformly starves the
# non-ghost heads: every ghost window is k=2, so a uniform draw gave
# pos/class=[150, 98, 20724, 507, 45, 140, 533] -- k=2 outnumbering k=4 by 460x.
# Training that would collapse the rare heads and fail the per-variant
# regression gate. Instead bucket each window by the labelled classes it
# carries and draw an equal quota from each, so every head keeps signal.
def win_classes(w):
    p = w.is_poisoned.values.astype(int)
    v = w.class_label_valid.values.astype(int) if "class_label_valid" in w.columns else np.ones(len(w), int)
    k = w.attack_number.fillna(0).values.astype(int) - 1
    return set(k[(p == 1) & (v == 1) & (k >= 0) & (k < ATTACK_CLASSES)].tolist())

buckets = {}
for w in nw:
    cs = win_classes(w)
    key = min(cs) if cs else -1          # -1 = all-clean window
    buckets.setdefault(key, []).append(w)
quota = max(1, NEG_SAMPLE // max(1, len(buckets)))
sampled = []
for key, lst in sorted(buckets.items()):
    take = lst if len(lst) <= quota else [lst[i] for i in rng.choice(len(lst), quota, replace=False)]
    sampled.extend(take)
    print(f"    bucket k={key:2d}: available={len(lst):6d} taken={len(take):5d}")
nw = sampled
wins = gw + nw
rng.shuffle(wins)
print(f"[gk2] windows: ghost-bearing={len(gw)} non-ghost(stratified)={len(nw)} total={len(wins)}")


def to_graph(w):
    """Build one Data object. psi + sig_mask are ZEROED (v4 fix + leak closure)."""
    n = len(w)
    f5 = (w[FEAT].values.astype(np.float64) - mean) / scale
    x = np.concatenate([f5, np.ones((n, 1)), np.zeros((n, 10))], axis=1).astype(np.float32)

    # vectorised edge predicate: within R_MAX_GRAPH and heading-aligned (cos>=0)
    px, py = w.pos_x.values, w.pos_y.values
    sp, hd = w.speed.values, w.heading.values
    vx, vy = sp * np.cos(hd), sp * np.sin(hd)
    d = np.hypot(px[:, None] - px[None, :], py[:, None] - py[None, :])
    dot = vx[:, None] * vx[None, :] + vy[:, None] * vy[None, :]
    den = np.hypot(vx, vy)[:, None] * np.hypot(vx, vy)[None, :] + 1e-9
    ok = (d <= R_MAX_GRAPH) & ((dot / den) >= 0.0)
    np.fill_diagonal(ok, False)
    src, dst = np.nonzero(ok)
    if len(src) == 0:
        return None

    y = torch.tensor(w.is_poisoned.values.astype(np.float32))
    atk = w.attack_number.fillna(0).values.astype(int)
    pois = w.is_poisoned.values.astype(int)
    valid = w.class_label_valid.values.astype(np.float32) if "class_label_valid" in w.columns \
        else np.ones(n, dtype=np.float32)
    ym = np.zeros((n, ATTACK_CLASSES), dtype=np.float32)
    for r in range(n):
        k = atk[r] - 1
        if pois[r] == 1 and 0 <= k < ATTACK_CLASSES:
            ym[r, k] = 1.0
    g = Data(x=torch.tensor(x), edge_index=torch.tensor(np.stack([src, dst]), dtype=torch.long), y=y)
    g.y_multi = torch.tensor(ym)
    g.cmask = torch.tensor(valid).unsqueeze(1)          # (N,1) 1=class loss applies
    g.is_ghost = torch.tensor((w.vehicle_id.values >= GHOST_VID_BASE).astype(np.float32))
    return g


graphs = [g for g in (to_graph(w) for w in wins) if g is not None]
print(f"[gk2] graphs built: {len(graphs)}  (dropped {len(wins)-len(graphs)} edgeless)")
sizes = np.array([g.x.shape[0] for g in graphs])
print(f"[gk2] graph size: min={sizes.min()} p50={np.median(sizes):.0f} max={sizes.max()}")

from sklearn.model_selection import train_test_split
train_g, val_g = train_test_split(graphs, test_size=0.2, random_state=42)

# ── 3. class weights over VALID rows only ─────────────────────────────────
tot = 0.0; pos = np.zeros(ATTACK_CLASSES)
for g in train_g:
    m = g.cmask.numpy()
    tot += float(m.sum())
    pos += (g.y_multi.numpy() * m).sum(axis=0)
neg = np.maximum(tot - pos, 0.0)
w_pos = np.where(pos > 0, tot / (2.0 * np.maximum(pos, 1.0)), 1.0)
w_neg = np.where(neg > 0, tot / (2.0 * np.maximum(neg, 1.0)), 1.0)
w_pos = np.minimum(w_pos, float(os.environ.get("MPTD_GAT_WPOS_CAP", "1e9")))
w_pos_t = torch.tensor(w_pos, dtype=torch.float, device=DEVICE)
w_neg_t = torch.tensor(w_neg, dtype=torch.float, device=DEVICE)
print(f"[gk2] valid class rows={int(tot)} pos/class={pos.astype(int).tolist()}")
print(f"[gk2] w_pos={np.round(w_pos,2).tolist()}")

model = GATDetector().to(DEVICE)
opt = torch.optim.Adam(model.parameters(), lr=float(os.environ.get("MPTD_GAT_LR", "1e-3")),
                       weight_decay=float(os.environ.get("MPTD_GAT_WD", "0.0")))
bce = nn.BCELoss()
GRAD_CLIP = float(os.environ.get("MPTD_GAT_GRAD_CLIP", "5.0"))


def masked_losses(g):
    score, atk = model(g.x, g.edge_index)
    score = score.squeeze(-1)
    ym, m = g.y_multi, g.cmask
    loss_s = bce(score, g.y)
    w = (ym * w_pos_t + (1.0 - ym) * w_neg_t) * m           # zero weight on invalid rows
    per = nn.functional.binary_cross_entropy(atk, ym, weight=w, reduction="sum")
    denom = m.sum() * ATTACK_CLASSES
    loss_k = per / torch.clamp(denom, min=1.0) * ATTACK_CLASSES
    return loss_s, loss_k


def val_loss():
    model.eval(); vl = 0.0
    with torch.no_grad():
        for g in val_g:
            g = g.to(DEVICE)
            ls, lk = masked_losses(g)
            vl += (ls + LOSS_K_W * lk).item()
    return vl / max(1, len(val_g))


best = float("inf"); best_state = copy.deepcopy(model.state_dict())
print(f"[gk2] training {EPOCHS} epochs on {len(train_g)} graphs (val {len(val_g)}) …")
for ep in range(EPOCHS):
    model.train(); tl = 0.0
    for g in train_g:
        g = g.to(DEVICE)
        opt.zero_grad()
        ls, lk = masked_losses(g)
        loss = ls + LOSS_K_W * lk
        loss.backward()
        if GRAD_CLIP > 0:
            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
        opt.step()
        # FIX A (sir, 2026-08-06): constrain score_scale POSITIVE.
        #
        # The previous run learned score_scale = -0.14742, i.e. "LOW s_i =
        # poisoned". That is a valid optimum, but Fix A exports the RAW s_i and
        # the fusion computes min(S/theta_S,1) assuming HIGH = anomalous, so the
        # signal was read backwards (raw AUC 0.4189; polarity-corrected 0.5811,
        # and 0.6774 on a held-out run).
        #
        # Sir specified:
        #     self.score_scale = nn.Parameter(torch.clamp(self.score_scale, min=0.01))
        # That does NOT work. In __init__ score_scale starts at 1.0, so the clamp
        # is a no-op and training still drives it negative. In forward() it REBINDS
        # self.score_scale to a new Parameter each pass, so the optimizer keeps
        # updating the original object while forward uses a different one, and
        # Parameter(clamp(...)) detaches it from the graph — training silently breaks.
        #
        # This is the projected-gradient equivalent: clamp in-place after the step.
        # Same intent, preserves the optimizer state and the autograd graph.
        if GK2_POSITIVE_SCALE:
            with torch.no_grad():
                model.score_scale.clamp_(min=0.01)
        tl += loss.item()
    vl = val_loss()
    if vl < best:
        best = vl; best_state = copy.deepcopy(model.state_dict())
    if (ep + 1) % 5 == 0 or ep == 0:
        print(f"  epoch {ep+1:3d}  train={tl/len(train_g):.4f}  val={vl:.4f}  best={best:.4f}", flush=True)
model.load_state_dict(best_state)
print(f"[gk2] restored best-val checkpoint ({best:.4f})")
print(f"[gk2] FIX A score_scale={float(model.score_scale):+.5f} bias={float(model.score_bias):+.5f} "
      f"-> polarity {'HIGH s_i = poisoned (CORRECT)' if float(model.score_scale)>0 else 'INVERTED — FIX A FAILED'}")

# ── 4. save + ONNX (same wrapper shape as v3/v4) ──────────────────────────
torch.save(model.state_dict(), os.path.join(STAGE, "gat_model.pt"))


class GATRawS(nn.Module):
    def __init__(self, b):
        super().__init__()
        self.conv1, self.conv2, self.act, self.cls_heads = b.conv1, b.conv2, b.act, b.cls_heads

    def forward(self, x, edge_index):
        e = self.act(self.conv1(x, edge_index)); e = self.act(self.conv2(e, edge_index))
        mu = e.mean(0, keepdim=True); sig = e.std(0, keepdim=True) + 1e-6
        s_i = ((e - mu) / sig).norm(dim=1, keepdim=True)
        return s_i, torch.sigmoid(self.cls_heads(e))


raw = GATRawS(model.cpu()).eval()
n = 16
torch.onnx.export(raw, (torch.randn(n, 16), torch.tensor([list(range(n)), list(range(n))], dtype=torch.long)),
                  os.path.join(STAGE, "gat_model.onnx"),
                  input_names=["x", "edge_index"], output_names=["scores", "attack_probs"],
                  dynamic_axes={"x": {0: "N"}, "edge_index": {1: "E"}, "scores": {0: "N"},
                                "attack_probs": {0: "N"}},
                  opset_version=16, dynamo=False)

# ── 5. DIAGNOSTIC: within-window separation, ghost vs real ────────────────
# This is the check that failed at AUC~0.50 on the deployed model.
def win_auc(v, mask):
    a, b = v[mask], v[~mask]
    if len(a) == 0 or len(b) == 0:
        return None
    gt = (a[:, None] > b[None, :]).sum(); eq = (a[:, None] == b[None, :]).sum()
    return float((gt + 0.5 * eq) / (len(a) * len(b)))


model.eval()
sA, bA, degen, pS, cS, k2p, k2c = [], [], 0, [], [], [], []
with torch.no_grad():
    for g in val_g:
        g = g.cpu()          # model was moved to CPU for the ONNX export above
        if g.is_ghost.sum() == 0:
            emb = model.act(model.conv1(g.x, g.edge_index)); emb = model.act(model.conv2(emb, g.edge_index))
            mu = emb.mean(0, keepdim=True); sg = emb.std(0, keepdim=True) + 1e-6
            s = ((emb - mu) / sg).norm(dim=1).numpy()
            cS += list(s); k2c += list(torch.sigmoid(model.cls_heads(emb)).numpy()[:, 2])
            continue
        emb = model.act(model.conv1(g.x, g.edge_index)); emb = model.act(model.conv2(emb, g.edge_index))
        mu = emb.mean(0, keepdim=True); sg = emb.std(0, keepdim=True) + 1e-6
        s = ((emb - mu) / sg).norm(dim=1).numpy()
        bv = torch.sigmoid(model.cls_heads(emb)).numpy()
        m = g.is_ghost.numpy() == 1
        if s.std() < 1e-6:
            degen += 1
        a1 = win_auc(s, m); a2 = win_auc(bv[:, 2], m)
        if a1 is not None: sA.append(a1)
        if a2 is not None: bA.append(a2)
        pS += list(s[m]); cS += list(s[~m])
        k2p += list(bv[m, 2]); k2c += list(bv[~m, 2])

sA, bA = np.array(sA), np.array(bA)
pS, cS = np.array(pS), np.array(cS)
k2p, k2c = np.array(k2p), np.array(k2c)
theta_s = float(np.percentile(cS, 95)) if len(cS) else 0.0
open(os.path.join(STAGE, "theta_s.txt"), "w").write(f"{theta_s:.6f}\n")

print("\n" + "=" * 70)
print("[gk2] WITHIN-WINDOW SEPARATION on held-out ghost windows")
print("=" * 70)
print(f"  ghost windows evaluated : {len(sA)}   S degenerate(all-equal): {degen} "
      f"({100*degen/max(len(sA),1):.1f}%)")
print(f"  S      AUC  mean={sA.mean():.4f} p50={np.median(sA):.4f}   (deployed model: 0.512)")
print(f"  bv[k2] AUC  mean={bA.mean():.4f} p50={np.median(bA):.4f}   (deployed model: 0.503)")
print(f"\n  theta_S (clean p95) = {theta_s:.3f}")
print(f"  S  ghost p50={np.median(pS):.3f}  clean p50={np.median(cS):.3f}")
print(f"  k2 head  ghost mean={k2p.mean():.4f} p50={np.median(k2p):.4f} | "
      f"clean mean={k2c.mean():.4f} p95={np.percentile(k2c,95):.4f}")
for th in (0.5, 0.8):
    print(f"    ghost bv_k2>={th}: {100*(k2p>=th).mean():5.1f}%   clean bv_k2>={th}: {100*(k2c>=th).mean():5.1f}%")
print(f"\n[gk2] saved to {STAGE} (ISOLATED — nothing deployed reads this)")
