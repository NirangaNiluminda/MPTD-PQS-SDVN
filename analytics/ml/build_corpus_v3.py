#!/usr/bin/env python3
"""Step 1 (final): GAT retrain corpus built ONLY from files that pass an
integrity gate, with ghost rings intact and ghosts labelled k=2.

History of this file -- both earlier attempts were wrong and are superseded:
  v1 beacon_train_master_ghost_k2.csv       merged the Aug-4 ghostcorpus; only
                                            21/2862 ghost rings had all 4
                                            members (predates Fix 2).
  v2 beacon_train_corpus_v2_ghostk2.csv     rings were intact but it pulled the
                                            arch_* runs from that same corpus,
                                            which carry ALL THREE known
                                            defects: MAP-BOUNDS clamp (2.85% of
                                            rows on the boundary), gt_pos
                                            off-by-2 (833.7 m median error on
                                            clean rows), and 55.9% duplicate
                                            rows. arch_* cannot be salvaged --
                                            after dedup+clamp removal 13 of 19
                                            runs are still internally unsorted.

INTEGRITY GATE (a file is rejected unless all hold):
  - no MAP-BOUNDS clamp signature   (<=0.1% of rows exactly on 0 or 2000)
  - zero duplicate rows             (appended-run signature)
  - sim_time sorted                 (no drop > 2 s; unsorted runs would splice
                                     time-disjoint beacons into one window)
  - contains BOTH poisoned and clean rows

NOT a disqualifier: the gt_pos NodeID off-by-2 bug. gt_pos_* are not model
inputs -- features are pos_x/pos_y/speed/heading/accel and the label is
is_poisoned. Excluding on gt would have thrown away most per-attack data for
no benefit.

CLASS-LABEL MASK: a0_* runs are combined-attack mode, so every row is
attack_number=0 -> k=-1 and no class label is set. Those rows are kept as graph
nodes (the GAT is relational; dropping them would distort window composition
away from deployment) but flagged class_label_valid=0 so a masked class loss can
skip them while the binary loss still uses them.
"""
import os, glob, numpy as np, pandas as pd

ROOT = "/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN"
DS = os.path.join(ROOT, "analytics/datasets/urban")
ML = os.path.dirname(os.path.abspath(__file__))
D = os.path.join(ML, "data")
OUT = os.path.join(D, "beacon_train_corpus_v3_ghostk2.csv")
GB = 10000
KEY = ["sim_time", "vehicle_id", "rsu_id", "pos_x", "pos_y"]
GHOST_SRC = ["a0_p40_m1", "a0_p40_m0", "a0_p60_m1"]


def gate(d, require_both=True):
    """Return (passed, reason)."""
    n = len(d)
    if n < 2000:
        return False, "too-small"
    clamp = int(((d.pos_x.round(1) == 0.0) | (d.pos_x.round(1) == 2000.0) |
                 (d.pos_y.round(1) == 0.0) | (d.pos_y.round(1) == 2000.0)).sum())
    if clamp / n > 0.001:
        return False, f"CLAMP({clamp})"
    if n - len(d[KEY].drop_duplicates()):
        return False, "DUPS"
    if int((d.sim_time.diff() < -2.0).sum()):
        return False, "UNSORTED"
    npois = int((d.is_poisoned == 1).sum())
    if require_both and (npois == 0 or n - npois == 0):
        return False, "one-class"
    return True, "ok"


parts, rejected = [], []

# --- ghost sources (rings intact) ----------------------------------------
for name in GHOST_SRC:
    d = pd.read_csv(os.path.join(DS, name, "beacon_log.csv"))
    ok, why = gate(d, require_both=False)
    if not ok:
        rejected.append((name, why)); continue
    d["run_id"] = name
    parts.append(d)
    print(f"[ghost] {name:16s} rows={len(d):7d} ghosts={int((d.vehicle_id>=GB).sum()):6d}")

# --- per-attack sources ---------------------------------------------------
n_acc = 0
for p in sorted(glob.glob(os.path.join(DS, "a[1-7]_*/beacon_log.csv"))):
    name = os.path.basename(os.path.dirname(p))
    try:
        d = pd.read_csv(p)
    except Exception:
        rejected.append((name, "read-error")); continue
    ok, why = gate(d)
    if not ok:
        rejected.append((name, why)); continue
    d["run_id"] = name
    parts.append(d); n_acc += 1
print(f"[attack] accepted {n_acc} per-attack files")

# --- master (clean negatives) --------------------------------------------
m = pd.read_csv(os.path.join(D, "beacon_train_master.csv"))
ok, why = gate(m, require_both=False)
if ok:
    m["run_id"] = "master_0"
    parts.append(m)
    print(f"[master] rows={len(m)}")
else:
    rejected.append(("master", why))

out = pd.concat(parts, ignore_index=True, sort=False)

# --- relabel ghosts to k=2 ------------------------------------------------
g = out.vehicle_id >= GB
print(f"\n[relabel] ghosts={int(g.sum())} "
      f"{out.loc[g,'attack_number'].value_counts().to_dict()} -> attack_number=3 (k=2)")
out.loc[g, "attack_number"] = 3
out.loc[g, "is_poisoned"] = 1

atk = out["attack_number"].fillna(0).astype(int)
pois = out["is_poisoned"].fillna(0).astype(int) == 1
out["class_label_valid"] = (~pois | ((atk >= 1) & (atk <= 7))).astype(int)
out.to_csv(OUT, index=False)

# ============================ verification ================================
chk = pd.read_csv(OUT)
g = chk.vehicle_id >= GB
p = chk.is_poisoned == 1
print(f"\n[verify] {OUT}")
print(f"  rows                : {len(chk)}")
print(f"  runs                : {chk.run_id.nunique()}")
print(f"  ghost rows          : {int(g.sum())}  k={sorted((chk.loc[g,'attack_number'].astype(int)-1).unique())}")
print(f"  clean / poisoned    : {int((~p).sum())} / {int(p.sum())}")
print(f"  class_label_valid   : {chk.class_label_valid.value_counts().to_dict()}")
vp = chk[p & (chk.class_label_valid == 1)]
print(f"  class dist (k)      : {(vp.attack_number.astype(int)-1).value_counts().sort_index().to_dict()}")
print(f"  x range             : {chk.pos_x.min():.1f}..{chk.pos_x.max():.1f}")
print(f"  clamped rows        : {int(((chk.pos_x.round(1)==0)|(chk.pos_x.round(1)==2000)|(chk.pos_y.round(1)==0)|(chk.pos_y.round(1)==2000)).sum())}")
print(f"  duplicate rows      : {len(chk)-len(chk[KEY+['run_id']].drop_duplicates())}")
uns = sum(1 for _r, gg in chk.groupby('run_id') if int((gg.sim_time.diff() < -2.0).sum()))
print(f"  unsorted runs       : {uns}")

tot = comp = 0
for r, grp in chk[g].groupby("run_id"):
    gg = grp.copy(); gg["ring"] = (gg.vehicle_id - GB) // 10
    sz = gg.groupby(["rsu_id", "ring", "sim_time"]).size()
    c = int((sz == 4).sum()); tot += len(sz); comp += c
print(f"  ghost rings         : {comp}/{tot} complete ({100*comp/max(tot,1):.1f}%)")

kd = (vp.attack_number.astype(int) - 1).value_counts()
allk = all(kd.get(k, 0) > 0 for k in range(7))
ok = comp == tot and allk and uns == 0
print(f"\n  all 7 classes present: {allk}   rings 100%: {comp==tot}   sorted: {uns==0}")
print("\nSTEP 1 SATISFIED" if ok else "\nSTEP 1 NOT satisfied")
print(f"\n[rejected] {len(rejected)} file(s); reasons: "
      f"{pd.Series([r for _n, r in rejected]).value_counts().to_dict()}")
