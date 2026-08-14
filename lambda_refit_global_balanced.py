#!/usr/bin/env python3
"""
lambda_refit_global_balanced.py — recalibrate urban_combined's GLOBAL FALLBACK
lambda triple (lambda_psi, lambda_gat, lambda_ae) on a CLASS-BALANCED sample
covering all seven attack types.

Why (Round 6, DQ5): the Phase 2 corpus actually used (beacon_train_master.csv)
is 100% attack_number=3 — zero samples from a1/a2/a4/a5/a6/a7 — at a 0.7%
poison rate. A global fallback fitted only on a3 has no reason to generalise,
and the fallback path carries the largest single share of beacons in combined
mode (~50%+ of evaluations). The underlying data is NOT missing; it just was
never assembled into the corpus.

Method (mirrors the validated lambda_refit_ab3/ab4 discipline):
  * data = [FUSION-RSU] rows from combined-attack runs (attack_number=0), which
    exercise the real deployed urban_combined pipeline end to end
  * restrict to khat == -1 rows ONLY — those are exactly the evaluations the
    global fallback triple governs. Rows with khat >= 0 use the per-attack
    lambda_sets and are irrelevant to this fit (and would bias it).
  * NO algebraic reconstruction: psi_fuse, S_over_thetaS_clamped and ae_norm are
    all logged directly, so phi for any candidate triple is computed exactly:
        psi_n = min(psi_fuse / psi_th, 1)
        phi   = lp*psi_n + lg*gat_clamped + la*ae_norm
    (An earlier attempt reconstructed gat_norm algebraically from phi and failed
     its own sanity check because it read raw `psi=` instead of `psi_fuse=`.
     Reading the logged terms directly removes that whole failure mode.)
  * CLASS BALANCING: each attack type's poisoned rows are reweighted to equal
    mass, so a3 (the largest malicious population) can no longer dominate the
    fit the way it dominates the raw sample. Honest rows keep weight 1 so the
    overall poisoned/honest balance is preserved.
  * fit on seeds 1+2, validate on unseen seed 3. phi_th stays 0.5.

Usage: python3 lambda_refit_global_balanced.py
"""
import re, os, math
from collections import defaultdict

D = "/tmp/claude-1001/-home-sdvn-mobility-flooding-Niranga-MPTD-PQS-SDVN/42ad9abc-b50e-48e5-a8a0-f709b9d1f263/scratchpad"
PSI_TH = 0.09
PHI_TH = 0.5
DEPLOYED = (0.5071, 0.1857, 0.3071)

RX_KHAT = re.compile(r'khat=(-?\d+)')
RX_PF   = re.compile(r'psi_fuse=([0-9.]+)')
RX_GAT  = re.compile(r'S_over_thetaS_clamped=([0-9.]+)')
RX_AE   = re.compile(r'ae_norm=([0-9.]+)')
RX_GT   = re.compile(r'gt_pois=(\d)')
RX_ATK  = re.compile(r'gt_atk=(\d)')


def load(seed):
    """Return list of (psi_n, gat, ae, y, atk) for khat==-1 rows."""
    f = f"{D}/CAL_combined_s{seed}.log"
    if not os.path.exists(f):
        return None
    rows = []
    for ln in open(f, errors="ignore"):
        if not ln.startswith("[FUSION-RSU"):
            continue
        mk = RX_KHAT.search(ln)
        if not mk or int(mk.group(1)) != -1:
            continue                     # global-fallback rows only
        mp, mg, ma = RX_PF.search(ln), RX_GAT.search(ln), RX_AE.search(ln)
        my, mt = RX_GT.search(ln), RX_ATK.search(ln)
        if not all([mp, mg, ma, my, mt]):
            continue
        psi_n = min(float(mp.group(1)) / PSI_TH, 1.0)
        rows.append((psi_n, float(mg.group(1)), float(ma.group(1)),
                     int(my.group(1)) == 1, int(mt.group(1))))
    return rows or None


def class_weights(rows):
    """Equal mass per malicious attack type; honest rows weight 1."""
    n_by_atk = defaultdict(int)
    for _, _, _, y, atk in rows:
        if y:
            n_by_atk[atk] += 1
    total_pois = sum(n_by_atk.values())
    k = len(n_by_atk) or 1
    w = []
    for _, _, _, y, atk in rows:
        if y and n_by_atk[atk] > 0:
            w.append((total_pois / k) / n_by_atk[atk])   # equalise across types
        else:
            w.append(1.0)
    return w


def wmcc(rows, w, lp, lg, la):
    tp = fp = tn = fn = 0.0
    for (psi_n, gat, ae, y, _), wi in zip(rows, w):
        pred = (lp * psi_n + lg * gat + la * ae) > PHI_TH
        if y and pred:       tp += wi
        elif y and not pred: fn += wi
        elif pred:           fp += wi
        else:                tn += wi
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return ((tp * tn - fp * fn) / d if d > 0 else 0.0), tp, fp, tn, fn


train_rows, train_w = [], []
for s in (1, 2):
    r = load(s)
    if r:
        train_rows += r
train_w = class_weights(train_rows)
test_rows = load(3)
if not train_rows or not test_rows:
    raise SystemExit("missing CAL_combined_s{1,2,3}.log")

# report the imbalance this fit is correcting
n_by = defaultdict(int)
for _, _, _, y, atk in train_rows:
    if y:
        n_by[atk] += 1
print("[refit-global] train fallback rows:", len(train_rows),
      "| held-out rows:", len(test_rows))
print("[refit-global] poisoned rows per attack type in raw train sample:")
for k in sorted(n_by):
    print(f"      a{k}: {n_by[k]:6d}  ({100*n_by[k]/sum(n_by.values()):5.1f}%)")
print("      -> reweighted to equal mass per type for the fit")
print()

# simplex grid search
best, best_m = None, -2.0
step = 0.05
g = [round(x * step, 3) for x in range(int(1 / step) + 1)]
for lp in g:
    for lg in g:
        la = round(1.0 - lp - lg, 3)
        if la < -1e-9 or la > 1.0:
            continue
        m, *_ = wmcc(train_rows, train_w, lp, lg, la)
        if m > best_m:
            best_m, best = m, (lp, lg, la)

lp, lg, la = best
print(f"[refit-global] TRAIN(seeds1+2, class-balanced) best = "
      f"(psi {lp:.3f}, gat {lg:.3f}, ae {la:.3f})  weighted MCC {best_m:.4f}")
m_dep, *_ = wmcc(train_rows, train_w, *DEPLOYED)
print(f"[refit-global] deployed {DEPLOYED} on same balanced train: MCC {m_dep:.4f}")
print()

# held-out, UNWEIGHTED (real-world population) — the honest test
tw = [1.0] * len(test_rows)
m_new, tp, fp, tn, fn = wmcc(test_rows, tw, lp, lg, la)
m_old, tp0, fp0, tn0, fn0 = wmcc(test_rows, tw, *DEPLOYED)
print("HELD-OUT seed 3 (unweighted, true population):")
print(f"{'config':>28s} | {'MCC':>8s} {'recall':>7s} {'FPR':>7s} | TP/FP/TN/FN")
print("-" * 88)
for name, m, a, b, c, d_ in (("deployed (0.507,0.186,0.307)", m_old, tp0, fp0, tn0, fn0),
                             (f"refit ({lp:.3f},{lg:.3f},{la:.3f})", m_new, tp, fp, tn, fn)):
    rec = a / (a + d_) if (a + d_) else float('nan')
    fpr = b / (b + c) if (b + c) else float('nan')
    print(f"{name:>28s} | {m:8.4f} {rec:7.3f} {fpr:7.3f} | "
          f"{int(a)}/{int(b)}/{int(c)}/{int(d_)}")
print()
print(f">>> held-out dMCC (refit - deployed) = {m_new - m_old:+.4f}")
print("    " + ("IMPROVEMENT — deploy" if m_new - m_old > 0.005 else
                "no meaningful improvement — do NOT deploy"))
