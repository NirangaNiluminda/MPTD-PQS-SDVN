#!/usr/bin/env python3
"""
phase2_constrained_refit.py — Phase 2 global-fallback weight optimisation under
the constraints specified in the Round 6 review (Fixes B and C).

Constraints (from the review letter, empirically justified):
  Fix B: lambda_gat >= 0.50   so the GAT term can independently cross Phi_th=0.5
                              and be decisive for stealth attacks where psi = 0
  Fix C: lambda_ae  <= 0.08   (= 0.3071 x 0.25, from the monotonic offline sweep)

This is constrained optimisation over the simplex, NOT manual tuning: the search
maximises MCC on training seeds and the chosen point is then scored on a held-out
seed that was never used for fitting. If the held-out result does not improve on
the deployed weights, that is reported and nothing is deployed.

Prerequisite: Fix A (theta_S raised to the 99th percentile of honest S) must be
deployed BEFORE generating the calibration logs this reads, because S/theta_S
clamping changes with theta_S and the fit is only valid for the theta_S in force.

Data: [FUSION-RSU] rows with khat == -1 (the global-fallback path this triple
governs) from combined-attack runs. psi_fuse / S_over_thetaS_clamped / ae_norm
are read directly from the log, so phi is recomputed exactly with no algebra.

Usage: python3 phase2_constrained_refit.py <log_prefix>
       e.g. python3 phase2_constrained_refit.py CALB_combined
"""
import re, os, sys, math

D = "/tmp/claude-1001/-home-sdvn-mobility-flooding-Niranga-MPTD-PQS-SDVN/42ad9abc-b50e-48e5-a8a0-f709b9d1f263/scratchpad"
PREFIX = sys.argv[1] if len(sys.argv) > 1 else "CALB_combined"
PSI_TH, PHI_TH = 0.09, 0.5
DEPLOYED = (0.5071, 0.1857, 0.3071)
LGAT_MIN, LAE_MAX = 0.50, 0.08          # Fix B / Fix C constraints


def load(seed):
    f = f"{D}/{PREFIX}_s{seed}.log"
    if not os.path.exists(f):
        return []
    rows = []
    for ln in open(f, errors="ignore"):
        if not ln.startswith("[FUSION-RSU"):
            continue
        mk = re.search(r'khat=(-?\d+)', ln)
        if not mk or int(mk.group(1)) != -1:
            continue
        mp = re.search(r'psi_fuse=([0-9.]+)', ln)
        mg = re.search(r'S_over_thetaS_clamped=([0-9.]+)', ln)
        ma = re.search(r'ae_norm=([0-9.]+)', ln)
        my = re.search(r'gt_pois=(\d)', ln)
        mt = re.search(r'gt_atk=(\d)', ln)
        if not all([mp, mg, ma, my, mt]):
            continue
        rows.append((min(float(mp.group(1)) / PSI_TH, 1.0),
                     float(mg.group(1)), float(ma.group(1)),
                     my.group(1) == '1', int(mt.group(1))))
    return rows


def score(rows, lp, lg, la):
    tp = fp = tn = fn = 0
    for psi, gat, ae, y, _ in rows:
        pred = (lp * psi + lg * gat + la * ae) > PHI_TH
        if y and pred:       tp += 1
        elif y:              fn += 1
        elif pred:           fp += 1
        else:                tn += 1
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    m = (tp * tn - fp * fn) / d if d > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) else float('nan')
    fpr = fp / (fp + tn) if (fp + tn) else float('nan')
    return m, rec, fpr, tp, fp, tn, fn


train = load(1) + load(2)
test = load(3)
if not train or not test:
    raise SystemExit(f"missing {PREFIX}_s{{1,2,3}}.log in {D}")

print(f"[phase2-constrained] train rows {len(train)} | held-out rows {len(test)}")
print(f"[phase2-constrained] constraints: lambda_gat >= {LGAT_MIN}, lambda_ae <= {LAE_MAX}")
print()

best, best_m = None, -2.0
step = 0.01
n = int(round(1 / step))
for i in range(n + 1):
    lg = round(i * step, 3)
    if lg < LGAT_MIN:
        continue
    for j in range(n + 1 - i):
        la = round(j * step, 3)
        if la > LAE_MAX:
            continue
        lp = round(1.0 - lg - la, 3)
        if lp < -1e-9:
            continue
        m, *_ = score(train, lp, lg, la)
        if m > best_m:
            best_m, best = m, (lp, lg, la)

lp, lg, la = best
print(f"TRAIN best (constrained) = (psi {lp:.3f}, gat {lg:.3f}, ae {la:.3f})  MCC {best_m:.4f}")
m_dep_tr, *_ = score(train, *DEPLOYED)
print(f"TRAIN deployed {DEPLOYED} -> MCC {m_dep_tr:.4f}")
print()

print("HELD-OUT seed 3:")
print(f"{'config':>30s} | {'MCC':>8s} {'recall':>7s} {'FPR':>7s} | TP/FP/TN/FN")
print("-" * 90)
rows_out = []
for name, w in (("deployed (0.507,0.186,0.307)", DEPLOYED),
                (f"constrained ({lp:.3f},{lg:.3f},{la:.3f})", (lp, lg, la))):
    m, rec, fpr, tp, fp, tn, fn = score(test, *w)
    rows_out.append(m)
    print(f"{name:>30s} | {m:8.4f} {rec:7.3f} {fpr:7.3f} | {tp}/{fp}/{tn}/{fn}")
d = rows_out[1] - rows_out[0]
print()
print(f">>> held-out dMCC (constrained - deployed) = {d:+.4f}")
print("    " + ("IMPROVEMENT — safe to deploy" if d > 0.005
                else "NO improvement — do NOT deploy, report as-is"))
