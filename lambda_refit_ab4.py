#!/usr/bin/env python3
"""
lambda_refit_ab4.py — refit lambda_ae for attack 1 (TP-S1 stealth drift) and
validate it on an UNSEEN seed.

Why this refit is required, not optional:
  The deployed attack-1 lambda set is (psi 0.5, gat 0.3, ae 0.2) with phi_th=0.5.
  The AE's maximum possible vote is lambda_ae*1.0 = 0.2 < 0.5, so on stealth drift
  (where psi contributes ~0.008 and GAT flags 0.000) the AE CANNOT move any
  decision — measured: removing the AE term flips exactly 0 beacons. The ablation
  is therefore vacuous by construction. Separately, lambda_ae=0.2 was fitted when
  the AE consumed ABSOLUTE position and scored ROC-AUC 0.463 (noise); the retrained
  residual AE scores 0.825, so its weight must be refitted.

Protocol (guards against the simplex/one-seed overfitting traps hit earlier):
  * fit lambda on seeds 1+2, evaluate on seed 3 (never seen)
  * lambda_psi/lambda_gat keep their relative proportions, rescaled to 1-lambda_ae,
    so only ONE parameter is fitted (minimal change to the deployed config)
  * phi_th stays 0.5 (global, shared with every other experiment - not touched)
  * AB4 = same rows with the AE term removed and psi/gat renormalised, i.e. exactly
    what --ablation_ab=4 computes in-sim (verified against the in-sim AB4 runs)

Usage: python3 lambda_refit_ab4.py
"""
import re, os, math, glob
import numpy as np

D   = "/home/sdvn_mobility_flooding/Desktop/SENTINEL_experiments/AB4_sweep/logs"
EPS = ("0.1", "0.2", "0.3", "0.4", "0.5")
PHI_TH   = 0.5
L_PSI, L_GAT, L_AE = 0.5, 0.3, 0.2          # deployed attack-1 set
RX = re.compile(r'psi=([0-9.]+) S=([0-9.eE+-]+) ae_norm=([0-9.]+) ae_raw=([0-9.]+)'
                r'.*?gt_pois=(\d) phi=([0-9.eE+-]+).*?full_anom=(YES|no)')


def load(eps, seed):
    f = f"{D}/CAL_eps{eps}_ab0_s{seed}.log"
    if not os.path.exists(f):
        return None
    psi, S, an, y, phi = [], [], [], [], []
    for ln in open(f, errors="ignore"):
        if not ln.startswith("[FUSION-RSU"):
            continue
        m = RX.search(ln)
        if not m:
            continue
        psi.append(float(m.group(1))); S.append(float(m.group(2)))
        an.append(float(m.group(3)));  y.append(m.group(5) == "1")
        phi.append(float(m.group(6)))
    if not y:
        return None
    return (np.array(psi), np.array(S), np.array(an),
            np.array(y, bool), np.array(phi))


def mcc(pred, y):
    pred = np.asarray(pred, bool)
    tp = int(np.sum(pred & y)); fp = int(np.sum(pred & ~y))
    fn = int(np.sum(~pred & y)); tn = int(np.sum(~pred & ~y))
    d = math.sqrt(float(tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    return ((tp*tn - fp*fn)/d if d > 0 else 0.0), tp, fp, fn, tn


def phi_with(lam_ae, psi, S, an, phi_logged):
    """Rebuild phi for a candidate lambda_ae.

    The logged phi already contains the psi+gat contribution under the deployed
    weights; strip the deployed AE term to recover it exactly (no need to guess
    the sim's internal GAT normalisation), then rescale psi/gat to 1-lam_ae and
    add the new AE term.
    """
    base = phi_logged - L_AE * an                 # = l_psi*psi + l_gat*S_norm
    return base * (1.0 - lam_ae) / (1.0 - L_AE) + lam_ae * an


def phi_ab4(psi, S, an, phi_logged):
    """AB4: AE removed, psi/gat renormalised to sum 1 (what ablation_ab=4 does)."""
    base = phi_logged - L_AE * an
    return base / (1.0 - L_AE)


# ── fit on seeds 1+2 ─────────────────────────────────────────────────────────
train = [(e, load(e, s)) for e in EPS for s in (1, 2)]
train = [(e, d) for e, d in train if d is not None]
test  = [(e, load(e, 3)) for e in EPS]
test  = [(e, d) for e, d in test if d is not None]
print(f"[lambda-refit] train points={len(train)}  test points={len(test)}")
if not train or not test:
    raise SystemExit("missing runs — generate seeds 2/3 first")

grid = np.arange(0.20, 0.86, 0.025)
scores = []
for lam in grid:
    ms = []
    for e, (psi, S, an, y, phi) in train:
        m, *_ = mcc(phi_with(lam, psi, S, an, phi) > PHI_TH, y)
        ms.append(m)
    scores.append(np.mean(ms))
best_lam = float(grid[int(np.argmax(scores))])
print(f"[lambda-refit] TRAIN(seeds1+2) best lambda_ae = {best_lam:.3f} "
      f"(mean MCC {max(scores):.4f}); deployed = {L_AE}")
print("  train curve: " + "  ".join(f"{l:.2f}:{s:.3f}" for l, s in zip(grid, scores)
                                    if abs((l*1000) % 50) < 1e-6))

# ── evaluate the frozen lambda on the unseen seed ────────────────────────────
print(f"\nHELD-OUT seed 3   (lambda_ae={best_lam:.3f} frozen from seeds 1+2, phi_th={PHI_TH})")
print(f"{'eps':>5} | {'FULL MCC':>9} {'recall':>7} {'FPR':>6} | {'AB4 MCC':>8} {'recall':>7} {'FPR':>6} | {'dMCC':>8}")
print("-"*82)
deltas = []
for e, (psi, S, an, y, phi) in test:
    pf = phi_with(best_lam, psi, S, an, phi)
    pa = phi_ab4(psi, S, an, phi)
    mf, tp, fp, fn, tn = mcc(pf > PHI_TH, y)
    ma, tp2, fp2, fn2, tn2 = mcc(pa > PHI_TH, y)
    deltas.append(mf - ma)
    print(f"{e:>5} | {mf:>9.4f} {tp/(tp+fn):>7.3f} {fp/(fp+tn):>6.3f} | "
          f"{ma:>8.4f} {tp2/(tp2+fn2):>7.3f} {fp2/(fp2+tn2):>6.3f} | {mf-ma:>+8.4f}")
print(f"\n>>> mean held-out dMCC (FULL - AB4) = {np.mean(deltas):+.4f}")
print(f"    {'VALID: the LSTM-AE contributes on stealth drift' if np.mean(deltas) > 0.01 else 'no contribution'}")

# sanity: deployed lambda reproduces the in-sim result (delta must be ~0)
d0 = []
for e, (psi, S, an, y, phi) in test:
    m0, *_ = mcc(phi > PHI_TH, y)
    ma, *_ = mcc(phi_ab4(psi, S, an, phi) > PHI_TH, y)
    d0.append(m0 - ma)
print(f"    sanity @ deployed lambda_ae=0.2: mean dMCC = {np.mean(d0):+.4f} (expect ~0, matches in-sim)")
print(f"\nRECOMMEND lambda_sets[attack=1] = (psi {L_PSI*(1-best_lam)/(1-L_AE):.3f}, "
      f"gat {L_GAT*(1-best_lam)/(1-L_AE):.3f}, ae {best_lam:.3f})")
