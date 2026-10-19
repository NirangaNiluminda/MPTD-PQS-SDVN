#!/usr/bin/env python3
"""
lambda_refit_ab3.py — refit lambda_gat for attack 3 (evasive Sybil-via-compromised-RSU,
--sybil_gat_evasive=1) and validate it on an UNSEEN seed.

Why this refit is required, not optional:
  The deployed global lambda set is (psi 0.5071, gat 0.1857, ae 0.3071) with phi_th=0.5.
  GAT's maximum possible vote is lambda_gat*1.0 = 0.1857 < 0.5, so on the evasive Sybil
  (engineered so psi~0 and ae_norm~0 by design — plausible kinematics, no temporal
  signature) GAT CANNOT move any decision, no matter how well-calibrated its score is —
  measured 2026-07-27: GAT-on vs GAT-off gave byte-identical fused confusion matrices
  even after fixing GAT's stale theta_S. The ablation is vacuous by construction until
  lambda_gat is refit.

Protocol (same discipline as lambda_refit_ab4.py):
  * fit lambda on seeds 1+2, evaluate on seed 3 (never seen)
  * lambda_psi/lambda_ae keep their relative proportions, rescaled to 1-lambda_gat,
    so only ONE parameter is fitted (minimal change to the deployed config) — this is
    exactly what the --lambda_gat CLI flag does in-sim (06d_ai_inference.h)
  * phi_th stays 0.5 (global, shared with every other experiment — not touched)
  * AB3 (GAT-disabled) = same rows with the GAT term removed and psi/ae renormalised,
    i.e. exactly what --ablation_ab=3 computes in-sim

Data: [FUSION-RSU*] log lines from `--attack_number=3 --n_coord=4 --ablation_mode=0
--sybil_gat_evasive=1 --seed={1,2,3}` runs (see AB3_HANDOFF.md §6 for the exact command).
psi and ae_norm are logged AS the already-weighted-ready terms (i.e. phi_logged =
L_PSI*psi + L_GAT*gat_norm + L_AE*ae_norm under the deployed weights), so base =
L_PSI*psi + L_AE*ae_norm is recovered directly from logged columns — no need to
reproduce GAT's internal normalisation.

Usage: python3 lambda_refit_ab3.py
"""
import re, os, math, glob
import numpy as np

D = "/tmp/claude-1001/-home-sdvn-mobility-flooding-Niranga-MPTD-PQS-SDVN/6472eadc-2635-44cc-8573-bb1807cc26d5/scratchpad"
PHI_TH = 0.5
L_PSI, L_GAT, L_AE = 0.5071, 0.1857, 0.3071   # deployed global set (fusion_weights.json)
RX = re.compile(r'psi=([0-9.]+).*?S=([0-9.eE+-]+).*?ae_norm=([0-9.]+).*?ae_raw=([0-9.eE+-]+)'
                r'.*?gt_pois=(\d).*?phi=([0-9.eE+-]+).*?full_anom=(YES|no)')


def load(seed):
    f = f"{D}/CAL_a3_nc4_s{seed}.log"
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


def phi_with(lam_gat, psi, an, phi_logged):
    """Rebuild phi for a candidate lambda_gat.

    base = L_PSI*psi + L_AE*an is recovered directly from the logged (already
    lambda-weighted) psi/ae_norm columns — this is exactly what phi_logged minus
    the deployed GAT term would give, without needing gat_norm explicitly.
    Rescale base to 1-lam_gat (keeping psi:ae ratio) and add the new GAT term,
    where gat_norm is recovered algebraically from the logged total phi.
    """
    base = L_PSI * psi + L_AE * an
    gat_norm = (phi_logged - base) / L_GAT
    return base * (1.0 - lam_gat) / (1.0 - L_GAT) + lam_gat * gat_norm


def phi_ab3(psi, an, phi_logged):
    """AB3: GAT removed, psi/ae renormalised to sum 1 (what --ablation_ab=3 does)."""
    base = L_PSI * psi + L_AE * an
    return base / (1.0 - L_GAT)


# ── fit on seeds 1+2 ─────────────────────────────────────────────────────────
train = [(s, load(s)) for s in (1, 2)]
train = [(s, d) for s, d in train if d is not None]
test  = [(s, load(s)) for s in (3,)]
test  = [(s, d) for s, d in test if d is not None]
print(f"[lambda-refit-ab3] train seeds={[s for s,_ in train]}  test seeds={[s for s,_ in test]}")
if not train or not test:
    raise SystemExit("missing runs — generate CAL_a3_nc4_s{1,2,3}.log first "
                      "(see AB3_HANDOFF.md §6 for the command)")

grid = np.arange(0.20, 0.96, 0.025)
scores = []
for lam in grid:
    ms = []
    for s, (psi, S, an, y, phi) in train:
        m, *_ = mcc(phi_with(lam, psi, an, phi) > PHI_TH, y)
        ms.append(m)
    scores.append(np.mean(ms))
best_lam = float(grid[int(np.argmax(scores))])
print(f"[lambda-refit-ab3] TRAIN(seeds1+2) best lambda_gat = {best_lam:.3f} "
      f"(mean MCC {max(scores):.4f}); deployed = {L_GAT}")
print("  train curve: " + "  ".join(f"{l:.2f}:{s:.3f}" for l, s in zip(grid, scores)
                                    if abs((l*1000) % 50) < 1e-6))

# ── evaluate the frozen lambda on the unseen seed ────────────────────────────
print(f"\nHELD-OUT seed 3   (lambda_gat={best_lam:.3f} frozen from seeds 1+2, phi_th={PHI_TH})")
print(f"{'seed':>5} | {'FULL MCC':>9} {'recall':>7} {'FPR':>6} | {'AB3 MCC':>8} {'recall':>7} {'FPR':>6} | {'dMCC':>8}")
print("-"*82)
deltas = []
for s, (psi, S, an, y, phi) in test:
    pf = phi_with(best_lam, psi, an, phi)
    pa = phi_ab3(psi, an, phi)
    mf, tp, fp, fn, tn = mcc(pf > PHI_TH, y)
    ma, tp2, fp2, fn2, tn2 = mcc(pa > PHI_TH, y)
    deltas.append(mf - ma)
    rec_f = tp/(tp+fn) if (tp+fn) else float('nan')
    fpr_f = fp/(fp+tn) if (fp+tn) else float('nan')
    rec_a = tp2/(tp2+fn2) if (tp2+fn2) else float('nan')
    fpr_a = fp2/(fp2+tn2) if (fp2+tn2) else float('nan')
    print(f"{s:>5} | {mf:>9.4f} {rec_f:>7.3f} {fpr_f:>6.3f} | "
          f"{ma:>8.4f} {rec_a:>7.3f} {fpr_a:>6.3f} | {mf-ma:>+8.4f}")
print(f"\n>>> held-out dMCC (FULL - AB3) = {np.mean(deltas):+.4f}")
print(f"    {'VALID: GAT contributes on the evasive Sybil' if np.mean(deltas) > 0.01 else 'no contribution'}")

# sanity: deployed lambda reproduces the in-sim result (delta must be ~0)
d0 = []
for s, (psi, S, an, y, phi) in test:
    m0, *_ = mcc(phi > PHI_TH, y)
    ma, *_ = mcc(phi_ab3(psi, an, phi) > PHI_TH, y)
    d0.append(m0 - ma)
print(f"    sanity @ deployed lambda_gat={L_GAT}: mean dMCC = {np.mean(d0):+.4f} (expect ~0, matches in-sim runs E/F)")
print(f"\nRECOMMEND lambda_sets[attack=3] = (psi {L_PSI*(1-best_lam)/(1-L_GAT):.3f}, "
      f"gat {best_lam:.3f}, ae {L_AE*(1-best_lam)/(1-L_GAT):.3f})")
print(f"  i.e. rerun the sim with: --lambda_gat={best_lam:.3f}")
