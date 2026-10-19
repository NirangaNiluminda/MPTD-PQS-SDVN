#!/usr/bin/env python3
"""
lambda_offline_sweep.py — re-derive the fusion weights lambda WITHOUT re-running
sims. Parses the [FUSION-RSU...] log lines (per-window tier scores + ground-truth
poison label) emitted by 08_detection_engine.h, reconstructs the normalized tier
scores exactly as fuse_scores() does, and sweeps lambda over the simplex.

For each lambda=(lp,lg,la), lp+lg+la=1:
    phi = lp*psi_n + lg*gat_n + la*ae_n ;  decision = phi > PHI_TH
    -> confusion matrix vs gt_pois -> eps-smoothed MCC (Eq 4.1) + FPR.

Reports: (1) validation that current lambda reproduces the sim MCC, (2) the MCC-
optimal lambda, (3) the best lambda subject to FPR<=cap. Nothing is written to
the sim; this only proposes weights to justify+redeploy.

Usage: python3 lambda_offline_sweep.py <MPTD-PQS_full.log> [PSI_TH] [THETA_S] [PHI_TH]
"""
import sys, re, math

LOG    = sys.argv[1]
PSI_TH = float(sys.argv[2]) if len(sys.argv) > 2 else 0.09
THETA_S= float(sys.argv[3]) if len(sys.argv) > 3 else 7.555182
PHI_TH = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5

# current deployed weights (models/urban/fusion_weights.json)
CUR = (0.55, 0.25, 0.20)

pat = re.compile(
    r"psi=([-\d.]+)\s+S=([-\d.]+)\s+ae_norm=([-\d.]+).*?gt_pois=([01]).*?phi=([-\d.]+)")

rows = []          # (psi_n, gat_n, ae_n, gt, phi_logged)
for line in open(LOG):
    if "FUSION-RSU" not in line:
        continue
    m = pat.search(line)
    if not m:
        continue
    psi, S, ae_n, gt, phi_log = (float(m.group(1)), float(m.group(2)),
                                 float(m.group(3)), int(m.group(4)), float(m.group(5)))
    psi_n = min(1.0, max(0.0, psi / PSI_TH))
    gat_n = min(1.0, max(0.0, S   / THETA_S))
    ae_n  = min(1.0, max(0.0, ae_n))           # already normalized in-sim
    rows.append((psi_n, gat_n, ae_n, gt, phi_log))

N = len(rows)
print(f"parsed {N} fused windows   (PSI_TH={PSI_TH} THETA_S={THETA_S} PHI_TH={PHI_TH})")


def mcc_fpr(lp, lg, la):
    s = lp + lg + la
    if s > 1e-9:
        lp, lg, la = lp / s, lg / s, la / s
    tp = fp = tn = fn = 0
    for psi_n, gat_n, ae_n, gt, _ in rows:
        phi = lp * psi_n + lg * gat_n + la * ae_n
        flag = phi > PHI_TH
        if   gt and flag:       tp += 1
        elif not gt and flag:   fp += 1
        elif not gt and not flag: tn += 1
        else:                   fn += 1
    e = 1e-12
    num = (tp + e) * (tn + e) - (fp + e) * (fn + e)
    den = math.sqrt((tp+fp+e)*(tp+fn+e)*(tn+fp+e)*(tn+fn+e))
    mcc = num / den
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return mcc, fpr, (tp, fp, tn, fn)


# ---- (0) validate current weights reproduce the sim -----------------------
# also cross-check phi reconstruction against logged phi
err = max(abs((CUR[0]*p + CUR[1]*g + CUR[2]*a) - phi)
          for (p, g, a, _, phi) in rows)
cm_mcc, cm_fpr, cm = mcc_fpr(*CUR)
print(f"\n[validate] max|phi_recomputed - phi_logged| = {err:.2e}  (should be ~0)")
print(f"[validate] current lambda={CUR} -> MCC={cm_mcc:.4f} FPR={cm_fpr:.4f}  "
      f"TP={cm[0]} FP={cm[1]} TN={cm[2]} FN={cm[3]}")
print(f"           (sim reported MCC_full=0.6490 FPR_full=0.0286 — should match)")

# ---- (1) full simplex grid -------------------------------------------------
STEP = 0.05
grid = []
n = int(round(1.0 / STEP))
for i in range(n + 1):
    for j in range(n + 1 - i):
        lp = i * STEP
        lg = j * STEP
        la = 1.0 - lp - lg
        if la < -1e-9:
            continue
        la = max(0.0, la)
        mcc, fpr, cm = mcc_fpr(lp, lg, la)
        grid.append((mcc, fpr, lp, lg, la, cm))

# best MCC overall
grid.sort(key=lambda r: -r[0])
print("\n=== TOP 8 by MCC (any FPR) ===")
print(f"{'lp(psi)':>8}{'lg(gat)':>8}{'la(ae)':>8}{'MCC':>8}{'FPR':>8}")
for mcc, fpr, lp, lg, la, cm in grid[:8]:
    print(f"{lp:8.2f}{lg:8.2f}{la:8.2f}{mcc:8.4f}{fpr:8.4f}")

# best MCC with FPR<=0.05 (paper operating constraint)
cap = 0.05
ok = [r for r in grid if r[1] <= cap]
ok.sort(key=lambda r: -r[0])
print(f"\n=== TOP 8 by MCC with FPR<= {cap} ===")
print(f"{'lp(psi)':>8}{'lg(gat)':>8}{'la(ae)':>8}{'MCC':>8}{'FPR':>8}")
for mcc, fpr, lp, lg, la, cm in ok[:8]:
    print(f"{lp:8.2f}{lg:8.2f}{la:8.2f}{mcc:8.4f}{fpr:8.4f}")

print(f"\nbaselines to beat @t=60: B2 GAT MCC_full=0.6946  B3 AE MCC_full=0.6667")
print(f"current fusion:            MCC_full=0.6490  (loses to both)")
