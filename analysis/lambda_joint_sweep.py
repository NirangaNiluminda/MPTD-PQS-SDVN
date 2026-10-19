#!/usr/bin/env python3
"""
lambda_joint_sweep.py — re-derive fusion weights lambda JOINTLY across attacks.

Reads attack{1..7}_full.log (mode-0 FUSION-RSU lines) from a run dir, reconstructs
the normalized tier scores (psi_n, gat_n, ae_n) + gt label per window, then sweeps
lambda over the simplex. For each lambda it computes per-attack MCC and reports the
lambda that maximizes (a) the MEAN MCC across attacks and (b) the WORST-CASE (min)
MCC across attacks — the robust choice that forces every tier to earn its weight
where it actually helps (Sybil/stealth), not just where the composite already wins.

Per-attack FPR<=0.05 is enforced as an operating constraint.

Usage: python3 lambda_joint_sweep.py <run_dir> [PSI_TH] [THETA_S] [PHI_TH]
"""
import sys, re, math, glob, os

RUN    = sys.argv[1]
PSI_TH = float(sys.argv[2]) if len(sys.argv) > 2 else 0.09
THETA_S= float(sys.argv[3]) if len(sys.argv) > 3 else 7.555182
PHI_TH = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
CUR    = (0.55, 0.25, 0.20)

pat = re.compile(
    r"psi=([-\d.]+)\s+S=([-\d.]+)\s+ae_norm=([-\d.]+).*?gt_pois=([01])")

# per-attack rows
attacks = {}
for path in sorted(glob.glob(os.path.join(RUN, "attack*_full.log"))):
    a = re.search(r"attack(\d+)_full", path).group(1)
    rows = []
    for line in open(path):
        if "FUSION-RSU" not in line:
            continue
        m = pat.search(line)
        if not m:
            continue
        psi, S, ae, gt = float(m[1]), float(m[2]), float(m[3]), int(m[4])
        rows.append((min(1.0, max(0.0, psi/PSI_TH)),
                     min(1.0, max(0.0, S/THETA_S)),
                     min(1.0, max(0.0, ae)), gt))
    if rows:
        attacks[a] = rows
        pos = sum(r[3] for r in rows)
        print(f"attack {a}: {len(rows)} windows, {pos} poisoned, {len(rows)-pos} clean")

if not attacks:
    print("no FUSION logs found — nothing to sweep"); sys.exit(1)


def mcc_fpr(rows, lp, lg, la):
    s = lp + lg + la
    if s > 1e-9:
        lp, lg, la = lp/s, lg/s, la/s
    tp = fp = tn = fn = 0
    for p, g, a, gt in rows:
        flag = (lp*p + lg*g + la*a) > PHI_TH
        if   gt and flag:        tp += 1
        elif not gt and flag:    fp += 1
        elif not gt and not flag: tn += 1
        else:                    fn += 1
    e = 1e-12
    num = (tp+e)*(tn+e) - (fp+e)*(fn+e)
    den = math.sqrt((tp+fp+e)*(tp+fn+e)*(tn+fp+e)*(tn+fn+e))
    fpr = fp/(fp+tn) if (fp+tn) else 0.0
    return num/den, fpr


def eval_lambda(lp, lg, la):
    per = {a: mcc_fpr(rows, lp, lg, la) for a, rows in attacks.items()}
    mccs = [v[0] for v in per.values()]
    fprs = [v[1] for v in per.values()]
    return sum(mccs)/len(mccs), min(mccs), max(fprs), per


# baseline: current lambda
mean_c, worst_c, maxfpr_c, per_c = eval_lambda(*CUR)
print(f"\n[current λ={CUR}]  meanMCC={mean_c:.4f}  worstMCC={worst_c:.4f}  maxFPR={maxfpr_c:.4f}")
for a in sorted(per_c):
    print(f"    attack {a}: MCC={per_c[a][0]:.4f} FPR={per_c[a][1]:.4f}")

# simplex grid
STEP = 0.05
n = int(round(1.0/STEP))
grid = []
for i in range(n+1):
    for j in range(n+1-i):
        lp, lg = i*STEP, j*STEP
        la = max(0.0, 1.0 - lp - lg)
        mean_m, worst_m, maxfpr, _ = eval_lambda(lp, lg, la)
        grid.append((mean_m, worst_m, maxfpr, lp, lg, la))

print("\n=== TOP 10 by MEAN MCC across attacks (FPR shown) ===")
for mean_m, worst_m, maxfpr, lp, lg, la in sorted(grid, key=lambda r: -r[0])[:10]:
    print(f"  λ=({lp:.2f},{lg:.2f},{la:.2f})  mean={mean_m:.4f}  worst={worst_m:.4f}  maxFPR={maxfpr:.4f}")

print("\n=== TOP 10 by WORST-CASE MCC (robust), maxFPR<=0.05 ===")
ok = [r for r in grid if r[2] <= 0.05]
for mean_m, worst_m, maxfpr, lp, lg, la in sorted(ok, key=lambda r: -r[1])[:10]:
    print(f"  λ=({lp:.2f},{lg:.2f},{la:.2f})  worst={worst_m:.4f}  mean={mean_m:.4f}  maxFPR={maxfpr:.4f}")

print("\nGuidance: a GOOD re-derived λ keeps lg,la meaningfully > 0 (tiers earn weight")
print("on attacks where ψ is blind). If the best λ still zeros GAT/AE across ALL")
print("attacks, that is evidence the ML tiers don't help on THIS attack set — a")
print("finding, not a tuning target. Do not deploy a degenerate (1,0,0).")
