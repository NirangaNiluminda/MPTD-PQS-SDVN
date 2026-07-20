#!/usr/bin/env python3
"""
lambda_per_attack_slsqp.py — sir's Change 5: K independent SLSQP optimisations,
one per attack class, to derive the attack-conditioned fusion weights λ^(k).

Reads a [FUSION-RSU ...] log per attack (each single-attack sim = one class's
Phase-2 partition), reconstructs the normalised tier scores exactly as
fuse_scores() does (ψ/ψ_th, S/θ_S, ae_norm already in [0,1]), then for each
attack solves:
    max_λ  eps-smoothed MCC(Φ>Φ_th)      s.t. Σλ=1, λ_j ≥ 0.05
via SLSQP. Writes the 7 λ-sets to models/<scen>/fusion_weights.json (replacing
the seed priors). ε-MCC matches Eq 4.1 (ε=1e-12).

Usage: python3 lambda_per_attack_slsqp.py <logdir> [scen=urban] [PSI_TH=0.09] [THETA_S] [PHI_TH=0.5]
  <logdir> holds fusion_a1.log .. fusion_a7.log
"""
import sys, os, re, json, math
import numpy as np
from scipy.optimize import minimize

LOGDIR = sys.argv[1]
SCEN   = sys.argv[2] if len(sys.argv) > 2 else "urban"
PSI_TH = float(sys.argv[3]) if len(sys.argv) > 3 else 0.09
ML     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analytics", "ml", "models")
THETA_S = (float(sys.argv[4]) if len(sys.argv) > 4
           else float(open(os.path.join(ML, SCEN, "theta_s.txt")).read().strip()))
PHI_TH = float(sys.argv[5]) if len(sys.argv) > 5 else 0.5
LAM_MIN = 0.05
EPS = 1e-12

pat = re.compile(r"psi=([-\d.]+)\s+S=([-\d.]+)\s+ae_norm=([-\d.]+).*?gt_pois=([01])")


def load_attack(a):
    f = os.path.join(LOGDIR, f"fusion_a{a}.log")
    rows = []
    if not os.path.isfile(f):
        return np.zeros((0, 4))
    for line in open(f):
        if "FUSION-RSU" not in line:
            continue
        m = pat.search(line)
        if not m:
            continue
        psi, S, ae, gt = float(m[1]), float(m[2]), float(m[3]), int(m[4])
        rows.append((min(1.0, max(0.0, psi / PSI_TH)),
                     min(1.0, max(0.0, S / THETA_S)),
                     min(1.0, max(0.0, ae)), gt))
    return np.array(rows) if rows else np.zeros((0, 4))


def mcc(lam, R):
    lp, lg, la = lam
    phi = lp * R[:, 0] + lg * R[:, 1] + la * R[:, 2]
    flag = phi > PHI_TH
    gt = R[:, 3] > 0.5
    tp = np.sum(flag & gt);  fp = np.sum(flag & ~gt)
    tn = np.sum(~flag & ~gt); fn = np.sum(~flag & gt)
    num = (tp + EPS) * (tn + EPS) - (fp + EPS) * (fn + EPS)
    den = math.sqrt((tp + fp + EPS) * (tp + fn + EPS) * (tn + fp + EPS) * (tn + fn + EPS))
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return num / den, fpr, (int(tp), int(fp), int(tn), int(fn))


def solve(R):
    if len(R) < 4 or R[:, 3].sum() == 0:            # no signal → keep global mean
        return None
    best = None
    cons = [{"type": "eq", "fun": lambda x: x.sum() - 1.0}]
    bnds = [(LAM_MIN, 1.0)] * 3
    for x0 in ([0.45, 0.35, 0.20], [0.6, 0.2, 0.2], [0.2, 0.6, 0.2], [0.34, 0.33, 0.33]):
        r = minimize(lambda x: -mcc(x, R)[0], x0, method="SLSQP", bounds=bnds,
                     constraints=cons, options={"maxiter": 200, "ftol": 1e-9})
        m, _, _ = mcc(r.x, R)
        if best is None or m > best[0]:
            best = (m, r.x)
    return best[1] / best[1].sum()


sets, gp, gg, ga = [], 0.0, 0.0, 0.0
GLOBAL = np.array([0.45, 0.35, 0.20])
print(f"[slsqp] scen={SCEN} PSI_TH={PSI_TH} THETA_S={THETA_S:.3f} PHI_TH={PHI_TH}")
for a in range(1, 8):
    R = load_attack(a)
    lam = solve(R)
    if lam is None:
        lam = GLOBAL.copy()
        note = f"(fallback global; n={len(R)} pois={int(R[:,3].sum()) if len(R) else 0})"
    else:
        m, fpr, cm = mcc(lam, R)
        note = f"MCC={m:.3f} FPR={fpr:.3f} TP/FP/TN/FN={cm} n={len(R)}"
    p, g, ae = float(lam[0]), float(lam[1]), float(lam[2])
    sets.append({"attack": a, "psi": round(p, 4), "gat": round(g, 4), "ae": round(ae, 4)})
    gp += p; gg += g; ga += ae
    print(f"  a{a}: λ=(ψ {p:.3f}, gat {g:.3f}, ae {ae:.3f})  {note}")

n = len(sets)
blob = {"phi_threshold": PHI_TH,
        "lambda_psi": round(gp / n, 4), "lambda_gat": round(gg / n, 4), "lambda_ae": round(ga / n, 4),
        "lambda_sets": sets,
        "_note": f"per-attack SLSQP (sir Change 5) on {SCEN} Phase-2 FUSION logs {LOGDIR}"}
out = os.path.join(ML, SCEN, "fusion_weights.json")
if os.path.exists(out):
    os.replace(out, out + ".bak_pre_slsqp")
json.dump(blob, open(out, "w"), indent=2)
print(f"[slsqp] wrote {out}")
