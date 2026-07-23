#!/usr/bin/env python3
"""
refit_lambda_combined.py — re-fit the fusion λ (ψ, GAT, AE weights) for the
combined-attack scenario, now that θ_S=55.9 makes the GAT informative. The old
λ (λ_gat=0.19) was fit for the saturated GAT, so it under-weights the now-useful
GAT. We extract the IN-SIM fusion inputs (ψ, GAT-S, AE-err + label) from the
seed-1 calibration FUSION log, normalise with the recalibrated thresholds, and
grid-search λ (simplex, sum=1) to maximise MCC at φ>0.5. Writes the global λ AND
overwrites the per-attack sets (combined = mixed attacks → one consistent λ) in
models/urban_combined/fusion_weights.json. Verify on a held-out seed afterwards.
"""
import sys, os, json, re, numpy as np, math

ROOT = os.path.dirname(os.path.abspath(__file__))
DST  = os.path.join(ROOT, "analytics", "ml", "models", "urban_combined")
LOG  = sys.argv[1]
THETA_S  = float(open(f"{DST}/theta_s.txt").read())
THETA_AE = float(open(f"{DST}/theta_ae.txt").read())
PSI_TH, PHI_TH = 0.09, 0.5

# ── extract in-sim fusion inputs from the FUSION log ──────────────────────────
rx = re.compile(r'psi=([\d.]+) S=([\d.]+) ae_norm=[\d.]+ ae_raw=([\d.]+).*gt_pois=(\d)')
psi, S, ae, y = [], [], [], []
for line in open(LOG):
    m = rx.search(line)
    if not m: continue
    psi.append(float(m.group(1))); S.append(float(m.group(2)))
    ae.append(float(m.group(3)));  y.append(int(m.group(4)))
psi, S, ae, y = map(np.array, (psi, S, ae, y))
print(f"[refit] fusion rows: {len(y)}  clean={int((y==0).sum())} poisoned={int((y==1).sum())}")

psi_n = np.clip(psi / PSI_TH, 0, 1)
gat_n = np.clip(S   / THETA_S, 0, 1)
ae_n  = np.clip(ae  / THETA_AE, 0, 1)

def mcc(pred, yy):
    tp=int(((pred==1)&(yy==1)).sum()); tn=int(((pred==0)&(yy==0)).sum())
    fp=int(((pred==1)&(yy==0)).sum()); fn=int(((pred==0)&(yy==1)).sum())
    d=math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    return (tp*tn-fp*fn)/d if d>0 else 0.0

# ── grid search over the λ simplex (step 0.05) ────────────────────────────────
best=(-2, None)
for lp in np.arange(0, 1.001, 0.05):
    for lg in np.arange(0, 1.001-lp, 0.05):
        la = 1.0 - lp - lg
        if la < -1e-9: continue
        phi = lp*psi_n + lg*gat_n + la*ae_n
        m = mcc((phi > PHI_TH).astype(int), y)
        if m > best[0]: best=(m, (round(lp,3), round(lg,3), round(la,3)))
print(f"[refit] best λ (ψ,GAT,AE) = {best[1]}  train-MCC={best[0]:.4f}")
lp, lg, la = best[1]
# also report the OLD λ for contrast
old = json.load(open(f"{DST}/fusion_weights.json"))
print(f"[refit] old global λ = ψ{old.get('lambda_psi')},GAT{old.get('lambda_gat')},AE{old.get('lambda_ae')}")

# ── write: global λ + overwrite per-attack sets with the same (combined=mixed) ─
old["lambda_psi"], old["lambda_gat"], old["lambda_ae"] = lp, lg, la
if "lambda_sets" in old:
    for s in old["lambda_sets"]:
        s["psi"], s["gat"], s["ae"] = lp, lg, la
json.dump(old, open(f"{DST}/fusion_weights.json", "w"), indent=2)
print(f"[refit] wrote {DST}/fusion_weights.json  (global + all per-attack sets = {best[1]})")
