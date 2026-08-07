#!/usr/bin/env python3
"""
lambda_refit_combined.py — refit the GLOBAL lambda_gat for urban_combined (Round 5
D1-D6 finding: D1~D4~D5~D6, GAT/AE add no measurable contribution in combined mode).

Restricted to khat=-1 (fallback/global-weight) rows only. D4/D6 logs showed ~48% of
rows use attack-conditioned lambda_sets (different lambda_psi/gat/ae per predicted
type) instead of the flat global (0.5071,0.1857,0.3071) triple. lambda_refit_ab3.py's
algebraic gat_norm recovery (phi_logged = L_PSI*psi + L_GAT*gat_norm + L_AE*ae_norm)
is only valid when the flat global triple was actually used to compute phi_logged for
that row. Fitting on the mixed population would misattribute gat_norm for the
attack-conditioned rows. khat=-1 rows are exactly where the global triple applied
unambiguously — also the single largest bucket (52.3% of D6's population), so this is
the right target for a global-fallback-weight fix regardless.

Per-attack lambda_sets recalibration is a separate, larger task (7 sets, not 1
parameter) — out of scope here.

Data: D6 (full mode) logs, seeds 1/2/3, already collected for the D1-D6 ablation batch
(ρ_a=0.60, combined attack, real topology). Same protocol as lambda_refit_ab3.py:
fit seeds 1+2, validate on held-out seed 3.
"""
import re, os, math
import numpy as np

D = "/tmp/claude-1001/-home-sdvn-mobility-flooding-Niranga-MPTD-PQS-SDVN/42ad9abc-b50e-48e5-a8a0-f709b9d1f263/scratchpad"
PHI_TH = 0.5
L_PSI, L_GAT, L_AE = 0.5071, 0.1857, 0.3071   # deployed global set (urban_combined/fusion_weights.json)
RX = re.compile(r'psi=([0-9.]+).*?S=([0-9.eE+-]+).*?ae_norm=([0-9.]+).*?ae_raw=([0-9.eE+-]+)'
                r'.*?gt_pois=(\d).*?phi=([0-9.eE+-]+).*?khat=(-?\d+).*?full_anom=(YES|no)')


def load(seed):
    f = f"{D}/D6_seed{seed}.log"
    if not os.path.exists(f):
        return None
    psi, S, an, y, phi = [], [], [], [], []
    for ln in open(f, errors="ignore"):
        if not ln.startswith("[FUSION-RSU"):
            continue
        m = RX.search(ln)
        if not m:
            continue
        if int(m.group(7)) != -1:   # only global-weight (fallback) rows are valid here
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
    base = L_PSI * psi + L_AE * an
    gat_norm = (phi_logged - base) / L_GAT
    return base * (1.0 - lam_gat) / (1.0 - L_GAT) + lam_gat * gat_norm


def phi_ab3(psi, an, phi_logged):
    base = L_PSI * psi + L_AE * an
    return base / (1.0 - L_GAT)


train = [(s, load(s)) for s in (1, 2)]
train = [(s, d) for s, d in train if d is not None]
test  = [(s, load(s)) for s in (3,)]
test  = [(s, d) for s, d in test if d is not None]
print(f"[lambda-refit-combined] train seeds={[s for s,_ in train]}  test seeds={[s for s,_ in test]}")
print(f"[lambda-refit-combined] fallback-only row counts: " +
      ", ".join(f"s{s}={len(d[3])}" for s, d in train + test))
if not train or not test:
    raise SystemExit("missing D6_seed{1,2,3}.log — run the D1-D6 batch first")

grid = np.arange(0.20, 0.96, 0.025)
scores = []
for lam in grid:
    ms = []
    for s, (psi, S, an, y, phi) in train:
        m, *_ = mcc(phi_with(lam, psi, an, phi) > PHI_TH, y)
        ms.append(m)
    scores.append(np.mean(ms))
best_lam = float(grid[int(np.argmax(scores))])
print(f"[lambda-refit-combined] TRAIN(seeds1+2) best lambda_gat = {best_lam:.3f} "
      f"(mean MCC {max(scores):.4f}); deployed = {L_GAT}")
print("  train curve: " + "  ".join(f"{l:.2f}:{s:.3f}" for l, s in zip(grid, scores)
                                    if abs((l*1000) % 50) < 1e-6))

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
print(f"    {'VALID: GAT contributes' if np.mean(deltas) > 0.01 else 'no contribution'}")

d0 = []
for s, (psi, S, an, y, phi) in test:
    m0, *_ = mcc(phi > PHI_TH, y)
    ma, *_ = mcc(phi_ab3(psi, an, phi) > PHI_TH, y)
    d0.append(m0 - ma)
print(f"    sanity @ deployed lambda_gat={L_GAT}: mean dMCC = {np.mean(d0):+.4f} (expect ~0)")
print(f"\nRECOMMEND global lambda set = (psi {L_PSI*(1-best_lam)/(1-L_GAT):.3f}, "
      f"gat {best_lam:.3f}, ae {L_AE*(1-best_lam)/(1-L_GAT):.3f})")
print(f"  i.e. deploy lambda_gat={best_lam:.3f} to urban_combined/fusion_weights.json global triple")
