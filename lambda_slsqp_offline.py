#!/usr/bin/env python3
"""
lambda_slsqp_offline.py — sir's Change 5, robust version.

Reconstructs the 3 fusion tier-scores (ψ_n, gat_n, ae_n) + gt for EVERY vehicle
in the G50 dataset per attack, using the DEPLOYED GAT + LSTM-AE ONNX + scaler
(exactly the C++ fuse_scores inputs), then runs K independent SLSQP fits to
derive λ^(k) maximising ε-smoothed MCC (Σλ=1, λ_j≥0.05). Guarantees both-class
coverage per attack (the FUSION stdout log did not). Writes models/<scen>/fusion_weights.json.

Usage: python3 lambda_slsqp_offline.py [scen=urban] [pens=40,60]
"""
import sys, os, json, math
import numpy as np, pandas as pd, onnxruntime as ort
from scipy.optimize import minimize
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "analytics", "ml"))
from gat_detector import build_edge_index, SIG_BITS

SCEN = sys.argv[1] if len(sys.argv) > 1 else "urban"
PENS = (sys.argv[2].split(",") if len(sys.argv) > 2 else ["40", "60"])
ML   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analytics", "ml", "models")
DS   = f"/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility/{SCEN}"
FEAT = ["pos_x", "pos_y", "speed", "heading", "accel"]
PSI_TH, PHI_TH, LAM_MIN, EPS = 0.09, 0.5, 0.05, 1e-12
# No hard FPR cap on the λ weights: sir's Change 5/8 spec constrains λ only by
# Σλ=1, λ_j≥0.05 and a positive-class weight (penalise FNs) — it favours recall,
# not an FPR ceiling. The paper's FPR≤0.05 is for single-threshold calibration
# (ψ_th/Φ_th on clean traces), NOT the fusion weights. Objective = max ε-MCC,
# which self-balances FP via its FP term. (Cap kept as an overridable knob;
# 1.0 = effectively no cap.) FPR reported per attack for full transparency.
FPR_CAP = float(sys.argv[6]) if len(sys.argv) > 6 else 1.0

sc = json.load(open(f"{ML}/{SCEN}/scaler.json"))
MEAN = np.array(sc["mean"]); SCALE = np.array(sc["scale"])          # 6-dim
THETA_S    = float(open(f"{ML}/{SCEN}/theta_s.txt").read().strip())
THETA_AE   = float(open(f"{ML}/{SCEN}/theta_ae.txt").read().strip())
THETA_HEAD = float(open(f"{ML}/{SCEN}/theta_head.txt").read().strip())  # head-detection tier
gat = ort.InferenceSession(f"{ML}/{SCEN}/gat_model.onnx")
ae  = ort.InferenceSession(f"{ML}/{SCEN}/lstm_ae_model.onnx")
W = 50 if SCEN=="urban" else 10


def tier_scores(d):
    """Return arrays psi_n, gat_n, ae_n, gt aligned per (vehicle,beacon) with a
    full 10-window (so ae is defined)."""
    d = d.sort_values(["vehicle_id", "sim_time"]).reset_index(drop=True)
    d["_tick"] = (d.sim_time / 0.1).round().astype(int)
    # 1) GAT S_i per (tick,vid)
    gat_n = {}
    for _, g in d.groupby("_tick"):
        if len(g) < 2: continue
        raw = g[FEAT].values.astype(np.float32)
        kin = ((raw - MEAN[:5]) / np.where(SCALE[:5] == 0, 1, SCALE[:5])).astype(np.float32)
        tau = np.ones((len(g), 1), np.float32)
        psi = g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1, 1)
        sm  = g["sig_mask"].fillna(0).values.astype(np.int64)
        bits = np.stack([((sm >> b) & 1) for b in range(SIG_BITS)], 1).astype(np.float32)
        x = np.hstack([kin, tau, psi, bits]).astype(np.float32)
        ei = build_edge_index(raw[:, :2].astype(np.float32), raw[:, 3].astype(np.float32),
                              raw[:, 2].astype(np.float32)).numpy().astype(np.int64)
        # GAT tier = spatial anomaly S_i / θ_S. (The head-detection variant
        # max_k ŷ^(k)/θ_head was tested and REJECTED: SLSQP drove its λ to the
        # 0.05 floor for 6/7 attacks — the heads are a good router but not a
        # detection tier; a5/a7 are control-plane with no beacon signature.)
        S = gat.run(None, {"x": x, "edge_index": ei})[0].reshape(-1)
        for i, (_, row) in enumerate(g.iterrows()):
            gat_n[(row._tick, row.vehicle_id)] = min(1.0, max(0.0, float(S[i]) / THETA_S))
    # 2) per-vehicle 10-window AE + assemble rows
    out = []
    for vid, g in d.groupby("vehicle_id"):
        g = g.reset_index(drop=True)
        arr = g[FEAT].values.astype(np.float32)
        win6 = np.hstack([arr, np.ones((len(g), 1), np.float32)])       # +tau
        win6 = (win6 - MEAN) / np.where(SCALE == 0, 1, SCALE)
        for j in range(W - 1, len(g)):
            key = (int(g._tick[j]), vid)
            if key not in gat_n: continue
            w = win6[j - W + 1:j + 1].astype(np.float32)[None]           # (1,10,6)
            rec = ae.run(None, {"x": w})[0]
            ae_err = float(np.mean((rec - w) ** 2))
            out.append((min(1.0, max(0.0, float(g.psi_score[j]) / PSI_TH)),
                        gat_n[key], min(1.0, max(0.0, ae_err / THETA_AE)),
                        int(g.is_poisoned[j])))
    return np.array(out) if out else np.zeros((0, 4))


def mcc(lam, R):
    phi = lam[0]*R[:,0] + lam[1]*R[:,1] + lam[2]*R[:,2]
    flag = phi > PHI_TH; gt = R[:,3] > 0.5
    tp=np.sum(flag&gt); fp=np.sum(flag&~gt); tn=np.sum(~flag&~gt); fn=np.sum(~flag&gt)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS)
    den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    fpr=fp/(fp+tn) if (fp+tn) else 0.0
    return num/den, fpr, (int(tp),int(fp),int(tn),int(fn))


def solve(R):
    """Max MCC s.t. FPR ≤ FPR_CAP (paper operating constraint). SLSQP from seeds
    (sir's K SLSQP) UNION a simplex grid, because the hard-threshold MCC/FPR
    surface is piecewise-constant (non-smooth) — the grid guarantees the best
    FEASIBLE λ is found. Falls back to the min-FPR λ if no point meets the cap.
    Returns (λ, feasible_bool)."""
    if len(R) < 8 or R[:,3].sum()==0 or (R[:,3]==0).sum()==0:
        return None
    cons_eq  = {"type":"eq",   "fun": lambda x: x.sum()-1.0}
    cons_fpr = {"type":"ineq", "fun": lambda x: FPR_CAP - mcc(x,R)[1]}   # FPR ≤ cap
    bnds = [(LAM_MIN,1.0)]*3
    cands = []
    for x0 in ([.45,.35,.2],[.6,.2,.2],[.2,.6,.2],[.2,.2,.6],[.34,.33,.33]):
        r = minimize(lambda x:-mcc(x,R)[0], x0, method="SLSQP", bounds=bnds,
                     constraints=[cons_eq,cons_fpr], options={"maxiter":300,"ftol":1e-9})
        x = np.clip(r.x, LAM_MIN, None); cands.append(x/x.sum())
    step = 0.05                                    # simplex-grid safeguard
    g = np.round(np.arange(LAM_MIN, 1.0-2*LAM_MIN+1e-9, step), 4)
    for lp in g:
        for lg in g:
            la = round(1.0-lp-lg, 4)
            if la < LAM_MIN-1e-9 or la > 1.0: continue
            cands.append(np.array([lp,lg,la]))
    best = best_feas = None
    for x in cands:
        m, fpr, _ = mcc(x, R)
        if best is None or m > best[0]: best = (m, fpr, x)
        if fpr <= FPR_CAP and (best_feas is None or m > best_feas[0]):
            best_feas = (m, fpr, x)
    if best_feas is not None:
        return best_feas[2]/best_feas[2].sum(), True
    return best[2]/best[2].sum(), False     # no feasible λ → keep max-MCC (min achievable FPR noted)


sets, gp, gg, ga = [], 0.0, 0.0, 0.0
GLOBAL=np.array([0.45,0.35,0.20])
print(f"[slsqp-offline] scen={SCEN} pens={PENS} THETA_S={THETA_S:.3f} THETA_AE={THETA_AE:.3f}")
for a in range(1,8):
    parts=[pd.read_csv(f"{DS}/a{a}_p{p}/beacon_log.csv") for p in PENS
           if os.path.isfile(f"{DS}/a{a}_p{p}/beacon_log.csv")]
    if not parts: print(f"  a{a}: no data"); sets.append({"attack":a,"psi":.45,"gat":.35,"ae":.20}); gp+=.45;gg+=.35;ga+=.2; continue
    R = np.vstack([tier_scores(p) for p in parts])
    res = solve(R)
    if res is None:
        lam=GLOBAL.copy(); note=f"(fallback no-signal; n={len(R)} pois={int(R[:,3].sum()) if len(R) else 0})"
    else:
        lam, feasible = res
        m,fpr,cm=mcc(lam,R)
        tag = "FPR≤cap" if feasible else f"NO-FEASIBLE(min FPR={fpr:.3f})"
        note=f"MCC={m:.3f} FPR={fpr:.3f} [{tag}] TP/FP/TN/FN={cm} n={len(R)}"
    p,g,e=float(lam[0]),float(lam[1]),float(lam[2])
    sets.append({"attack":a,"psi":round(p,4),"gat":round(g,4),"ae":round(e,4)}); gp+=p;gg+=g;ga+=e
    print(f"  a{a}: λ=(ψ {p:.3f}, gat {g:.3f}, ae {e:.3f})  {note}")

n=len(sets)
blob={"phi_threshold":PHI_TH,"lambda_psi":round(gp/n,4),"lambda_gat":round(gg/n,4),
      "lambda_ae":round(ga/n,4),"lambda_sets":sets,
      "_note":f"per-attack SLSQP (sir Change 5) offline on {SCEN} G50 pens {PENS}"}
out=f"{ML}/{SCEN}/fusion_weights.json"
if os.path.exists(out): os.replace(out,out+".bak_pre_slsqp")
json.dump(blob,open(out,"w"),indent=2)
print(f"[slsqp-offline] wrote {out}")
