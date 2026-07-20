#!/usr/bin/env python3
"""
sig_weights_offline.py — sir's Change 1 (attack-conditioned signature weights).

For each attack class k, learn a 9-dim signature reliability weight vector
w_s^(k) (w_s>=0, sum=1) that maximises the eps-MCC of the rule-based decision
  psi_i = sum_s w_s^(k) * bit_s(sig_mask)   >   psi_th
against is_poisoned — i.e. up-weight the signatures that fire on that attack's
poisoned beacons and suppress signatures that don't (or that fire on honest
beacons, which currently add FP). Also learns ONE aggregate vector w_s (all
attacks pooled) for the lightweight mode / low-confidence fallback.

Writes the sets back into models/<scen>/fusion_weights.json:
  "sig_weight_sets": [{"attack":k, "w":[9]}...]   (full mode)
  "sig_weight_global": [9]                          (lightweight / fallback)

Usage: python3 sig_weights_offline.py [scen=urban] [pens=40,60]
"""
import sys, os, json, math
import numpy as np, pandas as pd
from scipy.optimize import minimize

SCEN = sys.argv[1] if len(sys.argv) > 1 else "urban"
PENS = (sys.argv[2].split(",") if len(sys.argv) > 2 else ["40", "60"])
ROOT = os.path.dirname(os.path.abspath(__file__))
ML   = os.path.join(ROOT, "analytics", "ml", "models", SCEN)
DS=os.environ.get("MPTD_DS_ROOT","/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility")+f"/{SCEN}"
SIG  = ["TP-S1","TP-S2","TP-S3","TP-S4","TP-S5","MP-S1","MP-S2","MP-S3","MP-S4"]
W_CUR = np.array([.15,.10,.10,.15,.15,.15,.05,.10,.05])   # current global SIG_WEIGHTS (C++)
PSI_TH, EPS = 0.09, 1e-12


def emcc(flag, gt):
    tp=np.sum(flag&gt); fp=np.sum(flag&~gt); tn=np.sum(~flag&~gt); fn=np.sum(~flag&gt)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS)
    den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    fpr=fp/(fp+tn) if (fp+tn) else 0.0
    return num/den, fpr, (int(tp),int(fp),int(tn),int(fn))


def hard_mcc(w, bits, gt):
    psi = bits @ w
    return emcc(psi > PSI_TH, gt)


def learn_w(bits, gt):
    """Max eps-MCC over the simplex {w>=0, sum w = 1}. Robust to the piecewise-
    constant hard-threshold surface: seed with (a) current global weights,
    (b) separation-proportional weights, (c) one-hot on each positively-separating
    signature, (d) uniform; refine each with SLSQP on a smoothed surrogate; then
    pick the candidate with the best HARD eps-MCC."""
    if gt.sum()==0 or (~gt).sum()==0 or len(bits)<8:
        return W_CUR.copy(), None
    P=bits[gt].mean(0); H=bits[~gt].mean(0); sep=np.clip(P-H, 0, None)
    seeds=[W_CUR.copy(), np.full(9,1/9)]
    if sep.sum()>0: seeds.append(sep/sep.sum())
    for s in range(9):
        if sep[s]>0:
            e=np.full(9,1e-3); e[s]=1.0; seeds.append(e/e.sum())
    cons=[{"type":"eq","fun":lambda x:x.sum()-1.0}]; bnds=[(0.0,1.0)]*9
    def smooth_neg(x):                       # smoothed -MCC surrogate for gradients
        psi=bits@x; z=1/(1+np.exp(-(psi-PSI_TH)/0.02))
        tp=np.sum(z[gt]); fp=np.sum(z[~gt]); fn=np.sum(1-z[gt]); tn=np.sum(1-z[~gt])
        num=tp*tn-fp*fn; den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS)+EPS)
        return -num/den
    cands=list(seeds)
    for x0 in seeds:
        try:
            r=minimize(smooth_neg,x0,method="SLSQP",bounds=bnds,constraints=cons,
                       options={"maxiter":200,"ftol":1e-9})
            x=np.clip(r.x,0,None); cands.append(x/x.sum() if x.sum()>0 else x0)
        except Exception: pass
    best=None
    for x in cands:
        m,fpr,cm=hard_mcc(x,bits,gt)
        if best is None or m>best[0]: best=(m,fpr,cm,x)
    return best[3]/best[3].sum(), (best[0],best[1],best[2])


def load_bits(a):
    parts=[pd.read_csv(f"{DS}/a{a}_p{p}/beacon_log.csv") for p in PENS
           if os.path.isfile(f"{DS}/a{a}_p{p}/beacon_log.csv")]
    if not parts: return None,None
    d=pd.concat(parts,ignore_index=True)
    sm=d.sig_mask.fillna(0).astype(np.int64).values
    # Speed-bound signature folded into TP-S3 (bit 2): reported speed > s_max.
    # Mirrors the C++ change (08_detection_engine.h). Env-gated for reproducibility.
    if os.environ.get("MPTD_SPEED_BOUND")=="1":
        sm = sm | ((d.speed.values > float(os.environ.get("MPTD_SMAX","33.33"))).astype(np.int64) << 2)
    bits=np.stack([((sm>>b)&1) for b in range(9)],1).astype(float)
    gt=d.is_poisoned.values==1
    return bits,gt


print(f"[sig-weights] scen={SCEN} pens={PENS}  (baseline = current global weights)")
sets=[]; allb=[]; allg=[]
for a in range(1,8):
    bits,gt=load_bits(a)
    if bits is None: print(f"  a{a}: no data"); sets.append({"attack":a,"w":W_CUR.tolist()}); continue
    allb.append(bits); allg.append(gt)
    w,info=learn_w(bits,gt)
    m_cur,fpr_cur,_=hard_mcc(W_CUR,bits,gt)
    top=np.argsort(-w)[:3]
    ts=", ".join(f"{SIG[i]}={w[i]:.2f}" for i in top)
    if info: print(f"  a{a}: psi-MCC {m_cur:.3f}→{info[0]:.3f} (FPR {fpr_cur:.3f}→{info[1]:.3f})  top: {ts}")
    sets.append({"attack":a,"w":[round(float(x),4) for x in w]})

# aggregate (lightweight / fallback) — all attacks pooled
if allb:
    B=np.vstack(allb); G=np.concatenate(allg)
    wg,info=learn_w(B,G); m_cur,_,_=hard_mcc(W_CUR,B,G)
    print(f"  GLOBAL: psi-MCC {m_cur:.3f}→{(info[0] if info else float('nan')):.3f}  top: "
          + ", ".join(f"{SIG[i]}={wg[i]:.2f}" for i in np.argsort(-wg)[:3]))
    wg=[round(float(x),4) for x in wg]
else:
    wg=W_CUR.tolist()

out=f"{ML}/fusion_weights.json"; blob=json.load(open(out))
blob["sig_weight_sets"]=sets
blob["sig_weight_global"]=wg
blob["_sig_note"]=f"sir Change1 per-attack signature weights, offline eps-MCC on {SCEN} G50 pens {PENS}"
if os.path.exists(out): os.replace(out,out+".bak_pre_sigw")
json.dump(blob,open(out,"w"),indent=2)
print(f"[sig-weights] wrote sig_weight_sets + sig_weight_global into {out}")
