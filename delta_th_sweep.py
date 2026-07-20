#!/usr/bin/env python3
"""
delta_th_sweep.py — sir Step 5: calibrate the drift threshold δ_th offline.

δ_th (config delta_th, default 10.0) gates TP-S4 (per-step dead-reckoning residual)
and TP-S5 (cumulative drift over drift_window_k=10 pairs). Both derive purely from
the reported trajectory (pos_x,pos_y,speed,heading,sim_time) already in the beacon
log, so we recompute bits 3/4 at each candidate δ_th WITHOUT re-simulating (the C++
computes exactly this on the received beacon; 08_detection_engine.h:378-408).

For each δ_th ∈ {5,7.5,10,12.5,15}: rebuild sig_mask (keep logged bits 0,1,2,5,6,7,8;
replace bits 3,4), score the lightweight rule ψ=Σ w_s·bit_s > ψ_th with the GLOBAL
weights (δ_th is a lightweight-mode rule threshold), and report ε-MCC / overall FPR
/ honest-only FPR. Pick the δ_th maximising MCC with FPR ≤ 0.05.

Usage: python3 delta_th_sweep.py [attack=2] [pens=40,60]
"""
import sys, os, math
import numpy as np, pandas as pd
A   = int(sys.argv[1]) if len(sys.argv)>1 else 2          # our a2 = sir's a1
PENS= (sys.argv[2].split(",") if len(sys.argv)>2 else ["40","60"])
DS  = "/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility/urban"
SIGW= np.array([.15,.10,.10,.15,.15,.15,.05,.10,.05])      # global SIG_WEIGHTS (C++)
PSI_TH=0.09; K=10; T_b=0.1; EPS=1e-12; GRID=[5.0,7.5,10.0,12.5,15.0]

def residual_and_drift(g):
    """Per-beacon TP-S4 residual + TP-S5 rolling drift_score (C++ 08_detection_engine.h)."""
    g=g.sort_values("sim_time")
    px=g.pos_x.values; py=g.pos_y.values; spd=g.speed.values; hdg=g.heading.values; ts=g.sim_time.values
    n=len(g); res=np.zeros(n); drift=np.zeros(n)
    for j in range(1,n):
        dt=ts[j]-ts[j-1]; dt=T_b if dt<=0 else dt
        pxh=px[j-1]+spd[j-1]*math.cos(hdg[j-1])*dt
        pyh=py[j-1]+spd[j-1]*math.sin(hdg[j-1])*dt
        res[j]=math.hypot(px[j]-pxh, py[j]-pyh)
    for j in range(1,n):
        k=min(K, j)                      # pairs available ending at j
        drift[j]=res[j-k+1:j+1].mean() if k>0 else 0.0
    return res, drift

def emcc(flag,gt):
    tp=np.sum(flag&gt);fp=np.sum(flag&~gt);tn=np.sum(~flag&~gt);fn=np.sum(~flag&gt)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    fpr=fp/(fp+tn) if (fp+tn) else 0.0
    return num/den, fpr

parts=[pd.read_csv(f"{DS}/a{A}_p{p}/beacon_log.csv") for p in PENS if os.path.isfile(f"{DS}/a{A}_p{p}/beacon_log.csv")]
# Beacon logs contain ~2x duplicate (vehicle_id,sim_time) rows; dedup so the offline
# dead-reckoning residual matches the C++ buffer stream (verified bit-exact vs logged).
d=pd.concat(parts,ignore_index=True).drop_duplicates(['vehicle_id','sim_time']).reset_index(drop=True)
# per-vehicle residual/drift, aligned back to rows
d=d.sort_values(["vehicle_id","sim_time"]).reset_index(drop=True)
res=np.zeros(len(d)); drift=np.zeros(len(d))
for vid,g in d.groupby("vehicle_id"):
    r,dr=residual_and_drift(g); res[g.index]=r; drift[g.index]=dr
sm=d.sig_mask.fillna(0).astype(np.int64).values
logbits=np.stack([((sm>>b)&1) for b in range(9)],1).astype(float)
gt=d.is_poisoned.values==1
print(f"[δ_th sweep] a{A} pens={PENS}  n={len(d)} pois={int(gt.sum())}  (current δ_th=10.0)")
print(f"{'δ_th':>6} | {'ψ-MCC':>7} {'FPR':>6} {'FPR_honest':>10} | TP-S4 P/H  TP-S5 P/H")
best=None
for dth in GRID:
    bits=logbits.copy()
    bits[:,3]=(res>dth).astype(float)       # TP-S4
    bits[:,4]=(drift>dth).astype(float)     # TP-S5
    psi=bits@SIGW; flag=psi>PSI_TH
    m,fpr=emcc(flag,gt)
    fpr_h=flag[~gt].mean()
    s4=f"{bits[gt,3].mean():.2f}/{bits[~gt,3].mean():.2f}"; s5=f"{bits[gt,4].mean():.2f}/{bits[~gt,4].mean():.2f}"
    print(f"{dth:>6} | {m:7.3f} {fpr:6.3f} {fpr_h:10.3f} | {s4}  {s5}")
    if fpr<=0.05 and (best is None or m>best[1]): best=(dth,m,fpr)
if best: print(f"\n[δ_th sweep] BEST (FPR≤0.05): δ_th={best[0]}  MCC={best[1]:.3f}  FPR={best[2]:.3f}")
else:    print("\n[δ_th sweep] no δ_th meets FPR≤0.05 — report max-MCC + note")
