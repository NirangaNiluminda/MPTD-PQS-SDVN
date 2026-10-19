#!/usr/bin/env python3
"""
mp_s2_sweep.py — sir Step 6: calibrate MP-S2 timing sync (τ_sync, ρ_sync) offline.

MP-S2 (paper Eq 3.17, 08_detection_engine.h:464-544) fires bit 6 when, over the
last K≤8 beacons of identity a, the fraction whose nearest-in-time beacon of a
co-located identity b (≤R_max_comm) lands within τ_sync exceeds ρ_sync. All inputs
(timestamps ≤10µs precision, positions) are in the beacon log, so we replicate the
C++ streaming buffer exactly and sweep (τ_sync,ρ_sync) WITHOUT re-simulating.

Validates offline bit6 vs the logged bit6 at the current (τ=1ms,ρ=0.8) first;
then sweeps τ∈{1,2,5,10}ms × ρ∈{0.6,0.7,0.8,0.9} and reports the ψ-tier ε-MCC/FPR
(global weights) for each, picking the max-MCC combo with FPR≤0.05.

Usage: python3 mp_s2_sweep.py [attack=4] [pens=40,60]
"""
import sys, os, math
import numpy as np, pandas as pd
from collections import deque, defaultdict
A   = int(sys.argv[1]) if len(sys.argv)>1 else 4          # our a4 = sir's a5 (impersonation)
PENS= (sys.argv[2].split(",") if len(sys.argv)>2 else ["40","60"])
DS  = "/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility/urban"
SIGW= np.array([.15,.10,.10,.15,.15,.15,.05,.10,.05]); PSI_TH=0.09; EPS=1e-12
R_MAX=270.0; HIST=20; K_MIN=3; K_MAX=8; NEAR_T=0.050
TAUS=[0.001,0.002,0.005,0.010]; RHOS=[0.6,0.7,0.8,0.9]

parts=[pd.read_csv(f"{DS}/a{A}_p{p}/beacon_log.csv") for p in PENS if os.path.isfile(f"{DS}/a{A}_p{p}/beacon_log.csv")]
d=pd.concat(parts,ignore_index=True).drop_duplicates(['vehicle_id','sim_time']).reset_index(drop=True)
d=d.sort_values("sim_time").reset_index(drop=True)   # global receive order (C++ processes in time order)
sm=d.sig_mask.fillna(0).astype(int).values
logbits=np.stack([((sm>>b)&1) for b in range(9)],1).astype(float)
gt=d.is_poisoned.values==1
N=len(d)

# streaming per-vehicle deque of (t,x,y), last HIST; compute per-beacon best_dt lists
buf=defaultdict(lambda: deque(maxlen=HIST))
# for each beacon store: list over co-located others of np.array(best_dt[K])
bestdt_per_beacon=[None]*N
vids=d.vehicle_id.values; ts=d.sim_time.values; xs=d.pos_x.values; ys=d.pos_y.values
for j in range(N):
    vid=vids[j]; buf[vid].append((ts[j],xs[j],ys[j]))
    va=buf[vid]
    if len(va)<K_MIN: continue
    ax,ay=va[-1][1],va[-1][2]
    K=min(len(va),K_MAX)
    a_times=[va[-1-k][0] for k in range(K)]
    others=[]
    for ov,vb in buf.items():
        if ov==vid or len(vb)<K_MIN: continue
        if math.hypot(vb[-1][1]-ax, vb[-1][2]-ay) >= R_MAX: continue
        b_times=[vb[-1-kk][0] for kk in range(min(len(vb),HIST))]
        bd=[]
        for ta in a_times:
            best=NEAR_T; found=False
            for tb in b_times:
                dd=abs(ta-tb)
                if dd<best: best=dd; found=True
            if found: bd.append(best)
        if len(bd)>=K_MIN: others.append(np.array(bd))
    bestdt_per_beacon[j]=others

def fire_bits(tau,rho):
    out=np.zeros(N)
    for j in range(N):
        ol=bestdt_per_beacon[j]
        if not ol: continue
        for bd in ol:
            frac=(bd<tau).mean()
            if frac>rho: out[j]=1.0; break
    return out

def emcc(flag,g):
    tp=np.sum(flag&g);fp=np.sum(flag&~g);tn=np.sum(~flag&~g);fn=np.sum(~flag&g)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.0)

# validate at current config
v=fire_bits(0.001,0.8)
print(f"[MP-S2 sweep] a{A} pens={PENS} n={N} pois={int(gt.sum())}")
print(f"VALIDATE @τ=1ms,ρ=0.8: offline bit6 vs logged agreement={ (v==logbits[:,6]).mean():.3f}  "
      f"offline P/H={v[gt].mean():.3f}/{v[~gt].mean():.3f}  logged P/H={logbits[gt,6].mean():.3f}/{logbits[~gt,6].mean():.3f}")

print(f"\nψ-tier ε-MCC / FPR by (τ_sync ms, ρ_sync)  [current=1ms,0.8]")
print("  ρ\\τ  |  " + "   ".join(f"{int(t*1000):>2}ms" for t in TAUS))
best=None
for rho in RHOS:
    row=[]
    for tau in TAUS:
        b6=fire_bits(tau,rho); bits=logbits.copy(); bits[:,6]=b6
        m,fpr=emcc(bits@SIGW>PSI_TH, gt)
        row.append(f"{m:.2f}/{fpr:.2f}")
        if fpr<=0.05 and (best is None or m>best[0]): best=(m,fpr,tau,rho)
    print(f"  {rho:>4} | " + "  ".join(f"{c:>9}" for c in row))
# also MP-S2 own separation at each tau (rho-independent view)
print("\nMP-S2 signature fire P/H by τ_sync:")
for tau in TAUS:
    b6=fire_bits(tau,0.0001)  # rho~0 → any sync → shows raw τ effect... use rho=0.6 real
for tau in TAUS:
    b6=fire_bits(tau,0.8)
    print(f"  τ={int(tau*1000)}ms,ρ=0.8: P/H={b6[gt].mean():.3f}/{b6[~gt].mean():.3f}")
if best: print(f"\n[MP-S2 sweep] BEST (FPR≤0.05): τ_sync={int(best[2]*1000)}ms ρ_sync={best[3]}  ψ-MCC={best[0]:.3f} FPR={best[1]:.3f}")
else: print("\n[MP-S2 sweep] no combo meets FPR≤0.05")
