#!/usr/bin/env python3
"""
fusion_refit_conditioned.py — sir Change 1+2 wired into the fusion, offline.

1. Recompute the psi tier with attack-conditioned signature weights w_s^(k̂)
   (Change 1): psi_i = bits_i · w^(k̂_i), where k̂_i = GAT head argmax. Change 2
   confidence gate: if max_k ŷ_i^(k) < θ_conf, fall back to the aggregate w
   (and, in fusion, to the average λ set).
2. Sweep θ_conf ∈ {0.5,0.6,0.7,0.8} on the train pens; pick the value maximising
   mean per-attack ε-MCC with mean fallback rate < 20%.
3. Refit λ^(k) per attack under the conditioned psi (SLSQP + simplex grid), and
   write λ + chosen θ_conf back into fusion_weights.json.

Caches GAT/AE tier scores + sig bits + k̂ + confidence per beacon so the θ_conf
sweep and λ refit run without re-invoking ONNX.

Usage: python3 fusion_refit_conditioned.py [scen=urban] [pens=40,60]
"""
import sys, os, json, math
import numpy as np, pandas as pd, onnxruntime as ort
from scipy.optimize import minimize
ROOT=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT,"analytics","ml"))
from gat_detector import build_edge_index, SIG_BITS

SCEN=sys.argv[1] if len(sys.argv)>1 else "urban"
PENS=(sys.argv[2].split(",") if len(sys.argv)>2 else ["40","60"])
ML=os.path.join(ROOT,"analytics","ml","models",SCEN)
DS=os.environ.get("MPTD_DS_ROOT","/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility")+f"/{SCEN}"
FEAT=["pos_x","pos_y","speed","heading","accel"]
PSI_TH,PHI_TH,LAM_MIN,EPS=0.09,0.5,0.05,1e-12
THETA_GRID=[0.5,0.6,0.7,0.8]; FALLBACK_MAX=0.20

sc=json.load(open(f"{ML}/scaler.json")); MEAN=np.array(sc["mean"]); SCALE=np.array(sc["scale"])
THETA_S=float(open(f"{ML}/theta_s.txt").read()); THETA_AE=float(open(f"{ML}/theta_ae.txt").read())
FW=json.load(open(f"{ML}/fusion_weights.json"))
WSETS={s["attack"]:np.array(s["w"]) for s in FW["sig_weight_sets"]}
WGLOB=np.array(FW["sig_weight_global"])
gat=ort.InferenceSession(f"{ML}/gat_model.onnx"); ae=ort.InferenceSession(f"{ML}/lstm_ae_model.onnx")
W=50 if SCEN=="urban" else 10   # L=50 urban AE (Step 4)


def cache_rows(d):
    """Per finished-window beacon: (gat_n, ae_n, gt, khat, conf, bit0..8)."""
    d=d.sort_values(["vehicle_id","sim_time"]).reset_index(drop=True)
    d["_tick"]=(d.sim_time/0.1).round().astype(int)
    ginfo={}
    for _,g in d.groupby("_tick"):
        if len(g)<2: continue
        raw=g[FEAT].values.astype(np.float32)
        kin=((raw-MEAN[:5])/np.where(SCALE[:5]==0,1,SCALE[:5])).astype(np.float32)
        tau=np.ones((len(g),1),np.float32); psi=g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1,1)
        sm=g["sig_mask"].fillna(0).values.astype(np.int64)
        bits=np.stack([((sm>>b)&1) for b in range(SIG_BITS)],1).astype(np.float32)
        x=np.hstack([kin,tau,psi,bits]).astype(np.float32)
        ei=build_edge_index(raw[:,:2].astype(np.float32),raw[:,3].astype(np.float32),raw[:,2].astype(np.float32)).numpy().astype(np.int64)
        o=gat.run(None,{"x":x,"edge_index":ei}); S=o[0].reshape(-1); ap=o[1]
        for i,(_,row) in enumerate(g.iterrows()):
            mx=int(ap[i].argmax())
            ginfo[(row._tick,row.vehicle_id)]=(min(1.0,max(0.0,float(S[i])/THETA_S)),mx+1,float(ap[i][mx]))
    rows=[]
    for vid,g in d.groupby("vehicle_id"):
        g=g.reset_index(drop=True); arr=g[FEAT].values.astype(np.float32)
        w6=(np.hstack([arr,np.ones((len(g),1),np.float32)])-MEAN)/np.where(SCALE==0,1,SCALE)
        sm=g["sig_mask"].fillna(0).values.astype(np.int64)
        for j in range(W-1,len(g)):
            key=(int(g._tick[j]),vid)
            if key not in ginfo: continue
            gat_n,khat,conf=ginfo[key]
            rec=ae.run(None,{"x":w6[j-W+1:j+1].astype(np.float32)[None]})[0]
            ae_n=min(1.0,max(0.0,float(np.mean((rec-w6[j-W+1:j+1][None])**2))/THETA_AE))
            b=[float((int(sm[j])>>bb)&1) for bb in range(9)]
            rows.append([gat_n,ae_n,int(g.is_poisoned[j]),khat,conf]+b)
    return np.array(rows) if rows else np.zeros((0,14))


def psi_n_of(rows, theta):
    """Conditioned psi_n per row with the θ_conf gate. Returns (psi_n, fell_back mask)."""
    bits=rows[:,5:14]; khat=rows[:,3].astype(int); conf=rows[:,4]
    psi=np.empty(len(rows)); fb=np.zeros(len(rows),bool)
    for i in range(len(rows)):
        if khat[i]>0 and conf[i]>=theta and khat[i] in WSETS:
            w=WSETS[khat[i]]
        else:
            w=WGLOB; fb[i]=True
        psi[i]=bits[i]@w
    return np.minimum(1.0,np.maximum(0.0,psi/PSI_TH)), fb


def mcc_of(lam,psi_n,gat_n,ae_n,gt):
    phi=lam[0]*psi_n+lam[1]*gat_n+lam[2]*ae_n
    flag=phi>PHI_TH; g=gt>0.5
    tp=np.sum(flag&g);fp=np.sum(flag&~g);tn=np.sum(~flag&~g);fn=np.sum(~flag&g)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS)
    den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den, (fp/(fp+tn) if (fp+tn) else 0.0)


def solve_lambda(psi_n,gat_n,ae_n,gt):
    if len(gt)<8 or gt.sum()==0 or (gt==0).sum()==0: return None
    def negm(x): return -mcc_of(x/x.sum(),psi_n,gat_n,ae_n,gt)[0]
    cons=[{"type":"eq","fun":lambda x:x.sum()-1.0}]; bnds=[(LAM_MIN,1.0)]*3; cands=[]
    for x0 in ([.45,.35,.2],[.6,.2,.2],[.2,.6,.2],[.2,.2,.6],[.34,.33,.33]):
        r=minimize(lambda x:-mcc_of(x,psi_n,gat_n,ae_n,gt)[0],x0,method="SLSQP",
                   bounds=bnds,constraints=cons,options={"maxiter":300,"ftol":1e-9})
        x=np.clip(r.x,LAM_MIN,None); cands.append(x/x.sum())
    g=np.round(np.arange(LAM_MIN,1.0-2*LAM_MIN+1e-9,0.05),4)
    for lp in g:
        for lg in g:
            la=round(1.0-lp-lg,4)
            if la<LAM_MIN-1e-9 or la>1.0: continue
            cands.append(np.array([lp,lg,la]))
    best=None
    for x in cands:
        m,_=mcc_of(x,psi_n,gat_n,ae_n,gt)
        if best is None or m>best[0]: best=(m,x)
    return best[1]/best[1].sum()


# ── cache all attacks ────────────────────────────────────────────────────────
print(f"[refit] scen={SCEN} pens={PENS}: caching tier scores + k̂ + conf …")
CACHE={}
for a in range(1,8):
    parts=[pd.read_csv(f"{DS}/a{a}_p{p}/beacon_log.csv") for p in PENS
           if os.path.isfile(f"{DS}/a{a}_p{p}/beacon_log.csv")]
    if not parts: continue
    CACHE[a]=np.vstack([cache_rows(p) for p in parts])
    print(f"  a{a}: n={len(CACHE[a])} pois={int(CACHE[a][:,2].sum())}")

# ── θ_conf sweep ─────────────────────────────────────────────────────────────
print("[refit] θ_conf sweep (mean per-attack ε-MCC @ refit-λ, fallback<20%):")
best_theta=None
for theta in THETA_GRID:
    mccs=[]; fbs=[]
    for a,R in CACHE.items():
        psi_n,fb=psi_n_of(R,theta); gat_n=R[:,0]; ae_n=R[:,1]; gt=R[:,2]
        lam=solve_lambda(psi_n,gat_n,ae_n,gt)
        if lam is None: continue
        m,_=mcc_of(lam,psi_n,gat_n,ae_n,gt); mccs.append(m); fbs.append(fb.mean())
    mm=float(np.mean(mccs)); mfb=float(np.mean(fbs))
    ok = mfb<FALLBACK_MAX
    print(f"  θ={theta}: mean MCC={mm:.3f}  mean fallback={mfb:.2f}  {'OK' if ok else 'fallback≥20%'}")
    if ok and (best_theta is None or mm>best_theta[1]): best_theta=(theta,mm)
if best_theta is None:   # none satisfied fallback<20% → take max-MCC anyway
    for theta in THETA_GRID:
        mccs=[]
        for a,R in CACHE.items():
            psi_n,_=psi_n_of(R,theta); lam=solve_lambda(psi_n,R[:,0],R[:,1],R[:,2])
            if lam is not None: mccs.append(mcc_of(lam,psi_n,R[:,0],R[:,1],R[:,2])[0])
        mm=float(np.mean(mccs))
        if best_theta is None or mm>best_theta[1]: best_theta=(theta,mm)
THETA_CONF=best_theta[0]
print(f"[refit] selected θ_conf={THETA_CONF} (mean MCC={best_theta[1]:.3f})")

# ── final λ refit at chosen θ_conf ───────────────────────────────────────────
sets=[]; gp=gg=ga=0.0
for a in range(1,8):
    if a not in CACHE: sets.append({"attack":a,"psi":.45,"gat":.35,"ae":.20}); gp+=.45;gg+=.35;ga+=.2; continue
    R=CACHE[a]; psi_n,fb=psi_n_of(R,THETA_CONF)
    lam=solve_lambda(psi_n,R[:,0],R[:,1],R[:,2])
    if lam is None: lam=np.array([.45,.35,.20])
    m,fpr=mcc_of(lam,psi_n,R[:,0],R[:,1],R[:,2])
    p,g,e=float(lam[0]),float(lam[1]),float(lam[2])
    sets.append({"attack":a,"psi":round(p,4),"gat":round(g,4),"ae":round(e,4)}); gp+=p;gg+=g;ga+=e
    print(f"  a{a}: λ=(ψ {p:.3f}, gat {g:.3f}, ae {e:.3f})  MCC={m:.3f} FPR={fpr:.3f} fallback={fb.mean():.2f}")

n=len(sets)
FW["phi_threshold"]=PHI_TH; FW["lambda_sets"]=sets
FW["lambda_psi"]=round(gp/n,4); FW["lambda_gat"]=round(gg/n,4); FW["lambda_ae"]=round(ga/n,4)
FW["theta_conf"]=THETA_CONF
FW["_note"]=f"Change1+2: conditioned-ψ λ refit + θ_conf={THETA_CONF}, offline {SCEN} G50 pens {PENS}"
out=f"{ML}/fusion_weights.json"; os.replace(out,out+".bak_pre_refit")
json.dump(FW,open(out,"w"),indent=2)
print(f"[refit] wrote λ sets + θ_conf into {out}")
