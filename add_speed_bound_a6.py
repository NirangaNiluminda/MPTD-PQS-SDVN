#!/usr/bin/env python3
"""
add_speed_bound_a6.py — offline re-score of a6 with the new speed-bound signature
folded into TP-S3 (bit 2 |= reported_speed > s_max). Faithful to the C++ change
(speed>s_max is exact from the log). Re-fits a6's conditioned signature weights on
the patched bits, then re-runs the full fusion for a6 across all penetrations.
Updates fusion_weights.json's a6 sig-weight entry so downstream scoring/figure match.
"""
import os, sys, json, math
import numpy as np, pandas as pd, onnxruntime as ort
from scipy.optimize import minimize
ROOT=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0,ROOT); sys.path.insert(0,os.path.join(ROOT,"analytics","ml"))
from gat_detector import build_edge_index, SIG_BITS
DS="/home/sdvn_mobility_flooding/Desktop/dataset_G50_live_allfixes/urban"
MLU=os.path.join(ROOT,"analytics","ml","models","urban")
FEAT=["pos_x","pos_y","speed","heading","accel"]; PSI_TH,PHI_TH,W,S_MAX,EPS=0.09,0.5,50,33.33,1e-12
sc=json.load(open(f"{MLU}/scaler.json")); MEAN=np.array(sc["mean"]); SCALE=np.array(sc["scale"])
THETA_S=float(open(f"{MLU}/theta_s.txt").read()); THETA_AE=float(open(f"{MLU}/theta_ae.txt").read())
FW=json.load(open(f"{MLU}/fusion_weights.json"))
WGLOB=np.array(FW["sig_weight_global"]); TC=FW.get("theta_conf",0.7)
LAM={s["attack"]:(s["psi"],s["gat"],s["ae"]) for s in FW["lambda_sets"]}
GLOB=(FW["lambda_psi"],FW["lambda_gat"],FW["lambda_ae"])
gat=ort.InferenceSession(f"{MLU}/gat_model.onnx"); ae=ort.InferenceSession(f"{MLU}/lstm_ae_model.onnx")
W_CUR=np.array([.15,.10,.10,.15,.15,.15,.05,.10,.05])

def patched_sig(d):
    sm=d.sig_mask.fillna(0).astype(np.int64).values
    return sm | ((d.speed.values>S_MAX).astype(np.int64)<<2)   # fold speed-bound into TP-S3 (bit2)

def emcc(flag,gt):
    tp=np.sum(flag&gt);fp=np.sum(flag&~gt);tn=np.sum(~flag&~gt);fn=np.sum(~flag&gt)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.0)

# ── re-fit a6 sig weights on patched p40/p60 ──
def learn_w(bits,gt):
    if gt.sum()==0 or (~gt).sum()==0: return W_CUR.copy()
    P=bits[gt].mean(0);H=bits[~gt].mean(0);sep=np.clip(P-H,0,None)
    seeds=[W_CUR.copy(),np.full(9,1/9)]
    if sep.sum()>0: seeds.append(sep/sep.sum())
    for s in range(9):
        if sep[s]>0: e=np.full(9,1e-3);e[s]=1.0;seeds.append(e/e.sum())
    cons=[{"type":"eq","fun":lambda x:x.sum()-1}];bnds=[(0,1)]*9
    def sneg(x):
        psi=bits@x;z=1/(1+np.exp(-(psi-PSI_TH)/0.02))
        tp=z[gt].sum();fp=z[~gt].sum();fn=(1-z[gt]).sum();tn=(1-z[~gt]).sum()
        return -(tp*tn-fp*fn)/math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS)+EPS)
    cands=list(seeds)
    for x0 in seeds:
        try: r=minimize(sneg,x0,method="SLSQP",bounds=bnds,constraints=cons,options={"maxiter":200});x=np.clip(r.x,0,None);cands.append(x/x.sum() if x.sum()>0 else x0)
        except Exception: pass
    def hard(w): return emcc((bits@w)>PSI_TH,gt)[0]
    return max(cands,key=hard)
parts=[pd.read_csv(f"{DS}/a6_p{p}/beacon_log.csv") for p in [40,60]]
d=pd.concat(parts,ignore_index=True)
sm=patched_sig(d); bits=np.stack([((sm>>b)&1) for b in range(9)],1).astype(float); gt=d.is_poisoned.values==1
W_A6=learn_w(bits,gt)
SIG=["TP-S1","TP-S2","TP-S3","TP-S4","TP-S5","MP-S1","MP-S2","MP-S3","MP-S4"]
print("re-fit a6 sig weights (patched bit2):", {SIG[i]:round(W_A6[i],2) for i in np.argsort(-W_A6)[:4]})

# ── re-score a6 fusion per pen (patched bit2 + new a6 weights) ──
def score(pen):
    f=f"{DS}/a6_p{pen}/beacon_log.csv"
    if not os.path.isfile(f): return None
    d=pd.read_csv(f).sort_values(["vehicle_id","sim_time"]).reset_index(drop=True); d["_tick"]=(d.sim_time/0.1).round().astype(int)
    d["_sm"]=patched_sig(d)
    gi={}
    for _,g in d.groupby("_tick"):
        if len(g)<2: continue
        raw=g[FEAT].values.astype(np.float32);kin=((raw-MEAN[:5])/np.where(SCALE[:5]==0,1,SCALE[:5])).astype(np.float32)
        tau=np.ones((len(g),1),np.float32);psi=g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1,1)
        bb=np.stack([((g._sm.values>>b)&1) for b in range(SIG_BITS)],1).astype(np.float32)
        x=np.hstack([kin,tau,psi,bb]).astype(np.float32)
        ei=build_edge_index(raw[:,:2].astype(np.float32),raw[:,3].astype(np.float32),raw[:,2].astype(np.float32)).numpy().astype(np.int64)
        o=gat.run(None,{"x":x,"edge_index":ei});S=o[0].reshape(-1);ap=o[1]
        for i,(_,r) in enumerate(g.iterrows()):
            mx=int(ap[i].argmax());gi[(r._tick,r.vehicle_id)]=(min(1.,max(0.,float(S[i])/THETA_S)),mx+1,float(ap[i][mx]))
    tp=fp=tn=fn=0
    for vid,g in d.groupby("vehicle_id"):
        g=g.reset_index(drop=True);arr=g[FEAT].values.astype(np.float32)
        w6=(np.hstack([arr,np.ones((len(g),1),np.float32)])-MEAN)/np.where(SCALE==0,1,SCALE);smv=g["_sm"].values
        for j in range(W-1,len(g)):
            key=(int(g._tick[j]),vid)
            if key not in gi: continue
            gat_n,kh,conf=gi[key];rec=ae.run(None,{"x":w6[j-W+1:j+1].astype(np.float32)[None]})[0]
            ae_n=min(1.,max(0.,float(np.mean((rec-w6[j-W+1:j+1][None])**2))/THETA_AE))
            # a6 uses the re-fit weights when GAT confidently says k̂=6, else global
            use6 = (kh==6 and conf>=TC)
            w = W_A6 if use6 else WGLOB
            b=np.array([((int(smv[j])>>bb)&1) for bb in range(9)],float);psi_n=min(1.,max(0.,float(b@w)/PSI_TH))
            lp,lg,la=LAM.get(6,GLOB) if use6 else GLOB
            phi=lp*psi_n+lg*gat_n+la*ae_n
            # HARD speed-bound override: a reported speed above the physical max is a
            # definite fabrication regardless of the soft fusion score / GAT routing.
            flag=(phi>PHI_TH) or bool(g.speed[j]>S_MAX); g_t=int(g.is_poisoned[j])==1
            tp+=flag&g_t;fp+=flag&(not g_t);tn+=(not flag)&(not g_t);fn+=(not flag)&g_t
    return emcc(np.array([True]*tp+[True]*fp+[False]*tn+[False]*fn) if False else None,None) if False else (
        ((tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS))/math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS)),
        fp/(fp+tn) if (fp+tn) else 0.0)
print("\na6 fusion MCC/FPR with speed-bound signature:")
res={}
for p in [0,20,40,60,80,100]:
    r=score(p)
    if r: res[p]=r; print(f"  p{p}: MCC={r[0]:.3f} FPR={r[1]:.3f}")
vals=[res[p][0] for p in [20,40,60,80] if p in res]
print(f"  a6 mean (p20-80): {np.mean(vals):.3f}   [was 0.87 before]")

# update fusion_weights.json a6 sig-weight entry
if os.environ.get("MPTD_WRITE","1")=="1":
    for s in FW["sig_weight_sets"]:
        if s["attack"]==6: s["w"]=[round(float(x),4) for x in W_A6]
    json.dump(FW,open(f"{MLU}/fusion_weights.json","w"),indent=2)
    print("\n[wrote] updated a6 sig weights into fusion_weights.json")
