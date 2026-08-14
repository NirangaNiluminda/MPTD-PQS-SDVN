#!/usr/bin/env python3
"""
validate_change12.py — held-out A/B test of sir Change 1+2 on the fusion.

BEFORE : psi_n = logged psi_score (global SIG_WEIGHTS) ; λ = pristine per-attack set.
AFTER  : psi_n = conditioned bits·w^(k̂) with θ_conf gate ; λ = refit set.
Both evaluated on HELD-OUT pens [20,80] (two-class), trained on [40,60].
Prints per-attack ε-MCC / FPR before→after.

Usage: python3 validate_change12.py [scen=urban]
"""
import sys, os, json, math
import numpy as np, pandas as pd, onnxruntime as ort
ROOT=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0,os.path.join(ROOT,"analytics","ml"))
from gat_detector import build_edge_index, SIG_BITS

SCEN=sys.argv[1] if len(sys.argv)>1 else "urban"
TEST_PENS=[20,80]
ML=os.path.join(ROOT,"analytics","ml","models",SCEN)
DS=f"/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility/{SCEN}"
FEAT=["pos_x","pos_y","speed","heading","accel"]; PSI_TH,PHI_TH,EPS=0.09,0.5,1e-12
sc=json.load(open(f"{ML}/scaler.json")); MEAN=np.array(sc["mean"]); SCALE=np.array(sc["scale"])
THETA_S=float(open(f"{ML}/theta_s.txt").read()); THETA_AE=float(open(f"{ML}/theta_ae.txt").read())
gat=ort.InferenceSession(f"{ML}/gat_model.onnx"); ae=ort.InferenceSession(f"{ML}/lstm_ae_model.onnx"); W=50 if SCEN=="urban" else 10

# AFTER weights (current fusion_weights.json)
FW=json.load(open(f"{ML}/fusion_weights.json"))
WSETS={s["attack"]:np.array(s["w"]) for s in FW["sig_weight_sets"]}; WGLOB=np.array(FW["sig_weight_global"])
THETA_CONF=FW.get("theta_conf",0.7)
LAM_AFTER={s["attack"]:(s["psi"],s["gat"],s["ae"]) for s in FW["lambda_sets"]}
# BEFORE weights (pristine, pre-patch)
PRE=json.load(open("/tmp/claude-1001/-home-sdvn-mobility-flooding-ns-allinone-3-35/eb76a788-2b45-4ff2-9a20-4bf2772b10fa/scratchpad/fusion_weights_pre_sigw.json"))
LAM_BEFORE={s["attack"]:(s["psi"],s["gat"],s["ae"]) for s in PRE["lambda_sets"]}
GLOB_BEFORE=(PRE["lambda_psi"],PRE["lambda_gat"],PRE["lambda_ae"])

def emcc(flag,gt):
    g=gt>0.5; tp=np.sum(flag&g);fp=np.sum(flag&~g);tn=np.sum(~flag&~g);fn=np.sum(~flag&g)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS); den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.0)

def cache(d):
    d=d.sort_values(["vehicle_id","sim_time"]).reset_index(drop=True); d["_tick"]=(d.sim_time/0.1).round().astype(int)
    ginfo={}
    for _,g in d.groupby("_tick"):
        if len(g)<2: continue
        raw=g[FEAT].values.astype(np.float32); kin=((raw-MEAN[:5])/np.where(SCALE[:5]==0,1,SCALE[:5])).astype(np.float32)
        tau=np.ones((len(g),1),np.float32); psi=g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1,1)
        sm=g["sig_mask"].fillna(0).values.astype(np.int64); bits=np.stack([((sm>>b)&1) for b in range(SIG_BITS)],1).astype(np.float32)
        x=np.hstack([kin,tau,psi,bits]).astype(np.float32)
        ei=build_edge_index(raw[:,:2].astype(np.float32),raw[:,3].astype(np.float32),raw[:,2].astype(np.float32)).numpy().astype(np.int64)
        o=gat.run(None,{"x":x,"edge_index":ei}); S=o[0].reshape(-1); ap=o[1]
        for i,(_,row) in enumerate(g.iterrows()):
            mx=int(ap[i].argmax()); ginfo[(row._tick,row.vehicle_id)]=(min(1.0,max(0.0,float(S[i])/THETA_S)),mx+1,float(ap[i][mx]))
    rows=[]
    for vid,g in d.groupby("vehicle_id"):
        g=g.reset_index(drop=True); arr=g[FEAT].values.astype(np.float32)
        w6=(np.hstack([arr,np.ones((len(g),1),np.float32)])-MEAN)/np.where(SCALE==0,1,SCALE)
        sm=g["sig_mask"].fillna(0).values.astype(np.int64); ps=g["psi_score"].fillna(0).values
        for j in range(W-1,len(g)):
            key=(int(g._tick[j]),vid)
            if key not in ginfo: continue
            gat_n,khat,conf=ginfo[key]; rec=ae.run(None,{"x":w6[j-W+1:j+1].astype(np.float32)[None]})[0]
            ae_n=min(1.0,max(0.0,float(np.mean((rec-w6[j-W+1:j+1][None])**2))/THETA_AE))
            b=[float((int(sm[j])>>bb)&1) for bb in range(9)]
            rows.append([gat_n,ae_n,int(g.is_poisoned[j]),khat,conf,min(1.0,max(0.0,float(ps[j])/PSI_TH))]+b)
    return np.array(rows) if rows else np.zeros((0,15))

print(f"[A/B] scen={SCEN} held-out pens={TEST_PENS}  θ_conf={THETA_CONF}")
print(f"{'atk':>4} | {'BEFORE MCC/FPR':>18} | {'AFTER MCC/FPR':>18} | ΔMCC")
mb=[]; ma=[]
for a in range(1,8):
    parts=[pd.read_csv(f"{DS}/a{a}_p{p}/beacon_log.csv") for p in TEST_PENS if os.path.isfile(f"{DS}/a{a}_p{p}/beacon_log.csv")]
    if not parts: continue
    R=np.vstack([cache(p) for p in parts]); gt=R[:,2]
    if gt.sum()==0 or (gt==0).sum()==0: continue
    # BEFORE
    lp,lg,la=LAM_BEFORE.get(a,GLOB_BEFORE); phi=lp*R[:,5]+lg*R[:,0]+la*R[:,1]; mb_,fb_=emcc(phi>PHI_TH,gt)
    # AFTER: conditioned psi + gate
    bits=R[:,6:15]; khat=R[:,3].astype(int); conf=R[:,4]; psi=np.empty(len(R))
    for i in range(len(R)):
        w=WSETS[khat[i]] if (khat[i]>0 and conf[i]>=THETA_CONF and khat[i] in WSETS) else WGLOB
        psi[i]=bits[i]@w
    psi_n=np.minimum(1.0,np.maximum(0.0,psi/PSI_TH))
    lp,lg,la=LAM_AFTER.get(a,(0.45,0.35,0.20)); phi=lp*psi_n+lg*R[:,0]+la*R[:,1]; ma_,fa_=emcc(phi>PHI_TH,gt)
    mb.append(mb_); ma.append(ma_)
    print(f"  a{a} | {mb_:6.3f} / {fb_:6.3f}     | {ma_:6.3f} / {fa_:6.3f}     | {ma_-mb_:+.3f}")
print(f"MEAN | {np.mean(mb):6.3f}            | {np.mean(ma):6.3f}            | {np.mean(ma)-np.mean(mb):+.3f}")
