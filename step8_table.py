#!/usr/bin/env python3
"""
step8_table.py — sir Step 8: full urban per-attack held-out MCC table (offline).

MPTD-full = conditioned ψ (w_s^(k̂)+θ_conf gate) + GAT + L=50 AE + refit λ.
Baselines = ONE global RF each (fair generalist), fit on loud p40/p60 all attacks.
Held-out test pens [20,80] (two-class). ε-MCC (Eq 4.1). This is the offline gate
before the live-sim rebuild.

Usage: python3 step8_table.py
"""
import sys, os, json, math
import numpy as np, pandas as pd, onnxruntime as ort
ROOT="/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN"
sys.path.insert(0,ROOT); sys.path.insert(0,os.path.join(ROOT,"analytics","ml"))
from gat_detector import build_edge_index, SIG_BITS
from mptd_pqs import ercan_b2_detector_v2 as B2, sharma_b3_detector_v2 as B3, ghaleb_b1_detector as B1
from sklearn.metrics import confusion_matrix
from sklearn.ensemble import RandomForestClassifier
SCEN="urban"; DS=f"/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility/{SCEN}"
ML=os.path.join(ROOT,"analytics","ml","models",SCEN)
FEAT=["pos_x","pos_y","speed","heading","accel"]; PSI_TH,PHI_TH,EPS=0.09,0.5,1e-12
TEST=[20,80]; TRAIN=[40,60]; ALL=[1,2,3,4,5,6,7]; W=50 if SCEN=="urban" else 10
sc=json.load(open(f"{ML}/scaler.json")); MEAN=np.array(sc["mean"]); SCALE=np.array(sc["scale"])
THETA_S=float(open(f"{ML}/theta_s.txt").read()); THETA_AE=float(open(f"{ML}/theta_ae.txt").read())
FW=json.load(open(f"{ML}/fusion_weights.json"))
WSETS={s["attack"]:np.array(s["w"]) for s in FW["sig_weight_sets"]}; WGLOB=np.array(FW["sig_weight_global"])
TC=FW.get("theta_conf",0.7); LAM={s["attack"]:(s["psi"],s["gat"],s["ae"]) for s in FW["lambda_sets"]}
gat=ort.InferenceSession(f"{ML}/gat_model.onnx"); ae=ort.InferenceSession(f"{ML}/lstm_ae_model.onnx")
def emcc(flag,g):
    tp=np.sum(flag&g);fp=np.sum(flag&~g);tn=np.sum(~flag&~g);fn=np.sum(~flag&g)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.0)
def mptd(a,p):
    f=f"{DS}/a{a}_p{p}/beacon_log.csv"
    if not os.path.isfile(f): return None
    d=pd.read_csv(f).sort_values(["vehicle_id","sim_time"]).reset_index(drop=True); d["_tick"]=(d.sim_time/0.1).round().astype(int)
    gi={}
    for _,g in d.groupby("_tick"):
        if len(g)<2: continue
        raw=g[FEAT].values.astype(np.float32); kin=((raw-MEAN[:5])/np.where(SCALE[:5]==0,1,SCALE[:5])).astype(np.float32)
        tau=np.ones((len(g),1),np.float32); psi=g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1,1)
        sm=g["sig_mask"].fillna(0).values.astype(np.int64); bits=np.stack([((sm>>b)&1) for b in range(SIG_BITS)],1).astype(np.float32)
        x=np.hstack([kin,tau,psi,bits]).astype(np.float32)
        ei=build_edge_index(raw[:,:2].astype(np.float32),raw[:,3].astype(np.float32),raw[:,2].astype(np.float32)).numpy().astype(np.int64)
        o=gat.run(None,{"x":x,"edge_index":ei}); S=o[0].reshape(-1); ap=o[1]
        for i,(_,r) in enumerate(g.iterrows()):
            mx=int(ap[i].argmax()); gi[(r._tick,r.vehicle_id)]=(min(1.,max(0.,float(S[i])/THETA_S)),mx+1,float(ap[i][mx]))
    tp=fp=tn=fn=0
    for vid,g in d.groupby("vehicle_id"):
        g=g.reset_index(drop=True); arr=g[FEAT].values.astype(np.float32)
        w6=(np.hstack([arr,np.ones((len(g),1),np.float32)])-MEAN)/np.where(SCALE==0,1,SCALE)
        sm=g["sig_mask"].fillna(0).values.astype(np.int64)
        for j in range(W-1,len(g)):
            key=(int(g._tick[j]),vid)
            if key not in gi: continue
            gat_n,kh,conf=gi[key]; rec=ae.run(None,{"x":w6[j-W+1:j+1].astype(np.float32)[None]})[0]
            ae_n=min(1.,max(0.,float(np.mean((rec-w6[j-W+1:j+1][None])**2))/THETA_AE))
            usek = kh if (kh>0 and conf>=TC and kh in WSETS) else -1
            w=WSETS[kh] if usek>0 else WGLOB; b=np.array([((int(sm[j])>>bb)&1) for bb in range(9)],float)
            psi_n=min(1.,max(0.,float(b@w)/PSI_TH))
            lp,lg,la=LAM.get(usek,(FW["lambda_psi"],FW["lambda_gat"],FW["lambda_ae"])) if usek>0 else (FW["lambda_psi"],FW["lambda_gat"],FW["lambda_ae"])
            phi=lp*psi_n+lg*gat_n+la*ae_n; flag=phi>PHI_TH; gt=int(g.is_poisoned[j])==1
            tp+=flag&gt;fp+=flag&(not gt);tn+=(not flag)&(not gt);fn+=(not flag)&gt
    m,fpr=emcc(np.array([True]*tp+[True]*fp+[False]*tn+[False]*fn) if False else None,None) if False else (None,None)
    # direct MCC from counts
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.)
def gfit(mod):
    fr=[mod.load_scenario(f"{DS}/a{a}_p{p}") for a in ALL for p in TRAIN]; fr=[x for x in fr if x is not None]
    d=pd.concat(fr,ignore_index=True).dropna(subset=mod.FEATURE_COLS+["label"])
    c=RandomForestClassifier(n_estimators=100,random_state=42,class_weight="balanced",n_jobs=-1); c.fit(d[mod.FEATURE_COLS].values,d["label"].values); return c
def bcm(mod,clf,a,p):
    te=mod.load_scenario(f"{DS}/a{a}_p{p}")
    if te is None: return None
    te=te.dropna(subset=mod.FEATURE_COLS+["label"])
    if len(te)<2: return None
    y=te["label"].values.astype(int); yp=clf.predict(te[mod.FEATURE_COLS].values).astype(int)
    cm=confusion_matrix(y,yp,labels=[0,1]); tn,fp,fn,tp=cm.ravel() if cm.size==4 else (cm[0,0],0,0,0)
    return emcc(np.r_[np.ones(tp,bool),np.ones(fp,bool),np.zeros(tn,bool),np.zeros(fn,bool)], np.r_[np.ones(tp,bool),np.zeros(fp,bool),np.zeros(tn,bool),np.ones(fn,bool)])[0]
def b1cm(a,p):
    aug=B1.load_scenario(f"{DS}/a{a}_p{p}")
    if aug is None or len(aug)<2: return None
    dd=B1.GhalebB1Detector().run(aug); y=aug["is_poisoned"].values.astype(int); yp=dd["pred"].values.astype(int)
    n=min(len(y),len(yp)); cm=confusion_matrix(y[:n],yp[:n],labels=[0,1]); tn,fp,fn,tp=cm.ravel() if cm.size==4 else (cm[0,0],0,0,0)
    return emcc(np.r_[np.ones(tp,bool),np.ones(fp,bool),np.zeros(tn,bool),np.zeros(fn,bool)], np.r_[np.ones(tp,bool),np.zeros(fp,bool),np.zeros(tn,bool),np.ones(fn,bool)])[0]
gB2=gfit(B2); gB3=gfit(B3)
print(f"STEP 8 — held-out per-attack MCC (test pens {TEST}, mean)  [urban, all offline fixes]")
print(f"{'atk':>4} | {'MPTD-full':>10} {'FPR':>5} | {'B1':>6} {'B2':>6} {'B3':>6} | winner")
rows=[]
for a in ALL:
    mm=[mptd(a,p) for p in TEST]; mm=[x for x in mm if x];
    mmcc=np.mean([x[0] for x in mm]); mfpr=np.mean([x[1] for x in mm])
    b1=np.nanmean([b1cm(a,p) for p in TEST]); b2=np.nanmean([bcm(B2,gB2,a,p) for p in TEST]); b3=np.nanmean([bcm(B3,gB3,a,p) for p in TEST])
    best=max([("MPTD",mmcc),("B1",b1),("B2",b2),("B3",b3)],key=lambda kv:(kv[1] if kv[1]==kv[1] else -9))
    print(f"  a{a} | {mmcc:10.3f} {mfpr:5.2f} | {b1:6.2f} {b2:6.2f} {b3:6.2f} | {best[0]}")
    rows.append((mmcc,b1,b2,b3))
R=np.array(rows)
print(f"MEAN | {np.nanmean(R[:,0]):10.3f}       | {np.nanmean(R[:,1]):6.2f} {np.nanmean(R[:,2]):6.2f} {np.nanmean(R[:,3]):6.2f}")
