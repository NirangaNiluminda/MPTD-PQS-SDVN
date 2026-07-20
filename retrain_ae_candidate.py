#!/usr/bin/env python3
"""
retrain_ae_candidate.py — Step 4 hypothesis test: does a longer LSTM-AE window
help the slow-drift attack (sir's a1 = our a2)?

Trains the deployed 6-dim AE (5 kinematic + tau, scaler.json-normalised) FRESH at
L=10 and L=50 on the SAME clean urban data (controls for everything except window),
then measures each AE tier's OWN separation (ROC-AUC + eps-MCC @ θ_ae) of poisoned
vs honest on the a2 held-out pens (and a1 for reference). Adopt L=50 only if it
actually separates a2 better. Nothing deployed unless it wins.

Usage: python3 retrain_ae_candidate.py
"""
import os, sys, json, math
import numpy as np, pandas as pd, torch
ROOT=os.path.dirname(os.path.abspath(__file__)); ML=os.path.join(ROOT,"analytics","ml")
sys.path.insert(0, ML)
from lstm_ae import LSTMAEDetector
from sklearn.metrics import roc_auc_score

SCEN="urban"; DS=f"/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility/{SCEN}"
FEAT=["pos_x","pos_y","speed","heading","accel"]; KAPPA=1.645; EPS=1e-12
DEV="cuda" if torch.cuda.is_available() else "cpu"
sc=json.load(open(f"{ML}/models/{SCEN}/scaler.json")); MEAN=np.array(sc["mean"],np.float32); SCALE=np.array(sc["scale"],np.float32)

def windows_6d(df, L, label=False):
    """Per-vehicle sliding L-windows, 6-dim (5 kin + tau=1), scaler-normalised.
    Returns (X[N,L,6], y[N] window-end is_poisoned) — y only if label=True."""
    df=df.sort_values(["vehicle_id","sim_time"])
    Xs=[]; ys=[]
    for _,g in df.groupby("vehicle_id"):
        f5=g[FEAT].values.astype(np.float32)
        if len(f5)<L: continue
        f6=np.hstack([f5, np.ones((len(f5),1),np.float32)])
        f6=(f6-MEAN)/np.where(SCALE==0,1,SCALE)
        idx=[f6[i:i+L] for i in range(len(f6)-L+1)]
        Xs.append(np.stack(idx))
        if label:
            poi=g["is_poisoned"].values.astype(int)
            ys.append(np.array([poi[i+L-1] for i in range(len(f6)-L+1)]))
    if not Xs: return np.zeros((0,L,6),np.float32), np.zeros((0,),int)
    X=np.concatenate(Xs).astype(np.float32)
    y=np.concatenate(ys) if label else np.zeros(len(X),int)
    return X,y

def train_ae(X, L, epochs=40):
    torch.manual_seed(42)
    m=LSTMAEDetector(feat_dim=6).to(DEV)
    opt=torch.optim.Adam(m.parameters(),lr=1e-3)
    n=len(X); vi=int(n*0.8)
    Xt=torch.tensor(X[:vi]); Xv=torch.tensor(X[vi:])
    for ep in range(epochs):
        m.train(); perm=torch.randperm(len(Xt))
        for i in range(0,len(Xt),128):
            b=Xt[perm[i:i+128]].to(DEV); opt.zero_grad()
            loss=((m(b)-b)**2).mean(); loss.backward(); opt.step()
    m.eval()
    with torch.no_grad():
        err=((m(Xv.to(DEV))-Xv.to(DEV))**2).mean(dim=(1,2)).cpu().numpy()
    theta=float(err.mean()+KAPPA*err.std())
    return m, theta

def ae_err(m, X):
    m.eval(); out=[]
    with torch.no_grad():
        for i in range(0,len(X),256):
            b=torch.tensor(X[i:i+256]).to(DEV)
            out.append(((m(b)-b)**2).mean(dim=(1,2)).cpu().numpy())
    return np.concatenate(out) if out else np.zeros(0)

def emcc_at(err, y, theta):
    flag=err>theta; g=y>0.5
    tp=np.sum(flag&g);fp=np.sum(flag&~g);tn=np.sum(~flag&~g);fn=np.sum(~flag&g)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.0)

clean=pd.read_csv(f"{ML}/data/beacon_clean_{SCEN}.csv")
print(f"[ae-cand] clean urban: {len(clean)} rows, {clean.vehicle_id.nunique()} vehicles")
results={}
for L in (10,50):
    Xc,_=windows_6d(clean,L)
    m,theta=train_ae(Xc,L)
    print(f"\n=== L={L}: trained on {len(Xc)} clean windows, θ_ae={theta:.5f} ===")
    for a in (2,1):   # a2 = slow-drift target; a1 for reference
        parts=[pd.read_csv(f"{DS}/a{a}_p{p}/beacon_log.csv") for p in [20,80] if os.path.isfile(f"{DS}/a{a}_p{p}/beacon_log.csv")]
        if not parts: continue
        d=pd.concat(parts,ignore_index=True)
        X,y=windows_6d(d,L,label=True)
        if y.sum()==0 or (y==0).sum()==0 or len(X)<8: print(f"  a{a}: insufficient"); continue
        err=ae_err(m,X); auc=roc_auc_score(y,err); mcc,fpr=emcc_at(err,y,theta)
        results[(L,a)]=(auc,mcc,fpr,int(y.sum()),len(y))
        print(f"  a{a}: AE-tier AUC={auc:.3f}  MCC@θ={mcc:.3f} FPR={fpr:.3f}  (pois {int(y.sum())}/{len(y)} windows)")

print("\n===== VERDICT (does L=50 beat L=10 at seeing the drift?) =====")
for a in (2,1):
    if (10,a) in results and (50,a) in results:
        a10=results[(10,a)]; a50=results[(50,a)]
        print(f"  a{a}: AUC {a10[0]:.3f}→{a50[0]:.3f} ({a50[0]-a10[0]:+.3f})   MCC {a10[1]:.3f}→{a50[1]:.3f} ({a50[1]-a10[1]:+.3f})")
