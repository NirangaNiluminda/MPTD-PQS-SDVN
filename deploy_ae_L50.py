#!/usr/bin/env python3
"""
deploy_ae_L50.py — Step 4 deploy: retrain the URBAN LSTM-AE at L=50 and export.

Trains the deployed 6-dim AE (5 kinematic + tau, scaler.json-normalised) on clean
urban data at window L=50, calibrates θ_ae, and overwrites the deployed urban
lstm_ae_model.onnx (input [B,50,6]) + theta_ae.txt. Backs up the L=10 versions.
Rural/highway are untouched (stay L=10, per sir's urban-only instruction).

Usage: python3 deploy_ae_L50.py
"""
import os, sys, json, math, shutil
import numpy as np, pandas as pd, torch
ROOT=os.path.dirname(os.path.abspath(__file__)); ML=os.path.join(ROOT,"analytics","ml")
sys.path.insert(0, ML)
from lstm_ae import LSTMAEDetector
SCEN="urban"; L=50; EPOCHS=60; KAPPA=1.645; DEV="cuda" if torch.cuda.is_available() else "cpu"
FEAT=["pos_x","pos_y","speed","heading","accel"]
MODELS=f"{ML}/models/{SCEN}"
sc=json.load(open(f"{MODELS}/scaler.json")); MEAN=np.array(sc["mean"],np.float32); SCALE=np.array(sc["scale"],np.float32)

def windows_6d(df, L):
    df=df.sort_values(["vehicle_id","sim_time"]); Xs=[]
    for _,g in df.groupby("vehicle_id"):
        f5=g[FEAT].values.astype(np.float32)
        if len(f5)<L: continue
        f6=(np.hstack([f5,np.ones((len(f5),1),np.float32)])-MEAN)/np.where(SCALE==0,1,SCALE)
        Xs.append(np.stack([f6[i:i+L] for i in range(len(f6)-L+1)]))
    return np.concatenate(Xs).astype(np.float32) if Xs else np.zeros((0,L,6),np.float32)

clean=pd.read_csv(f"{ML}/data/beacon_clean_{SCEN}.csv")
X=windows_6d(clean,L); print(f"[deploy-ae] urban clean windows L={L}: {len(X)}")
torch.manual_seed(42); m=LSTMAEDetector(feat_dim=6).to(DEV); opt=torch.optim.Adam(m.parameters(),lr=1e-3)
vi=int(len(X)*0.8); Xt=torch.tensor(X[:vi]); Xv=torch.tensor(X[vi:])
for ep in range(EPOCHS):
    m.train(); perm=torch.randperm(len(Xt))
    for i in range(0,len(Xt),128):
        b=Xt[perm[i:i+128]].to(DEV); opt.zero_grad(); ((m(b)-b)**2).mean().backward(); opt.step()
m.eval()
with torch.no_grad():
    err=((m(Xv.to(DEV))-Xv.to(DEV))**2).mean(dim=(1,2)).cpu().numpy()
theta=float(err.mean()+KAPPA*err.std()); print(f"[deploy-ae] θ_ae (L={L}) = {theta:.6f}")

# backup + export ONNX ([B,L,6]) + theta
onnx_path=f"{MODELS}/lstm_ae_model.onnx"; theta_path=f"{MODELS}/theta_ae.txt"
shutil.copy(onnx_path, onnx_path+".bak_L10"); shutil.copy(theta_path, theta_path+".bak_L10")
dummy=torch.randn(1,L,6,dtype=torch.float32).to(DEV)
torch.onnx.export(m, dummy, onnx_path, input_names=["x"], output_names=["recon"],
                  dynamic_axes={"x":{0:"batch"},"recon":{0:"batch"}}, opset_version=11)
open(theta_path,"w").write(f"{theta:.6f}\n")
print(f"[deploy-ae] wrote {onnx_path} (input [B,{L},6]) + theta_ae.txt  (L=10 backed up)")
# sanity: reload and check shape
import onnxruntime as ort
s=ort.InferenceSession(onnx_path); print("[deploy-ae] onnx input:", s.get_inputs()[0].shape)
