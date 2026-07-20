#!/usr/bin/env python3
"""
compute_theta_head.py — calibrate the multi-task GAT head-detection threshold
θ_head on CLEAN traces (θ_S-analogue, paper Phase-1b style). The head detection
score is s_head = max_k ŷ_i^(k) (probability the node executes ANY attack).
θ_head = 95th percentile of s_head over clean nodes, so the head-detection tier
fires only above the clean operating point — fixing the 0.5-threshold over-firing.
Writes models/<scen>/theta_head.txt.
"""
import os, sys, json, numpy as np, pandas as pd, onnxruntime as ort
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "analytics", "ml"))
from gat_detector import build_edge_index, SIG_BITS
ML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analytics", "ml", "models")
FEAT = ["pos_x","pos_y","speed","heading","accel"]; PCTL = 95.0

for scen in (sys.argv[1:] or ["urban","rural","highway"]):
    clean = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "analytics","ml","data",f"beacon_clean_{scen}.csv")
    if not os.path.isfile(clean):
        print(f"[{scen}] SKIP no clean csv"); continue
    sc=json.load(open(f"{ML}/{scen}/scaler.json")); MEAN=np.array(sc["mean"]); SCALE=np.array(sc["scale"])
    sess=ort.InferenceSession(f"{ML}/{scen}/gat_model.onnx")
    d=pd.read_csv(clean); d["_tick"]=(d.sim_time/0.1).round().astype(int)
    for c in ("psi_score","sig_mask"):
        if c not in d.columns: d[c]=0
    smax=[]
    for _,g in d.groupby("_tick"):
        if len(g)<2: continue
        raw=g[FEAT].values.astype(np.float32)
        kin=((raw-MEAN[:5])/np.where(SCALE[:5]==0,1,SCALE[:5])).astype(np.float32)
        tau=np.ones((len(g),1),np.float32); psi=g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1,1)
        sm=g["sig_mask"].fillna(0).values.astype(np.int64)
        bits=np.stack([((sm>>b)&1) for b in range(SIG_BITS)],1).astype(np.float32)
        x=np.hstack([kin,tau,psi,bits]).astype(np.float32)
        ei=build_edge_index(raw[:,:2].astype(np.float32),raw[:,3].astype(np.float32),raw[:,2].astype(np.float32)).numpy().astype(np.int64)
        ap=sess.run(None,{"x":x,"edge_index":ei})[1]
        smax.extend(ap.max(1).tolist())
    smax=np.array(smax); th=float(np.percentile(smax,PCTL))
    open(f"{ML}/{scen}/theta_head.txt","w").write(f"{th:.6f}\n")
    print(f"[{scen}] clean nodes={len(smax)} s_head mean={smax.mean():.3f} "
          f"p50={np.percentile(smax,50):.3f} p95(θ_head)={th:.3f} max={smax.max():.3f}")
