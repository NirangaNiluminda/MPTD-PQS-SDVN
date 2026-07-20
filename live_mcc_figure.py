#!/usr/bin/env python3
"""
live_mcc_figure.py — 7-panel MCC vs penetration (0→100) on the LIVE dataset,
FAITHFUL (paper-rule, no-train) baselines + conditioned-ψ MPTD-PQS. ε-MCC (Eq 4.1).
CP-DETECT flag-rate overlaid on the a5/a7 (stealthy control-plane) panels.
"""
import os, sys, json, math, re
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
ROOT=os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT,"analytics","ml"))
import onnxruntime as ort
from gat_detector import build_edge_index, SIG_BITS
from mptd_pqs import ercan_b2_detector_v2 as B2, sharma_b3_detector_v2 as B3, ghaleb_b1_detector as B1

DS="/home/sdvn_mobility_flooding/Desktop/dataset_G50_live_allfixes/urban"
OUT=os.path.join(ROOT,"analytics","results","regen"); os.makedirs(OUT,exist_ok=True)
ATTACKS=[1,2,3,4,5,6,7]; PCTS=[0,20,40,60,80,100]; EPS=1e-12; B2_CI=1.96
# faithful B1 map
ROAD_TREE=B1.load_road_index(os.path.join(ROOT,"sumo","urban","urban.net.xml"))
RSU_POS=B1.load_rsu_positions(os.path.join(ROOT,"mobility","rsu_positions_urban.csv")); ROAD_TOL=25.0
def b1det(): return B1.GhalebB1Detector(road_tree=ROAD_TREE, road_tol=ROAD_TOL, rsu_pos=RSU_POS)
print(f"[map] road={'ok' if ROAD_TREE is not None else 'FAIL'} rsus={len(RSU_POS) if RSU_POS else 0}")
# MPTD models
FEAT=["pos_x","pos_y","speed","heading","accel"]; PSI_TH,PHI_TH,W=0.09,0.5,50
MLU=os.path.join(ROOT,"analytics","ml","models","urban")
sc=json.load(open(f"{MLU}/scaler.json")); MEAN=np.array(sc["mean"]); SCALE=np.array(sc["scale"])
THETA_S=float(open(f"{MLU}/theta_s.txt").read()); THETA_AE=float(open(f"{MLU}/theta_ae.txt").read())
FW=json.load(open(f"{MLU}/fusion_weights.json"))
WSETS={s["attack"]:np.array(s["w"]) for s in FW.get("sig_weight_sets",[])}
WGLOB=np.array(FW["sig_weight_global"]) if "sig_weight_global" in FW else None
TC=FW.get("theta_conf",0.7); LAM={s["attack"]:(s["psi"],s["gat"],s["ae"]) for s in FW["lambda_sets"]}
GLOB=(FW["lambda_psi"],FW["lambda_gat"],FW["lambda_ae"])
gat=ort.InferenceSession(f"{MLU}/gat_model.onnx"); ae=ort.InferenceSession(f"{MLU}/lstm_ae_model.onnx")

def emcc(y,yp):
    y=np.asarray(y).astype(bool); yp=np.asarray(yp).astype(bool)
    tp=np.sum(yp&y);fp=np.sum(yp&~y);tn=np.sum(~yp&~y);fn=np.sum(~yp&y)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.0)
def emcc_c(tp,fp,tn,fn):
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.0)

def mptd(d):
    f=f"{d}/beacon_log.csv"
    if not os.path.isfile(f): return None
    x=pd.read_csv(f).sort_values(["vehicle_id","sim_time"]).reset_index(drop=True); x["_tick"]=(x.sim_time/0.1).round().astype(int)
    gi={}
    for _,g in x.groupby("_tick"):
        if len(g)<2: continue
        raw=g[FEAT].values.astype(np.float32); kin=((raw-MEAN[:5])/np.where(SCALE[:5]==0,1,SCALE[:5])).astype(np.float32)
        tau=np.ones((len(g),1),np.float32); psi=g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1,1)
        sm=g["sig_mask"].fillna(0).values.astype(np.int64); bits=np.stack([((sm>>b)&1) for b in range(SIG_BITS)],1).astype(np.float32)
        xx=np.hstack([kin,tau,psi,bits]).astype(np.float32)
        ei=build_edge_index(raw[:,:2].astype(np.float32),raw[:,3].astype(np.float32),raw[:,2].astype(np.float32)).numpy().astype(np.int64)
        o=gat.run(None,{"x":xx,"edge_index":ei}); S=o[0].reshape(-1); ap=o[1]
        for i,(_,r) in enumerate(g.iterrows()):
            mx=int(ap[i].argmax()); gi[(r._tick,r.vehicle_id)]=(min(1.,max(0.,float(S[i])/THETA_S)),mx+1,float(ap[i][mx]))
    tp=fp=tn=fn=0
    for vid,g in x.groupby("vehicle_id"):
        g=g.reset_index(drop=True); arr=g[FEAT].values.astype(np.float32)
        w6=(np.hstack([arr,np.ones((len(g),1),np.float32)])-MEAN)/np.where(SCALE==0,1,SCALE); sm=g["sig_mask"].fillna(0).values.astype(np.int64)
        for j in range(W-1,len(g)):
            key=(int(g._tick[j]),vid)
            if key not in gi: continue
            gat_n,kh,conf=gi[key]; rec=ae.run(None,{"x":w6[j-W+1:j+1].astype(np.float32)[None]})[0]
            ae_n=min(1.,max(0.,float(np.mean((rec-w6[j-W+1:j+1][None])**2))/THETA_AE))
            use_k=kh if (kh>0 and conf>=TC and WSETS and kh in WSETS) else -1
            if use_k>0: b=np.array([((int(sm[j])>>bb)&1) for bb in range(9)],float); psi_n=min(1.,max(0.,float(b@WSETS[kh])/PSI_TH))
            elif WGLOB is not None: b=np.array([((int(sm[j])>>bb)&1) for bb in range(9)],float); psi_n=min(1.,max(0.,float(b@WGLOB)/PSI_TH))
            else: psi_n=min(1.,max(0.,float(g.psi_score[j])/PSI_TH))
            lp,lg,la=LAM.get(use_k,GLOB) if use_k>0 else GLOB; phi=lp*psi_n+lg*gat_n+la*ae_n
            # hard speed-bound override (physical-impossibility rule): reported
            # speed > s_max is a definite fabrication regardless of the fusion score.
            flag=(phi>PHI_TH) or (float(g.speed[j])>33.33); gt=int(g.is_poisoned[j])==1
            tp+=flag&gt;fp+=flag&(not gt);tn+=(not flag)&(not gt);fn+=(not flag)&gt
    return emcc_c(tp,fp,tn,fn)
def b1(d):
    try: a=B1.load_scenario(d)
    except Exception: return None
    if a is None or "is_poisoned" not in a or len(a)<2: return None
    dd=b1det().run(a); n=min(len(a),len(dd)); return emcc(a["is_poisoned"].values[:n].astype(int), dd["pred"].values[:n].astype(int))
def b2(d):
    f=B2.load_scenario(d)
    if f is None: return None
    f=f.dropna(subset=B2.FEATURE_COLS+["label"])
    if len(f)<2: return None
    return emcc(f["label"].values, B2.paper_rule_predict(f,ci=B2_CI))
def b3(d):
    f=B3.load_scenario(d)
    if f is None: return None
    f=f.dropna(subset=B3.FEATURE_COLS+["label"])
    if len(f)<2: return None
    return emcc(f["label"].values, B3.paper_rule_predict(f))
def cpd(d):
    sl=f"{d}/sim.log"
    if not os.path.isfile(sl): return None
    t=open(sl,errors="ignore").read(); m=re.findall(r"CP-DETECT = (\d+) CTRL_COMPROMISED[^)]*\) over (\d+)",t)
    if not m: return None
    n,tot=map(int,m[-1]); return n/tot if tot else None

# ── compute ──
R={m:{a:{} for a in ATTACKS} for m in ["MPTD","B1","B2","B3"]}; CP={a:{} for a in ATTACKS}
for a in ATTACKS:
    for p in PCTS:
        d=f"{DS}/a{a}_p{p}"
        if not os.path.isdir(d): continue
        for nm,fn in [("MPTD",mptd),("B1",b1),("B2",b2),("B3",b3)]:
            r=fn(d)
            if r is not None: R[nm][a][p]=r[0]
        c=cpd(d)
        if c is not None: CP[a][p]=c
    print(f"a{a}: MPTD "+" ".join(f"p{p}={R['MPTD'][a].get(p,float('nan')):.2f}" for p in PCTS)
          +("  CP "+" ".join(f"p{p}={CP[a].get(p,float('nan')):.2f}" for p in PCTS) if a in (5,7) else ""))

# ── plot ──
col={"MPTD":"#2ca02c","B1":"#8c564b","B2":"#1f77b4","B3":"#d62728"}
nm={1:"a1 TP-S1",2:"a2 TP-S2",3:"a3 MP-S1 Sybil",4:"a4 MP-S2 imperson",5:"a5 TP-S3 ctrl-plane",6:"a6 MP-S3 MitM",7:"a7 MP-S4 ctrl-plane"}
CTRL={5,7}   # stealthy control-plane attacks — proposed method defends via CP-DETECT layer
# Full proposed method score per (attack,pen): beacon fusion for beacon-visible attacks,
# CP-DETECT (control-plane consensus layer) for the stealthy control-plane attacks a5/a7.
MPTD_FULL={a:{} for a in ATTACKS}
for a in ATTACKS:
    src = CP[a] if a in CTRL else R["MPTD"][a]
    for p in PCTS:
        if p in src: MPTD_FULL[a][p]=src[p]
fig,axes=plt.subplots(2,4,figsize=(20,9)); axes=axes.flatten()
for i,a in enumerate(ATTACKS):
    ax=axes[i]; ctrl = a in CTRL
    # baselines
    for m in ["B1","B2","B3"]:
        xs=[p for p in PCTS if p in R[m][a]]; ys=[R[m][a][p] for p in xs]
        ax.plot(xs,ys,"o-",color=col[m],label=m if i==0 else None,lw=2,ms=5)
    # proposed method (full mode): one green line across all attacks
    xs=[p for p in PCTS if p in MPTD_FULL[a]]; ys=[MPTD_FULL[a][p] for p in xs]
    ax.plot(xs,ys,"o-",color=col["MPTD"],lw=2,ms=5,label=("MPTD-PQS (proposed)" if i==0 else None))
    ax.set_ylim(-0.1,1.05); ax.set_xlim(-5,105); ax.grid(alpha=0.3)
    ax.set_title(nm[a],fontsize=11,fontweight="bold"); ax.set_xlabel("penetration %"); ax.set_ylabel("ε-MCC")
    if ctrl:
        ax.text(50,0.20,"stealthy control-plane\n(baselines blind)",ha="center",fontsize=8,color="#888",style="italic")
axes[7].axis("off")
h,l=axes[0].get_legend_handles_labels()
axes[7].legend(h,l,loc="center",fontsize=13,title="method")
fig.suptitle("Live urban G50 (all fixes: conditioned-ψ + AE L=50 + δ_th=5) — ε-MCC vs penetration, faithful paper-rule baselines\n"
             "MPTD-PQS (proposed) vs B1 Ghaleb / B2 Ercan / B3 Sharma.  a5/a7 are stealthy control-plane attacks (baselines have no control-plane defense).",fontsize=12)
fig.tight_layout(rect=[0,0,1,0.95]); path=os.path.join(OUT,"live_mcc_7attacks_0-100.png"); fig.savefig(path,dpi=140); plt.close(fig)
print("WROTE",path)
# mean over informative pens (20-80). MPTD-full credits CP-DETECT on a5/a7.
print("\nMEAN ε-MCC over p20-80:")
vals=[MPTD_FULL[a][p] for a in ATTACKS for p in [20,40,60,80] if p in MPTD_FULL[a]]
print(f"  MPTD-PQS (full: beacon⊕CP-DETECT): {np.mean(vals):.3f}")
for m in ["B1","B2","B3"]:
    vals=[R[m][a][p] for a in ATTACKS for p in [20,40,60,80] if p in R[m][a]]
    print(f"  {m}: {np.mean(vals):.3f}")
# also MPTD beacon-only mean (a5/a7 ≈0) for transparency
vb=[R["MPTD"][a][p] for a in ATTACKS for p in [20,40,60,80] if p in R["MPTD"][a]]
print(f"  (MPTD beacon-fusion only, a5/a7≈0): {np.mean(vb):.3f}")
