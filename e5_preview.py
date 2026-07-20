#!/usr/bin/env python3
"""
e5_preview.py — SENTINEL Step-1 preview: per-attack MCC table at ρ_a≈0.40 (p40)
from the live all-fixes dataset. MPTD full mode (beacon fusion; CP-DETECT for the
stealthy control-plane a5/a7) vs faithful paper-rule baselines B1/B2/B3. ε-MCC.
Single-seed preview — the ≥3-seed + full-metric E5 is the follow-on campaign.
"""
import os, sys, json, math, re
import numpy as np, pandas as pd, onnxruntime as ort
ROOT="/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN"; sys.path.insert(0,ROOT); sys.path.insert(0,os.path.join(ROOT,"analytics","ml"))
from gat_detector import build_edge_index, SIG_BITS
from mptd_pqs import ercan_b2_detector_v2 as B2, sharma_b3_detector_v2 as B3, ghaleb_b1_detector as B1
DS=os.path.join(ROOT,"analytics","datasets","urban"); PEN=40; EPS=1e-12; B2_CI=1.96; S_MAX=33.33
RT=B1.load_road_index(os.path.join(ROOT,"sumo","urban","urban.net.xml")); RP=B1.load_rsu_positions(os.path.join(ROOT,"mobility","rsu_positions_urban.csv"))
FEAT=["pos_x","pos_y","speed","heading","accel"]; PSI_TH,PHI_TH,W=0.09,0.5,50
MLU=os.path.join(ROOT,"analytics","ml","models","urban"); sc=json.load(open(f"{MLU}/scaler.json")); MEAN=np.array(sc["mean"]); SCALE=np.array(sc["scale"])
THETA_S=float(open(f"{MLU}/theta_s.txt").read()); THETA_AE=float(open(f"{MLU}/theta_ae.txt").read())
FW=json.load(open(f"{MLU}/fusion_weights.json")); WSETS={s["attack"]:np.array(s["w"]) for s in FW["sig_weight_sets"]}; WGLOB=np.array(FW["sig_weight_global"])
TC=FW.get("theta_conf",0.7); LAM={s["attack"]:(s["psi"],s["gat"],s["ae"]) for s in FW["lambda_sets"]}; GLOB=(FW["lambda_psi"],FW["lambda_gat"],FW["lambda_ae"])
gat=ort.InferenceSession(f"{MLU}/gat_model.onnx"); ae=ort.InferenceSession(f"{MLU}/lstm_ae_model.onnx")
# sir's attack labels ↔ our code number
NAME={1:"a1 TP-S1 (comp-RSU drift)",2:"a2 TP-S2 (mal-vehicle)",3:"a3 MP-S1 (Sybil-RSU)",4:"a4 MP-S2 (impersonation)",5:"a5 TP-S3 (ctrl-plane)*",6:"a6 MP-S3 (MitM)",7:"a7 MP-S4 (ctrl-plane)*"}
def emcc(y,yp):
    y=np.asarray(y).astype(bool);yp=np.asarray(yp).astype(bool)
    tp=np.sum(yp&y);fp=np.sum(yp&~y);tn=np.sum(~yp&~y);fn=np.sum(~yp&y)
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.0)
def mptd(a):
    f=f"{DS}/a{a}_p40_m0/beacon_log.csv"
    if not os.path.isfile(f): return None
    d=pd.read_csv(f).sort_values(["vehicle_id","sim_time"]).reset_index(drop=True); d["_tick"]=(d.sim_time/0.1).round().astype(int)
    gi={}
    for _,g in d.groupby("_tick"):
        if len(g)<2: continue
        raw=g[FEAT].values.astype(np.float32);kin=((raw-MEAN[:5])/np.where(SCALE[:5]==0,1,SCALE[:5])).astype(np.float32)
        tau=np.ones((len(g),1),np.float32);psi=g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1,1)
        sm=g["sig_mask"].fillna(0).values.astype(np.int64);bits=np.stack([((sm>>b)&1) for b in range(SIG_BITS)],1).astype(np.float32)
        x=np.hstack([kin,tau,psi,bits]).astype(np.float32);ei=build_edge_index(raw[:,:2].astype(np.float32),raw[:,3].astype(np.float32),raw[:,2].astype(np.float32)).numpy().astype(np.int64)
        o=gat.run(None,{"x":x,"edge_index":ei});S=o[0].reshape(-1);ap=o[1]
        for i,(_,r) in enumerate(g.iterrows()):
            mx=int(ap[i].argmax());gi[(r._tick,r.vehicle_id)]=(min(1.,max(0.,float(S[i])/THETA_S)),mx+1,float(ap[i][mx]))
    tp=fp=tn=fn=0
    for vid,g in d.groupby("vehicle_id"):
        g=g.reset_index(drop=True);arr=g[FEAT].values.astype(np.float32);w6=(np.hstack([arr,np.ones((len(g),1),np.float32)])-MEAN)/np.where(SCALE==0,1,SCALE);sm=g["sig_mask"].fillna(0).values.astype(np.int64)
        for j in range(W-1,len(g)):
            key=(int(g._tick[j]),vid)
            if key not in gi: continue
            gat_n,kh,conf=gi[key];rec=ae.run(None,{"x":w6[j-W+1:j+1].astype(np.float32)[None]})[0];ae_n=min(1.,max(0.,float(np.mean((rec-w6[j-W+1:j+1][None])**2))/THETA_AE))
            uk=kh if (kh>0 and conf>=TC and kh in WSETS) else -1;w=WSETS[kh] if uk>0 else WGLOB;b=np.array([((int(sm[j])>>bb)&1) for bb in range(9)],float);psi_n=min(1.,max(0.,float(b@w)/PSI_TH))
            lp,lg,la=LAM.get(uk,GLOB) if uk>0 else GLOB;phi=lp*psi_n+lg*gat_n+la*ae_n
            flag=(phi>PHI_TH) or (float(g.speed[j])>S_MAX);gt=int(g.is_poisoned[j])==1
            tp+=flag&gt;fp+=flag&(not gt);tn+=(not flag)&(not gt);fn+=(not flag)&gt
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS);den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    return num/den,(fp/(fp+tn) if (fp+tn) else 0.)
def cpd(a):
    sl=f"/home/sdvn_mobility_flooding/Desktop/dataset_G50_live_allfixes/urban/a{a}_p40/sim.log"
    if not os.path.isfile(sl): return None
    m=re.findall(r"CP-DETECT = (\d+) CTRL_COMPROMISED[^)]*\) over (\d+)",open(sl,errors="ignore").read())
    if not m: return None
    n,tot=map(int,m[-1]);return n/tot if tot else None
def offline_ttd(a):
    f=f"{DS}/a{a}_p40_m0/beacon_log.csv"
    if not os.path.isfile(f): return None
    d=pd.read_csv(f).sort_values(["vehicle_id","sim_time"]); ts=[]
    for vid,g in d.groupby("vehicle_id"):
        p=g[g.is_poisoned==1]
        if len(p)==0: continue
        onset=p.sim_time.min(); det=g[(g.detected==1)&(g.sim_time>=onset)]
        if len(det)==0: continue
        ts.append(det.sim_time.min()-onset)
    return float(np.mean(ts)) if ts else None

def base(mod,a,ci=None):
    d=f"{DS}/a{a}_p40_m0"
    if mod=="B1":
        aug=B1.load_scenario(d);
        if aug is None or len(aug)<2: return None
        dd=B1.GhalebB1Detector(road_tree=RT,road_tol=25.0,rsu_pos=RP).run(aug);n=min(len(aug),len(dd));return emcc(aug["is_poisoned"].values[:n].astype(int),dd["pred"].values[:n].astype(int))
    M=B2 if mod=="B2" else B3;f=M.load_scenario(d)
    if f is None: return None
    f=f.dropna(subset=M.FEATURE_COLS+["label"])
    if len(f)<2: return None
    return emcc(f["label"].values, M.paper_rule_predict(f,ci=B2_CI) if mod=="B2" else M.paper_rule_predict(f))

print(f"SENTINEL E5 (PREVIEW) — per-attack MCC @ ρ_a≈0.40 (p40), single seed, live all-fixes urban")
print(f"{'attack (sir label)':<28} | {'MPTD-PQS':>10} | {'B1 Ghaleb':>10} | {'B2 Ercan':>9} | {'B3 Sharma':>10}")
print("-"*80)
rows=[]
for a in range(1,8):
    m=mptd(a); mm = m[0] if m else float('nan')
    if a in (5,7):
        c=cpd(a); disp=f"{c:.2f}(CP)" if c is not None else f"{mm:.2f}"
    else: disp=f"{mm:.2f}"
    b1=base("B1",a); b2=base("B2",a); b3=base("B3",a)
    g=lambda x:(f"{x[0]:.2f}" if x else "  -")
    print(f"{NAME[a]:<28} | {disp:>10} | {g(b1):>10} | {g(b2):>9} | {g(b3):>10}")
    rows.append((a,mm,b1[0] if b1 else np.nan,b2[0] if b2 else np.nan,b3[0] if b3 else np.nan))
print("-"*80)
R=np.array([r[1:] for r in rows])
print(f"{'MEAN':<28} | {np.nanmean(R[:,0]):>10.2f} | {np.nanmean(R[:,1]):>10.2f} | {np.nanmean(R[:,2]):>9.2f} | {np.nanmean(R[:,3]):>10.2f}")
print("\n* a5/a7 = stealthy control-plane: MPTD value is CP-DETECT flag-rate (beacon detectors incl. baselines ≈0).")

# ── SENTINEL full-mode secondary metrics from archived metrics.csv ──
print("\nSENTINEL full-mode metrics (from metrics.csv):")
print(f"{'attack':<28} | {'TTD':>7} {'CDER':>6} {'TDEE':>6} {'TPE':>7} {'PBPO_Full':>9}")
for a in range(1,8):
    mf=f"{DS}/a{a}_p40_m0/metrics.csv"
    if not os.path.isfile(mf): print(f"{NAME[a]:<28} | (no metrics.csv)"); continue
    m=pd.read_csv(mf).iloc[-1]
    def gv(c): return f"{m[c]:.3f}" if c in m and pd.notna(m[c]) else "  -"
    _t=offline_ttd(a); ttdv=f"{_t:.2f}" if _t is not None else "-"   # offline (C++ TTD metric buggy)
    print(f"{NAME[a]:<28} | {ttdv:>7} {gv('CDER'):>6} {gv('TDEE'):>6} {gv('TPE'):>7} {gv('PBPO_Full_ms'):>9}")
