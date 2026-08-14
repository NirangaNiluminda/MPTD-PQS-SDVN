#!/usr/bin/env python3
"""
heldout_regen_full.py — regenerate the SOTA figure with the UPDATED proposed
method (multi-task GAT + ψ/sig_mask features + FPR-capped attack-conditioned λ).

MPTD-PQS_full is scored OFFLINE (re-score, not re-simulate): per (attack,pct) it
reconstructs the 3 fusion tier-scores + k̂ from the DEPLOYED GAT/LSTM-AE ONNX +
scaler, applies Φ = λ^(k̂)·(ψ_n,gat_n,ae_n) > Φ_th (deployed fusion_weights.json),
and builds the confusion matrix vs is_poisoned. Baselines (Ercan B2, Sharma B3)
are fit on the SAME train pcts and predicted per pct — a fair, shared split.

Split: λ + baselines TRAINED on p40/p60 (in-sample); HELD-OUT test pcts 0/20/80/100
(0/100 are single-class → ε-MCC still defined). ε-smoothed MCC (Eq 4.1).

Usage: python3 heldout_regen_full.py [scen=urban]
"""
import sys, os, json, math
import numpy as np, pandas as pd, onnxruntime as ort
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "analytics", "ml"))
from gat_detector import build_edge_index, SIG_BITS
from mptd_pqs import ercan_b2_detector_v2 as B2
from mptd_pqs import sharma_b3_detector_v2 as B3
from mptd_pqs import ghaleb_b1_detector as B1
from sklearn.metrics import confusion_matrix

SCEN = sys.argv[1] if len(sys.argv) > 1 else "urban"
ROOT = os.path.dirname(os.path.abspath(__file__))
ML   = os.path.join(ROOT, "analytics", "ml", "models", SCEN)
DS   = f"/home/sdvn_mobility_flooding/Desktop/dataset_G50-mobility/{SCEN}"
OUT  = os.path.join(ROOT, "analytics", "results", "regen"); os.makedirs(OUT, exist_ok=True)
ATTACKS = [1,2,3,4,5,6,7]; TRAIN_PCTS = [40,60]; TEST_PCTS = [0,20,40,60,80,100]
FEAT = ["pos_x","pos_y","speed","heading","accel"]; PSI_TH=0.09; EPS=1e-12; W=50 if SCEN=="urban" else 10

sc = json.load(open(f"{ML}/scaler.json")); MEAN=np.array(sc["mean"]); SCALE=np.array(sc["scale"])
THETA_S=float(open(f"{ML}/theta_s.txt").read()); THETA_AE=float(open(f"{ML}/theta_ae.txt").read())
THETA_HEAD=float(open(f"{ML}/theta_head.txt").read())   # head-detection tier threshold
FW = json.load(open(f"{ML}/fusion_weights.json")); PHI_TH=FW["phi_threshold"]
LAM = {s["attack"]: (s["psi"], s["gat"], s["ae"]) for s in FW["lambda_sets"]}
GLOB = (FW["lambda_psi"], FW["lambda_gat"], FW["lambda_ae"])
# sir Change 1+2: attack-conditioned signature weights w_s^(k̂) + θ_conf gate.
# Present only if the fusion_weights.json was produced by the conditioned refit.
_WSETS = {s["attack"]: np.array(s["w"]) for s in FW.get("sig_weight_sets", [])}
_WGLOB = np.array(FW["sig_weight_global"]) if "sig_weight_global" in FW else None
_THETA_CONF = FW.get("theta_conf", 0.7)
_COND = bool(_WSETS) and _WGLOB is not None
gat = ort.InferenceSession(f"{ML}/gat_model.onnx"); ae = ort.InferenceSession(f"{ML}/lstm_ae_model.onnx")


def emcc(tp,fp,tn,fn):
    num=(tp+EPS)*(tn+EPS)-(fp+EPS)*(fn+EPS)
    den=math.sqrt((tp+fp+EPS)*(tp+fn+EPS)*(tn+fp+EPS)*(tn+fn+EPS))
    fpr=fp/(fp+tn) if (fp+tn) else 0.0
    return num/den, fpr


def mptd_cm(d):
    """Offline proposed-method decision → (tp,fp,tn,fn) using deployed models+λ."""
    d = d.sort_values(["vehicle_id","sim_time"]).reset_index(drop=True)
    d["_tick"] = (d.sim_time/0.1).round().astype(int)
    ginfo = {}   # (tick,vid) -> (gat_n, khat)
    for _, g in d.groupby("_tick"):
        if len(g) < 2: continue
        raw = g[FEAT].values.astype(np.float32)
        kin = ((raw-MEAN[:5])/np.where(SCALE[:5]==0,1,SCALE[:5])).astype(np.float32)
        tau = np.ones((len(g),1),np.float32); psi=g["psi_score"].fillna(0).values.astype(np.float32).reshape(-1,1)
        sm  = g["sig_mask"].fillna(0).values.astype(np.int64)
        bits= np.stack([((sm>>b)&1) for b in range(SIG_BITS)],1).astype(np.float32)
        x = np.hstack([kin,tau,psi,bits]).astype(np.float32)
        ei = build_edge_index(raw[:,:2].astype(np.float32),raw[:,3].astype(np.float32),raw[:,2].astype(np.float32)).numpy().astype(np.int64)
        o = gat.run(None,{"x":x,"edge_index":ei}); S=o[0].reshape(-1); ap=o[1]
        for i,(_,row) in enumerate(g.iterrows()):
            mx=int(ap[i].argmax()); kh = mx+1 if ap[i][mx] > 0.5 else -1
            # GAT tier = spatial S_i/θ_S (head-detection tier rejected — see sweep note)
            ginfo[(row._tick,row.vehicle_id)] = (min(1.0,max(0.0,float(S[i])/THETA_S)), mx+1, float(ap[i][mx]))
    tp=fp=tn=fn=0
    for vid, g in d.groupby("vehicle_id"):
        g=g.reset_index(drop=True); arr=g[FEAT].values.astype(np.float32)
        w6=(np.hstack([arr,np.ones((len(g),1),np.float32)])-MEAN)/np.where(SCALE==0,1,SCALE)
        for j in range(W-1,len(g)):
            key=(int(g._tick[j]),vid)
            if key not in ginfo: continue
            gat_n,khat,conf = ginfo[key]
            rec=ae.run(None,{"x":w6[j-W+1:j+1].astype(np.float32)[None]})[0]
            ae_n=min(1.0,max(0.0,float(np.mean((rec-w6[j-W+1:j+1][None])**2))/THETA_AE))
            if _COND:
                # Change 2 gate: commit to k̂ only if confident, else fall back to
                # aggregate signature weights + average λ (GLOB).
                use_k = khat if (khat>0 and conf>=_THETA_CONF and khat in _WSETS) else -1
                w = _WSETS[khat] if use_k>0 else _WGLOB
                sm = g.sig_mask[j]; sm = 0 if (sm!=sm) else int(sm)   # NaN-safe
                bits = np.array([((sm>>bb)&1) for bb in range(9)],float)
                psi_n = min(1.0,max(0.0, float(bits@w)/PSI_TH)); kh = use_k
            else:
                psi_n=min(1.0,max(0.0,float(g.psi_score[j])/PSI_TH))
                kh = khat if conf>0.5 else -1
            lp,lg,la = LAM.get(kh, GLOB) if kh>0 else GLOB
            phi = lp*psi_n + lg*gat_n + la*ae_n
            flag = phi > PHI_TH; gt = int(g.is_poisoned[j])==1
            tp+=flag&gt; fp+=flag&(not gt); tn+=(not flag)&(not gt); fn+=(not flag)&gt
    return tp,fp,tn,fn


def base_fit(mod, a):
    frames=[mod.load_scenario(f"{DS}/a{a}_p{p}") for p in TRAIN_PCTS]
    frames=[f for f in frames if f is not None]
    if not frames: return None
    fr=pd.concat(frames,ignore_index=True); X=fr[mod.FEATURE_COLS].values; y=fr["label"].values
    if len(np.unique(y))<2: return None
    from sklearn.ensemble import RandomForestClassifier
    c=RandomForestClassifier(n_estimators=100,random_state=42,class_weight="balanced",n_jobs=-1)
    c.fit(X,y); return c


def base_cm(mod, clf, a, p):
    te=mod.load_scenario(f"{DS}/a{a}_p{p}")
    if te is None or clf is None: return None
    te=te.dropna(subset=mod.FEATURE_COLS+["label"])
    X=te[mod.FEATURE_COLS].values; y=te["label"].values.astype(int); yp=clf.predict(X).astype(int)
    cm=confusion_matrix(y,yp,labels=[0,1])
    tn,fp,fn,tp=cm.ravel() if cm.size==4 else (cm[0,0],0,0,0)
    return int(tp),int(fp),int(tn),int(fn)


def b1_cm(a, p):
    """Ghaleb B1 LTT — rule-based, no fit: run detector, cm vs is_poisoned."""
    try: aug = B1.load_scenario(f"{DS}/a{a}_p{p}")
    except Exception: return None
    if aug is None or "is_poisoned" not in aug or len(aug) < 2: return None
    try: dd = B1.GhalebB1Detector().run(aug)
    except Exception: return None
    y = aug["is_poisoned"].values.astype(int); yp = dd["pred"].values.astype(int)
    n = min(len(y), len(yp)); y, yp = y[:n], yp[:n]
    cm = confusion_matrix(y, yp, labels=[0,1])
    tn,fp,fn,tp = cm.ravel() if cm.size==4 else (cm[0,0],0,0,0)
    return int(tp),int(fp),int(tn),int(fn)

def base_fit_global(mod):
    """ONE model per baseline trained on ALL attacks' train pcts combined —
    the fair generalist comparison vs MPTD's single model (no per-attack
    specialisation). Matches the established 'baseline = one global model' rule."""
    frames=[mod.load_scenario(f"{DS}/a{a}_p{p}") for a in ATTACKS for p in TRAIN_PCTS]
    frames=[f for f in frames if f is not None]
    if not frames: return None
    fr=pd.concat(frames,ignore_index=True)
    fr=fr.dropna(subset=mod.FEATURE_COLS+["label"])
    X=fr[mod.FEATURE_COLS].values; y=fr["label"].values
    if len(np.unique(y))<2: return None
    from sklearn.ensemble import RandomForestClassifier
    c=RandomForestClassifier(n_estimators=100,random_state=42,class_weight="balanced",n_jobs=-1)
    c.fit(X,y); return c

BASELINE_MODE = os.environ.get("BASELINE_MODE","perattack")   # perattack | global
SUFX = "" if BASELINE_MODE=="perattack" else "_global"
print(f"[regen] {SCEN}: baseline_mode={BASELINE_MODE}, fitting on p{TRAIN_PCTS} …")
if BASELINE_MODE=="global":
    gb2=base_fit_global(B2); gb3=base_fit_global(B3)
    b2={a:gb2 for a in ATTACKS}; b3={a:gb3 for a in ATTACKS}
else:
    b2 = {a: base_fit(B2,a) for a in ATTACKS}
    b3 = {a: base_fit(B3,a) for a in ATTACKS}
R = {}   # (metric)-> per method per attack per pct
methods=["MPTD-PQS_full","B1_Ghaleb","B2_Ercan","B3_Sharma"]
data={m:{a:{} for a in ATTACKS} for m in methods}
for a in ATTACKS:
    for p in TEST_PCTS:
        d=None
        try: d=pd.read_csv(f"{DS}/a{a}_p{p}/beacon_log.csv")
        except FileNotFoundError: pass
        if d is not None:
            cm=mptd_cm(d); data["MPTD-PQS_full"][a][p]=emcc(*cm)
        cmb1=b1_cm(a,p)
        if cmb1: data["B1_Ghaleb"][a][p]=emcc(*cmb1)
        for mod,fit,name in [(B2,b2[a],"B2_Ercan"),(B3,b3[a],"B3_Sharma")]:
            cm=base_cm(mod,fit,a,p)
            if cm: data[name][a][p]=emcc(*cm)
    row=lambda nm: " ".join(f"p{p}={data[nm][a].get(p,(float('nan'),))[0]:.2f}" for p in TEST_PCTS)
    print(f"  a{a} MPTD MCC: {row('MPTD-PQS_full')}")

col={"MPTD-PQS_full":"#2ca02c","B1_Ghaleb":"#8c564b","B2_Ercan":"#1f77b4","B3_Sharma":"#d62728"}
for mi,(metric,idx,up) in enumerate([("MCC",0,True),("FPR",1,False)]):
    fig,axes=plt.subplots(2,4,figsize=(20,8)); axes=axes.flatten()
    for i,a in enumerate(ATTACKS):
        ax=axes[i]
        for m in methods:
            xs=[p for p in TEST_PCTS if p in data[m][a]]; ys=[data[m][a][p][idx] for p in xs]
            ax.plot(xs,ys,"o-",color=col[m],label=m,lw=2,ms=5)
        for tp in TRAIN_PCTS: ax.axvline(tp,color="gray",ls=":",alpha=0.4)
        ax.set_title(f"Attack {a}"); ax.set_xlabel("penetration %"); ax.set_ylabel(metric); ax.grid(alpha=0.3)
        if metric=="MCC": ax.set_ylim(-0.1,1.05)
    axes[0].legend(fontsize=8); axes[7].axis("off")
    _bl = "7 per-attack specialist models" if BASELINE_MODE=="perattack" else "ONE global model (all 7 attacks)"
    fig.suptitle(f"HELD-OUT {metric} ({'↑' if up else '↓'} better) — {SCEN} — MPTD-PQS(1 generalist) vs Ghaleb/Ercan/Sharma [{_bl}]. dotted=train pcts",fontsize=12)
    fig.tight_layout(rect=[0,0,1,0.96]); path=os.path.join(OUT,f"regen_{SCEN}_{metric}{SUFX}.png")
    fig.savefig(path,dpi=140); plt.close(fig); print(f"[regen] wrote {path}")
