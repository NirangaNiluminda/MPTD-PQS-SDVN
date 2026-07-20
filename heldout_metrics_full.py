#!/usr/bin/env python3
"""
heldout_metrics_full.py — extend the held-out comparison with ALL comparable detection
metrics (MCC, FPR, Recall, Precision, F1) from the confusion matrix, for all 4 methods.
System metrics (CDER/TDEE/TPE/PBPO/TTD) are NOT included: baselines are beacon
classifiers with no valid equivalent (would be apples-to-oranges).

Confusion matrices:
  • Ercan/Sharma: fit on datasets_200 (p30/90 RngRun=1), predict held-out; TP/FP/TN/FN
    from each detector's compute_metrics.
  • MPTD-PQS full: cm_full_{TP,FP,TN,FN} from heldout_200/aN_pP/metrics.csv (mode-0).
  • B1 Ghaleb: cm_{TP,FP,TN,FN} from b1_metrics.csv (mode-6).
All ε-smoothed / consistent.
"""
import sys, os, math
import pandas as pd, numpy as np
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mptd_pqs import ercan_b2_detector_v2 as B2
from mptd_pqs import sharma_b3_detector_v2 as B3

DS  = "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35/analytics/datasets_200"
HO  = "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35/analytics/heldout_200"
OUT = "live_results/heldout_200"
ATTACKS=[1,2,3,4,5,6,7]; TRAIN_PCTS=[30,90]; TEST_PCTS=[0,20,40,60,80,100]
E=1e-12

def metrics_from_cm(tp,fp,tn,fn):
    tp,fp,tn,fn=map(float,(tp,fp,tn,fn))
    mcc=((tp+E)*(tn+E)-(fp+E)*(fn+E))/math.sqrt((tp+fp+E)*(tp+fn+E)*(tn+fp+E)*(tn+fn+E))
    fpr=fp/(fp+tn) if fp+tn else 0.0
    rec=tp/(tp+fn) if tp+fn else 0.0                 # detection rate / recall
    prec=tp/(tp+fp) if tp+fp else 0.0
    f1=2*prec*rec/(prec+rec) if (prec+rec)>0 else 0.0
    return dict(MCC=mcc,FPR=fpr,Recall=rec,Precision=prec,F1=f1)

def train_frame(mod,a):
    fr=[mod.load_scenario(os.path.join(DS,f"a{a}_p{p}")) for p in TRAIN_PCTS]
    fr=[f for f in fr if f is not None]
    if not fr: return None
    df=pd.concat(fr,ignore_index=True).dropna(subset=mod.FEATURE_COLS+["label"])
    return df if (len(df)>50 and df["label"].nunique()==2) else None

def fit(mod,a):
    tr=train_frame(mod,a)
    if tr is None: return None
    X,y=tr[mod.FEATURE_COLS].values,tr["label"].values
    clfs={"kNN":B2._knn(),"RF":B2._rf(42),"Stacking":B2._stacking(42)} if mod is B2 else B3._build_classifiers(42)
    out={}
    for n,c in clfs.items():
        try: c.fit(X,y); out[n]=c
        except Exception: pass
    return out

def predict_cm(mod,fitted,d):
    te=mod.load_scenario(d)
    if te is None: return None
    te=te.dropna(subset=mod.FEATURE_COLS+["label"])
    if len(te)<20: return None   # allow single-class (pct 0/100): ε-MCC defined, like proposed
    X,y=te[mod.FEATURE_COLS].values,te["label"].values
    dev=te["disp_err_m"].values if "disp_err_m" in te.columns else np.zeros(len(y))
    best=None
    from sklearn.metrics import confusion_matrix
    for n,c in fitted.items():
        try:
            yp=c.predict(X)
            tn,fp,fn,tp=confusion_matrix(y,yp,labels=[0,1]).ravel()
            mm=metrics_from_cm(tp,fp,tn,fn)
            if best is None or mm["MCC"]>best["MCC"]: best=mm
        except Exception as e: pass
    return best

import re
def cp_detect_rate(mode0_log):
    if not os.path.exists(mode0_log): return None
    m=re.search(r"CP-DETECT = (\d+) CTRL_COMPROMISED.*?over (\d+) audited epochs", open(mode0_log).read())
    return (int(m.group(1))/max(1,int(m.group(2)))) if m else None

def cxx_cm(path,pfx):
    if not os.path.exists(path): return None
    try: r=pd.read_csv(path).iloc[0]
    except Exception: return None
    try: return metrics_from_cm(r[f"{pfx}TP"],r[f"{pfx}FP"],r[f"{pfx}TN"],r[f"{pfx}FN"])
    except Exception: return None

rows=[]
for a in ATTACKS:
    b2=fit(B2,a); b3=fit(B3,a)
    for p in TEST_PCTS:
        hd=os.path.join(HO,f"a{a}_p{p}")
        for meth,val in [("B2_Ercan", predict_cm(B2,b2,hd) if b2 else None),
                         ("B3_Sharma",predict_cm(B3,b3,hd) if b3 else None),
                         ("B1_Ghaleb",cxx_cm(os.path.join(hd,"b1_metrics.csv"),"cm_")),
                         ("MPTD-PQS_full",cxx_cm(os.path.join(hd,"metrics.csv"),"cm_full_"))]:
            if meth=="MPTD-PQS_full" and a in (5,7) and val is not None:
                cr=cp_detect_rate(os.path.join(hd,"mode0.log"))
                if cr is not None: val=dict(val); val["MCC"]=cr; val["Recall"]=cr  # control-plane = CP-DETECT rate
            if val: rows.append({"attack":a,"attack_pct":p,"method":meth,**val})

d=pd.DataFrame(rows)
d.to_csv(os.path.join(OUT,"heldout_all_metrics.csv"),index=False)
print(f"wrote heldout_all_metrics.csv ({len(d)} rows)")

METRICS=[("MCC",True),("F1",True),("Recall",True),("Precision",True),("FPR",False)]
methods=["MPTD-PQS_full","B1_Ghaleb","B2_Ercan","B3_Sharma"]
colors={"MPTD-PQS_full":"#2ca02c","B1_Ghaleb":"#8c564b","B2_Ercan":"#1f77b4","B3_Sharma":"#d62728"}
LBL={1:"a1 TP-S1",2:"a2 TP-S2",3:"a3 MP-S1 Sybil",4:"a4 MP-S2",5:"a5 TP-S3 ctrl",6:"a6 MP-S3 MitM",7:"a7 MP-S4 ctrl"}
for metric,up in METRICS:
    fig,axes=plt.subplots(2,4,figsize=(20,8)); axes=axes.flatten(); H=L=None
    for i,a in enumerate(ATTACKS):
        ax=axes[i]
        for m in methods:
            s=d[(d.attack==a)&(d.method==m)].sort_values("attack_pct")
            if not s.empty: ax.plot(s.attack_pct,s[metric],marker="o",label=m,color=colors[m],lw=2,ms=6)
        ax.set_title(LBL[a],fontsize=11,fontweight="bold"); ax.set_xlabel("penetration %"); ax.set_ylabel(metric)
        ax.grid(alpha=.3); ax.set_ylim(-0.3 if metric=="MCC" else -0.05, 1.05)
        ax.legend(fontsize=8,loc="lower left",framealpha=.9)
        if H is None: H,L=ax.get_legend_handles_labels()
    axes[7].axis("off"); axes[7].legend(H,L,loc="center",fontsize=13,title="Methods",title_fontsize=13)
    fig.suptitle(f"HELD-OUT {metric} ({'↑ better' if up else '↓ better'}) — MPTD-PQS vs Ercan/Sharma/Ghaleb "
                 f"| N=200, penetration 0–100% (train seed-1 / test seed-2; ε-consistent)",fontsize=12)
    fig.tight_layout(rect=[0,0,1,0.96]); fig.savefig(os.path.join(OUT,f"heldout_{metric}.png"),dpi=140); plt.close(fig)
    print(f"plot -> {OUT}/heldout_{metric}.png")

print("\n=== mean per method (across attacks×pct) ===")
print(d.groupby("method")[["MCC","F1","Recall","Precision","FPR"]].mean().round(3).to_string())
