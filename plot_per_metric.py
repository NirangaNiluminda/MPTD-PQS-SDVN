#!/usr/bin/env python3
"""
plot_per_metric.py — per-metric SOTA matrices (method × attack), from matrix.csv.
Also rebuilds the composite detection-score heatmap using CP-DETECT (parsed from the
control-plane logs) for attacks 5,7 instead of the degenerate 1-CDER.

For each of the 8 metric types produces a method×attack heatmap with the correct
color direction (higher-better vs lower-better). Baselines attributed faithfully:
control-plane CP-DETECT belongs to the proposed architecture (Algorithm 7); standalone
baselines have no controller-consensus auditor -> 0.

Usage: python3 plot_per_metric.py <run_dir>   (reads run_dir/matrix.csv + a5/a7 logs)
"""
import sys, os, csv, re, math, glob
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RUN = sys.argv[1]
CSV = os.path.join(RUN, "matrix.csv")
OUT = RUN
FULL_MODES = {"0","2","3","4","5","7","8"}
CONTROL = {"5","7"}
METHOD_ORDER = ["MPTD-PQS_full","B1_Ghaleb","B2_stdGAT","B3_stdAE"]
ATT = {"1":"TP-S1\nRSUdrift","2":"TP-S2\nspeed","3":"MP-S1\nSybil","4":"MP-S2\nimprs",
       "5":"TP-S3\nctrl","6":"MP-S3\nMitM","7":"MP-S4\nctrl"}

def fnum(x):
    try: return float(x)
    except: return float("nan")

rows = list(csv.DictReader(open(CSV)))
attacks = sorted({r["attack"] for r in rows}, key=int)
methods = [m for m in METHOD_ORDER if any(r["method"]==m for r in rows)]

# --- CP-DETECT rate for control-plane (proposed only; baselines 0 = no such detector) ---
def cp_rate(att):
    for pat in (f"a{att}_MPTD-PQS_full_newlam.log", f"a{att}_MPTD-PQS_full.log"):
        p=os.path.join(RUN,pat)
        if os.path.exists(p):
            t=open(p).read()
            m=re.search(r"CP-DETECT = (\d+) CTRL_COMPROMISED.*?over (\d+) audited epochs", t)
            if m: return int(m.group(1))/max(1,int(m.group(2)))
    return float("nan")
CP={a:cp_rate(a) for a in CONTROL if a in attacks}

def get(method,att,col):
    for r in rows:
        if r["method"]==method and r["attack"]==att:
            return fnum(r.get(col,"nan"))
    return float("nan")

def native_det(method,att):
    """composite detection score: MCC (spatial) / CP-DETECT (control-plane, proposed only)."""
    if att in CONTROL:
        return CP.get(att,float("nan")) if method=="MPTD-PQS_full" else 0.0
    mode=next((r["mode"] for r in rows if r["method"]==method and r["attack"]==att),"")
    return get(method,att,"MCC_full") if str(mode).strip() in FULL_MODES else get(method,att,"MCC")

def heat(grid, title, cmap, vmin, vmax, fname, fmt="{:.2f}", box_best=None):
    fig,ax=plt.subplots(figsize=(1.35*len(attacks)+2.2, 0.95*len(methods)+2))
    im=ax.imshow(grid,cmap=cmap,vmin=vmin,vmax=vmax,aspect="auto")
    ax.set_xticks(range(len(attacks))); ax.set_xticklabels([ATT.get(a,a) for a in attacks],fontsize=8)
    ax.set_yticks(range(len(methods))); ax.set_yticklabels(methods,fontsize=9)
    for i in range(len(methods)):
        for j in range(len(attacks)):
            v=grid[i,j]
            ax.text(j,i,"n/a" if math.isnan(v) else fmt.format(v),ha="center",va="center",fontsize=8)
    if box_best:  # box the winner per column
        for j in range(len(attacks)):
            col=[(i,grid[i,j]) for i in range(len(methods)) if not math.isnan(grid[i,j])]
            if col:
                wi=(max if box_best=="max" else min)(col,key=lambda t:t[1])[0]
                ax.add_patch(plt.Rectangle((j-0.5,wi-0.5),1,1,fill=False,edgecolor="blue",lw=2.4))
    fig.colorbar(im,ax=ax); ax.set_title(title,fontsize=10)
    fig.tight_layout(); fig.savefig(os.path.join(OUT,fname),dpi=140); plt.close(fig)
    return fname

def build(valfn,mask=None):
    g=np.full((len(methods),len(attacks)),np.nan)
    for i,m in enumerate(methods):
        for j,a in enumerate(attacks):
            v=valfn(m,a)
            if mask and mask(v): v=float("nan")
            g[i,j]=v
    return g

made=[]
# 1) composite detection score (CP-DETECT for control-plane) — the CORRECTED main heatmap
g=build(native_det)
made.append(heat(g,"Detection score — MCC (spatial) / CP-DETECT rate (control-plane 5,7, proposed only)\n"
                 "blue box = per-attack winner  (higher=better)","RdYlGn",-0.2,1.0,
                 "matrix_detection_cpfix.png",box_best="max"))

# 2) per-metric matrices  (col, pretty, cmap direction, vmin, vmax, better)
#   higher-better -> RdYlGn ; lower-better -> RdYlGn_r
def nat(col_full,col_lw):
    def f(m,a):
        mode=next((r["mode"] for r in rows if r["method"]==m and r["attack"]==a),"")
        return get(m,a,col_full) if str(mode).strip() in FULL_MODES else get(m,a,col_lw)
    return f
METRICS=[
  ("MCC",  nat("MCC_full","MCC"),      "RdYlGn",  -0.2,1.0,"max",None),
  ("FPR",  nat("FPR_full","FPR"),      "RdYlGn_r", 0.0,0.5,"min",None),
  ("PARR", lambda m,a:get(m,a,"PARR"), "RdYlGn",   0.0,1.0,"max",lambda v:v<-0.5),  # -1 = N/A
  ("CDER", lambda m,a:get(m,a,"CDER"), "RdYlGn_r", 0.0,1.0,"min",None),
  ("TDEE", lambda m,a:get(m,a,"TDEE"), "RdYlGn_r", 0.0,1.0,"min",None),
  ("TPE",  lambda m,a:get(m,a,"TPE"),  "RdYlGn_r", 0.0,None,"min",None),
  ("PBPO_Full_ms", lambda m,a:get(m,a,"PBPO_Full_ms"),"RdYlGn_r",0.0,None,"min",None),
  ("TTD",  lambda m,a:get(m,a,"TTD"),  "RdYlGn_r", 0.0,None,"min",None),
]
for name,fn,cmap,vmin,vmax,better,mask in METRICS:
    g=build(fn,mask)
    vmx=vmax if vmax is not None else (np.nanmax(g) if np.isfinite(np.nanmax(g)) else 1.0)
    arrow="↑" if better=="max" else "↓"
    made.append(heat(g,f"{name}  ({arrow} better) — method × attack",cmap,vmin,vmx,
                     f"metric_{name}.png",fmt="{:.2f}",box_best=better))

# 3) combined grid of all metric heatmaps
n=len(METRICS)+1; cols=3; rws=(n+cols-1)//cols
fig,axes=plt.subplots(rws,cols,figsize=(5.0*cols,3.0*rws)); axes=axes.flatten()
panels=[("Detection (CP-fixed)",build(native_det),"RdYlGn",-0.2,1.0,"max")]
for name,fn,cmap,vmin,vmax,better,mask in METRICS:
    g=build(fn,mask); vmx=vmax if vmax is not None else np.nanmax(g)
    panels.append((f"{name} ({'↑' if better=='max' else '↓'})",g,cmap,vmin,vmx,better))
for k,(t,g,cmap,vmin,vmax,better) in enumerate(panels):
    ax=axes[k]; im=ax.imshow(g,cmap=cmap,vmin=vmin,vmax=vmax,aspect="auto")
    ax.set_xticks(range(len(attacks))); ax.set_xticklabels([a for a in attacks],fontsize=7)
    ax.set_yticks(range(len(methods))); ax.set_yticklabels([m.replace("_","\n") for m in methods],fontsize=6)
    for i in range(len(methods)):
        for j in range(len(attacks)):
            v=g[i,j]; ax.text(j,i,"" if math.isnan(v) else f"{v:.2f}",ha="center",va="center",fontsize=6)
    ax.set_title(t,fontsize=9)
for k in range(len(panels),len(axes)): axes[k].axis("off")
fig.suptitle("MPTD-PQS vs B1/B2/B3 — all metrics × 7 attacks (cols a1..a7)",fontsize=13)
fig.tight_layout(rect=[0,0,1,0.97]); fig.savefig(os.path.join(OUT,"all_metrics_grid.png"),dpi=140); plt.close(fig)
made.append("all_metrics_grid.png")

print("CP-DETECT control-plane rates (proposed): "+", ".join(f"a{a}={CP[a]:.2f}" for a in CP))
print("generated in", OUT+":")
for f in made: print("  ", f)
