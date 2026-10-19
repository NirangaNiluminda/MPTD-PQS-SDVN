#!/usr/bin/env python3
"""AB5 (full AI removed = lightweight only) speed-sweep deliverable, 6 panels.
FULL = mode0 fusion metrics; AB5 = mode1 lightweight. CDER uses CDER_full for FULL
(fusion-verdict control error) vs LW CDER for AB5. TDEE/TPE detector-invariant."""
import re,os,numpy as np,matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
D="/home/sdvn_mobility_flooding/Desktop/SENTINEL_experiments/AB5_final"
V=(10,60,100,140); SEEDS=(1,2,3); x=np.arange(4)
def gv(f,pat):
    if not os.path.exists(f): return np.nan
    for ln in open(f,errors='ignore'):
        if ln.startswith(pat):
            m=re.search(r'=\s*([-0-9.]+)',ln); return float(m.group(1)) if m else np.nan
    return np.nan
def agg(mode,pat):
    M=[];S=[]
    for v in V:
        xs=[gv(f"{D}/v{v}_m{mode}_s{s}.log",pat) for s in SEEDS]; xs=[z for z in xs if z==z]
        M.append(np.mean(xs) if xs else np.nan); S.append(np.std(xs) if xs else 0)
    return np.array(M),np.array(S)
C={0:"#1f77b4",4:"#ff7f0e"}
# (title, FULL pat, AB5 pat, ylabel, note)
P=[("(a) detection quality — MCC","  MCC_full","  MCC ","MCC","FULL=fusion, AB5=lightweight"),
   ("(b) control-plane error — CDER","  CDER_full","  CDER ","CDER","FULL=fusion verdict (CDER_full)"),
   ("(c) detection latency — TTD (s)","  TTD ","  TTD ","TTD (s)","AB5=-1: lightweight never localizes"),
   ("(d) density error — TDEE","  TDEE","  TDEE","TDEE","detector-invariant"),
   ("(e) trajectory error — TPE (m)","  TPE ","  TPE ","TPE (m)","detector-invariant (attack-side)"),
   ("(f) per-beacon overhead — PBPO (ms)","  PBPO_Full","  PBPO_Full","PBPO (ms)","the AI-layer cost")]
fig,axes=plt.subplots(2,3,figsize=(16,8.5))
for ax,(title,fp,ap,yl,note) in zip(axes.flat,P):
    fm,fs=agg(0,fp); am,as_=agg(1,ap)
    ax.errorbar(x,fm,yerr=fs,color=C[0],marker="o",ms=7,lw=2,capsize=3,elinewidth=1.2)
    ax.errorbar(x,am,yerr=as_,color=C[4],marker="s",ms=7,lw=2,capsize=3,elinewidth=1.2,ls="--")
    ax.annotate("full",xy=(x[-1],fm[-1]),xytext=(6,0),textcoords="offset points",color=C[0],fontsize=10,fontweight="bold",va="center")
    ax.annotate("AB5",xy=(x[-1],am[-1]),xytext=(6,0),textcoords="offset points",color=C[4],fontsize=10,fontweight="bold",va="center")
    ax.text(0.03,0.94,note,transform=ax.transAxes,fontsize=8.5,va="top",color="#444441")
    ax.set_xticks(x); ax.set_xticklabels([str(v) for v in V])
    ax.set_xlabel("vehicle speed (km/h)",fontsize=10); ax.set_ylabel(yl,fontsize=10)
    ax.set_title(title,fontsize=11); ax.set_xlim(-0.25,3.55); ax.grid(True,alpha=0.3,lw=0.6)
h=[plt.Line2D([0],[0],color=C[0],marker="o",lw=2,label="SENTINEL (full AI layer)"),
   plt.Line2D([0],[0],color=C[4],marker="s",lw=2,label="AB5 (lightweight only)")]
fig.legend(handles=h,loc="lower center",ncol=2,frameon=False,fontsize=11,bbox_to_anchor=(0.5,-0.02))
fig.suptitle("AB5 — Detection Infeasible Zone: full AI layer vs lightweight-only across vehicle speed "
             "(combined attack, 3 seeds, mean ± s.d.)",fontsize=12.5,y=1.0)
fig.tight_layout(rect=[0,0.03,1,0.99])
o=f"{D}/fig_AB5_speed_sweep"
fig.savefig(o+".png",dpi=200,bbox_inches="tight"); fig.savefig(o+".pdf",bbox_inches="tight")
print("saved:",o+".png / .pdf")
