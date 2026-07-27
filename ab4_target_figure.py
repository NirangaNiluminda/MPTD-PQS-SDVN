#!/usr/bin/env python3
"""AB4 TARGET figure — what the four metrics would look like if the system were
instrumented and wired as intended. Panels (a),(b) are MEASURED (already correct
once read off the fusion); (c),(d) are MODELLED projections computed from the
measured recall / FPR / poison fraction, NOT simulation output. Clearly marked.
"""
import numpy as np, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
EPS=("0.1","0.2","0.3","0.4","0.5"); x=np.arange(5)
# measured (fusion-reconstructed)
mcc_f=[-0.021,0.019,0.133,0.273,0.367]; mcc_f_sd=[0.090,0.084,0.088,0.102,0.122]
mcc_a=[0.024,0.024,0.024,0.025,0.025];  mcc_a_sd=[0.082,0.082,0.082,0.076,0.076]
ttd_f=[5.613,5.613,5.346,4.644,4.394];  ttd_f_sd=[1.882,1.882,2.018,0.657,0.259]
# modelled: CDER with FPR cut to 0.05 (well-calibrated AE), same recall
cder_f=[0.186,0.178,0.151,0.115,0.089]; cder_a=[0.184]*5
# modelled: TPE if detected poisoned beacons were excluded from the estimate
tpe_f=[0.139,0.248,0.348,0.437,0.523];  tpe_a=[0.145,0.260,0.375,0.491,0.606]
C={0:"#1f77b4",4:"#ff7f0e"}
fig,axes=plt.subplots(1,4,figsize=(19,4.3))
P=[("(a) detection quality  [MEASURED]","MCC",mcc_f,mcc_f_sd,mcc_a,mcc_a_sd,None),
   ("(b) detection latency  [MEASURED]","TTD (s)",ttd_f,ttd_f_sd,None,None,"AB4: no detection\n(censored)"),
   ("(c) control-plane error  [MODEL]","CDER",cder_f,None,cder_a,None,"model: AE FPR cut\n0.247 → 0.05"),
   ("(d) trajectory error  [MODEL]","TPE (m)",tpe_f,None,tpe_a,None,"model: detected beacons\nexcluded from estimate")]
for ax,(title,ylab,f,fsd,a,asd,note) in zip(axes,P):
    if fsd is not None:
        ax.errorbar(x,f,yerr=fsd,color=C[0],marker="o",ms=7,lw=2,capsize=3,elinewidth=1.2)
    else:
        ax.plot(x,f,color=C[0],marker="o",ms=7,lw=2)
    if a is not None:
        if asd is not None: ax.errorbar(x,a,yerr=asd,color=C[4],marker="s",ms=7,lw=2,capsize=3,elinewidth=1.2)
        else: ax.plot(x,a,color=C[4],marker="s",ms=7,lw=2,ls="--")
        ax.annotate("AB4",xy=(x[-1],a[-1]),xytext=(7,0),textcoords="offset points",
                    color=C[4],fontsize=11,fontweight="bold",va="center")
    else:
        ax.axhline(8.0,color=C[4],lw=2,ls=":"); ax.annotate("AB4 ✗",xy=(x[-1],8.0),
                    xytext=(7,0),textcoords="offset points",color=C[4],fontsize=11,
                    fontweight="bold",va="center")
    ax.annotate("full",xy=(x[-1],f[-1]),xytext=(7,0),textcoords="offset points",
                color=C[0],fontsize=11,fontweight="bold",va="center")
    if note: ax.text(0.03,0.95,note,transform=ax.transAxes,fontsize=9,va="top",color="#444441")
    ax.set_xticks(x); ax.set_xticklabels(EPS)
    ax.set_xlabel(r"stealth drift bound  $\epsilon_{max}$  (m per beacon)",fontsize=11)
    ax.set_ylabel(ylab,fontsize=11); ax.set_title(title,fontsize=12)
    ax.set_xlim(-0.25,4.45); ax.grid(True,alpha=0.3,lw=0.6)
h=[plt.Line2D([0],[0],color=C[0],marker="o",lw=2,label="SENTINEL (full)"),
   plt.Line2D([0],[0],color=C[4],marker="s",lw=2,label="AB4 (LSTM-AE removed)")]
fig.legend(handles=h,loc="lower center",ncol=2,frameon=False,fontsize=11,bbox_to_anchor=(0.5,-0.045))
fig.suptitle("AB4 TARGET — how the four metrics should behave once TTD/CDER read the fusion, "
             "the AE is calibrated, and detection drives mitigation  (c,d are models, not runs)",
             fontsize=12.5,y=1.02)
fig.tight_layout(rect=[0,0.04,1,1])
o="/home/sdvn_mobility_flooding/Desktop/SENTINEL_experiments/AB4_final/fig_AB4_TARGET"
fig.savefig(o+".png",dpi=200,bbox_inches="tight"); fig.savefig(o+".pdf",bbox_inches="tight")
print("saved:",o+".png / .pdf")
