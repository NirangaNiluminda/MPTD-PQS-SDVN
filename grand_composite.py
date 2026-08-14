#!/usr/bin/env python3
"""
grand_composite.py — ONE figure with ALL sensitivity panels:
  - detection params (MCC blue + FPR red twin axis) from DELIVERABLE_MASTER
  - overhead/latency params (single axis) from the latency deliverable
Usage: python3 grand_composite.py <detection_csv> <latency_csv> <out.png>
"""
import sys, csv, math
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DET = sys.argv[1]; LAT = sys.argv[2]; OUT = sys.argv[3]

SEL = {"psi_th":0.05,"kappa_th":0.50,"delta_th":5.0,"maxspeed":100,"drift_window":15,
       "k_sybil":4.0,"phi_th":0.51,"kappa_ae":3.0,"phi_max":1.5708,"dropout":0.6,
       "lr":0.005,"weight_decay":0.0,"gat_heads":4,"gat_hidden":32,"leaky_slope":0.2,
       "attack_pct":40,"stealth_gamma":0.7}
LAB = {"psi_th":r"$\psi_{th}$","kappa_th":r"$\kappa_{th}$ (KL)","delta_th":r"$\delta_{th}$",
       "maxspeed":r"$s_{max}$","drift_window":"drift window","k_sybil":"Sybil density",
       "phi_th":r"$\Phi_{th}$","kappa_ae":r"$\kappa$ (AE MAD)","phi_max":r"$\phi_{max}$",
       "dropout":"GAT dropout","lr":"GAT lr","weight_decay":"GAT weight decay",
       "gat_heads":"GAT heads","gat_hidden":"GAT hidden","leaky_slope":"LeakyReLU slope",
       "attack_pct":r"$\rho_a$ (attack %)","stealth_gamma":r"$\gamma$ (stealth)",
       "fhe_n":r"FHE $N$ (latency ms)","trs_n":r"TRS $n$ ($N_{ring}$=n-1)",
       "zone_density":r"$|V_j|$ ($\log_2$ rekey)"}
DORDER = ["psi_th","kappa_th","delta_th","maxspeed","drift_window","k_sybil","phi_max",
          "dropout","lr","weight_decay","gat_heads","gat_hidden","leaky_slope","kappa_ae",
          "phi_th","attack_pct","stealth_gamma"]
LORDER = [("fhe_n","latency_ms"),("trs_n","n_ring_msgs"),("zone_density","rekey_msgs")]

def fnum(x):
    try: return float(x)
    except: return float("nan")

# detection data
det = defaultdict(lambda: defaultdict(list))
for r in csv.DictReader(open(DET)):
    m = fnum(r["MCC_full"]);  m = fnum(r["MCC"]) if math.isnan(m) else m
    f = fnum(r["FPR_full"]);  f = fnum(r["FPR"]) if math.isnan(f) else f
    if not math.isnan(fnum(r["value"])) and not math.isnan(m):
        det[r["param"]][fnum(r["value"])].append((m,f))
# latency data
lat = defaultdict(lambda: defaultdict(float))
for r in csv.DictReader(open(LAT)):
    for m in ("latency_ms","n_ring_msgs","rekey_msgs"):
        y = fnum(r.get(m,""))
        if not math.isnan(y): lat[r["param"]][fnum(r["value"])] = y

det_present = [p for p in DORDER if det.get(p)]
lat_present = [(p,m) for (p,m) in LORDER if lat.get(p)]
panels = det_present + lat_present
n = len(panels); cols = 5; rws = (n+cols-1)//cols
fig, axes = plt.subplots(rws, cols, figsize=(4.2*cols, 3.2*rws))
axes = axes.flatten()

def draw_det(ax, p):
    xs = sorted(det[p]); mm=[sum(v[0] for v in det[p][x])/len(det[p][x]) for x in xs]
    fm=[sum(v[1] for v in det[p][x])/len(det[p][x]) for x in xs]
    ax.plot(xs,mm,marker="o",color="#1f77b4"); ax.set_ylim(0,1); ax.grid(alpha=0.3)
    ax.set_ylabel("MCC",color="#1f77b4",fontsize=8); ax.tick_params(labelsize=7)
    ax2=ax.twinx(); ax2.plot(xs,fm,marker="s",ls="--",color="#d62728",ms=3)
    ax2.axhline(0.05,color="#d62728",ls=":",lw=0.7); ax2.set_ylim(0,max(0.1,max(fm)*1.3))
    ax2.set_ylabel("FPR",color="#d62728",fontsize=8); ax2.tick_params(labelsize=7)
    s=SEL.get(p)
    if s is not None and s in xs:
        i=xs.index(s); ax.scatter([s],[mm[i]],s=140,marker="*",color="gold",edgecolor="k",zorder=5)
    ax.set_title(LAB.get(p,p),fontsize=9)

def draw_lat(ax, p, m):
    xs=sorted(lat[p]); ys=[lat[p][x] for x in xs]
    ax.plot(xs,ys,marker="o",color="#2ca02c"); ax.grid(alpha=0.3)
    ax.set_ylabel(m.replace("_"," "),fontsize=8); ax.tick_params(labelsize=7)
    ax.set_title(LAB.get(p,p)+"  [overhead]",fontsize=9)

for i,item in enumerate(panels):
    if isinstance(item,tuple): draw_lat(axes[i],item[0],item[1])
    else: draw_det(axes[i],item)
for j in range(len(panels),len(axes)): axes[j].axis("off")
fig.suptitle("MPTD-PQS — Full Sensitivity Analysis (blue=MCC, red=FPR, star=selected; green=overhead)",
             fontsize=13)
fig.tight_layout(rect=[0,0,1,0.97])
fig.savefig(OUT,dpi=140); print("saved",OUT,"panels:",len(panels))
