#!/usr/bin/env python3
"""
plot_sota_matrix.py — baseline x attack SOTA matrix.
Reads matrix.csv (attack,method,mode,MCC,FPR,MCC_full,...), builds the MCC matrix
(rows=method, cols=attack) using each method's NATIVE score (proposed/B2/B3 = MCC_full;
B1 = LW MCC), a heatmap figure, and a text table marking the per-attack winner.

Attack legend (06a_attack_models.h):
 1 TP-S1 RSU pos-drift | 2 TP-S2 speed/heading exagg (B1 turf) | 3 MP-S1 Sybil (GAT turf)
 4 MP-S2 impersonation | 5 TP-S3 ctrl interception | 6 MP-S3 MitM speed shift | 7 MP-S4 ctrl poison
Usage: python3 plot_sota_matrix.py <matrix.csv>
"""
import sys, csv, os, math, re
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CSV = sys.argv[1] if len(sys.argv) > 1 else "matrix.csv"
OUT = os.path.dirname(os.path.abspath(CSV))
FULL_MODES = {"0", "2", "3", "4", "5", "7", "8"}
# Control-plane attacks: vehicles are HONEST (no poisoned beacons), so beacon-level
# MCC is degenerate — a do-nothing detector scores ~1.0. Judge these by the proposed
# CP-DETECT (Algorithm 7) controller-consensus auditor: detection rate = CTRL_COMPROMISED
# alerts / audited epochs, parsed from the proposed-mode log. CP-DETECT is a component of
# the proposed MPTD-PQS architecture; the standalone baselines (Ghaleb speed/reach, pure
# GAT spatial, pure AE temporal) have NO controller-consensus auditor -> 0.  This is
# DETECTION, not mitigation (CDER stays ~1.0 at t=30 — a separate limitation).
CONTROL_PLANE = {"5", "7"}   # TP-S3 (attack 5), MP-S4 (attack 7)
PROPOSED = "MPTD-PQS_full"
ATTACK_LBL = {"1":"TP-S1\nRSU drift","2":"TP-S2\nspeed(B1)","3":"MP-S1\nSybil(GAT)",
              "4":"MP-S2\nimperson","5":"TP-S3 ctrl\n[CP-DETECT]","6":"MP-S3\nMitM",
              "7":"MP-S4 ctrl\n[CP-DETECT]"}
METHOD_ORDER = ["MPTD-PQS_full", "B1_Ghaleb", "B2_stdGAT", "B3_stdAE"]

def fnum(x):
    try: return float(x)
    except: return float("nan")

# CP-DETECT rate for the PROPOSED mode on each control-plane attack (parsed from its log).
def _cp_rate(att):
    for pat in (f"a{att}_MPTD-PQS_full_newlam.log", f"a{att}_MPTD-PQS_full.log"):
        p = os.path.join(OUT, pat)
        if os.path.exists(p):
            m = re.search(r"CP-DETECT = (\d+) CTRL_COMPROMISED.*?over (\d+) audited epochs", open(p).read())
            if m:
                return int(m.group(1)) / max(1, int(m.group(2)))
    return float("nan")
CP = {a: _cp_rate(a) for a in CONTROL_PLANE}

rows = list(csv.DictReader(open(CSV)))
def native_mcc(r):
    a = str(r["attack"]).strip()
    if a in CONTROL_PLANE:
        # CP-DETECT detection rate — PROPOSED full mode only; faithful standalone
        # baselines have no controller-consensus auditor -> 0.
        return CP.get(a, float("nan")) if r["method"] == PROPOSED else 0.0
    return fnum(r["MCC_full"]) if str(r["mode"]).strip() in FULL_MODES else fnum(r["MCC"])

attacks = sorted({r["attack"] for r in rows}, key=lambda x:int(x))
methods = [m for m in METHOD_ORDER if any(r["method"]==m for r in rows)]
M = {(r["method"], r["attack"]): native_mcc(r) for r in rows}

# ---- heatmap ----
import numpy as np
grid = np.array([[M.get((m,a), float("nan")) for a in attacks] for m in methods])
fig, ax = plt.subplots(figsize=(1.5*len(attacks)+2, 1.0*len(methods)+2))
im = ax.imshow(grid, cmap="RdYlGn", vmin=-0.2, vmax=1.0, aspect="auto")
ax.set_xticks(range(len(attacks))); ax.set_xticklabels([ATTACK_LBL.get(a,a) for a in attacks], fontsize=8)
ax.set_yticks(range(len(methods))); ax.set_yticklabels(methods, fontsize=9)
for i in range(len(methods)):
    for j in range(len(attacks)):
        v = grid[i,j]
        ax.text(j, i, "n/a" if math.isnan(v) else f"{v:.2f}", ha="center", va="center",
                fontsize=8, color="black")
# star per-attack winner
for j,a in enumerate(attacks):
    col = [(i, grid[i,j]) for i in range(len(methods)) if not math.isnan(grid[i,j])]
    if col:
        wi = max(col, key=lambda t:t[1])[0]
        ax.add_patch(plt.Rectangle((j-0.5, wi-0.5), 1, 1, fill=False, edgecolor="blue", lw=2.5))
fig.colorbar(im, ax=ax, label="detection score (higher=better)")
ax.set_title("SOTA baseline × attack — detection score (blue box = per-attack winner)\n"
             "spatial attacks: MCC (proposed/B2/B3=MCC_full, B1=LW MCC)  |  "
             "control-plane 5,7: CP-DETECT rate (proposed only; baselines have no ctrl auditor)", fontsize=9)
fig.tight_layout(); fig.savefig(os.path.join(OUT,"sota_matrix.png"), dpi=140)

# ---- text summary ----
L = ["SOTA MATRIX — detection score (MCC spatial; CP-DETECT rate for control-plane 5,7)",
     "  NOTE: control-plane = CP-DETECT (Algorithm 7) rate, PROPOSED only (baselines=0);",
     "        this is DETECTION not mitigation (CDER~1.0 at t=30 = separate limitation).",
     "="*64]
hdr = f"{'method':<16}" + "".join(f"a{a:<6}" for a in attacks) + "  mean  worst"
L.append(hdr)
for m in methods:
    vals = [M.get((m,a),float('nan')) for a in attacks]
    ok = [v for v in vals if not math.isnan(v)]
    mean = sum(ok)/len(ok) if ok else float('nan')
    worst = min(ok) if ok else float('nan')
    L.append(f"{m:<16}" + "".join(f"{(('%.2f'%v) if not math.isnan(v) else 'n/a'):<7}" for v in vals)
             + f"  {mean:.3f} {worst:.3f}")
L.append("")
L.append("Per-attack winner:")
for a in attacks:
    col = [(m, M.get((m,a),float('nan'))) for m in methods]
    col = [(m,v) for m,v in col if not math.isnan(v)]
    if col:
        w = max(col, key=lambda t:t[1])
        L.append(f"  a{a} ({ATTACK_LBL.get(a,a).replace(chr(10),' ')}): {w[0]} ({w[1]:.3f})")
txt = "\n".join(L)
open(os.path.join(OUT,"sota_matrix_summary.txt"),"w").write(txt+"\n")
print(txt)
print(f"\nfigure -> {OUT}/sota_matrix.png")
