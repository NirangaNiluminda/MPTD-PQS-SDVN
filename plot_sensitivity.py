#!/usr/bin/env python3
"""
plot_sensitivity.py — turn run_sensitivity.sh output into figures + LaTeX.

Input : sensitivity.csv  (param,value,seed,MCC,FPR,MCC_full,FPR_full,cm_*)
Output (next to the CSV):
  sens_<param>.png        one figure per parameter (MCC left axis, FPR right)
  sensitivity_combined.png ONE final figure — all sweeps in a 2x3 grid
  sensitivity_tables.tex   the five paper tables, filled (mean+/-std), bold = selected

Uses MCC_full (full-system fused detector); falls back to LW MCC if full is nan.
Usage: python3 plot_sensitivity.py <sensitivity.csv>
"""
import sys, os, csv, math
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CSV = sys.argv[1] if len(sys.argv) > 1 else "sensitivity.csv"
OUT = os.path.dirname(os.path.abspath(CSV))

# paper-selected (bold) value per parameter, and pretty labels
SEL   = {"psi_th":0.09, "kappa_th":0.50, "delta_th":10.0,
         "maxspeed":100, "drift_window":10, "k_sybil":5.0, "phi_th":0.5108}
LABEL = {"psi_th":r"$\psi_{th}$ (composite alert)", "kappa_th":r"$\kappa_{th}$ (KL, nats)",
         "delta_th":r"$\delta_{th}$ (drift, m)", "maxspeed":r"$s_{max}$ (km/h)",
         "drift_window":"drift window (beacons)", "k_sybil":"Sybil density factor",
         "phi_th":r"$\Phi_{th}$ (fusion decision)", "attack_pct":r"$\rho_a$ (attack \%)"}
ORDER = ["psi_th","kappa_th","delta_th","maxspeed","drift_window","k_sybil","phi_th","attack_pct"]

def fnum(x):
    try: return float(x)
    except Exception: return float("nan")

# rows[param][value] = list of (mcc, fpr) across seeds  (prefer full, fall back LW)
rows = defaultdict(lambda: defaultdict(list))
for r in csv.DictReader(open(CSV)):
    p, v = r["param"], fnum(r["value"])
    mcc = fnum(r["MCC_full"]);  mcc = fnum(r["MCC"]) if math.isnan(mcc) else mcc
    fpr = fnum(r["FPR_full"]);  fpr = fnum(r["FPR"]) if math.isnan(fpr) else fpr
    if not math.isnan(mcc): rows[p][v].append((mcc, fpr))

def agg(p):
    """return sorted [(value, mcc_mean, mcc_std, fpr_mean, fpr_std)]"""
    out = []
    for v in sorted(rows[p]):
        ms = [m for m, _ in rows[p][v]]; fs = [f for _, f in rows[p][v]]
        mm = sum(ms)/len(ms); fm = sum(fs)/len(fs)
        msd = (sum((x-mm)**2 for x in ms)/len(ms))**0.5
        fsd = (sum((x-fm)**2 for x in fs)/len(fs))**0.5
        out.append((v, mm, msd, fm, fsd))
    return out

def draw(ax, p):
    d = agg(p)
    if not d: ax.set_title(LABEL.get(p,p)+" (no data)"); return
    xs=[r[0] for r in d]; mm=[r[1] for r in d]; ms=[r[2] for r in d]
    fm=[r[3] for r in d]; fs=[r[4] for r in d]
    ax.errorbar(xs, mm, yerr=ms, marker="o", color="#1f77b4", label="MCC", capsize=3)
    ax.set_ylabel("MCC", color="#1f77b4"); ax.tick_params(axis="y", labelcolor="#1f77b4")
    ax.set_xlabel(LABEL.get(p,p)); ax.set_ylim(0,1); ax.grid(alpha=0.3)
    ax2=ax.twinx()
    ax2.errorbar(xs, fm, yerr=fs, marker="s", ls="--", color="#d62728", label="FPR", capsize=3)
    ax2.axhline(0.05, color="#d62728", ls=":", lw=0.8)
    ax2.set_ylabel("FPR", color="#d62728"); ax2.tick_params(axis="y", labelcolor="#d62728")
    ax2.set_ylim(0, max(0.1, max(fm)*1.3 if fm else 0.1))
    sel = SEL.get(p)
    if sel is not None and sel in xs:                 # star the selected point
        i = xs.index(sel); ax.scatter([sel],[mm[i]], s=200, marker="*",
                                      color="gold", edgecolor="k", zorder=5)
    ax.set_title(LABEL.get(p,p))

present = [p for p in ORDER if rows.get(p)]

# 1) one figure per parameter
for p in present:
    fig, ax = plt.subplots(figsize=(5,3.5)); draw(ax, p)
    fig.tight_layout(); fig.savefig(os.path.join(OUT,f"sens_{p}.png"), dpi=140); plt.close(fig)

# 2) ONE combined figure — 2x3 grid, all sweeps
n=len(present); cols=3; rws=max(1,(n+cols-1)//cols)
fig, axes = plt.subplots(rws, cols, figsize=(5*cols, 3.6*rws))
axes = axes.flatten() if hasattr(axes,"flatten") else [axes]
for i,p in enumerate(present): draw(axes[i], p)
for j in range(len(present), len(axes)): axes[j].axis("off")
fig.suptitle("Full-System Sensitivity Analysis (urban, full mode)  —  "
             "MCC (blue) & FPR (red);  ★ = paper-selected value;  FPR 0.05 dotted",
             fontsize=12)
fig.tight_layout(rect=[0,0,1,0.96])
comb=os.path.join(OUT,"sensitivity_combined.png"); fig.savefig(comb, dpi=140); plt.close(fig)

# 3) filled LaTeX tables (mean+/-std, bold = selected)
def cell(p, v, m, s, f, fs):
    bold = (SEL.get(p)==v)
    mcc=f"{m:.3f}$\\pm${s:.3f}"; fpr=f"{f:.3f}"
    return (f"\\textbf{{{v}}} & \\textbf{{{mcc}}} & \\textbf{{{fpr}}}" if bold
            else f"{v} & {mcc} & {fpr}")
tex=[]
for p in present:
    tex.append(f"% ---- {p} ({LABEL.get(p,p)}) ----")
    for (v,m,s,f,fs) in agg(p): tex.append(cell(p,v,m,s,f,fs)+r" \\")
    tex.append("")
open(os.path.join(OUT,"sensitivity_tables.tex"),"w").write("\n".join(tex))

# ------------------------------------------------------------------ #
# TEXT-MESSAGE summary (sir's ask: "summary of selected values" +     #
# "sensitivity sweeps as a text message"). Plain text, chat-pasteable. #
# ------------------------------------------------------------------ #
# plain-text labels for the chat message (the plots keep the LaTeX ones)
TXTLABEL = {"phi_th":"Phi_th (fusion decision threshold)",
            "attack_pct":"rho_a (attack penetration %)",
            "psi_th":"psi_th (composite alert threshold)",
            "kappa_th":"kappa_th (KL divergence, nats)",
            "delta_th":"delta_th (drift threshold, m)",
            "maxspeed":"s_max (speed bound, km/h)",
            "drift_window":"drift window (beacons)",
            "k_sybil":"K_sybil (Sybil density factor)"}

def best_at_fpr(p, cap=0.05):
    """data-driven pick: highest MCC among points with FPR<=cap; else global max MCC."""
    d = agg(p)
    ok = [r for r in d if r[3] <= cap]
    pool = ok if ok else d
    b = max(pool, key=lambda r: r[1])
    return b, bool(ok)

L = []
L.append("="*60)
L.append(" MPTD-PQS  FULL-SYSTEM SENSITIVITY ANALYSIS  (urban, full mode)")
L.append("="*60)
L.append("")
L.append("SELECTED VALUES  (best MCC with FPR<=0.05; * = agrees with paper):")
for p in present:
    b, within = best_at_fpr(p)
    agree = "*" if SEL.get(p) == b[0] else " "
    tag = "" if within else "  (no pt met FPR<=0.05 -> max-MCC shown)"
    L.append(f"  {agree} {TXTLABEL.get(p,p):<34} = {b[0]:<6}"
             f"  MCC {b[1]:.3f}+/-{b[2]:.3f}   FPR {b[3]:.3f}{tag}")
L.append("")
L.append("FULL SWEEPS  (all values kept; > marks the selected point):")
for p in present:
    b,_ = best_at_fpr(p)
    L.append("")
    L.append(TXTLABEL.get(p,p))
    L.append(f"   {'value':<8}{'MCC (mean+/-std)':<22}{'FPR':<8}")
    for (v,m,s,f,fs) in agg(p):
        mark = ">" if v == b[0] else " "
        L.append(f" {mark} {v:<8}{f'{m:.3f}+/-{s:.3f}':<22}{f:.3f}")
L.append("")
L.append(f"(figures: sensitivity_combined.png + sens_<param>.png ; LaTeX: sensitivity_tables.tex)")
TXT = "\n".join(L)
open(os.path.join(OUT, "sensitivity_summary.txt"), "w").write(TXT + "\n")
print(TXT)
print(f"\nsaved: {OUT}/sensitivity_summary.txt  (this is the text message for sir)")
print(f"       {OUT}/sensitivity_combined.png  +  sens_*.png  +  sensitivity_tables.tex")
