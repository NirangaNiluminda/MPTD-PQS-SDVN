#!/usr/bin/env python3
"""
plot_sota_comparison.py — MPTD-PQS (full mode) vs 3 SOTA baselines (B1/B2/B3),
9 evaluation metrics. Reads comparison.csv (one row per method) and produces a
grouped multi-panel bar figure + a winner-summary.

Metric direction: HIGHER better = MCC, PARR ; LOWER better = FPR, CDER, TDEE,
TPE, PBPO, TTD. The proposed method is highlighted; a check/cross marks whether
it beats ALL 3 baselines on each metric.

Usage: python3 plot_sota_comparison.py <comparison.csv>
"""
import sys, csv, os, math
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CSV = sys.argv[1] if len(sys.argv) > 1 else "comparison.csv"
OUT = os.path.dirname(os.path.abspath(CSV))

# metric -> (column, higher_is_better, pretty)
METRICS = [
    ("MCC",   True,  "MCC"),          ("FPR",  False, "FPR"),
    ("PARR",  True,  "PARR"),         ("CDER", False, "CDER"),
    ("TDEE",  False, "TDEE (m)"),     ("TPE",  False, "TPE (m)"),
    ("PBPO_Full_ms", False, "PBPO (ms)"), ("TTD", False, "TTD (s)"),
]
PROP = "MPTD-PQS_full"


def fnum(x):
    try: return float(x)
    except Exception: return float("nan")


rows = list(csv.DictReader(open(CSV)))
# Fair apples-to-apples: score every method on its OWN native detector output,
# all through the same eps-smoothed MCC (Eq 4.1).
#   full-mode variants (proposed mode 0, B2 GAT mode 2, B3 AE mode 3, and any of
#   A2/A3/A4/A5) emit the fusion decision -> MCC_full/FPR_full.
#   B1 Ghaleb (mode 6) / A1 (mode 1) have no fusion tier -> LW MCC/FPR.
FULL_MODES = {"0", "2", "3", "4", "5", "7", "8"}  # 7/8 = genuine standalone GAT/AE, scored via cm_full
def is_full(r):
    return str(r.get("mode", "")).strip() in FULL_MODES
def mval(r, col):
    if col == "MCC":  return fnum(r.get("MCC_full", r["MCC"]) if is_full(r) else r.get("MCC", "nan"))
    if col == "FPR":  return fnum(r.get("FPR_full", r["FPR"]) if is_full(r) else r.get("FPR", "nan"))
    return fnum(r.get(col, "nan"))

methods = [r["method"] for r in rows]
colors = ["#2ca02c" if m == PROP else "#1f77b4" for m in methods]

n = len(METRICS); cols = 4; rws = (n + cols - 1) // cols
fig, axes = plt.subplots(rws, cols, figsize=(4.2 * cols, 3.4 * rws))
axes = axes.flatten()
summary = []
for i, (col, hib, pretty) in enumerate(METRICS):
    vals = [mval(r, col) for r in rows]
    ax = axes[i]
    bars = ax.bar(range(len(methods)), vals, color=colors)
    ax.set_xticks(range(len(methods)))
    ax.set_xticklabels([m.replace("_full", "").replace("_", "\n") for m in methods], fontsize=7)
    ax.set_title(pretty + ("  ↑" if hib else "  ↓"), fontsize=10)
    ax.grid(axis="y", alpha=0.3)
    # is proposed best?
    pi = methods.index(PROP)
    others = [v for j, v in enumerate(vals) if j != pi and not math.isnan(v)]
    pv = vals[pi]
    if not math.isnan(pv) and others:
        wins = all(pv >= o for o in others) if hib else all(pv <= o for o in others)
        summary.append((pretty, "WIN" if wins else "lose", round(pv, 3)))
        ax.text(0.5, 0.92, "✓ best" if wins else "✗", transform=ax.transAxes,
                ha="center", color=("green" if wins else "red"), fontsize=11, fontweight="bold")
for j in range(len(METRICS), len(axes)): axes[j].axis("off")
fig.suptitle("MPTD-PQS (full mode) vs SOTA baselines B1/B2/B3 @ t=10s  "
             "(green=proposed; ↑ higher better, ↓ lower better)", fontsize=12)
fig.tight_layout(rect=[0, 0, 1, 0.96])
fig.savefig(os.path.join(OUT, "sota_comparison.png"), dpi=140)

wins = sum(1 for _, w, _ in summary if w == "WIN")
print(f"proposed wins {wins}/{len(summary)} metrics")
for p, w, v in summary: print(f"  {p:<12} {w:<5} (proposed={v})")
print(f"figure -> {OUT}/sota_comparison.png")
