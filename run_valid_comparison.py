#!/usr/bin/env python3
"""
run_valid_comparison.py — VALID MCC+FPR comparison: MPTD-PQS(full) vs B1 Ghaleb /
B2 Ercan / B3 Sharma, at the baselines' own config (N=135, pct 30/60/90).

Baselines are scored from the existing datasets/aN_pP/ beacon_logs via the ε-fixed
Python detectors (5-fold CV). MPTD-PQS is read from datasets/aN_pP/metrics.csv
(MCC_full / FPR_full from mode-0 full-fusion runs). Only MCC and FPR are compared —
the other metrics are not apples-to-apples for beacon-classifier baselines.

Per baseline, the BEST-MCC classifier per scenario is chosen (strongest baseline =
most conservative for the superiority claim).

Usage: python3 run_valid_comparison.py <datasets_root> <out_dir> [--baselines-only]
"""
import sys, os, csv, math
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mptd_pqs import ghaleb_b1_detector as B1
from mptd_pqs import ercan_b2_detector_v2 as B2
from mptd_pqs import sharma_b3_detector_v2 as B3

DATASETS = sys.argv[1] if len(sys.argv) > 1 else "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35/analytics/datasets"
OUT      = sys.argv[2] if len(sys.argv) > 2 else "live_results/valid_cmp"
BASE_ONLY = "--baselines-only" in sys.argv
os.makedirs(OUT, exist_ok=True)
ATTACKS = [1,2,3,4,5,6,7]; PCTS = [30,60,90]


def best_per_scenario(df, label):
    """From a run_full_sweep df (per-classifier rows), pick best-MCC classifier per (attack,pct)."""
    rows = []
    if df is None or df.empty:
        return pd.DataFrame(columns=["attack","attack_pct","method","MCC","FPR"])
    for (a, p), g in df.groupby(["attack", "attack_pct"]):
        gi = g.loc[g["MCC_mean"].idxmax()]
        rows.append({"attack": int(a), "attack_pct": int(p), "method": label,
                     "MCC": float(gi["MCC_mean"]), "FPR": float(gi["FPR_mean"])})
    return pd.DataFrame(rows)


def load_mptd(datasets):
    rows = []
    for a in ATTACKS:
        for p in PCTS:
            m = os.path.join(datasets, f"a{a}_p{p}", "metrics.csv")
            if not os.path.exists(m):
                continue
            try:
                r = pd.read_csv(m).iloc[0]
            except Exception:
                continue
            mf = float(r.get("MCC_full", 0.0)); ff = float(r.get("FPR_full", 0.0))
            has_full = ("MCC_full" in r.index) and (abs(mf) > 1e-9 or abs(ff) > 1e-9)
            rows.append({"attack": a, "attack_pct": p, "method": "MPTD-PQS_full",
                         "MCC": mf if has_full else float(r.get("MCC", 0.0)),
                         "FPR": ff if has_full else float(r.get("FPR", 0.0))})
    return pd.DataFrame(rows)


print("[1/3] scoring baselines from datasets (5-fold CV, ε-MCC) ...")
b1 = best_per_scenario(B1.run_full_sweep(DATASETS, seed=42), "B1_Ghaleb")
print(f"   B1 done: {len(b1)} scenarios")
b2 = best_per_scenario(B2.run_full_sweep(DATASETS, seed=42), "B2_Ercan")
print(f"   B2 done: {len(b2)} scenarios")
b3 = best_per_scenario(B3.run_full_sweep(DATASETS, seed=42), "B3_Sharma")
print(f"   B3 done: {len(b3)} scenarios")

parts = [b1, b2, b3]
if not BASE_ONLY:
    mp = load_mptd(DATASETS)
    print(f"[2/3] MPTD-PQS full metrics: {len(mp)} scenarios found")
    if mp.empty:
        print("   WARN: no MPTD-PQS metrics.csv yet (run mode-0 sims first)")
    parts.append(mp)

allc = pd.concat(parts, ignore_index=True)
allc.to_csv(os.path.join(OUT, "valid_comparison.csv"), index=False)
print(f"[3/3] wrote {OUT}/valid_comparison.csv")

# ---- plots: MCC and FPR, method × (attack,pct) grouped bars per attack ----
methods = ["MPTD-PQS_full","B1_Ghaleb","B2_Ercan","B3_Sharma"]
colors  = {"MPTD-PQS_full":"#2ca02c","B1_Ghaleb":"#8c564b","B2_Ercan":"#1f77b4","B3_Sharma":"#d62728"}
for metric, better in [("MCC","up"), ("FPR","down")]:
    fig, axes = plt.subplots(2, 4, figsize=(20, 8)); axes = axes.flatten()
    for i, a in enumerate(ATTACKS):
        ax = axes[i]
        for mi, m in enumerate(methods):
            sub = allc[(allc.attack==a) & (allc.method==m)].sort_values("attack_pct")
            if sub.empty: continue
            ax.plot(sub.attack_pct, sub[metric], marker="o", label=m, color=colors[m])
        ax.set_title(f"a{a}", fontsize=10); ax.set_xlabel("attack pct %"); ax.set_ylabel(metric)
        ax.grid(alpha=0.3)
        if metric=="MCC": ax.set_ylim(-0.3,1.05)
        if i==0: ax.legend(fontsize=7)
    for j in range(len(ATTACKS), len(axes)): axes[j].axis("off")
    fig.suptitle(f"{metric} ({'↑' if better=='up' else '↓'} better) — MPTD-PQS(full) vs Ercan/Sharma/Ghaleb "
                 f"(N=135, ε-MCC, best-classifier per baseline)", fontsize=13)
    fig.tight_layout(rect=[0,0,1,0.96])
    fig.savefig(os.path.join(OUT, f"cmp_{metric}.png"), dpi=140); plt.close(fig)
    print(f"   plot -> {OUT}/cmp_{metric}.png")

# summary table
print("\n=== MCC by attack×pct (best baseline classifier; ε-smoothed) ===")
piv = allc.pivot_table(index=["attack","attack_pct"], columns="method", values="MCC")
print(piv.to_string())
