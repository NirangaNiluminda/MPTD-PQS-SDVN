#!/usr/bin/env python3
"""
plot_baselines_real.py — grouped bar chart of B1/B2/B3 vs MPTD-PQS using the
ACTUAL simulation/prediction outputs (not the hardcoded literature constants in
metrics_visualization.BASELINES).

Per method, per scenario a<attack>_p<pct>:
  B2 (Ercan)  : live_results/ercan_a<a>_p<p>.csv   -> MCC/FPR from label vs pred_*
  B3 (Sharma) : live_results/sharma_a<a>_p<p>.csv  -> MCC/FPR from label vs pred_*
  MPTD-PQS    : <ns3>/analytics/results/sweep/metrics_a<a>_p<p>_s60_m1.csv (A1)
  B1 (Ghaleb) : <ns3>/analytics/results/sweep/metrics_a<a>_p<p>_s60_m6.csv (mode 6)
                (only if you ran the sim with --ablation_mode=6 for this scenario)

For the ML baselines (B2/B3) the classifier with the highest MCC is shown and
its name annotated.

Usage:
  python3 plot_baselines_real.py <attack> <pct> [out.png]
  e.g.  python3 plot_baselines_real.py 2 20 live_results/baseline_a2_p20.png
"""
import os
import sys
import glob
import pandas as pd
import numpy as np
from sklearn.metrics import matthews_corrcoef, confusion_matrix

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT = os.path.dirname(os.path.abspath(__file__))
NS3 = os.environ.get("NS3", os.path.expanduser("~/ns-allinone-3.35/ns-3.35"))


def _mcc_fpr(y_true, y_pred):
    mcc = matthews_corrcoef(y_true, y_pred) if len(np.unique(y_true)) > 1 else float("nan")
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return mcc, fpr


def best_ml_baseline(csv_path):
    """Return (best_clf_name, mcc, fpr) over all pred_* columns, or None."""
    if not os.path.isfile(csv_path):
        return None
    df = pd.read_csv(csv_path)
    if "label" not in df.columns:
        return None
    y = df["label"].astype(int).values
    best = None
    for col in [c for c in df.columns if c.startswith("pred_")]:
        mcc, fpr = _mcc_fpr(y, df[col].astype(int).values)
        if best is None or mcc > best[1]:
            best = (col.replace("pred_", ""), mcc, fpr)
    return best


def mptd_metrics(csv_path, mcc_col="MCC", fpr_col="FPR"):
    """Read MCC/FPR from a sim sweep metrics CSV, or None."""
    if not os.path.isfile(csv_path):
        return None
    df = pd.read_csv(csv_path)
    if df.empty:
        return None
    return float(df.iloc[0][mcc_col]), float(df.iloc[0][fpr_col])


def main():
    if len(sys.argv) < 3:
        print(f"Usage: python3 {os.path.basename(__file__)} <attack> <pct> [out.png]")
        sys.exit(1)
    a, p = int(sys.argv[1]), int(sys.argv[2])
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(
        PROJECT, "live_results", f"baseline_a{a}_p{p}.png")
    os.makedirs(os.path.dirname(out), exist_ok=True)

    sweep = os.path.join(NS3, "analytics", "results", "sweep")
    rows = []  # (label, mcc, fpr)

    # B1 — Ghaleb, runs inside NS-3 at ablation_mode=6
    b1 = mptd_metrics(os.path.join(sweep, f"metrics_a{a}_p{p}_s60_m6.csv"))
    if b1:
        rows.append((f"B1\nGhaleb 2014", *b1))

    # B2 — Ercan ML
    b2 = best_ml_baseline(os.path.join(PROJECT, "live_results", f"ercan_a{a}_p{p}.csv"))
    if b2:
        rows.append((f"B2\nErcan ({b2[0]})", b2[1], b2[2]))

    # B3 — Sharma ML
    b3 = best_ml_baseline(os.path.join(PROJECT, "live_results", f"sharma_a{a}_p{p}.csv"))
    if b3:
        rows.append((f"B3\nSharma ({b3[0]})", b3[1], b3[2]))

    # MPTD-PQS — A1 metrics from the sim
    ours = mptd_metrics(os.path.join(sweep, f"metrics_a{a}_p{p}_s60_m1.csv"))
    if ours:
        rows.append((f"MPTD-PQS\n(ours)", *ours))

    if not rows:
        print(f"No data found for a{a}_p{p}. Did you run train/predict and the sim?")
        sys.exit(2)

    labels = [r[0] for r in rows]
    mccs = [r[1] for r in rows]
    fprs = [r[2] for r in rows]
    print(f"\n  Scenario a{a}_p{p}")
    print(f"  {'Method':<22} {'MCC':>7} {'FPR':>7}")
    for lab, m, f in zip(labels, mccs, fprs):
        print(f"  {lab.replace(chr(10),' '):<22} {m:>7.4f} {f:>7.4f}")

    x = np.arange(len(labels))
    bar_w = 0.38
    fig, ax = plt.subplots(figsize=(max(7, 1.8 * len(labels)), 5))
    b_mcc = ax.bar(x - bar_w / 2, mccs, bar_w, label="MCC ↑", color="#1f77b4", alpha=0.85)
    b_fpr = ax.bar(x + bar_w / 2, fprs, bar_w, label="FPR ↓", color="#d62728", alpha=0.85)
    for bars in (b_mcc, b_fpr):
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{bar.get_height():.3f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Metric value", fontsize=11)
    ax.set_title(f"Detection accuracy — attack {a} @ {p}% (64-RSU grid, held-out run)",
                 fontsize=12, fontweight="bold")
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=10)
    ax.grid(True, axis="y", alpha=0.3)
    if rows and rows[-1][0].startswith("MPTD-PQS"):
        ax.axvspan(len(labels) - 1 - 0.5, len(labels) - 0.5, alpha=0.08, color="green")
    plt.tight_layout()
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n  Saved: {out}")


if __name__ == "__main__":
    main()
