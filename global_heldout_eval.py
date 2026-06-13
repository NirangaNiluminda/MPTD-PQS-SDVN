#!/usr/bin/env python3
"""
global_heldout_eval.py — score the FROZEN global baseline models on FRESH
held-out simulation runs (RngRun=2), per attack scenario.

The global RF models (models_global/{ercan,sharma}_global_RF.joblib) are NOT
retrained here. We only load them and predict on each held-out run's
beacon_log.csv, then build per-attack charts.

Subcommands
-----------
  predict <attack> <pct>
      Read analytics/results/beacon_log.csv (the just-finished held-out run),
      extract each baseline's features, predict with the frozen global model,
      compute MCC/FPR/PARR, and append rows to live_results/global_heldout_results.csv.
      Also pulls B1 (m6) and MPTD-PQS (m1) for that scenario from the sweep CSVs.

  plot
      Read the results CSV and emit per-attack charts:
        live_results/global_heldout_perattack.png   (rows=attacks, cols=MCC/FPR)

Usage:
  python3 global_heldout_eval.py predict 1 30
  python3 global_heldout_eval.py plot
"""
import os, sys, glob, re
import numpy as np
import pandas as pd
import joblib

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT = os.path.dirname(os.path.abspath(__file__))
NS3 = os.environ.get("NS3", os.path.expanduser("~/ns-allinone-3.35/ns-3.35"))
sys.path.insert(0, PROJECT)

from mptd_pqs import ercan_b2_detector_v2 as B2
from mptd_pqs import sharma_b3_detector_v2 as B3

RESULTS_DIR = os.path.join(NS3, "analytics", "results")
SWEEP_DIR = os.path.join(RESULTS_DIR, "sweep")
MODELS_DIR = os.path.join(NS3, "models_global")
OUT_CSV = os.path.join(PROJECT, "live_results", "global_heldout_results.csv")

METHODS = {  # label -> (module, frozen model path)
    "B2 Ercan (global)":  (B2, os.path.join(MODELS_DIR, "ercan_global_RF.joblib")),
    "B3 Sharma (global)": (B3, os.path.join(MODELS_DIR, "sharma_global_RF.joblib")),
}


def _sweep_metric(attack, pct, mode):
    f = os.path.join(SWEEP_DIR, f"metrics_a{attack}_p{pct}_s60_m{mode}.csv")
    if not os.path.isfile(f):
        return None
    df = pd.read_csv(f)
    if df.empty:
        return None
    r = df.iloc[0]
    return float(r.get("MCC", np.nan)), float(r.get("FPR", np.nan)), float(r.get("PARR", np.nan))


def predict(attack, pct):
    rows = []
    for label, (mod, mpath) in METHODS.items():
        if not os.path.isfile(mpath):
            print(f"  MISSING frozen model: {mpath}"); continue
        feat = mod.load_scenario(RESULTS_DIR)
        if feat is None or len(feat) == 0:
            print(f"  no features for {label}"); continue
        feat = feat.dropna(subset=mod.FEATURE_COLS + ["label"])
        if feat["label"].nunique() < 2:
            print(f"  single-class held-out set for {label} (a{attack}_p{pct})")
        clf = joblib.load(mpath)
        pred = clf.predict(feat[mod.FEATURE_COLS].values)
        m = mod.compute_metrics(feat["label"].astype(int).values, pred.astype(int),
                                feat["disp_err_m"].values, len(feat))
        rows.append((attack, pct, label, m["MCC"], m["FPR"], m["PARR"]))
        print(f"  {label:<20} a{attack}_p{pct}  MCC={m['MCC']:.4f} FPR={m['FPR']:.4f}")

    b1 = _sweep_metric(attack, pct, 6)
    if b1: rows.append((attack, pct, "B1 Ghaleb (rule)", *b1))
    mp = _sweep_metric(attack, pct, 1)
    if mp: rows.append((attack, pct, "MPTD-PQS (ours)", *mp))

    df = pd.DataFrame(rows, columns=["attack", "pct", "method", "MCC", "FPR", "PARR"])
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    header = not os.path.isfile(OUT_CSV)
    df.to_csv(OUT_CSV, mode="a", header=header, index=False)


STYLE = {
    "B1 Ghaleb (rule)":   ("#9467bd", "-^"),
    "B2 Ercan (global)":  ("#1f77b4", "-o"),
    "B3 Sharma (global)": ("#2ca02c", "-s"),
    "MPTD-PQS (ours)":    ("#8b0000", "--D"),
}


def plot():
    if not os.path.isfile(OUT_CSV):
        print(f"No results CSV at {OUT_CSV}"); sys.exit(1)
    df = pd.read_csv(OUT_CSV).drop_duplicates(["attack", "pct", "method"], keep="last")
    attacks = sorted(df["attack"].unique())
    pcts = sorted(df["pct"].unique())
    ALABEL = {1: "a1: TP-S1 (RSU drift)", 2: "a2: TP-S2 (speed/heading)",
              3: "a3: MP-S1 (Sybil ghost)"}

    fig, axes = plt.subplots(len(attacks), 2, figsize=(12, 3.6 * len(attacks)),
                             squeeze=False)
    for i, atk in enumerate(attacks):
        sub = df[df["attack"] == atk]
        for j, (metric, ylab, ylim) in enumerate(
                [("MCC", "MCC (↑)", (-0.1, 1.05)), ("FPR", "FPR (↓)", None)]):
            ax = axes[i][j]
            for method, (color, style) in STYLE.items():
                s = sub[sub["method"] == method].sort_values("pct")
                if s.empty:
                    continue
                ax.plot(s["pct"], s[metric], style, color=color, label=method,
                        lw=2.0 if "MPTD" in method else 1.6,
                        ms=7 if "MPTD" in method else 5)
            ax.set_title(f"{ALABEL.get(atk, f'attack {atk}')} — {metric} vs %",
                         fontsize=10, fontweight="bold")
            ax.set_xlabel("Attack penetration ρ_a (%)")
            ax.set_ylabel(ylab)
            ax.set_xticks(pcts)
            ax.grid(True, ls="--", alpha=0.4)
            if ylim: ax.set_ylim(*ylim)
            if i == 0 and j == 0:
                ax.legend(fontsize=8)
    fig.suptitle("Existing methods (frozen GLOBAL model) vs MPTD-PQS — per attack, held-out (RngRun=2)",
                 fontsize=13, fontweight="bold")
    plt.tight_layout()
    out = os.path.join(PROJECT, "live_results", "global_heldout_perattack.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out}")

    # console summary
    print("\n  attack  pct  method                MCC     FPR    PARR")
    for _, r in df.sort_values(["attack", "pct", "method"]).iterrows():
        print(f"  a{int(r['attack']):<5} {int(r['pct']):>3}  {r['method']:<20} "
              f"{r['MCC']:>7.4f} {r['FPR']:>6.4f} {r['PARR']:>6.4f}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "predict":
        predict(int(sys.argv[2]), int(sys.argv[3]))
    elif len(sys.argv) >= 2 and sys.argv[1] == "plot":
        plot()
    else:
        print(__doc__); sys.exit(1)
