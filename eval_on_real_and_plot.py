#!/usr/bin/env python3
"""
eval_on_real_and_plot.py   (TEAMMATE RUNS THIS ON THE REAL NETWORK DATA)
=======================================================================
Loads the FROZEN generalized models produced by train_global_models.py and scores
them on the REAL network dataset (same folder layout as the NS-3 datasets: one
folder per scenario aN_pP/ containing beacon_log.csv, metrics.csv, and the
attack-specific real-position logs).

For each (attack, pct) it computes all 7 project metrics and a 95% confidence
interval by VEHICLE-LEVEL BOOTSTRAP (resampling test vehicles with replacement),
which is the correct way to get error bars from a single frozen model on a single
test set. MPTD-PQS (ours, ablation mode 1) and B1 Ghaleb (mode 6) are read from
each scenario's metrics.csv and overlaid.

Outputs (into <out_dir>):
  results_real.csv                 tidy long table behind every point
  metric_MCC.png ... metric_PBPO.png   one figure per metric

Usage:
  python3 eval_on_real_and_plot.py <real_datasets_root> <models_dir> <out_dir>
  e.g.  python3 eval_on_real_and_plot.py ./real_data ./models_global ./real_plots
"""
import os, sys, glob, re, math
import numpy as np
import pandas as pd
import joblib

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT)
from mptd_pqs import ercan_b2_detector_v2 as B2
from mptd_pqs import sharma_b3_detector_v2 as B3

N_BOOT = 300                       # bootstrap resamples for the CI
METRICS = ["MCC", "FPR", "PARR", "CDER", "TDEE", "TPE", "PBPO"]
DETECTION_METRICS = {"MCC", "FPR"}
METRIC_LABEL = {
    "MCC":  "Matthews Correlation Coefficient (MCC)",
    "FPR":  "False Positive Rate (FPR)",
    "PARR": "Poisoned Attack Rejection Rate (PARR)",
    "CDER": "Control Decision Error Rate, CDER [m]",
    "TDEE": "Trajectory Deviation Error Energy, TDEE [m\u00b2]",
    "TPE":  "Trajectory Poisoning Effectiveness (TPE)",
    "PBPO": "Per-Beacon Processing Overhead (PBPO) [ms]",
}
ATTACK_LABEL = {
    1: "a1: TP-S1 (RSU drift)",   2: "a2: TP-S2 (speed/heading)",
    3: "a3: MP-S1 (Sybil ghost)", 4: "a4: MP-S2 (impersonation)",
    5: "a5: TP-S3 (flooding)",    6: "a6: MitM intercept",
    7: "a7: Controller poison",
}
STYLE = {
    "B1 Ghaleb (rule)":   ("#9467bd", "-^"),
    "B2 Ercan (global)":  ("#1f77b4", "-o"),
    "B3 Sharma (global)": ("#2ca02c", "-s"),
    "MPTD-PQS (ours)":    ("#8b0000", "--D"),
}


def boot_ci(feat, mod, clf, n_boot=N_BOOT):
    """Point estimate + 95% CI for each metric via vehicle-level bootstrap."""
    y = feat["label"].astype(int).values
    pred = clf.predict(feat[mod.FEATURE_COLS].values)
    de = feat["disp_err_m"].values
    vids = feat["vehicle_id"].values
    uniq = np.unique(vids)
    point = mod.compute_metrics(y, pred, de, len(y))
    boots = {m: [] for m in METRICS}
    rng = np.random.default_rng(42)
    for _ in range(n_boot):
        pick = rng.choice(uniq, size=len(uniq), replace=True)
        mask = np.isin(vids, pick)
        if len(np.unique(y[mask])) < 2:
            continue
        m = mod.compute_metrics(y[mask], pred[mask], de[mask], int(mask.sum()))
        for k in METRICS:
            boots[k].append(m[k])
    out = {}
    for k in METRICS:
        b = np.array(boots[k], dtype=float)
        if len(b) > 1:
            lo, hi = np.percentile(b, [2.5, 97.5])
            out[k] = (point[k], (hi - lo) / 2.0)
        else:
            out[k] = (point[k], 0.0)
    return out


def baseline_rows(label, mod, clf, root):
    rows = []
    for d in sorted(glob.glob(os.path.join(root, "a*_p*"))):
        m = re.search(r"a(\d+)_p(\d+)$", os.path.basename(d))
        if not m:
            continue
        atk, pct = int(m.group(1)), int(m.group(2))
        feat = mod.load_scenario(d)
        if feat is None or len(feat) == 0:
            continue
        feat = feat.dropna(subset=mod.FEATURE_COLS + ["label"])
        if feat["label"].nunique() < 2:        # need both classes
            continue
        ci = boot_ci(feat, mod, clf)
        for met in METRICS:
            mean, half = ci[met]
            rows.append(dict(method=label, attack=atk, pct=pct, metric=met,
                             mean=round(float(mean), 4), ci95=round(float(half), 4)))
    return rows


def sim_rows(root):
    rows = []
    for d in sorted(glob.glob(os.path.join(root, "a*_p*"))):
        f = os.path.join(d, "metrics.csv")
        if not os.path.isfile(f):
            continue
        try:
            mdf = pd.read_csv(f)
        except Exception:
            continue
        for _, r in mdf.iterrows():
            method = {1: "MPTD-PQS (ours)", 6: "B1 Ghaleb (rule)"}.get(
                int(r.get("ablation_mode", 1)))
            if method is None:
                continue
            tdee = float(r.get("TDEE", -1))
            vals = {"MCC": float(r.get("MCC", np.nan)), "FPR": float(r.get("FPR", np.nan)),
                    "PARR": float(r.get("PARR", np.nan)), "CDER": float(r.get("CDER", np.nan)),
                    "TDEE": (np.nan if tdee < 0 else tdee), "TPE": float(r.get("TPE", np.nan)),
                    "PBPO": float(r.get("PBPO_LW_ms", np.nan))}
            for met, v in vals.items():
                rows.append(dict(method=method, attack=int(r["attack_number"]),
                                 pct=int(r["attack_pct"]), metric=met, mean=v, ci95=0.0))
    return rows


def plot_metric(df, metric, out_dir):
    sub = df[(df["metric"] == metric) & (df["pct"] > 0)]
    if sub.empty:
        return
    attacks = sorted(sub["attack"].unique())
    ncols = min(4, len(attacks)); nrows = math.ceil(len(attacks) / ncols)
    fig, axes = plt.subplots(nrows, ncols, figsize=(5 * ncols, 4 * nrows), squeeze=False)
    note = "" if metric in DETECTION_METRICS else "  (baseline value is a proxy)"
    fig.suptitle(f"{METRIC_LABEL[metric]} vs attack penetration{note}",
                 fontsize=13, fontweight="bold", y=1.01)
    for i, atk in enumerate(attacks):
        ax = axes[i // ncols][i % ncols]; a = sub[sub["attack"] == atk]
        for method, (color, sty) in STYLE.items():
            s = a[a["method"] == method].sort_values("pct")
            if s.empty:
                continue
            ax.errorbar(s["pct"], s["mean"], yerr=s["ci95"], fmt=sty, color=color,
                        label=method, capsize=4,
                        lw=2.2 if "MPTD" in method else 1.6,
                        ms=7 if "MPTD" in method else 5)
        ax.set_title(ATTACK_LABEL.get(atk, f"attack {atk}"), fontsize=9)
        ax.set_xlabel("Attack penetration \u03c1_a (%)", fontsize=8)
        ax.set_ylabel(METRIC_LABEL[metric], fontsize=8)
        ax.grid(True, ls="--", alpha=0.4); ax.legend(fontsize=6, loc="best")
        if metric == "MCC":
            ax.set_ylim(-0.15, 1.05)
    for k in range(len(attacks), nrows * ncols):
        axes[k // ncols][k % ncols].set_visible(False)
    plt.tight_layout()
    out = os.path.join(out_dir, f"metric_{metric}.png")
    plt.savefig(out, dpi=150, bbox_inches="tight"); plt.close()
    print(f"  saved {out}")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "./real_data"
    models_dir = sys.argv[2] if len(sys.argv) > 2 else "./models_global"
    out_dir = sys.argv[3] if len(sys.argv) > 3 else "./real_plots"
    os.makedirs(out_dir, exist_ok=True)

    all_rows = []
    for tag, mod, label in [("ercan", B2, "B2 Ercan (global)"),
                            ("sharma", B3, "B3 Sharma (global)")]:
        mpath = os.path.join(models_dir, f"{tag}_global_RF.joblib")
        if not os.path.isfile(mpath):
            print(f"  MISSING frozen model {mpath} -- run train_global_models.py first")
            continue
        print(f"== {label}: scoring real data with frozen model ==")
        clf = joblib.load(mpath)
        all_rows += baseline_rows(label, mod, clf, root)
    all_rows += sim_rows(root)

    res = pd.DataFrame(all_rows)
    csv = os.path.join(out_dir, "results_real.csv")
    res.to_csv(csv, index=False)
    print(f"\n  tidy results CSV: {csv}\n")
    for metric in METRICS:
        plot_metric(res, metric, out_dir)
    print("\n[done]")


if __name__ == "__main__":
    main()