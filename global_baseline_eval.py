#!/usr/bin/env python3
"""
global_baseline_eval.py — ONE global model per ML baseline (not per-scenario).

Motivation
----------
The original *_train_save.py scripts froze a SEPARATE model for every
(attack x pct) scenario. A deployable misbehaviour detector should instead be a
single GLOBAL model that flags an attacker regardless of attack type or
penetration rate. This script:

  1. Pools every analytics/datasets/aN_pP/ scenario into one feature table
     (reusing each baseline's own feature extractor + real-position augmentation).
  2. Splits by VEHICLE (GroupShuffleSplit) so a vehicle's beacons never straddle
     train/test — i.e. the model is scored on vehicles it never trained on.
  3. Trains ONE global RandomForest per method (B2 Ercan, B3 Sharma) and freezes
     it to models_global/.
  4. Reports MCC / FPR / PARR on the held-out test set, broken down by attack
     percentage, and overlays the MPTD-PQS metrics (from the sim sweep CSVs) and
     B1 (Ghaleb, mode-6) where available.
  5. Emits a chart: MCC-vs-pct and FPR-vs-pct, one line per existing method plus
     an MPTD-PQS reference line.

Usage:
  python3 global_baseline_eval.py [datasets_root] [out_dir]
"""
import os, sys, glob, re
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit
import joblib

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

PROJECT = os.path.dirname(os.path.abspath(__file__))
NS3 = os.environ.get("NS3", os.path.expanduser("~/ns-allinone-3.35/ns-3.35"))
sys.path.insert(0, PROJECT)

from mptd_pqs import ercan_b2_detector_v2 as B2
from mptd_pqs import sharma_b3_detector_v2 as B3

TEST_FRAC = 0.30
SEED = 42


def discover_scenarios(root):
    out = []
    for d in sorted(glob.glob(os.path.join(root, "a*_p*"))):
        m = re.search(r"a(\d+)_p(\d+)$", os.path.basename(d))
        if m and os.path.isfile(os.path.join(d, "beacon_log.csv")):
            out.append((int(m.group(1)), int(m.group(2)), d))
    return out


def pool_features(mod, scenarios):
    """Load + concat every scenario's feature table, tagging pct and vehicle group."""
    frames = []
    for atk, pct, d in scenarios:
        feat = mod.load_scenario(d)            # both modules accept (dir)
        if feat is None or len(feat) == 0:
            continue
        feat = feat.dropna(subset=mod.FEATURE_COLS + ["label"]).copy()
        feat["pct"] = pct
        feat["attack"] = atk
        # group = scenario+vehicle so the SAME vehicle in the SAME run stays together
        feat["grp"] = f"a{atk}_p{pct}_" + feat["vehicle_id"].astype(str)
        frames.append(feat)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def train_global(mod, df, name, models_dir):
    """Train ONE global RF on a vehicle-grouped split; return (model, test_df)."""
    X = df[mod.FEATURE_COLS].values
    y = df["label"].astype(int).values
    groups = df["grp"].values
    gss = GroupShuffleSplit(n_splits=1, test_size=TEST_FRAC, random_state=SEED)
    tr, te = next(gss.split(X, y, groups))
    clf = mod._rf(seed=SEED)
    clf.fit(X[tr], y[tr])
    os.makedirs(models_dir, exist_ok=True)
    path = os.path.join(models_dir, f"{name}_global_RF.joblib")
    joblib.dump(clf, path)
    test = df.iloc[te].copy()
    test["pred"] = clf.predict(X[te])
    print(f"  [{name}] global RF: train={len(tr)} test={len(te)} rows "
          f"(test vehicles held out) -> {path}")
    return clf, test


def metrics_by_pct(mod, test):
    """Return dict pct -> (MCC, FPR, PARR) using the method's own compute_metrics."""
    out = {}
    for pct, g in test.groupby("pct"):
        m = mod.compute_metrics(g["label"].astype(int).values,
                                g["pred"].astype(int).values,
                                g["disp_err_m"].values, len(g))
        out[int(pct)] = (m["MCC"], m["FPR"], m["PARR"])
    # overall
    m = mod.compute_metrics(test["label"].astype(int).values,
                            test["pred"].astype(int).values,
                            test["disp_err_m"].values, len(test))
    out["ALL"] = (m["MCC"], m["FPR"], m["PARR"])
    return out


def sim_metric_by_pct(mode):
    """Average MCC/FPR/PARR across attack types per pct from sweep metrics_*_m{mode}.csv."""
    sweep = os.path.join(NS3, "analytics", "results", "sweep")
    by = {}
    for f in glob.glob(os.path.join(sweep, f"metrics_a*_p*_s60_m{mode}.csv")):
        m = re.search(r"metrics_a(\d+)_p(\d+)_s60_m\d+", os.path.basename(f))
        if not m:
            continue
        pct = int(m.group(2))
        try:
            df = pd.read_csv(f)
        except Exception:
            continue
        if df.empty:
            continue
        r = df.iloc[0]
        by.setdefault(pct, []).append((float(r.get("MCC", np.nan)),
                                       float(r.get("FPR", np.nan)),
                                       float(r.get("PARR", np.nan))))
    return {p: tuple(np.nanmean(np.array(v), axis=0)) for p, v in by.items()}


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(NS3, "analytics", "datasets")
    out_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(PROJECT, "live_results")
    os.makedirs(out_dir, exist_ok=True)
    models_dir = os.path.join(NS3, "models_global")

    scenarios = discover_scenarios(root)
    if not scenarios:
        print(f"No scenarios under {root}")
        sys.exit(1)
    pcts = sorted({p for _, p, _ in scenarios})
    print(f"Scenarios: {[f'a{a}_p{p}' for a,p,_ in scenarios]}")
    print(f"Pcts: {pcts}\n")

    results = {}  # method -> {pct: (MCC,FPR,PARR)}
    for tag, mod in [("ercan", B2), ("sharma", B3)]:
        print(f"== Pooling {tag} features ==")
        df = pool_features(mod, scenarios)
        if df.empty or df["label"].nunique() < 2:
            print(f"  skip {tag}: insufficient data/classes")
            continue
        print(f"  pooled rows={len(df)} label={df['label'].value_counts().to_dict()}")
        _, test = train_global(mod, df, tag, models_dir)
        results[tag] = metrics_by_pct(mod, test)

    mptd = sim_metric_by_pct(1)   # MPTD-PQS A1
    b1   = sim_metric_by_pct(6)   # B1 Ghaleb

    # ── print summary ────────────────────────────────────────────────────────
    print("\n================  GLOBAL-MODEL ACCURACY (held-out test)  ================")
    hdr = f"{'method':<16}{'pct':>5}{'MCC':>9}{'FPR':>9}{'PARR':>9}"
    print(hdr); print("-" * len(hdr))
    nm = {"ercan": "B2 Ercan(glob)", "sharma": "B3 Sharma(glob)"}
    for tag in ("ercan", "sharma"):
        if tag not in results:
            continue
        for pct in pcts + ["ALL"]:
            if pct in results[tag]:
                mcc, fpr, parr = results[tag][pct]
                print(f"{nm[tag]:<16}{str(pct):>5}{mcc:>9.4f}{fpr:>9.4f}{parr:>9.4f}")
    for tag, src in (("B1 Ghaleb", b1), ("MPTD-PQS", mptd)):
        for pct in pcts:
            if pct in src:
                mcc, fpr, parr = src[pct]
                print(f"{tag:<16}{str(pct):>5}{mcc:>9.4f}{fpr:>9.4f}{parr:>9.4f}")

    # ── chart: MCC & FPR vs pct, one line per method ─────────────────────────
    fig, (axm, axf) = plt.subplots(1, 2, figsize=(13, 5))
    series = []
    if "ercan" in results:
        series.append(("B2 Ercan (global RF)", "#1f77b4", "-o", results["ercan"]))
    if "sharma" in results:
        series.append(("B3 Sharma (global RF)", "#2ca02c", "-s", results["sharma"]))
    if b1:
        series.append(("B1 Ghaleb (rule)", "#9467bd", "-^",
                       {p: b1[p] for p in b1}))
    for label, color, style, data in series:
        xs = [p for p in pcts if p in data]
        axm.plot(xs, [data[p][0] for p in xs], style, color=color, label=label, lw=1.8)
        axf.plot(xs, [data[p][1] for p in xs], style, color=color, label=label, lw=1.8)
    if mptd:
        xs = [p for p in pcts if p in mptd]
        axm.plot(xs, [mptd[p][0] for p in xs], "--D", color="#8b0000",
                 label="MPTD-PQS (ours)", lw=2.2, ms=7)
        axf.plot(xs, [mptd[p][1] for p in xs], "--D", color="#8b0000",
                 label="MPTD-PQS (ours)", lw=2.2, ms=7)
    for ax, ttl, yl in [(axm, "MCC vs attack %", "MCC  (higher = better)"),
                        (axf, "FPR vs attack %", "FPR  (lower = better)")]:
        ax.set_title(ttl, fontweight="bold")
        ax.set_xlabel("Attack penetration  ρ_a  (%)")
        ax.set_ylabel(yl)
        ax.grid(True, ls="--", alpha=0.4)
        ax.legend(fontsize=8)
        ax.set_xticks(pcts)
    axm.set_ylim(-0.1, 1.05)
    fig.suptitle("Existing methods (B1/B2/B3, single GLOBAL model) vs MPTD-PQS",
                 fontsize=13, fontweight="bold")
    plt.tight_layout()
    out = os.path.join(out_dir, "global_baseline_vs_pct.png")
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\nSaved chart: {out}")
    print(f"Global models in: {models_dir}")


if __name__ == "__main__":
    main()
