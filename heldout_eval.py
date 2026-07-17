#!/usr/bin/env python3
"""
heldout_eval.py — VALID held-out MCC+FPR comparison, penetration sweep 0..100.

Protocol (no within-scenario CV → no memorization):
  • B2 Ercan / B3 Sharma: TRAIN on RngRun=1 data (datasets p30+p60+p90 combined per
    attack = robust cross-penetration model), PREDICT on RngRun=2 heldout at each test
    pct. Best-MCC classifier per test scenario. ε-smoothed MCC (matches C++).
  • B1 Ghaleb: C++ mode-6 metrics (ε-MCC), from heldout/aN_pP/b1_metrics.csv.
  • MPTD-PQS full: C++ mode-0 MCC_full/FPR_full, from heldout/aN_pP/metrics.csv,
    EXCEPT control-plane attacks 5,7 -> CP-DETECT rate (Algorithm-7 controller
    auditor) parsed from mode0.log, because MPTD detects those via CP-DETECT, not
    the beacon confusion matrix. (Baselines keep their beacon-MCC on 5,7.)

Only MCC + FPR (apples-to-apples for beacon-classifier baselines).
Usage: python3 heldout_eval.py <datasets_root> <heldout_root> <out_dir>
"""
import sys, os, re, math
import pandas as pd, numpy as np
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mptd_pqs import ercan_b2_detector_v2 as B2
from mptd_pqs import sharma_b3_detector_v2 as B3

TRAIN = sys.argv[1] if len(sys.argv) > 1 else "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35/analytics/datasets"
HELD  = sys.argv[2] if len(sys.argv) > 2 else "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35/analytics/heldout"
OUT   = sys.argv[3] if len(sys.argv) > 3 else "live_results/heldout_pct"
os.makedirs(OUT, exist_ok=True)
ATTACKS = [1,2,3,4,5,6,7]
TRAIN_PCTS = [30,60,90]          # existing RngRun=1 data → combined training
TEST_PCTS  = [0,20,40,60,80,100] # held-out penetration sweep
CONTROL = {5,7}


def train_frame(mod, attack):
    """Concat RngRun=1 scenarios (p30/60/90) for one attack → one training frame."""
    frames = []
    for p in TRAIN_PCTS:
        d = os.path.join(TRAIN, f"a{attack}_p{p}")
        f = mod.load_scenario(d)
        if f is not None:
            frames.append(f)
    if not frames:
        return None
    df = pd.concat(frames, ignore_index=True).dropna(subset=mod.FEATURE_COLS + ["label"])
    return df if (len(df) > 50 and df["label"].nunique() == 2) else None


def fit_classifiers(mod, attack):
    tr = train_frame(mod, attack)
    if tr is None:
        return None, None
    Xtr, ytr = tr[mod.FEATURE_COLS].values, tr["label"].values
    if mod is B2:
        clfs = {"kNN": B2._knn(), "RF": B2._rf(42), "Stacking": B2._stacking(42)}
    else:
        clfs = B3._build_classifiers(42)
    fitted = {}
    for name, clf in clfs.items():
        try:
            clf.fit(Xtr, ytr); fitted[name] = clf
        except Exception as e:
            print(f"    {mod.__name__} {name} fit failed: {e}")
    return fitted, mod


def predict_best(mod, fitted, held_dir):
    te = mod.load_scenario(held_dir)
    if te is None:
        return None
    te = te.dropna(subset=mod.FEATURE_COLS + ["label"])
    if len(te) < 20 or te["label"].nunique() < 2:
        return None   # degenerate (pct 0/100) — MCC undefined
    Xte, yte = te[mod.FEATURE_COLS].values, te["label"].values
    devs = te["disp_err_m"].values if "disp_err_m" in te.columns else np.zeros(len(yte))
    best = None
    for name, clf in fitted.items():
        try:
            yp = clf.predict(Xte)
            m = mod.compute_metrics(yte, yp, devs, len(yte))
            if best is None or m["MCC"] > best["MCC"]:
                best = {"MCC": m["MCC"], "FPR": m["FPR"], "clf": name}
        except Exception:
            pass
    return best


def read_cxx(path, mcc_col):
    if not os.path.exists(path): return None
    try: r = pd.read_csv(path).iloc[0]
    except Exception: return None
    fpr = "FPR_full" if mcc_col == "MCC_full" else "FPR"
    return {"MCC": float(r.get(mcc_col, 0.0)), "FPR": float(r.get(fpr, 0.0))}


def cp_detect_rate(mode0_log):
    if not os.path.exists(mode0_log): return None
    m = re.search(r"CP-DETECT = (\d+) CTRL_COMPROMISED.*?over (\d+) audited epochs", open(mode0_log).read())
    return (int(m.group(1)) / max(1, int(m.group(2)))) if m else None


rows = []
# fit baselines ONCE per attack (robust cross-pct model), then sweep test pcts
for a in ATTACKS:
    print(f"[attack {a}] training baselines on RngRun=1 (p30+p60+p90) ...")
    b2f, _ = fit_classifiers(B2, a)
    b3f, _ = fit_classifiers(B3, a)
    for p in TEST_PCTS:
        hd = os.path.join(HELD, f"a{a}_p{p}")
        # baselines (skip if degenerate test set)
        if b2f:
            r = predict_best(B2, b2f, hd)
            if r: rows.append({"attack": a, "attack_pct": p, "method": "B2_Ercan", "MCC": r["MCC"], "FPR": r["FPR"]})
        if b3f:
            r = predict_best(B3, b3f, hd)
            if r: rows.append({"attack": a, "attack_pct": p, "method": "B3_Sharma", "MCC": r["MCC"], "FPR": r["FPR"]})
        # B1 (C++ mode-6)
        b1 = read_cxx(os.path.join(hd, "b1_metrics.csv"), "MCC")
        if b1: rows.append({"attack": a, "attack_pct": p, "method": "B1_Ghaleb", **b1})
        # MPTD-PQS: CP-DETECT rate for control-plane, else MCC_full
        if a in CONTROL:
            cr = cp_detect_rate(os.path.join(hd, "mode0.log"))
            mp = read_cxx(os.path.join(hd, "metrics.csv"), "MCC_full")
            if cr is not None:
                rows.append({"attack": a, "attack_pct": p, "method": "MPTD-PQS_full",
                             "MCC": cr, "FPR": (mp["FPR"] if mp else float("nan"))})
        else:
            mp = read_cxx(os.path.join(hd, "metrics.csv"), "MCC_full")
            if mp: rows.append({"attack": a, "attack_pct": p, "method": "MPTD-PQS_full", **mp})
        print(f"   a{a} p{p} done")

allc = pd.DataFrame(rows)
allc.to_csv(os.path.join(OUT, "heldout_pct_comparison.csv"), index=False)
print(f"\nwrote {OUT}/heldout_pct_comparison.csv  ({len(allc)} rows)")

methods = ["MPTD-PQS_full","B1_Ghaleb","B2_Ercan","B3_Sharma"]
colors  = {"MPTD-PQS_full":"#2ca02c","B1_Ghaleb":"#8c564b","B2_Ercan":"#1f77b4","B3_Sharma":"#d62728"}
LBL = {1:"a1 TP-S1",2:"a2 TP-S2",3:"a3 MP-S1",4:"a4 MP-S2",5:"a5 TP-S3 ctrl[CP]",6:"a6 MP-S3",7:"a7 MP-S4 ctrl[CP]"}
for metric, up in [("MCC", True), ("FPR", False)]:
    fig, axes = plt.subplots(2, 4, figsize=(20, 8)); axes = axes.flatten()
    for i, a in enumerate(ATTACKS):
        ax = axes[i]
        for m in methods:
            sub = allc[(allc.attack==a) & (allc.method==m)].sort_values("attack_pct")
            if not sub.empty: ax.plot(sub.attack_pct, sub[metric], marker="o", label=m, color=colors[m])
        ax.set_title(LBL[a], fontsize=10); ax.set_xlabel("attack pct %"); ax.set_ylabel(metric); ax.grid(alpha=.3)
        if metric=="MCC": ax.set_ylim(-0.3,1.05)
        if i==0: ax.legend(fontsize=7)
    for j in range(len(ATTACKS), len(axes)): axes[j].axis("off")
    fig.suptitle(f"HELD-OUT {metric} ({'↑' if up else '↓'} better) — MPTD-PQS(full) vs Ercan/Sharma/Ghaleb, "
                 f"penetration 0–100%  (train seed-1 p30/60/90 / test seed-2; ε-MCC; a5/a7=CP-DETECT)", fontsize=12)
    fig.tight_layout(rect=[0,0,1,0.96]); fig.savefig(os.path.join(OUT, f"heldout_pct_{metric}.png"), dpi=140); plt.close(fig)
    print(f"plot -> {OUT}/heldout_pct_{metric}.png")

if not allc.empty:
    print("\n=== HELD-OUT MCC (ε-smoothed; a5/a7 = CP-DETECT rate) ===")
    print(allc.pivot_table(index=["attack","attack_pct"], columns="method", values="MCC").round(3).to_string())
