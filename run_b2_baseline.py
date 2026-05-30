#!/usr/bin/env python3
"""
run_b2_baseline.py  —  Ercan et al. (2022) B2 baseline evaluation
Metrics: our 7 project metrics (MCC, FPR, PARR, CDER, TDEE, TPE, PBPO)
"""
from __future__ import annotations
import json, os, sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
NS3_CSV     = os.path.join(SCRIPT_DIR, "analytics", "results", "rsu_relay_log.csv")
SYN_TMPL    = os.path.join(SCRIPT_DIR, "analytics", "results", "rsu_relay_log_attack{}.csv")
sys.path.insert(0, SCRIPT_DIR)

from mptd_pqs.ercan_b2_detector import (
    ErcanB2Detector, extract_features_from_ns3, penetration_sweep,
)

MPTD_PQS_RESULTS = {
    "MCC": 0.7303, "FPR": 0.2000, "PARR": 1.0000,
    "CDER": 1203.52, "TDEE": 6344185.03, "TPE": 0.4000, "PBPO": 0.2857,
}

ATTACK_LABELS = {
    1: "TP-S1\nRSU drift",
    2: "TP-S2\nspeed/heading",
    3: "MP-S1\nSybil ghost",
    4: "MP-S2\nimpersonation",
    5: "TP-S3\ncontroller",
}

def run_main(feat_df):
    det  = ErcanB2Detector(seed=42)
    res  = det.run(feat_df)
    rows = []
    for method, m in res.items():
        print(f"  {method:10s}: MCC={m['MCC']:+.4f}  FPR={m['FPR']:.4f}  "
              f"PARR={m['PARR']:.4f}  CDER={m['CDER']:.2f}m  "
              f"TDEE={m['TDEE']:.0f}  TPE={m['TPE']:.4f}  PBPO={m['PBPO']:.4f}")
        rows.append({"Method": method, **m})
    return pd.DataFrame(rows)

def run_multi_attack(det):
    print("\n[B2] Per-attack-type evaluation (RF)")
    rows = []
    for atk_num, label in ATTACK_LABELS.items():
        csv = NS3_CSV if atk_num == 1 else SYN_TMPL.format(atk_num)
        if not os.path.exists(csv):
            print(f"  attack_{atk_num}: file missing, skip"); continue
        feat = extract_features_from_ns3(csv, seed=42)
        res  = det.run(feat)
        rf   = res.get("RF", {})
        print(f"  attack_{atk_num}: MCC={rf.get('MCC',0):+.4f}  "
              f"PARR={rf.get('PARR',0):.4f}  PBPO={rf.get('PBPO',0):.4f}")
        rows.append({"Attack": f"attack_{atk_num}",
                     "Label": label.replace("\n"," "), **rf})
    return pd.DataFrame(rows)

def plot_dashboard(sweep_df, multi_df, out_path):
    fig, axes = plt.subplots(1, 3, figsize=(15, 4))
    fig.suptitle("B2 — Ercan et al. (2022): Detection Performance vs. Penetration Rate",
                 fontsize=11, fontweight="bold")

    C_B2   = "#2ca02c"
    C_MPTD = "#d62728"

    # Panel 1 — MCC vs rho
    ax = axes[0]
    ax.plot(sweep_df["rho"], sweep_df["RF_MCC"], "o-", color=C_B2, lw=2, ms=6, label="B2-Ercan")
    ax.fill_between(sweep_df["rho"], sweep_df["RF_MCC"], alpha=0.10, color=C_B2)
    ax.axhline(MPTD_PQS_RESULTS["MCC"], color=C_MPTD, ls="--", lw=1.5, label="MPTD-PQS")
    for x, y in zip(sweep_df["rho"], sweep_df["RF_MCC"]):
        ax.annotate(f"{y:.3f}", (x, y), textcoords="offset points",
                    xytext=(0, 7), ha="center", fontsize=7.5)
    ax.set(xlabel="Attack Penetration Rate (ρ_a)", ylabel="MCC",
           title="MCC vs. ρ_a", ylim=(-0.1, 1.1))
    ax.grid(True, alpha=0.3); ax.legend(fontsize=9)

    # Panel 2 — PARR vs rho
    ax = axes[1]
    ax.plot(sweep_df["rho"], sweep_df["RF_PARR"], "o-", color=C_B2, lw=2, ms=6, label="B2-Ercan")
    ax.fill_between(sweep_df["rho"], sweep_df["RF_PARR"], alpha=0.10, color=C_B2)
    ax.axhline(MPTD_PQS_RESULTS["PARR"], color=C_MPTD, ls="--", lw=1.5, label="MPTD-PQS")
    for x, y in zip(sweep_df["rho"], sweep_df["RF_PARR"]):
        ax.annotate(f"{y:.3f}", (x, y), textcoords="offset points",
                    xytext=(0, 7), ha="center", fontsize=7.5)
    ax.set(xlabel="Attack Penetration Rate (ρ_a)", ylabel="PARR",
           title="PARR vs. ρ_a", ylim=(-0.05, 1.15))
    ax.grid(True, alpha=0.3); ax.legend(fontsize=9)

    # Panel 3 — MCC per attack type
    ax = axes[2]
    if multi_df is not None and len(multi_df):
        labels = [ATTACK_LABELS[int(a.split("_")[1])].replace("\n", "\n")
                  for a in multi_df["Attack"]]
        bars = ax.bar(labels, multi_df["MCC"], color=C_B2, width=0.5)
        ax.axhline(MPTD_PQS_RESULTS["MCC"], color=C_MPTD, ls="--", lw=1.5, label="MPTD-PQS MCC")
        for bar, val in zip(bars, multi_df["MCC"]):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + 0.01,
                    f"{val:.3f}", ha="center", fontsize=8)
        ax.set(xlabel="Attack Type", ylabel="MCC (RF)",
               title="MCC per Attack Type", ylim=(0, 1.2))
        ax.tick_params(axis="x", labelsize=8)
        ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n  Dashboard → {out_path}")

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("="*65)
    print("  B2 Baseline — Ercan et al. (2022)")
    print("  CV: Leave-One-Vehicle-Out | Metrics: 7 project metrics")
    print("="*65)

    # Section 1: main NS-3 result
    print(f"\n[B2] Loading data: {NS3_CSV}")
    feat_df = extract_features_from_ns3(NS3_CSV, seed=42)
    print(f"  Rows: {len(feat_df)}  labels: {feat_df['label'].value_counts().to_dict()}")
    print("\n[B2] Main evaluation (attack_1, all methods)")
    main_df = run_main(feat_df)
    main_df.to_csv(os.path.join(RESULTS_DIR, "b2_ercan_main_result.csv"), index=False)

    # Section 2: penetration sweep
    print("\n[B2] Penetration sweep")
    sweep = penetration_sweep(feat_df, seed=42)
    for r in sweep:
        print(f"  rho={r['rho']:.3f}  n_mal={r['n_mal']}  "
              f"RF_MCC={r['RF_MCC']:+.4f}  RF_PARR={r['RF_PARR']:.4f}  "
              f"RF_PBPO={r['RF_PBPO']:.4f}")
    sweep_df = pd.DataFrame(sweep)
    sweep_df.to_csv(os.path.join(RESULTS_DIR, "b2_ercan_penetration_sweep.csv"), index=False)

    # Section 3: per-attack-type
    det      = ErcanB2Detector(seed=42)
    multi_df = run_multi_attack(det)
    multi_df.to_csv(os.path.join(RESULTS_DIR, "b2_ercan_multi_attack.csv"), index=False)

    # Section 4: comparison table
    rf      = main_df[main_df["Method"] == "RF"].iloc[0]
    metrics = ["MCC","FPR","PARR","CDER","TDEE","TPE","PBPO"]
    comp_df = pd.DataFrame([
        {"System": "MPTD-PQS (ours)", **{m: MPTD_PQS_RESULTS[m] for m in metrics}},
        {"System": "B2-Ercan RF",     **{m: rf[m] for m in metrics}},
    ])
    print("\n" + "="*65)
    print("  COMPARISON: B2 Ercan vs MPTD-PQS")
    print(comp_df.to_string(index=False))
    comp_df.to_csv(os.path.join(RESULTS_DIR, "b2_ercan_summary.csv"), index=False)

    # Dashboard
    plot_dashboard(sweep_df, multi_df,
                   os.path.join(RESULTS_DIR, "b2_ercan_dashboard.png"))

    # JSON
    json_out = {
        "system": "B2_Ercan2022",
        "main_results": {r["Method"]: {k:v for k,v in r.items() if k!="Method"}
                         for _, r in main_df.iterrows()},
        "sweep_rf":        sweep_df.to_dict(orient="records"),
        "multi_attack_rf": multi_df.to_dict(orient="records"),
        "comparison":      comp_df.to_dict(orient="records"),
    }
    with open(os.path.join(RESULTS_DIR, "b2_ercan_results.json"), "w") as f:
        json.dump(json_out, f, indent=2)

    print(f"\n[B2] All outputs in: {RESULTS_DIR}")

if __name__ == "__main__":
    main()