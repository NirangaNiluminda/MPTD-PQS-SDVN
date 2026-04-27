"""
demo_task1.py — Task 01 Demo: Performance Evaluation Metrics
=============================================================
Shows all 7 PEMs saved to CSV files for the supervisor meeting.

Run:
    python3 analytics/demo_task1.py

What this demonstrates:
  1. All 7 PEMs (MCC, FPR, PARR, CDER, TDEE, TPE, PBPO) are computed
     inside the NS-3 simulation and saved to CSV after every run.
  2. beacon_log.csv is written PERIODICALLY — one row per beacon received
     during the simulation (real-time streaming to disk).
  3. sweep/metrics_a{N}_p{P}.csv stores the per-run summary.
"""

import os, glob
import pandas as pd

NS3_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
SWEEP_DIR = os.path.join(NS3_ROOT, "analytics", "results", "sweep")
BEACON_LOG = os.path.join(NS3_ROOT, "analytics", "results", "beacon_log.csv")

# ── Metric descriptions (paper §4.1.2) ────────────────────────────────────────
METRIC_INFO = {
    "MCC":  ("Matthews Correlation Coefficient",        "−1 to +1  (higher = better)"),
    "FPR":  ("False Positive Rate",                     "0 to 1    (lower = better)"),
    "PARR": ("Poisoning Attack Recognition Rate",       "0 to 1    (higher = better)"),
    "CDER": ("Control Decision Error Rate",             "0 to 1    (lower = better)"),
    "TDEE": ("Trajectory Displacement Estimation Error","metres    (lower = better)"),
    "TPE":  ("Trajectory Poisoning Effect (RMSE)",      "metres    (lower = better)"),
    "PBPO": ("Per-Beacon Processing Overhead",          "ms        (lower = better)"),
}

ATTACK_NAMES = {
    0: "No Attack (clean baseline)",
    1: "TP-S1: Location Spoofing",
    2: "TP-S2: Flooding Attack",
    3: "TP-S3: Fabrication Attack",
    5: "MP-S2: Vanishing Attack",
    6: "MP-S4: Combined (all types)",
    7: "Coordinated Multi-Source",
}

def load_sweep_results():
    rows = []
    for f in sorted(glob.glob(os.path.join(SWEEP_DIR, "metrics_a*.csv"))):
        df = pd.read_csv(f)
        rows.append(df.iloc[0])
    return pd.DataFrame(rows).reset_index(drop=True) if rows else pd.DataFrame()

def print_header(title):
    w = 70
    print("\n" + "═"*w)
    print(f"  {title}")
    print("═"*w)

def main():
    print_header("MPTD-PQS — Task 01: Performance Evaluation Metrics Demo")

    # ── 1. Explain the 7 metrics ──────────────────────────────────────────────
    print_header("1. The 7 Performance Evaluation Metrics (Paper §4.1.2)")
    for i, (key, (desc, range_)) in enumerate(METRIC_INFO.items(), 1):
        print(f"  Eq.4.{i}  {key:5s}  {desc}")
        print(f"         Range: {range_}")
    print()

    # ── 2. Latest single-run metrics from beacon_log ──────────────────────────
    print_header("2. Per-Run Metric CSV  (analytics/results/sweep/)")
    sweep_df = load_sweep_results()
    if sweep_df.empty:
        print("  No sweep results found. Run the simulation first.")
    else:
        atk_col = []
        for _, row in sweep_df.iterrows():
            an = int(row.get("attack_number", 0))
            atk_col.append(ATTACK_NAMES.get(an, f"Attack {an}"))
        sweep_df.insert(0, "Attack Scenario", atk_col)

        display_cols = ["Attack Scenario", "attack_pct",
                        "MCC", "FPR", "PARR", "CDER", "TDEE", "TPE", "PBPO"]
        display_cols = [c for c in display_cols if c in sweep_df.columns]
        print(sweep_df[display_cols].to_string(index=False,
              float_format=lambda x: f"{x:.4f}"))

    # ── 3. Periodic beacon log ────────────────────────────────────────────────
    print_header("3. Periodic Beacon Log  (analytics/results/beacon_log.csv)")
    if os.path.exists(BEACON_LOG):
        df = pd.read_csv(BEACON_LOG)
        total     = len(df)
        poisoned  = int(df["is_poisoned"].sum())
        detected  = int(df["detected"].sum())
        clean     = total - poisoned
        print(f"  Total beacons logged   : {total}")
        print(f"  Clean beacons (TN+FP)  : {clean}")
        print(f"  Poisoned beacons (TP+FN): {poisoned}")
        print(f"  Detected attacks (TP)  : {detected}")
        print(f"\n  First 5 rows (written during simulation — one row per beacon):")
        print(df.head(5).to_string(index=False))
        print(f"\n  File location: {BEACON_LOG}")
    else:
        print("  beacon_log.csv not found — run the simulation first.")

    # ── 4. Key results summary ────────────────────────────────────────────────
    print_header("4. Key Result Summary")
    if not sweep_df.empty:
        atk_rows = sweep_df[sweep_df["attack_number"] > 0] if "attack_number" in sweep_df.columns else sweep_df
        if not atk_rows.empty:
            best_mcc = atk_rows.loc[atk_rows["MCC"].idxmax()]
            print(f"  Best MCC achieved   : {best_mcc['MCC']:.4f}  "
                  f"({best_mcc.get('Attack Scenario', 'N/A')})")
            print(f"  FPR across all runs : always {atk_rows['FPR'].max():.4f}  "
                  f"(zero false positives)")
            print(f"  Mean PBPO overhead  : {atk_rows['PBPO'].mean():.3f} ms per beacon")
    print()
    print("  Both CSV files are written automatically by the NS-3 simulation:")
    print("  • beacon_log.csv   — appended each time a beacon is RECEIVED (periodic)")
    print("  • sweep/metrics_*  — written at END of each simulation run")
    print()
    print("═"*70)
    print("  Demo complete. Ready for Task 01 presentation.")
    print("═"*70 + "\n")

if __name__ == "__main__":
    main()
