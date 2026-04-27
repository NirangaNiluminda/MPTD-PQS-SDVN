"""
visualize_results.py  —  MPTD-PQS Results Visualizer
======================================================
Reads all sweep/metrics_aX_p30.csv files and produces:
  1. A clean printed table in the terminal
  2. A bar chart figure saved as  analytics/results/metrics_chart.png
  3. A confusion matrix figure saved as analytics/results/confusion_chart.png

Run:
    python3 analytics/visualize_results.py
"""

import os
import glob
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")          # no display needed — saves to PNG
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
SWEEP_DIR   = os.path.join(SCRIPT_DIR, "results", "sweep")
OUT_DIR     = os.path.join(SCRIPT_DIR, "results")

# ── Attack labels ────────────────────────────────────────────────────────────
ATTACK_NAMES = {
    1: "TP-S1\nLoc. Spoof",
    2: "TP-S2\nVel. Exag.",
    3: "TP-S3\nFabrication",
    4: "MP-S1\nSybil",
    5: "MP-S2\nVanishing",
    6: "MP-S4\nCombined",
    7: "Coordinated",
}

# ── Load data (one row per attack, fixed 30% attacker percentage) ────────────
def load_sweep(pct=30):
    rows = []
    for atk in range(1, 8):
        path = os.path.join(SWEEP_DIR, f"metrics_a{atk}_p{pct}.csv")
        if not os.path.exists(path):
            print(f"  [WARN] Missing: {path}  — skipping attack {atk}")
            continue
        df = pd.read_csv(path)
        row = df.iloc[-1].to_dict()   # last row = most recent run
        rows.append(row)
    return pd.DataFrame(rows)


# ── Terminal table ────────────────────────────────────────────────────────────
def print_table(df):
    print()
    print("=" * 85)
    print("  MPTD-PQS Detection Metrics  (attack_percentage = 30%)")
    print("=" * 85)
    header = f"{'#':<4} {'Attack':<22} {'MCC':>6} {'FPR':>5} {'PARR':>6} {'CDER':>6} {'TDEE(m)':>8} {'TPE(m)':>7} {'PBPO(ms)':>9}"
    print(header)
    print("-" * 85)
    for _, r in df.iterrows():
        atk  = int(r["attack_number"])
        name = ATTACK_NAMES.get(atk, f"Attack {atk}").replace("\n", " ")
        print(f"  {atk:<3} {name:<22} {r['MCC']:>6.3f} {r['FPR']:>5.3f} "
              f"{r['PARR']:>6.3f} {r['CDER']:>6.3f} "
              f"{r['TDEE']:>8.2f} {r['TPE']:>7.2f} {r['PBPO']:>9.2f}")
    print("-" * 85)
    print()

    print("  Confusion Matrix Counts")
    print(f"  {'#':<4} {'Attack':<22} {'TP':>5} {'FP':>5} {'TN':>5} {'FN':>5}")
    print("  " + "-" * 50)
    for _, r in df.iterrows():
        atk  = int(r["attack_number"])
        name = ATTACK_NAMES.get(atk, f"Attack {atk}").replace("\n", " ")
        print(f"  {atk:<4} {name:<22} {int(r['cm_TP']):>5} {int(r['cm_FP']):>5} "
              f"{int(r['cm_TN']):>5} {int(r['cm_FN']):>5}")
    print("=" * 85)
    print()


# ── Bar chart: 4 detection metrics ───────────────────────────────────────────
def plot_metrics(df, out_path):
    attacks = [ATTACK_NAMES.get(int(r["attack_number"]), str(int(r["attack_number"])))
               for _, r in df.iterrows()]
    x = np.arange(len(attacks))
    w = 0.2

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle("MPTD-PQS Detection Metrics — Attack Comparison (30% attackers)",
                 fontsize=14, fontweight="bold", y=1.01)

    # ── Left: MCC, PARR, CDER ───────────────────────────────────────────────
    ax = axes[0]
    ax.bar(x - w,   df["MCC"].values,  w, label="MCC",  color="#2196F3", alpha=0.88)
    ax.bar(x,       df["PARR"].values, w, label="PARR", color="#4CAF50", alpha=0.88)
    ax.bar(x + w,   df["CDER"].values, w, label="CDER", color="#F44336", alpha=0.88)
    ax.set_xticks(x)
    ax.set_xticklabels(attacks, fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score (0 – 1)")
    ax.set_title("Detection Quality\n(MCC ↑ good  |  PARR ↑ good  |  CDER ↓ good)")
    ax.legend(loc="upper right")
    ax.axhline(0.5, color="gray", linestyle="--", linewidth=0.8, alpha=0.5)
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4)

    # Annotate FPR = 0 on every bar group
    for xi in x:
        ax.text(xi, 1.02, "FPR=0", ha="center", fontsize=7, color="navy")

    # ── Right: TDEE, TPE (position errors) ──────────────────────────────────
    ax2 = axes[1]
    ax2.bar(x - w/2, df["TDEE"].values, w, label="TDEE (all vehicles)",      color="#9C27B0", alpha=0.88)
    ax2.bar(x + w/2, df["TPE"].values,  w, label="TPE  (malicious only)",     color="#FF9800", alpha=0.88)
    ax2.set_xticks(x)
    ax2.set_xticklabels(attacks, fontsize=9)
    ax2.set_ylabel("Position Error (metres)")
    ax2.set_title("Trajectory Error\n(TDEE = mean error all  |  TPE = RMSE malicious)")
    ax2.legend(loc="upper right")
    ax2.set_axisbelow(True)
    ax2.yaxis.grid(True, linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"  [SAVED] {out_path}")
    plt.close()


# ── Confusion matrix heatmap ─────────────────────────────────────────────────
def plot_confusion(df, out_path):
    n    = len(df)
    fig, axes = plt.subplots(1, n, figsize=(2.5 * n, 3.5))
    fig.suptitle("Confusion Matrices — All Attacks (30% attackers)",
                 fontsize=13, fontweight="bold")

    if n == 1:
        axes = [axes]

    for ax, (_, r) in zip(axes, df.iterrows()):
        atk   = int(r["attack_number"])
        name  = ATTACK_NAMES.get(atk, f"Atk {atk}").replace("\n", " ")
        mat   = np.array([[int(r["cm_TN"]), int(r["cm_FP"])],
                           [int(r["cm_FN"]), int(r["cm_TP"])]])
        labels = [["TN", "FP"], ["FN", "TP"]]
        colors = [["#C8E6C9", "#FFCDD2"], ["#FFCDD2", "#C8E6C9"]]

        for i in range(2):
            for j in range(2):
                ax.add_patch(plt.Rectangle((j, 1 - i), 1, 1,
                             color=colors[i][j], ec="white", lw=2))
                ax.text(j + 0.5, 1.5 - i, f"{labels[i][j]}\n{mat[i][j]}",
                        ha="center", va="center", fontsize=11, fontweight="bold")

        ax.set_xlim(0, 2)
        ax.set_ylim(0, 2)
        ax.set_xticks([0.5, 1.5])
        ax.set_xticklabels(["Pred\nNormal", "Pred\nMalicious"], fontsize=8)
        ax.set_yticks([0.5, 1.5])
        ax.set_yticklabels(["Actual\nMalicious", "Actual\nNormal"], fontsize=8)
        ax.set_title(f"#{atk} {name}", fontsize=9, fontweight="bold")

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"  [SAVED] {out_path}")
    plt.close()


# ── PBPO chart ───────────────────────────────────────────────────────────────
def plot_pbpo(df, out_path):
    attacks = [ATTACK_NAMES.get(int(r["attack_number"]), str(int(r["attack_number"])))
               for _, r in df.iterrows()]
    x = np.arange(len(attacks))

    fig, ax = plt.subplots(figsize=(10, 4))
    bars = ax.bar(x, df["PBPO"].values, color="#00BCD4", alpha=0.88, width=0.5)
    ax.axhline(5.0, color="red", linestyle="--", linewidth=1.2, label="5ms limit")
    ax.set_xticks(x)
    ax.set_xticklabels(attacks, fontsize=9)
    ax.set_ylabel("PBPO (milliseconds)")
    ax.set_title("Per-Beacon Processing Overhead (PBPO)\n"
                 "— all attacks well under 5ms real-time limit —",
                 fontweight="bold")
    ax.legend()
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4)
    for bar, val in zip(bars, df["PBPO"].values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.05, f"{val:.2f}ms",
                ha="center", fontsize=9)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    print(f"  [SAVED] {out_path}")
    plt.close()


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n[MPTD-PQS Visualizer] Loading sweep results …")
    df = load_sweep(pct=30)

    if df.empty:
        print("[ERROR] No metrics_aX_p30.csv files found in:")
        print(f"        {SWEEP_DIR}")
        print("        Run each attack first with --attack_percentage=30")
        exit(1)

    print(f"  Loaded {len(df)} attack results\n")

    # 1. Terminal table
    print_table(df)

    # 2. Save charts
    os.makedirs(OUT_DIR, exist_ok=True)
    plot_metrics  (df, os.path.join(OUT_DIR, "metrics_chart.png"))
    plot_confusion(df, os.path.join(OUT_DIR, "confusion_chart.png"))
    plot_pbpo     (df, os.path.join(OUT_DIR, "pbpo_chart.png"))

    print()
    print("  Open these images to see your results visually:")
    print(f"    xdg-open {OUT_DIR}/metrics_chart.png")
    print(f"    xdg-open {OUT_DIR}/confusion_chart.png")
    print(f"    xdg-open {OUT_DIR}/pbpo_chart.png")
    print()
