"""
plot_per_attack.py  —  MPTD-PQS  |  Metric vs Attack Percentage
================================================================
Creates one publication-quality figure per ATTACK SCENARIO.

Each figure:
  X-axis : Attack Percentage (%)  — increasing left to right
  Y-axis : Chosen metric (MCC, DR, FPR, Precision, F1)
  Lines  : MPTD-PQS (Proposed)  — one line for now
           [add baseline methods here later]

Supervisor's exact requirement:
  "A plot per each metric.  Since you have still not implemented
   existing techniques for result benchmarking, you will have only
   1 graph per plot: the proposed method."

Outputs  →  analytics/results/figures/per_attack/
  fig_a1_mcc.png / .pdf  ...  fig_a7_mcc.png / .pdf
  fig_a1_all.png / .pdf  ...  fig_a7_all.png / .pdf   (all 5 metrics)
  fig_combined_mcc.png   — all attacks on one page (supervisor style)

Run:
    cd /home/niranga/ns-allinone-3.35/ns-3.35
    python3 analytics/plot_per_attack.py
"""

import os, glob
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.gridspec import GridSpec

# ─── Paths ────────────────────────────────────────────────────────────────────
ROOT      = "/home/niranga/ns-allinone-3.35/ns-3.35"
SWEEP_DIR = os.path.join(ROOT, "analytics", "results", "sweep")
OUT_DIR   = os.path.join(ROOT, "analytics", "results", "figures", "per_attack")
os.makedirs(OUT_DIR, exist_ok=True)

# ─── Attack descriptions ──────────────────────────────────────────────────────
ATTACK_META = {
    1: ("A1", "TP-S1",  "Trajectory Poisoning:\nCompromised RSU Position Drift"),
    2: ("A2", "TP-S2",  "Trajectory Poisoning:\nMalicious Vehicle Trajectory"),
    3: ("A3", "MP-S1",  "Mobility Pattern:\nGhost Identity (Compromised RSU)"),
    4: ("A4", "MP-S2",  "Mobility Pattern:\nVehicle Identity Theft (Sybil)"),
    5: ("A5", "MP-S3",  "Mobility Pattern:\nData Plane MitM"),
    6: ("A6", "MP-S3b", "Mobility Pattern:\nMitM Intercept Variant"),
    7: ("A7", "MP-S4",  "Mobility Pattern:\nControl Plane Poisoning"),
}

# ─── Plot styling (matches supervisor's reference figure) ─────────────────────
PROPOSED = dict(color="#D32F2F", marker="o", markersize=8,
                linewidth=2.5, linestyle="-", label="MPTD-PQS (Proposed)", zorder=5)

# Placeholder colours for future baseline methods
BASELINES = [
    dict(color="#1565C0", marker="*",  markersize=9,  linewidth=2, linestyle="--", label="Ack-based"),
    dict(color="#E91E8C", marker="^",  markersize=8,  linewidth=2, linestyle="-.", label="Hop cnt-based"),
    dict(color="#212121", marker="D",  markersize=7,  linewidth=2, linestyle=":",  label="RREQ-based"),
    dict(color="#2E7D32", marker="s",  markersize=7,  linewidth=2, linestyle="-",  label="Hybrid"),
]

# ─── Load & prepare data ──────────────────────────────────────────────────────
def load_data():
    files  = sorted(glob.glob(os.path.join(SWEEP_DIR, "metrics_a*.csv")))
    data   = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    data   = data[data["total_received"] > 0].copy()

    # ε = 10⁻⁶ : supervisor-specified numerical stability constant.
    # Added to all four CM cells before any metric computation so the
    # MCC denominator never reaches exactly zero (occurs when TN=0 and
    # FP=0 at 100 % attack percentage).  Value is small enough that it
    # does not visibly distort counts that are already non-zero.
    eps = 1e-6
    tp = data["cm_TP"].astype(float) + eps
    fp = data["cm_FP"].astype(float) + eps
    tn = data["cm_TN"].astype(float) + eps
    fn = data["cm_FN"].astype(float) + eps

    data["DR"]        = tp / (tp + fn)
    data["Precision"] = tp / (tp + fp)
    data["F1"]        = 2*tp / (2*tp + fp + fn)

    # Recompute MCC from smoothed counts (replaces raw CSV MCC value).
    # Denominator is now always > 0 → defined at every attack percentage
    # including 100 % where TN_raw = 0.
    denom = np.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    data["MCC"] = (tp*tn - fp*fn) / denom

    return data

# ─── Helper: style one axes ───────────────────────────────────────────────────
def _style_ax(ax, xlabel, ylabel, title, ylim=(0, 1.05)):
    ax.set_xlabel(xlabel, fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title,   fontsize=11, fontweight="bold", pad=5)
    ax.set_xlim(0, 105)
    if ylim:
        ax.set_ylim(*ylim)
    ax.xaxis.set_major_locator(ticker.MultipleLocator(20))
    ax.yaxis.set_major_locator(ticker.MultipleLocator(0.2))
    ax.tick_params(labelsize=10)
    ax.grid(True, linestyle="--", alpha=0.45)

# ─── Figure 1: One MCC figure per attack (supervisor style) ──────────────────
def plot_mcc_per_attack(data):
    """
    7 separate figures — each looks like supervisor's Figure 11.
    Currently 1 red line (proposed).  Add baselines below when ready.
    """
    for atk_num, (short, pid, title) in ATTACK_META.items():
        sub = (data[data["attack_number"] == atk_num]
               .sort_values("attack_pct")
               .dropna(subset=["MCC"]))

        if sub.empty:
            print(f"  SKIP A{atk_num}: no valid MCC data")
            continue

        fig, ax = plt.subplots(figsize=(6, 4.5))

        # ── Proposed method (RED solid line) ──────────────────────────────────
        ax.plot(sub["attack_pct"], sub["MCC"], **PROPOSED)

        # ── TO ADD BASELINES LATER — uncomment and fill values ────────────────
        # baseline_pcts = [0, 20, 40, 60, 80, 100]
        # ax.plot(baseline_pcts, [0.86, 0.81, 0.75, 0.62, 0.43, 0.10],
        #         **BASELINES[0])   # Ack-based
        # ax.plot(baseline_pcts, [0.88, 0.60, 0.40, 0.20, 0.10, 0.05],
        #         **BASELINES[1])   # Hop cnt-based
        # ─────────────────────────────────────────────────────────────────────

        _style_ax(ax,
                  xlabel="Attack Percentage (%)",
                  ylabel="Matthews Correlation Coefficient",
                  title=f"MCC Analysis — {pid}: {title.replace(chr(10), ' ')}")

        ax.legend(fontsize=10, loc="upper right", framealpha=0.9)
        fig.tight_layout()

        out = os.path.join(OUT_DIR, f"fig_a{atk_num}_mcc")
        fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
        fig.savefig(out + ".pdf",          bbox_inches="tight")
        plt.close(fig)
        print(f"  [OK] {out}.png")

# ─── Figure 2: All metrics for one attack (5-line subplot) ───────────────────
METRIC_SPECS = [
    ("MCC",       "MCC",                           (0, 1.05), "#D32F2F"),
    ("DR",        "Detection Rate",                (0, 1.05), "#1565C0"),
    ("FPR",       "False Positive Rate",           (0, 1.05), "#E91E8C"),
    ("Precision", "Precision",                     (0, 1.05), "#2E7D32"),
    ("F1",        "F1-Score",                      (0, 1.05), "#FF6F00"),
]

def plot_all_metrics_per_attack(data):
    """
    For each attack: one figure with 5 metric lines vs attack percentage.
    This gives a complete picture of proposed-method performance per attack.
    """
    for atk_num, (short, pid, title) in ATTACK_META.items():
        sub = (data[data["attack_number"] == atk_num]
               .sort_values("attack_pct"))

        if sub.empty:
            continue

        fig, ax = plt.subplots(figsize=(7, 5))

        any_plotted = False
        for col, lbl, ylim, clr in METRIC_SPECS:
            s = sub.dropna(subset=[col])
            if len(s) < 2:
                continue
            ax.plot(s["attack_pct"], s[col],
                    color=clr, marker="o", markersize=7,
                    linewidth=2.2, linestyle="-", label=lbl)
            any_plotted = True

        if not any_plotted:
            plt.close(fig)
            continue

        ax.set_xlabel("Attack Percentage (%)", fontsize=12)
        ax.set_ylabel("Metric Value",           fontsize=12)
        ax.set_title(f"MPTD-PQS Performance — {pid}: {title.replace(chr(10), ' ')}",
                     fontsize=11, fontweight="bold")
        ax.set_xlim(0, 105)
        ax.set_ylim(0, 1.05)
        ax.xaxis.set_major_locator(ticker.MultipleLocator(20))
        ax.yaxis.set_major_locator(ticker.MultipleLocator(0.2))
        ax.tick_params(labelsize=10)
        ax.grid(True, linestyle="--", alpha=0.45)
        ax.legend(fontsize=9.5, loc="best", framealpha=0.9, ncol=2)

        fig.tight_layout()
        out = os.path.join(OUT_DIR, f"fig_a{atk_num}_all_metrics")
        fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
        fig.savefig(out + ".pdf",          bbox_inches="tight")
        plt.close(fig)
        print(f"  [OK] {out}.png")

# ─── Figure 3: Combined grid — all attacks, MCC only (supervisor overview) ───
def plot_combined_mcc_grid(data):
    """
    Single page: 2 × 4 grid of MCC plots — one subplot per attack.
    Looks like the supervisor's reference figure but for all 7 attacks.
    """
    attacks = [a for a in ATTACK_META if not
               data[(data["attack_number"]==a) & data["MCC"].notna()].empty]

    ncol = 4
    nrow = int(np.ceil(len(attacks) / ncol))

    fig = plt.figure(figsize=(ncol * 4.5, nrow * 3.8))
    gs  = GridSpec(nrow, ncol, figure=fig, hspace=0.55, wspace=0.38)

    for idx, atk_num in enumerate(sorted(attacks)):
        r, c = divmod(idx, ncol)
        ax   = fig.add_subplot(gs[r, c])

        short, pid, title = ATTACK_META[atk_num]
        sub = (data[data["attack_number"] == atk_num]
               .sort_values("attack_pct")
               .dropna(subset=["MCC"]))

        if not sub.empty:
            ax.plot(sub["attack_pct"], sub["MCC"],
                    color="#D32F2F", marker="o", markersize=6,
                    linewidth=2.2, linestyle="-", label="MPTD-PQS")

        ax.set_title(f"{pid}: {title.split(chr(10))[0]}", fontsize=9.5, fontweight="bold")
        ax.set_xlabel("Attack %", fontsize=9)
        ax.set_ylabel("MCC",      fontsize=9)
        ax.set_xlim(0, 105)
        ax.set_ylim(0, 1.05)
        ax.xaxis.set_major_locator(ticker.MultipleLocator(20))
        ax.yaxis.set_major_locator(ticker.MultipleLocator(0.2))
        ax.tick_params(labelsize=8)
        ax.grid(True, linestyle="--", alpha=0.45)
        ax.legend(fontsize=7.5, loc="upper right", framealpha=0.85)

    fig.suptitle("MPTD-PQS: MCC Analysis per Attack Scenario",
                 fontsize=14, fontweight="bold", y=1.02)
    fig.tight_layout()

    out = os.path.join(OUT_DIR, "fig_combined_mcc")
    fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(out + ".pdf",          bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] {out}.png")

# ─── Figure 4: Combined grid — all attacks, all metrics ──────────────────────
def plot_combined_all_metrics_grid(data):
    """
    Full overview: rows = attack scenarios, columns = metrics.
    """
    attacks  = sorted([a for a in ATTACK_META if a != 0
                       and not data[data["attack_number"]==a].empty])
    metrics  = [(col, lbl, clr) for col, lbl, _, clr in METRIC_SPECS]

    nrow, ncol = len(attacks), len(metrics)
    fig = plt.figure(figsize=(ncol * 3.8, nrow * 3.0))
    gs  = GridSpec(nrow, ncol, figure=fig, hspace=0.65, wspace=0.40)

    for ri, atk_num in enumerate(attacks):
        short, pid, _ = ATTACK_META[atk_num]
        sub = data[data["attack_number"] == atk_num].sort_values("attack_pct")

        for ci, (col, lbl, clr) in enumerate(metrics):
            ax = fig.add_subplot(gs[ri, ci])
            s  = sub.dropna(subset=[col])

            if len(s) >= 2:
                ax.plot(s["attack_pct"], s[col],
                        color=clr, marker="o", markersize=5,
                        linewidth=1.8, linestyle="-")
            else:
                ax.text(0.5, 0.5, "No data", transform=ax.transAxes,
                        ha="center", va="center", fontsize=8, color="grey")

            if ri == 0:
                ax.set_title(lbl, fontsize=8.5, fontweight="bold")
            if ci == 0:
                ax.set_ylabel(f"{pid}\n{short}", fontsize=8, labelpad=2)

            ax.set_xlim(0, 105)
            ax.set_ylim(0, 1.05)
            ax.xaxis.set_major_locator(ticker.MultipleLocator(20))
            ax.yaxis.set_major_locator(ticker.MultipleLocator(0.5))
            ax.tick_params(labelsize=7)
            ax.grid(True, linestyle="--", alpha=0.4)

    fig.suptitle("MPTD-PQS: All Metrics per Attack Scenario (X = Attack %)",
                 fontsize=12, fontweight="bold", y=1.01)
    fig.tight_layout()

    out = os.path.join(OUT_DIR, "fig_combined_all")
    fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(out + ".pdf",          bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] {out}.png")

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("=" * 62)
    print("  MPTD-PQS — Per-Attack Metric Plots (Supervisor Style)")
    print("=" * 62)

    print(f"\nLoading: {SWEEP_DIR}")
    data = load_data()
    print(f"  {len(data)} valid rows | attacks: {sorted(data['attack_number'].unique())}\n")

    print("── Figure set 1: MCC vs Attack %  (one figure per attack) ──")
    plot_mcc_per_attack(data)

    print("\n── Figure set 2: All metrics vs Attack %  (one per attack) ──")
    plot_all_metrics_per_attack(data)

    print("\n── Figure set 3: Combined MCC grid  (all attacks one page) ──")
    plot_combined_mcc_grid(data)

    print("\n── Figure set 4: Full overview grid  (attacks × metrics) ────")
    plot_combined_all_metrics_grid(data)

    print(f"\nAll outputs → {OUT_DIR}")
    files = sorted(os.listdir(OUT_DIR))
    print(f"\n{'File':<42}  {'Size':>8}")
    print("-" * 53)
    for f in files:
        sz = os.path.getsize(os.path.join(OUT_DIR, f))
        print(f"  {f:<40}  {sz/1024:7.1f} KB")
    print("\nDone!")

if __name__ == "__main__":
    main()
