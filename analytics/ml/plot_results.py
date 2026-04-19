"""
plot_results.py — MPTD-PQS Stage 8 Result Visualisation
Paper Chapter 4 figures

Reads analytics/results/sweep/sweep_summary.csv and produces:
  Fig 1 — MCC by attack type and mode      (answers RQ2, RQ4)
  Fig 2 — FPR by penetration rate and mode (answers RQ3, RQ4)
  Fig 3 — MCC by speed regime              (answers RQ1)
  Fig 4 — Ablation bar chart A1-A5 vs MPTD-PQS (answers RQ2-RQ4)
  Fig 5 — PARR: A4 vs MPTD-PQS by penetration rate (answers RQ5)
  Fig 6 — CDER: A5 vs MPTD-PQS (answers RQ6)
  Fig 7 — PBPO: LW vs Full overhead in ms (answers RQ3, RQ5)

Usage:
  python3 plot_results.py \\
      --summary_csv ../results/sweep/sweep_summary.csv \\
      --out_dir     ../results/figures
"""

import argparse
import os
import sys
import warnings

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.ticker as mticker
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("[plot] matplotlib not available — writing CSV summaries only")


# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------
ATTACK_LABELS = {
    1: "TP-S1\n(traj drift)",
    2: "TP-S2\n(speed spoof)",
    3: "TP-S3\n(ctrl poison)",
    4: "MP-S1\n(density lie)",
    5: "MP-S2\n(Sybil RSU)",
    6: "MP-S3\n(MitM)",
    7: "MP-S4\n(coord)",
}

MODE_COLORS = {
    "MPTD-PQS":   "#1f77b4",   # blue — full system
    "A1_LW_only": "#ff7f0e",   # orange
    "A2_GAT_only":"#2ca02c",   # green
    "A3_AE_only": "#d62728",   # red
    "A4_no_TRS":  "#9467bd",   # purple
    "A5_no_chain":"#8c564b",   # brown
    "B1_rule":    "#e377c2",   # pink
    "B2_LSTM_AE": "#7f7f7f",   # grey
    "B3_AE_diff": "#bcbd22",   # yellow-green
}

MODE_LABELS = {
    "MPTD-PQS":   "MPTD-PQS (full)",
    "A1_LW_only": "A1 — LW only",
    "A2_GAT_only":"A2 — GAT only",
    "A3_AE_only": "A3 — AE only",
    "A4_no_TRS":  "A4 — no TRS/FHE",
    "A5_no_chain":"A5 — no blockchain",
}

SPEED_ORDER  = ["low", "medium", "high"]
SPEED_LABELS = {"low": "Low\n(≤30 km/h)",
                "medium": "Medium\n(30-80 km/h)",
                "high": "High\n(>80 km/h)"}

FIG_DPI    = 150
FIG_W      = 9
FIG_H      = 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def save_fig(fig, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fig.savefig(path, dpi=FIG_DPI, bbox_inches="tight")
    plt.close(fig)
    print(f"[plot] → {path}")


def mean_by(df, groupby, metric):
    return df.groupby(groupby)[metric].mean().reset_index()


def filter_modes(df, modes):
    return df[df["mode"].isin(modes)]


# ---------------------------------------------------------------------------
# Fig 1 — MCC by attack type (main modes)
# Paper RQ2, RQ4
# ---------------------------------------------------------------------------

def fig_mcc_by_attack(df, out_dir):
    modes     = ["MPTD-PQS", "A1_LW_only", "A2_GAT_only", "A3_AE_only"]
    sub       = filter_modes(df, modes)
    pivot     = sub.groupby(["attack_number", "mode"])["MCC"].mean().unstack()

    # Ensure all modes present
    for m in modes:
        if m not in pivot.columns:
            pivot[m] = 0.0
    pivot = pivot[modes]

    x     = np.arange(len(pivot))
    width = 0.18

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    for i, mode in enumerate(modes):
        offset = (i - len(modes) / 2 + 0.5) * width
        bars   = ax.bar(x + offset, pivot[mode].values,
                        width=width, label=MODE_LABELS.get(mode, mode),
                        color=MODE_COLORS.get(mode, "#333333"),
                        alpha=0.85, edgecolor="white")

    ax.set_xlabel("Attack Scenario", fontsize=12)
    ax.set_ylabel("MCC", fontsize=12)
    ax.set_title("Detection Quality (MCC) by Attack Type\nMPTD-PQS vs Ablations (avg over penetration rates & speed regimes)",
                 fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels([ATTACK_LABELS.get(i+1, str(i+1)) for i in range(len(pivot))],
                        fontsize=9)
    ax.set_ylim(-0.1, 1.05)
    ax.axhline(0, color="black", linewidth=0.8, linestyle="--")
    ax.legend(fontsize=9, loc="upper right")
    ax.grid(axis="y", alpha=0.3)

    save_fig(fig, os.path.join(out_dir, "fig1_mcc_by_attack.pdf"))

    # Also save PNG
    fig2, ax2 = plt.subplots(figsize=(FIG_W, FIG_H))
    for i, mode in enumerate(modes):
        offset = (i - len(modes) / 2 + 0.5) * width
        ax2.bar(x + offset, pivot[mode].values,
                width=width, label=MODE_LABELS.get(mode, mode),
                color=MODE_COLORS.get(mode, "#333333"),
                alpha=0.85, edgecolor="white")
    ax2.set_xlabel("Attack Scenario"); ax2.set_ylabel("MCC")
    ax2.set_title("MCC by Attack Type")
    ax2.set_xticks(x)
    ax2.set_xticklabels([ATTACK_LABELS.get(i+1, str(i+1)) for i in range(len(pivot))], fontsize=9)
    ax2.set_ylim(-0.1, 1.05); ax2.axhline(0, color="black", linewidth=0.8, linestyle="--")
    ax2.legend(fontsize=9); ax2.grid(axis="y", alpha=0.3)
    save_fig(fig2, os.path.join(out_dir, "fig1_mcc_by_attack.png"))


# ---------------------------------------------------------------------------
# Fig 2 — FPR by penetration rate
# Paper RQ3, RQ4
# ---------------------------------------------------------------------------

def fig_fpr_by_penetration(df, out_dir):
    modes = ["MPTD-PQS", "A1_LW_only", "A2_GAT_only", "A3_AE_only"]
    sub   = filter_modes(df, modes)
    pivot = sub.groupby(["attack_pct", "mode"])["FPR"].mean().unstack()

    for m in modes:
        if m not in pivot.columns:
            pivot[m] = 0.0
    pivot = pivot[modes]
    pcts  = sorted(pivot.index.tolist())

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    for mode in modes:
        vals = [pivot.loc[p, mode] if p in pivot.index else 0.0 for p in pcts]
        ax.plot(pcts, vals, marker="o", linewidth=2,
                label=MODE_LABELS.get(mode, mode),
                color=MODE_COLORS.get(mode, "#333333"))

    ax.set_xlabel("Penetration Rate ρ_a (%)", fontsize=12)
    ax.set_ylabel("False Positive Rate (FPR)", fontsize=12)
    ax.set_title("FPR vs Penetration Rate\n(avg over attack types & speed regimes)", fontsize=11)
    ax.set_xticks(pcts)
    ax.set_xticklabels([f"{p}%" for p in pcts])
    ax.set_ylim(-0.02, 1.02)
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3)

    save_fig(fig, os.path.join(out_dir, "fig2_fpr_by_penetration.pdf"))

    fig2, ax2 = plt.subplots(figsize=(FIG_W, FIG_H))
    for mode in modes:
        vals = [pivot.loc[p, mode] if p in pivot.index else 0.0 for p in pcts]
        ax2.plot(pcts, vals, marker="o", linewidth=2,
                 label=MODE_LABELS.get(mode, mode),
                 color=MODE_COLORS.get(mode, "#333333"))
    ax2.set_xlabel("Penetration Rate (%)"); ax2.set_ylabel("FPR")
    ax2.set_title("FPR by Penetration Rate")
    ax2.set_xticks(pcts); ax2.set_xticklabels([f"{p}%" for p in pcts])
    ax2.set_ylim(-0.02, 1.02); ax2.legend(fontsize=9); ax2.grid(alpha=0.3)
    save_fig(fig2, os.path.join(out_dir, "fig2_fpr_by_penetration.png"))


# ---------------------------------------------------------------------------
# Fig 3 — MCC by speed regime (RQ1)
# ---------------------------------------------------------------------------

def fig_mcc_by_speed(df, out_dir):
    modes = ["MPTD-PQS", "A1_LW_only"]
    sub   = filter_modes(df, modes)

    # Only rows with speed_label column
    if "speed_label" not in sub.columns:
        print("[plot] speed_label column missing — skipping Fig 3")
        return

    pivot = sub.groupby(["speed_label", "mode"])["MCC"].mean().unstack()
    # Reorder rows by speed regime
    present = [s for s in SPEED_ORDER if s in pivot.index]
    pivot   = pivot.loc[present]

    for m in modes:
        if m not in pivot.columns:
            pivot[m] = 0.0
    pivot = pivot[modes]

    x     = np.arange(len(pivot))
    width = 0.3

    fig, ax = plt.subplots(figsize=(7, 5))
    for i, mode in enumerate(modes):
        offset = (i - 0.5) * width
        ax.bar(x + offset, pivot[mode].values, width=width,
               label=MODE_LABELS.get(mode, mode),
               color=MODE_COLORS.get(mode, "#333333"),
               alpha=0.85, edgecolor="white")

    ax.set_xlabel("Vehicle Speed Regime", fontsize=12)
    ax.set_ylabel("MCC", fontsize=12)
    ax.set_title("MCC vs Speed Regime — Mobility Amplification Effect (RQ1)", fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels([SPEED_LABELS.get(s, s) for s in present])
    ax.set_ylim(-0.1, 1.05)
    ax.axhline(0, color="black", linewidth=0.8, linestyle="--")
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    save_fig(fig, os.path.join(out_dir, "fig3_mcc_by_speed.pdf"))

    fig2, ax2 = plt.subplots(figsize=(7, 5))
    for i, mode in enumerate(modes):
        offset = (i - 0.5) * width
        ax2.bar(x + offset, pivot[mode].values, width=width,
                label=MODE_LABELS.get(mode, mode),
                color=MODE_COLORS.get(mode, "#333333"),
                alpha=0.85, edgecolor="white")
    ax2.set_xlabel("Speed Regime"); ax2.set_ylabel("MCC")
    ax2.set_title("MCC by Speed Regime")
    ax2.set_xticks(x); ax2.set_xticklabels([SPEED_LABELS.get(s, s) for s in present])
    ax2.set_ylim(-0.1, 1.05); ax2.legend(fontsize=10); ax2.grid(axis="y", alpha=0.3)
    save_fig(fig2, os.path.join(out_dir, "fig3_mcc_by_speed.png"))


# ---------------------------------------------------------------------------
# Fig 4 — Ablation bar chart (RQ2-RQ4)
# ---------------------------------------------------------------------------

def fig_ablation_mcc(df, out_dir):
    ablation_modes = ["MPTD-PQS", "A1_LW_only", "A2_GAT_only",
                      "A3_AE_only", "A4_no_TRS", "A5_no_chain"]
    sub    = filter_modes(df, ablation_modes)
    means  = sub.groupby("mode")["MCC"].mean()
    stds   = sub.groupby("mode")["MCC"].std().fillna(0)

    # Reorder
    present = [m for m in ablation_modes if m in means.index]
    vals    = [means[m] for m in present]
    errs    = [stds[m]  for m in present]
    colors  = [MODE_COLORS.get(m, "#333333") for m in present]
    labels  = [MODE_LABELS.get(m, m) for m in present]

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(present))
    ax.bar(x, vals, yerr=errs, capsize=4, color=colors,
           alpha=0.85, edgecolor="white")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9, rotation=15, ha="right")
    ax.set_ylabel("Mean MCC (± std)", fontsize=12)
    ax.set_title("Ablation Study — Component Contribution to MCC\n(avg over all attacks, penetration rates, speed regimes)",
                 fontsize=11)
    ax.set_ylim(-0.1, 1.1)
    ax.axhline(0, color="black", linewidth=0.8, linestyle="--")
    ax.grid(axis="y", alpha=0.3)

    save_fig(fig, os.path.join(out_dir, "fig4_ablation_mcc.pdf"))

    fig2, ax2 = plt.subplots(figsize=(8, 5))
    ax2.bar(x, vals, yerr=errs, capsize=4, color=colors, alpha=0.85, edgecolor="white")
    ax2.set_xticks(x); ax2.set_xticklabels(labels, fontsize=9, rotation=15, ha="right")
    ax2.set_ylabel("Mean MCC"); ax2.set_title("Ablation Study MCC")
    ax2.set_ylim(-0.1, 1.1); ax2.axhline(0, color="black", linewidth=0.8, linestyle="--")
    ax2.grid(axis="y", alpha=0.3)
    save_fig(fig2, os.path.join(out_dir, "fig4_ablation_mcc.png"))


# ---------------------------------------------------------------------------
# Fig 5 — PARR: A4 vs MPTD-PQS by penetration rate (RQ5)
# ---------------------------------------------------------------------------

def fig_parr_trs(df, out_dir):
    modes = ["MPTD-PQS", "A4_no_TRS"]
    sub   = filter_modes(df, modes)
    pivot = sub.groupby(["attack_pct", "mode"])["PARR"].mean().unstack()

    for m in modes:
        if m not in pivot.columns:
            pivot[m] = 0.0
    pivot = pivot[modes]
    pcts  = sorted(pivot.index.tolist())

    fig, ax = plt.subplots(figsize=(7, 5))
    for mode in modes:
        vals = [pivot.loc[p, mode] if p in pivot.index else 0.0 for p in pcts]
        ax.plot(pcts, vals, marker="s", linewidth=2,
                label=MODE_LABELS.get(mode, mode),
                color=MODE_COLORS.get(mode, "#333333"))

    ax.set_xlabel("Penetration Rate ρ_a (%)", fontsize=12)
    ax.set_ylabel("PARR — Poisoned Aggregate Rejection Rate", fontsize=12)
    ax.set_title("TRS Mitigation: PARR vs Penetration Rate (RQ5)", fontsize=11)
    ax.set_xticks(pcts)
    ax.set_xticklabels([f"{p}%" for p in pcts])
    ax.set_ylim(-0.05, 1.10)
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)
    ax.fill_between(pcts,
                    [pivot.loc[p, "MPTD-PQS"] if p in pivot.index else 0 for p in pcts],
                    [pivot.loc[p, "A4_no_TRS"] if p in pivot.index else 0 for p in pcts],
                    alpha=0.15, color="#1f77b4", label="TRS gain")

    save_fig(fig, os.path.join(out_dir, "fig5_parr_trs.pdf"))

    fig2, ax2 = plt.subplots(figsize=(7, 5))
    for mode in modes:
        vals = [pivot.loc[p, mode] if p in pivot.index else 0.0 for p in pcts]
        ax2.plot(pcts, vals, marker="s", linewidth=2,
                 label=MODE_LABELS.get(mode, mode),
                 color=MODE_COLORS.get(mode, "#333333"))
    ax2.set_xlabel("Penetration (%)"); ax2.set_ylabel("PARR")
    ax2.set_title("PARR vs Penetration Rate")
    ax2.set_xticks(pcts); ax2.set_xticklabels([f"{p}%" for p in pcts])
    ax2.set_ylim(-0.05, 1.10); ax2.legend(fontsize=10); ax2.grid(alpha=0.3)
    save_fig(fig2, os.path.join(out_dir, "fig5_parr_trs.png"))


# ---------------------------------------------------------------------------
# Fig 6 — CDER: blockchain contribution A5 vs MPTD-PQS (RQ6)
# ---------------------------------------------------------------------------

def fig_cder_blockchain(df, out_dir):
    modes = ["MPTD-PQS", "A5_no_chain"]
    sub   = filter_modes(df, modes)
    pivot = sub.groupby(["attack_number", "mode"])["CDER"].mean().unstack()

    for m in modes:
        if m not in pivot.columns:
            pivot[m] = 0.0
    pivot = pivot[modes]

    x     = np.arange(len(pivot))
    width = 0.3

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    for i, mode in enumerate(modes):
        offset = (i - 0.5) * width
        ax.bar(x + offset, pivot[mode].values, width=width,
               label=MODE_LABELS.get(mode, mode),
               color=MODE_COLORS.get(mode, "#333333"),
               alpha=0.85, edgecolor="white")

    ax.set_xlabel("Attack Scenario", fontsize=12)
    ax.set_ylabel("CDER — Control Decision Error Rate", fontsize=12)
    ax.set_title("Blockchain Contribution: CDER by Attack (RQ6)\nLower is better",
                 fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels([ATTACK_LABELS.get(i+1, str(i+1)) for i in range(len(pivot))],
                        fontsize=9)
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    save_fig(fig, os.path.join(out_dir, "fig6_cder_blockchain.pdf"))

    fig2, ax2 = plt.subplots(figsize=(FIG_W, FIG_H))
    for i, mode in enumerate(modes):
        offset = (i - 0.5) * width
        ax2.bar(x + offset, pivot[mode].values, width=width,
                label=MODE_LABELS.get(mode, mode),
                color=MODE_COLORS.get(mode, "#333333"),
                alpha=0.85, edgecolor="white")
    ax2.set_xlabel("Attack Scenario"); ax2.set_ylabel("CDER")
    ax2.set_title("CDER by Attack Scenario")
    ax2.set_xticks(x); ax2.set_xticklabels([ATTACK_LABELS.get(i+1, str(i+1)) for i in range(len(pivot))], fontsize=9)
    ax2.legend(fontsize=10); ax2.grid(axis="y", alpha=0.3)
    save_fig(fig2, os.path.join(out_dir, "fig6_cder_blockchain.png"))


# ---------------------------------------------------------------------------
# Fig 7 — PBPO overhead (RQ3, RQ5)
# ---------------------------------------------------------------------------

def fig_pbpo(df, out_dir):
    modes = ["MPTD-PQS", "A1_LW_only", "A4_no_TRS"]
    sub   = filter_modes(df, modes)
    means = sub.groupby("mode")["PBPO_ms"].mean()
    stds  = sub.groupby("mode")["PBPO_ms"].std().fillna(0)

    present = [m for m in modes if m in means.index]
    vals    = [means[m] for m in present]
    errs    = [stds[m]  for m in present]
    labels  = [MODE_LABELS.get(m, m) for m in present]
    colors  = [MODE_COLORS.get(m, "#333333") for m in present]

    fig, ax = plt.subplots(figsize=(7, 5))
    x = np.arange(len(present))
    ax.bar(x, vals, yerr=errs, capsize=5, color=colors,
           alpha=0.85, edgecolor="white")
    ax.axhline(100, color="red", linestyle="--", linewidth=1.5,
               label="LW deadline T_b = 100 ms")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_ylabel("Mean PBPO (ms)", fontsize=12)
    ax.set_title("Per-Beacon Processing Overhead (RQ3, RQ5)", fontsize=11)
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)

    save_fig(fig, os.path.join(out_dir, "fig7_pbpo_overhead.pdf"))

    fig2, ax2 = plt.subplots(figsize=(7, 5))
    ax2.bar(x, vals, yerr=errs, capsize=5, color=colors, alpha=0.85, edgecolor="white")
    ax2.axhline(100, color="red", linestyle="--", linewidth=1.5, label="100ms deadline")
    ax2.set_xticks(x); ax2.set_xticklabels(labels, fontsize=10)
    ax2.set_ylabel("Mean PBPO (ms)"); ax2.set_title("PBPO Overhead")
    ax2.legend(fontsize=10); ax2.grid(axis="y", alpha=0.3)
    save_fig(fig2, os.path.join(out_dir, "fig7_pbpo_overhead.png"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="MPTD-PQS Stage 8 Plotter")
    parser.add_argument("--summary_csv", required=True,
                        help="Path to sweep_summary.csv")
    parser.add_argument("--out_dir", required=True,
                        help="Output directory for figures")
    args = parser.parse_args()

    if not HAS_MPL:
        print("[plot] matplotlib not available — cannot generate figures")
        sys.exit(1)

    if not os.path.exists(args.summary_csv):
        print(f"[plot] {args.summary_csv} not found")
        sys.exit(1)

    df = pd.read_csv(args.summary_csv)
    print(f"[plot] Loaded {len(df)} rows from {args.summary_csv}")
    print(f"       Modes: {df['mode'].unique().tolist()}")
    print(f"       Attacks: {sorted(df['attack_number'].unique().tolist())}")
    print(f"       Pcts: {sorted(df['attack_pct'].unique().tolist())}")

    os.makedirs(args.out_dir, exist_ok=True)

    print("[plot] Generating Fig 1 — MCC by attack type …")
    fig_mcc_by_attack(df, args.out_dir)

    print("[plot] Generating Fig 2 — FPR by penetration rate …")
    fig_fpr_by_penetration(df, args.out_dir)

    print("[plot] Generating Fig 3 — MCC by speed regime …")
    fig_mcc_by_speed(df, args.out_dir)

    print("[plot] Generating Fig 4 — Ablation MCC …")
    fig_ablation_mcc(df, args.out_dir)

    print("[plot] Generating Fig 5 — PARR TRS contribution …")
    fig_parr_trs(df, args.out_dir)

    print("[plot] Generating Fig 6 — CDER blockchain contribution …")
    fig_cder_blockchain(df, args.out_dir)

    print("[plot] Generating Fig 7 — PBPO overhead …")
    fig_pbpo(df, args.out_dir)

    print(f"[plot] All figures saved to {args.out_dir}")


if __name__ == "__main__":
    main()
