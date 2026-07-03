"""
plot_metrics_vs_attack_pct.py  —  MPTD-PQS Metric Plots
=========================================================
Generates publication-quality figures from sweep/ CSV results.

Supervisor requirement:
  "A plot per each metric. Since you have still not implemented existing
   techniques for result benchmarking, you will have only 1 graph per
   plot: the proposed method."

Each figure shows MPTD-PQS performance (one line per attack scenario)
across attack percentages.  When baseline methods are added later, extra
lines can be added to each figure with minimal changes.

Metrics produced (PNG + PDF):
  fig_mcc.png/pdf        — Matthews Correlation Coefficient
  fig_fpr.png/pdf        — False Positive Rate
  fig_dr.png/pdf         — Detection Rate
  fig_precision.png/pdf  — Precision
  fig_f1.png/pdf         — F1-Score
  fig_cder.png/pdf       — Compromised Data Exposure Rate
  fig_pbpo.png/pdf       — Protocol Processing Overhead (ms)
  fig_overview.png/pdf   — All 7 metrics in one combined grid figure

Run:
    cd /home/niranga/ns-allinone-3.35/ns-3.35
    python3 analytics/plot_metrics_vs_attack_pct.py
"""

import os
import glob
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")          # headless — works without a display
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.gridspec import GridSpec

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT      = "/home/niranga/ns-allinone-3.35/ns-3.35"
SWEEP_DIR = os.path.join(ROOT, "analytics", "results", "sweep")
OUT_DIR   = os.path.join(ROOT, "analytics", "results", "figures", "metric_plots")
os.makedirs(OUT_DIR, exist_ok=True)

# ── Attack metadata ────────────────────────────────────────────────────────────
# Each entry: display label, line colour, marker symbol
ATTACK_INFO = {
    1: {"label": "A1: TP-S1 (RSU Pos Drift)",      "color": "#E53935", "marker": "o"},
    2: {"label": "A2: TP-S2 (Vehicle Traj)",        "color": "#8E24AA", "marker": "s"},
    3: {"label": "A3: MP-S1 (Ghost IDs)",           "color": "#1E88E5", "marker": "^"},
    4: {"label": "A4: MP-S2 (Identity Theft)",      "color": "#00ACC1", "marker": "D"},
    5: {"label": "A5: MP-S3 (Data Plane MitM)",     "color": "#43A047", "marker": "v"},
    6: {"label": "A6: MP-S3 MitM (Variant)",        "color": "#FB8C00", "marker": "P"},
    7: {"label": "A7: MP-S4 (Ctrl Plane Poison)",   "color": "#6D4C41", "marker": "X"},
}

# ── Load sweep CSV files ───────────────────────────────────────────────────────
def load_sweep_data():
    """Read all metrics_a*.csv from SWEEP_DIR, drop bad rows, add derived cols."""
    files = sorted(glob.glob(os.path.join(SWEEP_DIR, "metrics_a*.csv")))
    if not files:
        raise FileNotFoundError(f"No sweep CSVs found in {SWEEP_DIR}")

    frames = []
    for f in files:
        try:
            df = pd.read_csv(f)
            frames.append(df)
        except Exception as e:
            print(f"  WARNING: could not read {f}: {e}")

    data = pd.concat(frames, ignore_index=True)

    # ── Drop rows that represent failed/empty simulation runs ──────────────────
    data = data[data["total_received"] > 0].copy()

    # ── Derived performance metrics ────────────────────────────────────────────
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


# ── Single-metric figure ───────────────────────────────────────────────────────
def plot_single_metric(data, metric_col, ylabel, title, filename,
                        ylim=None, ax_in=None, legend=True):
    """
    Draw one metric vs attack_pct, one line per attack scenario.
    If ax_in is provided the figure is drawn on that axes (for the grid plot).
    Returns the axes object.
    """
    standalone = (ax_in is None)
    if standalone:
        fig, ax = plt.subplots(figsize=(7, 5))
    else:
        ax = ax_in

    plotted_any = False
    all_pcts    = set()

    for atk_num in sorted(data["attack_number"].unique()):
        if atk_num not in ATTACK_INFO:
            continue
        info = ATTACK_INFO[atk_num]

        sub = (data[data["attack_number"] == atk_num]
               .sort_values("attack_pct")
               .dropna(subset=[metric_col]))

        if len(sub) < 2:
            # Only 1 valid point — draw a single marker without connecting line
            if len(sub) == 1:
                ax.plot(sub["attack_pct"].values, sub[metric_col].values,
                        color=info["color"], marker=info["marker"],
                        markersize=8, linestyle="none",
                        label=info["label"])
                all_pcts.update(sub["attack_pct"].values.tolist())
                plotted_any = True
            continue

        ax.plot(sub["attack_pct"], sub[metric_col],
                label      = info["label"],
                color      = info["color"],
                marker     = info["marker"],
                markersize = 7,
                linewidth  = 2.0,
                linestyle  = "-")
        all_pcts.update(sub["attack_pct"].values.tolist())
        plotted_any = True

    # ── Axes formatting ────────────────────────────────────────────────────────
    ax.set_xlabel("Attack Percentage (%)", fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title, fontsize=12, fontweight="bold", pad=6)

    if ylim:
        ax.set_ylim(ylim)

    if all_pcts:
        ax.set_xticks(sorted(all_pcts))
    ax.tick_params(labelsize=10)
    ax.grid(True, linestyle="--", alpha=0.45)

    if legend and plotted_any:
        ax.legend(fontsize=7.5, loc="best", framealpha=0.9,
                  ncol=1, handlelength=1.8)

    if not plotted_any:
        ax.text(0.5, 0.5, f"No data for {metric_col}",
                transform=ax.transAxes, ha="center", va="center",
                fontsize=11, color="grey")

    if standalone:
        fig.tight_layout()
        png_path = os.path.join(OUT_DIR, filename + ".png")
        pdf_path = os.path.join(OUT_DIR, filename + ".pdf")
        fig.savefig(png_path, dpi=300, bbox_inches="tight")
        fig.savefig(pdf_path,          bbox_inches="tight")
        plt.close(fig)
        print(f"  [OK] {png_path}")

    return ax


# ── Combined overview figure (2 × 4 grid) ─────────────────────────────────────
def plot_overview(data, metric_specs):
    """Draw all metrics in one 2-row × 4-column grid figure."""
    n   = len(metric_specs)
    ncol = 4
    nrow = int(np.ceil(n / ncol))

    fig = plt.figure(figsize=(ncol * 5.5, nrow * 4.5))
    gs  = GridSpec(nrow, ncol, figure=fig, hspace=0.45, wspace=0.38)

    for idx, (metric_col, ylabel, title, filename, ylim) in enumerate(metric_specs):
        r, c = divmod(idx, ncol)
        ax   = fig.add_subplot(gs[r, c])
        plot_single_metric(data, metric_col, ylabel, title, filename,
                           ylim=ylim, ax_in=ax,
                           legend=(idx == 0))   # legend only on first subplot

    # Shared legend below the grid
    handles, labels = [], []
    for atk_num in sorted(ATTACK_INFO.keys()):
        info = ATTACK_INFO[atk_num]
        h, = plt.plot([], [],
                      color  = info["color"],
                      marker = info["marker"],
                      markersize=7, linewidth=2,
                      label  = info["label"])
        handles.append(h)
        labels.append(info["label"])

    fig.legend(handles, labels,
               loc="lower center", ncol=4,
               fontsize=9, framealpha=0.9,
               bbox_to_anchor=(0.5, -0.04))

    fig.suptitle("MPTD-PQS: Performance Metrics vs Attack Percentage",
                 fontsize=14, fontweight="bold", y=1.01)

    png_path = os.path.join(OUT_DIR, "fig_overview.png")
    pdf_path = os.path.join(OUT_DIR, "fig_overview.pdf")
    fig.savefig(png_path, dpi=300, bbox_inches="tight")
    fig.savefig(pdf_path,          bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] {png_path}")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  MPTD-PQS  —  Metric Plot Generator")
    print("=" * 60)

    print(f"\nLoading sweep data from:\n  {SWEEP_DIR}\n")
    data = load_sweep_data()

    print(f"  Rows loaded  : {len(data)}")
    print(f"  Attack types : {sorted(data['attack_number'].unique())}")
    print(f"  Attack pcts  : {sorted(data['attack_pct'].unique())}")
    print()

    # ── Metric specifications ─────────────────────────────────────────────────
    # (column, y-axis label, plot title, output filename, (y_min, y_max))
    # Paper §4.2 (2026-07 rewrite): FPR, DR, Precision, F1 are dropped as *primary*
    # metrics — MCC subsumes them. FPR is still computed in the sim (it remains the
    # threshold-calibration criterion), just not reported here. New primary metrics
    # (TTD via compute_ttd.py; FRR, COO, BWO, TCL) land in later stages — see
    # scratch/mptd_pqs_sdvn/METRICS_UPGRADE_PLAN.md.
    metric_specs = [
        ("MCC",
         "Matthews Correlation Coefficient",
         "MCC vs Attack %",
         "fig_mcc",
         (0.0, 1.05)),

        ("CDER",
         "Correct Decision Rate (Accuracy)",
         "Correct Detection-to-Error Ratio vs Attack %",
         "fig_cder",
         (0.0, 1.05)),

        ("PBPO",
         "Protocol Overhead (ms)",
         "Beacon Processing Overhead vs Attack %",
         "fig_pbpo",
         (0.0, None)),
    ]

    # ── Individual figures ────────────────────────────────────────────────────
    print("Generating individual metric figures ...")
    for metric_col, ylabel, title, filename, ylim in metric_specs:
        print(f"  Plotting {metric_col} ...", end=" ", flush=True)
        if metric_col not in data.columns:
            print("SKIP (column not found)")
            continue
        plot_single_metric(data, metric_col, ylabel, title, filename, ylim)

    # ── Combined overview ─────────────────────────────────────────────────────
    print("\nGenerating combined overview figure ...", end=" ", flush=True)
    plot_overview(data, metric_specs)

    print(f"\nAll figures saved to:\n  {OUT_DIR}")
    print("\nFiles created:")
    for f in sorted(os.listdir(OUT_DIR)):
        path = os.path.join(OUT_DIR, f)
        size = os.path.getsize(path)
        print(f"  {f:35s}  {size/1024:7.1f} KB")

    print("\nDone!")


if __name__ == "__main__":
    main()
