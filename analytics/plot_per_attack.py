"""
plot_per_attack.py  —  MPTD-PQS  |  Metric vs Attack Percentage
================================================================
Multi-line comparison: MPTD-PQS A1 (Proposed) vs A4 no-PQ vs B1 Ghaleb LTT

Each MCC figure:
  X-axis : Attack Percentage (%)
  Y-axis : MCC (or other metric)
  Lines  : Red   solid  — MPTD-PQS A1 (Proposed)    ablation_mode=1
           Blue  dashed — A4: No PQ-Crypto            ablation_mode=4
           Green dashed — B1: Ghaleb LTT (2014)       ablation_mode=6

Figure sets produced:
  set 1  fig_a{1-7}_mcc.png/.pdf        — MCC per attack, 3 lines
  set 2  fig_a{1-7}_all_metrics.png     — all 5 metrics, A1 only
  set 3  fig_combined_mcc.png/.pdf      — all attacks, 3 lines each subplot
  set 4  fig_combined_all.png/.pdf      — attacks x metrics grid (A1 only)
  set 5  fig_mcc_comparison.png/.pdf    — ablation comparison grid (A1/A4/B1)

Outputs  →  analytics/results/figures/per_attack/

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

# ─── Method line styles (keyed by ablation_mode integer) ─────────────────────
METHOD_STYLES = {
    1: dict(color="#D32F2F", marker="o", markersize=8,  linewidth=2.5,
            linestyle="-",  label="MPTD-PQS A1 (Proposed)", zorder=5),
    4: dict(color="#1565C0", marker="s", markersize=7,  linewidth=2.0,
            linestyle="--", label="A4: No PQ-Crypto",        zorder=4),
    6: dict(color="#2E7D32", marker="^", markersize=8,  linewidth=2.0,
            linestyle="--", label="B1: Ghaleb LTT (2014)",   zorder=3),
}

# ─── Load & prepare data ──────────────────────────────────────────────────────
def load_data():
    """
    Read all metrics_a*.csv files from SWEEP_DIR.
    Computes DR, Precision, F1, MCC from confusion-matrix columns.
    Ensures ablation_mode column is present (defaults to 1 for legacy files).
    Returns one combined DataFrame.
    """
    files = sorted(glob.glob(os.path.join(SWEEP_DIR, "metrics_a*.csv")))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {SWEEP_DIR}")

    frames = []
    for f in files:
        try:
            frames.append(pd.read_csv(f))
        except Exception as e:
            print(f"  WARN: could not read {f}: {e}")

    data = pd.concat(frames, ignore_index=True)
    data = data[data["total_received"] > 0].copy()

    # Ensure ablation_mode column (old CSVs without it default to m=1)
    if "ablation_mode" not in data.columns:
        data["ablation_mode"] = 1
    data["ablation_mode"] = data["ablation_mode"].astype(int)

    # ε = 10⁻⁶ : numerical stability so MCC denominator never reaches zero
    # (occurs when TN=0 and FP=0 at 100% attack percentage)
    eps = 1e-6
    tp = data["cm_TP"].astype(float) + eps
    fp = data["cm_FP"].astype(float) + eps
    tn = data["cm_TN"].astype(float) + eps
    fn = data["cm_FN"].astype(float) + eps

    data["DR"]        = tp / (tp + fn)
    data["Precision"] = tp / (tp + fp)
    data["F1"]        = 2*tp / (2*tp + fp + fn)

    # Recompute MCC from smoothed counts — always defined
    denom = np.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    data["MCC"] = (tp*tn - fp*fn) / denom

    # When no attack exists (total_poisoned=0), all metrics are undefined → 0
    no_attack = data["total_poisoned"] == 0
    for col in ["MCC", "DR", "Precision", "F1"]:
        data.loc[no_attack, col] = 0.0

    return data

# ─── Helper: apply common axes style ─────────────────────────────────────────
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

# ─── Figure set 1: One MCC figure per attack, 3 lines ────────────────────────
def plot_mcc_per_attack(data):
    """
    7 separate figures (one per attack scenario).
    Each shows MCC vs Attack % for A1, A4, B1 on the same axes.
    Supervisor style: matches Figure 11 layout.
    """
    for atk_num, (short, pid, title) in ATTACK_META.items():
        fig, ax = plt.subplots(figsize=(6, 4.5))
        plotted = 0

        for mode, style in METHOD_STYLES.items():
            sub = (data[(data["attack_number"] == atk_num) &
                        (data["ablation_mode"] == mode)]
                   .sort_values("attack_pct")
                   .dropna(subset=["MCC"]))
            if sub.empty:
                continue
            ax.plot(sub["attack_pct"], sub["MCC"], **style)
            plotted += 1

        if plotted == 0:
            print(f"  SKIP A{atk_num}: no valid MCC data")
            plt.close(fig)
            continue

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

# ─── Figure set 2: All 5 metrics per attack — proposed method only ────────────
METRIC_SPECS = [
    ("MCC",       "MCC",                 (0, 1.05), "#D32F2F"),
    ("DR",        "Detection Rate",      (0, 1.05), "#1565C0"),
    ("FPR",       "False Positive Rate", (0, 1.05), "#E91E8C"),
    ("Precision", "Precision",           (0, 1.05), "#2E7D32"),
    ("F1",        "F1-Score",            (0, 1.05), "#FF6F00"),
]

def plot_all_metrics_per_attack(data):
    """
    For each attack: one figure with 5 metric lines (A1 proposed only).
    Gives a complete per-attack picture for the proposed method chapter.
    """
    proposed = data[data["ablation_mode"] == 1]

    for atk_num, (short, pid, title) in ATTACK_META.items():
        sub = (proposed[proposed["attack_number"] == atk_num]
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
        ax.set_title(f"MPTD-PQS A1 — {pid}: {title.replace(chr(10), ' ')}",
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

# ─── Figure set 3: Combined MCC grid — all attacks, 3 lines per subplot ───────
def plot_combined_mcc_grid(data):
    """
    Single page: 2×4 grid of MCC subplots.
    Each subplot shows A1 (red), A4 (blue dashed), B1 (green dashed).
    """
    attacks = sorted([a for a in ATTACK_META
                      if not data[(data["attack_number"]==a) &
                                  data["MCC"].notna()].empty])
    ncol = 4
    nrow = int(np.ceil(len(attacks) / ncol))

    fig = plt.figure(figsize=(ncol * 4.5, nrow * 3.8))
    gs  = GridSpec(nrow, ncol, figure=fig, hspace=0.55, wspace=0.38)

    for idx, atk_num in enumerate(sorted(attacks)):
        r, c = divmod(idx, ncol)
        ax   = fig.add_subplot(gs[r, c])

        short, pid, title = ATTACK_META[atk_num]
        plotted_any = False

        for mode, style in METHOD_STYLES.items():
            sub = (data[(data["attack_number"] == atk_num) &
                        (data["ablation_mode"] == mode)]
                   .sort_values("attack_pct")
                   .dropna(subset=["MCC"]))
            if sub.empty:
                continue
            small_style = dict(style, markersize=5, linewidth=1.8)
            ax.plot(sub["attack_pct"], sub["MCC"], **small_style)
            plotted_any = True

        ax.set_title(f"{pid}: {title.split(chr(10))[0]}", fontsize=9.5, fontweight="bold")
        ax.set_xlabel("Attack %", fontsize=9)
        ax.set_ylabel("MCC",      fontsize=9)
        ax.set_xlim(0, 105)
        ax.set_ylim(0, 1.05)
        ax.xaxis.set_major_locator(ticker.MultipleLocator(20))
        ax.yaxis.set_major_locator(ticker.MultipleLocator(0.2))
        ax.tick_params(labelsize=8)
        ax.grid(True, linestyle="--", alpha=0.45)
        if plotted_any:
            ax.legend(fontsize=7, loc="upper right", framealpha=0.85)

    fig.suptitle("MPTD-PQS vs Ablations: MCC per Attack Scenario",
                 fontsize=14, fontweight="bold", y=1.02)
    fig.tight_layout()

    out = os.path.join(OUT_DIR, "fig_combined_mcc")
    fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(out + ".pdf",          bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] {out}.png")

# ─── Figure set 4: Combined attacks×metrics grid — A1 proposed only ───────────
def plot_combined_all_metrics_grid(data):
    """
    Full overview: rows = attack scenarios, columns = 5 metrics.
    Uses A1 (proposed) data only — detailed method performance overview.
    """
    proposed = data[data["ablation_mode"] == 1]
    attacks  = sorted([a for a in ATTACK_META if a != 0
                       and not proposed[proposed["attack_number"]==a].empty])
    metrics  = [(col, lbl, clr) for col, lbl, _, clr in METRIC_SPECS]

    nrow, ncol = len(attacks), len(metrics)
    fig = plt.figure(figsize=(ncol * 3.8, nrow * 3.0))
    gs  = GridSpec(nrow, ncol, figure=fig, hspace=0.65, wspace=0.40)

    for ri, atk_num in enumerate(attacks):
        short, pid, _ = ATTACK_META[atk_num]
        sub = proposed[proposed["attack_number"] == atk_num].sort_values("attack_pct")

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

    fig.suptitle("MPTD-PQS A1 (Proposed): All Metrics per Attack Scenario",
                 fontsize=12, fontweight="bold", y=1.01)
    fig.tight_layout()

    out = os.path.join(OUT_DIR, "fig_combined_all")
    fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(out + ".pdf",          bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] {out}.png")

# ─── Figure set 6: PARR per attack — blockchain revocation effectiveness ──────
def plot_parr_per_attack(data):
    """
    PARR = fraction of poisoned vehicles revoked by the blockchain layer
    (3+ consecutive detections trigger ring-signature revocation).

    One figure per attack, 3 lines (A1, A4, B1).
    Lower detection quality (B1) → fewer revocations → lower PARR.
    A4 ≈ A1 because revocation is driven by detection count, not TRS crypto itself.
    """
    for atk_num, (short, pid, title) in ATTACK_META.items():
        fig, ax = plt.subplots(figsize=(6, 4.5))
        plotted = 0

        for mode, style in METHOD_STYLES.items():
            sub = (data[(data["attack_number"] == atk_num) &
                        (data["ablation_mode"] == mode)]
                   .sort_values("attack_pct")
                   .dropna(subset=["PARR"]))
            if sub.empty:
                continue
            # Only show points where attack actually exists (pct > 0)
            sub_atk = sub[sub["attack_pct"] > 0]
            if sub_atk.empty:
                continue
            ax.plot(sub_atk["attack_pct"], sub_atk["PARR"], **style)
            plotted += 1

        if plotted == 0:
            plt.close(fig)
            continue

        _style_ax(ax,
                  xlabel="Attack Percentage (%)",
                  ylabel="Poisoned Aggregate Rejection Rate",
                  title=f"PARR — {pid}: {title.replace(chr(10), ' ')}")

        ax.legend(fontsize=10, loc="best", framealpha=0.9)
        fig.tight_layout()

        out = os.path.join(OUT_DIR, f"fig_a{atk_num}_parr")
        fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
        fig.savefig(out + ".pdf",          bbox_inches="tight")
        plt.close(fig)
        print(f"  [OK] {out}.png")


def plot_parr_combined_grid(data):
    """
    2×4 grid — PARR per attack, all three methods.
    Key figure for RQ5: blockchain contribution.
    """
    attacks = sorted(ATTACK_META.keys())
    ncol = 4
    nrow = int(np.ceil(len(attacks) / ncol))

    fig = plt.figure(figsize=(ncol * 4.5, nrow * 3.8 + 0.6))
    gs  = GridSpec(nrow, ncol, figure=fig, hspace=0.60, wspace=0.38)

    legend_handles = []
    legend_labels  = []

    for idx, atk_num in enumerate(attacks):
        r, c = divmod(idx, ncol)
        ax   = fig.add_subplot(gs[r, c])
        short, pid, title = ATTACK_META[atk_num]

        for mode, style in METHOD_STYLES.items():
            sub = (data[(data["attack_number"] == atk_num) &
                        (data["ablation_mode"] == mode) &
                        (data["attack_pct"] > 0)]
                   .sort_values("attack_pct")
                   .dropna(subset=["PARR"]))
            if sub.empty:
                continue
            s2 = dict(style, markersize=5, linewidth=1.8)
            h, = ax.plot(sub["attack_pct"], sub["PARR"], **s2)
            if idx == 0:
                legend_handles.append(h)
                legend_labels.append(style["label"])

        ax.set_title(f"{pid}: {title.split(chr(10))[0]}", fontsize=9.5, fontweight="bold")
        ax.set_xlabel("Attack %", fontsize=8.5)
        ax.set_ylabel("PARR",     fontsize=8.5)
        ax.set_xlim(15, 105)
        ax.set_ylim(0, 1.05)
        ax.xaxis.set_major_locator(ticker.MultipleLocator(20))
        ax.yaxis.set_major_locator(ticker.MultipleLocator(0.2))
        ax.tick_params(labelsize=7.5)
        ax.grid(True, linestyle="--", alpha=0.45)

    if legend_handles:
        fig.legend(handles=legend_handles, labels=legend_labels,
                   loc="lower center", ncol=3, fontsize=10,
                   framealpha=0.92, bbox_to_anchor=(0.5, -0.03))

    fig.suptitle("PARR: Blockchain Revocation Effectiveness (A1 vs A4 vs B1)",
                 fontsize=13, fontweight="bold", y=1.02)
    fig.tight_layout(rect=[0, 0.05, 1, 1])

    out = os.path.join(OUT_DIR, "fig_parr_combined")
    fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(out + ".pdf",          bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] {out}.png")


# ─── Figure set 7: CDER per attack — end-to-end control-plane error rate ──────
def plot_cder_per_attack(data):
    """
    CDER = fraction of SDN controller decisions corrupted by residual poisoning.
    Lower = better. CDER=1.0 for attacks 5 & 7 (malicious controller — all decisions wrong).

    One figure per attack, 3 lines (A1, A4, B1).
    A1 should have lower CDER than B1 — fewer attacks slip through to the controller.
    """
    for atk_num, (short, pid, title) in ATTACK_META.items():
        fig, ax = plt.subplots(figsize=(6, 4.5))
        plotted = 0

        for mode, style in METHOD_STYLES.items():
            sub = (data[(data["attack_number"] == atk_num) &
                        (data["ablation_mode"] == mode)]
                   .sort_values("attack_pct")
                   .dropna(subset=["CDER"]))
            if sub.empty:
                continue
            ax.plot(sub["attack_pct"], sub["CDER"], **style)
            plotted += 1

        if plotted == 0:
            plt.close(fig)
            continue

        _style_ax(ax,
                  xlabel="Attack Percentage (%)",
                  ylabel="Control Decision Error Rate  (lower = better)",
                  title=f"CDER — {pid}: {title.replace(chr(10), ' ')}",
                  ylim=(0, 1.05))

        # Annotation for attacks where CDER=1 (malicious controller)
        if atk_num in (5, 7):
            ax.annotate("Malicious controller\n(CDER→1.0 by design)",
                        xy=(50, 0.95), fontsize=8.5, ha="center",
                        color="#555555",
                        bbox=dict(boxstyle="round,pad=0.3", fc="lightyellow",
                                  ec="grey", alpha=0.8))

        ax.legend(fontsize=10, loc="upper left", framealpha=0.9)
        fig.tight_layout()

        out = os.path.join(OUT_DIR, f"fig_a{atk_num}_cder")
        fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
        fig.savefig(out + ".pdf",          bbox_inches="tight")
        plt.close(fig)
        print(f"  [OK] {out}.png")


def plot_cder_combined_grid(data):
    """
    2×4 grid — CDER per attack, all three methods.
    Key figure for RQ2 and RQ6: end-to-end mitigation effectiveness.
    """
    attacks = sorted(ATTACK_META.keys())
    ncol = 4
    nrow = int(np.ceil(len(attacks) / ncol))

    fig = plt.figure(figsize=(ncol * 4.5, nrow * 3.8 + 0.6))
    gs  = GridSpec(nrow, ncol, figure=fig, hspace=0.60, wspace=0.38)

    legend_handles = []
    legend_labels  = []

    for idx, atk_num in enumerate(attacks):
        r, c = divmod(idx, ncol)
        ax   = fig.add_subplot(gs[r, c])
        short, pid, title = ATTACK_META[atk_num]

        for mode, style in METHOD_STYLES.items():
            sub = (data[(data["attack_number"] == atk_num) &
                        (data["ablation_mode"] == mode)]
                   .sort_values("attack_pct")
                   .dropna(subset=["CDER"]))
            if sub.empty:
                continue
            s2 = dict(style, markersize=5, linewidth=1.8)
            h, = ax.plot(sub["attack_pct"], sub["CDER"], **s2)
            if idx == 0:
                legend_handles.append(h)
                legend_labels.append(style["label"])

        ax.set_title(f"{pid}: {title.split(chr(10))[0]}", fontsize=9.5, fontweight="bold")
        ax.set_xlabel("Attack %", fontsize=8.5)
        ax.set_ylabel("CDER",     fontsize=8.5)
        ax.set_xlim(0, 105)
        ax.set_ylim(0, 1.10)
        ax.xaxis.set_major_locator(ticker.MultipleLocator(20))
        ax.yaxis.set_major_locator(ticker.MultipleLocator(0.2))
        ax.tick_params(labelsize=7.5)
        ax.grid(True, linestyle="--", alpha=0.45)

        # Mark malicious-controller attacks
        if atk_num in (5, 7):
            ax.text(0.5, 0.88, "ctrl malicious", transform=ax.transAxes,
                    fontsize=7, ha="center", color="#888888",
                    style="italic")

    if legend_handles:
        fig.legend(handles=legend_handles, labels=legend_labels,
                   loc="lower center", ncol=3, fontsize=10,
                   framealpha=0.92, bbox_to_anchor=(0.5, -0.03))

    fig.suptitle("CDER: Control-Plane Error Rate — End-to-End Mitigation (A1 vs A4 vs B1)",
                 fontsize=13, fontweight="bold", y=1.02)
    fig.tight_layout(rect=[0, 0.05, 1, 1])

    out = os.path.join(OUT_DIR, "fig_cder_combined")
    fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(out + ".pdf",          bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] {out}.png")


# ─── Figure set 5: NEW — Ablation comparison grid (A1 vs A4 vs B1) ───────────
def plot_mcc_comparison_grid(data):
    """
    2×4 grid, one subplot per attack.
    All three methods on same axes with shared legend at bottom.
    Key figure for RQ2 (ablation study) and RQ3 (baseline comparison).
    """
    attacks = sorted(ATTACK_META.keys())
    ncol = 4
    nrow = int(np.ceil(len(attacks) / ncol))

    fig = plt.figure(figsize=(ncol * 4.5, nrow * 3.8 + 0.6))
    gs  = GridSpec(nrow, ncol, figure=fig, hspace=0.60, wspace=0.38)

    legend_handles = []
    legend_labels  = []

    for idx, atk_num in enumerate(attacks):
        r, c = divmod(idx, ncol)
        ax   = fig.add_subplot(gs[r, c])

        short, pid, title = ATTACK_META[atk_num]

        for mode, style in METHOD_STYLES.items():
            sub = (data[(data["attack_number"] == atk_num) &
                        (data["ablation_mode"] == mode)]
                   .sort_values("attack_pct")
                   .dropna(subset=["MCC"]))
            if sub.empty:
                continue
            s2 = dict(style, markersize=5, linewidth=1.8)
            h, = ax.plot(sub["attack_pct"], sub["MCC"], **s2)
            if idx == 0:
                legend_handles.append(h)
                legend_labels.append(style["label"])

        ax.set_title(f"{pid}: {title.split(chr(10))[0]}", fontsize=9.5, fontweight="bold")
        ax.set_xlabel("Attack %", fontsize=8.5)
        ax.set_ylabel("MCC",      fontsize=8.5)
        ax.set_xlim(0, 105)
        ax.set_ylim(0, 1.05)
        ax.xaxis.set_major_locator(ticker.MultipleLocator(20))
        ax.yaxis.set_major_locator(ticker.MultipleLocator(0.2))
        ax.tick_params(labelsize=7.5)
        ax.grid(True, linestyle="--", alpha=0.45)

    if legend_handles:
        fig.legend(handles=legend_handles, labels=legend_labels,
                   loc="lower center", ncol=3, fontsize=10,
                   framealpha=0.92, bbox_to_anchor=(0.5, -0.03))

    fig.suptitle("MCC Comparison: MPTD-PQS A1 vs A4 (No PQ) vs B1 Ghaleb LTT",
                 fontsize=13, fontweight="bold", y=1.02)
    fig.tight_layout(rect=[0, 0.05, 1, 1])

    out = os.path.join(OUT_DIR, "fig_mcc_comparison")
    fig.savefig(out + ".png", dpi=300, bbox_inches="tight")
    fig.savefig(out + ".pdf",          bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] {out}.png")

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("=" * 64)
    print("  MPTD-PQS — Per-Attack Plots  |  A1 vs A4 vs B1 Comparison")
    print("=" * 64)

    print(f"\nLoading CSVs from: {SWEEP_DIR}")
    data = load_data()
    modes   = sorted(data["ablation_mode"].unique())
    attacks = sorted(data["attack_number"].unique())
    print(f"  {len(data)} valid rows")
    print(f"  attack_numbers   : {attacks}")
    print(f"  ablation_modes   : {modes}")
    mode_labels = {1: "A1 (Proposed)", 4: "A4 no-PQ", 6: "B1 Ghaleb LTT"}
    for m in modes:
        n = len(data[data["ablation_mode"] == m])
        print(f"    mode {m}  {mode_labels.get(m,'?'):20s} : {n} rows")
    print()

    print("── Figure set 1: MCC vs Attack %  (one figure per attack, 3 lines) ──")
    plot_mcc_per_attack(data)

    print("\n── Figure set 2: All metrics vs Attack %  (A1 proposed only) ──────")
    plot_all_metrics_per_attack(data)

    print("\n── Figure set 3: Combined MCC grid  (all 7 attacks, 3 lines each) ──")
    plot_combined_mcc_grid(data)

    print("\n── Figure set 4: Full overview grid  (A1 attacks × 5 metrics) ──────")
    plot_combined_all_metrics_grid(data)

    print("\n── Figure set 5: Ablation comparison grid  (A1 vs A4 vs B1) ────────")
    plot_mcc_comparison_grid(data)

    print("\n── Figure set 6: PARR — blockchain revocation effectiveness ─────────")
    plot_parr_per_attack(data)
    plot_parr_combined_grid(data)

    print("\n── Figure set 7: CDER — control-plane error rate ────────────────────")
    plot_cder_per_attack(data)
    plot_cder_combined_grid(data)

    print(f"\nAll outputs → {OUT_DIR}")
    files = sorted(os.listdir(OUT_DIR))
    print(f"\n{'File':<44}  {'Size':>8}")
    print("-" * 55)
    for f in files:
        sz = os.path.getsize(os.path.join(OUT_DIR, f))
        print(f"  {f:<42}  {sz/1024:7.1f} KB")
    print("\nDone!")

if __name__ == "__main__":
    main()
