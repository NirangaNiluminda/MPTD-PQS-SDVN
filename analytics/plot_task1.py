"""
plot_task1.py — Task 01 Presentation Plots
===========================================
Generates publication-quality figures from sweep/ CSV results.

Outputs (analytics/results/figures/):
  fig1_mcc_by_attack.png   — MCC bar chart across attack scenarios
  fig2_all_metrics.png     — Heat-map / grouped bar of all 7 PEMs
  fig3_pct_sweep.png       — MCC/PARR/CDER vs attack percentage (attack 1)
  fig4_beacon_timeline.png — Beacon arrivals with is_poisoned / detected overlay

Run:
    python3 analytics/plot_task1.py
"""

import os, glob
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")          # headless — no display needed
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

NS3_ROOT   = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
SWEEP_DIR  = os.path.join(NS3_ROOT, "analytics", "results", "sweep")
BEACON_CSV = os.path.join(NS3_ROOT, "analytics", "results", "beacon_log.csv")
FIG_DIR    = os.path.join(NS3_ROOT, "analytics", "results", "figures")
os.makedirs(FIG_DIR, exist_ok=True)

# ── colour palette ────────────────────────────────────────────────────────────
COLORS = {
    "MCC":  "#2196F3",   # blue
    "FPR":  "#F44336",   # red
    "PARR": "#4CAF50",   # green
    "CDER": "#FF9800",   # orange
    "TDEE": "#9C27B0",   # purple
    "TPE":  "#00BCD4",   # cyan
    "PBPO": "#795548",   # brown
}

ATTACK_LABELS = {
    0: "No Attack\n(baseline)",
    1: "TP-S1\nLocation\nSpoofing",
    2: "TP-S2\nFlooding",
    3: "TP-S3\nFabrication",
    5: "MP-S2\nVanishing",
    6: "MP-S4\nCombined",
    7: "Coordinated\nMulti-Source",
}

# ── helpers ───────────────────────────────────────────────────────────────────

def load_sweep():
    rows = []
    for f in sorted(glob.glob(os.path.join(SWEEP_DIR, "metrics_a*.csv"))):
        df = pd.read_csv(f)
        rows.append(df.iloc[0])
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows).reset_index(drop=True)
    df["attack_number"]  = df["attack_number"].astype(int)
    df["attack_pct"]     = df["attack_pct"].astype(float)
    return df

def save(fig, name):
    path = os.path.join(FIG_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  Saved → {path}")


# ══════════════════════════════════════════════════════════════════════════════
# Figure 1 — MCC bar chart, one bar per attack type at 30 % (or best available)
# ══════════════════════════════════════════════════════════════════════════════

def fig1_mcc_by_attack(df):
    # Pick one representative row per attack type
    target_pct = 30
    rows = []
    for an, grp in df.groupby("attack_number"):
        # prefer 30 %, else take the row with highest MCC
        at30 = grp[grp["attack_pct"] == target_pct]
        row  = at30.iloc[0] if len(at30) else grp.loc[grp["MCC"].idxmax()]
        rows.append(row)
    sub = pd.DataFrame(rows).sort_values("attack_number")

    labels = [ATTACK_LABELS.get(int(r["attack_number"]),
              f"Attack {int(r['attack_number'])}") for _, r in sub.iterrows()]
    mccs   = sub["MCC"].values

    fig, ax = plt.subplots(figsize=(10, 5))
    bar_colors = [COLORS["MCC"] if m > 0.5 else "#90CAF9" for m in mccs]
    bars = ax.bar(range(len(labels)), mccs, color=bar_colors, edgecolor="white",
                  linewidth=1.2, zorder=3)

    # value labels on bars
    for bar, val in zip(bars, mccs):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                f"{val:.3f}", ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax.axhline(0.5, color="grey", linestyle="--", linewidth=1, label="Threshold = 0.5", zorder=2)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(-0.05, 1.15)
    ax.set_ylabel("MCC  (Matthews Correlation Coefficient)", fontsize=11)
    ax.set_title("Fig 1 — MCC Across Attack Scenarios  (attack_pct = 30 %)", fontsize=12, fontweight="bold")
    ax.legend(fontsize=9)
    ax.grid(axis="y", alpha=0.3, zorder=0)
    ax.spines[["top", "right"]].set_visible(False)

    save(fig, "fig1_mcc_by_attack.png")


# ══════════════════════════════════════════════════════════════════════════════
# Figure 2 — All 7 PEMs side-by-side for the 30 % attack scenarios
# ══════════════════════════════════════════════════════════════════════════════

def fig2_all_metrics(df):
    at30 = df[df["attack_pct"] == 30].copy()
    if at30.empty:
        at30 = df.copy()
    at30 = at30.sort_values("attack_number")

    metrics  = ["MCC", "FPR", "PARR", "CDER"]   # 0–1 range → subplot A
    metrics2 = ["TDEE", "TPE", "PBPO"]            # metres/ms → subplot B

    labels = [ATTACK_LABELS.get(int(r["attack_number"]),
              f"A{int(r['attack_number'])}") for _, r in at30.iterrows()]
    x = np.arange(len(labels))
    n = len(metrics)
    w = 0.18

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))
    fig.suptitle("Fig 2 — All 7 PEMs Across Attack Scenarios  (attack_pct = 30 %)",
                 fontsize=12, fontweight="bold", y=1.01)

    # ── Subplot A: MCC / FPR / PARR / CDER ───────────────────────────────────
    for i, m in enumerate(metrics):
        vals = at30[m].values
        ax1.bar(x + (i - n/2 + 0.5)*w, vals, width=w,
                color=COLORS[m], label=m, edgecolor="white", zorder=3)

    ax1.set_xticks(x); ax1.set_xticklabels(labels, fontsize=8)
    ax1.set_ylim(0, 1.1)
    ax1.set_ylabel("Score  (0–1)", fontsize=10)
    ax1.set_title("Detection Quality Metrics", fontsize=10)
    ax1.legend(fontsize=9, loc="upper left")
    ax1.grid(axis="y", alpha=0.3); ax1.spines[["top","right"]].set_visible(False)

    # ── Subplot B: TDEE / TPE / PBPO ─────────────────────────────────────────
    n2 = len(metrics2)
    for i, m in enumerate(metrics2):
        vals = at30[m].values
        unit = "ms" if m == "PBPO" else "m"
        ax2.bar(x + (i - n2/2 + 0.5)*w, vals, width=w,
                color=COLORS[m], label=f"{m} ({unit})", edgecolor="white", zorder=3)

    ax2.set_xticks(x); ax2.set_xticklabels(labels, fontsize=8)
    ax2.set_ylabel("Value  (metres or ms)", fontsize=10)
    ax2.set_title("Trajectory & Overhead Metrics", fontsize=10)
    ax2.legend(fontsize=9)
    ax2.grid(axis="y", alpha=0.3); ax2.spines[["top","right"]].set_visible(False)

    plt.tight_layout()
    save(fig, "fig2_all_metrics.png")


# ══════════════════════════════════════════════════════════════════════════════
# Figure 3 — Sweep: MCC / PARR / CDER vs. attack_percentage  (attack_number=1)
# ══════════════════════════════════════════════════════════════════════════════

def fig3_pct_sweep(df):
    sub = df[df["attack_number"] == 1].sort_values("attack_pct").copy()
    if len(sub) < 2:
        print("  [fig3] Not enough attack-1 rows to plot — skipping.")
        return

    pcts = sub["attack_pct"].values
    fig, ax = plt.subplots(figsize=(8, 5))

    for metric, label, ls in [
            ("MCC",  "MCC  ↑ higher=better",  "-"),
            ("PARR", "PARR ↑ higher=better",  "--"),
            ("CDER", "CDER ↓ lower=better",   ":"),
        ]:
        ax.plot(pcts, sub[metric].values, marker="o", linestyle=ls,
                color=COLORS[metric], linewidth=2, markersize=7, label=label)

    ax.set_xlabel("Attack Percentage  (%)", fontsize=11)
    ax.set_ylabel("Metric Score", fontsize=11)
    ax.set_title("Fig 3 — MCC / PARR / CDER vs. Attack Percentage\n(TP-S1: Location Spoofing)",
                 fontsize=11, fontweight="bold")
    ax.set_ylim(-0.05, 1.05)
    ax.legend(fontsize=10)
    ax.grid(alpha=0.3)
    ax.spines[["top", "right"]].set_visible(False)
    save(fig, "fig3_pct_sweep.png")


# ══════════════════════════════════════════════════════════════════════════════
# Figure 4 — Beacon timeline: sim_time vs vehicle, poisoned / detected overlay
# ══════════════════════════════════════════════════════════════════════════════

def fig4_beacon_timeline():
    if not os.path.exists(BEACON_CSV):
        print("  [fig4] beacon_log.csv not found — skipping.")
        return

    df = pd.read_csv(BEACON_CSV)
    # Use only the last simulation run (highest attack_number or last rows)
    # Pick the run with the most poisoned beacons for a visually rich plot
    if "attack_number" in df.columns:
        best_an = df.groupby("attack_number")["is_poisoned"].sum().idxmax()
        sub = df[df["attack_number"] == best_an].copy()
    else:
        sub = df.copy()

    # Limit to a meaningful time window
    sub = sub[sub["sim_time"] <= sub["sim_time"].max()].copy()
    vids = sorted(sub["vehicle_id"].unique())
    yticks = {v: i for i, v in enumerate(vids)}

    fig, ax = plt.subplots(figsize=(12, max(4, len(vids)*0.45 + 1)))

    for _, row in sub.iterrows():
        y = yticks[row["vehicle_id"]]
        t = row["sim_time"]
        if row["is_poisoned"] and row["detected"]:
            color, marker, zorder = "#F44336", "x", 4    # TP — red X
        elif row["is_poisoned"] and not row["detected"]:
            color, marker, zorder = "#FF9800", "^", 3    # FN — orange triangle
        elif not row["is_poisoned"]:
            color, marker, zorder = "#4CAF50", ".", 2    # TN — green dot
        else:
            color, marker, zorder = "#9C27B0", "s", 5    # FP — purple square
        ax.scatter(t, y, color=color, marker=marker, s=30 if marker=="." else 55,
                   zorder=zorder, alpha=0.85)

    ax.set_yticks(list(yticks.values()))
    ax.set_yticklabels([f"V{v}" for v in vids], fontsize=8)
    ax.set_xlabel("Simulation Time (s)", fontsize=11)
    ax.set_ylabel("Vehicle ID", fontsize=11)
    an_lbl = ATTACK_LABELS.get(int(best_an), f"Attack {best_an}") if "attack_number" in df.columns else ""
    ax.set_title(f"Fig 4 — Beacon Timeline: Poisoned / Detected Overlay\n({an_lbl.replace(chr(10),' ')})",
                 fontsize=11, fontweight="bold")

    legend_items = [
        mpatches.Patch(color="#4CAF50", label="TN — clean, not flagged"),
        mpatches.Patch(color="#F44336", label="TP — poisoned, detected ✓"),
        mpatches.Patch(color="#FF9800", label="FN — poisoned, missed ✗"),
        mpatches.Patch(color="#9C27B0", label="FP — clean, false alarm"),
    ]
    ax.legend(handles=legend_items, fontsize=9, loc="upper right")
    ax.grid(axis="x", alpha=0.2)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    save(fig, "fig4_beacon_timeline.png")


# ══════════════════════════════════════════════════════════════════════════════
# Figure 5 — Confusion matrix heat-map for best attack scenario
# ══════════════════════════════════════════════════════════════════════════════

def fig5_confusion_heatmap(df):
    # Best MCC row
    atk = df[df["attack_number"] > 0]
    if atk.empty:
        return
    best = atk.loc[atk["MCC"].idxmax()]
    cm = np.array([[int(best["cm_TN"]), int(best["cm_FP"])],
                   [int(best["cm_FN"]), int(best["cm_TP"])]])

    fig, ax = plt.subplots(figsize=(5, 4.5))
    im = ax.imshow(cm, cmap="Blues", aspect="equal")

    classes = ["Benign\n(predicted)", "Attack\n(predicted)"]
    true_classes = ["Benign\n(actual)", "Attack\n(actual)"]
    ax.set_xticks([0,1]); ax.set_xticklabels(classes, fontsize=10)
    ax.set_yticks([0,1]); ax.set_yticklabels(true_classes, fontsize=10)

    total = cm.sum()
    for i in range(2):
        for j in range(2):
            val = cm[i, j]
            pct = 100 * val / total if total else 0
            color = "white" if val > cm.max()*0.6 else "black"
            ax.text(j, i, f"{val}\n({pct:.1f}%)", ha="center", va="center",
                    color=color, fontsize=12, fontweight="bold")

    atk_name = ATTACK_LABELS.get(int(best["attack_number"]), "").replace("\n"," ")
    pct_val  = int(best["attack_pct"])
    ax.set_title(f"Fig 5 — Confusion Matrix\n{atk_name}  ({pct_val}% attackers)\n"
                 f"MCC = {best['MCC']:.4f}",
                 fontsize=10, fontweight="bold")
    plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    plt.tight_layout()
    save(fig, "fig5_confusion_heatmap.png")


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    df = load_sweep()
    if df.empty:
        print("No sweep results found — run the simulation first.")
        return

    print(f"Loaded {len(df)} sweep rows. Generating figures…")
    fig1_mcc_by_attack(df)
    fig2_all_metrics(df)
    fig3_pct_sweep(df)
    fig4_beacon_timeline()
    fig5_confusion_heatmap(df)

    print(f"\n✓ All figures saved to: {FIG_DIR}")
    print("  fig1_mcc_by_attack.png  — MCC across attack scenarios")
    print("  fig2_all_metrics.png    — All 7 PEMs grouped bar")
    print("  fig3_pct_sweep.png      — MCC/PARR/CDER vs attack %")
    print("  fig4_beacon_timeline.png— Beacon timeline with TP/TN/FP/FN")
    print("  fig5_confusion_heatmap.png — Confusion matrix for best run")

if __name__ == "__main__":
    main()
