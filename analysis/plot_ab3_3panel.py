#!/usr/bin/env python3
"""AB3 (GAT ablation) — 3-panel (MCC_full, TTD, CDER_full) vs n_coord.
Single seed (seed=1) — no error bars yet; see AB3_HANDOFF.md sec 10 for the
3-seed-mean caveat before this goes in the paper. Real topology (200v/64RSU),
attack_number=3, attack_percentage=20, theta_S=42.62, lambda_gat=0.7."""
import numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

N_COORD = [1, 2, 4, 5, 10, 20]

FULL = {
    "MCC":  [0.667, 0.666, 0.520, 0.473, 0.345, 0.414],
    "TTD":  [12.893, 12.893, 12.90, 12.893, 12.893, 12.893],
    "CDER": [0.039, 0.039, 0.040, 0.041, 0.038, 0.028],
}
GATOFF = {
    "MCC":  [-0.060, -0.060, -0.049, -0.047, -0.042, -0.038],
    "TTD":  [97.967, 97.966, 97.97, 97.966, 118.123, 118.225],
    "CDER": [0.117, 0.117, 0.100, 0.096, 0.085, 0.082],
}

C_FULL, C_AB3 = "#2563eb", "#dc2626"
SERIES = [(FULL, "FULL (GAT on)", C_FULL, "o"),
          (GATOFF, "AB3 (GAT removed)", C_AB3, "s")]
PANELS = [("MCC", r"MCC$_{\mathrm{full}}$", (-0.15, 0.85)),
          ("TTD", "Time-to-detect (s)", None),
          ("CDER", "CDER (fusion)", None)]

fig, axes = plt.subplots(1, 3, figsize=(15, 4.4))
for ax, (metric, ylab, ylim) in zip(axes, PANELS):
    for data, label, c, mk in SERIES:
        ax.plot(N_COORD, data[metric], color=c, marker=mk, ms=7, lw=2, label=label)
    ax.set_xlabel(r"Coordinated Sybil identities per RSU  ($n_{\mathrm{coord}}$)", fontsize=10.5)
    ax.set_ylabel(ylab, fontsize=11)
    ax.set_xscale("log")
    ax.set_xticks(N_COORD); ax.set_xticklabels([str(n) for n in N_COORD])
    if ylim: ax.set_ylim(*ylim)
    ax.grid(True, alpha=0.25, linewidth=0.6)
    ax.set_title(ylab.split("(")[0].strip(), fontsize=11)
axes[0].legend(frameon=False, fontsize=9, loc="upper right")
fig.suptitle("AB3 ablation — GAT removed, Sybil-via-compromised-RSU (evasive)\n"
             r"real topology 200v/64RSU, $\rho_a$=0.20, single seed", fontsize=12.5, y=1.06)
fig.tight_layout()

OUT = "/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN"
for ext in ("pdf", "png"):
    fig.savefig(f"{OUT}/fig_AB3_ablation_curve.{ext}", dpi=200, bbox_inches="tight")
print(f"saved 3-panel: {OUT}/fig_AB3_ablation_curve.[pdf,png]")

print("\nDelta (Full - GAT-off) MCC per n_coord:")
for i, n in enumerate(N_COORD):
    print(f"  n_coord={n:>2}  FULL={FULL['MCC'][i]:+.3f}  GAT-off={GATOFF['MCC'][i]:+.3f}  "
          f"delta={FULL['MCC'][i]-GATOFF['MCC'][i]:+.3f}")
