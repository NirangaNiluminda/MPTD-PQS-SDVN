#!/usr/bin/env python3
"""
ab4_figure.py — AB4 (LSTM-AE ablation) deliverable figure.

All four metrics are computed OFFLINE from the per-beacon [FUSION-RSU] decisions,
because the in-sim TTD and CDER counters are wired to the LW/rule tier
(`t_alert = first LW detection`; `wrong = detected XOR is_poisoned` with the LW
flag), not to the fusion output. The LSTM-AE only enters the fusion, so those two
in-sim metrics are structurally blind to this ablation — they came out identical
to 4 dp for FULL and AB4. Reconstructing them from `full_anom` measures what the
paper actually intends.

  MCC   Matthews correlation of (gt_pois, full_anom)
  TTD   per-attacker mean of (first full_anom=YES) - (first gt_pois=1),
        timestamped via the enclosing [IPFS-STORE] epoch t_start
  CDER  (FP + FN) / total control decisions, using full_anom
  TPE   read from the run summary (attack-side; unaffected by the ablation)

Config: attack 1 (TP-S1 sub-gate stealth drift), rho_a=0.20, stealth_fraction=1.0,
30 s, 5 seeds, theta_ae=0.7937, lambda_ae=0.65 (per-run override).
"""
import re, os, math
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

D     = "/home/sdvn_mobility_flooding/Desktop/SENTINEL_experiments/AB4_final"
OUT   = "/home/sdvn_mobility_flooding/Desktop/SENTINEL_experiments/AB4_final/fig_AB4_ablation"
EPS   = ("0.1", "0.2", "0.3", "0.4", "0.5")
SEEDS = (1, 2, 3, 4, 5)
RXF = re.compile(r'^\[FUSION-RSU(\d+)\] epoch=(\d+) vid=(\d+).*?gt_pois=(\d).*?full_anom=(YES|no)')
RXI = re.compile(r'^\[IPFS-STORE-RSU(\d+)\] epoch=(\d+).*?t_start=([0-9.]+)')


def run_metrics(eps, ab, seed):
    f = f"{D}/eps{eps}_ab{ab}_s{seed}.log"
    if not os.path.exists(f):
        return None
    ts, onset, alert = {}, {}, {}
    tp = fp = fn = tn = 0
    tpe = np.nan
    for ln in open(f, errors="ignore"):
        if ln.startswith("[IPFS-STORE-RSU"):
            m = RXI.match(ln)
            if m:
                ts[(m.group(1), m.group(2))] = float(m.group(3))
            continue
        if ln.startswith("[FUSION-RSU"):
            m = RXF.match(ln)
            if not m:
                continue
            rsu, ep, vid = m.group(1), m.group(2), m.group(3)
            pois, det = m.group(4) == "1", m.group(5) == "YES"
            if pois and det:      tp += 1
            elif pois:            fn += 1
            elif det:             fp += 1
            else:                 tn += 1
            t = ts.get((rsu, ep))
            if t is None:
                continue
            if pois and (vid not in onset or t < onset[vid]): onset[vid] = t
            if det  and (vid not in alert or t < alert[vid]): alert[vid] = t
            continue
        if ln.startswith("  TPE "):
            mm = re.search(r'=\s*([-0-9.]+)', ln)
            if mm: tpe = float(mm.group(1))
    den = math.sqrt(float(tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    mcc = ((tp*tn - fp*fn)/den) if den > 0 else 0.0
    tot = tp+fp+fn+tn
    cder = (fp+fn)/tot if tot else np.nan
    lat = [alert[v]-onset[v] for v in onset if v in alert and alert[v] >= onset[v]]
    ttd = np.mean(lat) if lat else np.nan
    return dict(MCC=mcc, TTD=ttd, CDER=cder, TPE=tpe,
                ndet=len(lat), npois=len(onset))


agg = {}
for e in EPS:
    for ab in (0, 4):
        rs = [r for s in SEEDS if (r := run_metrics(e, ab, s))]
        for k in ("MCC", "TTD", "CDER", "TPE"):
            v = [r[k] for r in rs if r[k] == r[k]]
            agg[(e, ab, k)] = (np.mean(v), np.std(v), len(v)) if v else (np.nan, 0.0, 0)
        agg[(e, ab, "ndet")]  = np.mean([r["ndet"] for r in rs]) if rs else np.nan
        agg[(e, ab, "npois")] = np.mean([r["npois"] for r in rs]) if rs else np.nan

x = np.arange(len(EPS))
PANELS = [("MCC",  "MCC",            "(a) detection quality"),
          ("TTD",  "TTD (s)",        "(b) detection latency"),
          ("CDER", "CDER",           "(c) control-plane decision error"),
          ("TPE",  "TPE (m)",        "(d) trajectory prediction error")]
C  = {0: "#1f77b4", 4: "#ff7f0e"}
MK = {0: "o",       4: "s"}
LB = {0: "SENTINEL (full)", 4: "AB4 (LSTM-AE removed)"}

fig, axes = plt.subplots(1, 4, figsize=(19, 4.3))
for ax, (key, ylab, title) in zip(axes, PANELS):
    # TPE is attack-side (accumulated over every beacon, no detection filter), so the
    # two curves are numerically IDENTICAL and would plot exactly on top of each other.
    # Offset the AB4 markers slightly so both series stay visible.
    overlap = (key == "TPE")
    for ab in (0, 4):
        m  = np.array([agg[(e, ab, key)][0] for e in EPS])
        sd = np.array([agg[(e, ab, key)][1] for e in EPS])
        xo = x + (0.06 if (overlap and ab == 4) else 0.0)
        ax.errorbar(xo, m, yerr=sd, color=C[ab], marker=MK[ab], ms=7, lw=2,
                    capsize=3, elinewidth=1.2, label=LB[ab],
                    ls="--" if (overlap and ab == 4) else "-",
                    alpha=0.85 if overlap else 1.0)
        fin = np.where(np.isfinite(m))[0]
        if len(fin):
            j = fin[-1]
            ax.annotate("full" if ab == 0 else "AB4", xy=(xo[j], m[j]),
                        xytext=(7, 6 if (overlap and ab == 4) else 0),
                        textcoords="offset points",
                        color=C[ab], fontsize=11, fontweight="bold", va="center")
    if key == "TPE":
        ax.text(0.03, 0.95, "curves identical:\nattack-side metric,\nno detection filter",
                transform=ax.transAxes, fontsize=9, va="top", color="#444441")
    if key == "TTD":
        ax.text(0.03, 0.06, "AB4 line = a single detection\nacross all seeds (s.d. = 0)",
                transform=ax.transAxes, fontsize=9, va="bottom", color="#444441")
    ax.set_xticks(x); ax.set_xticklabels(EPS)
    ax.set_xlabel(r"stealth drift bound  $\epsilon_{max}$  (m per beacon)", fontsize=11)
    ax.set_ylabel(ylab, fontsize=11)
    ax.set_title(title, fontsize=12)
    ax.set_xlim(-0.25, len(EPS)-0.55)
    ax.grid(True, alpha=0.3, lw=0.6)
handles = [plt.Line2D([0], [0], color=C[a], marker=MK[a], lw=2, label=LB[a]) for a in (0, 4)]
fig.legend(handles=handles, loc="lower center", ncol=2, frameon=False,
           fontsize=11, bbox_to_anchor=(0.5, -0.045))
fig.suptitle(r"AB4 — LSTM-AE ablation under stealth trajectory drift "
             r"($\rho_a$=0.20, attack TP-S1, 5 seeds, mean $\pm$ s.d.)",
             fontsize=12.5, y=1.02)
fig.tight_layout(rect=[0, 0.04, 1, 1])
fig.savefig(OUT + ".png", dpi=200, bbox_inches="tight")
fig.savefig(OUT + ".pdf", bbox_inches="tight")
print("saved:", OUT + ".png / .pdf\n")

for key, ylab, _ in PANELS:
    print(f"--- {ylab} ---")
    print(f"{'eps':>5} | {'SENTINEL full':>17} | {'AB4':>17} | {'delta':>9}")
    for e in EPS:
        fm, fs, _ = agg[(e, 0, key)]; am, as_, _ = agg[(e, 4, key)]
        print(f"{e:>5} | {fm:>9.4f} ± {fs:<5.3f} | {am:>9.4f} ± {as_:<5.3f} | {fm-am:>+9.4f}")
    print()
print("attacker vehicles detected (mean over seeds):")
for e in EPS:
    print(f"  eps={e}: full {agg[(e,0,'ndet')]:.1f}/{agg[(e,0,'npois')]:.1f}"
          f"   AB4 {agg[(e,4,'ndet')]:.1f}/{agg[(e,4,'npois')]:.1f}")
