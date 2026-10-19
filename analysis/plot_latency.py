#!/usr/bin/env python3
"""
plot_latency.py — plots the OVERHEAD/LATENCY sensitivity params (#12 FHE ring-dim N,
#13 TRS ring-size n, #25 vehicle zone density). Unlike the detection params, these
do NOT move MCC — so the y-axis is the overhead metric (latency ms / COO / BWO /
rekey cost), NOT MCC.

Input CSV (from the blockchain-ON latency sweeps): columns
  param,value,seed,<metric...>   where <metric> is any of:
  latency_ms, coo, bwo_ratio, rekey_msgs, sign_ms, ...
Any numeric non-{param,value,seed} column is auto-plotted vs value.

Output (next to CSV): lat_<param>.png per param, latency_combined.png, latency_tables.tex
Usage: python3 plot_latency.py <latency.csv>
"""
import sys, os, csv, math
from collections import defaultdict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CSV = sys.argv[1] if len(sys.argv) > 1 else "latency.csv"
OUT = os.path.dirname(os.path.abspath(CSV))

LABEL = {"fhe_n": r"FHE ring dim $N$", "trs_n": r"TRS ring size $n$",
         "zone_density": r"vehicle zone density $|\mathcal{V}_j|$"}
YLABEL = {"latency_ms": "latency (ms)", "sign_ms": "TRS sign latency (ms)",
          "coo": "crypto op. overhead (COO)", "bwo_ratio": "bandwidth overhead ratio",
          "rekey_msgs": r"LKH rekey msgs ($\log_2|V_j|$)"}


def fnum(x):
    try: return float(x)
    except Exception: return float("nan")


def main():
    rdr = list(csv.DictReader(open(CSV)))
    if not rdr:
        print("no data in", CSV); return
    cols = rdr[0].keys()
    metrics = [c for c in cols if c not in ("param", "value", "seed") and
               any(not math.isnan(fnum(r.get(c, ""))) for r in rdr)]
    # rows[param][metric][value] = list across seeds
    data = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for r in rdr:
        for m in metrics:
            v = fnum(r["value"]); y = fnum(r.get(m, ""))
            if not math.isnan(v) and not math.isnan(y):
                data[r["param"]][m][v].append(y)

    tex = []
    for p in data:
        for m in data[p]:
            xs = sorted(data[p][m])
            ys = [sum(data[p][m][x]) / len(data[p][m][x]) for x in xs]
            fig, ax = plt.subplots(figsize=(5, 3.5))
            ax.plot(xs, ys, marker="o", color="#2077b4")
            ax.set_xlabel(LABEL.get(p, p)); ax.set_ylabel(YLABEL.get(m, m))
            ax.set_title(f"{LABEL.get(p,p)} — {YLABEL.get(m,m)}"); ax.grid(alpha=0.3)
            fig.tight_layout(); fig.savefig(os.path.join(OUT, f"lat_{p}_{m}.png"), dpi=140)
            plt.close(fig)
            tex.append(f"% {p} / {m}")
            for x, y in zip(xs, ys):
                tex.append(f"{x} & {y:.3f} \\\\")
    # combined grid
    panels = [(p, m) for p in data for m in data[p]]
    if panels:
        n = len(panels); cols_ = min(3, n); rws = max(1, (n + cols_ - 1) // cols_)
        fig, axes = plt.subplots(rws, cols_, figsize=(5 * cols_, 3.6 * rws))
        axes = axes.flatten() if hasattr(axes, "flatten") else [axes]
        for i, (p, m) in enumerate(panels):
            xs = sorted(data[p][m]); ys = [sum(data[p][m][x]) / len(data[p][m][x]) for x in xs]
            axes[i].plot(xs, ys, marker="o", color="#2077b4")
            axes[i].set_xlabel(LABEL.get(p, p)); axes[i].set_ylabel(YLABEL.get(m, m))
            axes[i].set_title(LABEL.get(p, p)); axes[i].grid(alpha=0.3)
        for j in range(len(panels), len(axes)): axes[j].axis("off")
        fig.suptitle("MPTD-PQS — Overhead/Latency Sensitivity (#12 FHE N, #13 TRS n, #25 zone density)")
        fig.tight_layout(rect=[0, 0, 1, 0.96])
        fig.savefig(os.path.join(OUT, "latency_combined.png"), dpi=140); plt.close(fig)
    open(os.path.join(OUT, "latency_tables.tex"), "w").write("\n".join(tex))
    print(f"latency plots -> {OUT}/lat_*.png + latency_combined.png ; metrics: {metrics}")


if __name__ == "__main__":
    main()
