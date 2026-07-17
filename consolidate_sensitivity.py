#!/usr/bin/env python3
"""
consolidate_sensitivity.py — gather EVERY completed sensitivity sweep from the
results/sensitivity folder into one master CSV, then generate all per-param plots
+ the composite + tables + summary (via plot_sensitivity.py). Re-run any time;
it picks up whatever sweeps have finished so far.

Sources (latest folder of each kind):
  OVERNIGHT_*/A_lw_params.csv   -> psi_th, delta_th, drift_window, kappa_th, k_sybil, maxspeed(s_max)
  OVERNIGHT_*/B_phi_th.csv      -> phi_th
  kappa_ae_sweep_*/sensitivity  -> kappa_ae
  OVERNIGHT_*/EXP1_rho_gamma    -> attack_pct (gamma=0.7), stealth_gamma (rho=40)   [Exp-1 axes]
  P1_phimax_*/sensitivity       -> phi_max
  P2_gat_retrain_*/sensitivity  -> dropout, lr, weight_decay, gat_heads, gat_hidden, leaky_slope

Usage: python3 consolidate_sensitivity.py [SENS_DIR]
"""
import os, sys, csv, glob, subprocess
from collections import Counter

SENS = sys.argv[1] if len(sys.argv) > 1 else \
    "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35/analytics/results/sensitivity"
HDR = ["param", "value", "seed", "MCC", "FPR", "MCC_full", "FPR_full"]


def latest(pat):
    fs = sorted(glob.glob(os.path.join(SENS, pat)), key=os.path.getmtime)
    return fs[-1] if fs else None


def add(rows, path, want, get):
    if not path or not os.path.isfile(path):
        return
    for r in csv.DictReader(open(path)):
        out = get(r)
        if out and out[0] in want:
            rows.append([out[0], out[1], out[2], r.get("MCC", "nan"),
                         r.get("FPR", "nan"), r.get("MCC_full", "nan"), r.get("FPR_full", "nan")])


def main():
    rows = []
    ov = latest("OVERNIGHT_*")
    if ov:
        nm = {"s_max": "maxspeed"}
        add(rows, f"{ov}/A_lw_params.csv",
            {"psi_th", "delta_th", "drift_window", "kappa_th", "k_sybil", "maxspeed"},
            lambda r: (nm.get(r["param"], r["param"]), r["value"], r["seed"]))
        add(rows, f"{ov}/B_phi_th.csv", {"phi_th"},
            lambda r: ("phi_th", r["value"], r["seed"]))
        # Exp-1 axes (attack%, stealth gamma)
        add(rows, f"{ov}/EXP1_rho_gamma.csv", {"attack_pct"},
            lambda r: ("attack_pct", r["rho_a"], r["seed"]) if abs(float(r["gamma"]) - 0.7) < 1e-6 else None)
        add(rows, f"{ov}/EXP1_rho_gamma.csv", {"stealth_gamma"},
            lambda r: ("stealth_gamma", r["gamma"], r["seed"]) if r["rho_a"] == "40" else None)
    add(rows, (latest("kappa_ae_sweep_*") or "") + "/sensitivity.csv", {"kappa_ae"},
        lambda r: ("kappa_ae", r["value"], "2"))
    add(rows, (latest("P1_phimax_*") or "") + "/sensitivity.csv", {"phi_max"},
        lambda r: ("phi_max", r["value"], r["seed"]))
    # prefer the seeded re-run (P2b) if present, else the original P2
    gat_src = latest("P2b_gat_seeded_*") or latest("P2_gat_retrain_*")
    add(rows, (gat_src or "") + "/sensitivity.csv",
        {"dropout", "lr", "weight_decay", "gat_heads", "gat_hidden", "leaky_slope"},
        lambda r: (r["param"], r["value"], "2"))

    out_dir = os.path.join(SENS, "DELIVERABLE_MASTER")
    os.makedirs(out_dir, exist_ok=True)
    mcsv = os.path.join(out_dir, "sensitivity.csv")
    csv.writer(open(mcsv, "w")).writerows([HDR] + rows)
    print("params consolidated:", dict(Counter(r[0] for r in rows)))
    print("master CSV ->", mcsv)

    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, NS3="/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35")
    subprocess.run(["python3", os.path.join(here, "plot_sensitivity.py"), mcsv], env=env)
    print(f"\nAll plots + composite + tables + summary -> {out_dir}")


if __name__ == "__main__":
    main()
