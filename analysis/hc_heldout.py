#!/usr/bin/env python3
"""
hc_heldout.py — health-check the held-out pipeline data as it lands.
Validates each heldout/aN_pP scenario for SENSIBLE metrics, and (if present) the
final held-out comparison. Catches: out-of-range values, degenerate/stale reads,
label-balance mismatch (poisoned fraction should track the pct), inflated baselines.

Usage: python3 hc_heldout.py [heldout_root] [comparison_csv]
"""
import sys, os, glob, csv, math
import pandas as pd

HO  = sys.argv[1] if len(sys.argv) > 1 else "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35/analytics/heldout"
CMP = sys.argv[2] if len(sys.argv) > 2 else "/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN/live_results/heldout_cmp/heldout_comparison.csv"
ATTACKS = [1,2,3,4,5,6,7]; PCTS = [0,20,30,40,60,80,90,100]
issues = 0

def fnum(x):
    try: return float(x)
    except: return float("nan")

print("="*70); print("HELD-OUT DATA HEALTH CHECK"); print("="*70)

seen_mccfull = {}
for a in ATTACKS:
    for p in PCTS:
        d = os.path.join(HO, f"a{a}_p{p}")
        tag = f"a{a}p{p}"
        mfile = os.path.join(d, "metrics.csv")
        bfile = os.path.join(d, "beacon_log.csv")
        if not os.path.exists(mfile):
            continue  # not produced yet — skip silently
        r = list(csv.DictReader(open(mfile)))[0]
        cm = {k: fnum(r.get(f"cm_full_{k}", "nan")) for k in ("TP","FP","TN","FN")}
        cmsum = sum(v for v in cm.values() if not math.isnan(v))
        mccf = fnum(r.get("MCC_full","nan")); fprf = fnum(r.get("FPR_full","nan"))
        b1f  = os.path.join(d, "b1_metrics.csv")
        b1mcc = fnum(list(csv.DictReader(open(b1f)))[0].get("MCC","nan")) if os.path.exists(b1f) else float("nan")
        flags = []
        # range checks
        if not (-1.0001 <= mccf <= 1.0001): flags.append(f"MCC_full={mccf} OUT OF RANGE"); issues+=1
        if not (0 <= fprf <= 1.0001):       flags.append(f"FPR_full={fprf} OUT OF RANGE"); issues+=1
        # confusion matrix must have data
        if cmsum < 1:                       flags.append("cm_full all zero (mode-0 didn't score?)"); issues+=1
        # poisoned fraction should roughly track pct (attack 5/7 = control-plane, no poisoned beacons: skip)
        pois_frac = (cm["TP"]+cm["FN"])/cmsum if cmsum>0 else float("nan")
        if a not in (5,7) and not math.isnan(pois_frac):
            exp = p/100.0
            if abs(pois_frac - exp) > 0.30:  flags.append(f"poisoned frac {pois_frac:.2f} far from pct {exp:.2f}")
        # beacon_log present + non-trivial
        if not os.path.exists(bfile) or os.path.getsize(bfile) < 10000:
            flags.append("beacon_log missing/tiny (baseline eval will fail)"); issues+=1
        # b1 sanity
        if not math.isnan(b1mcc) and not (-1.0001 <= b1mcc <= 1.0001): flags.append(f"B1 MCC={b1mcc} OOR"); issues+=1
        seen_mccfull[tag] = mccf
        status = "OK " if not flags else "🚩 "
        print(f"{status}{tag:7} MCC_full={mccf:+.3f} FPR={fprf:.3f} pois_frac={pois_frac:.2f} "
              f"B1={b1mcc:+.3f}  {'; '.join(flags)}")

# stale-read: identical MCC_full across many scenarios
vals = [v for v in seen_mccfull.values() if not math.isnan(v)]
if len(vals) >= 4 and max(vals)-min(vals) < 1e-6:
    print(f"🚩 STALE-READ suspected: MCC_full identical ({vals[0]:.4f}) across {len(vals)} scenarios"); issues+=1

print(f"\nscenarios validated: {len(seen_mccfull)}/21")

# final comparison sanity (if present)
if os.path.exists(CMP):
    print("\n" + "-"*70); print("FINAL COMPARISON SANITY")
    d = pd.read_csv(CMP)
    for m in ("MCC","FPR"):
        bad = d[(d[m] < -1.0001) | (d[m] > 1.0001)]
        if len(bad): print(f"🚩 {len(bad)} {m} out of range"); issues+=1
    # inflated-baseline check: held-out baselines ~0.99 everywhere => CV leaked in
    for base in ("B2_Ercan","B3_Sharma"):
        sub = d[d.method==base]
        if len(sub) >= 4 and (sub.MCC > 0.97).mean() > 0.8:
            print(f"🚩 {base} MCC>0.97 in >80% of cells — looks like CV memorization, NOT held-out"); issues+=1
    print(d.pivot_table(index=["attack","attack_pct"], columns="method", values="MCC").round(3).to_string())

print("\n" + ("✅ no hard issues" if issues==0 else f"🚩 {issues} issue(s) flagged above"))
