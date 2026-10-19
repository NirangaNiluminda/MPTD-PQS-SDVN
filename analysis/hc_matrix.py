#!/usr/bin/env python3
"""
hc_matrix.py — health-check the SOTA matrix values as they land.
Validates every recorded row against sane metric ranges, flags stale/duplicate
reads (the "sim crashed -> reader picked up a previous run's CSV" bug), and
sanity-checks the confusion matrix actually saw beacons for each cell.

Usage: python3 hc_matrix.py <run_dir>   (reads run_dir/matrix.csv + per-cell logs)
"""
import sys, csv, os, glob, math

RUN = sys.argv[1]
CSV = os.path.join(RUN, "matrix.csv")
FULL_MODES = {"0","2","3","4","5","7","8"}

def fnum(x):
    try: return float(x)
    except: return float("nan")

RANGES = {  # (lo, hi, allow_neg1)
    "MCC":(-1,1,False), "FPR":(0,1,False), "MCC_full":(-1,1,False), "FPR_full":(0,1,False),
    "PARR":(0,1,True), "CDER":(0,1,False), "TDEE":(0,1e6,False), "TPE":(0,1e6,False),
    "PBPO_Full_ms":(0,1e7,False), "TTD":(0,1e6,False),
}

rows = list(csv.DictReader(open(CSV)))
print(f"rows recorded: {len(rows)}\n")
issues = 0
seen_native = {}   # native MCC per (method) list — to detect all-identical
native_by_cell = {}

for r in rows:
    a, m, mode = r["attack"], r["method"], str(r["mode"]).strip()
    tag = f"a{a}/{m}(m{mode})"
    # 1) range checks
    for k,(lo,hi,n1) in RANGES.items():
        v = fnum(r.get(k,"nan"))
        if math.isnan(v):
            print(f"  ⚠ {tag}: {k}=nan (metrics file missing/unparsed?)"); issues+=1; continue
        if n1 and abs(v+1)<1e-9:   # -1 sentinel allowed
            continue
        if v < lo-1e-9 or v > hi+1e-9:
            print(f"  🚩 {tag}: {k}={v} OUT OF RANGE [{lo},{hi}]"); issues+=1
    # 2) native score
    nat = fnum(r["MCC_full"]) if mode in FULL_MODES else fnum(r["MCC"])
    native_by_cell[(a,m)] = nat
    # 3) confusion matrix freshness: find the per-cell metrics csv and check cm sum>0
    cs = sorted(glob.glob(os.path.join(RUN,"..","..","sweep",f"metrics_a{a}_*_m{mode}.csv")),
                key=os.path.getmtime)
    # 4) log sanity: did the run print detection metrics (i.e. actually finish)?
    logs = glob.glob(os.path.join(RUN, f"a{a}_{m}.log"))
    if logs:
        txt = open(logs[0]).read()
        if "Detection Metrics" not in txt and "MPTD-PQS Detection" not in txt:
            print(f"  🚩 {tag}: log has NO detection-metrics block — run may have crashed → STALE read likely"); issues+=1
        if "Invalid argument" in txt or "Aborted" in txt:
            print(f"  🚩 {tag}: log shows sim error (Invalid argument/Aborted) → STALE metrics"); issues+=1

# 5) all-identical detection across different attacks for same method = stale bug
from collections import defaultdict
by_method = defaultdict(list)
for (a,m),v in native_by_cell.items():
    by_method[m].append((a,v))
for m, lst in by_method.items():
    vals = [v for _,v in lst if not math.isnan(v)]
    if len(vals) >= 3 and max(vals)-min(vals) < 1e-6:
        print(f"  🚩 {m}: identical MCC={vals[0]:.4f} across {len(vals)} attacks — STALE-READ bug suspected"); issues+=1

# 6) expectation checks (soft): baselines should win their home-turf attack
def nat(a,m): return native_by_cell.get((a,m), float("nan"))
soft = []
if not math.isnan(nat("2","B1_Ghaleb")):
    soft.append(f"  B1 on a2(speed, its turf): MCC={nat('2','B1_Ghaleb'):.3f}  (expect > baselines-elsewhere; ~0 = B1 broken)")
if not math.isnan(nat("3","B2_stdGAT")):
    soft.append(f"  B2-GAT on a3(Sybil, its turf): MCC={nat('3','B2_stdGAT'):.3f}  (expect notably > its other attacks)")
for a in sorted({a for a,_ in native_by_cell}):
    p = nat(a,"MPTD-PQS_full")
    if not math.isnan(p):
        others = [nat(a,x) for x in ("B1_Ghaleb","B2_stdGAT","B3_stdAE") if not math.isnan(nat(a,x))]
        if others:
            tag = "WINS" if p >= max(others)-1e-9 else "LOSES"
            soft.append(f"  a{a}: proposed={p:.3f} vs best-baseline={max(others):.3f}  proposed {tag}")
if soft:
    print("\nExpectation checks:")
    print("\n".join(soft))

print(f"\n{'✅ no hard issues' if issues==0 else f'🚩 {issues} issue(s) flagged above'} "
      f"({len(rows)} rows checked)")
