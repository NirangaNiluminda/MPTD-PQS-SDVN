#!/usr/bin/env bash
# Quick health-check for the running sensitivity sweep. Auto-finds the newest
# sensitivity run and flags any degenerate result (single-class confusion,
# MCC~0, or too-few beacons) so a bad attacker-seed realization can't sneak in.
# Usage:  bash sens_health.sh
NS3=/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
O=$(ls -td "$NS3"/analytics/results/sensitivity/run_* 2>/dev/null | head -1)
C="$O/sensitivity.csv"
[ -f "$C" ] || { echo "no sensitivity CSV yet at $O"; exit 0; }
echo "run: $(basename "$O")   |  now $(date '+%H:%M:%S')"
echo "progress: $(($(wc -l < "$C")-1)) / 75 runs   |  on: $(tail -1 /tmp/sensitivity_sweep.log 2>/dev/null)"
echo
python3 - "$C" <<'PY'
import csv,math,sys
rows=list(csv.DictReader(open(sys.argv[1])))
print(f"{'param':<11}{'val':<7}{'seed':<5}{'MCC':>7}{'MCCfull':>9}{'FPRfull':>9}   (TP,FP,TN,FN)      health")
nbad=0
for r in rows:
    g=lambda k:(float(r[k]) if r.get(k,'') not in ('','nan') else float('nan'))
    TP,FP,TN,FN=g('cm_TP'),g('cm_FP'),g('cm_TN'),g('cm_FN'); mf=g('MCC_full')
    bad=[]
    if TP==0 or TN==0: bad.append("SINGLE-CLASS")
    if math.isnan(mf) or abs(mf)<1e-6: bad.append("MCC~0")
    if (TP+FP+TN+FN)<500: bad.append("FEW-BEACONS")
    if bad: nbad+=1
    print(f"{r['param']:<11}{r['value']:<7}{r['seed']:<5}{g('MCC'):>7.3f}{mf:>9.3f}{g('FPR_full'):>9.3f}   "
          f"({TP:.0f},{FP:.0f},{TN:.0f},{FN:.0f})   {'OK' if not bad else ' '.join(bad)}")
print(f"\n{'ALL HEALTHY' if nbad==0 else f'>>> {nbad} DEGENERATE run(s) — re-run those points with a pinned --rsu_seed afterward'}")
PY