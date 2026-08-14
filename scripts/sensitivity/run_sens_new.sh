#!/usr/bin/env bash
# New full-system sensitivity sweeps (paper tables added in main(3).tex):
#   phi_th     -> tab:phith-sensitivity  (fusion decision threshold; via fusion_weights.json, no rebuild)
#   attack_pct -> tab:attackpct-sensitivity (attack penetration rho_a; via --attack_percentage)
# Full mode + live Fabric. 1 seed by default (supplementary tables; crypto tables handled separately).
# Usage:  SEEDS=1 SIMT=20 bash run_sens_new.sh <phi_th|attack_pct>
set -uo pipefail
NS3=/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
WHICH="${1:?usage: run_sens_new.sh <phi_th|attack_pct>}"
SEEDS=${SEEDS:-1}; SIMT=${SIMT:-20}; ATTACK=${ATTACK:-1}; PCT=${PCT:-50}
FJSON=$NS3/analytics/ml/models/urban/fusion_weights.json
declare -A GRID=( [phi_th]="0.30 0.40 0.5108 0.60 0.70" [attack_pct]="10 25 50 75" )
[ -n "${GRID[$WHICH]:-}" ] || { echo "unknown sweep '$WHICH'"; exit 1; }

STAMP=$(date +%Y%m%d_%H%M%S)
OUT="$NS3/analytics/results/sensitivity/new_${WHICH}_${STAMP}"; mkdir -p "$OUT"
CSV="$OUT/sensitivity.csv"
echo "param,value,seed,MCC,FPR,MCC_full,FPR_full,PARR,CDER,COO_epoch,TCL_confirm" > "$CSV"
cd "$NS3"; export LD_LIBRARY_PATH="$NS3/build/lib:$HOME/.local/lib:$HOME/.local/lib64"
BIN=./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn
BASE="--mobility_source=1 --mobility_scenario=0 --maxspeed=60 --N_RSUs=64 --N_Vehicles=200 \
--ablation_mode=0 --skip_blockchain=false --routing_algorithm=4 \
--attack_number=$ATTACK --simTime=$SIMT"

# back up the fusion json (phi_th sweep mutates it) and restore on any exit
cp "$FJSON" "$FJSON.bak_new" 2>/dev/null || true
restore(){ [ -f "$FJSON.bak_new" ] && mv -f "$FJSON.bak_new" "$FJSON"; }
trap restore EXIT
setphi(){ python3 -c "import json;p='$FJSON';d=json.load(open(p));d['phi_threshold']=float('$1');json.dump(d,open(p,'w'))"; }
pull(){ python3 -c "
import csv,sys
try: r=list(csv.DictReader(open('$1')))[0]
except Exception: print('nan nan nan nan nan nan nan nan'); sys.exit()
g=lambda k:r.get(k,'nan')
print(g('MCC'),g('FPR'),g('MCC_full'),g('FPR_full'),g('PARR'),g('CDER'),g('COO_epoch'),g('TCL_confirm'))"; }

echo "[NEW] $WHICH sweep  seeds=$SEEDS  blockchain=on  -> $OUT"
for v in ${GRID[$WHICH]}; do
  for s in $(seq 2 $((SEEDS+1))); do
    PCTUSE=$PCT
    if [ "$WHICH" = "phi_th" ]; then setphi "$v"; else PCTUSE="$v"; fi
    echo "  [NEW] $WHICH=$v seed=$s (pct=$PCTUSE) ..."
    MPTD_CA_IDENTITY=0 $BIN $BASE --attack_percentage=$PCTUSE --RngRun=$s > "$OUT/${WHICH}_${v}_s${s}.log" 2>&1
    C=$(ls -t analytics/results/sweep/metrics_*_m0.csv 2>/dev/null | head -1)
    read MCC FPR MCCf FPRf PARR CDER COO TCL < <(pull "$C")
    echo "$WHICH,$v,$s,$MCC,$FPR,$MCCf,$FPRf,$PARR,$CDER,$COO,$TCL" >> "$CSV"
    echo "     -> MCC_full=$MCCf FPR_full=$FPRf PARR=$PARR CDER=$CDER"
  done
done
restore
echo "[NEW] $WHICH done -> $CSV"
column -t -s, "$CSV"
