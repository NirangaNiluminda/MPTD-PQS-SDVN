#!/usr/bin/env bash
# Sweep ONE calibration threshold under a chosen ATTACK — used for the
# attack-matched re-runs (kappa_th under attack 6 MitM, k_sybil under attack 3
# Sybil), since a trajectory-poisoning (attack 1) run never fires MP-S3 / MP-S1.
# Self-contained; does NOT touch the running run_sensitivity.sh.
# Usage:  ATTACK=6 SEEDS=3 SIMT=20 bash run_sens_one.sh kappa_th
set -uo pipefail
NS3=/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
PARAM="${1:?usage: run_sens_one.sh <psi_th|kappa_th|delta_th|drift_window|k_sybil>}"
ATTACK=${ATTACK:-1}; PCT=${PCT:-50}; SIMT=${SIMT:-20}; SEEDS=${SEEDS:-3}
declare -A GRID=( [psi_th]="0.05 0.07 0.09 0.11 0.15" [kappa_th]="0.10 0.30 0.50 1.00" \
  [delta_th]="5.0 7.5 10.0 12.5 15.0" [drift_window]="5 10 15 20" [k_sybil]="3.0 4.0 5.0 6.0" )
declare -A FLAG=( [psi_th]=--psi_th [kappa_th]=--kappa_th [delta_th]=--delta_th \
  [drift_window]=--drift_window_k [k_sybil]=--k_sybil )
[ -n "${GRID[$PARAM]:-}" ] || { echo "unknown param $PARAM"; exit 1; }

STAMP=$(date +%Y%m%d_%H%M%S)
OUT="$NS3/analytics/results/sensitivity/fix_${PARAM}_a${ATTACK}_${STAMP}"; mkdir -p "$OUT"
CSV="$OUT/sensitivity.csv"
echo "param,value,seed,MCC,FPR,MCC_full,FPR_full,cm_TP,cm_FP,cm_TN,cm_FN" > "$CSV"
cd "$NS3"; export LD_LIBRARY_PATH="$NS3/build/lib:$HOME/.local/lib:$HOME/.local/lib64"
BIN=./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn
COMMON="--mobility_source=1 --mobility_scenario=0 --maxspeed=60 --N_RSUs=64 --N_Vehicles=200 \
--ablation_mode=0 --skip_blockchain=false --routing_algorithm=4 \
--attack_number=$ATTACK --attack_percentage=$PCT --simTime=$SIMT"

echo "[FIX] $PARAM under attack=$ATTACK  seeds=$SEEDS  blockchain=on  -> $OUT"
for v in ${GRID[$PARAM]}; do
  for s in $(seq 2 $((SEEDS+1))); do
    echo "  [FIX] $PARAM=$v seed=$s attack=$ATTACK ..."
    MPTD_CA_IDENTITY=0 $BIN $COMMON ${FLAG[$PARAM]}=$v --RngRun=$s > "$OUT/${PARAM}_${v}_s${s}.log" 2>&1
    C=$(ls -t analytics/results/sweep/metrics_*_m0.csv 2>/dev/null | head -1)
    read MCC FPR MCCf FPRf TP FP TN FN < <(python3 -c "
import csv,sys
try: r=list(csv.DictReader(open('$C')))[0]
except Exception: print('nan nan nan nan nan nan nan nan'); sys.exit()
g=lambda k:r.get(k,'nan'); print(g('MCC'),g('FPR'),g('MCC_full'),g('FPR_full'),g('cm_TP'),g('cm_FP'),g('cm_TN'),g('cm_FN'))")
    echo "$PARAM,$v,$s,$MCC,$FPR,$MCCf,$FPRf,$TP,$FP,$TN,$FN" >> "$CSV"
  done
done
echo "[FIX] done -> $CSV"
cd /home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN && python3 plot_sensitivity.py "$CSV"
