#!/usr/bin/env bash
# =============================================================================
# Full-system sensitivity analysis — MPTD-PQS-SDVN (paper §4.3.4 grid tables).
#
# Sweeps each LW-detector hyper-parameter ONE AT A TIME (all others at default),
# in FULL mode (GAT + LSTM-AE + PQ crypto), skip_blockchain=true (ledger does
# not affect MCC/FPR, so we skip Fabric to keep each run ~1 min). >=SEEDS seeds
# per point; records mean+/-std MCC and FPR to a tidy CSV that plot_sensitivity.py
# turns into per-parameter plots + one combined plot + the filled LaTeX tables.
#
# Fills: tab:threshold-sensitivity (psi_th), tab:kl-sensitivity (kappa_th),
#        tab:drift-sensitivity (delta_th), tab:smax-sensitivity (maxspeed),
#        tab:window-sybil-sensitivity (drift_window_k, K_sybil).
#
# Usage:  bash run_sensitivity.sh                 # all 5 tables, urban, 3 seeds
#         PARAMS="psi_th" SEEDS=3 bash run_sensitivity.sh   # one table only
#         ATTACK=1 PCT=50 SIMT=20 SEEDS=3 bash run_sensitivity.sh
# =============================================================================
set -uo pipefail
NS3=/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35
ATTACK=${ATTACK:-1}; PCT=${PCT:-50}; SIMT=${SIMT:-20}; SEEDS=${SEEDS:-3}
BLOCKCHAIN=${BLOCKCHAIN:-on}     # sir: keep blockchain ON (live Fabric). set BLOCKCHAIN=off to skip.
# which parameters to sweep (space-separated); default = all five tables
PARAMS=${PARAMS:-"psi_th kappa_th delta_th maxspeed window_sybil"}

STAMP=$(date +%Y%m%d_%H%M%S)
OUT="$NS3/analytics/results/sensitivity/run_${STAMP}"
mkdir -p "$OUT"
CSV="$OUT/sensitivity.csv"
echo "param,value,seed,MCC,FPR,MCC_full,FPR_full,cm_TP,cm_FP,cm_TN,cm_FN" > "$CSV"

cd "$NS3" || exit 1
export LD_LIBRARY_PATH="$NS3/build/lib:$HOME/.local/lib:$HOME/.local/lib64"
BIN=./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn
# full mode (GAT + LSTM-AE + PQ crypto), urban SUMO map.
COMMON="--mobility_source=1 --mobility_scenario=0 --maxspeed=60 --N_RSUs=64 \
--N_Vehicles=200 --ablation_mode=0 \
--attack_number=$ATTACK --attack_percentage=$PCT --simTime=$SIMT"
# sir: blockchain ON → live Hyperledger Fabric (routing_algorithm=4, skip_blockchain=false,
# User1 identity fallback via MPTD_CA_IDENTITY=0). Each run re-registers all nodes on-chain.
CAENV=""
if [ "$BLOCKCHAIN" = "on" ]; then
  COMMON="$COMMON --skip_blockchain=false --routing_algorithm=4"
  CAENV="MPTD_CA_IDENTITY=0"
else
  COMMON="$COMMON --skip_blockchain=true"
fi

# grids (bold = paper-selected default)
declare -A GRID=(
  [psi_th]="0.05 0.07 0.09 0.11 0.15"
  [kappa_th]="0.10 0.30 0.50 1.00"
  [delta_th]="5.0 7.5 10.0 12.5 15.0"
  [maxspeed]="80 100 120"            # urban s_max column
  [window_sybil_win]="5 10 15 20"    # drift_window_k
  [window_sybil_syb]="3.0 4.0 5.0 6.0"  # K_sybil
)

# pull MCC/FPR/confusion out of the metrics CSV a run just wrote
pull () {  # $1=metrics csv  -> echoes "MCC FPR MCCf FPRf TP FP TN FN"
  python3 - "$1" <<'PY'
import sys,csv
try: r=list(csv.DictReader(open(sys.argv[1])))[0]
except Exception: print("nan nan nan nan nan nan nan nan"); sys.exit()
g=lambda k:r.get(k,"nan")
print(g("MCC"),g("FPR"),g("MCC_full"),g("FPR_full"),
      g("cm_TP"),g("cm_FP"),g("cm_TN"),g("cm_FN"))
PY
}

run_point () {  # $1=param-label  $2=flag-string  $3=value(for logging)
  local label="$1" flags="$2" val="$3" s mcsv
  for s in $(seq 2 $((SEEDS+1))); do
    local tag="${label}_${val}_s${s}"
    echo "  [SENS] $label=$val seed=$s  (blockchain=$BLOCKCHAIN) ..."
    env $CAENV $BIN $COMMON $flags --RngRun=$s > "$OUT/${tag}.log" 2>&1
    mcsv=$(ls -t analytics/results/sweep/metrics_*_m0.csv 2>/dev/null | head -1)
    read MCC FPR MCCf FPRf TP FP TN FN < <(pull "$mcsv")
    echo "$label,$val,$s,$MCC,$FPR,$MCCf,$FPRf,$TP,$FP,$TN,$FN" >> "$CSV"
  done
}

echo "[SENS] full-system sensitivity  a${ATTACK}_p${PCT}  t=${SIMT}s  seeds=${SEEDS}  blockchain=${BLOCKCHAIN}  -> $OUT"
for p in $PARAMS; do
  case "$p" in
    psi_th)   for v in ${GRID[psi_th]};   do run_point psi_th   "--psi_th=$v"   "$v"; done ;;
    kappa_th) for v in ${GRID[kappa_th]}; do run_point kappa_th "--kappa_th=$v" "$v"; done ;;
    delta_th) for v in ${GRID[delta_th]}; do run_point delta_th "--delta_th=$v" "$v"; done ;;
    maxspeed) for v in ${GRID[maxspeed]}; do run_point maxspeed "--maxspeed=$v" "$v"; done ;;
    window_sybil)
      for v in ${GRID[window_sybil_win]}; do run_point drift_window "--drift_window_k=$v" "$v"; done
      for v in ${GRID[window_sybil_syb]}; do run_point k_sybil      "--k_sybil=$v"        "$v"; done ;;
    *) echo "  [SENS] unknown param '$p' (skipped)";;
  esac
done

echo "[SENS] raw results: $CSV"
echo "[SENS] plotting + LaTeX ..."
cd /home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN && python3 plot_sensitivity.py "$CSV"
echo "[SENS] DONE. plots + tables next to the CSV in: $OUT"
