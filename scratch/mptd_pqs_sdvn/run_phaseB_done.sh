#!/usr/bin/env bash
# =============================================================================
# run_phaseB_done.sh — held-out scoring (Phase B) for scenarios that already
# have a Phase-A dataset folder. Produces the B1/B2/B3 vs MPTD-PQS plots.
#
# Assumes B2/B3 models are ALREADY trained+frozen (models_ercan_b2 / _sharma_b3).
# For each existing analytics/datasets/aN_pP:
#   RngRun=2 mode=1 -> held-out beacon_log + MPTD-PQS A1 metrics (m1)
#                      predict B2/B3 -> live_results/{ercan,sharma}_aN_pP.csv
#   RngRun=2 mode=6 -> B1 (Ghaleb) metrics (m6)
#   plot_baselines_real.py aN pP   (plotted immediately so screenshots appear ASAP)
# =============================================================================
set -uo pipefail

NS3="${NS3:-$HOME/ns-allinone-3.35/ns-3.35}"
PROJ="${PROJ:-$HOME/Niranga/MPTD-PQS-SDVN}"
cd "$NS3"
export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:${LD_LIBRARY_PATH:-}"

SIMTIME=30
SPEED=60
RES="$NS3/analytics/results"
B2DIR="$NS3/models_ercan_b2"
B3DIR="$NS3/models_sharma_b3"
LIVE="$PROJ/live_results"
SIMLOG="$NS3/scratch/mptd_pqs_sdvn/sim_live.log"
mkdir -p "$LIVE"

ts() { date '+%H:%M:%S'; }
log() { echo "[$(ts)] $*"; }

run_sim() {  # atk pct mode rng
  { echo "=========="; echo "[$(ts)] SIM a$1_p$2 mode=$3 RngRun=$4"; echo "=========="; } > "$SIMLOG"
  ./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=135 \
    --skip_blockchain=true --ablation_mode=$3 --attack_number=$1 \
    --attack_percentage=$2 --maxspeed=$SPEED --simTime=$SIMTIME --RngRun=$4" \
    >> "$SIMLOG" 2>&1
}

# Discover completed scenarios from dataset folders that contain a beacon_log
SCN=()
for d in "$NS3"/analytics/datasets/a*_p*; do
  [ -f "$d/beacon_log.csv" ] && SCN+=("$(basename "$d")")
done
log "Scenarios to score (${#SCN[@]}): ${SCN[*]}"

for s in "${SCN[@]}"; do
  atk="${s#a}"; atk="${atk%%_*}"
  pct="${s##*_p}"
  log "===== ${s}  (attack ${atk}, pct ${pct}) ====="

  log "[B m1] held-out sim ${s}"
  if run_sim "$atk" "$pct" 1 2; then
    python3 mptd_pqs/ercan_b2_live_predict.py  "$RES/beacon_log.csv" "$atk" "$pct" "$B2DIR" \
      "$LIVE/ercan_a${atk}_p${pct}.csv"  >/dev/null 2>&1 || log "  WARN B2 predict failed ${s}"
    python3 mptd_pqs/sharma_b3_live_predict.py "$RES/beacon_log.csv" "$atk" "$pct" "$B3DIR" \
      "$LIVE/sharma_a${atk}_p${pct}.csv" >/dev/null 2>&1 || log "  WARN B3 predict failed ${s}"
  else
    log "  FAILED ${s} (RUN B m1)"
  fi

  log "[B m6] B1 Ghaleb ${s}"
  run_sim "$atk" "$pct" 6 2 || log "  FAILED ${s} (RUN B m6)"

  log "[PLOT] ${s}"
  ( cd "$PROJ" && python3 plot_baselines_real.py "$atk" "$pct" \
      "live_results/baseline_a${atk}_p${pct}.png" 2>&1 | tail -8 ) || log "  plot failed ${s}"
done

log "===== PHASE B (completed scenarios) DONE ====="
log "Plots: $LIVE/baseline_a*_p*.png"
