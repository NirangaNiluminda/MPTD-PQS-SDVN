#!/usr/bin/env bash
# =============================================================================
# run_heldout_perattack.sh — score the FROZEN global baseline models on FRESH
# held-out runs, per attack scenario. The global RF models in models_global/
# are NOT retrained; we only run RngRun=2 sims and predict with them.
#
# For atk in 1 2 3, pct in 30 60 90:
#   mode=1 RngRun=2 -> fresh held-out beacon_log.csv + MPTD-PQS A1 metrics (m1)
#                      global_heldout_eval.py predict <atk> <pct>
#                        (loads frozen global RF, scores B2/B3, pulls B1+MPTD)
# Finally: global_heldout_eval.py plot -> live_results/global_heldout_perattack.png
# =============================================================================
set -uo pipefail

NS3="${NS3:-$HOME/ns-allinone-3.35/ns-3.35}"
PROJ="${PROJ:-$HOME/Desktop/G11/MPTD-PQS-SDVN}"
cd "$NS3"
export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:${LD_LIBRARY_PATH:-}"

SIMTIME=10
SPEED=60
RES="$NS3/analytics/results"
LIVE="$PROJ/live_results"
SIMLOG="$NS3/scratch/mptd_pqs_sdvn/sim_live.log"
RESULTS_CSV="$LIVE/global_heldout_results.csv"
mkdir -p "$LIVE"

ts()  { date '+%H:%M:%S'; }
log() { echo "[$(ts)] $*"; }

run_sim() {  # atk pct mode rng
  { echo "=========="; echo "[$(ts)] SIM a$1_p$2 mode=$3 RngRun=$4"; echo "=========="; } > "$SIMLOG"
  ./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=200 \
    --skip_blockchain=true --ablation_mode=$3 --attack_number=$1 \
    --attack_percentage=$2 --maxspeed=$SPEED --simTime=$SIMTIME --RngRun=$4" \
    >> "$SIMLOG" 2>&1
}

# Fresh results CSV so the per-attack chart only reflects this held-out batch.
rm -f "$RESULTS_CSV"

log "===== HELD-OUT per-attack scoring (frozen global models) START ====="
for atk in 1 2 3 4 5 6 7; do
  for pct in 0 20 40 60 80 100; do
    s="a${atk}_p${pct}"
    log "===== ${s} : held-out sim (mode 1, RngRun=2) ====="
    if run_sim "$atk" "$pct" 1 2; then
      ( cd "$PROJ" && NS3="$NS3" python3 global_heldout_eval.py predict "$atk" "$pct" 2>&1 | tail -8 ) \
        || log "  WARN predict failed ${s}"
    else
      log "  FAILED ${s} (held-out sim)"
    fi
  done
done

log "regenerating per-attack chart..."
( cd "$PROJ" && NS3="$NS3" python3 global_heldout_eval.py plot 2>&1 | tail -40 )
log "===== HELD-OUT per-attack scoring DONE ====="
log "Chart: $LIVE/global_heldout_perattack.png"
