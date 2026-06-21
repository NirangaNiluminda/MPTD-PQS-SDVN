#!/usr/bin/env bash
# =============================================================================
# run_global_pipeline.sh — end-to-end GLOBAL-model baseline pipeline, ALL ATTACKS.
#
#   PHASE A  (RngRun=1, mode=1)  -> training data  -> analytics/datasets/aN_pP/
#   TRAIN    global_baseline_eval.py -> ONE global RF per method, FROZEN to
#            models_global/{ercan,sharma}_global_RF.joblib
#   PHASE C  (RngRun=2) held-out scoring of the FROZEN model, per scenario:
#              mode=6 -> B1 Ghaleb metrics (m6)
#              mode=1 -> MPTD-PQS metrics (m1) + fresh held-out beacon_log
#              global_heldout_eval.py predict <atk> <pct>  (scores B2/B3 frozen)
#   PLOT     global_heldout_eval.py plot -> live_results/global_heldout_perattack.png
#
# No leakage: train on RngRun=1, score on RngRun=2 (different vehicles/seed).
# Resumable: Phase-A sims and B1(m6) sims are SKIPPED when their output exists;
#            the frozen model is always retrained on all available data and the
#            held-out (mode=1) scoring is always re-run so every chart row comes
#            from the SAME freshly-frozen model.
# =============================================================================
set -uo pipefail

NS3="${NS3:-$HOME/ns-allinone-3.35/ns-3.35}"
PROJ="${PROJ:-$HOME/Niranga/MPTD-PQS-SDVN}"
cd "$NS3"
export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:${LD_LIBRARY_PATH:-}"

ATTACKS=(1 2 3 4 5 6 7)
PCTS=(30 60 90)
SIMTIME=30
SPEED=60

RES="$NS3/analytics/results"
SWEEP="$RES/sweep"
DATASETS="$NS3/analytics/datasets"
LIVE="$PROJ/live_results"
SIMLOG="$NS3/scratch/mptd_pqs_sdvn/sim_live.log"
RESULTS_CSV="$LIVE/global_heldout_results.csv"
mkdir -p "$SWEEP" "$DATASETS" "$LIVE"

ts()  { date '+%H:%M:%S'; }
log() { echo "[$(ts)] $*"; }

run_sim() {  # atk pct mode rng
  { echo "=========="; echo "[$(ts)] SIM a$1_p$2 mode=$3 RngRun=$4"; echo "=========="; } > "$SIMLOG"
  ./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=135 \
    --skip_blockchain=true --ablation_mode=$3 --attack_number=$1 \
    --attack_percentage=$2 --maxspeed=$SPEED --simTime=$SIMTIME --RngRun=$4" \
    >> "$SIMLOG" 2>&1
}

log "build check..."
./waf build >/dev/null 2>&1 && log "build OK" || { log "BUILD FAILED — abort"; exit 1; }

# ── PHASE A: training data (RngRun=1, mode=1) ───────────────────────────────
log "===== PHASE A: training data (RngRun=1, mode=1) ====="
for atk in "${ATTACKS[@]}"; do for pct in "${PCTS[@]}"; do
  d="$DATASETS/a${atk}_p${pct}"
  if [ -f "$d/beacon_log.csv" ]; then log "[A] SKIP a${atk}_p${pct} (dataset exists)"; continue; fi
  log "[A] a${atk}_p${pct}"
  if run_sim "$atk" "$pct" 1 1; then
    mkdir -p "$d"
    cp "$RES/beacon_log.csv" "$d/" 2>/dev/null || log "  WARN: no beacon_log a${atk}_p${pct}"
    for f in tp_s1_poison_log.csv vehicle_tx_log.csv ghost_identity_log.csv \
             mitm_intercept_log.csv controller_poison_log.csv metrics.csv; do
      cp "$RES/$f" "$d/" 2>/dev/null || true
    done
  else
    log "  FAILED a${atk}_p${pct} (PHASE A)"
  fi
done; done

# ── TRAIN + FREEZE the global models ────────────────────────────────────────
log "===== TRAIN + FREEZE global RF (all available attacks) ====="
( cd "$PROJ" && NS3="$NS3" python3 global_baseline_eval.py 2>&1 | tail -40 )

# ── PHASE C: held-out scoring of the FROZEN model (RngRun=2) ────────────────
log "===== PHASE C: held-out scoring (RngRun=2) ====="
rm -f "$RESULTS_CSV"   # fresh: all rows from the just-frozen model
for atk in "${ATTACKS[@]}"; do for pct in "${PCTS[@]}"; do
  s="a${atk}_p${pct}"
  m6="$SWEEP/metrics_a${atk}_p${pct}_s60_m6.csv"
  if [ -f "$m6" ]; then
    log "[C m6] SKIP ${s} (B1 metrics exist)"
  else
    log "[C m6] ${s} (B1 Ghaleb)"
    run_sim "$atk" "$pct" 6 2 || log "  FAILED ${s} (m6)"
  fi
  log "[C m1] ${s} (MPTD held-out + B2/B3 predict)"
  if run_sim "$atk" "$pct" 1 2; then
    ( cd "$PROJ" && NS3="$NS3" python3 global_heldout_eval.py predict "$atk" "$pct" 2>&1 | tail -6 ) \
      || log "  WARN predict failed ${s}"
  else
    log "  FAILED ${s} (m1)"
  fi
done; done

# ── PLOT ────────────────────────────────────────────────────────────────────
log "regenerating per-attack chart..."
( cd "$PROJ" && NS3="$NS3" python3 global_heldout_eval.py plot 2>&1 | tail -60 )
log "===== GLOBAL PIPELINE (all attacks) DONE ====="
log "Frozen models: $NS3/models_global/"
log "Per-attack chart: $LIVE/global_heldout_perattack.png"
log "Averaged chart:   $LIVE/global_baseline_vs_pct.png"
