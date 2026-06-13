#!/usr/bin/env bash
# run_b1_sweep.sh — fill in B1 (Ghaleb, ablation_mode=6) metrics across attack %.
# B1 is rule-based (no training), so any run gives its metrics. Matches the
# attacks/pcts that the global B2/B3 models pooled (attacks 1-3 x p30/60/90).
# After the runs, regenerates the global comparison chart.
set -uo pipefail
NS3="${NS3:-$HOME/ns-allinone-3.35/ns-3.35}"
PROJ="${PROJ:-$HOME/Niranga/MPTD-PQS-SDVN}"
cd "$NS3"
export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:${LD_LIBRARY_PATH:-}"
SIMLOG="$NS3/scratch/mptd_pqs_sdvn/sim_live.log"
ts(){ date '+%H:%M:%S'; }
log(){ echo "[$(ts)] $*"; }

for atk in 1 2 3; do for pct in 30 60 90; do
  out="$NS3/analytics/results/sweep/metrics_a${atk}_p${pct}_s60_m6.csv"
  if [ -f "$out" ]; then log "SKIP a${atk}_p${pct} (m6 exists)"; continue; fi
  log "B1 run a${atk}_p${pct} (mode 6)"
  { echo "[$(ts)] B1 a${atk}_p${pct}"; } > "$SIMLOG"
  ./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=135 \
    --skip_blockchain=true --ablation_mode=6 --attack_number=${atk} \
    --attack_percentage=${pct} --maxspeed=60 --simTime=30 --RngRun=2" \
    >> "$SIMLOG" 2>&1 || log "  FAILED a${atk}_p${pct}"
done; done

log "regenerating global comparison chart..."
cd "$PROJ" && NS3="$NS3" python3 global_baseline_eval.py 2>&1 | tail -30
log "B1 sweep + chart refresh DONE"
