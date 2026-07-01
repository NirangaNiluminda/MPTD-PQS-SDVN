#!/usr/bin/env bash
# =============================================================================
# run_all_scenarios.sh — full evaluation sweep across the THREE SUMO scenarios
#
#   urban   (scenario 0)  — low-speed regime    60 km/h, 135 veh, 64 RSU
#   rural   (scenario 1)  — mid-speed regime    90 km/h, 138 veh, 44 RSU
#   highway (scenario 2)  — high-speed regime  150 km/h, 200 veh, 23 RSU
#                           (trace tag = "autobahn")
#
# For each scenario it loops over attacks x percentages x ablation modes and
# runs the ns-3 binary with the SUMO mobility trace for that scenario.
#
# ── OUTPUT FOLDERS (the whole point of this script) ──────────────────────────
# Output segregation is done INSIDE the binary, keyed off --mobility_scenario
# via mptd_scenario_name() (10_metrics_csv.h). Provided NS3_ROOT/DATASET_ROOT are
# correct for THIS machine, every run lands in:
#
#   $NS3/analytics/results/<urban|rural|highway>/        ← detailed per-run logs
#       beacon_log.csv, tp_s1_poison_log.csv, ... (TRUNCATED each run)
#   $NS3/analytics/results/sweep/metrics_aN_pP_sSPD_mM.csv  ← master metric row
#   $PROJ/analytics/datasets/<scenario>/aN_pP/           ← committable archive
#       beacon_log.csv + attacker-detail + metrics.csv  (per attack x pct)
#
# The master metrics file (results/sweep/) is the ONE path the binary does NOT
# tag with the scenario name. Two scenarios that share a --maxspeed would there-
# fore collide there. We avoid that two ways: (a) the three scenarios use three
# DISTINCT speeds (60/90/150 -> s60/s90/s150), and (b) this script ALSO copies
# each metrics file into results/sweep/<scenario>/ so provenance is explicit.
#
# ── CRITICAL: compile-time paths ─────────────────────────────────────────────
# NS3_ROOT / FAB_ROOT / DATASET_ROOT are #defines in 02_config_globals.h, baked
# in at BUILD time — a runtime flag cannot move the output. The committed values
# target a dev VM (/home/vboxuser/...). This script rewrites them to match THIS
# node before building, so output goes to the correct folder. (Leaves the source
# file modified on disk; that is expected — the committed value is for a
# different machine. Do not commit the path edit.)
#
# Usage:
#   ./run_all_scenarios.sh                  # all scenarios, default sweep
#   SCN="rural highway" ./run_all_scenarios.sh   # subset of scenarios
#   ATTACKS="1 4 7" PCTS="20" MODES="1" ./run_all_scenarios.sh
#   SKIP_BC=false ./run_all_scenarios.sh    # live-blockchain regime (needs Fabric up)
# =============================================================================
set -uo pipefail

# ── Per-node paths (override via env if your layout differs) ──────────────────
NS3="${NS3:-$HOME/ns-allinone-3.35/ns-3.35}"
PROJ="${PROJ:-$HOME/Niranga/MPTD-PQS-SDVN}"
FAB="${FAB:-$HOME/fabric-samples}"
CFG="$PROJ/scratch/mptd_pqs_sdvn/02_config_globals.h"

# ── Sweep dimensions (override via env) ───────────────────────────────────────
ATTACKS=(${ATTACKS:-1 2 3 4 5 6 7})
PCTS=(${PCTS:-0 20 40 60 80 100})   # 0 = clean baseline; 100 = all selected attackers
MODES=(${MODES:-1})            # 1=A1 LW-only (enough for the dataset); 0=Full, 2=GAT, 3=AE, 4=no-PQ, 5=no-BC, 6=B1
SIMTIME="${SIMTIME:-30}"
SKIP_BC="${SKIP_BC:-true}"     # true = detection sweep (no Fabric); false = live BC
# Per-run wall-clock cap (seconds). Feasible runs finish in ~29 min; the highway
# scenario at 200 veh can drive the ns-3.35 WiFi PHY into an infinite zero-time
# event loop (spins at 100% CPU, sim clock frozen) — those runs are killed after
# this cap and logged as JAMMED so the sweep continues instead of hanging forever.
# -k grace: if the spinning process ignores SIGTERM, SIGKILL follows 30 s later.
RUN_TIMEOUT="${RUN_TIMEOUT:-2700}"

# ── Scenario table: name | scenario_id | maxspeed | N_Vehicles | N_RSUs ───────
# maxspeed MUST match an existing mobility/mobility_<tag>_<speed>.tcl or the
# binary silently falls back to the 16-vehicle hardcoded provider.
SCN_NAMES=(urban   rural   highway)
SCN_IDS=(   0       1       2)
SCN_SPEED=( 60      90      150)
SCN_NVEH=(  135     138     200)
SCN_NRSU=(  64      44      23)

# Which scenarios to run (default all three). Match against SCN_NAMES.
WANT="${SCN:-urban rural highway}"

ts() { date '+%H:%M:%S'; }
log() { echo "[$(ts)] $*"; }

# ── 1) Patch compile-time paths to THIS node (idempotent) ─────────────────────
patch_paths() {
  [ -f "$CFG" ] || { log "FATAL: config not found: $CFG"; exit 1; }
  local changed=0
  patch1() { # macro value
    local cur; cur=$(grep -E "^#define $1 " "$CFG" | head -1 | sed -E 's/.*"(.*)".*/\1/')
    if [ "$cur" != "$2" ]; then
      sed -i -E "s|^#define $1 .*|#define $1 \"$2\"|" "$CFG"
      log "  patched $1: \"$cur\" -> \"$2\""
      changed=1
    fi
  }
  patch1 NS3_ROOT     "$NS3"
  patch1 FAB_ROOT     "$FAB"
  patch1 DATASET_ROOT "$PROJ"
  [ "$changed" -eq 1 ] && log "  (02_config_globals.h modified for this node — do NOT commit)" \
                        || log "  paths already correct"
}

log "===== run_all_scenarios.sh ====="
log "NS3=$NS3"
log "PROJ=$PROJ"
log "scenarios='$WANT'  attacks='${ATTACKS[*]}'  pcts='${PCTS[*]}'  modes='${MODES[*]}'  skip_bc=$SKIP_BC"

log "checking compile-time paths..."
patch_paths

# ── 2) Build (only my target; the shared scratch dir has unrelated programs) ──
# NOTE: we build with --targets=mptd_pqs_sdvn and then invoke the compiled binary
# DIRECTLY in the loop (not `./waf --run`). `./waf --run` forces a FULL build of
# every scratch program, and a sibling program (scratch/routing.cc) is currently
# broken (missing paillier_he.h) — it would abort all our runs. Direct invocation
# bypasses that entirely.
cd "$NS3"
export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:$HOME/.local/lib64:${LD_LIBRARY_PATH:-}"
BIN="$NS3/build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn"
log "building mptd_pqs_sdvn..."
if ./waf build --targets=mptd_pqs_sdvn >/tmp/run_all_build.log 2>&1; then
  log "build OK"
else
  log "BUILD FAILED — see /tmp/run_all_build.log"; tail -15 /tmp/run_all_build.log; exit 1
fi
[ -x "$BIN" ] || { log "FATAL: binary not found after build: $BIN"; exit 1; }

RES="$NS3/analytics/results"
mkdir -p "$RES/sweep"

# ── 3) Sweep ──────────────────────────────────────────────────────────────────
TOTAL=0; DONE=0; FAILED=0; SKIPPED=0; JAMMED=0
for name in $WANT; do
  for m in "${MODES[@]}"; do for a in "${ATTACKS[@]}"; do for p in "${PCTS[@]}"; do
    TOTAL=$((TOTAL+1)); done; done; done
done
START=$(date +%s)
log "starting $TOTAL runs..."

for name in $WANT; do
  # resolve scenario tuple by name
  idx=-1
  for i in "${!SCN_NAMES[@]}"; do [ "${SCN_NAMES[$i]}" = "$name" ] && idx=$i; done
  if [ "$idx" -lt 0 ]; then log "WARN: unknown scenario '$name' — skipping"; continue; fi
  sid="${SCN_IDS[$idx]}"; spd="${SCN_SPEED[$idx]}"; nveh="${SCN_NVEH[$idx]}"; nrsu="${SCN_NRSU[$idx]}"

  # trace presence check — fail loud instead of silent hardcoded fallback
  tag=$([ "$name" = "highway" ] && echo autobahn || echo "$name")
  trace="$NS3/mobility/mobility_${tag}_${spd}.tcl"
  if [ ! -f "$trace" ]; then
    log "WARN: missing trace $trace — scenario '$name' would fall back to hardcoded; SKIPPING scenario"
    continue
  fi
  mkdir -p "$RES/sweep/$name"
  log "── scenario=$name (id=$sid, $spd km/h, $nveh veh, $nrsu RSU) ─────────────"

  for m in "${MODES[@]}"; do for a in "${ATTACKS[@]}"; do for p in "${PCTS[@]}"; do
    DONE=$((DONE+1))
    metrics="$RES/sweep/metrics_a${a}_p${p}_s${spd}_m${m}.csv"   # binary writes here
    tagged="$RES/sweep/$name/metrics_a${a}_p${p}_s${spd}_m${m}.csv"  # our per-scenario copy

    if [ -f "$tagged" ]; then
      SKIPPED=$((SKIPPED+1))
      log "SKIP  $DONE/$TOTAL  $name a=$a p=$p m=$m (exists)"
      continue
    fi

    log "RUN   $DONE/$TOTAL  $name a=$a p=$p m=$m ..."
    timeout -k 30 "$RUN_TIMEOUT" "$BIN" \
          --mobility_source=1 \
          --mobility_scenario=$sid \
          --maxspeed=$spd \
          --N_Vehicles=$nveh \
          --N_RSUs=$nrsu \
          --skip_blockchain=$SKIP_BC \
          --ablation_mode=$m \
          --attack_number=$a \
          --attack_percentage=$p \
          --simTime=$SIMTIME >/tmp/run_all_sim.log 2>&1
    rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
      JAMMED=$((JAMMED+1))
      log "  -> JAMMED: killed after ${RUN_TIMEOUT}s (ns-3.35 WiFi PHY overload, rc=$rc) — $name a=$a p=$p"
    elif [ "$rc" -eq 0 ] && [ -f "$metrics" ]; then
      cp "$metrics" "$tagged"                         # provenance-tagged copy
      MCC=$(tail -1 "$metrics" | cut -d',' -f10)
      FPR=$(tail -1 "$metrics" | cut -d',' -f11)
      log "  -> MCC=$MCC FPR=$FPR  (results/$name/, datasets/$name/a${a}_p${p}/)"
    elif [ "$rc" -eq 0 ]; then
      FAILED=$((FAILED+1))
      log "  -> WARN: no metrics file written (mobility/path fallback?). See /tmp/run_all_sim.log"
    else
      FAILED=$((FAILED+1))
      log "  -> FAILED rc=$rc (see /tmp/run_all_sim.log)"; tail -8 /tmp/run_all_sim.log
    fi

    NOW=$(date +%s); EL=$((NOW-START))
    if [ "$DONE" -gt 0 ] && [ "$EL" -gt 0 ]; then
      ETA=$(( (TOTAL-DONE) * EL / DONE )); log "  -> progress $DONE/$TOTAL  ETA ~$((ETA/60))m"
    fi
  done; done; done
done

EL=$(( $(date +%s) - START ))
log "===== DONE: $DONE runs in $((EL/60))m$((EL%60))s  (skipped=$SKIPPED failed=$FAILED jammed=$JAMMED) ====="
log "per-scenario logs : $RES/<urban|rural|highway>/"
log "per-scenario metric: $RES/sweep/<scenario>/metrics_*.csv"
log "committable dataset: $PROJ/analytics/datasets/<scenario>/aN_pP/"
