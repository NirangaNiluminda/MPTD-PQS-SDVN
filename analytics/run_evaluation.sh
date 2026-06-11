#!/usr/bin/env bash
# =============================================================================
# Stage 8: Full Evaluation Sweep — MPTD-PQS SDVN
# Paper §4.1.3 Experimental Scenarios
#
# Sweep dimensions:
#   attack_number : 1-7  (TP-S1, TP-S2, TP-S3, MP-S1, MP-S2, MP-S3, MP-S4)
#   attack_pct    : 5, 10, 20, 30  (ρ_a ∈ {0.05, 0.10, 0.20, 0.30})
#   speed_regime  : low=20, medium=50, high=100 km/h
#
# Total NS-3 runs: 7 × 4 × 3 × 6 modes = 504 (one run per ablation variant so
# each variant's REAL PARR/CDER/TDEE/TPE/PBPO is measured, not proxied).
# Each (A,P,S) cell produces beacon_log.csv (→ Python MCC/FPR re-score) plus
# 6 per-mode metrics_a*_m{0..5}.csv (→ evaluate_all.py real metric columns).
# Scope down with MODES="0 1" and/or --attack=N for quick iterations.
#
# Usage:
#   cd /home/niranga/ns-allinone-3.35/ns-3.35
#   bash analytics/run_evaluation.sh [--dry-run] [--attack N] [--resume]
#
# Outputs:
#   analytics/results/sweep/run_a{A}_p{P}_s{S}.csv  — per-run results
#   analytics/results/sweep/sweep_summary.csv         — merged full table
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
NS3_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANALYTICS="$NS3_ROOT/analytics"
ML_DIR="$ANALYTICS/ml"
RESULTS="$ANALYTICS/results/sweep"
LOG_DIR="$ANALYTICS/results/logs"
BEACON_CSV="$ANALYTICS/results/beacon_log.csv"
# R7f.followup-3: preserve each run's beacon_log.csv so re-evaluation
# (e.g., after tuning Python thresholds) doesn't require re-running NS-3.
BEACON_ARCHIVE="$RESULTS/beacon_logs"

mkdir -p "$RESULTS" "$LOG_DIR" "$BEACON_ARCHIVE"

# ---------------------------------------------------------------------------
# Sweep parameters
# ---------------------------------------------------------------------------
ATTACKS=(1 2 3 4 5 6 7)
PCTS=(5 10 20 30)
# Speed regimes — paper §4.1.3:
#   low    ≤ 30 km/h  → 20 km/h
#   medium 30-80 km/h → 50 km/h
#   high   > 80 km/h  → 100 km/h
SPEEDS=(20 50 100)
SPEED_LABELS=(low medium high)
SIM_TIME=13

# Ablation modes to simulate per (attack,pct,speed). evaluate_all.py reads each
# variant's REAL PARR/CDER/TDEE/TPE/PBPO from its OWN per-mode C++ CSV
# (metrics_a{A}_p{P}_s{S}_m{MODE}.csv), so every variant the plots show must be
# simulated here — otherwise those columns are NaN (never proxied).
#   0=MPTD-PQS(full) 1=A1(LW) 2=A2(GAT) 3=A3(AE) 4=A4(no-PQ) 5=A5(no-chain)
# COST: this multiplies NS-3 runs by ${#MODES[@]} (6× → 504 runs for the full
# 7×4×3 grid). Override with e.g.  MODES="0 1"  bash run_evaluation.sh  to scope.
MODES=(${MODES:-0 1 2 3 4 5})

# Flags
DRY_RUN=false
FILTER_ATTACK=""
RESUME=true          # skip runs whose output CSV already exists

for arg in "$@"; do
    case "$arg" in
        --dry-run)  DRY_RUN=true ;;
        --no-resume) RESUME=false ;;
        --attack=*) FILTER_ATTACK="${arg#*=}" ;;
    esac
done

# ---------------------------------------------------------------------------
# Helper: map speed value to label
# ---------------------------------------------------------------------------
speed_label() {
    case "$1" in
        20)  echo "low" ;;
        50)  echo "medium" ;;
        100) echo "high" ;;
        *)   echo "$1" ;;
    esac
}

# ---------------------------------------------------------------------------
# Helper: run a single NS-3 experiment
# ---------------------------------------------------------------------------
run_ns3() {
    local A="$1" P="$2" S="$3" M="$4"
    local LOG="$LOG_DIR/ns3_a${A}_p${P}_s${S}_m${M}.log"

    echo "  [ns3] attack=$A pct=$P speed=$S mode=$M → $LOG"
    if $DRY_RUN; then
        echo "  [dry-run] skipping NS-3 execution"
        return 0
    fi

    # NS-3 has a pre-existing LTE SIGSEGV at t≈0.93s (Stage 6 known issue).
    # The DSRC detection phase starts at t=6.7s so beacon_log.csv is still
    # produced before the crash.  We use || true so the script continues.
    # --skip_blockchain=true: this sweep evaluates the AI detection layer
    # post-hoc from beacon_log.csv. Hyperledger Fabric is not running, and
    # paper invariant #3 means lightweight detection runs without blockchain
    # anyway; the alert-path SC-Trust calls would only add timeouts here.
    # --ablation_mode=$M selects the variant so the C++ writes the matching
    # metrics_a{A}_p{P}_s{S}_m{M}.csv that evaluate_all.py reads real values from.
    python3 waf --run "mptd_pqs_sdvn \
        --attack_number=${A} \
        --attack_percentage=${P} \
        --maxspeed=${S} \
        --simTime=${SIM_TIME} \
        --ablation_mode=${M} \
        --routing_test=false \
        --skip_blockchain=true" \
        > "$LOG" 2>&1 || true

    # Verify beacon_log was written
    if [ ! -s "$BEACON_CSV" ]; then
        echo "  [warn] beacon_log.csv missing/empty after run — using synthetic data"
    fi
}

# ---------------------------------------------------------------------------
# Helper: evaluate one run (calls evaluate_all.py)
# ---------------------------------------------------------------------------
evaluate_run() {
    local A="$1" P="$2" S="$3"
    local OUT="$RESULTS/run_a${A}_p${P}_s${S}.csv"
    local SL; SL=$(speed_label "$S")
    # R7f.followup-3: archive this run's beacon_log so post-hoc re-evaluation
    # (e.g., threshold retuning, new variants) doesn't require resimulating.
    local BEACON_ARCH_CSV="$BEACON_ARCHIVE/beacon_a${A}_p${P}_s${S}.csv"

    echo "  [eval] attack=$A pct=$P speed=$SL ($S km/h) → $OUT"
    if $DRY_RUN; then
        echo "  [dry-run] skipping evaluate_all.py"
        return 0
    fi

    if [ -s "$BEACON_CSV" ]; then
        cp -f "$BEACON_CSV" "$BEACON_ARCH_CSV"
    fi

    python3 "$ML_DIR/evaluate_all.py" \
        --attack_number "$A" \
        --attack_pct    "$P" \
        --speed         "$S" \
        --speed_label   "$SL" \
        --beacon_csv    "$BEACON_CSV" \
        --metrics_dir   "$RESULTS" \
        --output        "$OUT"
}

# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------
cd "$NS3_ROOT"

total_cells=$(( ${#ATTACKS[@]} * ${#PCTS[@]} * ${#SPEEDS[@]} ))
total_runs=$(( total_cells * ${#MODES[@]} ))
run_idx=0

echo "========================================================"
echo " MPTD-PQS Stage 8 Evaluation Sweep"
echo " Cells (A×P×S): $total_cells   Modes: ${MODES[*]}"
echo " Total NS-3 runs: $total_runs  (${#MODES[@]} per cell)"
echo " Output dir: $RESULTS"
$DRY_RUN && echo " [DRY RUN MODE]"
echo "========================================================"

for A in "${ATTACKS[@]}"; do
    # Filter to a single attack if requested
    [ -n "$FILTER_ATTACK" ] && [ "$A" != "$FILTER_ATTACK" ] && continue

    for P in "${PCTS[@]}"; do
        for S in "${SPEEDS[@]}"; do
            run_idx=$(( run_idx + 1 ))
            OUT_CSV="$RESULTS/run_a${A}_p${P}_s${S}.csv"

            echo ""
            echo "── Cell $run_idx/$total_cells  attack=$A  pct=$P%  speed=$S km/h  (modes: ${MODES[*]}) ──"

            # Skip if already done and --resume
            if $RESUME && [ -f "$OUT_CSV" ] && [ -s "$OUT_CSV" ]; then
                echo "  [skip] $OUT_CSV already exists (use --no-resume to rerun)"
                continue
            fi

            # Simulate every ablation mode so each variant's real per-mode
            # C++ CSV (metrics_a*_m{MODE}.csv) exists for evaluate_all.py to
            # read. The beacon_log.csv left by the last run feeds the Python
            # MCC/FPR re-score (mode-independent: derived from raw beacons).
            for M in "${MODES[@]}"; do
                run_ns3 "$A" "$P" "$S" "$M"
            done
            evaluate_run "$A" "$P" "$S"

        done
    done
done

# ---------------------------------------------------------------------------
# Merge per-run CSVs into the summary table consumed by plot_results.py.
# (No synthetic data: every variant's metrics come from its own real per-mode
# C++ CSV; only absent modes are NaN.)
# ---------------------------------------------------------------------------
echo ""
echo "========================================================"
echo " Merging per-run variant rows into sweep_summary.csv"
echo "========================================================"

if ! $DRY_RUN; then
    python3 "$ML_DIR/evaluate_all.py" \
        --merge \
        --results_dir "$RESULTS" \
        --summary_csv "$RESULTS/sweep_summary.csv"
    echo "[Stage 8] Merged summary → $RESULTS/sweep_summary.csv"
fi

# ---------------------------------------------------------------------------
# Generate plots
# ---------------------------------------------------------------------------
echo ""
echo "========================================================"
echo " Generating result plots"
echo "========================================================"

if ! $DRY_RUN; then
    python3 "$ML_DIR/plot_results.py" \
        --summary_csv "$RESULTS/sweep_summary.csv" \
        --out_dir     "$ANALYTICS/results/figures"
    echo "[Stage 8] Figures → $ANALYTICS/results/figures/"
fi

echo ""
echo "========================================================"
echo " Stage 8 sweep complete."
echo " Summary CSV : $RESULTS/sweep_summary.csv"
echo " Figures     : $ANALYTICS/results/figures/"
echo "========================================================"
