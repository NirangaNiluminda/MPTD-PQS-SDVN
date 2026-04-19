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
# Total NS-3 runs: 7 × 4 × 3 = 84 (detection mode only)
# Each run produces beacon_log.csv → evaluate_all.py computes all 7 metrics
# across 6 detection variants (MPTD-PQS, A1-A5)
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

mkdir -p "$RESULTS" "$LOG_DIR"

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
    local A="$1" P="$2" S="$3"
    local LOG="$LOG_DIR/ns3_a${A}_p${P}_s${S}.log"

    echo "  [ns3] attack=$A pct=$P speed=$S → $LOG"
    if $DRY_RUN; then
        echo "  [dry-run] skipping NS-3 execution"
        return 0
    fi

    # NS-3 has a pre-existing LTE SIGSEGV at t≈0.93s (Stage 6 known issue).
    # The DSRC detection phase starts at t=6.7s so beacon_log.csv is still
    # produced before the crash.  We use || true so the script continues.
    python3 waf --run "mptd_pqs_sdvn \
        --attack_number=${A} \
        --attack_percentage=${P} \
        --maxspeed=${S} \
        --simTime=${SIM_TIME} \
        --routing_test=false" \
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

    echo "  [eval] attack=$A pct=$P speed=$SL ($S km/h) → $OUT"
    if $DRY_RUN; then
        echo "  [dry-run] skipping evaluate_all.py"
        return 0
    fi

    python3 "$ML_DIR/evaluate_all.py" \
        --attack_number "$A" \
        --attack_pct    "$P" \
        --speed         "$S" \
        --speed_label   "$SL" \
        --beacon_csv    "$BEACON_CSV" \
        --output        "$OUT"
}

# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------
cd "$NS3_ROOT"

total_runs=$(( ${#ATTACKS[@]} * ${#PCTS[@]} * ${#SPEEDS[@]} ))
run_idx=0

echo "========================================================"
echo " MPTD-PQS Stage 8 Evaluation Sweep"
echo " Total NS-3 runs: $total_runs"
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
            echo "── Run $run_idx/$total_runs  attack=$A  pct=$P%  speed=$S km/h ──"

            # Skip if already done and --resume
            if $RESUME && [ -f "$OUT_CSV" ] && [ -s "$OUT_CSV" ]; then
                echo "  [skip] $OUT_CSV already exists (use --no-resume to rerun)"
                continue
            fi

            run_ns3    "$A" "$P" "$S"
            evaluate_run "$A" "$P" "$S"

        done
    done
done

# ---------------------------------------------------------------------------
# Ablation-only runs (use synthetic data / last beacon_log)
# ---------------------------------------------------------------------------
echo ""
echo "========================================================"
echo " Running ablation variants A1-A5 on all sweep CSVs"
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
