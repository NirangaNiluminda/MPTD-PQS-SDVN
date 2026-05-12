#!/usr/bin/env bash
# =============================================================================
# run_sweep.sh — MPTD-PQS Evaluation Sweep
# Runs all combinations required by RQ1–RQ6 of the paper.
#
# Usage:
#   ./run_sweep.sh            — full sweep (all modes, attacks, speeds, pcts)
#   ./run_sweep.sh quick      — critical subset only (A1 + B1, medium speed)
#   ./run_sweep.sh rq1        — RQ1 speed regime sweep (A1, all attacks, 3 speeds)
#
# Output: analytics/results/sweep/metrics_a{N}_p{P}_s{S}_m{M}.csv
#         (one file per run, never overwrites another combination)
#
# Total runs (full): 7 attacks × 4 pcts × 3 speeds × 4 modes = 336 runs
# Estimated time:    ~25s/run → ~140 min full, ~35 min quick
# =============================================================================

set -e
cd /home/niranga/ns-allinone-3.35/ns-3.35

# ── Parameters ────────────────────────────────────────────────────────────────
ATTACKS=(1 2 3 4 5 6 7)
PCTS=(5 10 20 30)          # attack_percentage → ρ_a ∈ {0.05, 0.10, 0.20, 0.30}
SPEEDS=(20 50 100)         # km/h: 20=urban(≤30), 50=suburban(30-80), 100=highway(>80)
SIMTIME=30                 # seconds per run (enough for steady-state metrics)

# Ablation modes:
#   1 = A1  Lightweight only (Rules + HMAC)          — default, answers RQ2/RQ3
#   4 = A4  Full detection, no TRS/FHE               — answers RQ5 (PARR comparison)
#   5 = A5  Full, no blockchain                      — answers RQ6 (BC contribution)
#   6 = B1  Ghaleb (2014) LTT baseline               — external comparison
MODES=(1 4 5 6)

# ── Mode selection ─────────────────────────────────────────────────────────────
MODE_ARG="${1:-full}"

case "$MODE_ARG" in
  quick)
    # Critical subset: A1 + B1, medium speed, all attacks & pcts
    MODES=(1 6)
    SPEEDS=(50)
    echo "[SWEEP] Mode: QUICK — A1+B1 baseline, medium speed (50 km/h)"
    ;;
  rq1)
    # RQ1: mobility amplification — A1 only, all speeds, 20% penetration
    MODES=(1)
    PCTS=(20)
    echo "[SWEEP] Mode: RQ1 — speed regime analysis (all speeds, 20% penetration, A1)"
    ;;
  rq5)
    # RQ5: TRS/PARR contribution — A1 vs A4 on RSU/MitM attacks
    MODES=(1 4)
    ATTACKS=(1 3 4 6)   # RSU-level + MitM attacks only
    SPEEDS=(50)
    echo "[SWEEP] Mode: RQ5 — PARR/TRS contribution (A1 vs A4)"
    ;;
  rq6)
    # RQ6: blockchain contribution — A1 vs A5 on controller attacks
    MODES=(1 5)
    ATTACKS=(5 7)        # controller-level attacks
    SPEEDS=(50)
    echo "[SWEEP] Mode: RQ6 — blockchain contribution (A1 vs A5)"
    ;;
  cder)
    # CDER Table: A1 vs A5 on ALL attacks (fills Table 5 completely)
    MODES=(1 5)
    PCTS=(20)
    SPEEDS=(50)
    echo "[SWEEP] Mode: CDER — A1 vs A5 (all attacks, pct=20%, speed=50 km/h)"
    ;;
  full|*)
    echo "[SWEEP] Mode: FULL — all 336 combinations"
    ;;
esac

# ── Ensure output directory ────────────────────────────────────────────────────
NS3_ROOT=/home/niranga/ns-allinone-3.35/ns-3.35
mkdir -p "${NS3_ROOT}/analytics/results/sweep"

# ── NS-3 build (once) ─────────────────────────────────────────────────────────
echo ""
echo "[SWEEP] ══════════════════════════════════════════════════════════"
echo "[SWEEP] Building simulation binary..."
echo "[SWEEP] ══════════════════════════════════════════════════════════"
python3 waf build 2>&1 | tail -5
echo "[SWEEP] Build OK"
echo ""

# ── Sweep ─────────────────────────────────────────────────────────────────────
TOTAL=$(( ${#ATTACKS[@]} * ${#PCTS[@]} * ${#SPEEDS[@]} * ${#MODES[@]} ))
DONE=0
FAILED=0
START_TS=$(date +%s)

echo "[SWEEP] Starting ${TOTAL} runs..."
echo "[SWEEP] ══════════════════════════════════════════════════════════"

for MODE in "${MODES[@]}"; do
  for ATK in "${ATTACKS[@]}"; do
    for PCT in "${PCTS[@]}"; do
      for SPD in "${SPEEDS[@]}"; do
        DONE=$((DONE + 1))
        OUTFILE="${NS3_ROOT}/analytics/results/sweep/metrics_a${ATK}_p${PCT}_s${SPD}_m${MODE}.csv"

        # Skip if already exists (resume interrupted sweep)
        if [ -f "$OUTFILE" ]; then
          echo "[SWEEP] SKIP ${DONE}/${TOTAL} a=${ATK} p=${PCT} s=${SPD} m=${MODE} (exists)"
          continue
        fi

        echo "[SWEEP] RUN  ${DONE}/${TOTAL} a=${ATK} p=${PCT} s=${SPD} m=${MODE}..."

        # Run simulation — output goes to /dev/null except errors
        if python3 waf --run \
              "mptd_pqs_sdvn \
              --routing_algorithm=4 \
              --routing_test=true \
              --attack_number=${ATK} \
              --attack_percentage=${PCT} \
              --maxspeed=${SPD} \
              --ablation_mode=${MODE} \
              --simTime=${SIMTIME}" \
              2>/dev/null ; then
          # Print the MCC from the generated CSV (last data line)
          if [ -f "$OUTFILE" ]; then
            MCC=$(tail -1 "$OUTFILE" | cut -d',' -f9)
            FPR=$(tail -1 "$OUTFILE" | cut -d',' -f10)
            echo "[SWEEP]  → MCC=${MCC}  FPR=${FPR}  ✓"
          fi
        else
          echo "[SWEEP]  → FAILED (exit $?)"
          FAILED=$((FAILED + 1))
        fi

        # Progress ETA
        NOW_TS=$(date +%s)
        ELAPSED=$((NOW_TS - START_TS))
        if [ "$DONE" -gt 0 ] && [ "$ELAPSED" -gt 0 ]; then
          RATE=$(echo "scale=2; $DONE / $ELAPSED" | bc 2>/dev/null || echo "?")
          REMAINING=$((TOTAL - DONE))
          ETA_S=$(echo "scale=0; $REMAINING / ($DONE / $ELAPSED)" | bc 2>/dev/null || echo "?")
          ETA_MIN=$(echo "scale=0; $ETA_S / 60" | bc 2>/dev/null || echo "?")
          echo "[SWEEP]  → Progress: ${DONE}/${TOTAL}  ETA: ~${ETA_MIN} min"
        fi

      done
    done
  done
done

END_TS=$(date +%s)
ELAPSED=$((END_TS - START_TS))

echo ""
echo "[SWEEP] ══════════════════════════════════════════════════════════"
echo "[SWEEP] DONE: ${DONE} runs in $((ELAPSED/60))m$((ELAPSED%60))s"
echo "[SWEEP] Failed: ${FAILED}"
echo "[SWEEP] Results in: scratch/mptd_pqs_sdvn/analytics/results/sweep/"
echo "[SWEEP] ══════════════════════════════════════════════════════════"
echo ""
echo "[SWEEP] Next step: run analyze_results.py to generate paper tables"
echo "  cd scratch/mptd_pqs_sdvn && python3 analyze_results.py"
