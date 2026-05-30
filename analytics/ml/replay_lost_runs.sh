#!/usr/bin/env bash
# ============================================================
# replay_lost_runs.sh — Re-run sweep iterations that lost to the
# R8 source-edit race (sweep was active while 06b1_trs_backend.h
# was being rewritten; intermediate broken states made waf reject
# the build, which propagated as `sim failed` for those runs).
# ============================================================
# What's missing from beacon_train_master.csv (per
# pandas group-by audit):
#   a3_p30, a3_p50
#   a4_p0, a4_p10, a4_p30, a4_p50
#   a5_p0, a5_p10, a5_p30, a5_p50
#   a6_p0, a6_p10, a6_p30, a6_p50
#   a7_p0, a7_p10, a7_p30
# Total: 17 runs. Per-run cost ≈ 80-90 s after first warm load.
# ETA: ~25-30 min.
#
# This script APPENDS to the existing master CSV (does not delete
# it) so the 11 already-good runs are preserved. Each new sim's
# beacon_log.csv contributes only its data rows (header stripped).
# ============================================================
set -euo pipefail

SIMTIME="${1:-12}"
NS3_ROOT="/home/niranga/ns-allinone-3.35/ns-3.35"
RESULTS="${NS3_ROOT}/analytics/results"
OUT_DIR="${NS3_ROOT}/analytics/ml/data"
MASTER="${OUT_DIR}/beacon_train_master.csv"

if [ ! -f "${MASTER}" ]; then
    echo "[replay] ERROR: master CSV does not exist at ${MASTER}"
    echo "[replay]   Run sweep_training_data.sh first to seed it."
    exit 1
fi

cd "${NS3_ROOT}"

# Tuples to replay: (attack, pct)
TUPLES=(
    "3 30" "3 50"
    "4 0"  "4 10" "4 30" "4 50"
    "5 0"  "5 10" "5 30" "5 50"
    "6 0"  "6 10" "6 30" "6 50"
    "7 0"  "7 10" "7 30"
)

n_done=0
n_fail=0
for t in "${TUPLES[@]}"; do
    read -r atk pct <<< "${t}"
    echo "[replay] attack=${atk} pct=${pct} simTime=${SIMTIME}"
    python3 waf --run "mptd_pqs_sdvn --attack_number=${atk} --routing_algorithm=4 \
      --routing_test=true --attack_percentage=${pct} --simTime=${SIMTIME} \
      --skip_blockchain=true" \
      > "/tmp/replay_a${atk}_p${pct}.log" 2>&1 || {
        echo "[replay] sim failed for atk=${atk} pct=${pct} — see /tmp/replay_a${atk}_p${pct}.log"
        n_fail=$((n_fail + 1))
        continue
    }
    src="${RESULTS}/beacon_log.csv"
    if [ ! -f "${src}" ]; then
        echo "[replay] beacon_log.csv missing after atk=${atk} pct=${pct}"
        n_fail=$((n_fail + 1))
        continue
    fi
    tail -n +2 "${src}" >> "${MASTER}"
    n_done=$((n_done + 1))
done

ROWS=$(wc -l < "${MASTER}")
echo "[replay] complete: ${n_done} succeeded, ${n_fail} failed"
echo "[replay] master CSV: ${MASTER}  (${ROWS} rows)"
