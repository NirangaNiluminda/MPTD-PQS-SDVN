#!/usr/bin/env bash
# ============================================================
# sweep_training_data.sh — R7c training-data generator (R7g.3 revision)
# ============================================================
# Runs the NS-3 sim across attack {1..7} × pct {10,30,50} PLUS a set of
# clean-baseline runs (pct=0) and concatenates every beacon_log.csv into one
# master training file. The base sim overwrites the per-run beacon_log.csv
# every invocation, so we copy it aside before the next run launches.
#
# R7g.3 changes:
#   - Add PCTS=0 clean-baseline runs (the original sweep had ZERO all-clean
#     snapshots — see ae_calibration_audit.py output — which starved both the
#     LSTM-AE training set and the GAT class balance).
#   - Pass --skip_blockchain=true so the sweep does NOT depend on a working
#     Hyperledger Fabric environment. Detection + beacon logging still run.
#   - Run baseline (pct=0) under each attack variant so AE windows for each
#     attack number have proper clean counterparts.
#
# Output: analytics/ml/data/beacon_train_master.csv
# Usage:  bash sweep_training_data.sh [simTime=20]
# ============================================================
set -euo pipefail

SIMTIME="${1:-20}"
NS3_ROOT="/home/niranga/ns-allinone-3.35/ns-3.35"
RESULTS="${NS3_ROOT}/analytics/results"
OUT_DIR="${NS3_ROOT}/analytics/ml/data"
MASTER="${OUT_DIR}/beacon_train_master.csv"

mkdir -p "${OUT_DIR}"
rm -f "${MASTER}"

ATTACKS=(1 2 3 4 5 6 7)
# R7g.3: include 0 (clean baseline) so the AE has a non-trivial clean window
# pool and the GAT sees class-balanced snapshots.
PCTS=(0 10 30 50)

cd "${NS3_ROOT}"

FIRST=1
for atk in "${ATTACKS[@]}"; do
  for pct in "${PCTS[@]}"; do
    echo "[sweep] attack=${atk}  pct=${pct}  simTime=${SIMTIME}"
    python3 waf --run "mptd_pqs_sdvn --attack_number=${atk} --routing_algorithm=4 \
      --routing_test=true --attack_percentage=${pct} --simTime=${SIMTIME} \
      --skip_blockchain=true" \
      > "/tmp/sweep_a${atk}_p${pct}.log" 2>&1 || {
        echo "[sweep] sim failed for atk=${atk} pct=${pct} — see log"
        continue
      }
    src="${RESULTS}/beacon_log.csv"
    if [ ! -f "${src}" ]; then
      echo "[sweep] beacon_log.csv missing after atk=${atk} pct=${pct}"
      continue
    fi
    if [ "${FIRST}" = "1" ]; then
      cp "${src}" "${MASTER}"
      FIRST=0
    else
      tail -n +2 "${src}" >> "${MASTER}"
    fi
  done
done

ROWS=$(wc -l < "${MASTER}")
echo "[sweep] master CSV: ${MASTER}  (${ROWS} rows)"
