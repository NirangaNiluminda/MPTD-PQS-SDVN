#!/usr/bin/env bash
set -euo pipefail

NS3_ROOT="/home/vboxuser/ns-allinone-3.35/ns-3.35"
ML_DATA_DIR="/home/vboxuser/Desktop/MPTD-PQS-SDVN/analytics/ml/data"

mkdir -p "${ML_DATA_DIR}"

echo "============================================================"
echo "Generating clean training data for URBAN scenario..."
echo "============================================================"
cd "${NS3_ROOT}"
python3 waf --run "mptd_pqs_sdvn \
  --attack_number=1 \
  --routing_algorithm=4 \
  --routing_test=true \
  --attack_percentage=0 \
  --simTime=15 \
  --skip_blockchain=true \
  --mobility_scenario=0 \
  --mobility_source=1 \
  --maxspeed=150 \
  --N_Vehicles=200" 2>&1

if [ -f "${NS3_ROOT}/analytics/results/beacon_log.csv" ]; then
    cp "${NS3_ROOT}/analytics/results/beacon_log.csv" "${ML_DATA_DIR}/beacon_clean_urban.csv"
    echo "Saved clean urban data to ${ML_DATA_DIR}/beacon_clean_urban.csv"
else
    echo "[ERROR] beacon_log.csv not found after urban simulation!"
    exit 1
fi

echo "============================================================"
echo "Generating clean training data for RURAL scenario..."
echo "============================================================"
python3 waf --run "mptd_pqs_sdvn \
  --attack_number=1 \
  --routing_algorithm=4 \
  --routing_test=true \
  --attack_percentage=0 \
  --simTime=15 \
  --skip_blockchain=true \
  --mobility_scenario=1 \
  --mobility_source=1 \
  --maxspeed=90 \
  --N_Vehicles=138" 2>&1

if [ -f "${NS3_ROOT}/analytics/results/beacon_log.csv" ]; then
    cp "${NS3_ROOT}/analytics/results/beacon_log.csv" "${ML_DATA_DIR}/beacon_clean_rural.csv"
    echo "Saved clean rural data to ${ML_DATA_DIR}/beacon_clean_rural.csv"
else
    echo "[ERROR] beacon_log.csv not found after rural simulation!"
    exit 1
fi

echo "============================================================"
echo "Generating clean training data for HIGHWAY scenario..."
echo "============================================================"
python3 waf --run "mptd_pqs_sdvn \
  --attack_number=1 \
  --routing_algorithm=4 \
  --routing_test=true \
  --attack_percentage=0 \
  --simTime=15 \
  --skip_blockchain=true \
  --mobility_scenario=2 \
  --mobility_source=1 \
  --maxspeed=150 \
  --N_Vehicles=200" 2>&1

if [ -f "${NS3_ROOT}/analytics/results/beacon_log.csv" ]; then
    cp "${NS3_ROOT}/analytics/results/beacon_log.csv" "${ML_DATA_DIR}/beacon_clean_highway.csv"
    echo "Saved clean highway data to ${ML_DATA_DIR}/beacon_clean_highway.csv"
else
    echo "[ERROR] beacon_log.csv not found after highway simulation!"
    exit 1
fi

echo "Data generation complete!"
