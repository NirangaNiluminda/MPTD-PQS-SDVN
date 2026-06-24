#!/usr/bin/env bash
# =============================================================================
# capture_crypto_evidence.sh
# Proves the NIST-L5 crypto (ML-DSA-87 TRS + OpenFHE BFV threshold-FHE + LKH)
# runs INSIDE the ns-3 simulation on LIVE beacon traffic — not just at startup.
#
# Produces two files in $OUT:
#   crypto_in_ns3_live.log   - full ns-3 run output (build + sim)
#   EVIDENCE_crypto_ns3.txt  - extracted proof lines for the professor
# =============================================================================
set -uo pipefail

NS3="${NS3:-$HOME/ns-allinone-3.35/ns-3.35}"
OUT="${OUT:-$HOME/crypto_evidence_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUT"
LOG="$OUT/crypto_in_ns3_live.log"
EV="$OUT/EVIDENCE_crypto_ns3.txt"

cd "$NS3" || { echo "ns-3 path not found: $NS3"; exit 1; }
export MPTD_CRYPTO_SELFTEST=1
export LD_LIBRARY_PATH="$PWD/build/lib:$HOME/.local/lib:${LD_LIBRARY_PATH:-}"

echo "=== [1/3] Building scratch program (crypto linked into ns-3) ==="
./waf build 2>&1 | tee "$LOG"

echo ""
echo "=== [2/3] Running LIVE simulation with traffic + attack + self-test ==="
# Real-network parameters (from run_real_network.sh): 200 vehicles, 64 RSUs,
# attack scenario 1 (compromised RSU) at 40%, 10s sim, fixed RngRun for repeatability.
./waf --run "mptd_pqs_sdvn --mobility_source=1 --N_RSUs=64 --N_Vehicles=200 \
  --attack_number=1 --attack_percentage=40 --maxspeed=60 --simTime=10 --RngRun=2" \
  2>&1 | tee -a "$LOG"

echo ""
echo "=== [3/3] Extracting evidence ==="
{
  echo "############################################################"
  echo "# EVIDENCE: NIST Level 5 crypto executing INSIDE ns-3"
  echo "# Host : $(hostname)"
  echo "# Date : $(date)"
  echo "# ns-3 : $NS3"
  echo "# Run  : mptd_pqs_sdvn  attack=1  pct=40  N_Veh=200  N_RSU=64  simTime=10"
  echo "############################################################"
  echo ""
  echo "===== (A) L5 PRIMITIVES INITIALISED + SELF-TEST (inside ns-3 main) ====="
  grep -E "CRYPTO/(TRS|FHE|THFHE|SELFTEST)|ML-DSA-87|HEStd_256_quantum|n=4 t=3|passed, .* failed" "$LOG" || echo "  (none found)"
  echo ""
  echo "===== (B) LKH / LOGICAL KEY HIERARCHY ACTIVE ====="
  grep -E "\[LKH\]" "$LOG" | head -20 || echo "  (none found)"
  echo ""
  echo "===== (C) CRYPTO ON LIVE BEACON TRAFFIC (proves it runs during the sim) ====="
  grep -E "TRS-verify|PARR|PBPO|SC-Register|CP-DETECT|IPFS" "$LOG" || echo "  (none found)"
  echo ""
  echo "===== (D) NON-ZERO SIMULATION ACTIVITY (proves traffic actually flowed) ====="
  grep -E "Trajectories received|Trajectories poisoned|Blockchain records|Attack number|Attack percentage" "$LOG" || echo "  (none found)"
  echo ""
  echo "===== (E) RESULT FILES ====="
  grep -E "Results CSV|Beacon log" "$LOG" || echo "  (none found)"
} | tee "$EV"

echo ""
echo "============================================================"
echo " DONE."
echo "   Full log : $LOG"
echo "   Evidence : $EV"
echo "============================================================"
echo ""
echo ">>> SANITY CHECK before sending to your professor:"
echo "    Section (D) must show NON-ZERO 'Trajectories received' and"
echo "    'Blockchain records'. If they are 0, the crypto did not run on"
echo "    live packets — see troubleshooting notes."