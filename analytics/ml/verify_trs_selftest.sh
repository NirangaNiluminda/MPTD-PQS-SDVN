#!/usr/bin/env bash
# ============================================================
# verify_trs_selftest.sh — R8.3c in-tree TRS selftest validator.
# ============================================================
# Runs one tiny sim with MPTD_CRYPTO_SELFTEST=1 set, captures the
# selftest output block, and checks that all TRS-* assertions pass.
# Exit code 0 = all green; 1 = any TRS-* FAIL or selftest didn't run.
#
# Independent of training/replay sweeps — uses simTime=4 (faster than
# any beacon emission so it short-circuits cleanly) and a known-good
# attack_number / pct combo that won't exercise CP-DETECT producer
# paths (which would need R8.4 wiring before they have anything to
# verify).
#
# What we're actually verifying here vs the standalone smoke test:
#   - Standalone (/tmp/trs_smoke): the *cryptographic logic* of the
#     header in isolation, with a hand-stubbed LKH HMAC.
#   - This one: the *in-tree integration* — that the header compiled
#     into the NS-3 binary uses the SAME LKH_K_RING bytes (via the
#     real 00_lkh_keys.h pure-C++ HMAC), produces the SAME master_pk,
#     and that the OpenSSL EC link inside NS-3 works end-to-end.
# A mismatch here would indicate an include-order or link-graph bug
# that the standalone smoke would miss.
# ============================================================
set -euo pipefail

NS3_ROOT="/home/niranga/ns-allinone-3.35/ns-3.35"
LOG="/tmp/trs_selftest_in_tree.log"

cd "${NS3_ROOT}"
export MPTD_CRYPTO_SELFTEST=1

echo "[selftest] running tiny sim with MPTD_CRYPTO_SELFTEST=1..."
python3 waf --run "mptd_pqs_sdvn --attack_number=1 --routing_algorithm=4 \
  --routing_test=true --attack_percentage=0 --simTime=4 \
  --skip_blockchain=true" \
  > "${LOG}" 2>&1 || {
    echo "[selftest] sim run FAILED — see ${LOG} for build/runtime error"
    exit 1
}

# Extract the [CRYPTO/SELFTEST] block.
echo
echo "===== TRS selftest output ====="
sed -n '/\[CRYPTO\/SELFTEST\] starting/,/\[CRYPTO\/SELFTEST\] done/p' "${LOG}" || true
echo "==============================="
echo

# Count TRS-* PASS/FAIL lines.
# Note: `grep -c` exits non-zero when there are 0 matches; combined with
# `|| echo 0` the variable ends up "0\n0" which breaks the [ -gt ] check
# below and silently masks real FAILs. Use `|| true` + default-empty
# fallback to keep the result a clean integer in all cases.
n_trs_pass=$(grep -c '\[PASS\] TRS-' "${LOG}" 2>/dev/null || true)
n_trs_fail=$(grep -c '\[FAIL\] TRS-' "${LOG}" 2>/dev/null || true)
n_trs_pass="${n_trs_pass:-0}"
n_trs_fail="${n_trs_fail:-0}"

echo "[selftest] TRS results: ${n_trs_pass} PASS, ${n_trs_fail} FAIL"

if [ "${n_trs_fail}" -gt 0 ]; then
    echo "[selftest] FAILED — at least one TRS-* assertion did not pass"
    exit 1
fi
if [ "${n_trs_pass}" -lt 8 ]; then
    echo "[selftest] FAILED — expected ≥8 TRS-* PASS lines, got ${n_trs_pass}"
    echo "[selftest] (selftest probably never ran — check the output above)"
    exit 1
fi

echo "[selftest] OK — R8.3c in-tree validation green"
exit 0
