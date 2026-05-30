#!/usr/bin/env bash
# =============================================================================
# fabric_invoke.sh — thin wrapper that lets the NS-3 RSU code submit chaincode
# transactions directly to the running Hyperledger Fabric test-network without
# going through any REST shim.
#
# Paper invariants satisfied:
#   • Invariant 1 — RSU→Blockchain direct (peer CLI talks to localhost:7051
#     endorser + localhost:7050 orderer via gRPC; no controller relay).
#   • Invariant 6 — no centralized bottleneck; per-RSU env scoping is identical
#     to a per-RSU Fabric Gateway client.
#
# This is the **interim** transport.  The production path is the C++ Fabric
# Gateway gRPC client (separate task).  Replacing this script with the gRPC
# client should be a no-op for callers, since both speak the same chaincode
# function signatures.
#
# Usage:
#   fabric_invoke.sh invoke <funcName> <arg1> <arg2> ...
#   fabric_invoke.sh query  <funcName> <arg1> <arg2> ...
#
# Env overrides:
#   FABRIC_TN_DIR   — fabric-samples/test-network path (default: standard install)
#   FABRIC_CHANNEL  — channel name              (default: mychannel)
#   FABRIC_CCNAME   — chaincode name            (default: trajectory)
#   FABRIC_ORG      — org index (1 or 2)        (default: 1)
#
# Output:
#   stdout: JSON payload returned by the chaincode (queries) or empty (invokes)
#   exit  : 0 on success, non-zero on failure
# =============================================================================
set -euo pipefail

FABRIC_TN_DIR="${FABRIC_TN_DIR:-/home/niranga/fabric-samples/test-network}"
FABRIC_CHANNEL="${FABRIC_CHANNEL:-mychannel}"
FABRIC_CCNAME="${FABRIC_CCNAME:-trajectory}"
FABRIC_ORG="${FABRIC_ORG:-1}"

if [ ! -d "$FABRIC_TN_DIR" ]; then
    echo "[fabric_invoke] FABRIC_TN_DIR not found: $FABRIC_TN_DIR" >&2
    exit 64
fi

cd "$FABRIC_TN_DIR"

# fabric-samples expects FABRIC_CFG_PATH to point at ../config/
export FABRIC_CFG_PATH="$FABRIC_TN_DIR/../config/"
export PATH="$FABRIC_TN_DIR/../bin:$PATH"

# envVar.sh dereferences $OVERRIDE_ORG and $VERBOSE without prior definition.
# Under `set -u` that's a fatal error, so pre-declare them as empty before
# sourcing. Sourcing is to stderr so the chatty banners don't pollute stdout.
export OVERRIDE_ORG=""
export VERBOSE=""
# shellcheck disable=SC1091
source "$FABRIC_TN_DIR/scripts/envVar.sh" >&2

# Override hostname resolution that the script assumes
export ORDERER_CA="$FABRIC_TN_DIR/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"
export PEER0_ORG1_CA="$FABRIC_TN_DIR/organizations/peerOrganizations/org1.example.com/tlsca/tlsca.org1.example.com-cert.pem"
export PEER0_ORG2_CA="$FABRIC_TN_DIR/organizations/peerOrganizations/org2.example.com/tlsca/tlsca.org2.example.com-cert.pem"

setGlobals "$FABRIC_ORG" >&2

ACTION="${1:-}"
FN="${2:-}"
if [ -z "$ACTION" ] || [ -z "$FN" ]; then
    echo "[fabric_invoke] usage: $0 invoke|query <funcName> [args...]" >&2
    exit 65
fi
shift 2

# Build the {"Args":[FN, arg1, ...]} JSON; quote every entry as a JSON string.
# fabric-contract-api-go treats Args[0] as the function name and forwards
# Args[1:] to the matched function — so we MUST NOT also include a top-level
# `"function"` key, and Args[0] is the function name (not a real arg).
ARGS_JSON='"'"$FN"'"'
for a in "$@"; do
    # JSON-escape: backslash → \\, quote → \", control chars dropped.
    esc=$(printf '%s' "$a" \
        | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
              -e 's/[[:cntrl:]]//g')
    ARGS_JSON="$ARGS_JSON"',"'"$esc"'"'
done
PAYLOAD='{"Args":['"$ARGS_JSON"']}'

case "$ACTION" in
    invoke)
        peer chaincode invoke \
            -o localhost:7050 \
            --ordererTLSHostnameOverride orderer.example.com \
            --tls --cafile "$ORDERER_CA" \
            -C "$FABRIC_CHANNEL" -n "$FABRIC_CCNAME" \
            --peerAddresses localhost:7051 --tlsRootCertFiles "$PEER0_ORG1_CA" \
            --peerAddresses localhost:9051 --tlsRootCertFiles "$PEER0_ORG2_CA" \
            -c "$PAYLOAD" 2>&1
        ;;
    query)
        peer chaincode query \
            -C "$FABRIC_CHANNEL" -n "$FABRIC_CCNAME" \
            -c "$PAYLOAD" 2>&1
        ;;
    *)
        echo "[fabric_invoke] unknown action: $ACTION (expected invoke|query)" >&2
        exit 66
        ;;
esac
