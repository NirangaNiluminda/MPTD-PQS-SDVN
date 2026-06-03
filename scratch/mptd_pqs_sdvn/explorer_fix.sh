#!/usr/bin/env bash
# =============================================================================
# explorer_fix.sh — repair Hyperledger Explorer after a Fabric crypto regen.
#
# WHY THIS EXISTS
#   `network.sh down` + `up` regenerates all crypto material. Two things then
#   break Explorer, neither related to the MPTD-PQS chaincode or ledger:
#
#   1. priv_sk filename mismatch (ALWAYS):
#      Explorer's connection-profile hardcodes the org1 admin key filename as
#      `priv_sk`, but Fabric (cryptogen AND fabric-ca) writes it hash-named
#      (e.g. 0858ebe5...{64hex}_sk). Explorer then dies on startup with:
#        "Failed to create wallet ... ENOENT .../keystore/priv_sk"
#      The container stays "Up" but port 8888 is dead. Fix = copy the real key
#      to a file literally named `priv_sk`.
#
#   2. stale PostgreSQL block cache (only after a ledger reset):
#      Explorer keeps its old indexed blocks; on a ledger reset the block
#      hashes no longer match and sync stalls, so the UI shows old tx/block
#      counts. Fix = drop the explorerdb volume and re-index from block 0
#      (the --resync flag below).
#
# USAGE
#   ./explorer_fix.sh            # fix priv_sk + restart explorer (fast path,
#                                #   use when explorer just won't load)
#   ./explorer_fix.sh --resync   # full recovery after `network.sh down/up`:
#                                #   wipe explorerdb volume, recreate, fix
#                                #   priv_sk, re-index from block 0
#
# ENV OVERRIDES (defaults match this machine's layout)
#   FABRIC_TN_DIR        test-network dir
#   EXPLORER_DIR         dir containing Explorer's docker-compose.yaml
#   EXPLORER_CONTAINER   Explorer app container name
#
# SAFETY
#   --resync runs `docker compose down -v` ONLY in EXPLORER_DIR, so it touches
#   the Explorer viewer's Postgres volume — NOT the fabric_test network or any
#   peer ledger. Your on-chain registrations are never at risk.
# =============================================================================
set -euo pipefail

FABRIC_TN_DIR="${FABRIC_TN_DIR:-/home/niranga/fabric-samples/test-network}"
EXPLORER_DIR="${EXPLORER_DIR:-/home/niranga/fabric-samples/explorer}"
EXPLORER_CONTAINER="${EXPLORER_CONTAINER:-explorer.mynetwork.com}"

ADMIN_KEYSTORE="$FABRIC_TN_DIR/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore"

RESYNC=0
if [ "${1:-}" = "--resync" ]; then RESYNC=1; fi

# ── helper: pick a docker compose invocation that exists on this host ────────
compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    elif command -v docker-compose >/dev/null 2>&1; then
        docker-compose "$@"
    else
        echo "[explorer_fix] ERROR: neither 'docker compose' nor 'docker-compose' found" >&2
        exit 70
    fi
}

# ── 1. fix the priv_sk filename (the always-needed step) ─────────────────────
if [ ! -d "$ADMIN_KEYSTORE" ]; then
    echo "[explorer_fix] ERROR: admin keystore not found: $ADMIN_KEYSTORE" >&2
    echo "[explorer_fix]        is the test-network up? (network.sh up ... -ca)" >&2
    exit 66
fi

# The real key is the hash-named *_sk file; exclude priv_sk itself so re-runs
# are idempotent (priv_sk also ends in _sk).
SRC_KEY="$(find "$ADMIN_KEYSTORE" -maxdepth 1 -type f -name '*_sk' ! -name 'priv_sk' | head -n1)"
if [ -z "$SRC_KEY" ]; then
    echo "[explorer_fix] ERROR: no hash-named *_sk key in $ADMIN_KEYSTORE" >&2
    echo "[explorer_fix]        the Admin@org1 MSP may not have been enrolled." >&2
    exit 67
fi

cp -f "$SRC_KEY" "$ADMIN_KEYSTORE/priv_sk"
echo "[explorer_fix] priv_sk <- $(basename "$SRC_KEY")"

# ── 2. optional full resync (wipe stale block cache) ─────────────────────────
if [ "$RESYNC" -eq 1 ]; then
    echo "[explorer_fix] --resync: wiping explorerdb volume and re-indexing..."
    ( cd "$EXPLORER_DIR" && compose down -v && compose up -d )
else
    # Fast path: just bounce the app so it re-reads the wallet.
    echo "[explorer_fix] restarting $EXPLORER_CONTAINER..."
    docker restart "$EXPLORER_CONTAINER" >/dev/null
fi

# ── 3. wait + report ─────────────────────────────────────────────────────────
echo "[explorer_fix] waiting 20s for Explorer to connect + sync..."
sleep 20
echo "[explorer_fix] ---- last 15 log lines ----"
docker logs "$EXPLORER_CONTAINER" --tail 15 2>&1 || true
echo "[explorer_fix] ----------------------------"
echo "[explorer_fix] done. reload http://localhost:8888"
echo "[explorer_fix] if the log shows 'Failed to create wallet' the key copy"
echo "[explorer_fix]   didn't take; if it shows 'syncBlocks: Finish' you're good."
