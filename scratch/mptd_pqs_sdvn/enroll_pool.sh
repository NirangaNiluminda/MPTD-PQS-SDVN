#!/usr/bin/env bash
# =============================================================================
# enroll_pool.sh — P4 Fabric-CA per-node enrollment (leased identity pool).
#
# WHY THIS EXISTS  (full rationale: P4_FABRIC_CA_ENROLLMENT.md)
#   Before P4 the gateway daemon submitted every NS-3 node's SC-Register through
#   ONE shared identity (User1@org1). Paper §3.5.5 Algorithm 7 wants each vehicle
#   / RSU to be its OWN Fabric client. This script pre-enrolls, against the
#   org1 Fabric-CA, a bounded POOL of client identities (leased by vehicles at
#   spawn) plus stable identities for each RSU and the controller. The gateway
#   daemon then loads these MSPs by name and signs each submission with the
#   caller's own cert.
#
#   Pool model (not unique-forever, not on-demand): the pool is sized to PEAK
#   CONCURRENT vehicles, so enrollment cost is bounded + front-loaded here at
#   bring-up — no fabric-ca latency on the mid-sim registration path. Set the
#   pool >= vehicle count and every vehicle gets a unique identity (the current
#   16-vehicle, paper-faithful case); shrink it for large SUMO runs (vehicles
#   lease/reuse slots, exactly like real-world V2X pseudonym pools).
#
# USAGE
#   ./enroll_pool.sh                 # enroll pool + RSU/CTRL identities
#   FABRIC_CA_POOL_SIZE=256 ./enroll_pool.sh   # bigger pool for SUMO
#   ./enroll_pool.sh --list          # list enrolled identity names + exit
#
# ENV OVERRIDES (defaults match this machine + the current sim topology)
#   FABRIC_TN_DIR          test-network dir
#   FABRIC_CA_POOL_SIZE    # of leasable vehicle client identities (default 32)
#   FABRIC_CA_RSU_COUNT    # of RSU identities          (default 4)
#   FABRIC_CA_CTRL_COUNT   # of controller identities   (default 1)
#   FABRIC_CA_WALLET       wallet root for enrolled MSPs
#
# OUTPUT
#   One MSP dir per identity under the wallet root:
#     <wallet>/<name>/msp/{signcerts,keystore,cacerts,...}
#   Identity names: pool0..pool{N-1}, rsu0..rsu{R-1}, ctrl0..ctrl{C-1}
#
# SAFETY / IDEMPOTENCY
#   Re-running is safe: an already-enrolled identity (signcert present in the
#   wallet) is skipped. Touches ONLY the CA + the wallet dir; never the peer
#   ledger or any chaincode state. Requires `network.sh up ... -ca` first
#   (ca_org1 @ localhost:7054 must be running).
# =============================================================================
set -euo pipefail

FABRIC_TN_DIR="${FABRIC_TN_DIR:-/home/niranga/fabric-samples/test-network}"
POOL_SIZE="${FABRIC_CA_POOL_SIZE:-32}"
RSU_COUNT="${FABRIC_CA_RSU_COUNT:-4}"
CTRL_COUNT="${FABRIC_CA_CTRL_COUNT:-4}"

CA_NAME="ca-org1"
CA_URL_HOST="localhost:7054"
CA_TLS_CERT="$FABRIC_TN_DIR/organizations/fabric-ca/org1/ca-cert.pem"
ORG1_HOME="$FABRIC_TN_DIR/organizations/peerOrganizations/org1.example.com"
NODEOU_CONFIG="$ORG1_HOME/msp/config.yaml"
WALLET="${FABRIC_CA_WALLET:-$ORG1_HOME/users/_mptd_pool}"

export PATH="$FABRIC_TN_DIR/../bin:$PATH"

# ── identity-name roster (single source of truth) ────────────────────────────
roster() {
    local i
    for ((i = 0; i < POOL_SIZE; i++));  do echo "pool$i"; done
    for ((i = 0; i < RSU_COUNT; i++));  do echo "rsu$i";  done
    for ((i = 0; i < CTRL_COUNT; i++)); do echo "ctrl$i"; done
}

if [ "${1:-}" = "--list" ]; then roster; exit 0; fi

# ── preflight ────────────────────────────────────────────────────────────────
if ! command -v fabric-ca-client >/dev/null 2>&1; then
    echo "[enroll_pool] ERROR: fabric-ca-client not on PATH (expected $FABRIC_TN_DIR/../bin)" >&2
    exit 70
fi
if [ ! -f "$CA_TLS_CERT" ]; then
    echo "[enroll_pool] ERROR: org1 CA TLS cert not found: $CA_TLS_CERT" >&2
    echo "[enroll_pool]        bring the network up WITH a CA: network.sh up createChannel -ca" >&2
    exit 66
fi
if [ ! -d "$ORG1_HOME/msp" ]; then
    echo "[enroll_pool] ERROR: CA-admin home not enrolled: $ORG1_HOME/msp" >&2
    echo "[enroll_pool]        the -ca bring-up should have enrolled the CA admin." >&2
    exit 67
fi
# CA-admin context: `register` is authorized via the admin identity enrolled
# into $ORG1_HOME/msp by the -ca bring-up.
export FABRIC_CA_CLIENT_HOME="$ORG1_HOME"

mkdir -p "$WALLET"
echo "[enroll_pool] wallet     = $WALLET"
echo "[enroll_pool] pool=$POOL_SIZE rsu=$RSU_COUNT ctrl=$CTRL_COUNT  (total $(roster | wc -l))"
echo "[enroll_pool] CA         = https://$CA_URL_HOST  caname=$CA_NAME"

enrolled=0 skipped=0
for name in $(roster); do
    msp_dir="$WALLET/$name/msp"
    # Idempotency: a signcert already present => identity enrolled, skip.
    if [ -d "$msp_dir/signcerts" ] && [ -n "$(ls -A "$msp_dir/signcerts" 2>/dev/null)" ]; then
        skipped=$((skipped + 1))
        continue
    fi

    secret="${name}pw"

    # 1. register (idempotent: tolerate "already registered"). Runs in the
    #    CA-admin context (FABRIC_CA_CLIENT_HOME=$ORG1_HOME).
    reg_out="$(fabric-ca-client register \
        --caname "$CA_NAME" \
        --id.name "$name" --id.secret "$secret" --id.type client \
        --tls.certfiles "$CA_TLS_CERT" 2>&1 || true)"
    if ! echo "$reg_out" | grep -qiE 'Password: |already registered'; then
        echo "[enroll_pool] WARN register $name: $reg_out" >&2
    fi

    # 2. enroll -> writes the MSP (signcert + hash-named key) into the wallet.
    if ! fabric-ca-client enroll \
        -u "https://$name:$secret@$CA_URL_HOST" \
        --caname "$CA_NAME" \
        -M "$msp_dir" \
        --tls.certfiles "$CA_TLS_CERT" >/dev/null 2>&1; then
        echo "[enroll_pool] ERROR: enroll $name failed" >&2
        exit 71
    fi

    # 3. NodeOU config.yaml so the cert's OU (client) is recognised by the MSP.
    cp -f "$NODEOU_CONFIG" "$msp_dir/config.yaml"
    enrolled=$((enrolled + 1))
done

echo "[enroll_pool] done: enrolled=$enrolled skipped(existing)=$skipped"
echo "[enroll_pool] sample identity dir:"
ls "$WALLET" | head -5 | sed 's/^/[enroll_pool]   /'
echo "[enroll_pool] point the daemon at this wallet via FABRIC_GW_WALLET=$WALLET"
