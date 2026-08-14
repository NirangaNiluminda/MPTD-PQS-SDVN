#!/usr/bin/env bash
# =============================================================================
#  MPTD-PQS — chaincode deploy (CCAAS) for the dynamic N-peer RSU network
# =============================================================================
#  Single RSU org (RSUMSP) with N peers.  Unlike the stock 2-org test-network,
#  we use ONE shared chaincode-as-a-service container (fixed address, not the
#  per-peer {{.peername}} template) that all N peers connect to — so the
#  chaincode footprint is O(1), not O(N).
#
#  Endorsement policy = RSUMSP.peer (any single RSU peer may endorse).  The
#  paper's 2f+1 / f+1 BFT thresholds (Eq 3.63 / 3.67) are NOT a Fabric
#  endorsement policy — they are counted inside the chaincode over distinct
#  RSU evidence signatures, which is what lets this scale to any N.
#
#  args:  N_PEERS  CHANNEL  CC_NAME  CC_SRC
# =============================================================================
set -euo pipefail

N_PEERS="${1:?N_PEERS}"; CHANNEL="${2:?CHANNEL}"; CC_NAME="${3:?CC_NAME}"; CC_SRC="${4:?CC_SRC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN="${SCRIPT_DIR}/generated"
FAB_ROOT="${FAB_ROOT:-/home/niranga/fabric-samples}"
export PATH="${FAB_ROOT}/bin:${PATH}"
export FABRIC_CFG_PATH="${FAB_ROOT}/config"

ORG_DOMAIN="rsu.example.com"
ORD_DOMAIN="example.com"
RSU_MSP="RSUMSP"
DOCKER_NET="mptd_fabric"
CCAAS_PORT=9999
CC_VERSION="1.0"
CC_SEQUENCE="${CC_SEQUENCE:-1}"

crypto="${GEN}/organizations"
ORDERER_CA="${crypto}/ordererOrganizations/${ORD_DOMAIN}/orderers/orderer0.${ORD_DOMAIN}/msp/tlscacerts/tlsca.${ORD_DOMAIN}-cert.pem"

# peer env for peer index $1
set_peer() {
  local i="$1" pport=$((11051 + $1))
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="${RSU_MSP}"
  export CORE_PEER_MSPCONFIGPATH="${crypto}/peerOrganizations/${ORG_DOMAIN}/users/Admin@${ORG_DOMAIN}/msp"
  export CORE_PEER_TLS_ROOTCERT_FILE="${crypto}/peerOrganizations/${ORG_DOMAIN}/peers/peer${i}.${ORG_DOMAIN}/tls/ca.crt"
  export CORE_PEER_ADDRESS="localhost:${pport}"
}

echo "[deploy] building CCAAS image from ${CC_SRC}/Dockerfile"
docker build -f "${CC_SRC}/Dockerfile" -t "${CC_NAME}_ccaas_image:latest" --build-arg CC_SERVER_PORT=${CCAAS_PORT} "${CC_SRC}"

echo "[deploy] packaging chaincode (shared CCAAS address ${CC_NAME}_ccaas:${CCAAS_PORT})"
tmp="$(mktemp -d)"
mkdir -p "$tmp/src" "$tmp/pkg"
cat > "$tmp/src/connection.json" <<EOF
{ "address": "${CC_NAME}_ccaas:${CCAAS_PORT}", "dial_timeout": "10s", "tls_required": false }
EOF
cat > "$tmp/pkg/metadata.json" <<EOF
{ "type": "ccaas", "label": "${CC_NAME}_${CC_VERSION}" }
EOF
tar -C "$tmp/src" -czf "$tmp/pkg/code.tar.gz" .
tar -C "$tmp/pkg" -czf "${GEN}/${CC_NAME}.tar.gz" metadata.json code.tar.gz
rm -rf "$tmp"

set_peer 0
PACKAGE_ID="$(peer lifecycle chaincode calculatepackageid "${GEN}/${CC_NAME}.tar.gz")"
echo "[deploy] package id: ${PACKAGE_ID}"

echo "[deploy] installing on ${N_PEERS} peers"
for ((i=0;i<N_PEERS;i++)); do
  set_peer "$i"
  peer lifecycle chaincode install "${GEN}/${CC_NAME}.tar.gz" 2>&1 | tail -1 || true
done

echo "[deploy] approve for ${RSU_MSP}"
set_peer 0
peer lifecycle chaincode approveformyorg -o localhost:7050 \
  --ordererTLSHostnameOverride orderer0.${ORD_DOMAIN} \
  --channelID "${CHANNEL}" --name "${CC_NAME}" --version "${CC_VERSION}" \
  --package-id "${PACKAGE_ID}" --sequence "${CC_SEQUENCE}" \
  --tls --cafile "${ORDERER_CA}" \
  --signature-policy "OR('${RSU_MSP}.peer')"

echo "[deploy] commit"
peer lifecycle chaincode commit -o localhost:7050 \
  --ordererTLSHostnameOverride orderer0.${ORD_DOMAIN} \
  --channelID "${CHANNEL}" --name "${CC_NAME}" --version "${CC_VERSION}" \
  --sequence "${CC_SEQUENCE}" --tls --cafile "${ORDERER_CA}" \
  --peerAddresses "localhost:11051" \
  --tlsRootCertFiles "${crypto}/peerOrganizations/${ORG_DOMAIN}/peers/peer0.${ORG_DOMAIN}/tls/ca.crt" \
  --signature-policy "OR('${RSU_MSP}.peer')"

echo "[deploy] starting ONE shared CCAAS container"
docker rm -f "${CC_NAME}_ccaas" 2>/dev/null || true
docker run --rm -d --name "${CC_NAME}_ccaas" \
  --network host \
  -e CHAINCODE_SERVER_ADDRESS=0.0.0.0:${CCAAS_PORT} \
  -e CHAINCODE_ID="${PACKAGE_ID}" -e CORE_CHAINCODE_ID_NAME="${PACKAGE_ID}" \
  "${CC_NAME}_ccaas_image:latest"

echo "[deploy] querying committed"
peer lifecycle chaincode querycommitted --channelID "${CHANNEL}" --name "${CC_NAME}" || true
echo "[deploy] done"
