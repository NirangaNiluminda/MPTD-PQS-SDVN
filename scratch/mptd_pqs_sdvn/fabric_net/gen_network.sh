#!/usr/bin/env bash
# =============================================================================
#  MPTD-PQS  —  Dynamic Hyperledger Fabric topology generator
# =============================================================================
#  Paper §3.5.5 (Fig 3.9):  RSUs = endorsing peers,  controllers = ordering
#  service.  This script renders a *distributed* Fabric network with ONE peer
#  per RSU and N_ORDERERS orderer nodes (the SDN controllers), removing the
#  2-peer single-point-of-failure of the stock fabric-samples test-network.
#
#  WHY THIS IS FAITHFUL TO THE PAPER
#  ---------------------------------
#   * Every RSU is its own Fabric peer node (own ledger replica + identity)  →
#     real ledger distribution across N nodes, not 2.            (invariant 6)
#   * Controllers are orderer nodes only (ordering service); they hold NO
#     world-state and run NO chaincode, so a controller is architecturally
#     incapable of deciding a revocation.                        (invariant 2)
#   * The paper's BFT thresholds (2f+1 vehicle revoke Eq 3.63, f+1 controller
#     CP-Detect Eq 3.67) are enforced *in the chaincode* by counting DISTINCT
#     RSU evidence signatures — NOT in the Fabric endorsement policy.  That is
#     what lets the topology scale to any N without a "43-of-64" endorsement
#     policy.  Endorsement policy is therefore the light `RSUMSP.peer`.
#
#  SCALE IS DYNAMIC
#  ----------------
#   N_PEERS is driven by --mobility_scenario at NS-3 run time:
#       urban   -> 64    rural -> 44    autobahn -> 23
#   cryptogen's  Template.Count=N  generates peer0..peer(N-1) automatically;
#   all peers share internal port 7051 (distinct container DNS names) and only
#   differ on host-exposed ports, so adding peers never collides internally.
#
#  USAGE
#  -----
#     ./gen_network.sh gen      N_PEERS [N_ORDERERS]   # render crypto+configtx+compose
#     ./gen_network.sh up                              # docker compose up (containers)
#     ./gen_network.sh channel                         # create channel + join all nodes
#     ./gen_network.sh deploy                           # package/install/approve/commit CC
#     ./gen_network.sh all      N_PEERS [N_ORDERERS]   # gen + up + channel + deploy
#     ./gen_network.sh down                            # tear everything down
#
#  Validate WITHOUT Docker (deterministic steps only):
#     ./gen_network.sh gen 4 3 && ./gen_network.sh genesis
# =============================================================================
set -euo pipefail

# ---- paths ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAB_ROOT="${FAB_ROOT:-/home/niranga/fabric-samples}"
BIN="${FAB_ROOT}/bin"
export PATH="${BIN}:${PATH}"
export FABRIC_CFG_PATH="${SCRIPT_DIR}/generated"      # configtx.yaml lives here for configtxgen

GEN="${SCRIPT_DIR}/generated"                          # all rendered artifacts (gitignored)
ORG_DOMAIN="rsu.example.com"
ORD_DOMAIN="example.com"
RSU_MSP="RSUMSP"
ORD_MSP="OrdererMSP"
CHANNEL="${CHANNEL:-mptdchannel}"
CC_NAME="${CC_NAME:-trajectory}"
CC_SRC="${CC_SRC:-${FAB_ROOT}/trajectory-chaincode}"
DOCKER_NET="mptd_fabric"
COMPOSE_PROJECT="mptdnet"

# Config persisted between subcommands so `up`/`channel`/`deploy` know N.
STATE="${GEN}/topology.env"

log()  { printf '\033[0;34m[gen]\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m[ ok]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[err]\033[0m %s\n' "$*" >&2; exit 1; }

# Byzantine fault tolerance: f = floor((n-1)/3); revoke needs 2f+1, CP-Detect f+1.
fbyz() { echo $(( ($1 - 1) / 3 )); }

# =============================================================================
#  gen — render crypto-config, configtx, compose for N_PEERS + N_ORDERERS
# =============================================================================
cmd_gen() {
  local N_PEERS="${1:?N_PEERS required}" N_ORD="${2:-5}"
  [ "$N_PEERS" -ge 1 ] || die "N_PEERS must be >=1"
  [ "$N_ORD"  -ge 1 ] || die "N_ORDERERS must be >=1"
  local f; f=$(fbyz "$N_PEERS")
  log "Rendering network: ${N_PEERS} RSU peers, ${N_ORD} orderer/controllers (f=${f}, revoke=2f+1=$((2*f+1)), cp-detect=f+1=$((f+1)))"

  rm -rf "$GEN"; mkdir -p "$GEN/channel-artifacts"
  mkdir -p "$STATE" 2>/dev/null || true; rm -rf "$STATE" 2>/dev/null || true
  {
    echo "N_PEERS=$N_PEERS"; echo "N_ORD=$N_ORD"; echo "FBYZ=$f"
    echo "CHANNEL=$CHANNEL"; echo "CC_NAME=$CC_NAME"
  } > "${GEN}/topology.env"

  _render_cryptogen "$N_PEERS" "$N_ORD"
  _render_configtx  "$N_PEERS" "$N_ORD"
  _render_compose   "$N_PEERS" "$N_ORD"
  ok "Rendered artifacts under ${GEN}"
}

_render_cryptogen() {
  local N_PEERS="$1" N_ORD="$2"
  # --- peer org (RSUs): Template.Count = N  -> peer0..peer(N-1) -------------
  cat > "${GEN}/crypto-config-rsu.yaml" <<EOF
PeerOrgs:
  - Name: RSU
    Domain: ${ORG_DOMAIN}
    EnableNodeOUs: true
    Template:
      Count: ${N_PEERS}
      SANS:
        - localhost
    Users:
      Count: 1
EOF
  # --- orderer org (controllers): one Spec per orderer ---------------------
  {
    echo "OrdererOrgs:"
    echo "  - Name: Orderer"
    echo "    Domain: ${ORD_DOMAIN}"
    echo "    EnableNodeOUs: true"
    echo "    Specs:"
    for ((j=0;j<N_ORD;j++)); do
      echo "      - Hostname: orderer${j}"
      echo "        SANS:"
      echo "          - localhost"
    done
  } > "${GEN}/crypto-config-orderer.yaml"
}

_render_configtx() {
  local N_PEERS="$1" N_ORD="$2"
  local crypto="${GEN}/organizations"
  # Raft consenters + orderer addresses (internal DNS, all on 7050).
  local consenters="" addresses=""
  for ((j=0;j<N_ORD;j++)); do
    consenters+="        - Host: orderer${j}.${ORD_DOMAIN}
          Port: 7050
          ClientTLSCert: ${crypto}/ordererOrganizations/${ORD_DOMAIN}/orderers/orderer${j}.${ORD_DOMAIN}/tls/server.crt
          ServerTLSCert: ${crypto}/ordererOrganizations/${ORD_DOMAIN}/orderers/orderer${j}.${ORD_DOMAIN}/tls/server.crt
"
    addresses+="            - orderer${j}.${ORD_DOMAIN}:7050
"
  done

  cat > "${GEN}/configtx.yaml" <<EOF
# Auto-generated by gen_network.sh — DO NOT EDIT BY HAND.
Organizations:
  - &OrdererOrg
    Name: OrdererOrg
    ID: ${ORD_MSP}
    MSPDir: ${crypto}/ordererOrganizations/${ORD_DOMAIN}/msp
    Policies:
      Readers:   { Type: Signature, Rule: "OR('${ORD_MSP}.member')" }
      Writers:   { Type: Signature, Rule: "OR('${ORD_MSP}.member')" }
      Admins:    { Type: Signature, Rule: "OR('${ORD_MSP}.admin')" }
    OrdererEndpoints:
$(for ((j=0;j<N_ORD;j++)); do echo "      - orderer${j}.${ORD_DOMAIN}:7050"; done)

  - &RSUOrg
    Name: RSUOrg
    ID: ${RSU_MSP}
    MSPDir: ${crypto}/peerOrganizations/${ORG_DOMAIN}/msp
    Policies:
      Readers:   { Type: Signature, Rule: "OR('${RSU_MSP}.admin','${RSU_MSP}.peer','${RSU_MSP}.client')" }
      Writers:   { Type: Signature, Rule: "OR('${RSU_MSP}.admin','${RSU_MSP}.client')" }
      Admins:    { Type: Signature, Rule: "OR('${RSU_MSP}.admin')" }
      Endorsement: { Type: Signature, Rule: "OR('${RSU_MSP}.peer')" }

Capabilities:
  Channel:    &ChannelCapabilities    { V2_0: true }
  Orderer:    &OrdererCapabilities    { V2_0: true }
  Application: &ApplicationCapabilities { V2_5: true }

Application: &ApplicationDefaults
  Organizations:
  Policies:
    Readers:     { Type: ImplicitMeta, Rule: "ANY Readers" }
    Writers:     { Type: ImplicitMeta, Rule: "ANY Writers" }
    Admins:      { Type: ImplicitMeta, Rule: "MAJORITY Admins" }
    LifecycleEndorsement: { Type: ImplicitMeta, Rule: "ANY Endorsement" }
    Endorsement:          { Type: ImplicitMeta, Rule: "ANY Endorsement" }
  Capabilities:
    <<: *ApplicationCapabilities

Orderer: &OrdererDefaults
  OrdererType: etcdraft
  EtcdRaft:
    Consenters:
${consenters}
  Addresses:
${addresses}
  BatchTimeout: 2s
  BatchSize:
    MaxMessageCount: 10
    AbsoluteMaxBytes: 99 MB
    PreferredMaxBytes: 512 KB
  Policies:
    Readers:         { Type: ImplicitMeta, Rule: "ANY Readers" }
    Writers:         { Type: ImplicitMeta, Rule: "ANY Writers" }
    Admins:          { Type: ImplicitMeta, Rule: "MAJORITY Admins" }
    BlockValidation: { Type: ImplicitMeta, Rule: "ANY Writers" }

Channel: &ChannelDefaults
  Policies:
    Readers: { Type: ImplicitMeta, Rule: "ANY Readers" }
    Writers: { Type: ImplicitMeta, Rule: "ANY Writers" }
    Admins:  { Type: ImplicitMeta, Rule: "MAJORITY Admins" }
  Capabilities:
    <<: *ChannelCapabilities

Profiles:
  MptdChannel:
    <<: *ChannelDefaults
    Orderer:
      <<: *OrdererDefaults
      Organizations:
        - *OrdererOrg
      Capabilities: *OrdererCapabilities
    Application:
      <<: *ApplicationDefaults
      Organizations:
        - *RSUOrg
      Capabilities: *ApplicationCapabilities
EOF
}

_render_compose() {
  local N_PEERS="$1" N_ORD="$2"
  local crypto="${GEN}/organizations"
  local f; f="${GEN}/compose.yaml"
  {
    echo "# Auto-generated by gen_network.sh — ${N_PEERS} RSU peers + ${N_ORD} orderers."
    echo "networks:"
    echo "  ${DOCKER_NET}:"
    echo "    name: ${DOCKER_NET}"
    echo "volumes:"
    for ((j=0;j<N_ORD;j++)); do echo "  orderer${j}.${ORD_DOMAIN}:"; done
    for ((i=0;i<N_PEERS;i++)); do echo "  peer${i}.${ORG_DOMAIN}:"; done
    echo "services:"
    # ---- orderers (controllers) ------------------------------------------
    for ((j=0;j<N_ORD;j++)); do
      local gport=$((7050 + j*100)) aport=$((7053 + j*100)) oport=$((8443 + j*100))
      local od="${crypto}/ordererOrganizations/${ORD_DOMAIN}/orderers/orderer${j}.${ORD_DOMAIN}"
      cat <<EOF
  orderer${j}.${ORD_DOMAIN}:
    container_name: orderer${j}.${ORD_DOMAIN}
    image: hyperledger/fabric-orderer:latest
    environment:
      - FABRIC_LOGGING_SPEC=INFO
      - ORDERER_GENERAL_LISTENADDRESS=0.0.0.0
      - ORDERER_GENERAL_LISTENPORT=7050
      - ORDERER_GENERAL_LOCALMSPID=${ORD_MSP}
      - ORDERER_GENERAL_LOCALMSPDIR=/var/hyperledger/orderer/msp
      - ORDERER_GENERAL_TLS_ENABLED=true
      - ORDERER_GENERAL_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_GENERAL_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_GENERAL_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_GENERAL_CLUSTER_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_GENERAL_BOOTSTRAPMETHOD=none
      - ORDERER_CHANNELPARTICIPATION_ENABLED=true
      - ORDERER_ADMIN_TLS_ENABLED=true
      - ORDERER_ADMIN_TLS_CERTIFICATE=/var/hyperledger/orderer/tls/server.crt
      - ORDERER_ADMIN_TLS_PRIVATEKEY=/var/hyperledger/orderer/tls/server.key
      - ORDERER_ADMIN_TLS_ROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_ADMIN_TLS_CLIENTROOTCAS=[/var/hyperledger/orderer/tls/ca.crt]
      - ORDERER_ADMIN_LISTENADDRESS=0.0.0.0:7053
      - ORDERER_OPERATIONS_LISTENADDRESS=0.0.0.0:8443
      - ORDERER_METRICS_PROVIDER=prometheus
    working_dir: /root
    command: orderer
    volumes:
      - ${od}/msp:/var/hyperledger/orderer/msp
      - ${od}/tls:/var/hyperledger/orderer/tls
      - orderer${j}.${ORD_DOMAIN}:/var/hyperledger/production/orderer
    ports:
      - ${gport}:7050
      - ${aport}:7053
      - ${oport}:8443
    networks:
      - ${DOCKER_NET}
EOF
    done
    # ---- peers (RSUs) -----------------------------------------------------
    for ((i=0;i<N_PEERS;i++)); do
      local pport=$((11051 + i)) opport=$((19444 + i))
      local pd="${crypto}/peerOrganizations/${ORG_DOMAIN}/peers/peer${i}.${ORG_DOMAIN}"
      cat <<EOF
  peer${i}.${ORG_DOMAIN}:
    container_name: peer${i}.${ORG_DOMAIN}
    image: hyperledger/fabric-peer:latest
    environment:
      - FABRIC_CFG_PATH=/etc/hyperledger/peercfg
      - FABRIC_LOGGING_SPEC=INFO
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tls/server.crt
      - CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tls/server.key
      - CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt
      - CORE_PEER_ID=peer${i}.${ORG_DOMAIN}
      - CORE_PEER_ADDRESS=peer${i}.${ORG_DOMAIN}:7051
      - CORE_PEER_LISTENADDRESS=0.0.0.0:7051
      - CORE_PEER_CHAINCODEADDRESS=peer${i}.${ORG_DOMAIN}:7052
      - CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:7052
      - CORE_PEER_GOSSIP_BOOTSTRAP=peer0.${ORG_DOMAIN}:7051
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer${i}.${ORG_DOMAIN}:7051
      - CORE_PEER_LOCALMSPID=${RSU_MSP}
      - CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp
      - CORE_OPERATIONS_LISTENADDRESS=0.0.0.0:9444
      - CORE_METRICS_PROVIDER=prometheus
      - CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG={"peername":"peer${i}rsu"}
      - CORE_CHAINCODE_EXECUTETIMEOUT=300s
    volumes:
      - ${pd}:/etc/hyperledger/fabric
      - peer${i}.${ORG_DOMAIN}:/var/hyperledger/production
    working_dir: /root
    command: peer node start
    ports:
      - ${pport}:7051
      - ${opport}:9444
    networks:
      - ${DOCKER_NET}
EOF
    done
  } > "$f"
}

# =============================================================================
#  genesis — generate crypto material + channel genesis block (NO Docker)
#            This is the deterministic, locally-validatable step.
# =============================================================================
cmd_genesis() {
  [ -f "${GEN}/crypto-config-rsu.yaml" ] || die "run 'gen' first"
  log "cryptogen: RSU peer org"
  cryptogen generate --config="${GEN}/crypto-config-rsu.yaml"     --output="${GEN}/organizations"
  log "cryptogen: orderer org"
  cryptogen generate --config="${GEN}/crypto-config-orderer.yaml" --output="${GEN}/organizations"
  log "configtxgen: ${CHANNEL} genesis block"
  configtxgen -profile MptdChannel -outputBlock "${GEN}/channel-artifacts/${CHANNEL}.block" -channelID "${CHANNEL}"
  ok "Crypto material + genesis block generated (validates topology without containers)"
}

# =============================================================================
#  up / channel / deploy / down  (require Docker)
# =============================================================================
cmd_up() {
  [ -f "${GEN}/compose.yaml" ] || die "run 'gen' first"
  [ -d "${GEN}/organizations" ] || cmd_genesis
  log "docker compose up"
  docker compose -p "${COMPOSE_PROJECT}" -f "${GEN}/compose.yaml" up -d
  ok "Containers started"
}

cmd_channel() {
  # shellcheck disable=SC1090
  source "${GEN}/topology.env"
  local crypto="${GEN}/organizations"
  export ORDERER_CA="${crypto}/ordererOrganizations/${ORD_DOMAIN}/orderers/orderer0.${ORD_DOMAIN}/msp/tlscacerts/tlsca.${ORD_DOMAIN}-cert.pem"
  log "osnadmin: joining ${N_ORD} orderers to ${CHANNEL}"
  for ((j=0;j<N_ORD;j++)); do
    local aport=$((7053 + j*100))
    local od="${crypto}/ordererOrganizations/${ORD_DOMAIN}/orderers/orderer${j}.${ORD_DOMAIN}"
    osnadmin channel join --channelID "${CHANNEL}" \
      --config-block "${GEN}/channel-artifacts/${CHANNEL}.block" \
      -o "localhost:${aport}" --ca-file "$ORDERER_CA" \
      --client-cert "${od}/tls/server.crt" --client-key "${od}/tls/server.key"
  done
  log "peer channel join: ${N_PEERS} peers"
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="${RSU_MSP}"
  export CORE_PEER_TLS_ROOTCERT_FILE="${crypto}/peerOrganizations/${ORG_DOMAIN}/peers/peer0.${ORG_DOMAIN}/tls/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="${crypto}/peerOrganizations/${ORG_DOMAIN}/users/Admin@${ORG_DOMAIN}/msp"
  for ((i=0;i<N_PEERS;i++)); do
    local pport=$((11051 + i))
    export CORE_PEER_ADDRESS="localhost:${pport}"
    export CORE_PEER_TLS_ROOTCERT_FILE="${crypto}/peerOrganizations/${ORG_DOMAIN}/peers/peer${i}.${ORG_DOMAIN}/tls/ca.crt"
    peer channel join -b "${GEN}/channel-artifacts/${CHANNEL}.block"
  done
  ok "Channel ${CHANNEL} created; all nodes joined"
}

cmd_deploy() {
  # shellcheck disable=SC1090
  source "${GEN}/topology.env"
  log "Deploying chaincode '${CC_NAME}' (CCAAS) across ${N_PEERS} peers"
  log "  (delegates to fabric-samples deployCCAAS pattern; see DEPLOY notes in README)"
  bash "${SCRIPT_DIR}/deploy_cc.sh" "${N_PEERS}" "${CHANNEL}" "${CC_NAME}" "${CC_SRC}"
  ok "Chaincode committed"
}

cmd_down() {
  if [ -f "${GEN}/compose.yaml" ]; then
    docker compose -p "${COMPOSE_PROJECT}" -f "${GEN}/compose.yaml" down -v || true
  fi
  docker rm -f $(docker ps -aq --filter "network=${DOCKER_NET}") 2>/dev/null || true
  ok "Network down"
}

cmd_all() {
  cmd_gen "$@"; cmd_genesis; cmd_up; sleep 3; cmd_channel; cmd_deploy
}

# ---- dispatch ---------------------------------------------------------------
case "${1:-}" in
  gen)     shift; cmd_gen "$@" ;;
  genesis) cmd_genesis ;;
  up)      cmd_up ;;
  channel) cmd_channel ;;
  deploy)  cmd_deploy ;;
  down)    cmd_down ;;
  all)     shift; cmd_all "$@" ;;
  *) cat <<EOF
MPTD-PQS dynamic Fabric topology generator
  gen N_PEERS [N_ORD]   render crypto-config + configtx + compose
  genesis               cryptogen + configtxgen (no Docker; validates topology)
  up                    docker compose up
  channel               create channel + join all orderers & peers
  deploy                package/install/approve/commit chaincode
  all N_PEERS [N_ORD]   gen+genesis+up+channel+deploy
  down                  tear down
EOF
    ;;
esac
