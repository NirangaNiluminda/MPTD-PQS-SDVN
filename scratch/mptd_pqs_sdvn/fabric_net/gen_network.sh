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
  # Users.Count sized for the P4 leased-identity pool (see _populate_wallet):
  # gateway daemon's default wallet (<org>/users/_mptd_pool/<name>/msp) needs
  # ONE genuinely distinct cryptogen-generated identity per RSU/vehicle/
  # controller slot -- SCBootstrapRSU/SCRegister fail 100% of the time
  # otherwise ("load identity ... no such file or directory"), which
  # cascades into every downstream metric coming back 0/-1 (found 2026-08-10,
  # every AB8 run up to that point was silently measuring nothing). Exactly
  # ${WALLET_TOTAL:-268} = N_PEERS(64) + pool(200, >= max N_Vehicles across
  # blockchain-enabled configs) + ctrl(4, matches N_Controllers default).
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
      Count: ${WALLET_TOTAL:-268}
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
  # Raft consenters + orderer addresses. Host networking (see _render_compose)
  # means every orderer shares the host's network namespace, so each MUST
  # listen on its own unique port -- can't all be 7050 anymore. Use the same
  # gport=7050+j*100 scheme the compose file uses, so the two stay consistent.
  local consenters="" addresses=""
  for ((j=0;j<N_ORD;j++)); do
    local gport=$((7050 + j*100))
    consenters+="        - Host: orderer${j}.${ORD_DOMAIN}
          Port: ${gport}
          ClientTLSCert: ${crypto}/ordererOrganizations/${ORD_DOMAIN}/orderers/orderer${j}.${ORD_DOMAIN}/tls/server.crt
          ServerTLSCert: ${crypto}/ordererOrganizations/${ORD_DOMAIN}/orderers/orderer${j}.${ORD_DOMAIN}/tls/server.crt
"
    addresses+="            - orderer${j}.${ORD_DOMAIN}:${gport}
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
$(for ((j=0;j<N_ORD;j++)); do echo "      - orderer${j}.${ORD_DOMAIN}:$((7050 + j*100))"; done)

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

  # HOST NETWORKING (2026-08-10): the custom bridge network on this host
  # started silently dropping bridge-forwarded TLS traffic after a disk-
  # cleanup reboot (survived br_netfilter reload, bridge recreation,
  # checksum-offload disable, dockerd restart, AND a full second reboot --
  # see HANDOFF notes). Every node now binds directly on the HOST network
  # namespace instead, which sidesteps the bridge/veth/NAT path entirely.
  # Consequence: Docker's embedded DNS (only available on custom bridge
  # networks) is gone, so every hostname a node might dial (its own peers,
  # all orderers) needs an explicit extra_hosts entry pointing at 127.0.0.1 --
  # and since all 69 nodes now share ONE port space, each needs its OWN
  # unique port everywhere its address is referenced (compose env vars AND
  # configtx.yaml's Raft consenters, kept in sync via the same gport/aport/
  # oport/pport/opport/ccport formulas in both places).
  local extra_hosts=""
  for ((j=0;j<N_ORD;j++)); do extra_hosts+="      - \"orderer${j}.${ORD_DOMAIN}:127.0.0.1\"
"; done
  for ((i=0;i<N_PEERS;i++)); do extra_hosts+="      - \"peer${i}.${ORG_DOMAIN}:127.0.0.1\"
"; done
  # Peers additionally need to resolve the shared CCAAS chaincode-service
  # container (deploy_cc.sh runs it with --network host too; the package
  # metadata embeds "<CC_NAME>_ccaas:<port>" as its dial address).
  local peer_extra_hosts="${extra_hosts}      - \"${CC_NAME}_ccaas:127.0.0.1\"
"

  {
    echo "# Auto-generated by gen_network.sh — ${N_PEERS} RSU peers + ${N_ORD} orderers."
    echo "# Host networking (see comment in _render_compose) -- no networks: block needed."
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
    network_mode: "host"
    extra_hosts:
${extra_hosts}    environment:
      - FABRIC_LOGGING_SPEC=INFO
      - ORDERER_GENERAL_LISTENADDRESS=0.0.0.0
      - ORDERER_GENERAL_LISTENPORT=${gport}
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
      - ORDERER_ADMIN_LISTENADDRESS=0.0.0.0:${aport}
      - ORDERER_OPERATIONS_LISTENADDRESS=0.0.0.0:${oport}
      - ORDERER_METRICS_PROVIDER=prometheus
    working_dir: /root
    command: orderer
    volumes:
      - ${od}/msp:/var/hyperledger/orderer/msp
      - ${od}/tls:/var/hyperledger/orderer/tls
      - orderer${j}.${ORD_DOMAIN}:/var/hyperledger/production/orderer
EOF
    done
    # ---- peers (RSUs) -----------------------------------------------------
    for ((i=0;i<N_PEERS;i++)); do
      local pport=$((11051 + i)) opport=$((19444 + i)) ccport=$((30051 + i))
      local pd="${crypto}/peerOrganizations/${ORG_DOMAIN}/peers/peer${i}.${ORG_DOMAIN}"
      cat <<EOF
  peer${i}.${ORG_DOMAIN}:
    container_name: peer${i}.${ORG_DOMAIN}
    image: hyperledger/fabric-peer:latest
    network_mode: "host"
    extra_hosts:
${peer_extra_hosts}    environment:
      - FABRIC_CFG_PATH=/etc/hyperledger/peercfg
      - FABRIC_LOGGING_SPEC=INFO
      - CORE_PEER_TLS_ENABLED=true
      - CORE_PEER_TLS_CERT_FILE=/etc/hyperledger/fabric/tls/server.crt
      - CORE_PEER_TLS_KEY_FILE=/etc/hyperledger/fabric/tls/server.key
      - CORE_PEER_TLS_ROOTCERT_FILE=/etc/hyperledger/fabric/tls/ca.crt
      - CORE_PEER_ID=peer${i}.${ORG_DOMAIN}
      - CORE_PEER_ADDRESS=peer${i}.${ORG_DOMAIN}:${pport}
      - CORE_PEER_LISTENADDRESS=0.0.0.0:${pport}
      - CORE_PEER_CHAINCODEADDRESS=peer${i}.${ORG_DOMAIN}:${ccport}
      - CORE_PEER_CHAINCODELISTENADDRESS=0.0.0.0:${ccport}
      - CORE_PEER_GOSSIP_BOOTSTRAP=peer0.${ORG_DOMAIN}:11051
      - CORE_PEER_GOSSIP_EXTERNALENDPOINT=peer${i}.${ORG_DOMAIN}:${pport}
      - CORE_PEER_LOCALMSPID=${RSU_MSP}
      - CORE_PEER_MSPCONFIGPATH=/etc/hyperledger/fabric/msp
      - CORE_OPERATIONS_LISTENADDRESS=0.0.0.0:${opport}
      - CORE_METRICS_PROVIDER=prometheus
      - CHAINCODE_AS_A_SERVICE_BUILDER_CONFIG={"peername":"peer${i}rsu"}
      - CORE_CHAINCODE_EXECUTETIMEOUT=300s
    volumes:
      - ${FAB_ROOT}/config:/etc/hyperledger/peercfg
      - ${pd}:/etc/hyperledger/fabric
      - peer${i}.${ORG_DOMAIN}:/var/hyperledger/production
    working_dir: /root
    command: peer node start
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
  _populate_wallet
  ok "Crypto material + genesis block generated (validates topology without containers)"
}

# ── _populate_wallet — P4 leased-identity pool from cryptogen's Users ────────
# The gateway daemon (fabric_gateway_daemon/main.go) defaults its wallet to
# <org>/users/_mptd_pool/<name>/msp and requires ONE identity per name it's
# asked to sign as (rsu0..rsu{R-1}, pool0..pool{P-1}, ctrl0..ctrl{C-1} --
# 11_blockchain_setup.h register_one()). cryptogen only produces sequentially
# NUMBERED users (User1..UserN), never these names directly, and (confirmed
# empirically 2026-08-10 in an isolated copy) regenerating cryptogen against
# an existing output tree replaces the CA wholesale -- there is no safe way
# to "add more users" to an already-deployed network's identity later. So
# this pairs 1:1 with cmd_genesis (same CA, same run) rather than being a
# separate/lazy step: User1..User64 -> rsu0..rsu63, User65..User264 ->
# pool0..pool199, User265..User268 -> ctrl0..ctrl3. Idempotent (skips a name
# whose msp/signcerts already exists) so re-running genesis without wiping
# is safe, but note cmd_gen's rm -rf "$GEN" makes that moot in practice.
_populate_wallet() {
  local org_home="${GEN}/organizations/peerOrganizations/${ORG_DOMAIN}"
  local wallet="${org_home}/users/_mptd_pool"
  local rsu_n=64 pool_n=200 ctrl_n=4
  mkdir -p "$wallet"
  local u=1 copied=0 skipped=0
  _assign() {
    local name="$1"
    local src="${org_home}/users/User${u}@${ORG_DOMAIN}/msp"
    local dst="${wallet}/${name}/msp"
    if [ -d "${dst}/signcerts" ] && [ -n "$(ls -A "${dst}/signcerts" 2>/dev/null)" ]; then
      skipped=$((skipped + 1))
    elif [ -d "$src" ]; then
      mkdir -p "$dst"
      cp -a "${src}/." "${dst}/"
      copied=$((copied + 1))
    else
      echo "[wallet] WARNING: no cryptogen identity for User${u} (needed for ${name})" >&2
    fi
    u=$((u + 1))
  }
  local i
  for ((i=0; i<rsu_n; i++));  do _assign "rsu${i}";  done
  for ((i=0; i<pool_n; i++)); do _assign "pool${i}"; done
  for ((i=0; i<ctrl_n; i++)); do _assign "ctrl${i}"; done
  log "wallet: ${copied} identities assigned, ${skipped} already present (rsu=${rsu_n} pool=${pool_n} ctrl=${ctrl_n}) -> ${wallet}"
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
  # FABRIC_CFG_PATH is pinned to ${GEN} above (so configtxgen finds configtx.yaml),
  # but the `peer` CLI also needs core.yaml on that same path — cryptogen never
  # renders one there. Without this the join loop fails immediately with
  # "Config File core Not Found" and every peer stays unjoined.
  [ -f "${GEN}/core.yaml" ] || cp "${FAB_ROOT}/config/core.yaml" "${GEN}/core.yaml"
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
  # Force-remove leftovers, but EXCLUDE co-tenants that merely attach to the
  # same network/project for observability (Hyperledger Explorer + its
  # Postgres, the CCAAS chaincode container).
  # Filtered by COMPOSE PROJECT LABEL, not network membership: nodes run under
  # network_mode: host (see _render_compose) since 2026-08-10, so they are no
  # longer members of ${DOCKER_NET} at all and a network= filter would silently
  # find nothing. Also still catches the (now empty/unused) old bridge's
  # members, for compatibility with any container generated before this change.
  local leftovers
  leftovers=$( { docker ps -aq --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" 2>/dev/null
                  docker ps -aq --filter "network=${DOCKER_NET}" 2>/dev/null; } | sort -u \
    | while read -r c; do
        n=$(docker inspect -f '{{.Name}}' "$c" 2>/dev/null | sed 's|^/||')
        case "$n" in explorer*|*explorerdb*|*ccaas*) ;; *) echo "$c" ;; esac
      done)
  [ -n "$leftovers" ] && docker rm -f $leftovers >/dev/null 2>&1 || true
  # `compose down -v` only removes volumes it still knows about. If it partially
  # failed (64 peers is a lot), or containers were force-removed first, the peer
  # ledger volumes are ORPHANED rather than deleted — and a later cmd_up happily
  # re-attaches them, silently reviving the old channel config / old CA. Sweep
  # them explicitly so a rebuild is always a real rebuild.
  local stale
  stale=$(docker volume ls -q --filter "name=^${COMPOSE_PROJECT}_" 2>/dev/null)
  if [ -n "$stale" ]; then
    echo "$stale" | xargs -r docker volume rm -f >/dev/null 2>&1 || true
    log "removed $(echo "$stale" | wc -l) stale ${COMPOSE_PROJECT}_* volumes"
  fi
  ok "Network down"
}

cmd_all() {
  # cmd_down FIRST — non-negotiable. cmd_gen regenerates the CA and every cert,
  # but peer ledger volumes are NOT recreated by cmd_up if they already exist.
  # Skipping the teardown therefore yields a Frankenstein network: new CA on
  # disk, but peers still attached to OLD volumes holding the OLD channel
  # config and OLD CA root. Those peers reject every identity signed by the new
  # CA with "creator org unknown / certificate signed by unknown authority",
  # which surfaces as ~40% random write failures, silent ResetLedger failures
  # (-> duplicate identities), and lost RSU/controller registrations. Diagnosed
  # the hard way 2026-07-27: 60/64 peers were still on June-17 volumes.
  cmd_down
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
