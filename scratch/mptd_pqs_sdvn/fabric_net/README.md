# MPTD-PQS — Dynamic Hyperledger Fabric Network

Paper §3.5.5 / Fig 3.9 permissioned blockchain, rendered as a **distributed**
Fabric network with **one peer per RSU** and **N controllers as Raft orderers**.
This replaces the stock 2-peer `fabric-samples/test-network` so that the ledger
is genuinely distributed across all RSUs (invariant 6) and no single controller
can decide a revocation (invariant 2).

> **Where this runs.** The full bring-up needs **Docker** (peers, orderers and the
> chaincode-as-a-service container are containers). The HPC lab node used for the
> live run **has Docker + Hyperledger Explorer + IPFS already installed**, so the
> end-to-end SC-Trust / SC-Revoke / CP-Detect run happens there. `gen` + `genesis`
> are deterministic and validate the topology **without** Docker (handy for a quick
> local sanity check).

---

## 1. Faithfulness to the paper

| Paper element | How this topology realises it |
|---------------|-------------------------------|
| RSUs = endorsing peers (Fig 3.9) | one `peer{i}.rsu.example.com` per RSU, own ledger replica + MSP identity |
| Controllers = ordering service | `orderer{j}.example.com` Raft consenters; hold **no** world-state, run **no** chaincode |
| Invariant 2 (controller non-authoritative) | a controller is architecturally an orderer only — it physically cannot endorse/commit a revocation |
| Invariant 6 (no central bottleneck) | N-way ledger replication; BFT counted in chaincode, not in a single check |
| BFT thresholds 2f+1 / f+1 (Eq 3.63 / 3.67) | enforced **inside the chaincode** by counting DISTINCT RSU evidence signatures — NOT a Fabric endorsement policy. The endorsement policy is the light `OR('RSUMSP.peer')`, which is what lets the network scale to any N without a `43-of-64`-style policy. |

The number of peers is **dynamic**, driven by `--mobility_scenario` at NS-3 run
time (the flag is an int: `0`=urban, `1`=rural, `2`=autobahn):

| Scenario (`--mobility_scenario`) | RSU peers (`N_PEERS`) | Orderers (`N_ORD`) | f = ⌊(N−1)/3⌋ | revoke 2f+1 | cp-detect f+1 |
|----------|------|------|------|------|------|
| urban (0)    | 64 | 5 | 21 | 43 | 22 |
| rural (1)    | 44 | 5 | 14 | 29 | 15 |
| autobahn (2) | 23 | 5 | 7  | 15 | 8  |

`cryptogen`'s `Template.Count=N` materialises `peer0..peer(N-1)` automatically;
all peers share internal port 7051 (distinct container DNS names) and differ only
on host-exposed ports (`11051+i`), so adding peers never collides internally.

---

## 2. Files

| File | Role |
|------|------|
| `gen_network.sh` | renders crypto-config + configtx + compose for N peers / N orderers; brings the network up; creates the channel; joins nodes; deploys chaincode |
| `deploy_cc.sh` | packages + installs + approves + commits the chaincode as **one shared CCAAS** container (O(1) footprint, not O(N)) |
| `generated/` | all rendered artifacts — crypto material, genesis block, compose file, topology.env. **gitignored**, regenerated on every `gen`. |

Environment overrides (all optional):

```bash
export FAB_ROOT=/home/niranga/fabric-samples   # where the fabric bin/ + chaincode src live
export CHANNEL=mptdchannel
export CC_NAME=trajectory
export CC_SRC=$FAB_ROOT/trajectory-chaincode    # source the CCAAS image is built from
```

---

## 3. Quick start (HPC node, Docker available)

```bash
cd scratch/mptd_pqs_sdvn/fabric_net

# urban scenario: 64 RSU peers + 5 controllers, full bring-up
./gen_network.sh all 64 5

# …or step by step:
./gen_network.sh gen 64 5     # render artifacts
./gen_network.sh genesis      # cryptogen + configtxgen (channel genesis block)
./gen_network.sh up           # docker compose up -d
./gen_network.sh channel      # osnadmin join orderers + peer channel join
./gen_network.sh deploy       # build CCAAS image, install/approve/commit chaincode
```

Tear down when finished:

```bash
./gen_network.sh down
```

## 4. Local validation (no Docker)

The deterministic half of the pipeline runs anywhere `cryptogen` + `configtxgen`
are on `PATH` (they ship in `fabric-samples/bin`). Use it to confirm a topology
renders and the genesis block builds before pushing to the HPC node:

```bash
./gen_network.sh gen 4 3 && ./gen_network.sh genesis
# → generated/organizations/…  +  generated/channel-artifacts/mptdchannel.block
```

---

## 5. How NS-3 talks to this network

NS-3 does **not** speak the Fabric SDK directly. The C++ simulation
(`06c_blockchain_api.h`) calls a local **fabric proxy** over a socket
(`mptd_fabric_call_socket`), which in turn invokes/queries the chaincode via the
`peer` CLI / gateway. At boot, `register_all_nodes()` (`11_blockchain_setup.h`)
registers every RSU (`SCBootstrapRSU`), vehicle and controller (`SCRegister` with
2f+1 RSU endorsements). During the run, the lightweight alert path and the
controller evidence path submit signed evidence; the cross-RSU drainer casts
revoke votes. At shutdown, `mptd_export_blockchain_evidence()` dumps the committed
ledger state to `analytics/results/blockchain_evidence.json`.

Run NS-3 against a live network by **omitting** `--skip_blockchain` (or setting it
`false`) and selecting the matching scenario:

```bash
./waf --run "mptd_pqs_sdvn --mobility_source=1 --mobility_scenario=0 \
  --N_RSUs=64 --skip_blockchain=false --ablation_mode=0 --attack_number=2 \
  --attack_percentage=20 --simTime=30"
```
(`--ablation_mode=0` = full mode: all AI + crypto + blockchain.)

`--skip_blockchain=true` (training sweeps, ablation A5) bypasses all of the above.

See `../BLOCKCHAIN_IMPLEMENTATION.md` for the chaincode contract reference,
signature scheme and evidence-flow diagrams.
