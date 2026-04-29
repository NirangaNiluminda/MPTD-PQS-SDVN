# MPTD-PQS SDVN Simulation

**Mobility Pattern & Trajectory Poisoning Detection with Post-Quantum Security**  
in Software-Defined Vehicular Networks (SDVNs)

Final Year Project — University of Ruhuna, Sri Lanka 2024/2025

---

## Project Overview

This simulation implements the MPTD-PQS framework, which detects and mitigates
mobility pattern and trajectory poisoning attacks in SDVNs using:

1. **Dual-mode detection** — Lightweight rule-based (at RSU) + Full AI-based (at controller)
2. **GAT spatial detector** — Graph Attention Network over vehicle-RSU graphs
3. **LSTM-AE temporal detector** — Autoencoder on beacon sequences (window k=20)
4. **SC-Trust + SC-Revoke** — Hyperledger Fabric smart contracts for distributed trust
5. **Post-Quantum TRS + FHE** — Simulated Threshold Ring Signatures + CKKS FHE

---

## System Architecture

```
NS-3 Simulation  ──(curl)──►  localhost:5001  ◄──  analytics/ml/prediction_server.py
       │                       (ML server)               (GAT + LSTM-AE inference)
       │
       └──(curl)──►  localhost:3000  ◄──  fabric-samples/trajectory-rest-api/server.py
                      (Fabric REST)              (Hyperledger Fabric blockchain)
                           │
                           ▼
                    Hyperledger Fabric
                    (peer0.org1, peer0.org2,
                     orderer, CA containers)
```

---

## Prerequisites

- NS-3 3.35 installed at `/home/niranga/ns-allinone-3.35/ns-3.35/`
- Docker Desktop (desktop-linux context) with `/home/niranga` added to File Sharing
- Python 3.8+, PyTorch, Flask, scikit-learn (see `analytics/ml/requirements.txt`)
- Hyperledger Fabric binaries in `/home/niranga/fabric-samples/bin/`

---

## ⚡ Quick Start — Full System

Open **3 terminals** and run in order:

### Before anything — set Docker context (every session)

```bash
# Run this FIRST every session, especially after a reboot or Docker Desktop restart.
docker context use desktop-linux
```

### Terminal 1 — Blockchain + REST API

```bash
cd /home/niranga/fabric-samples/test-network
pkill -f docker-api-proxy.py 2>/dev/null || true
python3 docker-api-proxy.py &

./network.sh up createChannel -ca
./network.sh deployCC -ccn trajectory -ccp ../trajectory-chaincode/chaincode -ccl go

cd /home/niranga/fabric-samples/trajectory-rest-api
python3 server.py
```

✅ Wait for: `Listening on http://0.0.0.0:3000`

### Terminal 2 — ML Prediction Server

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35/analytics/ml
python3 prediction_server.py
```

✅ Wait for: `Running on http://127.0.0.1:5001`

### Terminal 3 — NS-3 Simulation

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35
python3 waf --run "mptd_pqs_sdvn \
    --attack_number=2 \
    --attack_percentage=30 \
    --simTime=13 \
    --routing_test=false"
```

---

## 🚀 How to Run

### Build

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35

# Incremental build (after C++ changes):
python3 waf build

# Full clean build (first time or after configure errors):
python3 waf distclean
python3 waf configure --enable-examples
python3 waf build
```

Build time: ~3 min full, ~30 s incremental.

### Run a single attack

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35

python3 waf --run "mptd_pqs_sdvn \
    --attack_number=<1-7> \
    --attack_percentage=30 \
    --simTime=13 \
    --routing_test=false"
```

### Run all 7 attacks in sequence

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35

for atk in 1 2 3 4 5 6 7; do
    echo "============================================"
    echo " Attack $atk"
    echo "============================================"
    python3 waf --run \
        "mptd_pqs_sdvn --attack_number=$atk \
         --routing_test=false \
         --attack_percentage=30 \
         --simTime=13" \
        2>&1 | grep -E "MCC|FPR|PARR|CDER|TDEE|TPE|PBPO|Confusion"
done
```

### Quick smoke test (no external services needed)

```bash
# routing_test=true skips blockchain + ML calls — fastest way to check the sim runs
python3 waf --run "mptd_pqs_sdvn --attack_number=2 --routing_test=true --simTime=5"
```

### Simulation Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `attack_number` | int | `1` | Attack scenario (1–7, see table below) |
| `attack_percentage` | int | `40` | % of nodes that are malicious (0–99) |
| `simTime` | double | `13.7` | Simulation duration in seconds |
| `routing_test` | bool | `true` | `false` = full mode (blockchain + ML); `true` = offline/fast |
| `maxspeed` | int | `60` | Vehicle speed cap in km/h |

---

## Attack Scenarios

All 7 attacks from the paper taxonomy (§3.4) are fully implemented and verified.

| `attack_number` | Paper ID | Attacker | Detection Algorithms | Description |
|---|---|---|---|---|
| **1** | **TP-S1** | Compromised RSU | TP-S1, TP-S4, TP-S5 | RSU intercepts honest vehicle beacons and shifts GPS coordinates before forwarding (Fig 3.1) |
| **2** | **TP-S2** | Malicious vehicle | TP-S2, TP-S4 | Vehicle sends beacons with exaggerated speed + heading drift (Fig 3.2) |
| **3** | **MP-S1** | Compromised RSU | MP-S1 (identity density) | RSU injects ghost vehicle IDs, inflating apparent traffic density — Sybil via RSU (Fig 3.4) |
| **4** | **MP-S2** | Malicious vehicle | MP-S4 (ghost transit) | Vehicle steals other vehicles' IDs and re-broadcasts extra beacons at its own position (Fig 3.5) |
| **5** | **TP-S3** | SDN controller | CP-DETECT, TP-S1, TP-S4, TP-S5 | Compromised controller intercepts honest beacons and modifies position + speed in the control plane (Fig 3.3) |
| **6** | **MP-S3** | Malicious vehicle | MP-S3 (KL divergence) | Malicious vehicle amplifies its reported speed past the KL-divergence threshold κ_th=1.5 — MitM relay attack (Fig 3.6) |
| **7** | **MP-S4** | Vehicles + controller | TP-S1/S2/S4 + MP-S3 + MP-S4 + CP | Coordinated multi-vector: combines TP-S2 trajectory drift, MP-S2 identity theft, and MP-S3 speed amplification simultaneously (Fig 3.7) |

### Verified Metrics (attack_percentage=30, simTime=13)

| `attack_number` | Paper ID | MCC | FPR | PARR | CDER |
|---|---|---|---|---|---|
| 1 | TP-S1 | 0.340 | 0.000 | 0.16 | 0.263 |
| 2 | TP-S2 | 0.933 | 0.000 | 0.90 | 0.025 |
| 3 | MP-S1 | 0.362 | 0.000 | 0.18 | 0.256 |
| 4 | MP-S2 | 0.220 | 0.108 | 0.28 | 0.413 |
| 5 | TP-S3 | 0.742 | 0.000 | 0.64 | 0.113 |
| 6 | MP-S3 | 0.911 | 0.000 | 0.85 | 0.021 |
| 7 | MP-S4 | 0.800 | 0.108 | 0.91 | 0.100 |

> FPR=0.108 for attacks 4 and 7 is expected — stolen-beacon injection causes the detection
> engine to flag some honest vehicles whose IDs were impersonated.

---

## Detection Signatures

The detection engine (`08_detection_engine.h`) runs 4 algorithms on every received beacon:

| Algorithm | Signatures | Equation |
|---|---|---|
| **TP-DETECT** (Alg 1) | TP-S1 kinematic, TP-S2 heading rate, TP-S3 acceleration, TP-S4 dead-reckoning, TP-S5 drift | §3.4.4, Eq 3.10–3.15 |
| **SYB-DETECT** (Alg 2) | MP-S1 identity density, MP-S2 sync timing, MP-S4 ghost transit | §3.4.4, Eq 3.7, 3.16, 3.17 |
| **MITM-DETECT** (Alg 3) | MP-S3 KL divergence | §3.4.4, Eq 3.18 |
| **CP-DETECT** (Alg 4) | Control-plane flag | §3.4.4 |

Composite score: ψ_i(t) = (|TP_violated| + |MP_violated|) / 9 > ψ_th = 0.3 → anomalous

---

## Evaluation Metrics (Paper §4.1.2)

| Metric | Description |
|---|---|
| **MCC** | Matthews Correlation Coefficient — primary detection quality |
| **FPR** | False Positive Rate — safety-critical for ITS |
| **PARR** | Poisoned Aggregate Rejection Rate — TRS mitigation recall |
| **CDER** | Control Decision Error Rate — end-to-end impact (1 − Accuracy) |
| **TDEE** | Traffic Density Estimation Error (m) — mean position error all beacons |
| **TPE** | Trajectory Prediction Error (m) — RMSE position error malicious only |
| **PBPO** | Per-Beacon Processing Overhead (ms) — real-time feasibility |

---

## ML Pipeline

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35/analytics/ml

# Install dependencies (first time only):
pip3 install -r requirements.txt

# Train models (run after simulation produces beacon_log.csv):
python3 train.py
# → saves models/gat_model.pt, lstm_ae_model.pt, scaler.pkl, theta_ae.txt

# Run baseline comparison:
python3 baseline_eval.py
# → analytics/results/baseline_comparison.csv

# Full evaluation sweep (84 runs, takes ~hours):
cd ../..
bash analytics/run_evaluation.sh             # all attacks
bash analytics/run_evaluation.sh --attack 2  # single attack only
bash analytics/run_evaluation.sh --resume    # skip completed runs
```

---

## 🔍 Fabric Explorer (Blockchain UI)

View all blocks, transactions, and chaincode calls in a web browser.

**Requirement:** Fabric network must already be running (Terminal 1 from Quick Start).

```bash
bash /home/niranga/fabric-samples/explorer/start-explorer.sh
```

Wait ~30 seconds, then open: **http://localhost:8080**

| Field | Value |
|---|---|
| URL | http://localhost:8080 |
| Username | `exploreradmin` |
| Password | `exploreradminpw` |

Stop Explorer:
```bash
cd /home/niranga/fabric-samples/explorer
docker compose down -v
```

---

## 📦 IPFS (Off-Chain Storage)

IPFS stores large trajectory data off-chain; only the CID hash goes to Fabric.

**Current status:** IPFS daemon is not installed on this machine.
The simulation REST API writes full trajectory JSON directly to Fabric (suitable
for demo). To enable full IPFS integration:

```bash
# Install IPFS
wget https://dist.ipfs.tech/kubo/v0.27.0/kubo_v0.27.0_linux-amd64.tar.gz
tar -xzf kubo_v0.27.0_linux-amd64.tar.gz
sudo bash kubo/install.sh

# Initialise and start daemon
ipfs init
ipfs daemon &

# Verify (should return {"Version":"0.27.0",...})
curl -s http://localhost:5001/api/v0/version
```

---

## 🛑 Shutting Down

Always stop Explorer before Fabric — Explorer holds open DB connections to peers.

```bash
# 1 — Stop Explorer (if running)
cd /home/niranga/fabric-samples/explorer && docker compose down -v

# 2 — Fix file ownership BEFORE stopping Fabric (prevents "Permission denied")
sudo chown -R $USER:$USER /home/niranga/fabric-samples/test-network/organizations/

# 3 — Stop Fabric
cd /home/niranga/fabric-samples/test-network
./network.sh down

# 4 — Stop background processes
pkill -f docker-api-proxy.py 2>/dev/null || true
pkill -f prediction_server.py 2>/dev/null || true
pkill -f "trajectory-rest-api/server.py" 2>/dev/null || true
```

> `network.sh down` wipes all blockchain data. Run `deployCC` again next startup.

---

## Repository Layout

```
scratch/mptd_pqs_sdvn/            NS-3 C++ simulation
  simulation.cc                   Entry point (includes all headers in order)
  wscript                         NS-3 build config

  01_includes.h                   Library includes (NS-3, std, crypto)
  02_config_globals.h             All simulation parameters and global constants
  03_packet_tags.h                BsmBeaconTag — BSM beacon packet tag
  04_state_globals.h              Per-vehicle/RSU runtime state (VehicleBeaconState)
  05_utils.h                      execCmd(), extractValue(), data_at_nodes structs

  06b_pq_crypto.h                 Post-Quantum crypto (TRS + FHE) — §3.3.2–3.3.3
  06c_blockchain_api.h            Fabric REST API calls (Store*/Flag*/CallSC*)
  06a_attack_models.h             All 7 attack models + PoisonTrajectoryByType()

  07_socket_layer.h               SimpleUdpApplication class + WiFi MAC params
  08_detection_engine.h           Detection engine: TP-DETECT, SYB-DETECT,
                                    MITM-DETECT, CP-DETECT (Algorithms 1–4)
  09_vehicle_beacon_tx.h          Vehicle beacon uplink + MP-S2 injection
  10_metrics_csv.h                7 paper metrics + beacon_log.csv writer
  11_blockchain_setup.h           Blockchain init, server config, controller assign
  12_main.h                       NS-3 topology, mobility model, scheduler

analytics/
  run_evaluation.sh               Master sweep (7 attacks × 4 percentages × 3 speeds)
  ml/
    gat_detector.py               GAT spatial anomaly detector (Eq. 3.38–3.42)
    lstm_ae.py                    LSTM autoencoder temporal detector (Eq. 3.43–3.53)
    score_fusion.py               Score fusion Φ = λ1ψ + λ2S + λ3(ε/θ) (Eq. 3.54)
    prediction_server.py          Flask server port 5001 — NS-3 → ML bridge
    train.py                      Train GAT + LSTM-AE from beacon_log.csv
    baseline_eval.py              B1–B3 + A1–A5 ablation comparison
    requirements.txt              Python dependencies
  results/
    beacon_log.csv                Per-beacon log produced by NS-3
    sweep/                        Per-run metric CSVs + sweep_summary.csv
    figures/                      Generated PDF/PNG plots

fabric-samples/
  test-network/
    network.sh                    Fabric network lifecycle script
    docker-api-proxy.py           TCP proxy: rewrites Docker API v1.25→v1.41
  trajectory-chaincode/
    chaincode/smartcontract.go    SC-Trust (Eq. 3.66) + SC-Revoke (Eq. 3.67)
  trajectory-rest-api/
    server.py                     REST API bridge (port 3000)
  explorer/
    start-explorer.sh             Starts Hyperledger Explorer (port 8080)
```

---

## Troubleshooting

### Port already in use (18054, 7051, etc.)

Old containers from a different Docker context are still running:
```bash
docker context use default
docker ps --format "{{.Names}}" | grep -E "ca_|peer|orderer" | xargs -r docker rm -f
docker context use desktop-linux
```

### Permission denied when running `network.sh down`

Files were created inside containers and are owned by root:
```bash
sudo chown -R $USER:$USER /home/niranga/fabric-samples/test-network/organizations/
./network.sh down
```

### Chaincode install fails: `client version 1.25 is too old`

The Docker API proxy is not running:
```bash
cd /home/niranga/fabric-samples/test-network
python3 docker-api-proxy.py &
```

### Containers not visible in Docker Desktop

Wrong Docker context:
```bash
docker context use desktop-linux
```

### Peer fails to join channel (connection refused on port 7051)

Proxy was not running when `network.sh up` was called — restart from scratch:
```bash
pkill -f docker-api-proxy.py 2>/dev/null || true
cd /home/niranga/fabric-samples/test-network
python3 docker-api-proxy.py &
./network.sh down 2>/dev/null; ./network.sh up createChannel -ca
```

---

## RAM Usage Reference

| Service | RAM | How to stop |
|---|---|---|
| Fabric containers (6 total) | ~1.5 GB | `./network.sh down` |
| Fabric Explorer + DB | ~400 MB | `docker compose down -v` in `explorer/` |
| Docker API proxy | ~10 MB | `pkill -f docker-api-proxy.py` |
| ML prediction server | ~500 MB | Ctrl+C |
| REST API server | ~100 MB | Ctrl+C |
| Docker Desktop engine | ~500 MB | Only if not needed |

---

## Key Implementation Notes

- **Simulated PQ crypto**: TRS uses FNV-1a hash + Fisher-Yates shuffle (no real Dilithium); FHE uses Box-Muller Gaussian noise σ=1e-6 to model CKKS error. Replace with OpenFHE library when available.
- **Blockchain non-blocking**: Simulation continues if Fabric is offline — all curl calls are fire-and-forget.
- **Score fusion**: Φ_i(t) = 0.3·ψ + 0.4·S + 0.3·(ε/θ_ae) > 0.5 (Eq. 3.54).
- **Docker API proxy**: Required because Fabric's embedded Docker client hardcodes API v1.25, but Docker Engine 29.x requires v1.40+. The TCP proxy at port 12375 rewrites the version in all request paths.
- **Attack 5 (TP-S3)**: Vehicles are honest; poisoning happens at `HandleBeaconReceived()` (the control plane). No vehicle-level malicious flag is set.
- **Attacks 6 & 7 bypass EnforceRealism**: MP-S3 requires the extreme speed value to reach the detector unclamped so KL-divergence (Eq. 3.18) fires.

---

## Stage History

| Stage | Commit | Description |
|---|---|---|
| 1–2 | `25f75ac` | Rename to mptd_pqs_sdvn, strip legacy routing |
| 3 | `e9d9f00` | Rewrite beacon uplink, strip legacy socket helpers |
| 4 | `607e170` | 7 paper metrics + beacon CSV logging |
| 5 | `e0a3272` | Python ML pipeline (GAT + LSTM-AE + Flask) |
| 6 | `4725416` | SC-Trust + SC-Revoke blockchain integration |
| 7 | `41ba65d` | TRS + simulated CKKS FHE |
| 8 | `cc85182` | Full evaluation sweep + 7 figures + ablations |
| 9 | `95a2c60` | Final Stage 8 cleanup |
| 10A | `7a7a3b0` | File restructure: split 06→06a/06b/06c, rename 07/08/09/11 |
| 10B | `a070210` | Full legacy LDA cleanup — remove 65 dead code items |
| 10C | `4a67112` | Implement TP-S3, MP-S3, MP-S4 (attacks 5, 6, 7) |
