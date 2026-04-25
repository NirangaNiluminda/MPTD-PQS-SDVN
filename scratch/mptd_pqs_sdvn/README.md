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

### Terminal 1 — Blockchain + REST API

```bash
# STEP 1: Start the Docker API version proxy (required — fixes Fabric/Docker compatibility)
cd /home/niranga/fabric-samples/test-network
python3 docker-api-proxy.py &

# STEP 2: Start the Fabric network (first time or after shutdown)
./network.sh up createChannel -ca
./network.sh deployCC -ccn trajectory -ccp ../trajectory-chaincode/chaincode -ccl go

# STEP 3: Start the REST API
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
    --attack_number=1 \
    --attack_percentage=20 \
    --maxspeed=50 \
    --simTime=13 \
    --routing_test=false"
```

---

## 🔍 Fabric Explorer (Blockchain UI)

View transactions, blocks, and chaincode activity in a web browser.

**Fabric network must be running first**, then run the single start script:

```bash
bash /home/niranga/fabric-samples/explorer/start-explorer.sh
```

Wait ~30 seconds, then open: **http://localhost:8080**

| Field | Value |
|-------|-------|
| Username | `exploreradmin` |
| Password | `exploreradminpw` |

**Stop Explorer:**
```bash
cd /home/niranga/fabric-samples/explorer
docker compose down -v
```

> **Why a script?** Fabric CA generates a new private key filename every time
> `network.sh up` runs. Explorer expects a file named `priv_sk` in each keystore
> directory. The script automatically creates that symlink before starting the
> containers so no manual steps are needed.

> **Explorer location:** `fabric-samples/explorer/` (NOT `blockchain-explorer/` —
> that older setup does not work with Fabric 2.5.x).

---

## 🛑 Shutting Down (Free RAM)

When you are done working, shut everything down to free RAM (~2 GB):

```bash
# Stop Explorer (if running)
cd /home/niranga/fabric-samples/explorer && docker compose down -v

# Stop Fabric containers (all 6 containers removed)
cd /home/niranga/fabric-samples/test-network
./network.sh down

# Stop the Docker API proxy
pkill -f docker-api-proxy.py

# Stop ML server and REST API: press Ctrl+C in their terminals
```

> **Note:** `network.sh down` wipes all blockchain data. You must run `deployCC` again next time you start up. This is normal — each simulation run generates fresh data.

---

## 🔁 Starting Up Again After Shutdown

```bash
# Terminal 1 — Blockchain stack
cd /home/niranga/fabric-samples/test-network
python3 docker-api-proxy.py &
./network.sh up createChannel -ca
./network.sh deployCC -ccn trajectory -ccp ../trajectory-chaincode/chaincode -ccl go
cd /home/niranga/fabric-samples/trajectory-rest-api && python3 server.py

# Terminal 2 — ML server
cd /home/niranga/ns-allinone-3.35/ns-3.35/analytics/ml && python3 prediction_server.py

# Terminal 3 — NS-3 simulation
cd /home/niranga/ns-allinone-3.35/ns-3.35
python3 waf --run "mptd_pqs_sdvn --attack_number=1 --routing_test=false --attack_percentage=20 --simTime=13"

# Optional Terminal 4 — Blockchain Explorer UI (after network is up)
bash /home/niranga/fabric-samples/explorer/start-explorer.sh
# → open http://localhost:8080  (exploreradmin / exploreradminpw)
```

> **One-time setup:** After a reboot, ensure Docker context is set correctly:
> ```bash
> docker context use desktop-linux
> ```

---

## Attack Scenarios

| `attack_number` | Paper ID | Type | Description |
|---|---|---|---|
| 1 | TP-S1 | Trajectory poisoning | Gradual position drift |
| 2 | TP-S2 | Trajectory poisoning | Speed spoofing |
| 3 | TP-S3 | Trajectory poisoning | Malicious controller |
| 4 | MP-S1 | Mobility pattern | Traffic density manipulation |
| 5 | MP-S2 | Mobility pattern | Sybil RSU injection |
| 6 | MP-S3 | Mobility pattern | Man-in-the-Middle |
| 7 | MP-S4 | Mobility pattern | Coordinated multi-source |

### Simulation Parameters

| Parameter | Values | Description |
|---|---|---|
| `attack_number` | 1–7 | Attack scenario |
| `attack_percentage` | 0–99 | % of malicious vehicles |
| `maxspeed` | km/h | Vehicle speed (20=low, 50=medium, 100=high) |
| `simTime` | seconds | Simulation duration (default 13) |
| `routing_test` | true/false | false = detection mode (use this) |

---

## Build NS-3

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35

# Incremental build (after C++ changes):
python3 waf build

# Full clean build (first time or if errors):
python3 waf distclean
python3 waf configure --enable-examples
python3 waf build
```

Build time: ~3 min full, ~30 s incremental.

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
bash analytics/run_evaluation.sh            # all attacks
bash analytics/run_evaluation.sh --attack 1 # single attack only
bash analytics/run_evaluation.sh --resume   # skip completed runs
```

---

## Evaluation Metrics (Paper §4.1.2)

| Metric | Description |
|---|---|
| MCC | Matthews Correlation Coefficient — primary detection quality |
| FPR | False Positive Rate — safety-critical for ITS |
| PARR | Poisoned Aggregate Rejection Rate — TRS mitigation |
| CDER | Control Decision Error Rate — end-to-end impact |
| TDEE | Traffic Density Estimation Error — MP attack impact |
| TPE | Trajectory Prediction Error — TP attack impact |
| PBPO | Per-Beacon Processing Overhead (ms) — real-time feasibility |

---

## Troubleshooting

### Simulation crashes with callback type mismatch (SIGIOT)
Already fixed in `07_security.h` — all four callbacks (`Rx`, `MacRx`, `MacTx`, `Enqueue`) include `std::string` context parameter.

### Port already in use (18054, 7051 etc.)
Old containers from a different Docker context are still running:
```bash
docker context use default
docker ps --format "{{.Names}}" | grep -E "ca_|peer|orderer" | xargs -r docker rm -f
docker context use desktop-linux
```

### Permission denied when running `network.sh down`
Files owned by root (created inside containers):
```bash
sudo chown -R $USER:$USER /home/niranga/fabric-samples/test-network/organizations/
./network.sh down
```

### Chaincode install fails: `client version 1.25 is too old`
The Docker API proxy is not running. Start it first:
```bash
cd /home/niranga/fabric-samples/test-network
python3 docker-api-proxy.py &
```

### Containers not visible in Docker Desktop
You are on the wrong Docker context:
```bash
docker context use desktop-linux
```

### Peer fails to join channel (connection refused on port 7051)
The peer container failed to start. Check:
```bash
docker ps -a | grep peer   # look for "Created" status (not "Up")
docker logs peer0.org1.example.com
```
Usually caused by proxy not running — see above.

---

## Repository Layout

```
scratch/mptd_pqs_sdvn/         NS-3 C++ simulation
  01_includes.h                 Library includes
  02_config_globals.h           Simulation parameters and global constants
  03_packet_tags.h              BSM beacon tag (BsmBeaconTag)
  04_state_globals.h            Per-vehicle/RSU runtime state
  05_utils.h                    Utility structs and helpers
  06_mrtpa_attack.h             Attack injectors + TRS/FHE (§3.3)
  07_security.h                 Security helpers + trace callbacks
  08_beacon_handlers.h          RSU beacon receive: rule-based detection + ML call
  09_send_lte.h                 LTE uplink beacon transmission
  10_metrics_csv.h              7 paper metrics + CSV logging
  11_blockchain_transmission.h  Hyperledger Fabric REST API calls
  12_main.h                     NS-3 topology, mobility, attack setup
  simulation.cc                 Entry point
  wscript                       NS-3 build config

analytics/
  run_evaluation.sh             Master sweep (7×4×3 = 84 NS-3 runs)
  ml/
    gat_detector.py             GAT spatial anomaly detector (Eq. 3.38–3.42)
    lstm_ae.py                  LSTM autoencoder temporal detector (Eq. 3.43–3.53)
    score_fusion.py             Score fusion Φ = λ1ψ + λ2S + λ3(ε/θ) (Eq. 3.54)
    prediction_server.py        Flask server port 5001 — NS-3→ML bridge
    train.py                    Train GAT + LSTM-AE from beacon_log.csv
    baseline_eval.py            B1-B3 + A1-A5 ablation comparison
    plot_results.py             7 publication figures (Fig 1–7)
    requirements.txt            Python dependencies
  results/
    beacon_log.csv              Per-beacon log (produced by NS-3)
    sweep/                      Per-run metric CSVs + sweep_summary.csv
    figures/                    Generated PDF/PNG plots

fabric-samples/
  test-network/
    network.sh                  Fabric network lifecycle script
    docker-api-proxy.py         TCP proxy: rewrites Docker API v1.25→v1.41
    compose/docker/
      docker-compose-test-net.yaml  Peer overlay (CORE_VM_ENDPOINT → proxy)
  trajectory-chaincode/
    chaincode/smartcontract.go  SC-Trust (Eq. 3.66) + SC-Revoke (Eq. 3.67)
  trajectory-rest-api/
    server.py                   REST API bridge (port 3000)
```

---

## RAM Usage Reference

| Service | RAM | Safe to stop when idle? |
|---|---|---|
| Fabric containers (6 total) | ~1.5 GB | ✅ `./network.sh down` |
| Fabric Explorer + DB | ~400 MB | ✅ `docker-compose down` in `blockchain-explorer/` |
| Docker API proxy | ~10 MB | ✅ `pkill -f docker-api-proxy.py` |
| ML prediction server | ~500 MB | ✅ Ctrl+C |
| REST API server | ~100 MB | ✅ Ctrl+C |
| Docker Desktop engine | ~500 MB | ⚠️ Only if not needed |

---

## Key Implementation Notes

- **Simulated PQ crypto**: TRS uses FNV-1a hash + Fisher-Yates shuffle (no real Dilithium); FHE uses Box-Muller Gaussian noise σ=1e-6 to model CKKS error. Replace with OpenFHE library when available (see `wscript` comments).
- **Blockchain**: Simulation continues if Fabric is offline — all curl calls are fire-and-forget (non-blocking).
- **Score fusion**: Φ_i(t) = 0.3·ψ + 0.4·S + 0.3·(ε/θ_ae) > 0.5 (Eq. 3.54).
- **Docker API proxy**: Required because Fabric peer's embedded Docker client (fsouza/go-dockerclient) hardcodes API v1.25, but Docker Engine 29.x requires minimum v1.40. The TCP proxy at port 12375 rewrites the version in all request paths.

---

## Stage History

| Stage | Commit | Description |
|---|---|---|
| 1–2 | `25f75ac` | Rename to mptd_pqs_sdvn, strip legacy routing |
| 3 | `e9d9f00` | Rewrite 09_send_lte.h, strip 07_security.h |
| 4 | `607e170` | 7 paper metrics + beacon CSV logging |
| 5 | `e0a3272` | Python ML pipeline (GAT + LSTM-AE + Flask) |
| 6 | `4725416` | SC-Trust + SC-Revoke blockchain integration |
| 7 | `41ba65d` | TRS + simulated CKKS FHE |
| 8 | `cc85182` | Full evaluation sweep + 7 figures + ablations |
| 9 | — | Final cleanup |
| 10 | `a76bb35` | Legacy LDA code removal (Option B) |
| 11 | `0bbc898` | Paper equation audit + 5 code fixes + callback fixes |
