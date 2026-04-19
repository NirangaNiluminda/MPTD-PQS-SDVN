# MPTD-PQS SDVN Simulation

**Mobility Pattern & Trajectory poisoning Detection with Post-Quantum Security**
in Software-Defined Vehicular Networks (SDVNs)

Final Year Project — NS-3 simulation codebase.

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

## Repository Layout

```
scratch/mptd_pqs_sdvn/         NS-3 C++ simulation
  01_includes.h                 Library includes
  02_config_globals.h           Simulation parameters and global constants
  03_packet_tags.h              BSM beacon tag getters/setters
  04_state_globals.h            Per-vehicle/RSU runtime state
  05_utils.h                    Utility structs and helpers
  06_mrtpa_attack.h             Attack injectors + TRS/FHE (§3.3.2-3.3.3)
  07_security.h                 Security helpers, Stage 7 reference
  08_beacon_handlers.h          RSU beacon receive: rule-based detection + ML call
  09_send_lte.h                 LTE uplink beacon transmission (BsmBeaconTag)
  10_metrics_csv.h              7 paper metrics + CSV logging
  11_blockchain_transmission.h  Hyperledger Fabric REST API calls
  12_main.h                     NS-3 main: topology, mobility, attack setup
  simulation.cc                 Entry point (#includes all headers above)
  wscript                       NS-3 build config

analytics/
  run_evaluation.sh             Stage 8 master sweep (7×4×3 = 84 NS-3 runs)
  ml/
    gat_detector.py             GAT spatial anomaly detector
    lstm_ae.py                  LSTM autoencoder temporal detector
    score_fusion.py             Score fusion Φ = λ1ψ + λ2S + λ3(ε/θ)
    prediction_server.py        Flask server (port 5001) for NS-3→ML bridge
    train.py                    Train GAT + LSTM-AE from beacon_log.csv
    evaluate_all.py             Stage 8: all 7 metrics for 6 detection variants
    baseline_eval.py            B1-B3 + A1-A5 ablation comparison
    plot_results.py             7 publication figures (Fig 1-7)
    requirements.txt            Python dependencies
  results/
    beacon_log.csv              Per-beacon log (produced by NS-3)
    sweep/                      Per-run metric CSVs + sweep_summary.csv  [git-ignored]
    figures/                    Generated PDF/PNG plots                   [git-ignored]
    logs/                       NS-3 run logs                             [git-ignored]

fabric-samples/trajectory-chaincode/
  chaincode/smartcontract.go    SC-Trust (Eq. 3.66) + SC-Revoke (Eq. 3.67)
```

---

## Build

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35

# Full clean build (first time or after changes):
python3 waf distclean
python3 waf configure --enable-examples
python3 waf build

# Incremental build:
python3 waf build
```

Build time: ~3 min full, ~30 s incremental.

---

## Running Attack Scenarios

### Parameters

| Parameter | Values | Description |
|---|---|---|
| `attack_number` | 1-7 | Attack scenario (see table below) |
| `attack_percentage` | 0-99 | % of malicious vehicles |
| `maxspeed` | km/h | Vehicle speed regime |
| `simTime` | seconds | Simulation duration (default 13.7) |
| `routing_test` | true/false | true=routing benchmark, false=detection mode |

### Attack Scenarios

| `attack_number` | Paper ID | Type | Description |
|---|---|---|---|
| 1 | TP-S1 | Trajectory poisoning | Gradual position drift |
| 2 | TP-S2 | Trajectory poisoning | Speed spoofing |
| 3 | TP-S3 | Trajectory poisoning | Malicious controller |
| 4 | MP-S1 | Mobility pattern | Traffic density manipulation |
| 5 | MP-S2 | Mobility pattern | Sybil RSU injection |
| 6 | MP-S3 | Mobility pattern | Man-in-the-Middle |
| 7 | MP-S4 | Mobility pattern | Coordinated multi-source |

### Example Runs

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35

# Attack 1 (trajectory drift), 20% malicious, medium speed, detection mode:
python3 waf --run "mptd_pqs_sdvn \
    --attack_number=1 \
    --attack_percentage=20 \
    --maxspeed=50 \
    --simTime=13 \
    --routing_test=false"

# Attack 5 (Sybil RSU), 30% malicious, high speed:
python3 waf --run "mptd_pqs_sdvn \
    --attack_number=5 \
    --attack_percentage=30 \
    --maxspeed=100 \
    --simTime=13 \
    --routing_test=false"

# Verify TRS + FHE output (Stage 7):
python3 waf --run "mptd_pqs_sdvn --attack_number=1 --simTime=1" 2>&1 | grep -E "TRS|FHE"
```

---

## ML Pipeline

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35/analytics/ml

# Install dependencies:
pip3 install -r requirements.txt

# 1. Run simulation to generate beacon_log.csv first (see above), then:

# 2. Train GAT + LSTM-AE models:
python3 train.py

# 3. Start prediction server (NS-3 calls this at runtime):
python3 prediction_server.py &

# 4. Run baseline + ablation comparison:
python3 baseline_eval.py

# 5. Stage 8 full evaluation sweep:
cd ../..
bash analytics/run_evaluation.sh

# 6. Generate figures:
python3 analytics/ml/plot_results.py \
    --summary_csv analytics/results/sweep/sweep_summary.csv \
    --out_dir analytics/results/figures
```

---

## Evaluation Metrics (Paper §4.1.2)

| Metric | Eq. | Description |
|---|---|---|
| MCC | 4.1 | Matthews Correlation Coefficient — primary detection quality |
| FPR | 4.2 | False Positive Rate — safety-critical for ITS |
| PARR | 4.3 | Poisoned Aggregate Rejection Rate — TRS mitigation effectiveness |
| CDER | 4.4 | Control Decision Error Rate — end-to-end impact |
| TDEE | 4.5 | Traffic Density Estimation Error — MP attack impact |
| TPE | 4.6 | Trajectory Prediction Error — TP attack impact |
| PBPO | 4.7 | Per-Beacon Processing Overhead (ms) — real-time feasibility |

---

## Detection Variants (Ablation, Paper §4.1.1)

| Variant | Description | Answers |
|---|---|---|
| MPTD-PQS | Full system | — |
| A1 | Lightweight only (rule-based ψ) | RQ2 |
| A2 | GAT only | RQ3 |
| A3 | Temporal AE only | RQ3 |
| A4 | Full detection, no TRS/FHE | RQ5 |
| A5 | Full detection, no blockchain | RQ6 |

---

## Key Implementation Notes

- **Pre-existing LTE SIGSEGV**: NS-3 crashes at t≈0.93s (Fabric REST API timing issue
  from Stage 6). DSRC detection starts at t=6.7s so `beacon_log.csv` is written before
  the crash. TRS/FHE verified via startup self-test in `12_main.h`.
- **Simulated PQ crypto**: TRS uses FNV-1a hash + Fisher-Yates shuffle (no real
  Dilithium); FHE uses Box-Muller Gaussian noise σ=1e-6 to model CKKS error.
  Replace with OpenFHE library when available (see `wscript` comments).
- **Blockchain**: Requires Hyperledger Fabric running at `localhost:3000` (IPFS REST API).
  Simulation continues if Fabric is offline (curl calls fail silently).
- **Score fusion**: Φ_i(t) = 0.3·ψ + 0.4·S + 0.3·(ε/θ_ae) > 0.5 (Eq. 3.54).

---

## Stage History

| Stage | Commit | Description |
|---|---|---|
| 1-2 | `25f75ac` | Rename to mptd_pqs_sdvn, strip legacy routing |
| 3 | `e9d9f00` | Rewrite 09_send_lte.h, strip 07_security.h |
| 4 | `607e170` | 7 paper metrics + beacon CSV logging |
| 5 | `e0a3272` | Python ML pipeline (GAT + LSTM-AE + Flask) |
| 6 | `4725416` | SC-Trust + SC-Revoke blockchain integration |
| 7 | `41ba65d` | TRS + simulated CKKS FHE (post-quantum crypto) |
| 8 | `cc85182` | Full evaluation sweep + 7 figures + ablations A1-A5 |
| 9 | — | Final cleanup + README (this file) |
