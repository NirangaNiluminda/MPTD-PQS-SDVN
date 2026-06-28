# MPTD-PQS-SDVN: Dual-Mode Detection and Blockchain Mitigation Framework

This repository houses the implementation of **MPTD-PQS**: *Signature-Characterized Dual-Mode GAT-Temporal Autoencoder with Blockchain-Enforced Post-Quantum Ring Signatures for Detection and Mitigation of MP (Mobility Pattern) and TP (Trajectory Poisoning) Attacks in SDVN*.

---

## 1. System Architecture

The MPTD-PQS-SDVN framework consists of three main components:

1. **C++ NS-3 Simulation (Data & Control Planes)**:
   - Simulates vehicle mobility (hardcoded and SUMO-derived), DSRC (802.11p) vehicle-to-vehicle/infrastructure communications, CSMA backhaul networks, and LTE cellular links.
   - Hosts the SDN data plane routing algorithms and coordinates attack models (TP-S1 to TP-S5, MP-S1 to MP-S4).
   - Runs the rule-based lightweight HMAC gate on the RSU level.

2. **Hyperledger Fabric Blockchain Consortium**:
   - Stores immutable security evidence, vehicle registries, and consortium credentials.
   - Enforces post-quantum threshold ring signatures (TRS) using CRYSTALS-Dilithium and ML-DSA-87 to authenticate messages.
   - Connects to the simulation through a REST API bridge.

3. **Machine Learning Pipeline (Spatial/Temporal Detectors & Fusion)**:
   - **GAT spatial detector**: Infers anomalies by constructing spatial vehicle topology graphs.
   - **LSTM-AE temporal detector**: Utilizes sliding windows of 20 beacons to identify sequential trajectory deviations (stealthy drifts).
   - **Score Fusion Engine (SLSQP)**: Learning-based weighted fusion model ($\lambda_1, \lambda_2, \lambda_3$) optimized by speed regimes (Urban, Rural, Highway).

---

## 2. Directory Layout

The workspace is organized as follows:

```
MPTD-PQS-SDVN/
├── analytics/              # ML pipeline, datasets, evaluation, and plotting
│   ├── ml/                 # ML scripts (train, train_fusion, evaluate_all)
│   │   ├── data/           # Master training CSV datasets
│   │   └── models/         # Scenario-specific model subfolders
│   └── results/            # Plotted curves and csv reports
├── chaincode/              # Go-based Hyperledger Fabric chaincode for transaction validation
├── scratch/                # C++ simulation source files (symlinked to NS-3 build)
│   └── mptd_pqs_sdvn/      # Core files: simulation.cc, 06d_ai_inference.h, etc.
├── mobility/               # SUMO-derived vehicle and RSU positioning files
├── real_data/              # Real-world datasets for cross-domain validation
├── GLOBAL_BASELINE_README.md  # Guide for running Sharma & Ercan baseline comparisons
└── README_HANDOFF.md       # Handoff instructions for baseline evaluation
```

---

## 3. Getting Started

### Prerequisites
- Ubuntu Linux (or VM)
- NS-3 Network Simulator (v3.35)
- Python 3.8+ with virtual environment
- Docker & Hyperledger Fabric binary tools (only for blockchain mode)

### A. Setup Python Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### B. Compile the C++ Simulation
Ensure you are in the NS-3 root folder:
```bash
cd /home/vboxuser/ns-allinone-3.35/ns-3.35
./waf build
```

---

## 4. Workflows

### 1. Running the Simulation
Execute the simulation for a specific attack number (1-7), attack percentage (0-100), and speed limit:
```bash
./waf --run "mptd_pqs_sdvn --attack_number=1 --attack_percentage=20 --simTime=10"
```
The simulation dynamically loads model configurations (GAT model, LSTM-AE models, scalers, weights) from the scenario directories inside `analytics/ml/models/` based on the active mobility parameters.

### 2. Optimizing Score Fusion Weights (Phase 2)
To re-run SLSQP optimization and calculate the scenario-specific $\lambda$ weights:
```bash
python analytics/ml/train_fusion.py
```
This updates `fusion_weights.json` configurations in `analytics/ml/models/urban/`, `rural/`, and `highway/`.

### 3. Evaluating Machine Learning Models
To evaluate the combined GAT + LSTM-AE + Fusion model classification metrics:
```bash
python analytics/ml/evaluate_all.py \
  --attack_number 1 \
  --attack_pct 20 \
  --speed 20 \
  --speed_label low \
  --beacon_csv analytics/ml/data/beacon_train_master.csv \
  --output results/evaluation_report.csv
```
This performs inference using the new scenario folder structure and writes MCC/FPR tables.
