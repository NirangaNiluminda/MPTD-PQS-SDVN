# MPTD-PQS Machine Learning Pipeline (Phase 2 & Phase 3)

This directory contains the Machine Learning (ML) source code, training scripts, evaluation suite, and scenario-specific models for the **MPTD-PQS-SDVN** detection framework.

---

## 1. Directory Structure

The assets are structured to maintain scenario separation while enabling dynamic selection at simulation runtime:

```
analytics/ml/
├── data/                          # Training and validation datasets
│   └── beacon_train_master.csv    # Master CSV with raw/poisoned beacons
├── models/                        # Trained models and calibration parameters
│   ├── shared/                    # Shared spatial models
│   │   ├── gat_model.pt           # PyTorch GAT model weights
│   │   └── gat_model.onnx         # ONNX spatial graph model
│   ├── urban/                     # Urban mobility scenario (<= 15 m/s)
│   │   ├── lstm_ae_model.pt       # PyTorch LSTM temporal autoencoder
│   │   ├── lstm_ae_model.onnx     # ONNX temporal model
│   │   ├── scaler.json            # StandardScaler params (mean, scale)
│   │   ├── theta_ae.txt           # Calibrated reconstruction threshold (θ_ae)
│   │   └── fusion_weights.json    # Optimal score fusion weights (λ_k)
│   ├── rural/                     # Rural mobility scenario (15 - 35 m/s)
│   │   ├── lstm_ae_model.pt
│   │   ├── lstm_ae_model.onnx
│   │   ├── scaler.json
│   │   ├── theta_ae.txt
│   │   └── fusion_weights.json
│   ├── highway/                   # Highway mobility scenario (> 35 m/s)
│   │   ├── lstm_ae_model.pt
│   │   ├── lstm_ae_model.onnx
│   │   ├── scaler.json
│   │   ├── theta_ae.txt
│   │   └── fusion_weights.json
│   └── ...                        # Default fallback asset copies
├── plots/                         # Evaluation and analysis curves
├── gat_detector.py                # Graph Attention Network (GAT) definition
├── lstm_ae.py                     # Long Short-Term Memory Autoencoder definition
├── score_fusion.py                # SLSQP weight optimization solver
├── train.py                       # Trainer for GAT spatial model
├── train_lstm_ae.py               # Trainer for LSTM-AE temporal models
├── train_fusion.py                # Phase 2 score fusion optimizer
├── evaluate_all.py                # Evaluation pipeline and baseline comparer
└── requirements.txt               # Dependencies list
```

---

## 2. Core Components & Scripts

### A. Model Architectures
- **`gat_detector.py`**: Defines the `GATDetector` spatial graph network. Builds spatial graphs of vehicles within range ($R_{max} = 300\text{m}$) and computes cooperative trust anomaly scores.
- **`lstm_ae.py`**: Defines the `LSTMAEDetector` temporal autoencoder. Takes sliding windows of 20 beacons per vehicle and calculates reconstruction errors.
- **`score_fusion.py`**: Formulates score fusion as a constrained optimization problem. Learn weights ($\lambda_1, \lambda_2, \lambda_3$) satisfying $\sum \lambda_k = 1.0$ and $\lambda_k \ge 0.05$ using Sequential Least Squares Programming (SLSQP).

### B. Training Pipeline
1. **`train.py`**: Train the spatial GAT network on cooperative beacon topology.
2. **`train_lstm_ae.py`**: Trains the temporal autoencoder independently for each scenario (Urban, Rural, Highway) and calibrates reconstruction threshold $\theta_{ae}$ using benign training logs.
3. **`train_fusion.py`**: Segregates training beacons by vehicle speed, scores GAT and LSTM-AE models, and runs the SLSQP optimizer to save optimal weights (`fusion_weights.json`) for each scenario directory.

### C. Evaluation & Inference
- **`evaluate_all.py`**: Performs end-to-end evaluation. Standardizes features with scenario scalers, runs joint GAT + LSTM-AE inference, applies fusion weights, and outputs MCC/FPR tables.
- **`prediction_server.py`**: REST API bridge for real-time inference during testing or live-deployment mode.

---

## 3. Workflow & Usage

### Setup virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run Score Fusion Weight Optimization (Phase 2)
Optimize fusion weights across speed regimes using the master training set:
```bash
python analytics/ml/train_fusion.py
```
This writes the learned weights directly into the scenario directories (`urban`, `rural`, `highway`).

### Run Offline Evaluation
Evaluate classification metrics (MCC, FPR) for a specific scenario:
```bash
python analytics/ml/evaluate_all.py \
  --attack_number 1 \
  --attack_pct 20 \
  --speed 20 \
  --speed_label low \
  --beacon_csv analytics/ml/data/beacon_train_master.csv \
  --output results/evaluation_report.csv
```
This loads assets dynamically from the corresponding scenario subdirectory, computes intermediate scores, fuses them, and saves the outputs.
