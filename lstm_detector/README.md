# LSTM-AE Temporal Anomaly Detector

This folder contains the scenario-specific **LSTM-AE component** of the MPTD-PQS framework (the temporal anomaly detector, paper §3.4.3 / Eqs. 3.43–3.45).

---

## 1. Setup & Environment
The code is optimized to run on standard CPUs or CUDA-enabled GPUs. Required libraries are:
- `torch`
- `numpy`
- `pandas`
- `scikit-learn`

---

## 2. Directory Structure
- `data/` : Folder for clean trajectory CSVs (e.g. `beacon_clean_urban.csv`).
- `checkpoints/` : Contains the saved scenario-specific PyTorch models, JSON scalers, and threshold parameters.

---

## 3. Workflow

### Step 1: Scenario Training
To train the model on a clean trajectory CSV:
```bash
python train.py --scenario urban --clean_csv data/beacon_clean_urban.csv
```

Optional parameters:
- `--epochs 50` : Set training epochs.
- `--sweep` : Run a hyperparameter sweep over the physics regularizer weight $\beta$.

### Step 2: Scoring & Validation
To score an evaluation CSV and calculate anomaly rates:
```bash
python score.py --scenario urban --attack_csv data/urban_attack.csv
```
