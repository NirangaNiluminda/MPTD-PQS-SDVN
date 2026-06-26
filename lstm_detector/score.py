import os
import sys
import argparse
import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import matthews_corrcoef, f1_score, confusion_matrix

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lstm_detector.config import SCENARIOS, WINDOW_SIZE, FEATURE_DIM, CHECKPOINT_DIR
from lstm_detector.model import LSTMAEDetector
from lstm_detector.dataset import load_beacon_csv, build_all_windows
from lstm_detector.train import calibrate_threshold

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def score_window(model: torch.nn.Module, window_seq: np.ndarray) -> float:
    model.eval()
    x = torch.tensor(window_seq, dtype=torch.float32).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        recon = model(x)
    return float(((recon - x) ** 2).mean().cpu())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True, choices=SCENARIOS)
    parser.add_argument("--attack_csv", required=True)
    args = parser.parse_args()

    print(f"\nScoring Scenario: {args.scenario.upper()} with file {args.attack_csv}")
    
    # Load model
    model = LSTMAEDetector().to(DEVICE)
    model_path = os.path.join(CHECKPOINT_DIR, f"lstm_ae_{args.scenario}.pt")
    if not os.path.exists(model_path):
        print(f"Error: Model checkpoint {model_path} not found.")
        return
    model.load_state_dict(torch.load(model_path, map_location=DEVICE))
    model.eval()

    # Load scaler
    scaler_path = os.path.join(CHECKPOINT_DIR, f"scaler_{args.scenario}.json")
    if not os.path.exists(scaler_path):
        print(f"Error: Scaler JSON {scaler_path} not found.")
        return
    import json
    with open(scaler_path) as f:
        scaler_data = json.load(f)
    scaler = StandardScaler()
    scaler.mean_ = np.array(scaler_data["mean"], dtype=np.float64)
    scaler.scale_ = np.array(scaler_data["scale"], dtype=np.float64)
    scaler.var_ = scaler.scale_ ** 2
    scaler.n_features_in_ = len(scaler.mean_)

    # Load threshold
    th_path = os.path.join(CHECKPOINT_DIR, f"theta_ae_{args.scenario}.txt")
    if not os.path.exists(th_path):
        print(f"Error: Threshold text file {th_path} not found.")
        return
    theta_ae = float(open(th_path).read().strip())
    print(f"Loaded threshold θ_ae = {theta_ae:.6f}")

    # Load data and score
    df = load_beacon_csv(args.attack_csv)
    windows = build_all_windows(df)
    if len(windows) == 0:
        print("No sequence windows could be built from the CSV file.")
        return

    # Normalize
    wins_norm = scaler.transform(windows.reshape(-1, FEATURE_DIM)).reshape(len(windows), WINDOW_SIZE, FEATURE_DIM)
    
    print(f"Scoring {len(wins_norm)} windows...")
    errors = []
    for w in wins_norm:
        err = score_window(model, w)
        errors.append(err)
    errors = np.array(errors)

    anomalies = errors > theta_ae
    anomaly_pct = anomalies.mean() * 100
    print(f"Mean Reconstruction Error: {errors.mean():.6f}")
    print(f"Max Reconstruction Error:  {errors.max():.6f}")
    print(f"Detected Anomalous Windows: {anomalies.sum()} / {len(anomalies)} ({anomaly_pct:.2f}%)")

    # Extract window labels for alignment (using label of last step of each window)
    group_keys = ["run_id", "vehicle_id"] if "run_id" in df.columns else ["vehicle_id"]
    y_list = []
    label_col = "is_poisoned" if "is_poisoned" in df.columns else ("label" if "label" in df.columns else None)
    if label_col is not None:
        for _key, vdf in df.groupby(group_keys):
            vdf = vdf.sort_values("sim_time").reset_index(drop=True)
            lbls = vdf[label_col].values
            if len(lbls) >= WINDOW_SIZE:
                y_list.extend(lbls[WINDOW_SIZE-1:])
        y_labels = np.array(y_list)
    else:
        y_labels = None

    # Write outputs
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{args.scenario}_scores.csv")
    
    df_out = pd.DataFrame({"recon_error": errors})
    if y_labels is not None and len(y_labels) == len(errors):
        df_out["label"] = y_labels
        if len(np.unique(y_labels)) >= 2:
            mcc = matthews_corrcoef(y_labels, anomalies.astype(int))
            f1 = f1_score(y_labels, anomalies.astype(int), zero_division=0)
            tn, fp, fn, tp = confusion_matrix(y_labels, anomalies.astype(int)).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            print(f"[LSTM Temporal Detector] MCC={mcc:.3f}  F1={f1:.3f}  FPR={fpr:.3f}  (TP={tp} FP={fp} FN={fn} TN={tn})")
            
    df_out.to_csv(out_path, index=False)
    print(f"Saved scores to {out_path}")

if __name__ == "__main__":
    main()
