"""
train_fusion.py — Phase 2 Score Fusion Weight Learning
Optimises scenario-specific fusion weights (lambda_1, lambda_2, lambda_3)
using SLSQP constrained optimization over training data.

The LSTM-AE score is computed with the SAME 6-dim model deployed to ns-3
(lstm_detector, [5 kinematic + tau_i], window=10). tau is z-scaled by the
6-dim scaler (trusted tau=1.0 -> 0.0); GAT keeps tau raw at 1.0. This makes the
learned lambda match the runtime epsilon/theta_ae distribution the C++ produces.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import torch

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, REPO_ROOT)

from gat_detector import GATDetector, score_snapshot
from score_fusion import learn_weights
from lstm_detector.model import LSTMAEDetector  # 6-dim bottleneck AE (deployed)

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LSTM_CKPT_DIR = os.path.join(REPO_ROOT, "lstm_detector", "checkpoints")


def _infer_ae_dims(sd):
    """Recover (feat_dim, hidden, latent, num_layers) from a checkpoint state_dict."""
    feat_dim = sd["encoder.weight_ih_l0"].shape[1]
    hidden   = sd["encoder.weight_ih_l0"].shape[0] // 4
    latent   = sd["to_latent.weight"].shape[0]
    num_layers = sum(1 for k in sd if k.startswith("encoder.weight_ih_l"))
    return feat_dim, hidden, latent, num_layers


def score_ae_window(ae, window_6):
    """Reconstruction MSE for one (window, 6) z-scaled window — mirrors the C++
    score_lstm_ae MSE over all window*6 cells."""
    x = torch.tensor(window_6, dtype=torch.float32, device=DEVICE).unsqueeze(0)
    with torch.no_grad():
        recon = ae(x)
    return float(((recon - x) ** 2).mean().cpu())

def get_scenario_for_run(run_df: pd.DataFrame) -> str:
    """
    Categorise a run into a scenario based on its maximum speed (m/s).
    - Urban: max speed <= 15.0 m/s
    - Rural: 15.0 < max speed <= 35.0 m/s
    - Highway: max speed > 35.0 m/s
    """
    max_speed = run_df["speed"].max()
    if max_speed <= 15.0:
        return "urban"
    elif max_speed <= 35.0:
        return "rural"
    else:
        return "highway"

def load_scenario_assets(scenario: str):
    """
    Load GAT (shared, 6-dim) + the deployed scenario-specific 6-dim LSTM-AE,
    its 6-dim scaler, per-scenario theta_ae, and window length.
    """
    # GAT model (shared)
    gat = GATDetector(in_dim=6).to(DEVICE)
    gat_path = os.path.join(MODEL_DIR, "shared", "gat_model.pt")
    if not os.path.exists(gat_path):
        gat_path = os.path.join(MODEL_DIR, "gat_model.pt")
    if os.path.exists(gat_path):
        gat.load_state_dict(torch.load(gat_path, map_location=DEVICE))
    gat.eval()

    # LSTM-AE model — the exact 6-dim checkpoint promoted to ns-3 (paper d=6).
    # Architecture dims are read from the checkpoint so the module matches the
    # trained weights (arch search produced hidden=32/latent=16, not defaults).
    ae_path = os.path.join(LSTM_CKPT_DIR, f"lstm_ae_{scenario}.pt")
    sd = torch.load(ae_path, map_location=DEVICE)
    feat_dim, hidden, latent, num_layers = _infer_ae_dims(sd)
    ae = LSTMAEDetector(feat_dim=feat_dim, hidden=hidden,
                        latent=latent, num_layers=num_layers).to(DEVICE)
    ae.load_state_dict(sd)
    ae.eval()

    # Window length from the selected architecture (all scenarios = 10).
    window = 10
    arch_path = os.path.join(LSTM_CKPT_DIR, f"arch_{scenario}.json")
    if os.path.exists(arch_path):
        with open(arch_path) as f:
            window = int(json.load(f).get("window", 10))

    # 6-dim scaler (5 kinematic + tau_i) — same file deployed to ns-3.
    scaler_path = os.path.join(LSTM_CKPT_DIR, f"scaler_{scenario}.json")
    if not os.path.exists(scaler_path):
        scaler_path = os.path.join(MODEL_DIR, scenario, "scaler.json")
    with open(scaler_path, "r") as f:
        scaler_data = json.load(f)
    mean = np.array(scaler_data["mean"], dtype=np.float32)
    scale = np.array(scaler_data["scale"], dtype=np.float32)

    # theta_ae — per-scenario calibrated threshold (median + kappa*MAD).
    theta_path = os.path.join(LSTM_CKPT_DIR, f"theta_ae_{scenario}.txt")
    if not os.path.exists(theta_path):
        theta_path = os.path.join(MODEL_DIR, scenario, "theta_ae.txt")
    with open(theta_path, "r") as f:
        theta_ae = float(f.read().strip())

    return gat, ae, mean, scale, theta_ae, window

def process_scenario(scenario: str, runs: list):
    """
    Runs model scoring and optimizes the fusion weights for a single scenario.
    """
    print(f"\n============================================================")
    print(f"Processing scenario: {scenario.upper()} ({len(runs)} runs)")
    print(f"============================================================")

    if len(runs) == 0:
        print(f"No runs found for scenario {scenario}. Skipping.")
        return

    # Load assets
    try:
        gat, ae, mean, scale, theta_ae, window = load_scenario_assets(scenario)
        print(f"Loaded assets for {scenario}: theta_ae={theta_ae:.6f} window={window}")
    except Exception as e:
        print(f"Failed to load assets for {scenario}: {e}. Skipping.")
        return

    psi_list = []
    gat_list = []
    ae_err_list = []
    label_list = []

    feat_cols = ["pos_x", "pos_y", "speed", "heading", "accel"]

    for run_idx, run_df in enumerate(runs):
        run_df = run_df.sort_values("sim_time").copy()
        
        # 1. Scale the 5 kinematic features with the 6-dim scaler's first 5 rows.
        kin = run_df[feat_cols].values.astype(np.float32)
        scaled_kin = (kin - mean[:5]) / np.where(scale[:5] == 0.0, 1.0, scale[:5])

        # tau_i defaults to 1.0 (trusted). The GAT path appends it RAW (=1.0);
        # the AE path z-scales it with the 6th scaler row (mean=1,scale=1 -> 0.0),
        # matching the C++ GAT (raw tau) vs LSTM (scaled tau) split.
        tau_ae = np.float32((1.0 - mean[5]) / (1.0 if scale[5] == 0.0 else scale[5]))

        for col_idx, col_name in enumerate(feat_cols):
            run_df[f"scaled_{col_name}"] = scaled_kin[:, col_idx]
        run_df["tau_gat"] = np.float32(1.0)   # raw tau for GAT
        run_df["tau_ae"]  = tau_ae            # scaled tau for AE

        # 2. Group by _tick to generate GAT scores
        T_B = 0.1
        run_df["_tick"] = (run_df["sim_time"] / T_B).round().astype(int)
        
        gat_scores_map = {}
        for t, grp in run_df.groupby("_tick"):
            grp_feats = grp[[f"scaled_{c}" for c in feat_cols] + ["tau_gat"]].values.astype(np.float32)
            # Run GAT
            gat_out = score_snapshot(gat, grp_feats, device=DEVICE)
            for idx, row_id in enumerate(grp.index):
                gat_scores_map[row_id] = gat_out[idx]

        run_df["gat_score"] = run_df.index.map(gat_scores_map)

        # 3. Sliding windows per vehicle to generate LSTM-AE scores. The AE
        # consumes 6 features [5 scaled kinematic + scaled tau_i], window=L,
        # exactly as the deployed ns-3 ring buffer feeds score_lstm_ae.
        ae_cols = [f"scaled_{c}" for c in feat_cols] + ["tau_ae"]
        ae_win = {}  # vehicle_id -> list of 6-feature rows
        ae_errors = []

        for row_idx, row in run_df.iterrows():
            vid = row["vehicle_id"]
            feat_row = row[ae_cols].values.astype(np.float32)

            if vid not in ae_win:
                ae_win[vid] = []
            ae_win[vid].append(feat_row)
            if len(ae_win[vid]) > window:
                ae_win[vid].pop(0)

            if len(ae_win[vid]) == window:
                w_arr = np.array(ae_win[vid], dtype=np.float32)
                ae_err = score_ae_window(ae, w_arr)
                ae_errors.append((row_idx, ae_err))
            else:
                ae_errors.append((row_idx, -1.0))  # Sentinel for incomplete window

        ae_err_df = pd.DataFrame(ae_errors, columns=["row_idx", "ae_error"]).set_index("row_idx")
        run_df["ae_error"] = ae_err_df["ae_error"]

        # Only keep rows where the window is complete
        valid_df = run_df[run_df["ae_error"] >= 0.0]
        
        if len(valid_df) > 0:
            psi_list.extend(valid_df["psi_score"].values)
            gat_list.extend(valid_df["gat_score"].values)
            ae_err_list.extend(valid_df["ae_error"].values)
            label_list.extend(valid_df["is_poisoned"].values)

        if (run_idx + 1) % 10 == 0 or (run_idx + 1) == len(runs):
            print(f"  Scored {run_idx + 1}/{len(runs)} runs...")

    if len(label_list) < 50:
        print(f"Insufficient scored samples ({len(label_list)}) for optimization. Skipping.")
        return

    psi_arr = np.array(psi_list, dtype=np.float32)
    gat_arr = np.array(gat_list, dtype=np.float32)
    ae_norm_arr = np.clip(np.array(ae_err_list, dtype=np.float32) / theta_ae, 0.0, 1.0)
    labels = np.array(label_list, dtype=np.float32)

    # 4. Optimize fusion weights
    print(f"Optimizing weights over {len(labels)} samples...")
    l1, l2, l3 = learn_weights(psi_arr, gat_arr, ae_norm_arr, labels, verbose=True)

    # Save to scenario-specific JSON
    weights = {
        "lambda_psi": float(l1),
        "lambda_gat": float(l2),
        "lambda_ae": float(l3),
        "phi_threshold": 0.5
    }
    
    out_path = os.path.join(MODEL_DIR, scenario, "fusion_weights.json")
    legacy_out_path = os.path.join(MODEL_DIR, f"fusion_weights_{scenario}.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(weights, f, indent=2)
    with open(legacy_out_path, "w") as f:
        json.dump(weights, f, indent=2)
    print(f"Saved weights to {out_path} and {legacy_out_path}")

    # Return weights if this is the default scenario to copy
    return weights

def main():
    master_csv = os.path.join(DATA_DIR, "beacon_train_master.csv")
    if not os.path.exists(master_csv):
        print(f"[ERROR] Master CSV not found at {master_csv}")
        return

    print(f"Loading master CSV from {master_csv}...")
    df = pd.read_csv(master_csv)

    # Segment into individual runs using boundary drop = 2.0
    if "run_id" not in df.columns:
        BOUNDARY_DROP = 2.0
        prev = df["sim_time"].shift(1)
        new_run = (prev.notna() & ((prev - df["sim_time"]) > BOUNDARY_DROP))
        df["run_id"] = new_run.cumsum().astype(int)

    # Group runs by scenario based on speed
    scenarios_runs = {"urban": [], "rural": [], "highway": []}
    
    for run_id, run_df in df.groupby("run_id"):
        scenario = get_scenario_for_run(run_df)
        scenarios_runs[scenario].append(run_df)

    urban_weights = None
    for scenario in ["urban", "rural", "highway"]:
        weights = process_scenario(scenario, scenarios_runs[scenario])
        if scenario == "urban":
            urban_weights = weights

    # Copy urban weights to generic fusion_weights.json as the default copy
    if urban_weights is not None:
        default_path = os.path.join(MODEL_DIR, "fusion_weights.json")
        with open(default_path, "w") as f:
            json.dump(urban_weights, f, indent=2)
        print(f"\nSaved default weights copy to {default_path}")

if __name__ == "__main__":
    main()
