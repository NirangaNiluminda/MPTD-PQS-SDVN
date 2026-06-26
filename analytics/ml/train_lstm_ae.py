"""
train_lstm_ae.py — Phase 1c LSTM-AE Training Pipeline
Trains scenario-specific LSTM-AE temporal anomaly detectors.
"""

import os
import sys
import json
import argparse
import math

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from lstm_ae import LSTMAEDetector, build_windows, calibrate_threshold, WINDOW_SIZE, FEATURE_DIM

# --- Constants ---
SCENARIOS = ["urban", "rural", "highway"]
BETA_CANDIDATES = [0.01, 0.05, 0.1, 0.5]
SCENARIO_BETA_DEFAULTS = {
    "urban":   0.01,
    "rural":   0.05,
    "highway": 0.1,
}
TRAIN_FRAC = 0.60
VAL_FRAC   = 0.20
DEVICE     = torch.device("cuda" if torch.cuda.is_available() else "cpu")
EPOCHS     = 50
BATCH_SIZE = 32
LR         = 1e-3
KAPPA      = 3.0
DT         = 0.1


def load_beacon_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if "run_id" not in df.columns:
        BOUNDARY_DROP = 2.0
        prev = df["sim_time"].shift(1)
        new_run = (prev.notna() & ((prev - df["sim_time"]) > BOUNDARY_DROP))
        df["run_id"] = new_run.cumsum().astype(int)
    return df


def filter_clean_only(df: pd.DataFrame) -> pd.DataFrame:
    if "is_poisoned" in df.columns:
        df = df[df["is_poisoned"] == 0].copy()
    return df


def temporal_split(df: pd.DataFrame, train_frac: float = TRAIN_FRAC, val_frac: float = VAL_FRAC):
    train_parts, val_parts, held_parts = [], [], []
    for run_id, rdf in df.groupby("run_id"):
        t_min = rdf["sim_time"].min()
        t_max = rdf["sim_time"].max()
        t_range = t_max - t_min
        if t_range <= 0:
            continue
        t_train_end = t_min + train_frac * t_range
        t_val_end   = t_min + (train_frac + val_frac) * t_range
        train_parts.append(rdf[rdf["sim_time"] < t_train_end])
        val_parts.append(rdf[(rdf["sim_time"] >= t_train_end) & (rdf["sim_time"] < t_val_end)])
        held_parts.append(rdf[rdf["sim_time"] >= t_val_end])

    train_df = pd.concat(train_parts, ignore_index=True) if train_parts else pd.DataFrame()
    val_df   = pd.concat(val_parts, ignore_index=True) if val_parts else pd.DataFrame()
    held_df  = pd.concat(held_parts, ignore_index=True) if held_parts else pd.DataFrame()
    return train_df, val_df, held_df


def build_all_windows(df: pd.DataFrame) -> np.ndarray:
    group_keys = ["run_id", "vehicle_id"] if "run_id" in df.columns else ["vehicle_id"]
    all_windows = []
    for _key, vdf in df.groupby(group_keys):
        vdf = vdf.sort_values("sim_time").reset_index(drop=True)
        wins = build_windows(vdf, vehicle_id=vdf["vehicle_id"].iloc[0])
        if len(wins) > 0:
            all_windows.append(wins)
    if not all_windows:
        return np.empty((0, WINDOW_SIZE, FEATURE_DIM), dtype=np.float32)
    return np.concatenate(all_windows, axis=0).astype(np.float32)


def kinematic_loss(recon: torch.Tensor, dt: float = DT) -> torch.Tensor:
    DELTA_TH = 10.0
    pos_x   = recon[:, :, 0]
    pos_y   = recon[:, :, 1]
    speed   = recon[:, :, 2]
    heading = recon[:, :, 3]
    pred_x = pos_x[:, :-1] + speed[:, :-1] * torch.cos(heading[:, :-1]) * dt
    pred_y = pos_y[:, :-1] + speed[:, :-1] * torch.sin(heading[:, :-1]) * dt
    r = torch.sqrt((pos_x[:, 1:] - pred_x) ** 2 + (pos_y[:, 1:] - pred_y) ** 2 + 1e-8)
    hinge = torch.clamp(r - DELTA_TH, min=0.0) ** 2
    return hinge.mean()


def train_model(train_windows: np.ndarray, val_windows: np.ndarray, beta: float, scaler: StandardScaler, epochs: int = EPOCHS):
    n_train = len(train_windows)
    n_val   = len(val_windows)
    train_flat = train_windows.reshape(-1, FEATURE_DIM)
    val_flat   = val_windows.reshape(-1, FEATURE_DIM)
    train_norm = scaler.transform(train_flat).reshape(n_train, WINDOW_SIZE, FEATURE_DIM)
    val_norm   = scaler.transform(val_flat).reshape(n_val, WINDOW_SIZE, FEATURE_DIM)

    train_t = torch.tensor(train_norm, dtype=torch.float32)
    val_t   = torch.tensor(val_norm, dtype=torch.float32)

    mean_t = torch.tensor(scaler.mean_, dtype=torch.float32, device=DEVICE).view(1, 1, FEATURE_DIM)
    scale_t = torch.tensor(scaler.scale_, dtype=torch.float32, device=DEVICE).view(1, 1, FEATURE_DIM)

    model   = LSTMAEDetector().to(DEVICE)
    opt     = torch.optim.Adam(model.parameters(), lr=LR)
    loss_fn = nn.MSELoss()

    history = []
    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        n_batches = 0
        for i in range(0, len(train_t), BATCH_SIZE):
            batch = train_t[i:i+BATCH_SIZE].to(DEVICE)
            opt.zero_grad()
            recon = model(batch)
            # Unnormalize recon to physical units for kinematic loss calculation
            recon_raw = recon * scale_t + mean_t
            loss = loss_fn(recon, batch) + beta * kinematic_loss(recon_raw)
            loss.backward()
            opt.step()
            total_loss += loss.item()
            n_batches += 1

        # Validation
        model.eval()
        with torch.no_grad():
            val_recon = model(val_t.to(DEVICE))
            val_loss  = loss_fn(val_recon, val_t.to(DEVICE)).item()

        history.append({"epoch": epoch + 1, "train_loss": round(total_loss / max(n_batches, 1), 6), "val_loss": round(val_loss, 6)})
        if (epoch + 1) % 10 == 0:
            print(f"      Epoch {epoch+1:3d}/{epochs}  train_loss={total_loss / max(n_batches, 1):.6f}  val_loss={val_loss:.6f}")
    return model, history


def sweep_beta(train_windows: np.ndarray, val_windows: np.ndarray, scaler: StandardScaler, candidates: list = BETA_CANDIDATES, epochs: int = EPOCHS) -> dict:
    results = []
    best_beta = candidates[0]
    best_val_loss = float('inf')
    for beta in candidates:
        print(f"\n    [β sweep] β = {beta}")
        model, history = train_model(train_windows, val_windows, beta, scaler, epochs=epochs)
        final_val = history[-1]["val_loss"]
        theta_ae = calibrate_threshold(
            model,
            torch.tensor(scaler.transform(val_windows.reshape(-1, FEATURE_DIM)).reshape(len(val_windows), WINDOW_SIZE, FEATURE_DIM), dtype=torch.float32),
            kappa=KAPPA, device=DEVICE
        )
        results.append({"beta": beta, "final_val_loss": final_val, "theta_ae": theta_ae})
        if final_val < best_val_loss:
            best_val_loss = final_val
            best_beta = beta
        print(f"    [β sweep] β={beta} → val_loss={final_val:.6f}, θ_ae={theta_ae:.6f}")
    return {"best_beta": best_beta, "results": results}


def train_scenario(scenario: str, data_dir: str, out_dir: str, do_sweep: bool = False, epochs: int = EPOCHS):
    print(f"\n{'='*60}\n  Phase 1c — LSTM-AE Training: {scenario.upper()}\n{'='*60}")
    scenario_csv = os.path.join(data_dir, f"beacon_clean_{scenario}.csv")
    master_csv   = os.path.join(data_dir, "beacon_train_master.csv")

    if os.path.exists(scenario_csv):
        df = load_beacon_csv(scenario_csv)
    elif os.path.exists(master_csv):
        df = load_beacon_csv(master_csv)
    else:
        print("  [ERROR] No dataset found. Exiting.")
        return

    df = filter_clean_only(df)
    train_df, val_df, _ = temporal_split(df)
    train_windows = build_all_windows(train_df)
    val_windows   = build_all_windows(val_df)

    if len(train_windows) < 2 or len(val_windows) < 2:
        all_windows = build_all_windows(df)
        train_idx, val_idx = train_test_split(np.arange(len(all_windows)), test_size=0.2, random_state=42)
        train_windows = all_windows[train_idx]
        val_windows   = all_windows[val_idx]

    scaler = StandardScaler()
    scaler.fit(train_windows.reshape(-1, FEATURE_DIM))

    if do_sweep:
        sweep_result = sweep_beta(train_windows, val_windows, scaler, epochs=epochs)
        beta = sweep_result["best_beta"]
        sweep_list = sweep_result["results"]
    else:
        beta = SCENARIO_BETA_DEFAULTS.get(scenario, 0.1)
        sweep_list = []

    model, loss_history = train_model(train_windows, val_windows, beta, scaler, epochs=epochs)

    # Threshold calibration
    val_norm = scaler.transform(val_windows.reshape(-1, FEATURE_DIM)).reshape(len(val_windows), WINDOW_SIZE, FEATURE_DIM)
    theta_ae = calibrate_threshold(model, torch.tensor(val_norm, dtype=torch.float32), kappa=KAPPA, device=DEVICE)

    # Save outputs
    os.makedirs(out_dir, exist_ok=True)
    torch.save(model.state_dict(), os.path.join(out_dir, f"lstm_ae_{scenario}.pt"))
    
    with open(os.path.join(out_dir, f"scaler_{scenario}.json"), "w") as f:
        json.dump({"feature_names": ["pos_x", "pos_y", "speed", "heading", "accel", "tau_i"], "mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist()}, f, indent=2)

    with open(os.path.join(out_dir, f"theta_ae_{scenario}.txt"), "w") as f:
        f.write(str(theta_ae))

    # Save meta json
    meta = {
        "scenario": scenario,
        "beta": beta,
        "theta_ae": theta_ae,
        "kappa": KAPPA,
        "epochs": epochs,
        "window_size": WINDOW_SIZE,
        "feature_dim": FEATURE_DIM,
        "n_train_windows": len(train_windows),
        "n_val_windows": len(val_windows),
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": scaler.scale_.tolist(),
        "final_train_loss": loss_history[-1]["train_loss"],
        "final_val_loss": loss_history[-1]["val_loss"],
        "loss_history": loss_history,
        "beta_sweep": {
            "best_beta": beta,
            "results": sweep_list
        }
    }
    with open(os.path.join(out_dir, f"lstm_ae_{scenario}_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)

    # ONNX export
    onnx_path = os.path.join(out_dir, f"lstm_ae_{scenario}.onnx")
    try:
        dummy = torch.randn(1, WINDOW_SIZE, FEATURE_DIM, dtype=torch.float32)
        torch.onnx.export(model.cpu(), dummy, onnx_path, input_names=["x"], output_names=["recon"], dynamic_axes={"x": {0: "B"}, "recon": {0: "B"}}, opset_version=16)
        print(f"  Exported ONNX → {onnx_path}")
    except Exception as e:
        print(f"  [WARNING] ONNX export failed: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", type=str, default="analytics/ml/data")
    parser.add_argument("--out_dir", type=str, default="analytics/ml/models")
    parser.add_argument("--sweep_beta", action="store_true")
    args = parser.parse_args()
    
    for scenario in SCENARIOS:
        train_scenario(scenario=scenario, data_dir=args.data_dir, out_dir=args.out_dir, do_sweep=args.sweep_beta)


if __name__ == "__main__":
    main()
