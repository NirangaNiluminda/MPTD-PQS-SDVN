import os
import sys
import json
import argparse
import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

# Add the parent directory of the current script to the system path to resolve local module imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lstm_detector.config import (
    FEATURE_DIM, EPOCHS, BATCH_SIZE, LR, DT, KAPPA,
    SCENARIOS, BETA_CANDIDATES, SCENARIO_BETA_DEFAULTS, CHECKPOINT_DIR
)
from lstm_detector.model import LSTMAEDetector
from lstm_detector.dataset import load_beacon_csv, filter_clean_only, temporal_split, build_all_windows

# Set device to GPU if available, otherwise fallback to CPU
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def kinematic_loss(recon_raw: torch.Tensor, dt: float = DT) -> torch.Tensor:
    """
    Computes the physics-informed kinematic constraint loss (Paper Eq. 3.39).
    Verifies that the predicted next state coordinates (pred_x, pred_y) match the 
    actual physical kinematics (dead reckoning check).
    
    Args:
        recon_raw: Unnormalized reconstructed trajectories of shape [Batch, SeqLen, Features]
        dt: The time step interval between sequence points (default = 0.1s)
    """
    DELTA_TH = 10.0  # Safe physical distance threshold bound
    
    # Extract kinematic parameters: pos_x (index 0), pos_y (index 1), speed (index 2), heading (index 3)
    pos_x   = recon_raw[:, :, 0]
    pos_y   = recon_raw[:, :, 1]
    speed   = recon_raw[:, :, 2]
    heading = recon_raw[:, :, 3]
    
    # Predict next step position based on dead reckoning kinematics equations
    pred_x = pos_x[:, :-1] + speed[:, :-1] * torch.cos(heading[:, :-1]) * dt
    pred_y = pos_y[:, :-1] + speed[:, :-1] * torch.sin(heading[:, :-1]) * dt
    
    # Calculate Euclidean distance between actual next position and predicted position
    r = torch.sqrt((pos_x[:, 1:] - pred_x) ** 2 + (pos_y[:, 1:] - pred_y) ** 2 + 1e-8)
    
    # Apply a hinge loss: penalize only deviations greater than DELTA_TH
    hinge = torch.clamp(r - DELTA_TH, min=0.0) ** 2
    return hinge.mean()

def train_model(train_wins: np.ndarray, val_wins: np.ndarray, beta: float, scaler: StandardScaler, epochs: int = EPOCHS):
    """
    Trains the LSTM Autoencoder model on benign trajectory windows.
    
    Args:
        train_wins: Training window sequences of shape [NumWindows, WindowSize, Features]
        val_wins: Validation window sequences of shape [NumWindows, WindowSize, Features]
        beta: Weight factor for the kinematic loss regularizer (Equation 3.45)
        scaler: Pre-fitted StandardScaler for normalization
        epochs: Number of training epochs
    """
    # Normalize features using the pre-fitted training scaler
    train_norm = scaler.transform(train_wins.reshape(-1, FEATURE_DIM)).reshape(len(train_wins), -1, FEATURE_DIM)
    val_norm   = scaler.transform(val_wins.reshape(-1, FEATURE_DIM)).reshape(len(val_wins), -1, FEATURE_DIM)

    # Initialize model, optimizer, and reconstruction MSE loss function
    model = LSTMAEDetector().to(DEVICE)
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    loss_fn = nn.MSELoss()

    # Move scaler mean and scale values to the target device for unnormalizing during loss calculation
    mean_t = torch.tensor(scaler.mean_, dtype=torch.float32, device=DEVICE).view(1, 1, FEATURE_DIM)
    scale_t = torch.tensor(scaler.scale_, dtype=torch.float32, device=DEVICE).view(1, 1, FEATURE_DIM)

    history = []
    for epoch in range(1, epochs + 1):
        model.train()
        permutation = torch.randperm(len(train_norm))
        epoch_loss = 0.0
        
        # Batch iteration
        for i in range(0, len(train_norm), BATCH_SIZE):
            indices = permutation[i:i+BATCH_SIZE]
            batch = torch.tensor(train_norm[indices], dtype=torch.float32, device=DEVICE)
            optimizer.zero_grad()
            
            # Forward pass: reconstruct the input sequence window
            recon = model(batch)

            # Un-normalize back to physical units to calculate kinematic physics loss
            recon_raw = recon * scale_t + mean_t

            # Combined Loss = Reconstruction Loss (MSE) + Beta * Kinematic Physical Loss
            loss = loss_fn(recon, batch) + beta * kinematic_loss(recon_raw)
            
            # Backward pass and weight updates
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item() * len(batch)
            
        epoch_loss /= len(train_norm)

        # Validation phase
        model.eval()
        with torch.no_grad():
            val_batch = torch.tensor(val_norm, dtype=torch.float32, device=DEVICE)
            val_recon = model(val_batch)
            val_recon_raw = val_recon * scale_t + mean_t
            val_loss = loss_fn(val_recon, val_batch) + beta * kinematic_loss(val_recon_raw)

        history.append({"epoch": epoch, "train_loss": epoch_loss, "val_loss": val_loss.item()})
        
        # Print progress update matching GAT style logs (every 5 epochs)
        if epoch == 1 or epoch % 5 == 0 or epoch == epochs:
            print(f"epoch {epoch:3d} | loss {epoch_loss:.6f} | val loss {val_loss.item():.6f}")
            
    return model, history

def calibrate_threshold(model: nn.Module, clean_windows: torch.Tensor, kappa: float = KAPPA) -> float:
    """
    Calibrates the anomaly detection threshold theta_ae from the clean reconstruction
    error distribution using robust statistics (Paper Eq. ta_threshold):

        theta_ae = median(E_clean) + kappa * MAD(E_clean)

    where MAD(E) = median(|E - median(E)|). Median+MAD replaces the previous mean+std
    rule because it resists outlier contamination in the clean calibration set, exactly
    as the paper mandates. NOTE: since MAD ~= 0.6745*std for normal data, a kappa tuned
    for the old mean+std rule will need re-tuning for this robust form.
    """
    model.eval()
    errors = []
    with torch.no_grad():
        for i in range(0, len(clean_windows), 64):
            batch = clean_windows[i:i+64].to(DEVICE)
            recon = model(batch)
            # Compute Mean Squared Error (MSE) reconstruction error per window
            mse   = ((recon - batch) ** 2).sum(dim=2).mean(dim=1)
            errors.extend(mse.cpu().numpy().tolist())

    errors = np.array(errors)
    # Robust threshold: median + kappa * MAD  (Paper Eq. ta_threshold)
    med = float(np.median(errors))
    mad = float(np.median(np.abs(errors - med)))
    theta = med + kappa * mad
    return theta

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True, choices=SCENARIOS, help="Target scenario (urban, rural, highway)")
    parser.add_argument("--clean_csv", required=True, help="Path to clean training CSV dataset")
    parser.add_argument("--epochs", type=int, default=EPOCHS, help="Number of training epochs")
    parser.add_argument("--sweep", action="store_true", help="Run beta parameter hyperparameter sweep")
    args = parser.parse_args()

    print(f"\nTraining LSTM-AE for Scenario: {args.scenario.upper()}")
    
    # Load and filter out any poisoned/anomaly data to ensure purely clean data for unsupervised learning
    df = load_beacon_csv(args.clean_csv)
    df = filter_clean_only(df)

    # Perform temporal split to prevent data leakage and build sequence windows
    train_df, val_df, _ = temporal_split(df)
    train_windows = build_all_windows(train_df)
    val_windows   = build_all_windows(val_df)

    # If the temporal split yields too few windows, fallback to a standard random train/validation split
    if len(train_windows) < 2 or len(val_windows) < 2:
        all_windows = build_all_windows(df)
        train_idx, val_idx = train_test_split(np.arange(len(all_windows)), test_size=0.2, random_state=42)
        train_windows = all_windows[train_idx]
        val_windows   = all_windows[val_idx]

    # Initialize and fit StandardScaler on the training data
    scaler = StandardScaler()
    scaler.fit(train_windows.reshape(-1, FEATURE_DIM))

    # Determine optimal beta value (either through a sweep or default scenario value)
    beta = SCENARIO_BETA_DEFAULTS[args.scenario]
    if args.sweep:
        print("Sweeping beta hyperparameters...")
        best_beta = beta
        best_val = float('inf')
        for b in BETA_CANDIDATES:
            _, hist = train_model(train_windows, val_windows, b, scaler, epochs=args.epochs)
            val_loss = hist[-1]["val_loss"]
            print(f"  Beta = {b} -> Val Loss = {val_loss:.6f}")
            if val_loss < best_val:
                best_val = val_loss
                best_beta = b
        beta = best_beta
        print(f"Selected Best Beta: {beta}")

    # Run the final training iteration with the chosen beta value
    print(f"Running final training run with Beta = {beta}...")
    model, history = train_model(train_windows, val_windows, beta, scaler, epochs=args.epochs)
    print(f"Final epoch train loss: {history[-1]['train_loss']:.6f}, val loss: {history[-1]['val_loss']:.6f}")

    # Calibrate anomaly threshold (theta_ae) on the validation set
    val_norm = scaler.transform(val_windows.reshape(-1, FEATURE_DIM)).reshape(len(val_windows), -1, FEATURE_DIM)
    theta_ae = calibrate_threshold(model, torch.tensor(val_norm, dtype=torch.float32), kappa=KAPPA)
    print(f"Calibrated Threshold: {theta_ae:.6f}")

    # Save model weights checkpoint
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    model_path = os.path.join(CHECKPOINT_DIR, f"lstm_ae_{args.scenario}.pt")
    torch.save(model.state_dict(), model_path)
    print(f"Saved model checkpoint to {model_path}")

    # Save scaler mean and scale parameter configuration as a JSON file
    scaler_path = os.path.join(CHECKPOINT_DIR, f"scaler_{args.scenario}.json")
    with open(scaler_path, "w") as f:
        json.dump({
            "feature_names": ["pos_x", "pos_y", "speed", "heading", "accel", "tau_i"],
            "mean": scaler.mean_.tolist(),
            "scale": scaler.scale_.tolist()
        }, f, indent=2)
    print(f"Saved scaler variables to {scaler_path}")

    # Save calibrated threshold value as a text file
    th_path = os.path.join(CHECKPOINT_DIR, f"theta_ae_{args.scenario}.txt")
    with open(th_path, "w") as f:
        f.write(f"{theta_ae:.6f}\n")
    print(f"Saved threshold to {th_path}")

if __name__ == "__main__":
    main()