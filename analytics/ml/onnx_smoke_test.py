#!/usr/bin/env python3
"""
onnx_smoke_test.py — R7g.2 standalone ONNX inference smoke test.

Verifies that gat_model.onnx and lstm_ae_model.onnx load via onnxruntime
and produce finite outputs of the expected shape on synthetic inputs that
mirror the C++ AiInferenceEngine in 06d_ai_inference.h.

Does NOT require Hyperledger Fabric or NS-3 to be running. Use this to
sanity-check model integrity after retraining, or before launching a sim
sweep, without paying simulation startup cost.

Expected I/O (from train.py and 06d_ai_inference.h):
  GAT      x: (N, 6)    float32   →   scores: (N, 1)   float32 ∈ [0,1]
  LSTM-AE  x: (B, 20, 5) float32  →   recon : (B,20,5) float32
"""
import json
import os
import sys
import numpy as np

try:
    import onnxruntime as ort
except ImportError:
    print("[smoke] FATAL: onnxruntime not installed (`pip install onnxruntime`)")
    sys.exit(2)


ML_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(ML_DIR, "models")

GAT_ONNX     = os.path.join(MODEL_DIR, "gat_model.onnx")
LSTM_AE_ONNX = os.path.join(MODEL_DIR, "lstm_ae_model.onnx")
SCALER_JSON  = os.path.join(MODEL_DIR, "scaler.json")
THETA_AE     = os.path.join(MODEL_DIR, "theta_ae.txt")

# Must match constants in 06d_ai_inference.h
GAT_FEATURE_DIM  = 6
LSTM_FEATURE_DIM = 5
LSTM_WINDOW_SIZE = 20
TAU_DEFAULT      = 1.0


def must_exist(path: str, label: str) -> None:
    if not os.path.exists(path):
        print(f"[smoke] FATAL: {label} missing at {path}")
        sys.exit(1)
    sz = os.path.getsize(path)
    print(f"[smoke] OK  {label:<14s} {sz:>9d} B  {path}")


def load_scaler() -> tuple[np.ndarray, np.ndarray]:
    with open(SCALER_JSON) as f:
        s = json.load(f)
    mean  = np.asarray(s["mean"],  dtype=np.float32)
    scale = np.asarray(s["scale"], dtype=np.float32)
    assert mean.shape  == (LSTM_FEATURE_DIM,), f"scaler.mean wrong shape: {mean.shape}"
    assert scale.shape == (LSTM_FEATURE_DIM,), f"scaler.scale wrong shape: {scale.shape}"
    print(f"[smoke] scaler.mean  = {mean.tolist()}")
    print(f"[smoke] scaler.scale = {scale.tolist()}")
    return mean, scale


def load_theta_ae() -> float:
    with open(THETA_AE) as f:
        theta = float(f.read().strip())
    print(f"[smoke] theta_ae     = {theta}")
    return theta


def smoke_gat(mean: np.ndarray, scale: np.ndarray) -> None:
    sess = ort.InferenceSession(GAT_ONNX, providers=["CPUExecutionProvider"])
    inputs = {i.name: (i.shape, i.type) for i in sess.get_inputs()}
    outputs = {o.name: (o.shape, o.type) for o in sess.get_outputs()}
    print(f"[smoke] GAT inputs : {inputs}")
    print(f"[smoke] GAT outputs: {outputs}")

    # Synthesize 16 vehicles in a plausible 1000x1000 m intersection,
    # mirroring the C++ side: normalize 5 kinematic cols, append tau=1.0.
    N = 16
    raw5 = np.zeros((N, LSTM_FEATURE_DIM), dtype=np.float32)
    raw5[:, 0] = np.linspace(200.0, 1800.0, N)     # pos_x
    raw5[:, 1] = 580.0                              # pos_y (single lane)
    raw5[:, 2] = 10.0                               # speed m/s
    raw5[:, 3] = 0.0                                # heading
    raw5[:, 4] = 0.0                                # accel

    safe = np.where(scale == 0.0, 1.0, scale)
    normed5 = (raw5 - mean) / safe
    feats6 = np.hstack([normed5, np.full((N, 1), TAU_DEFAULT, dtype=np.float32)])
    assert feats6.shape == (N, GAT_FEATURE_DIM)

    # Self-loop edges (matches C++ fallback when graph is sparse)
    edge_index = np.vstack([np.arange(N), np.arange(N)]).astype(np.int64)

    scores = sess.run(None, {"x": feats6, "edge_index": edge_index})[0]
    print(f"[smoke] GAT scores shape={scores.shape} dtype={scores.dtype}")
    print(f"[smoke] GAT scores min={float(scores.min()):.6f}  max={float(scores.max()):.6f}  mean={float(scores.mean()):.6f}")
    assert scores.shape[0] == N, f"GAT output row count mismatch: {scores.shape}"
    assert np.all(np.isfinite(scores)), "GAT produced NaN/Inf"
    assert float(scores.min()) >= -1e-3 and float(scores.max()) <= 1.0 + 1e-3, \
        f"GAT scores outside [0,1]: [{scores.min()},{scores.max()}]"
    print(f"[smoke] GAT  ✓ pass")


def smoke_lstm_ae(mean: np.ndarray, scale: np.ndarray, theta_ae: float) -> None:
    sess = ort.InferenceSession(LSTM_AE_ONNX, providers=["CPUExecutionProvider"])
    inputs = {i.name: (i.shape, i.type) for i in sess.get_inputs()}
    outputs = {o.name: (o.shape, o.type) for o in sess.get_outputs()}
    print(f"[smoke] LSTM-AE inputs : {inputs}")
    print(f"[smoke] LSTM-AE outputs: {outputs}")

    # One 20-beacon window of a vehicle going east at 10 m/s, dt=0.1s.
    # Should yield LOW reconstruction error (clean trajectory).
    win = np.zeros((1, LSTM_WINDOW_SIZE, LSTM_FEATURE_DIM), dtype=np.float32)
    for t in range(LSTM_WINDOW_SIZE):
        win[0, t, 0] = 200.0 + 10.0 * 0.1 * t   # pos_x
        win[0, t, 1] = 580.0                     # pos_y
        win[0, t, 2] = 10.0                      # speed
        win[0, t, 3] = 0.0                       # heading
        win[0, t, 4] = 0.0                       # accel

    safe = np.where(scale == 0.0, 1.0, scale)
    win_n = (win - mean) / safe
    recon = sess.run(None, {"x": win_n.astype(np.float32)})[0]
    print(f"[smoke] LSTM-AE recon shape={recon.shape} dtype={recon.dtype}")
    mse_clean = float(np.mean((recon - win_n) ** 2))
    print(f"[smoke] LSTM-AE MSE (clean window)    = {mse_clean:.6f}  vs theta_ae={theta_ae:.6f}")

    # Synthesize a poisoned window: large positional teleport mid-window.
    win_bad = win.copy()
    win_bad[0, 10:, 0] += 200.0                 # +200m jump in pos_x at t=10
    win_bad_n = (win_bad - mean) / safe
    recon_bad = sess.run(None, {"x": win_bad_n.astype(np.float32)})[0]
    mse_bad = float(np.mean((recon_bad - win_bad_n) ** 2))
    print(f"[smoke] LSTM-AE MSE (poisoned window) = {mse_bad:.6f}  vs theta_ae={theta_ae:.6f}")

    assert recon.shape == (1, LSTM_WINDOW_SIZE, LSTM_FEATURE_DIM), \
        f"LSTM-AE recon shape wrong: {recon.shape}"
    assert np.all(np.isfinite(recon)), "LSTM-AE produced NaN/Inf"
    assert np.all(np.isfinite(recon_bad)), "LSTM-AE produced NaN/Inf on poisoned"
    # Sanity: poisoned MSE should not be drastically less than clean
    if mse_bad < mse_clean * 0.5:
        print(f"[smoke] WARN: poisoned MSE ({mse_bad}) much LESS than clean ({mse_clean}) — model may be insensitive to teleport")
    print(f"[smoke] LSTM-AE  ✓ pass")


def main() -> int:
    print("=" * 70)
    print("  MPTD-PQS R7g.2 — Standalone ONNX inference smoke test")
    print("=" * 70)
    must_exist(GAT_ONNX,     "GAT ONNX")
    must_exist(LSTM_AE_ONNX, "LSTM-AE ONNX")
    must_exist(SCALER_JSON,  "scaler.json")
    must_exist(THETA_AE,     "theta_ae.txt")

    mean, scale = load_scaler()
    theta_ae    = load_theta_ae()
    print("-" * 70)
    smoke_gat(mean, scale)
    print("-" * 70)
    smoke_lstm_ae(mean, scale, theta_ae)
    print("=" * 70)
    print("  ALL CHECKS PASSED")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
