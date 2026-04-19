"""
prediction_server.py — MPTD-PQS Flask Prediction Server  (Stage 5)
Listens on http://localhost:5001

Endpoints:
  POST /predict   — receive beacon features, return fused Φ score + decision
  GET  /health    — liveness probe

Expected POST JSON:
{
  "vehicle_id" : int,
  "psi_score"  : float,        // rule-based score from NS-3 [0,1]
  "features"   : [px,py,sp,hd,ac]  // 5-dim feature vector (raw, server normalises)
}

Response JSON:
{
  "vehicle_id"  : int,
  "phi_score"   : float,       // fused Φ_i(t) ∈ [0,1]
  "is_anomalous": bool,
  "gat_score"   : float,       // S_i from GAT
  "ae_error"    : float,       // ε_i raw reconstruction MSE
  "ae_norm"     : float        // ε_i / θ_ae
}
"""

import os, sys, json, pickle
import numpy as np
import torch
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.dirname(__file__))
from gat_detector  import GATDetector, score_snapshot
from lstm_ae       import LSTMAEDetector, score_window, WINDOW_SIZE, FEATURE_DIM
from score_fusion  import fuse

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ML_DIR    = os.path.dirname(__file__)
MODEL_DIR = os.path.join(ML_DIR, "models")

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ---------------------------------------------------------------------------
# Load models at startup
# ---------------------------------------------------------------------------
def _load_gat():
    m = GATDetector().to(DEVICE)
    ckpt = os.path.join(MODEL_DIR, "gat_model.pt")
    if os.path.exists(ckpt):
        m.load_state_dict(torch.load(ckpt, map_location=DEVICE))
        print(f"[server] GAT model loaded from {ckpt}")
    else:
        print("[server] WARNING: gat_model.pt not found — using random weights (run train.py first)")
    m.eval()
    return m


def _load_ae():
    m = LSTMAEDetector().to(DEVICE)
    ckpt = os.path.join(MODEL_DIR, "lstm_ae_model.pt")
    if os.path.exists(ckpt):
        m.load_state_dict(torch.load(ckpt, map_location=DEVICE))
        print(f"[server] LSTM-AE model loaded from {ckpt}")
    else:
        print("[server] WARNING: lstm_ae_model.pt not found — using random weights")
    m.eval()
    return m


def _load_theta():
    path = os.path.join(MODEL_DIR, "theta_ae.txt")
    if os.path.exists(path):
        theta = float(open(path).read().strip())
        print(f"[server] θ_ae = {theta:.6f}")
        return theta
    print("[server] WARNING: theta_ae.txt not found — using default 0.05")
    return 0.05


def _load_scaler():
    path = os.path.join(MODEL_DIR, "scaler.pkl")
    if os.path.exists(path):
        with open(path, "rb") as f:
            sc = pickle.load(f)
        print("[server] Scaler loaded")
        return sc
    return None


# ---------------------------------------------------------------------------
# Per-vehicle sliding window buffer (holds last WINDOW_SIZE feature vectors)
# ---------------------------------------------------------------------------
class WindowBuffer:
    def __init__(self):
        self._buf: dict[int, list] = {}

    def push(self, vehicle_id: int, feat: list) -> np.ndarray | None:
        """Add one feature vector; return window array when full, else None."""
        if vehicle_id not in self._buf:
            self._buf[vehicle_id] = []
        self._buf[vehicle_id].append(feat)
        if len(self._buf[vehicle_id]) > WINDOW_SIZE:
            self._buf[vehicle_id].pop(0)
        if len(self._buf[vehicle_id]) == WINDOW_SIZE:
            return np.array(self._buf[vehicle_id], dtype=np.float32)
        return None

    def all_vehicles_snapshot(self) -> dict[int, list]:
        """Return current last-seen feature for each vehicle (for GAT snapshot)."""
        return {vid: buf[-1] for vid, buf in self._buf.items() if buf}


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)

gat_model  = None
ae_model   = None
theta_ae   = None
scaler     = None
win_buffer = WindowBuffer()


@app.before_request
def _init_models():
    global gat_model, ae_model, theta_ae, scaler
    if gat_model is None:
        gat_model = _load_gat()
        ae_model  = _load_ae()
        theta_ae  = _load_theta()
        scaler    = _load_scaler()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "device": str(DEVICE)})


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    vehicle_id = int(data.get("vehicle_id", 0))
    psi_score  = float(data.get("psi_score", 0.0))
    features   = list(data.get("features", [0.0] * FEATURE_DIM))

    # Pad / truncate features to FEATURE_DIM
    features = (features + [0.0] * FEATURE_DIM)[:FEATURE_DIM]

    # Normalise if scaler available
    if scaler is not None:
        features = scaler.transform([features])[0].tolist()

    # --- LSTM-AE score (ε_i)
    window_arr = win_buffer.push(vehicle_id, features)
    if window_arr is not None:
        ae_error = score_window(ae_model, window_arr, device=DEVICE)
    else:
        ae_error = 0.0   # not enough history yet → no anomaly signal

    # --- GAT score (S_i) — snapshot of all currently buffered vehicles
    snapshot_dict = win_buffer.all_vehicles_snapshot()
    vids_sorted   = sorted(snapshot_dict.keys())
    feat_matrix   = np.array([snapshot_dict[v] for v in vids_sorted], dtype=np.float32)

    gat_scores = score_snapshot(gat_model, feat_matrix, device=DEVICE)
    # Map back to the queried vehicle
    if vehicle_id in vids_sorted:
        idx       = vids_sorted.index(vehicle_id)
        gat_score = float(gat_scores[idx])
    else:
        gat_score = 0.0

    # --- Fuse
    result = fuse(psi_score, gat_score, ae_error, theta_ae)

    return jsonify({
        "vehicle_id"  : vehicle_id,
        "phi_score"   : round(result.phi_score, 6),
        "is_anomalous": result.is_anomalous,
        "gat_score"   : round(result.gat_score, 6),
        "ae_error"    : round(result.ae_error, 6),
        "ae_norm"     : round(result.ae_norm, 6),
    })


if __name__ == "__main__":
    print("[server] Starting MPTD-PQS prediction server on port 5001 …")
    app.run(host="0.0.0.0", port=5001, debug=False)
