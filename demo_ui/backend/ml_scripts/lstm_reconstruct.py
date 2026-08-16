#!/usr/bin/env python3
"""Offline, read-only LSTM-AE reconstruction for one vehicle's beacon window.

Runs the EXACT deployed ONNX artifact via onnxruntime — never a separately
tracked .pt checkpoint, which this project has repeatedly found drifts from
what's actually deployed (see CLAUDE.md dead-ends / retrain history). This
script changes nothing: it loads the same file the simulator loads and
performs a forward pass, nothing else. No simulator code, no exported model,
no threshold is touched.

Feature construction verified line-by-line against:
  - scratch/mptd_pqs_sdvn/04_state_globals.h:611-648 (lstm_ring_push_resid)
  - scratch/mptd_pqs_sdvn/06d_ai_inference.h:295-330, 4460-4472
  - <model_dir>/scaler.json (feature_names, mean, scale — matches exactly)

Residual formula (dead-reckoning residual, "AB4 fix" per scaler.json's own
_note field — the model was retrained on residuals, not absolute position):
    res_x    = (px(t) - px(t-1)) - speed(t) * T_b * cos(heading(t))
    res_y    = (py(t) - py(t-1)) - speed(t) * T_b * sin(heading(t))
    dspeed   = speed(t) - speed(t-1)
    dheading = wrap_to_pi(heading(t) - heading(t-1))
    accel    = accel(t)              [raw column, not differenced]
    tau_i    = 1.0                    [hardcoded trusted default —
                                        08_detection_engine.h:4460-4472]
The FIRST beacon of a vehicle's life has no predecessor, so its residual
channels are exactly 0 (on-manifold for the clean-trained model) — this
must be computed over each vehicle's FULL beacon history, not just the
trailing window, or the window's first row gets a spurious zero-residual
that was never actually zero in the real ring buffer.
T_b = 0.1s (02_config_globals.h:640, 100ms / IEEE 802.11p).

Inference happens entirely in z-scaled space (scaler.json mean/scale) —
06d_ai_inference.h scales the ring dump before the ONNX call, so the
model's own reconstruction error, and theta_ae, are both z-scaled-space
MSE. This script reports that figure as ae_raw_estimate specifically so it
can be cross-checked against a real logged ae_raw for the same vehicle —
see verify_lstm_reconstruct.py.

Usage:
    <repo>/gat_detector/.venv/bin/python3 lstm_reconstruct.py \
        --beacon-log <path/to/beacon_log.csv> --vehicle-id <N> \
        --model-dir <path/to/analytics/ml/models/urban> \
        [--end-time <T>]

Prints one JSON object to stdout.
"""
import argparse
import csv
import json
import math
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

T_B = 0.1
FEATURE_NAMES = ["res_x", "res_y", "dspeed", "dheading", "accel", "tau_i"]


def wrap_pi(a: float) -> float:
    while a > math.pi:
        a -= 2 * math.pi
    while a <= -math.pi:
        a += 2 * math.pi
    return a


def load_rows(beacon_log: str, vehicle_id: int) -> list[dict]:
    rows = []
    with open(beacon_log, newline="") as fh:
        for r in csv.DictReader(fh):
            if int(r["vehicle_id"]) != vehicle_id:
                continue
            rows.append(
                {
                    "t": float(r["sim_time"]),
                    "px": float(r["pos_x"]),
                    "py": float(r["pos_y"]),
                    "speed": float(r["speed"]),
                    "heading": float(r["heading"]),
                    "accel": float(r["accel"]),
                    "is_poisoned": r["is_poisoned"] == "1",
                    "detected": r["detected"] == "1",
                }
            )
    rows.sort(key=lambda r: r["t"])
    return rows


def residual_features(rows: list[dict]) -> list[list[float]]:
    """rows: chronological FULL beacon history for ONE vehicle. Returns one
    6-tuple per row, in the exact scaler.json feature order. Row 0 is always
    zero-residual — there is no predecessor for a vehicle's first beacon,
    matching lstm_ring_push_resid()'s `*pv_st` first-beacon branch."""
    feats = []
    prev = None
    for r in rows:
        if prev is None:
            rx = ry = dsp = dhd = 0.0
        else:
            dx = r["px"] - prev["px"]
            dy = r["py"] - prev["py"]
            rx = dx - r["speed"] * T_B * math.cos(r["heading"])
            ry = dy - r["speed"] * T_B * math.sin(r["heading"])
            dsp = r["speed"] - prev["speed"]
            dhd = wrap_pi(r["heading"] - prev["heading"])
        feats.append([rx, ry, dsp, dhd, r["accel"], 1.0])
        prev = r
    return feats


def reconstruct(beacon_log: str, vehicle_id: int, model_dir: str, end_time: float | None) -> dict:
    mdir = Path(model_dir)
    scaler = json.loads((mdir / "scaler.json").read_text())
    theta_ae = float((mdir / "theta_ae.txt").read_text().strip())
    if scaler["feature_names"] != FEATURE_NAMES:
        raise SystemExit(
            f"scaler.json feature_names {scaler['feature_names']} != expected {FEATURE_NAMES} "
            "— model/scaler pair has changed since this script was verified, stop and re-check"
        )
    mean = np.array(scaler["mean"], dtype=np.float32)
    scale = np.array(scaler["scale"], dtype=np.float32)

    sess = ort.InferenceSession(str(mdir / "lstm_ae_model.onnx"))
    window = sess.get_inputs()[0].shape[1]
    if not isinstance(window, int):
        raise SystemExit(f"model input window dim is dynamic ({window!r}); this script needs a fixed shape")

    rows = load_rows(beacon_log, vehicle_id)
    if end_time is not None:
        rows = [r for r in rows if r["t"] <= end_time]
    if len(rows) < window:
        return {"error": f"only {len(rows)} beacons for vehicle {vehicle_id} (need {window})"}

    feats_full = residual_features(rows)  # full history, so residuals are real
    window_rows = rows[-window:]
    window_feats = feats_full[-window:]  # trailing slice of RESIDUALS, not raw rows

    X = np.array(window_feats, dtype=np.float32)  # (window, 6) raw residual units
    Xz = (X - mean) / scale

    input_name = sess.get_inputs()[0].name
    recon_z = sess.run(None, {input_name: Xz[None, :, :].astype(np.float32)})[0][0]  # (window, 6)
    recon_raw = recon_z * scale + mean

    per_channel_mse_z = ((recon_z - Xz) ** 2).mean(axis=0).tolist()
    ae_raw_estimate = float(((recon_z - Xz) ** 2).mean())

    # Integrated "expected trajectory" (companion view, not the source of
    # truth — the residual channels above are): re-apply the dead-reckoning
    # step the model was trained to leave near-zero, but substitute the
    # MODEL'S reconstructed residual for the real one. Speed/heading are the
    # vehicle's own REPORTED values (real, not modelled) — only the
    # deviation-from-physics term comes from the network. Anchored at the
    # window's first REAL position, since the model has no absolute-position
    # channel to anchor to on its own.
    exp_x, exp_y = window_rows[0]["px"], window_rows[0]["py"]
    expected_traj = [{"t": window_rows[0]["t"], "pos_x": exp_x, "pos_y": exp_y}]
    for i in range(1, window):
        r = window_rows[i]
        rx_hat, ry_hat = float(recon_raw[i][0]), float(recon_raw[i][1])
        exp_x = exp_x + rx_hat + r["speed"] * T_B * math.cos(r["heading"])
        exp_y = exp_y + ry_hat + r["speed"] * T_B * math.sin(r["heading"])
        expected_traj.append({"t": r["t"], "pos_x": exp_x, "pos_y": exp_y})

    return {
        "vehicle_id": vehicle_id,
        "window": window,
        "theta_ae": theta_ae,
        "ae_raw_estimate": ae_raw_estimate,
        "flagged": ae_raw_estimate > theta_ae,
        "feature_names": FEATURE_NAMES,
        "per_channel_mse_z": per_channel_mse_z,
        "expected_trajectory": expected_traj,
        "beacons": [
            {
                "t": r["t"],
                "pos_x": r["px"],
                "pos_y": r["py"],
                "speed": r["speed"],
                "heading": r["heading"],
                "is_poisoned": r["is_poisoned"],
                "detected": r["detected"],
                "actual_raw": window_feats[i],
                "reconstructed_raw": recon_raw[i].tolist(),
            }
            for i, r in enumerate(window_rows)
        ],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--beacon-log", required=True)
    ap.add_argument("--vehicle-id", required=True, type=int)
    ap.add_argument("--model-dir", required=True)
    ap.add_argument("--end-time", type=float, default=None)
    args = ap.parse_args()
    try:
        out = reconstruct(args.beacon_log, args.vehicle_id, args.model_dir, args.end_time)
    except Exception as e:  # noqa: BLE001 — this is a CLI boundary, report and exit
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
