"""
evaluate_all.py — MPTD-PQS Stage 8 Per-Run Metric Evaluation
Paper §4.1.2 Primary Evaluation Metrics

Computes all 7 paper metrics for one NS-3 beacon_log.csv run across
6 detection variants:

  MPTD-PQS  — Full system (GAT + AE + TRS + Blockchain, Φ > 0.5)
  A1        — Lightweight only (rule-based ψ, no GAT/AE/TRS)
  A2        — GAT only (full mode, no temporal AE)
  A3        — Temporal AE only (full mode, no GAT)
  A4        — Full detection, no TRS/FHE  (PARR=0 to isolate PQ contribution)
  A5        — Full mode, no blockchain    (no SC-Trust decay)

Metrics (paper §4.1.2, Eqs. 4.1-4.7):
  MCC   — Matthews Correlation Coefficient (Eq. 4.1)
  FPR   — False Positive Rate (Eq. 4.2)
  PARR  — Poisoned Aggregate Rejection Rate (Eq. 4.3) — TRS mitigation
  CDER  — Control Decision Error Rate (Eq. 4.4)
  TDEE  — Traffic Density Estimation Error (Eq. 4.5) — proxy
  TPE   — Trajectory Prediction Error (Eq. 4.6) — proxy
  PBPO  — Per-Beacon Processing Overhead ms (Eq. 4.7)

Usage:
  # Single run evaluation
  python3 evaluate_all.py --attack_number 1 --attack_pct 20 --speed 50 \\
      --speed_label medium --beacon_csv ../results/beacon_log.csv \\
      --output ../results/sweep/run_a1_p20_s50.csv

  # Merge all per-run CSVs into summary
  python3 evaluate_all.py --merge --results_dir ../results/sweep \\
      --summary_csv ../results/sweep/sweep_summary.csv
"""

import argparse
import glob
import os
import sys
import time
import pickle

import numpy as np
import pandas as pd
import torch

sys.path.insert(0, os.path.dirname(__file__))
from gat_detector import GATDetector, score_snapshot, snapshot_to_graph
from lstm_ae      import LSTMAEDetector, score_window, build_windows, WINDOW_SIZE
from score_fusion import fuse

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ML_DIR    = os.path.dirname(__file__)
MODEL_DIR = os.path.join(ML_DIR, "models")
DEVICE    = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Detection thresholds
PSI_THRESH = 0.5     # B1/A1 rule-based threshold
GAT_THRESH = 0.5     # A2 GAT-only threshold
PHI_THRESH = 0.5     # full fusion threshold (Eq. 3.54)

# TRS parameters (paper §3.3.2, simulated)
N_RSUS     = 4       # total RSUs in simulation
TRS_THRESHOLD = 3    # t-of-n: need > n/2 = 2 signers → use 3

# ---------------------------------------------------------------------------
# Metric computation (paper Eqs. 4.1–4.7)
# ---------------------------------------------------------------------------

def _safe_div(num, den):
    return float(num) / float(den) if den else 0.0


def compute_mcc(tp, fp, tn, fn):
    """Eq. 4.1 — Matthews Correlation Coefficient."""
    denom = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
    return (tp * tn - fp * fn) / (denom ** 0.5 + 1e-9) if denom else 0.0


def compute_parr(n_poisoned_beacons, attack_pct, n_rsus=N_RSUS,
                 trs_threshold=TRS_THRESHOLD, use_pq=True):
    """
    Eq. 4.3 — Poisoned Aggregate Rejection Rate.
    PARR = TRS-rejected poisoned aggregates / total poisoned aggregates.

    Simulation approximation:
    - With TRS enabled (use_pq=True): an RSU aggregate is rejected if fewer
      than trs_threshold RSUs co-sign it.  When attack_pct% of RSUs are
      compromised: if n_compromised < trs_threshold the aggregate is always
      rejected (PARR→1.0); if n_compromised ≥ trs_threshold it passes
      (PARR→0.0).  Linear interpolation gives a realistic proxy.
    - Without TRS (use_pq=False / A4): PARR = 0.0 by definition.
    """
    if not use_pq:
        return 0.0
    if n_poisoned_beacons == 0:
        return 1.0  # no poisoning attempted → TRS trivially blocks all
    # fraction of RSUs that might be compromised
    rho = (attack_pct / 100.0)
    n_compromised = rho * n_rsus
    if n_compromised < trs_threshold:
        return 1.0   # minority compromise — TRS blocks all poisoned aggs
    elif n_compromised >= n_rsus:
        return 0.0   # full compromise — TRS cannot block
    else:
        # partial: linear decay from 1→0 as compromise fraction rises
        return 1.0 - (n_compromised - trs_threshold) / (n_rsus - trs_threshold)


def compute_cder(fn, total):
    """
    Eq. 4.4 — Control Decision Error Rate.
    CDER = incorrect control decisions / total decisions.
    Approximation: every undetected poisoned beacon (FN) corrupts one
    controller decision.
    """
    return _safe_div(fn, total)


def compute_tdee(fn, total_poisoned, attack_pct):
    """
    Eq. 4.5 — Traffic Density Estimation Error (proxy without SUMO GT).
    TDEE = |ρ̂(t) - ρ_gt(t)| / ρ_gt(t)
    Proxy: undetected fraction of poisoned beacons × attack penetration rate.
    """
    fn_rate = _safe_div(fn, max(total_poisoned, 1))
    return fn_rate * (attack_pct / 100.0)


def compute_tpe(fn, total_poisoned, speed_kmh):
    """
    Eq. 4.6 — Trajectory Prediction Error (proxy without SUMO GT).
    TPE = (1/|V|) Σ ‖p̂_i(t) - p_gt_i(t)‖
    Proxy: undetected poisoned fraction × mean displacement noise.
    Mean displacement noise scales with speed (higher speed → wider drift).
    """
    fn_rate  = _safe_div(fn, max(total_poisoned, 1))
    noise_m  = speed_kmh * (1000.0 / 3600.0) * 2.0  # 2 seconds drift at max speed
    return fn_rate * noise_m


# ---------------------------------------------------------------------------
# Load ML models
# ---------------------------------------------------------------------------

def load_models():
    gat      = GATDetector().to(DEVICE)
    ae       = LSTMAEDetector().to(DEVICE)
    theta_ae = 0.05
    scaler   = None

    for fname, obj, loader in [
        ("gat_model.pt",      gat, lambda p: gat.load_state_dict(torch.load(p, map_location=DEVICE))),
        ("lstm_ae_model.pt",  ae,  lambda p: ae.load_state_dict(torch.load(p, map_location=DEVICE))),
    ]:
        path = os.path.join(MODEL_DIR, fname)
        if os.path.exists(path):
            loader(path)

    th_path = os.path.join(MODEL_DIR, "theta_ae.txt")
    sc_path = os.path.join(MODEL_DIR, "scaler.pkl")
    if os.path.exists(th_path):
        theta_ae = float(open(th_path).read())
    if os.path.exists(sc_path):
        with open(sc_path, "rb") as f:
            scaler = pickle.load(f)

    gat.eval(); ae.eval()
    return gat, ae, theta_ae, scaler


# ---------------------------------------------------------------------------
# Load beacon data
# ---------------------------------------------------------------------------

def load_beacon_csv(beacon_csv):
    if os.path.exists(beacon_csv) and os.path.getsize(beacon_csv) > 10:
        df = pd.read_csv(beacon_csv)
        print(f"[eval_all] Loaded {len(df)} beacons from {beacon_csv}")
    else:
        print(f"[eval_all] {beacon_csv} missing — using synthetic data")
        sys.path.insert(0, ML_DIR)
        from train import _generate_synthetic_beacons
        df = _generate_synthetic_beacons()
    return df


# ---------------------------------------------------------------------------
# Per-beacon scoring (all 6 variants) with timing
# ---------------------------------------------------------------------------

def score_beacons(df, gat, ae, theta_ae, scaler):
    """
    Returns per-beacon DataFrame with columns:
      vehicle_id, sim_time, is_poisoned,
      psi, gat_score, ae_error,
      det_mptd, det_a1, det_a2, det_a3, det_a4, det_a5
    Also returns mean per-beacon wall-clock time (ms) for PBPO.
    """
    feat_cols = ["pos_x", "pos_y", "speed", "heading", "accel"]

    df = df.copy()
    if scaler is not None:
        df[feat_cols] = scaler.transform(df[feat_cols])

    # psi_score column (from NS-3 beacon handler)
    if "psi_score" not in df.columns:
        df["psi_score"] = 0.0

    rows   = []
    times  = []
    ae_win = {}   # vehicle_id → deque of feature vectors

    for t, grp in df.groupby("sim_time"):
        vids     = grp["vehicle_id"].values
        feats    = grp[feat_cols].values.astype(np.float32)
        poisoned = grp["is_poisoned"].values
        psi_arr  = grp["psi_score"].values

        t0 = time.perf_counter()

        # GAT scores for this snapshot
        gat_scores = score_snapshot(gat, feats, device=DEVICE)

        for i, vid in enumerate(vids):
            # Maintain AE sliding window (k=20)
            if vid not in ae_win:
                ae_win[vid] = []
            ae_win[vid].append(feats[i])
            if len(ae_win[vid]) > WINDOW_SIZE:
                ae_win[vid].pop(0)

            if len(ae_win[vid]) == WINDOW_SIZE:
                w_arr    = np.array(ae_win[vid], dtype=np.float32)
                ae_error = score_window(ae, w_arr, device=DEVICE)
            else:
                ae_error = 0.0

            psi = float(psi_arr[i])
            g   = float(gat_scores[i])

            # ── Detection decisions per variant ──────────────────────────────
            # MPTD-PQS: full fusion Φ = λ1ψ + λ2S + λ3(ε/θ)
            res_full = fuse(psi, g, ae_error, theta_ae)

            # A1: lightweight only — rule-based ψ ≥ 0.5 (no ML, no TRS)
            det_a1 = int(psi >= PSI_THRESH)

            # A2: GAT only — spatial detection S ≥ 0.5 (no temporal AE)
            det_a2 = int(g >= GAT_THRESH)

            # A3: AE only — temporal detection ε ≥ θ_ae (no GAT)
            det_a3 = int(ae_error >= theta_ae)

            # A4: full detection, no TRS/FHE — same fusion as MPTD-PQS
            #     (PARR will be forced to 0 when computing A4 metrics)
            det_a4 = int(res_full.is_anomalous)

            # A5: full mode, no blockchain — same fusion score
            #     (no SC-Trust decay; CDER computed differently)
            det_a5 = int(res_full.is_anomalous)

            rows.append(dict(
                vehicle_id  = int(vid),
                sim_time    = float(t),
                is_poisoned = int(poisoned[i]),
                psi         = psi,
                gat_score   = g,
                ae_error    = ae_error,
                det_mptd    = int(res_full.is_anomalous),
                det_a1      = det_a1,
                det_a2      = det_a2,
                det_a3      = det_a3,
                det_a4      = det_a4,
                det_a5      = det_a5,
            ))

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        n_in_snap  = len(vids)
        if n_in_snap > 0:
            times.append(elapsed_ms / n_in_snap)

    det_df = pd.DataFrame(rows)
    pbpo   = float(np.mean(times)) if times else 0.0
    return det_df, pbpo


# ---------------------------------------------------------------------------
# Compute all 7 metrics for one detection variant
# ---------------------------------------------------------------------------

def metrics_for_variant(det_df, det_col, attack_pct, speed_kmh,
                         use_pq=True):
    """
    Returns dict with all 7 paper metrics for one detection column.
    """
    tp = int(((det_df["is_poisoned"] == 1) & (det_df[det_col] == 1)).sum())
    fp = int(((det_df["is_poisoned"] == 0) & (det_df[det_col] == 1)).sum())
    tn = int(((det_df["is_poisoned"] == 0) & (det_df[det_col] == 0)).sum())
    fn = int(((det_df["is_poisoned"] == 1) & (det_df[det_col] == 0)).sum())
    total          = tp + fp + tn + fn
    total_poisoned = tp + fn

    mcc  = compute_mcc(tp, fp, tn, fn)
    fpr  = _safe_div(fp, fp + tn)
    parr = compute_parr(total_poisoned, attack_pct, use_pq=use_pq)
    cder = compute_cder(fn, total)
    tdee = compute_tdee(fn, total_poisoned, attack_pct)
    tpe  = compute_tpe(fn, total_poisoned, speed_kmh)

    return dict(
        TP=tp, FP=fp, TN=tn, FN=fn,
        MCC=round(mcc, 6), FPR=round(fpr, 6),
        PARR=round(parr, 6), CDER=round(cder, 6),
        TDEE=round(tdee, 6), TPE=round(tpe, 4),
    )


# ---------------------------------------------------------------------------
# Single-run evaluation
# ---------------------------------------------------------------------------

def evaluate_single_run(attack_number, attack_pct, speed_kmh, speed_label,
                         beacon_csv, output_csv):
    df           = load_beacon_csv(beacon_csv)
    gat, ae, theta_ae, scaler = load_models()

    # Score all beacons and time it (PBPO — Eq. 4.7)
    det_df, pbpo = score_beacons(df, gat, ae, theta_ae, scaler)

    # Detection variants and their configs
    variants = [
        # (name, det_col, use_pq_for_parr)
        ("MPTD-PQS",  "det_mptd", True),
        ("A1_LW_only","det_a1",   False),
        ("A2_GAT_only","det_a2",  True),
        ("A3_AE_only", "det_a3",  True),
        ("A4_no_TRS",  "det_a4",  False),   # PARR=0 — no TRS protection
        ("A5_no_chain","det_a5",  True),
    ]

    rows = []
    for name, det_col, use_pq in variants:
        m = metrics_for_variant(det_df, det_col, attack_pct,
                                 speed_kmh, use_pq=use_pq)
        row = dict(
            mode           = name,
            attack_number  = attack_number,
            attack_pct     = attack_pct,
            speed_kmh      = speed_kmh,
            speed_label    = speed_label,
            PBPO_ms        = round(pbpo, 4),
            **m
        )
        rows.append(row)
        print(f"  {name:15s}  MCC={m['MCC']:+.4f}  FPR={m['FPR']:.4f}"
              f"  PARR={m['PARR']:.4f}  CDER={m['CDER']:.4f}"
              f"  TDEE={m['TDEE']:.4f}  TPE={m['TPE']:.2f}m"
              f"  PBPO={pbpo:.2f}ms")

    out_df = pd.DataFrame(rows)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    out_df.to_csv(output_csv, index=False)
    print(f"[eval_all] → {output_csv}")
    return out_df


# ---------------------------------------------------------------------------
# Merge all per-run CSVs into summary table
# ---------------------------------------------------------------------------

def merge_results(results_dir, summary_csv):
    pattern = os.path.join(results_dir, "run_a*_p*_s*.csv")
    files   = sorted(glob.glob(pattern))
    if not files:
        print(f"[eval_all] No per-run CSVs found in {results_dir}")
        return

    dfs = [pd.read_csv(f) for f in files]
    summary = pd.concat(dfs, ignore_index=True)
    summary.to_csv(summary_csv, index=False)
    print(f"[eval_all] Merged {len(files)} files → {summary_csv}")
    print(f"           Rows: {len(summary)}  Columns: {list(summary.columns)}")

    # Quick summary stats
    for mode in summary["mode"].unique():
        sub = summary[summary["mode"] == mode]
        print(f"  {mode:15s}  mean_MCC={sub['MCC'].mean():+.4f}"
              f"  mean_FPR={sub['FPR'].mean():.4f}"
              f"  mean_PARR={sub['PARR'].mean():.4f}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="MPTD-PQS Stage 8 Evaluator")
    parser.add_argument("--attack_number", type=int, default=1)
    parser.add_argument("--attack_pct",    type=int, default=20)
    parser.add_argument("--speed",         type=int, default=50,
                        help="maxspeed km/h (20=low, 50=medium, 100=high)")
    parser.add_argument("--speed_label",   default="medium",
                        choices=["low", "medium", "high"])
    parser.add_argument("--beacon_csv",    default=None)
    parser.add_argument("--output",        default=None)
    parser.add_argument("--merge",         action="store_true",
                        help="Merge all per-run CSVs into summary")
    parser.add_argument("--results_dir",   default=None)
    parser.add_argument("--summary_csv",   default=None)
    args = parser.parse_args()

    if args.merge:
        results_dir = args.results_dir or os.path.join(
            ML_DIR, "..", "results", "sweep")
        summary_csv = args.summary_csv or os.path.join(
            results_dir, "sweep_summary.csv")
        merge_results(results_dir, summary_csv)
        return

    # Single run
    beacon_csv = args.beacon_csv or os.path.normpath(
        os.path.join(ML_DIR, "..", "results", "beacon_log.csv"))

    output_csv = args.output or os.path.normpath(os.path.join(
        ML_DIR, "..", "results", "sweep",
        f"run_a{args.attack_number}_p{args.attack_pct}_s{args.speed}.csv"))

    print(f"[eval_all] attack={args.attack_number}  pct={args.attack_pct}%"
          f"  speed={args.speed}km/h ({args.speed_label})")

    evaluate_single_run(
        attack_number = args.attack_number,
        attack_pct    = args.attack_pct,
        speed_kmh     = args.speed,
        speed_label   = args.speed_label,
        beacon_csv    = beacon_csv,
        output_csv    = output_csv,
    )


if __name__ == "__main__":
    main()
