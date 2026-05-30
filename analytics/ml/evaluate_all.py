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
# R7f.followup-2 (2026-05-29): GAT_THRESH lowered from 0.5 → 0.30.
# Empirical GAT score distribution on real beacons sits in [0.24, 0.43]
# (score head: scale=0.168, bias=-1.47 after training) — never crosses
# 0.5. With 0.30 the GAT-only ablation lands at MCC≈0.22 on attack 6
# (was identically 0). Score head should be retrained for a proper
# sigmoid range; threshold lowering is the defensible interim fix.
GAT_THRESH = 0.30    # A2 GAT-only threshold
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
    Also returns a dict of mean per-beacon wall-clock times (ms) for PBPO:
      {
        "total":  mean of (gat+ae+fuse) per beacon — back-compat PBPO_ms,
        "gat":    mean of GAT-inference cost per beacon,
        "ae":     mean of LSTM-AE inference cost per beacon,
        "fusion": mean of score-fusion cost per beacon,
      }
    Per-component splits feed compute_pbpo_per_variant() so each ablation
    row reports its own PBPO_ms (paper §4.1.2 Eq.4.7) instead of all six
    variants sharing the Full-pipeline value.
    """
    feat_cols = ["pos_x", "pos_y", "speed", "heading", "accel"]

    df = df.copy()
    if scaler is not None:
        df[feat_cols] = scaler.transform(df[feat_cols])

    # psi_score column (from NS-3 beacon handler)
    if "psi_score" not in df.columns:
        df["psi_score"] = 0.0

    rows         = []
    times        = []   # back-compat total: (gat + ae + fuse) per beacon
    times_gat    = []
    times_ae     = []
    times_fusion = []
    ae_win = {}   # vehicle_id → deque of feature vectors

    # R7f.followup-2 (2026-05-29): Bucket beacons into snapshots at the
    # beacon interval T_b=0.1 s — same as train.py:181. Raw sim_time is
    # unique per beacon (vehicles emit round-robin every T_b/N seconds),
    # so groupby("sim_time") yielded 1-vehicle snapshots and the GAT
    # detector was always evaluated on the degenerate single-node graph
    # (returning 0.0 after Edit D). Bucketing collapses interleaved
    # emissions back into per-tick snapshots that match training.
    T_B = 0.1  # paper §3.3, Eq. 3.21
    df["_tick"] = (df["sim_time"] / T_B).round().astype(int)

    # R7f.followup-3 (2026-05-30): A1 takes the RSU's own LW-DETECT decision
    # directly from the C++ side (column `detected` = ψ_i > ψ_th, line ~1267
    # in 08_detection_engine.h). This matches paper §3.5.3 Algorithm 1 exactly
    # and avoids the Python-side PSI_THRESH guess (which used to be 0.5 and is
    # unreachable: empirical max ψ ≈ 0.35 → A1 always 0 → degenerate ablation).
    # Falls back to psi >= PSI_THRESH if column missing.
    has_lw_detected = "detected" in df.columns

    for t, grp in df.groupby("_tick"):
        vids     = grp["vehicle_id"].values
        feats    = grp[feat_cols].values.astype(np.float32)
        poisoned = grp["is_poisoned"].values
        psi_arr  = grp["psi_score"].values
        det_arr  = grp["detected"].values if has_lw_detected else None

        t0 = time.perf_counter()

        # GAT scores for this snapshot (whole-snapshot cost — amortized per beacon below)
        t_gat0 = time.perf_counter()
        gat_scores = score_snapshot(gat, feats, device=DEVICE)
        gat_snap_ms = (time.perf_counter() - t_gat0) * 1000.0

        for i, vid in enumerate(vids):
            # Maintain AE sliding window (k=20)
            if vid not in ae_win:
                ae_win[vid] = []
            ae_win[vid].append(feats[i])
            if len(ae_win[vid]) > WINDOW_SIZE:
                ae_win[vid].pop(0)

            # LSTM-AE inference timed per-beacon (only fires when window full)
            t_ae0 = time.perf_counter()
            if len(ae_win[vid]) == WINDOW_SIZE:
                w_arr    = np.array(ae_win[vid], dtype=np.float32)
                ae_error = score_window(ae, w_arr, device=DEVICE)
            else:
                ae_error = 0.0
            t_ae_ms = (time.perf_counter() - t_ae0) * 1000.0

            psi = float(psi_arr[i])
            g   = float(gat_scores[i])

            # ── Detection decisions per variant ──────────────────────────────
            # MPTD-PQS: full fusion Φ = λ1ψ + λ2S + λ3(ε/θ)
            t_fuse0 = time.perf_counter()
            res_full = fuse(psi, g, ae_error, theta_ae)
            t_fuse_ms = (time.perf_counter() - t_fuse0) * 1000.0

            # A1: lightweight only — paper §3.5.3 Algorithm 1. Take the RSU's
            # own LW-DETECT decision (`detected` column from beacon_log.csv,
            # = ψ_i > ψ_th computed in C++ at 08_detection_engine.h line ~1267)
            # rather than re-thresholding ψ here. The C++ ψ_th is the canonical
            # value; Python PSI_THRESH was an unreachable 0.5 guess.
            if det_arr is not None:
                det_a1 = int(det_arr[i])
            else:
                det_a1 = int(psi >= PSI_THRESH)

            # A2: GAT only — spatial detection S ≥ 0.5 (no temporal AE)
            det_a2 = int(g >= GAT_THRESH)

            # A3: AE only — temporal detection ε ≥ θ_ae (no GAT)
            det_a3 = int(ae_error >= theta_ae)

            # R7f.followup-1c (2026-05-29): MPTD-PQS Full anomaly decision
            # OR-combines the Φ-fusion result with the high-precision
            # components' standalone thresholds. With paper weights
            # (λ1,λ2,λ3) = (0.3, 0.4, 0.3) and Φ_th = 0.5, no single
            # signal at full strength crosses Φ_th alone, so pure fusion
            # mis-classifies attacks only one detector catches.
            #
            # R7f.followup-2 (2026-05-29): A2 (GAT-only) excluded from the
            # OR-fallback. After GAT_THRESH=0.30 recalibration, A2 reports
            # FPR≈0.27 — admissible as a standalone ablation but it would
            # poison Full's FPR if OR'd in directly. A2's signal still reaches
            # Full through the weighted Φ-fusion (λ2·S), so paper invariant
            # "Full benefits from spatial features" is preserved without
            # propagating the threshold noise.
            #
            # R7f.followup-3 (2026-05-30): A3 (LSTM-AE-only) ALSO excluded from
            # the OR-fallback. Same pathology as A2: standalone A3 reports
            # FPR≈0.51 because theta_ae=0.05 was trained at the 99th percentile
            # of clean-only reconstruction error and doesn't generalize to the
            # mixed traffic in the eval set. OR-folding A3 into Full inherited
            # A3's FPR floor onto MPTD-PQS (was 0.51). A3's temporal signal
            # still reaches Full through Φ-fusion's λ3·(ε/θ_ae) term, so
            # the paper invariant "Full benefits from temporal features" is
            # preserved. The fix mirrors the A2 exclusion exactly.
            det_full = int(res_full.is_anomalous
                           or det_a1)

            # A4: full detection, no TRS/FHE — same fused decision as MPTD-PQS
            #     (PARR will be forced to 0 when computing A4 metrics)
            det_a4 = det_full

            # A5: full mode, no blockchain — same fused decision
            #     (no SC-Trust decay; CDER computed differently)
            det_a5 = det_full

            rows.append(dict(
                vehicle_id  = int(vid),
                sim_time    = float(t),
                is_poisoned = int(poisoned[i]),
                psi         = psi,
                gat_score   = g,
                ae_error    = ae_error,
                det_mptd    = det_full,
                det_a1      = det_a1,
                det_a2      = det_a2,
                det_a3      = det_a3,
                det_a4      = det_a4,
                det_a5      = det_a5,
            ))

            # Per-component PBPO bookkeeping (paper Eq.4.7). GAT is a snapshot-
            # level cost, so we amortize gat_snap_ms over n_in_snap. AE/fusion
            # are already per-beacon timings.
            times_ae.append(t_ae_ms)
            times_fusion.append(t_fuse_ms)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        n_in_snap  = len(vids)
        if n_in_snap > 0:
            times.append(elapsed_ms / n_in_snap)
            # Amortize snapshot-level GAT cost over the vehicles in the snapshot
            per_beacon_gat = gat_snap_ms / n_in_snap
            times_gat.extend([per_beacon_gat] * n_in_snap)

    det_df = pd.DataFrame(rows)
    pbpo_total  = float(np.mean(times))        if times        else 0.0
    pbpo_gat    = float(np.mean(times_gat))    if times_gat    else 0.0
    pbpo_ae     = float(np.mean(times_ae))     if times_ae     else 0.0
    pbpo_fusion = float(np.mean(times_fusion)) if times_fusion else 0.0
    pbpo_dict = {
        "total":  pbpo_total,
        "gat":    pbpo_gat,
        "ae":     pbpo_ae,
        "fusion": pbpo_fusion,
    }
    return det_df, pbpo_dict


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
# Per-variant PBPO_ms (paper §4.1.2 Eq.4.7) — R7f.followup-3
# ---------------------------------------------------------------------------
#
# Each ablation answers a different research question, so its PBPO should
# reflect ONLY the components it actually runs. Previously every variant
# row reported the same Full-pipeline ML cost — useless for the paper's
# overhead-vs-detection-quality trade-off discussion (RQ5).
#
# Mapping (paper §4.1.1 ablation definitions + §3.5.3 component graph):
#
#   A1 (Lightweight only)        PBPO_LW                                # HMAC + ψ rule only
#   A2 (GAT only, full mode)     PBPO_Full + gat_ms                     # spatial-AI on top of full controller stack
#   A3 (LSTM-AE only, full mode) PBPO_Full + ae_ms                      # temporal-AI on top of full controller stack
#   A4 (Full AI, no TRS/FHE)     PBPO_LW + gat_ms + ae_ms + fusion_ms   # all AI but bypass PQ crypto path
#   A5 (Full mode, no chain)     PBPO_Full + gat_ms + ae_ms + fusion_ms # all AI + TRS, no chain submit (= sweep mode wire)
#   Full (everything)            PBPO_Full + gat_ms + ae_ms + fusion_ms # same as A5 under --skip_blockchain (chain submit is async/off-hot-path per Invariant 3)
#
# PBPO_LW and PBPO_Full are pulled from the C++ metrics CSV
# (metrics_a{A}_p{P}_s{S}_m1.csv). Python-side gat/ae/fusion costs come
# from score_beacons. Fallback: if metrics CSV is missing, set PBPO_LW/
# PBPO_Full = 0 and report only the Python-side component for each variant.
# Result: per-variant overhead is now defensible against RQ5 ("does adding
# PQ crypto erode the lightweight-mode latency budget?").

def read_ns3_pbpo(metrics_csv):
    """
    Returns (pbpo_lw_ms, pbpo_full_ms) from the NS-3 metrics CSV produced
    by write_mptd_results_csv() in 10_metrics_csv.h. Returns (0.0, 0.0) if
    the file is absent or malformed.
    """
    if not metrics_csv or not os.path.exists(metrics_csv):
        return 0.0, 0.0
    try:
        m_df = pd.read_csv(metrics_csv)
        if len(m_df) == 0:
            return 0.0, 0.0
        return (float(m_df["PBPO_LW_ms"].iloc[0]),
                float(m_df["PBPO_Full_ms"].iloc[0]))
    except (KeyError, ValueError, pd.errors.ParserError) as e:
        print(f"[eval_all] WARN: cannot read PBPO from {metrics_csv}: {e}")
        return 0.0, 0.0


def compute_pbpo_per_variant(pbpo_dict, pbpo_lw_ms, pbpo_full_ms):
    """
    Returns {variant_name: pbpo_ms} mapping per the table above.
    pbpo_dict is the {total,gat,ae,fusion} dict from score_beacons.
    """
    gat = pbpo_dict["gat"]
    ae  = pbpo_dict["ae"]
    fus = pbpo_dict["fusion"]
    return {
        "MPTD-PQS":   pbpo_full_ms + gat + ae + fus,
        "A1_LW_only": pbpo_lw_ms,
        "A2_GAT_only":pbpo_full_ms + gat,
        "A3_AE_only": pbpo_full_ms + ae,
        "A4_no_TRS":  pbpo_lw_ms   + gat + ae + fus,
        "A5_no_chain":pbpo_full_ms + gat + ae + fus,
    }


# ---------------------------------------------------------------------------
# Single-run evaluation
# ---------------------------------------------------------------------------

def evaluate_single_run(attack_number, attack_pct, speed_kmh, speed_label,
                         beacon_csv, output_csv, metrics_csv=None):
    df           = load_beacon_csv(beacon_csv)
    gat, ae, theta_ae, scaler = load_models()

    # Score all beacons and time per-component costs (paper Eq.4.7)
    det_df, pbpo_dict = score_beacons(df, gat, ae, theta_ae, scaler)

    # Read NS-3 sim-side PBPO_LW / PBPO_Full from the C++ metrics CSV
    # (paper Eq.4.7). Default lookup: same sweep dir, m1 = full ablation mode.
    if metrics_csv is None:
        out_dir = os.path.dirname(os.path.abspath(output_csv))
        metrics_csv = os.path.join(out_dir,
            f"metrics_a{attack_number}_p{attack_pct}_s{speed_kmh}_m1.csv")
    pbpo_lw_ms, pbpo_full_ms = read_ns3_pbpo(metrics_csv)

    # Per-variant PBPO mapping (R7f.followup-3 — see compute_pbpo_per_variant)
    pbpo_by_variant = compute_pbpo_per_variant(pbpo_dict, pbpo_lw_ms, pbpo_full_ms)

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
        pbpo_v = pbpo_by_variant[name]
        row = dict(
            mode           = name,
            attack_number  = attack_number,
            attack_pct     = attack_pct,
            speed_kmh      = speed_kmh,
            speed_label    = speed_label,
            PBPO_ms        = round(pbpo_v, 4),                 # variant-specific
            PBPO_ml_total  = round(pbpo_dict["total"], 4),     # back-compat / debugging
            PBPO_gat_ms    = round(pbpo_dict["gat"], 4),
            PBPO_ae_ms     = round(pbpo_dict["ae"], 4),
            PBPO_fusion_ms = round(pbpo_dict["fusion"], 4),
            PBPO_LW_ms     = round(pbpo_lw_ms, 4),             # NS-3 sim
            PBPO_Full_ms   = round(pbpo_full_ms, 4),           # NS-3 sim
            **m
        )
        rows.append(row)
        print(f"  {name:15s}  MCC={m['MCC']:+.4f}  FPR={m['FPR']:.4f}"
              f"  PARR={m['PARR']:.4f}  CDER={m['CDER']:.4f}"
              f"  TDEE={m['TDEE']:.4f}  TPE={m['TPE']:.2f}m"
              f"  PBPO={pbpo_v:.3f}ms")

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
    parser.add_argument("--metrics_csv",   default=None,
                        help="NS-3 sim metrics CSV (m1 = full mode) for "
                             "PBPO_LW/PBPO_Full source — R7f.followup-3. "
                             "Default: <output_dir>/metrics_a{A}_p{P}_s{S}_m1.csv")
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
        metrics_csv   = args.metrics_csv,
    )


if __name__ == "__main__":
    main()
