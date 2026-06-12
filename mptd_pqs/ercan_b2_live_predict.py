"""
ercan_b2_live_predict.py
========================
STEP 2 — Load saved Ercan B2 models and run them on LIVE simulation data.

This is what you run when NS-3 produces new beacon data in real time.

Usage:
  python mptd_pqs/ercan_b2_live_predict.py  \
         <beacon_csv>  \
         <attack_num>  \
         <attack_pct>  \
         <models_dir>  \
         [output_csv]

Example:
  python mptd_pqs/ercan_b2_live_predict.py  \
         live_data/beacon_log.csv  1  30  \
         ../models_ercan_b2  \
         live_results/ercan_predictions.csv

What it does:
  1. Reads a live beacon_log.csv from NS-3
  2. Extracts the same 11 Ercan features (no labels needed)
  3. Loads the saved models for the matching attack/pct scenario
  4. Runs all 3 classifiers and outputs per-row predictions
  5. Prints a quick accuracy report if ground-truth labels exist
     in the beacon_log (is_poisoned column)
"""

from __future__ import annotations

import math, os, sys
import numpy as np
import pandas as pd
from typing import Optional

import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mptd_pqs.ercan_b2_detector_v2 import (
    _augment_with_real_pos,
    extract_features,
    compute_metrics,
    FEATURE_COLS,
)


def load_model(models_dir: str, attack: int, pct: int, clf_name: str):
    """Load a saved classifier from disk."""
    tag  = f"ercan_a{attack}_p{pct}"
    path = os.path.join(models_dir, f"{tag}_{clf_name}.joblib")
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model not found: {path}\n"
            f"Run ercan_b2_train_save.py first."
        )
    return joblib.load(path)


def predict_live(beacon_csv:  str,
                 attack_num:  int,
                 attack_pct:  int,
                 models_dir:  str,
                 scenario_dir: Optional[str] = None,
                 output_csv:  Optional[str] = None,
                 seed: int = 42):
    """
    Run Ercan B2 classifiers on a live/new beacon_log.csv.

    Parameters
    ----------
    beacon_csv   : path to the new NS-3 beacon_log.csv
    attack_num   : which attack type (1–7) — used to pick the right saved model
    attack_pct   : which attack percentage (0,30,60,90) — used to pick model
    models_dir   : folder where saved .joblib models live
    scenario_dir : folder containing attack-specific logs (tp_s1_poison_log etc.)
                   if None, uses the folder containing beacon_csv
    output_csv   : if given, saves per-row predictions to this CSV
    """

    print(f"\n{'='*55}")
    print(f"  Ercan B2 — Live Prediction")
    print(f"  Beacon CSV  : {beacon_csv}")
    print(f"  Attack      : a{attack_num}_p{attack_pct}")
    print(f"  Models from : {models_dir}")
    print(f"{'='*55}")

    # ── 1. Load beacon data ────────────────────────────────────────────────
    if not os.path.exists(beacon_csv):
        print(f"ERROR: beacon CSV not found: {beacon_csv}")
        return

    beacon = pd.read_csv(beacon_csv)
    print(f"  Loaded {len(beacon)} beacon rows")

    # ── 2. Augment with real positions (needed for RSSI feature) ──────────
    sc_dir = scenario_dir or os.path.dirname(beacon_csv)
    beacon_aug = _augment_with_real_pos(beacon, sc_dir)

    # ── 3. Extract features ────────────────────────────────────────────────
    feat_df = extract_features(beacon_aug, seed=seed)
    feat_df = feat_df.dropna(subset=FEATURE_COLS)

    if len(feat_df) == 0:
        print("ERROR: No valid feature rows after extraction.")
        return

    X = feat_df[FEATURE_COLS].values
    print(f"  Feature matrix: {X.shape}")

    # ── 4. Load models and predict ─────────────────────────────────────────
    results = {}
    for clf_name in ["kNN", "RF", "Stacking"]:
        try:
            model = load_model(models_dir, attack_num, attack_pct, clf_name)
            preds = model.predict(X)
            results[clf_name] = preds
            print(f"  {clf_name:10s} → predicted {preds.sum()} malicious "
                  f"out of {len(preds)} ({100*preds.mean():.1f}%)")
        except FileNotFoundError as e:
            print(f"  WARNING: {e}")

    if not results:
        print("No models loaded. Exiting.")
        return

    # ── 5. Add predictions to feature dataframe ───────────────────────────
    for clf_name, preds in results.items():
        feat_df[f"pred_{clf_name}"] = preds

    # ── 6. If ground-truth labels exist, compute metrics ──────────────────
    if "label" in feat_df.columns:
        y_true   = feat_df["label"].values
        disp_err = feat_df["disp_err_m"].values if "disp_err_m" in feat_df.columns \
                   else np.zeros(len(y_true))
        n_total  = len(y_true)
        print(f"\n  Ground truth available — computing metrics:")
        print(f"  {'Classifier':<12} {'MCC':>6} {'FPR':>6} {'PARR':>6} {'PBPO':>8}")
        print(f"  {'-'*42}")
        for clf_name, preds in results.items():
            m = compute_metrics(y_true, preds, disp_err, n_total)
            print(f"  {clf_name:<12} {m['MCC']:>6.4f} {m['FPR']:>6.4f} "
                  f"{m['PARR']:>6.4f} {m['PBPO']:>8.4f}")

    # ── 7. Save predictions CSV ────────────────────────────────────────────
    if output_csv:
        os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
        feat_df.to_csv(output_csv, index=False)
        print(f"\n  Predictions saved: {output_csv}")

    print("\n[Done]")
    return feat_df


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python ercan_b2_live_predict.py "
              "<beacon_csv> <attack_num> <attack_pct> <models_dir> [output_csv]")
        sys.exit(1)

    beacon_csv  = sys.argv[1]
    attack_num  = int(sys.argv[2])
    attack_pct  = int(sys.argv[3])
    models_dir  = sys.argv[4]
    output_csv  = sys.argv[5] if len(sys.argv) > 5 else None
    scenario_dir = os.path.dirname(beacon_csv)

    predict_live(beacon_csv, attack_num, attack_pct,
                 models_dir, scenario_dir, output_csv)