"""
sharma_b3_live_predict.py
=========================
STEP 2 — Load saved Sharma B3 models and run on LIVE simulation data.

Usage:
  python mptd_pqs/sharma_b3_live_predict.py  \
         <beacon_csv>  \
         <attack_num>  \
         <attack_pct>  \
         <models_dir>  \
         [output_csv]

Example:
  python mptd_pqs/sharma_b3_live_predict.py  \
         live_data/beacon_log.csv  1  30  \
         ../models_sharma_b3  \
         live_results/sharma_predictions.csv
"""

from __future__ import annotations

import os, sys
import numpy as np
import pandas as pd
from typing import Optional

import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mptd_pqs.sharma_b3_detector_v2 import (
    _augment_with_real_pos,
    extract_features,
    compute_metrics,
    FEATURE_COLS,
)


def load_model(models_dir: str, attack: int, pct: int, clf_name: str):
    tag  = f"sharma_a{attack}_p{pct}"
    path = os.path.join(models_dir, f"{tag}_{clf_name}.joblib")
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Model not found: {path}\n"
            f"Run sharma_b3_train_save.py first."
        )
    return joblib.load(path)


CLF_NAMES = ["SVM", "KNN", "NaiveBayes", "RF", "Ensemble_Boosting", "Ensemble_Voting"]


def predict_live(beacon_csv:   str,
                 attack_num:   int,
                 attack_pct:   int,
                 models_dir:   str,
                 scenario_dir: Optional[str] = None,
                 output_csv:   Optional[str] = None):

    print(f"\n{'='*55}")
    print(f"  Sharma B3 — Live Prediction")
    print(f"  Beacon CSV  : {beacon_csv}")
    print(f"  Attack      : a{attack_num}_p{attack_pct}")
    print(f"  Models from : {models_dir}")
    print(f"{'='*55}")

    if not os.path.exists(beacon_csv):
        print(f"ERROR: beacon CSV not found: {beacon_csv}")
        return

    beacon = pd.read_csv(beacon_csv)
    print(f"  Loaded {len(beacon)} beacon rows")

    sc_dir = scenario_dir or os.path.dirname(beacon_csv)
    beacon_aug = _augment_with_real_pos(beacon, sc_dir)

    feat_df = extract_features(beacon_aug)
    feat_df = feat_df.dropna(subset=FEATURE_COLS)

    if len(feat_df) == 0:
        print("ERROR: No valid feature rows after extraction.")
        return

    X = feat_df[FEATURE_COLS].values
    print(f"  Feature matrix: {X.shape}")

    results = {}
    for clf_name in CLF_NAMES:
        try:
            model = load_model(models_dir, attack_num, attack_pct, clf_name)
            preds = model.predict(X)
            results[clf_name] = preds
            print(f"  {clf_name:<20s} → {preds.sum()} malicious "
                  f"/ {len(preds)} ({100*preds.mean():.1f}%)")
        except FileNotFoundError as e:
            print(f"  WARNING: {e}")

    if not results:
        print("No models loaded. Exiting.")
        return

    for clf_name, preds in results.items():
        feat_df[f"pred_{clf_name}"] = preds

    if "label" in feat_df.columns:
        y_true   = feat_df["label"].values
        disp_err = feat_df["disp_err_m"].values if "disp_err_m" in feat_df.columns \
                   else np.zeros(len(y_true))
        n_total  = len(y_true)
        print(f"\n  Ground truth available — metrics:")
        print(f"  {'Classifier':<22} {'MCC':>6} {'FPR':>6} {'PARR':>6} {'PBPO':>8}")
        print(f"  {'-'*46}")
        for clf_name, preds in results.items():
            m = compute_metrics(y_true, preds, disp_err, n_total)
            print(f"  {clf_name:<22} {m['MCC']:>6.4f} {m['FPR']:>6.4f} "
                  f"{m['PARR']:>6.4f} {m['PBPO']:>8.4f}")

    if output_csv:
        os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
        feat_df.to_csv(output_csv, index=False)
        print(f"\n  Predictions saved: {output_csv}")

    print("\n[Done]")
    return feat_df


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python sharma_b3_live_predict.py "
              "<beacon_csv> <attack_num> <attack_pct> <models_dir> [output_csv]")
        sys.exit(1)

    beacon_csv   = sys.argv[1]
    attack_num   = int(sys.argv[2])
    attack_pct   = int(sys.argv[3])
    models_dir   = sys.argv[4]
    output_csv   = sys.argv[5] if len(sys.argv) > 5 else None
    scenario_dir = os.path.dirname(beacon_csv)

    predict_live(beacon_csv, attack_num, attack_pct,
                 models_dir, scenario_dir, output_csv)