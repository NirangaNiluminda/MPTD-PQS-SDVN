"""
ercan_b2_train_model.py
=======================
Train ONE Ercan B2 model (per classifier) on ALL available NS-3 data.
Saves 3 files total:
    models/ercan_kNN.joblib
    models/ercan_RF.joblib
    models/ercan_Stacking.joblib

Run ONCE from inside MPTD-PQS-SDVN/:

    python mptd_pqs\ercan_b2_train_model.py ..\datasets ..\models

After this, run ercan_b2_results.py to evaluate and get graphs.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
import joblib

from mptd_pqs.ercan_b2_detector_v2 import (
    load_scenario,
    FEATURE_COLS,
    ATTACK_NUMS,
    ATTACK_PCTS,
    _knn, _rf, _stacking,
)


def train_one_model(datasets_root: str, models_dir: str, seed: int = 42):
    os.makedirs(models_dir, exist_ok=True)

    print("=" * 60)
    print("  Ercan B2 — Training one model on all data")
    print(f"  Datasets : {datasets_root}")
    print(f"  Models   : {models_dir}")
    print("=" * 60)

    # ── Step 1: collect all features from all scenarios ───────────────────
    all_X, all_y = [], []

    for atk in ATTACK_NUMS:
        for pct in ATTACK_PCTS:
            folder = os.path.join(datasets_root, f"a{atk}_p{pct}")
            if not os.path.isdir(folder):
                continue
            print(f"  Loading a{atk}_p{pct} ...", end=" ", flush=True)
            feat = load_scenario(folder, seed=seed)
            if feat is None or len(feat) == 0:
                print("skip")
                continue
            feat = feat.dropna(subset=FEATURE_COLS + ["label"])
            if len(np.unique(feat["label"].values)) < 2:
                print("skip (single class)")
                continue
            all_X.append(feat[FEATURE_COLS].values)
            all_y.append(feat["label"].values)
            print(f"rows={len(feat)}")

    if not all_X:
        print("ERROR: no data found. Check datasets path.")
        return

    X = np.vstack(all_X)
    y = np.concatenate(all_y)
    print(f"\n  Total training rows : {len(X)}")
    print(f"  Malicious rows      : {y.sum()} ({100*y.mean():.1f}%)")
    print(f"  Honest rows         : {(1-y).sum()}")

    # ── Step 2: train and save each classifier ────────────────────────────
    classifiers = {
        "kNN":      _knn(),
        "RF":       _rf(seed=seed),
        "Stacking": _stacking(seed=seed),
    }

    for name, clf in classifiers.items():
        print(f"\n  Training {name} ...", end=" ", flush=True)
        clf.fit(X, y)
        path = os.path.join(models_dir, f"ercan_{name}.joblib")
        joblib.dump(clf, path)
        print(f"saved → {path}")

    print("\n[Done] 3 model files saved.")
    print("  Next step: run ercan_b2_results.py to evaluate and plot graphs.")


if __name__ == "__main__":
    root      = sys.argv[1] if len(sys.argv) > 1 else "../datasets"
    model_dir = sys.argv[2] if len(sys.argv) > 2 else "../models"
    train_one_model(root, model_dir)