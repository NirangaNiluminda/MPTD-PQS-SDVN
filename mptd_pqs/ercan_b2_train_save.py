"""
ercan_b2_train_save.py
======================
STEP 1 — Train Ercan B2 models on all NS-3 datasets and save them to disk.
Run this ONCE offline on the full datasets folder.

Usage:
  python mptd_pqs/ercan_b2_train_save.py ../datasets ../models_ercan_b2

What it does:
  - Loads all a{attack}_p{pct} scenarios
  - Trains kNN, RF, Stacking on ALL data in each scenario (no CV split)
  - Saves one .joblib file per scenario per classifier
  - Also saves the feature scaler fitted on training data

Saved file naming:
  models_ercan_b2/
    ercan_a1_p30_kNN.joblib
    ercan_a1_p30_RF.joblib
    ercan_a1_p30_Stacking.joblib
    ercan_a1_p30_scaler.joblib   ← StandardScaler for kNN/Stacking
    ercan_a2_p30_kNN.joblib
    ... etc for all 28 scenarios
"""

from __future__ import annotations

import math, os, sys
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple

import joblib

from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# ── import feature extraction from the existing detector ──────────────────
# Add the parent folder so we can import from the same mptd_pqs package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mptd_pqs.ercan_b2_detector_v2 import (
    load_scenario,
    FEATURE_COLS,
    ATTACK_NUMS,
    ATTACK_PCTS,
)

# ── Classifiers ────────────────────────────────────────────────────────────

def _knn(k: int = 5) -> Pipeline:
    return Pipeline([("scaler", StandardScaler()),
                     ("clf",    KNeighborsClassifier(n_neighbors=k, n_jobs=-1))])

def _rf(seed: int = 42) -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=100, random_state=seed, n_jobs=-1)

def _stacking(seed: int = 42) -> StackingClassifier:
    return StackingClassifier(
        estimators=[("knn", _knn()), ("rf", _rf(seed=seed))],
        final_estimator=LogisticRegression(max_iter=1000, random_state=seed),
        cv=3, n_jobs=-1)


def train_and_save(datasets_root: str, models_dir: str, seed: int = 42):
    os.makedirs(models_dir, exist_ok=True)

    print("=" * 60)
    print("  Ercan B2 — Training and saving models")
    print(f"  Datasets : {datasets_root}")
    print(f"  Models   : {models_dir}")
    print("=" * 60)

    saved_count = 0

    for atk in ATTACK_NUMS:
        for pct in ATTACK_PCTS:
            folder = os.path.join(datasets_root, f"a{atk}_p{pct}")
            if not os.path.isdir(folder):
                continue

            print(f"\n  a{atk}_p{pct} — loading features...", end=" ", flush=True)
            feat = load_scenario(folder, seed=seed)

            if feat is None or len(feat) == 0:
                print("SKIP (empty)")
                continue

            feat = feat.dropna(subset=FEATURE_COLS + ["label"])
            X = feat[FEATURE_COLS].values
            y = feat["label"].values

            if len(np.unique(y)) < 2:
                print("SKIP (single class)")
                continue

            tag = f"ercan_a{atk}_p{pct}"
            print(f"rows={len(feat)}")

            # ── Train and save each classifier ──────────────────────────
            for name, clf in [("kNN",      _knn()),
                               ("RF",       _rf(seed=seed)),
                               ("Stacking", _stacking(seed=seed))]:
                print(f"    Training {name}...", end=" ", flush=True)
                clf.fit(X, y)
                out_path = os.path.join(models_dir, f"{tag}_{name}.joblib")
                joblib.dump(clf, out_path)
                print(f"saved → {os.path.basename(out_path)}")
                saved_count += 1

            # ── Also save a standalone StandardScaler for live inference ──
            # (kNN and Stacking have scaler built-in, but for raw feature
            #  input from live simulation we expose a standalone scaler too)
            scaler = StandardScaler().fit(X)
            scaler_path = os.path.join(models_dir, f"{tag}_scaler.joblib")
            joblib.dump(scaler, scaler_path)

    print(f"\n[Done] {saved_count} model files saved to: {models_dir}")


if __name__ == "__main__":
    root      = sys.argv[1] if len(sys.argv) > 1 else "../datasets"
    model_dir = sys.argv[2] if len(sys.argv) > 2 else "../models_ercan_b2"
    train_and_save(root, model_dir)