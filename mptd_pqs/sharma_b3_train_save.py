"""
sharma_b3_train_save.py
=======================
STEP 1 — Train Sharma B3 models on all NS-3 datasets and save to disk.
Run this ONCE offline.

Usage:
  python mptd_pqs/sharma_b3_train_save.py ../datasets ../models_sharma_b3

Saved file naming:
  models_sharma_b3/
    sharma_a1_p30_SVM.joblib
    sharma_a1_p30_KNN.joblib
    sharma_a1_p30_RF.joblib
    sharma_a1_p30_NaiveBayes.joblib
    sharma_a1_p30_Ensemble_Boosting.joblib
    sharma_a1_p30_Ensemble_Voting.joblib
    ... etc for all 28 scenarios
"""

from __future__ import annotations

import os, sys
import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# from mptd_pqs.sharma_b3_detector_v2 import (
#     load_scenario,
#     FEATURE_COLS,
#     ATTACK_NUMS,
#     ATTACK_PCTS,
#     _svm, _knn, _naive_bayes, _rf, _ensemble_boosting, _ensemble_voting,
# )
from mptd_pqs.sharma_b3_detector_v2 import (
    load_scenario,
    FEATURE_COLS,
    ATTACK_NUMS,
    ATTACK_PCTS,
    _svm,
    _knn,
    _nb,
    _rf,
    _ensemble_boost,
    _ensemble_vote,
)


# CLASSIFIERS = {
#     "SVM":               _svm,
#     "KNN":               _knn,
#     "NaiveBayes":        lambda seed=42: _naive_bayes(),
#     "RF":                _rf,
#     "Ensemble_Boosting": _ensemble_boosting,
#     "Ensemble_Voting":   _ensemble_voting,
# }
CLASSIFIERS = {
    "SVM":               _svm,
    "KNN":               _knn,
    "NaiveBayes":        lambda seed=42: _nb(),
    "RF":                _rf,
    "Ensemble_Boosting": _ensemble_boost,
    "Ensemble_Voting":   _ensemble_vote,
}


def train_and_save(datasets_root: str, models_dir: str, seed: int = 42):
    os.makedirs(models_dir, exist_ok=True)

    print("=" * 60)
    print("  Sharma B3 — Training and saving models")
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
            feat = load_scenario(folder)

            if feat is None or len(feat) == 0:
                print("SKIP (empty)")
                continue

            feat = feat.dropna(subset=FEATURE_COLS + ["label"])
            X = feat[FEATURE_COLS].values
            y = feat["label"].values

            if len(np.unique(y)) < 2:
                print("SKIP (single class)")
                continue

            tag = f"sharma_a{atk}_p{pct}"
            print(f"rows={len(feat)}")

            for name, clf_fn in CLASSIFIERS.items():
                print(f"    Training {name}...", end=" ", flush=True)
                clf = clf_fn(seed=seed) if name not in ("NaiveBayes", "KNN") \
                      else clf_fn()
                clf.fit(X, y)
                out_path = os.path.join(models_dir, f"{tag}_{name}.joblib")
                joblib.dump(clf, out_path)
                print(f"saved → {os.path.basename(out_path)}")
                saved_count += 1

    print(f"\n[Done] {saved_count} model files saved to: {models_dir}")


if __name__ == "__main__":
    root      = sys.argv[1] if len(sys.argv) > 1 else "../datasets"
    model_dir = sys.argv[2] if len(sys.argv) > 2 else "../models_sharma_b3"
    train_and_save(root, model_dir)