#!/usr/bin/env python3
"""
train_global_models.py  (RUN THIS ON THE NS-3 TRAINING DATA)
============================================================
Trains ONE generalized RandomForest per ML baseline (B2 Ercan, B3 Sharma) on the
POOLED NS-3 datasets and freezes each model to disk. These frozen models are then
handed to the teammate who evaluates them on the REAL network data.

Because the real network data is the held-out test set, we train on ALL the NS-3
rows (max training signal). A vehicle-grouped cross-val score is printed only as a
sanity check that the model is not degenerate.

Outputs (into <models_dir>):
  ercan_global_RF.joblib
  sharma_global_RF.joblib
  feature_cols.json        (the exact feature order each model expects)

Usage:
  python3 train_global_models.py <ns3_datasets_root> <models_dir>
  e.g.  python3 train_global_models.py ./datasets ./models_global
"""
import os, sys, glob, re, json
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import GroupKFold
from sklearn.metrics import matthews_corrcoef

PROJECT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT)
from mptd_pqs import ercan_b2_detector_v2 as B2
from mptd_pqs import sharma_b3_detector_v2 as B3


def pool(mod, root):
    frames = []
    for d in sorted(glob.glob(os.path.join(root, "a*_p*"))):
        if not re.search(r"a\d+_p\d+$", os.path.basename(d)):
            continue
        feat = mod.load_scenario(d)
        if feat is None or len(feat) == 0:
            continue
        feat = feat.dropna(subset=mod.FEATURE_COLS + ["label"]).copy()
        feat["grp"] = f"{os.path.basename(d)}_" + feat["vehicle_id"].astype(str)
        frames.append(feat)
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def sanity_cv(mod, df):
    X = df[mod.FEATURE_COLS].values
    y = df["label"].astype(int).values
    g = df["grp"].values
    n = min(5, len(np.unique(g)))
    gk = GroupKFold(n)
    yt, yp = [], []
    for tr, te in gk.split(X, y, g):
        if len(np.unique(y[tr])) < 2:
            continue
        c = mod._rf(seed=42); c.fit(X[tr], y[tr])
        yt += list(y[te]); yp += list(c.predict(X[te]))
    return matthews_corrcoef(yt, yp) if len(set(yt)) > 1 else float("nan")


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "./datasets"
    models_dir = sys.argv[2] if len(sys.argv) > 2 else "./models_global"
    os.makedirs(models_dir, exist_ok=True)

    for tag, mod in [("ercan", B2), ("sharma", B3)]:
        print(f"== {tag}: pooling NS-3 features ==")
        df = pool(mod, root)
        if df.empty or df["label"].nunique() < 2:
            print(f"  SKIP {tag}: insufficient data/classes"); continue
        print(f"  pooled rows={len(df)}  labels={df['label'].value_counts().to_dict()}")
        cv = sanity_cv(mod, df)
        print(f"  vehicle-grouped CV sanity MCC = {cv:.3f}")
        clf = mod._rf(seed=42)
        clf.fit(df[mod.FEATURE_COLS].values, df["label"].astype(int).values)
        path = os.path.join(models_dir, f"{tag}_global_RF.joblib")
        joblib.dump(clf, path)
        json.dump({tag: mod.FEATURE_COLS},
                  open(os.path.join(models_dir, f"{tag}_feature_cols.json"), "w"), indent=2)
        print(f"  frozen model -> {path}\n")

    print("[done] hand the whole models_dir folder to the teammate.")


if __name__ == "__main__":
    main()