"""
sharma_b3_results.py
====================
Load saved Sharma B3 model, run on a datasets folder, produce graphs.
Works for BOTH the original datasets AND any live simulation data.

Run from inside MPTD-PQS-SDVN/:

    On original datasets:
        python mptd_pqs\sharma_b3_results.py ..\datasets ..\models ..\results_sharma_b3

    On live simulation data:
        python mptd_pqs\sharma_b3_results.py ..\live_datasets ..\models ..\results_sharma_live

Output in results folder:
    sharma_b3_mcc_vs_attack_pct.png
    sharma_b3_fpr_vs_attack_pct.png
    sharma_b3_parr_vs_attack_pct.png
    sharma_b3_cder_vs_attack_pct.png
    sharma_b3_tdee_vs_attack_pct.png
    sharma_b3_tpe_vs_attack_pct.png
    sharma_b3_pbpo_vs_attack_pct.png
    sharma_b3_results.csv
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
import joblib

from mptd_pqs.sharma_b3_detector_v2 import (
    load_scenario,
    compute_metrics,
    plot_all_metrics,
    FEATURE_COLS,
    ATTACK_NUMS,
    ATTACK_PCTS,
    METRICS_TO_PLOT,
    _build_classifiers,
)

CLF_NAMES = list(_build_classifiers().keys())


def load_models(models_dir: str) -> dict:
    """Load the 6 saved Sharma models. Raise clear error if missing."""
    models = {}
    for name in CLF_NAMES:
        path = os.path.join(models_dir, f"sharma_{name}.joblib")
        if not os.path.exists(path):
            print(f"ERROR: model not found: {path}")
            print("Run sharma_b3_train_model.py first.")
            sys.exit(1)
        models[name] = joblib.load(path)
        print(f"  Loaded: sharma_{name}.joblib")
    return models


def evaluate_scenario(feat_df: pd.DataFrame, models: dict):
    """Predict with saved models and compute metrics. No retraining."""
    feat_df  = feat_df.dropna(subset=FEATURE_COLS + ["label"])
    if len(feat_df) == 0:
        return {}

    X        = feat_df[FEATURE_COLS].values
    y_true   = feat_df["label"].values
    disp_err = feat_df["disp_err_m"].values \
               if "disp_err_m" in feat_df.columns else np.zeros(len(y_true))
    n_total  = len(y_true)

    if len(np.unique(y_true)) < 2:
        return {}

    results = {}
    for name, model in models.items():
        y_pred = model.predict(X)
        results[name] = compute_metrics(y_true, y_pred, disp_err, n_total)
    return results


def run(data_root: str, models_dir: str, results_dir: str):
    os.makedirs(results_dir, exist_ok=True)

    print("=" * 60)
    print("  Sharma B3 — Evaluate with Saved Model")
    print(f"  Data    : {data_root}")
    print(f"  Models  : {models_dir}")
    print(f"  Output  : {results_dir}")
    print("=" * 60)

    # ── Load saved models ─────────────────────────────────────────────────
    print("\n[1/3] Loading saved models...")
    models = load_models(models_dir)

    # ── Evaluate all scenarios ────────────────────────────────────────────
    print("\n[2/3] Evaluating scenarios...")
    rows = []

    for atk in ATTACK_NUMS:
        for pct in ATTACK_PCTS:
            folder = os.path.join(data_root, f"a{atk}_p{pct}")
            if not os.path.isdir(folder):
                continue
            print(f"  a{atk}_p{pct} ...", end=" ", flush=True)

            feat = load_scenario(folder)
            if feat is None or len(feat) == 0:
                print("SKIP (empty)")
                continue

            res = evaluate_scenario(feat, models)
            if not res:
                print("SKIP (single class)")
                continue

            mcc_rf = res.get("RandomForest", {}).get("MCC", "n/a")
            print(f"rows={len(feat)}, RF MCC={mcc_rf}")

            for clf_name, mets in res.items():
                row = {"attack": atk, "attack_pct": pct, "classifier": clf_name}
                for m in METRICS_TO_PLOT:
                    row[f"{m}_mean"] = mets.get(m, 0.0)
                    row[f"{m}_ci95"] = 0.0
                rows.append(row)

    if not rows:
        print("No results. Check data folder structure.")
        return

    sweep_df = pd.DataFrame(rows)

    # ── Save CSV ──────────────────────────────────────────────────────────
    csv_path = os.path.join(results_dir, "sharma_b3_results.csv")
    sweep_df.to_csv(csv_path, index=False)
    print(f"\n  CSV saved: {csv_path}")

    # ── Print summary ─────────────────────────────────────────────────────
    rf = sweep_df[sweep_df["classifier"] == "RandomForest"]
    print("\n  Summary (RandomForest):")
    print(rf[["attack","attack_pct","MCC_mean","FPR_mean",
               "PARR_mean","CDER_mean","PBPO_mean"]].to_string(index=False))

    # ── Plots ─────────────────────────────────────────────────────────────
    print("\n[3/3] Generating graphs...")
    plot_all_metrics(sweep_df, results_dir)

    print(f"\n[Done] Graphs and CSV in: {results_dir}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python mptd_pqs\\sharma_b3_results.py "
              "<data_folder> <models_folder> <results_folder>")
        sys.exit(1)
    run(sys.argv[1], sys.argv[2], sys.argv[3])