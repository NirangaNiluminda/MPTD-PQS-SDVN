"""
sharma_b3_detector_v2.py
========================
B3 Baseline: Sharma & Liu (2021)
"A Machine-Learning-Based Data-Centric Misbehavior Detection Model for
 Internet of Vehicles", IEEE IoT Journal Vol.8 No.6, March 2021.
DOI: 10.1109/JIOT.2020.3035035

REAL NS-3 DATA VERSION
----------------------
Reads the NS-3 simulation output CSVs from datasets/a{atk}_p{pct}/ —
the exact same folder layout used by the Ercan B2 detector.

Per scenario folder:
  beacon_log.csv        – per-beacon log received by an RSU
  metrics.csv           – MPTD-PQS pipeline output (our system's metrics)
  tp_s1_poison_log.csv  – (attack 1) per-beacon real/fake positions
  vehicle_tx_log.csv    – (attacks 2,4) per-tx real/sent positions
  ghost_identity_log.csv– (attack 3) Sybil ghost identities
  mitm_intercept_log.csv– (attack 6) MitM intercepts
  controller_poison_log.csv – (attack 7) controller poisoned beacons

Column mapping (beacon_log → Sharma paper):
  pos_x / pos_y     -> declared BSM position (the "received GPS"; possibly faked)
  speed             -> declared speed (scalar)
  heading           -> declared heading (radians)
  is_poisoned       -> ground-truth label (0=honest, 1=malicious)
  rsu_id            -> RSU that received the beacon
  vehicle_id        -> sender ID

Sharma features (Section IV of the paper):
  Section IV.1 — 6 kinematic discrepancy features:
    dist_x, dist_y, dist_mag    – Δ between consecutive declared positions
    vel_x,  vel_y,  vel_mag     – declared velocity components + magnitude
  Section IV.2a — Location Plausibility (LP) check, Eqs (1)-(4):
    predicted_x_95 = x_i + Δt·v_x + a(x,95)·Δt
    predicted_y_95 = y_i + Δt·v_y + a(y,95)·Δt
    predicted_x_99 = x_i + Δt·v_x + a(x,99)·Δt
    predicted_y_99 = y_i + Δt·v_y + a(y,99)·Δt
    → score 0 = inside 95% CI, 1 = inside 99% CI only, 2 = outside both
    → lp_x ∈ {0,1,2}, lp_y ∈ {0,1,2}, lp_total = lp_x + lp_y ∈ {0,…,4}
  Section IV.2b — Movement Plausibility (MP) check:
    mp_flag = 1 if total displacement ≈ 0 AND average declared speed > 0
              0 otherwise

Six classifiers (Section V of the paper):
  SVM (RBF), kNN (k=5), Naïve Bayes, Random Forest,
  Ensemble-Boosting (AdaBoost), Ensemble-Voting

Evaluation
----------
  • Cross-validation : StratifiedKFold (5-fold) per scenario
  • Sweep            : 7 attack types × 4 attack percentages (0/30/60/90)
  • Project metrics  : MCC, FPR, PARR, CDER, TDEE, TPE, PBPO
  • Plots            : mean ± 95% CI vs attack percentage,
                       MPTD-PQS (our system) overlaid for direct comparison
"""

from __future__ import annotations

import math
import os
import numpy as np
import pandas as pd
import scipy.stats as stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from typing import Dict, List, Optional, Tuple

from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import (RandomForestClassifier, AdaBoostClassifier,
                              VotingClassifier)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import confusion_matrix, matthews_corrcoef

# ─────────────────────────────────────────────────────────────────────────────
#  PHYSICAL CONSTANTS (SAE J2735 / 802.11p)
# ─────────────────────────────────────────────────────────────────────────────
BEACON_INTERVAL_S = 0.1          # 100 ms beacon interval (SAE J2735)

# Sharma Table II — confidence interval of average acceleration (urban driving).
# We use a normal model of acceleration with μ=0, σ=1.5 m/s² (urban).
# 95% half-width  = 1.960σ → 2.940 m/s²
# 99% half-width  = 2.576σ → 3.864 m/s²
ACCEL_STD_MS2 = 1.5
A_95 = 1.960 * ACCEL_STD_MS2     # 2.94 m/s² — half-width of 95% CI
A_99 = 2.576 * ACCEL_STD_MS2     # 3.864 m/s² — half-width of 99% CI

# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE COLUMNS (Section IV of Sharma 2021)
# ─────────────────────────────────────────────────────────────────────────────
KINEMATIC_COLS = [
    "dist_x", "dist_y", "dist_mag",  # Δ declared position
    "vel_x",  "vel_y",  "vel_mag",   # declared velocity decomposed + magnitude
]
PLAUSIBILITY_COLS = [
    "lp_x",       # LP score for x-axis           {0,1,2}
    "lp_y",       # LP score for y-axis           {0,1,2}
    "lp_total",   # lp_x + lp_y                   {0,…,4}
    "mp_flag",    # Movement plausibility         {0,1}
]
FEATURE_COLS = KINEMATIC_COLS + PLAUSIBILITY_COLS

CDER_THRESHOLD = 10.0   # metres — same as Ercan
N_SPLITS = 5            # StratifiedKFold splits


# ─────────────────────────────────────────────────────────────────────────────
#  PLAUSIBILITY CHECK HELPERS (Section IV.2 / Eqs 1–4)
# ─────────────────────────────────────────────────────────────────────────────

def _lp_score_axis(declared: float,
                   prev_declared: float,
                   prev_speed_component: float,
                   dt: float) -> float:
    """
    Location Plausibility score for one axis (x or y), Sharma Eqs 1-4.

      predicted(95) = prev + Δt·v + a(95)·Δt
      predicted(99) = prev + Δt·v + a(99)·Δt
        ↑ centre + Δt-scaled half-width of the acceleration CI

    Score 0 : declared inside 95% CI  (most plausible)
    Score 1 : outside 95% but inside 99% CI (borderline)
    Score 2 : outside 99% CI            (implausible)
    """
    centre  = prev_declared + dt * prev_speed_component
    range95 = A_95 * dt        # half-width 95% CI
    range99 = A_99 * dt        # half-width 99% CI
    deviation = abs(declared - centre)
    if deviation <= range95:
        return 0.0
    elif deviation <= range99:
        return 1.0
    else:
        return 2.0


def _mp_score(total_displacement: float,
              avg_speed: float) -> float:
    """
    Movement Plausibility check (Section IV.2b).
    MP = 1 if vehicle claims to be moving (avg_speed > 0) but its overall
           displacement is essentially 0 (constant-location attacker)
    MP = 0 otherwise
    """
    if total_displacement < 0.5 and avg_speed > 0.5:
        return 1.0
    return 0.0


# ─────────────────────────────────────────────────────────────────────────────
#  REAL-POSITION AUGMENTATION (for CDER / TDEE — same logic as Ercan)
# ─────────────────────────────────────────────────────────────────────────────

def _augment_with_real_pos(beacon: pd.DataFrame,
                            scenario_dir: str) -> pd.DataFrame:
    """
    Add columns real_pos_x, real_pos_y, disp_err_m to beacon_log so that
    the project's CDER / TDEE metrics can be computed.
    """
    b = beacon.copy()
    b = b.sort_values(["vehicle_id", "sim_time"]).reset_index(drop=True)
    b["real_pos_x"] = b["pos_x"]
    b["real_pos_y"] = b["pos_y"]
    b["disp_err_m"] = 0.0

    poison_csv = os.path.join(scenario_dir, "tp_s1_poison_log.csv")
    if os.path.exists(poison_csv):
        p = pd.read_csv(poison_csv).sort_values(["vehicle_id", "sim_time"]).reset_index(drop=True)
        for vid in p["vehicle_id"].unique():
            b_mask = (b["vehicle_id"] == vid) & (b["is_poisoned"] == 1)
            b_idx  = b[b_mask].index
            p_rows = p[p["vehicle_id"] == vid].reset_index(drop=True)
            if len(b_idx) == len(p_rows):
                b.loc[b_idx, "real_pos_x"] = p_rows["real_pos_x"].values
                b.loc[b_idx, "real_pos_y"] = p_rows["real_pos_y"].values
                b.loc[b_idx, "disp_err_m"] = p_rows["disp_err_m"].values
        return b

    tx_csv = os.path.join(scenario_dir, "vehicle_tx_log.csv")
    if os.path.exists(tx_csv):
        tx = pd.read_csv(tx_csv).sort_values(["vehicle_id", "sim_time"]).reset_index(drop=True)
        for vid in tx["vehicle_id"].unique():
            b_mask = b["vehicle_id"] == vid
            b_idx  = b[b_mask].index
            t_rows = tx[tx["vehicle_id"] == vid].reset_index(drop=True)
            if len(b_idx) == len(t_rows):
                b.loc[b_idx, "real_pos_x"] = t_rows["real_pos_x"].values
                b.loc[b_idx, "real_pos_y"] = t_rows["real_pos_y"].values
                b.loc[b_idx, "disp_err_m"] = t_rows["disp_err_m"].values
        return b

    ghost_csv = os.path.join(scenario_dir, "ghost_identity_log.csv")
    if os.path.exists(ghost_csv):
        g = pd.read_csv(ghost_csv)
        mean_disp = float(g["displacement_m"].mean()) if "displacement_m" in g.columns else 150.0
        b.loc[b["is_poisoned"] == 1, "disp_err_m"] = mean_disp
        return b

    return b


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE EXTRACTION (Section IV of Sharma 2021)
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(beacon_aug: pd.DataFrame) -> pd.DataFrame:
    """
    Compute the 10 Sharma features from an augmented beacon_log DataFrame.
      - 6 kinematic discrepancy features
      - 3 LP plausibility scores (lp_x, lp_y, lp_total)
      - 1 MP flag

    Returns a DataFrame with FEATURE_COLS + ['label', 'vehicle_id', 'disp_err_m'].
    """
    records: List[Dict] = []

    for vid, grp in beacon_aug.groupby("vehicle_id", sort=False):
        grp = grp.sort_values("sim_time").reset_index(drop=True)

        # Per-vehicle journey stats for MP check (Section IV.2b)
        first_x = float(grp["pos_x"].iloc[0])
        first_y = float(grp["pos_y"].iloc[0])
        last_x  = float(grp["pos_x"].iloc[-1])
        last_y  = float(grp["pos_y"].iloc[-1])
        total_displacement = math.hypot(last_x - first_x, last_y - first_y)
        avg_speed = float(grp["speed"].mean())
        mp_flag = _mp_score(total_displacement, avg_speed)

        prev = None
        for _, row in grp.iterrows():
            rx  = float(row["pos_x"])
            ry  = float(row["pos_y"])
            spd = float(row["speed"])
            hdg = float(row["heading"])

            vx = spd * math.cos(hdg)
            vy = spd * math.sin(hdg)
            vmag = math.hypot(vx, vy)

            if prev is not None:
                dt    = max(float(row["sim_time"]) - float(prev["sim_time"]), 1e-6)
                p_rx  = float(prev["pos_x"])
                p_ry  = float(prev["pos_y"])
                p_spd = float(prev["speed"])
                p_hdg = float(prev["heading"])
                p_vx  = p_spd * math.cos(p_hdg)
                p_vy  = p_spd * math.sin(p_hdg)

                dist_x = rx - p_rx
                dist_y = ry - p_ry
                dist_mag = math.hypot(dist_x, dist_y)
                vel_x = vx - p_vx
                vel_y = vy - p_vy

                lp_x = _lp_score_axis(rx, p_rx, p_vx, dt)
                lp_y = _lp_score_axis(ry, p_ry, p_vy, dt)
            else:
                dist_x = dist_y = dist_mag = 0.0
                vel_x = vel_y = 0.0
                lp_x = lp_y = 0.0

            records.append({
                "vehicle_id":  int(vid),
                "dist_x":      dist_x,
                "dist_y":      dist_y,
                "dist_mag":    dist_mag,
                "vel_x":       vel_x,
                "vel_y":       vel_y,
                "vel_mag":     vmag,
                "lp_x":        lp_x,
                "lp_y":        lp_y,
                "lp_total":    lp_x + lp_y,
                "mp_flag":     mp_flag,
                "label":       int(row["is_poisoned"]),
                "disp_err_m":  float(row["disp_err_m"]),
            })
            prev = row

    return pd.DataFrame(records)


def load_scenario(scenario_dir: str) -> Optional[pd.DataFrame]:
    """Load one NS-3 scenario folder → Sharma feature DataFrame."""
    beacon_csv = os.path.join(scenario_dir, "beacon_log.csv")
    if not os.path.exists(beacon_csv):
        return None
    beacon = pd.read_csv(beacon_csv)
    aug    = _augment_with_real_pos(beacon, scenario_dir)
    return extract_features(aug)


# ─────────────────────────────────────────────────────────────────────────────
#  CLASSIFIERS (Section V of Sharma 2021)
# ─────────────────────────────────────────────────────────────────────────────

def _svm(seed: int = 42) -> Pipeline:
    return Pipeline([("scaler", StandardScaler()),
                     ("clf",    SVC(kernel="rbf", C=1.0, gamma="scale",
                                    random_state=seed))])


def _knn(k: int = 5) -> Pipeline:
    return Pipeline([("scaler", StandardScaler()),
                     ("clf",    KNeighborsClassifier(n_neighbors=k, n_jobs=-1))])


def _nb() -> Pipeline:
    return Pipeline([("scaler", StandardScaler()),
                     ("clf",    GaussianNB())])


def _rf(seed: int = 42) -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=100, random_state=seed, n_jobs=-1)


def _ensemble_boost(seed: int = 42) -> AdaBoostClassifier:
    # Use default algorithm — works across sklearn versions
    return AdaBoostClassifier(n_estimators=50, learning_rate=1.0,
                              random_state=seed)


def _ensemble_vote(seed: int = 42) -> VotingClassifier:
    return VotingClassifier(
        estimators=[("knn", _knn()),
                    ("rf",  _rf(seed=seed)),
                    ("nb",  _nb())],
        voting="hard", n_jobs=-1)


def _build_classifiers(seed: int = 42) -> Dict[str, object]:
    """The six Sharma classifiers from Section V."""
    return {
        "SVM":              _svm(seed=seed),
        "kNN":              _knn(),
        "NaiveBayes":       _nb(),
        "RandomForest":     _rf(seed=seed),
        "EnsembleBoosting": _ensemble_boost(seed=seed),
        "EnsembleVoting":   _ensemble_vote(seed=seed),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  PROJECT METRICS — IDENTICAL DEFINITION TO ercan_b2_detector_v2.py
#  (Sir's instruction: "evaluate OUR 7 metrics for the state-of-the-art
#   work's proposed method")
# ─────────────────────────────────────────────────────────────────────────────

def compute_metrics(y_true: np.ndarray,
                    y_pred: np.ndarray,
                    disp_err: np.ndarray,
                    n_total: int) -> Dict:
    """
    Return MCC, FPR, PARR, CDER, TDEE, TPE, PBPO for one test fold.
    Same definitions as the Ercan B2 detector.
    """
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

    # ε-smoothed MCC (Eq 4.1) — matches the C++ MPTD-PQS pipeline (ε=1e-12) so the
    # baseline MCC is comparable in degenerate / class-imbalance cases (raw
    # sklearn matthews_corrcoef returns 0 there, diverging from MPTD-PQS).
    _e   = 1e-12
    _num = (tp + _e) * (tn + _e) - (fp + _e) * (fn + _e)
    _den = ((tp + fp + _e) * (tp + fn + _e) * (tn + fp + _e) * (tn + fn + _e)) ** 0.5
    mcc  = float(_num / _den)

    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    parr = tp / n_total if n_total > 0 else 0.0

    # CDER : mean disp_err on missed poisoned beacons (FN), normalised by threshold
    fn_mask = (y_true == 1) & (y_pred == 0)
    if fn_mask.sum() > 0:
        cder = float(np.mean(disp_err[fn_mask])) / CDER_THRESHOLD
    else:
        cder = 0.0

    # TDEE : mean squared disp_err on missed poisoned beacons
    if fn_mask.sum() > 0:
        tdee = float(np.mean(disp_err[fn_mask] ** 2))
    else:
        tdee = 0.0

    # TPE  : fraction of poisoned beacons that slipped past detection
    poisoned = (y_true == 1).sum()
    tpe = (fn_mask.sum() / poisoned) if poisoned > 0 else 0.0

    # PBPO : proxy = FP rate × poisoned share (cheap blockchain-persistence offset)
    pbpo = fpr * (poisoned / n_total) if n_total > 0 else 0.0

    return {"MCC": mcc, "FPR": fpr, "PARR": parr, "CDER": cder,
            "TDEE": tdee, "TPE": tpe, "PBPO": pbpo}


# ─────────────────────────────────────────────────────────────────────────────
#  PER-SCENARIO 5-FOLD CV WITH 95% CI
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_scenario_with_ci(feat_df: pd.DataFrame,
                               seed: int = 42) -> Dict[str, Dict]:
    feat_df = feat_df.dropna(subset=FEATURE_COLS + ["label"])
    if len(feat_df) < 10:
        return {}
    X    = feat_df[FEATURE_COLS].values
    y    = feat_df["label"].values
    devs = feat_df["disp_err_m"].values
    n_total = len(y)
    if len(np.unique(y)) < 2:
        return {}

    skf = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=seed)

    classifiers   = _build_classifiers(seed=seed)
    fold_results: Dict[str, List[Dict]] = {name: [] for name in classifiers}

    for tr_idx, te_idx in skf.split(X, y):
        X_tr, X_te = X[tr_idx], X[te_idx]
        y_tr        = y[tr_idx]
        if len(np.unique(y_tr)) < 2:
            continue
        for name, clf in classifiers.items():
            # Re-build each fold so estimators don't share state
            cls = _build_classifiers(seed=seed)[name]
            cls.fit(X_tr, y_tr)
            yp = cls.predict(X_te)
            m  = compute_metrics(y[te_idx], yp, devs[te_idx], n_total=n_total)
            fold_results[name].append(m)

    out: Dict[str, Dict] = {}
    METRICS = ["MCC", "FPR", "PARR", "CDER", "TDEE", "TPE", "PBPO"]
    for clf_name, folds in fold_results.items():
        if not folds:
            continue
        out[clf_name] = {}
        for m in METRICS:
            vals = np.array([f[m] for f in folds])
            mean = float(vals.mean())
            if len(vals) > 1:
                ci = float(stats.t.ppf(0.975, df=len(vals)-1)
                           * vals.std(ddof=1) / math.sqrt(len(vals)))
            else:
                ci = 0.0
            out[clf_name][m] = {"mean": round(mean, 4),
                                "ci95": round(ci, 4),
                                "values": vals.tolist()}
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  SWEEP
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_PCTS = [0, 30, 60, 90]
ATTACK_NUMS = [1, 2, 3, 4, 5, 6, 7]
ATTACK_LABELS = {
    1: "a1: TP-S1 (RSU drift)",
    2: "a2: TP-S2 (speed/heading)",
    3: "a3: MP-S1 (Sybil ghost)",
    4: "a4: MP-S2 (impersonation)",
    5: "a5: TP-S3 (flooding)",
    6: "a6: MitM intercept",
    7: "a7: Controller poison",
}

# Six Sharma classifier styles
CLF_STYLE = {
    "SVM":              {"color": "#1f77b4", "linestyle": "-",  "marker": "o"},
    "kNN":              {"color": "#ff7f0e", "linestyle": "--", "marker": "s"},
    "NaiveBayes":       {"color": "#9467bd", "linestyle": ":",  "marker": "v"},
    "RandomForest":     {"color": "#2ca02c", "linestyle": "-",  "marker": "^"},
    "EnsembleBoosting": {"color": "#17becf", "linestyle": "--", "marker": "P"},
    "EnsembleVoting":   {"color": "#bcbd22", "linestyle": ":",  "marker": "X"},
}

MPTD_PQS_STYLE = {
    "color":     "#8b0000",
    "linestyle": "-.",
    "marker":    "D",
    "linewidth": 2.2,
    "markersize": 7,
    "label":     "MPTD-PQS (Our System)",
}


def run_full_sweep(datasets_root: str, seed: int = 42) -> pd.DataFrame:
    rows = []
    for atk in ATTACK_NUMS:
        for pct in ATTACK_PCTS:
            folder = os.path.join(datasets_root, f"a{atk}_p{pct}")
            if not os.path.isdir(folder):
                continue
            print(f"  Loading a{atk}_p{pct} ...", end=" ", flush=True)
            feat = load_scenario(folder)
            if feat is None or len(feat) == 0:
                print("SKIP (empty)")
                continue
            ci_res = evaluate_scenario_with_ci(feat, seed=seed)
            if not ci_res:
                print("SKIP (single class)")
                continue
            print(f"rows={len(feat)}, label={feat['label'].value_counts().to_dict()}")
            for clf, mets in ci_res.items():
                row = {"attack": atk, "attack_pct": pct, "classifier": clf}
                for m, v in mets.items():
                    row[f"{m}_mean"] = v["mean"]
                    row[f"{m}_ci95"] = v["ci95"]
                rows.append(row)
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
#  MPTD-PQS (our system) LOADER
# ─────────────────────────────────────────────────────────────────────────────

def load_mptd_pqs_metrics(datasets_root: str) -> pd.DataFrame:
    """Read each datasets/a*_p*/metrics.csv → tidy DataFrame."""
    rows = []
    for atk in ATTACK_NUMS:
        for pct in ATTACK_PCTS:
            mfile = os.path.join(datasets_root, f"a{atk}_p{pct}", "metrics.csv")
            if not os.path.exists(mfile):
                continue
            try:
                df = pd.read_csv(mfile)
            except Exception:
                continue
            if df.empty:
                continue
            row = df.iloc[0]
            tdee = float(row.get("TDEE", -1))
            rows.append({
                "attack":     atk,
                "attack_pct": pct,
                "MCC":  float(row.get("MCC",  0.0)),
                "FPR":  float(row.get("FPR",  0.0)),
                "PARR": float(row.get("PARR", 0.0)),
                "CDER": float(row.get("CDER", 0.0)),
                "TDEE": (float("nan") if tdee < 0 else tdee),
                "TPE":  float(row.get("TPE",  0.0)),
                "PBPO": float(row.get("PBPO_LW_ms", 0.0)),
            })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
#  PLOTTING
# ─────────────────────────────────────────────────────────────────────────────

METRICS_TO_PLOT = ["MCC", "FPR", "PARR", "CDER", "TDEE", "TPE", "PBPO"]
METRIC_LABELS = {
    "MCC":  "Matthews Correlation Coefficient (MCC)",
    "FPR":  "False Positive Rate (FPR)",
    "PARR": "Poisoned Attack Record Rate (PARR)",
    "CDER": "Cumulative Deviation Error Rate, CDER [m]",
    "TDEE": "Trajectory Deviation Error Energy, TDEE [m²]",
    "TPE":  "Trajectory Poisoning Effectiveness (TPE)",
    "PBPO": "Poisoned Blockchain Persistence Offset (PBPO)",
}


def plot_metric_vs_attack_pct(sweep_df: pd.DataFrame,
                               metric: str,
                               out_path: str,
                               mptd_pqs_df: Optional[pd.DataFrame] = None):
    attacks_present = sorted(sweep_df["attack"].unique())
    n_plots = len(attacks_present)
    ncols = min(4, n_plots)
    nrows = math.ceil(n_plots / ncols)

    fig, axes = plt.subplots(nrows, ncols,
                              figsize=(5 * ncols, 4 * nrows),
                              squeeze=False)
    fig.suptitle(f"Sharma & Liu (B3) vs. MPTD-PQS — {METRIC_LABELS[metric]}\n"
                 f"vs. Attack Percentage",
                 fontsize=12, fontweight="bold", y=1.01)

    for idx, atk in enumerate(attacks_present):
        ax  = axes[idx // ncols][idx % ncols]
        sub = sweep_df[sweep_df["attack"] == atk]

        for clf, style in CLF_STYLE.items():
            sub_c = sub[sub["classifier"] == clf].sort_values("attack_pct")
            if sub_c.empty:
                continue
            x    = sub_c["attack_pct"].values
            y    = sub_c[f"{metric}_mean"].values
            yerr = sub_c[f"{metric}_ci95"].values
            ax.errorbar(x, y, yerr=yerr,
                        label=f"B3-Sharma ({clf})",
                        color=style["color"],
                        linestyle=style["linestyle"],
                        marker=style["marker"],
                        linewidth=1.5,
                        markersize=4,
                        capsize=3)

        if mptd_pqs_df is not None and metric in mptd_pqs_df.columns:
            mp = mptd_pqs_df[mptd_pqs_df["attack"] == atk].sort_values("attack_pct")
            mp = mp.dropna(subset=[metric])
            if not mp.empty:
                ax.plot(mp["attack_pct"].values,
                        mp[metric].values,
                        color=MPTD_PQS_STYLE["color"],
                        linestyle=MPTD_PQS_STYLE["linestyle"],
                        marker=MPTD_PQS_STYLE["marker"],
                        linewidth=MPTD_PQS_STYLE["linewidth"],
                        markersize=MPTD_PQS_STYLE["markersize"],
                        label=MPTD_PQS_STYLE["label"])

        ax.set_title(ATTACK_LABELS.get(atk, f"Attack {atk}"), fontsize=9)
        ax.set_xlabel("Attack Percentage, ρ_a (%)", fontsize=8)
        ax.set_ylabel(METRIC_LABELS[metric], fontsize=8)
        ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.7)
        ax.legend(fontsize=5, loc="best", ncol=1)
        ax.tick_params(labelsize=7)

    for idx in range(len(attacks_present), nrows * ncols):
        axes[idx // ncols][idx % ncols].set_visible(False)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Plot saved: {out_path}")


def plot_all_metrics(sweep_df: pd.DataFrame, out_dir: str,
                     mptd_pqs_df: Optional[pd.DataFrame] = None):
    os.makedirs(out_dir, exist_ok=True)
    for metric in METRICS_TO_PLOT:
        out = os.path.join(out_dir, f"sharma_b3_{metric.lower()}_vs_attack_pct.png")
        plot_metric_vs_attack_pct(sweep_df, metric, out, mptd_pqs_df=mptd_pqs_df)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main(datasets_root: str = "datasets",
         results_dir:  str = "results_sharma_b3"):

    os.makedirs(results_dir, exist_ok=True)
    print("=" * 65)
    print("  Sharma & Liu (2021) B3 Baseline — NS-3 Real Data")
    print(f"  Dataset root : {datasets_root}")
    print(f"  Results dir  : {results_dir}")
    print(f"  CV           : StratifiedKFold ({N_SPLITS}-fold)")
    print(f"  Classifiers  : SVM, kNN, NaiveBayes, RF, AdaBoost, Voting")
    print(f"  Metrics      : {', '.join(METRICS_TO_PLOT)}")
    print("=" * 65)

    print("\n[1/4] Running full sweep (all attacks × all attack percentages)...")
    sweep_df = run_full_sweep(datasets_root, seed=42)
    csv_path = os.path.join(results_dir, "sharma_b3_sweep_results.csv")
    sweep_df.to_csv(csv_path, index=False)
    print(f"\n  Sweep CSV saved: {csv_path}")

    print("\n[2/4] Loading MPTD-PQS metrics from each scenario's metrics.csv ...")
    mptd_pqs_df = load_mptd_pqs_metrics(datasets_root)
    mptd_csv_path = os.path.join(results_dir, "mptd_pqs_metrics.csv")
    mptd_pqs_df.to_csv(mptd_csv_path, index=False)
    print(f"  MPTD-PQS CSV saved : {mptd_csv_path}")
    print(f"  Rows               : {len(mptd_pqs_df)}")

    print("\n[3/4] Summary (RandomForest, all scenarios):")
    rf_df = sweep_df[sweep_df["classifier"] == "RandomForest"].copy()
    if not rf_df.empty:
        print(rf_df[["attack", "attack_pct",
                     "MCC_mean", "MCC_ci95",
                     "FPR_mean", "PARR_mean",
                     "CDER_mean", "PBPO_mean"]].to_string(index=False))

    print("\n[4/4] Generating plots (Sharma baselines + MPTD-PQS overlay)...")
    plot_all_metrics(sweep_df, results_dir, mptd_pqs_df=mptd_pqs_df)

    print(f"\n[Done] All outputs in: {results_dir}")
    return sweep_df


if __name__ == "__main__":
    import sys
    root    = sys.argv[1] if len(sys.argv) > 1 else "datasets"
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "results_sharma_b3"
    main(datasets_root=root, results_dir=out_dir)
