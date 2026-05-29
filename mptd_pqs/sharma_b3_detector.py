"""
mptd_pqs/sharma_b3_detector.py
================================
B3 Baseline: Sharma & Liu (2021)
"A Machine-Learning-Based Data-Centric Misbehavior Detection Model for
Internet of Vehicles"  IEEE IoT Journal, Vol.8 No.6, March 2021.
DOI: 10.1109/JIOT.2020.3035035

Implementation notes
--------------------
  Data source  : NS-3 rsu_relay_log.csv  (same file used by B1 and B2)
  Evaluation   : Stratified 5-fold cross-validation
  Metrics      : OUR 7 project metrics — MCC, FPR, PARR, CDER, TDEE, TPE, PBPO
  Classifiers  : SVM, kNN (k=5), Naïve Bayes, Random Forest,
                 Ensemble-Boosting (AdaBoost), Ensemble-Voting

Sharma features extracted (Section IV of paper):
  Core kinematic  : dist_x, dist_y, dist_mag  (position discrepancy)
                    vel_x,  vel_y,  vel_mag    (velocity discrepancy)
  LP check        : lp_x, lp_y, lp_total      (location plausibility score 0-4)
  MP check        : mp_flag                    (movement plausibility 0 or 1)

Plausibility checks follow paper equations (1)–(4) exactly:
  predicted(x,95) = x_i + t·v_x + a(x,95)·t      [Eq.1]
  predicted(y,95) = y_i + t·v_y + a(y,95)·t      [Eq.2]
  predicted(x,99) = x_i + t·v_x + a(x,99)·t      [Eq.3]
  predicted(y,99) = y_i + t·v_y + a(y,99)·t      [Eq.4]
  Confidence interval from Table II:  μ±1.96σ  (95%), μ±2.576σ (99%)

Design decision: LP and MP checks are computed from the NS-3 columns
(recv_pos_x/y for declared position, real_pos_x/y for ground truth
acceleration estimation, speed_ms and heading_rad for velocity).
The plausibility check score is added as additional features alongside the
raw kinematic discrepancy features — matching the paper's Section IV
architecture ("integrate plausibility checks with ML techniques").
"""
from __future__ import annotations

import math
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple

from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, VotingClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import confusion_matrix, matthews_corrcoef

# ─────────────────────────────────────────────────────────────────────────────
#  PHYSICAL CONSTANTS  (SAE J2735 / 802.11p defaults)
# ─────────────────────────────────────────────────────────────────────────────
BEACON_INTERVAL_S = 0.1        # 100 ms beacon interval (SAE J2735)
ACCEL_MEAN_MS2    = 0.0        # μ_a  — mean acceleration (Table II)
ACCEL_STD_MS2     = 1.5        # σ_a  — std dev of acceleration (Table II, urban)
Z_95              = 1.960      # z-score for 95% confidence interval
Z_99              = 2.576      # z-score for 99% confidence interval

# LP check: a(x,95) = μ ± 1.96σ  →  range half-width
A_95 = Z_95 * ACCEL_STD_MS2   # = 2.94 m/s²
A_99 = Z_99 * ACCEL_STD_MS2   # = 3.864 m/s²

# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE NAMES  (Section IV of Sharma & Liu 2021)
# ─────────────────────────────────────────────────────────────────────────────
#  6 kinematic discrepancy features (distance & velocity in x, y + magnitude)
KINEMATIC_COLS = [
    "dist_x", "dist_y", "dist_mag",   # Δ between consecutive declared positions
    "vel_x",  "vel_y",  "vel_mag",    # declared speed decomposed + magnitude
]
#  3 LP plausibility features + 1 MP flag  (Section IV.2)
PLAUSIBILITY_COLS = [
    "lp_x",       # LP score for x-coordinate  [0,2]
    "lp_y",       # LP score for y-coordinate  [0,2]
    "lp_total",   # lp_x + lp_y                [0,4]
    "mp_flag",    # Movement plausibility       {0,1}
]
FEATURE_COLS = KINEMATIC_COLS + PLAUSIBILITY_COLS


# ─────────────────────────────────────────────────────────────────────────────
#  PLAUSIBILITY CHECK HELPERS  (Section IV.2 / Equations 1–4)
# ─────────────────────────────────────────────────────────────────────────────

def _lp_score_axis(declared: float,
                   prev_declared: float,
                   prev_speed_component: float,
                   dt: float) -> float:
    """
    Location Plausibility score for one axis (x or y).

    Computes the 95% and 99% confidence prediction intervals using
    Sharma Eq.1/Eq.3 (for x) or Eq.2/Eq.4 (for y):
        predicted(95) = prev + dt·v + A_95·dt
        predicted(99) = prev + dt·v + A_99·dt

    Score  0 : declared position within 95% CI  (most plausible)
    Score  1 : outside 95% but inside 99% CI    (borderline)
    Score  2 : outside 99% CI                   (implausible)

    Returns float in {0.0, 1.0, 2.0}.
    """
    # predicted centre  =  prev + dt * v
    centre  = prev_declared + dt * prev_speed_component
    range95 = A_95 * dt   # half-width of 95% CI
    range99 = A_99 * dt   # half-width of 99% CI

    deviation = abs(declared - centre)

    if deviation <= range95:
        return 0.0        # within 95% — plausible
    elif deviation <= range99:
        return 1.0        # between 95% and 99% — borderline
    else:
        return 2.0        # beyond 99% — implausible


def _mp_score(total_displacement: float,
              avg_speed_from_velocity: float) -> float:
    """
    Movement Plausibility check (Section IV.2b of Sharma & Liu 2021).

    MP = 1  if overall_displacement == 0  AND  avg_velocity != 0
            (constant-location attack: vehicle claims to move but stays put)
    MP = 0  if overall_displacement != 0  OR   avg_velocity == 0

    Parameters
    ----------
    total_displacement          : |last_pos − first_pos|  (metres)
    avg_speed_from_velocity     : mean of declared speed_ms over the journey
    """
    if total_displacement < 0.5 and avg_speed_from_velocity > 0.5:
        return 1.0   # suspicious: no net movement but claims non-zero speed
    return 0.0


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE EXTRACTION FROM NS-3 rsu_relay_log.csv
# ─────────────────────────────────────────────────────────────────────────────

def extract_features_from_ns3(csv_path: str) -> pd.DataFrame:
    """
    Load NS-3 rsu_relay_log.csv and compute the Sharma & Liu (2021)
    feature set (Section IV).

    NS-3 columns used:
      sim_time       – beacon timestamp
      vehicle_id     – sender identity
      recv_pos_x/y   – declared position in BSM (possibly faked)
      real_pos_x/y   – true position (used for reference only in MP check
                        via ground-truth displacement — not available to
                        the detector in practice, so we use declared pos
                        for displacement as the paper intends)
      speed_ms       – declared speed (scalar)
      heading_rad    – declared heading (for speed decomposition)
      is_poisoned    – ground truth label
      disp_err_m     – |real − declared| position error (for CDER/TDEE)

    Returns a DataFrame with FEATURE_COLS + ['label', 'vehicle_id', 'disp_err_m']
    """
    raw     = pd.read_csv(csv_path)
    records: List[Dict] = []

    for vid, grp in raw.groupby("vehicle_id", sort=False):
        grp = grp.sort_values("sim_time").reset_index(drop=True)

        # Per-vehicle journey stats for MP check
        # Use DECLARED positions (what the detector sees), not real_pos
        first_rx = float(grp["recv_pos_x"].iloc[0])
        first_ry = float(grp["recv_pos_y"].iloc[0])
        last_rx  = float(grp["recv_pos_x"].iloc[-1])
        last_ry  = float(grp["recv_pos_y"].iloc[-1])
        total_displacement = math.hypot(last_rx - first_rx, last_ry - first_ry)
        avg_declared_speed = float(grp["speed_ms"].mean())
        mp = _mp_score(total_displacement, avg_declared_speed)

        prev_row = None
        for _, row in grp.iterrows():
            rx  = float(row["recv_pos_x"])
            ry  = float(row["recv_pos_y"])
            spd = float(row["speed_ms"])
            hdg = float(row["heading_rad"])

            # Speed components from heading
            vx = spd * math.cos(hdg)
            vy = spd * math.sin(hdg)

            # ── Kinematic discrepancy features ─────────────────────────────
            if prev_row is not None:
                dt    = max(float(row["sim_time"]) - float(prev_row["sim_time"]),
                            1e-6)
                p_rx  = float(prev_row["recv_pos_x"])
                p_ry  = float(prev_row["recv_pos_y"])
                p_spd = float(prev_row["speed_ms"])
                p_hdg = float(prev_row["heading_rad"])
                p_vx  = p_spd * math.cos(p_hdg)
                p_vy  = p_spd * math.sin(p_hdg)

                dist_x   = rx  - p_rx
                dist_y   = ry  - p_ry
                dist_mag = math.hypot(dist_x, dist_y)
                vel_x    = vx  - p_vx
                vel_y    = vy  - p_vy
                vel_mag  = math.hypot(vel_x, vel_y)

                # ── LP check (Eq.1–4) ─────────────────────────────────────
                lp_x     = _lp_score_axis(rx, p_rx, p_vx, dt)
                lp_y     = _lp_score_axis(ry, p_ry, p_vy, dt)
                lp_total = lp_x + lp_y
            else:
                # First beacon — no previous state; zero discrepancy, neutral LP
                dist_x = dist_y = dist_mag = 0.0
                vel_x  = vel_y  = vel_mag  = 0.0
                lp_x   = lp_y  = lp_total  = 0.0

            records.append({
                "vehicle_id": int(vid),
                # kinematic
                "dist_x":    dist_x,
                "dist_y":    dist_y,
                "dist_mag":  dist_mag,
                "vel_x":     vel_x,
                "vel_y":     vel_y,
                "vel_mag":   vel_mag,
                # plausibility
                "lp_x":      lp_x,
                "lp_y":      lp_y,
                "lp_total":  lp_total,
                "mp_flag":   mp,
                # labels / evaluation
                "label":     int(row["is_poisoned"]),
                "disp_err_m": float(row["disp_err_m"]),
            })
            prev_row = row

    return pd.DataFrame(records)


# ─────────────────────────────────────────────────────────────────────────────
#  CLASSIFIERS  (Section V of Sharma & Liu 2021 — six algorithms)
# ─────────────────────────────────────────────────────────────────────────────

def _svm(seed: int = 42) -> Pipeline:
    """SVM with RBF kernel and feature scaling (discriminative classifier)."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    SVC(kernel="rbf", C=1.0, gamma="scale",
                       random_state=seed, probability=False)),
    ])


def _knn(k: int = 5) -> Pipeline:
    """k-Nearest Neighbour — k=5, Euclidean distance requires scaling."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    KNeighborsClassifier(n_neighbors=k, n_jobs=-1)),
    ])


def _naive_bayes() -> Pipeline:
    """Gaussian Naïve Bayes — feature independence assumption."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    GaussianNB()),
    ])


def _random_forest(seed: int = 42) -> RandomForestClassifier:
    """Random Forest — 100 trees, no scaling needed."""
    return RandomForestClassifier(
        n_estimators=100, random_state=seed, n_jobs=-1)


def _ensemble_boosting(seed: int = 42) -> Pipeline:
    """
    Ensemble-Boosting (AdaBoost over decision stumps).
    Incrementally builds ensemble, weighting hard examples more — Section V.5.
    """
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    AdaBoostClassifier(n_estimators=100, random_state=seed,
                                      )),
    ])


def _ensemble_voting(seed: int = 42) -> VotingClassifier:
    """
    Ensemble-Voting (soft majority vote of SVM + kNN + RF).
    Reduces variance/bias by combining diverse weak learners — Section V.6.
    Hard voting used since SVM probability calibration adds overhead.
    """
    return VotingClassifier(
        estimators=[
            ("svm", Pipeline([("sc", StandardScaler()),
                               ("clf", SVC(kernel="rbf", random_state=seed))])),
            ("knn", Pipeline([("sc", StandardScaler()),
                               ("clf", KNeighborsClassifier(n_neighbors=5))])),
            ("rf",  _random_forest(seed=seed)),
        ],
        voting="hard", n_jobs=-1,
    )


# ─────────────────────────────────────────────────────────────────────────────
#  PROJECT METRICS  (same helper as B2 for consistency)
# ─────────────────────────────────────────────────────────────────────────────

CDER_THRESHOLD = 10.0   # metres — consistent with metrics_calculator.py


def compute_our_metrics(y_true: np.ndarray,
                        y_pred: np.ndarray,
                        disp_err: np.ndarray,
                        n_total: int) -> Dict:
    """
    Compute all 7 project metrics for Sharma's detection output.

    y_true    : ground truth labels (0=honest, 1=poisoned)
    y_pred    : predicted labels
    disp_err  : position error in metres for each row (0 for honest)
    n_total   : total beacon records (denominator for TPE / PBPO)
    """
    cm_vals           = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp    = cm_vals.ravel()

    mcc  = float(matthews_corrcoef(y_true, y_pred))
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    parr = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    # FN rows = missed attacks → escape into system (undetected poisoning)
    fn_mask  = (y_true == 1) & (y_pred == 0)
    fn_devs  = disp_err[fn_mask]
    exceeded = fn_devs[fn_devs > CDER_THRESHOLD]
    cder     = float(exceeded.mean()) if len(exceeded) > 0 else 0.0
    tdee     = float(np.sum(fn_devs ** 2))

    n_poisoned = int((y_true == 1).sum())
    tpe  = n_poisoned / n_total if n_total > 0 else 0.0
    pbpo = int(fn) / n_total    if n_total > 0 else 0.0

    return dict(
        TP=int(tp), FP=int(fp), TN=int(tn), FN=int(fn),
        MCC=round(mcc,  4),
        FPR=round(fpr,  4),
        PARR=round(parr, 4),
        CDER=round(cder, 4),
        TDEE=round(tdee, 2),
        TPE=round(tpe,  4),
        PBPO=round(pbpo, 4),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN DETECTOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class SharmaB3Detector:
    """
    Sharma & Liu (2021) data-centric ML misbehavior detector.

    Implements all six classifiers from the paper with optional
    feature sets (kinematic only vs kinematic + plausibility checks).

    Parameters
    ----------
    seed          : random seed for reproducible classifiers
    with_plausibility : if True (default), include LP and MP check features,
                        mirroring the paper's evaluation with plausibility checks.
                        Set to False to reproduce the 'without checks' baseline.
    n_splits      : number of stratified k-fold splits (default 5)
    """

    # Classifier registry: name → factory function
    CLASSIFIERS = {
        "SVM":               _svm,
        "kNN":               _knn,
        "NaiveBayes":        _naive_bayes,
        "RandomForest":      _random_forest,
        "Ensemble_Boosting": _ensemble_boosting,
        "Ensemble_Voting":   _ensemble_voting,
    }

    def __init__(self,
                 seed: int = 42,
                 with_plausibility: bool = True,
                 n_splits: int = 5):
        self.seed              = seed
        self.with_plausibility = with_plausibility
        self.n_splits          = n_splits

    def _feature_cols(self) -> List[str]:
        """Return the active feature column list based on configuration."""
        if self.with_plausibility:
            return FEATURE_COLS                  # all 10 features
        return KINEMATIC_COLS                    # 6 kinematic only

    def run(self, feat_df: pd.DataFrame) -> Dict[str, Dict]:
        """
        Run all six classifiers with stratified k-fold cross-validation.

        Parameters
        ----------
        feat_df : output of extract_features_from_ns3()

        Returns
        -------
        dict  classifier_name → project metrics dict (7 metrics + confusion)
        """
        active_cols = self._feature_cols()
        feat_df     = feat_df.dropna(subset=active_cols + ["label"])

        X       = feat_df[active_cols].values.astype(np.float64)
        y       = feat_df["label"].values
        devs    = feat_df["disp_err_m"].values
        n_total = len(y)

        skf = StratifiedKFold(n_splits=self.n_splits, shuffle=True,
                               random_state=self.seed)

        # Collectors: store per-fold predictions for aggregation
        collectors: Dict[str, Dict] = {
            name: dict(yt=[], yp=[], de=[])
            for name in self.CLASSIFIERS
        }

        for tr_idx, te_idx in skf.split(X, y):
            X_tr, X_te = X[tr_idx], X[te_idx]
            y_tr        = y[tr_idx]

            # Guard: need both classes in training fold
            if len(np.unique(y_tr)) < 2:
                continue

            NO_SEED = {"kNN", "NaiveBayes"}
            for name, factory in self.CLASSIFIERS.items():
                clf = factory(seed=self.seed) if name not in NO_SEED \
                      else factory()
                clf.fit(X_tr, y_tr)
                y_pred = clf.predict(X_te)

                collectors[name]["yt"].extend(y[te_idx].tolist())
                collectors[name]["yp"].extend(y_pred.tolist())
                collectors[name]["de"].extend(devs[te_idx].tolist())

        results: Dict[str, Dict] = {}
        for name, col in collectors.items():
            if not col["yt"]:
                continue
            results[name] = compute_our_metrics(
                np.array(col["yt"]),
                np.array(col["yp"]),
                np.array(col["de"]),
                n_total=n_total,
            )
        return results


# ─────────────────────────────────────────────────────────────────────────────
#  PENETRATION SWEEP  (mirror of B2 penetration_sweep for consistent comparison)
# ─────────────────────────────────────────────────────────────────────────────

def penetration_sweep(feat_df: pd.DataFrame,
                      classifier: str = "RandomForest",
                      seed: int = 42) -> List[Dict]:
    """
    Simulate different attack penetration rates by subsampling N out of the
    available malicious vehicles in the NS-3 data.

    Parameters
    ----------
    feat_df    : output of extract_features_from_ns3()
    classifier : which of the 6 Sharma classifiers to use for the sweep
    seed       : random seed

    Returns
    -------
    list of dicts: {rho, n_mal, <classifier>_<metric>...}
    """
    mal_vids = sorted(feat_df[feat_df["label"] == 1]["vehicle_id"].unique())
    hon_vids = sorted(feat_df[feat_df["label"] == 0]["vehicle_id"].unique())
    rng      = np.random.default_rng(seed)
    rows     = []

    for n_mal in range(1, len(mal_vids) + 1):
        chosen_mal = rng.choice(mal_vids, n_mal, replace=False).tolist()
        subset     = feat_df[feat_df["vehicle_id"].isin(hon_vids + chosen_mal)].copy()
        rho        = n_mal / (n_mal + len(hon_vids))

        det = SharmaB3Detector(seed=seed, with_plausibility=True)
        res = det.run(subset)
        clf_res = res.get(classifier, {})

        rows.append({
            "n_mal":  n_mal,
            "n_hon":  len(hon_vids),
            "rho":    round(rho, 3),
            **{f"{classifier}_{k}": v for k, v in clf_res.items()},
        })

    return rows


# ─────────────────────────────────────────────────────────────────────────────
#  ABLATION: WITH vs WITHOUT PLAUSIBILITY CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def ablation_plausibility(feat_df: pd.DataFrame,
                          seed: int = 42) -> Dict[str, Dict]:
    """
    Compare detection performance with and without plausibility checks
    (LP + MP features), reproducing Table III / Table IV of the paper.

    Returns
    -------
    dict: {
        "with_checks":    {classifier: metrics},
        "without_checks": {classifier: metrics},
    }
    """
    det_with    = SharmaB3Detector(seed=seed, with_plausibility=True)
    det_without = SharmaB3Detector(seed=seed, with_plausibility=False)
    return {
        "with_checks":    det_with.run(feat_df),
        "without_checks": det_without.run(feat_df),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  SMOKE TEST
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    csv = os.path.join(os.path.dirname(__file__),
                       "../analytics/results/rsu_relay_log.csv")
    if not os.path.exists(csv):
        print("rsu_relay_log.csv not found — run from project root")
        sys.exit(1)

    print("=== Sharma B3 — Stratified 5-Fold CV on NS-3 data ===")
    feat = extract_features_from_ns3(csv)
    print(f"Features: {feat.shape}  label dist: {feat['label'].value_counts().to_dict()}")
    print(f"Active features (with plausibility): {FEATURE_COLS}")

    det = SharmaB3Detector(with_plausibility=True)
    res = det.run(feat)
    print("\n--- Our 7 metrics (with plausibility checks) ---")
    for method, m in res.items():
        print(f"\n  {method}:")
        for k, v in m.items():
            print(f"    {k:<8}: {v}")