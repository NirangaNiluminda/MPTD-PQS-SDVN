"""
ercan_b2_detector_new.py
========================
B2 Baseline: Ercan et al. (2022)
"Misbehavior Detection for Position Falsification Attacks in VANETs
Using Machine Learning" IEEE Access 2022. DOI: 10.1109/ACCESS.2021.3136706

REAL NS-3 DATA VERSION
----------------------
Reads the NS-3 simulation output CSVs from the datasets/ folder.
Each scenario is one folder: datasets/a{attack}_p{pct}/
  beacon_log.csv       — one row per beacon received by an RSU
  tp_s1_poison_log.csv — (attack 1 only) per-beacon real/fake positions + disp_err_m
  vehicle_tx_log.csv   — (attacks 2,4) per-transmit real/sent positions + disp_err_m

Column mapping (beacon_log):
  pos_x / pos_y    -> declared (possibly faked) BSM position = Ercan's recv_pos
  speed            -> declared speed
  gt_pos_x/y       -> NOT the vehicle's own real pos (ignore)
  rsu_id           -> which RSU received the beacon
  vehicle_id       -> sender ID
  is_poisoned      -> ground-truth label (0 = honest, 1 = malicious)

Real position sourcing (for RSSI estimation):
  a1 (TP-S1)  — tp_s1_poison_log: real_pos_x/y matched by vehicle+row-order
  a2, a4      — vehicle_tx_log: real_pos_x/y matched by vehicle+row-order
  a3, a5-a7   — no separate real-pos log; use declared pos as real pos
                (a5=controller attack, a6=MitM, a7=controller poison; the
                 beacon payload itself is not position-falsified in space
                 so RSSI-declared distance is consistent)

Ercan features (Section III-A common + III-B proposed):
  Common : recv_pos_x, recv_pos_y, speed_ms,
           Δpos_x (Eq.1), Δpos_y (Eq.1),
           Δspeed (Eq.2),
           dist_decl (Eq.5 adapted: distance from declared pos to RSU),
           speed_diff (Eq.6: |speed| since RSU is stationary)
  New    : AoA  (Eq.7),  d_hat RSSI-estimated distance (Eq.10),
           delta_d |dist_decl − d_hat| (Eq.11)

RSSI physics (802.11p / ETSI ITS-G5 urban VANET):
  PT=20 dBm, PL_D0=47 dB (d0=10 m), n=2.7, σ=8 dB (log-normal shadowing)

Evaluation:
  • Cross-validation: StratifiedKFold (5-fold) per scenario file
  • Classifiers: kNN (k=5), RF (100 trees), Stacking (kNN+RF → Logistic)
  • Sweep: across attack percentages 0, 30, 60, 90 for each attack type
  • Metrics: MCC, FPR, PARR, CDER, TDEE, TPE, PBPO
  • Plots: mean ± 95% CI across 5 folds vs attack percentage
           separate plot per attack type (a1..a7)
"""

from __future__ import annotations

import math
import os
import glob
import numpy as np
import pandas as pd
import scipy.stats as stats
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from typing import Dict, List, Optional, Tuple

from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import confusion_matrix, matthews_corrcoef

# ─────────────────────────────────────────────────────────────────────────────
#  PHYSICAL CONSTANTS  (802.11p / ETSI ITS-G5 urban VANET)
# ─────────────────────────────────────────────────────────────────────────────
PT       = 20.0   # Tx power [dBm]
PL_D0    = 47.0   # Path loss at reference distance d0=10m [dB]
D0       = 10.0   # Reference distance [m]
N_EXP    = 2.7    # Path-loss exponent (urban VANET, NLOS)
SIGMA_DB = 8.0    # Log-normal shadowing std dev [dB]

# RSU positions [metres]. Loaded from the SAME file NS-3 uses to place RSUs
# (mobility/rsu_positions_urban.csv, "rsu_id,x,y"), so the dist_decl / speed_diff
# features (Ercan Eq. 5/6) are computed against the ACTUAL placed RSUs — including
# the supervisor-mandated 8x8 = 64-RSU grid (2026-06-12). Earlier this was a
# hardcoded 4-RSU line layout (250/750/1250/1750 @ y=480), which gave every
# rsu_id >= 4 a bogus fallback position under SUMO-trace runs and corrupted the
# distance feature. Falls back to the legacy 4-RSU test-grid if the CSV is absent
# (i.e. test-net runs with --mobility_source=0).
_LEGACY_RSU_POS = {
    0: (250.0, 480.0), 1: (750.0, 480.0),
    2: (1250.0, 480.0), 3: (1750.0, 480.0),
}


def load_rsu_positions(csv_path: Optional[str] = None) -> Dict[int, Tuple[float, float]]:
    """Read RSU (x, y) keyed by rsu_id from mobility/rsu_positions_urban.csv.

    This is the exact file NS-3 loads in SUMO-trace mode (12_main.h:799), so the
    Python baseline sees the same RSU topology the simulation ran with. Returns
    the legacy 4-RSU layout if the CSV cannot be read."""
    if csv_path is None:
        csv_path = os.path.join(os.path.dirname(__file__), "..",
                                "mobility", "rsu_positions_urban.csv")
    try:
        df = pd.read_csv(csv_path)
        pos = {int(r["rsu_id"]): (float(r["x"]), float(r["y"]))
               for _, r in df.iterrows()}
        if pos:
            return pos
    except (FileNotFoundError, KeyError, ValueError):
        pass
    return dict(_LEGACY_RSU_POS)


RSU_POS: Dict[int, Tuple[float, float]] = load_rsu_positions()

FEATURE_COLS = [
    "recv_pos_x", "recv_pos_y",      # declared BSM position (possibly faked)
    "speed_ms",                       # declared speed
    "d_recv_pos_x", "d_recv_pos_y",  # Δ declared position (Eq. 1)
    "d_speed_ms",                     # Δ declared speed (Eq. 2)
    "dist_decl",                      # declared dist to RSU (Eq. 5 adapted)
    "speed_diff",                     # |speed|, RSU is stationary (Eq. 6)
    "aoa",                            # Angle of Arrival (Eq. 7)
    "d_hat",                          # RSSI-estimated distance (Eq. 10)
    "delta_d",                        # |dist_decl − d_hat| (Eq. 11)
]

CDER_THRESHOLD = 10.0   # metres

N_SPLITS = 5            # StratifiedKFold splits


# ─────────────────────────────────────────────────────────────────────────────
#  RSSI HELPERS  (Ercan Eq. 8–11)
# ─────────────────────────────────────────────────────────────────────────────

def _simulate_rssi(real_x: float, real_y: float,
                   rsu_xy: Tuple[float, float],
                   rng: np.random.Generator) -> float:
    """RSSI from TRUE position (radio signal cannot be spoofed). Eq. 8+9."""
    d  = max(math.hypot(real_x - rsu_xy[0], real_y - rsu_xy[1]), D0)
    pl = PL_D0 + 10.0 * N_EXP * math.log10(d / D0) + float(rng.normal(0, SIGMA_DB))
    return PT - pl


def _d_hat_from_rssi(rssi: float) -> float:
    """Estimate distance from RSSI. Eq. 10."""
    return max(D0 * (10.0 ** ((PT - rssi - PL_D0) / (10.0 * N_EXP))), D0)


# ─────────────────────────────────────────────────────────────────────────────
#  REAL-POSITION AUGMENTATION
#  Match beacon_log rows with the attack-specific real-position log
#  so that RSSI is computed from the TRUE vehicle position.
# ─────────────────────────────────────────────────────────────────────────────

def _augment_with_real_pos(beacon: pd.DataFrame,
                            scenario_dir: str) -> pd.DataFrame:
    """
    Add columns real_pos_x, real_pos_y, disp_err_m to beacon_log.

    Strategy per attack type:
      tp_s1_poison_log.csv  (attack 1)  → row-order align per vehicle_id
      vehicle_tx_log.csv    (attack 2,4)→ row-order align per vehicle_id
      (none)                (attack 3,5,6,7) → real = declared, disp_err = 0
    """
    b = beacon.copy()
    b = b.sort_values(["vehicle_id", "sim_time"]).reset_index(drop=True)

    # Defaults: real position = declared position, no error
    b["real_pos_x"] = b["pos_x"]
    b["real_pos_y"] = b["pos_y"]
    b["disp_err_m"] = 0.0

    # --- attack 1: tp_s1_poison_log ---
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

    # --- attacks 2, 4: vehicle_tx_log ---
    tx_csv = os.path.join(scenario_dir, "vehicle_tx_log.csv")
    if os.path.exists(tx_csv):
        tx = pd.read_csv(tx_csv).sort_values(["vehicle_id", "sim_time"]).reset_index(drop=True)
        # vehicle_tx_log covers ALL vehicles (honest + malicious)
        for vid in tx["vehicle_id"].unique():
            b_mask = b["vehicle_id"] == vid
            b_idx  = b[b_mask].index
            t_rows = tx[tx["vehicle_id"] == vid].reset_index(drop=True)
            if len(b_idx) == len(t_rows):
                b.loc[b_idx, "real_pos_x"] = t_rows["real_pos_x"].values
                b.loc[b_idx, "real_pos_y"] = t_rows["real_pos_y"].values
                b.loc[b_idx, "disp_err_m"] = t_rows["disp_err_m"].values
        return b

    # --- attacks 3, 5, 6, 7: no explicit real-pos log ---
    # For a3 (Sybil ghost): ghost nodes are entirely fabricated.
    # Their declared position IS the injected position; we cannot
    # get a true RF position from the log. We set disp_err = 150 m
    # (the displacement used in NS3 for ghost generation) for poisoned rows.
    ghost_csv = os.path.join(scenario_dir, "ghost_identity_log.csv")
    if os.path.exists(ghost_csv):
        g = pd.read_csv(ghost_csv)
        # Use the mean displacement as disp_err for poisoned rows
        mean_disp = float(g["displacement_m"].mean()) if "displacement_m" in g.columns else 150.0
        b.loc[b["is_poisoned"] == 1, "disp_err_m"] = mean_disp
        return b

    # a5, a6, a7: controller/MITM attacks; position error comes from indirect
    # route manipulation, not direct BSM position falsification.
    # We leave disp_err_m = 0 (these attacks don't directly falsify BSM position,
    # so Ercan's position-falsification features are expected to struggle here).
    return b


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE EXTRACTION  (from augmented beacon_log DataFrame)
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(beacon_aug: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """
    Compute the 11 Ercan features from an augmented beacon_log DataFrame.
    Returns a DataFrame with FEATURE_COLS + ['label', 'vehicle_id', 'disp_err_m'].
    """
    rng     = np.random.default_rng(seed)
    records: List[Dict] = []

    for vid, grp in beacon_aug.groupby("vehicle_id", sort=False):
        grp    = grp.sort_values("sim_time").reset_index(drop=True)
        rsu_id = int(grp["rsu_id"].iloc[0])
        rsu_xy = RSU_POS.get(rsu_id, (0.0, 580.0))
        prev   = None

        for _, row in grp.iterrows():
            rx  = float(row["pos_x"])       # declared (possibly faked) x
            ry  = float(row["pos_y"])       # declared y
            spd = float(row["speed"])       # declared speed
            tx  = float(row["real_pos_x"])  # true x (for RSSI)
            ty  = float(row["real_pos_y"])  # true y (for RSSI)

            # ── Common features ──────────────────────────────────────────────
            # Eq. 1: Δ declared position
            d_rx = rx - float(prev["pos_x"])   if prev is not None else 0.0
            d_ry = ry - float(prev["pos_y"])   if prev is not None else 0.0
            # Eq. 2: Δ declared speed
            d_sp = spd - float(prev["speed"])  if prev is not None else 0.0
            # Eq. 5 (adapted): declared Euclidean distance from declared pos to RSU
            dist_decl  = math.hypot(rx - rsu_xy[0], ry - rsu_xy[1])
            # Eq. 6: |speed| (RSU has speed=0, so diff = |vehicle speed|)
            speed_diff = abs(spd)

            # ── Proposed features ────────────────────────────────────────────
            # Eq. 7: Angle of Arrival (from RSU to declared vehicle position)
            dx  = rx - rsu_xy[0]
            dy  = ry - rsu_xy[1]
            aoa = math.atan2(dy, dx) if (abs(dx) + abs(dy)) > 1e-6 else 0.0
            # Eq. 8+9+10: RSSI from TRUE position → estimated distance d_hat
            rssi  = _simulate_rssi(tx, ty, rsu_xy, rng)
            d_hat = _d_hat_from_rssi(rssi)
            # Eq. 11: |declared distance − RSSI-estimated distance|
            delta_d = abs(dist_decl - d_hat)

            records.append({
                "vehicle_id":   int(vid),
                "recv_pos_x":   rx,
                "recv_pos_y":   ry,
                "speed_ms":     spd,
                "d_recv_pos_x": d_rx,
                "d_recv_pos_y": d_ry,
                "d_speed_ms":   d_sp,
                "dist_decl":    dist_decl,
                "speed_diff":   speed_diff,
                "aoa":          aoa,
                "d_hat":        d_hat,
                "delta_d":      delta_d,
                "label":        int(row["is_poisoned"]),
                "disp_err_m":   float(row["disp_err_m"]),
            })
            prev = row

    return pd.DataFrame(records)


def load_scenario(scenario_dir: str, seed: int = 42) -> Optional[pd.DataFrame]:
    """
    Load one NS-3 scenario folder → feature DataFrame.
    Returns None if beacon_log.csv is missing.
    """
    beacon_csv = os.path.join(scenario_dir, "beacon_log.csv")
    if not os.path.exists(beacon_csv):
        return None
    beacon = pd.read_csv(beacon_csv)
    aug    = _augment_with_real_pos(beacon, scenario_dir)
    return extract_features(aug, seed=seed)


def paper_rule_predict(feat_df: pd.DataFrame, ci: float = 2.576) -> np.ndarray:
    """Ercan 2021 RSSI plausibility decision — NO TRAINING, NO OUR-DATA FITTING.

    Ercan's distinctive contribution is the mismatch between the DECLARED
    distance to the RSU (dist_decl, from the possibly-faked BSM position) and
    the distance ESTIMATED from RSSI (d_hat), which cannot be spoofed because
    received power depends on the true propagation distance (Eqs 8-11).

    Instead of an ML classifier (which the paper trains, but sir's rule forbids
    training on our data), we flag a message when the declared and RSSI-based
    distances disagree beyond the log-normal shadowing model's own CI. The
    RSSI distance estimate is multiplicative-lognormal with
        σ_d = SIGMA_DB / (10 · N_EXP)   [in log10 units],
    so the decision is a pure z-test on log-distance at the 99% level
    (ci=2.576) — the threshold comes from the 802.11p propagation model, never
    from our labels.

    NOTE: only fires where a real-position log exists (a1/a2/a4); for attacks
    with no true-position log (a3/a5/a6/a7) real==declared → d_hat≈dist_decl →
    no RSSI signal, which is the honest outcome for a position-falsification
    detector on non-position attacks.
    """
    sigma_d = SIGMA_DB / (10.0 * N_EXP)          # log10 std of the distance estimate
    dd = np.maximum(feat_df["dist_decl"].values, D0)
    dh = np.maximum(feat_df["d_hat"].values,     D0)
    z  = np.abs(np.log10(dd) - np.log10(dh)) / max(sigma_d, 1e-9)
    return (z > ci).astype(int)


# ─────────────────────────────────────────────────────────────────────────────
#  CLASSIFIERS  (Section III-C)
# ─────────────────────────────────────────────────────────────────────────────

def _knn(k: int = 5) -> Pipeline:
    """kNN with z-score normalisation (Euclidean distance requires scaling)."""
    return Pipeline([("scaler", StandardScaler()),
                     ("clf",    KNeighborsClassifier(n_neighbors=k, n_jobs=-1))])


def _rf(seed: int = 42) -> RandomForestClassifier:
    """Random Forest — scaling not required."""
    return RandomForestClassifier(n_estimators=100, random_state=seed, n_jobs=-1)


def _stacking(seed: int = 42) -> StackingClassifier:
    """Stacking: kNN + RF → Logistic Regression (Fig. 7 of Ercan paper)."""
    return StackingClassifier(
        estimators=[("knn", _knn()), ("rf", _rf(seed=seed))],
        final_estimator=LogisticRegression(max_iter=1000, random_state=seed),
        cv=3, n_jobs=-1)


# ─────────────────────────────────────────────────────────────────────────────
#  PROJECT METRICS
# ─────────────────────────────────────────────────────────────────────────────

def compute_metrics(y_true: np.ndarray,
                    y_pred: np.ndarray,
                    disp_err: np.ndarray,
                    n_total: int) -> Dict:
    """
    Compute all 7 project metrics.

    Parameters
    ----------
    y_true    : ground truth labels (0=honest, 1=poisoned)
    y_pred    : Ercan predicted labels
    disp_err  : position displacement error [m] for each row
    n_total   : total beacon records in this scenario (denominator for TPE/PBPO)
    """
    cm           = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # ε-smoothed MCC (Eq 4.1) — matches the C++ MPTD-PQS pipeline (ε=1e-12) so the
    # baseline MCC is comparable in degenerate / class-imbalance cases (raw
    # sklearn matthews_corrcoef returns 0 there, diverging from MPTD-PQS).
    _e   = 1e-12
    _num = (tp + _e) * (tn + _e) - (fp + _e) * (fn + _e)
    _den = ((tp + fp + _e) * (tp + fn + _e) * (tn + fp + _e) * (tn + fn + _e)) ** 0.5
    mcc  = float(_num / _den)
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    parr = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    fn_mask  = (y_true == 1) & (y_pred == 0)           # missed attacks
    fn_devs  = disp_err[fn_mask]
    exceeded = fn_devs[fn_devs > CDER_THRESHOLD]
    cder     = float(exceeded.mean()) if len(exceeded) > 0 else 0.0
    tdee     = float(np.sum(fn_devs ** 2))

    n_poisoned = int((y_true == 1).sum())
    tpe  = n_poisoned / n_total if n_total > 0 else 0.0
    pbpo = int(fn)  / n_total if n_total > 0 else 0.0

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
#  CROSS-VALIDATED EVALUATION  (StratifiedKFold, 5-fold)
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_scenario(feat_df: pd.DataFrame,
                      seed: int = 42) -> Dict[str, Dict]:
    """
    Run 5-fold stratified CV on one scenario's feature DataFrame.
    Returns per-classifier metrics aggregated over all folds.
    """
    feat_df = feat_df.dropna(subset=FEATURE_COLS + ["label"])
    if len(feat_df) < 10:
        return {}

    X       = feat_df[FEATURE_COLS].values
    y       = feat_df["label"].values
    devs    = feat_df["disp_err_m"].values
    n_total = len(y)

    if len(np.unique(y)) < 2:
        return {}

    skf = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=seed)
    collectors = {
        "kNN":      {"yt": [], "yp": [], "de": []},
        "RF":       {"yt": [], "yp": [], "de": []},
        "Stacking": {"yt": [], "yp": [], "de": []},
    }

    for tr_idx, te_idx in skf.split(X, y):
        X_tr, X_te = X[tr_idx], X[te_idx]
        y_tr        = y[tr_idx]
        if len(np.unique(y_tr)) < 2:
            continue
        for name, clf in [("kNN",      _knn()),
                           ("RF",       _rf(seed=seed)),
                           ("Stacking", _stacking(seed=seed))]:
            clf.fit(X_tr, y_tr)
            yp = clf.predict(X_te)
            collectors[name]["yt"].extend(y[te_idx].tolist())
            collectors[name]["yp"].extend(yp.tolist())
            collectors[name]["de"].extend(devs[te_idx].tolist())

    results: Dict[str, Dict] = {}
    for name, col in collectors.items():
        if not col["yt"]:
            continue
        results[name] = compute_metrics(
            np.array(col["yt"]),
            np.array(col["yp"]),
            np.array(col["de"]),
            n_total=n_total,
        )
    return results


def evaluate_scenario_with_ci(feat_df: pd.DataFrame,
                               seed: int = 42) -> Dict[str, Dict]:
    """
    Run 5-fold CV and return per-fold metrics to compute mean + 95% CI.
    Returns dict: classifier → metric → {"mean", "ci95", "values"}
    """
    feat_df = feat_df.dropna(subset=FEATURE_COLS + ["label"])
    if len(feat_df) < 10:
        return {}

    X       = feat_df[FEATURE_COLS].values
    y       = feat_df["label"].values
    devs    = feat_df["disp_err_m"].values
    n_total = len(y)

    if len(np.unique(y)) < 2:
        return {}

    skf        = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=seed)
    fold_results: Dict[str, List[Dict]] = {
        "kNN": [], "RF": [], "Stacking": []
    }

    for tr_idx, te_idx in skf.split(X, y):
        X_tr, X_te = X[tr_idx], X[te_idx]
        y_tr        = y[tr_idx]
        if len(np.unique(y_tr)) < 2:
            continue
        for name, clf in [("kNN",      _knn()),
                           ("RF",       _rf(seed=seed)),
                           ("Stacking", _stacking(seed=seed))]:
            clf.fit(X_tr, y_tr)
            yp = clf.predict(X_te)
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
                ci   = float(stats.t.ppf(0.975, df=len(vals)-1) * vals.std(ddof=1) / math.sqrt(len(vals)))
            else:
                ci = 0.0
            out[clf_name][m] = {"mean": round(mean, 4), "ci95": round(ci, 4), "values": vals.tolist()}
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  SWEEP: ALL ATTACK TYPES × ALL ATTACK PERCENTAGES
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_PCTS   = [0, 30, 60, 90]
ATTACK_NUMS   = [1, 2, 3, 4, 5, 6, 7]

ATTACK_LABELS = {
    1: "a1: TP-S1 (RSU drift)",
    2: "a2: TP-S2 (speed/heading)",
    3: "a3: MP-S1 (Sybil ghost)",
    4: "a4: MP-S2 (impersonation)",
    5: "a5: TP-S3 (flooding)",
    6: "a6: MitM intercept",
    7: "a7: Controller poison",
}

# Classifier line styles and colours for the plots
CLF_STYLE = {
    "kNN":      {"color": "#1f77b4", "linestyle": "-",  "marker": "o"},
    "RF":       {"color": "#2ca02c", "linestyle": "--", "marker": "s"},
    "Stacking": {"color": "#d62728", "linestyle": ":",  "marker": "^"},
}


def run_full_sweep(datasets_root: str, seed: int = 42) -> pd.DataFrame:
    """
    Iterate over all a{i}_p{pct} folders, evaluate Ercan on each,
    and return a tidy results DataFrame.

    Columns: attack, attack_pct, classifier, MCC_mean, MCC_ci95, ...
    """
    rows = []
    for atk in ATTACK_NUMS:
        for pct in ATTACK_PCTS:
            folder = os.path.join(datasets_root, f"a{atk}_p{pct}")
            if not os.path.isdir(folder):
                continue
            print(f"  Loading a{atk}_p{pct} ...", end=" ", flush=True)
            feat = load_scenario(folder, seed=seed)
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


# Style for our own system overlay (MPTD-PQS) — distinct from baseline classifier styles
MPTD_PQS_STYLE = {
    "color":     "#8b0000",   # dark red
    "linestyle": "-.",        # dash-dot
    "marker":    "D",         # diamond
    "linewidth": 2.2,
    "markersize": 7,
    "label":     "MPTD-PQS (Our System)",
}


def load_mptd_pqs_metrics(datasets_root: str) -> pd.DataFrame:
    """
    Read each datasets/a{atk}_p{pct}/metrics.csv (NS-3 MPTD-PQS pipeline output)
    and return a tidy DataFrame: attack, attack_pct, MCC, FPR, PARR, CDER, TDEE, TPE, PBPO.

    Mapping of metrics.csv columns -> the project's 7 metrics:
      MCC       <- 'MCC'
      FPR       <- 'FPR'
      PARR      <- 'PARR'
      CDER      <- 'CDER'
      TDEE      <- 'TDEE'       (NaN if -1 sentinel)
      TPE       <- 'TPE'
      PBPO      <- 'PBPO_LW_ms' (lightweight blockchain persistence offset, ms)
    """
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
            # FULL-mode fusion detection: prefer MCC_full/FPR_full (Eq 3.46 fused
            # Φ decision, ε-smoothed) — the proposed method's real output. Fall back
            # to LW MCC/FPR only if the full-mode columns are absent (mode-1 runs).
            _mcc_full = float(row.get("MCC_full", 0.0))
            _fpr_full = float(row.get("FPR_full", 0.0))
            _has_full = ("MCC_full" in df.columns) and (abs(_mcc_full) > 1e-9 or abs(_fpr_full) > 1e-9)
            rows.append({
                "attack":     atk,
                "attack_pct": pct,
                "MCC":        (_mcc_full if _has_full else float(row.get("MCC", 0.0))),
                "FPR":        (_fpr_full if _has_full else float(row.get("FPR", 0.0))),
                "PARR":       float(row.get("PARR", 0.0)),
                "CDER":       float(row.get("CDER", 0.0)),
                "TDEE":       (float("nan") if tdee < 0 else tdee),
                "TPE":        float(row.get("TPE",  0.0)),
                "PBPO":       float(row.get("PBPO_LW_ms", 0.0)),
            })
    return pd.DataFrame(rows)


def plot_metric_vs_attack_pct(sweep_df: pd.DataFrame,
                               metric: str,
                               out_path: str,
                               mptd_pqs_df: Optional[pd.DataFrame] = None):
    """
    One figure per metric, subplots = one per attack type.
    X-axis: attack percentage. Y-axis: metric mean ± 95% CI.
    Each Ercan classifier gets its own line; MPTD-PQS (our system) overlaid.
    """
    attacks_present = sorted(sweep_df["attack"].unique())
    n_plots = len(attacks_present)
    ncols = min(4, n_plots)
    nrows = math.ceil(n_plots / ncols)

    fig, axes = plt.subplots(nrows, ncols,
                              figsize=(5 * ncols, 4 * nrows),
                              squeeze=False)
    fig.suptitle(f"Ercan et al. (B2) vs. MPTD-PQS — {METRIC_LABELS[metric]}\nvs. Attack Percentage",
                 fontsize=12, fontweight="bold", y=1.01)

    for idx, atk in enumerate(attacks_present):
        ax   = axes[idx // ncols][idx % ncols]
        sub  = sweep_df[sweep_df["attack"] == atk]

        # ── Ercan classifier lines ───────────────────────────────────────────
        for clf, style in CLF_STYLE.items():
            sub_c = sub[sub["classifier"] == clf].sort_values("attack_pct")
            if sub_c.empty:
                continue
            x    = sub_c["attack_pct"].values
            y    = sub_c[f"{metric}_mean"].values
            yerr = sub_c[f"{metric}_ci95"].values
            ax.errorbar(x, y, yerr=yerr,
                        label=f"B2-Ercan ({clf})",
                        color=style["color"],
                        linestyle=style["linestyle"],
                        marker=style["marker"],
                        linewidth=1.8,
                        markersize=5,
                        capsize=4)

        # ── MPTD-PQS overlay (our system) ────────────────────────────────────
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
        ax.legend(fontsize=6, loc="best")
        ax.tick_params(labelsize=7)

    # Hide empty subplots
    for idx in range(len(attacks_present), nrows * ncols):
        axes[idx // ncols][idx % ncols].set_visible(False)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Plot saved: {out_path}")


def plot_all_metrics(sweep_df: pd.DataFrame, out_dir: str,
                     mptd_pqs_df: Optional[pd.DataFrame] = None):
    """Generate one plot per metric, with MPTD-PQS overlay on each."""
    os.makedirs(out_dir, exist_ok=True)
    for metric in METRICS_TO_PLOT:
        out = os.path.join(out_dir, f"ercan_b2_{metric.lower()}_vs_attack_pct.png")
        plot_metric_vs_attack_pct(sweep_df, metric, out, mptd_pqs_df=mptd_pqs_df)


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main(datasets_root: str = "datasets",
         results_dir:  str = "results_ercan_b2"):

    os.makedirs(results_dir, exist_ok=True)

    print("=" * 65)
    print("  Ercan et al. (2022) B2 Baseline — NS-3 Real Data")
    print(f"  Dataset root : {datasets_root}")
    print(f"  Results dir  : {results_dir}")
    print(f"  CV           : StratifiedKFold ({N_SPLITS}-fold)")
    print(f"  Metrics      : {', '.join(METRICS_TO_PLOT)}")
    print("=" * 65)

    # ── Sweep ────────────────────────────────────────────────────────────────
    print("\n[1/4] Running full sweep (all attacks × all attack percentages)...")
    sweep_df = run_full_sweep(datasets_root, seed=42)

    csv_path = os.path.join(results_dir, "ercan_b2_sweep_results.csv")
    sweep_df.to_csv(csv_path, index=False)
    print(f"\n  Sweep CSV saved: {csv_path}")

    # ── Load MPTD-PQS (our system) results from metrics.csv files ────────────
    print("\n[2/4] Loading MPTD-PQS metrics from each scenario's metrics.csv ...")
    mptd_pqs_df = load_mptd_pqs_metrics(datasets_root)
    mptd_csv_path = os.path.join(results_dir, "mptd_pqs_metrics.csv")
    mptd_pqs_df.to_csv(mptd_csv_path, index=False)
    print(f"  MPTD-PQS CSV saved : {mptd_csv_path}")
    print(f"  Rows               : {len(mptd_pqs_df)}")

    # ── Print summary table ──────────────────────────────────────────────────
    print("\n[3/4] Summary (RF classifier, all scenarios):")
    rf_df = sweep_df[sweep_df["classifier"] == "RF"].copy()
    print(rf_df[["attack", "attack_pct",
                 "MCC_mean", "MCC_ci95",
                 "FPR_mean", "PARR_mean",
                 "CDER_mean", "PBPO_mean"]].to_string(index=False))

    # ── Plots ────────────────────────────────────────────────────────────────
    print("\n[4/4] Generating plots (Ercan baselines + MPTD-PQS overlay)...")
    plot_all_metrics(sweep_df, results_dir, mptd_pqs_df=mptd_pqs_df)

    print(f"\n[Done] All outputs in: {results_dir}")
    return sweep_df


if __name__ == "__main__":
    import sys
    root    = sys.argv[1] if len(sys.argv) > 1 else "datasets"
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "results_ercan_b2"
    main(datasets_root=root, results_dir=out_dir)
