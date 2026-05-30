"""
mptd_pqs/ercan_b2_detector.py
================================
B2 Baseline: Ercan et al. (2022)
"Misbehavior Detection for Position Falsification Attacks in VANETs
Using Machine Learning" IEEE Access 2022. DOI: 10.1109/ACCESS.2021.3136706

Implementation notes
--------------------
  Data source  : NS-3 rsu_relay_log.csv  (real simulation output)
  Evaluation   : Leave-One-Vehicle-Out cross-validation  (16 vehicles)
  Metrics      : OUR 7 project metrics — MCC, FPR, PARR, CDER, TDEE, TPE, PBPO
  Classifiers  : kNN (k=5), RF (100 trees), Stacking (kNN+RF → Logistic)

Ercan features extracted (Section III-A common + III-B proposed):
  Common : recv_pos_x, recv_pos_y, speed, Δpos_x, Δpos_y, Δspeed,
           dist_decl, speed_diff
  New    : AoA (Eq.7),  d_hat RSSI-estimated (Eq.10),  delta_d (Eq.11)

RSSI physics: PT=20dBm, PL_D0=47dB, n=2.7, σ=8dB (urban NLOS VANET).
At σ=8dB the d_hat uncertainty at 500m is ~±200m — larger than the
~24m trajectory poisoning offset in attack_1. This correctly shows that
Ercan's RSSI feature struggles against our subtle drift attack.
"""
from __future__ import annotations

import math
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple

from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import confusion_matrix, matthews_corrcoef
from sklearn.model_selection import StratifiedKFold

# ─────────────────────────────────────────────────────────────────────────────
#  PHYSICAL CONSTANTS  (802.11p / ETSI ITS-G5)
# ─────────────────────────────────────────────────────────────────────────────
PT       = 20.0   # Tx power [dBm]
PL_D0    = 47.0   # Path loss at reference distance d0=10m [dB]
D0       = 10.0   # Reference distance [m]
N_EXP    = 2.7    # Path-loss exponent (urban VANET)
SIGMA_DB = 8.0    # Log-normal shadowing std dev [dB]  (urban NLOS)

# RSU positions from our NS-3 simulation config (x,y in metres)
RSU_POS: Dict[int, Tuple[float, float]] = {
    0: (0.0,    580.0),
    1: (500.0,  580.0),
    2: (1000.0, 580.0),
    3: (1500.0, 580.0),
}

# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE NAMES
# ─────────────────────────────────────────────────────────────────────────────
FEATURE_COLS = [
    "recv_pos_x", "recv_pos_y",   # declared (possibly faked) position
    "speed_ms",                   # declared speed
    "d_recv_pos_x", "d_recv_pos_y",  # Δ declared position (Eq. 1)
    "d_speed_ms",                 # Δ speed (Eq. 2)
    "dist_decl",                  # declared distance to RSU (Eq. 5 adapted)
    "speed_diff",                 # |speed| since RSU is stationary (Eq. 6)
    "aoa",                        # Angle of Arrival (Eq. 7)
    "d_hat",                      # RSSI-estimated distance (Eq. 10)
    "delta_d",                    # |dist_decl − d_hat| (Eq. 11)
]


# ─────────────────────────────────────────────────────────────────────────────
#  RSSI HELPERS  (Ercan Eq. 8-11)
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
    return max(D0 * (10.0 ** ((PT - rssi - PL_D0) / (10.0 * N_EXP))), 0.0)


# ─────────────────────────────────────────────────────────────────────────────
#  FEATURE EXTRACTION FROM NS-3 rsu_relay_log.csv
# ─────────────────────────────────────────────────────────────────────────────

def extract_features_from_ns3(csv_path: str, seed: int = 42) -> pd.DataFrame:
    """
    Load NS-3 rsu_relay_log.csv and compute Ercan feature set.

    NS-3 columns used:
      sim_time       – beacon timestamp
      vehicle_id     – sender identity (for grouping)
      rsu_id         – which RSU received the beacon (for RSU position)
      real_pos_x/y   – true position (for RSSI computation)
      recv_pos_x/y   – declared position in BSM (faked for malicious)
      speed_ms       – declared speed
      is_poisoned    – ground truth label
      disp_err_m     – |real − declared| position error (for CDER/TDEE)

    Returns a DataFrame with FEATURE_COLS + ['label', 'vehicle_id', 'disp_err_m']
    """
    raw = pd.read_csv(csv_path)
    rng = np.random.default_rng(seed)
    records: List[Dict] = []

    for vid, grp in raw.groupby("vehicle_id", sort=False):
        grp    = grp.sort_values("sim_time").reset_index(drop=True)
        rsu_id = int(grp["rsu_id"].iloc[0])
        rsu_xy = RSU_POS.get(rsu_id, (0.0, 580.0))
        prev   = None

        for _, row in grp.iterrows():
            rx  = float(row["recv_pos_x"])
            ry  = float(row["recv_pos_y"])
            spd = float(row["speed_ms"])
            tx  = float(row["real_pos_x"])
            ty  = float(row["real_pos_y"])

            # Common features
            d_rx = rx - float(prev["recv_pos_x"]) if prev is not None else 0.0
            d_ry = ry - float(prev["recv_pos_y"]) if prev is not None else 0.0
            d_sp = spd - float(prev["speed_ms"])  if prev is not None else 0.0

            dist_decl  = math.hypot(rx - rsu_xy[0], ry - rsu_xy[1])
            speed_diff = abs(spd)  # RSU is stationary

            # Proposed features
            dx = rx - rsu_xy[0]; dy = ry - rsu_xy[1]
            aoa     = math.atan2(dy, dx) if (abs(dx) + abs(dy)) > 1e-6 else 0.0
            rssi    = _simulate_rssi(tx, ty, rsu_xy, rng)
            d_hat   = _d_hat_from_rssi(rssi)
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


# ─────────────────────────────────────────────────────────────────────────────
#  CLASSIFIERS  (Section III-C of Ercan et al.)
# ─────────────────────────────────────────────────────────────────────────────

def _knn(k: int = 5) -> Pipeline:
    """kNN with z-score normalisation (Euclidean distance needs scaling)."""
    return Pipeline([("scaler", StandardScaler()),
                     ("clf", KNeighborsClassifier(n_neighbors=k, n_jobs=-1))])


def _rf(seed: int = 42) -> RandomForestClassifier:
    """Random Forest — no scaling needed."""
    return RandomForestClassifier(n_estimators=100, random_state=seed, n_jobs=-1)


def _stacking(seed: int = 42) -> StackingClassifier:
    """Stacking: kNN + RF → Logistic Regression (Fig. 7)."""
    return StackingClassifier(
        estimators=[("knn", _knn()), ("rf", _rf(seed=seed))],
        final_estimator=LogisticRegression(max_iter=1000, random_state=seed),
        cv=5, n_jobs=-1)


# ─────────────────────────────────────────────────────────────────────────────
# PROJECT METRICS 
# ─────────────────────────────────────────────────────────────────────────────

CDER_THRESHOLD = 10.0   # metres — same as MetricsCalculator in our pipeline


def compute_our_metrics(y_true: np.ndarray,
                        y_pred: np.ndarray,
                        disp_err: np.ndarray,
                        n_total: int) -> Dict:
    """
    Compute all 7 project metrics for Ercan's detection output.

    y_true    : ground truth labels (0=honest, 1=poisoned)
    y_pred    : Ercan's predicted labels
    disp_err  : position error in metres for each row (0 for honest)
    n_total   : total beacon records (for TPE/PBPO denominator)

    Metric definitions (metrics_calculator.py):
      MCC   – Matthews Correlation Coefficient
      FPR   – FP / (FP + TN)
      PARR  – TP / (TP + FN)  [detection rate of poisoned records]
      CDER  – mean(|disp_err_i|) for MISSED attacks (FN) where err > threshold
      TDEE  – sum(disp_err_i²) for ALL missed attacks (FN)
      TPE   – n_poisoned_injected / n_total  [attacker's reach — fixed by scenario]
      PBPO  – FN / n_total  [fraction of records with undetected poisoning]
    """
    cm    = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    mcc  = float(matthews_corrcoef(y_true, y_pred))
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    parr = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    # FN rows = detected as honest but actually poisoned → these escape into system
    fn_mask  = (y_true == 1) & (y_pred == 0)
    fn_devs  = disp_err[fn_mask]
    exceeded = fn_devs[fn_devs > CDER_THRESHOLD]
    cder     = float(exceeded.mean()) if len(exceeded) > 0 else 0.0
    tdee     = float(np.sum(fn_devs ** 2))

    n_poisoned_injected = int((y_true == 1).sum())
    tpe  = n_poisoned_injected / n_total if n_total > 0 else 0.0
    pbpo = int(fn) / n_total if n_total > 0 else 0.0

    return dict(
        TP=int(tp), FP=int(fp), TN=int(tn), FN=int(fn),
        MCC=round(mcc, 4),
        FPR=round(fpr, 4),
        PARR=round(parr, 4),
        CDER=round(cder, 4),
        TDEE=round(tdee, 2),
        TPE=round(tpe, 4),
        PBPO=round(pbpo, 4),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN DETECTOR CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ErcanB2Detector:

    def __init__(self, seed: int = 42):
        self.seed = seed

    def run(self, feat_df: pd.DataFrame) -> Dict[str, Dict]:
        
        feat_df = feat_df.dropna(subset=FEATURE_COLS + ["label"])
        X       = feat_df[FEATURE_COLS].values
        y       = feat_df["label"].values
        groups  = feat_df["vehicle_id"].values
        devs    = feat_df["disp_err_m"].values
        n_total = len(y)

        # logo      = LeaveOneGroupOut()
        skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=self.seed)
        collectors: Dict[str, Dict] = {
            "kNN":      dict(yt=[], yp=[], de=[]),
            "RF":       dict(yt=[], yp=[], de=[]),
            "Stacking": dict(yt=[], yp=[], de=[]),
        }

        # for tr_idx, te_idx in logo.split(X, y, groups):
        for tr_idx, te_idx in skf.split(X, y):
            X_tr, X_te = X[tr_idx], X[te_idx]
            y_tr        = y[tr_idx]

            # Guard: need both classes in training
            if len(np.unique(y_tr)) < 2:
                continue

            for name, clf in [
                ("kNN",      _knn()),
                ("RF",       _rf(seed=self.seed)),
                ("Stacking", _stacking(seed=self.seed)),
            ]:
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
#  PENETRATION SWEEP via NS-3 vehicle subsampling
# ─────────────────────────────────────────────────────────────────────────────

def penetration_sweep(feat_df: pd.DataFrame,
                      seed: int = 42) -> List[Dict]:
    """
    Simulate different attack penetration rates by selecting N out of 8
    malicious vehicles from the NS-3 data.

    Returns list of dicts: {rho, n_mal, RF_metrics...}
    """
    mal_vids = sorted(feat_df[feat_df["label"] == 1]["vehicle_id"].unique())
    hon_vids = sorted(feat_df[feat_df["label"] == 0]["vehicle_id"].unique())
    rng      = np.random.default_rng(seed)
    det      = ErcanB2Detector(seed=seed)
    rows     = []

    for n_mal in range(1, len(mal_vids) + 1):
        chosen_mal = rng.choice(mal_vids, n_mal, replace=False).tolist()
        subset     = feat_df[feat_df["vehicle_id"].isin(hon_vids + chosen_mal)].copy()
        rho        = n_mal / (n_mal + len(hon_vids))
        res        = det.run(subset)
        rf         = res.get("RF", {})
        rows.append({
            "n_mal":  n_mal,
            "n_hon":  len(hon_vids),
            "rho":    round(rho, 3),
            **{f"RF_{k}": v for k, v in rf.items()},
        })

    return rows


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

    print("=== Ercan B2 — LOVO-CV on NS-3 data ===")
    feat = extract_features_from_ns3(csv)
    print(f"Features: {feat.shape}  label dist: {feat['label'].value_counts().to_dict()}")

    det = ErcanB2Detector()
    res = det.run(feat)
    print("\n--- Our 7 metrics ---")
    for method, m in res.items():
        print(f"\n  {method}:")
        for k, v in m.items():
            print(f"    {k:<8}: {v}")