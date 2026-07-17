"""
mptd_pqs/ghaleb_b1_detector.py
================================
B1 Baseline: Ghaleb et al. (2014)
"Mobility Pattern Based Misbehavior Detection in Vehicular Ad Hoc Networks
to Enhance Safety" — ICCVE 2014.

REAL NS-3 DATA VERSION
----------------------
Reads the NS-3 simulation output CSVs from the datasets/ folder.
Each scenario is one folder: datasets/a{attack}_p{pct}/
  beacon_log.csv            — one row per beacon received by an RSU
  tp_s1_poison_log.csv      — (attack 1 only) real/fake positions + disp_err_m
  vehicle_tx_log.csv        — (attacks 2,4) real/sent positions + disp_err_m
  ghost_identity_log.csv    — (attack 3) ghost identity records

Column mapping (beacon_log):
  pos_x / pos_y    -> declared (possibly faked) BSM position
  speed            -> declared speed
  heading          -> declared heading [rad]  (if present, else 0)
  rsu_id           -> which RSU received the beacon
  vehicle_id       -> sender ID
  sim_time         -> simulation timestamp [s]
  is_poisoned      -> ground-truth label (0 = honest, 1 = malicious)
  detected         -> MPTD-PQS online decision (used for proposed-system eval)

Ghaleb B1 modules (faithfully re-implemented):
  Module 1 — Security Verification   : PKI group-signature (always-pass, as in paper)
  Module 2 — Location Verification
      2a  Road-map boundary          : |y − road_centre_y| ≤ road_half_w
      2b  Transmission range         : declared position within WAVE range of RSU
      2c  Occupied location          : no two vehicles at identical position
      2d  Speed-of-light constraint  : dist(Lprev, Lcurr) / dt ≤ c  (Eq.1)
  Module 3 — Movement Analysis       : abnormal LTT bounding-box area difference
  Module 4 — Plausibility Detection  : speed within [0, 240 km/h]

Final decision: OR of all module flags (any violation → malicious).

Real position augmentation mirrors ercan_b2_detector_new.py exactly so that
disp_err_m is consistently sourced across both baselines.
"""

from __future__ import annotations

import math
import os
import numpy as np
import pandas as pd
import scipy.stats as stats
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from sklearn.metrics import confusion_matrix, matthews_corrcoef
from sklearn.model_selection import StratifiedKFold, KFold

# ───────────────────────────────────────────────────────────────────
#  PHYSICAL / PROTOCOL CONSTANTS  (IEEE 802.11p / VANET defaults)
# ───────────────────────────────────────────────────────────────────
Tb              = 0.1          # beacon interval [s]
WAVE_RANGE_M    = 300.0        # V2V/V2I comm range [m]  (1 hop)
SPEED_MIN_MS    = 0.0          # 0 km/h in m/s
SPEED_MAX_MS    = 66.67        # 240 km/h in m/s  (Ghaleb upper plausibility bound)
ROAD_HALF_W     = 21.0         # half-width of a 3-lane road [m]
ROAD_CENTRE_Y   = 580.0        # NS-3 road centreline Y coordinate [m]
LTT_WINDOW      = 6            # LTT evidence accumulation window (beacons)
AREA_DIFF_TH    = 600.0        # m²  suspicious LTT area-difference (Module 3)
MIN_VEH_SEP     = 2.0          # m   minimum legal vehicle separation (Module 2c)

CDER_THRESHOLD  = 10.0         # metres — for CDER metric
N_SPLITS        = 5            # StratifiedKFold splits

# RSU positions matching ercan_b2_detector_new.py
RSU_POS: Dict[int, Tuple[float, float]] = {
    0: (0.0,    580.0),
    1: (500.0,  580.0),
    2: (1000.0, 580.0),
    3: (1500.0, 580.0),
}

# ───────────────────────────────────────────────────────────────────
#  ATTACK / SCENARIO METADATA
# ───────────────────────────────────────────────────────────────────
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

PROPOSED_NAME = "MPTD-PQS (Proposed)"


# ───────────────────────────────────────────────────────────────────
#  REAL-POSITION AUGMENTATION  (mirrors ercan_b2_detector_new.py)
# ───────────────────────────────────────────────────────────────────

def _augment_with_real_pos(beacon: pd.DataFrame,
                            scenario_dir: str) -> pd.DataFrame:
    """
    Add columns real_pos_x, real_pos_y, disp_err_m to a beacon_log DataFrame.

    Sourcing strategy per attack:
      tp_s1_poison_log.csv  (attack 1)   → row-order align per vehicle_id
      vehicle_tx_log.csv    (attacks 2,4) → row-order align per vehicle_id
      ghost_identity_log.csv (attack 3)   → mean displacement for poisoned rows
      (none)                (attacks 5,6,7) → real = declared, disp_err = 0
    """
    b = beacon.copy()
    b = b.sort_values(["vehicle_id", "sim_time"]).reset_index(drop=True)

    # Defaults
    b["real_pos_x"] = b["pos_x"]
    b["real_pos_y"] = b["pos_y"]
    b["disp_err_m"] = 0.0

    # Attack 1 — TP-S1
    poison_csv = os.path.join(scenario_dir, "tp_s1_poison_log.csv")
    if os.path.exists(poison_csv):
        p = (pd.read_csv(poison_csv)
               .sort_values(["vehicle_id", "sim_time"])
               .reset_index(drop=True))
        for vid in p["vehicle_id"].unique():
            b_mask = (b["vehicle_id"] == vid) & (b["is_poisoned"] == 1)
            b_idx  = b[b_mask].index
            p_rows = p[p["vehicle_id"] == vid].reset_index(drop=True)
            if len(b_idx) == len(p_rows):
                b.loc[b_idx, "real_pos_x"] = p_rows["real_pos_x"].values
                b.loc[b_idx, "real_pos_y"] = p_rows["real_pos_y"].values
                b.loc[b_idx, "disp_err_m"] = p_rows["disp_err_m"].values
        return b

    # Attacks 2, 4 — vehicle_tx_log
    tx_csv = os.path.join(scenario_dir, "vehicle_tx_log.csv")
    if os.path.exists(tx_csv):
        tx = (pd.read_csv(tx_csv)
                .sort_values(["vehicle_id", "sim_time"])
                .reset_index(drop=True))
        for vid in tx["vehicle_id"].unique():
            b_mask = b["vehicle_id"] == vid
            b_idx  = b[b_mask].index
            t_rows = tx[tx["vehicle_id"] == vid].reset_index(drop=True)
            if len(b_idx) == len(t_rows):
                b.loc[b_idx, "real_pos_x"] = t_rows["real_pos_x"].values
                b.loc[b_idx, "real_pos_y"] = t_rows["real_pos_y"].values
                b.loc[b_idx, "disp_err_m"] = t_rows["disp_err_m"].values
        return b

    # Attack 3 — ghost_identity_log
    ghost_csv = os.path.join(scenario_dir, "ghost_identity_log.csv")
    if os.path.exists(ghost_csv):
        g = pd.read_csv(ghost_csv)
        mean_disp = (float(g["displacement_m"].mean())
                     if "displacement_m" in g.columns else 150.0)
        b.loc[b["is_poisoned"] == 1, "disp_err_m"] = mean_disp
        return b

    # Attacks 5, 6, 7 — no position falsification in BSM
    return b


# ───────────────────────────────────────────────────────────────────
#  METRICS
# ───────────────────────────────────────────────────────────────────

def compute_metrics(y_true: np.ndarray,
                    y_pred: np.ndarray,
                    disp_err: np.ndarray,
                    n_total: int) -> Dict:
    """Compute all 7 project metrics."""
    cm             = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # ε-smoothed MCC (Eq 4.1) — matches the C++ MPTD-PQS pipeline (ε=1e-12) so the
    # baseline MCC is comparable in degenerate / class-imbalance cases.
    _e   = 1e-12
    _num = (tp + _e) * (tn + _e) - (fp + _e) * (fn + _e)
    _den = ((tp + fp + _e) * (tp + fn + _e) * (tn + fp + _e) * (tn + fn + _e)) ** 0.5
    mcc  = float(_num / _den)
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    parr = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    fn_mask  = (y_true == 1) & (y_pred == 0)
    fn_devs  = disp_err[fn_mask]
    exceeded = fn_devs[fn_devs > CDER_THRESHOLD]
    cder     = float(exceeded.mean()) if len(exceeded) > 0 else 0.0
    tdee     = float(np.sum(fn_devs ** 2))

    n_poisoned = int((y_true == 1).sum())
    tpe  = n_poisoned / n_total if n_total > 0 else 0.0
    pbpo = int(fn)    / n_total if n_total > 0 else 0.0

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


# ───────────────────────────────────────────────────────────────────
#  INTERNAL STATE
# ───────────────────────────────────────────────────────────────────

@dataclass
class _VehicleState:
    """Per-vehicle LTT history."""
    ltt: List[Tuple[float, float, float]] = field(default_factory=list)


# ───────────────────────────────────────────────────────────────────
#  GHALEB B1 DETECTOR  (rule-based, stateful)
# ───────────────────────────────────────────────────────────────────

class GhalebB1Detector:
    """
    Pure rule-based misbehavior detector as in Ghaleb et al. (2014).

    Operates on NS-3 beacon_log rows (augmented with real_pos_x/y).
    All four modules produce binary flags; final prediction = OR of all flags.

    Parameters
    ----------
    speed_max_ms    : Module 4 upper speed plausibility bound [m/s]
    speed_min_ms    : Module 4 lower bound [m/s]
    road_centre_y   : Y coordinate of road centreline in NS-3 scenario [m]
    road_half_w     : Module 2a road half-width [m]
    wave_range      : Module 2b RSU transmission range [m]
    min_veh_sep     : Module 2c minimum vehicle separation [m]
    area_diff_th    : Module 3 LTT area-difference threshold [m²]
    ltt_window      : LTT evidence window (number of beacons)
    """

    def __init__(self,
                 speed_max_ms:  float = SPEED_MAX_MS,
                 speed_min_ms:  float = SPEED_MIN_MS,
                 road_centre_y: float = ROAD_CENTRE_Y,
                 road_half_w:   float = ROAD_HALF_W,
                 wave_range:    float = WAVE_RANGE_M,
                 min_veh_sep:   float = MIN_VEH_SEP,
                 area_diff_th:  float = AREA_DIFF_TH,
                 ltt_window:    int   = LTT_WINDOW):
        self.speed_max    = speed_max_ms
        self.speed_min    = speed_min_ms
        self.road_centre  = road_centre_y
        self.road_half_w  = road_half_w
        self.wave_range   = wave_range
        self.min_veh_sep  = min_veh_sep
        self.area_diff_th = area_diff_th
        self.ltt_window   = ltt_window
        self._state: Dict[str, _VehicleState] = {}

    # ── helpers ─────────────────────────────────────────────────

    def _get_state(self, vid) -> _VehicleState:
        k = str(vid)
        if k not in self._state:
            self._state[k] = _VehicleState()
        return self._state[k]

    def _update_ltt(self, vid, x: float, y: float, t: float) -> None:
        st = self._get_state(vid)
        st.ltt.append((x, y, t))
        if len(st.ltt) > self.ltt_window:
            st.ltt = st.ltt[-self.ltt_window:]

    @staticmethod
    def _bbox_area(pts: List[Tuple[float, float, float]]) -> float:
        if len(pts) < 2:
            return 0.0
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        return (max(xs) - min(xs) + 1.0) * (max(ys) - min(ys) + 1.0)

    def _ltt_area_diff(self, vid) -> float:
        """Module 3: bounding-box area diff between earlier/current LTT views."""
        st   = self._get_state(vid)
        n    = len(st.ltt)
        if n < 2:
            return 0.0
        half      = max(1, n // 2)
        prev_area = self._bbox_area(st.ltt[:half])
        curr_area = self._bbox_area(st.ltt[half:])
        return abs(curr_area - prev_area)

    # ── per-beacon detection ─────────────────────────────────────

    def detect_beacon(self,
                      row:      dict,
                      prev_row: Optional[dict],
                      rsu_xy:   Tuple[float, float],
                      peer_positions: Optional[List[Tuple[float, float]]] = None
                      ) -> dict:
        """
        Run all four Ghaleb modules for one incoming BSM beacon.

        Parameters
        ----------
        row            : current beacon dict (vehicle_id, pos_x, pos_y,
                         speed, sim_time, [heading])
        prev_row       : previous beacon from same vehicle (None on first)
        rsu_xy         : (x, y) of the receiving RSU
        peer_positions : list of (x,y) of other vehicles at same timestep
        """
        vid  = row["vehicle_id"]
        x    = float(row["pos_x"])
        y    = float(row["pos_y"])
        s_ms = float(row["speed"])
        t    = float(row["sim_time"])
        flags = dict(m1=0, m2a=0, m2b=0, m2c=0, m2d=0, m3=0, m4=0)

        # Module 1 — Security Verification (PKI always-pass, per paper)
        flags["m1"] = 0

        # Module 2a — Road-Map Boundary
        if abs(y - self.road_centre) > self.road_half_w:
            flags["m2a"] = 1

        # Module 2b — Transmission Range (declared pos must be near RSU)
        dist_rsu = math.hypot(x - rsu_xy[0], y - rsu_xy[1])
        if dist_rsu > self.wave_range * 4:   # lenient 4× (matches original)
            flags["m2b"] = 1

        # Module 2c — Occupied Location (anti-Sybil)
        if peer_positions:
            for px, py in peer_positions:
                if math.hypot(x - px, y - py) < self.min_veh_sep:
                    flags["m2c"] = 1
                    break

        # Module 2d — Speed-of-Light / Kinematic Constraint  (Eq.1)
        if prev_row is not None and str(prev_row["vehicle_id"]) == str(vid):
            dt   = t - float(prev_row["sim_time"])
            dist = math.hypot(x - float(prev_row["pos_x"]),
                              y - float(prev_row["pos_y"]))
            if dt > 1e-9 and (dist / dt) > self.speed_max:
                flags["m2d"] = 1

        # Module 3 — Movement Analysis (LTT area difference)
        self._update_ltt(vid, x, y, t)
        area_d = self._ltt_area_diff(vid)
        if area_d > self.area_diff_th:
            flags["m3"] = 1

        # Module 4 — Plausibility (speed bounds)
        s_kmh = s_ms * 3.6
        if not (self.speed_min * 3.6 <= s_kmh <= 240.0):
            flags["m4"] = 1

        pred = int(any(flags.values()))
        return {
            **flags,
            "pred":      pred,
            "area_diff": round(area_d, 4),
            "speed_kmh": round(s_kmh,  4),
            "vehicle_id": vid,
            "sim_time":   t,
        }

    # ── batch runner ─────────────────────────────────────────────

    def run(self, beacon_aug: pd.DataFrame) -> pd.DataFrame:
        """
        Run the detector over an augmented beacon_log DataFrame.

        Parameters
        ----------
        beacon_aug : DataFrame produced by load_scenario()
                     Must contain: vehicle_id, pos_x, pos_y, speed,
                                   sim_time, rsu_id, is_poisoned, disp_err_m

        Returns
        -------
        DataFrame with module flags, pred, label, disp_err_m columns.
        """
        self._state.clear()
        results: List[Dict] = []

        # Per-timestep peer map for Module 2c
        peer_map: Dict[float, List[Tuple[float, float, str]]] = {}
        for _, row in beacon_aug.iterrows():
            tk = float(row["sim_time"])
            peer_map.setdefault(tk, []).append(
                (float(row["pos_x"]), float(row["pos_y"]), str(row["vehicle_id"]))
            )

        for vid, grp in beacon_aug.groupby("vehicle_id", sort=False):
            grp  = grp.sort_values("sim_time").reset_index(drop=True)
            prev = None

            # Use first RSU seen for this vehicle
            rsu_id = int(grp["rsu_id"].iloc[0])
            rsu_xy = RSU_POS.get(rsu_id, (0.0, ROAD_CENTRE_Y))

            for _, row in grp.iterrows():
                r   = row.to_dict()
                tk  = float(r["sim_time"])
                peers = [(px, py)
                         for px, py, pvid in peer_map.get(tk, [])
                         if pvid != str(vid)]

                det             = self.detect_beacon(r, prev, rsu_xy, peers)
                det["label"]    = int(row["is_poisoned"])
                det["disp_err_m"] = float(row["disp_err_m"])
                det["attack_type"] = str(row.get("attack_type", "unknown"))
                results.append(det)
                prev = r

        return pd.DataFrame(results)

    def reset(self) -> None:
        self._state.clear()


# ───────────────────────────────────────────────────────────────────
#  SCENARIO LOADER
# ───────────────────────────────────────────────────────────────────

def load_scenario(scenario_dir: str) -> Optional[pd.DataFrame]:
    """
    Load one NS-3 scenario folder → augmented beacon_log DataFrame.
    Returns None if beacon_log.csv is missing or unreadable.
    """
    beacon_csv = os.path.join(scenario_dir, "beacon_log.csv")
    if not os.path.exists(beacon_csv):
        return None
    beacon = pd.read_csv(beacon_csv)

    # Ensure required columns exist; add heading=0 if missing
    if "heading" not in beacon.columns:
        beacon["heading"] = 0.0
    if "attack_type" not in beacon.columns:
        beacon["attack_type"] = "unknown"

    return _augment_with_real_pos(beacon, scenario_dir)


# ───────────────────────────────────────────────────────────────────
#  FOLD-WISE EVALUATION  (mirrors ercan_b2_detector_new.py)
# ───────────────────────────────────────────────────────────────────

def evaluate_scenario_with_ci(beacon_aug: pd.DataFrame,
                               seed: int = 42) -> Dict[str, Dict]:
    """
    Run Ghaleb B1 over beacon_aug and compute 5-fold metrics + 95% CI.

    The detector is stateless per-fold: a fresh GhalebB1Detector() is
    instantiated and run on each fold's test rows independently.
    (Training data is not used — B1 is purely rule-based.)

    Returns
    -------
    dict  →  metric  →  {"mean", "ci95", "values"}
    """
    y_true  = beacon_aug["is_poisoned"].values.astype(int)
    disp    = beacon_aug["disp_err_m"].values.astype(float)
    n_total = len(y_true)

    if n_total < N_SPLITS:
        return {}

    # ── Run the full-dataset detector once to get predictions ──
    det     = GhalebB1Detector()
    det_df  = det.run(beacon_aug)
    y_pred  = det_df["pred"].values.astype(int)

    # ── Fold the predictions (same splitter as baselines) ──────
    if len(np.unique(y_true)) >= 2:
        splitter = StratifiedKFold(n_splits=N_SPLITS, shuffle=True,
                                   random_state=seed)
        splits   = list(splitter.split(np.zeros(n_total), y_true))
    else:
        splitter = KFold(n_splits=N_SPLITS, shuffle=True, random_state=seed)
        splits   = list(splitter.split(np.zeros(n_total)))

    folds = []
    for _, te_idx in splits:
        folds.append(compute_metrics(
            y_true[te_idx], y_pred[te_idx], disp[te_idx], n_total=n_total
        ))

    METRICS = ["MCC", "FPR", "PARR", "CDER", "TDEE", "TPE", "PBPO"]
    out: Dict[str, Dict] = {}
    for m in METRICS:
        vals = np.array([f[m] for f in folds])
        mean = float(vals.mean())
        ci   = (float(stats.t.ppf(0.975, df=len(vals) - 1)
                      * vals.std(ddof=1) / math.sqrt(len(vals)))
                if len(vals) > 1 else 0.0)
        out[m] = {"mean": round(mean, 4), "ci95": round(ci, 4),
                  "values": vals.tolist()}
    return out


# ───────────────────────────────────────────────────────────────────
#  FULL SWEEP
# ───────────────────────────────────────────────────────────────────

def run_full_sweep(datasets_root: str, seed: int = 42) -> pd.DataFrame:
    """
    Iterate over all a{i}_p{pct} folders and evaluate Ghaleb B1.
    Returns a tidy DataFrame (same column layout as ercan_b2_detector_new.py).
    """
    rows = []
    for atk in ATTACK_NUMS:
        for pct in ATTACK_PCTS:
            folder = os.path.join(datasets_root, f"a{atk}_p{pct}")
            if not os.path.isdir(folder):
                continue
            print(f"  Loading a{atk}_p{pct} ...", end=" ", flush=True)
            aug = load_scenario(folder)
            if aug is None or len(aug) == 0:
                print("SKIP (empty)")
                continue
            ci_res = evaluate_scenario_with_ci(aug, seed=seed)
            if not ci_res:
                print("SKIP (no metrics)")
                continue
            labels = aug["is_poisoned"].value_counts().to_dict()
            print(f"rows={len(aug)}, label={labels}")
            row = {"attack": atk, "attack_pct": pct, "classifier": "B1-Ghaleb"}
            for m, v in ci_res.items():
                row[f"{m}_mean"] = v["mean"]
                row[f"{m}_ci95"] = v["ci95"]
            rows.append(row)
    return pd.DataFrame(rows)


# ───────────────────────────────────────────────────────────────────
#  PROPOSED-SYSTEM EVALUATION  (from beacon_log `detected` column)
# ───────────────────────────────────────────────────────────────────

def evaluate_proposed_with_ci(beacon_aug: pd.DataFrame,
                               seed: int = 42) -> Dict[str, Dict]:
    """
    Fold-wise evaluation of MPTD-PQS `detected` column.
    Mirrors ercan_b2_detector_new.py::evaluate_proposed_with_ci().
    """
    if "detected" not in beacon_aug.columns:
        return {}
    y_true  = beacon_aug["is_poisoned"].values.astype(int)
    y_pred  = beacon_aug["detected"].values.astype(int)
    devs    = beacon_aug["disp_err_m"].values.astype(float)
    n_total = len(y_true)
    if n_total < N_SPLITS:
        return {}

    if len(np.unique(y_true)) >= 2:
        splitter = StratifiedKFold(n_splits=N_SPLITS, shuffle=True,
                                   random_state=seed)
        splits   = list(splitter.split(np.zeros(n_total), y_true))
    else:
        splitter = KFold(n_splits=N_SPLITS, shuffle=True, random_state=seed)
        splits   = list(splitter.split(np.zeros(n_total)))

    folds = []
    for _, te_idx in splits:
        folds.append(compute_metrics(
            y_true[te_idx], y_pred[te_idx], devs[te_idx], n_total=n_total
        ))

    METRICS = ["MCC", "FPR", "PARR", "CDER", "TDEE", "TPE", "PBPO"]
    out: Dict[str, Dict] = {}
    for m in METRICS:
        vals = np.array([f[m] for f in folds])
        mean = float(vals.mean())
        ci   = (float(stats.t.ppf(0.975, df=len(vals) - 1)
                      * vals.std(ddof=1) / math.sqrt(len(vals)))
                if len(vals) > 1 else 0.0)
        out[m] = {"mean": round(mean, 4), "ci95": round(ci, 4)}
    return out


def run_proposed_sweep(datasets_root: str, seed: int = 42) -> pd.DataFrame:
    """Evaluate MPTD-PQS on every a{i}_p{pct} folder (reads `detected` col)."""
    rows = []
    for atk in ATTACK_NUMS:
        for pct in ATTACK_PCTS:
            folder     = os.path.join(datasets_root, f"a{atk}_p{pct}")
            beacon_csv = os.path.join(folder, "beacon_log.csv")
            if not os.path.exists(beacon_csv):
                continue
            beacon = pd.read_csv(beacon_csv)
            if "heading" not in beacon.columns:
                beacon["heading"] = 0.0
            aug  = _augment_with_real_pos(beacon, folder)
            mets = evaluate_proposed_with_ci(aug, seed=seed)
            if not mets:
                continue
            row = {"attack": atk, "attack_pct": pct,
                   "classifier": PROPOSED_NAME}
            for m, v in mets.items():
                row[f"{m}_mean"] = v["mean"]
                row[f"{m}_ci95"] = v["ci95"]
            rows.append(row)
    return pd.DataFrame(rows)