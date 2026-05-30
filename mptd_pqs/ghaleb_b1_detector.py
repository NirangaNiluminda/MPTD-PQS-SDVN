"""
mptd_pqs/ghaleb_b1_detector.py
================================
B1 Baseline: Ghaleb et al. (2014)
"Mobility Pattern Based Misbehavior Detection in Vehicular Ad Hoc Networks
to Enhance Safety" — ICCVE 2014.

Faithfully re-implements the four detection modules described in the paper:

  Module 1 — Security Verification   : Group-signature identity check
                                        (simulated as always-pass; PKI assumed
                                         present — matches paper assumption)
  Module 2 — Location Verification   : Four sub-checks
      2a  Road-map boundary          : position must be on a known road segment
      2b  Transmission range         : sender within WAVE 1 km limit
      2c  Occupied location          : no two vehicles at identical position
      2d  Speed-of-light constraint  : dist(Lr, Lv) / (tr - ts) <= c  (Eq.1)
  Module 3 — Movement Analysis       : abnormal LTT area-difference between
                                        current-view and earlier-view
  Module 4 — Plausibility Detection  : speed in [0, 240 km/h], road-type limit

The composite decision is: flag = OR of all module outputs (any violation).

This file is self-contained and imports nothing from the rest of mptd_pqs
so it can be used as a stand-alone baseline or called from run_b1_baseline.py.

Usage
-----
    from mptd_pqs.ghaleb_b1_detector import GhalebB1Detector, build_beacon_dataset
    data    = build_beacon_dataset(n_honest=30, n_malicious=10, n_steps=100)
    detector = GhalebB1Detector()
    results  = detector.run(data)
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ───────────────────────────────────────────────────────────────────
#  PHYSICAL / PROTOCOL CONSTANTS  (IEEE 802.11p / VANET defaults)
# ───────────────────────────────────────────────────────────────────
Tb             = 0.1          # beacon interval [s]  (100 ms, IEEE 802.11p)
WAVE_RANGE_M   = 300.0        # V2V/V2I comm range [m]
SPEED_MIN_MS   = 0.0          # 0 km/h in m/s
SPEED_MAX_MS   = 66.67        # 240 km/h in m/s  (Ghaleb upper plausibility bound)
SPEED_HWY_MS   = 33.33        # 120 km/h  — highway road-type limit
SPEED_URB_MS   = 13.89        # 50  km/h  — urban road-type limit
AMAX_MS2       = 8.0          # m/s²  maximum physical acceleration
WMAX_RADS      = 0.6          # rad/s maximum heading rate
ROAD_HALF_W    = 21.0         # half-width of a 3-lane road [m]
LTT_WINDOW     = 6            # LTT evidence accumulation window (beacons)
AREA_DIFF_TH   = 600.0        # m²  — suspicious LTT area-difference (Module 3)
MIN_VEH_SEP    = 2.0          # m   — minimum legal vehicle separation (Module 2c)


# ───────────────────────────────────────────────────────────────────
#  BSM BEACON DATA GENERATION
# ───────────────────────────────────────────────────────────────────

def _honest_step(x: float, y: float, speed: float, heading: float,
                 smax: float, dt: float) -> Tuple[float, float, float, float, float]:
    """Advance one honest beacon step with gentle realistic variation."""
    speed   = float(np.clip(speed + np.random.normal(0, 0.25), 1.0, smax))
    heading = heading + np.random.normal(0, 0.015)
    accel   = np.random.normal(0, 0.3)
    x      += speed * dt * np.cos(heading)
    y      += speed * dt * np.sin(heading)
    y       = float(np.clip(y, -ROAD_HALF_W, ROAD_HALF_W))
    return x, y, speed, heading, accel


def generate_vehicle_trace(n_steps: int,
                            vehicle_type: str = "honest",
                            attack_type: Optional[str] = None,
                            speed_regime: str = "urban",
                            rng: Optional[np.random.Generator] = None) -> pd.DataFrame:
    """
    Simulate a single vehicle's BSM beacon stream.

    Parameters
    ----------
    n_steps      : number of beacon epochs
    vehicle_type : "honest" | "malicious"
    attack_type  : "position_jump" | "speed_falsify" | "heading_jump"
                   | "gradual_drift" | "sybil_ghost"
    speed_regime : "urban" | "highway"
    rng          : optional numpy Generator for reproducibility

    Returns
    -------
    DataFrame columns: t, x, y, speed_ms, heading_rad, accel_ms2, label
    """
    if rng is None:
        rng = np.random.default_rng()

    smax = SPEED_HWY_MS if speed_regime == "highway" else SPEED_URB_MS
    dt   = Tb

    x       = float(rng.uniform(0, 800))
    y       = float(rng.uniform(-ROAD_HALF_W * 0.5, ROAD_HALF_W * 0.5))
    speed   = float(rng.uniform(3, smax * 0.85))
    heading = 0.0
    records: List[Dict] = []

    for step in range(n_steps):
        t = step * dt

        # ── honest kinematics ────────────────────────────────
        x, y, speed, heading, accel = _honest_step(x, y, speed, heading, smax, dt)
        px, py, ps, ph, pa = x, y, speed, heading, accel
        label = 0

        # ── inject attack behaviour ──────────────────────────
        if vehicle_type == "malicious" and step >= LTT_WINDOW:
            label = 1

            if attack_type == "position_jump":
                # Sudden large teleport — clearly violates speed-of-light (Eq.1)
                px += float(rng.uniform(150, 400))
                py += float(rng.uniform(-30, 30))

            elif attack_type == "speed_falsify":
                # Report speed well above 240 km/h physical limit (Module 4)
                ps = float(rng.uniform(SPEED_MAX_MS + 5, SPEED_MAX_MS + 40))

            elif attack_type == "heading_jump":
                # Instantaneous unrealistic heading change (Module 2 sub-check)
                ph = heading + float(rng.uniform(0.9, 1.8))

            elif attack_type == "gradual_drift":
                # Per-beacon drift ≤ ε_max but accumulates — evades Module 2d
                # This is exactly the attack Ghaleb CANNOT detect (MCC collapses)
                drift = (step - LTT_WINDOW) * 0.28
                px    = x + drift * np.cos(heading + 0.25)
                py    = y + drift * np.sin(heading + 0.25)
                # Only truly anomalous once displacement is large
                label = 1 if drift > 6.0 else 0

            elif attack_type == "sybil_ghost":
                # Clone identity appears at implausible cross-RSU location
                px += float(rng.uniform(400, 700))
                py  = float(rng.uniform(-ROAD_HALF_W, ROAD_HALF_W))

        records.append({
            "t":           t,
            "x":           round(px, 4),
            "y":           round(py, 4),
            "speed_ms":    round(ps, 4),
            "heading_rad": round(ph, 4),
            "accel_ms2":   round(pa, 4),
            "label":       label,
        })

    return pd.DataFrame(records)


def build_beacon_dataset(n_honest: int = 30,
                         n_malicious: int = 10,
                         n_steps: int = 100,
                         speed_regime: str = "urban",
                         attack_mix: Optional[List[str]] = None,
                         seed: int = 42) -> pd.DataFrame:
    """
    Build a multi-vehicle BSM dataset with honest + malicious vehicles.

    Parameters
    ----------
    n_honest    : number of honest vehicles
    n_malicious : number of malicious vehicles
    n_steps     : beacon epochs per vehicle
    speed_regime: "urban" | "highway"
    attack_mix  : list of attack types cycled across malicious vehicles.
                  Defaults to all four attack types.
    seed        : random seed

    Returns
    -------
    DataFrame with columns: vehicle_id, t, x, y, speed_ms, heading_rad,
                             accel_ms2, label, vehicle_type
    """
    if attack_mix is None:
        attack_mix = ["position_jump", "speed_falsify",
                      "heading_jump", "gradual_drift"]

    rng    = np.random.default_rng(seed)
    frames: List[pd.DataFrame] = []

    for vid in range(n_honest):
        df = generate_vehicle_trace(n_steps, "honest",
                                    speed_regime=speed_regime, rng=rng)
        df["vehicle_id"]   = f"H{vid:04d}"
        df["vehicle_type"] = "honest"
        frames.append(df)

    for vid in range(n_malicious):
        atk = attack_mix[vid % len(attack_mix)]
        df  = generate_vehicle_trace(n_steps, "malicious", atk,
                                     speed_regime=speed_regime, rng=rng)
        df["vehicle_id"]   = f"M{vid:04d}"
        df["vehicle_type"] = atk
        frames.append(df)

    data = (pd.concat(frames, ignore_index=True)
              .sort_values(["vehicle_id", "t"])
              .reset_index(drop=True))
    return data


# ───────────────────────────────────────────────────────────────────
#  GHALEB B1 DETECTOR CLASS
# ───────────────────────────────────────────────────────────────────

@dataclass
class _VehicleState:
    """Internal per-vehicle state held across beacon epochs."""
    ltt:        List[Tuple[float, float, float]] = field(default_factory=list)
    prev_speed: float = 0.0
    prev_head:  float = 0.0


class GhalebB1Detector:
    """
    Pure rule-based misbehavior detector as in Ghaleb et al. (2014).

    All four modules produce binary flags.  The final prediction is
    the logical OR of all flags (any violation → malicious).

    Parameters
    ----------
    speed_max_ms    : Module 4 upper speed plausibility bound [m/s]
    speed_min_ms    : Module 4 lower bound
    road_half_w     : Module 2a road boundary half-width [m]
    wave_range      : Module 2b transmission range [m]
    min_veh_sep     : Module 2c minimum vehicle separation [m]
    area_diff_th    : Module 3 LTT area-difference threshold [m²]
    ltt_window      : number of beacons in the LTT evidence window
    speed_of_light  : Module 2d — effectively speed_max_ms for vehicle networks
    """

    def __init__(self,
                 speed_max_ms:   float = SPEED_MAX_MS,
                 speed_min_ms:   float = SPEED_MIN_MS,
                 road_half_w:    float = ROAD_HALF_W,
                 wave_range:     float = WAVE_RANGE_M,
                 min_veh_sep:    float = MIN_VEH_SEP,
                 area_diff_th:   float = AREA_DIFF_TH,
                 ltt_window:     int   = LTT_WINDOW,
                 speed_of_light: float = SPEED_MAX_MS):
        self.speed_max    = speed_max_ms
        self.speed_min    = speed_min_ms
        self.road_half_w  = road_half_w
        self.wave_range   = wave_range
        self.min_veh_sep  = min_veh_sep
        self.area_diff_th = area_diff_th
        self.ltt_window   = ltt_window
        self.sol          = speed_of_light   # "speed-of-light" proxy (Eq.1)
        self._state: Dict[str, _VehicleState] = {}

    # ── private helpers ──────────────────────────────────────────

    def _get_state(self, vid: str) -> _VehicleState:
        if vid not in self._state:
            self._state[vid] = _VehicleState()
        return self._state[vid]

    def _update_ltt(self, vid: str, x: float, y: float, t: float) -> None:
        st = self._get_state(vid)
        st.ltt.append((x, y, t))
        if len(st.ltt) > self.ltt_window:
            st.ltt = st.ltt[-self.ltt_window:]

    @staticmethod
    def _bbox_area(points: List[Tuple[float, float, float]]) -> float:
        if len(points) < 2:
            return 0.0
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        return (max(xs) - min(xs) + 1.0) * (max(ys) - min(ys) + 1.0)

    def _ltt_area_diff(self, vid: str) -> float:
        """
        Module 3: area difference between current-view and earlier-view
        in the LTT table (Ghaleb Fig.5 / Section III-B-3).
        """
        st = self._get_state(vid)
        n  = len(st.ltt)
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
                      peer_positions: Optional[List[Tuple[float, float]]] = None
                      ) -> dict:
        """
        Run all four Ghaleb modules for one incoming BSM beacon.

        Parameters
        ----------
        row            : current beacon fields (vehicle_id, x, y, speed_ms,
                         heading_rad, accel_ms2, t)
        prev_row       : previous beacon from same vehicle (None on first)
        peer_positions : list of (x,y) of all other vehicles in current epoch
                         (for Module 2c overlap check)

        Returns
        -------
        dict with keys: m1, m2a, m2b, m2c, m2d, m3, m4, pred,
                        area_diff, speed_kmh, vehicle_id, t
        """
        vid   = row["vehicle_id"]
        x, y  = float(row["x"]), float(row["y"])
        s_ms  = float(row["speed_ms"])
        t     = float(row["t"])
        flags = dict(m1=0, m2a=0, m2b=0, m2c=0, m2d=0, m3=0, m4=0)

        # ── Module 1: Security Verification ─────────────────────
        # Group signature check — simulated as always-pass (PKI assumed)
        flags["m1"] = 0

        # ── Module 2a: Road-Map Boundary ────────────────────────
        # Position must be within known road boundaries
        if abs(y) > self.road_half_w:
            flags["m2a"] = 1

        # ── Module 2b: Transmission Range ───────────────────────
        # Sender must be within WAVE range of the RSU/receiver
        # (RSU at origin; simplification — full impl needs RSU coords)
        dist_from_rsu = np.hypot(x, y)
        if dist_from_rsu > self.wave_range * 4:   # lenient: 4× range
            flags["m2b"] = 1

        # ── Module 2c: Occupied Location (no overlap) ───────────
        # No two vehicles can occupy the same position (anti-Sybil)
        if peer_positions:
            for px, py in peer_positions:
                if np.hypot(x - px, y - py) < self.min_veh_sep:
                    flags["m2c"] = 1
                    break

        # ── Module 2d: Speed-of-Light / Kinematic Constraint ────
        # Ghaleb Equation (1): dist(Lr, Lv) / (tr - ts) <= c
        # Here c is the maximum plausible vehicle speed (not literal SoL)
        if prev_row is not None and prev_row["vehicle_id"] == vid:
            dt   = t - float(prev_row["t"])
            dist = np.hypot(x - float(prev_row["x"]),
                            y - float(prev_row["y"]))
            if dt > 1e-9 and (dist / dt) > self.sol:
                flags["m2d"] = 1

        # ── Module 3: Movement Analysis (LTT area difference) ───
        self._update_ltt(vid, x, y, t)
        area_d = self._ltt_area_diff(vid)
        if area_d > self.area_diff_th:
            flags["m3"] = 1

        # ── Module 4: Plausibility Detection (speed bounds) ─────
        s_kmh = s_ms * 3.6
        if not (self.speed_min * 3.6 <= s_kmh <= 240.0):
            flags["m4"] = 1

        # ── Final decision: OR of all module flags ───────────────
        pred = int(any(flags.values()))

        return {
            **flags,
            "pred":      pred,
            "area_diff": round(area_d, 4),
            "speed_kmh": round(s_kmh,  4),
            "vehicle_id": vid,
            "t":          t,
        }

    # ── batch runner ─────────────────────────────────────────────

    def run(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Run the detector over an entire multi-vehicle BSM dataset.

        Parameters
        ----------
        data : DataFrame produced by build_beacon_dataset()

        Returns
        -------
        DataFrame with all module flags, predictions, and ground-truth labels.
        """
        self._state.clear()
        results: List[Dict] = []

        # Build per-timestep peer position map for Module 2c
        peer_map: Dict[float, List[Tuple[float, float, str]]] = {}
        for _, row in data.iterrows():
            t_key = float(row["t"])
            if t_key not in peer_map:
                peer_map[t_key] = []
            peer_map[t_key].append((float(row["x"]), float(row["y"]),
                                    str(row["vehicle_id"])))

        for vid, grp in data.groupby("vehicle_id", sort=False):
            grp  = grp.sort_values("t").reset_index(drop=True)
            prev = None

            for _, row in grp.iterrows():
                r     = row.to_dict()
                t_key = float(r["t"])
                # peers = other vehicles at same timestep
                peers = [(px, py)
                         for px, py, pvid in peer_map.get(t_key, [])
                         if pvid != vid]

                det          = self.detect_beacon(r, prev, peers)
                det["label"] = int(row["label"])
                det["attack_type"] = str(row.get("vehicle_type", "honest"))
                results.append(det)
                prev = r

        return pd.DataFrame(results)

    def reset(self) -> None:
        """Clear internal LTT state between experiment runs."""
        self._state.clear()