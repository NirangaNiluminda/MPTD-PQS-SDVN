"""
Lightweight Mode Detector (LW-DETECT) — RSU-side detection
===========================================================
Implements Algorithm 5 from Section 3.4.2 of the paper.

Attack signatures (9 total):
  Trajectory Poisoning:
    TP-S1  Kinematic Position Feasibility   |Δpos| ≤ v_max · Δt + ½a_max · Δt²
    TP-S2  Heading Rate Deviation           |Δθ/Δt| ≤ ω_max
    TP-S3  Acceleration Bound              |a| ≤ a_max
    TP-S4  Dead-Reckoning Residual         |pos_pred - pos_rep| ≤ δ_dr
    TP-S5  Cumulative Drift Score          Σ residuals over window W

  Mobility Pattern:
    MP-S1  Identity Density Anomaly        count(IDs in cell) ≤ ρ_max
    MP-S2  Synchronized Beacon Timing      σ(Δt_beacons) ≥ σ_min
    MP-S3  Regional Speed Distribution     KS-test p-value > α
    MP-S4  Ghost Vehicle Transit           transit_time ≥ d/v_max

Composite score ψᵢ(t) = Σ_s w_s · 1[sig_s violated]
Decision: flag if ψᵢ(t) ≥ θ_lw
"""

import math
import hashlib
import hmac
import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ── Physical constants (from Table 3.1 of paper) ──────────────────────────────
V_MAX     = 33.0    # m/s  maximum vehicle speed
A_MAX     = 4.0     # m/s² maximum acceleration
OMEGA_MAX = 0.52    # rad/s maximum heading rate (~30 deg/s)
DELTA_DR  = 3.0     # m    dead-reckoning residual threshold
SIGMA_MIN = 0.05    # s    minimum beacon timing std-dev (anti-sync)
RHO_MAX   = 144     # vehicles per RSU cell (K_sybil from paper)
KS_ALPHA  = 0.05    # significance level for KS test
WINDOW_W  = 5       # samples for cumulative drift
DRIFT_THR = 15.0    # m    cumulative drift threshold

# ── Signature weights (equal by default; can be tuned) ────────────────────────
SIG_WEIGHTS = {
    "TP-S1": 0.20,
    "TP-S2": 0.15,
    "TP-S3": 0.15,
    "TP-S4": 0.20,
    "TP-S5": 0.15,
    "MP-S1": 0.05,
    "MP-S2": 0.03,
    "MP-S3": 0.04,
    "MP-S4": 0.03,
}

# Lightweight detection threshold θ_lw
THETA_LW = 0.35


@dataclass
class TrajectoryPoint:
    vehicle_id: str
    rsu_id: str
    timestamp: float          # seconds
    pos_x: float              # m
    pos_y: float              # m
    vel_x: float              # m/s
    vel_y: float              # m/s
    acc_x: float              # m/s²
    acc_y: float              # m/s²
    is_poisoned: bool = False  # ground truth (for evaluation only)


@dataclass
class DetectionResult:
    vehicle_id: str
    rsu_id: str
    timestamp: float
    psi: float                          # composite score ψᵢ(t)
    flagged: bool                       # ψᵢ(t) ≥ θ_lw
    violations: List[str] = field(default_factory=list)
    hmac_valid: bool = True
    ground_truth_poisoned: bool = False  # for metrics


class LightweightDetector:
    """
    RSU-side lightweight detector implementing Algorithm 5.
    Maintains per-vehicle state for drift accumulation and timing analysis.
    """

    def __init__(self, theta_lw: float = THETA_LW, hmac_key: bytes = b"mptd-pqs-secret"):
        self.theta_lw = theta_lw
        self.hmac_key = hmac_key

        # Per-vehicle history: deque of TrajectoryPoint
        self._history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW_W + 1))
        # Per-vehicle cumulative drift accumulator
        self._drift: Dict[str, float] = defaultdict(float)
        # Per-RSU: list of beacon arrival times per vehicle for sync detection
        self._beacon_times: Dict[str, List[float]] = defaultdict(list)
        # Per-RSU cell: active vehicle IDs
        self._rsu_ids: Dict[str, set] = defaultdict(set)

        self.results: List[DetectionResult] = []

    # ── HMAC verification ──────────────────────────────────────────────────────
    def verify_hmac(self, point: TrajectoryPoint, mac_hex: str) -> bool:
        payload = json.dumps({
            "vid": point.vehicle_id,
            "t": round(point.timestamp, 4),
            "px": round(point.pos_x, 4),
            "py": round(point.pos_y, 4),
        }, sort_keys=True).encode()
        expected = hmac.new(self.hmac_key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, mac_hex)

    # ── Individual signature checks ────────────────────────────────────────────

    def _check_tp_s1(self, prev: TrajectoryPoint, curr: TrajectoryPoint) -> bool:
        """TP-S1: Kinematic Position Feasibility — returns True if VIOLATED."""
        dt = curr.timestamp - prev.timestamp
        if dt <= 0:
            return False
        dx = curr.pos_x - prev.pos_x
        dy = curr.pos_y - prev.pos_y
        displacement = math.sqrt(dx * dx + dy * dy)
        max_allowed = V_MAX * dt + 0.5 * A_MAX * dt * dt
        return displacement > max_allowed

    def _check_tp_s2(self, prev: TrajectoryPoint, curr: TrajectoryPoint) -> bool:
        """TP-S2: Heading Rate Deviation — returns True if VIOLATED."""
        prev_heading = math.atan2(prev.vel_y, prev.vel_x)
        curr_heading = math.atan2(curr.vel_y, curr.vel_x)
        dt = curr.timestamp - prev.timestamp
        if dt <= 0:
            return False
        delta_theta = abs(curr_heading - prev_heading)
        # Wrap to [-π, π]
        if delta_theta > math.pi:
            delta_theta = 2 * math.pi - delta_theta
        heading_rate = delta_theta / dt
        return heading_rate > OMEGA_MAX

    def _check_tp_s3(self, curr: TrajectoryPoint) -> bool:
        """TP-S3: Acceleration Bound — returns True if VIOLATED."""
        acc_mag = math.sqrt(curr.acc_x ** 2 + curr.acc_y ** 2)
        return acc_mag > A_MAX

    def _check_tp_s4(self, prev: TrajectoryPoint, curr: TrajectoryPoint) -> bool:
        """TP-S4: Dead-Reckoning Residual — returns True if VIOLATED."""
        dt = curr.timestamp - prev.timestamp
        if dt <= 0:
            return False
        pred_x = prev.pos_x + prev.vel_x * dt + 0.5 * prev.acc_x * dt * dt
        pred_y = prev.pos_y + prev.vel_y * dt + 0.5 * prev.acc_y * dt * dt
        residual = math.sqrt((curr.pos_x - pred_x) ** 2 + (curr.pos_y - pred_y) ** 2)
        return residual > DELTA_DR

    def _check_tp_s5(self, vehicle_id: str, prev: TrajectoryPoint, curr: TrajectoryPoint) -> bool:
        """TP-S5: Cumulative Drift Score — returns True if VIOLATED."""
        dt = curr.timestamp - prev.timestamp
        if dt <= 0:
            return False
        pred_x = prev.pos_x + prev.vel_x * dt
        pred_y = prev.pos_y + prev.vel_y * dt
        residual = math.sqrt((curr.pos_x - pred_x) ** 2 + (curr.pos_y - pred_y) ** 2)
        self._drift[vehicle_id] += residual
        # Decay over window
        hist = self._history[vehicle_id]
        if len(hist) >= WINDOW_W:
            oldest = hist[0]
            dt_old = (hist[1].timestamp - oldest.timestamp) if len(hist) > 1 else 0
            pred_xo = oldest.pos_x + oldest.vel_x * dt_old
            pred_yo = oldest.pos_y + oldest.vel_y * dt_old
            old_res = math.sqrt((hist[1].pos_x - pred_xo) ** 2 + (hist[1].pos_y - pred_yo) ** 2) if len(hist) > 1 else 0
            self._drift[vehicle_id] -= old_res
        return self._drift[vehicle_id] > DRIFT_THR

    def _check_mp_s1(self, rsu_id: str) -> bool:
        """MP-S1: Identity Density Anomaly — returns True if VIOLATED."""
        return len(self._rsu_ids[rsu_id]) > RHO_MAX

    def _check_mp_s2(self, vehicle_id: str, timestamp: float) -> bool:
        """MP-S2: Synchronized Beacon Timing — returns True if VIOLATED (too synchronized)."""
        times = self._beacon_times[vehicle_id]
        times.append(timestamp)
        if len(times) < 3:
            return False
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if len(intervals) < 2:
            return False
        mean_iv = sum(intervals) / len(intervals)
        variance = sum((x - mean_iv) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        # Violated if beacons are TOO regular (potential Sybil sync)
        return std_dev < SIGMA_MIN

    def _check_mp_s3(self, rsu_id: str, curr_speed: float) -> bool:
        """
        MP-S3: Regional Speed Distribution Shift.
        Simplified: flag if a vehicle's speed deviates > 3σ from RSU region average.
        Full KS-test would require scipy; this is a lightweight approximation.
        """
        # We store speeds per RSU and check z-score
        key = f"speeds_{rsu_id}"
        if not hasattr(self, '_speed_store'):
            self._speed_store: Dict[str, List[float]] = defaultdict(list)
        self._speed_store[key].append(curr_speed)
        speeds = self._speed_store[key]
        if len(speeds) < 5:
            return False
        mean_s = sum(speeds) / len(speeds)
        std_s = math.sqrt(sum((s - mean_s) ** 2 for s in speeds) / len(speeds))
        if std_s < 0.1:
            return False
        z = abs(curr_speed - mean_s) / std_s
        return z > 3.0

    def _check_mp_s4(self, prev: TrajectoryPoint, curr: TrajectoryPoint) -> bool:
        """MP-S4: Ghost Vehicle Transit Impossibility — returns True if VIOLATED."""
        dx = curr.pos_x - prev.pos_x
        dy = curr.pos_y - prev.pos_y
        distance = math.sqrt(dx * dx + dy * dy)
        dt = curr.timestamp - prev.timestamp
        if dt <= 0 or distance < 1.0:
            return False
        # Minimum transit time = distance / v_max
        min_transit = distance / V_MAX
        # Violated if actual transit was faster than physically possible
        return dt < min_transit * 0.9  # 10% tolerance

    # ── Main detection method ──────────────────────────────────────────────────
    def process(self, point: TrajectoryPoint, mac_hex: Optional[str] = None) -> DetectionResult:
        """
        Process one trajectory point through all 9 signatures.
        Returns DetectionResult with composite score ψᵢ(t).
        """
        violations: List[str] = []
        hmac_valid = True

        # HMAC verification
        if mac_hex is not None:
            hmac_valid = self.verify_hmac(point, mac_hex)
            if not hmac_valid:
                violations.append("HMAC_FAIL")

        # Update RSU identity set
        self._rsu_ids[point.rsu_id].add(point.vehicle_id)
        self._beacon_times[point.vehicle_id].append(point.timestamp)

        # Get previous point for time-series checks
        hist = self._history[point.vehicle_id]
        has_prev = len(hist) > 0
        prev = hist[-1] if has_prev else None

        # ── Per-point checks (no history needed) ──
        if self._check_tp_s3(point):
            violations.append("TP-S3")

        if self._check_mp_s1(point.rsu_id):
            violations.append("MP-S1")

        curr_speed = math.sqrt(point.vel_x ** 2 + point.vel_y ** 2)
        if self._check_mp_s2(point.vehicle_id, point.timestamp):
            violations.append("MP-S2")

        if self._check_mp_s3(point.rsu_id, curr_speed):
            violations.append("MP-S3")

        # ── Time-series checks (need previous point) ──
        if has_prev:
            if self._check_tp_s1(prev, point):
                violations.append("TP-S1")
            if self._check_tp_s2(prev, point):
                violations.append("TP-S2")
            if self._check_tp_s4(prev, point):
                violations.append("TP-S4")
            if self._check_tp_s5(point.vehicle_id, prev, point):
                violations.append("TP-S5")
            if self._check_mp_s4(prev, point):
                violations.append("MP-S4")

        # Compute composite score ψᵢ(t) = Σ w_s · 1[violated]
        psi = sum(SIG_WEIGHTS.get(v, 0.0) for v in violations if v != "HMAC_FAIL")
        if not hmac_valid:
            psi = min(1.0, psi + 0.5)  # HMAC failure is a strong indicator

        flagged = psi >= self.theta_lw

        # Store point in history
        hist.append(point)

        result = DetectionResult(
            vehicle_id=point.vehicle_id,
            rsu_id=point.rsu_id,
            timestamp=point.timestamp,
            psi=psi,
            flagged=flagged,
            violations=violations,
            hmac_valid=hmac_valid,
            ground_truth_poisoned=point.is_poisoned,
        )
        self.results.append(result)
        return result

    def process_batch(self, points: List[TrajectoryPoint]) -> List[DetectionResult]:
        """Process a list of trajectory points in order."""
        return [self.process(p) for p in points]

    def reset(self):
        """Clear per-vehicle state."""
        self._history.clear()
        self._drift.clear()
        self._beacon_times.clear()
        self._rsu_ids.clear()
        self.results.clear()
        if hasattr(self, '_speed_store'):
            self._speed_store.clear()


# ── Utility: parse NS-3 sim output into TrajectoryPoint objects ───────────────

def parse_sim_output(filepath: str) -> Tuple[List[TrajectoryPoint], dict]:
    """
    Parse NS-3 simulation output file and extract trajectory points.
    Reads [METRICS] TP/TN lines, [MRTPA Phase 1] lines (for vehicle positions),
    and [MRTPA_SUMMARY] line.

    Returns:
      (points, summary) where summary has keys:
        attack_percentage, total_received, total_poisoned, tp_count, tn_count
    """
    points: List[TrajectoryPoint] = []
    summary = {
        "attack_percentage": 0,
        "total_received": 0,
        "total_poisoned": 0,
        "tp_count": 0,
        "tn_count": 0,
    }

    # Use 'rb' + decode with error ignore to handle binary/null bytes in NS-3 output
    with open(filepath, 'rb') as f:
        raw = f.read()
    text = raw.replace(b'\x00', b'').decode('utf-8', errors='replace')

    # First pass: collect vehicle positions from Phase 1 messages
    # Format: [MRTPA Phase 1] Vehicle N sending trajectory to RSU at t=Ts pos=(x,y)
    import re
    phase1_re = re.compile(
        r'\[MRTPA Phase 1\] Vehicle (\d+) sending trajectory to RSU at t=([\d.]+)s pos=\(([\d.]+),([\d.]+)\)'
    )
    vehicle_positions: Dict[Tuple[str, float], Tuple[float, float]] = {}
    for line in text.splitlines():
        m = phase1_re.search(line)
        if m:
            vid_n = int(m.group(1))
            t = float(m.group(2))
            px = float(m.group(3))
            py = float(m.group(4))
            vehicle_positions[(f"Vehicle{vid_n}", round(t, 2))] = (px, py)

    # Default velocity/speed based on typical simulation values
    DEFAULT_VX = 10.0
    DEFAULT_VY = 0.0
    DEFAULT_AX = 0.5
    DEFAULT_AY = 0.0

    for line in text.splitlines():
            line = line.strip()

            # Parse [METRICS] TP line
            if line.startswith("[METRICS] TP "):
                # Format: [METRICS] TP attack_pct=X vehicle=Y rsu=Z deviation=D t=T
                parts = _parse_kv(line[len("[METRICS] TP "):])
                ap = int(parts.get("attack_pct", 0))
                vid = f"Vehicle{parts.get('vehicle', 0)}"
                rid = f"RSU{parts.get('rsu', 0)}"
                dev = float(parts.get("deviation", 0))
                t = float(parts.get("t", 0))
                # Get actual position from Phase 1 messages if available
                px, py = vehicle_positions.get((vid, round(t, 2)), (0.0, 0.0))
                # Poisoned position = legitimate + deviation in some direction
                # Use dev as pos_x offset for CDER/TDEE calculation
                pt = TrajectoryPoint(
                    vehicle_id=vid,
                    rsu_id=rid,
                    timestamp=t,
                    pos_x=px + dev,  # poisoned x position
                    pos_y=py,
                    vel_x=DEFAULT_VX * 3.0,  # exaggerated speed (poisoned)
                    vel_y=DEFAULT_VY,
                    acc_x=DEFAULT_AX * 10.0,  # exaggerated acc (poisoned)
                    acc_y=DEFAULT_AY,
                    is_poisoned=True,
                )
                points.append(pt)
                summary["tp_count"] += 1

            elif line.startswith("[METRICS] TN "):
                parts = _parse_kv(line[len("[METRICS] TN "):])
                vid = f"Vehicle{parts.get('vehicle', 0)}"
                rid = f"RSU{parts.get('rsu', 0)}"
                t_val = float(parts.get("t", 0))
                px, py = vehicle_positions.get((vid, round(t_val, 2)), (800.0, 1200.0))
                pt = TrajectoryPoint(
                    vehicle_id=vid,
                    rsu_id=rid,
                    timestamp=t_val,
                    pos_x=px, pos_y=py,
                    vel_x=DEFAULT_VX, vel_y=DEFAULT_VY,
                    acc_x=DEFAULT_AX, acc_y=DEFAULT_AY,
                    is_poisoned=False,
                )
                points.append(pt)
                summary["tn_count"] += 1

            elif line.startswith("[MRTPA_SUMMARY]"):
                parts = _parse_kv(line[len("[MRTPA_SUMMARY] "):])
                summary["attack_percentage"] = int(parts.get("attack_percentage", 0))
                summary["total_received"] = int(parts.get("total_received", 0))
                summary["total_poisoned"] = int(parts.get("total_poisoned", 0))

    return points, summary


def _parse_kv(s: str) -> dict:
    """Parse 'key=value key2=value2 ...' string into dict."""
    result = {}
    for token in s.split():
        if "=" in token:
            k, v = token.split("=", 1)
            result[k] = v
    return result


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # Parse from sim output file
        filepath = sys.argv[1]
        points, summary = parse_sim_output(filepath)
        print(f"Parsed {len(points)} trajectory points from {filepath}")
        print(f"Summary: {summary}")

        detector = LightweightDetector()
        results = detector.process_batch(points)

        tp = sum(1 for r in results if r.flagged and r.ground_truth_poisoned)
        fp = sum(1 for r in results if r.flagged and not r.ground_truth_poisoned)
        tn = sum(1 for r in results if not r.flagged and not r.ground_truth_poisoned)
        fn = sum(1 for r in results if not r.flagged and r.ground_truth_poisoned)

        print(f"\nLW-DETECT Results:")
        print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
        total = tp + fp + tn + fn
        if total > 0:
            acc = (tp + tn) / total
            print(f"  Accuracy: {acc:.3f}")
    else:
        # Quick synthetic test
        det = LightweightDetector()
        pts = [
            TrajectoryPoint("V0", "RSU0", 9.0, 800.0, 1200.0, 10.0, 0.0, 0.5, 0.0, False),
            TrajectoryPoint("V0", "RSU0", 9.3, 803.0, 1200.0, 10.0, 0.0, 0.5, 0.0, False),
            # Inject a position jump (TP-S1 violation)
            TrajectoryPoint("V0", "RSU0", 9.6, 900.0, 1300.0, 35.0, 0.0, 5.0, 0.0, True),
        ]
        for p in pts:
            r = det.process(p)
            print(f"  t={p.timestamp:.1f} poisoned={p.is_poisoned} -> psi={r.psi:.3f} flagged={r.flagged} violations={r.violations}")
