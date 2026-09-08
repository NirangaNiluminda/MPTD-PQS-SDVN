"""Read beacon_log.csv into time-indexed frames for map replay.

Source of truth: scratch/mptd_pqs_sdvn/10_metrics_csv.h:185-187 (header) and
:1198-1247 (row writer). Written per-row with an open/close per write, so it
is safe to tail live as well as read as a finished file.

Columns:
  sim_time, vehicle_id, rsu_id, pos_x, pos_y, speed, heading, accel,
  is_poisoned, detected, sig_mask, psi_score, attack_number, attack_pct,
  attacker_class, gt_pos_x, gt_pos_y, gt_speed

TRAP (10_metrics_csv.h:1214-1220 comment): ghost identities (vehicle_id
>= GHOST_VID_BASE = 10000) have no backing ns-3 Node/MobilityModel. Their
gt_pos_*/gt_speed columns are copies of the reported pose, NOT real ground
truth — there is no "actual" position for a fabricated identity. The UI must
never draw a rubber-band line (claimed vs. actual) for a ghost; is_ghost must
be checked before any "claimed vs actual" visual is built.
"""

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, TextIO

GHOST_VID_BASE = 10000

# attacker_class values — VERBATIM from the AttackerClass enum at
# 02_config_globals.h:204-208. Do not reorder from memory: an earlier version
# of this file guessed 1=rsu/2=vehicle/3=controller and omitted MITM entirely,
# which mislabelled the attacker on every single attack type.
ATTACKER_NONE = 0
ATTACKER_MALICIOUS_VEHICLE = 1  # TP-S2 (a2), MP-S2 (a4)
ATTACKER_COMPROMISED_RSU = 2  # TP-S1 (a1), MP-S1 (a3)
ATTACKER_MITM = 3  # MP-S3 (a6)
ATTACKER_MALICIOUS_CONTROLLER = 4  # TP-S3 (a5), MP-S4 (a7)

ATTACKER_CLASS_LABELS = {
    ATTACKER_NONE: "none",
    ATTACKER_MALICIOUS_VEHICLE: "malicious_vehicle",
    ATTACKER_COMPROMISED_RSU: "compromised_rsu",
    ATTACKER_MITM: "mitm_relay",
    ATTACKER_MALICIOUS_CONTROLLER: "malicious_controller",
}

# Plain-language, for the non-technical audience.
ATTACKER_CLASS_PLAIN = {
    ATTACKER_NONE: "no attacker",
    ATTACKER_MALICIOUS_VEHICLE: "a lying vehicle",
    ATTACKER_COMPROMISED_RSU: "a hijacked roadside unit",
    ATTACKER_MITM: "an intercepting relay vehicle",
    ATTACKER_MALICIOUS_CONTROLLER: "a hijacked network controller",
}


@dataclass
class Beacon:
    sim_time: float
    vehicle_id: int
    rsu_id: int
    pos_x: float
    pos_y: float
    speed: float
    heading: float
    accel: float
    is_poisoned: bool
    detected: bool
    sig_mask: int
    psi_score: float
    attack_number: int
    attack_pct: int
    attacker_class: int
    gt_pos_x: float
    gt_pos_y: float
    gt_speed: float

    @property
    def is_ghost(self) -> bool:
        return self.vehicle_id >= GHOST_VID_BASE

    @property
    def has_ground_truth(self) -> bool:
        """False for ghosts — their gt_* columns are not real ground truth."""
        return not self.is_ghost

    @property
    def drift_m(self) -> float:
        """Euclidean distance between claimed and actual position.

        Meaningless for ghosts (see has_ground_truth); callers must check
        has_ground_truth before using this for a rubber-band visual.
        """
        return ((self.pos_x - self.gt_pos_x) ** 2 + (self.pos_y - self.gt_pos_y) ** 2) ** 0.5


def _row_to_beacon(row: dict) -> Beacon:
    return Beacon(
        sim_time=float(row["sim_time"]),
        vehicle_id=int(row["vehicle_id"]),
        rsu_id=int(row["rsu_id"]),
        pos_x=float(row["pos_x"]),
        pos_y=float(row["pos_y"]),
        speed=float(row["speed"]),
        heading=float(row["heading"]),
        accel=float(row["accel"]),
        is_poisoned=row["is_poisoned"] == "1",
        detected=row["detected"] == "1",
        sig_mask=int(row["sig_mask"]),
        psi_score=float(row["psi_score"]),
        attack_number=int(row["attack_number"]),
        attack_pct=int(row["attack_pct"]),
        attacker_class=int(row["attacker_class"]),
        gt_pos_x=float(row["gt_pos_x"]),
        gt_pos_y=float(row["gt_pos_y"]),
        gt_speed=float(row["gt_speed"]),
    )


def iter_beacons(fh: TextIO) -> Iterator[Beacon]:
    for row in csv.DictReader(fh):
        yield _row_to_beacon(row)


def load_beacons(path: str | Path) -> list[Beacon]:
    with open(path, newline="") as fh:
        return list(iter_beacons(fh))


def frames_by_time(beacons: list[Beacon], bucket_s: float = 0.1) -> dict[float, list[Beacon]]:
    """Group beacons into time buckets for scrubber-style replay.

    bucket_s should match the beacon rate (default 0.1s == the project's
    10 Hz data_transmission_frequency, 02_config_globals.h:158).
    """
    frames: dict[float, list[Beacon]] = {}
    for b in beacons:
        key = round(b.sim_time / bucket_s) * bucket_s
        frames.setdefault(key, []).append(b)
    return frames
