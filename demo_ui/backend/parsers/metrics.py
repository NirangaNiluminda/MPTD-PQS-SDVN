"""Parse [METRICS] stdout lines — real per-vehicle position/kinematics.

Unlike [FUSION-RSU*] (fusion.py), which only carries the final scalar scores,
these lines are printed once per vehicle per RSU-processed beacon and carry
the actual ground-truth-adjacent position — the ingredient needed for a
real (not fabricated) spatial "who's nearby" view for this capture, since
the capture log has no per-neighbour GAT attention re-inference available.

Example lines:
  [METRICS] TP attack=0 vehicle=45 rsu=35 pos_x=1609.2 pos_y=1543.3 speed=0.0 heading=0.0 accel=0.0 t=7.0 sig=
  [METRICS] TN attack=0 vehicle=126 rsu=11 pos_x=1510.111 pos_y=749.528 speed=13.600 heading=1.794 accel=0.000 t=7.060

`sig=` is only ever present on TP-classified lines (signature bits are moot
for a true negative) — trailing group is optional, defaults to "".
"""

import re
from dataclasses import dataclass
from typing import Iterator, TextIO

_LINE_RE = re.compile(
    r"^\[METRICS\]\s+(?P<cls>TP|TN|FP|FN)\s+"
    r"attack=(?P<attack>-?\d+)\s+"
    r"vehicle=(?P<vehicle>\d+)\s+"
    r"rsu=(?P<rsu>\d+)\s+"
    r"pos_x=(?P<pos_x>-?[\d.]+)\s+"
    r"pos_y=(?P<pos_y>-?[\d.]+)\s+"
    r"speed=(?P<speed>-?[\d.]+)\s+"
    r"heading=(?P<heading>-?[\d.]+)\s+"
    r"accel=(?P<accel>-?[\d.]+)\s+"
    r"t=(?P<t>[\d.]+)"
    r"(?:\s+sig=(?P<sig>\S*))?"
)


@dataclass
class MetricsSample:
    cls: str  # TP | TN | FP | FN — the run's own confusion-matrix classification
    attack: int
    vehicle: int
    rsu: int
    pos_x: float
    pos_y: float
    speed: float
    heading: float
    accel: float
    t: float
    sig: str


def parse_line(line: str) -> MetricsSample | None:
    m = _LINE_RE.search(line)
    if not m:
        return None
    g = m.groupdict()
    return MetricsSample(
        cls=g["cls"],
        attack=int(g["attack"]),
        vehicle=int(g["vehicle"]),
        rsu=int(g["rsu"]),
        pos_x=float(g["pos_x"]),
        pos_y=float(g["pos_y"]),
        speed=float(g["speed"]),
        heading=float(g["heading"]),
        accel=float(g["accel"]),
        t=float(g["t"]),
        sig=g["sig"] or "",
    )


def iter_samples(fh: TextIO) -> Iterator[MetricsSample]:
    for line in fh:
        s = parse_line(line)
        if s is not None:
            yield s
