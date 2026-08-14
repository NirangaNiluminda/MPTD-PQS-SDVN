"""Map geometry: RSU positions and vehicle mobility traces.

RSU positions: mobility/rsu_positions_<scenario>.csv, header "rsu_id,x,y".
64 RSUs for urban (mobility/rsu_positions_urban.csv).

Mobility trace: mobility/mobility_<scenario>_<speed>.tcl, ns-2 format.
One waypoint per node per second:
  $ns_ at <t> "$node_(<id>) setdest <x> <y> <speed>"
Confirmed against mobility_urban_60.tcl: 200 nodes x 291 waypoints
(0..290s, "290s dwell" per commit b91c7c1) = 58200 setdest lines, matching
`grep -c setdest` exactly.

R_max_comm = 270.0 m is the DSRC communication range used for RSU coverage
circles (02_config_globals.h:641).
"""

import csv
import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

R_MAX_COMM = 270.0

_SETDEST_RE = re.compile(
    r'\$ns_ at (?P<t>[\d.]+) "\$node_\((?P<nid>\d+)\) '
    r'setdest (?P<x>-?[\d.]+) (?P<y>-?[\d.]+) (?P<speed>-?[\d.]+)"'
)


@dataclass(frozen=True)
class RsuPosition:
    rsu_id: int
    x: float
    y: float


@dataclass(frozen=True)
class Waypoint:
    t: float
    x: float
    y: float
    speed: float


def load_rsu_positions(path: str | Path) -> list[RsuPosition]:
    with open(path, newline="") as fh:
        return [
            RsuPosition(int(row["rsu_id"]), float(row["x"]), float(row["y"]))
            for row in csv.DictReader(fh)
        ]


def load_mobility_trace(path: str | Path) -> dict[int, list[Waypoint]]:
    """Parse an ns-2 .tcl trace into per-node waypoint lists, time-sorted."""
    trace: dict[int, list[Waypoint]] = {}
    with open(path) as fh:
        for line in fh:
            m = _SETDEST_RE.search(line)
            if not m:
                continue
            nid = int(m.group("nid"))
            wp = Waypoint(
                t=float(m.group("t")),
                x=float(m.group("x")),
                y=float(m.group("y")),
                speed=float(m.group("speed")),
            )
            trace.setdefault(nid, []).append(wp)
    for wps in trace.values():
        wps.sort(key=lambda w: w.t)
    return trace


def position_at(waypoints: list[Waypoint], t: float) -> Waypoint | None:
    """Most recent waypoint at or before t (matches the sim's step-hold model).

    Waypoints must already be time-sorted (as returned by load_mobility_trace).
    """
    if not waypoints:
        return None
    times = [w.t for w in waypoints]
    idx = bisect_right(times, t) - 1
    if idx < 0:
        return waypoints[0]
    return waypoints[idx]


# Headroom the simulator adds around the raw trace extent when deriving
# min/max_position_{x,y} — "never bind on sub-gate drift" (12_main.h:636-638).
MAP_BOUNDS_MARGIN = 100.0


def trace_bounds(trace: dict[int, list[Waypoint]], padded: bool = False) -> dict[str, float]:
    """Raw trace extent by default; pass padded=True to match the sim's own
    [MAP-BOUNDS] printed values (extent +/- MAP_BOUNDS_MARGIN on each side).

    Validated against a real run's startup log: raw extent
    x=[710.68, 2654.81] y=[606.33, 2326.87] -> padded (this sim's printed
    [MAP-BOUNDS]) x=[610.68, 2754.81] y=[506.33, 2426.87].
    """
    xs = [w.x for wps in trace.values() for w in wps]
    ys = [w.y for wps in trace.values() for w in wps]
    m = MAP_BOUNDS_MARGIN if padded else 0.0
    return {
        "x_min": min(xs) - m, "x_max": max(xs) + m,
        "y_min": min(ys) - m, "y_max": max(ys) + m,
    }
