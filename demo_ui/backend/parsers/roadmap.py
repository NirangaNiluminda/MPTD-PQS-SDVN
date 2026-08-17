"""Extract drawable road geometry from a SUMO .net.xml.

WHY THIS WORKS (verified, not assumed): the mobility traces and the SUMO
network share one coordinate frame. urban.net.xml declares

    convBoundary="664.17,508.21,2663.34,2494.55"

and the parsed mobility_urban_60.tcl extent is x[710.68, 2654.81]
y[606.33, 2326.87] — strictly inside it. So lane shapes can be drawn in the
same plane as vehicle positions with NO transform, and vehicles land on the
roads rather than beside them.

(origBoundary="139.687,35.681,139.724,35.708" is the real-world footprint —
Shinjuku, Tokyo — but we deliberately stay in SUMO-local metres because that
is the frame the simulator, the RSU CSVs and the traces all speak.)

What we emit:
  * roads     — one polyline per non-internal lane, plus its width
  * junctions — the polygon SUMO computes for each real intersection

Internal edges (function="internal") are the little connector stubs *inside*
junctions; 7778 of the 16733 lanes in the urban net are internal. They are
skipped because the junction polygons already fill that area — drawing both
doubles the geometry for no visual gain.

Parsing 9.5 MB of XML takes a moment, so the result is cached to JSON next to
the .net.xml and reused until the source file is newer.
"""

import json
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

# Lanes SUMO builds for non-car modes clutter the picture without adding
# meaning for a vehicular-network demo.
_SKIP_LANE_TYPES = {"highway.footway", "highway.path", "highway.steps",
                    "highway.pedestrian", "highway.cycleway", "highway.bridleway"}

# Coordinates rounded to 0.1 m — far finer than a screen pixel at any usable
# zoom, and it roughly halves the JSON the laptop has to pull over the tunnel.
_ND = 1


@dataclass
class RoadMap:
    roads: list[dict]
    junctions: list[list[list[float]]]
    bounds: dict[str, float]


def _parse_shape(shape: str) -> list[list[float]]:
    pts = []
    for pair in shape.split():
        x, _, y = pair.partition(",")
        try:
            pts.append([round(float(x), _ND), round(float(y), _ND)])
        except ValueError:
            continue
    return pts


def parse_net(net_path: str | Path) -> RoadMap:
    roads: list[dict] = []
    junctions: list[list[list[float]]] = []

    # iterparse + clear() keeps peak memory flat on a 9.5 MB net.
    context = ET.iterparse(str(net_path), events=("end",))
    for _, elem in context:
        if elem.tag == "edge":
            if elem.get("function") == "internal":
                elem.clear()
                continue
            etype = elem.get("type") or ""
            if etype in _SKIP_LANE_TYPES:
                elem.clear()
                continue
            for lane in elem.findall("lane"):
                shape = lane.get("shape")
                if not shape:
                    continue
                pts = _parse_shape(shape)
                if len(pts) >= 2:
                    roads.append(
                        {
                            "p": pts,
                            "w": round(float(lane.get("width") or 3.2), 1),
                        }
                    )
            elem.clear()
        elif elem.tag == "junction":
            # "internal" junctions are bookkeeping nodes with no real footprint.
            if elem.get("type") == "internal":
                elem.clear()
                continue
            shape = elem.get("shape")
            if shape:
                pts = _parse_shape(shape)
                if len(pts) >= 3:
                    junctions.append(pts)
            elem.clear()

    xs = [p[0] for r in roads for p in r["p"]]
    ys = [p[1] for r in roads for p in r["p"]]
    bounds = (
        {"x_min": min(xs), "x_max": max(xs), "y_min": min(ys), "y_max": max(ys)}
        if xs
        else {"x_min": 0, "x_max": 0, "y_min": 0, "y_max": 0}
    )
    return RoadMap(roads=roads, junctions=junctions, bounds=bounds)


@dataclass
class TrafficSignal:
    id: str
    x: float
    y: float
    phases: list[dict]  # [{"duration": float, "state": str}, ...]


def _junction_from_via(via: str) -> str:
    """':<junction_id>_<linkIndex>_<pathIndex>' -> junction_id.

    A joined/clustered traffic light (netconvert --tls.join) has no junction
    of its own — its tlLogic id names the cluster, not a point. Every
    <connection tl="..."> it governs names an internal lane in `via` that
    DOES start at that light's real junction, so stripping the trailing
    "_<linkIndex>_<pathIndex>" recovers it. Verified against this net: all
    20 joined tlLogic ids resolve this way, 0 left unresolved.
    """
    body = via[1:] if via.startswith(":") else via
    return body.rsplit("_", 2)[0]


def parse_traffic_signals(net_path: str | Path) -> list[TrafficSignal]:
    """Real, static (fixed-cycle) traffic-light programs from a SUMO net.

    "static" means the phase at time t is deterministic — t mod (sum of
    phase durations) — so the frontend can compute current signal state
    from this one-time payload without a live SUMO/TraCI connection.
    Actuated/other program types are skipped rather than guessed.
    """
    root = ET.parse(str(net_path)).getroot()
    junctions = {j.get("id"): j for j in root.findall("junction")}

    first_via_by_tl: dict[str, str] = {}
    for c in root.findall("connection"):
        tl = c.get("tl")
        if tl and tl not in first_via_by_tl and c.get("via"):
            first_via_by_tl[tl] = c.get("via")

    signals: list[TrafficSignal] = []
    for tl in root.findall("tlLogic"):
        if tl.get("type") != "static":
            continue
        tl_id = tl.get("id")
        j = junctions.get(tl_id)
        if j is None:
            via = first_via_by_tl.get(tl_id)
            j = junctions.get(_junction_from_via(via)) if via else None
        if j is None:
            continue  # unresolvable — skip rather than guess a position
        phases = [
            {"duration": float(p.get("duration")), "state": p.get("state")}
            for p in tl.findall("phase")
            if p.get("duration") and p.get("state")
        ]
        if not phases:
            continue
        signals.append(TrafficSignal(id=tl_id, x=float(j.get("x")), y=float(j.get("y")), phases=phases))
    return signals


def load_traffic_signals(net_path: str | Path, cache_dir: str | Path | None = None) -> list[dict]:
    """Parsed traffic signals as a JSON-ready list, cached beside the source net."""
    net_path = Path(net_path)
    cache = Path(cache_dir or net_path.parent) / f".{net_path.stem}.signals.json"

    if cache.is_file() and cache.stat().st_mtime >= net_path.stat().st_mtime:
        try:
            with open(cache) as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass

    signals = parse_traffic_signals(net_path)
    payload = [{"id": s.id, "x": s.x, "y": s.y, "phases": s.phases} for s in signals]
    try:
        tmp = cache.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            json.dump(payload, fh, separators=(",", ":"))
        os.replace(tmp, cache)
    except OSError:
        pass
    return payload


def load_roadmap(net_path: str | Path, cache_dir: str | Path | None = None) -> dict:
    """Parsed roadmap as a JSON-ready dict, cached beside the source net."""
    net_path = Path(net_path)
    cache = Path(cache_dir or net_path.parent) / f".{net_path.stem}.roadmap.json"

    if cache.is_file() and cache.stat().st_mtime >= net_path.stat().st_mtime:
        try:
            with open(cache) as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass  # regenerate below

    rm = parse_net(net_path)
    payload = {
        "roads": rm.roads,
        "junctions": rm.junctions,
        "bounds": rm.bounds,
        "source": net_path.name,
    }
    try:
        tmp = cache.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            json.dump(payload, fh, separators=(",", ":"))
        os.replace(tmp, cache)
    except OSError:
        pass  # cache is an optimisation, not a requirement
    return payload
