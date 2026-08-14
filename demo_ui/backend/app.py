"""FastAPI backend for the SENTINEL demo UI.

Serves the replay corpus (parsers/catalog.py) and the built frontend. Every
number returned here is read from a real file — see DEMO_UI_PLAN_2026-08-14.md
section 9 ("what this plan deliberately does not do"): no metric is
recomputed or smoothed here, only decoded/aggregated for display.
"""

from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

import config
from parsers import beacon as beacon_parser
from parsers import catalog
from parsers import geometry
from parsers import sigmask

app = FastAPI(title="SENTINEL Demo API")

# CORS open for local dev (Vite on :5173 talking to FastAPI on :8000).
# Tighten if this is ever exposed beyond an SSH tunnel / LAN demo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "corpus_root": str(config.CORPUS_ROOT),
        "corpus_exists": config.CORPUS_ROOT.is_dir(),
    }


# ── Scenario catalog ────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _scenarios() -> list[catalog.Scenario]:
    return catalog.scan_corpus(config.CORPUS_ROOT)


def _scenario_or_404(scenario_id: str) -> catalog.Scenario:
    for s in _scenarios():
        if s.id == scenario_id:
            return s
    raise HTTPException(404, f"scenario not found: {scenario_id}")


@app.get("/api/scenarios")
def list_scenarios():
    return [
        {
            "id": s.id,
            "road": s.road,
            "attack_number": s.attack_number,
            "attack_name": s.attack_name,
            "attack_pct": s.attack_pct,
        }
        for s in _scenarios()
    ]


# ── Beacon replay (map data) ────────────────────────────────────────────────

@lru_cache(maxsize=8)
def _beacons_for(scenario_id: str) -> tuple[beacon_parser.Beacon, ...]:
    s = _scenario_or_404(scenario_id)
    path = s.dir / "beacon_log.csv"
    if not path.is_file():
        raise HTTPException(404, f"beacon_log.csv missing for {scenario_id}")
    return tuple(beacon_parser.load_beacons(path))


def _beacon_to_dict(b: beacon_parser.Beacon) -> dict:
    accusations = [
        {"code": a.code, "name": a.name, "detail": a.detail, "weight": a.weight}
        for a in sigmask.decode(b.sig_mask)
    ]
    return {
        "sim_time": b.sim_time,
        "vehicle_id": b.vehicle_id,
        "rsu_id": b.rsu_id,
        "pos": {"x": b.pos_x, "y": b.pos_y},
        "gt_pos": {"x": b.gt_pos_x, "y": b.gt_pos_y} if b.has_ground_truth else None,
        "speed": b.speed,
        "heading": b.heading,
        "is_poisoned": b.is_poisoned,
        "detected": b.detected,
        "is_ghost": b.is_ghost,
        "sig_mask": b.sig_mask,
        "psi_score": b.psi_score,
        "attacker_class": b.attacker_class,
        "attacker_class_label": beacon_parser.ATTACKER_CLASS_LABELS.get(b.attacker_class, "unknown"),
        "drift_m": b.drift_m if b.has_ground_truth else None,
        "accusations": accusations,
    }


@app.get("/api/scenarios/{scenario_id:path}/timerange")
def scenario_timerange(scenario_id: str):
    beacons = _beacons_for(scenario_id)
    if not beacons:
        return {"t_min": 0.0, "t_max": 0.0, "count": 0}
    times = [b.sim_time for b in beacons]
    return {"t_min": min(times), "t_max": max(times), "count": len(beacons)}


@app.get("/api/scenarios/{scenario_id:path}/frame")
def scenario_frame(scenario_id: str, t: float, window: float = 0.15):
    """Beacons within [t, t+window) — one frame for the map replay scrubber."""
    beacons = _beacons_for(scenario_id)
    frame = [b for b in beacons if t <= b.sim_time < t + window]
    return {"t": t, "window": window, "beacons": [_beacon_to_dict(b) for b in frame]}


@app.get("/api/scenarios/{scenario_id:path}/vehicle/{vehicle_id}")
def vehicle_trajectory(scenario_id: str, vehicle_id: int):
    """Full time series for one vehicle — feeds the Defence Stack Inspector."""
    beacons = _beacons_for(scenario_id)
    track = sorted((b for b in beacons if b.vehicle_id == vehicle_id), key=lambda b: b.sim_time)
    if not track:
        raise HTTPException(404, f"vehicle {vehicle_id} not found in {scenario_id}")
    return {
        "vehicle_id": vehicle_id,
        "is_ghost": track[0].is_ghost,
        "ground_truth_attack_number": track[0].attack_number,
        "track": [_beacon_to_dict(b) for b in track],
    }


# NOTE: registered LAST among /api/scenarios/* routes on purpose. Starlette
# matches routes in registration order, and {scenario_id:path} is a greedy
# converter with no required suffix here — if this were declared before
# /timerange, /frame, /vehicle/{id}, it would swallow their trailing segments
# into scenario_id and shadow all three (confirmed live: hit /timerange before
# reordering and got back "scenario not found: <id>/timerange").
@app.get("/api/scenarios/{scenario_id:path}")
def scenario_detail(scenario_id: str):
    s = _scenario_or_404(scenario_id)
    metrics_path = s.dir / "metrics.csv"
    metrics_row = None
    if metrics_path.is_file():
        import csv

        with open(metrics_path, newline="") as fh:
            rows = list(csv.DictReader(fh))
            metrics_row = rows[0] if rows else None
    return {
        "id": s.id,
        "road": s.road,
        "attack_number": s.attack_number,
        "attack_name": s.attack_name,
        "attack_pct": s.attack_pct,
        "metrics": metrics_row,
    }


# ── Signature-mask decode (utility, also useful standalone for the frontend) ─

@app.get("/api/sigmask/{mask}")
def decode_sigmask(mask: int):
    accusations = sigmask.decode(mask)
    return {
        "mask": mask,
        "psi": sigmask.psi_from_mask(mask),
        "psi_th": sigmask.PSI_TH,
        "anomalous": sigmask.is_anomalous(mask),
        "accusations": [
            {"code": a.code, "name": a.name, "detail": a.detail, "weight": a.weight}
            for a in accusations
        ],
    }


# ── Map geometry ─────────────────────────────────────────────────────────────

@lru_cache(maxsize=8)
def _geometry_for(road: str):
    files = config.ROAD_TRACE_FILES.get(road)
    if files is None:
        raise HTTPException(404, f"no known geometry for road type: {road}")
    rsu_path = config.MOBILITY_DIR / files["rsu"]
    trace_path = config.MOBILITY_DIR / files["trace"]
    if not rsu_path.is_file() or not trace_path.is_file():
        raise HTTPException(404, f"geometry files missing for {road}: {rsu_path}, {trace_path}")
    rsus = geometry.load_rsu_positions(rsu_path)
    trace = geometry.load_mobility_trace(trace_path)
    return rsus, trace


@app.get("/api/geometry/{road}")
def road_geometry(road: str):
    rsus, trace = _geometry_for(road)
    bounds = geometry.trace_bounds(trace, padded=True)
    return {
        "road": road,
        "r_max_comm": geometry.R_MAX_COMM,
        "bounds": bounds,
        "rsus": [{"rsu_id": r.rsu_id, "x": r.x, "y": r.y} for r in rsus],
        "vehicle_count": len(trace),
    }


@app.get("/api/geometry/{road}/positions")
def road_positions(road: str, t: float):
    """All vehicle positions at time t (step-hold model) — used to draw the
    full fleet on the map even for scenarios/times with no beacon activity."""
    _, trace = _geometry_for(road)
    out = []
    for nid, waypoints in trace.items():
        wp = geometry.position_at(waypoints, t)
        if wp is not None:
            out.append({"vehicle_id": nid, "x": wp.x, "y": wp.y, "speed": wp.speed})
    return {"t": t, "positions": out}


# ── Serve the built frontend (present after `npm run build`) ───────────────

_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="frontend")
