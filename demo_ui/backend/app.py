"""FastAPI backend for the SENTINEL demo UI.

Serves the replay corpus (parsers/catalog.py) and the built frontend. Every
number returned here is read from a real file — see DEMO_UI_PLAN_2026-08-14.md
section 9 ("what this plan deliberately does not do"): no metric is
recomputed or smoothed here, only decoded/aggregated for display.
"""

import json
import subprocess
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
import bisect
import math
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

import config
from parsers import beacon as beacon_parser
from parsers import block_feed
from parsers import capture_analytics
from parsers import catalog
from parsers import csv_explorer
from parsers import fusion
from parsers import metrics
from parsers import revoke_votes
from parsers import geometry
from parsers import ipfs_client
from parsers import ledger
from parsers import roadmap
from parsers import run_manager
from parsers import run_summary
from parsers import sigmask
from parsers import topology

app = FastAPI(title="SENTINEL Demo API")

# CORS open for local dev (Vite on :5173 talking to FastAPI on :8000).
# Tighten if this is ever exposed beyond an SSH tunnel / LAN demo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# The road network is ~1 MB of repetitive coordinate JSON and compresses hard.
# Matters because the demo is driven from a laptop over an SSH tunnel.
app.add_middleware(GZipMiddleware, minimum_size=1024)


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
        "attacker_class_plain": beacon_parser.ATTACKER_CLASS_PLAIN.get(b.attacker_class, "unknown"),
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


@app.get("/api/scenarios/{scenario_id:path}/lstm_reconstruction/{vehicle_id}")
def lstm_reconstruction(scenario_id: str, vehicle_id: int, end_time: float | None = None):
    """Real LSTM-AE reconstruction for one vehicle's trailing beacon window,
    computed by ml_scripts/lstm_reconstruct.py against the EXACT deployed
    ONNX artifact (never a separately-tracked checkpoint — this project has
    repeatedly found those drift from what's actually deployed). Offline and
    read-only: no simulator code, exported model, or threshold is touched.

    Runs in gat_detector/.venv (has onnxruntime; this backend's own venv
    does not) via a short-lived subprocess — see config.ML_VENV_PYTHON.
    """
    s = _scenario_or_404(scenario_id)
    beacon_log = s.dir / "beacon_log.csv"
    if not beacon_log.is_file():
        raise HTTPException(404, f"beacon_log.csv missing for {scenario_id}")
    model_dir = config.ML_MODEL_ROOT / s.road
    if not (model_dir / "lstm_ae_model.onnx").is_file():
        raise HTTPException(404, f"no deployed LSTM-AE model for road type {s.road}")

    args = [
        str(config.ML_VENV_PYTHON),
        str(config.ML_SCRIPTS_DIR / "lstm_reconstruct.py"),
        "--beacon-log", str(beacon_log),
        "--vehicle-id", str(vehicle_id),
        "--model-dir", str(model_dir),
    ]
    if end_time is not None:
        args += ["--end-time", str(end_time)]

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "LSTM-AE reconstruction timed out")
    if proc.returncode != 0:
        raise HTTPException(500, f"lstm_reconstruct.py failed: {proc.stderr[-2000:]}")
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise HTTPException(500, f"lstm_reconstruct.py produced non-JSON output: {proc.stdout[-2000:]}")
    if "error" in out:
        raise HTTPException(404, out["error"])
    return out


@app.get("/api/scenarios/{scenario_id:path}/gat_attention/{vehicle_id}")
def gat_attention(scenario_id: str, vehicle_id: int, end_time: float | None = None, window_s: float = 10.0):
    """Real GAT attention weights for one vehicle's neighbour graph,
    computed by ml_scripts/gat_attention.py. The deployed ONNX never
    exposes attention (verified: the graph's own node list routes the GAT
    layers straight into the next op, no attention tensor reaches an
    output), so this loads weights from the ONNX file's own initializers —
    NOT gat_model.pt, a different, out-of-date checkpoint in the same
    directory — and asks torch_geometric's GATConv for
    return_attention_weights=True. Cross-checked against the real ONNX
    output for the identical input on every call (score_onnx_cross_check_
    max_abs_diff in the response). Offline and read-only.
    """
    s = _scenario_or_404(scenario_id)
    beacon_log = s.dir / "beacon_log.csv"
    if not beacon_log.is_file():
        raise HTTPException(404, f"beacon_log.csv missing for {scenario_id}")
    model_dir = config.ML_MODEL_ROOT / s.road
    if not (model_dir / "gat_model.onnx").is_file():
        raise HTTPException(404, f"no deployed GAT model for road type {s.road}")

    args = [
        str(config.ML_VENV_PYTHON),
        str(config.ML_SCRIPTS_DIR / "gat_attention.py"),
        "--beacon-log", str(beacon_log),
        "--vehicle-id", str(vehicle_id),
        "--model-dir", str(model_dir),
        "--window-s", str(window_s),
    ]
    if end_time is not None:
        args += ["--end-time", str(end_time)]

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "GAT attention extraction timed out")
    if proc.returncode != 0:
        raise HTTPException(500, f"gat_attention.py failed: {proc.stderr[-2000:]}")
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise HTTPException(500, f"gat_attention.py produced non-JSON output: {proc.stdout[-2000:]}")
    if "error" in out:
        raise HTTPException(404, out["error"])
    return out


@app.get("/api/scenarios/{scenario_id:path}/trails")
def scenario_trails(scenario_id: str, t: float, lookback: float = 6.0, max_vehicles: int = 400):
    """Recent movement history per vehicle, for motion trails on the map.

    Uses REPORTED positions (what each vehicle claimed), so a poisoned
    vehicle's trail visibly diverges from the honest traffic flow — which is
    the point. Ground-truth trails would hide the attack.
    """
    beacons = _beacons_for(scenario_id)
    lo = max(t - lookback, 0.0)
    tracks: dict[int, list[tuple[float, float, float]]] = {}
    for b in beacons:
        if lo <= b.sim_time <= t:
            tracks.setdefault(b.vehicle_id, []).append((b.sim_time, b.pos_x, b.pos_y))
    out = []
    for vid, pts in list(tracks.items())[:max_vehicles]:
        pts.sort(key=lambda p: p[0])
        if len(pts) >= 2:
            out.append({"vehicle_id": vid, "path": [[p[1], p[2]] for p in pts]})
    return {"t": t, "lookback": lookback, "trails": out}


@app.get("/api/scenarios/{scenario_id:path}/stats")
def scenario_stats(scenario_id: str, t: float | None = None, window: float = 0.15):
    """Live counters for the KPI header.

    Cumulative up to time t (or whole run if t is omitted). These are counted
    straight off the beacon rows — the confusion-matrix style figures here are
    the UI's own tally of beacon outcomes for the selected window, NOT the
    simulator's reported MCC/FPR. Scenario-level MCC comes from metrics.csv
    via /api/scenarios/{id} and must not be recomputed here.
    """
    # Inclusive of the frame currently on screen. /frame returns
    # [t, t+window), so counting only sim_time <= t made the header read
    # "1 beacon" while the feed beside it listed fifteen — the beacons in
    # the live frame have sim_time fractionally greater than t.
    beacons = _beacons_for(scenario_id)
    cutoff = None if t is None else t + window
    rows = [b for b in beacons if cutoff is None or b.sim_time < cutoff]
    tp = sum(1 for b in rows if b.is_poisoned and b.detected)
    fn = sum(1 for b in rows if b.is_poisoned and not b.detected)
    fp = sum(1 for b in rows if not b.is_poisoned and b.detected)
    tn = sum(1 for b in rows if not b.is_poisoned and not b.detected)
    return {
        "t": t,
        "beacons": len(rows),
        "poisoned": tp + fn,
        "clean": fp + tn,
        "caught": tp,
        "missed": fn,
        "false_alarms": fp,
        "vehicles_seen": len({b.vehicle_id for b in rows}),
        "ghosts_seen": len({b.vehicle_id for b in rows if b.is_ghost}),
        "note": "window tally of beacon outcomes; scenario MCC/FPR come from metrics.csv",
    }


@app.get("/api/scenarios/{scenario_id:path}/topology")
def scenario_topology(scenario_id: str):
    """Controllers, their RSU clusters, and the hostile-entity roster.

    Controller positions are DERIVED centroids (see parsers/topology.py) —
    the simulator gives control-plane nodes no coordinates.
    """
    s = _scenario_or_404(scenario_id)
    rsus, _ = _geometry_for(s.road)
    beacons = list(_beacons_for(scenario_id))
    controllers = topology.build_controllers(rsus)
    roster = topology.build_threat_roster(beacons, n_rsus=len(rsus))
    for c in controllers:
        c.hostile = c.controller_id in roster.hostile_controllers
    return {
        "scenario_id": scenario_id,
        "attack_number": s.attack_number,
        "attack_name": s.attack_name,
        "controllers": [
            {
                "controller_id": c.controller_id,
                "x": c.x,
                "y": c.y,
                "rsu_ids": c.rsu_ids,
                "position_is_derived": c.position_is_derived,
                "hostile": c.hostile,
            }
            for c in controllers
        ],
        "compromised_rsus": sorted(roster.compromised_rsus),
        "malicious_vehicles": sorted(roster.malicious_vehicles),
        "mitm_relays": sorted(roster.mitm_relays),
        "hostile_controllers": sorted(roster.hostile_controllers),
        "rsu_controller_map": {
            r.rsu_id: topology.controller_for_rsu(r.rsu_id, len(rsus), topology.DEFAULT_N_CONTROLLERS)
            for r in rsus
        },
        # The mobility trace and RSU grid are the full TOPOLOGY (used for map
        # geometry/coverage regardless of scenario); these are which of those
        # positions actually produced/received a beacon anywhere in this
        # scenario's whole recording — real vs merely-present-on-the-map.
        "active_vehicle_ids": sorted({b.vehicle_id for b in beacons}),
        "active_rsu_ids": sorted({b.rsu_id for b in beacons}),
    }


# ── Attack explainer (per-attack description + real E5 result comparison) ──

@lru_cache(maxsize=1)
def _e5_results() -> dict:
    if not config.E5_RESULTS_FILE.is_file():
        return {}
    with open(config.E5_RESULTS_FILE) as fh:
        import json

        return json.load(fh)


@app.get("/api/attacks")
def list_attacks():
    """One entry per attack variant (1-7, no combined/0): description, which
    entity is hostile, and the measured SENTINEL-vs-baseline comparison from
    results_e5_final/e5_final_table.json — including the variants where a
    baseline actually beats SENTINEL_Full (TP-S1, TP-S3, MP-S4). Never hide
    those; showing only the wins would misrepresent the evaluation."""
    e5 = _e5_results()
    scenarios = _scenarios()
    out = []
    for n in range(1, 8):
        code, _, human = catalog.ATTACK_NAMES[n].partition(":")
        info = catalog.ATTACK_INFO[n]
        result = e5.get(code, {})
        full = result.get("SENTINEL_Full")
        baselines = {k: result.get(k) for k in ("B1", "B2", "B3") if result.get(k)}
        best_baseline = max(
            ((k, v["MCC"]) for k, v in baselines.items() if "MCC" in v),
            key=lambda kv: kv[1],
            default=(None, None),
        )
        # Point the "show me" link at a mid-intensity urban recording if one
        # exists in the corpus, so the card can jump straight into a replay.
        # Deliberately urban-only, no fallback to rural/highway: those maps
        # have known rendering issues and are disabled in Network Replay's
        # own picker (ScenarioPicker.tsx) — a "show me" link must not offer a
        # jump target that screen won't actually let a user reach on its own.
        # No urban sample for this attack number means no link, not a broken
        # one.
        sample = next(
            (s.id for s in scenarios if s.road == "urban" and s.attack_number == n and s.attack_pct == 40),
            next((s.id for s in scenarios if s.road == "urban" and s.attack_number == n), None),
        )
        out.append(
            {
                "attack_number": n,
                "code": code,
                "human_name": human.replace("-", " "),
                "actor": info["actor"],
                "description": info["plain"],
                "sentinel_full": full,
                "sentinel_lw": result.get("SENTINEL_LW"),
                "baselines": baselines,
                "best_baseline_code": best_baseline[0],
                "best_baseline_mcc": best_baseline[1],
                "baseline_wins": (
                    best_baseline[1] is not None
                    and full is not None
                    and best_baseline[1] > full.get("MCC", -999)
                ),
                "sample_scenario_id": sample,
            }
        )
    return out


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


@lru_cache(maxsize=4)
def _roadmap_for(road: str) -> dict:
    rel = config.ROAD_NET_FILES.get(road)
    if rel is None:
        raise HTTPException(404, f"no SUMO network configured for road type: {road}")
    net_path = config.SUMO_DIR / rel
    if not net_path.is_file():
        raise HTTPException(404, f"SUMO network file missing: {net_path}")
    return roadmap.load_roadmap(net_path)


@app.get("/api/roadmap/{road}")
def road_map(road: str):
    """Real street geometry from the SUMO network the traces were built on.

    Drawn in the same coordinate frame as vehicles/RSUs — no transform. First
    call parses the .net.xml (~0.3 s for urban) and caches to disk.
    """
    return _roadmap_for(road)


@lru_cache(maxsize=4)
def _signals_for(road: str) -> list[dict]:
    rel = config.ROAD_NET_FILES.get(road)
    if rel is None:
        raise HTTPException(404, f"no SUMO network configured for road type: {road}")
    net_path = config.SUMO_DIR / rel
    if not net_path.is_file():
        raise HTTPException(404, f"SUMO network file missing: {net_path}")
    return roadmap.load_traffic_signals(net_path)


@app.get("/api/roadmap/{road}/signals")
def road_signals(road: str):
    """Real, fixed-cycle traffic-light programs from the SUMO network.

    Static (non-adaptive) programs only — phase at any time t is
    deterministic (t mod cycle length), computed client-side from this
    one-time payload. No live SUMO/TraCI connection involved.
    """
    return {"signals": _signals_for(road)}


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


# ═══════════════════════════════════════════════════════════════════════════
# CATCH-ALL — MUST STAY BELOW EVERY OTHER /api/scenarios/* ROUTE.
#
# Starlette matches routes in REGISTRATION ORDER, not by specificity, and
# {scenario_id:path} is a greedy converter that will happily swallow
# "urban/a1_p40/topology" whole. Declaring this above the sub-routes shadows
# every one of them and they 404 with "scenario not found: <id>/<suffix>".
# This has now bitten twice — once for /timerange|/frame|/vehicle, once for
# /trails|/stats|/topology. Add new sub-routes ABOVE this line, never below.
# ═══════════════════════════════════════════════════════════════════════════
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


# ── Blockchain ledger. Defaults to the on-disk snapshot (see
#    scripts/snapshot_ledger.py and parsers/ledger.py for why the demo
#    doesn't depend on Fabric being reachable at presentation time), but
#    /api/ledger/refresh can replace it in-memory with a live query against
#    the real gateway daemon — same shape, so every existing endpoint below
#    picks up live data for free once a refresh has run. ────────────────────

_current_ledger_snapshot: dict | None = None
_ledger_refresh_state = {"status": "idle", "started_at": None, "finished_at": None, "error": None}


def _ledger_snapshot() -> dict:
    global _current_ledger_snapshot
    if _current_ledger_snapshot is not None:
        return _current_ledger_snapshot
    if not config.LEDGER_SNAPSHOT.is_file():
        raise HTTPException(
            404,
            "No ledger snapshot yet. Run: cd demo_ui/backend && "
            "python3 scripts/snapshot_ledger.py",
        )
    _current_ledger_snapshot = ledger.load_snapshot(config.LEDGER_SNAPSHOT)
    return _current_ledger_snapshot


def _run_ledger_refresh():
    global _current_ledger_snapshot
    _ledger_refresh_state.update(status="running", started_at=time.time(), error=None)
    try:
        data = ledger.build_snapshot()
        _current_ledger_snapshot = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "live": True,
            "data": data,
        }
        _ledger_refresh_state.update(status="idle", finished_at=time.time())
    except Exception as e:  # noqa: BLE001 — surfaced to the UI, not swallowed
        _ledger_refresh_state.update(status="idle", finished_at=time.time(), error=str(e))


@app.post("/api/ledger/refresh")
def ledger_refresh():
    """Kicks off a real, live query against every chaincode function the
    demo shows. ledger.py's own docstring: a single call can legitimately
    take up to ~20-30s under load, and there are 7 of them here — this runs
    in a background thread and the UI polls /api/ledger/refresh_status
    rather than holding a request open for minutes."""
    if _ledger_refresh_state["status"] == "running":
        return {"status": "already_running"}
    threading.Thread(target=_run_ledger_refresh, daemon=True).start()
    return {"status": "started"}


@app.get("/api/ledger/refresh_status")
def ledger_refresh_status():
    snap = None
    try:
        snap = _ledger_snapshot()
    except HTTPException:
        pass
    return {
        **_ledger_refresh_state,
        "captured_at": snap["captured_at"] if snap else None,
        "is_live": bool(snap and snap.get("live")),
    }


@app.get("/api/explorer_url")
def explorer_url():
    # Read fresh, not at import time — see config.EXPLORER_TUNNEL_URL_FILE's
    # own comment: this second tunnel's URL is ephemeral and the file is
    # whatever a human last wrote there, so a missing/empty file must mean
    # "no link" rather than serving a stale one baked in at server start.
    try:
        url = config.EXPLORER_TUNNEL_URL_FILE.read_text().strip()
    except FileNotFoundError:
        url = ""
    return {"url": url or None}


def _ledger_data(key: str) -> list:
    d = _ledger_snapshot()["data"].get(key)
    if isinstance(d, dict) and "_error" in d:
        raise HTTPException(502, f"ledger query '{key}' failed at capture time: {d['_error']}")
    return d or []


@app.get("/api/ledger/summary")
def ledger_summary():
    snap = _ledger_snapshot()
    rsu = _ledger_data("rsu_trust")
    veh = _ledger_data("vehicle_trust")
    ctrl = _ledger_data("controller_trust")
    return {
        "captured_at": snap["captured_at"],
        "is_live": bool(snap.get("live")),
        "rsus": {
            "total": len(rsu),
            "trusted": sum(1 for r in rsu if r.get("State") == "TRUSTED"),
            "demoted": sum(1 for r in rsu if r.get("State") not in (None, "TRUSTED")),
        },
        "vehicles": {
            "total": len(veh),
            "decayed": sum(1 for v in veh if v.get("UpdateCount", 0) > 0),
        },
        "controllers": {
            "total": len(ctrl),
            "decayed": sum(1 for c in ctrl if c.get("UpdateCount", 0) > 0),
        },
        "revocations": len(_ledger_data("revocations")),
        "controller_flags": len(_ledger_data("controller_flags")),
        "reassignments": len(_ledger_data("reassignments")),
    }


@app.get("/api/ledger/trust/{entity}")
def ledger_trust(entity: str):
    """entity: rsu | vehicle | controller. Sorted worst-trust first."""
    key = {"rsu": "rsu_trust", "vehicle": "vehicle_trust", "controller": "controller_trust"}.get(entity)
    if key is None:
        raise HTTPException(404, f"unknown entity type: {entity} (expected rsu|vehicle|controller)")
    rows = _ledger_data(key)
    return sorted(rows, key=lambda r: r.get("TrustScore", 1))


@app.get("/api/ledger/revocations")
def ledger_revocations():
    return _ledger_data("revocations")


@app.get("/api/ledger/flags")
def ledger_flags():
    return _ledger_data("controller_flags")


@app.get("/api/ledger/reassignments")
def ledger_reassignments():
    return _ledger_data("reassignments")


# ── Live block feed — real "Committed block [N]" lines tailed straight off
#    the peer container's own log, see parsers/block_feed.py for why this
#    (not the ns-3 process) is the one honest source for block creation.
#
#    Plain polled REST, not SSE: Cloudflare Quick Tunnels (trycloudflare.com,
#    what this demo gets shared through) do not stream SSE-over-GET in real
#    time — cloudflared buffers the whole response until the connection
#    closes, which for an infinite live stream never happens (tracked
#    upstream: github.com/cloudflare/cloudflared/issues/1449). Confirmed
#    directly: the old SSE endpoint answered instantly on localhost and
#    returned zero bytes over the tunnel even after 8s. Polling has no such
#    dependency on how the transport handles a long-lived connection. ───────

@app.get("/api/ledger/blocks/recent")
def ledger_blocks_recent():
    height = block_feed.chain_height()
    try:
        recent = block_feed.fetch_recent(tail=400)[-30:]
    except block_feed.BlockFeedError as e:
        raise HTTPException(502, str(e))
    return {"container": block_feed.PEER_CONTAINER, "height": height, "recent": recent}


# ── FUSION capture: the [FUSION-RSU*] stdout from one blockchain-enabled
#    run, giving the psi/S/ae_norm/phi breakdown the replay corpus lacks
#    (that corpus was recorded at ablation_mode=1, so it never ran fusion). ─

@lru_cache(maxsize=1)
def _capture_events() -> list[fusion.FusionEvent]:
    if not config.FUSION_CAPTURE_LOG.is_file():
        raise HTTPException(404, f"no FUSION capture log at {config.FUSION_CAPTURE_LOG}")
    with open(config.FUSION_CAPTURE_LOG) as fh:
        return list(fusion.iter_events(fh))


def _fusion_event_to_dict(e: "fusion.FusionEvent") -> dict:
    accusations = [
        {"code": a.code, "name": a.name, "detail": a.detail, "weight": a.weight}
        for a in sigmask.decode(e.sig_mask)
    ]
    return {
        "rsu_id": e.rsu_id,
        "epoch": e.epoch,
        "t": e.t,
        "vid": e.vid,
        "psi": e.psi,
        "psi_fuse": e.psi_fuse,  # psi normalised to [0,1] against psi_th — the actual term summed into phi
        "S": e.S,
        "thetaS": e.thetaS,
        "S_norm": e.S_over_thetaS_clamped,  # S/thetaS clamped to [0,1] — the actual GAT term summed into phi
        "ae_norm": e.ae_norm,  # already the [0,1] term used in the fusion sum
        "ae_raw": e.ae_raw,
        "phi": e.phi,
        "khat": e.khat,
        "gt_pois": e.gt_pois,
        "gt_atk": e.gt_atk,
        "sig_mask": e.sig_mask,
        "full_anom": e.full_anom,
        "accusations": accusations,
    }


@app.get("/api/capture/summary")
def capture_summary():
    events = _capture_events()
    vids = {e.vid for e in events}
    poisoned = sum(1 for e in events if e.gt_pois)
    flagged = sum(1 for e in events if e.full_anom)
    return {
        "source": config.FUSION_CAPTURE_LOG.name,
        "events": len(events),
        "vehicles": len(vids),
        "gt_poisoned": poisoned,
        "flagged": flagged,
        "t_min": min((e.t for e in events), default=0),
        "t_max": max((e.t for e in events), default=0),
    }


@app.get("/api/capture/vehicles")
def capture_vehicles():
    """One row per vehicle that appears in the capture, worst-first (missed
    poisoning ranks above caught, which ranks above clean) so the interesting
    cases are easy to find without scrolling 200+ entries."""
    events = _capture_events()
    by_vid: dict[int, list] = {}
    for e in events:
        by_vid.setdefault(e.vid, []).append(e)

    rows = []
    for vid, evs in by_vid.items():
        poisoned = sum(1 for e in evs if e.gt_pois)
        flagged = sum(1 for e in evs if e.gt_pois and e.full_anom)
        # This capture is a COMBINED-attack recording — different vehicles
        # (and occasionally the same vehicle at different times) carry
        # different real attack_number ground truth. gt_atk IS attack_number
        # directly (1-7), 0 = honest at that instant — confirmed against the
        # simulator's own [FUSION-RSU*] print, not a derived/offset value.
        attack_types = sorted({e.gt_atk for e in evs if e.gt_pois and e.gt_atk > 0})
        rows.append(
            {
                "vid": vid,
                "events": len(evs),
                "gt_poisoned": poisoned,
                "flagged": flagged,
                "missed": poisoned - flagged,
                "attack_types": attack_types,
            }
        )

    def rank(r):
        return (0 if r["missed"] > 0 else 1 if r["gt_poisoned"] > 0 else 2, -r["events"])

    return sorted(rows, key=rank)


@app.get("/api/capture/crypto_summary")
def capture_crypto_summary():
    """PQ-crypto cost + off-chain (IPFS) storage numbers from the end-of-run
    ATTACK SUMMARY block. See parsers/run_summary.py for why ipfs_is_real is
    hardcoded False: this run's IPFS daemon connection was refused, and the
    simulator latched to its deterministic FNV-1a fallback for every window."""
    if not config.FUSION_CAPTURE_LOG.is_file():
        raise HTTPException(404, f"no capture log at {config.FUSION_CAPTURE_LOG}")
    text = config.FUSION_CAPTURE_LOG.read_text()
    s = run_summary.parse_run_summary(text)
    return {
        "ipfs": {
            "windows_stored": s.ipfs_windows,
            "hashes_on_chain": s.ipfs_hashes,
            "is_real_daemon": s.ipfs_is_real,
            "note": (
                "This run's IPFS connection to 127.0.0.1:5002 was refused; "
                "the simulator fell back to its deterministic FNV-1a stub "
                "for every window (04_state_globals.h:391). These hashes "
                "are NOT real content-addressed IPFS CIDs."
            ),
        },
        "pq_crypto_cost_ms": {
            "epoch_total": s.coo_epoch_ms,
            "trs_sign": s.coo_trs_ms,
            "fhe_aggregate": s.coo_fhe_ms,
            "dkg": s.coo_dkg_ms,
            "epochs_sampled": s.coo_epochs_sampled,
        },
        "bandwidth_overhead": {
            "ratio_vs_baseline": s.bwo_ratio,
            "hmac_bytes": s.bwo_hmac_bytes,
            "fhe_bytes": s.bwo_fhe_bytes,
            "trs_bytes": s.bwo_trs_bytes,
            "rekey_bytes": s.bwo_rekey_bytes,
            "baseline_bytes": s.bwo_base_bytes,
        },
        "chaincode_latency_ms": {
            "confirm": s.tcl_confirm_ms,
            "confirm_invokes": s.tcl_confirm_invokes,
            "reassign": s.tcl_reassign_ms,
            "reassign_rollovers": s.tcl_reassign_rollovers,
        },
        "trs_verify": {"ok": s.trs_verify_ok, "fail": s.trs_verify_fail},
        "cp_detect": {
            "alerts": s.cp_detect_alerts,
            "epochs_audited": s.cp_detect_epochs_audited,
        },
        "ttd_seconds": s.ttd_s,
    }


@app.get("/api/capture/threshold_sweep")
def capture_threshold_sweep():
    """Precision/recall/F1 of the real fused decisions against ground truth,
    swept across the decision threshold. Uses the actual phi each event
    already carries — sanity-checked to reproduce the simulator's own
    confusion matrix exactly at threshold=0.5 (TP=12756 FP=70 TN=4480
    FN=1110, matching the printed ATTACK SUMMARY byte-for-byte)."""
    points = capture_analytics.threshold_sweep(_capture_events())
    return [
        {
            "threshold": p.threshold,
            "tp": p.tp, "fp": p.fp, "tn": p.tn, "fn": p.fn,
            "precision": p.precision, "recall": p.recall, "f1": p.f1,
        }
        for p in points
    ]


@app.get("/api/capture/layer_agreement")
def capture_layer_agreement_endpoint():
    return capture_analytics.layer_agreement(_capture_events())


@app.get("/api/capture/latency_histogram")
def capture_latency_histogram():
    return capture_analytics.detection_latency(_capture_events())


@lru_cache(maxsize=1)
def _revoke_votes() -> list["revoke_votes.RevokeVote"]:
    if not config.FUSION_CAPTURE_LOG.is_file():
        raise HTTPException(404, f"no capture log at {config.FUSION_CAPTURE_LOG}")
    with open(config.FUSION_CAPTURE_LOG) as fh:
        return list(revoke_votes.iter_votes(fh))


@app.get("/api/capture/attack_evidence/{attack_number}")
def capture_attack_evidence(attack_number: int):
    """Real per-layer detection profile for one attack variant (1-7),
    filtered from the capture on the simulator's own gt_atk ground-truth
    label. Two variants (TP-S3, MP-S4) have zero events in this particular
    90s recording — n_events==0 in the response, not a fabricated figure.

    mitigation is real [SC-REVOKE-VOTE-RSU*] activity against this same
    attack's real poisoned vehicles, from this same file — see
    capture_analytics.mitigation_for_attack's docstring for why it's never
    cross-referenced against the separate ledger snapshot."""
    events = _capture_events()
    result = capture_analytics.attack_evidence(events, attack_number)
    if result.get("n_events", 0) > 0:
        result["mitigation"] = capture_analytics.mitigation_for_attack(events, _revoke_votes(), attack_number)
    return result


@app.get("/api/capture/vehicle/{vid}")
def capture_vehicle(vid: int):
    events = [e for e in _capture_events() if e.vid == vid]
    if not events:
        raise HTTPException(404, f"vehicle {vid} has no FUSION events in the capture")
    events.sort(key=lambda e: e.t)
    return {"vid": vid, "events": [_fusion_event_to_dict(e) for e in events]}


# ── [METRICS] positions: this capture has no per-neighbour GAT re-inference
#    available (unlike the replay corpus — see gat_attention.py), but it DOES
#    print real per-vehicle pos_x/pos_y on every processed beacon. That's
#    enough for a real (not fabricated) "who was nearby" proximity view —
#    explicitly NOT attention weights, since those were never computed here. ─

_NEIGHBOUR_T_TOLERANCE_S = 1.0  # ignore a vehicle whose nearest sample is older/newer than this


@lru_cache(maxsize=1)
def _metrics_samples() -> list["metrics.MetricsSample"]:
    if not config.FUSION_CAPTURE_LOG.is_file():
        raise HTTPException(404, f"no capture log at {config.FUSION_CAPTURE_LOG}")
    with open(config.FUSION_CAPTURE_LOG) as fh:
        return list(metrics.iter_samples(fh))


@lru_cache(maxsize=1)
def _metrics_by_vehicle() -> dict[int, list["metrics.MetricsSample"]]:
    by_vid: dict[int, list] = {}
    for s in _metrics_samples():
        by_vid.setdefault(s.vehicle, []).append(s)
    for samples in by_vid.values():
        samples.sort(key=lambda s: s.t)
    return by_vid


@lru_cache(maxsize=1)
def _fusion_by_vehicle() -> dict[int, list["fusion.FusionEvent"]]:
    by_vid: dict[int, list] = {}
    for e in _capture_events():
        by_vid.setdefault(e.vid, []).append(e)
    for events in by_vid.values():
        events.sort(key=lambda e: e.t)
    return by_vid


def _nearest_by_t(sorted_items: list, t: float, key):
    """Item whose `key(item)` is closest to t, plus the abs time delta. Assumes
    sorted_items is sorted ascending by key(item); empty input -> (None, inf)."""
    if not sorted_items:
        return None, float("inf")
    keys = [key(x) for x in sorted_items]
    i = bisect.bisect_left(keys, t)
    candidates = [j for j in (i - 1, i) if 0 <= j < len(sorted_items)]
    best = min(candidates, key=lambda j: abs(keys[j] - t))
    return sorted_items[best], abs(keys[best] - t)


@app.get("/api/capture/vehicle/{vid}/neighbours")
def capture_vehicle_neighbours(vid: int, t: float, radius_m: float = 300.0):
    """Real positions from [METRICS] lines, not attention weights — this
    capture's log never re-ran the GAT with attention output requested (that
    only happens for the replay corpus, see /api/scenarios/.../gat_attention).
    Distance-only: edges here mean "was this close," not "attended to this
    much." """
    by_vehicle = _metrics_by_vehicle()
    if vid not in by_vehicle:
        raise HTTPException(404, f"vehicle {vid} has no [METRICS] samples in the capture")

    target, target_dt = _nearest_by_t(by_vehicle[vid], t, key=lambda s: s.t)
    if target is None or target_dt > _NEIGHBOUR_T_TOLERANCE_S:
        raise HTTPException(404, f"vehicle {vid} has no [METRICS] sample within {_NEIGHBOUR_T_TOLERANCE_S}s of t={t}")

    fusion_by_vehicle = _fusion_by_vehicle()

    neighbours = []
    for other_vid, samples in by_vehicle.items():
        if other_vid == vid:
            continue
        sample, dt = _nearest_by_t(samples, target.t, key=lambda s: s.t)
        if sample is None or dt > _NEIGHBOUR_T_TOLERANCE_S:
            continue
        distance = math.hypot(sample.pos_x - target.pos_x, sample.pos_y - target.pos_y)
        if distance > radius_m:
            continue
        gt_pois = False
        fev, fdt = _nearest_by_t(fusion_by_vehicle.get(other_vid, []), target.t, key=lambda e: e.t)
        if fev is not None and fdt <= _NEIGHBOUR_T_TOLERANCE_S:
            gt_pois = fev.gt_pois
        neighbours.append(
            {
                "vehicle_id": other_vid,
                "pos_x": sample.pos_x,
                "pos_y": sample.pos_y,
                "distance_m": distance,
                "is_poisoned": gt_pois,
            }
        )
    neighbours.sort(key=lambda n: n["distance_m"])

    return {
        "vehicle_id": vid,
        "t": target.t,
        "target_pos": {"x": target.pos_x, "y": target.pos_y},
        "neighbours": neighbours,
    }


# ── IPFS: real daemon, on-demand — deliberately separate from the simulator
#    (which only talks to IPFS live during a run, hours away for any full
#    sim) so the UI can demonstrate a genuine add/pin/fetch round trip against
#    whatever's actually running right now, using real data already on hand.
#    Every capture/replay run recorded so far hit connection-refused and fell
#    back to the deterministic FNV-1a stub (see run_summary.py) — this is not
#    that: it's a live call to the daemon, and it fails honestly (503) rather
#    than ever fabricating a CID if the daemon isn't reachable. ─────────────

class IpfsPinRequest(BaseModel):
    label: str
    payload: dict


@app.get("/api/ipfs/status")
def ipfs_status():
    return ipfs_client.status()


@app.post("/api/ipfs/pin")
def ipfs_pin(req: IpfsPinRequest):
    try:
        result = ipfs_client.add_json(req.payload, filename=f"{req.label}.json")
    except ipfs_client.IpfsUnreachable as e:
        raise HTTPException(503, f"IPFS daemon unreachable: {e}")
    return {"label": req.label, **result}


# ── Run console: launch, track, and stream real simulation runs ────────────

class LaunchRunRequest(BaseModel):
    attack_number: int = 0
    attack_pct: int = 40
    sim_time: float = 30.0
    mobility_scenario: int = 0
    n_vehicles: int = 200
    n_rsus: int = 64
    enable_gat: bool = True
    enable_lstm_ae: bool = True
    enable_blockchain: bool = False
    seed: int = 1
    force: bool = False  # bypass a failed deployed-model check — not recommended


@app.get("/api/runs/model-check")
def runs_model_check():
    """So the launch form can show model status before the user fills
    anything in, not just as a rejection after they hit launch."""
    return run_manager.verify_deployed_model()


@app.post("/api/runs")
def runs_launch(req: LaunchRunRequest):
    rc = run_manager.RunConfig(
        attack_number=req.attack_number,
        attack_pct=req.attack_pct,
        sim_time=req.sim_time,
        mobility_scenario=req.mobility_scenario,
        n_vehicles=req.n_vehicles,
        n_rsus=req.n_rsus,
        enable_gat=req.enable_gat,
        enable_lstm_ae=req.enable_lstm_ae,
        enable_blockchain=req.enable_blockchain,
        seed=req.seed,
    )
    try:
        record = run_manager.launch_run(rc, force=req.force)
    except ValueError as e:
        raise HTTPException(409, str(e))
    except FileNotFoundError as e:
        raise HTTPException(500, f"simulator binary not found: {e}")
    return asdict(record)


@app.get("/api/runs")
def runs_list():
    return run_manager.list_runs()


# Measured 2026-08-15: a 200-vehicle run's [SIM] t=Ns heartbeat can be
# ~400KB apart under real beacon volume. 2MB gives comfortable margin
# without loading a log that reaches tens of MB (seen up to 93MB in this
# session) fully into memory on every poll.
_PROGRESS_TAIL_BYTES = 2_000_000


@app.get("/api/runs/{run_id}")
def runs_detail(run_id: str):
    rec = run_manager.get_run(run_id)
    if rec is None:
        raise HTTPException(404, f"no run with id {run_id}")
    log_path = Path(rec["log_path"])
    tail = ""
    if log_path.is_file():
        size = log_path.stat().st_size
        with open(log_path, "rb") as fh:
            fh.seek(max(0, size - _PROGRESS_TAIL_BYTES))
            tail = fh.read().decode(errors="replace")
    progress = run_manager.parse_progress(tail, rec["config"], run_id=run_id)
    live_metrics = run_manager.update_live_metrics(run_id, rec["log_path"], sim_time_total=float(rec["config"]["sim_time"]))
    history = run_manager.get_metrics_history(run_id)
    return {**rec, "progress": progress, "live_metrics": live_metrics, "metrics_history": history}


@app.post("/api/runs/{run_id}/stop")
def runs_stop(run_id: str):
    ok = run_manager.stop_run(run_id)
    if not ok:
        raise HTTPException(404, f"no running process for {run_id}")
    return {"stopped": True}


# Plain polled REST, not SSE — see ledger_blocks_recent's comment above for
# why: Cloudflare Quick Tunnels don't stream SSE-over-GET in real time, they
# buffer until the connection closes, which never happens for a live-tailed
# log. Byte-offset incremental read, same pattern run_manager's own
# update_live_metrics already uses for the same log file.
@app.get("/api/runs/{run_id}/log")
def runs_log(run_id: str, offset: int = 0):
    rec = run_manager.get_run(run_id)
    if rec is None:
        raise HTTPException(404, f"no run with id {run_id}")
    log_path = Path(rec["log_path"])

    lines: list[str] = []
    next_offset = offset
    if log_path.is_file():
        with open(log_path, "rb") as fh:
            fh.seek(offset)
            chunk = fh.read()
        last_nl = chunk.rfind(b"\n")
        if last_nl != -1:
            complete = chunk[: last_nl + 1]
            next_offset = offset + len(complete)
            lines = complete.decode(errors="replace").splitlines()

    return {"lines": lines, "next_offset": next_offset, "done": not run_manager._is_alive(rec["pid"])}


# ── CSV explorer: generic "pick a CSV, pick two columns, plot it" — see
#    parsers/csv_explorer.py's docstring for why headerless sources are
#    labelled "Column N" rather than guessed. ────────────────────────────────

@app.get("/api/csv_sources")
def csv_sources():
    return csv_explorer.list_sources()


@app.get("/api/csv_sources/{source_id}/columns")
def csv_source_columns(source_id: str):
    try:
        return csv_explorer.read_columns(source_id)
    except KeyError:
        raise HTTPException(404, f"unknown CSV source: {source_id}")


@app.get("/api/csv_sources/{source_id}/data")
def csv_source_data(source_id: str, x: str, y: str, max_points: int = 2000):
    try:
        return csv_explorer.read_xy(source_id, x, y, max_points=max_points)
    except KeyError as e:
        raise HTTPException(404, str(e))


# ── Results & ablation (E1/E2 figures as static images, E5 as data,
#    D1/D4/D6 ablation as documented facts) ─────────────────────────────────

for _key, _dir in config.RESULTS_DIRS.items():
    if _dir.is_dir():
        app.mount(f"/static/results_{_key}", StaticFiles(directory=str(_dir)), name=f"results_{_key}")


@app.get("/api/results/e5")
def results_e5():
    return _e5_results()


@app.get("/api/results/ablation")
def results_ablation():
    """D1 (no ML) / D4 (GAT only) / D6 (GAT+LSTM-AE), combined attack, 40%
    intensity, urban, seed 1. Hardcoded from CLAUDE.md's documented,
    simulator-printed values (2026-08-07) rather than re-derived here — this
    is exactly the kind of number a parsing bug could silently corrupt, and
    RUN_CONFIG.md/CLAUDE.md already carry it as the audited source of truth.
    Update this alongside CLAUDE.md if those figures are ever revised."""
    return {
        "source": "CLAUDE.md 'Current state' section, 2026-08-07",
        "config": "300s combined-attack run, seed 1, rho_a 0.40, urban",
        "windows": [
            {
                "cutoff_s": 90,
                "ordering_holds": True,
                "arms": {"D1": 0.8339, "D4": 0.8432, "D6": 0.8477},
            },
            {
                "cutoff_s": 300,
                "ordering_holds": False,
                "arms": {"D1": 0.763, "D4": 0.758, "D6": 0.766},
                "note": "D4 falls 0.005 below D1 over the full run. The D4-vs-D1 "
                "gap (0.0011 at 90s) is inside ONNX run-to-run variance (~0.007) "
                "and should not be read as a resolved ordering.",
            },
        ],
    }


@app.get("/api/results/ablation_studies")
def results_ablation_studies():
    """The paper's own 11-variant ablation study (report/main.tex, "Attack
    Modeling"/ablation chapter, \\subsection{AB1..AB11} — NOT the same thing
    as /api/results/ablation above, which is a separate D1/D4/D6 time-cutoff
    analysis under one fixed scenario. Every number here was read directly
    out of main.tex's own results prose (each entry's "citation" gives the
    line range) — this endpoint transcribes the paper, it does not
    re-derive or re-verify the underlying sweeps. AB8 has no "results" key:
    the paper itself discloses (main.tex:8715-8722) that this ablation was
    never completed experimentally — that gap is real and shown as a gap,
    not filled in or omitted."""
    return [
        {
            "number": 1,
            "category": "Detection",
            "title": "Rule-Based Signatures Removed",
            "ablates": "The nine rule-based signatures and composite score ψ_i(t) (Eq 3.21)",
            "swept": "attacker penetration ρ_a ∈ {0.05, 0.10, 0.20, 0.30, 0.40}",
            "headline": "MCC_full at ρ_a=0.40: full 0.781 vs AB1 0.395",
            "finding": "Removing the rule signatures costs roughly half the achieved detection quality at every penetration rate in the sweep.",
            "caveat": "The quoted TTD (12.74–15.44s vs 0.59–6.04s) is from an independent single-seed check, not the 3-seed manifest; PBPO is a mechanism argument, not a measured data column.",
            "citation": "main.tex:7157-7276",
            "has_results": True,
        },
        {
            "number": 2,
            "category": "Detection",
            "title": "HMAC Removed",
            "ablates": "HMAC beacon integrity and anti-replay verification (Eq 3.42)",
            "swept": "MitM penetration ρ_MitM ∈ {0.05, 0.10, 0.20, 0.30, 0.40, 0.8}",
            "headline": "MCC_full at ρ_MitM=0.80: full 0.942 vs AB2 0.479 — but AB2 is HIGHER than full at ρ≤0.10",
            "finding": "Below ρ_MitM≈0.3 the ablated arm's MCC is actually higher — a measurement artefact, not a real advantage: HMAC's fail-fast gate discards modified beacons before they can be scored as a caught true positive, so removing the gate inflates AB2's measured MCC while making the system strictly less safe. CDER (which scores control outcomes, not beacon verdicts) is the fair arbiter here. Above ρ≈0.3 the artefact is overwhelmed and AB2 collapses.",
            "caveat": "The low-penetration inversion (0.718 vs 0.602 at ρ=0.05) is real and explained above, not noise — don't read it as HMAC being harmful.",
            "citation": "main.tex:7276-7380",
            "has_results": True,
        },
        {
            "number": 3,
            "category": "Detection",
            "title": "GAT Disabled",
            "ablates": "The GAT spatial anomaly detector",
            "swept": "coordinated Sybil identities per RSU, n_coord ∈ {1, 2, 5, 10, 20}",
            "headline": "MCC_full: full 0.332→0.180 vs AB3 at or below zero (−0.007 to −0.115)",
            "finding": "Without the GAT, coordinated Sybil identities are effectively undetectable — MCC falls to zero or negative across the whole sweep.",
            "caveat": "Explicitly marked preliminary by the paper itself: only 3 seeds, high seed variance (realized poison rate ranged 6.3–18.8% across seeds at fixed ρ_a=0.20).",
            "citation": "main.tex:7380-7517",
            "has_results": True,
        },
        {
            "number": 4,
            "category": "Detection",
            "title": "LSTM-AE Disabled",
            "ablates": "The LSTM temporal autoencoder (reconstruction error ε̂)",
            "swept": "stealth drift bound ε_max ∈ {0.1, 0.2, 0.3, 0.4, 0.5} m/beacon",
            "headline": "MCC_full at ε_max=0.5m: full 0.367 vs AB4 flat at 0.025 — identical seed-for-seed across the sweep",
            "finding": "The ablated system's response to stealth drift magnitude is exactly zero, not just small — the paper calls this \"the cleanest ablation in the study\" because a sub-threshold-per-beacon drift attack is structurally invisible to rule signatures and only the LSTM-AE's cumulative-window view catches it.",
            "caveat": "TTD handling of the \"never detected\" sentinel value across seeds needs confirmation before the plotted figure is fully trusted (in-file TODO).",
            "citation": "main.tex:7517-7685",
            "has_results": True,
        },
        {
            "number": 5,
            "category": "Detection",
            "title": "Full AI Layer Removed (Lightweight Mode Only)",
            "ablates": "Both GAT and LSTM-AE together — detection relies solely on HMAC + rule signatures",
            "swept": "vehicle speed regime, v ∈ {10, 60, 100, 140} km/h",
            "headline": "MCC_full: full 0.867 (flat) vs Lightweight-only 0.267–0.367 across speed regimes",
            "finding": "This is the direct Lightweight-Mode-vs-Full-Mode comparison: with both AI detectors removed, detection quality drops by more than half and stays flat regardless of speed — the AI layer is what recovers the loss, not speed-regime tuning.",
            "caveat": "TTD is a \"never detected\" sentinel value at every speed and every seed for the ablated arm.",
            "citation": "main.tex:7685-7857",
            "has_results": True,
        },
        {
            "number": 6,
            "category": "Cryptography",
            "title": "TRS Threshold Signing Gate Removed",
            "ablates": "t-of-n threshold ring signing, weakened to a single signer with no quorum",
            "swept": "compromised ring-member fraction f/n ∈ {0, 0.25, 0.5, 0.75, 1.0} (n=4)",
            "headline": "PARR at f/n=0.5: full t-of-n quorum 0.800 vs AB6 single-signer 0.000",
            "finding": "A single compromised ring member fully defeats a non-quorum signer — the threshold gate is what makes a poisoned aggregate rejectable at all, not an incremental improvement.",
            "caveat": None,
            "citation": "main.tex:7857-7981",
            "has_results": True,
        },
        {
            "number": 7,
            "category": "Cryptography",
            "title": "FHE Pre-Coordination Encryption Removed (PQ vs. classical)",
            "ablates": "Compares the full post-quantum PQ-FHE-TRS pipeline against a classical ECDSA-class baseline (Shamir-Schnorr-P256)",
            "swept": "RSU signing-ring size n ∈ {4, 6, 8, 10, 12}",
            "headline": "TRS signing latency: PQ (ML-DSA-87/Dilithium5) ~22.0ms flat vs classical ~3.48ms — a 6.34× ratio; bandwidth overhead ~10.5× baseline",
            "finding": "Post-quantum signing costs roughly 6× a classical scheme, and the full crypto pipeline (FHE + TRS) adds about 10.5× bandwidth over plain beacons — the measured price of PQ-safety and FHE-based aggregate privacy.",
            "caveat": None,
            "citation": "main.tex:7981-8143",
            "has_results": True,
        },
        {
            "number": 8,
            "category": "Trust",
            "title": "RSU Three-State Trust Lifecycle Removed",
            "ablates": "The RSU trust-state lifecycle (TRUSTED → PROBATIONARY → DEMOTED)",
            "swept": None,
            "headline": None,
            "finding": None,
            "caveat": "Not among the completed studies — the paper discloses this itself: \"is not among the completed studies reported in Chapter Results... the RQ6 claim regarding trust-management sub-components is correspondingly supported by AB9 and AB10 alone.\" Shown here as a real gap, not filled in with a number.",
            "citation": "main.tex:4236, 8715-8722",
            "has_results": False,
        },
        {
            "number": 9,
            "category": "Trust",
            "title": "Multi-Controller Architecture Removed",
            "ablates": "Multiple controllers with cross-controller conflict detection (CP-DETECT) and revocation, reduced to a single controller with no revocation pathway",
            "swept": "controller compromise onset t_comp / T_sim ∈ {0, 0.25, 0.5, 0.75, 1.0}",
            "headline": "CDER decays 0.633 → 0.265 as compromise onset moves later in the run — near-linear",
            "finding": "Without a revocation pathway, control-decision damage is simply proportional to how long the compromised controller stays exposed — a controller compromised at the start corrupts decisions for the whole run, one compromised at the end corrupts almost none.",
            "caveat": "An unresolved in-file TODO in the paper's own source flags that the archived sweep may contain only the single-controller (ablated) arm, with no full-mode comparison series in the underlying data — treat the full-system baseline for this ablation with caution.",
            "citation": "main.tex:8143-8240",
            "has_results": True,
        },
        {
            "number": 10,
            "category": "Trust",
            "title": "Blockchain Trust Layer Removed",
            "ablates": "SC-Trust / SC-Revoke — the 2f+1 BFT-endorsed on-chain revocation requirement",
            "swept": "attack penetration ρ_a ∈ {0, 0.2, 0.4, 0.6, 0.8, 1.0}",
            "headline": "CDER separation reaches 0.021 at ρ_a=1.0 (full 0.679 vs ablated 0.700) — small but consistent in sign above ρ_a=0.6",
            "finding": "Without the 2f+1 BFT endorsement requirement, revocation depends on one controller's own view and becomes less reliable as more entities misbehave — directionally as predicted, though the effect size is small.",
            "caveat": "The paper flags this explicitly: \"A 0.02 difference in CDER sits close to the resolution at which the ablated arm's values were logged — several of its rows carry only one decimal place.\" Read this as establishing direction, not a precise magnitude.",
            "citation": "main.tex:8240-8421",
            "has_results": True,
        },
        {
            "number": 11,
            "category": "Key Management",
            "title": "LKH Replaced with Unicast Key Distribution",
            "ablates": "Logical Key Hierarchy group rekeying, replaced with per-vehicle unicast rekey messages",
            "swept": "group size |V_j| ∈ {40, 80, 120, 160, 200}",
            "headline": "Rekey messages at |V_j|=200: LKH 8 vs unicast 199 — a 24.9× reduction",
            "finding": "LKH's message count matches its closed-form prediction ⌈log2|V_j|⌉ EXACTLY at every point, not just approximately — the strongest possible confirmation that the deployed mechanism is what the analysis assumes it is.",
            "caveat": "Run as a standalone micro-benchmark of the rekey mechanism itself, not inside a full network simulation.",
            "citation": "main.tex:8421-8600",
            "has_results": True,
        },
    ]


# ── Serve the built frontend (present after `npm run build`) ───────────────

_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="frontend")
