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
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

import config
from parsers import beacon as beacon_parser
from parsers import catalog
from parsers import fusion
from parsers import geometry
from parsers import ledger
from parsers import roadmap
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
        sample = next(
            (s.id for s in scenarios if s.road == "urban" and s.attack_number == n and s.attack_pct == 40),
            next((s.id for s in scenarios if s.attack_number == n), None),
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


# ── Blockchain ledger (from a snapshot, not a live query — see
#    scripts/snapshot_ledger.py and parsers/ledger.py for why) ──────────────

@lru_cache(maxsize=1)
def _ledger_snapshot() -> dict:
    if not config.LEDGER_SNAPSHOT.is_file():
        raise HTTPException(
            404,
            "No ledger snapshot yet. Run: cd demo_ui/backend && "
            "python3 scripts/snapshot_ledger.py",
        )
    return ledger.load_snapshot(config.LEDGER_SNAPSHOT)


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
        rows.append(
            {
                "vid": vid,
                "events": len(evs),
                "gt_poisoned": poisoned,
                "flagged": flagged,
                "missed": poisoned - flagged,
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


@app.get("/api/capture/vehicle/{vid}")
def capture_vehicle(vid: int):
    events = [e for e in _capture_events() if e.vid == vid]
    if not events:
        raise HTTPException(404, f"vehicle {vid} has no FUSION events in the capture")
    events.sort(key=lambda e: e.t)
    return {"vid": vid, "events": [_fusion_event_to_dict(e) for e in events]}


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


# ── Serve the built frontend (present after `npm run build`) ───────────────

_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="frontend")
