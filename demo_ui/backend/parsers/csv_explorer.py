"""Generic "pick a CSV, pick two columns, plot it" explorer.

Deliberately never guesses a column's MEANING. Two real CSV shapes exist in
this project:
  - headered (e.g. a run's own beacon_log.csv/metrics.csv — kBeaconHeader is
    written in 10_metrics_csv.h) -> real column names, used as-is.
  - headerless (results_e1_final/e2_raw_results.csv -- config.py's own
    RESULTS_DIRS comment: "no generating script survives in the repo, so
    their ~13 numeric columns can't be safely re-derived") -> columns are
    labelled positionally ("Column 0", "Column 1", ...), never invented
    names. That comment is exactly the mistake this module is built to
    avoid repeating.

Sources are a small static whitelist plus dynamically-discovered outputs of
runs actually launched through this app's Run Console — never an open path,
so there's no path-traversal surface.
"""

import csv
import io
from pathlib import Path

import config
from parsers import run_manager

# Static, known-safe CSVs. No header row in either — see module docstring.
_STATIC_SOURCES = {
    "e1_sweep": {
        "label": "E1 — penetration/intensity sweep (raw)",
        "path": config.RESULTS_DIRS["e1"] / "e1_raw_results.csv",
        "has_header": False,
    },
    "e2_sweep": {
        "label": "E2 — speed regime sweep (raw)",
        "path": config.RESULTS_DIRS["e2"] / "e2_raw_results.csv",
        "has_header": False,
    },
}


def _run_sources() -> dict[str, dict]:
    """One entry per launched run that has a real beacon_log.csv on disk yet
    (per_pid_results=1 always set by resolve_args, so the path is
    deterministic: analytics/results/{scenario}_pid{PID}/beacon_log.csv)."""
    out: dict[str, dict] = {}
    scenario_names = {0: "urban", 1: "rural", 2: "highway"}
    for rec in run_manager.list_runs():
        cfg = rec["config"]
        scenario = scenario_names.get(cfg.get("mobility_scenario", 0), "urban")
        run_dir = config.NS3_ROOT / "analytics" / "results" / f"{scenario}_pid{rec['pid']}"
        csv_path = run_dir / "beacon_log.csv"
        if csv_path.is_file():
            out[f"run_{rec['run_id']}"] = {
                "label": f"Run {rec['run_id']} — beacon_log.csv ({'live' if rec['alive'] else 'finished'})",
                "path": csv_path,
                "has_header": True,
            }
    return out


def list_sources() -> list[dict]:
    sources = {**_STATIC_SOURCES, **_run_sources()}
    return [
        {"id": sid, "label": s["label"], "exists": s["path"].is_file()}
        for sid, s in sources.items()
    ]


def _resolve(source_id: str) -> dict:
    sources = {**_STATIC_SOURCES, **_run_sources()}
    s = sources.get(source_id)
    if s is None:
        raise KeyError(source_id)
    return s


def _read_rows(path: Path, has_header: bool) -> tuple[list[str], list[list[str]]]:
    with open(path, newline="", errors="replace") as fh:
        reader = csv.reader(fh)
        rows = list(reader)
    if not rows:
        return [], []
    if has_header:
        return rows[0], rows[1:]
    n_cols = len(rows[0])
    return [f"Column {i}" for i in range(n_cols)], rows


def read_columns(source_id: str, preview_rows: int = 5) -> dict:
    s = _resolve(source_id)
    if not s["path"].is_file():
        return {"columns": [], "row_count": 0, "preview": [], "has_header": s["has_header"]}
    header, rows = _read_rows(s["path"], s["has_header"])
    return {
        "columns": header,
        "row_count": len(rows),
        "preview": rows[:preview_rows],
        "has_header": s["has_header"],
    }


def read_xy(source_id: str, x_col: str, y_col: str, max_points: int = 2000) -> dict:
    s = _resolve(source_id)
    header, rows = _read_rows(s["path"], s["has_header"])
    if x_col not in header or y_col not in header:
        raise KeyError(f"column not found: {x_col!r} or {y_col!r} not in {header}")
    xi, yi = header.index(x_col), header.index(y_col)

    xs: list[float] = []
    ys: list[float] = []
    for row in rows:
        if xi >= len(row) or yi >= len(row):
            continue
        try:
            xs.append(float(row[xi]))
            ys.append(float(row[yi]))
        except ValueError:
            continue  # non-numeric cell (e.g. e2's trailing "trace_confirmed=1") -- skip, don't fake a 0

    n = len(xs)
    if n > max_points:
        # Even decimation, not a random sample — keeps a sweep's shape intact
        # rather than introducing sampling noise into what's meant to be a
        # real, exact plot.
        step = n / max_points
        idx = [int(i * step) for i in range(max_points)]
        xs = [xs[i] for i in idx]
        ys = [ys[i] for i in idx]

    return {"x": xs, "y": ys, "n_total": n, "n_returned": len(xs)}
