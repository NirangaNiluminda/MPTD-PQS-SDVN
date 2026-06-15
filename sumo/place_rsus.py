#!/usr/bin/env python3
# =============================================================================
# place_rsus.py — realistic, coverage-aware RSU placement for SUMO maps
#
# WHY: the paper (§4.1.3) specifies NO RSU count or placement, so this is a
# simulation choice. RSUs are placed on the real road network (intersections),
# biased toward where vehicles actually drive (from the .tcl trace), and spread
# out so they cover the travelled roads. Works for ANY SUMO city — point it at
# that city's net.xml + trace and regenerate the CSV; no NS-3 code change.
#
# CANDIDATE CASCADE (so it never fails, even with no traffic lights):
#   1. traffic_light junctions          (most realistic)
#   2. + priority / multi-road junctions (intersections without signals)
#   3. + all non-internal junctions      (sparse / rural maps)
#   4. uniform grid over the map         (last resort, always works)
# Candidates are then filtered to those near real traffic, and N_RSUs are picked
# by farthest-point (k-center) sampling so they spread to cover the road usage.
#
# COVERAGE is MEASURED, not promised: the script reports the fraction of sampled
# vehicle positions within --range of at least one chosen RSU. Bump --n_rsus
# until that number meets your target (~90%+ is plenty; 100% is not achievable
# with finite RSUs and is not required — gap vehicles reconnect at the next RSU).
#
# Output: CSV "rsu_id,x,y" consumed by NS-3 (12_main.h) under --mobility_source=1.
#
# Usage:
#   python3 sumo/place_rsus.py \
#       --net   sumo/urban/urban.net.xml \
#       --trace mobility/mobility_urban_150.tcl \
#       --n_rsus 25 --range 270 \
#       --out   mobility/rsu_positions_urban.csv
# =============================================================================
import argparse
import csv
import math
import re
import sys
import xml.etree.ElementTree as ET


def parse_junctions(net_path):
    """Return (tl, priority, other) lists of (x,y) from a SUMO net.xml.

    tl       : type == 'traffic_light'  (signalized intersections)
    priority : real road junctions that merge >=2 edges, unsignalized
    other    : remaining non-internal junctions (dead_end, etc.)
    Internal junctions are skipped (they are lane-internal artefacts).
    """
    tl, priority, other = [], [], []
    # iterparse keeps memory bounded on the ~10 MB net file.
    for _event, elem in ET.iterparse(net_path, events=("end",)):
        if elem.tag != "junction":
            continue
        jtype = elem.get("type", "")
        if jtype == "internal":
            elem.clear()
            continue
        try:
            x = float(elem.get("x"))
            y = float(elem.get("y"))
        except (TypeError, ValueError):
            elem.clear()
            continue
        if jtype == "traffic_light":
            tl.append((x, y))
        elif jtype in ("priority", "right_before_left", "allway_stop",
                       "traffic_light_right_on_red", "priority_stop"):
            priority.append((x, y))
        else:
            other.append((x, y))
        elem.clear()
    return tl, priority, other


_TCL_SETDEST = re.compile(r'setdest\s+([\d.eE+-]+)\s+([\d.eE+-]+)\s+([\d.eE+-]+)')
_TCL_SETX = re.compile(r'set\s+X_\s+([\d.eE+-]+)')
_TCL_SETY = re.compile(r'set\s+Y_\s+([\d.eE+-]+)')


def parse_trace_positions(trace_path):
    """Collect a cloud of (x,y) vehicle positions across the whole .tcl trace.

    Uses every setdest waypoint plus the initial 'set X_/Y_' positions, giving a
    spatial sample of where vehicles actually are over the run. This drives both
    density-aware placement and the coverage measurement.
    """
    pts = []
    pending_x = None
    with open(trace_path, "r") as fh:
        for line in fh:
            m = _TCL_SETDEST.search(line)
            if m:
                pts.append((float(m.group(1)), float(m.group(2))))
                continue
            mx = _TCL_SETX.search(line)
            if mx:
                pending_x = float(mx.group(1))
                continue
            my = _TCL_SETY.search(line)
            if my and pending_x is not None:
                pts.append((pending_x, float(my.group(1))))
                pending_x = None
    return pts


def grid_candidates(pts, n_rsus):
    """Last-resort fallback: a uniform grid over the trace bounding box."""
    if not pts:
        return []
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    xmin, xmax, ymin, ymax = min(xs), max(xs), min(ys), max(ys)
    cols = max(1, int(math.ceil(math.sqrt(n_rsus))))
    rows = max(1, int(math.ceil(n_rsus / cols)))
    cand = []
    for r in range(rows):
        for c in range(cols):
            # cell centres
            fx = (c + 0.5) / cols
            fy = (r + 0.5) / rows
            cand.append((xmin + fx * (xmax - xmin),
                         ymin + fy * (ymax - ymin)))
    return cand


def grid_overlay(pts, rows, cols, spacing):
    """Supervisor-mandated layout (2026-06-12): a fixed rows×cols RSU grid with
    a fixed metre `spacing` horizontally and vertically, CENTRED over the
    travelled area (trace bounding-box centre).

    Unlike grid_candidates() (which stretches a grid to fill the bbox), this
    lays an EXACT uniform grid at the requested physical spacing — the RSU
    topology is then a controlled, reproducible variable independent of where
    the roads happen to be. With spacing < DSRC range every vehicle stays in
    range of >=1 RSU (overlapping coverage, no gaps).

    Returns a list of (x, y), row-major (RSU 0 = bottom-left)."""
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    cx = (min(xs) + max(xs)) / 2.0
    cy = (min(ys) + max(ys)) / 2.0
    x0 = cx - (cols - 1) * spacing / 2.0
    y0 = cy - (rows - 1) * spacing / 2.0
    rsus = []
    for r in range(rows):
        for c in range(cols):
            rsus.append((x0 + c * spacing, y0 + r * spacing))
    return rsus


def density_filter(cands, pts, radius):
    """Keep only candidates with >=1 vehicle sample within `radius`.

    Ensures every RSU sits where traffic actually flows (not an empty corner).
    Returns list of (x, y, density) where density = #samples in range.
    """
    r2 = radius * radius
    out = []
    for cx, cy in cands:
        d = 0
        for px, py in pts:
            if (px - cx) ** 2 + (py - cy) ** 2 <= r2:
                d += 1
        if d > 0:
            out.append((cx, cy, d))
    return out


def farthest_point_select(cands, n):
    """Greedy k-center: spread N points to maximise minimum spacing.

    Seeded by the highest-density candidate, then each new pick is the candidate
    farthest from all chosen so far. Gives even coverage of the travelled area.
    cands: list of (x, y, density). Returns list of (x, y).
    """
    if not cands:
        return []
    if len(cands) <= n:
        return [(c[0], c[1]) for c in cands]
    chosen = [max(cands, key=lambda c: c[2])]  # densest first
    chosen_xy = [(chosen[0][0], chosen[0][1])]
    while len(chosen_xy) < n:
        best, best_d = None, -1.0
        for c in cands:
            xy = (c[0], c[1])
            if xy in chosen_xy:
                continue
            dmin = min((xy[0] - sx) ** 2 + (xy[1] - sy) ** 2
                       for sx, sy in chosen_xy)
            if dmin > best_d:
                best_d, best = dmin, xy
        if best is None:
            break
        chosen_xy.append(best)
    return chosen_xy


def coverage_pct(rsus, pts, radius):
    """Fraction of vehicle-position samples within `radius` of some RSU."""
    if not pts:
        return 0.0
    r2 = radius * radius
    covered = 0
    for px, py in pts:
        for rx, ry in rsus:
            if (px - rx) ** 2 + (py - ry) ** 2 <= r2:
                covered += 1
                break
    return 100.0 * covered / len(pts)


def main():
    ap = argparse.ArgumentParser(description="Realistic coverage-aware RSU placement for a SUMO map")
    ap.add_argument("--net", help="SUMO .net.xml road network (not needed in --grid mode)")
    ap.add_argument("--trace", required=True, help="ns-2 .tcl mobility trace")
    ap.add_argument("--n_rsus", type=int, help="number of RSUs (coverage-aware mode)")
    ap.add_argument("--range", type=float, default=270.0,
                    help="DSRC coverage radius in metres (default 270; 41 dBm DSRC)")
    ap.add_argument("--grid", metavar="ROWSxCOLS",
                    help="uniform-grid mode, e.g. 8x8 (overrides coverage-aware placement)")
    ap.add_argument("--spacing", type=float, default=250.0,
                    help="grid spacing in metres, H and V (default 250; used with --grid)")
    ap.add_argument("--out", required=True, help="output CSV (rsu_id,x,y)")
    args = ap.parse_args()

    pts = parse_trace_positions(args.trace)
    print(f"[place_rsus] vehicle position samples from trace: {len(pts)}")
    if not pts:
        print("[place_rsus] ERROR: no vehicle positions parsed from trace", file=sys.stderr)
        return 2

    # ── Grid mode (supervisor-mandated, 2026-06-12) ───────────────────────────
    if args.grid:
        rows, cols = (int(v) for v in args.grid.lower().split("x"))
        rsus = grid_overlay(pts, rows, cols, args.spacing)
        cov = coverage_pct(rsus, pts, args.range)
        with open(args.out, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["rsu_id", "x", "y"])
            for i, (x, y) in enumerate(rsus):
                w.writerow([i, f"{x:.2f}", f"{y:.2f}"])
        print(f"[place_rsus] GRID mode: {rows}x{cols} = {len(rsus)} RSUs, "
              f"{args.spacing:.0f} m spacing, centred on trace -> {args.out}")
        print(f"[place_rsus] MEASURED COVERAGE = {cov:.1f}% of vehicle-position "
              f"samples within {args.range:.0f} m of an RSU")
        return 0

    if not args.n_rsus or not args.net:
        print("[place_rsus] ERROR: coverage-aware mode needs --net and --n_rsus "
              "(or use --grid ROWSxCOLS)", file=sys.stderr)
        return 2

    print(f"[place_rsus] net   = {args.net}")
    print(f"[place_rsus] trace = {args.trace}")
    print(f"[place_rsus] N_RSUs= {args.n_rsus}   range= {args.range} m")

    tl, priority, other = parse_junctions(args.net)
    print(f"[place_rsus] junctions: traffic_light={len(tl)} "
          f"priority={len(priority)} other={len(other)}")

    # Candidate cascade: grow the pool until it is comfortably larger than
    # N_RSUs so farthest-point sampling has room to spread.
    want = max(args.n_rsus * 3, args.n_rsus)
    pool = list(tl)
    tier = "traffic_light"
    if len(pool) < want:
        pool += priority
        tier = "traffic_light+priority"
    if len(pool) < want:
        pool += other
        tier = "all junctions"
    if len(pool) < args.n_rsus:
        pool = grid_candidates(pts, args.n_rsus)
        tier = "uniform grid (fallback)"
    print(f"[place_rsus] candidate pool = {len(pool)}  (tier: {tier})")

    # Keep candidates on travelled roads; relax if that leaves too few.
    cands = density_filter(pool, pts, args.range)
    if len(cands) < args.n_rsus:
        print(f"[place_rsus] only {len(cands)} candidates near traffic; "
              f"relaxing density filter")
        cands = [(x, y, 1) for (x, y) in pool]
    else:
        print(f"[place_rsus] candidates near traffic = {len(cands)}")

    rsus = farthest_point_select(cands, args.n_rsus)
    cov = coverage_pct(rsus, pts, args.range)

    with open(args.out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["rsu_id", "x", "y"])
        for i, (x, y) in enumerate(rsus):
            w.writerow([i, f"{x:.2f}", f"{y:.2f}"])

    print(f"[place_rsus] wrote {len(rsus)} RSU positions -> {args.out}")
    print(f"[place_rsus] MEASURED COVERAGE = {cov:.1f}% of vehicle-position "
          f"samples within {args.range:.0f} m of an RSU")
    if cov < 80.0:
        print(f"[place_rsus] NOTE: coverage < 80% — consider raising --n_rsus")
    return 0


if __name__ == "__main__":
    sys.exit(main())
