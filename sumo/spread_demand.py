#!/usr/bin/env python3
"""
spread_demand.py — re-space SUMO vehicle departures for a busy-but-flowing run.

WHY THIS EXISTS
---------------
The route files produced by build_sumo_trace.sh insert every vehicle inside a
tiny INSERT_WINDOW (~20 s). Dumping ~270 vehicles onto the map in 20 s gridlocks
it (teleports, vehicles frozen bumper-to-bumper). That congestion is a *demand*
artefact, NOT a map defect — the OSM/.net.xml only describes roads.

This script reads the existing routes_*.rou.xml, keeps the routes / vTypes /
colors / guiShapes EXACTLY as they are, and only rewrites each <vehicle>'s
`depart` time so departures are spread uniformly over [0, SPREAD]. Vehicles are
round-robin interleaved across types, so the mix on screen stays representative
the whole run. Originals are never modified — new files get a suffix.

It also writes a ready-to-run .sumocfg and (optionally) runs sumo headless to
report peak concurrent vehicles + teleports so you can confirm it flows.

USAGE
-----
  python3 spread_demand.py --dir urban --net urban.net.xml \
      --spread 300 --end 600 --measure

  # then visualise:
  sumo-gui -c urban/flow.sumocfg
"""
import argparse, glob, os, sys, subprocess
import xml.etree.ElementTree as ET


def load_vehicles(route_files):
    """Return (vtype_elems_by_file, list_of(depart, vehicle_elem, file_idx))."""
    trees = []
    vehicles = []  # (vehicle_elem,)
    for fi, f in enumerate(route_files):
        t = ET.parse(f)
        root = t.getroot()
        trees.append((f, t, root))
        for v in root.findall("vehicle"):
            vehicles.append(v)
    return trees, vehicles


def respace(trees, spread):
    """Interleave vehicles across files, assign uniform departs over [0,spread]."""
    # collect (file_idx, vehicle_elem) grouped per file, preserving order
    per_file = []
    for fi, (f, t, root) in enumerate(trees):
        per_file.append([v for v in root.findall("vehicle")])

    # round-robin merge so types stay mixed through the run
    merged = []
    i = 0
    while any(i < len(lst) for lst in per_file):
        for lst in per_file:
            if i < len(lst):
                merged.append(lst[i])
        i += 1

    n = len(merged)
    if n == 0:
        return 0
    step = spread / n if n > 1 else 0.0
    for k, v in enumerate(merged):
        v.set("depart", f"{k * step:.2f}")
    return n


def write_routes(trees, suffix):
    out_files = []
    for f, t, root in trees:
        # SUMO requires vehicles sorted by depart within a file
        veh = root.findall("vehicle")
        for v in veh:
            root.remove(v)
        veh.sort(key=lambda e: float(e.get("depart")))
        for v in veh:
            root.append(v)
        base, ext = os.path.splitext(f)
        # strip an existing .rou -> base is "routes_car.rou"
        of = base + suffix + ext
        t.write(of, encoding="UTF-8", xml_declaration=True)
        out_files.append(os.path.basename(of))
    return out_files


def write_cfg(cfg_path, net, route_basenames, end):
    routes_csv = ",".join(route_basenames)
    cfg = f"""<configuration>
    <input>
        <net-file value="{net}"/>
        <route-files value="{routes_csv}"/>
    </input>
    <time>
        <begin value="0"/>
        <end value="{end}"/>
        <step-length value="1.0"/>
    </time>
    <processing>
        <time-to-teleport value="120"/>
        <ignore-route-errors value="true"/>
    </processing>
</configuration>
"""
    open(cfg_path, "w").write(cfg)


def measure(cfg_path, end):
    """Run sumo headless, parse summary for peak running + teleports."""
    summary = cfg_path + ".summary.xml"
    cmd = ["sumo", "-c", cfg_path, "--summary", summary,
           "--no-step-log", "--no-warnings", "--end", str(end)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    teleports = 0
    for line in (r.stdout + r.stderr).splitlines():
        if "Teleports:" in line:
            print("   " + line.strip())
    peak = 0
    peak_t = 0
    if os.path.exists(summary):
        for ev, el in ET.iterparse(summary):
            if el.tag == "step":
                run = int(el.get("running", "0"))
                if run > peak:
                    peak = run
                    peak_t = float(el.get("time", "0"))
                el.clear()
    return peak, peak_t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="urban")
    ap.add_argument("--net", default="urban.net.xml")
    ap.add_argument("--spread", type=float, default=300.0,
                    help="departures spread uniformly over [0,spread] seconds")
    ap.add_argument("--end", type=float, default=600.0)
    ap.add_argument("--suffix", default="_flow")
    ap.add_argument("--cfg", default="flow.sumocfg")
    ap.add_argument("--measure", action="store_true")
    args = ap.parse_args()

    d = args.dir
    route_files = sorted(glob.glob(os.path.join(d, "routes_*.rou.xml")))
    # exclude already-spread outputs and .alt files
    route_files = [f for f in route_files
                   if args.suffix not in f and ".rou.alt" not in f]
    if not route_files:
        print(f"no routes_*.rou.xml in {d}", file=sys.stderr)
        sys.exit(1)
    print("input route files:", [os.path.basename(f) for f in route_files])

    trees, _ = load_vehicles(route_files)
    n = respace(trees, args.spread)
    out_files = write_routes(trees, args.suffix)
    print(f"re-spaced {n} vehicles over [0,{args.spread:.0f}]s "
          f"(~{n/args.spread:.2f} veh/s) -> {out_files}")

    cfg_path = os.path.join(d, args.cfg)
    write_cfg(cfg_path, args.net, out_files, args.end)
    print(f"wrote {cfg_path}")

    if args.measure:
        print(f"measuring (sumo headless, end={args.end:.0f}s)...")
        peak, peak_t = measure(cfg_path, args.end)
        print(f"   PEAK CONCURRENT = {peak} vehicles (at t={peak_t:.0f}s)")
        print(f"\nvisualise:  sumo-gui -c {cfg_path}")


if __name__ == "__main__":
    main()
