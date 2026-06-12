# OSM → SUMO → NS-3 Mobility Pipeline

How real city traffic gets into the NS-3 simulation. Everything is
**auto-generated from scripts** — no file is built by hand.

---

## The big picture

```
  ┌── OpenStreetMap ──┐   ┌──────────────── SUMO ─────────────────┐   ┌──── NS-3 ────┐
  │                   │   │                                       │   │              │
  urban.osm  ───────► urban.net.xml  +  routes_*.rou.xml ───────► mobility_urban_*.tcl ──► sim
  (raw map data)      (roads only)      (vehicles + trips)         (trajectory table)   (nodes move)
```

- **OSM** = the city **roads** (no vehicles).
- **SUMO** = adds the **vehicles** and **simulates their movement** on those roads.
- **NS-3** = reads a SUMO-exported **trajectory file** (`.tcl`) and drags its
  nodes along the exact same paths.

NS-3 never reads SUMO files directly — it only reads the `.tcl` trajectory.

---

## Files in the pipeline

| Stage | File | What it is | Made by | Auto / manual |
|-------|------|------------|---------|---------------|
| 1. Raw map | `urban/urban.osm` | OpenStreetMap export of the area | downloaded from OSM | downloaded |
| 2a. Roads | `urban/urban.net.xml` | SUMO road network (lanes, junctions, lights) | `netconvert` | **auto** |
| 2b. Vehicles | `urban/routes_*_flow.rou.xml` | 200 vehicles + routes + colours/shapes | `randomTrips.py` | **auto** |
| 2c. Run config | `urban/flow.sumocfg` | points SUMO at net + route files | the script | **auto** |
| 2d. Trajectory | `mobility/mobility_urban_*.tcl` | every vehicle's (x,y) per second | SUMO `--fcd-output` + `traceExporter.py` | **auto** |
| 3. NS-3 import | `scratch/.../09b_mobility_provider.h` | `Ns2MobilityHelper` reads the `.tcl` | (C++ already wired) | — |

---

## The two scripts — and which to use

There are **two** generator scripts in `sumo/`. They do different jobs:

### A. `build_sumo_trace.sh` — makes the NS-3 trajectory (`.tcl`)

- **Purpose:** the *original* end-to-end pipeline. Builds `urban.net.xml` from
  the OSM, generates demand, and exports the `mobility_urban_<speed>.tcl`
  trajectory **that NS-3 consumes**.
- **Use it when:** you need to (re)generate the `.tcl` file for an NS-3 run,
  or rebuild the road network from a new OSM.
- **Output:** `mobility/mobility_<tag>_<speed>.tcl`
- **Caveat:** its demand floods all vehicles in ~20 s with looping routes →
  the *SUMO-GUI view* of it looks congested (fine for NS-3 traces, ugly to demo).

### B. `gen_flow_demand.sh` — makes a busy-but-flowing SUMO-GUI scene  ← NEW

- **Purpose:** produce a realistic, **visually flowing** 200-vehicle urban
  scene with distinct colours/shapes, for **SUMO-GUI demos / screenshots /
  clips** (e.g. supervisor deliverable #3).
- **Use it when:** you want to *watch* the traffic in SUMO-GUI and it must look
  busy yet not gridlocked.
- **Output:** `urban/routes_*_flow.rou.xml` + `urban/flow.sumocfg`
- It does **not** touch the OSM or the road network, and does **not** itself
  produce the NS-3 `.tcl` (see "feeding it to NS-3" below).

### Which one?

| Goal | Script |
|------|--------|
| Watch / record traffic in SUMO-GUI (demo, screenshot, clip) | **`gen_flow_demand.sh`** |
| Generate the `.tcl` trajectory for an NS-3 run | **`build_sumo_trace.sh`** |
| Rebuild roads from a new/different OSM map | **`build_sumo_trace.sh`** |

---

## Commands

### Generate + watch a flowing scene (demo)
```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35/sumo
./gen_flow_demand.sh urban urban.net.xml 450 600   # DIR NET SPREAD END
sumo-gui -c urban/flow.sumocfg
```
In SUMO-GUI: **View → Vehicles → Color by → "given/assigned vehicle color"**
to see the per-type colours (else everything is yellow).
See `FLOW_DEMAND.md` for the colour/shape table and measured results.

### Generate the NS-3 trajectory and run NS-3
```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35/sumo
./build_sumo_trace.sh            # writes mobility/mobility_urban_<speed>.tcl
cd /home/niranga/ns-allinone-3.35/ns-3.35
./waf --run "mptd_pqs_sdvn --mobility_source=1"
```

---

## What to open, to view what

| To view… | Open | With |
|----------|------|------|
| Moving traffic (the demo) | `urban/flow.sumocfg` | `sumo-gui -c urban/flow.sumocfg` |
| Just the roads / map | `urban/urban.net.xml` | `netedit urban.net.xml` |
| The raw OSM | `urban/urban.osm` | openstreetmap.org / JOSM |

---

## Feeding the *flowing* demand into NS-3 (optional, not yet done)

`gen_flow_demand.sh` makes a nice SUMO-GUI scene but stops at `flow.sumocfg`.
To run that *same* 200-vehicle demand inside NS-3 you would:

1. Export a `.tcl` trajectory from `flow.sumocfg`
   (`sumo --fcd-output` → `traceExporter.py`, same final steps as
   `build_sumo_trace.sh`).
2. Point NS-3 at it with `--mobility_source=1`.

> **Blocker:** NS-3 currently sizes its per-vehicle arrays for 16 vehicles
> (`total_size=16`, `MAX_NODES=40` in `02_config_globals.h`). A 200-vehicle
> trace overflows them (SIGSEGV / 0 beacons). The `total_size`/`MAX_NODES`
> scale-up must land **before** the flowing demand can drive an NS-3 run.

---

## Summary

- OSM gives roads, SUMO adds vehicles + movement, NS-3 replays the `.tcl`.
- Everything is script-generated; nothing is hand-authored.
- **`build_sumo_trace.sh`** → the NS-3 trajectory (`.tcl`).
- **`gen_flow_demand.sh`** → the busy, flowing SUMO-GUI demo scene.
