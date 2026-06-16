# SUMO Flowing Demand — Busy-but-Flowing Urban Traffic

How to generate a realistic, multi-class urban traffic scene in SUMO that is
**busy** (≈200 vehicles, ~140 concurrent) yet **flows** (no gridlock), with each
vehicle type shown in a distinct **colour and shape**.

This is a SUMO-only data/config workflow. **No NS-3 C++ code is involved.**

---

## 0. Update (2026-06-15): burst-spawn for screenshots (supervisor directive)

For the **screenshot / NetAnim deliverable** the supervisor requires the *full*
fleet to be **co-present** in one frame. The "spread departures over a window"
demand in §2 ramps up gradually, so any single screenshot shows only a fraction
of the fleet. The directive is the opposite: **spawn every vehicle at `t=0`**,
let lane-insertion capacity drain the queue (this fill-in time is the
**warmup**), then screenshot once the network is at full density.

Each scenario therefore has a **burst-spawn view route file** and a
`view.sumocfg`:

| Scenario  | `sumo/<dir>/` | View config (`view.sumocfg` → route) | Fleet | Full-density (warmup) | Screenshot at |
|-----------|---------------|--------------------------------------|-------|-----------------------|---------------|
| Urban     | `urban/`      | `routes_view_burst.rou.xml`          | 200   | ≈5 s                  | t ≥ 5 s       |
| Rural     | `rural/`      | `routes_view_burst.rou.xml`          | 138   | ≈55 s (133 by 20 s)   | t ≈ 30–55 s   |
| Autobahn  | `autobahn/`   | `routes_view_burst.rou.xml`          | 200   | ≈69 s                 | t ≈ 70–120 s  |

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35/sumo
sumo-gui -c urban/view.sumocfg      # let it run to ≥5 s, then screenshot
sumo-gui -c rural/view.sumocfg      # run to ≈55 s
sumo-gui -c autobahn/view.sumocfg   # run to ≈70 s
```

Why the warmup differs: urban has many fringe entry edges so all 200 enter
within ~5 s; the rural network is sparse; the autobahn is a single ~7 km
corridor whose two-lane on-ramps cap the insertion rate (so 200 take ~70 s to
fill, after which they co-exist along the corridor without gridlock). The
NS-3/NetAnim `.tcl` trace is already warmup-shifted (§ build_sumo_trace.sh
step [5]), so NetAnim shows the full co-present fleet from its t=0.

> The §2–§4 "spread over a window" workflow below is retained for the *flowing
> demo / clip* use case; the burst-spawn views above are the ones used for the
> full-fleet screenshots.

---

## 1. Why the old scene was congested (and why it was NOT the map's fault)

The OSM map / `urban.net.xml` describes **roads only** — it contains zero
vehicles. Vehicles come from a *separately generated demand* (`routes_*.rou.xml`).
The original demand had two flaws:

1. **All ~273 vehicles departed in the first 20 s** (`INSERT_WINDOW=20` in
   `build_sumo_trace.sh`) → the grid was flooded instantly.
2. Trips were built with `--intermediate` → **looping routes that never exit**
   the map → vehicles piled up until everything jammed (teleports, frozen rows).

So congestion is a **demand** artefact. The fix lives entirely in demand
generation — never in the map.

---

## 2. The fix: `gen_flow_demand.sh`

A reusable generator that produces flowing demand for any `.net.xml`:

- Vehicles **enter at the map fringe → cross → exit** (`--fringe-factor 10`,
  `--min-distance 800`, *no* `--intermediate`), so concurrent count stays bounded.
- Departures are **spread uniformly over a window** (default 450 s) so the
  network ramps up smoothly instead of flooding.
- Per-type **colour, shape, max speed, length** are baked into each `vType`.
- Over-generates 1.5× then uniformly subsamples to **exact** target counts
  (`--validate` drops disconnected trips, so we generate extra and trim).
- Runs `sumo` headless at the end and reports peak concurrent + teleports.

### Run it

```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35/sumo
./gen_flow_demand.sh [DIR] [NET] [SPREAD] [END]
# defaults:           urban  urban.net.xml  450     600
```

Outputs (in `urban/`):
- `routes_<type>_flow.rou.xml` ×5  (originals `routes_*.rou.xml` left untouched)
- `flow.sumocfg`  (ready to open)

### Visualise

```bash
sumo-gui -c urban/flow.sumocfg
```

In SUMO-GUI set **View → Vehicles → Color by → "given/assigned vehicle color"**
so the per-type colours below are shown (otherwise everything is yellow).

---

## 3. Colour & shape code

| Type  | Count | vClass    | Colour (RGB)   | Swatch        | guiShape        | maxSpeed   | length |
|-------|-------|-----------|----------------|---------------|-----------------|------------|--------|
| car   | 100   | passenger | `1,0,0`        | 🔴 red        | `passenger`     | 41.67 m/s  | 4.5 m  |
| bus   | 25    | bus       | `0,0,1`        | 🔵 blue       | `bus`           | 27.78 m/s  | 12.0 m |
| lorry | 25    | truck     | `0,0.8,0`      | 🟢 green      | `truck`         | 25.00 m/s  | 7.5 m  |
| van   | 25    | delivery  | `1,0.6,0`      | 🟠 orange     | `delivery`      | 33.33 m/s  | 5.5 m  |
| truck | 25    | truck     | `1,0,1`        | 🟣 magenta    | `truck/trailer` | 23.61 m/s  | 10.0 m |

**Total = 200 vehicles (100 cars + 100 other).**

These attributes live on the `<vType>` element of each route file, e.g.:

```xml
<vType id="carf_passenger" vClass="passenger" maxSpeed="41.67" length="4.5"
       color="1,0,0" guiShape="passenger"/>
```

To change a colour/shape, edit the `VEH=(...)` table at the top of
`gen_flow_demand.sh` and re-run — the values are reapplied to every vehicle.

---

## 4. Verified result (SPREAD=450, END=600)

| Metric                       | Value                          |
|------------------------------|--------------------------------|
| Composition                  | 100 car, 25 bus, 25 lorry, 25 van, 25 truck |
| Peak concurrent              | **141 vehicles** (t≈414 s)     |
| Teleports in first 300 s     | **3**                          |
| Total teleports / collisions | 20 / **0**                     |

Running-vehicle ramp (steady, no flooding):

| t (s)   | 60 | 120 | 180 | 240 | **300** | 360 | 450 | 600 |
|---------|----|-----|-----|-----|---------|-----|-----|-----|
| running | 30 | 55  | 85  | 105 | **122** | 131 | 139 | 91  |
| halting | 9  | 23  | 24  | 54  | 43      | 53  | 52  | 66  |

`halting < running` throughout → vehicles wait at red lights, not gridlock.
The few teleports are `yield` timeouts at a handful of unregulated OSM junctions
(a vehicle waiting >120 s is teleported by SUMO); they are not collisions or
network-wide jams.

---

## 5. Tuning for other maps / densities

| Want                         | Change                                         |
|------------------------------|------------------------------------------------|
| Fewer concurrent / less jam  | raise `SPREAD` (e.g. 450 → 600)                |
| Busier scene                 | raise per-type counts in the `VEH=(...)` table |
| Different city               | pass a different `NET` (`.net.xml`)            |
| Longer demo                  | raise `END`                                    |

> Note: this 2 km × 2 km grid gridlocks above ~200 concurrent vehicles. Keep
> peak concurrent ≲ 150 for clean flow on a map this size.
