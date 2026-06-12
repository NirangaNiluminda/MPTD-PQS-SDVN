#!/usr/bin/env bash
# gen_flow_demand.sh — generate a BUSY-BUT-FLOWING SUMO demand for a given .net.xml
#
# WHY: the build_sumo_trace.sh routes use --intermediate (looping trips that never
# exit), so vehicles accumulate until the grid gridlocks. For a realistic urban
# scene that *flows*, vehicles must enter at the map fringe, cross, and EXIT.
# This script generates point-to-point fringe trips, spreads departures over a
# window, and bakes in per-type color / guiShape / maxSpeed / length so SUMO-GUI
# shows a distinct, moving, multi-class urban stream.
#
# USAGE:  ./gen_flow_demand.sh [DIR] [NET] [SPREAD] [END]
#   DIR     default urban
#   NET     default urban.net.xml   (relative to DIR)
#   SPREAD  default 300   departures spread over [0,SPREAD]s
#   END     default 600   simulation length
#
# OUTPUT: DIR/routes_<name>_flow.rou.xml (×5) + DIR/flow.sumocfg
# Then:   sumo-gui -c DIR/flow.sumocfg
set -euo pipefail

DIR="${1:-urban}"
NET="${2:-urban.net.xml}"
SPREAD="${3:-450}"
END="${4:-600}"
SEED=42
SUMO_HOME="${SUMO_HOME:-/usr/share/sumo}"

cd "$(dirname "$0")/$DIR"

#                name   vClass     count vmax    len   color      guiShape
VEH=(
  "car    passenger 100 41.67 4.5  1,0,0   passenger"
  "bus    bus        25 27.78 12.0 0,0,1   bus"
  "lorry  truck      25 25.00 7.5  0,0.8,0 truck"
  "van    delivery   25 33.33 5.5  1,0.6,0 delivery"
  "truck  truck      25 23.61 10.0 1,0,1   truck/trailer"
)

ROUTE_BASENAMES=()
idx=0
for row in "${VEH[@]}"; do
  read -r name vclass count vmax vlen color shape <<<"$row"
  # over-generate 1.5x (--validate drops disconnected trips), then uniformly
  # subsample exactly `count` so departures stay spread across the whole window.
  period=$(python3 -c "print(f'{$SPREAD/($count*1.5):.4f}')")
  echo "[gen] $name x$count (vClass=$vclass) over ${SPREAD}s, period=${period}s"
  python3 "$SUMO_HOME/tools/randomTrips.py" -n "$NET" \
    -o "trips_${name}_flow.xml" -r "routes_${name}_flow.rou.xml" \
    --begin 0 --end "$SPREAD" --period "$period" \
    --fringe-factor 10 --min-distance 800 \
    --vehicle-class "$vclass" --prefix "${name}f" \
    --seed "$((SEED + idx))" --validate >/dev/null 2>&1
  python3 - "routes_${name}_flow.rou.xml" "$count" "$vmax" "$vlen" "$color" "$shape" "$SPREAD" <<'PY'
import sys, xml.etree.ElementTree as ET
f, count, vmax, vlen, color, shape, spread = sys.argv[1], int(sys.argv[2]), *sys.argv[3:7], float(sys.argv[7])
t = ET.parse(f); root = t.getroot()
for vt in root.findall("vType"):
    vt.set("maxSpeed", vmax); vt.set("length", vlen)
    vt.set("color", color); vt.set("guiShape", shape)
veh = root.findall("vehicle")
veh.sort(key=lambda e: float(e.get("depart")))
# uniform subsample to `count`, then re-space departs evenly over [0,spread]
if len(veh) > count:
    step = len(veh) / count
    keep = {int(i*step) for i in range(count)}
    veh = [v for j, v in enumerate(veh) if j in keep]
for v in root.findall("vehicle"):
    root.remove(v)
n = len(veh); dt = spread/n if n > 1 else 0.0
for k, v in enumerate(veh):
    v.set("depart", f"{k*dt:.2f}")
    root.append(v)
t.write(f, encoding="UTF-8", xml_declaration=True)
print(f"      -> kept {n} {f}")
PY
  ROUTE_BASENAMES+=("routes_${name}_flow.rou.xml")
  idx=$((idx + 1))
done

ROUTES_CSV=$(IFS=,; echo "${ROUTE_BASENAMES[*]}")
cat > flow.sumocfg <<EOF
<configuration>
    <input>
        <net-file value="$NET"/>
        <route-files value="$ROUTES_CSV"/>
    </input>
    <time>
        <begin value="0"/>
        <end value="$END"/>
        <step-length value="1.0"/>
    </time>
    <processing>
        <time-to-teleport value="120"/>
        <ignore-route-errors value="true"/>
    </processing>
</configuration>
EOF
echo "[gen] wrote flow.sumocfg (routes: $ROUTES_CSV, end=${END}s)"

echo "[measure] sumo headless ${END}s ..."
sumo -c flow.sumocfg --summary /tmp/flow_summary.xml --statistics-output /tmp/flow_stats.xml \
     --no-step-log --no-warnings --end "$END" >/dev/null 2>&1 || true
python3 - <<'PY'
import xml.etree.ElementTree as ET
peak=peakt=0
for _,el in ET.iterparse('/tmp/flow_summary.xml'):
    if el.tag=='step':
        r=int(el.get('running','0'))
        if r>peak: peak,peakt=r,float(el.get('time','0'))
        el.clear()
print(f"      PEAK CONCURRENT = {peak} vehicles (at t={peakt:.0f}s)")
try:
    s=ET.parse('/tmp/flow_stats.xml').getroot()
    tp=s.find('teleports');
    if tp is not None: print(f"      TELEPORTS total={tp.get('total')} jam={tp.get('jam')} yield={tp.get('yield')} wrongLane={tp.get('wrongLane')}")
    co=s.find('safety')
    if co is not None: print(f"      COLLISIONS={co.get('collisions')}")
    vt=s.find('vehicleTripStatistics')
    if vt is not None: print(f"      mean trip duration={vt.get('duration')}s, mean speed={vt.get('speed')}m/s")
except Exception as e: print('stats:',e)
PY
echo "[done] visualise:  sumo-gui -c $DIR/flow.sumocfg"
