#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────
# build_sumo_trace.sh — OSM → SUMO → ns-2 mobility trace pipeline
#
# Produces $NS3_ROOT/mobility/mobility_<tag>_<speed>.tcl, the file consumed by
# the NS-3 FcdTraceMobilityProvider (09b_mobility_provider.h) when run with
#   --mobility_source=1 --mobility_scenario=<0|1|2> --maxspeed=<speed>
#
# Paper §4.1.3 speed regimes → selector tags (default_sumo_trace_path()):
#   scenario 0 = urban     → tag "urban"
#   scenario 1 = non-urban → tag "rural"
#   scenario 2 = highway   → tag "autobahn"
#
# Supervisor spec (2026-06-10, urban regime, HPC realistic run):
#   • measured ~2 km × 2 km region (OSM extract CLIPPED to a 2 km geo-box, so
#     the built network — not just the download bbox — is ~2 km per side)
#   • 200 vehicles, 5 SUMO vehicle types with realistic per-type max speeds:
#       100 cars   (vClass passenger, maxSpeed 150 km/h = 41.67 m/s, len 4.5 m)
#        25 buses  (vClass bus,       maxSpeed 100 km/h = 27.78 m/s, len 12 m)
#        25 lorries(vClass truck,     maxSpeed  90 km/h = 25.00 m/s, len 7.5 m)
#        25 vans   (vClass delivery,  maxSpeed 120 km/h = 33.33 m/s, len 5.5 m)
#        25 trucks (vClass truck,     maxSpeed  85 km/h = 23.61 m/s, len 10 m)
#   NOTE: maxSpeed is the vehicle's engine cap. SUMO also obeys each road's
#   OSM speed limit and uses the MINIMUM, so 150 km/h only materialises on a
#   road that actually allows it (urban side-streets stay ~50 km/h). This is
#   realistic and intended.
#   NOTE on "truck": SUMO's articulated vClass `trailer` (~16 m) cannot be
#   inserted on the short edges of a dense Tokyo grid (insertion fails → 0
#   trucks). We model both lorry and truck as rigid vClass `truck`, kept
#   distinct by length/maxSpeed (lorry 7.5 m/90 km/h vs truck 10 m/85 km/h).
#   This is routable and realistic for a dense urban map.
#
# Why a warmup-shift step (the non-obvious part):
#   SUMO populates the network gradually (insertion is lane-limited), so at
#   t=0 only a few vehicles exist. An NS-3 node mapped to a not-yet-departed
#   vehicle would sit frozen at the origin (0,0,0) → corrupt early beacons.
#   We therefore let SUMO run a WARMUP, keep only vehicles present at the
#   warmup boundary, take the next WINDOW seconds, and subtract WARMUP from
#   all timestamps so the exported trace starts fully populated at t=0.
#
# Usage:
#   ./build_sumo_trace.sh <regime> <tag> <speed> <bbox S,W,N,E> [warmup] [window] [seed]
# Example (Shinjuku urban, measured 2 km × 2 km, supervisor-approved 2026-06-10):
#   ./build_sumo_trace.sh urban urban 150 "35.683517,139.695438,35.701483,139.717562" 10 15 42
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

REGIME="${1:?regime dir name, e.g. urban}"
TAG="${2:?selector tag: urban|rural|autobahn}"
SPEED="${3:?speed tag for filename, matches --maxspeed}"
BBOX="${4:?bbox as S,W,N,E (lat,lon,lat,lon)}"
WARMUP="${5:-25}"
WINDOW="${6:-15}"     # must be >= NS-3 simTime
SEED="${7:-42}"

# ── Vehicle mix (supervisor spec). Parallel arrays: name vclass maxspeed(m/s) length(m) count
#    To re-tune the regime, edit these arrays in lock-step.
VEH_NAME=(car      bus   lorry van      truck)
VEH_CLASS=(passenger bus  truck delivery truck)
VEH_VMAX=(41.67    27.78 25.00 33.33    23.61)
VEH_LEN=(4.5       12.0  7.5   5.5      10.0)
VEH_COUNT=(100     25    25    25       25)
# Departures are SPREAD over [0, INSERT_WINDOW] (not bunched) so 200 vehicles
# insert without congestion-discard; we OVER-GENERATE by OVERGEN to absorb
# route-validation losses + insertion failures, then select the exact target
# counts that survive the whole export window (see step [5]).
INSERT_WINDOW=20.0
OVERGEN=1.8

: "${SUMO_HOME:?SUMO_HOME must be set}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS3_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK="$SCRIPT_DIR/$REGIME"
mkdir -p "$WORK"; cd "$WORK"

# Overpass bbox is S,W,N,E; build the query for highway ways + their nodes only
IFS=',' read -r S W N E <<< "$BBOX"
echo "[1/6] downloading roads-only OSM extract for bbox S=$S W=$W N=$N E=$E"
if [ ! -s "$REGIME.osm" ]; then
  Q="[out:xml][timeout:180];(way[\"highway\"]($S,$W,$N,$E););(._;>;);out body;"
  curl -s -m 200 -o "$REGIME.osm" --data-urlencode "data=$Q" \
    "https://overpass-api.de/api/interpreter"
fi
grep -q "<way" "$REGIME.osm" || { echo "OSM download failed"; exit 1; }

echo "[2/6] netconvert → $REGIME.net.xml (cropped to an exact 2 km × 2 km box)"
# Two passes are needed. Overpass returns whole ways crossing the bbox, and a
# geo-boundary keeps any straddling way's full geometry — so a one-pass clip
# still spills to ~3 km. Pass 1 builds the full net; pass 2 re-reads it and
# crops to a 2000×2000 m box centred on the network in PROJECTED metres
# (--keep-edges.in-boundary), then re-normalises the offset to (0,0).
SIDE=2000   # metres per side (supervisor: 2 km × 2 km)
netconvert --osm-files "$REGIME.osm" -o "${REGIME}_full.net.xml" \
  --type-files "$SUMO_HOME/data/typemap/osmNetconvert.typ.xml" \
  --geometry.remove --ramps.guess --junctions.join \
  --tls.guess-signals --tls.discard-simple --tls.join \
  --remove-edges.isolated \
  --osm.elevation false --no-turnarounds.tls true
# Build an edge keep-list: keep an edge only if BOTH of its endpoint junctions
# lie inside the centred 2 km box. (netconvert's --keep-edges.in-boundary keeps
# any edge that merely *touches* the box, so long through-roads survive whole
# and the net stays ~3 km. Requiring both endpoints inside crops cleanly.)
python3 - "${REGIME}_full.net.xml" "$SIDE" keep_edges.txt <<'PY'
import sys, xml.etree.ElementTree as ET
net=sys.argv[1]; side=float(sys.argv[2]); half=side/2.0; out=sys.argv[3]
root=ET.parse(net).getroot()
xmin,ymin,xmax,ymax=[float(v) for v in root.find('location').get('convBoundary').split(',')]
cx,cy=(xmin+xmax)/2,(ymin+ymax)/2
bx0,by0,bx1,by1=cx-half,cy-half,cx+half,cy+half
jx={}
for j in root.findall('junction'):
    if j.get('function')=='internal': continue
    jx[j.get('id')]=(float(j.get('x')),float(j.get('y')))
def inside(jid):
    p=jx.get(jid)
    return p and bx0<=p[0]<=bx1 and by0<=p[1]<=by1
keep=[]
for e in root.findall('edge'):
    if e.get('function')=='internal': continue
    if inside(e.get('from')) and inside(e.get('to')):
        keep.append(e.get('id'))
open(out,'w').write("\n".join(keep)+"\n")
print(f"      box=({bx0:.0f},{by0:.0f})-({bx1:.0f},{by1:.0f})m, kept {len(keep)} edges")
PY
netconvert -s "${REGIME}_full.net.xml" -o "$REGIME.net.xml" \
  --keep-edges.input-file keep_edges.txt --remove-edges.isolated

echo "[3/6] randomTrips per vehicle type (over-generate ${OVERGEN}×, spread over ${INSERT_WINDOW}s)"
ROUTE_FILES=()
for i in "${!VEH_NAME[@]}"; do
  name="${VEH_NAME[$i]}"; vclass="${VEH_CLASS[$i]}"; count="${VEH_COUNT[$i]}"
  gen=$(echo "($count * $OVERGEN)/1" | bc)            # over-generate (integer)
  period=$(echo "scale=6; $INSERT_WINDOW / $gen" | bc)
  echo "      • $name (vClass=$vclass, target=$count, generate≈$gen, period=${period}s)"
  python3 "$SUMO_HOME/tools/randomTrips.py" -n "$REGIME.net.xml" \
    -o "trips_${name}.xml" -r "routes_${name}.rou.xml" \
    --begin 0 --end "$INSERT_WINDOW" --period "$period" \
    --fringe-factor 5 --intermediate 5 --min-distance 600 \
    --vehicle-class "$vclass" --prefix "$name" --seed "$((SEED + i))" --validate
  ROUTE_FILES+=("routes_${name}.rou.xml")
done

echo "[3b/6] inject realistic per-type maxSpeed + length into each generated vType"
python3 - "${VEH_NAME[*]}" "${VEH_VMAX[*]}" "${VEH_LEN[*]}" <<'PY'
import sys, glob, xml.etree.ElementTree as ET
names = sys.argv[1].split(); vmax = sys.argv[2].split(); vlen = sys.argv[3].split()
vmap = {n: (vm, vl) for n, vm, vl in zip(names, vmax, vlen)}  # name -> (maxSpeed, length)
for f in glob.glob("routes_*.rou.xml"):
    t = ET.parse(f); root = t.getroot()
    for vt in root.findall("vType"):
        for n, (vm, vl) in vmap.items():
            if vt.get("id", "").startswith(n + "_"):   # vType id is "<name>_<vClass>"
                vt.set("maxSpeed", vm); vt.set("length", vl); break
    t.write(f, encoding="UTF-8", xml_declaration=True)
    print(f"      patched {f}: " +
          ", ".join(f"{vt.get('id')}→{vt.get('maxSpeed')}m/s,{vt.get('length')}m"
                    for vt in root.findall('vType')))
PY

ROUTES_CSV=$(IFS=,; echo "${ROUTE_FILES[*]}")
echo "[4/6] sumo --fcd-output over warmup+window (route files: $ROUTES_CSV)"
sumo -n "$REGIME.net.xml" -r "$ROUTES_CSV" --fcd-output fcd.xml \
  --begin 0 --end "$(echo "$WARMUP + $WINDOW + 5" | bc)" \
  --step-length 1.0 --no-step-log --no-warnings

echo "[5/6] warmup-shift to t=0 + select exact per-type target counts (full-window)"
python3 - "$WARMUP" "$WINDOW" "${VEH_NAME[*]}" "${VEH_COUNT[*]}" <<'PY'
import sys, xml.etree.ElementTree as ET
from collections import defaultdict
WARMUP=float(sys.argv[1]); WINDOW=float(sys.argv[2])
names=sys.argv[3].split(); counts=[int(x) for x in sys.argv[4].split()]
target=dict(zip(names,counts))
root=ET.parse('fcd.xml').getroot()

# window timesteps = those in [WARMUP, WARMUP+WINDOW]; a vehicle is eligible only
# if it is present in EVERY one of them (so NS-3 never sees it freeze/disappear).
window_steps=[ts for ts in root.findall('timestep')
              if WARMUP-1e-6 <= float(ts.get('time')) <= WARMUP+WINDOW+1e-6]
present=defaultdict(set); vtype={}
for ts in window_steps:
    for v in ts.findall('vehicle'):
        vid=v.get('id'); present[float(ts.get('time'))].add(vid); vtype[vid]=v.get('type','?')
full=set.intersection(*[present[float(ts.get('time'))] for ts in window_steps]) if window_steps else set()

def name_of(vid_type):  # vType id is "<name>_<vClass>"
    return vid_type.split('_',1)[0]

# pick exactly target[name] survivors per type (sorted for determinism)
selected=set(); chosen=defaultdict(int)
for vid in sorted(full):
    nm=name_of(vtype[vid])
    if nm in target and chosen[nm] < target[nm]:
        selected.add(vid); chosen[nm]+=1

out=ET.Element('fcd-export'); n=0
for ts in window_steps:
    t=float(ts.get('time'))
    nts=ET.SubElement(out,'timestep',{'time':f"{t-WARMUP:.2f}"})
    for v in ts.findall('vehicle'):
        if v.get('id') in selected:
            ET.SubElement(nts,'vehicle',v.attrib); n+=1
ET.ElementTree(out).write('fcd_shifted.xml',encoding='UTF-8',xml_declaration=True)

total=sum(chosen.values())
print(f"      full-window survivors available per type: "
      + ", ".join(f"{nm}={sum(1 for v in full if name_of(vtype[v])==nm)}" for nm in names))
print(f"      SELECTED {total} vehicles, window 0..{WINDOW:.0f}s, {n} records")
print("      final mix: " + ", ".join(f"{nm}={chosen[nm]}/{target[nm]}" for nm in names))
short=[nm for nm in names if chosen[nm] < target[nm]]
if short:
    print(f"      WARNING: under target for {short} — raise OVERGEN or adjust WARMUP/WINDOW")
PY

echo "[6/6] traceExporter → mobility/mobility_${TAG}_${SPEED}.tcl"
python3 "$SUMO_HOME/tools/traceExporter.py" --fcd-input fcd_shifted.xml \
  --ns2mobility-output "$NS3_ROOT/mobility/mobility_${TAG}_${SPEED}.tcl" \
  --begin 0 --end "$(echo "$WINDOW + 1" | bc)"

NODES=$(grep -oE 'node_\(([0-9]+)\)' "$NS3_ROOT/mobility/mobility_${TAG}_${SPEED}.tcl" | sort -u | wc -l)
echo "DONE: mobility_${TAG}_${SPEED}.tcl  ($NODES vehicles)"
echo "Run NS-3 with:  --mobility_source=1 --mobility_scenario=<0|1|2> --maxspeed=${SPEED} --N_Vehicles=${NODES}"
