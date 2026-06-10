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
# Example (Shinjuku urban, the locked map, supervisor-approved 2026-06-10):
#   ./build_sumo_trace.sh urban urban 60 "35.685,139.698,35.700,139.715" 5 15 42
# ─────────────────────────────────────────────────────────────────────────
set -euo pipefail

REGIME="${1:?regime dir name, e.g. urban}"
TAG="${2:?selector tag: urban|rural|autobahn}"
SPEED="${3:?speed tag for filename, matches --maxspeed}"
BBOX="${4:?bbox as S,W,N,E (lat,lon,lat,lon)}"
WARMUP="${5:-5}"
WINDOW="${6:-15}"     # must be >= NS-3 simTime
SEED="${7:-42}"

: "${SUMO_HOME:?SUMO_HOME must be set}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS3_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK="$SCRIPT_DIR/$REGIME"
mkdir -p "$WORK"; cd "$WORK"

# Overpass bbox is S,W,N,E; build the query for highway ways + their nodes only
IFS=',' read -r S W N E <<< "$BBOX"
echo "[1/5] downloading roads-only OSM extract for bbox S=$S W=$W N=$N E=$E"
if [ ! -s "$REGIME.osm" ]; then
  Q="[out:xml][timeout:180];(way[\"highway\"]($S,$W,$N,$E););(._;>;);out body;"
  curl -s -m 200 -o "$REGIME.osm" --data-urlencode "data=$Q" \
    "https://overpass-api.de/api/interpreter"
fi
grep -q "<way" "$REGIME.osm" || { echo "OSM download failed"; exit 1; }

echo "[2/5] netconvert → $REGIME.net.xml (passenger-drivable roads only)"
netconvert --osm-files "$REGIME.osm" -o "$REGIME.net.xml" \
  --type-files "$SUMO_HOME/data/typemap/osmNetconvert.typ.xml" \
  --geometry.remove --ramps.guess --junctions.join \
  --tls.guess-signals --tls.discard-simple --tls.join \
  --remove-edges.isolated --keep-edges.by-vclass passenger \
  --osm.elevation false --no-turnarounds.tls true

echo "[3/5] randomTrips → demand front-loaded into first 2s, validated"
python3 "$SUMO_HOME/tools/randomTrips.py" -n "$REGIME.net.xml" \
  -o trips.xml -r routes.rou.xml \
  --begin 0 --end 2 --period 0.01 --fringe-factor 5 \
  --vehicle-class passenger --prefix veh --seed "$SEED" --validate

echo "[4/5] sumo --fcd-output (warmup + window), then warmup-shift to t=0"
sumo -n "$REGIME.net.xml" -r routes.rou.xml --fcd-output fcd.xml \
  --begin 0 --end "$(echo "$WARMUP + $WINDOW + 5" | bc)" \
  --step-length 1.0 --no-step-log --no-warnings
python3 - "$WARMUP" "$WINDOW" <<'PY'
import sys, xml.etree.ElementTree as ET
WARMUP=float(sys.argv[1]); WINDOW=float(sys.argv[2])
root=ET.parse('fcd.xml').getroot()
keep=set()
for ts in root.findall('timestep'):
    if abs(float(ts.get('time'))-WARMUP)<1e-6:
        keep={v.get('id') for v in ts.findall('vehicle')}; break
out=ET.Element('fcd-export'); n=0
for ts in root.findall('timestep'):
    t=float(ts.get('time'))
    if t<WARMUP-1e-6 or t>WARMUP+WINDOW+1e-6: continue
    nts=ET.SubElement(out,'timestep',{'time':f"{t-WARMUP:.2f}"})
    for v in ts.findall('vehicle'):
        if v.get('id') in keep:
            ET.SubElement(nts,'vehicle',v.attrib); n+=1
ET.ElementTree(out).write('fcd_shifted.xml',encoding='UTF-8',xml_declaration=True)
print(f"      kept {len(keep)} vehicles, window 0..{WINDOW:.0f}s, {n} records")
PY

echo "[5/5] traceExporter → mobility/mobility_${TAG}_${SPEED}.tcl"
python3 "$SUMO_HOME/tools/traceExporter.py" --fcd-input fcd_shifted.xml \
  --ns2mobility-output "$NS3_ROOT/mobility/mobility_${TAG}_${SPEED}.tcl" \
  --begin 0 --end "$(echo "$WINDOW + 1" | bc)"

NODES=$(grep -oE 'node_\(([0-9]+)\)' "$NS3_ROOT/mobility/mobility_${TAG}_${SPEED}.tcl" | sort -u | wc -l)
echo "DONE: mobility_${TAG}_${SPEED}.tcl  ($NODES vehicles)"
echo "Run NS-3 with:  --mobility_source=1 --mobility_scenario=<0|1|2> --maxspeed=${SPEED}"
