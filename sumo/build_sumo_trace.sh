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
# OVERGEN env-overridable: highway/rural regimes need more over-generation
# because fast transit + sparse routes lose more vehicles before window end.
OVERGEN="${OVERGEN:-1.8}"
# FRINGE env-overridable: randomTrips --fringe-factor biases trips to start/end
# at network-boundary edges (through-traffic). Highway regimes want this HIGH
# (e.g. 50) so vehicles enter/exit at the motorway ends and drive its full
# length, instead of looping on surface streets and leaving the motorway empty.
FRINGE="${FRINGE:-5}"
# MINDIST env-overridable: randomTrips --min-distance (metres). Highway regimes
# want this LARGE so each vehicle traverses most of the mainline and stays
# present for the whole export window (short trips exit mid-window and are
# dropped by the full-window-presence filter, starving the survivor count).
MINDIST="${MINDIST:-600}"

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
SIDE="${SIDE_M:-2000}"   # metres per side (supervisor: urban 2 km; highway needs a longer strip — override via SIDE_M)
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
def crosses_box(e):
    # True if the edge's geometry intersects the crop box (bbox-overlap test on
    # its lane shape). Used for motorway edges so a long through-edge that merely
    # straddles the box border is kept WHOLE — the highway stays continuous
    # across the map instead of being chopped into a stub by the strict
    # both-endpoints rule — without dragging the whole 7 km A9 into the net.
    for lane in e.findall('lane'):
        xs=[];ys=[]
        for p in lane.get('shape','').split():
            x,y=map(float,p.split(',')); xs.append(x); ys.append(y)
        if xs and min(xs)<=bx1 and max(xs)>=bx0 and min(ys)<=by1 and max(ys)>=by0:
            return True
    return False
keep=[]
mw=0
for e in root.findall('edge'):
    if e.get('function')=='internal': continue
    et=e.get('type') or ''
    if et.startswith('highway.motorway'):
        if crosses_box(e):
            keep.append(e.get('id')); mw+=1
        continue
    if inside(e.get('from')) and inside(e.get('to')):
        keep.append(e.get('id'))
open(out,'w').write("\n".join(keep)+"\n")
print(f"      box=({bx0:.0f},{by0:.0f})-({bx1:.0f},{by1:.0f})m, kept {len(keep)} edges ({mw} motorway edges crossing box kept whole)")
PY
netconvert -s "${REGIME}_full.net.xml" -o "$REGIME.net.xml" \
  --keep-edges.input-file keep_edges.txt --remove-edges.isolated

# MW_BIAS env (highway regime): weight every motorway edge as a randomTrips
# src/dst so generated traffic is highway-dominant instead of looping on surface
# streets and leaving the motorway empty. Builds mwbias.src.xml / mwbias.dst.xml
# from the cropped net; passed via --weights-prefix below. Leave MW_BIAS unset
# for urban/rural (uniform edge selection).
WEIGHT_ARGS=()
if [ -n "${MW_BIAS:-}" ]; then
  python3 - "$REGIME.net.xml" "$MW_BIAS" <<'PY'
import sys, xml.etree.ElementTree as ET
net, w = sys.argv[1], sys.argv[2]
root = ET.parse(net).getroot()
# Weight ONLY the mainline carriageway (type == 'highway.motorway'), NOT the
# ramps ('highway.motorway_link'). Including ramps makes vehicles loop on the
# short interchange edges instead of driving the through-carriageway, leaving
# the mainline empty. Mainline-only src+dst makes them traverse the A9 itself.
mw = [e.get('id') for e in root.iter('edge')
      if e.get('function') != 'internal' and (e.get('type') or '') == 'highway.motorway']
# Weight BOTH source and destination onto the motorway so the whole trip runs
# along the highway — the only way vehicles are genuinely ON the carriageway for
# the export window (dst-only just routes them toward it; they spend the window
# on surface approach roads). Trades total count (one corridor congests) for a
# visibly populated highway, which is the point of the autobahn scenario.
for tag in ('src', 'dst'):
    with open(f'mwbias.{tag}.xml', 'w') as f:
        f.write('<edgedata>\n  <interval begin="0" end="100000">\n')
        for eid in mw:
            f.write(f'    <edge id="{eid}" value="{w}"/>\n')
        f.write('  </interval>\n</edgedata>\n')
print(f"      MW_BIAS={w}: weighted {len(mw)} motorway edges as trip src+dst")
PY
  WEIGHT_ARGS=(--weights-prefix mwbias)
fi

ROUTE_FILES=()
if [ -n "${MW_FLOW:-}" ]; then
  # ── Highway flow mode (MW_FLOW = per-type over-generation factor) ──────────
  # randomTrips picks arbitrary O-D pairs, so on a single motorway corridor most
  # trips are starved by min-distance/fringe filtering (→ very few vehicles) and
  # those that survive enter the carriageway then turn off onto a surface road
  # (→ not "straight on the highway"). Instead, emit continuous SUMO <flow>s that
  # run end-to-end along each carriageway (corridor entry edge → far exit edge),
  # so every vehicle traverses the full mainline and the count is set directly by
  # the insertion rate. A long warmup (auto-bumped below) lets the ~7 km corridor
  # fill before the export window opens.
  echo "[3/6] highway flow mode: end-to-end corridor flows (over-generate ${MW_FLOW}×)"
  python3 - "$REGIME.net.xml" "$MW_FLOW" "${VEH_NAME[*]}" "${VEH_CLASS[*]}" "${VEH_VMAX[*]}" "${VEH_LEN[*]}" "${VEH_COUNT[*]}" <<'PY'
import sys, math, xml.etree.ElementTree as ET
net=sys.argv[1]; overgen=float(sys.argv[2])
names=sys.argv[3].split(); vclass=sys.argv[4].split()
vmax=[float(x) for x in sys.argv[5].split()]; vlen=[float(x) for x in sys.argv[6].split()]
counts=[int(x) for x in sys.argv[7].split()]
root=ET.parse(net).getroot()
mw={}
for e in root.findall('edge'):
    if e.get('function')=='internal': continue
    if (e.get('type') or '')=='highway.motorway':      # mainline only, not _link ramps
        mw[e.get('id')]=(e.get('from'),e.get('to'))
froms=set(f for f,_ in mw.values()); tos=set(t for _,t in mw.values())
jx={j.get('id'):(float(j.get('x')),float(j.get('y')))
    for j in root.findall('junction') if j.get('function')!='internal'}
# corridor entries = mainline edges whose 'from' is fed by no other mainline edge;
# exits = mainline edges whose 'to' feeds no other mainline edge.
sources=[eid for eid,(f,t) in mw.items() if f not in tos]
sinks=[eid for eid,(f,t) in mw.items() if t not in froms]
# pair each entry with the farthest exit (opposite corridor end) → full traversal.
pairs=[]; used=set()
for s in sources:
    sf=jx[mw[s][0]]; best=None; bd=-1
    for k in sinks:
        if k in used: continue
        kt=jx[mw[k][1]]; d=math.hypot(kt[0]-sf[0],kt[1]-sf[1])
        if d>bd: bd=d; best=k
    if best is not None: pairs.append((s,best,bd)); used.add(best)
if not pairs: sys.exit("ERROR: no motorway corridor (no highway.motorway entry/exit edges found)")
T=sum(d for *_,d in pairs)/len(pairs)/28.0           # mean traversal at ~28 m/s (mixed fleet)
open('corridor_T.txt','w').write(f"{T:.1f}\n")
lines=['<routes>']
for n,vc,vm,vl in zip(names,vclass,vmax,vlen):
    lines.append(f'    <vType id="{n}_{vc}" vClass="{vc}" maxSpeed="{vm}" length="{vl}" />')
for n,vc,cnt in zip(names,vclass,counts):
    period=len(pairs)*T/(overgen*max(cnt,1))          # rate that holds ~overgen×cnt present
    for pi,(src,dst,_) in enumerate(pairs):
        lines.append(f'    <flow id="f{pi}_{n}" type="{n}_{vc}" from="{src}" to="{dst}" '
                     f'begin="0" end="100000" period="{period:.3f}" '
                     f'departLane="free" departSpeed="max"/>')
lines.append('</routes>')
open('routes_flow.rou.xml','w').write("\n".join(lines)+"\n")
print(f"      {len(pairs)} corridor pair(s), mean traversal ~{T:.0f}s; "
      f"{len(names)} vTypes flowed (target mix held at {overgen}× before window-select)")
PY
  ROUTE_FILES=("routes_flow.rou.xml")
  # corridor must fill before the export window; bump WARMUP to traversal time +10s
  NEED=$(echo "($(cat corridor_T.txt) + 10)/1" | bc)
  if [ "$(echo "$WARMUP < $NEED" | bc)" -eq 1 ]; then
    echo "      WARMUP $WARMUP → $NEED s (corridor fill time) so window opens on a full highway"
    WARMUP="$NEED"
  fi
else
  echo "[3/6] randomTrips per vehicle type (over-generate ${OVERGEN}×, spread over ${INSERT_WINDOW}s)"
  for i in "${!VEH_NAME[@]}"; do
    name="${VEH_NAME[$i]}"; vclass="${VEH_CLASS[$i]}"; count="${VEH_COUNT[$i]}"
    gen=$(echo "($count * $OVERGEN)/1" | bc)            # over-generate (integer)
    period=$(echo "scale=6; $INSERT_WINDOW / $gen" | bc)
    echo "      • $name (vClass=$vclass, target=$count, generate≈$gen, period=${period}s)"
    python3 "$SUMO_HOME/tools/randomTrips.py" -n "$REGIME.net.xml" \
      -o "trips_${name}.xml" -r "routes_${name}.rou.xml" \
      --begin 0 --end "$INSERT_WINDOW" --period "$period" \
      --fringe-factor "$FRINGE" --intermediate 5 --min-distance "$MINDIST" \
      "${WEIGHT_ARGS[@]}" \
      --vehicle-class "$vclass" --prefix "$name" --seed "$((SEED + i))" --validate
    ROUTE_FILES+=("routes_${name}.rou.xml")
  done
fi

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
