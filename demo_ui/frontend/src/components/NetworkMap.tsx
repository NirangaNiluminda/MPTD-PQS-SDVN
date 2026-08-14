import DeckGL from "@deck.gl/react";
import { OrthographicView, Color } from "@deck.gl/core";
import { ScatterplotLayer, LineLayer } from "@deck.gl/layers";
import { usePlayback } from "../store/playback";

// Sim coordinates are plain meters on an arbitrary local origin (not lon/lat),
// so we use an OrthographicView rather than deck.gl's default geo view.
// y is left as the simulator reports it — flip the sign here if "up" on
// screen should mean "north" for a given trace; purely a display choice.
const INITIAL_VIEW_STATE = {
  target: [1650, 1450, 0] as [number, number, number], // ~centre of the urban trace bounds
  zoom: -1.2,
};

const COLORS: Record<string, Color> = {
  honest: [140, 150, 165, 200],
  poisonedDetected: [255, 176, 40, 230],
  poisonedMissed: [255, 70, 70, 240], // is_poisoned but NOT detected — a real false negative
  ghost: [205, 70, 225, 230],
  rsu: [70, 210, 230, 180],
  rsuCoverage: [70, 210, 230, 18],
  rubberBand: [255, 255, 255, 90],
};

function beaconColor(b: {
  is_ghost: boolean;
  is_poisoned: boolean;
  detected: boolean;
}): Color {
  if (b.is_ghost) return COLORS.ghost;
  if (b.is_poisoned && !b.detected) return COLORS.poisonedMissed;
  if (b.is_poisoned && b.detected) return COLORS.poisonedDetected;
  return COLORS.honest;
}

export default function NetworkMap() {
  const { geometry, positions, beacons, road } = usePlayback();

  if (!geometry) {
    return (
      <div className="flex h-full items-center justify-center text-slate-500">
        Select a scenario to load the map.
      </div>
    );
  }

  const rsuLayer = new ScatterplotLayer({
    id: "rsu-markers",
    data: geometry.rsus,
    getPosition: (d) => [d.x, d.y],
    getRadius: 14,
    radiusUnits: "meters",
    getFillColor: COLORS.rsu,
    pickable: true,
  });

  const rsuCoverageLayer = new ScatterplotLayer({
    id: "rsu-coverage",
    data: geometry.rsus,
    getPosition: (d) => [d.x, d.y],
    getRadius: geometry.r_max_comm,
    radiusUnits: "meters",
    getFillColor: COLORS.rsuCoverage,
    stroked: false,
  });

  // Base layer: the full fleet, from the mobility trace (always present,
  // regardless of whether a beacon fired at this instant).
  const fleetLayer = new ScatterplotLayer({
    id: "fleet",
    data: positions,
    getPosition: (d) => [d.x, d.y],
    getRadius: 5,
    radiusUnits: "meters",
    getFillColor: COLORS.honest,
    pickable: false,
  });

  // Overlay: beacons that actually fired detection logic this frame —
  // colored by ground truth / detection outcome, drawn on top of the fleet.
  const beaconLayer = new ScatterplotLayer({
    id: "beacons",
    data: beacons,
    getPosition: (d) => [d.pos.x, d.pos.y],
    getRadius: 9,
    radiusUnits: "meters",
    getFillColor: (d) => beaconColor(d),
    pickable: true,
  });

  // Rubber-band: claimed position -> actual (ground-truth) position.
  // Never drawn for ghosts (has_ground_truth is false server-side -> gt_pos null).
  const rubberBandData = beacons.filter(
    (b) => b.gt_pos !== null && b.is_poisoned
  );
  const rubberBandLayer = new LineLayer({
    id: "rubber-bands",
    data: rubberBandData,
    getSourcePosition: (d) => [d.pos.x, d.pos.y],
    getTargetPosition: (d) => [d.gt_pos!.x, d.gt_pos!.y],
    getColor: COLORS.rubberBand,
    getWidth: 2,
    widthUnits: "pixels",
  });

  return (
    <DeckGL
      views={new OrthographicView({ id: "map" })}
      initialViewState={INITIAL_VIEW_STATE}
      controller={true}
      layers={[
        rsuCoverageLayer,
        rsuLayer,
        fleetLayer,
        rubberBandLayer,
        beaconLayer,
      ]}
      getTooltip={({ object }) =>
        object &&
        ("vehicle_id" in object
          ? {
              text: `V${object.vehicle_id}${
                object.is_ghost ? " (ghost)" : ""
              }\n${object.is_poisoned ? "POISONED" : "clean"} / ${
                object.detected ? "detected" : "MISSED"
              }${
                object.drift_m != null
                  ? `\ndrift: ${object.drift_m.toFixed(0)} m`
                  : ""
              }`,
            }
          : "rsu_id" in object
          ? { text: `RSU${object.rsu_id}` }
          : null)
      }
    >
      <div className="pointer-events-none absolute left-3 top-3 rounded bg-black/50 px-2 py-1 text-xs text-slate-300">
        {road} · {geometry.rsus.length} RSUs · {positions.length} vehicles ·{" "}
        {beacons.length} beacons this frame
      </div>
    </DeckGL>
  );
}
