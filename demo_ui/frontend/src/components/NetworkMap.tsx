import { useMemo, useState, useCallback } from "react";
import DeckGL from "@deck.gl/react";
import { OrthographicView, Color } from "@deck.gl/core";
import {
  ScatterplotLayer,
  LineLayer,
  PathLayer,
  IconLayer,
  PolygonLayer,
} from "@deck.gl/layers";
import { usePlayback } from "../store/playback";
import { BeaconDto } from "../api";
import { ENTITY, STATUS, hexToRgba, Rgba } from "../design/tokens";

// Sim coordinates are plain metres on a local origin (not lon/lat), so this is
// an OrthographicView, not a geo view.
const INITIAL_VIEW_STATE = {
  target: [1680, 1460, 0] as [number, number, number],
  zoom: -1.35,
  minZoom: -3,
  maxZoom: 4,
};

// Entity colours are validated (see design/tokens.ts). The CVD margin sits in
// the 6-8 band, which is legal ONLY alongside secondary encoding — hence every
// class below also differs in SHAPE and carries a text label in the legend.
const C = {
  rsu: hexToRgba(ENTITY.rsu, 235),
  rsuDim: hexToRgba(ENTITY.rsu, 120),
  coverage: hexToRgba(ENTITY.rsu, 14),
  controller: hexToRgba(ENTITY.controller, 240),
  controllerLink: hexToRgba(ENTITY.controller, 55),
  vehicle: hexToRgba(ENTITY.vehicleClean, 190),
  vehicleDim: hexToRgba(ENTITY.vehicleClean, 90),
  ghost: hexToRgba(ENTITY.ghost, 240),
  caught: hexToRgba(STATUS.caught, 245),
  missed: hexToRgba(STATUS.missed, 250),
  hostile: hexToRgba(STATUS.missed, 235),
  band: [255, 255, 255, 70] as Rgba,
  bandMissed: hexToRgba(STATUS.missed, 130),
  selected: [255, 255, 255, 255] as Rgba,
};

function beaconColor(b: BeaconDto): Color {
  if (b.is_poisoned && !b.detected) return C.missed;
  if (b.is_poisoned && b.detected) return C.caught;
  if (b.is_ghost) return C.ghost;
  return C.vehicle;
}

/** Square outline for RSUs — shape is load-bearing, not decoration. */
function squareAt(x: number, y: number, r: number) {
  return [
    [x - r, y - r],
    [x + r, y - r],
    [x + r, y + r],
    [x - r, y + r],
  ];
}

/** Diamond for controllers — visually distinct from RSU squares at any zoom. */
function diamondAt(x: number, y: number, r: number) {
  return [
    [x, y - r],
    [x + r, y],
    [x, y + r],
    [x - r, y],
  ];
}

/**
 * deck.gl draws into a WebGL canvas. If WebGL is unavailable or the GPU
 * process is blocklisted, deck renders NOTHING and throws no error — the
 * surrounding React UI keeps working, so the app looks fine while the map is
 * simply black. That silent mode cost a debugging round; detect it up front
 * and say so instead.
 */
function webglAvailable(): boolean {
  try {
    const c = document.createElement("canvas");
    return !!(c.getContext("webgl2") || c.getContext("webgl"));
  } catch {
    return false;
  }
}

export default function NetworkMap() {
  const {
    geometry,
    positions,
    beacons,
    trails,
    topology,
    layers,
    selectedVehicle,
    selectVehicle,
  } = usePlayback();

  const [glOk] = useState(webglAvailable);
  const [glError, setGlError] = useState<string | null>(null);
  // Bumping this key remounts DeckGL, which resets the view to
  // INITIAL_VIEW_STATE — the escape hatch when a stray scroll/drag has
  // panned the network off-screen.
  const [viewKey, setViewKey] = useState(0);
  const resetView = useCallback(() => setViewKey((k) => k + 1), []);

  const compromisedRsus = useMemo(
    () => new Set(topology?.compromised_rsus ?? []),
    [topology]
  );

  const deckLayers = useMemo(() => {
    if (!geometry) return [];
    const L: any[] = [];

    if (layers.coverage) {
      L.push(
        new ScatterplotLayer({
          id: "rsu-coverage",
          data: geometry.rsus,
          getPosition: (d: any) => [d.x, d.y],
          getRadius: geometry.r_max_comm,
          radiusUnits: "meters",
          getFillColor: C.coverage,
          stroked: false,
          pickable: false,
        })
      );
    }

    // Controller -> its RSU cluster. Off by default: 64 lines is a lot of ink.
    if (layers.controllerLinks && topology) {
      const links: any[] = [];
      for (const c of topology.controllers) {
        for (const rid of c.rsu_ids) {
          const r = geometry.rsus.find((x) => x.rsu_id === rid);
          if (r) links.push({ from: [c.x, c.y], to: [r.x, r.y], hostile: c.hostile });
        }
      }
      L.push(
        new LineLayer({
          id: "controller-links",
          data: links,
          getSourcePosition: (d: any) => d.from,
          getTargetPosition: (d: any) => d.to,
          getColor: (d: any) => (d.hostile ? C.hostile : C.controllerLink),
          getWidth: 1,
          widthUnits: "pixels",
        })
      );
    }

    // Movement trails from REPORTED positions, so a poisoned vehicle's trail
    // visibly peels away from honest traffic.
    if (layers.trails && trails.length) {
      L.push(
        new PathLayer({
          id: "trails",
          data: trails,
          getPath: (d: any) => d.path,
          getColor: C.vehicleDim,
          getWidth: 1.5,
          widthUnits: "pixels",
          capRounded: true,
          jointRounded: true,
          pickable: false,
        })
      );
    }

    // RSUs as squares; hijacked ones filled with the critical status colour.
    L.push(
      new PolygonLayer({
        id: "rsus",
        data: geometry.rsus,
        getPolygon: (d: any) => squareAt(d.x, d.y, 26),
        getFillColor: (d: any) =>
          compromisedRsus.has(d.rsu_id) ? C.hostile : C.rsu,
        getLineColor: (d: any) =>
          compromisedRsus.has(d.rsu_id) ? C.missed : C.rsuDim,
        getLineWidth: 2,
        lineWidthUnits: "pixels",
        stroked: true,
        filled: true,
        pickable: true,
      })
    );

    // Full fleet from the mobility trace — present even when no beacon fired.
    // radiusMinPixels matters more than radius here: at the default zoom a
    // 6 m car is ~2 px and reads as dust. The floor keeps every vehicle a
    // legible dot at any zoom, which is the whole point of showing them.
    L.push(
      new ScatterplotLayer({
        id: "fleet",
        data: positions,
        getPosition: (d: any) => [d.x, d.y],
        getRadius: 14,
        radiusUnits: "meters",
        radiusMinPixels: 3.5,
        radiusMaxPixels: 9,
        getFillColor: C.vehicle,
        stroked: true,
        getLineColor: [8, 12, 18, 200],
        getLineWidth: 1,
        lineWidthUnits: "pixels",
        pickable: true,
        onClick: (info: any) =>
          info.object && selectVehicle(info.object.vehicle_id),
      })
    );

    // Rubber band: claimed position -> true position. Never for ghosts (the
    // server sends gt_pos: null for them — a fabricated identity has no
    // "actual" location to compare against).
    if (layers.rubberBands) {
      const bands = beacons.filter((b) => b.gt_pos && b.is_poisoned);
      L.push(
        new LineLayer({
          id: "rubber-bands",
          data: bands,
          getSourcePosition: (d: BeaconDto) => [d.pos.x, d.pos.y],
          getTargetPosition: (d: BeaconDto) => [d.gt_pos!.x, d.gt_pos!.y],
          getColor: (d: BeaconDto) => (d.detected ? C.band : C.bandMissed),
          getWidth: (d: BeaconDto) => (d.detected ? 1.5 : 2.5),
          widthUnits: "pixels",
        })
      );
      // Hollow ring marking where the vehicle ACTUALLY is.
      L.push(
        new ScatterplotLayer({
          id: "truth-anchors",
          data: bands,
          getPosition: (d: BeaconDto) => [d.gt_pos!.x, d.gt_pos!.y],
          getRadius: 7,
          radiusUnits: "meters",
          radiusMinPixels: 3,
          filled: false,
          stroked: true,
          getLineColor: C.band,
          getLineWidth: 1.5,
          lineWidthUnits: "pixels",
          pickable: false,
        })
      );
    }

    // Active beacons, coloured by ground truth vs detection outcome. These sit
    // above the fleet dots and must stay clearly larger than them.
    L.push(
      new ScatterplotLayer({
        id: "beacons",
        data: beacons,
        getPosition: (d: BeaconDto) => [d.pos.x, d.pos.y],
        getRadius: (d: BeaconDto) => (d.is_poisoned ? 26 : 18),
        radiusUnits: "meters",
        radiusMinPixels: 6,
        radiusMaxPixels: 16,
        getFillColor: beaconColor,
        stroked: true,
        getLineColor: (d: BeaconDto) =>
          d.vehicle_id === selectedVehicle ? C.selected : [0, 0, 0, 120],
        getLineWidth: (d: BeaconDto) =>
          d.vehicle_id === selectedVehicle ? 3 : 1,
        lineWidthUnits: "pixels",
        pickable: true,
        onClick: (info: any) =>
          info.object && selectVehicle(info.object.vehicle_id),
        updateTriggers: { getLineColor: selectedVehicle, getLineWidth: selectedVehicle },
      })
    );

    // Ghosts get a cross on top: magenta-vs-aqua fails CVD, so shape carries it.
    const ghosts = beacons.filter((b) => b.is_ghost);
    if (ghosts.length) {
      L.push(
        new PathLayer({
          id: "ghost-marks",
          data: ghosts.flatMap((g) => {
            const r = 14;
            return [
              { path: [[g.pos.x - r, g.pos.y - r], [g.pos.x + r, g.pos.y + r]] },
              { path: [[g.pos.x - r, g.pos.y + r], [g.pos.x + r, g.pos.y - r]] },
            ];
          }),
          getPath: (d: any) => d.path,
          getColor: C.ghost,
          getWidth: 2,
          widthUnits: "pixels",
          pickable: false,
        })
      );
    }

    // Controllers last so they sit above everything.
    if (topology) {
      L.push(
        new PolygonLayer({
          id: "controllers",
          data: topology.controllers,
          getPolygon: (d: any) => diamondAt(d.x, d.y, 58),
          getFillColor: (d: any) => (d.hostile ? C.hostile : C.controller),
          getLineColor: (d: any) => (d.hostile ? C.missed : [255, 255, 255, 110]),
          getLineWidth: 2.5,
          lineWidthUnits: "pixels",
          stroked: true,
          filled: true,
          pickable: true,
        })
      );
    }

    return L;
  }, [
    geometry,
    positions,
    beacons,
    trails,
    topology,
    layers,
    compromisedRsus,
    selectedVehicle,
    selectVehicle,
  ]);

  if (!glOk || glError) {
    return (
      <div className="flex h-full items-center justify-center p-8">
        <div className="max-w-md rounded-lg border border-status-missed/40 bg-status-missed/10 p-5">
          <h2 className="mb-2 text-sm font-semibold text-status-missed">
            The map can’t draw — WebGL is unavailable in this browser
          </h2>
          <p className="mb-3 text-xs leading-relaxed text-ink-secondary">
            Everything else on this page is live and correct; only the GPU-drawn
            network view is affected. {glError && `(${glError})`}
          </p>
          <ol className="list-decimal space-y-1 pl-4 text-xs text-ink-secondary">
            <li>
              Open <code className="text-ink-primary">chrome://gpu</code> and
              check whether WebGL is listed as “Hardware accelerated”.
            </li>
            <li>
              In <code className="text-ink-primary">chrome://settings/system</code>,
              enable “Use graphics acceleration when available”, then restart
              Chrome.
            </li>
            <li>
              Still stuck? Launch with{" "}
              <code className="text-ink-primary">
                google-chrome --enable-unsafe-swiftshader
              </code>{" "}
              to render in software.
            </li>
          </ol>
        </div>
      </div>
    );
  }

  if (!geometry) {
    return (
      <div className="flex h-full items-center justify-center text-ink-muted">
        Select a scenario to load the network.
      </div>
    );
  }

  return (
    <>
    <button
      onClick={resetView}
      className="absolute right-3 top-3 z-10 rounded-md border border-surface-hairline bg-surface-panel/95 px-2.5 py-1.5 text-xs text-ink-secondary backdrop-blur transition-colors hover:text-ink-primary"
      title="Re-centre the network if you have panned or zoomed away"
    >
      Reset view
    </button>
    <DeckGL
      key={viewKey}
      views={new OrthographicView({ id: "map" })}
      initialViewState={INITIAL_VIEW_STATE}
      controller={true}
      layers={deckLayers}
      onError={(e: any) => setGlError(e?.message ?? String(e))}
      getCursor={({ isHovering }) => (isHovering ? "pointer" : "grab")}
      getTooltip={({ object }: any) => {
        if (!object) return null;
        if ("controller_id" in object) {
          return {
            text:
              `CONTROLLER ${object.controller_id}` +
              (object.hostile ? "  ⚠ HIJACKED" : "") +
              `\nmanages ${object.rsu_ids.length} RSUs` +
              `\n(position derived from its RSU cluster)`,
          };
        }
        if ("rsu_id" in object) {
          return {
            text:
              `RSU ${object.rsu_id}` +
              (compromisedRsus.has(object.rsu_id) ? "  ⚠ HIJACKED" : ""),
          };
        }
        if ("vehicle_id" in object) {
          const b = object as BeaconDto;
          if (!("is_poisoned" in b)) return { text: `Vehicle ${object.vehicle_id}` };
          return {
            text:
              `Vehicle ${b.vehicle_id}${b.is_ghost ? "  (GHOST identity)" : ""}\n` +
              `${b.is_poisoned ? "LYING" : "honest"} · ${
                b.detected ? "flagged" : b.is_poisoned ? "MISSED" : "not flagged"
              }` +
              (b.drift_m != null && b.drift_m > 1
                ? `\noff by ${b.drift_m.toFixed(0)} m`
                : "") +
              `\nclick to inspect`,
          };
        }
        return null;
      }}
    />
    </>
  );
}
