import { useMemo, useState, useCallback, useEffect, useRef } from "react";
import DeckGL from "@deck.gl/react";
import { OrthographicView, Color, LinearInterpolator } from "@deck.gl/core";
import {
  ScatterplotLayer,
  LineLayer,
  PathLayer,
  IconLayer,
  PolygonLayer,
  TextLayer,
} from "@deck.gl/layers";
import { usePlayback } from "../store/playback";
import { BeaconDto } from "../api";
import { useTokens, hexToRgba, Rgba, ThemeName } from "../design/tokens";
import { useTheme } from "../store/theme";

const PSI_TH = 0.09; // 08_detection_engine.h — the rule-signature decision line, same constant VehicleDrawer plots against
const IDLE_SPEED_MPS = 0.3; // "Hide idle vehicles" threshold — well below walking pace, clears sensor/GPS jitter

// Sim coordinates are plain metres on a local origin (not lon/lat), so this is
// an OrthographicView, not a geo view.
const INITIAL_VIEW_STATE = {
  target: [1680, 1460, 0] as [number, number, number],
  zoom: -1.35,
  minZoom: -3,
  maxZoom: 4,
};

// FlyToInterpolator assumes a geospatial (longitude/latitude) view and
// throws on a plain OrthographicView; LinearInterpolator just tweens the
// listed viewState props directly, which is what a metres-on-a-plane map
// needs for a smooth pan-to-selection.
const PAN_INTERPOLATOR = new LinearInterpolator({ transitionProps: ["target", "zoom"] });

// Street network base-map greys, deliberately NOT part of the validated data
// palette (basemap chrome, not a categorical/status colour). Dark recedes
// against a near-black page; light inverts to a near-white road on a soft
// grey page — same "roads read as texture, not data" intent either way.
const ROAD: Record<ThemeName, { junction: Rgba; roadCasing: Rgba; roadSurface: Rgba }> = {
  dark: {
    junction: [30, 38, 48, 255],
    roadCasing: [22, 29, 38, 255],
    roadSurface: [38, 47, 59, 255],
  },
  light: {
    junction: [221, 227, 234, 255],
    roadCasing: [199, 208, 218, 255],
    roadSurface: [255, 255, 255, 255],
  },
};

// Entity colours are validated per-theme (see design/tokens.ts). The CVD
// margin sits in the 6-8 band, which is legal ONLY alongside secondary
// encoding — hence every class below also differs in SHAPE and carries a
// text label in the legend.
function buildColors(theme: ThemeName, ENTITY: Record<string, string>, STATUS: Record<string, string>) {
  return {
    ...ROAD[theme],
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
    band: (theme === "dark" ? [255, 255, 255, 70] : [14, 22, 32, 90]) as Rgba,
    bandMissed: hexToRgba(STATUS.missed, 130),
    selected: (theme === "dark" ? [255, 255, 255, 255] : [14, 22, 32, 255]) as Rgba,
    // Suspicion halos — soft, low-alpha rings behind a beacon dot, sized by
    // psi_score rather than the binary caught/missed outcome the dot itself
    // already encodes. Reuses the validated caught/missed hues at low alpha
    // instead of introducing a new "glow" colour.
    haloAmber: hexToRgba(STATUS.caught, 55),
    haloRed: hexToRgba(STATUS.missed, 70),
    // LSTM-AE "expected trajectory" overlay — reuses the validated caught/
    // caution colour rather than introducing an unvalidated new hue.
    aeExpected: hexToRgba(STATUS.caught, 230),
    // GAT attention lines — reuses the validated controller colour (aqua),
    // distinct from the AE overlay's amber and from every entity colour
    // already on the map.
    gatLine: hexToRgba(ENTITY.controller, 200),
    // Traffic-signal phase colours — reuses the validated status quartet
    // (never a new hue) for a completely different meaning (light phase,
    // not detection outcome). Kept visually separable from the security
    // language by shape (triangle, used nowhere else) and by being opt-in.
    signalGreen: hexToRgba(STATUS.good, 235),
    signalAmber: hexToRgba(STATUS.caught, 235),
    signalRed: hexToRgba(STATUS.missed, 235),
  };
}

/**
 * Real, fixed-cycle SUMO phase lookup — t mod (sum of phase durations) tells
 * you which phase you're in, exactly how the simulator's own static traffic-
 * light programs work. No live SUMO/TraCI connection, no interpolation.
 */
function signalStateAt(phases: { duration: number; state: string }[], t: number): string {
  const cycle = phases.reduce((s, p) => s + p.duration, 0);
  if (cycle <= 0) return "";
  let clock = ((t % cycle) + cycle) % cycle;
  for (const p of phases) {
    if (clock < p.duration) return p.state;
    clock -= p.duration;
  }
  return phases[phases.length - 1].state;
}

/** A phase's state string is one char per controlled approach — reduce a
 * possibly-mixed intersection to one representative colour: any yellow
 * anywhere means "transitioning" (amber); otherwise majority green/red. */
function signalPhaseColor(state: string, C: MapColors): Color {
  if (!state) return C.signalRed;
  let green = 0,
    red = 0;
  for (const ch of state) {
    if (ch === "y" || ch === "Y") return C.signalAmber;
    if (ch === "G" || ch === "g") green++;
    else if (ch === "r" || ch === "R") red++;
  }
  return green >= red ? C.signalGreen : C.signalRed;
}

type MapColors = ReturnType<typeof buildColors>;

function beaconColor(C: MapColors) {
  return (b: BeaconDto): Color => {
    if (b.is_poisoned && !b.detected) return C.missed;
    if (b.is_poisoned && b.detected) return C.caught;
    if (b.is_ghost) return C.ghost;
    return C.vehicle;
  };
}

interface RegionCell {
  cx: number;
  cy: number;
  n: number;
  caught: number;
  missed: number;
}

/**
 * Region-level clustering: bins the full fleet + active beacons into a grid
 * over the road bounds. Each cell reports a count and its WORST observed
 * state — a cell with even one missed detection is coloured as missed, so
 * clustering never visually launders a real miss into "looks clean".
 */
function buildRegionCells(
  bounds: { x_min: number; x_max: number; y_min: number; y_max: number },
  positions: { x: number; y: number }[],
  beacons: BeaconDto[],
  cols = 6,
  rows = 4
): RegionCell[] {
  const w = (bounds.x_max - bounds.x_min) / cols;
  const h = (bounds.y_max - bounds.y_min) / rows;
  if (w <= 0 || h <= 0) return [];
  const cells: RegionCell[] = Array.from({ length: cols * rows }, (_, i) => ({
    cx: bounds.x_min + (i % cols) * w + w / 2,
    cy: bounds.y_min + Math.floor(i / cols) * h + h / 2,
    n: 0,
    caught: 0,
    missed: 0,
  }));
  const cellIndex = (x: number, y: number) => {
    const col = Math.min(cols - 1, Math.max(0, Math.floor((x - bounds.x_min) / w)));
    const row = Math.min(rows - 1, Math.max(0, Math.floor((y - bounds.y_min) / h)));
    return row * cols + col;
  };
  for (const p of positions) cells[cellIndex(p.x, p.y)].n++;
  for (const b of beacons) {
    if (!b.is_poisoned) continue;
    const c = cells[cellIndex(b.pos.x, b.pos.y)];
    if (b.detected) c.caught++;
    else c.missed++;
  }
  return cells.filter((c) => c.n > 0);
}

// Infrastructure markers are drawn as ICONS sized in PIXELS, not polygons
// sized in metres. A metre-sized marker looks right at the default zoom and
// then swells to fill the screen the moment you zoom into a junction — which
// is exactly what happened before this. Pixel sizing keeps RSUs and
// controllers legible and proportionate at every zoom level.
//
// mask:true makes deck.gl treat the SVG's alpha as a stencil and tint it with
// getColor, so one white glyph serves both the normal and hijacked states.
const svgUri = (svg: string) =>
  `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;

const SQUARE_ICON = {
  url: svgUri(
    `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><rect x="4" y="4" width="24" height="24" rx="3" fill="#fff"/></svg>`
  ),
  width: 32,
  height: 32,
  mask: true,
};

const DIAMOND_ICON = {
  url: svgUri(
    `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><path d="M16 2 L30 16 L16 30 L2 16 Z" fill="#fff"/></svg>`
  ),
  width: 32,
  height: 32,
  mask: true,
};

const TRIANGLE_ICON = {
  url: svgUri(
    `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><path d="M16 3 L29 28 L3 28 Z" fill="#fff"/></svg>`
  ),
  width: 32,
  height: 32,
  mask: true,
};

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
    roadmap,
    signals,
    t,
    mapDetail,
    selectedVehicle,
    selectVehicle,
    hoveredVehicle,
    setHoveredVehicle,
    lstmReconstruction,
    gatAttention,
  } = usePlayback();

  const [glOk] = useState(webglAvailable);
  const [glError, setGlError] = useState<string | null>(null);

  // Controlled view state so a panel-side selection can pan/centre the map
  // on that vehicle — the escape hatch for a stray scroll/drag is the Reset
  // view button, which now just re-applies INITIAL_VIEW_STATE in place
  // rather than remounting DeckGL.
  const [viewState, setViewState] = useState<any>(INITIAL_VIEW_STATE);
  const resetView = useCallback(
    () =>
      setViewState((v: any) => ({
        ...INITIAL_VIEW_STATE,
        transitionDuration: 450,
        transitionInterpolator: PAN_INTERPOLATOR,
      })),
    []
  );

  const theme = useTheme((s) => s.theme);
  const tokens = useTokens();
  const C = useMemo(
    () => buildColors(theme, tokens.ENTITY, tokens.STATUS),
    [theme, tokens]
  );

  const compromisedRsus = useMemo(
    () => new Set(topology?.compromised_rsus ?? []),
    [topology]
  );

  // A single lookup used both to pan the camera and to draw the selection
  // pulse/hover ring at the right spot — prefers the live beacon (fresher,
  // carries state) and falls back to the raw mobility-trace position.
  const findPos = useCallback(
    (vid: number): [number, number] | null => {
      const b = beacons.find((x) => x.vehicle_id === vid);
      if (b) return [b.pos.x, b.pos.y];
      const p = positions.find((x) => x.vehicle_id === vid);
      return p ? [p.x, p.y] : null;
    },
    [beacons, positions]
  );

  const showIndividual = mapDetail === "street" || mapDetail === "entity";

  // Panel -> map: centre the camera on a newly selected vehicle. Guarded to
  // individual-detail levels only — region/district never draw a marker to
  // centre on. A map-originated click re-centres on the same spot it was
  // already at, which is a harmless no-op animation.
  useEffect(() => {
    if (selectedVehicle == null || !showIndividual) return;
    const pos = findPos(selectedVehicle);
    if (!pos) return;
    setViewState((v: any) => ({
      ...v,
      target: [pos[0], pos[1], 0],
      transitionDuration: 500,
      transitionInterpolator: PAN_INTERPOLATOR,
    }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedVehicle]);

  // Selection pulse: a soft ring that grows and fades on a ~1.1s loop,
  // visually distinct from (and layered outside) the marker's own severity
  // colour — the pulse never touches getFillColor, only a separate layer.
  const [pulseT, setPulseT] = useState(0);
  useEffect(() => {
    if (selectedVehicle == null || !showIndividual) return;
    let raf = 0;
    const start = performance.now();
    const step = (now: number) => {
      setPulseT(((now - start) % 1100) / 1100);
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [selectedVehicle, showIndividual]);

  const deckLayers = useMemo(() => {
    if (!geometry) return [];
    const L: any[] = [];

    // ── Region: collapse the whole fleet into area clusters ─────────────────
    // No individual entity, no road network, no rubber bands — a cell with
    // even one missed poisoning renders as missed, so this can't visually
    // launder a real detection failure into "looks clean from far away."
    if (mapDetail === "region") {
      const cells = buildRegionCells(geometry.bounds, positions, beacons);
      L.push(
        new ScatterplotLayer({
          id: "region-cells",
          data: cells,
          getPosition: (d: RegionCell) => [d.cx, d.cy],
          getRadius: (d: RegionCell) => 40 + Math.sqrt(d.n) * 22,
          radiusUnits: "meters",
          radiusMinPixels: 18,
          radiusMaxPixels: 90,
          getFillColor: (d: RegionCell) =>
            d.missed > 0 ? C.missed : d.caught > 0 ? C.caught : C.vehicleDim,
          opacity: 0.55,
          stroked: true,
          getLineColor: [255, 255, 255, 60],
          getLineWidth: 1,
          lineWidthUnits: "pixels",
          pickable: false,
        })
      );
      L.push(
        new TextLayer({
          id: "region-labels",
          data: cells,
          getPosition: (d: RegionCell) => [d.cx, d.cy],
          getText: (d: RegionCell) =>
            d.missed > 0
              ? `${d.n}\n${d.missed} missed`
              : d.caught > 0
              ? `${d.n}\n${d.caught} caught`
              : `${d.n}`,
          getSize: 12,
          sizeUnits: "pixels",
          getColor: [235, 240, 245, 235],
          fontFamily: "IBM Plex Mono, monospace",
          getTextAnchor: "middle",
          getAlignmentBaseline: "center",
        })
      );
      return L;
    }

    // District hides per-vehicle state (colour, trails, rubber bands) — only
    // street level and above show WHO is lying, not just THAT traffic exists.
    // (showIndividual itself is computed once in component scope above, so
    // the pan/pulse effects can share the same value.)

    // ── Street network, drawn first so everything else sits on top ─────────
    // Geometry comes straight from the SUMO .net.xml the traces were
    // generated on, in the same coordinate frame (verified: the net's
    // convBoundary contains the trace extent), so vehicles land ON the roads
    // with no transform applied.
    if (layers.streets && roadmap) {
      // Junction polygons fill intersections; SUMO's internal connector lanes
      // are skipped server-side because these already cover that area.
      L.push(
        new PolygonLayer({
          id: "junctions",
          data: roadmap.junctions,
          getPolygon: (d: any) => d,
          getFillColor: C.junction,
          stroked: false,
          filled: true,
          pickable: false,
        })
      );
      // Casing under the surface gives roads a defined edge against the page.
      L.push(
        new PathLayer({
          id: "road-casing",
          data: roadmap.roads,
          getPath: (d: any) => d.p,
          getColor: C.roadCasing,
          getWidth: (d: any) => d.w + 1.6,
          widthUnits: "meters",
          widthMinPixels: 1.5,
          capRounded: true,
          jointRounded: true,
          pickable: false,
        })
      );
      L.push(
        new PathLayer({
          id: "road-surface",
          data: roadmap.roads,
          getPath: (d: any) => d.p,
          getColor: C.roadSurface,
          getWidth: (d: any) => d.w,
          widthUnits: "meters",
          widthMinPixels: 1,
          capRounded: true,
          jointRounded: true,
          pickable: false,
        })
      );
    }

    // Real, fixed-cycle SUMO traffic-light state — explains WHY a vehicle is
    // stopped (red phase) instead of leaving it unexplained. Opt-in and
    // small/triangular so it never competes with the security-status
    // language (colour+shape) the rest of the map is built around.
    if (layers.trafficSignals && signals && signals.length) {
      L.push(
        new IconLayer({
          id: "traffic-signals",
          data: signals,
          getPosition: (d: any) => [d.x, d.y],
          getIcon: () => TRIANGLE_ICON,
          getSize: 11,
          sizeUnits: "pixels",
          getColor: (d: any) => signalPhaseColor(signalStateAt(d.phases, t), C),
          pickable: true,
          updateTriggers: { getColor: t },
        })
      );
    }

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
    if (showIndividual && layers.trails && trails.length) {
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

    // RSUs as squares; hijacked ones take the critical status colour.
    L.push(
      new IconLayer({
        id: "rsus",
        data: geometry.rsus,
        getPosition: (d: any) => [d.x, d.y],
        getIcon: () => SQUARE_ICON,
        getSize: 15,
        sizeUnits: "pixels",
        getColor: (d: any) =>
          compromisedRsus.has(d.rsu_id) ? C.hostile : C.rsu,
        pickable: true,
        updateTriggers: { getColor: compromisedRsus },
      })
    );

    // Full fleet from the mobility trace — present even when no beacon fired.
    // radiusMinPixels matters more than radius here: at the default zoom a
    // 6 m car is ~2 px and reads as dust. The floor keeps every vehicle a
    // legible dot at any zoom, which is the whole point of showing them.
    //
    // "Hide idle vehicles" is a presentation filter only — it drops dots
    // whose CURRENT sampled speed is near zero (parked/idling/waiting to
    // depart, real mobility-trace behaviour, not a bug). It never touches
    // positions data or any captured result; off by default.
    const fleetData = layers.hideIdle ? positions.filter((p: any) => p.speed > IDLE_SPEED_MPS) : positions;
    L.push(
      new ScatterplotLayer({
        id: "fleet",
        data: fleetData,
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
    if (showIndividual && layers.rubberBands) {
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

    // Suspicion halos: a soft ring sized by psi_score magnitude, independent
    // of ground truth — this is what surfaces an elevated-but-unresolved
    // reading (including a near-miss on an honest vehicle) that the binary
    // caught/missed dot colour below can't show on its own.
    if (showIndividual) {
      const suspicious = beacons.filter((b) => b.psi_score > PSI_TH);
      if (suspicious.length) {
        L.push(
          new ScatterplotLayer({
            id: "suspicion-halos",
            data: suspicious,
            getPosition: (d: BeaconDto) => [d.pos.x, d.pos.y],
            getRadius: (d: BeaconDto) => (d.psi_score > 0.3 ? 46 : 32),
            radiusUnits: "meters",
            radiusMinPixels: 10,
            radiusMaxPixels: 28,
            getFillColor: (d: BeaconDto) => (d.psi_score > 0.3 ? C.haloRed : C.haloAmber),
            stroked: false,
            pickable: false,
          })
        );
      }
    }

    // Hover ring: a lightweight, non-pulsing outline on whatever vehicle the
    // pointer or the panel is currently over. Never drawn on top of the
    // selection (the pulse below already owns that vehicle's ring) so the
    // two states can't visually collide.
    if (showIndividual && hoveredVehicle != null && hoveredVehicle !== selectedVehicle) {
      const pos = findPos(hoveredVehicle);
      if (pos) {
        L.push(
          new ScatterplotLayer({
            id: "hover-ring",
            data: [{ pos }],
            getPosition: (d: any) => d.pos,
            getRadius: 24,
            radiusUnits: "meters",
            radiusMinPixels: 13,
            filled: false,
            stroked: true,
            getLineColor: C.selected,
            getLineWidth: 1.5,
            lineWidthUnits: "pixels",
            pickable: false,
          })
        );
      }
    }

    // Selection pulse: an expanding, fading ring around the selected vehicle
    // — deliberately a SEPARATE layer from the marker's own severity colour
    // (getFillColor on "beacons" below), never overwriting it. This is what
    // makes "currently selected" visually distinct from "flagged/suspicious".
    if (showIndividual && selectedVehicle != null) {
      const pos = findPos(selectedVehicle);
      if (pos) {
        L.push(
          new ScatterplotLayer({
            id: "selection-pulse",
            data: [{ pos }],
            getPosition: (d: any) => d.pos,
            getRadius: 20 + pulseT * 26,
            radiusUnits: "meters",
            radiusMinPixels: 11 + pulseT * 16,
            filled: false,
            stroked: true,
            getLineColor: [C.selected[0], C.selected[1], C.selected[2], Math.round(220 * (1 - pulseT))] as Color,
            getLineWidth: 2,
            lineWidthUnits: "pixels",
            pickable: false,
          })
        );
        // A steady inner ring keeps the selection visible between pulse
        // cycles (the animated ring above fades to zero every loop).
        L.push(
          new ScatterplotLayer({
            id: "selection-ring",
            data: [{ pos }],
            getPosition: (d: any) => d.pos,
            getRadius: 16,
            radiusUnits: "meters",
            radiusMinPixels: 9,
            filled: false,
            stroked: true,
            getLineColor: C.selected,
            getLineWidth: 2,
            lineWidthUnits: "pixels",
            pickable: false,
          })
        );
      }
    }

    // Active beacons, coloured by ground truth vs detection outcome. These sit
    // above the fleet dots and must stay clearly larger than them. Hidden
    // below street level: per-vehicle state IS the individual identity that
    // district is meant to withhold.
    if (showIndividual) {
      L.push(
        new ScatterplotLayer({
          id: "beacons",
          data: beacons,
          getPosition: (d: BeaconDto) => [d.pos.x, d.pos.y],
          getRadius: (d: BeaconDto) => (d.is_poisoned ? 26 : 18),
          radiusUnits: "meters",
          radiusMinPixels: 6,
          radiusMaxPixels: 16,
          getFillColor: beaconColor(C),
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
    }

    // Ghosts get a cross on top: magenta-vs-aqua fails CVD, so shape carries it.
    const ghosts = showIndividual ? beacons.filter((b) => b.is_ghost) : [];
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

    // Entity level only: vehicle-ID labels for anything poisoned, so a
    // single-intersection zoom can name names. Skipped at street level
    // because labels for the whole fleet would collide into noise.
    if (mapDetail === "entity") {
      const flagged = beacons.filter((b) => b.is_poisoned || b.is_ghost);
      if (flagged.length) {
        L.push(
          new TextLayer({
            id: "entity-labels",
            data: flagged,
            getPosition: (d: BeaconDto) => [d.pos.x, d.pos.y],
            getText: (d: BeaconDto) => `#${d.vehicle_id}`,
            getSize: 11,
            sizeUnits: "pixels",
            getColor: [235, 240, 245, 235],
            fontFamily: "IBM Plex Mono, monospace",
            getPixelOffset: [0, -18],
            getTextAnchor: "middle",
          })
        );
      }
    }

    // LSTM-AE "expected trajectory" — real reported speed/heading, but the
    // model's own reconstructed residual instead of the vehicle's actual
    // one. Only drawn for the vehicle it was computed for (selectVehicle
    // clears the reconstruction on any change, but this guard also covers
    // the one-frame window before that clear lands).
    if (lstmReconstruction && lstmReconstruction.vehicle_id === selectedVehicle) {
      const pts = lstmReconstruction.expected_trajectory;
      L.push(
        new PathLayer({
          id: "ae-expected-trajectory",
          data: [{ path: pts.map((p) => [p.pos_x, p.pos_y]) }],
          getPath: (d: any) => d.path,
          getColor: C.aeExpected,
          getWidth: 2.5,
          widthUnits: "pixels",
          capRounded: true,
          jointRounded: true,
          pickable: false,
        })
      );
      L.push(
        new ScatterplotLayer({
          id: "ae-expected-endpoint",
          data: [pts[pts.length - 1]],
          getPosition: (d: any) => [d.pos_x, d.pos_y],
          getRadius: 6,
          radiusUnits: "meters",
          radiusMinPixels: 4,
          filled: false,
          stroked: true,
          getLineColor: C.aeExpected,
          getLineWidth: 2,
          lineWidthUnits: "pixels",
          pickable: false,
        })
      );
    }

    // GAT attention lines — real per-neighbour attention weight from the
    // deployed model's first layer, one line per neighbour the target
    // vehicle's embedding actually drew from. Width carries the weight so
    // the strongest influence is visually obvious without reading numbers.
    if (gatAttention && gatAttention.vehicle_id === selectedVehicle && gatAttention.neighbours.length > 0) {
      L.push(
        new LineLayer({
          id: "gat-attention-lines",
          data: gatAttention.neighbours,
          getSourcePosition: (d: any) => [gatAttention.target_pos.x, gatAttention.target_pos.y],
          getTargetPosition: (d: any) => [d.pos_x, d.pos_y],
          getColor: C.gatLine,
          getWidth: (d: any) => 1 + d.attention_weight * 6,
          widthUnits: "pixels",
          pickable: false,
        })
      );
      L.push(
        new ScatterplotLayer({
          id: "gat-attention-neighbours",
          data: gatAttention.neighbours,
          getPosition: (d: any) => [d.pos_x, d.pos_y],
          getRadius: 5,
          radiusUnits: "meters",
          radiusMinPixels: 3,
          filled: false,
          stroked: true,
          getLineColor: C.gatLine,
          getLineWidth: 2,
          lineWidthUnits: "pixels",
          pickable: false,
        })
      );
    }

    // Controllers last so they sit above everything.
    if (topology) {
      L.push(
        new IconLayer({
          id: "controllers",
          data: topology.controllers,
          getPosition: (d: any) => [d.x, d.y],
          getIcon: () => DIAMOND_ICON,
          getSize: 30,
          sizeUnits: "pixels",
          getColor: (d: any) => (d.hostile ? C.hostile : C.controller),
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
    roadmap,
    signals,
    t,
    mapDetail,
    showIndividual,
    compromisedRsus,
    selectedVehicle,
    selectVehicle,
    hoveredVehicle,
    findPos,
    pulseT,
    lstmReconstruction,
    gatAttention,
    C,
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
      views={new OrthographicView({ id: "map" })}
      viewState={viewState}
      onViewStateChange={({ viewState: v }: any) => setViewState(v)}
      controller={true}
      layers={deckLayers}
      onError={(e: any) => setGlError(e?.message ?? String(e))}
      getCursor={({ isHovering }) => (isHovering ? "pointer" : "grab")}
      onHover={({ object }: any) => {
        // Map -> panel hover sync: any pickable object carrying a
        // vehicle_id (fleet dot or live beacon) highlights its detection
        // row; anything else (RSU/controller/empty canvas) clears it.
        setHoveredVehicle(object && "vehicle_id" in object ? object.vehicle_id : null);
      }}
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
              `\nψ = ${b.psi_score.toFixed(3)}` +
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
