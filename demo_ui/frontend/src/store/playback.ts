import { create } from "zustand";
import {
  api,
  BeaconDto,
  GeometryDto,
  ScenarioDetailDto,
  ScenarioSummary,
  StatsDto,
  TopologyDto,
  TrailDto,
  VehiclePositionDto,
} from "../api";

export interface LayerToggles {
  coverage: boolean;
  trails: boolean;
  rubberBands: boolean;
  controllerLinks: boolean;
}

interface PlaybackState {
  scenarios: ScenarioSummary[];
  scenarioId: string | null;
  road: string | null;
  detail: ScenarioDetailDto | null;
  topology: TopologyDto | null;

  tMin: number;
  tMax: number;
  t: number;
  playing: boolean;
  speed: number;

  geometry: GeometryDto | null;
  positions: VehiclePositionDto[];
  beacons: BeaconDto[];
  trails: TrailDto[];
  stats: StatsDto | null;

  selectedVehicle: number | null;
  vehicleTrack: BeaconDto[] | null;
  loadingVehicle: boolean;

  layers: LayerToggles;
  loading: boolean;
  error: string | null;

  loadScenarios: () => Promise<void>;
  selectScenario: (id: string) => Promise<void>;
  seek: (t: number) => Promise<void>;
  play: () => void;
  pause: () => void;
  setSpeed: (s: number) => void;
  tick: (dtRealSeconds: number) => Promise<void>;
  selectVehicle: (vid: number | null) => Promise<void>;
  toggleLayer: (k: keyof LayerToggles) => void;
}

// Monotonic token so a slow in-flight seek can never overwrite a newer one.
let seekToken = 0;

export const usePlayback = create<PlaybackState>((set, get) => ({
  scenarios: [],
  scenarioId: null,
  road: null,
  detail: null,
  topology: null,

  tMin: 0,
  tMax: 0,
  t: 0,
  playing: false,
  speed: 1,

  geometry: null,
  positions: [],
  beacons: [],
  trails: [],
  stats: null,

  selectedVehicle: null,
  vehicleTrack: null,
  loadingVehicle: false,

  layers: {
    coverage: true,
    trails: true,
    rubberBands: true,
    controllerLinks: false,
  },
  loading: false,
  error: null,

  loadScenarios: async () => {
    try {
      set({ scenarios: await api.scenarios(), error: null });
    } catch (e) {
      set({ error: `Could not load scenarios: ${(e as Error).message}` });
    }
  },

  selectScenario: async (id: string) => {
    const s = get().scenarios.find((sc) => sc.id === id);
    if (!s) return;
    set({
      scenarioId: id,
      road: s.road,
      playing: false,
      loading: true,
      error: null,
      selectedVehicle: null,
      vehicleTrack: null,
      trails: [],
      beacons: [],
    });
    try {
      const [tr, geom, detail, topo] = await Promise.all([
        api.timerange(id),
        api.geometry(s.road),
        api.detail(id),
        api.topology(id),
      ]);
      set({
        tMin: tr.t_min,
        tMax: tr.t_max,
        t: tr.t_min,
        geometry: geom,
        detail,
        topology: topo,
        loading: false,
      });
      await get().seek(tr.t_min);
    } catch (e) {
      set({ loading: false, error: `Could not load ${id}: ${(e as Error).message}` });
    }
  },

  seek: async (t: number) => {
    const { scenarioId, road, tMin, tMax, layers } = get();
    if (!scenarioId || !road) return;
    const clamped = Math.min(Math.max(t, tMin), tMax);
    const token = ++seekToken;
    set({ t: clamped });
    try {
      const [frame, pos, stats, trails] = await Promise.all([
        api.frame(scenarioId, clamped, 0.15),
        api.positions(road, clamped),
        api.stats(scenarioId, clamped),
        layers.trails
          ? api.trails(scenarioId, clamped, 6)
          : Promise.resolve({ t: clamped, lookback: 0, trails: [] as TrailDto[] }),
      ]);
      if (token !== seekToken) return; // a newer seek already landed
      set({
        beacons: frame.beacons,
        positions: pos.positions,
        stats,
        trails: trails.trails,
      });
    } catch (e) {
      if (token === seekToken) set({ error: (e as Error).message });
    }
  },

  play: () => set({ playing: true }),
  pause: () => set({ playing: false }),
  setSpeed: (s: number) => set({ speed: s }),

  tick: async (dtRealSeconds: number) => {
    const { playing, t, tMax, speed, seek, pause } = get();
    if (!playing) return;
    const next = t + dtRealSeconds * speed;
    if (next >= tMax) {
      pause();
      await seek(tMax);
      return;
    }
    await seek(next);
  },

  selectVehicle: async (vid: number | null) => {
    const { scenarioId } = get();
    if (vid === null || !scenarioId) {
      set({ selectedVehicle: null, vehicleTrack: null });
      return;
    }
    set({ selectedVehicle: vid, loadingVehicle: true, vehicleTrack: null });
    try {
      const res = await api.vehicle(scenarioId, vid);
      if (get().selectedVehicle !== vid) return;
      set({ vehicleTrack: res.track, loadingVehicle: false });
    } catch {
      if (get().selectedVehicle === vid) set({ loadingVehicle: false });
    }
  },

  toggleLayer: (k) => {
    const layers = { ...get().layers, [k]: !get().layers[k] };
    set({ layers });
    if (k === "trails") void get().seek(get().t);
  },
}));
