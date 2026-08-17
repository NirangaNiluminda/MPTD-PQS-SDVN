import { create } from "zustand";
import {
  api,
  BeaconDto,
  GatAttentionDto,
  GeometryDto,
  LstmReconstructionDto,
  RoadMapDto,
  ScenarioDetailDto,
  ScenarioSummary,
  StatsDto,
  TopologyDto,
  TrailDto,
  VehiclePositionDto,
} from "../api";

export interface LayerToggles {
  streets: boolean;
  coverage: boolean;
  trails: boolean;
  rubberBands: boolean;
  controllerLinks: boolean;
  // Purely a rendering filter — hides fleet dots reporting near-zero speed
  // in the current mobility-trace sample (parked/idling/waiting-to-depart
  // vehicles). Never touches the underlying trace or any captured result;
  // off by default so it can't be mistaken for the map's normal behaviour.
  hideIdle: boolean;
}

// Level of detail: separate from continuous camera zoom (deck.gl still
// handles pan/scroll), this controls WHICH layers render — region-level
// clustering vs. every individual entity. Default "street" preserves the
// map's pre-existing always-full-detail behaviour for anyone who never
// touches the new control.
export type MapDetail = "region" | "district" | "street" | "entity";

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
  roadmap: RoadMapDto | null;
  positions: VehiclePositionDto[];
  beacons: BeaconDto[];
  trails: TrailDto[];
  stats: StatsDto | null;

  selectedVehicle: number | null;
  vehicleTrack: BeaconDto[] | null;
  loadingVehicle: boolean;

  // Lighter-weight than selection: sets a temporary map<->panel highlight
  // without fetching a track or touching selectedVehicle. Cleared on
  // pointer-leave by whichever side set it.
  hoveredVehicle: number | null;
  setHoveredVehicle: (vid: number | null) => void;

  // Real offline LSTM-AE reconstruction for the selected vehicle — fetched
  // on demand (it runs a real inference subprocess, not free), never
  // automatically on every vehicle click. Cleared whenever the selected
  // vehicle changes so a stale result can't be shown against a new one.
  lstmReconstruction: LstmReconstructionDto | null;
  lstmLoading: boolean;
  lstmError: string | null;
  loadLstmReconstruction: () => Promise<void>;

  // Real offline GAT attention weights — same on-demand/cleared-on-change
  // discipline as the LSTM-AE reconstruction above.
  gatAttention: GatAttentionDto | null;
  gatLoading: boolean;
  gatError: string | null;
  loadGatAttention: () => Promise<void>;

  layers: LayerToggles;
  mapDetail: MapDetail;
  setMapDetail: (d: MapDetail) => void;
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
  roadmap: null,
  positions: [],
  beacons: [],
  trails: [],
  stats: null,

  selectedVehicle: null,
  vehicleTrack: null,
  loadingVehicle: false,

  hoveredVehicle: null,
  setHoveredVehicle: (vid) => set({ hoveredVehicle: vid }),

  lstmReconstruction: null,
  lstmLoading: false,
  lstmError: null,
  loadLstmReconstruction: async () => {
    const { scenarioId, selectedVehicle, t } = get();
    if (!scenarioId || selectedVehicle === null) return;
    const forVehicle = selectedVehicle;
    set({ lstmLoading: true, lstmError: null });
    try {
      const res = await api.lstmReconstruction(scenarioId, forVehicle, t);
      if (get().selectedVehicle !== forVehicle) return; // vehicle changed mid-flight
      set({ lstmReconstruction: res, lstmLoading: false });
    } catch (e) {
      if (get().selectedVehicle === forVehicle) {
        set({ lstmError: (e as Error).message, lstmLoading: false });
      }
    }
  },

  gatAttention: null,
  gatLoading: false,
  gatError: null,
  loadGatAttention: async () => {
    const { scenarioId, selectedVehicle, t } = get();
    if (!scenarioId || selectedVehicle === null) return;
    const forVehicle = selectedVehicle;
    set({ gatLoading: true, gatError: null });
    try {
      const res = await api.gatAttention(scenarioId, forVehicle, t);
      if (get().selectedVehicle !== forVehicle) return;
      set({ gatAttention: res, gatLoading: false });
    } catch (e) {
      if (get().selectedVehicle === forVehicle) {
        set({ gatError: (e as Error).message, gatLoading: false });
      }
    }
  },

  layers: {
    streets: true,
    coverage: true,
    trails: true,
    rubberBands: true,
    controllerLinks: false,
    hideIdle: false,
  },
  mapDetail: "street",
  setMapDetail: (d) => set({ mapDetail: d }),
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
      // Street geometry is ~1 MB and road-type-scoped, so fetch it separately
      // and never let a failure here block the rest of the scenario.
      api
        .roadmap(s.road)
        .then((rm) => {
          if (get().road === s.road) set({ roadmap: rm });
        })
        .catch(() => set({ roadmap: null }));
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
      set({
        selectedVehicle: null,
        vehicleTrack: null,
        lstmReconstruction: null,
        lstmError: null,
        gatAttention: null,
        gatError: null,
      });
      return;
    }
    set({
      selectedVehicle: vid,
      loadingVehicle: true,
      vehicleTrack: null,
      lstmReconstruction: null,
      lstmError: null,
      gatAttention: null,
      gatError: null,
    });
    try {
      const res = await api.vehicle(scenarioId, vid);
      if (get().selectedVehicle !== vid) return;
      set({ vehicleTrack: res.track, loadingVehicle: false });
    } catch {
      // Overwhelmingly a 404: this vehicle is in the mobility trace (still
      // drawn on the map from /positions) but never appears in this
      // capture's beacon log — most often because its route never came
      // within an RSU's range during the recorded window. That's confirmed
      // "no data," not a failed fetch, so record it as an empty track
      // rather than leaving vehicleTrack stuck at null (indistinguishable
      // from "still loading") — the panel needs the distinction to show an
      // honest empty state instead of silently showing nothing.
      if (get().selectedVehicle === vid) set({ vehicleTrack: [], loadingVehicle: false });
    }
  },

  toggleLayer: (k) => {
    const layers = { ...get().layers, [k]: !get().layers[k] };
    set({ layers });
    if (k === "trails") void get().seek(get().t);
  },
}));
