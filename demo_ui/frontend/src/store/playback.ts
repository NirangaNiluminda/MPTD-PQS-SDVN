import { create } from "zustand";
import {
  api,
  BeaconDto,
  GeometryDto,
  ScenarioSummary,
  VehiclePositionDto,
} from "../api";

interface PlaybackState {
  scenarios: ScenarioSummary[];
  scenarioId: string | null;
  road: string | null;

  tMin: number;
  tMax: number;
  t: number;
  playing: boolean;
  speed: number; // 1, 5, 20

  geometry: GeometryDto | null;
  positions: VehiclePositionDto[]; // full fleet at time t (map base layer)
  beacons: BeaconDto[]; // detection-relevant beacons at time t (overlay)

  loadScenarios: () => Promise<void>;
  selectScenario: (id: string) => Promise<void>;
  seek: (t: number) => Promise<void>;
  play: () => void;
  pause: () => void;
  setSpeed: (s: number) => void;
  tick: (dtRealSeconds: number) => Promise<void>;
}

export const usePlayback = create<PlaybackState>((set, get) => ({
  scenarios: [],
  scenarioId: null,
  road: null,

  tMin: 0,
  tMax: 0,
  t: 0,
  playing: false,
  speed: 1,

  geometry: null,
  positions: [],
  beacons: [],

  loadScenarios: async () => {
    const scenarios = await api.scenarios();
    set({ scenarios });
  },

  selectScenario: async (id: string) => {
    const s = get().scenarios.find((sc) => sc.id === id);
    if (!s) return;
    set({ scenarioId: id, road: s.road, playing: false });

    const [tr, geom] = await Promise.all([
      api.timerange(id),
      api.geometry(s.road),
    ]);
    set({ tMin: tr.t_min, tMax: tr.t_max, t: tr.t_min, geometry: geom });
    await get().seek(tr.t_min);
  },

  seek: async (t: number) => {
    const { scenarioId, road, tMin, tMax } = get();
    if (!scenarioId || !road) return;
    const clamped = Math.min(Math.max(t, tMin), tMax);
    set({ t: clamped });
    const [frame, pos] = await Promise.all([
      api.frame(scenarioId, clamped, 0.15),
      api.positions(road, clamped),
    ]);
    // Guard against out-of-order responses when scrubbing fast.
    if (get().t !== clamped) return;
    set({ beacons: frame.beacons, positions: pos.positions });
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
}));
