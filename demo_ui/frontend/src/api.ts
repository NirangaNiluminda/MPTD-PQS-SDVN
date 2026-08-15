// Thin client for demo_ui/backend/app.py. Field names mirror the FastAPI
// response shapes exactly (see app.py's _beacon_to_dict / route handlers) —
// no renaming here so a diff against the backend is a diff against this file.

export interface ScenarioSummary {
  id: string;
  road: "urban" | "rural" | "highway";
  attack_number: number;
  attack_name: string;
  attack_pct: number;
}

export interface Accusation {
  code: string;
  name: string;
  detail: string;
  weight: number;
}

export interface BeaconDto {
  sim_time: number;
  vehicle_id: number;
  rsu_id: number;
  pos: { x: number; y: number };
  gt_pos: { x: number; y: number } | null;
  speed: number;
  heading: number;
  is_poisoned: boolean;
  detected: boolean;
  is_ghost: boolean;
  sig_mask: number;
  psi_score: number;
  attacker_class: number;
  attacker_class_label: string;
  /** Non-technical phrasing, e.g. "a hijacked roadside unit". */
  attacker_class_plain: string;
  drift_m: number | null;
  accusations: Accusation[];
}

export interface FrameDto {
  t: number;
  window: number;
  beacons: BeaconDto[];
}

export interface TimerangeDto {
  t_min: number;
  t_max: number;
  count: number;
}

export interface RsuDto {
  rsu_id: number;
  x: number;
  y: number;
}

export interface GeometryDto {
  road: string;
  r_max_comm: number;
  bounds: { x_min: number; x_max: number; y_min: number; y_max: number };
  rsus: RsuDto[];
  vehicle_count: number;
}

export interface VehiclePositionDto {
  vehicle_id: number;
  x: number;
  y: number;
  speed: number;
}

export interface ControllerDto {
  controller_id: number;
  x: number;
  y: number;
  rsu_ids: number[];
  /** Controllers have no simulator coordinates; x/y is a derived cluster centroid. */
  position_is_derived: boolean;
  hostile: boolean;
}

export interface TopologyDto {
  scenario_id: string;
  attack_number: number;
  attack_name: string;
  controllers: ControllerDto[];
  compromised_rsus: number[];
  malicious_vehicles: number[];
  mitm_relays: number[];
  hostile_controllers: number[];
  rsu_controller_map: Record<string, number>;
}

export interface TrailDto {
  vehicle_id: number;
  path: [number, number][];
}

export interface StatsDto {
  t: number | null;
  beacons: number;
  poisoned: number;
  clean: number;
  caught: number;
  missed: number;
  false_alarms: number;
  vehicles_seen: number;
  ghosts_seen: number;
  note: string;
}

export interface RoadMapDto {
  /** One polyline per lane: p = points, w = lane width in metres. */
  roads: { p: [number, number][]; w: number }[];
  junctions: [number, number][][];
  bounds: { x_min: number; x_max: number; y_min: number; y_max: number };
  source: string;
}

export interface ScenarioDetailDto {
  id: string;
  road: string;
  attack_number: number;
  attack_name: string;
  attack_pct: number;
  metrics: Record<string, string> | null;
}

const BASE = ""; // same-origin: Vite dev proxy in dev, FastAPI static mount in prod

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path);
  if (!res.ok) {
    throw new Error(`${path} -> HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  scenarios: () => getJson<ScenarioSummary[]>("/api/scenarios"),
  timerange: (scenarioId: string) =>
    getJson<TimerangeDto>(`/api/scenarios/${scenarioId}/timerange`),
  frame: (scenarioId: string, t: number, window = 0.15) =>
    getJson<FrameDto>(
      `/api/scenarios/${scenarioId}/frame?t=${t}&window=${window}`
    ),
  vehicle: (scenarioId: string, vehicleId: number) =>
    getJson<{ vehicle_id: number; is_ghost: boolean; track: BeaconDto[] }>(
      `/api/scenarios/${scenarioId}/vehicle/${vehicleId}`
    ),
  geometry: (road: string) => getJson<GeometryDto>(`/api/geometry/${road}`),
  positions: (road: string, t: number) =>
    getJson<{ t: number; positions: VehiclePositionDto[] }>(
      `/api/geometry/${road}/positions?t=${t}`
    ),
  detail: (scenarioId: string) =>
    getJson<ScenarioDetailDto>(`/api/scenarios/${scenarioId}`),
  topology: (scenarioId: string) =>
    getJson<TopologyDto>(`/api/scenarios/${scenarioId}/topology`),
  trails: (scenarioId: string, t: number, lookback = 6) =>
    getJson<{ t: number; lookback: number; trails: TrailDto[] }>(
      `/api/scenarios/${scenarioId}/trails?t=${t}&lookback=${lookback}`
    ),
  stats: (scenarioId: string, t: number) =>
    getJson<StatsDto>(`/api/scenarios/${scenarioId}/stats?t=${t}`),
  roadmap: (road: string) => getJson<RoadMapDto>(`/api/roadmap/${road}`),
};
