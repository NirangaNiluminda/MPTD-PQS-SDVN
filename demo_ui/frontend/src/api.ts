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
};
