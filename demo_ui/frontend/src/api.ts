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

// Real offline LSTM-AE reconstruction — see demo_ui/backend/ml_scripts/
// lstm_reconstruct.py. Runs the exact deployed ONNX artifact against this
// vehicle's real trailing beacon window; nothing here is simulated or
// estimated beyond the model's own forward pass.
export interface LstmReconstructionBeaconDto {
  t: number;
  pos_x: number;
  pos_y: number;
  speed: number;
  heading: number;
  is_poisoned: boolean;
  detected: boolean;
  /** [res_x, res_y, dspeed, dheading, accel, tau_i] — real residual units. */
  actual_raw: number[];
  reconstructed_raw: number[];
}

export interface LstmReconstructionDto {
  vehicle_id: number;
  window: number;
  theta_ae: number;
  ae_raw_estimate: number;
  flagged: boolean;
  feature_names: string[];
  per_channel_mse_z: number[];
  expected_trajectory: { t: number; pos_x: number; pos_y: number }[];
  beacons: LstmReconstructionBeaconDto[];
}

// Real offline GAT attention weights — see demo_ui/backend/ml_scripts/
// gat_attention.py. The deployed ONNX never exposes attention (verified:
// nothing routes it to an output), so this loads weights from the ONNX
// file's own initializers and asks torch_geometric directly. Cross-checked
// against the real ONNX score for the identical input on every call —
// score_verified/score_onnx_cross_check_max_abs_diff below.
export interface GatNeighbourDto {
  vehicle_id: number;
  attention_weight: number;
  pos_x: number;
  pos_y: number;
  is_poisoned: boolean;
  detected: boolean;
  distance_m: number;
}

export interface GatAttentionDto {
  vehicle_id: number;
  snapshot_size: number;
  edge_count: number;
  score: number;
  score_onnx_cross_check_max_abs_diff: number;
  score_verified: boolean;
  is_poisoned: boolean;
  detected: boolean;
  target_pos: { x: number; y: number };
  neighbours: GatNeighbourDto[];
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
  /** Which mobility-trace vehicles / RSU-grid positions actually produced or
   * received a beacon anywhere in this scenario's recording — real
   * participants, distinct from every position drawn on the map for
   * topology context. */
  active_vehicle_ids: number[];
  active_rsu_ids: number[];
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

export interface TrafficSignalDto {
  id: string;
  x: number;
  y: number;
  /** Fixed-cycle program — real, from the SUMO net, never a live TraCI feed. */
  phases: { duration: number; state: string }[];
}

// ── Blockchain ledger (point-in-time snapshot, see scripts/snapshot_ledger.py)

export interface LedgerSummaryDto {
  captured_at: string;
  is_live: boolean;
  rsus: { total: number; trusted: number; demoted: number };
  vehicles: { total: number; decayed: number };
  controllers: { total: number; decayed: number };
  revocations: number;
  controller_flags: number;
  reassignments: number;
}

export interface LedgerRefreshStatusDto {
  status: "idle" | "running";
  started_at: number | null;
  finished_at: number | null;
  error: string | null;
  captured_at: string | null;
  is_live: boolean;
}

/** One real "Committed block [N]" line off the Fabric peer container's own
 * log — see backend parsers/block_feed.py. */
export interface BlockCommitDto {
  block: number;
  channel: string;
  tx_count: number;
  commit_ms: number;
  hash: string;
  log_ts: string | null;
}

export interface ChainHeightDto {
  height: number;
  currentBlockHash: string;
  previousBlockHash: string;
}

export interface BlocksRecentDto {
  container: string;
  height: ChainHeightDto | null;
  recent: BlockCommitDto[];
}

export interface TrustRecordDto {
  ID: string;
  RSUID?: string;
  VehicleID?: string;
  ControllerID?: string;
  TrustScore: number;
  State?: string; // present on RSU records only
  UpdateCount: number;
  ConsecutiveLowEpochs: number;
  Probationary?: boolean;
  LastEpochTimestamp: string;
  UpdatedAt: string;
}

export interface RevocationDto {
  ID: string;
  RSUID?: string;
  VehicleID: string;
  Reason: string;
  Timestamp: string;
  RevokedAt: string;
}

export interface ControllerFlagDto {
  ID: string;
  ControllerID: string;
  VehicleID: string;
  Epoch: string;
  ConflictCount: number;
  NumRSUs: number;
  ThresholdFP1: number;
  FlaggedAt: string;
}

export interface ReassignmentDto {
  ID: string;
  ExcludedController: string;
  SuccessorController: string;
  Reason: string;
  Epoch: string;
  At: string;
}

// ── FUSION capture ([FUSION-RSU*] stdout from one blockchain-enabled run) ───

export interface CaptureSummaryDto {
  source: string;
  events: number;
  vehicles: number;
  gt_poisoned: number;
  flagged: number;
  t_min: number;
  t_max: number;
}

export interface CaptureVehicleRowDto {
  vid: number;
  events: number;
  gt_poisoned: number;
  flagged: number;
  missed: number;
  /** Real attack_number(s) (1-7) this vehicle was actually poisoned under in
   * this combined-attack capture — empty if never poisoned. Usually one
   * value; more than one means the vehicle was hit by different attack
   * mechanisms at different points in the same 90s run. */
  attack_types: number[];
}

export interface SweepPointDto {
  threshold: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
}

export interface LayerAgreementDto {
  n_events: number;
  matrix: Record<string, Record<string, number | null>>;
  flag_rates: Record<string, number>;
}

export interface LatencyHistogramDto {
  vehicles_considered: number;
  vehicles_missed_entirely: number;
  latencies_seconds: number[];
}

export interface AttackSignatureHitDto {
  code: string;
  name: string;
  detail: string;
  count: number;
  pct: number;
}

// n_events==0 means this variant has NO per-event trace in the single
// captured recording this endpoint reads from (TP-S3, MP-S4) — every other
// field is then absent, not zero-filled, so the UI can't mistake "not
// captured" for "measured and zero".
// Real [SC-REVOKE-VOTE-RSU*] activity against this attack's real poisoned
// vehicles, from the SAME capture file the rest of AttackEvidenceDto reads —
// deliberately not cross-referenced against the separate ledger snapshot
// (no run ID ties the two together). Most votes never cross the 2f+1
// threshold in a short window; vehicles_with_votes: 0 is an honest outcome.
export interface AttackMitigationDto {
  vehicles_with_votes: number;
  total_votes_cast: number;
  any_crossed_threshold: boolean;
  sample: { vehicle_id: number; votes: number; threshold: number; revoked: boolean }[];
}

export interface AttackEvidenceDto {
  attack_number: number;
  n_events: number;
  n_caught?: number;
  n_missed?: number;
  detection_rate?: number;
  mean_psi_fuse?: number;
  mean_gat_score?: number;
  mean_ae_norm?: number;
  top_signatures?: AttackSignatureHitDto[];
  mitigation?: AttackMitigationDto;
}

export interface CryptoSummaryDto {
  ipfs: {
    windows_stored: number;
    hashes_on_chain: number;
    is_real_daemon: boolean;
    note: string;
  };
  pq_crypto_cost_ms: {
    epoch_total: number;
    trs_sign: number;
    fhe_aggregate: number;
    dkg: number;
    epochs_sampled: number;
  };
  bandwidth_overhead: {
    ratio_vs_baseline: number;
    hmac_bytes: number;
    fhe_bytes: number;
    trs_bytes: number;
    rekey_bytes: number;
    baseline_bytes: number;
  };
  chaincode_latency_ms: {
    confirm: number;
    confirm_invokes: number;
    reassign: number;
    reassign_rollovers: number;
  };
  trs_verify: { ok: number; fail: number };
  cp_detect: { alerts: number; epochs_audited: number };
  ttd_seconds: number;
}

export interface FusionEventDto {
  rsu_id: number;
  epoch: number;
  t: number;
  vid: number;
  psi: number;
  psi_fuse: number;
  S: number;
  thetaS: number;
  S_norm: number;
  ae_norm: number;
  ae_raw: number;
  phi: number;
  khat: number;
  gt_pois: boolean;
  gt_atk: number;
  sig_mask: number;
  full_anom: boolean;
  accusations: Accusation[];
}

// Real [METRICS] positions from the capture log — NOT attention weights.
// This capture never re-ran the GAT with attention output requested (only
// the replay corpus's gat_attention does that); this is a real but
// distance-only "who was nearby" view. See app.py's capture_vehicle_neighbours.
export interface CaptureNeighbourDto {
  vehicle_id: number;
  pos_x: number;
  pos_y: number;
  distance_m: number;
  is_poisoned: boolean;
}

export interface CaptureNeighboursDto {
  vehicle_id: number;
  t: number;
  target_pos: { x: number; y: number };
  neighbours: CaptureNeighbourDto[];
}

// Real local IPFS daemon, queried/used live and on demand — NOT the
// simulator's own IPFS calls (those only happen during a run, and every
// captured run so far hit connection-refused and fell back to a fabricated
// FNV-1a hash; see CryptoSummaryDto's ipfs.note). A pin here is a genuine
// add against whatever daemon is actually reachable right now.
export interface IpfsStatusDto {
  reachable: boolean;
  peer_id?: string;
  addresses?: string[];
  version?: string;
  error?: string;
}

export interface IpfsPinResultDto {
  label: string;
  cid: string;
  size_bytes: number;
  gateway_url: string;
}

export interface AttackResultDto {
  MCC: number;
  MCC_std?: number;
  TTD?: number;
  CDER?: number;
  PBPO_ms?: number;
}

export interface AttackInfoDto {
  attack_number: number;
  code: string;
  human_name: string;
  actor: string;
  description: string;
  sentinel_full: AttackResultDto | null;
  sentinel_lw: AttackResultDto | null;
  baselines: Record<string, AttackResultDto>;
  best_baseline_code: string | null;
  best_baseline_mcc: number | null;
  baseline_wins: boolean;
  sample_scenario_id: string | null;
}

// The paper's own 11-variant ablation study (report/main.tex \subsection{AB1
// ..AB11}) — distinct from resultsAblation() above, which is a separate
// D1/D4/D6 time-cutoff analysis under one fixed scenario. AB8 has
// has_results=false: the paper itself discloses that ablation was never
// completed experimentally.
export interface AblationStudyDto {
  number: number;
  category: "Detection" | "Cryptography" | "Trust" | "Key Management";
  title: string;
  ablates: string;
  swept: string | null;
  headline: string | null;
  finding: string | null;
  caveat: string | null;
  citation: string;
  has_results: boolean;
}

// ── Run console (launches a REAL simulation process) ────────────────────────

export interface ModelCheckDto {
  ok: boolean;
  gat_model_link: { actual: string | null; expected: string; ok: boolean };
  theta_s: { actual: string | null; expected: string; ok: boolean };
  theta_ae: { actual: string | null; expected: string; ok: boolean };
}

export interface LaunchRunRequest {
  attack_number: number;
  attack_pct: number;
  sim_time: number;
  mobility_scenario: number;
  n_vehicles: number;
  n_rsus: number;
  enable_gat: boolean;
  enable_lstm_ae: boolean;
  enable_blockchain: boolean;
  seed: number;
  force?: boolean;
}

export interface RunProgressDto {
  phase: "starting" | "registering" | "simulating" | "finished";
  pct: number;
  sim_time_reached?: number;
  registered?: number;
  expected?: number;
  eta_seconds: number;
  mcc_full?: number | null;
  stale?: boolean;
}

// Live confusion matrix, accumulated from this run's own [FUSION-RSU*]
// lines as they're printed — real-time, not a final summary. See
// run_manager.py's update_live_metrics for why it tracks a byte offset
// instead of re-scanning a tail window (exactly-once counting).
export interface LiveMetricsDto {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  n_events: number;
  mcc: number;
  fpr: number;
}

// One real point per poll, keyed by the run's own simulated time — see
// run_manager.py's record_metrics_point. Grows live while a run is alive;
// this IS the "watch the attack actually happening" timeline, not a
// post-hoc file.
export interface MetricsHistoryPointDto extends LiveMetricsDto {
  t: number;
}

export interface RunRecordDto {
  run_id: string;
  pid: number;
  cmd: string[];
  log_path: string;
  config: LaunchRunRequest;
  started_at: number;
  model_check: ModelCheckDto;
  alive: boolean;
  progress?: RunProgressDto;
  live_metrics?: LiveMetricsDto;
  metrics_history?: MetricsHistoryPointDto[];
}

export interface CsvSourceDto {
  id: string;
  label: string;
  exists: boolean;
}

export interface CsvColumnsDto {
  columns: string[];
  row_count: number;
  preview: string[][];
  has_header: boolean;
}

export interface CsvDataDto {
  x: number[];
  y: number[];
  n_total: number;
  n_returned: number;
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

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => null);
    throw new Error(detail?.detail ?? `${path} -> HTTP ${res.status}`);
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
  lstmReconstruction: (scenarioId: string, vehicleId: number, endTime?: number) =>
    getJson<LstmReconstructionDto>(
      `/api/scenarios/${scenarioId}/lstm_reconstruction/${vehicleId}` +
        (endTime != null ? `?end_time=${endTime}` : "")
    ),
  gatAttention: (scenarioId: string, vehicleId: number, endTime?: number) =>
    getJson<GatAttentionDto>(
      `/api/scenarios/${scenarioId}/gat_attention/${vehicleId}` +
        (endTime != null ? `?end_time=${endTime}` : "")
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
  trafficSignals: (road: string) =>
    getJson<{ signals: TrafficSignalDto[] }>(`/api/roadmap/${road}/signals`),

  ledgerSummary: () => getJson<LedgerSummaryDto>("/api/ledger/summary"),
  ledgerTrust: (entity: "rsu" | "vehicle" | "controller") =>
    getJson<TrustRecordDto[]>(`/api/ledger/trust/${entity}`),
  ledgerRevocations: () => getJson<RevocationDto[]>("/api/ledger/revocations"),
  ledgerFlags: () => getJson<ControllerFlagDto[]>("/api/ledger/flags"),
  ledgerReassignments: () => getJson<ReassignmentDto[]>("/api/ledger/reassignments"),
  ledgerRefresh: () => postJson<{ status: string }>("/api/ledger/refresh", {}),
  ledgerRefreshStatus: () => getJson<LedgerRefreshStatusDto>("/api/ledger/refresh_status"),
  blocksRecent: () => getJson<BlocksRecentDto>("/api/ledger/blocks/recent"),
  explorerUrl: () => getJson<{ url: string | null }>("/api/explorer_url"),

  captureSummary: () => getJson<CaptureSummaryDto>("/api/capture/summary"),
  captureVehicles: () => getJson<CaptureVehicleRowDto[]>("/api/capture/vehicles"),
  captureVehicle: (vid: number) =>
    getJson<{ vid: number; events: FusionEventDto[] }>(`/api/capture/vehicle/${vid}`),
  ipfsStatus: () => getJson<IpfsStatusDto>("/api/ipfs/status"),
  ipfsPin: (label: string, payload: unknown) =>
    postJson<IpfsPinResultDto>("/api/ipfs/pin", { label, payload }),
  captureNeighbours: (vid: number, t: number) =>
    getJson<CaptureNeighboursDto>(`/api/capture/vehicle/${vid}/neighbours?t=${t}`),
  captureCryptoSummary: () => getJson<CryptoSummaryDto>("/api/capture/crypto_summary"),
  captureThresholdSweep: () => getJson<SweepPointDto[]>("/api/capture/threshold_sweep"),
  captureLayerAgreement: () => getJson<LayerAgreementDto>("/api/capture/layer_agreement"),
  captureLatencyHistogram: () => getJson<LatencyHistogramDto>("/api/capture/latency_histogram"),
  captureAttackEvidence: (attackNumber: number) =>
    getJson<AttackEvidenceDto>(`/api/capture/attack_evidence/${attackNumber}`),

  attacks: () => getJson<AttackInfoDto[]>("/api/attacks"),

  resultsE5: () => getJson<Record<string, any>>("/api/results/e5"),
  runsModelCheck: () => getJson<ModelCheckDto>("/api/runs/model-check"),
  runsLaunch: (req: LaunchRunRequest) =>
    postJson<RunRecordDto>("/api/runs", req),
  runsList: () => getJson<RunRecordDto[]>("/api/runs"),
  runsDetail: (runId: string) => getJson<RunRecordDto>(`/api/runs/${runId}`),
  runsStop: (runId: string) => postJson<{ stopped: boolean }>(`/api/runs/${runId}/stop`, {}),
  runLog: (runId: string, offset: number) =>
    getJson<{ lines: string[]; next_offset: number; done: boolean }>(
      `/api/runs/${runId}/log?offset=${offset}`
    ),

  csvSources: () => getJson<CsvSourceDto[]>("/api/csv_sources"),
  csvColumns: (sourceId: string) => getJson<CsvColumnsDto>(`/api/csv_sources/${sourceId}/columns`),
  csvData: (sourceId: string, x: string, y: string) =>
    getJson<CsvDataDto>(`/api/csv_sources/${sourceId}/data?x=${encodeURIComponent(x)}&y=${encodeURIComponent(y)}`),

  resultsAblation: () =>
    getJson<{
      source: string;
      config: string;
      windows: {
        cutoff_s: number;
        ordering_holds: boolean;
        arms: { D1: number; D4: number; D6: number };
        note?: string;
      }[];
    }>("/api/results/ablation"),

  resultsAblationStudies: () => getJson<AblationStudyDto[]>("/api/results/ablation_studies"),
};
