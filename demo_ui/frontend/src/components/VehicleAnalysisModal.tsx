import { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  Cell,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import { CircleSlash } from "lucide-react";
import { api, IpfsPinResultDto } from "../api";
import { usePlayback } from "../store/playback";
import { useTokens } from "../design/tokens";
import { currentBeaconAt } from "./vehicleTrack";
import Accordion from "./Accordion";
import DrillModal from "./DrillModal";
import EgoGraph from "./EgoGraph";
import StatusPill, { SemanticStatus } from "./StatusPill";

const PSI_TH = 0.09; // 08_detection_engine.h — the rule-signature decision line

// scaler.json feature order — see demo_ui/backend/ml_scripts/lstm_reconstruct.py.
const CHANNEL_LABEL: Record<string, string> = {
  res_x: "sideways drift",
  res_y: "forward drift",
  dspeed: "speed change",
  dheading: "turn rate",
  accel: "acceleration",
  tau_i: "trust signal",
};

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <span className="text-xs text-ink-muted">{label}</span>
      <span className="text-right text-xs font-medium text-ink-primary">{value}</span>
    </div>
  );
}

function OverviewStat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="rounded-lg border border-surface-hairline bg-surface-page p-3 text-center">
      <div className="text-badge font-semibold uppercase tracking-wide text-ink-muted">{label}</div>
      <div className={`mt-1 font-mono text-lg font-bold ${tone ?? "text-ink-primary"}`}>{value}</div>
    </div>
  );
}

/**
 * Never a raw HTTP/error string in the UI — this is the ONE place a failed
 * or not-applicable analysis renders, so a 404 never leaks as
 * "/api/scenarios/.../lstm_reconstruction/... -> HTTP 404" the way the raw
 * store error does internally.
 */
function AnalysisUnavailable({ detail }: { detail?: string }) {
  return (
    <div className="flex flex-col items-center gap-1.5 rounded-lg border border-dashed border-surface-hairline2 bg-surface-page px-4 py-8 text-center">
      <CircleSlash size={18} className="text-ink-muted" aria-hidden />
      <p className="text-xs font-medium text-ink-secondary">Analysis unavailable</p>
      <p className="max-w-xs text-[11px] leading-relaxed text-ink-muted">
        {detail ?? "This analysis was not generated for the selected replay scenario."}
      </p>
    </div>
  );
}

function ChartSkeleton({ label, height = 200 }: { label: string; height?: number }) {
  return (
    <div>
      <p className="mb-2 text-[10px] text-ink-muted">{label}</p>
      <div className="animate-pulse rounded-lg bg-surface-page" style={{ height }} />
    </div>
  );
}

type SectionState = "loading" | "unavailable" | "not_applicable" | "ready";

export default function VehicleAnalysisModal({
  open,
  onClose,
  origin,
}: {
  open: boolean;
  onClose: () => void;
  origin: { dx: number; dy: number };
}) {
  const {
    scenarioId,
    selectedVehicle,
    vehicleTrack,
    t,
    lstmReconstruction,
    lstmLoading,
    lstmError,
    loadLstmReconstruction,
    gatAttention,
    gatLoading,
    gatError,
    loadGatAttention,
  } = usePlayback();
  const { SERIES, STATUS, INK, SURFACE } = useTokens();
  const axisStroke = SURFACE.hairlineStrong;
  const [ruleOpen, setRuleOpen] = useState(false);
  const [summaryOpen, setSummaryOpen] = useState(false);
  const [ipfsPinning, setIpfsPinning] = useState(false);
  const [ipfsResult, setIpfsResult] = useState<IpfsPinResultDto | null>(null);
  const [ipfsPinError, setIpfsPinError] = useState<string | null>(null);

  const current = useMemo(() => currentBeaconAt(vehicleTrack, t), [vehicleTrack, t]);

  // A pin from a previous vehicle/track shouldn't linger once the selection
  // changes underneath this modal.
  useEffect(() => {
    setIpfsResult(null);
    setIpfsPinError(null);
    setIpfsPinning(false);
  }, [selectedVehicle]);

  const pinToIpfs = async () => {
    if (!vehicleTrack || selectedVehicle == null) return;
    setIpfsPinning(true);
    setIpfsPinError(null);
    try {
      const result = await api.ipfsPin(`${(scenarioId ?? "scenario").replace(/\//g, "_")}_veh${selectedVehicle}`, {
        scenario_id: scenarioId,
        vehicle_id: selectedVehicle,
        beacon_count: vehicleTrack.length,
        beacons: vehicleTrack,
      });
      setIpfsResult(result);
    } catch (e) {
      setIpfsPinError(String(e));
    } finally {
      setIpfsPinning(false);
    }
  };

  // The moment the modal opens is the "on demand" trigger for both real
  // model inferences — they used to be gated behind expanding an accordion
  // in the sidebar; opening Full Analysis is the equivalent deliberate
  // action now that those accordions live here instead.
  useEffect(() => {
    if (!open || selectedVehicle == null || current?.is_ghost) return;
    if (!lstmReconstruction && !lstmLoading && !lstmError) loadLstmReconstruction();
    if (!gatAttention && !gatLoading && !gatError) loadGatAttention();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, selectedVehicle]);

  const series = useMemo(
    () =>
      (vehicleTrack ?? []).map((b) => ({
        t: Number(b.sim_time.toFixed(2)),
        psi: b.psi_score,
        drift: b.drift_m ?? 0,
      })),
    [vehicleTrack]
  );

  if (selectedVehicle === null || !vehicleTrack) return null;

  const poisonedCount = vehicleTrack.filter((b) => b.is_poisoned).length;
  const missedCount = vehicleTrack.filter((b) => b.is_poisoned && !b.detected).length;

  const decision: { status: SemanticStatus; label: string } = !current
    ? { status: "inactive", label: "NO DATA" }
    : !current.is_poisoned
    ? { status: "safe", label: "HONEST" }
    : current.detected
    ? { status: "warning", label: "LYING — CAUGHT" }
    : { status: "compromised", label: "LYING — MISSED" };

  const isGhost = !!current?.is_ghost;
  const lstmState: SectionState = isGhost ? "not_applicable" : lstmError ? "unavailable" : lstmReconstruction ? "ready" : "loading";
  const gatState: SectionState = isGhost ? "not_applicable" : gatError ? "unavailable" : gatAttention ? "ready" : "loading";

  const lstmBars = lstmReconstruction
    ? lstmReconstruction.feature_names.map((name, i) => ({
        name: CHANNEL_LABEL[name] ?? name,
        z: lstmReconstruction.per_channel_mse_z[i],
      }))
    : [];
  const zTone = (v: number) => (v > 10 ? STATUS.missed : v > 1 ? STATUS.caught : STATUS.good);

  const gatBars = gatAttention
    ? gatAttention.neighbours.map((n) => ({
        name: `V${n.vehicle_id}`,
        weight: Number((n.attention_weight * 100).toFixed(1)),
        poisoned: n.is_poisoned,
        distance: n.distance_m,
      }))
    : [];

  // Same beacons already fetched for the bar chart above, re-shaped into one
  // real actual-vs-reconstructed series per channel (feature_names order).
  const lstmChannelSeries = lstmReconstruction
    ? lstmReconstruction.feature_names.map((name, i) => ({
        key: name,
        label: CHANNEL_LABEL[name] ?? name,
        points: lstmReconstruction.beacons.map((b) => ({
          t: Number(b.t.toFixed(2)),
          actual: b.actual_raw[i],
          reconstructed: b.reconstructed_raw[i],
        })),
      }))
    : [];

  // Same neighbours already fetched for the bar chart above, laid out at
  // their real position relative to the target instead of ranked by weight.
  const gatNodes = gatAttention
    ? gatAttention.neighbours.map((n) => ({
        id: n.vehicle_id,
        dx: n.pos_x - gatAttention.target_pos.x,
        dy: n.pos_y - gatAttention.target_pos.y,
        weight: n.attention_weight,
        distance: n.distance_m,
        poisoned: n.is_poisoned,
      }))
    : [];

  return (
    <DrillModal
      open={open}
      onClose={onClose}
      origin={origin}
      title={`Vehicle ${selectedVehicle} — Full Analysis`}
      badge={<StatusPill status={decision.status}>{decision.label}</StatusPill>}
      maxWidth="max-w-4xl"
    >
      {/* Level 1 — what happened */}
      <section>
        <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
          Analysis overview
        </p>
        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
          <OverviewStat label="Status" value={decision.label} />
          <OverviewStat label="Attacker type" value={current?.attacker_class_plain ?? "—"} />
          <OverviewStat
            label="Position error"
            value={current?.drift_m != null ? `${current.drift_m.toFixed(1)} m` : "n/a"}
          />
          <OverviewStat label="ψ score" value={current ? current.psi_score.toFixed(3) : "—"} />
        </div>
      </section>

      {/* Level 2 — why */}
      <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
        <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
          Why it was flagged
        </h3>
        {current && current.accusations.length > 0 ? (
          <p className="text-body leading-relaxed text-ink-secondary">
            <span className="font-medium text-ink-primary">{current.accusations[0].name}.</span>{" "}
            {current.accusations[0].detail}
          </p>
        ) : (
          <p className="text-body text-ink-muted">
            {current?.is_poisoned
              ? "No rule signature fired — this lie went unnoticed by the signature tier."
              : "No signatures tripped."}
          </p>
        )}
      </section>

      {/* Level 3 — visual evidence */}
      <p className="mt-1.5 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
        Visual evidence — what the models observed
      </p>

      <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
        <h3 className="mb-3 text-body font-semibold text-ink-primary">
          LSTM-AE reconstruction — time-pattern analysis
        </h3>
        {lstmState === "not_applicable" && (
          <AnalysisUnavailable detail="Not applicable — a fabricated (ghost) identity has no real trajectory to reconstruct." />
        )}
        {lstmState === "loading" && <ChartSkeleton label="Loading LSTM-AE analysis…" height={220} />}
        {lstmState === "unavailable" && <AnalysisUnavailable />}
        {lstmState === "ready" && lstmReconstruction && (
          <>
            <div className="mb-3 flex items-baseline justify-between">
              <span className="text-xs text-ink-muted">Reconstruction error</span>
              <span
                className={`font-mono text-base font-semibold ${
                  lstmReconstruction.flagged ? "text-status-missed" : "text-status-good"
                }`}
              >
                {lstmReconstruction.ae_raw_estimate.toFixed(2)} / θ={lstmReconstruction.theta_ae.toFixed(2)}
              </span>
            </div>
            <div className="h-52">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={lstmBars} layout="vertical" margin={{ top: 8, right: 28, bottom: 8, left: 8 }}>
                  <CartesianGrid stroke={SURFACE.hairline} horizontal={false} />
                  <XAxis type="number" tick={{ fill: INK.muted, fontSize: 11 }} stroke={axisStroke} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={110}
                    tick={{ fill: INK.secondary, fontSize: 11 }}
                    stroke={axisStroke}
                  />
                  <Tooltip
                    contentStyle={{
                      background: SURFACE.raised,
                      border: `1px solid ${SURFACE.hairline}`,
                      borderRadius: 6,
                      fontSize: 12,
                    }}
                    labelStyle={{ color: INK.secondary }}
                  />
                  <Bar dataKey="z" name="z-scaled residual" radius={[0, 4, 4, 0]}>
                    {lstmBars.map((d, i) => (
                      <Cell key={i} fill={zTone(d.z)} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-ink-muted">
              Per-channel MSE (z-scaled residual units) from the deployed ONNX model's reconstruction of this
              vehicle's last {lstmReconstruction.window} beacons — the same artifact the simulator loads, run
              offline and read-only. An "expected trajectory" line is drawn on the map alongside the real one.
            </p>
          </>
        )}
      </section>

      {lstmState === "ready" && lstmReconstruction && lstmReconstruction.beacons.length > 0 && (
        <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
          <h3 className="mb-1 text-body font-semibold text-ink-primary">
            LSTM-AE reconstruction — actual vs. reconstructed
          </h3>
          <p className="mb-3 text-[11px] text-ink-muted">
            Same real reconstruction as above, per channel over the last {lstmReconstruction.window} beacons —
            solid is what was reported, dashed is what the autoencoder expected.
          </p>
          <div className="mb-2 flex items-center justify-center gap-4 text-[10px] text-ink-muted">
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-0.5 w-4" style={{ background: SERIES[0] }} /> actual
            </span>
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-0.5 w-4 border-t-2 border-dashed" style={{ borderColor: SERIES[1] }} />{" "}
              reconstructed
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {lstmChannelSeries.map((ch) => (
              <div key={ch.key} className="rounded-md border border-surface-hairline bg-surface-page p-2">
                <p className="mb-1 text-center text-[10px] font-medium text-ink-secondary">{ch.label}</p>
                <div className="h-24">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={ch.points} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
                      <XAxis dataKey="t" hide />
                      <YAxis hide domain={["auto", "auto"]} />
                      <Tooltip
                        contentStyle={{
                          background: SURFACE.raised,
                          border: `1px solid ${SURFACE.hairline}`,
                          borderRadius: 6,
                          fontSize: 11,
                        }}
                        labelStyle={{ color: INK.secondary }}
                        labelFormatter={(v) => `t=${v}s`}
                      />
                      <Line
                        type="monotone"
                        dataKey="actual"
                        stroke={SERIES[0]}
                        strokeWidth={1.75}
                        dot={false}
                        isAnimationActive={false}
                        name="actual"
                      />
                      <Line
                        type="monotone"
                        dataKey="reconstructed"
                        stroke={SERIES[1]}
                        strokeWidth={1.75}
                        strokeDasharray="3 2"
                        dot={false}
                        isAnimationActive={false}
                        name="reconstructed"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
        <h3 className="mb-3 text-body font-semibold text-ink-primary">GAT spatial analysis — real, offline</h3>
        {gatState === "not_applicable" && (
          <AnalysisUnavailable detail="Not applicable — a fabricated (ghost) identity was never embedded by the deployed GAT." />
        )}
        {gatState === "loading" && <ChartSkeleton label="Loading GAT analysis…" height={220} />}
        {gatState === "unavailable" && <AnalysisUnavailable />}
        {gatState === "ready" && gatAttention && (
          <>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs text-ink-muted">Spatial anomaly score</span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-semibold text-ink-primary">
                  {gatAttention.score.toFixed(2)}
                </span>
                <span className={`text-[11px] ${gatAttention.score_verified ? "text-status-good" : "text-status-missed"}`}>
                  {gatAttention.score_verified ? "✓ verified against deployed model" : "⚠ NOT verified"}
                </span>
              </div>
            </div>
            {gatAttention.neighbours.length === 0 ? (
              <p className="text-xs text-ink-muted">
                No other vehicle was within range and heading-aligned in this snapshot — this vehicle's embedding
                came from itself alone.
              </p>
            ) : (
              <>
                <p className="mb-2 text-[10px] uppercase tracking-wider text-ink-muted">
                  Who it attended to ({gatAttention.snapshot_size - 1} in range)
                </p>
                <div className="h-52">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={gatBars} layout="vertical" margin={{ top: 8, right: 28, bottom: 8, left: 8 }}>
                      <CartesianGrid stroke={SURFACE.hairline} horizontal={false} />
                      <XAxis
                        type="number"
                        unit="%"
                        tick={{ fill: INK.muted, fontSize: 11 }}
                        stroke={axisStroke}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        width={56}
                        tick={{ fill: INK.secondary, fontSize: 11 }}
                        stroke={axisStroke}
                      />
                      <Tooltip
                        contentStyle={{
                          background: SURFACE.raised,
                          border: `1px solid ${SURFACE.hairline}`,
                          borderRadius: 6,
                          fontSize: 12,
                        }}
                        labelStyle={{ color: INK.secondary }}
                        formatter={(value: number, _n, p: any) => [`${value}% · ${p.payload.distance.toFixed(0)}m away`, "attention"]}
                      />
                      <Bar dataKey="weight" name="attention share" radius={[0, 4, 4, 0]}>
                        {gatBars.map((d, i) => (
                          <Cell key={i} fill={d.poisoned ? STATUS.missed : SERIES[0]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </>
            )}
            <p className="mt-3 text-[11px] leading-relaxed text-ink-muted">
              Real attention weights from the deployed GAT's first layer, extracted by re-running its own weights
              with attention output requested. Lines to each neighbour are drawn on the map, weighted by
              attention share.
            </p>
          </>
        )}
      </section>

      {gatState === "ready" && gatAttention && (
        <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
          <h3 className="mb-1 text-body font-semibold text-ink-primary">GAT spatial analysis — ego-graph</h3>
          <p className="mb-3 text-[11px] text-ink-muted">
            Same real attention weights as above, laid out at each neighbour's actual relative position — edge
            thickness is attention share, node colour is honest/poisoned.
          </p>
          <EgoGraph centerLabel={`V${selectedVehicle} (this vehicle)`} nodes={gatNodes} edgeUnit="attention" />
        </section>
      )}

      <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
        <h3 className="mb-1 text-body font-semibold text-ink-primary">Suspicion score over time</h3>
        <p className="mb-3 text-[11px] text-ink-muted">ψ vs its decision threshold ({PSI_TH})</p>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={series} margin={{ top: 8, right: 24, bottom: 8, left: 8 }}>
              <CartesianGrid stroke={SURFACE.hairline} />
              <XAxis
                dataKey="t"
                tick={{ fill: INK.muted, fontSize: 11 }}
                stroke={axisStroke}
                label={{ value: "time (s)", position: "insideBottom", offset: -6, fill: INK.muted, fontSize: 10 }}
              />
              <YAxis
                tick={{ fill: INK.muted, fontSize: 11 }}
                stroke={axisStroke}
                label={{ value: "ψ", angle: -90, position: "insideLeft", fill: INK.muted, fontSize: 10 }}
              />
              <Tooltip
                contentStyle={{
                  background: SURFACE.raised,
                  border: `1px solid ${SURFACE.hairline}`,
                  borderRadius: 6,
                  fontSize: 12,
                }}
                labelStyle={{ color: INK.secondary }}
              />
              <Legend wrapperStyle={{ fontSize: 11, color: INK.secondary }} />
              <ReferenceLine
                y={PSI_TH}
                stroke={STATUS.caught}
                strokeDasharray="4 3"
                label={{ value: `decision threshold`, position: "insideTopRight", fill: STATUS.caught, fontSize: 10 }}
              />
              <ReferenceLine x={Number(t.toFixed(2))} stroke={`${INK.primary}44`} />
              <Line
                type="monotone"
                dataKey="psi"
                stroke={SERIES[0]}
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
                name="ψ score"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
        <h3 className="mb-1 text-body font-semibold text-ink-primary">Metres between claim and truth</h3>
        <p className="mb-3 text-[11px] text-ink-muted">reported position vs ground truth, over time</p>
        {isGhost ? (
          <AnalysisUnavailable detail="Not applicable — a fabricated (ghost) identity has no ground-truth position to compare against." />
        ) : (
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={series} margin={{ top: 8, right: 24, bottom: 8, left: 8 }}>
                <CartesianGrid stroke={SURFACE.hairline} />
                <XAxis
                  dataKey="t"
                  tick={{ fill: INK.muted, fontSize: 11 }}
                  stroke={axisStroke}
                  label={{ value: "time (s)", position: "insideBottom", offset: -6, fill: INK.muted, fontSize: 10 }}
                />
                <YAxis
                  tick={{ fill: INK.muted, fontSize: 11 }}
                  stroke={axisStroke}
                  label={{ value: "metres", angle: -90, position: "insideLeft", fill: INK.muted, fontSize: 10 }}
                />
                <Tooltip
                  contentStyle={{
                    background: SURFACE.raised,
                    border: `1px solid ${SURFACE.hairline}`,
                    borderRadius: 6,
                    fontSize: 12,
                  }}
                  labelStyle={{ color: INK.secondary }}
                />
                <Legend wrapperStyle={{ fontSize: 11, color: INK.secondary }} />
                <ReferenceLine x={Number(t.toFixed(2))} stroke={`${INK.primary}44`} />
                <Line
                  type="monotone"
                  dataKey="drift"
                  stroke={SERIES[1]}
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                  name="drift (m)"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </section>

      <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
        <h3 className="mb-1 text-body font-semibold text-ink-primary">Off-chain evidence — pin to IPFS (live)</h3>
        <p className="mb-3 text-[11px] leading-relaxed text-ink-muted">
          Every captured run so far hit connection-refused against the IPFS daemon and fell back to a
          deterministic stand-in hash (see Results &amp; Ablation's IPFS card). This talks to the real daemon
          running right now — pinning this vehicle's actual beacon window and returning a genuine
          content-addressed CID, not a simulated one.
        </p>
        {!ipfsResult && (
          <button
            onClick={pinToIpfs}
            disabled={ipfsPinning}
            className="rounded-md bg-entity-rsu px-3 py-1.5 text-xs font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {ipfsPinning ? "Pinning…" : `Pin this vehicle's beacon window (${vehicleTrack.length} beacons)`}
          </button>
        )}
        {ipfsPinError && (
          <p className="mt-2 text-[11px] text-status-missed">{ipfsPinError}</p>
        )}
        {ipfsResult && (
          <div className="flex flex-col gap-1.5 rounded-md border border-surface-hairline bg-surface-page p-3 text-[11px]">
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-ink-muted">CID</span>
              <span className="font-mono text-ink-primary">{ipfsResult.cid}</span>
            </div>
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-ink-muted">Size</span>
              <span className="font-mono text-ink-secondary">{ipfsResult.size_bytes.toLocaleString()} bytes</span>
            </div>
            <a
              href={ipfsResult.gateway_url}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-1 font-medium text-entity-rsu hover:underline"
            >
              Open on the real IPFS gateway →
            </a>
          </div>
        )}
      </section>

      {/* Level 4 — technical evidence, collapsed by default */}
      <p className="mt-1.5 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
        Advanced technical evidence
      </p>

      {current && current.accusations.length > 0 && (
        <Accordion
          open={ruleOpen}
          onToggle={() => setRuleOpen((v) => !v)}
          bodyMaxHeight={360}
          header={
            <span className="text-body font-semibold text-ink-primary">
              Rule / signature evidence ({current.accusations.length})
            </span>
          }
        >
          <div className="border-t border-surface-hairline p-4">
            <ul className="space-y-2.5">
              {current.accusations.map((a) => (
                <li key={a.code}>
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs font-medium text-ink-primary">{a.name}</span>
                    <span className="font-mono text-[10px] text-ink-muted">
                      {a.code} · w={a.weight}
                    </span>
                  </div>
                  <p className="text-[11px] leading-snug text-ink-secondary">{a.detail}</p>
                </li>
              ))}
            </ul>
          </div>
        </Accordion>
      )}

      <Accordion
        open={summaryOpen}
        onToggle={() => setSummaryOpen((v) => !v)}
        bodyMaxHeight={200}
        header={<span className="text-body font-semibold text-ink-primary">Whole-run summary</span>}
      >
        <div className="border-t border-surface-hairline p-4">
          <Row label="Beacons sent" value={vehicleTrack.length} />
          <Row label="Of those, lies" value={poisonedCount} />
          <Row
            label="Lies that slipped through"
            value={<span className={missedCount ? "text-status-missed" : ""}>{missedCount}</span>}
          />
        </div>
      </Accordion>
    </DrillModal>
  );
}
