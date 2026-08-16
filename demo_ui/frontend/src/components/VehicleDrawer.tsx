import { useMemo, useState } from "react";
import {
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import { usePlayback } from "../store/playback";
import { useTokens } from "../design/tokens";
import Accordion from "./Accordion";

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

export default function VehicleDrawer() {
  const {
    selectedVehicle,
    vehicleTrack,
    loadingVehicle,
    selectVehicle,
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
  const [lstmOpen, setLstmOpen] = useState(false);
  const [gatOpen, setGatOpen] = useState(false);

  const series = useMemo(
    () =>
      (vehicleTrack ?? []).map((b) => ({
        t: Number(b.sim_time.toFixed(2)),
        psi: b.psi_score,
        drift: b.drift_m ?? 0,
        poisoned: b.is_poisoned ? 1 : 0,
        detected: b.detected ? 1 : 0,
      })),
    [vehicleTrack]
  );

  // The beacon nearest the current playback time — what the map is showing now.
  const current = useMemo(() => {
    if (!vehicleTrack?.length) return null;
    let best = vehicleTrack[0];
    for (const b of vehicleTrack) {
      if (Math.abs(b.sim_time - t) < Math.abs(best.sim_time - t)) best = b;
    }
    return best;
  }, [vehicleTrack, t]);

  if (selectedVehicle === null) return null;

  const poisonedCount = (vehicleTrack ?? []).filter((b) => b.is_poisoned).length;
  const missedCount = (vehicleTrack ?? []).filter(
    (b) => b.is_poisoned && !b.detected
  ).length;

  return (
    <aside className="flex w-[420px] shrink-0 flex-col overflow-hidden border-l border-surface-hairline bg-surface-panel">
      <header className="flex items-center justify-between border-b border-surface-hairline px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-ink-primary">
            Vehicle {selectedVehicle}
            {current?.is_ghost && (
              <span className="ml-2 rounded bg-entity-ghost/20 px-1.5 py-0.5 text-[10px] font-medium text-entity-ghost">
                GHOST IDENTITY
              </span>
            )}
          </h2>
          <p className="text-[11px] text-ink-muted">
            {vehicleTrack?.length ?? 0} beacons in this run
          </p>
        </div>
        <button
          className="rounded px-2 py-1 text-lg leading-none text-ink-muted hover:bg-surface-raised hover:text-ink-primary"
          onClick={() => selectVehicle(null)}
          aria-label="Close"
        >
          ×
        </button>
      </header>

      {loadingVehicle && (
        <div className="p-4 text-xs text-ink-muted">Loading trajectory…</div>
      )}

      {!loadingVehicle && vehicleTrack && (
        <div className="flex-1 space-y-4 overflow-y-auto p-4">
          <section className="rounded-lg border border-surface-hairline bg-surface-raised p-3">
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
              At t = {t.toFixed(1)}s
            </h3>
            {current ? (
              <>
                <Row
                  label="Status"
                  value={
                    current.is_poisoned ? (
                      current.detected ? (
                        <span className="text-status-caught">Lying — caught</span>
                      ) : (
                        <span className="text-status-missed">Lying — MISSED</span>
                      )
                    ) : (
                      <span className="text-status-good">Honest</span>
                    )
                  }
                />
                <Row label="Attacker type" value={current.attacker_class_plain} />
                <Row label="Reported by" value={`RSU ${current.rsu_id}`} />
                <Row label="Speed" value={`${current.speed.toFixed(1)} m/s`} />
                <Row
                  label="Position error"
                  value={
                    current.drift_m == null
                      ? "n/a (fabricated ID)"
                      : `${current.drift_m.toFixed(1)} m`
                  }
                />
                <Row label="ψ score" value={current.psi_score.toFixed(3)} />
              </>
            ) : (
              <p className="text-xs text-ink-muted">No beacon at this time.</p>
            )}
          </section>

          <section className="rounded-lg border border-surface-hairline bg-surface-raised p-3">
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
              Why it was flagged
            </h3>
            {current && current.accusations.length > 0 ? (
              <ul className="space-y-2">
                {current.accusations.map((a) => (
                  <li key={a.code}>
                    <div className="flex items-baseline justify-between gap-2">
                      <span className="text-xs font-medium text-ink-primary">
                        {a.name}
                      </span>
                      <span className="font-mono text-[10px] text-ink-muted">
                        {a.code} · w={a.weight}
                      </span>
                    </div>
                    <p className="text-[11px] leading-snug text-ink-secondary">
                      {a.detail}
                    </p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-ink-muted">
                {current?.is_poisoned
                  ? "No rule signature fired — this lie went unnoticed by the signature tier."
                  : "No signatures tripped."}
              </p>
            )}
          </section>

          {!current?.is_ghost && (
            <Accordion
              open={lstmOpen}
              onToggle={() => {
                if (!lstmOpen && !lstmReconstruction && !lstmLoading) loadLstmReconstruction();
                setLstmOpen((v) => !v);
              }}
              bodyMaxHeight={340}
              header={
                <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                  LSTM-AE reconstruction — real, offline
                </span>
              }
            >
              <div className="border-t border-surface-hairline p-3">
                {lstmLoading && (
                  <p className="text-xs text-ink-muted">
                    Running real inference against the deployed model…
                  </p>
                )}
                {lstmError && <p className="text-xs text-status-missed">{lstmError}</p>}
                {lstmReconstruction && (
                  <>
                    <div className="mb-2.5 flex items-baseline justify-between">
                      <span className="text-[11px] text-ink-muted">Reconstruction error</span>
                      <span
                        className={`font-mono text-sm font-semibold ${
                          lstmReconstruction.flagged ? "text-status-missed" : "text-status-good"
                        }`}
                      >
                        {lstmReconstruction.ae_raw_estimate.toFixed(2)} / θ=
                        {lstmReconstruction.theta_ae.toFixed(2)}
                      </span>
                    </div>
                    <div className="space-y-1.5">
                      {lstmReconstruction.feature_names.map((name, i) => {
                        const v = lstmReconstruction.per_channel_mse_z[i];
                        const tone = v > 10 ? "text-status-missed" : v > 1 ? "text-status-caught" : "text-status-good";
                        return (
                          <div key={name} className="flex items-center justify-between gap-2 text-[10.5px]">
                            <span className="text-ink-secondary">{CHANNEL_LABEL[name] ?? name}</span>
                            <span className={`font-mono ${tone}`}>{v.toFixed(3)}</span>
                          </div>
                        );
                      })}
                    </div>
                    <p className="mt-2.5 text-[10px] leading-relaxed text-ink-muted">
                      Per-channel MSE (z-scaled residual units) from the
                      deployed ONNX model's reconstruction of this vehicle's
                      last {lstmReconstruction.window} beacons — the same
                      artifact the simulator loads, run offline and read-only.
                      An "expected trajectory" line — same reported
                      speed/heading, model-reconstructed deviation — is drawn
                      on the map alongside the real one.
                    </p>
                  </>
                )}
              </div>
            </Accordion>
          )}

          {!current?.is_ghost && (
            <Accordion
              open={gatOpen}
              onToggle={() => {
                if (!gatOpen && !gatAttention && !gatLoading) loadGatAttention();
                setGatOpen((v) => !v);
              }}
              bodyMaxHeight={340}
              header={
                <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                  GAT attention — real, offline
                </span>
              }
            >
              <div className="border-t border-surface-hairline p-3">
                {gatLoading && (
                  <p className="text-xs text-ink-muted">
                    Running real inference against the deployed model…
                  </p>
                )}
                {gatError && <p className="text-xs text-status-missed">{gatError}</p>}
                {gatAttention && (
                  <>
                    <div className="mb-1 flex items-baseline justify-between">
                      <span className="text-[11px] text-ink-muted">Spatial anomaly score</span>
                      <span className="font-mono text-sm font-semibold text-ink-primary">
                        {gatAttention.score.toFixed(2)}
                      </span>
                    </div>
                    <div className="mb-2.5 flex items-center gap-1.5 text-[10px]">
                      <span
                        className={gatAttention.score_verified ? "text-status-good" : "text-status-missed"}
                      >
                        {gatAttention.score_verified ? "✓ verified against deployed model" : "⚠ NOT verified"}
                      </span>
                      <span className="text-ink-muted">
                        (Δ{gatAttention.score_onnx_cross_check_max_abs_diff.toExponential(1)})
                      </span>
                    </div>
                    {gatAttention.neighbours.length === 0 ? (
                      <p className="text-xs text-ink-muted">
                        No other vehicle was within range and heading-aligned in this
                        snapshot — this vehicle's embedding came from itself alone.
                      </p>
                    ) : (
                      <>
                        <p className="mb-1.5 text-[10px] uppercase tracking-wider text-ink-muted">
                          Who it attended to ({gatAttention.snapshot_size - 1} in range)
                        </p>
                        <div className="space-y-1.5">
                          {gatAttention.neighbours.map((n) => (
                            <div key={n.vehicle_id} className="flex items-center gap-2 text-[10.5px]">
                              <span className="w-12 shrink-0 font-mono text-ink-primary">
                                V{n.vehicle_id}
                              </span>
                              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-page">
                                <div
                                  className="h-full rounded-full"
                                  style={{
                                    width: `${n.attention_weight * 100}%`,
                                    background: n.is_poisoned ? STATUS.missed : SERIES[0],
                                  }}
                                />
                              </div>
                              <span className="w-10 shrink-0 text-right font-mono text-ink-secondary">
                                {(n.attention_weight * 100).toFixed(0)}%
                              </span>
                              <span className="w-14 shrink-0 text-right text-ink-muted">
                                {n.distance_m.toFixed(0)}m
                              </span>
                            </div>
                          ))}
                        </div>
                      </>
                    )}
                    <p className="mt-2.5 text-[10px] leading-relaxed text-ink-muted">
                      Real attention weights from the deployed GAT's first
                      layer, extracted by re-running its own weights (not a
                      separately-tracked checkpoint) with attention output
                      requested — the ONNX file never exposes this itself.
                      Neighbour set approximates this vehicle's real-time RSU
                      window; the score above is illustrative of scale, not
                      calibrated to θ_S. Lines to each neighbour are drawn on
                      the map, weighted by attention share.
                    </p>
                  </>
                )}
              </div>
            </Accordion>
          )}

          <section className="rounded-lg border border-surface-hairline bg-surface-raised p-3">
            <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
              Suspicion score over time
            </h3>
            <p className="mb-2 text-[10px] text-ink-muted">
              ψ vs its decision threshold ({PSI_TH})
            </p>
            <div className="h-36">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={series} margin={{ top: 4, right: 8, bottom: 4, left: -12 }}>
                  <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                  <XAxis
                    dataKey="t"
                    tick={{ fill: INK.muted, fontSize: 10 }}
                    stroke={axisStroke}
                  />
                  <YAxis tick={{ fill: INK.muted, fontSize: 10 }} stroke={axisStroke} />
                  <Tooltip
                    contentStyle={{
                      background: SURFACE.raised,
                      border: `1px solid ${SURFACE.hairline}`,
                      borderRadius: 6,
                      fontSize: 11,
                    }}
                    labelStyle={{ color: INK.secondary }}
                  />
                  <ReferenceLine
                    y={PSI_TH}
                    stroke={STATUS.caught}
                    strokeDasharray="4 3"
                  />
                  <ReferenceLine x={Number(t.toFixed(2))} stroke={`${INK.primary}44`} />
                  <Line
                    type="monotone"
                    dataKey="psi"
                    stroke={SERIES[0]}
                    strokeWidth={2}
                    dot={false}
                    isAnimationActive={false}
                    name="ψ"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </section>

          {!current?.is_ghost && (
            <section className="rounded-lg border border-surface-hairline bg-surface-raised p-3">
              <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                How far the claim drifted from reality
              </h3>
              <p className="mb-2 text-[10px] text-ink-muted">metres between claim and truth</p>
              <div className="h-32">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={series} margin={{ top: 4, right: 8, bottom: 4, left: -12 }}>
                    <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                    <XAxis
                      dataKey="t"
                      tick={{ fill: INK.muted, fontSize: 10 }}
                      stroke={axisStroke}
                    />
                    <YAxis tick={{ fill: INK.muted, fontSize: 10 }} stroke={axisStroke} />
                    <Tooltip
                      contentStyle={{
                        background: SURFACE.raised,
                        border: `1px solid ${SURFACE.hairline}`,
                        borderRadius: 6,
                        fontSize: 11,
                      }}
                      labelStyle={{ color: INK.secondary }}
                    />
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
            </section>
          )}

          <section className="rounded-lg border border-surface-hairline bg-surface-raised p-3">
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
              Whole-run summary
            </h3>
            <Row label="Beacons sent" value={vehicleTrack.length} />
            <Row label="Of those, lies" value={poisonedCount} />
            <Row
              label="Lies that slipped through"
              value={
                <span className={missedCount ? "text-status-missed" : ""}>
                  {missedCount}
                </span>
              }
            />
          </section>
        </div>
      )}
    </aside>
  );
}
