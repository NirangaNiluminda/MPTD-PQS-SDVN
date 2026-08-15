import { useEffect, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  api,
  CaptureSummaryDto,
  CaptureVehicleRowDto,
  FusionEventDto,
} from "../api";
import { useTokens } from "../design/tokens";
import Accordion from "../components/Accordion";

const GHOST_VID_BASE = 10000;
const PHI_TH = 0.5; // fusion decision threshold, 08_detection_engine.h FusionParams default
// Same constant as demo_ui/backend/parsers/capture_analytics.py's THETA_AE —
// this run's AE alarm point, confirmed via the [AI-INIT] startup line, not a
// per-event field so it can't be read off `current` itself.
const THETA_AE = 33.693885;

function VehicleRow({
  row,
  selected,
  onClick,
}: {
  row: CaptureVehicleRowDto;
  selected: boolean;
  onClick: () => void;
}) {
  const isGhost = row.vid >= GHOST_VID_BASE;
  return (
    <button
      onClick={onClick}
      className={`flex w-full items-center gap-2 border-b border-surface-hairline/60 px-3 py-2 text-left text-xs transition-colors hover:bg-surface-raised ${
        selected ? "bg-surface-raised" : ""
      }`}
    >
      <span className="font-mono text-ink-primary">V{row.vid}</span>
      {isGhost && (
        <span className="rounded bg-entity-ghost/20 px-1.5 py-0.5 text-[10px] text-entity-ghost">
          GHOST
        </span>
      )}
      <span className="ml-auto text-ink-muted">{row.events} ev</span>
      {row.missed > 0 ? (
        <span className="rounded bg-status-missed/20 px-1.5 py-0.5 text-[10px] font-medium text-status-missed">
          {row.missed} missed
        </span>
      ) : row.gt_poisoned > 0 ? (
        <span className="rounded bg-status-caught/20 px-1.5 py-0.5 text-[10px] font-medium text-status-caught">
          all caught
        </span>
      ) : (
        <span className="rounded bg-status-good/15 px-1.5 py-0.5 text-[10px] text-status-good">
          clean
        </span>
      )}
    </button>
  );
}

export default function DefenceInspectorScreen() {
  const { SERIES, STATUS, INK, SURFACE } = useTokens();
  const [summary, setSummary] = useState<CaptureSummaryDto | null>(null);
  const [vehicles, setVehicles] = useState<CaptureVehicleRowDto[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [events, setEvents] = useState<FusionEventDto[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [openSignal, setOpenSignal] = useState<number | null>(null);

  useEffect(() => {
    api
      .captureSummary()
      .then(setSummary)
      .catch((e) => setError(String(e)));
    api
      .captureVehicles()
      .then((rows) => {
        setVehicles(rows);
        if (rows.length) setSelected(rows[0].vid);
      })
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (selected === null) return;
    setEvents(null);
    api
      .captureVehicle(selected)
      .then((r) => setEvents(r.events))
      .catch((e) => setError(String(e)));
  }, [selected]);

  const filtered = useMemo(
    () =>
      filter.trim()
        ? vehicles.filter((v) => String(v.vid).includes(filter.trim()))
        : vehicles,
    [vehicles, filter]
  );

  const chartData = useMemo(
    () =>
      (events ?? []).map((e) => ({
        t: Number(e.t.toFixed(2)),
        psi_fuse: e.psi_fuse,
        S_norm: e.S_norm,
        ae_norm: e.ae_norm,
        phi: e.phi,
        gt_pois: e.gt_pois ? 1 : 0,
        full_anom: e.full_anom ? 1 : 0,
      })),
    [events]
  );

  const isGhost = selected != null && selected >= GHOST_VID_BASE;
  const current = events && events.length ? events[events.length - 1] : null;

  if (error) {
    return (
      <div className="flex h-full items-center justify-center p-8">
        <div className="max-w-md rounded-lg border border-status-missed/40 bg-status-missed/10 p-5 text-sm text-status-missed">
          {error}
          <p className="mt-2 text-xs text-ink-secondary">
            This screen needs a captured [FUSION-RSU*] log at
            demo_ui/captures/combined_bc_90s.log — the replay corpus alone
            can't feed it (it was recorded at ablation_mode=1, so the fusion
            tier never ran).
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full">
      <aside className="flex w-72 shrink-0 flex-col border-r border-surface-hairline bg-surface-panel">
        <div className="border-b border-surface-hairline p-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
            Defence stack inspector
          </h2>
          {summary && (
            <p className="mt-1 text-[11px] leading-relaxed text-ink-secondary">
              {summary.events.toLocaleString()} fusion decisions across{" "}
              {summary.vehicles} vehicles, t=[{summary.t_min.toFixed(0)}–
              {summary.t_max.toFixed(0)}s]. This is a single captured run —
              not the replay corpus.
            </p>
          )}
          <input
            className="mt-2 w-full rounded border border-surface-hairline bg-surface-raised px-2 py-1 text-xs text-ink-primary outline-none focus:border-entity-rsu"
            placeholder="Filter by vehicle ID…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <div className="flex-1 overflow-y-auto">
          {filtered.map((row) => (
            <VehicleRow
              key={row.vid}
              row={row}
              selected={row.vid === selected}
              onClick={() => setSelected(row.vid)}
            />
          ))}
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto p-5">
        {selected === null && (
          <div className="text-sm text-ink-muted">Select a vehicle.</div>
        )}

        {selected !== null && (
          <div className="mx-auto max-w-4xl space-y-5">
            <header className="flex items-center gap-2">
              <h1 className="text-lg font-semibold text-ink-primary">
                Vehicle {selected}
              </h1>
              {isGhost && (
                <span className="rounded bg-entity-ghost/20 px-2 py-0.5 text-[11px] font-medium text-entity-ghost">
                  GHOST IDENTITY — fabricated, no real vehicle behind it
                </span>
              )}
              {current && (
                <span className="text-xs text-ink-muted">
                  {events!.length} decisions over t=[
                  {events![0].t.toFixed(1)}–{current.t.toFixed(1)}s]
                </span>
              )}
            </header>

            {!events && (
              <div className="text-xs text-ink-muted">Loading…</div>
            )}

            {events && current && (
              <>
                <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
                  <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    Latest decision (t={current.t.toFixed(2)}s, RSU{current.rsu_id})
                  </h3>
                  <p className="mb-3 text-[11px] text-ink-secondary">
                    Φ = λ<sub>ψ</sub>·ψ̂ + λ<sub>gat</sub>·Ŝ + λ<sub>ae</sub>·ε̂
                    (Eq 3.46) — the three components below are each already
                    normalised to [0,1], the exact terms the simulator sums.
                    Per-attack λ weights aren't carried in this log line, so
                    the bars show the normalised signals feeding the sum,
                    not the final weighted split.
                  </p>
                  <div className="mb-3 flex items-center gap-3 text-xs">
                    <span className="text-ink-muted">Verdict:</span>
                    <span
                      className={
                        current.full_anom
                          ? "font-medium text-status-caught"
                          : "text-status-good"
                      }
                    >
                      {current.full_anom ? "ANOMALOUS — flagged" : "clean — not flagged"}
                    </span>
                    <span className="text-ink-muted">·</span>
                    <span className="text-ink-muted">
                      ground truth: {current.gt_pois ? "poisoned" : "honest"}
                    </span>
                    {current.gt_pois && !current.full_anom && (
                      <span className="rounded bg-status-missed/20 px-1.5 py-0.5 font-medium text-status-missed">
                        FALSE NEGATIVE — this lie went undetected
                      </span>
                    )}
                    {!current.gt_pois && current.full_anom && (
                      <span className="rounded bg-status-caught/20 px-1.5 py-0.5 font-medium text-status-caught">
                        FALSE POSITIVE — honest traffic flagged
                      </span>
                    )}
                  </div>

                  <div className="flex flex-col gap-2">
                    {[
                      {
                        label: "ψ̂ (rules)",
                        value: current.psi_fuse,
                        color: SERIES[0],
                        body: (
                          <div className="flex flex-col gap-1.5 text-[11px] text-ink-secondary">
                            <p>
                              Raw rule score ψ={current.psi.toFixed(3)}, fused
                              ψ̂={current.psi_fuse.toFixed(3)} (threshold 0.09).
                            </p>
                            {current.accusations.length > 0 ? (
                              <ul className="space-y-0.5">
                                {current.accusations.map((a) => (
                                  <li key={a.code}>
                                    ▸ {a.name}{" "}
                                    <span className="text-ink-muted">— {a.detail}</span>
                                  </li>
                                ))}
                              </ul>
                            ) : (
                              <p className="text-ink-muted">No rule signatures tripped.</p>
                            )}
                          </div>
                        ),
                      },
                      {
                        label: "Ŝ (GAT)",
                        value: current.S_norm,
                        color: SERIES[1],
                        body: (
                          <p className="text-[11px] text-ink-secondary">
                            Graph-attention score S={current.S.toFixed(2)}, this
                            RSU's threshold θ<sub>S</sub>={current.thetaS.toFixed(2)}.
                            Ratio S/θ<sub>S</sub> ={" "}
                            {(current.S / current.thetaS).toFixed(3)}
                            {current.S / current.thetaS > 1 ? " — over the line." : "."}
                          </p>
                        ),
                      },
                      {
                        label: "ε̂ (LSTM-AE)",
                        value: current.ae_norm,
                        color: SERIES[2],
                        body: (
                          <p className="text-[11px] text-ink-secondary">
                            Reconstruction error ae_raw=
                            {current.ae_raw.toFixed(3)} against this run's alarm
                            point θ<sub>ae</sub>={THETA_AE.toFixed(3)}
                            {current.ae_raw > THETA_AE
                              ? " — above it, flagged by this layer alone."
                              : " — below it, this layer alone would not flag."}
                          </p>
                        ),
                      },
                      {
                        label: "Φ (fused)",
                        value: current.phi,
                        color: current.full_anom ? STATUS.caught : SURFACE.hairlineStrong,
                        threshold: PHI_TH,
                        body: (
                          <p className="text-[11px] text-ink-secondary">
                            Φ = λ<sub>ψ</sub>·ψ̂ + λ<sub>gat</sub>·Ŝ + λ<sub>ae</sub>·ε̂
                            (Eq 3.46) = {current.phi.toFixed(3)}, decision
                            threshold 0.5. Predicted class k̂={current.khat}
                            {current.khat >= 0 ? ` (attack ${current.khat + 1})` : " (none)"}.
                          </p>
                        ),
                      },
                    ].map((s, i) => (
                      <Accordion
                        key={s.label}
                        open={openSignal === i}
                        onToggle={() => setOpenSignal((v) => (v === i ? null : i))}
                        bodyMaxHeight={160}
                        header={
                          <div className="flex flex-1 flex-col gap-1">
                            <div className="flex items-baseline justify-between gap-2">
                              <span className="text-xs font-semibold">{s.label}</span>
                              <span
                                className="font-mono text-sm font-semibold"
                                style={{ color: s.color }}
                              >
                                {s.value.toFixed(3)}
                              </span>
                            </div>
                            <div className="relative h-1.5 w-full overflow-hidden rounded bg-surface-page">
                              <div
                                className="anim-sweep h-full rounded"
                                style={{
                                  width: `${Math.max(0, Math.min(1, s.value)) * 100}%`,
                                  background: s.color,
                                }}
                              />
                              {s.threshold != null && (
                                <div
                                  className="absolute top-0 h-full w-px bg-ink-primary/60"
                                  style={{ left: `${s.threshold * 100}%` }}
                                />
                              )}
                            </div>
                          </div>
                        }
                      >
                        <div className="border-t border-surface-hairline px-3.5 pb-3 pt-2.5">
                          {s.body}
                        </div>
                      </Accordion>
                    ))}
                  </div>
                </section>

                <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
                  <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    Fused decision Φ over time
                  </h3>
                  <p className="mb-2 text-[10px] text-ink-muted">
                    Dashed line = decision threshold (Φ &gt; {PHI_TH})
                  </p>
                  <div className="h-40">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: -12 }}>
                        <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                        <XAxis dataKey="t" tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} />
                        <YAxis domain={[0, 1]} tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} />
                        <Tooltip
                          contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }}
                          labelStyle={{ color: INK.secondary }}
                        />
                        <ReferenceLine y={PHI_TH} stroke={STATUS.caught} strokeDasharray="4 3" />
                        <Line type="monotone" dataKey="phi" name="Φ" stroke={SERIES[3]} strokeWidth={2} dot={false} isAnimationActive={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </section>

                <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
                  <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    The three signals over time
                  </h3>
                  <div className="h-44">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: -12 }}>
                        <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                        <XAxis dataKey="t" tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} />
                        <YAxis domain={[0, 1]} tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} />
                        <Tooltip
                          contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }}
                          labelStyle={{ color: INK.secondary }}
                        />
                        <Legend wrapperStyle={{ fontSize: 11 }} />
                        <Area type="monotone" dataKey="psi_fuse" name="ψ̂ rules" stroke={SERIES[0]} fill={SERIES[0]} fillOpacity={0.12} isAnimationActive={false} />
                        <Area type="monotone" dataKey="S_norm" name="Ŝ GAT" stroke={SERIES[1]} fill={SERIES[1]} fillOpacity={0.12} isAnimationActive={false} />
                        <Area type="monotone" dataKey="ae_norm" name="ε̂ LSTM-AE" stroke={SERIES[2]} fill={SERIES[2]} fillOpacity={0.12} isAnimationActive={false} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </section>
              </>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

