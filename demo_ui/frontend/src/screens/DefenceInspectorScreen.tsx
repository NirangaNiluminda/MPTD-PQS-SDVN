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
  AttackInfoDto,
  CaptureSummaryDto,
  CaptureVehicleRowDto,
  CaptureNeighboursDto,
  FusionEventDto,
} from "../api";
import { useTokens } from "../design/tokens";
import { usePlayback } from "../store/playback";
import Accordion from "../components/Accordion";
import EgoGraph from "../components/EgoGraph";

const GHOST_VID_BASE = 10000;
const PHI_TH = 0.5; // fusion decision threshold, 08_detection_engine.h FusionParams default
// Same constant as demo_ui/backend/parsers/capture_analytics.py's THETA_AE —
// this run's AE alarm point, confirmed via the [AI-INIT] startup line, not a
// per-event field so it can't be read off `current` itself.
const THETA_AE = 33.693885;

function VehicleRow({
  row,
  selected,
  attackByNumber,
  onClick,
}: {
  row: CaptureVehicleRowDto;
  selected: boolean;
  attackByNumber: Map<number, AttackInfoDto>;
  onClick: () => void;
}) {
  const isGhost = row.vid >= GHOST_VID_BASE;
  return (
    <button
      onClick={onClick}
      className={`flex w-full flex-col gap-1 border-b border-surface-hairline/60 px-3 py-2 text-left text-xs transition-colors hover:bg-surface-raised ${
        selected ? "bg-surface-raised" : ""
      }`}
    >
      <div className="flex w-full items-center gap-2">
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
      </div>
      {row.attack_types.length > 0 && (
        <span className="truncate text-[10px] text-ink-muted">
          {row.attack_types
            .map((n) => attackByNumber.get(n)?.code ?? `attack ${n}`)
            .join(" + ")}
        </span>
      )}
    </button>
  );
}

export default function DefenceInspectorScreen() {
  const { SERIES, STATUS, INK, SURFACE } = useTokens();
  const { lastSelectedVehicleId, setLastSelectedVehicleId } = usePlayback();
  const [summary, setSummary] = useState<CaptureSummaryDto | null>(null);
  const [vehicles, setVehicles] = useState<CaptureVehicleRowDto[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [events, setEvents] = useState<FusionEventDto[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [openSignal, setOpenSignal] = useState<number | null>(null);
  const [trendsOpen, setTrendsOpen] = useState(false);
  const [neighbours, setNeighbours] = useState<CaptureNeighboursDto | null>(null);
  const [attacks, setAttacks] = useState<AttackInfoDto[]>([]);

  // This capture is a combined-attack recording (real, verified: gt_atk
  // values 1/3/4 etc. coexist across different vehicles in the same run,
  // not one attack type) — this lookup is what turns that raw number into
  // the same code/human_name the Attack Explainer tab already uses.
  const attackByNumber = useMemo(
    () => new Map(attacks.map((a) => [a.attack_number, a])),
    [attacks]
  );

  const presentAttackCodes = useMemo(() => {
    const nums = new Set<number>();
    for (const v of vehicles) for (const n of v.attack_types) nums.add(n);
    return Array.from(nums)
      .sort((a, b) => a - b)
      .map((n) => attackByNumber.get(n)?.code ?? `attack ${n}`);
  }, [vehicles, attackByNumber]);

  useEffect(() => {
    api
      .captureSummary()
      .then(setSummary)
      .catch((e) => setError(String(e)));
    api.attacks().then(setAttacks).catch(() => setAttacks([]));
    api
      .captureVehicles()
      .then((rows) => {
        setVehicles(rows);
        // A vehicle picked on Network Replay's map carries over here as the
        // default, so switching tabs to dig into the same vehicle doesn't
        // mean re-finding it in a 56-row list — but only if this capture
        // (a different recorded run) actually has data for it.
        const carriedOver = rows.find((r) => r.vid === lastSelectedVehicleId);
        if (carriedOver) setSelected(carriedOver.vid);
        else if (rows.length) setSelected(rows[0].vid);
      })
      .catch((e) => setError(String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (selected === null) return;
    setEvents(null);
    setNeighbours(null);
    api
      .captureVehicle(selected)
      .then((r) => setEvents(r.events))
      .catch((e) => setError(String(e)));
  }, [selected]);

  const latestT = events && events.length ? events[events.length - 1].t : null;

  useEffect(() => {
    if (selected === null || latestT === null) return;
    setNeighbours(null);
    api
      .captureNeighbours(selected, latestT)
      .then(setNeighbours)
      // No [METRICS] sample within tolerance, or this vehicle wasn't in the
      // corpus at all — a quiet miss, not a screen-level error.
      .catch(() => setNeighbours(null));
  }, [selected, latestT]);

  const selectVehicleRow = (vid: number) => {
    setSelected(vid);
    setLastSelectedVehicleId(vid);
  };

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

  // Real [METRICS] positions, not attention weights — this capture never
  // re-ran the GAT with attention output requested, so there's no weight to
  // show here the way Network Replay's ego-graph has one.
  const egoNodes = neighbours
    ? neighbours.neighbours.map((n) => ({
        id: n.vehicle_id,
        dx: n.pos_x - neighbours.target_pos.x,
        dy: n.pos_y - neighbours.target_pos.y,
        distance: n.distance_m,
        poisoned: n.is_poisoned,
      }))
    : [];

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
              {summary.t_max.toFixed(0)}s]. A single captured run — not the
              replay corpus — and a{" "}
              <span className="font-medium text-ink-primary">combined-attack</span> recording: multiple real
              attack types coexist in it
              {presentAttackCodes.length > 0 && <> ({presentAttackCodes.join(", ")})</>}, not one. Each
              vehicle's own attack type is shown next to it below and in its detail view.
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
              attackByNumber={attackByNumber}
              onClick={() => selectVehicleRow(row.vid)}
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
                    (Eq 3.48) — the three components below are each already
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
                      ground truth:{" "}
                      {current.gt_pois
                        ? `poisoned — ${attackByNumber.get(current.gt_atk)?.code ?? `attack ${current.gt_atk}`} (${
                            attackByNumber.get(current.gt_atk)?.human_name ?? "unknown"
                          })`
                        : "honest"}
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
                            (Eq 3.48) = {current.phi.toFixed(3)}, decision
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

                {!isGhost && (
                  <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
                    <h3 className="mb-1 text-body font-semibold text-ink-primary">
                      Nearby vehicles — real positions
                    </h3>
                    <p className="mb-3 text-[11px] leading-relaxed text-ink-muted">
                      From this capture's own [METRICS] lines at t={current.t.toFixed(2)}s — real ground-truth
                      positions, but this run never re-ran the GAT with attention output requested, so edges
                      here mean "was within {"≤"}300m," not "attended to this much" the way Network
                      Replay's ego-graph does.
                    </p>
                    {neighbours ? (
                      <EgoGraph centerLabel={`V${selected}`} nodes={egoNodes} />
                    ) : (
                      <p className="text-xs text-ink-muted">
                        No [METRICS] position sample within 1s of t={current.t.toFixed(2)}s for this vehicle.
                      </p>
                    )}
                  </section>
                )}

                <Accordion
                  open={trendsOpen}
                  onToggle={() => setTrendsOpen((v) => !v)}
                  bodyMaxHeight={520}
                  header={
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                      Trends over time — Φ and the three signals
                    </span>
                  }
                >
                  <div className="flex flex-col gap-4 border-t border-surface-hairline p-4">
                    <div>
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
                    </div>

                    <div>
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
                    </div>
                  </div>
                </Accordion>
              </>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

