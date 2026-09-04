import { useEffect, useRef, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, LaunchRunRequest, LiveMetricsDto, MetricsHistoryPointDto, ModelCheckDto, RunRecordDto } from "../api";
import BlockFeedPanel from "../components/BlockFeedPanel";
import DrillModal, { originFromEvent } from "../components/DrillModal";
import ProvenanceChip from "../components/ProvenanceChip";
import { useTokens } from "../design/tokens";

type HistoryMetric = "mcc" | "fpr" | "tp" | "fp" | "tn" | "fn" | "n_events";
const HISTORY_METRIC_LABEL: Record<HistoryMetric, string> = {
  mcc: "Live MCC",
  fpr: "Live FPR",
  tp: "True positives (cumulative)",
  fp: "False positives (cumulative)",
  tn: "True negatives (cumulative)",
  fn: "False negatives (cumulative)",
  n_events: "Fusion events scored (cumulative)",
};

const CHART_HEIGHT = 208; // was 160 — bumped for visibility; skeleton below must match exactly

/**
 * Empty-state placeholder that fills the SAME footprint as the real chart
 * (same height, same header above it stays untouched) so nothing jumps
 * when real data arrives — a faux gridline frame plus a phase-aware
 * explanation of when data will actually start landing, instead of the
 * chart area collapsing to a single line of text.
 */
function ChartSkeleton({ message }: { message: string }) {
  return (
    <div
      className="relative flex items-center justify-center overflow-hidden rounded-md border border-dashed border-surface-hairline2 bg-surface-page"
      style={{ height: CHART_HEIGHT }}
    >
      <div className="pointer-events-none absolute inset-3 flex flex-col justify-between opacity-50">
        <div className="h-px w-full bg-surface-hairline" />
        <div className="h-px w-full bg-surface-hairline" />
        <div className="h-px w-full bg-surface-hairline" />
        <div className="h-px w-full bg-surface-hairline" />
      </div>
      <p className="relative max-w-[80%] text-center text-[10.5px] leading-relaxed text-ink-muted">
        <span className="mb-1 block animate-pulse text-base leading-none">⋯</span>
        {message}
      </p>
    </div>
  );
}

/**
 * Real-time, interactive — plots this run's OWN growing metrics_history
 * (one real point per poll, keyed by the run's simulated time) so the
 * attack's actual detection performance is visible unfolding over the
 * run's timeline, not just a final snapshot. "Flexible" = pick which
 * signal to watch, same interaction pattern as the CSV explorer's column
 * picker, applied to live data instead of a static file.
 */
function LiveMetricsChart({ history, pendingMessage }: { history: MetricsHistoryPointDto[]; pendingMessage: string }) {
  const { SERIES, INK, SURFACE } = useTokens();
  const [metric, setMetric] = useState<HistoryMetric>("mcc");
  const hasData = history.length >= 2;

  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <label className="text-[10px] text-ink-secondary">
          Watch:{" "}
          <select
            value={metric}
            onChange={(e) => setMetric(e.target.value as HistoryMetric)}
            className="ml-1 rounded border border-surface-hairline bg-surface-page px-1.5 py-0.5 text-[10px] text-ink-primary outline-none focus:border-entity-rsu"
          >
            {(Object.keys(HISTORY_METRIC_LABEL) as HistoryMetric[]).map((m) => (
              <option key={m} value={m}>
                {HISTORY_METRIC_LABEL[m]}
              </option>
            ))}
          </select>
        </label>
        <span className="text-[10px] text-ink-muted">
          {history.length} point{history.length === 1 ? "" : "s"}
        </span>
      </div>
      {hasData ? (
        <div style={{ height: CHART_HEIGHT }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={history} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
              <XAxis
                dataKey="t"
                type="number"
                domain={["dataMin", "dataMax"]}
                tick={{ fill: INK.muted, fontSize: 9 }}
                stroke={SURFACE.hairlineStrong}
                label={{ value: "sim time (s)", position: "insideBottom", offset: -2, fill: INK.muted, fontSize: 9 }}
              />
              <YAxis tick={{ fill: INK.muted, fontSize: 9 }} stroke={SURFACE.hairlineStrong} width={40} />
              <Tooltip
                contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }}
                labelStyle={{ color: INK.secondary }}
                labelFormatter={(t) => `t=${t}s`}
              />
              <Line
                type="monotone"
                dataKey={metric}
                stroke={SERIES[0]}
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
                name={HISTORY_METRIC_LABEL[metric]}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <ChartSkeleton message={pendingMessage} />
      )}
    </div>
  );
}

/** All four confusion counts at once — the "everything together" view next
 * to the flexible single-signal picker above, not a replacement for it. */
function ConfusionCountsChart({ history, pendingMessage }: { history: MetricsHistoryPointDto[]; pendingMessage: string }) {
  const { INK, SURFACE, STATUS, SERIES } = useTokens();
  const hasData = history.length >= 2;
  return (
    <div>
      <p className="mb-1 text-[10px] text-ink-secondary">All four counts, together</p>
      {hasData ? (
        <div style={{ height: CHART_HEIGHT }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={history} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
              <XAxis
                dataKey="t"
                type="number"
                domain={["dataMin", "dataMax"]}
                tick={{ fill: INK.muted, fontSize: 9 }}
                stroke={SURFACE.hairlineStrong}
                label={{ value: "sim time (s)", position: "insideBottom", offset: -2, fill: INK.muted, fontSize: 9 }}
              />
              <YAxis tick={{ fill: INK.muted, fontSize: 9 }} stroke={SURFACE.hairlineStrong} width={40} />
              <Tooltip
                contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }}
                labelStyle={{ color: INK.secondary }}
                labelFormatter={(t) => `t=${t}s`}
              />
              <Legend wrapperStyle={{ fontSize: 9 }} />
              <Line type="monotone" dataKey="tp" stroke={STATUS.good} strokeWidth={1.5} dot={false} isAnimationActive={false} name="TP" />
              <Line type="monotone" dataKey="fp" stroke={STATUS.missed} strokeWidth={1.5} dot={false} isAnimationActive={false} name="FP" />
              <Line type="monotone" dataKey="tn" stroke={SERIES[2]} strokeWidth={1.5} strokeDasharray="4 2" dot={false} isAnimationActive={false} name="TN" />
              <Line type="monotone" dataKey="fn" stroke={SERIES[3]} strokeWidth={1.5} strokeDasharray="4 2" dot={false} isAnimationActive={false} name="FN" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <ChartSkeleton message={pendingMessage} />
      )}
    </div>
  );
}

const ATTACK_OPTIONS = [
  { n: 0, label: "Combined (all 7 at once)" },
  { n: 1, label: "TP-S1 — hijacked RSU trajectory poisoning" },
  { n: 2, label: "TP-S2 — lying vehicle trajectory poisoning" },
  { n: 3, label: "MP-S1 — Sybil via compromised RSU" },
  { n: 4, label: "MP-S2 — Sybil via vehicle impersonation" },
  { n: 5, label: "TP-S3 — hijacked controller trajectory poisoning" },
  { n: 6, label: "MP-S3 — MitM data-plane relay" },
  { n: 7, label: "MP-S4 — hijacked controller mobility-model poisoning" },
];

const SIM_SLOWDOWN_FACTOR = 40.5; // mirrors backend run_manager.py — measured, not a guess
const SEC_PER_REGISTRATION = 2.7;

function formatDuration(totalSeconds: number): string {
  if (totalSeconds <= 0) return "0s";
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = Math.round(totalSeconds % 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function clientEta(req: LaunchRunRequest): number {
  const simPart = req.sim_time * SIM_SLOWDOWN_FACTOR;
  if (!req.enable_blockchain) return simPart;
  const identities = req.n_vehicles + req.n_rsus + 4;
  return identities * SEC_PER_REGISTRATION + simPart;
}

/** Why there's nothing to plot yet, phrased around what's actually true of
 * THIS run right now (registering vs. starting vs. just-begun) instead of a
 * generic "waiting for data" — same underlying reasoning as ProgressBar's
 * phase text, reused so the two never contradict each other. */
function pendingChartMessage(run: RunRecordDto): string {
  const p = run.progress;
  if (!run.alive) {
    return p?.phase === "finished"
      ? "This run finished with too little data to draw a trend."
      : "Run stopped before enough detection data was collected to plot.";
  }
  if (!p || p.phase === "starting") {
    return "Simulation is starting — the first point lands as soon as the detection layer scores a beacon.";
  }
  if (p.phase === "registering") {
    return `Registering identities on-chain (${p.registered}/${p.expected}) — plotting begins once the simulation itself starts, in ~${formatDuration(
      p.eta_seconds
    )}.`;
  }
  return "First point recorded — a trend line begins once a second point lands on the simulated timeline.";
}

function ModelCheckBanner({ check }: { check: ModelCheckDto | null }) {
  if (!check) return null;
  if (check.ok) {
    return (
      <div className="mb-4 rounded border border-status-good/30 bg-status-good/10 px-3 py-2 text-xs text-status-good">
        ✓ Deployed model verified — gat_model.onnx, θ_S, θ_ae all match the
        expected values.
      </div>
    );
  }
  return (
    <div className="mb-4 rounded border border-status-missed/40 bg-status-missed/10 p-3 text-xs text-status-missed">
      <p className="font-medium">
        ⚠ Deployed model does NOT match the expected reverted state.
      </p>
      <p className="mt-1 text-ink-secondary">
        CLAUDE.md: "Deployed model must stay reverted" — the Fix-A swap once
        collapsed MCC to 0.036. A launch will be refused unless you tick
        "launch anyway" below.
      </p>
      <ul className="mt-2 space-y-0.5 font-mono text-[10px]">
        <li>
          gat_model.onnx → {check.gat_model_link.actual ?? "MISSING"}{" "}
          {check.gat_model_link.ok ? "✓" : `(expected ${check.gat_model_link.expected})`}
        </li>
        <li>
          θ_S = {check.theta_s.actual ?? "MISSING"}{" "}
          {check.theta_s.ok ? "✓" : `(expected ${check.theta_s.expected})`}
        </li>
        <li>
          θ_ae = {check.theta_ae.actual ?? "MISSING"}{" "}
          {check.theta_ae.ok ? "✓" : `(expected ${check.theta_ae.expected})`}
        </li>
      </ul>
    </div>
  );
}

function ProgressBar({ run }: { run: RunRecordDto }) {
  const p = run.progress;
  if (!p) return null;

  // A run can be dead (stopped or crashed) without ever reaching "finished"
  // — confirmed directly: a run stopped mid-sim showed "Simulating — t=7s/
  // 15s" with a live-looking "~5m remaining" countdown forever after,
  // because the progress text only checked p.phase, never run.alive. An ETA
  // for a process that no longer exists is not an estimate, it's a lie.
  const incomplete = !run.alive && p.phase !== "finished";

  const color = incomplete
    ? "bg-ink-muted"
    : p.phase === "finished"
    ? "bg-status-good"
    : p.phase === "registering"
    ? "bg-status-caught"
    : "bg-entity-rsu";
  return (
    <div>
      <div className="flex items-center justify-between text-[11px] text-ink-secondary">
        <span>
          {incomplete && "Stopped before completion — last seen: "}
          {p.phase === "registering" &&
            `Registering identities on-chain — ${p.registered}/${p.expected}`}
          {p.phase === "simulating" &&
            `simulating, t=${p.sim_time_reached ?? 0}s / ${run.config.sim_time}s`}
          {p.phase === "finished" &&
            `Finished — MCC_full ${p.mcc_full?.toFixed(3) ?? "n/a"}`}
          {p.phase === "starting" && (incomplete ? "starting" : "Starting…")}
          {!incomplete && p.stale && " (waiting for next log update…)"}
        </span>
        {p.phase !== "finished" && !incomplete && (
          <span>~{formatDuration(p.eta_seconds)} remaining</span>
        )}
      </div>
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-surface-page">
        <div
          className={`h-full rounded-full transition-all ${color}`}
          style={{ width: `${p.pct}%` }}
        />
      </div>
    </div>
  );
}

function LiveMetricsPanel({
  m,
  pendingMessage,
  alive,
}: {
  m: LiveMetricsDto;
  pendingMessage: string;
  alive: boolean;
}) {
  const pending = m.n_events === 0;
  const cell = (label: string, value: number | null, tone: string) => (
    <div
      className={`flex flex-col items-center rounded px-2 py-0.5 ${
        value === null ? "border border-dashed border-surface-hairline2" : "bg-surface-page"
      }`}
    >
      <span className="text-[8px] uppercase tracking-wide text-ink-muted">{label}</span>
      <span className={`font-mono text-xs font-bold ${value === null ? "text-ink-muted" : tone}`}>
        {value === null ? "—" : value.toLocaleString()}
      </span>
    </div>
  );
  return (
    <div className="mt-2 flex flex-wrap items-center gap-3 border-t border-surface-hairline pt-2">
      <div className="grid grid-cols-2 gap-1">
        {cell("TP", pending ? null : m.tp, "text-status-good")}
        {cell("FP", pending ? null : m.fp, "text-status-missed")}
        {cell("FN", pending ? null : m.fn, "text-status-missed")}
        {cell("TN", pending ? null : m.tn, "text-status-good")}
      </div>
      <div className="flex flex-col gap-0.5 text-[10px] text-ink-secondary">
        <span>
          Live MCC{" "}
          <span className={`font-mono font-semibold ${pending ? "text-ink-muted" : "text-ink-primary"}`}>
            {pending ? "—" : m.mcc.toFixed(3)}
          </span>{" "}
          · Live FPR{" "}
          <span className={`font-mono font-semibold ${pending ? "text-ink-muted" : "text-ink-primary"}`}>
            {pending ? "—" : m.fpr.toFixed(3)}
          </span>
        </span>
        <span className="max-w-sm text-ink-muted">
          {pending
            ? pendingMessage
            : alive
            ? `${m.n_events.toLocaleString()} fusion events scored so far, updating live`
            : `${m.n_events.toLocaleString()} total fusion events scored — run finished, final tally`}
        </span>
      </div>
    </div>
  );
}

// Real log tags this ns-3 process actually prints — confirmed by grepping
// live run output, not guessed. "Block creation" has no distinct line of
// its own here (Fabric's own block-commit log lives in the peer/orderer
// containers, outside this process's stdout) — SC-REGISTER/SC-REVOKE-VOTE
// are this process's own real submissions to the chaincode, which is the
// honest version of "blockchain activity" available from this log.
const LOG_CATEGORIES: { key: string; label: string; pattern: RegExp | null }[] = [
  { key: "all", label: "All", pattern: null },
  { key: "chain", label: "Blockchain", pattern: /\[SC-|\[BLOCKCHAIN\]|\[BC-EXPORT\]|\[C-TRUSTED\]|\[RING-ELECT\]|\[CFLAG|\[ALERT_CP-CONFLICT\]/ },
  { key: "ipfs", label: "IPFS", pattern: /\[IPFS/ },
  { key: "detect", label: "Detection", pattern: /\[FUSION-RSU|\[LW-DETECT|\[MGT-RX\]|\[RSU-ASSIGN\]/ },
];

/**
 * The floating window — one place to see a live (or finished) run's full
 * picture: live confusion matrix, two synced time-series charts on the
 * run's own simulated timeline, and the filtered log tabs, all together
 * instead of scattered across a cramped list row.
 */
function RunDetailModal({
  run,
  open,
  onClose,
  origin,
  onStop,
}: {
  run: RunRecordDto | null;
  open: boolean;
  onClose: () => void;
  origin: { dx: number; dy: number };
  onStop: (id: string) => void;
}) {
  const [logLines, setLogLines] = useState<string[]>([]);
  const [logFilter, setLogFilter] = useState("all");

  // Polled, not SSE — Cloudflare Quick Tunnels (what this demo gets shared
  // through) buffer SSE-over-GET until the connection closes, which for a
  // live-tailed log never happens (tracked upstream as
  // cloudflare/cloudflared#1449; confirmed directly against this app's own
  // endpoints — instant on localhost, hung indefinitely over the tunnel).
  useEffect(() => {
    if (!open || !run) return;
    setLogLines([]);
    let cancelled = false;
    let offset = 0;
    let timer: number | undefined;
    const poll = () => {
      api
        .runLog(run.run_id, offset)
        .then((res) => {
          if (cancelled) return;
          offset = res.next_offset;
          if (res.lines.length > 0) {
            setLogLines((prev) => {
              const next = [...prev, ...res.lines];
              return next.length > 800 ? next.slice(-800) : next;
            });
          }
          if (!res.done) timer = window.setTimeout(poll, 1000);
        })
        .catch(() => {
          if (!cancelled) timer = window.setTimeout(poll, 2000);
        });
    };
    poll();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, run?.run_id]);

  if (!run) return null;
  const c = run.config;
  const attackLabel = ATTACK_OPTIONS.find((a) => a.n === c.attack_number)?.label ?? `attack ${c.attack_number}`;
  const active = LOG_CATEGORIES.find((cat) => cat.key === logFilter);
  const filteredLog = active?.pattern ? logLines.filter((l) => active.pattern!.test(l)) : logLines;
  const pendingMsg = pendingChartMessage(run);

  return (
    <DrillModal
      open={open}
      onClose={onClose}
      origin={origin}
      title={attackLabel}
      subtitle={`${c.attack_pct}% intensity · seed ${c.seed}${c.enable_blockchain ? " · blockchain" : ""}`}
      badge={
        <ProvenanceChip
          kind={run.alive ? "live" : "replayed"}
          detail={run.alive ? "process still running" : "process finished or was stopped"}
        />
      }
      maxWidth="max-w-4xl"
    >
      <div className="flex items-center gap-3">
        <div className="flex-1">
          <ProgressBar run={run} />
        </div>
        {run.alive && (
          <button
            onClick={() => onStop(run.run_id)}
            className="shrink-0 rounded bg-status-missed/20 px-3 py-1.5 text-xs font-medium text-status-missed hover:bg-status-missed/30"
          >
            Stop
          </button>
        )}
      </div>

      {run.live_metrics && <LiveMetricsPanel m={run.live_metrics} pendingMessage={pendingMsg} alive={run.alive} />}

      <div className="mt-4">
        <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-ink-secondary">
          Live trend charts — simulated time
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-surface-hairline bg-surface-raised p-3 shadow-sm">
            <ConfusionCountsChart history={run.metrics_history ?? []} pendingMessage={pendingMsg} />
          </div>
          <div className="rounded-lg border border-surface-hairline bg-surface-raised p-3 shadow-sm">
            <LiveMetricsChart history={run.metrics_history ?? []} pendingMessage={pendingMsg} />
          </div>
        </div>
      </div>

      {c.enable_blockchain && (
        <div className="mt-4">
          <BlockFeedPanel
            title="Live blockchain transactions"
            caption="The real, current mptdchannel — not filtered to this run specifically, but with blockchain enabled here, this run's own SC-REGISTER / SC-REVOKE-VOTE calls are most of what's landing on it right now."
          />
        </div>
      )}

      <div className="mt-4">
        <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
          Log — filtered views
        </p>
        <div className="flex flex-wrap gap-1">
          {LOG_CATEGORIES.map((cat) => {
            const count = cat.pattern ? logLines.filter((l) => cat.pattern!.test(l)).length : logLines.length;
            return (
              <button
                key={cat.key}
                onClick={() => setLogFilter(cat.key)}
                className={`rounded px-2 py-1 text-[10px] font-medium transition-colors ${
                  logFilter === cat.key
                    ? "bg-entity-rsu text-white"
                    : "bg-surface-raised text-ink-secondary hover:text-ink-primary"
                }`}
              >
                {cat.label} {count > 0 && `(${count})`}
              </button>
            );
          })}
        </div>
        <div className="mt-1.5 max-h-96 overflow-y-auto rounded-lg border border-surface-hairline bg-surface-page p-2 font-mono text-[10px] leading-relaxed text-ink-secondary">
          {logLines.length === 0 && <div className="text-ink-muted">Waiting for output…</div>}
          {logLines.length > 0 && filteredLog.length === 0 && (
            <div className="text-ink-muted">
              No {active?.label.toLowerCase()} lines seen yet in this run
              {logFilter === "chain" && !c.enable_blockchain && " — blockchain wasn't enabled for this run"}.
            </div>
          )}
          {filteredLog.map((l, i) => (
            <div key={i} className="whitespace-pre-wrap">
              {l}
            </div>
          ))}
        </div>
      </div>
    </DrillModal>
  );
}

function RunCard({
  run,
  onOpen,
  onStop,
}: {
  run: RunRecordDto;
  onOpen: (e: React.MouseEvent<HTMLButtonElement>) => void;
  onStop: (id: string) => void;
}) {
  const c = run.config;
  const attackLabel = ATTACK_OPTIONS.find((a) => a.n === c.attack_number)?.label ?? `attack ${c.attack_number}`;
  const m = run.live_metrics;

  return (
    <div className="rounded-lg border border-surface-hairline bg-surface-panel transition-colors hover:border-surface-hairline2">
      <button onClick={onOpen} className="flex w-full items-center gap-3 p-3 text-left">
        <span
          className={`h-2 w-2 shrink-0 rounded-full ${
            run.alive ? "animate-pulse bg-status-good" : "bg-ink-muted"
          }`}
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 truncate text-xs font-medium text-ink-primary">
            <span className="truncate">
              {attackLabel} · {c.attack_pct}% · seed {c.seed}
              {c.enable_blockchain && " · blockchain"}
            </span>
            <ProvenanceChip
              kind={run.alive ? "live" : "replayed"}
              detail={run.alive ? "process still running" : "process finished or was stopped"}
              compact
            />
          </div>
          <div className="mt-1">
            <ProgressBar run={run} />
          </div>
          {m && m.n_events > 0 && (
            <p className="mt-1 text-[10px] text-ink-secondary">
              Live MCC <span className="font-mono font-semibold text-ink-primary">{m.mcc.toFixed(3)}</span> · FPR{" "}
              <span className="font-mono font-semibold text-ink-primary">{m.fpr.toFixed(3)}</span> ·{" "}
              {m.n_events.toLocaleString()} events
            </p>
          )}
        </div>
        <span className="shrink-0 text-[11px] font-semibold text-entity-rsu">Full view →</span>
      </button>
      {run.alive && (
        <div className="flex justify-end border-t border-surface-hairline px-3 py-1.5">
          <button
            onClick={() => onStop(run.run_id)}
            className="rounded bg-status-missed/20 px-2 py-1 text-[11px] font-medium text-status-missed hover:bg-status-missed/30"
          >
            Stop
          </button>
        </div>
      )}
    </div>
  );
}

export default function RunConsoleScreen() {
  const [modelCheck, setModelCheck] = useState<ModelCheckDto | null>(null);
  const [runs, setRuns] = useState<RunRecordDto[]>([]);
  const [openRunId, setOpenRunId] = useState<string | null>(null);
  const openOrigin = useRef<{ dx: number; dy: number }>({ dx: 0, dy: 0 });
  const [error, setError] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);

  const [form, setForm] = useState<LaunchRunRequest>({
    attack_number: 2,
    attack_pct: 40,
    sim_time: 30,
    mobility_scenario: 0,
    n_vehicles: 200,
    n_rsus: 64,
    enable_gat: true,
    enable_lstm_ae: true,
    enable_blockchain: false,
    seed: 1,
  });
  const [forceOverride, setForceOverride] = useState(false);

  const refreshRuns = () => {
    api
      .runsList()
      .then((list) =>
        Promise.all(list.map((r) => api.runsDetail(r.run_id).catch(() => r)))
      )
      .then(setRuns)
      .catch(() => {});
  };

  useEffect(() => {
    api.runsModelCheck().then(setModelCheck).catch(() => {});
    refreshRuns();
    const interval = setInterval(refreshRuns, 4000);
    return () => clearInterval(interval);
  }, []);

  const launch = async () => {
    setError(null);
    setLaunching(true);
    try {
      await api.runsLaunch({ ...form, force: forceOverride });
      refreshRuns();
    } catch (e) {
      setError(String((e as Error).message ?? e));
    } finally {
      setLaunching(false);
    }
  };

  const stop = async (id: string) => {
    try {
      await api.runsStop(id);
      refreshRuns();
    } catch {
      // run may have exited on its own between click and request — refresh either way
      refreshRuns();
    }
  };

  const openRun = openRunId ? runs.find((r) => r.run_id === openRunId) ?? null : null;

  return (
    <div className="h-full overflow-y-auto p-5">
      <div className="mx-auto max-w-3xl space-y-6">
        <header>
          <h1 className="text-lg font-semibold text-ink-primary">
            Run console
          </h1>
          <p className="mt-1 text-xs text-ink-secondary">
            Launches a REAL simulation process on this machine — not a
            replay. Every safe-default flag from RUN_CONFIG.md's traps
            table is applied automatically and cannot be overridden here.
          </p>
        </header>

        <ModelCheckBanner check={modelCheck} />

        <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-ink-muted">
            Launch a new run
          </h2>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="text-xs text-ink-secondary">
              Attack
              <select
                className="mt-1 w-full rounded border border-surface-hairline bg-surface-raised px-2 py-1.5 text-xs text-ink-primary outline-none focus:border-entity-rsu"
                value={form.attack_number}
                onChange={(e) => setForm({ ...form, attack_number: Number(e.target.value) })}
              >
                {ATTACK_OPTIONS.map((a) => (
                  <option key={a.n} value={a.n}>
                    {a.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="text-xs text-ink-secondary">
              Intensity — {form.attack_pct}% hostile
              <input
                type="range"
                min={0}
                max={100}
                step={10}
                value={form.attack_pct}
                onChange={(e) => setForm({ ...form, attack_pct: Number(e.target.value) })}
                className="mt-2 w-full accent-entity-rsu"
              />
            </label>

            <label className="text-xs text-ink-secondary">
              Sim duration (seconds)
              <input
                type="number"
                min={5}
                max={300}
                value={form.sim_time}
                onChange={(e) => setForm({ ...form, sim_time: Number(e.target.value) })}
                className="mt-1 w-full rounded border border-surface-hairline bg-surface-raised px-2 py-1.5 text-xs text-ink-primary outline-none focus:border-entity-rsu"
              />
            </label>

            <label className="text-xs text-ink-secondary">
              Seed
              <input
                type="number"
                value={form.seed}
                onChange={(e) => setForm({ ...form, seed: Number(e.target.value) })}
                className="mt-1 w-full rounded border border-surface-hairline bg-surface-raised px-2 py-1.5 text-xs text-ink-primary outline-none focus:border-entity-rsu"
              />
            </label>
          </div>

          <div className="mt-3 flex flex-wrap gap-4">
            <label className="flex items-center gap-2 text-xs text-ink-secondary">
              <input
                type="checkbox"
                className="accent-entity-rsu"
                checked={form.enable_gat}
                onChange={(e) => setForm({ ...form, enable_gat: e.target.checked })}
              />
              GAT spatial
            </label>
            <label className="flex items-center gap-2 text-xs text-ink-secondary">
              <input
                type="checkbox"
                className="accent-entity-rsu"
                checked={form.enable_lstm_ae}
                onChange={(e) => setForm({ ...form, enable_lstm_ae: e.target.checked })}
              />
              LSTM-AE temporal
            </label>
            <label className="flex items-center gap-2 text-xs text-ink-secondary">
              <input
                type="checkbox"
                className="accent-entity-rsu"
                checked={form.enable_blockchain}
                onChange={(e) => setForm({ ...form, enable_blockchain: e.target.checked })}
              />
              Blockchain (adds ~12 min identity registration)
            </label>
          </div>

          <div className="mt-3 rounded bg-surface-raised px-3 py-2 text-[11px] text-ink-secondary">
            Estimated time: <span className="font-mono text-ink-primary">~{formatDuration(clientEta(form))}</span>{" "}
            (measured ~40x sim slowdown{form.enable_blockchain ? " + ~2.7s per identity registered" : ""} — an
            estimate, not a guarantee)
          </div>

          {modelCheck && !modelCheck.ok && (
            <label className="mt-3 flex items-center gap-2 text-xs text-status-missed">
              <input
                type="checkbox"
                checked={forceOverride}
                onChange={(e) => setForceOverride(e.target.checked)}
              />
              Launch anyway despite the model mismatch above (not recommended)
            </label>
          )}

          {error && (
            <div className="mt-3 rounded border border-status-missed/40 bg-status-missed/10 px-3 py-2 text-xs text-status-missed">
              {error}
            </div>
          )}

          <button
            onClick={launch}
            disabled={launching || (modelCheck != null && !modelCheck.ok && !forceOverride)}
            className="mt-4 w-full rounded bg-entity-rsu py-2 text-xs font-medium text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-30"
          >
            {launching ? "Launching…" : "Launch simulation"}
          </button>
        </section>

        <section>
          <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-ink-muted">
            Runs {runs.length > 0 && `(${runs.length})`}
          </h2>
          {runs.length === 0 && (
            <p className="text-xs text-ink-muted">No runs launched yet.</p>
          )}
          <div className="space-y-3">
            {runs.map((r) => (
              <RunCard
                key={r.run_id}
                run={r}
                onStop={stop}
                onOpen={(e) => {
                  openOrigin.current = originFromEvent(e);
                  setOpenRunId(r.run_id);
                }}
              />
            ))}
          </div>
        </section>
      </div>

      <RunDetailModal
        run={openRun}
        open={openRunId != null}
        onClose={() => setOpenRunId(null)}
        origin={openOrigin.current}
        onStop={stop}
      />
    </div>
  );
}
