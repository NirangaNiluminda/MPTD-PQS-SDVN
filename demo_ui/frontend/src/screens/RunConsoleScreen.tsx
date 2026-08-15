import { useEffect, useRef, useState } from "react";
import { api, LaunchRunRequest, ModelCheckDto, RunRecordDto } from "../api";

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
  const color =
    p.phase === "finished"
      ? "bg-status-good"
      : p.phase === "registering"
      ? "bg-status-caught"
      : "bg-entity-rsu";
  return (
    <div>
      <div className="flex items-center justify-between text-[11px] text-ink-secondary">
        <span>
          {p.phase === "registering" &&
            `Registering identities on-chain — ${p.registered}/${p.expected}`}
          {p.phase === "simulating" &&
            `Simulating — t=${p.sim_time_reached ?? 0}s / ${run.config.sim_time}s`}
          {p.phase === "finished" &&
            `Finished — MCC_full ${p.mcc_full?.toFixed(3) ?? "n/a"}`}
          {p.phase === "starting" && "Starting…"}
          {p.stale && " (waiting for next log update…)"}
        </span>
        {p.phase !== "finished" && (
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

function RunCard({
  run,
  onStop,
  expanded,
  onToggleExpand,
}: {
  run: RunRecordDto;
  onStop: (id: string) => void;
  expanded: boolean;
  onToggleExpand: () => void;
}) {
  const [logLines, setLogLines] = useState<string[]>([]);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!expanded) {
      esRef.current?.close();
      esRef.current = null;
      return;
    }
    setLogLines([]);
    const es = new EventSource(api.runStreamUrl(run.run_id));
    esRef.current = es;
    es.onmessage = (ev) => {
      const line = JSON.parse(ev.data) as string;
      setLogLines((prev) => (prev.length > 500 ? [...prev.slice(-500), line] : [...prev, line]));
    };
    es.addEventListener("done", () => es.close());
    es.onerror = () => es.close();
    return () => es.close();
  }, [expanded, run.run_id]);

  const c = run.config;
  const attackLabel = ATTACK_OPTIONS.find((a) => a.n === c.attack_number)?.label ?? `attack ${c.attack_number}`;

  return (
    <div className="rounded-lg border border-surface-hairline bg-surface-panel">
      <div className="flex items-center gap-3 p-3">
        <span
          className={`h-2 w-2 shrink-0 rounded-full ${
            run.alive ? "animate-pulse bg-status-good" : "bg-ink-muted"
          }`}
        />
        <div className="min-w-0 flex-1">
          <div className="truncate text-xs font-medium text-ink-primary">
            {attackLabel} · {c.attack_pct}% · seed {c.seed}
            {c.enable_blockchain && " · blockchain"}
          </div>
          <div className="mt-1">
            <ProgressBar run={run} />
          </div>
        </div>
        <button
          onClick={onToggleExpand}
          className="shrink-0 rounded bg-surface-raised px-2 py-1 text-[11px] text-ink-secondary hover:text-ink-primary"
        >
          {expanded ? "Hide log" : "View log"}
        </button>
        {run.alive && (
          <button
            onClick={() => onStop(run.run_id)}
            className="shrink-0 rounded bg-status-missed/20 px-2 py-1 text-[11px] font-medium text-status-missed hover:bg-status-missed/30"
          >
            Stop
          </button>
        )}
      </div>
      {expanded && (
        <div className="max-h-64 overflow-y-auto border-t border-surface-hairline bg-surface-page p-2 font-mono text-[10px] leading-relaxed text-ink-secondary">
          {logLines.length === 0 && <div className="text-ink-muted">Waiting for output…</div>}
          {logLines.map((l, i) => (
            <div key={i} className="whitespace-pre-wrap">
              {l}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function RunConsoleScreen() {
  const [modelCheck, setModelCheck] = useState<ModelCheckDto | null>(null);
  const [runs, setRuns] = useState<RunRecordDto[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
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
                expanded={expandedId === r.run_id}
                onToggleExpand={() => setExpandedId(expandedId === r.run_id ? null : r.run_id)}
              />
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
