import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, AttackInfoDto } from "../api";
import { SERIES, INK } from "../design/tokens";

interface AblationDto {
  source: string;
  config: string;
  windows: {
    cutoff_s: number;
    ordering_holds: boolean;
    arms: { D1: number; D4: number; D6: number };
    note?: string;
  }[];
}

function Callout({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded border border-status-caught/30 bg-status-caught/5 px-3 py-2 text-[11px] leading-relaxed text-ink-secondary">
      {children}
    </div>
  );
}

export default function ResultsScreen() {
  const [attacks, setAttacks] = useState<AttackInfoDto[] | null>(null);
  const [ablation, setAblation] = useState<AblationDto | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.attacks(), api.resultsAblation()])
      .then(([a, ab]) => {
        setAttacks(a);
        setAblation(ab);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const chartData = attacks?.map((a) => ({
    code: a.code,
    SENTINEL: a.sentinel_full?.MCC ?? 0,
    "best baseline": a.best_baseline_mcc ?? 0,
  }));

  return (
    <div className="h-full overflow-y-auto p-5">
      <div className="mx-auto max-w-5xl space-y-6">
        <header>
          <h1 className="text-lg font-semibold text-ink-primary">
            Results &amp; ablation
          </h1>
          <p className="mt-1 text-xs text-ink-secondary">
            Reported figures with their evaluation windows stated explicitly
            — an MCC without a window attached is not comparable to another.
          </p>
        </header>

        {error && (
          <div className="rounded border border-status-missed/40 bg-status-missed/10 p-4 text-xs text-status-missed">
            {error}
          </div>
        )}

        <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
          <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
            SENTINEL vs. best baseline, per attack (E5)
          </h2>
          <p className="mb-3 text-[11px] text-ink-secondary">
            From <code className="text-ink-primary">results_e5_final/e5_final_table.json</code>.
            Baselines beat SENTINEL on 3 of 7 variants — bars below zero on
            the baseline series where that happens are shown, not clipped.
          </p>
          {chartData && (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 4, right: 8, bottom: 4, left: -12 }}>
                  <CartesianGrid stroke="#1f2933" vertical={false} />
                  <XAxis dataKey="code" tick={{ fill: INK.muted, fontSize: 11 }} stroke="#2c3742" />
                  <YAxis tick={{ fill: INK.muted, fontSize: 11 }} stroke="#2c3742" />
                  <Tooltip
                    contentStyle={{ background: "#151c24", border: "1px solid #1f2933", borderRadius: 6, fontSize: 11 }}
                    labelStyle={{ color: INK.secondary }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="SENTINEL" fill={SERIES[0]} radius={[2, 2, 0, 0]} isAnimationActive={false} />
                  <Bar dataKey="best baseline" fill={SERIES[1]} radius={[2, 2, 0, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </section>

        {ablation && (
          <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
            <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              Ablation: does more machine learning help?
            </h2>
            <p className="mb-3 text-[11px] text-ink-secondary">
              D1 = rule signatures only. D4 = + GAT spatial. D6 = + LSTM-AE
              temporal. {ablation.config}. Source: {ablation.source}.
            </p>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              {ablation.windows.map((w) => (
                <div key={w.cutoff_s} className="rounded border border-surface-hairline bg-surface-raised p-3">
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-xs font-medium text-ink-primary">
                      {w.cutoff_s}s cutoff
                    </span>
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                        w.ordering_holds
                          ? "bg-status-good/15 text-status-good"
                          : "bg-status-missed/20 text-status-missed"
                      }`}
                    >
                      {w.ordering_holds ? "D1 < D4 < D6 holds" : "ordering fails"}
                    </span>
                  </div>
                  <dl className="space-y-1 text-xs">
                    {(["D1", "D4", "D6"] as const).map((arm) => (
                      <div key={arm} className="flex justify-between">
                        <dt className="text-ink-muted">{arm}</dt>
                        <dd className="font-mono text-ink-primary">
                          {w.arms[arm].toFixed(4)}
                        </dd>
                      </div>
                    ))}
                  </dl>
                  {w.note && <Callout>{w.note}</Callout>}
                </div>
              ))}
            </div>
          </section>
        )}

        <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
          <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
            E1 — penetration rate × combined-attack intensity
          </h2>
          <p className="mb-3 text-[11px] text-ink-secondary">
            Pre-generated figure, shown as originally produced — the source
            CSV's ~13 unlabeled numeric columns and generating script
            weren't recoverable, so this is served as-is rather than
            re-plotted from a guess at column meaning.
          </p>
          <img
            src="/static/results_e1/e1_penetration_intensity.png"
            alt="E1 — SENTINEL MCC across attack penetration rate and intensity"
            className="w-full rounded border border-surface-hairline bg-white"
          />
        </section>

        <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
          <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
            E2 — speed regime sweep
          </h2>
          <img
            src="/static/results_e2/e2_speed_regime.png"
            alt="E2 — speed regime sweep"
            className="w-full rounded border border-surface-hairline bg-white"
          />
        </section>
      </div>
    </div>
  );
}
