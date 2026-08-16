import { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
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
  CryptoSummaryDto,
  LayerAgreementDto,
  LatencyHistogramDto,
  SweepPointDto,
} from "../api";
import { useTokens } from "../design/tokens";
import Accordion from "../components/Accordion";

const LAYER_LABEL: Record<string, string> = { rules: "Rules", gat: "GAT", lstm_ae: "LSTM-AE" };
const LAYER_ORDER = ["rules", "gat", "lstm_ae"];

function formatBytes(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)} KB`;
  return `${n} B`;
}

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
  const { SERIES, STATUS, INK, SURFACE } = useTokens();
  const [attacks, setAttacks] = useState<AttackInfoDto[] | null>(null);
  const [ablation, setAblation] = useState<AblationDto | null>(null);
  const [sweep, setSweep] = useState<SweepPointDto[] | null>(null);
  const [agreement, setAgreement] = useState<LayerAgreementDto | null>(null);
  const [latency, setLatency] = useState<LatencyHistogramDto | null>(null);
  const [crypto, setCrypto] = useState<CryptoSummaryDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openWindow, setOpenWindow] = useState<number | null>(0);

  useEffect(() => {
    Promise.all([api.attacks(), api.resultsAblation()])
      .then(([a, ab]) => {
        setAttacks(a);
        setAblation(ab);
      })
      .catch((e) => setError(String(e)));
    // Separate failure domain: these come from the capture log, which may
    // not exist in every deployment (see run_summary's own note on that).
    api.captureThresholdSweep().then(setSweep).catch(() => setSweep(null));
    api.captureLayerAgreement().then(setAgreement).catch(() => setAgreement(null));
    api.captureLatencyHistogram().then(setLatency).catch(() => setLatency(null));
    api.captureCryptoSummary().then(setCrypto).catch(() => setCrypto(null));
  }, []);

  const sweepChartData = sweep?.map((p) => ({
    threshold: p.threshold,
    precision: p.precision,
    recall: p.recall,
    f1: p.f1,
  }));

  const peakF1 = useMemo(() => {
    if (!sweep) return null;
    return sweep.reduce((best, p) => ((p.f1 ?? -1) > (best?.f1 ?? -1) ? p : best), sweep[0]);
  }, [sweep]);

  const latencyBins = useMemo(() => {
    if (!latency) return null;
    const bins = [
      { label: "0s (same window)", test: (v: number) => v === 0 },
      { label: "0–1s", test: (v: number) => v > 0 && v <= 1 },
      { label: "1–2s", test: (v: number) => v > 1 && v <= 2 },
      { label: "2–3s", test: (v: number) => v > 2 && v <= 3 },
      { label: "3–5s", test: (v: number) => v > 3 && v <= 5 },
      { label: ">5s", test: (v: number) => v > 5 },
    ];
    return bins.map((b) => ({
      label: b.label,
      count: latency.latencies_seconds.filter(b.test).length,
    }));
  }, [latency]);

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
                  <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                  <XAxis dataKey="code" tick={{ fill: INK.muted, fontSize: 11 }} stroke={SURFACE.hairlineStrong} />
                  <YAxis tick={{ fill: INK.muted, fontSize: 11 }} stroke={SURFACE.hairlineStrong} />
                  <Tooltip
                    contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }}
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

        {sweep && (
          <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
            <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              Threshold sweep — precision, recall, F1 vs. decision threshold
            </h2>
            <p className="mb-3 text-[11px] text-ink-secondary">
              Computed post-hoc from the real fused score (Φ) each event in
              one blockchain-enabled capture run already carries — sweeping
              the decision threshold re-slices existing data, no
              re-simulation. Sanity-checked: at threshold 0.5 this exactly
              reproduces the simulator's own printed confusion matrix
              (TP=12756 FP=70 TN=4480 FN=1110).
              {peakF1 && (
                <>
                  {" "}
                  Peak F1 ({peakF1.f1?.toFixed(3)}) falls at threshold{" "}
                  {peakF1.threshold.toFixed(2)} — the deployed operating
                  point is 0.5, so the peak and the actual choice do not
                  coincide here.
                </>
              )}
            </p>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={sweepChartData ?? []} margin={{ top: 4, right: 8, bottom: 4, left: -12 }}>
                  <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                  <XAxis
                    dataKey="threshold"
                    type="number"
                    domain={[0, 1]}
                    tick={{ fill: INK.muted, fontSize: 10 }}
                    stroke={SURFACE.hairlineStrong}
                  />
                  <YAxis domain={[0, 1]} tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} />
                  <Tooltip
                    contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }}
                    labelStyle={{ color: INK.secondary }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <ReferenceLine x={0.5} stroke={STATUS.caught} strokeDasharray="4 3" label={{ value: "deployed (0.5)", fill: STATUS.caught, fontSize: 10, position: "top" }} />
                  <Line type="monotone" dataKey="precision" stroke={SERIES[0]} strokeWidth={2} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="recall" stroke={SERIES[1]} strokeWidth={2} dot={false} isAnimationActive={false} />
                  <Line type="monotone" dataKey="f1" stroke={SERIES[2]} strokeWidth={2.5} dot={false} isAnimationActive={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </section>
        )}

        {(agreement || latencyBins) && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            {agreement && (
              <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
                <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
                  Layer agreement — are the three tiers redundant?
                </h2>
                <p className="mb-3 text-[11px] text-ink-secondary">
                  Pairwise agreement on each layer's own binary decision,
                  from {agreement.n_events.toLocaleString()} real events.
                  High agreement is the case for dropping a layer; low
                  agreement is the case for keeping both. Agreement is not
                  accuracy — two layers can agree and both be wrong.
                </p>
                <div className="overflow-hidden rounded border border-surface-hairline">
                  <div className="grid grid-cols-4 bg-surface-raised text-center text-[10px] font-semibold text-ink-muted">
                    <div className="p-1.5" />
                    {LAYER_ORDER.map((l) => (
                      <div key={l} className="p-1.5">{LAYER_LABEL[l]}</div>
                    ))}
                  </div>
                  {LAYER_ORDER.map((row) => (
                    <div key={row} className="grid grid-cols-4 border-t border-surface-hairline text-center text-xs">
                      <div className="flex items-center justify-center bg-surface-raised p-1.5 font-semibold text-ink-muted">
                        {LAYER_LABEL[row]}
                      </div>
                      {LAYER_ORDER.map((col) => {
                        const v = agreement.matrix[row]?.[col];
                        return (
                          <div
                            key={col}
                            className="flex items-center justify-center p-1.5 font-mono"
                            style={
                              v == null
                                ? undefined
                                : { background: `rgba(57,135,229,${Math.min(v, 0.9) * 0.35})` }
                            }
                          >
                            {v == null ? "—" : v.toFixed(2)}
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
                <div className="mt-2 flex gap-4 text-[10px] text-ink-muted">
                  {LAYER_ORDER.map((l) => (
                    <span key={l}>
                      {LAYER_LABEL[l]} flags {(agreement.flag_rates[l] * 100).toFixed(0)}%
                    </span>
                  ))}
                </div>
              </section>
            )}

            {latencyBins && latency && (
              <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
                <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
                  Detection latency — onset to first catch
                </h2>
                <p className="mb-3 text-[11px] text-ink-secondary">
                  {latency.vehicles_considered} vehicles were poisoned at some
                  point in the capture; {latency.vehicles_missed_entirely}{" "}
                  {latency.vehicles_missed_entirely === 1 ? "was" : "were"}{" "}
                  never caught at all and is excluded from this distribution
                  — binning a miss as "slow" would misstate the tail. Not the
                  same figure as the simulator's own printed TTD mean shown
                  in the Ledger screen; this is a distribution built here
                  from the raw events.
                </p>
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={latencyBins} margin={{ top: 4, right: 8, bottom: 4, left: -12 }}>
                      <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                      <XAxis dataKey="label" tick={{ fill: INK.muted, fontSize: 9 }} stroke={SURFACE.hairlineStrong} />
                      <YAxis tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} />
                      <Tooltip
                        contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }}
                        labelStyle={{ color: INK.secondary }}
                      />
                      <Bar dataKey="count" fill={SERIES[0]} radius={[2, 2, 0, 0]} isAnimationActive={false} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </section>
            )}
          </div>
        )}

        {ablation && (
          <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
            <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              Ablation: does more machine learning help?
            </h2>
            <p className="mb-3 text-[11px] text-ink-secondary">
              D1 = rule signatures only. D4 = + GAT spatial. D6 = + LSTM-AE
              temporal. {ablation.config}. Source: {ablation.source}.
            </p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {ablation.windows.map((w, i) => (
                <Accordion
                  key={w.cutoff_s}
                  open={openWindow === i}
                  onToggle={() => setOpenWindow((v) => (v === i ? null : i))}
                  bodyMaxHeight={220}
                  header={
                    <div className="flex flex-1 items-center justify-between">
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
                  }
                >
                  <div className="border-t border-surface-hairline p-3">
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
                    {w.note && (
                      <div className="mt-2">
                        <Callout>{w.note}</Callout>
                      </div>
                    )}
                  </div>
                </Accordion>
              ))}
            </div>
          </section>
        )}

        <section className="rounded-lg border border-surface-hairline bg-surface-panel p-4">
          <h2 className="mb-1 text-xs font-semibold uppercase tracking-wider text-ink-muted">
            Cost of the defence
          </h2>
          <p className="mb-3 text-[11px] text-ink-secondary">
            Accuracy numbers above say nothing about what this costs to run.
            Every figure here is measured, not estimated — the same capture
            and E5 sources used everywhere else in this app.
          </p>

          {attacks && (
            <div className="mb-4 overflow-hidden rounded border border-surface-hairline">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="bg-surface-raised text-[10px] uppercase tracking-wider text-ink-muted">
                    <th className="px-3 py-1.5 font-semibold">Attack</th>
                    <th className="px-3 py-1.5 font-semibold">Per-beacon overhead</th>
                    <th className="px-3 py-1.5 font-semibold">CDER</th>
                    <th className="px-3 py-1.5 font-semibold">Time to detect</th>
                  </tr>
                </thead>
                <tbody>
                  {attacks.map((a) => (
                    <tr key={a.attack_number} className="border-t border-surface-hairline">
                      <td className="px-3 py-1.5 font-mono text-ink-primary">{a.code}</td>
                      <td className="px-3 py-1.5 font-mono text-ink-secondary">
                        {a.sentinel_full?.PBPO_ms != null ? `${a.sentinel_full.PBPO_ms.toFixed(2)} ms` : "n/a"}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-ink-secondary">
                        {a.sentinel_full?.CDER != null ? a.sentinel_full.CDER.toFixed(3) : "n/a"}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-ink-secondary">
                        {a.sentinel_full?.TTD != null ? `${a.sentinel_full.TTD.toFixed(2)} s` : "n/a"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="border-t border-surface-hairline bg-surface-page px-3 py-2 text-[10px] leading-relaxed text-ink-muted">
                PBPO = per-beacon processing overhead (ms, SENTINEL_Full).
                CDER is the ratio this attack's detection cost adds relative
                to baseline processing — both from{" "}
                <code className="text-ink-primary">results_e5_final/e5_final_table.json</code>,
                the same source as the accuracy chart above.
              </p>
            </div>
          )}

          {crypto && (
            <div className="flex flex-col gap-4">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <h3 className="mb-2 text-[11px] font-medium text-ink-secondary">
                    Per-epoch crypto latency ({crypto.pq_crypto_cost_ms.epochs_sampled} epochs)
                  </h3>
                  <dl className="space-y-1.5 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">Ring signature (TRS)</dt>
                      <dd className="font-mono text-ink-primary">
                        {crypto.pq_crypto_cost_ms.trs_sign.toFixed(2)} ms
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">Homomorphic aggregate (FHE)</dt>
                      <dd className="font-mono text-ink-primary">
                        {crypto.pq_crypto_cost_ms.fhe_aggregate.toFixed(1)} ms
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">Key distribution (DKG)</dt>
                      <dd className="font-mono text-ink-primary">
                        {crypto.pq_crypto_cost_ms.dkg.toFixed(1)} ms
                      </dd>
                    </div>
                    <div className="flex justify-between border-t border-surface-hairline pt-1.5">
                      <dt className="text-ink-secondary">Epoch total</dt>
                      <dd className="font-mono font-medium text-ink-primary">
                        {crypto.pq_crypto_cost_ms.epoch_total.toFixed(0)} ms
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">TRS signature verification</dt>
                      <dd className="font-mono text-status-good">
                        {crypto.trs_verify.ok} ok / {crypto.trs_verify.fail} fail
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">Chaincode confirm latency</dt>
                      <dd className="font-mono text-ink-primary">
                        {crypto.chaincode_latency_ms.confirm.toFixed(0)} ms (
                        {crypto.chaincode_latency_ms.confirm_invokes} invokes)
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">Controller reassign latency</dt>
                      <dd className="font-mono text-ink-primary">
                        {crypto.chaincode_latency_ms.reassign.toFixed(0)} ms (
                        {crypto.chaincode_latency_ms.reassign_rollovers} rollovers)
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">Time-to-detect, this capture (mean)</dt>
                      <dd className="font-mono text-ink-primary">{crypto.ttd_seconds.toFixed(2)} s</dd>
                    </div>
                  </dl>
                  <p className="mt-1.5 text-[10px] leading-relaxed text-ink-muted">
                    Not the same figure as the per-attack TTD in the table
                    above — that's from the dedicated E5 measurement, this is
                    the mean across the one blockchain-enabled capture.
                  </p>
                </div>

                <div>
                  <h3 className="mb-2 text-[11px] font-medium text-ink-secondary">
                    Bandwidth overhead — {crypto.bandwidth_overhead.ratio_vs_baseline.toFixed(1)}×
                    baseline
                  </h3>
                  <dl className="space-y-1.5 text-xs">
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">Baseline (plain beacons)</dt>
                      <dd className="font-mono text-ink-primary">
                        {formatBytes(crypto.bandwidth_overhead.baseline_bytes)}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">+ HMAC auth</dt>
                      <dd className="font-mono text-ink-primary">
                        {formatBytes(crypto.bandwidth_overhead.hmac_bytes)}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">+ FHE ciphertext</dt>
                      <dd className="font-mono text-status-caught">
                        {formatBytes(crypto.bandwidth_overhead.fhe_bytes)}
                      </dd>
                    </div>
                    <div className="flex justify-between">
                      <dt className="text-ink-muted">+ TRS signatures</dt>
                      <dd className="font-mono text-ink-primary">
                        {formatBytes(crypto.bandwidth_overhead.trs_bytes)}
                      </dd>
                    </div>
                  </dl>
                  <p className="mt-2 text-[10px] leading-relaxed text-ink-muted">
                    FHE ciphertext dominates the overhead — this is the
                    measured cost of computing regional aggregates (e.g. mean
                    speed) without any RSU ever decrypting an individual
                    vehicle's data.
                  </p>
                </div>
              </div>

              <div className="rounded border border-surface-hairline p-3">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <h3 className="text-[11px] font-medium text-ink-secondary">
                      Off-chain beacon-window store (IPFS)
                    </h3>
                    <p className="mt-1 text-xs text-ink-primary">
                      {crypto.ipfs.windows_stored.toLocaleString()} windows
                      stored off-chain, {crypto.ipfs.hashes_on_chain.toLocaleString()}{" "}
                      hashes committed on-chain
                    </p>
                  </div>
                  <span className="shrink-0 rounded bg-status-serious/20 px-2 py-1 text-[10px] font-medium text-status-serious">
                    SIMULATED — not a real IPFS daemon
                  </span>
                </div>
                <p className="mt-2 rounded bg-surface-page px-2.5 py-2 text-[10px] leading-relaxed text-ink-muted">
                  {crypto.ipfs.note}
                </p>
              </div>
            </div>
          )}
        </section>

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
