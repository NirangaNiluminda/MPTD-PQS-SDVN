import {
  Area,
  Bar,
  BarChart,
  CartesianGrid,
  ComposedChart,
  ErrorBar,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useTokens } from "../design/tokens";

function SectionHeader({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="mb-3">
      <h2 className="text-base font-bold leading-snug text-ink-primary">{title}</h2>
      <p className="mt-1 text-[12.5px] leading-relaxed text-ink-muted">{subtitle}</p>
    </div>
  );
}

function ChartCard({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0 rounded-lg border border-surface-hairline bg-surface-panel p-4">
      {title && <h3 className="mb-2 text-center text-[13px] font-bold text-ink-primary">{title}</h3>}
      {children}
    </div>
  );
}

// ── Data ──────────────────────────────────────────────────────────────────
// AB1/AB5/AB10/AB3/AB4: transcribed and directly verified against
// report/main.tex's own results prose (see each section's citation). The
// baseline-vs-penetration comparison (B1/B2/B3 vs MPTD-PQS) was supplied
// directly and is NOT cross-checked against this repo's own
// results_e1_final data, which records a different comparison (Full vs.
// Lightweight mode across attack intensity, not baseline methods) — shown
// as provided, not re-derived.

const AB1_DATA = [
  { x: 0.05, full: 0.621, ablated: 0.361, gap: 0.621 - 0.361 },
  { x: 0.1, full: 0.723, ablated: 0.38, gap: 0.723 - 0.38 },
  { x: 0.2, full: 0.739, ablated: 0.413, gap: 0.739 - 0.413 },
  { x: 0.3, full: 0.774, ablated: 0.444, gap: 0.774 - 0.444 },
  { x: 0.4, full: 0.781, ablated: 0.395, gap: 0.781 - 0.395 },
];

const AB5_DATA = [
  { x: 10, full: 0.867, ablated: 0.333, gap: 0.867 - 0.333 },
  { x: 60, full: 0.833, ablated: 0.367, gap: 0.833 - 0.367 },
  { x: 100, full: 0.867, ablated: 0.367, gap: 0.867 - 0.367 },
  { x: 140, full: 0.867, ablated: 0.267, gap: 0.867 - 0.267 },
];

const AB10_DATA = [
  { label: "ρ_a = 0", full: 0.0, ablated: 0.08 },
  { label: "ρ_a = 0.8", full: 0.0, ablated: 0.2 },
];

const BASELINE_PENETRATION_DATA = [
  { pct: 0, B1: 0, B2: 0, B3: 0, "MPTD-PQS": 0 },
  { pct: 20, B1: 0.31, B2: 0.03, B3: 0.53, "MPTD-PQS": 0.775 },
  { pct: 40, B1: 0.185, B2: 0.01, B3: 0.535, "MPTD-PQS": 0.74 },
  { pct: 60, B1: 0.13, B2: -0.01, B3: 0.305, "MPTD-PQS": 0.43 },
  { pct: 80, B1: 0.125, B2: -0.02, B3: 0.295, "MPTD-PQS": 0.37 },
  { pct: 100, B1: 0, B2: 0, B3: 0, "MPTD-PQS": 0 },
];

const AB3_DATA = [
  { x: 1, full: 0.33, fullErr: 0.33, ablated: -0.01, ablatedErr: 0.09 },
  { x: 2, full: 0.33, fullErr: 0.33, ablated: -0.01, ablatedErr: 0.09 },
  { x: 5, full: 0.205, fullErr: 0.245, ablated: -0.105, ablatedErr: 0.08 },
  { x: 10, full: 0.145, fullErr: 0.185, ablated: -0.115, ablatedErr: 0.08 },
  { x: 20, full: 0.18, fullErr: 0.205, ablated: -0.05, ablatedErr: 0.1 },
];

const AB4_DATA = [
  { x: 0.1, full: -0.021, fullErr: 0.12, ablated: 0.024, ablatedErr: 0.08 },
  { x: 0.2, full: 0.019, fullErr: 0.1, ablated: 0.024, ablatedErr: 0.08 },
  { x: 0.3, full: 0.133, fullErr: 0.095, ablated: 0.024, ablatedErr: 0.08 },
  { x: 0.4, full: 0.273, fullErr: 0.105, ablated: 0.025, ablatedErr: 0.075 },
  { x: 0.5, full: 0.367, fullErr: 0.125, ablated: 0.025, ablatedErr: 0.075 },
];

export default function ResultsScreen() {
  const { SERIES, STATUS, INK, SURFACE } = useTokens();
  const accentFull = SERIES[0];
  const accentAblated = STATUS.caught;

  return (
    <div className="h-full overflow-y-auto p-5">
      <div className="mx-auto max-w-5xl space-y-8">
        <header>
          <h1 className="text-lg font-semibold text-ink-primary">Results &amp; ablation</h1>
          <p className="mt-1 text-xs text-ink-secondary">
            The paper's own ablation findings, shown as real charts rather than static figures.
          </p>
        </header>

        <section>
          <SectionHeader
            title="MPTD-PQS vs. three baselines across attack penetration"
            subtitle="B1 = Ghaleb et al. (2014), B2 = Ercan et al. (2022), B3 = Sharma &amp; Liu (2021), vs. MPTD-PQS full mode. Provided directly — not cross-verified against this repo's own results_e1_final data, which records a different comparison (Full vs. Lightweight mode, not these baseline methods)."
          />
          <ChartCard>
            <div className="h-72 w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={BASELINE_PENETRATION_DATA} margin={{ top: 4, right: 12, bottom: 4, left: -12 }}>
                  <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                  <XAxis
                    dataKey="pct"
                    tick={{ fill: INK.muted, fontSize: 10 }}
                    stroke={SURFACE.hairlineStrong}
                    label={{ value: "Attack penetration (%)", position: "insideBottom", offset: -2, fill: INK.muted, fontSize: 10 }}
                  />
                  <YAxis domain={[-0.05, 1]} tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} label={{ value: "MCC", angle: -90, position: "insideLeft", fill: INK.muted, fontSize: 10 }} />
                  <Tooltip contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }} labelStyle={{ color: INK.secondary }} />
                  <Legend wrapperStyle={{ fontSize: 10 }} />
                  <Line type="monotone" dataKey="B1" name="B1 (Ghaleb)" stroke="#a16207" strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} />
                  <Line type="monotone" dataKey="B2" name="B2 (Ercan)" stroke="#2563eb" strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} />
                  <Line type="monotone" dataKey="B3" name="B3 (Sharma)" stroke="#dc2626" strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} />
                  <Line type="monotone" dataKey="MPTD-PQS" name="MPTD-PQS (proposed)" stroke="#16a34a" strokeWidth={2.5} dot={{ r: 3 }} isAnimationActive={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
        </section>

        <section>
          <SectionHeader
            title="Lightweight mode is necessary but not sufficient; full mode is more capable but not self-sufficient"
            subtitle="AB1 removes the rule layer while retaining AI; AB5 removes the AI layer while retaining rules. report/main.tex:8558-8567 (synthesis), 7157-7276 (AB1), 7685-7857 (AB5)."
          />
          <div className="grid min-w-0 grid-cols-1 gap-4 sm:grid-cols-2">
            <ChartCard title="AB1 — rules removed, AI retained">
              <div className="h-64 w-full min-w-0">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={AB1_DATA} margin={{ top: 4, right: 12, bottom: 4, left: -12 }}>
                    <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                    <XAxis
                      dataKey="x"
                      type="number"
                      domain={[0.05, 0.4]}
                      tick={{ fill: INK.muted, fontSize: 10 }}
                      stroke={SURFACE.hairlineStrong}
                      label={{ value: "Attack penetration rate ρ_a", position: "insideBottom", offset: -2, fill: INK.muted, fontSize: 10 }}
                    />
                    <YAxis domain={[0, 1]} tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} label={{ value: "MCC (fused verdict)", angle: -90, position: "insideLeft", fill: INK.muted, fontSize: 10 }} />
                    <Tooltip contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }} labelStyle={{ color: INK.secondary }} />
                    <Legend wrapperStyle={{ fontSize: 10 }} />
                    <Area type="monotone" dataKey="ablated" stackId="a1" stroke="none" fill="transparent" legendType="none" isAnimationActive={false} />
                    <Area type="monotone" dataKey="gap" stackId="a1" stroke="none" fill={accentFull} fillOpacity={0.12} legendType="none" isAnimationActive={false} />
                    <Line type="monotone" dataKey="full" name="Full system" stroke={accentFull} strokeWidth={2.5} dot={{ r: 3 }} isAnimationActive={false} />
                    <Line type="monotone" dataKey="ablated" name="Rule signatures removed (AB1)" stroke={accentAblated} strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </ChartCard>

            <ChartCard title="AB5 — AI removed, rules retained">
              <div className="h-64 w-full min-w-0">
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={AB5_DATA} margin={{ top: 4, right: 12, bottom: 4, left: -12 }}>
                    <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                    <XAxis
                      dataKey="x"
                      type="number"
                      domain={[10, 140]}
                      tick={{ fill: INK.muted, fontSize: 10 }}
                      stroke={SURFACE.hairlineStrong}
                      label={{ value: "Vehicle speed [km/h]", position: "insideBottom", offset: -2, fill: INK.muted, fontSize: 10 }}
                    />
                    <YAxis domain={[0, 1]} tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} label={{ value: "MCC", angle: -90, position: "insideLeft", fill: INK.muted, fontSize: 10 }} />
                    <Tooltip contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }} labelStyle={{ color: INK.secondary }} />
                    <Legend wrapperStyle={{ fontSize: 10 }} />
                    <Area type="monotone" dataKey="ablated" stackId="a5" stroke="none" fill="transparent" legendType="none" isAnimationActive={false} />
                    <Area type="monotone" dataKey="gap" stackId="a5" stroke="none" fill={accentFull} fillOpacity={0.12} legendType="none" isAnimationActive={false} />
                    <Line type="monotone" dataKey="full" name="Full system" stroke={accentFull} strokeWidth={2.5} dot={{ r: 3 }} isAnimationActive={false} />
                    <Line type="monotone" dataKey="ablated" name="AI layer removed (AB5)" stroke="#10b981" strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </ChartCard>
          </div>
        </section>

        <section>
          <SectionHeader
            title="The trust layer's value is in mitigation, not detection"
            subtitle="AB10 — false revocation of honest vehicles. The full system never wrongly revokes; removing the on-chain BFT quorum lets false revocations climb with attack penetration. report/main.tex:8285-8300."
          />
          <ChartCard>
            <div className="h-64 w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={AB10_DATA} margin={{ top: 4, right: 12, bottom: 4, left: -12 }}>
                  <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: INK.muted, fontSize: 11 }} stroke={SURFACE.hairlineStrong} />
                  <YAxis
                    domain={[0, 0.25]}
                    tick={{ fill: INK.muted, fontSize: 10 }}
                    stroke={SURFACE.hairlineStrong}
                    label={{ value: "FRR_revoke — honest vehicles wrongly revoked", angle: -90, position: "insideLeft", fill: INK.muted, fontSize: 10 }}
                  />
                  <Tooltip contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }} labelStyle={{ color: INK.secondary }} />
                  <Legend wrapperStyle={{ fontSize: 10 }} />
                  <Bar dataKey="full" name="Full system (BFT SC-Revoke)" fill={accentFull} radius={[2, 2, 0, 0]} isAnimationActive={false} />
                  <Bar dataKey="ablated" name="Blockchain removed (AB10)" fill={STATUS.missed} radius={[2, 2, 0, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="mt-2 text-center text-[11px] italic text-ink-muted">
              At ρ_a = 0.8: 1 honest vehicle in 5 wrongly and permanently revoked.
            </p>
          </ChartCard>
        </section>

        <section>
          <SectionHeader
            title="AB3 — GAT disabled"
            subtitle="Detection quality vs. coordinated Sybil identities per RSU. Sybil-only attack, ρ_a=0.20, 3 seeds — preliminary, high seed variance. report/main.tex:7380-7517."
          />
          <ChartCard>
            <div className="h-64 w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={AB3_DATA} margin={{ top: 4, right: 12, bottom: 4, left: -12 }}>
                  <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                  <XAxis
                    dataKey="x"
                    tick={{ fill: INK.muted, fontSize: 10 }}
                    stroke={SURFACE.hairlineStrong}
                    label={{ value: "Coordinated Sybil identities per RSU (n_coord)", position: "insideBottom", offset: -2, fill: INK.muted, fontSize: 10 }}
                  />
                  <YAxis tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} label={{ value: "MCC", angle: -90, position: "insideLeft", fill: INK.muted, fontSize: 10 }} />
                  <Tooltip contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }} labelStyle={{ color: INK.secondary }} />
                  <Legend wrapperStyle={{ fontSize: 10 }} />
                  <Line type="monotone" dataKey="full" name="FULL (GAT on)" stroke={accentFull} strokeWidth={2.5} dot={{ r: 3 }} isAnimationActive={false}>
                    <ErrorBar dataKey="fullErr" width={4} stroke={accentFull} strokeOpacity={0.6} />
                  </Line>
                  <Line type="monotone" dataKey="ablated" name="AB3 (GAT removed)" stroke={STATUS.caught} strokeWidth={2} strokeDasharray="5 3" dot={{ r: 3 }} isAnimationActive={false}>
                    <ErrorBar dataKey="ablatedErr" width={4} stroke={STATUS.caught} strokeOpacity={0.6} />
                  </Line>
                </LineChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
        </section>

        <section>
          <SectionHeader
            title="AB4 — LSTM-AE disabled"
            subtitle="Detection quality vs. stealth drift bound. Stealth trajectory poisoning (TP-S1), ρ_a=0.20, 5 seeds. Numerically identical, seed-for-seed, across the whole sweep for the ablated arm. report/main.tex:7517-7685."
          />
          <ChartCard>
            <div className="h-64 w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={AB4_DATA} margin={{ top: 4, right: 12, bottom: 4, left: -12 }}>
                  <CartesianGrid stroke={SURFACE.hairline} vertical={false} />
                  <XAxis
                    dataKey="x"
                    tick={{ fill: INK.muted, fontSize: 10 }}
                    stroke={SURFACE.hairlineStrong}
                    label={{ value: "Stealth drift bound ε_max (m per beacon)", position: "insideBottom", offset: -2, fill: INK.muted, fontSize: 10 }}
                  />
                  <YAxis tick={{ fill: INK.muted, fontSize: 10 }} stroke={SURFACE.hairlineStrong} label={{ value: "MCC", angle: -90, position: "insideLeft", fill: INK.muted, fontSize: 10 }} />
                  <Tooltip contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }} labelStyle={{ color: INK.secondary }} />
                  <Legend wrapperStyle={{ fontSize: 10 }} />
                  <Line type="monotone" dataKey="full" name="MPTD-PQS (full)" stroke={accentFull} strokeWidth={2.5} dot={{ r: 3 }} isAnimationActive={false}>
                    <ErrorBar dataKey="fullErr" width={4} stroke={accentFull} strokeOpacity={0.6} />
                  </Line>
                  <Line type="monotone" dataKey="ablated" name="AB4 (LSTM-AE removed)" stroke={STATUS.caught} strokeWidth={2} dot={{ r: 3 }} isAnimationActive={false}>
                    <ErrorBar dataKey="ablatedErr" width={4} stroke={STATUS.caught} strokeOpacity={0.6} />
                  </Line>
                </LineChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
        </section>
      </div>
    </div>
  );
}
