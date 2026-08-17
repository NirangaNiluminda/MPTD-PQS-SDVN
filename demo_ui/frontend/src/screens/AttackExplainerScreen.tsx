import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronLeft, ChevronRight, Radar, TriangleAlert, X } from "lucide-react";
import { api, AttackEvidenceDto, AttackInfoDto } from "../api";
import { useSemanticTokens, useTokens } from "../design/tokens";
import { useMode } from "../store/mode";
import Accordion from "../components/Accordion";
import StatusPill, { SemanticStatus } from "../components/StatusPill";

const ACTOR_LABEL: Record<string, string> = {
  compromised_rsu: "Hijacked roadside unit",
  malicious_vehicle: "Lying vehicle",
  malicious_controller: "Hijacked controller",
  mitm_relay: "Intercepting relay vehicle",
};

const ACTOR_GLYPH: Record<string, string> = {
  compromised_rsu: "■",
  malicious_vehicle: "●",
  malicious_controller: "◆",
  mitm_relay: "▲",
};

type Verdict = "sentinel" | "close" | "baseline";

const VERDICT_LABEL: Record<Verdict, string> = {
  sentinel: "CAUGHT",
  close: "TOO CLOSE TO CALL",
  baseline: "BASELINE WINS",
};

const VERDICT_SEMANTIC: Record<Verdict, SemanticStatus> = {
  sentinel: "safe",
  close: "warning",
  baseline: "compromised",
};

function verdictOf(a: AttackInfoDto): Verdict {
  if (a.baseline_wins) return "baseline";
  const gap =
    a.sentinel_full && a.best_baseline_mcc != null
      ? a.sentinel_full.MCC - a.best_baseline_mcc
      : null;
  const std = a.sentinel_full?.MCC_std ?? 0;
  // "Too close to call" is a real statistical read, not a picked number: the
  // gap between SENTINEL and the best baseline sits inside SENTINEL's own
  // measured across-seed std — the only uncertainty figure this data has.
  if (gap != null && Math.abs(gap) <= std) return "close";
  return "sentinel";
}

function pct01(mcc: number | null | undefined): number {
  // MCC ranges [-1,1]; clamp to [0,1] for a bar width — the raw signed value
  // is always shown alongside as text, so nothing is hidden by the clamp.
  if (mcc == null) return 0;
  return Math.max(0, Math.min(1, mcc)) * 100;
}

// Plain-English metric labels (refinement #3) — Greek/mathematical notation
// is Expert-mode only. The three metrics are exactly the three fusion
// layers (rules / GAT / LSTM-AE) this app names the same way everywhere
// else, so the plain labels stay consistent with the rest of the app.
const METRIC_LABEL = {
  psi: { expert: "Mean ψ̂", plain: "Rule Confidence" },
  gat: { expert: "Mean Ŝ", plain: "Spatial Anomaly" },
  ae: { expert: "Mean ε̂", plain: "Time-Pattern Anomaly" },
} as const;

function AttackLegend() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        onMouseEnter={() => setOpen(true)}
        className="flex items-center gap-1.5 rounded-md border border-surface-hairline2 bg-surface-raised px-3 py-1.5 text-badge font-semibold text-ink-secondary transition-colors hover:text-ink-primary"
      >
        Key
        <ChevronDown size={14} className={`transition-transform ${open ? "rotate-180" : ""}`} aria-hidden />
      </button>
      {open && (
        <div
          onMouseLeave={() => setOpen(false)}
          className="anim-rise absolute right-0 top-full z-20 mt-1.5 w-72 rounded-lg border border-surface-hairline2 bg-surface-panel p-3.5 shadow-2xl"
        >
          <p className="mb-2 text-badge font-semibold uppercase tracking-wider text-ink-muted">
            Shape = attacker type
          </p>
          <div className="flex flex-col gap-1.5">
            {Object.entries(ACTOR_GLYPH).map(([actor, glyph]) => (
              <div key={actor} className="flex items-center gap-2.5 text-body text-ink-secondary">
                <span className="w-5 text-center font-mono text-ink-primary">{glyph}</span>
                {ACTOR_LABEL[actor]}
              </div>
            ))}
          </div>
          <p className="mb-2 mt-3.5 text-badge font-semibold uppercase tracking-wider text-ink-muted">
            Color = outcome
          </p>
          <div className="flex flex-col gap-1.5">
            {(["sentinel", "close", "baseline"] as Verdict[]).map((v) => (
              <StatusPill key={v} status={VERDICT_SEMANTIC[v]} compact>
                {VERDICT_LABEL[v]}
              </StatusPill>
            ))}
          </div>
          <p className="mt-3 text-badge leading-relaxed text-ink-muted">
            Shape and color are never the only signal — every tile also
            carries the attack name and outcome as text.
          </p>
        </div>
      )}
    </div>
  );
}

function MetricCard({
  metricKey,
  value,
}: {
  metricKey: keyof typeof METRIC_LABEL;
  value: number | undefined;
}) {
  const mode = useMode((s) => s.mode);
  const label = METRIC_LABEL[metricKey][mode];
  // Qualitative read only — these are AGGREGATE means across every event of
  // this type, not a single event's score, so there's no exact threshold
  // line to draw here the way there is per-event elsewhere in the app. The
  // banding communicates "how strongly this layer engaged on average", not
  // a pass/fail crossing.
  // "compromised" (red) is reserved app-wide for failure/negative outcomes —
  // a strong signal here is a good thing (the layer engaged), so it reads as
  // "informational" (blue) rather than red.
  const tone: SemanticStatus = value == null ? "inactive" : value > 0.6 ? "informational" : value > 0.3 ? "warning" : "safe";
  const toneLabel = value == null ? "No data" : tone === "informational" ? "Strong signal" : tone === "warning" ? "Moderate signal" : "Weak signal";
  return (
    <div className="flex flex-col items-center gap-2.5 rounded-lg border border-surface-hairline bg-surface-page p-4 text-center">
      <span className="text-badge font-semibold uppercase tracking-wide text-ink-muted">{label}</span>
      <span className="font-mono text-3xl font-bold text-ink-primary">
        {value != null ? value.toFixed(3) : "—"}
      </span>
      <StatusPill status={tone} compact>
        {toneLabel}
      </StatusPill>
    </div>
  );
}

function EvidenceBody({ evidence }: { evidence: AttackEvidenceDto | null | undefined }) {
  if (evidence === undefined) {
    return <p className="text-body text-ink-secondary">Loading…</p>;
  }
  if (!evidence || evidence.n_events === 0) {
    return (
      <p className="text-body leading-relaxed text-ink-secondary">
        This variant has no per-event trace in the single captured
        blockchain-enabled recording (
        <code className="text-ink-primary">captures/combined_bc_90s.log</code>
        , 90s) this section reads from — it simply didn't occur in that run.
        The accuracy numbers above come from a separate, dedicated E5
        measurement and stand on their own.
      </p>
    );
  }
  return (
    <div className="flex flex-col gap-4">
      <p className="text-body leading-relaxed text-ink-secondary">
        {evidence.n_events.toLocaleString()} poisoned events with this ground
        truth in the capture, {evidence.n_caught?.toLocaleString()} caught
        ({((evidence.detection_rate ?? 0) * 100).toFixed(1)}%),{" "}
        {evidence.n_missed?.toLocaleString()} missed.
      </p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <MetricCard metricKey="psi" value={evidence.mean_psi_fuse} />
        <MetricCard metricKey="gat" value={evidence.mean_gat_score} />
        <MetricCard metricKey="ae" value={evidence.mean_ae_norm} />
      </div>
      {evidence.top_signatures && evidence.top_signatures.length > 0 && (
        <div>
          <p className="mb-2 text-badge font-semibold uppercase tracking-wider text-ink-muted">
            Most-tripped rule signatures
          </p>
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            {evidence.top_signatures.map((s, i) => {
              const spanFull =
                i === evidence.top_signatures!.length - 1 && evidence.top_signatures!.length % 2 === 1;
              return (
              <div
                key={s.code}
                className={`flex flex-col gap-1.5 rounded-lg border border-surface-hairline bg-surface-page p-3 ${spanFull ? "sm:col-span-2" : ""}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="text-body font-semibold leading-tight text-ink-primary">{s.name}</span>
                  <span className="shrink-0 font-mono text-xl font-bold text-entity-rsu">
                    {(s.pct * 100).toFixed(0)}%
                  </span>
                </div>
                <StatusPill status="warning" compact>
                  Signature matched
                </StatusPill>
                <p className="text-badge leading-relaxed text-ink-secondary">
                  {s.detail} Fired in {(s.pct * 100).toFixed(0)}% of this attack's real events.
                </p>
              </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function TechnicalDataBody({ attack, evidence }: { attack: AttackInfoDto; evidence: AttackEvidenceDto | null | undefined }) {
  const rows: { glyph: string; text: string }[] = [];
  if (attack.baseline_wins) {
    rows.push({
      glyph: "⚠",
      text: `The best baseline (${attack.best_baseline_code}) scores higher here — ${attack.best_baseline_mcc?.toFixed(3)} vs SENTINEL's ${attack.sentinel_full?.MCC.toFixed(3)}. Shown as measured, not hidden.`,
    });
  }
  if (attack.sentinel_full?.MCC_std != null) {
    rows.push({
      glyph: "○",
      text: `SENTINEL's MCC varies ±${attack.sentinel_full.MCC_std.toFixed(3)} across seeds — treat differences smaller than that as noise, not a real gap.`,
    });
  }
  if (evidence && evidence.n_events > 0 && evidence.n_events < 200) {
    rows.push({
      glyph: "⚠",
      text: `Only ${evidence.n_events} events of this type appear in the capture used for the evidence above — a thin sample next to the other variants.`,
    });
  }
  if (evidence && evidence.n_events === 0) {
    rows.push({
      glyph: "⚠",
      text: "No per-event trace exists for this variant in the current recording — the evidence tab above cannot say anything this number doesn't already.",
    });
  }
  const full = attack.sentinel_full;
  return (
    <div className="flex flex-col gap-4">
      {rows.length > 0 ? (
        <ul className="flex flex-col gap-2">
          {rows.map((r, i) => (
            <li key={i} className="flex items-start gap-2 text-body leading-relaxed text-ink-secondary">
              <span className={`mt-0.5 shrink-0 font-semibold ${r.glyph === "⚠" ? "text-status-caught" : "text-ink-secondary"}`}>{r.glyph}</span>
              <span>{r.text}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-body text-ink-secondary">No caveats flagged for this variant.</p>
      )}
      {(full?.CDER != null || full?.PBPO_ms != null) && (
        <div className="grid grid-cols-2 gap-3 border-t border-surface-hairline pt-3.5 text-center">
          {full?.CDER != null && (
            <div>
              <div className="text-badge uppercase tracking-wide text-ink-muted">CDER</div>
              <div className="font-mono text-body text-ink-primary">{full.CDER.toFixed(3)}</div>
            </div>
          )}
          {full?.PBPO_ms != null && (
            <div>
              <div className="text-badge uppercase tracking-wide text-ink-muted">per-beacon overhead</div>
              <div className="font-mono text-body text-ink-primary">{full.PBPO_ms.toFixed(2)} ms</div>
            </div>
          )}
        </div>
      )}
      <p className="border-t border-surface-hairline pt-3 font-mono text-badge text-ink-muted">
        Source: results_e5_final/e5_final_table.json
        {evidence && evidence.n_events > 0 && " · captures/combined_bc_90s.log"}
      </p>
    </div>
  );
}

export default function AttackExplainerScreen({
  onShowScenario,
}: {
  onShowScenario: (scenarioId: string) => void;
}) {
  const semantic = useSemanticTokens();
  const [attacks, setAttacks] = useState<AttackInfoDto[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const [evidenceByAttack, setEvidenceByAttack] = useState<Record<number, AttackEvidenceDto | null>>({});
  const [technicalOpen, setTechnicalOpen] = useState(false);
  const openOrigin = useRef<{ dx: number; dy: number }>({ dx: 0, dy: 0 });

  useEffect(() => {
    api
      .attacks()
      .then(setAttacks)
      .catch((e) => setError(String(e)));
  }, []);

  const tallies = useMemo(() => {
    if (!attacks) return null;
    const counts: Record<Verdict, number> = { sentinel: 0, close: 0, baseline: 0 };
    for (const a of attacks) counts[verdictOf(a)]++;
    return counts;
  }, [attacks]);

  const openAttack = attacks && openIndex != null ? attacks[openIndex] : null;
  const openEvidence = openAttack ? evidenceByAttack[openAttack.attack_number] : undefined;

  const loadEvidence = (attackNumber: number) => {
    if (attackNumber in evidenceByAttack) return;
    api
      .captureAttackEvidence(attackNumber)
      .then((ev) => setEvidenceByAttack((m) => ({ ...m, [attackNumber]: ev })))
      .catch(() => setEvidenceByAttack((m) => ({ ...m, [attackNumber]: null })));
  };

  const open = (index: number, e: React.MouseEvent<HTMLButtonElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    openOrigin.current = {
      dx: r.left + r.width / 2 - window.innerWidth / 2,
      dy: r.top + r.height / 2 - window.innerHeight / 2,
    };
    setOpenIndex(index);
    setTechnicalOpen(false);
    if (attacks) loadEvidence(attacks[index].attack_number);
  };

  const close = () => setOpenIndex(null);

  const step = (delta: number) => {
    if (!attacks || openIndex == null) return;
    const next = (openIndex + delta + attacks.length) % attacks.length;
    setOpenIndex(next);
    setTechnicalOpen(false);
    loadEvidence(attacks[next].attack_number);
  };

  const winCount = attacks?.filter((a) => a.baseline_wins).length ?? 0;

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mx-auto max-w-6xl">
        <header className="mb-6 flex flex-wrap items-end justify-between gap-5">
          <div className="max-w-2xl">
            <h1 className="text-section-title text-ink-primary">
              Seven ways to poison this network
            </h1>
            <p className="mt-1.5 text-body leading-relaxed text-ink-secondary">
              Each tile is one attack. Color and shape say how it ended;
              nothing else is shown yet. Open one for the evidence, the
              caveats, and what produced the number. Every figure comes
              straight from{" "}
              <code className="text-ink-primary">results_e5_final/e5_final_table.json</code>
              {attacks && winCount > 0 && (
                <> — on {winCount} of 7 variants a baseline actually scores higher.</>
              )}
            </p>
          </div>
          <div className="flex items-center gap-5">
            {tallies && (
              <div className="flex gap-5">
                {(["sentinel", "close", "baseline"] as Verdict[]).map((v) => (
                  <div key={v} className="flex flex-col gap-0.5">
                    <span
                      className="font-mono text-hero leading-none"
                      style={{ color: semantic[VERDICT_SEMANTIC[v]] }}
                    >
                      {tallies[v]}
                    </span>
                    <span className="text-badge font-bold uppercase tracking-widest text-ink-muted">
                      {VERDICT_LABEL[v]}
                    </span>
                  </div>
                ))}
              </div>
            )}
            <AttackLegend />
          </div>
        </header>

        {error && (
          <div className="rounded border border-status-missed/40 bg-status-missed/10 p-4 text-body text-status-missed">
            {error}
          </div>
        )}

        {!attacks && !error && <div className="text-body text-ink-secondary">Loading…</div>}

        {attacks && (
          <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {attacks.map((a, i) => {
              const v = verdictOf(a);
              const color = semantic[VERDICT_SEMANTIC[v]];
              return (
                <button
                  key={a.attack_number}
                  onClick={(e) => open(i, e)}
                  className="flex flex-col gap-3 rounded-lg border border-surface-hairline bg-surface-panel p-4 text-left transition-all hover:-translate-y-0.5 hover:border-surface-hairline2 hover:shadow-lg"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xl leading-none" style={{ color }}>
                      {ACTOR_GLYPH[a.actor] ?? "●"}
                    </span>
                    <StatusPill status={VERDICT_SEMANTIC[v]} compact>
                      {VERDICT_LABEL[v]}
                    </StatusPill>
                  </div>
                  <div className="mt-auto flex flex-col gap-0.5">
                    <span className="text-body font-semibold leading-tight text-ink-primary">
                      {a.human_name}
                    </span>
                    <span className="text-badge text-ink-secondary">
                      {ACTOR_LABEL[a.actor] ?? a.actor}
                    </span>
                  </div>
                  <div className="h-[3px] overflow-hidden rounded-full bg-surface-hairline">
                    <div
                      className="anim-sweep h-full rounded-full"
                      style={{ width: `${pct01(a.sentinel_full?.MCC)}%`, background: color }}
                    />
                  </div>
                </button>
              );
            })}
            {/* Refinement #2: 7 tiles leave a dangling gap in a 4-col grid —
                an explicit placeholder reads as intentional, not broken. */}
            <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-surface-hairline2 p-4 text-center text-ink-muted">
              <span className="text-2xl leading-none">+</span>
              <span className="text-badge">More attack variants coming</span>
            </div>
          </div>
        )}
      </div>

      {openAttack && (
        <>
          <div
            onClick={close}
            className="anim-fadein fixed inset-0 z-20 bg-black/60 backdrop-blur-[3px]"
          />
          <div className="fixed inset-0 z-30 flex items-start justify-center overflow-y-auto p-[5vh_16px_4vh] pointer-events-none">
            <div
              className="pointer-events-auto my-[5vh] w-full max-w-2xl overflow-hidden rounded-xl border border-surface-hairline2 bg-surface-panel shadow-2xl"
              style={
                {
                  "--fx": `${openOrigin.current.dx}px`,
                  "--fy": `${openOrigin.current.dy}px`,
                } as React.CSSProperties
              }
            >
              <div className="anim-panel-in">
                <DrillHeader
                  attack={openAttack}
                  evidence={openEvidence}
                  onClose={close}
                  onWatch={
                    openAttack.sample_scenario_id
                      ? () => {
                          onShowScenario(openAttack.sample_scenario_id!);
                          close();
                        }
                      : undefined
                  }
                />
                <div className="flex flex-col gap-4 p-5">
                  <AccuracyPanel attack={openAttack} />

                  <div className="rounded-lg border border-surface-hairline bg-surface-panel">
                    <div className="px-3.5 pt-3.5">
                      <p className="text-badge font-semibold uppercase tracking-wider text-ink-muted">
                        How the system knew
                      </p>
                    </div>
                    <div className="p-3.5">
                      <EvidenceBody evidence={openEvidence} />
                    </div>
                  </div>

                  <div className="overflow-hidden rounded-lg border-l-4 border-status-caught shadow-md">
                    <Accordion
                      open={technicalOpen}
                      onToggle={() => setTechnicalOpen((v) => !v)}
                      bodyMaxHeight={480}
                      header={
                        <span className="flex items-center gap-2 text-body font-semibold text-ink-primary">
                          <TriangleAlert size={16} className="shrink-0 text-status-caught" aria-hidden />
                          Caveats &amp; Technical Data
                        </span>
                      }
                    >
                      <div className="border-t border-surface-hairline p-3.5">
                        <TechnicalDataBody attack={openAttack} evidence={openEvidence} />
                      </div>
                    </Accordion>
                  </div>

                  <div className="flex items-center justify-between border-t border-surface-hairline pt-3.5">
                    <button
                      onClick={() => step(-1)}
                      className="flex items-center gap-1 text-badge font-medium text-ink-secondary transition-colors hover:text-ink-primary"
                    >
                      <ChevronLeft size={15} aria-hidden /> Previous attack
                    </button>
                    <button
                      onClick={() => step(1)}
                      className="flex items-center gap-1 text-badge font-medium text-ink-secondary transition-colors hover:text-ink-primary"
                    >
                      Next attack <ChevronRight size={15} aria-hidden />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function DrillHeader({
  attack,
  evidence,
  onClose,
  onWatch,
}: {
  attack: AttackInfoDto;
  evidence: AttackEvidenceDto | null | undefined;
  onClose: () => void;
  onWatch?: () => void;
}) {
  const semantic = useSemanticTokens();
  const v = verdictOf(attack);
  const color = semantic[VERDICT_SEMANTIC[v]];
  const detectionRate = evidence && evidence.n_events > 0 ? evidence.detection_rate ?? null : null;

  return (
    <div className="sticky top-0 z-10 border-b border-surface-hairline bg-surface-panel p-5">
      <div className="flex items-start gap-3.5">
        <span className="font-mono text-2xl leading-none" style={{ color }}>
          {ACTOR_GLYPH[attack.actor] ?? "●"}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <h2 className="text-section-title text-ink-primary">{attack.human_name}</h2>
            <StatusPill status={VERDICT_SEMANTIC[v]}>{VERDICT_LABEL[v]}</StatusPill>
          </div>
          <p className="mt-1.5 text-body leading-relaxed text-ink-secondary">{attack.description}</p>
        </div>
        {/* Refinement #6: only the primary CTA and close live in the header —
            previous/next moved to a lighter nav row at the bottom. */}
        <div className="flex shrink-0 items-center gap-2">
          {onWatch && (
            <button
              onClick={onWatch}
              className="flex items-center gap-1.5 rounded-md border border-entity-rsu bg-entity-rsu px-3.5 py-2 text-badge font-semibold text-white transition-all hover:opacity-90 active:scale-[0.97]"
            >
              <Radar size={14} aria-hidden />
              Watch on live map
            </button>
          )}
          <button
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-md border border-surface-hairline2 bg-surface-raised text-ink-secondary transition-colors hover:text-ink-primary"
            aria-label="Close"
          >
            <X size={15} aria-hidden />
          </button>
        </div>
      </div>
      {/* Refinement #7: the attack summary should communicate impact at a
          glance — a real, evidence-derived detection rate, not a decorative
          number. Only shown once the evidence fetch has actually resolved. */}
      {detectionRate != null && (
        <div className="mt-3.5">
          <StatusPill status={detectionRate >= 0.995 ? "safe" : detectionRate >= 0.5 ? "warning" : "compromised"}>
            {(detectionRate * 100).toFixed(detectionRate >= 0.995 || detectionRate === 0 ? 0 : 1)}% caught in this capture
          </StatusPill>
        </div>
      )}
    </div>
  );
}

function AccuracyPanel({ attack }: { attack: AttackInfoDto }) {
  const { SERIES } = useTokens();
  const full = attack.sentinel_full;
  return (
    <div className="anim-rise flex flex-col gap-3.5 rounded-lg border border-surface-hairline bg-surface-raised p-4">
      <span className="text-body font-semibold text-ink-primary">
        Accuracy against the published baseline
      </span>
      <div className="flex items-center gap-3">
        <span className="w-20 text-body font-medium text-ink-secondary">SENTINEL</span>
        <div className="h-7 flex-1 overflow-hidden rounded-md bg-surface-page">
          <div
            className="anim-sweep h-full"
            style={{ width: `${pct01(full?.MCC)}%`, background: SERIES[0] }}
          />
        </div>
        <span className="w-16 shrink-0 text-right font-mono text-xl font-bold" style={{ color: SERIES[0] }}>
          {full ? full.MCC.toFixed(3) : "n/a"}
        </span>
      </div>
      <div className="flex items-center gap-3">
        <span className="w-20 text-body font-medium text-ink-secondary">Baseline</span>
        <div className="h-7 flex-1 overflow-hidden rounded-md bg-surface-page">
          <div
            className="anim-sweep h-full"
            style={{ width: `${pct01(attack.best_baseline_mcc)}%`, background: SERIES[1] }}
          />
        </div>
        <span className="w-16 shrink-0 text-right font-mono text-xl font-bold text-ink-secondary">
          {attack.best_baseline_mcc != null ? attack.best_baseline_mcc.toFixed(3) : "n/a"}
        </span>
      </div>
      <div className="flex items-start gap-2 border-t border-surface-hairline pt-3">
        <span className="text-body text-ink-secondary">
          {attack.baseline_wins ? (
            <span className="font-medium text-status-missed">
              ⚠ {attack.best_baseline_code} outperforms SENTINEL here — shown as measured.
            </span>
          ) : (
            <span className="font-medium text-status-good">SENTINEL leads on this variant.</span>
          )}
          {full?.TTD != null && ` Mean time to detect: ${full.TTD.toFixed(2)}s.`}
        </span>
      </div>
      <p className="font-mono text-badge text-ink-muted">MCC, results_e5_final/e5_final_table.json</p>
    </div>
  );
}
