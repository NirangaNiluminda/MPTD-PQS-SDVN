import { useEffect, useMemo, useRef, useState } from "react";
import { api, AttackEvidenceDto, AttackInfoDto } from "../api";
import { useTokens } from "../design/tokens";
import Accordion from "../components/Accordion";

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

function verdictColorKey(v: Verdict): "good" | "caught" | "missed" {
  if (v === "sentinel") return "good";
  if (v === "close") return "caught";
  return "missed";
}

function pct01(mcc: number | null | undefined): number {
  // MCC ranges [-1,1]; clamp to [0,1] for a bar width — the raw signed value
  // is always shown alongside as text, so nothing is hidden by the clamp.
  if (mcc == null) return 0;
  return Math.max(0, Math.min(1, mcc)) * 100;
}

function EvidenceBody({ evidence }: { evidence: AttackEvidenceDto | null | undefined }) {
  if (evidence === undefined) {
    return <p className="text-[11px] text-ink-muted">Loading…</p>;
  }
  if (!evidence || evidence.n_events === 0) {
    return (
      <p className="text-[11px] leading-relaxed text-ink-secondary">
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
    <div className="flex flex-col gap-2.5 text-[11px] text-ink-secondary">
      <p>
        {evidence.n_events.toLocaleString()} poisoned events with this ground
        truth in the capture, {evidence.n_caught?.toLocaleString()} caught
        ({((evidence.detection_rate ?? 0) * 100).toFixed(1)}%),{" "}
        {evidence.n_missed?.toLocaleString()} missed.
      </p>
      <div className="grid grid-cols-3 gap-2 text-center">
        <div className="rounded bg-surface-raised p-1.5">
          <div className="text-[9px] uppercase tracking-wide text-ink-muted">mean ψ̂</div>
          <div className="font-mono text-xs text-ink-primary">{evidence.mean_psi_fuse?.toFixed(3)}</div>
        </div>
        <div className="rounded bg-surface-raised p-1.5">
          <div className="text-[9px] uppercase tracking-wide text-ink-muted">mean Ŝ</div>
          <div className="font-mono text-xs text-ink-primary">{evidence.mean_gat_score?.toFixed(3)}</div>
        </div>
        <div className="rounded bg-surface-raised p-1.5">
          <div className="text-[9px] uppercase tracking-wide text-ink-muted">mean ε̂</div>
          <div className="font-mono text-xs text-ink-primary">{evidence.mean_ae_norm?.toFixed(3)}</div>
        </div>
      </div>
      {evidence.top_signatures && evidence.top_signatures.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] uppercase tracking-wider text-ink-muted">
            Most-tripped rule signatures
          </p>
          <ul className="space-y-1">
            {evidence.top_signatures.map((s) => (
              <li key={s.code} className="flex items-baseline justify-between gap-2">
                <span>
                  {s.name} <span className="text-ink-muted">— {s.detail}</span>
                </span>
                <span className="shrink-0 font-mono text-ink-primary">
                  {(s.pct * 100).toFixed(0)}%
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function CaveatsBody({ attack, evidence }: { attack: AttackInfoDto; evidence: AttackEvidenceDto | null | undefined }) {
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
  if (rows.length === 0) {
    return <p className="text-[11px] text-ink-muted">No caveats flagged for this variant.</p>;
  }
  return (
    <ul className="flex flex-col gap-2">
      {rows.map((r, i) => (
        <li key={i} className="flex items-start gap-2 text-[11px] leading-relaxed text-ink-secondary">
          <span className="mt-0.5 shrink-0 text-ink-muted">{r.glyph}</span>
          <span>{r.text}</span>
        </li>
      ))}
    </ul>
  );
}

export default function AttackExplainerScreen({
  onShowScenario,
}: {
  onShowScenario: (scenarioId: string) => void;
}) {
  const { STATUS } = useTokens();
  const [attacks, setAttacks] = useState<AttackInfoDto[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const [evidenceByAttack, setEvidenceByAttack] = useState<Record<number, AttackEvidenceDto | null>>({});
  const [evidenceOpen, setEvidenceOpen] = useState(true);
  const [caveatsOpen, setCaveatsOpen] = useState(false);
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
    setEvidenceOpen(true);
    setCaveatsOpen(false);
    if (attacks) loadEvidence(attacks[index].attack_number);
  };

  const close = () => setOpenIndex(null);

  const step = (delta: number) => {
    if (!attacks || openIndex == null) return;
    const next = (openIndex + delta + attacks.length) % attacks.length;
    setOpenIndex(next);
    setEvidenceOpen(true);
    setCaveatsOpen(false);
    loadEvidence(attacks[next].attack_number);
  };

  const winCount = attacks?.filter((a) => a.baseline_wins).length ?? 0;

  return (
    <div className="h-full overflow-y-auto p-5">
      <div className="mx-auto max-w-6xl">
        <header className="mb-5 flex flex-wrap items-end justify-between gap-5">
          <div className="max-w-2xl">
            <h1 className="text-lg font-semibold text-ink-primary">
              Seven ways to poison this network
            </h1>
            <p className="mt-1 text-xs leading-relaxed text-ink-secondary">
              Each tile is one attack. Colour and shape say how it ended;
              nothing else is shown yet. Open one for the evidence, the
              caveats, and what produced the number. Every figure comes
              straight from{" "}
              <code className="text-ink-primary">results_e5_final/e5_final_table.json</code>
              {attacks && winCount > 0 && (
                <> — on {winCount} of 7 variants a baseline actually scores higher.</>
              )}
            </p>
          </div>
          {tallies && (
            <div className="flex gap-5">
              {(["sentinel", "close", "baseline"] as Verdict[]).map((v) => (
                <div key={v} className="flex flex-col gap-0.5">
                  <span
                    className="font-mono text-2xl font-semibold leading-none"
                    style={{
                      color:
                        verdictColorKey(v) === "good"
                          ? STATUS.good
                          : verdictColorKey(v) === "caught"
                          ? STATUS.caught
                          : STATUS.missed,
                    }}
                  >
                    {tallies[v]}
                  </span>
                  <span className="text-[9px] font-bold uppercase tracking-widest text-ink-muted">
                    {VERDICT_LABEL[v]}
                  </span>
                </div>
              ))}
            </div>
          )}
        </header>

        {error && (
          <div className="rounded border border-status-missed/40 bg-status-missed/10 p-4 text-xs text-status-missed">
            {error}
          </div>
        )}

        {!attacks && !error && <div className="text-xs text-ink-muted">Loading…</div>}

        {attacks && (
          <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {attacks.map((a, i) => {
              const v = verdictOf(a);
              const color =
                verdictColorKey(v) === "good"
                  ? STATUS.good
                  : verdictColorKey(v) === "caught"
                  ? STATUS.caught
                  : STATUS.missed;
              return (
                <button
                  key={a.attack_number}
                  onClick={(e) => open(i, e)}
                  className="flex flex-col gap-3 rounded-lg border border-surface-hairline bg-surface-panel p-3.5 text-left transition-all hover:-translate-y-0.5 hover:border-surface-hairline2 hover:shadow-lg"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xl leading-none" style={{ color: ACTOR_GLYPH[a.actor] ? color : color }}>
                      {ACTOR_GLYPH[a.actor] ?? "●"}
                    </span>
                    <span className="text-[9px] font-bold tracking-wider" style={{ color }}>
                      {VERDICT_LABEL[v]}
                    </span>
                  </div>
                  <div className="mt-auto flex flex-col gap-0.5">
                    <span className="text-sm font-semibold leading-tight text-ink-primary">
                      {a.human_name}
                    </span>
                    <span className="text-[11px] text-ink-muted">
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
                <DrillHeader attack={openAttack} onClose={close} />
                <div className="flex flex-col gap-3.5 p-5">
                  <AccuracyPanel attack={openAttack} />

                  <Accordion
                    open={evidenceOpen}
                    onToggle={() => setEvidenceOpen((v) => !v)}
                    bodyMaxHeight={420}
                    header={
                      <div className="flex flex-1 items-center gap-2">
                        <span className="text-xs font-semibold text-ink-primary">
                          How the system knew
                        </span>
                      </div>
                    }
                  >
                    <div className="border-t border-surface-hairline p-3.5">
                      <EvidenceBody evidence={evidenceByAttack[openAttack.attack_number]} />
                    </div>
                  </Accordion>

                  <Accordion
                    open={caveatsOpen}
                    onToggle={() => setCaveatsOpen((v) => !v)}
                    bodyMaxHeight={420}
                    header={
                      <div className="flex flex-1 items-center gap-2">
                        <span className="text-xs font-semibold text-ink-primary">
                          What this number does not say
                        </span>
                      </div>
                    }
                  >
                    <div className="border-t border-surface-hairline p-3.5">
                      <CaveatsBody
                        attack={openAttack}
                        evidence={evidenceByAttack[openAttack.attack_number]}
                      />
                    </div>
                  </Accordion>

                  <div className="flex flex-wrap gap-2 pt-1">
                    {openAttack.sample_scenario_id && (
                      <button
                        onClick={() => {
                          onShowScenario(openAttack.sample_scenario_id!);
                          close();
                        }}
                        className="flex items-center gap-2 rounded-md border border-entity-rsu bg-entity-rsu px-3.5 py-2 text-xs font-semibold text-white transition-opacity hover:opacity-90"
                      >
                        <span className="font-mono text-[11px]">◉</span>
                        Watch it happen on the map
                      </button>
                    )}
                    <button
                      onClick={() => step(-1)}
                      className="rounded-md border border-surface-hairline2 bg-surface-raised px-3.5 py-2 text-xs text-ink-secondary transition-colors hover:text-ink-primary"
                    >
                      ← previous
                    </button>
                    <button
                      onClick={() => step(1)}
                      className="rounded-md border border-surface-hairline2 bg-surface-raised px-3.5 py-2 text-xs text-ink-secondary transition-colors hover:text-ink-primary"
                    >
                      next →
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

function DrillHeader({ attack, onClose }: { attack: AttackInfoDto; onClose: () => void }) {
  const { STATUS } = useTokens();
  const v = verdictOf(attack);
  const color =
    verdictColorKey(v) === "good" ? STATUS.good : verdictColorKey(v) === "caught" ? STATUS.caught : STATUS.missed;
  return (
    <div className="sticky top-0 z-10 flex items-start gap-3.5 border-b border-surface-hairline bg-surface-panel p-5">
      <span className="font-mono text-2xl leading-none" style={{ color }}>
        {ACTOR_GLYPH[attack.actor] ?? "●"}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2.5">
          <h2 className="text-base font-semibold text-ink-primary">{attack.human_name}</h2>
          <span
            className="rounded-full border px-2 py-0.5 text-[9px] font-bold tracking-wider"
            style={{ color, borderColor: color }}
          >
            {VERDICT_LABEL[v]}
          </span>
        </div>
        <p className="mt-1.5 text-xs leading-relaxed text-ink-secondary">{attack.description}</p>
      </div>
      <button
        onClick={onClose}
        className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-surface-hairline2 bg-surface-raised text-sm text-ink-secondary hover:text-ink-primary"
      >
        ✕
      </button>
    </div>
  );
}

function AccuracyPanel({ attack }: { attack: AttackInfoDto }) {
  const { SERIES, STATUS } = useTokens();
  const full = attack.sentinel_full;
  return (
    <div className="anim-rise flex flex-col gap-3 rounded-lg border border-surface-hairline bg-surface-raised p-4">
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="text-[11.5px] font-semibold text-ink-primary">
          Accuracy against the published baseline
        </span>
        <span className="ml-auto font-mono text-[10px] text-ink-muted">
          MCC, results_e5_final/e5_final_table.json
        </span>
      </div>
      <div className="flex items-center gap-3">
        <span className="w-16 text-[10.5px] text-ink-muted">SENTINEL</span>
        <div className="h-5 flex-1 overflow-hidden rounded bg-surface-page">
          <div
            className="anim-sweep h-full"
            style={{ width: `${pct01(full?.MCC)}%`, background: SERIES[0] }}
          />
        </div>
        <span className="w-14 shrink-0 text-right font-mono text-sm font-semibold" style={{ color: SERIES[0] }}>
          {full ? full.MCC.toFixed(3) : "n/a"}
        </span>
      </div>
      <div className="flex items-center gap-3">
        <span className="w-16 text-[10.5px] text-ink-muted">baseline</span>
        <div className="h-5 flex-1 overflow-hidden rounded bg-surface-page">
          <div
            className="anim-sweep h-full"
            style={{ width: `${pct01(attack.best_baseline_mcc)}%`, background: SERIES[1] }}
          />
        </div>
        <span className="w-14 shrink-0 text-right font-mono text-sm font-semibold text-ink-secondary">
          {attack.best_baseline_mcc != null ? attack.best_baseline_mcc.toFixed(3) : "n/a"}
        </span>
      </div>
      <div className="flex items-start gap-2 border-t border-surface-hairline pt-2.5 text-xs">
        <span className="text-ink-muted">
          {attack.baseline_wins ? (
            <span className="text-status-missed">
              ⚠ {attack.best_baseline_code} outperforms SENTINEL here — shown as measured.
            </span>
          ) : (
            <span className="text-status-good">SENTINEL leads on this variant.</span>
          )}
          {full?.MCC_std != null && ` MCC std across seeds: ±${full.MCC_std.toFixed(3)}.`}
          {full?.TTD != null && ` Mean time to detect: ${full.TTD.toFixed(2)}s.`}
        </span>
      </div>
      {(full?.CDER != null || full?.PBPO_ms != null) && (
        <div className="grid grid-cols-2 gap-2 border-t border-surface-hairline pt-2.5 text-center">
          {full?.CDER != null && (
            <div>
              <div className="text-[9px] uppercase tracking-wide text-ink-muted">CDER</div>
              <div className="font-mono text-xs text-ink-primary">{full.CDER.toFixed(3)}</div>
            </div>
          )}
          {full?.PBPO_ms != null && (
            <div>
              <div className="text-[9px] uppercase tracking-wide text-ink-muted">per-beacon overhead</div>
              <div className="font-mono text-xs text-ink-primary">{full.PBPO_ms.toFixed(2)} ms</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
