import { useEffect, useState } from "react";
import { api, AttackInfoDto } from "../api";

const ACTOR_LABEL: Record<string, string> = {
  compromised_rsu: "Hijacked roadside unit",
  malicious_vehicle: "Lying vehicle",
  malicious_controller: "Hijacked controller",
  mitm_relay: "Intercepting relay vehicle",
};

const ACTOR_COLOR: Record<string, string> = {
  compromised_rsu: "text-entity-rsu",
  malicious_vehicle: "text-status-missed",
  malicious_controller: "text-entity-controller",
  mitm_relay: "text-entity-ghost",
};

function AttackCard({
  attack,
  onShowMe,
}: {
  attack: AttackInfoDto;
  onShowMe: (scenarioId: string) => void;
}) {
  const full = attack.sentinel_full;
  return (
    <div className="flex flex-col rounded-lg border border-surface-hairline bg-surface-panel">
      <header className="border-b border-surface-hairline p-4">
        <div className="flex items-center justify-between">
          <span className="font-mono text-sm font-semibold text-ink-primary">
            {attack.code}
          </span>
          <span className={`text-[11px] font-medium ${ACTOR_COLOR[attack.actor] ?? "text-ink-secondary"}`}>
            {ACTOR_LABEL[attack.actor] ?? attack.actor}
          </span>
        </div>
        <h3 className="mt-1 text-sm text-ink-primary">{attack.human_name}</h3>
      </header>

      <div className="flex-1 p-4">
        <p className="text-xs leading-relaxed text-ink-secondary">
          {attack.description}
        </p>

        <div className="mt-4 space-y-2">
          <div className="flex items-baseline justify-between">
            <span className="text-[11px] text-ink-muted">SENTINEL (full stack)</span>
            <span className="font-mono text-sm font-semibold text-ink-primary">
              MCC {full ? full.MCC.toFixed(3) : "n/a"}
            </span>
          </div>
          {full?.TTD != null && (
            <div className="flex items-baseline justify-between text-[11px]">
              <span className="text-ink-muted">Time to detect</span>
              <span className="font-mono text-ink-secondary">{full.TTD.toFixed(2)}s</span>
            </div>
          )}

          {attack.best_baseline_code && attack.best_baseline_mcc != null && (
            <div
              className={`mt-2 rounded px-2.5 py-2 text-[11px] ${
                attack.baseline_wins
                  ? "border border-status-missed/40 bg-status-missed/10"
                  : "bg-surface-raised"
              }`}
            >
              <div className="flex items-baseline justify-between">
                <span className="text-ink-muted">
                  Best baseline ({attack.best_baseline_code})
                </span>
                <span
                  className={`font-mono ${
                    attack.baseline_wins ? "font-semibold text-status-missed" : "text-ink-secondary"
                  }`}
                >
                  MCC {attack.best_baseline_mcc.toFixed(3)}
                </span>
              </div>
              {attack.baseline_wins && (
                <p className="mt-1 text-status-missed">
                  ⚠ The baseline outperforms SENTINEL on this attack. Shown as
                  measured — not hidden.
                </p>
              )}
            </div>
          )}
        </div>
      </div>

      <footer className="border-t border-surface-hairline p-3">
        <button
          disabled={!attack.sample_scenario_id}
          onClick={() => attack.sample_scenario_id && onShowMe(attack.sample_scenario_id)}
          className="w-full rounded bg-entity-rsu py-1.5 text-xs font-medium text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-30"
        >
          Show me this attack →
        </button>
      </footer>
    </div>
  );
}

export default function AttackExplainerScreen({
  onShowScenario,
}: {
  onShowScenario: (scenarioId: string) => void;
}) {
  const [attacks, setAttacks] = useState<AttackInfoDto[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .attacks()
      .then(setAttacks)
      .catch((e) => setError(String(e)));
  }, []);

  const winCount = attacks?.filter((a) => a.baseline_wins).length ?? 0;

  return (
    <div className="h-full overflow-y-auto p-5">
      <div className="mx-auto max-w-6xl">
        <header className="mb-5">
          <h1 className="text-lg font-semibold text-ink-primary">
            The seven attack variants
          </h1>
          <p className="mt-1 max-w-3xl text-xs text-ink-secondary">
            Every reported number comes straight from{" "}
            <code className="text-ink-primary">results_e5_final/e5_final_table.json</code> —
            SENTINEL's own full-stack fusion score against the strongest of
            three baselines (B1/B2/B3), per attack.
            {attacks && winCount > 0 && (
              <>
                {" "}
                On {winCount} of 7 variants a baseline actually scores
                higher — flagged below rather than omitted.
              </>
            )}
          </p>
        </header>

        {error && (
          <div className="rounded border border-status-missed/40 bg-status-missed/10 p-4 text-xs text-status-missed">
            {error}
          </div>
        )}

        {!attacks && !error && (
          <div className="text-xs text-ink-muted">Loading…</div>
        )}

        {attacks && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {attacks.map((a) => (
              <AttackCard key={a.attack_number} attack={a} onShowMe={onShowScenario} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
