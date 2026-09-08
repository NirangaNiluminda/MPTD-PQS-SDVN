import { useEffect, useState } from "react";
import { Radar } from "lucide-react";
import { api, AttackInfoDto } from "../api";
import { useSemanticTokens } from "../design/tokens";
import SdvnConceptAnimation from "../components/SdvnConceptAnimation";
import { ACTOR_GLYPH, ACTOR_LABEL } from "./AttackExplainerScreen";

const PROP_LEGEND: { prop: string; represents: string }[] = [
  { prop: "Toy car", represents: "vehicle" },
  { prop: "Envelope handed car → tower", represents: "beacon message" },
  { prop: "Rigifoam pole", represents: "RSU" },
  { prop: "Bristle-board layout", represents: "street network" },
  { prop: "Red ribbon on one prop", represents: "\"this one is compromised\"" },
];

const STAGE_HINT: Record<string, string> = {
  compromised_rsu:
    "Mark the toy RSU tower. Have a toy car hand it an honest envelope; the tower re-writes the position before relaying it onward.",
  malicious_vehicle:
    "Mark one toy car. It writes a false-but-plausible position on its own envelope before handing it to the RSU.",
  malicious_controller:
    "No car or RSU needs marking — say so explicitly. The compromise happens off-stage, at a controller board you can represent as a small box behind the RSU tower, away from the toy cars entirely.",
  mitm_relay:
    "Place a toy car between two others as a relay. It quietly re-writes the speed value on an envelope as it passes through.",
};

export default function PhysicalTestbedScreen({
  onShowScenario,
}: {
  onShowScenario: (scenarioId: string) => void;
}) {
  const semantic = useSemanticTokens();
  const [attacks, setAttacks] = useState<AttackInfoDto[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .attacks()
      .then(setAttacks)
      .catch((e) => setError(String(e)));
  }, []);

  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mx-auto max-w-5xl space-y-6">
        <header>
          <h1 className="text-section-title text-ink-primary">
            Physical testbed — from toy cars to this screen
          </h1>
          <p className="mt-1.5 max-w-[75ch] text-body leading-relaxed text-ink-secondary">
            A guide for building and staging the toy prototype (cars, envelope "beacons," rigifoam/bristle-board
            infrastructure), and for tying each staged attack straight into the real, measured software next to
            it. Nothing on this page is simulator output — the legend and staging notes are guidance; the
            "Watch this attack live" buttons below jump into the same real recordings the rest of this app
            uses.
          </p>
        </header>

        <section>
          <p className="mb-2.5 text-badge font-semibold uppercase tracking-wider text-ink-muted">
            How the communication works
          </p>
          <SdvnConceptAnimation />
          <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1">
            {PROP_LEGEND.map((p) => (
              <span key={p.prop} className="text-[10px] text-ink-muted">
                <span className="font-medium text-ink-secondary">{p.prop}</span> = {p.represents}
              </span>
            ))}
          </div>
        </section>

        <section>
          <p className="mb-1 text-badge font-semibold uppercase tracking-wider text-ink-muted">
            Staged scenes — one per real attack type
          </p>
          <p className="mb-2.5 text-[11px] text-ink-muted">
            Stage the physical scene, explain it, then click through to watch the exact same attack replay live
            on the real map.
          </p>

          {error && (
            <div className="rounded border border-status-missed/40 bg-status-missed/10 p-4 text-body text-status-missed">
              {error}
            </div>
          )}
          {!attacks && !error && <div className="text-body text-ink-secondary">Loading…</div>}

          {attacks && (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {attacks.map((a) => (
                <div key={a.attack_number} className="flex flex-col gap-2.5 rounded-lg border border-surface-hairline bg-surface-panel p-4">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-lg leading-none" style={{ color: semantic.informational }}>
                      {ACTOR_GLYPH[a.actor] ?? "●"}
                    </span>
                    <div className="min-w-0">
                      <div className="text-body font-semibold leading-tight text-ink-primary">{a.human_name}</div>
                      <div className="text-badge text-ink-secondary">{ACTOR_LABEL[a.actor] ?? a.actor}</div>
                    </div>
                  </div>
                  <p className="text-[11px] leading-relaxed text-ink-secondary">{a.description}</p>
                  {STAGE_HINT[a.actor] && (
                    <p className="rounded-md bg-surface-page p-2.5 text-[11px] leading-relaxed text-ink-muted">
                      <span className="font-semibold text-ink-secondary">Stage it: </span>
                      {STAGE_HINT[a.actor]}
                    </p>
                  )}
                  {a.sample_scenario_id && (
                    <button
                      onClick={() => onShowScenario(a.sample_scenario_id!)}
                      className="mt-auto flex items-center justify-center gap-1.5 self-start rounded-md border border-entity-rsu bg-entity-rsu px-3 py-1.5 text-badge font-semibold text-white transition-all hover:opacity-90 active:scale-[0.97]"
                    >
                      <Radar size={13} aria-hidden />
                      Watch this attack live
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
          <p className="mb-2 text-badge font-semibold uppercase tracking-wider text-ink-muted">
            Suggested run order
          </p>
          <ol className="flex flex-col gap-1.5 text-body leading-relaxed text-ink-secondary">
            <li>1. Walk through the prop legend above so evaluators know what they're looking at.</li>
            <li>2. Stage one honest pass — every car hands over an unmodified envelope — to establish the baseline.</li>
            <li>3. Mark a car or tower and stage one attack scene, using the hint on that attack's card.</li>
            <li>4. Switch to this laptop and click "Watch this attack live" for the same attack — the real detection happens on screen in seconds.</li>
            <li>5. Repeat step 3–4 for one or two more attack types if time allows; no need to stage all seven.</li>
          </ol>
        </section>
      </div>
    </div>
  );
}
