import { useEffect, useState } from "react";
import { usePlayback } from "./store/playback";
import NetworkReplayScreen from "./screens/NetworkReplayScreen";
import DefenceInspectorScreen from "./screens/DefenceInspectorScreen";
import LedgerScreen from "./screens/LedgerScreen";
import AttackExplainerScreen from "./screens/AttackExplainerScreen";
import ResultsScreen from "./screens/ResultsScreen";
import RunConsoleScreen from "./screens/RunConsoleScreen";
import ProvenanceChip from "./components/ProvenanceChip";
import { ProvenanceKind } from "./design/tokens";

type Tab = "attacks" | "replay" | "inspector" | "ledger" | "results" | "console";

interface ScreenMeta {
  title: string;
  blurb: string;
  provenance: ProvenanceKind;
}

// Grouped by what a viewer is trying to DO, not by implementation — matches
// how someone actually approaches this system: learn what the attacks are,
// then watch the defence work, then check the evidence behind it.
const NAV_GROUPS: { title: string; tabs: Tab[] }[] = [
  { title: "Understand", tabs: ["attacks"] },
  { title: "Observe", tabs: ["replay", "inspector", "ledger"] },
  { title: "Evaluate", tabs: ["results", "console"] },
];

const TAB_LABEL: Record<Tab, string> = {
  attacks: "Attack Explainer",
  replay: "Network Replay",
  inspector: "Defence Stack Inspector",
  ledger: "Blockchain Ledger",
  results: "Results & Ablation",
  console: "Run Console",
};

const SCREEN_META: Record<Tab, ScreenMeta> = {
  attacks: {
    title: "Attack Explainer",
    blurb:
      "The seven ways an attacker can poison this network, what each does, and how well the defence handles it against a baseline — including where the baseline wins.",
    provenance: "snapshot",
  },
  replay: {
    title: "Network Replay",
    blurb:
      "Every vehicle, roadside unit, and controller in the road network, replayed from a recorded simulation. Lines connect a claimed position to the real one for anything caught lying.",
    provenance: "replayed",
  },
  inspector: {
    title: "Defence Stack Inspector",
    blurb:
      "Pick a vehicle and see the three independent signals — rule signatures, a graph attention network, an LSTM autoencoder — that combine into one fused decision.",
    provenance: "replayed",
  },
  ledger: {
    title: "Blockchain Ledger",
    blurb:
      "Trust decay, revocation votes, and controller reassignments recorded on-chain, plus the measured cost of the post-quantum cryptography behind them.",
    provenance: "snapshot",
  },
  results: {
    title: "Results & Ablation",
    blurb:
      "What happens to accuracy when parts of the defence are switched off — every figure states the window it was measured over and the caveat that goes with it.",
    provenance: "snapshot",
  },
  console: {
    title: "Run Console",
    blurb:
      "Launch a real simulation on this machine — not a replay. Runs take minutes to hours; safe-default flags are applied automatically.",
    provenance: "live",
  },
};

export default function App() {
  const [tab, setTab] = useState<Tab>("attacks");
  const loadScenarios = usePlayback((s) => s.loadScenarios);
  const selectScenario = usePlayback((s) => s.selectScenario);

  // Loaded once here, not inside NetworkReplayScreen — that screen only
  // mounts when its tab is active, but "Show me this attack" (below) needs
  // the scenario list available before the replay screen has ever mounted.
  useEffect(() => {
    loadScenarios();
  }, [loadScenarios]);

  // Attack Explainer's "Show me this attack" jumps into the replay screen
  // with that scenario already loaded — the store is global so this just
  // needs to flip the tab and kick off the same selection the picker uses.
  const showScenario = (scenarioId: string) => {
    setTab("replay");
    void selectScenario(scenarioId);
  };

  const meta = SCREEN_META[tab];

  return (
    <div className="grid h-screen grid-rows-[auto_1fr] bg-surface-page">
      <header className="flex items-center gap-3 border-b border-surface-hairline bg-surface-page px-4 py-2.5">
        <h1 className="text-sm font-semibold tracking-wide text-ink-primary">
          SENTINEL
        </h1>
        <span className="hidden text-xs text-ink-muted lg:inline">
          Trajectory-poisoning defence for software-defined vehicle networks
        </span>
      </header>

      <div className="grid min-h-0 grid-cols-[188px_1fr]">
        <nav className="flex flex-col gap-4 overflow-y-auto border-r border-surface-hairline bg-surface-panel px-2.5 py-3">
          {NAV_GROUPS.map((group) => (
            <div key={group.title} className="flex flex-col gap-0.5">
              <div className="px-2 pb-1 text-[9px] font-bold uppercase tracking-widest text-ink-muted">
                {group.title}
              </div>
              {group.tabs.map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`rounded px-2.5 py-1.5 text-left text-xs font-medium transition-colors ${
                    tab === t
                      ? "border border-surface-hairline2 bg-surface-raised text-ink-primary"
                      : "border border-transparent text-ink-secondary hover:bg-surface-raised hover:text-ink-primary"
                  }`}
                >
                  {TAB_LABEL[t]}
                </button>
              ))}
            </div>
          ))}

          <div className="mt-auto flex flex-col gap-1.5 border-t border-surface-hairline pt-3">
            <div className="px-2 text-[9px] font-bold uppercase tracking-widest text-ink-muted">
              Data state key
            </div>
            <div className="flex flex-col gap-1 px-2">
              <ProvenanceChip kind="live" compact />
              <ProvenanceChip kind="replayed" compact />
              <ProvenanceChip kind="snapshot" compact />
            </div>
          </div>
        </nav>

        <main className="grid min-h-0 min-w-0 grid-rows-[auto_1fr]">
          <div className="flex items-start justify-between gap-4 border-b border-surface-hairline bg-surface-panel px-4 py-2.5">
            <div className="min-w-0">
              <h2 className="text-base font-semibold text-ink-primary">{meta.title}</h2>
              <p className="mt-0.5 max-w-[70ch] text-[11px] leading-relaxed text-ink-secondary">
                {meta.blurb}
              </p>
            </div>
            <div className="shrink-0 pt-0.5">
              <ProvenanceChip kind={meta.provenance} />
            </div>
          </div>

          <div className="min-h-0 overflow-hidden">
            {tab === "attacks" && <AttackExplainerScreen onShowScenario={showScenario} />}
            {tab === "replay" && <NetworkReplayScreen />}
            {tab === "inspector" && <DefenceInspectorScreen />}
            {tab === "ledger" && <LedgerScreen />}
            {tab === "results" && <ResultsScreen />}
            {tab === "console" && <RunConsoleScreen />}
          </div>
        </main>
      </div>
    </div>
  );
}
