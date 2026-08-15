import { useEffect, useState } from "react";
import { usePlayback } from "./store/playback";
import NetworkReplayScreen from "./screens/NetworkReplayScreen";
import DefenceInspectorScreen from "./screens/DefenceInspectorScreen";
import LedgerScreen from "./screens/LedgerScreen";
import AttackExplainerScreen from "./screens/AttackExplainerScreen";
import ResultsScreen from "./screens/ResultsScreen";

type Tab = "attacks" | "replay" | "inspector" | "ledger" | "results";

const TABS: { id: Tab; label: string }[] = [
  { id: "attacks", label: "Attack Explainer" },
  { id: "replay", label: "Network Replay" },
  { id: "inspector", label: "Defence Stack Inspector" },
  { id: "ledger", label: "Blockchain Ledger" },
  { id: "results", label: "Results & Ablation" },
];

const SUBTITLE: Record<Tab, string> = {
  attacks: "reference guide",
  replay: "replaying recorded simulation",
  inspector: "single captured run",
  ledger: "point-in-time snapshot",
  results: "reported figures",
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

  return (
    <div className="flex h-screen flex-col bg-surface-page">
      <header className="flex items-center gap-3 border-b border-surface-hairline bg-surface-page px-4 py-2.5">
        <h1 className="text-sm font-semibold tracking-wide text-ink-primary">
          SENTINEL
        </h1>
        <span className="text-xs text-ink-muted">
          Trajectory-poisoning defence for software-defined vehicle networks
        </span>

        <nav className="ml-6 flex gap-1">
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`rounded px-3 py-1.5 text-xs font-medium transition-colors ${
                tab === t.id
                  ? "bg-entity-rsu text-white"
                  : "text-ink-secondary hover:bg-surface-raised hover:text-ink-primary"
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>

        <span className="ml-auto rounded bg-surface-raised px-2 py-1 text-[10px] text-ink-muted">
          {SUBTITLE[tab]}
        </span>
      </header>

      <div className="flex-1 overflow-hidden">
        {tab === "attacks" && <AttackExplainerScreen onShowScenario={showScenario} />}
        {tab === "replay" && <NetworkReplayScreen />}
        {tab === "inspector" && <DefenceInspectorScreen />}
        {tab === "ledger" && <LedgerScreen />}
        {tab === "results" && <ResultsScreen />}
      </div>
    </div>
  );
}
