import { useState } from "react";
import NetworkReplayScreen from "./screens/NetworkReplayScreen";
import DefenceInspectorScreen from "./screens/DefenceInspectorScreen";
import LedgerScreen from "./screens/LedgerScreen";

type Tab = "replay" | "inspector" | "ledger";

const TABS: { id: Tab; label: string }[] = [
  { id: "replay", label: "Network Replay" },
  { id: "inspector", label: "Defence Stack Inspector" },
  { id: "ledger", label: "Blockchain Ledger" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("replay");

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
          {tab === "replay"
            ? "replaying recorded simulation"
            : tab === "inspector"
            ? "single captured run"
            : "point-in-time snapshot"}
        </span>
      </header>

      <div className="flex-1 overflow-hidden">
        {tab === "replay" && <NetworkReplayScreen />}
        {tab === "inspector" && <DefenceInspectorScreen />}
        {tab === "ledger" && <LedgerScreen />}
      </div>
    </div>
  );
}
