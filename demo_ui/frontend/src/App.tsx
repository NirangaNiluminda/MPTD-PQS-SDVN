import { useEffect, useState } from "react";
import { usePlayback } from "./store/playback";
import { useMode, CopyMode } from "./store/mode";
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
  blurb: Record<CopyMode, string>;
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
    blurb: {
      plain:
        "Seven ways someone can try to fool this network, and whether our defence actually catches each one — compared with a simpler existing method. Every result is shown, even the ones where the simpler method wins.",
      expert:
        "Threat taxonomy across 7 attack variants with hostile-entity assignment and measured MCC against the strongest of three baselines (B1/B2/B3), from results_e5_final/e5_final_table.json — including variants where a baseline outperforms SENTINEL_Full.",
    },
    provenance: "snapshot",
  },
  replay: {
    title: "Network Replay",
    blurb: {
      plain:
        "A recorded drive-through of the road network. Every dot is a car, every square a roadside sensor, every diamond a network controller. When a car lies about its position, a line shows the gap between its claim and the truth.",
      expert:
        "Entity-level replay of a completed simulation over the real Shinjuku street graph. Claim-vs-ground-truth vectors, RSU coverage discs (R_max_comm = 270 m), and derived controller-cluster assignment, filtered by class and detection outcome.",
    },
    provenance: "replayed",
  },
  inspector: {
    title: "Defence Stack Inspector",
    blurb: {
      plain:
        "Click any car to see exactly why it was trusted or not. Three separate checks — hard rules, a pattern-matching AI, and a memory-based AI — each form their own opinion, and those combine into one final decision.",
      expert:
        "Per-vehicle decomposition of the fused decision Φ (Eq 3.46) into its three normalised inputs — rule signatures (ψ̂), GAT spatial score (Ŝ), LSTM-AE reconstruction (ε̂) — against the 0.5 threshold, from one blockchain-enabled capture run's [FUSION-RSU*] output.",
    },
    provenance: "replayed",
  },
  ledger: {
    title: "Blockchain Ledger",
    blurb: {
      plain:
        "A permanent, tamper-proof record. Cars and roadside sensors that keep misbehaving lose trust over time and eventually get removed from the network; a compromised controller can be voted out by the honest ones.",
      expert:
        "Point-in-time snapshot of the Hyperledger Fabric ledger: RSU/vehicle/controller trust-score decay, the append-only revocation and CP-DETECT flag log, and measured PQ-crypto cost (TRS/FHE/DKG latency, bandwidth overhead).",
    },
    provenance: "snapshot",
  },
  results: {
    title: "Results & Ablation",
    blurb: {
      plain:
        "What happens to accuracy if pieces of the defence are removed, one at a time. Every number here states exactly how it was measured and what its limits are — not just the figure that looks best.",
      expert:
        "D1/D4/D6 ablation (rules-only / +GAT / +GAT+LSTM-AE) at both a 90 s and 300 s window, the E1 penetration-intensity and E2 speed-regime sweeps, and the E5 baseline comparison — every figure states its window and caveat inline.",
    },
    provenance: "snapshot",
  },
  console: {
    title: "Run Console",
    blurb: {
      plain:
        "Start a brand-new simulation for real, right now, on this machine — not a recording. It can take a few minutes to a few hours, and you can watch it happen live.",
      expert:
        "Launches the compiled simulator directly with every documented safe-default flag pre-applied (routing_test=false, ablation_mode=0, gat_det_flag_heads=0, the routing_algorithm/skip_blockchain pairing). Verifies the deployed model before every launch.",
    },
    provenance: "live",
  },
};

export default function App() {
  const [tab, setTab] = useState<Tab>("attacks");
  const loadScenarios = usePlayback((s) => s.loadScenarios);
  const selectScenario = usePlayback((s) => s.selectScenario);
  const mode = useMode((s) => s.mode);
  const setMode = useMode((s) => s.setMode);

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

        <div className="ml-auto flex items-center gap-0.5 rounded-md border border-surface-hairline2 bg-surface-raised p-0.5">
          <button
            onClick={() => setMode("plain")}
            className={`rounded px-2.5 py-1 text-[11px] font-medium transition-colors ${
              mode === "plain" ? "bg-entity-rsu text-white" : "text-ink-secondary hover:text-ink-primary"
            }`}
          >
            Plain English
          </button>
          <button
            onClick={() => setMode("expert")}
            className={`rounded px-2.5 py-1 text-[11px] font-medium transition-colors ${
              mode === "expert" ? "bg-entity-rsu text-white" : "text-ink-secondary hover:text-ink-primary"
            }`}
          >
            Expert
          </button>
        </div>
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
                {meta.blurb[mode]}
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
