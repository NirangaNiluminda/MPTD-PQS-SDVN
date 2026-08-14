import { useMemo } from "react";
import { usePlayback } from "../store/playback";

const ROADS = ["urban", "rural", "highway"] as const;

export default function ScenarioPicker() {
  const { scenarios, scenarioId, selectScenario } = usePlayback();

  // Group by road, then list attack/pct combos actually present in the
  // corpus — do not assume full coverage (highway has fewer than urban/rural).
  const byRoad = useMemo(() => {
    const m: Record<string, typeof scenarios> = {};
    for (const s of scenarios) {
      (m[s.road] ??= []).push(s);
    }
    for (const road of Object.keys(m)) {
      m[road].sort((a, b) =>
        a.attack_number !== b.attack_number
          ? a.attack_number - b.attack_number
          : a.attack_pct - b.attack_pct
      );
    }
    return m;
  }, [scenarios]);

  const current = scenarios.find((s) => s.id === scenarioId);

  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-slate-800 bg-slate-900 px-4 py-2 text-sm">
      <span className="text-slate-400">Scenario</span>
      <select
        className="rounded bg-slate-800 px-2 py-1 text-slate-100"
        value={scenarioId ?? ""}
        onChange={(e) => selectScenario(e.target.value)}
      >
        <option value="" disabled>
          {scenarios.length ? "Choose a scenario…" : "Loading…"}
        </option>
        {ROADS.filter((r) => byRoad[r]?.length).map((road) => (
          <optgroup key={road} label={road}>
            {byRoad[road].map((s) => (
              <option key={s.id} value={s.id}>
                {s.attack_name} · {s.attack_pct}% malicious
              </option>
            ))}
          </optgroup>
        ))}
      </select>
      {current && (
        <span className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-400">
          {current.id}
        </span>
      )}
    </div>
  );
}
