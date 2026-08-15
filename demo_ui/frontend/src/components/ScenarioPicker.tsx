import { useMemo } from "react";
import { usePlayback } from "../store/playback";

const ROADS = ["urban", "rural", "highway"] as const;

/** "TP-S1:MaliciousRSU-TrajectoryPoisoning" -> readable pieces. */
function splitName(attackName: string) {
  const [code, rest = ""] = attackName.split(":");
  return { code, human: rest.replace(/-/g, " ") };
}

export default function ScenarioPicker() {
  const { scenarios, scenarioId, selectScenario, detail, topology, loading } =
    usePlayback();

  const byRoad = useMemo(() => {
    const m: Record<string, typeof scenarios> = {};
    for (const s of scenarios) (m[s.road] ??= []).push(s);
    for (const r of Object.keys(m))
      m[r].sort((a, b) =>
        a.attack_number !== b.attack_number
          ? a.attack_number - b.attack_number
          : a.attack_pct - b.attack_pct
      );
    return m;
  }, [scenarios]);

  const named = detail ? splitName(detail.attack_name) : null;

  return (
    <div className="flex flex-wrap items-center gap-4 border-b border-surface-hairline bg-surface-page px-4 py-2.5">
      <select
        className="rounded-md border border-surface-hairline bg-surface-raised px-3 py-1.5 text-sm text-ink-primary outline-none focus:border-entity-rsu"
        value={scenarioId ?? ""}
        onChange={(e) => selectScenario(e.target.value)}
      >
        <option value="" disabled>
          {scenarios.length ? "Choose an attack scenario…" : "Loading…"}
        </option>
        {ROADS.filter((r) => byRoad[r]?.length).map((road) => (
          <optgroup key={road} label={road.toUpperCase()}>
            {byRoad[road].map((s) => {
              const n = splitName(s.attack_name);
              return (
                <option key={s.id} value={s.id}>
                  {n.code} — {n.human} · {s.attack_pct}% hostile
                </option>
              );
            })}
          </optgroup>
        ))}
      </select>

      {loading && <span className="text-xs text-ink-muted">Loading scenario…</span>}

      {named && !loading && (
        <div className="flex items-center gap-3">
          <div>
            <div className="text-sm font-medium text-ink-primary">{named.human}</div>
            <div className="text-[11px] text-ink-muted">
              {named.code} · {detail!.road} · {detail!.attack_pct}% of nodes hostile
            </div>
          </div>
          {topology && (
            <div className="flex gap-1.5">
              {topology.compromised_rsus.length > 0 && (
                <span className="rounded bg-status-missed/15 px-2 py-1 text-[10px] text-status-missed">
                  {topology.compromised_rsus.length} hijacked RSU
                  {topology.compromised_rsus.length > 1 ? "s" : ""}
                </span>
              )}
              {topology.hostile_controllers.length > 0 && (
                <span className="rounded bg-status-missed/15 px-2 py-1 text-[10px] text-status-missed">
                  {topology.hostile_controllers.length} hijacked controller
                  {topology.hostile_controllers.length > 1 ? "s" : ""}
                </span>
              )}
              {topology.malicious_vehicles.length > 0 && (
                <span className="rounded bg-status-missed/15 px-2 py-1 text-[10px] text-status-missed">
                  {topology.malicious_vehicles.length} lying vehicles
                </span>
              )}
              {topology.mitm_relays.length > 0 && (
                <span className="rounded bg-status-missed/15 px-2 py-1 text-[10px] text-status-missed">
                  {topology.mitm_relays.length} intercepting relays
                </span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
