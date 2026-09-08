import { useEffect, useMemo, useRef, useState } from "react";
import { usePlayback } from "../store/playback";
import { ScenarioSummary } from "../api";

const ROADS = ["urban", "rural", "highway"] as const;
type Road = (typeof ROADS)[number];

const ROAD_LABEL: Record<Road, string> = { urban: "Urban", rural: "Rural", highway: "Highway" };

// Rural and highway maps have known rendering issues — disabled for the demo
// rather than removed, so the corpus counts and the fact that these road
// types exist stay visible instead of silently disappearing.
const ROAD_DISABLED: Record<Road, boolean> = { urban: false, rural: true, highway: true };

/** "TP-S1:MaliciousRSU-TrajectoryPoisoning" -> readable pieces. */
function splitName(attackName: string) {
  const [code, rest = ""] = attackName.split(":");
  return { code, human: rest.replace(/-/g, " ") };
}

export default function ScenarioPicker() {
  const { scenarios, scenarioId, selectScenario, detail, topology, loading } =
    usePlayback();
  const [open, setOpen] = useState(false);
  const [road, setRoad] = useState<Road>("urban");
  const [attackNumber, setAttackNumber] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Grouped once, reused by both browse mode and search mode.
  const byRoad = useMemo(() => {
    const m: Record<Road, ScenarioSummary[]> = { urban: [], rural: [], highway: [] };
    for (const s of scenarios) m[s.road].push(s);
    for (const r of ROADS)
      m[r].sort((a, b) =>
        a.attack_number !== b.attack_number
          ? a.attack_number - b.attack_number
          : a.attack_pct - b.attack_pct
      );
    return m;
  }, [scenarios]);

  // Attack types actually present for the selected road, in catalog order —
  // some road/attack combinations are missing (highway has 29, not 42).
  const attacksForRoad = useMemo(() => {
    const seen = new Map<number, ScenarioSummary>();
    for (const s of byRoad[road]) if (!seen.has(s.attack_number)) seen.set(s.attack_number, s);
    return [...seen.values()].sort((a, b) => a.attack_number - b.attack_number);
  }, [byRoad, road]);

  const intensitiesForAttack = useMemo(() => {
    if (attackNumber === null) return [];
    return byRoad[road]
      .filter((s) => s.attack_number === attackNumber)
      .sort((a, b) => a.attack_pct - b.attack_pct);
  }, [byRoad, road, attackNumber]);

  const searchResults = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return scenarios
      .filter((s) => !ROAD_DISABLED[s.road as Road])
      .filter((s) => {
        const n = splitName(s.attack_name);
        return (
          n.code.toLowerCase().includes(q) ||
          n.human.toLowerCase().includes(q) ||
          s.road.includes(q) ||
          `${s.attack_pct}`.includes(q)
        );
      })
      .sort((a, b) => a.road.localeCompare(b.road) || a.attack_number - b.attack_number || a.attack_pct - b.attack_pct)
      .slice(0, 40);
  }, [scenarios, query]);

  const pick = (id: string) => {
    selectScenario(id);
    setOpen(false);
    setQuery("");
    setAttackNumber(null);
  };

  const named = detail ? splitName(detail.attack_name) : null;

  return (
    <div className="relative border-b border-surface-hairline bg-surface-page px-4 py-2.5">
      <div className="flex flex-wrap items-center gap-4">
        <button
          onClick={() => setOpen((v) => !v)}
          className="flex min-w-[280px] items-center justify-between gap-2 rounded-md border border-surface-hairline bg-surface-raised px-3 py-1.5 text-left text-sm text-ink-primary outline-none transition-colors hover:border-surface-hairline2 focus:border-entity-rsu"
        >
          <span className={named ? "" : "text-ink-muted"}>
            {named
              ? `${named.code} — ${named.human} · ${detail!.attack_pct}% hostile`
              : scenarios.length
              ? "Choose an attack scenario…"
              : "Loading…"}
          </span>
          <span aria-hidden className="text-ink-muted">{open ? "▴" : "▾"}</span>
        </button>

        {loading && <span className="text-xs text-ink-muted">Loading scenario…</span>}

        {named && !loading && (
          <div className="flex items-center gap-3">
            <div className="text-[11px] text-ink-muted">
              {detail!.road} · {scenarios.length} scenarios in the corpus
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

      {open && (
        <div
          ref={panelRef}
          className="absolute left-4 top-full z-20 mt-1.5 flex w-[560px] flex-col gap-3 rounded-lg border border-surface-hairline2 bg-surface-panel p-3 shadow-2xl"
        >
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by attack, road, or intensity…"
            className="rounded-md border border-surface-hairline bg-surface-raised px-3 py-1.5 text-sm text-ink-primary outline-none focus:border-entity-rsu"
          />

          {query.trim() ? (
            <div className="flex max-h-80 flex-col gap-0.5 overflow-y-auto">
              {searchResults.length === 0 && (
                <p className="px-2 py-3 text-xs text-ink-muted">No scenario matches "{query}".</p>
              )}
              {searchResults.map((s) => {
                const n = splitName(s.attack_name);
                return (
                  <button
                    key={s.id}
                    onClick={() => pick(s.id)}
                    className="flex items-center justify-between gap-2 rounded px-2.5 py-1.5 text-left text-xs transition-colors hover:bg-surface-raised"
                  >
                    <span className="text-ink-primary">
                      <span className="font-mono text-ink-secondary">{n.code}</span> — {n.human}
                    </span>
                    <span className="shrink-0 text-ink-muted">
                      {s.road} · {s.attack_pct}%
                    </span>
                  </button>
                );
              })}
            </div>
          ) : (
            <>
              <div className="flex gap-1.5">
                {ROADS.map((r) => (
                  <button
                    key={r}
                    disabled={ROAD_DISABLED[r]}
                    onClick={() => {
                      if (ROAD_DISABLED[r]) return;
                      setRoad(r);
                      setAttackNumber(null);
                    }}
                    title={ROAD_DISABLED[r] ? `${ROAD_LABEL[r]} map is temporarily disabled for this demo` : undefined}
                    className={`flex-1 rounded px-2 py-1.5 text-xs font-semibold transition-colors ${
                      ROAD_DISABLED[r]
                        ? "cursor-not-allowed bg-surface-raised text-ink-muted opacity-40"
                        : road === r
                        ? "bg-entity-rsu text-white"
                        : "bg-surface-raised text-ink-secondary hover:text-ink-primary"
                    }`}
                  >
                    {ROAD_LABEL[r]}
                    <span className="ml-1.5 font-normal opacity-70">{byRoad[r].length}</span>
                  </button>
                ))}
              </div>

              <div className="grid grid-cols-2 gap-1.5">
                {attacksForRoad.map((s) => {
                  const n = splitName(s.attack_name);
                  const count = byRoad[road].filter((x) => x.attack_number === s.attack_number).length;
                  return (
                    <button
                      key={s.attack_number}
                      onClick={() => setAttackNumber((v) => (v === s.attack_number ? null : s.attack_number))}
                      className={`flex flex-col gap-0.5 rounded border px-2.5 py-1.5 text-left transition-colors ${
                        attackNumber === s.attack_number
                          ? "border-entity-rsu bg-surface-raised"
                          : "border-surface-hairline bg-transparent hover:border-surface-hairline2"
                      }`}
                    >
                      <span className="font-mono text-[10px] text-ink-secondary">{n.code}</span>
                      <span className="text-[11px] leading-tight text-ink-primary">{n.human}</span>
                      <span className="text-[9px] text-ink-muted">{count} intensity level{count !== 1 ? "s" : ""}</span>
                    </button>
                  );
                })}
              </div>

              {attackNumber !== null && (
                <div className="flex flex-wrap gap-1.5 border-t border-surface-hairline pt-2.5">
                  {intensitiesForAttack.map((s) => (
                    <button
                      key={s.id}
                      onClick={() => pick(s.id)}
                      className={`rounded-full border px-3 py-1 text-xs font-medium transition-colors ${
                        s.id === scenarioId
                          ? "border-entity-rsu bg-entity-rsu text-white"
                          : "border-surface-hairline2 bg-surface-raised text-ink-secondary hover:text-ink-primary"
                      }`}
                    >
                      {s.attack_pct}% hostile
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
