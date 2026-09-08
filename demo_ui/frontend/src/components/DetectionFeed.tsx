import { useEffect, useMemo, useRef, useState } from "react";
import { CircleSlash } from "lucide-react";
import { usePlayback } from "../store/playback";
import { BeaconDto } from "../api";
import StatusPill, { SemanticStatus } from "./StatusPill";
import VehicleEventDetail from "./VehicleEventDetail";

type FilterKey = "all" | "caught" | "missed" | "honest";

function outcome(b: BeaconDto): { status: SemanticStatus; label: string; filter: FilterKey } {
  if (!b.is_poisoned) return { status: "safe", label: "HONEST", filter: "honest" };
  if (b.detected) return { status: "warning", label: "CAUGHT ATTACK", filter: "caught" };
  return { status: "compromised", label: "MISSED LIE", filter: "missed" };
}

const FILTERS: { key: FilterKey; label: string }[] = [
  { key: "all", label: "All" },
  { key: "caught", label: "Caught" },
  { key: "missed", label: "Missed" },
  { key: "honest", label: "Honest" },
];

export default function DetectionFeed() {
  const { beacons, t, selectedVehicle, selectVehicle, hoveredVehicle, setHoveredVehicle, vehicleTrack } =
    usePlayback();
  const [filter, setFilter] = useState<FilterKey>("all");
  const rowRefs = useRef<Map<number, HTMLDivElement>>(new Map());

  // The frame endpoint returns a lookback WINDOW (currently 0.15s), not a
  // single instant — a vehicle beaconing faster than that window can appear
  // more than once. The feed is vehicle-centric (one row per Vehicle ID), so
  // dedupe to each vehicle's most recent beacon before anything else keys
  // off vehicle_id — otherwise two rows race for the same React key and the
  // same DOM ref slot.
  const byVehicle = useMemo(() => {
    const m = new Map<number, BeaconDto>();
    for (const b of beacons) {
      const prev = m.get(b.vehicle_id);
      if (!prev || b.sim_time >= prev.sim_time) m.set(b.vehicle_id, b);
    }
    return [...m.values()];
  }, [beacons]);

  // Most consequential first: missed lies, then caught lies, then false
  // alarms, then quiet honest traffic. Surfacing false negatives at the top
  // is deliberate — they are the finding this project cares about.
  const rank = (x: BeaconDto) => (x.is_poisoned && !x.detected ? 0 : x.is_poisoned ? 1 : x.detected ? 2 : 3);
  const sorted = useMemo(() => [...byVehicle].sort((a, b) => rank(a) - rank(b)), [byVehicle]);

  const counts = useMemo(() => {
    const c = { all: byVehicle.length, caught: 0, missed: 0, honest: 0 };
    for (const b of byVehicle) c[outcome(b).filter]++;
    return c;
  }, [byVehicle]);

  // If the selected vehicle has no beacon in this exact instant's window (the
  // frame is a ~150ms slice, not a growing log), synthesize its row from the
  // already-fetched whole-run track so the expansion never loses its anchor
  // mid-inspection just because playback advanced a frame.
  const selectedInWindow = selectedVehicle != null && beacons.some((b) => b.vehicle_id === selectedVehicle);
  const synthetic = useMemo(() => {
    if (selectedVehicle == null || selectedInWindow || !vehicleTrack?.length) return null;
    let best = vehicleTrack[0];
    for (const b of vehicleTrack) {
      if (Math.abs(b.sim_time - t) < Math.abs(best.sim_time - t)) best = b;
    }
    return best;
  }, [selectedVehicle, selectedInWindow, vehicleTrack, t]);

  const displayList = useMemo(() => {
    const base = filter === "all" ? sorted : sorted.filter((b) => outcome(b).filter === filter);
    if (synthetic && (filter === "all" || outcome(synthetic).filter === filter)) {
      return [synthetic, ...base];
    }
    return base;
  }, [sorted, filter, synthetic]);

  // Not every vehicle in the mobility trace ever transmits a beacon this
  // capture recorded — most never come within an RSU's range during the
  // window that was captured. Selecting one of those from the map (the grey
  // "fleet" dots are clickable too) used to leave the panel showing nothing
  // at all once the empty track came back, which reads as broken rather than
  // "no data." Surface it as its own honest state instead, pinned above the
  // real rows so it's never lost among them. Filter-scoped to "all" since it
  // doesn't belong to any caught/missed/honest bucket.
  const selectedHasNoTrack =
    selectedVehicle != null && !selectedInWindow && vehicleTrack != null && vehicleTrack.length === 0;

  // Keep the selected row in view whenever selection changes, from either side.
  useEffect(() => {
    if (selectedVehicle == null) return;
    rowRefs.current.get(selectedVehicle)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [selectedVehicle]);

  // A hovered row (including one set by a map-marker hover) scrolls into
  // view too, but only "if necessary" — scrollIntoView is a no-op when the
  // element is already visible.
  useEffect(() => {
    if (hoveredVehicle == null || hoveredVehicle === selectedVehicle) return;
    rowRefs.current.get(hoveredVehicle)?.scrollIntoView({ block: "nearest" });
  }, [hoveredVehicle, selectedVehicle]);

  const toggle = (vid: number) => selectVehicle(selectedVehicle === vid ? null : vid);

  return (
    <div className="flex h-full flex-col overflow-hidden border-l border-surface-hairline bg-surface-panel">
      <div className="flex items-baseline justify-between border-b border-surface-hairline px-3 py-2">
        <span className="text-badge font-semibold uppercase tracking-wider text-ink-secondary">
          {counts.all} Events · <span className="text-status-missed">{counts.missed} Missed</span> ·{" "}
          <span className="text-status-caught">{counts.caught} Caught</span>
        </span>
        <span className="font-mono text-badge text-ink-muted">t={t.toFixed(1)}s</span>
      </div>

      <div className="flex gap-1 border-b border-surface-hairline px-2 py-1.5">
        {FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={`flex-1 rounded px-1.5 py-1 text-[10.5px] font-semibold transition-colors ${
              filter === f.key
                ? "bg-entity-rsu text-white"
                : "bg-surface-raised text-ink-secondary hover:text-ink-primary"
            }`}
          >
            {f.label} {counts[f.key]}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto">
        {displayList.length === 0 && !selectedHasNoTrack && (
          <div className="px-3 py-6 text-center text-body text-ink-muted">
            {filter === "all" ? "No radio traffic at this instant." : `No ${filter} events at this instant.`}
          </div>
        )}
        {selectedHasNoTrack && filter === "all" && (
          <div
            ref={(el) => {
              if (el) rowRefs.current.set(selectedVehicle!, el);
              else rowRefs.current.delete(selectedVehicle!);
            }}
            className="border-b border-surface-hairline/60 bg-surface-raised"
            style={{ borderLeft: "3px solid rgb(var(--c-entity-rsu))" }}
          >
            <button onClick={() => toggle(selectedVehicle!)} className="block w-full px-3.5 py-3 text-left">
              <span className="font-mono text-body font-semibold text-ink-primary">V{selectedVehicle}</span>
              <div className="mt-1.5 flex items-center gap-2">
                <StatusPill status="inactive" compact>
                  NO DATA
                </StatusPill>
                <span className="truncate text-badge text-ink-secondary">Never beaconed in this capture</span>
              </div>
            </button>
            <div className="space-y-3 border-t border-surface-hairline bg-surface-page/60 p-3.5">
              <div className="flex items-start gap-2.5 rounded-lg border border-dashed border-surface-hairline2 bg-surface-raised p-3.5">
                <CircleSlash size={16} className="mt-0.5 shrink-0 text-ink-muted" aria-hidden />
                <p className="text-xs leading-relaxed text-ink-secondary">
                  This vehicle has no recorded radio activity in this capture — most likely because its route never
                  came within an RSU's ~270 m range during the recorded window. It's still part of the underlying
                  mobility trace, which is why it's visible on the map.
                </p>
              </div>
            </div>
          </div>
        )}
        {displayList.map((b) => {
          const o = outcome(b);
          const isSelected = selectedVehicle === b.vehicle_id;
          const isHovered = hoveredVehicle === b.vehicle_id && !isSelected;
          const topSignature = b.accusations[0]?.name;
          return (
            <div
              key={b.vehicle_id}
              ref={(el) => {
                if (el) rowRefs.current.set(b.vehicle_id, el);
                else rowRefs.current.delete(b.vehicle_id);
              }}
              className={`border-b border-surface-hairline/60 transition-colors ${
                isSelected ? "bg-surface-raised" : isHovered ? "bg-surface-raised/50" : ""
              }`}
              style={{ borderLeft: isSelected ? "3px solid rgb(var(--c-entity-rsu))" : "3px solid transparent" }}
              onMouseEnter={() => setHoveredVehicle(b.vehicle_id)}
              onMouseLeave={() => setHoveredVehicle(null)}
            >
              <button onClick={() => toggle(b.vehicle_id)} className="block w-full px-3.5 py-3 text-left">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-body font-semibold text-ink-primary">V{b.vehicle_id}</span>
                  {b.is_ghost && (
                    <span className="rounded bg-entity-ghost/20 px-1.5 py-0.5 text-[10px] font-medium text-entity-ghost">
                      GHOST
                    </span>
                  )}
                  <span className="ml-auto font-mono text-[10px] text-ink-muted">{b.sim_time.toFixed(1)}s</span>
                </div>
                <div className="mt-1.5 flex items-center gap-2">
                  <StatusPill status={o.status} compact>
                    {o.label}
                  </StatusPill>
                  {topSignature && <span className="truncate text-badge text-ink-secondary">{topSignature}</span>}
                  {b.is_poisoned && b.accusations.length === 0 && (
                    <span className="truncate text-badge text-status-missed/80">No signature fired</span>
                  )}
                </div>
              </button>
              {isSelected && <VehicleEventDetail />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
