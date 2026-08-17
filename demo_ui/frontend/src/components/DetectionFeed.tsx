import { useState } from "react";
import { ArrowRight, ChevronLeft } from "lucide-react";
import { usePlayback } from "../store/playback";
import { BeaconDto } from "../api";
import StatusPill, { SemanticStatus } from "./StatusPill";

const PAGE_SIZE = 8;

function outcome(b: BeaconDto): { status: SemanticStatus; label: string } {
  if (!b.is_poisoned) return { status: "safe", label: "HONEST" };
  if (b.detected) return { status: "warning", label: "CAUGHT ATTACK" };
  return { status: "compromised", label: "MISSED LIE" };
}

export default function DetectionFeed() {
  const { beacons, t, selectVehicle } = usePlayback();
  const [feedOpen, setFeedOpen] = useState(false);
  const [visible, setVisible] = useState(PAGE_SIZE);

  // Most consequential first: missed lies, then caught lies, then false
  // alarms, then quiet honest traffic. Surfacing false negatives at the top
  // is deliberate — they are the finding this project cares about.
  const rank = (x: BeaconDto) =>
    x.is_poisoned && !x.detected
      ? 0
      : x.is_poisoned
      ? 1
      : x.detected
      ? 2
      : 3;
  const sorted = [...beacons].sort((a, b) => rank(a) - rank(b));
  const caughtCount = beacons.filter((b) => b.is_poisoned && b.detected).length;
  const missedCount = beacons.filter((b) => b.is_poisoned && !b.detected).length;

  if (!feedOpen) {
    return (
      <div className="flex h-full flex-col border-l border-surface-hairline bg-surface-panel">
        <div className="flex items-baseline justify-between border-b border-surface-hairline px-3 py-2">
          <span className="text-badge font-semibold uppercase tracking-wider text-ink-muted">
            Detection feed
          </span>
          <span className="font-mono text-badge text-ink-muted">t={t.toFixed(1)}s</span>
        </div>
        <button
          onClick={() => {
            setFeedOpen(true);
            setVisible(PAGE_SIZE);
          }}
          className="flex flex-1 flex-col items-start justify-center gap-2 px-4 text-left transition-colors hover:bg-surface-raised"
        >
          <span className="font-mono text-2xl font-bold text-ink-primary">
            <span className="text-status-missed">{missedCount}</span> missed ·{" "}
            <span className="text-status-caught">{caughtCount}</span> caught
          </span>
          <span className="inline-flex items-center gap-1 text-body font-semibold text-entity-rsu">
            View detection feed <ArrowRight size={14} strokeWidth={2.5} aria-hidden />
          </span>
        </button>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col overflow-hidden border-l border-surface-hairline bg-surface-panel">
      <div className="flex items-center gap-2 border-b border-surface-hairline px-3 py-2">
        <button
          onClick={() => setFeedOpen(false)}
          className="flex items-center gap-1 rounded px-1 py-0.5 text-badge font-semibold text-ink-secondary transition-colors hover:text-ink-primary"
        >
          <ChevronLeft size={13} aria-hidden />
          Summary
        </button>
        <span className="ml-auto font-mono text-badge text-ink-muted">t={t.toFixed(1)}s</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {sorted.length === 0 && (
          <div className="px-3 py-6 text-center text-body text-ink-muted">
            No radio traffic at this instant.
          </div>
        )}
        {sorted.slice(0, visible).map((b) => {
          const o = outcome(b);
          const topSignature = b.accusations[0]?.name;
          return (
            <button
              key={`${b.vehicle_id}-${b.sim_time}`}
              onClick={() => selectVehicle(b.vehicle_id)}
              className="block w-full border-b border-surface-hairline/60 px-3.5 py-3 text-left transition-colors hover:bg-surface-raised"
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-body font-semibold text-ink-primary">
                  V{b.vehicle_id}
                </span>
                {b.is_ghost && (
                  <span className="rounded bg-entity-ghost/20 px-1.5 py-0.5 text-[10px] font-medium text-entity-ghost">
                    GHOST
                  </span>
                )}
              </div>
              <div className="mt-1.5 flex items-center gap-2">
                <StatusPill status={o.status} compact>
                  {o.label}
                </StatusPill>
                {topSignature && (
                  <span className="truncate text-badge text-ink-secondary">{topSignature}</span>
                )}
                {b.is_poisoned && b.accusations.length === 0 && (
                  <span className="truncate text-badge text-status-missed/80">
                    No signature fired
                  </span>
                )}
              </div>
            </button>
          );
        })}
        {visible < sorted.length && (
          <button
            onClick={() => setVisible((v) => v + PAGE_SIZE)}
            className="w-full border-b border-surface-hairline/60 py-2.5 text-center text-badge font-semibold text-entity-rsu transition-colors hover:bg-surface-raised"
          >
            Load more ({sorted.length - visible} remaining)
          </button>
        )}
      </div>
    </div>
  );
}
