import { usePlayback } from "../store/playback";
import { BeaconDto } from "../api";

function Badge({ b }: { b: BeaconDto }) {
  if (!b.is_poisoned)
    return (
      <span className="rounded bg-status-good/15 px-1.5 py-0.5 text-[10px] font-medium text-status-good">
        HONEST
      </span>
    );
  if (b.detected)
    return (
      <span className="rounded bg-status-caught/20 px-1.5 py-0.5 text-[10px] font-medium text-status-caught">
        ⚑ CAUGHT
      </span>
    );
  return (
    <span className="rounded bg-status-missed/20 px-1.5 py-0.5 text-[10px] font-medium text-status-missed">
      ✕ MISSED
    </span>
  );
}

export default function DetectionFeed() {
  const { beacons, t, selectVehicle, selectedVehicle } = usePlayback();

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

  return (
    <div className="flex h-full flex-col overflow-hidden border-l border-surface-hairline bg-surface-panel">
      <div className="flex items-baseline justify-between border-b border-surface-hairline px-3 py-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
          Live detection feed
        </span>
        <span className="font-mono text-[10px] text-ink-muted">
          t={t.toFixed(1)}s
        </span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {sorted.length === 0 && (
          <div className="px-3 py-6 text-center text-xs text-ink-muted">
            No radio traffic at this instant.
          </div>
        )}
        {sorted.map((b) => (
          <button
            key={`${b.vehicle_id}-${b.sim_time}`}
            onClick={() => selectVehicle(b.vehicle_id)}
            className={`block w-full border-b border-surface-hairline/60 px-3 py-2 text-left transition-colors hover:bg-surface-raised ${
              selectedVehicle === b.vehicle_id ? "bg-surface-raised" : ""
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs text-ink-primary">
                V{b.vehicle_id}
              </span>
              {b.is_ghost && (
                <span className="rounded bg-entity-ghost/20 px-1.5 py-0.5 text-[10px] font-medium text-entity-ghost">
                  ✕ GHOST
                </span>
              )}
              <Badge b={b} />
              {b.drift_m != null && b.drift_m > 5 && (
                <span className="ml-auto font-mono text-[10px] text-ink-muted">
                  {b.drift_m.toFixed(0)}m off
                </span>
              )}
            </div>
            {b.accusations.length > 0 && (
              <ul className="mt-1 space-y-0.5">
                {b.accusations.slice(0, 3).map((a) => (
                  <li key={a.code} className="text-[11px] text-ink-secondary">
                    <span className="text-ink-muted">▸</span> {a.name}
                  </li>
                ))}
                {b.accusations.length > 3 && (
                  <li className="text-[10px] text-ink-muted">
                    +{b.accusations.length - 3} more
                  </li>
                )}
              </ul>
            )}
            {b.is_poisoned && b.accusations.length === 0 && (
              <p className="mt-1 text-[11px] text-status-missed/80">
                No signature fired — this lie was invisible to the rule tier.
              </p>
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
