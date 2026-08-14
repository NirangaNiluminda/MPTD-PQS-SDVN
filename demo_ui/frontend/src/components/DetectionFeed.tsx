import { usePlayback } from "../store/playback";
import { BeaconDto } from "../api";

function statusBadge(b: BeaconDto) {
  if (!b.is_poisoned) return null;
  if (b.detected)
    return (
      <span className="rounded bg-amber-900/60 px-1.5 py-0.5 text-[10px] font-medium text-amber-300">
        FLAGGED
      </span>
    );
  return (
    <span className="rounded bg-red-900/60 px-1.5 py-0.5 text-[10px] font-medium text-red-300">
      MISSED
    </span>
  );
}

export default function DetectionFeed() {
  const { beacons, t } = usePlayback();

  // Most interesting first: poisoned-and-missed, then poisoned-and-flagged,
  // then everything else. This is the honesty-first ordering — false
  // negatives are the finding this project cares most about surfacing.
  const sorted = [...beacons].sort((a, b) => {
    const rank = (x: BeaconDto) =>
      x.is_poisoned && !x.detected ? 0 : x.is_poisoned ? 1 : 2;
    return rank(a) - rank(b);
  });

  return (
    <div className="flex h-full flex-col overflow-hidden border-l border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 px-3 py-2 text-xs font-medium text-slate-400">
        DETECTION FEED — t = {t.toFixed(1)}s
      </div>
      <div className="flex-1 overflow-y-auto">
        {sorted.length === 0 && (
          <div className="px-3 py-4 text-xs text-slate-500">
            No beacon activity at this instant.
          </div>
        )}
        {sorted.map((b) => (
          <div
            key={`${b.vehicle_id}-${b.sim_time}`}
            className="border-b border-slate-800/60 px-3 py-2 text-xs"
          >
            <div className="flex items-center gap-2">
              <span className="font-mono text-slate-300">
                V{b.vehicle_id}
              </span>
              {b.is_ghost && (
                <span className="rounded bg-purple-900/60 px-1.5 py-0.5 text-[10px] text-purple-300">
                  GHOST
                </span>
              )}
              {statusBadge(b)}
              {b.drift_m != null && b.drift_m > 5 && (
                <span className="text-slate-500">
                  drift {b.drift_m.toFixed(0)}m
                </span>
              )}
            </div>
            {b.accusations.length > 0 && (
              <ul className="mt-1 space-y-0.5 pl-1 text-slate-400">
                {b.accusations.map((a) => (
                  <li key={a.code}>
                    <span className="text-slate-500">▸</span> {a.name}
                  </li>
                ))}
              </ul>
            )}
            {b.is_poisoned && b.accusations.length === 0 && (
              <div className="mt-1 pl-1 text-slate-500">
                (poisoned, but no signature tripped — ψ = {b.psi_score.toFixed(3)})
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
