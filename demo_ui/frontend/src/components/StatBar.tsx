import { usePlayback } from "../store/playback";

function Stat({
  label,
  value,
  tone = "neutral",
  hint,
}: {
  label: string;
  value: string | number;
  tone?: "neutral" | "caught" | "missed" | "ghost";
  hint?: string;
}) {
  const toneClass =
    tone === "caught"
      ? "text-status-caught"
      : tone === "missed"
      ? "text-status-missed"
      : tone === "ghost"
      ? "text-entity-ghost"
      : "text-ink-primary";
  return (
    <div className="flex flex-col px-4 py-2" title={hint}>
      <span className="text-[10px] uppercase tracking-wider text-ink-muted">
        {label}
      </span>
      <span className={`text-lg font-semibold leading-tight ${toneClass}`}>
        {value}
      </span>
    </div>
  );
}

export default function StatBar() {
  const { stats, detail, topology } = usePlayback();

  if (!stats || !detail) {
    return (
      <div className="flex h-[58px] items-center border-b border-surface-hairline bg-surface-panel px-4 text-sm text-ink-muted">
        No scenario loaded.
      </div>
    );
  }

  const hostileCount =
    (topology?.compromised_rsus.length ?? 0) +
    (topology?.hostile_controllers.length ?? 0) +
    (topology?.malicious_vehicles.length ?? 0) +
    (topology?.mitm_relays.length ?? 0);

  // MCC comes from the simulator's own metrics.csv — never recomputed here.
  const mcc = detail.metrics?.MCC_full ?? detail.metrics?.MCC;

  return (
    <div className="flex flex-wrap items-stretch divide-x divide-surface-hairline border-b border-surface-hairline bg-surface-panel">
      <Stat label="Beacons so far" value={stats.beacons.toLocaleString()} />
      <Stat
        label="Attacks caught"
        value={stats.caught.toLocaleString()}
        tone="caught"
        hint="Poisoned beacons the system flagged"
      />
      <Stat
        label="Attacks missed"
        value={stats.missed.toLocaleString()}
        tone="missed"
        hint="Poisoned beacons that slipped through (false negatives)"
      />
      <Stat
        label="False alarms"
        value={stats.false_alarms.toLocaleString()}
        hint="Honest beacons wrongly flagged (false positives)"
      />
      {stats.ghosts_seen > 0 && (
        <Stat label="Ghost IDs" value={stats.ghosts_seen} tone="ghost" />
      )}
      <Stat label="Hostile nodes" value={hostileCount} tone="missed" />
      {mcc != null && (
        <Stat
          label="Run MCC"
          value={Number(mcc).toFixed(3)}
          hint="From the simulator's own metrics.csv for the FULL run — not recomputed here, and not windowed to the current playback time."
        />
      )}
    </div>
  );
}
