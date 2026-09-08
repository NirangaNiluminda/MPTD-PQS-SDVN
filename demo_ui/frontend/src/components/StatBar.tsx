import { useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import { usePlayback } from "../store/playback";
import { useTokens } from "../design/tokens";

function HeroStat({
  label,
  value,
  color,
  tooltip,
}: {
  label: string;
  value: string | number;
  color?: string;
  tooltip?: string;
}) {
  return (
    <div
      className="flex min-w-[128px] flex-col gap-1 rounded-xl border border-surface-hairline bg-surface-panel px-5 py-3.5"
      title={tooltip}
    >
      <span
        className="font-mono text-3xl font-bold leading-none tracking-tight"
        style={color ? { color } : undefined}
      >
        {value}
      </span>
      <span className="text-badge font-semibold uppercase tracking-wide text-ink-muted">{label}</span>
    </div>
  );
}

function SecondaryStat({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="flex items-baseline gap-2 px-3 py-1.5">
      <span className="font-mono text-base font-semibold" style={color ? { color } : undefined}>
        {value}
      </span>
      <span className="text-badge uppercase tracking-wide text-ink-muted">{label}</span>
    </div>
  );
}

export default function StatBar() {
  const { stats, detail, topology, t } = usePlayback();
  const { STATUS, ENTITY } = useTokens();
  const [secondaryOpen, setSecondaryOpen] = useState(false);

  if (!stats || !detail) {
    return (
      <div className="flex h-[76px] items-center border-b border-surface-hairline bg-surface-page px-4 text-body text-ink-muted">
        No scenario loaded.
      </div>
    );
  }

  const hostileCount =
    (topology?.compromised_rsus.length ?? 0) +
    (topology?.hostile_controllers.length ?? 0) +
    (topology?.malicious_vehicles.length ?? 0) +
    (topology?.mitm_relays.length ?? 0);

  const upToT = `up to t=${t.toFixed(0)}s`;
  const secondaryCount = 2 + (stats.ghosts_seen > 0 ? 1 : 0);

  return (
    <div className="flex flex-col gap-2 border-b border-surface-hairline bg-surface-page px-4 py-3">
      <div className="flex flex-wrap items-stretch gap-2.5">
        <HeroStat
          label="Beacons so far"
          value={stats.beacons.toLocaleString()}
          tooltip={`Replayed — counted ${upToT} in ${detail.id}`}
        />

        <button
          onClick={() => setSecondaryOpen((v) => !v)}
          className="ml-auto flex shrink-0 items-center gap-1.5 self-start rounded-md border border-surface-hairline px-2.5 py-1.5 text-badge font-medium text-ink-muted transition-colors hover:border-surface-hairline2 hover:text-ink-primary"
          aria-expanded={secondaryOpen}
        >
          {secondaryOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          {secondaryOpen ? "Fewer stats" : `${secondaryCount} more stats`}
        </button>
      </div>

      {secondaryOpen && (
        <div className="anim-rise flex flex-wrap items-center divide-x divide-surface-hairline rounded-lg border border-surface-hairline bg-surface-panel">
          <SecondaryStat
            label="False alarms"
            value={stats.false_alarms.toLocaleString()}
          />
          <SecondaryStat
            label="Hostile nodes"
            value={hostileCount}
            color={STATUS.missed}
          />
          {stats.ghosts_seen > 0 && (
            <SecondaryStat label="Ghost IDs" value={stats.ghosts_seen} color={ENTITY.ghost} />
          )}
        </div>
      )}
    </div>
  );
}
