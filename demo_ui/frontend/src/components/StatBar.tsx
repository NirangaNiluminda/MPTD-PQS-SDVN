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

  // MCC comes from the simulator's own metrics.csv — never recomputed here.
  //
  // Two traps this has to survive, both found by looking at real corpus rows:
  //
  // 1. The whole replay corpus was recorded with ablation_mode=1 (AB1), so
  //    every cm_full_* is 0 and MCC_full is 0 for EVERY scenario. Preferring
  //    MCC_full therefore showed a flat 0.000 everywhere. Fall back to the
  //    lightweight tier when the full tier produced no confusion matrix, and
  //    say which tier is on screen.
  //
  // 2. MCC is UNDEFINED, not zero, when a confusion-matrix margin is empty.
  //    At 100% hostile there are no honest beacons, so TN=FP=0 and the
  //    denominator sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN)) is 0. The simulator
  //    writes 0; rendering that as "MCC 0.000" reads as total failure when
  //    the run actually caught 4288/4288 with zero false alarms. Show n/a.
  const m = detail.metrics;
  const num = (k: string) => (m?.[k] != null ? Number(m[k]) : null);

  const fullRan =
    (num("cm_full_TP") ?? 0) + (num("cm_full_FP") ?? 0) +
    (num("cm_full_TN") ?? 0) + (num("cm_full_FN") ?? 0) > 0;

  const tier = fullRan ? "full" : "lightweight";
  const cm = fullRan
    ? { tp: num("cm_full_TP"), fp: num("cm_full_FP"), tn: num("cm_full_TN"), fn: num("cm_full_FN") }
    : { tp: num("cm_TP"), fp: num("cm_FP"), tn: num("cm_TN"), fn: num("cm_FN") };

  // Undefined whenever any marginal of the 2x2 table is empty.
  const mccDefined =
    cm.tp != null && cm.fp != null && cm.tn != null && cm.fn != null &&
    cm.tp + cm.fp > 0 && cm.tp + cm.fn > 0 &&
    cm.tn + cm.fp > 0 && cm.tn + cm.fn > 0;

  const mccRaw = fullRan ? num("MCC_full") : num("MCC");
  const mccLabel = `MCC (${tier})`;
  const mccCaveat = mccDefined
    ? `Whole-run figure from metrics.csv (${tier} tier) — not windowed to t=${t.toFixed(0)}s.`
    : `Undefined, not zero: empty confusion-matrix margin (TP=${cm.tp} FP=${cm.fp} TN=${cm.tn} FN=${cm.fn}). ` +
      `Detection was actually ${cm.tp}/${(cm.tp ?? 0) + (cm.fn ?? 0)} caught, ${cm.fp} false alarms.`;

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
        <HeroStat
          label="Attacks caught"
          value={stats.caught.toLocaleString()}
          color={STATUS.caught}
          tooltip={`Replayed, ${upToT} — poisoned beacons the system flagged`}
        />
        <HeroStat
          label="Attacks missed"
          value={stats.missed.toLocaleString()}
          color={STATUS.missed}
          tooltip={`Replayed, ${upToT} — poisoned beacons that slipped through (false negatives)`}
        />
        {mccRaw != null && (
          <HeroStat
            label={mccLabel}
            value={mccDefined ? mccRaw.toFixed(3) : "n/a"}
            tooltip={mccCaveat}
          />
        )}

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
