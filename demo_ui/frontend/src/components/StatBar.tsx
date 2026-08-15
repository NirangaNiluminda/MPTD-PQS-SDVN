import { usePlayback } from "../store/playback";
import KpiCard from "./KpiCard";
import { STATUS, ENTITY } from "../design/tokens";

export default function StatBar() {
  const { stats, detail, topology, t, scenarioId } = usePlayback();

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

  return (
    <div className="flex flex-wrap items-stretch divide-x divide-surface-hairline border-b border-surface-hairline bg-surface-panel">
      <KpiCard
        label="Beacons so far"
        value={stats.beacons.toLocaleString()}
        provenance="replayed"
        provenanceDetail={upToT}
        basis={`Counted ${upToT} in ${scenarioId ?? "this recording"}`}
      />
      <KpiCard
        label="Attacks caught"
        value={stats.caught.toLocaleString()}
        color={STATUS.caught}
        provenance="replayed"
        provenanceDetail={upToT}
        basis="Poisoned beacons the system flagged"
      />
      <KpiCard
        label="Attacks missed"
        value={stats.missed.toLocaleString()}
        color={STATUS.missed}
        provenance="replayed"
        provenanceDetail={upToT}
        basis="Poisoned beacons that slipped through (false negatives)"
      />
      <KpiCard
        label="False alarms"
        value={stats.false_alarms.toLocaleString()}
        provenance="replayed"
        provenanceDetail={upToT}
        basis="Honest beacons wrongly flagged (false positives)"
      />
      {stats.ghosts_seen > 0 && (
        <KpiCard
          label="Ghost IDs"
          value={stats.ghosts_seen}
          color={ENTITY.ghost}
          provenance="replayed"
          provenanceDetail={upToT}
        />
      )}
      <KpiCard
        label="Hostile nodes"
        value={hostileCount}
        color={STATUS.missed}
        provenance="replayed"
        provenanceDetail="ground truth for the whole scenario"
      />
      {mccRaw != null && (
        <KpiCard
          label={mccLabel}
          value={mccDefined ? mccRaw.toFixed(3) : "n/a"}
          provenance="replayed"
          provenanceDetail="whole run, not windowed"
          basis={mccCaveat}
        />
      )}
    </div>
  );
}
