import StatusPill, { SemanticStatus, STATUS_LABEL } from "./StatusPill";

const ALL_STATUSES: SemanticStatus[] = ["safe", "warning", "compromised", "informational", "inactive"];

/** "Every page must include a visible legend" — pass `only` to show just the
 * subset of the five roles that screen actually uses. */
export default function StatusLegend({ only }: { only?: SemanticStatus[] }) {
  const items = only ?? ALL_STATUSES;
  return (
    <div className="flex flex-wrap items-center gap-2">
      {items.map((s) => (
        <StatusPill key={s} status={s} compact>
          {STATUS_LABEL[s]}
        </StatusPill>
      ))}
    </div>
  );
}
