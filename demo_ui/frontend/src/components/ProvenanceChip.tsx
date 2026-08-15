import { PROVENANCE, ProvenanceKind } from "../design/tokens";

/**
 * Every number in this app is one of three things: LIVE (can change under
 * you), REPLAYED (fixed to a recording), or a POINT-IN-TIME snapshot (may
 * already be stale). This chip is the one place that distinction is drawn,
 * so it must appear anywhere a viewer could otherwise assume "live" by
 * default — which is the dangerous assumption for a demo like this.
 */
export default function ProvenanceChip({
  kind,
  detail,
  compact = false,
}: {
  kind: ProvenanceKind;
  /** Extra context for the tooltip, e.g. "recorded 2026-08-15, urban/a1_p40". */
  detail?: string;
  compact?: boolean;
}) {
  const p = PROVENANCE[kind];
  const title = detail ? `${p.label} — ${detail}` : p.label;
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded border border-surface-hairline2 bg-surface-raised font-mono ${
        compact ? "px-1.5 py-0.5 text-[9px]" : "px-2 py-1 text-[10px]"
      }`}
      style={{ color: p.color }}
    >
      <span aria-hidden>{p.glyph}</span>
      <span className="tracking-wide">{p.label}</span>
    </span>
  );
}
