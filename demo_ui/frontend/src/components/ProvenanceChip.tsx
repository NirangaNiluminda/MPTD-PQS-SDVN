import { useTokens, ProvenanceKind } from "../design/tokens";

/**
 * Every number in this app is one of three things: LIVE (can change under
 * you), REPLAYED (fixed to a recording), or a POINT-IN-TIME snapshot (may
 * already be stale). This chip is the one place that distinction is drawn,
 * so it must appear anywhere a viewer could otherwise assume "live" by
 * default — which is the dangerous assumption for a demo like this. The
 * hover tooltip carries the full explanation now that the always-visible
 * sidebar legend was removed as redundant with this chip appearing next to
 * every page title.
 */
const DEFAULT_DETAIL: Record<ProvenanceKind, string> = {
  live: "This screen reflects a real process running right now — it can change while you watch.",
  replayed: "This screen replays a completed, fixed recording — nothing here changes.",
  snapshot: "This screen shows a snapshot taken at one point in time — it may already be stale; re-run the capture to refresh it.",
};

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
  const { PROVENANCE } = useTokens();
  const p = PROVENANCE[kind];
  const title = `${p.label} — ${detail ?? DEFAULT_DETAIL[kind]}`;
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-full border border-surface-hairline2 bg-surface-raised font-mono ${
        compact ? "px-1.5 py-0.5 text-[9px]" : "px-2.5 py-1 text-badge"
      }`}
      style={{ color: p.color }}
    >
      <span aria-hidden>{p.glyph}</span>
      <span className="tracking-wide">{p.label}</span>
    </span>
  );
}
