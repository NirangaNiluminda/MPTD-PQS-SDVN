import { ReactNode } from "react";

/**
 * A landing-view tile: headline stat + one line of context, click to open
 * the full detail in a DrillModal. The abstract-first / drill-down-second
 * pattern this whole redesign pass is built around — every screen that
 * used to dump every chart at once now shows a grid of these instead.
 */
export default function SummaryCard({
  label,
  value,
  valueColor,
  caption,
  onClick,
}: {
  label: string;
  value: ReactNode;
  valueColor?: string;
  caption?: ReactNode;
  onClick: (e: React.MouseEvent<HTMLButtonElement>) => void;
}) {
  return (
    <button
      onClick={onClick}
      className="flex flex-col gap-1.5 rounded-lg border border-surface-hairline bg-surface-panel p-4 text-left transition-all hover:-translate-y-0.5 hover:border-surface-hairline2 hover:shadow-lg"
    >
      <span className="text-[10px] font-bold uppercase tracking-widest text-ink-muted">{label}</span>
      <span className="font-mono text-2xl font-semibold text-ink-primary" style={valueColor ? { color: valueColor } : undefined}>
        {value}
      </span>
      {caption && <span className="text-[11px] leading-relaxed text-ink-secondary">{caption}</span>}
      <span className="mt-1 text-[10px] font-medium text-entity-rsu">View details →</span>
    </button>
  );
}
