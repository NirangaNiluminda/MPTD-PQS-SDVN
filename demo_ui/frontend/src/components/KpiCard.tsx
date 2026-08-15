import { ProvenanceKind } from "../design/tokens";
import ProvenanceChip from "./ProvenanceChip";

export interface KpiCardProps {
  label: string;
  value: string | number;
  unit?: string;
  glyph?: string;
  /** CSS color for the value + glyph. Defaults to ink-primary via className. */
  color?: string;
  /** Methodology line — "how was this counted". Mono, secondary ink. */
  basis?: string;
  /** Honesty line — the thing a reader must not assume. Muted, wraps. */
  caveat?: string;
  provenance?: ProvenanceKind;
  provenanceDetail?: string;
  /**
   * compact = a tight horizontal tile for a top-of-screen strip (basis/
   * caveat collapse into the title tooltip instead of rendering inline).
   * full = a vertical card with basis/caveat always visible — for a rail
   * or a grid where reading depth matters more than density.
   */
  variant?: "compact" | "full";
}

export default function KpiCard({
  label,
  value,
  unit,
  glyph,
  color,
  basis,
  caveat,
  provenance,
  provenanceDetail,
  variant = "compact",
}: KpiCardProps) {
  const tooltip = [basis, caveat].filter(Boolean).join(" — ");

  if (variant === "compact") {
    return (
      <div className="flex flex-col px-4 py-2" title={tooltip || undefined}>
        <div className="flex items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-wider text-ink-muted">
            {label}
          </span>
          {provenance && <ProvenanceChip kind={provenance} detail={provenanceDetail} compact />}
        </div>
        <span
          className={`font-mono text-lg font-semibold leading-tight ${color ? "" : "text-ink-primary"}`}
          style={color ? { color } : undefined}
        >
          {glyph && <span className="mr-1">{glyph}</span>}
          {value}
          {unit && <span className="ml-1 text-xs font-normal text-ink-muted">{unit}</span>}
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-1.5 border-b border-surface-hairline px-4 py-3 last:border-0">
      <div className="flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-wider text-ink-muted">
          {label}
        </span>
        {provenance && (
          <span className="ml-auto">
            <ProvenanceChip kind={provenance} detail={provenanceDetail} compact />
          </span>
        )}
      </div>
      <div className="flex items-baseline gap-1.5">
        {glyph && (
          <span className="font-mono text-sm" style={{ color }}>
            {glyph}
          </span>
        )}
        <span
          className="font-mono text-xl font-semibold leading-none tracking-tight"
          style={{ color: color ?? undefined }}
        >
          {value}
        </span>
        {unit && <span className="text-xs text-ink-muted">{unit}</span>}
      </div>
      {basis && <div className="font-mono text-[10px] leading-snug text-ink-secondary">{basis}</div>}
      {caveat && <div className="text-[10px] leading-snug text-ink-muted">{caveat}</div>}
    </div>
  );
}
