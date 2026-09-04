import { useTokens } from "../design/tokens";

export interface EgoGraphNode {
  id: number;
  dx: number;
  dy: number;
  distance: number;
  poisoned: boolean;
  /** 0..1 attention share. Omit for a distance-only (no re-inference) view — edges then render at a constant weight instead of implying a weight that was never computed. */
  weight?: number;
}

/**
 * Real neighbours laid out at their true position relative to a centre
 * vehicle — used for both the GAT attention ego-graph (VehicleAnalysisModal,
 * weight = real attention share) and the capture log's proximity view
 * (DefenceInspectorScreen, no weight — distance only).
 */
export default function EgoGraph({
  centerLabel,
  nodes,
  edgeUnit = "attention",
}: {
  centerLabel: string;
  nodes: EgoGraphNode[];
  edgeUnit?: string;
}) {
  const { SERIES, STATUS, INK, SURFACE } = useTokens();

  if (nodes.length === 0) {
    return (
      <p className="text-xs text-ink-muted">
        No neighbours to lay out — this vehicle's embedding came from itself alone.
      </p>
    );
  }

  const maxDist = Math.max(...nodes.map((n) => Math.hypot(n.dx, n.dy)), 1);
  const scale = 100 / maxDist;

  const placedLabels: { px: number; py: number }[] = [];
  const layout = nodes.map((n) => {
    const px = 130 + n.dx * scale;
    const py = 130 + n.dy * scale;
    const showLabel = !placedLabels.some((p) => Math.hypot(p.px - px, p.py - py) < 16);
    if (showLabel) placedLabels.push({ px, py });
    return { ...n, px, py, showLabel };
  });

  return (
    <>
      <div className="flex justify-center">
        <svg viewBox="0 0 260 260" width="100%" style={{ maxWidth: 320, height: "auto" }}>
          {layout.map((n) => (
            <line
              key={`e-${n.id}`}
              x1={130}
              y1={130}
              x2={n.px}
              y2={n.py}
              stroke={n.poisoned ? STATUS.missed : SERIES[0]}
              strokeWidth={n.weight != null ? 1.5 + n.weight * 9 : 2}
              strokeOpacity={n.weight != null ? 0.3 + n.weight * 0.7 : 0.55}
            />
          ))}
          {layout.map((n) => (
            <g key={`n-${n.id}`}>
              <circle
                cx={n.px}
                cy={n.py}
                r={7}
                fill={n.poisoned ? STATUS.missed : SERIES[0]}
                stroke={SURFACE.raised}
                strokeWidth={1.5}
              >
                <title>
                  {`V${n.id} — ${n.weight != null ? `${(n.weight * 100).toFixed(1)}% ${edgeUnit}, ` : ""}${n.distance.toFixed(
                    0
                  )}m away`}
                </title>
              </circle>
              {n.showLabel && (
                <text x={n.px} y={n.py - 11} textAnchor="middle" fontSize={9} fill={INK.secondary}>
                  V{n.id}
                </text>
              )}
            </g>
          ))}
          <circle cx={130} cy={130} r={9} fill="none" stroke={INK.primary} strokeWidth={2} />
          <circle cx={130} cy={130} r={3.5} fill={INK.primary} />
          <text x={130} y={130 + 24} textAnchor="middle" fontSize={9} fontWeight={600} fill={INK.primary}>
            {centerLabel}
          </text>
        </svg>
      </div>
      <div className="mt-2 flex items-center justify-center gap-4 text-[10px] text-ink-muted">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: SERIES[0] }} /> honest
          neighbour
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: STATUS.missed }} /> poisoned
          neighbour
        </span>
      </div>
    </>
  );
}
