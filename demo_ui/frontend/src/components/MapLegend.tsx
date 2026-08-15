import { usePlayback } from "../store/playback";
import { ENTITY, STATUS } from "../design/tokens";

// Shape is part of the encoding, not decoration: the validated palette clears
// the normal-vision floor but sits in the CVD warn band, which is only
// permitted with a secondary channel. These glyphs are that channel.
function Swatch({ color, shape }: { color: string; shape: "sq" | "di" | "ci" | "x" }) {
  const common = { width: 12, height: 12 } as const;
  if (shape === "sq")
    return (
      <svg {...common} viewBox="0 0 12 12">
        <rect x="1.5" y="1.5" width="9" height="9" fill={color} stroke="#fff3" />
      </svg>
    );
  if (shape === "di")
    return (
      <svg {...common} viewBox="0 0 12 12">
        <polygon points="6,1 11,6 6,11 1,6" fill={color} stroke="#fff3" />
      </svg>
    );
  if (shape === "x")
    return (
      <svg {...common} viewBox="0 0 12 12">
        <path d="M2 2 L10 10 M10 2 L2 10" stroke={color} strokeWidth="2" fill="none" />
      </svg>
    );
  return (
    <svg {...common} viewBox="0 0 12 12">
      <circle cx="6" cy="6" r="4.5" fill={color} />
    </svg>
  );
}

const ITEMS: { label: string; color: string; shape: "sq" | "di" | "ci" | "x" }[] = [
  { label: "Roadside unit", color: ENTITY.rsu, shape: "sq" },
  { label: "Controller", color: ENTITY.controller, shape: "di" },
  { label: "Hijacked node", color: STATUS.missed, shape: "sq" },
  { label: "Honest vehicle", color: ENTITY.vehicleClean, shape: "ci" },
  { label: "Lie — caught", color: STATUS.caught, shape: "ci" },
  { label: "Lie — missed", color: STATUS.missed, shape: "ci" },
  { label: "Ghost identity", color: ENTITY.ghost, shape: "x" },
];

export default function MapLegend() {
  const { layers, toggleLayer } = usePlayback();

  const toggles: { k: keyof typeof layers; label: string }[] = [
    { k: "coverage", label: "Radio range" },
    { k: "trails", label: "Movement trails" },
    { k: "rubberBands", label: "Claim → truth" },
    { k: "controllerLinks", label: "Controller links" },
  ];

  return (
    <div className="pointer-events-auto absolute bottom-3 left-3 w-52 rounded-lg border border-surface-hairline bg-surface-panel/95 p-3 backdrop-blur">
      <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
        Legend
      </div>
      <ul className="space-y-1.5">
        {ITEMS.map((it) => (
          <li key={it.label} className="flex items-center gap-2 text-xs text-ink-secondary">
            <Swatch color={it.color} shape={it.shape} />
            {it.label}
          </li>
        ))}
      </ul>
      <div className="mt-3 border-t border-surface-hairline pt-2">
        <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
          Layers
        </div>
        {toggles.map((t) => (
          <label
            key={t.k}
            className="flex cursor-pointer items-center gap-2 py-0.5 text-xs text-ink-secondary hover:text-ink-primary"
          >
            <input
              type="checkbox"
              className="accent-entity-rsu"
              checked={layers[t.k]}
              onChange={() => toggleLayer(t.k)}
            />
            {t.label}
          </label>
        ))}
      </div>
    </div>
  );
}
