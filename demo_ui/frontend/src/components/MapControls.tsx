import { useState } from "react";
import { usePlayback, LayerToggles } from "../store/playback";
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

const LEGEND_ITEMS: { label: string; color: string; shape: "sq" | "di" | "ci" | "x" }[] = [
  { label: "Roadside unit", color: ENTITY.rsu, shape: "sq" },
  { label: "Controller", color: ENTITY.controller, shape: "di" },
  { label: "Hijacked node", color: STATUS.missed, shape: "sq" },
  { label: "Honest vehicle", color: ENTITY.vehicleClean, shape: "ci" },
  { label: "Lie — caught", color: STATUS.caught, shape: "ci" },
  { label: "Lie — missed", color: STATUS.missed, shape: "ci" },
  { label: "Ghost identity", color: ENTITY.ghost, shape: "x" },
];

const LAYER_DEFAULTS: LayerToggles = {
  streets: true,
  coverage: true,
  trails: true,
  rubberBands: true,
  controllerLinks: false,
};

const LAYER_CHIPS: { k: keyof LayerToggles; label: string }[] = [
  { k: "streets", label: "Street map" },
  { k: "coverage", label: "Radio range" },
  { k: "trails", label: "Movement trails" },
  { k: "rubberBands", label: "Claim → truth" },
  { k: "controllerLinks", label: "Controller links" },
];

function TabButton({
  open,
  label,
  badge,
  onClick,
}: {
  open: boolean;
  label: string;
  badge?: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-1.5 rounded-md border border-surface-hairline2 bg-surface-panel/95 px-2.5 py-1.5 font-mono text-[10px] font-medium text-ink-secondary shadow-lg backdrop-blur transition-colors hover:text-ink-primary"
    >
      <span aria-hidden>{open ? "▾" : "▸"}</span>
      {label}
      {badge && <span className="text-ink-muted">{badge}</span>}
    </button>
  );
}

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full border px-2.5 py-1 text-[10.5px] font-medium transition-colors ${
        active
          ? "border-surface-hairline2 bg-surface-raised text-ink-primary"
          : "border-surface-hairline bg-transparent text-ink-muted hover:text-ink-secondary"
      }`}
    >
      {children}
    </button>
  );
}

export default function MapControls() {
  const { layers, toggleLayer } = usePlayback();
  const [controlsOpen, setControlsOpen] = useState(true);
  const [legendOpen, setLegendOpen] = useState(false);

  const changedCount = LAYER_CHIPS.filter((c) => layers[c.k] !== LAYER_DEFAULTS[c.k]).length;

  const resetLayers = () => {
    (Object.keys(LAYER_DEFAULTS) as (keyof LayerToggles)[]).forEach((k) => {
      if (layers[k] !== LAYER_DEFAULTS[k]) toggleLayer(k);
    });
  };

  return (
    <div className="pointer-events-auto absolute left-3 top-3 z-10 flex max-w-[min(90%,380px)] flex-col gap-1.5">
      <div className="flex gap-1.5">
        <TabButton open={controlsOpen} label="Controls" onClick={() => setControlsOpen((v) => !v)} />
        <TabButton open={legendOpen} label="Legend" onClick={() => setLegendOpen((v) => !v)} />
        {changedCount > 0 && (
          <button
            onClick={resetLayers}
            className="rounded-md border border-surface-hairline2 bg-surface-panel/95 px-2.5 py-1.5 font-mono text-[10px] font-medium text-ink-secondary shadow-lg backdrop-blur hover:text-ink-primary"
          >
            ↺ reset ({changedCount})
          </button>
        )}
      </div>

      {controlsOpen && (
        <div className="rounded-lg border border-surface-hairline2 bg-surface-panel/95 p-2.5 shadow-lg backdrop-blur">
          <div className="mb-1.5 text-[9px] font-bold uppercase tracking-widest text-ink-muted">
            Layers
          </div>
          <div className="flex flex-wrap gap-1.5">
            {LAYER_CHIPS.map((c) => (
              <Chip key={c.k} active={layers[c.k]} onClick={() => toggleLayer(c.k)}>
                {c.label}
              </Chip>
            ))}
          </div>
        </div>
      )}

      {legendOpen && (
        <div className="rounded-lg border border-surface-hairline2 bg-surface-panel/95 p-2.5 shadow-lg backdrop-blur">
          <div className="mb-1.5 text-[9px] font-bold uppercase tracking-widest text-ink-muted">
            Shape = class · colour = state
          </div>
          <ul className="grid grid-cols-2 gap-x-4 gap-y-1">
            {LEGEND_ITEMS.map((it) => (
              <li key={it.label} className="flex items-center gap-2 whitespace-nowrap text-[10.5px] text-ink-secondary">
                <Swatch color={it.color} shape={it.shape} />
                {it.label}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
