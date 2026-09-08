import { useEffect, useRef, useState } from "react";
import { SlidersHorizontal, X } from "lucide-react";
import { usePlayback, LayerToggles, MapDetail } from "../store/playback";
import { useTokens } from "../design/tokens";

const DETAIL_STEPS: { level: MapDetail; label: string; note: string }[] = [
  {
    level: "region",
    label: "Region",
    note: "Entities collapse into area clusters — count and worst-case state only. Nothing overlaps, no individual is drawn.",
  },
  {
    level: "district",
    label: "District",
    note: "Infrastructure at full detail; vehicles shown as density dots only. Individual identity is not readable at this level, by design.",
  },
  {
    level: "street",
    label: "Street",
    note: "Every entity drawn with its own shape. Flagged vehicles get a claim-vs-actual line. The default view.",
  },
  {
    level: "entity",
    label: "Entity",
    note: "Adds vehicle-ID labels for anything poisoned. Best used zoomed into one area — labels will collide across the full network.",
  },
];

// Shape is part of the encoding, not decoration: the validated palette clears
// the normal-vision floor but sits in the CVD warn band, which is only
// permitted with a secondary channel. These glyphs are that channel.
function Swatch({ color, shape }: { color: string; shape: "sq" | "di" | "ci" | "x" | "tri" }) {
  const common = { width: 12, height: 12 } as const;
  if (shape === "sq")
    return (
      <svg {...common} viewBox="0 0 12 12">
        <rect x="1.5" y="1.5" width="9" height="9" fill={color} stroke="rgb(var(--c-surface-panel) / 0.8)" />
      </svg>
    );
  if (shape === "di")
    return (
      <svg {...common} viewBox="0 0 12 12">
        <polygon points="6,1 11,6 6,11 1,6" fill={color} stroke="rgb(var(--c-surface-panel) / 0.8)" />
      </svg>
    );
  if (shape === "x")
    return (
      <svg {...common} viewBox="0 0 12 12">
        <path d="M2 2 L10 10 M10 2 L2 10" stroke={color} strokeWidth="2" fill="none" />
      </svg>
    );
  if (shape === "tri")
    return (
      <svg {...common} viewBox="0 0 12 12">
        <polygon points="6,1.5 10.8,10 1.2,10" fill={color} stroke="rgb(var(--c-surface-panel) / 0.8)" />
      </svg>
    );
  return (
    <svg {...common} viewBox="0 0 12 12">
      <circle cx="6" cy="6" r="4.5" fill={color} />
    </svg>
  );
}

function buildLegendItems(
  ENTITY: Record<string, string>,
  STATUS: Record<string, string>
): { label: string; color: string; shape: "sq" | "di" | "ci" | "x" | "tri" }[] {
  return [
    { label: "Roadside unit", color: ENTITY.rsu, shape: "sq" },
    { label: "Controller", color: ENTITY.controller, shape: "di" },
    { label: "Hijacked node", color: STATUS.missed, shape: "sq" },
    { label: "Honest vehicle", color: ENTITY.vehicleClean, shape: "ci" },
    { label: "Lie — caught", color: STATUS.caught, shape: "ci" },
    { label: "Lie — missed", color: STATUS.missed, shape: "ci" },
    { label: "Ghost identity", color: ENTITY.ghost, shape: "x" },
    { label: "Traffic signal (colour = live phase)", color: STATUS.caught, shape: "tri" },
  ];
}

const LAYER_DEFAULTS: LayerToggles = {
  streets: true,
  coverage: true,
  trails: true,
  rubberBands: true,
  controllerLinks: false,
  hideIdle: true,
  trafficSignals: false,
  activeOnly: true,
};

const LAYER_CHIPS: { k: keyof LayerToggles; label: string }[] = [
  { k: "streets", label: "Street map" },
  { k: "coverage", label: "Radio range" },
  { k: "trails", label: "Movement trails" },
  { k: "rubberBands", label: "Claim → truth" },
  { k: "controllerLinks", label: "Controller links" },
  { k: "hideIdle", label: "Hide idle vehicles" },
  { k: "trafficSignals", label: "Traffic signals" },
  { k: "activeOnly", label: "Active participants only" },
];

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

/** Closes on outside click / Escape — the same popover discipline as ScenarioPicker. */
function useDismiss(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) close();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, close]);
  return ref;
}

function MapSettings() {
  const { layers, toggleLayer, mapDetail, setMapDetail } = usePlayback();
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);
  const ref = useDismiss(open, close);
  const activeStep = DETAIL_STEPS.find((s) => s.level === mapDetail) ?? DETAIL_STEPS[2];
  const changedCount = LAYER_CHIPS.filter((c) => layers[c.k] !== LAYER_DEFAULTS[c.k]).length;

  const resetLayers = () => {
    (Object.keys(LAYER_DEFAULTS) as (keyof LayerToggles)[]).forEach((k) => {
      if (layers[k] !== LAYER_DEFAULTS[k]) toggleLayer(k);
    });
  };

  return (
    <div ref={ref} className="pointer-events-auto absolute left-3 top-3 z-10">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 rounded-md border border-surface-hairline2 bg-surface-panel/95 px-2.5 py-1.5 font-mono text-[10px] font-medium text-ink-secondary shadow-lg backdrop-blur transition-colors hover:text-ink-primary"
      >
        <SlidersHorizontal size={12} aria-hidden />
        Map Settings
        {changedCount > 0 && <span className="text-ink-muted">({changedCount})</span>}
      </button>

      {open && (
        <div className="anim-rise mt-1.5 w-[300px] rounded-lg border border-surface-hairline2 bg-surface-panel/95 p-3 shadow-2xl backdrop-blur">
          <div className="mb-1.5 flex items-center justify-between">
            <span className="text-[9px] font-bold uppercase tracking-widest text-ink-muted">
              Detail level
            </span>
            <button onClick={close} aria-label="Close map settings" className="text-ink-muted hover:text-ink-primary">
              <X size={13} />
            </button>
          </div>
          <div className="flex gap-1">
            {DETAIL_STEPS.map((s) => (
              <button
                key={s.level}
                onClick={() => setMapDetail(s.level)}
                className={`flex-1 rounded px-2 py-1 text-[10.5px] font-semibold transition-colors ${
                  mapDetail === s.level
                    ? "bg-entity-rsu text-white"
                    : "bg-surface-raised text-ink-secondary hover:text-ink-primary"
                }`}
              >
                {s.label}
              </button>
            ))}
          </div>
          <p className="mb-1.5 mt-1.5 text-[10px] leading-relaxed text-ink-muted">{activeStep.note}</p>

          <div className="mb-1.5 flex items-center justify-between border-t border-surface-hairline pt-2">
            <span className="text-[9px] font-bold uppercase tracking-widest text-ink-muted">Layers</span>
            {changedCount > 0 && (
              <button onClick={resetLayers} className="font-mono text-[9.5px] text-ink-muted hover:text-ink-primary">
                ↺ reset
              </button>
            )}
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
    </div>
  );
}

function MapLegend() {
  const { ENTITY, STATUS } = useTokens();
  const legendItems = buildLegendItems(ENTITY, STATUS);
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);
  const ref = useDismiss(open, close);

  return (
    <div ref={ref} className="pointer-events-auto absolute bottom-3 left-3 z-10">
      {open && (
        <div className="anim-rise mb-1.5 rounded-lg border border-surface-hairline2 bg-surface-panel/95 p-2.5 shadow-2xl backdrop-blur">
          <div className="mb-1.5 text-[9px] font-bold uppercase tracking-widest text-ink-muted">
            Shape = class · colour = state
          </div>
          <ul className="grid grid-cols-2 gap-x-4 gap-y-1">
            {legendItems.map((it) => (
              <li key={it.label} className="flex items-center gap-2 whitespace-nowrap text-[10.5px] text-ink-secondary">
                <Swatch color={it.color} shape={it.shape} />
                {it.label}
              </li>
            ))}
          </ul>
        </div>
      )}
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2.5 rounded-md border border-surface-hairline2 bg-surface-panel/95 px-2.5 py-1.5 font-mono text-[10px] font-medium text-ink-secondary shadow-lg backdrop-blur transition-colors hover:text-ink-primary"
      >
        <span className="flex items-center gap-1">
          <Swatch color={ENTITY.vehicleClean} shape="ci" /> Vehicle
        </span>
        <span className="flex items-center gap-1">
          <Swatch color={ENTITY.rsu} shape="sq" /> Sensor
        </span>
        <span className="flex items-center gap-1">
          <Swatch color={ENTITY.controller} shape="di" /> Controller
        </span>
        <span className="text-ink-muted">━ Position gap</span>
      </button>
    </div>
  );
}

export default function MapControls() {
  return (
    <>
      <MapSettings />
      <MapLegend />
    </>
  );
}
