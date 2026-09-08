import { useEffect, useMemo, useRef, useState } from "react";
import { ReactFlow, Background, BackgroundVariant, Controls, Node, Edge, ReactFlowProvider, useReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Play, Pause, SkipBack, SkipForward, ArrowLeft, Maximize, Minimize } from "lucide-react";
import { threatNodeTypes, threatEdgeTypes, ThreatNodeData, ThreatEdgeData, EDGE_HANDLES } from "../components/attackmodel/ThreatModelNodes";
import {
  THREAT_NODES,
  VARIANTS,
  VARIANT_ORDER,
  CATEGORY_LABEL,
  CATEGORY_CARD,
  PACKET_COLOR,
  ViewMode,
  VariantCode,
  Category,
} from "../components/attackmodel/attackModelData";
import { ACTOR_LABEL, ACTOR_GLYPH } from "./AttackExplainerScreen";
import { useTheme } from "../store/theme";

const STEP_MS = 2000;

const PACKET_LEGEND: { kind: keyof typeof PACKET_COLOR; label: string }[] = [
  { kind: "honest", label: "Honest data / safe BSM" },
  { kind: "poisoned", label: "Poisoned / falsified data" },
  { kind: "sybil", label: "Impersonated Sybil packet" },
  { kind: "faulty_control", label: "Faulty control packet" },
  { kind: "blocked", label: "Suppressed / blocked warning" },
];

function TaxonomyCard({ category, onPick }: { category: Category; onPick: (v: VariantCode) => void }) {
  const card = CATEGORY_CARD[category];
  const accent = category === "trajectory" ? "#38bdf8" : "#ec4899";
  return (
    <div
      className="flex flex-1 flex-col gap-3 rounded-2xl border-2 bg-surface-panel p-5"
      style={{ borderColor: `${accent}66` }}
    >
      <h3 className="text-section-title text-ink-primary">{CATEGORY_LABEL[category]}</h3>
      <p className="text-body leading-relaxed text-ink-secondary">{card.summary}</p>
      <button
        onClick={() => onPick(category === "trajectory" ? "a1" : "a3")}
        className="mt-auto self-start rounded-md px-3 py-1.5 text-xs font-semibold text-white transition-opacity hover:opacity-90"
        style={{ background: accent }}
      >
        Explore a variant →
      </button>
    </div>
  );
}

function VariantButton({ code, active, onClick }: { code: VariantCode; active: boolean; onClick: () => void }) {
  const v = VARIANTS[code];
  const accent = v.category === "trajectory" ? "#38bdf8" : "#ec4899";
  return (
    <button
      onClick={onClick}
      className={`flex flex-col items-start gap-1 rounded-lg border-2 p-3 text-left transition-colors ${
        active ? "bg-surface-raised" : "border-surface-hairline bg-surface-panel hover:bg-surface-raised"
      }`}
      style={active ? { borderColor: accent } : undefined}
    >
      <span className="font-mono text-[11.5px] font-bold uppercase tracking-wide" style={{ color: accent }}>
        {v.paperCode} · {v.plane === "data" ? "Data plane" : "Control plane"}
      </span>
      <span className="text-[14.5px] font-semibold leading-tight text-ink-primary">{v.label}</span>
      <span className="text-[12px] leading-snug text-ink-muted">{v.description}</span>
    </button>
  );
}

function TaxonomyOverview({ onPick }: { onPick: (v: VariantCode) => void }) {
  return (
    <div className="h-full overflow-y-auto p-6">
      <div className="mx-auto flex max-w-5xl flex-col gap-6">
        <div className="flex flex-col gap-4 sm:flex-row">
          <TaxonomyCard category="trajectory" onPick={onPick} />
          <TaxonomyCard category="mobility_pattern" onPick={onPick} />
        </div>

        <div>
          <p className="mb-2 text-[13px] font-semibold uppercase tracking-wider text-ink-muted">
            All 7 variants — click one to step through it
          </p>
          <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
            {VARIANT_ORDER.map((code) => (
              <VariantButton key={code} code={code} active={false} onClick={() => onPick(code)} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function VariantCanvas({ variant, stepIndex }: { variant: VariantCode; stepIndex: number }) {
  const v = VARIANTS[variant];
  const step = v.steps[stepIndex];
  const theme = useTheme((s) => s.theme);

  // The paper's own figures (3.1–3.7) never draw a separate "attacker
  // vehicle" for the four variants where the RSU or the Controller itself
  // is the compromised entity (a1, a3, a5, a7) — verified directly against
  // those figures. A fixed 5-node topology rendered that node anyway, doing
  // nothing, in every variant. Instead of hardcoding which variants omit
  // it, derive the used node set from the variant's own step data (any id
  // that ever appears as an edge endpoint or a skull/deceived target across
  // ALL its steps) — computed once per variant, not per step, so the
  // topology stays stable through that variant's whole walkthrough and
  // only differs BETWEEN variants.
  const usedNodeIds = useMemo(() => {
    const ids = new Set<string>();
    for (const s of v.steps) {
      if (s.skullNode) ids.add(s.skullNode);
      if (s.deceivedNode) ids.add(s.deceivedNode);
      for (const e of s.edges) {
        ids.add(e.source);
        ids.add(e.target);
      }
    }
    return ids;
  }, [v]);

  const nodes: Node<ThreatNodeData>[] = useMemo(
    () =>
      THREAT_NODES.filter((n) => usedNodeIds.has(n.id)).map((n) => ({
        id: n.id,
        type: "threatNode",
        position: { x: n.x, y: n.y },
        data: {
          label: n.label,
          kind: n.kind,
          hasSkull: step.skullNode === n.id,
          hasCloudBadge: step.deceivedNode === n.id,
        },
      })),
    [step, usedNodeIds]
  );

  const edges: Edge<ThreatEdgeData>[] = useMemo(
    () =>
      step.edges.map((e, i) => {
        const handles = EDGE_HANDLES[`${e.source}->${e.target}`];
        return {
          id: `${variant}-${stepIndex}-${i}`,
          source: e.source,
          target: e.target,
          sourceHandle: handles?.sourceHandle,
          targetHandle: handles?.targetHandle,
          type: "threatEdge",
          animated: e.kind !== "blocked",
          label: e.label,
          data: { kind: e.kind },
        };
      }),
    [step, variant, stepIndex]
  );

  const { fitView } = useReactFlow();
  useEffect(() => {
    const id = requestAnimationFrame(() => fitView({ padding: 0.3, duration: 200 }));
    return () => cancelAnimationFrame(id);
  }, [variant, fitView]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={threatNodeTypes}
      edgeTypes={threatEdgeTypes}
      proOptions={{ hideAttribution: true }}
      minZoom={0.4}
      maxZoom={1.5}
      colorMode={theme}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
    >
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color={theme === "dark" ? "#1e293b" : "#c7d0da"} />
      <Controls
        showInteractive={false}
        className="!bg-surface-panel [&_button]:!border-surface-hairline [&_button]:!bg-surface-panel [&_button]:!fill-ink-secondary"
      />
    </ReactFlow>
  );
}

function VariantSidebar({
  variant,
  stepIndex,
  onNext,
  onPrev,
  isPlaying,
  onTogglePlay,
}: {
  variant: VariantCode;
  stepIndex: number;
  onNext: () => void;
  onPrev: () => void;
  isPlaying: boolean;
  onTogglePlay: () => void;
}) {
  const v = VARIANTS[variant];
  const step = v.steps[stepIndex];
  const accent = v.category === "trajectory" ? "#38bdf8" : "#ec4899";
  const finished = stepIndex >= v.steps.length - 1;

  return (
    <div className="flex w-[320px] shrink-0 flex-col gap-4 overflow-y-auto border-l border-surface-hairline bg-surface-panel p-4">
      <div>
        <span className="font-mono text-[11.5px] font-bold uppercase tracking-wide" style={{ color: accent }}>
          {v.paperCode} · attack #{v.attackNumber}
        </span>
        <h3 className="mt-0.5 text-section-title text-ink-primary">{v.label}</h3>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <span
            className="rounded-full px-2 py-0.5 text-[11px] font-semibold text-white"
            style={{ background: v.plane === "data" ? "#0284c7" : "#7c3aed" }}
          >
            {v.plane === "data" ? "Data plane" : "Control plane"}
          </span>
          <span className="rounded-full bg-surface-raised px-2 py-0.5 text-[11px] font-medium text-ink-secondary">
            {ACTOR_GLYPH[v.actor] ?? "●"} {ACTOR_LABEL[v.actor] ?? v.actor}
          </span>
        </div>
      </div>

      <p className="text-[13.5px] leading-relaxed text-ink-secondary">{v.description}</p>

      <div className="rounded-lg border border-surface-hairline bg-surface-raised p-3">
        <div className="flex items-center justify-between">
          <span className="text-[13px] font-semibold uppercase tracking-wide text-ink-muted">
            Step {stepIndex + 1} / {v.steps.length}
          </span>
          <span
            className="rounded px-1.5 py-0.5 font-mono text-[11px] font-bold text-white"
            style={{ background: accent }}
            title="The paper's own figure step number(s) this beat corresponds to — report/main.pdf Figures 3.1–3.7"
          >
            PAPER {step.paperSteps.toUpperCase()}
          </span>
        </div>
        <p className="mt-1.5 text-[14px] leading-relaxed text-ink-primary">{step.caption}</p>
      </div>

      <div>
        <div className="text-[13px] font-semibold uppercase tracking-wide text-ink-muted">Packet legend</div>
        <div className="mt-1.5 flex flex-col gap-1.5">
          {PACKET_LEGEND.map((p) => (
            <div key={p.kind} className="flex items-center gap-2 text-[12px] text-ink-secondary">
              <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: PACKET_COLOR[p.kind] }} />
              {p.label}
            </div>
          ))}
        </div>
      </div>

      <div className="mt-auto flex items-center justify-center gap-2 border-t border-surface-hairline pt-3">
        <button
          onClick={onPrev}
          disabled={stepIndex === 0}
          className="flex h-8 w-8 items-center justify-center rounded-full bg-surface-raised text-ink-secondary transition-colors hover:text-ink-primary disabled:cursor-not-allowed disabled:opacity-30"
          aria-label="Previous step"
        >
          <SkipBack size={14} />
        </button>
        <button
          onClick={onTogglePlay}
          disabled={finished && !isPlaying}
          className="flex h-10 w-10 items-center justify-center rounded-full text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-30"
          style={{ background: accent }}
          aria-label={isPlaying ? "Pause" : "Play"}
        >
          {isPlaying ? <Pause size={16} /> : <Play size={16} />}
        </button>
        <button
          onClick={onNext}
          disabled={finished}
          className="flex h-8 w-8 items-center justify-center rounded-full bg-surface-raised text-ink-secondary transition-colors hover:text-ink-primary disabled:cursor-not-allowed disabled:opacity-30"
          aria-label="Next step"
        >
          <SkipForward size={14} />
        </button>
      </div>
    </div>
  );
}

export default function AttackModelExplorerScreen() {
  const [viewMode, setViewMode] = useState<ViewMode>("TAXONOMY_OVERVIEW");
  const [selectedVariant, setSelectedVariant] = useState<VariantCode>("a1");
  const [currentStep, setCurrentStep] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  // Real browser Fullscreen (not a CSS "maximize") — same pattern as
  // Architecture Explorer / Network Replay, so Esc also exits it natively.
  useEffect(() => {
    const onChange = () => setIsFullscreen(document.fullscreenElement === rootRef.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  const toggleFullscreen = () => {
    if (document.fullscreenElement) {
      document.exitFullscreen();
    } else {
      rootRef.current?.requestFullscreen();
    }
  };

  const totalSteps = VARIANTS[selectedVariant].steps.length;

  // Auto-advance every STEP_MS while playing; stops itself at the last step
  // rather than looping — a finished walkthrough should read as "done", not
  // silently restart mid-glance.
  useEffect(() => {
    if (!isPlaying) return;
    if (currentStep >= totalSteps - 1) {
      setIsPlaying(false);
      return;
    }
    const t = window.setTimeout(() => setCurrentStep((s) => Math.min(s + 1, totalSteps - 1)), STEP_MS);
    return () => window.clearTimeout(t);
  }, [isPlaying, currentStep, totalSteps]);

  const pickVariant = (v: VariantCode) => {
    setSelectedVariant(v);
    setCurrentStep(0);
    setIsPlaying(false);
    setViewMode("VARIANT_EXPLORER");
  };

  const selectFromGrid = (v: VariantCode) => {
    if (v === selectedVariant && viewMode === "VARIANT_EXPLORER") return;
    setSelectedVariant(v);
    setCurrentStep(0);
    setIsPlaying(false);
  };

  return (
    <div ref={rootRef} className="flex h-full flex-col bg-surface-page">
      <div className="flex items-center justify-between border-b border-surface-hairline bg-surface-panel px-4 py-2.5">
        <div className="flex items-center gap-2 text-[13px]">
          {viewMode === "VARIANT_EXPLORER" ? (
            <button
              onClick={() => setViewMode("TAXONOMY_OVERVIEW")}
              className="flex items-center gap-1.5 rounded px-1.5 py-0.5 font-semibold text-ink-primary transition-colors hover:bg-surface-raised"
            >
              <ArrowLeft size={14} /> Back to taxonomy
            </button>
          ) : (
            <span className="font-semibold text-ink-primary">Attack taxonomy</span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {viewMode === "VARIANT_EXPLORER" && (
            <div className="flex flex-wrap items-center gap-1">
              {VARIANT_ORDER.map((code) => (
                <button
                  key={code}
                  onClick={() => selectFromGrid(code)}
                  className={`rounded px-2 py-1 font-mono text-[11.5px] font-semibold transition-colors ${
                    selectedVariant === code
                      ? "bg-entity-rsu text-white"
                      : "bg-surface-raised text-ink-secondary hover:text-ink-primary"
                  }`}
                >
                  {VARIANTS[code].paperCode}
                </button>
              ))}
            </div>
          )}
          <button
            onClick={toggleFullscreen}
            title={isFullscreen ? "Exit full screen" : "Full screen"}
            className="flex items-center gap-1.5 rounded bg-surface-raised px-2.5 py-1 text-[11.5px] font-medium text-ink-secondary transition-colors hover:text-ink-primary"
          >
            {isFullscreen ? <Minimize size={13} /> : <Maximize size={13} />}
            {isFullscreen ? "Exit full screen" : "Full screen"}
          </button>
        </div>
      </div>

      <div className="min-h-0 flex-1">
        {viewMode === "TAXONOMY_OVERVIEW" ? (
          <TaxonomyOverview onPick={pickVariant} />
        ) : (
          <div className="flex h-full">
            <div className="relative min-w-0 flex-1">
              <ReactFlowProvider>
                <VariantCanvas variant={selectedVariant} stepIndex={currentStep} />
              </ReactFlowProvider>
            </div>
            <VariantSidebar
              variant={selectedVariant}
              stepIndex={currentStep}
              onNext={() => setCurrentStep((s) => Math.min(s + 1, totalSteps - 1))}
              onPrev={() => setCurrentStep((s) => Math.max(s - 1, 0))}
              isPlaying={isPlaying}
              onTogglePlay={() => {
                if (!isPlaying && currentStep >= totalSteps - 1) setCurrentStep(0);
                setIsPlaying((p) => !p);
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
