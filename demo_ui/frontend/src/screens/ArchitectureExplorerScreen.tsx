import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Node,
  Edge,
  NodeMouseHandler,
  ReactFlowProvider,
  useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ChevronRight, Play, RotateCcw, Home, Maximize, Minimize, Code2, X } from "lucide-react";
import { architectureNodeTypes, ArchNodeData, NodeStatus } from "../components/architecture/ArchitectureNodes";
import { useTheme } from "../store/theme";
import {
  abstractGraph,
  LEVEL2_GRAPHS,
  ALGO_DETAIL_GRAPHS,
  ALGO_PSEUDOCODE,
  SCENARIOS,
  KEY_MGMT_SCENARIOS,
  ViewName,
  SubFlow,
  ScenarioName,
  KeyMgmtScenarioName,
  Scenario,
} from "../components/architecture/architectureData";

// Where each drillable node on a Level-1/Level-2 canvas leads. Kept as one
// explicit lookup rather than embedded per-node so the graph data files stay
// pure data (no navigation logic mixed into node definitions).
const DRILL_TARGETS: Record<string, { view: ViewName; subFlow?: SubFlow }> = {
  rsu: { view: "LIGHTWEIGHT_MODE" },
  ctrl: { view: "FULL_MODE" },
  // NOT FULL_MODE: verified directly (report/main.tex:3195-3232 +
  // 07_socket_layer.h:178-201) that the FHE/TRS pipeline is an RSU-ring +
  // Cloud exchange the controller has no part in — clicking Cloud should
  // not land on "Full Mode — SDVN Controller".
  cloud: { view: "ALGO_DETAIL", subFlow: "PQ_FHE_TRS" },
  chain: { view: "BLOCKCHAIN_LAYER" },
  "lw-tp": { view: "ALGO_DETAIL", subFlow: "TP_DETECT" },
  "lw-syb": { view: "ALGO_DETAIL", subFlow: "SYB_DETECT" },
  "lw-mitm": { view: "ALGO_DETAIL", subFlow: "MITM_DETECT" },
  "bc-cpdetect": { view: "ALGO_DETAIL", subFlow: "CP_DETECT" },
  "fm-trs": { view: "ALGO_DETAIL", subFlow: "PQ_FHE_TRS" },
  "bc-revoke": { view: "ALGO_DETAIL", subFlow: "SC_REVOKE" },
  "bc-register": { view: "ALGO_DETAIL", subFlow: "SC_REGISTER" },
  "km-rsu": { view: "ALGO_DETAIL", subFlow: "LKH_REKEY" },
  "km-ring": { view: "ALGO_DETAIL", subFlow: "DKG_KEYGEN" },
  "km-chain": { view: "BLOCKCHAIN_LAYER" },
};

const VIEW_LABEL: Record<ViewName, string> = {
  ABSTRACT: "System overview",
  LIGHTWEIGHT_MODE: "Lightweight Mode — RSU cluster",
  FULL_MODE: "Full Mode — SDVN controller",
  BLOCKCHAIN_LAYER: "Blockchain & trust layer",
  KEY_MANAGEMENT: "Key management & reassignment",
  ALGO_DETAIL: "Algorithm detail",
};

const KEY_MGMT_SUBFLOWS: SubFlow[] = ["DKG_KEYGEN", "LKH_REKEY"];

const SCENARIO_ORDER: ScenarioName[] = [
  "NORMAL",
  "TRAJECTORY_POISONING",
  "SYBIL_ATTACK",
  "MITM_ATTACK",
  "CONTROLLER_COMPROMISE",
];

function statusesForStep(steps: (typeof SCENARIOS)[ScenarioName]["steps"], uptoIndex: number) {
  const nodeStatus: Record<string, NodeStatus> = {};
  const litEdges = new Set<string>();
  for (let i = 0; i <= uptoIndex; i++) {
    const step = steps[i];
    for (const id of step.pass) nodeStatus[id] = "pass";
    for (const id of step.flagged) nodeStatus[id] = "flagged";
    for (const id of step.activeEdges) litEdges.add(id);
  }
  const current = steps[uptoIndex];
  for (const id of current.evaluating) {
    if (nodeStatus[id] === undefined) nodeStatus[id] = "evaluating";
  }
  return { nodeStatus, litEdges };
}

function Breadcrumb({
  view,
  subFlow,
  onJump,
}: {
  view: ViewName;
  subFlow: SubFlow;
  onJump: (view: ViewName, subFlow?: SubFlow) => void;
}) {
  const crumbs: { label: string; onClick: () => void }[] = [
    { label: "Architecture", onClick: () => onJump("ABSTRACT") },
  ];
  if (view !== "ABSTRACT") {
    if (view === "ALGO_DETAIL" && subFlow) {
      // Show the parent Level-2 view this algorithm belongs under, so the
      // trail reads as a real path, not just a bare "Algorithm detail" leaf.
      const parent: ViewName =
        subFlow === "CP_DETECT" || subFlow === "SC_REVOKE" || subFlow === "SC_REGISTER"
          ? "BLOCKCHAIN_LAYER"
          : subFlow === "PQ_FHE_TRS"
          ? "FULL_MODE"
          : subFlow === "DKG_KEYGEN" || subFlow === "LKH_REKEY"
          ? "KEY_MANAGEMENT"
          : "LIGHTWEIGHT_MODE";
      crumbs.push({ label: VIEW_LABEL[parent], onClick: () => onJump(parent) });
      crumbs.push({ label: ALGO_DETAIL_GRAPHS[subFlow].title.split(" — ")[0], onClick: () => onJump(view, subFlow) });
    } else {
      crumbs.push({ label: VIEW_LABEL[view], onClick: () => onJump(view) });
    }
  }
  return (
    <div className="flex items-center gap-1.5 text-[13px]">
      {crumbs.map((c, i) => (
        <span key={i} className="flex items-center gap-1.5">
          {i > 0 && <ChevronRight size={13} className="text-ink-muted" />}
          <button
            onClick={c.onClick}
            className={`rounded px-1.5 py-0.5 transition-colors ${
              i === crumbs.length - 1
                ? "font-semibold text-ink-primary"
                : "text-ink-muted hover:bg-surface-raised hover:text-ink-secondary"
            }`}
          >
            {i === 0 && <Home size={12} className="mr-1 inline -translate-y-px" />}
            {c.label}
          </button>
        </span>
      ))}
    </div>
  );
}

/**
 * The real algorithm pseudocode, verified against report/main.tex's own
 * algorithm environments — a deeper abstraction layer than the flowchart
 * (which shows the SHAPE of the decision logic; this shows the literal
 * steps as the thesis writes them, variable names included). An overlay,
 * not a permanent panel, so it doesn't compete with the canvas for space.
 */
function PseudocodePanel({ subFlow, onClose }: { subFlow: Exclude<SubFlow, null>; onClose: () => void }) {
  const blocks = ALGO_PSEUDOCODE[subFlow];
  return (
    <div className="absolute inset-y-0 right-0 z-10 flex w-full max-w-md flex-col border-l border-surface-hairline2 bg-surface-panel/97 shadow-2xl backdrop-blur">
      <div className="flex items-center justify-between border-b border-surface-hairline px-4 py-3">
        <div className="flex items-center gap-2">
          <Code2 size={15} className="text-emerald-500" />
          <span className="text-[13.5px] font-semibold uppercase tracking-wider text-ink-secondary">
            Real algorithm pseudocode
          </span>
        </div>
        <button onClick={onClose} className="rounded p-1 text-ink-muted hover:bg-surface-raised hover:text-ink-secondary">
          <X size={15} />
        </button>
      </div>
      <div className="flex-1 overflow-y-auto p-4">
        {blocks.map((block, bi) => (
          <div key={bi} className={bi > 0 ? "mt-5" : ""}>
            <p className="text-[14px] font-bold text-emerald-600">{block.title}</p>
            {block.inputs && (
              <p className="mt-1 font-mono text-[12px] text-ink-secondary">
                <span className="text-ink-muted">input:</span> {block.inputs}
              </p>
            )}
            {block.output && (
              <p className="mt-0.5 font-mono text-[12px] text-ink-secondary">
                <span className="text-ink-muted">output:</span> {block.output}
              </p>
            )}
            <ol className="mt-2.5 flex flex-col gap-1.5">
              {block.steps.map((step, si) => (
                <li key={si} className="flex gap-2 font-mono text-[12.5px] leading-relaxed text-ink-secondary">
                  <span className="shrink-0 text-ink-muted">{si + 1}.</span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>
        ))}
        <p className="mt-5 border-t border-surface-hairline pt-3 text-[11.5px] leading-relaxed text-ink-muted">
          Transcribed from report/main.tex's own algorithm environments (cross-checked against the compiled PDF) —
          not paraphrased from the flowchart, and not from the .h/.go source comments, which carry stale
          numbering from earlier drafts.
        </p>
      </div>
    </div>
  );
}

function SimulationPanel<S extends string>({
  label,
  scenarioOrder,
  scenarioLabel,
  scenario,
  setScenario,
  isSimulating,
  step,
  totalSteps,
  caption,
  description,
  startLabel,
  onStart,
  onNext,
  onReset,
}: {
  label: string;
  scenarioOrder: readonly S[];
  scenarioLabel: (s: S) => string;
  scenario: S;
  setScenario: (s: S) => void;
  isSimulating: boolean;
  step: number;
  totalSteps: number;
  caption: string | null;
  description: string;
  startLabel: string;
  onStart: () => void;
  onNext: () => void;
  onReset: () => void;
}) {
  const finished = isSimulating && step >= totalSteps - 1;
  return (
    <div className="flex flex-col gap-2 border-t border-surface-hairline bg-surface-panel/95 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11.5px] font-semibold uppercase tracking-wider text-ink-muted">{label}</span>
        <div className="flex flex-wrap gap-1">
          {scenarioOrder.map((s) => (
            <button
              key={s}
              onClick={() => setScenario(s)}
              disabled={isSimulating}
              className={`rounded px-2 py-1 text-[12.5px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                scenario === s ? "bg-entity-rsu text-white" : "bg-surface-raised text-ink-secondary hover:text-ink-primary"
              }`}
            >
              {scenarioLabel(s)}
            </button>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          {!isSimulating ? (
            <button
              onClick={onStart}
              className="flex items-center gap-1.5 rounded bg-emerald-600 px-3 py-1.5 text-[12.5px] font-semibold text-white hover:bg-emerald-500"
            >
              <Play size={13} /> {startLabel}
            </button>
          ) : (
            <>
              <button
                onClick={onNext}
                disabled={finished}
                className="rounded bg-entity-rsu px-3 py-1.5 text-[12.5px] font-semibold text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {finished ? "Complete" : `Step ${step + 1}/${totalSteps} — next →`}
              </button>
              <button
                onClick={onReset}
                className="flex items-center gap-1.5 rounded bg-surface-raised px-2.5 py-1.5 text-[12.5px] font-medium text-ink-secondary hover:text-ink-primary"
              >
                <RotateCcw size={13} /> Reset
              </button>
            </>
          )}
        </div>
      </div>
      <p className="text-[12.5px] leading-relaxed text-ink-secondary">
        {isSimulating && caption ? <span className="text-ink-primary">{caption}</span> : description}
      </p>
    </div>
  );
}

function ArchitectureCanvas({
  view,
  subFlow,
  onNodeClick,
  simulationOverlay,
}: {
  view: ViewName;
  subFlow: SubFlow;
  onNodeClick: (id: string) => void;
  simulationOverlay: { nodeStatus: Record<string, NodeStatus>; litEdges: Set<string> } | null;
}) {
  const graph = useMemo(() => {
    if (view === "ABSTRACT") return abstractGraph;
    if (view === "ALGO_DETAIL" && subFlow) return ALGO_DETAIL_GRAPHS[subFlow];
    return LEVEL2_GRAPHS[view] ?? abstractGraph;
  }, [view, subFlow]);

  const nodes: Node<ArchNodeData>[] = useMemo(
    () =>
      graph.nodes.map((nd) => ({
        ...nd,
        data: {
          ...nd.data,
          status: simulationOverlay?.nodeStatus[nd.id] ?? "idle",
        },
      })),
    [graph, simulationOverlay]
  );

  const edges: Edge[] = useMemo(
    () =>
      graph.edges.map((ed) => {
        const lit = simulationOverlay?.litEdges.has(ed.id);
        return lit
          ? {
              ...ed,
              animated: true,
              style: { ...ed.style, stroke: "#38bdf8", strokeWidth: 2.5 },
            }
          : ed;
      }),
    [graph, simulationOverlay]
  );

  const handleNodeClick: NodeMouseHandler = useCallback(
    (_e, node) => {
      onNodeClick(node.id);
    },
    [onNodeClick]
  );

  // `fitView` as a mount-time prop computes its bounding box before these
  // custom nodes (auto-sized via min-w/max-w, not a fixed width) have
  // actually been measured by the browser — verified directly: the
  // rightmost node in a wide pipeline (e.g. the Composite Anomaly Scorer)
  // rendered clipped past the viewport edge. Calling fitView() imperatively
  // after each graph swap, once layout has settled, fits the real
  // measured size instead of an estimate.
  const { fitView } = useReactFlow();
  useEffect(() => {
    const id = requestAnimationFrame(() => {
      fitView({ padding: 0.25, duration: 200 });
    });
    return () => cancelAnimationFrame(id);
  }, [graph, fitView]);

  // This whole screen used to hardcode colorMode="dark" plus literal
  // !bg-slate-* overrides on Controls/MiniMap — confirmed live (both dev and
  // production builds) that it stayed black under the app's global light-
  // theme toggle while every other screen correctly went light. `theme` here
  // drives xyflow's own light/dark chrome, and the Controls/MiniMap classes
  // now use this app's surface/ink tokens (which already flip with
  // data-theme) instead of fixed slate values.
  const theme = useTheme((s) => s.theme);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={architectureNodeTypes}
      onNodeClick={handleNodeClick}
      proOptions={{ hideAttribution: true }}
      minZoom={0.3}
      colorMode={theme}
      defaultEdgeOptions={{ type: "smoothstep" }}
    >
      <Background variant={BackgroundVariant.Dots} gap={22} size={1} color={theme === "dark" ? "#1e293b" : "#c7d0da"} />
      <Controls className="!bg-surface-panel [&_button]:!border-surface-hairline [&_button]:!bg-surface-panel [&_button]:!fill-ink-secondary" />
      <MiniMap
        className="!bg-surface-panel"
        maskColor={theme === "dark" ? "rgba(15,23,42,0.7)" : "rgba(238,241,245,0.75)"}
        nodeColor={theme === "dark" ? "#334155" : "#c7d0da"}
        pannable
        zoomable
        style={{ width: 130, height: 90 }}
      />
    </ReactFlow>
  );
}

const KEY_MGMT_SCENARIO_ORDER: KeyMgmtScenarioName[] = ["DKG_SETUP", "VEHICLE_REGISTRATION", "CONTROLLER_REASSIGNMENT"];

export default function ArchitectureExplorerScreen() {
  const [currentView, setCurrentView] = useState<ViewName>("ABSTRACT");
  const [selectedSubFlow, setSelectedSubFlow] = useState<SubFlow>(null);
  const [activeAttackScenario, setActiveAttackScenario] = useState<ScenarioName>("NORMAL");
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationStep, setSimulationStep] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showPseudocode, setShowPseudocode] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  // Key-management lifecycle (DKG setup / vehicle registration / controller
  // reassignment) is a separate scenario set from the attack-detection
  // SCENARIOS above — different graph, different node ids, and every step
  // stays on the one KEY_MANAGEMENT view instead of jumping views. Kept as
  // its own state rather than folded into the attack-scenario state so the
  // two simulations can never conflict with each other.
  const [kmScenario, setKmScenario] = useState<KeyMgmtScenarioName>("DKG_SETUP");
  const [kmSimulating, setKmSimulating] = useState(false);
  const [kmStep, setKmStep] = useState(0);
  const inKeyMgmtArea =
    currentView === "KEY_MANAGEMENT" ||
    (currentView === "ALGO_DETAIL" && !!selectedSubFlow && KEY_MGMT_SUBFLOWS.includes(selectedSubFlow));

  // The sidebar/header chrome around this screen eats into an already-dense
  // canvas — real browser Fullscreen (not just a CSS "maximize") gives the
  // diagram the whole monitor, and reacts to the user pressing Esc too
  // (native exit), not just our own button.
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

  const scenario = SCENARIOS[activeAttackScenario];
  const totalSteps = scenario.steps.length;
  const kmScenarioObj: Scenario = KEY_MGMT_SCENARIOS[kmScenario];
  const kmTotalSteps = kmScenarioObj.steps.length;

  // The controller-compromise scenario spans three views — when a step's
  // own view differs from the one on screen, follow it there automatically
  // rather than leaving the animation invisible on the wrong canvas.
  useEffect(() => {
    if (!isSimulating) return;
    const stepView = scenario.steps[simulationStep].view;
    if (stepView !== currentView) {
      setCurrentView(stepView);
      setSelectedSubFlow(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isSimulating, simulationStep, activeAttackScenario]);

  const jump = (view: ViewName, subFlow?: SubFlow) => {
    setIsSimulating(false);
    setSimulationStep(0);
    setKmSimulating(false);
    setKmStep(0);
    setCurrentView(view);
    setSelectedSubFlow(subFlow ?? null);
    setShowPseudocode(false);
  };

  const handleNodeClick = (id: string) => {
    if (isSimulating || kmSimulating) return; // don't let exploration clicks fight a running animation
    const target = DRILL_TARGETS[id];
    if (target) jump(target.view, target.subFlow);
  };

  const startSimulation = () => {
    setKmSimulating(false);
    setKmStep(0);
    setCurrentView(scenario.steps[0].view);
    setSelectedSubFlow(null);
    setSimulationStep(0);
    setIsSimulating(true);
  };

  const nextStep = () => setSimulationStep((s) => Math.min(s + 1, totalSteps - 1));

  const resetSimulation = () => {
    setIsSimulating(false);
    setSimulationStep(0);
  };

  // Key-management steps never change view (every step lives on
  // KEY_MANAGEMENT), so unlike the attack scenario's effect above, starting
  // this simulation just needs to land the canvas on that one view once.
  const startKmSimulation = () => {
    setIsSimulating(false);
    setSimulationStep(0);
    setCurrentView("KEY_MANAGEMENT");
    setSelectedSubFlow(null);
    setKmStep(0);
    setKmSimulating(true);
  };

  const nextKmStep = () => setKmStep((s) => Math.min(s + 1, kmTotalSteps - 1));

  const resetKmSimulation = () => {
    setKmSimulating(false);
    setKmStep(0);
  };

  const simulationOverlay =
    isSimulating && scenario.steps[simulationStep].view === currentView
      ? statusesForStep(scenario.steps, simulationStep)
      : kmSimulating && currentView === "KEY_MANAGEMENT"
      ? statusesForStep(kmScenarioObj.steps, kmStep)
      : null;

  return (
    <div ref={rootRef} className="flex h-full flex-col bg-surface-page">
      <div className="flex items-center justify-between border-b border-surface-hairline bg-surface-panel/95 px-4 py-2.5">
        <Breadcrumb view={currentView} subFlow={selectedSubFlow} onJump={jump} />
        <div className="flex items-center gap-2">
          <button
            onClick={toggleFullscreen}
            title={isFullscreen ? "Exit full screen" : "Full screen"}
            className="flex items-center gap-1.5 rounded bg-surface-raised px-2.5 py-1 text-[12.5px] font-medium text-ink-secondary hover:text-ink-primary"
          >
            {isFullscreen ? <Minimize size={12} /> : <Maximize size={12} />}
            {isFullscreen ? "Exit full screen" : "Full screen"}
          </button>
          {currentView !== "KEY_MANAGEMENT" && (
            <button
              onClick={() => jump("KEY_MANAGEMENT")}
              className="rounded bg-surface-raised px-2.5 py-1 text-[12.5px] font-medium text-ink-secondary hover:text-ink-primary"
            >
              Key management
            </button>
          )}
          {currentView === "ALGO_DETAIL" && selectedSubFlow && (
            <button
              onClick={() => setShowPseudocode((v) => !v)}
              className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-[12.5px] font-medium ${
                showPseudocode ? "bg-emerald-600 text-white" : "bg-surface-raised text-ink-secondary hover:text-ink-primary"
              }`}
            >
              <Code2 size={13} /> {showPseudocode ? "Hide pseudocode" : "Show real pseudocode"}
            </button>
          )}
          {currentView !== "ABSTRACT" && (
            <button
              onClick={() => jump("ABSTRACT")}
              className="rounded bg-surface-raised px-2.5 py-1 text-[12.5px] font-medium text-ink-secondary hover:text-ink-primary"
            >
              ← Back to overview
            </button>
          )}
        </div>
      </div>

      <div className="relative min-h-0 flex-1">
        <ReactFlowProvider>
          <ArchitectureCanvas
            view={currentView}
            subFlow={selectedSubFlow}
            onNodeClick={handleNodeClick}
            simulationOverlay={simulationOverlay}
          />
        </ReactFlowProvider>
        {showPseudocode && currentView === "ALGO_DETAIL" && selectedSubFlow && (
          <PseudocodePanel subFlow={selectedSubFlow} onClose={() => setShowPseudocode(false)} />
        )}
      </div>

      {inKeyMgmtArea ? (
        <SimulationPanel
          label="Scenario"
          scenarioOrder={KEY_MGMT_SCENARIO_ORDER}
          scenarioLabel={(s) => KEY_MGMT_SCENARIOS[s].label}
          scenario={kmScenario}
          setScenario={setKmScenario}
          isSimulating={kmSimulating}
          step={kmStep}
          totalSteps={kmTotalSteps}
          caption={kmSimulating ? kmScenarioObj.steps[kmStep].caption : null}
          description={kmScenarioObj.description}
          startLabel="Simulate lifecycle step"
          onStart={startKmSimulation}
          onNext={nextKmStep}
          onReset={resetKmSimulation}
        />
      ) : (
        <SimulationPanel
          label="Scenario"
          scenarioOrder={SCENARIO_ORDER}
          scenarioLabel={(s) => SCENARIOS[s].label}
          scenario={activeAttackScenario}
          setScenario={setActiveAttackScenario}
          isSimulating={isSimulating}
          step={simulationStep}
          totalSteps={totalSteps}
          caption={isSimulating ? scenario.steps[simulationStep].caption : null}
          description={scenario.description}
          startLabel="Simulate beacon epoch"
          onStart={startSimulation}
          onNext={nextStep}
          onReset={resetSimulation}
        />
      )}
    </div>
  );
}
