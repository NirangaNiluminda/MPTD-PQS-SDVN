import { Handle, Position, NodeProps } from "@xyflow/react";
import { useTheme } from "../../store/theme";

export type NodeCategory = "ai" | "rsu" | "blockchain" | "crypto" | "alert" | "generic" | "vehicle" | "cloud";
export type NodeStatus = "idle" | "evaluating" | "pass" | "flagged";

export interface ArchNodeData {
  label: string;
  subtitle?: string;
  category: NodeCategory;
  algoRef?: string;
  drillable?: boolean;
  status?: NodeStatus;
  [key: string]: unknown;
}

// Spec's exact category palette — a deliberate departure from this app's
// validated chart palette (design/tokens.ts), which is built and CVD-tested
// for DATA encoding (map dots, status quartets, chart series). This is an
// architecture diagram, not a data chart: every node also carries a text
// label, so color here is a wayfinding aid, not the sole channel of
// meaning — the same mitigation this app's own token file requires
// elsewhere before relying on hue at all.
//
// Kept as two explicit light/dark maps (not a CSS-variable trick) because
// these are literal Tailwind utility classes, not this app's surface/ink
// tokens — the whole screen used to hardcode the DARK half of this only,
// which is why it stayed black under the global light-theme toggle (a real,
// confirmed bug: verified live that the rest of the app's chrome went light
// while this canvas stayed bg-slate-950 regardless).
const CATEGORY_STYLE: Record<"dark" | "light", Record<NodeCategory, { border: string; bg: string; text: string; badge: string }>> = {
  dark: {
    ai: { border: "border-cyan-500", bg: "bg-cyan-950/40", text: "text-cyan-300", badge: "bg-cyan-500/20 text-cyan-300" },
    rsu: { border: "border-amber-500", bg: "bg-amber-950/40", text: "text-amber-300", badge: "bg-amber-500/20 text-amber-300" },
    blockchain: { border: "border-purple-500", bg: "bg-purple-950/40", text: "text-purple-300", badge: "bg-purple-500/20 text-purple-300" },
    crypto: { border: "border-emerald-500", bg: "bg-emerald-950/40", text: "text-emerald-300", badge: "bg-emerald-500/20 text-emerald-300" },
    alert: { border: "border-rose-500", bg: "bg-rose-950/40", text: "text-rose-300", badge: "bg-rose-500/20 text-rose-300" },
    vehicle: { border: "border-slate-500", bg: "bg-slate-800/60", text: "text-slate-200", badge: "bg-slate-500/20 text-slate-300" },
    cloud: { border: "border-sky-500", bg: "bg-sky-950/40", text: "text-sky-300", badge: "bg-sky-500/20 text-sky-300" },
    generic: { border: "border-slate-600", bg: "bg-slate-800/60", text: "text-slate-200", badge: "bg-slate-500/20 text-slate-300" },
  },
  light: {
    ai: { border: "border-cyan-600", bg: "bg-cyan-50", text: "text-cyan-800", badge: "bg-cyan-100 text-cyan-800" },
    rsu: { border: "border-amber-600", bg: "bg-amber-50", text: "text-amber-800", badge: "bg-amber-100 text-amber-800" },
    blockchain: { border: "border-purple-600", bg: "bg-purple-50", text: "text-purple-800", badge: "bg-purple-100 text-purple-800" },
    crypto: { border: "border-emerald-600", bg: "bg-emerald-50", text: "text-emerald-800", badge: "bg-emerald-100 text-emerald-800" },
    alert: { border: "border-rose-600", bg: "bg-rose-50", text: "text-rose-800", badge: "bg-rose-100 text-rose-800" },
    vehicle: { border: "border-slate-400", bg: "bg-slate-100", text: "text-slate-800", badge: "bg-slate-200 text-slate-700" },
    cloud: { border: "border-sky-600", bg: "bg-sky-50", text: "text-sky-800", badge: "bg-sky-100 text-sky-800" },
    generic: { border: "border-slate-400", bg: "bg-slate-100", text: "text-slate-800", badge: "bg-slate-200 text-slate-700" },
  },
};

const STATUS_RING: Record<NodeStatus, string> = {
  idle: "",
  evaluating: "ring-2 ring-sky-400 shadow-[0_0_16px_rgba(56,189,248,0.55)] animate-pulse",
  pass: "ring-2 ring-emerald-400 shadow-[0_0_16px_rgba(52,211,153,0.55)]",
  flagged: "ring-2 ring-rose-500 shadow-[0_0_16px_rgba(244,63,94,0.6)]",
};

/** The one custom node type this whole diagram uses, differentiated by
 * data.category/status rather than by registering many node types — keeps
 * React Flow's nodeTypes map trivial and every visual rule in one place. */
export function ArchNode({ data }: NodeProps) {
  const d = data as unknown as ArchNodeData;
  const theme = useTheme((s) => s.theme);
  const style = CATEGORY_STYLE[theme][d.category] ?? CATEGORY_STYLE[theme].generic;
  const ring = STATUS_RING[d.status ?? "idle"];
  const subtitleColor = theme === "dark" ? "text-slate-400" : "text-slate-600";
  const hintColor = "text-slate-500"; // mid-gray reads fine against either surface

  return (
    <div
      className={`min-w-[215px] max-w-[280px] rounded-lg border-2 ${style.border} ${style.bg} px-3.5 py-3 text-left shadow-lg transition-shadow duration-300 ${ring} ${
        d.drillable ? "cursor-pointer hover:brightness-125" : ""
      }`}
    >
      <Handle type="target" position={Position.Top} className="!bg-slate-500" />
      <Handle type="target" position={Position.Left} className="!bg-slate-500" />
      <div className="flex items-start justify-between gap-2">
        <span className={`text-[14.5px] font-semibold leading-tight ${style.text}`}>{d.label}</span>
        {d.status === "pass" && <span className="shrink-0 text-emerald-500">✓</span>}
        {d.status === "flagged" && <span className="shrink-0 text-rose-500">⚑</span>}
      </div>
      {d.subtitle && <p className={`mt-1 text-[12px] leading-snug ${subtitleColor}`}>{d.subtitle}</p>}
      {d.algoRef && (
        <span className={`mt-2 inline-block rounded px-1.5 py-0.5 font-mono text-[10.5px] font-semibold ${style.badge}`}>
          {d.algoRef}
        </span>
      )}
      {d.drillable && <span className={`mt-1.5 block text-[10.5px] font-medium ${hintColor}`}>click to open →</span>}
      <Handle type="source" position={Position.Bottom} className="!bg-slate-500" />
      <Handle type="source" position={Position.Right} className="!bg-slate-500" />
    </div>
  );
}

/** Diamond decision node — Level 3 flowcharts use rectangles for process
 * steps (the default ArchNode above) and this shape specifically for
 * branching conditions, per the spec's flowchart-notation requirement. */
export function DecisionNode({ data }: NodeProps) {
  const d = data as unknown as ArchNodeData;
  const theme = useTheme((s) => s.theme);
  const ring = STATUS_RING[d.status ?? "idle"];
  const diamond = theme === "dark" ? "border-amber-400 bg-amber-950/50" : "border-amber-500 bg-amber-100";
  const label = theme === "dark" ? "text-amber-200" : "text-amber-900";
  return (
    <div className={`relative flex h-[104px] w-[172px] items-center justify-center transition-shadow duration-300 ${ring}`}>
      <div className={`absolute inset-0 rotate-45 rounded-md border-2 ${diamond}`} />
      <Handle type="target" position={Position.Top} className="!bg-slate-500" />
      <span className={`relative px-5 text-center text-[12.5px] font-semibold leading-tight ${label}`}>{d.label}</span>
      <Handle type="source" position={Position.Bottom} id="yes" className="!bg-slate-500" style={{ left: "30%" }} />
      <Handle type="source" position={Position.Right} id="no" className="!bg-slate-500" />
    </div>
  );
}

export const architectureNodeTypes = { archNode: ArchNode, decision: DecisionNode };
