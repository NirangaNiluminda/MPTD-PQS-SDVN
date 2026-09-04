import { Handle, Position, NodeProps, EdgeProps, BaseEdge, EdgeLabelRenderer, getSmoothStepPath } from "@xyflow/react";
import { Skull, CloudAlert, Mail, MailWarning, Fingerprint, TrafficCone, Ban, Server, RadioTower, Car, Ghost } from "lucide-react";
import { useTheme } from "../../store/theme";
import { PacketKind, PACKET_COLOR } from "./attackModelData";

export interface ThreatNodeData {
  label: string;
  kind: "controller" | "rsu" | "car" | "ghost";
  hasSkull: boolean;
  hasCloudBadge: boolean;
  [key: string]: unknown;
}

const NODE_ICON: Record<ThreatNodeData["kind"], typeof Server> = {
  controller: Server,
  rsu: RadioTower,
  car: Car,
  ghost: Ghost,
};

// Fixed handle-id pairs for the small set of directed edges this fixed
// triangular topology actually uses — see attackModelData.ts's own comment
// for the full enumeration. Anonymous handles would leave React Flow to
// guess which of a node's several top/bottom handles an edge means (a node
// like RSU needs BOTH an up-link and a down-link handle since edges flow
// in either direction depending on the step), so every edge built from
// ThreatStep.edges must resolve source/target handle ids through this table
// rather than leaving them undefined.
export const EDGE_HANDLES: Record<string, { sourceHandle: string; targetHandle: string }> = {
  "car1->rsu": { sourceHandle: "car1-top-s", targetHandle: "rsu-bottom-t" },
  "rsu->ctrl": { sourceHandle: "rsu-top-s", targetHandle: "ctrl-bottom-t" },
  "ctrl->rsu": { sourceHandle: "ctrl-bottom-s", targetHandle: "rsu-top-t" },
  "rsu->car1": { sourceHandle: "rsu-bottom-s", targetHandle: "car1-top-t" },
  "rsu->car2": { sourceHandle: "rsu-bottom-s", targetHandle: "car2-top-t" },
  "attacker->rsu": { sourceHandle: "attacker-top-s", targetHandle: "rsu-bottom-t" },
  "car1->attacker": { sourceHandle: "car1-right-s", targetHandle: "attacker-left-t" },
  // Fabricated Sybil identities (Figures 3.4/3.5) — same rsu-bottom-t target
  // handle real cars and the attacker already share; React Flow allows
  // multiple edges to converge on one handle, which is exactly the visual
  // this needs (several fake identities landing on the RSU at once).
  "ghost1->rsu": { sourceHandle: "ghost1-top-s", targetHandle: "rsu-bottom-t" },
  "ghost2->rsu": { sourceHandle: "ghost2-top-s", targetHandle: "rsu-bottom-t" },
};

/** One node component for all 5 fixed topology positions, differentiated by
 * data.kind — every handle this graph's 7 distinct directed edges (see
 * EDGE_HANDLES) ever need is declared once here, whether or not the current
 * step happens to use it. */
export function ThreatNode({ data, id }: NodeProps) {
  const d = data as unknown as ThreatNodeData;
  const theme = useTheme((s) => s.theme);
  const Icon = NODE_ICON[d.kind];
  const isGhost = d.kind === "ghost";
  const accent = d.kind === "controller" ? "#a855f7" : d.kind === "rsu" ? "#f59e0b" : isGhost ? "#3b82f6" : "#38bdf8";
  const bg = theme === "dark" ? "bg-slate-900" : "bg-white";
  const text = theme === "dark" ? "text-slate-100" : "text-slate-800";
  const sub = "text-slate-500"; // mid-gray reads fine against either surface

  return (
    <div
      className={`relative flex w-[190px] flex-col items-center gap-2 rounded-xl border-2 ${bg} ${text} px-3.5 py-3.5 text-center shadow-lg transition-shadow duration-300 ${
        isGhost ? "opacity-70" : ""
      }`}
      style={{ borderColor: accent, borderStyle: isGhost ? "dashed" : "solid" }}
    >
      {id === "car1" && (
        <>
          <Handle type="source" position={Position.Top} id="car1-top-s" className="!bg-slate-500" />
          <Handle type="target" position={Position.Top} id="car1-top-t" className="!bg-slate-500" style={{ left: "35%" }} />
          <Handle type="source" position={Position.Right} id="car1-right-s" className="!bg-slate-500" />
        </>
      )}
      {id === "attacker" && (
        <>
          <Handle type="target" position={Position.Left} id="attacker-left-t" className="!bg-slate-500" />
          <Handle type="source" position={Position.Top} id="attacker-top-s" className="!bg-slate-500" />
        </>
      )}
      {id === "car2" && <Handle type="target" position={Position.Top} id="car2-top-t" className="!bg-slate-500" />}
      {id === "ghost1" && <Handle type="source" position={Position.Top} id="ghost1-top-s" className="!bg-blue-500" />}
      {id === "ghost2" && <Handle type="source" position={Position.Top} id="ghost2-top-s" className="!bg-blue-500" />}
      {id === "rsu" && (
        <>
          <Handle type="target" position={Position.Bottom} id="rsu-bottom-t" className="!bg-slate-500" style={{ left: "35%" }} />
          <Handle type="source" position={Position.Bottom} id="rsu-bottom-s" className="!bg-slate-500" style={{ left: "65%" }} />
          <Handle type="source" position={Position.Top} id="rsu-top-s" className="!bg-slate-500" style={{ left: "35%" }} />
          <Handle type="target" position={Position.Top} id="rsu-top-t" className="!bg-slate-500" style={{ left: "65%" }} />
        </>
      )}
      {id === "ctrl" && (
        <>
          <Handle type="target" position={Position.Bottom} id="ctrl-bottom-t" className="!bg-slate-500" style={{ left: "35%" }} />
          <Handle type="source" position={Position.Bottom} id="ctrl-bottom-s" className="!bg-slate-500" style={{ left: "65%" }} />
        </>
      )}

      {d.hasSkull && (
        <div
          className="absolute -right-3 -top-3 flex h-7 w-7 items-center justify-center rounded-full border-2 border-white shadow-md"
          style={{ background: "#dc2626" }}
          title="Compromised entity"
        >
          <Skull size={14} className="text-white" strokeWidth={2.5} />
        </div>
      )}
      {d.hasCloudBadge && (
        <div
          className="absolute -left-3 -top-3 flex h-7 w-7 items-center justify-center rounded-full border-2 border-white shadow-md"
          style={{ background: "#7c3aed" }}
          title="Controller deceived — fake safe / fake collision model"
        >
          <CloudAlert size={14} className="text-white" strokeWidth={2.5} />
        </div>
      )}

      <Icon size={24} style={{ color: accent }} strokeWidth={2} />
      <span className="text-[14px] font-semibold leading-tight">{d.label}</span>
      {d.hasCloudBadge && <span className="text-[10.5px] font-medium uppercase tracking-wide text-purple-400">deceived</span>}
      <span className={`text-[11px] ${sub}`}>{isGhost ? "fabricated identity" : d.hasSkull ? "COMPROMISED" : "honest"}</span>
    </div>
  );
}

export const threatNodeTypes = { threatNode: ThreatNode };

// ── CUSTOM ANIMATED "PACKET" EDGE ────────────────────────────────────────
export interface ThreatEdgeData {
  kind: PacketKind;
  [key: string]: unknown;
}

const PACKET_ICON: Record<PacketKind, typeof Mail> = {
  honest: Mail,
  poisoned: MailWarning,
  sybil: Fingerprint,
  faulty_control: TrafficCone,
  blocked: Ban,
};

export function ThreatEdge({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, data, label }: EdgeProps) {
  const d = data as unknown as ThreatEdgeData;
  const color = PACKET_COLOR[d.kind];
  const Icon = PACKET_ICON[d.kind];
  const blocked = d.kind === "blocked";

  const [path, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
    borderRadius: 10,
  });

  return (
    <>
      {/* animated:true (set by the caller on every non-blocked edge) applies
          xyflow's own built-in dash-flow keyframes via the react-flow__edge-
          animated class already shipped in @xyflow/react/dist/style.css —
          no custom keyframe needed here, just the color/glow/dash overrides. */}
      <BaseEdge
        id={id}
        path={path}
        style={{
          stroke: color,
          strokeWidth: 2.5,
          strokeDasharray: blocked ? "3 4" : "6 4",
          filter: `drop-shadow(0 0 6px ${color}CC)`,
          opacity: blocked ? 0.6 : 1,
        }}
      />
      <EdgeLabelRenderer>
        <div
          className="pointer-events-none absolute flex flex-col items-center gap-0.5"
          style={{ transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)` }}
        >
          <div
            className="flex h-6 w-6 items-center justify-center rounded-full border-2 border-white shadow-md"
            style={{ background: color, filter: `drop-shadow(0 0 8px ${color}CC)` }}
          >
            <Icon size={12} className="text-white" strokeWidth={2.5} />
          </div>
          {typeof label === "string" && (
            <span
              className="whitespace-nowrap rounded px-2 py-1 text-[11px] font-semibold text-white shadow"
              style={{ background: `${color}E6` }}
            >
              {label}
            </span>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

export const threatEdgeTypes = { threatEdge: ThreatEdge };
