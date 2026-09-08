import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight } from "lucide-react";
import { useSemanticTokens, useTokens } from "../design/tokens";
import { SemanticStatus } from "./StatusPill";

/**
 * A small, looping, ILLUSTRATIVE architecture diagram — infrastructure
 * (buildings, RSUs, controllers) on top, the real detection/mitigation
 * pipeline (rule signatures -> GAT -> LSTM-AE -> fusion -> ledger) below.
 * Deliberately NOT bound to any real capture or replay data (every other
 * screen in this app is), and deliberately built to match the REAL
 * communication mechanics found in this project's own ns-3 source:
 *
 *  - every vehicle beacons roughly every 100 ms (09_vehicle_beacon_tx.h) —
 *    shown as a constant, fast stream of small packets in the global view.
 *  - vehicle -> RSU beacon is a UNICAST (send_lte_dataunicast_alone), not a
 *    broadcast; RSU -> vehicle control reply IS a broadcast on
 *    3.255.255.255:9999 — asymmetric with the uplink.
 *  - RSU selection is NOT nearest-RSU: best_rsu_for_position() scores by
 *    predicted link-lifetime / distance with 15% hysteresis, so a vehicle
 *    doesn't ping-pong at a coverage boundary (08_detection_engine.h §RSU-LL).
 *  - there is no real honest vehicle-to-vehicle broadcast in this system —
 *    the only "V2V" in the source is an attacker intercepting a nearby
 *    honest vehicle's beacon (MP-S3) — so this diagram doesn't show one.
 *  - a flagged beacon casts ONE revoke-vote, not an instant revocation —
 *    matches the real [SC-REVOKE-VOTE-RSUx] threshold=3 BFT mechanism.
 *
 * Filtering: at 100ms/beacon, showing every packet's full detection
 * breakdown for everyone at once is unreadable, so the global (unfocused)
 * view only shows the fast packet stream — no per-stage detail. Clicking a
 * vehicle, RSU, or controller focuses the view: everything else dims,
 * only that entity's traffic keeps flowing, and periodically one of its
 * beacons is pulled out and walked through the slow pipeline below, with
 * its own mitigation state (vote count / revocation), not a shared one.
 */

interface Pt {
  x: number;
  y: number;
}

const VIEW_W = 900;
const VIEW_H = 210;
const ROAD_Y = 150;
const ROAD_X0 = 40;
const ROAD_X1 = 860;
const ROAD_LEN = ROAD_X1 - ROAD_X0;
// Large enough that the two RSUs' coverage overlaps in the middle and each
// reaches its own edge of the road — no gap where a vehicle would be
// bonded to neither RSU and unable to beacon at all. (110 left a real
// ~180px dead zone between the two circles; 215 closes it with margin.)
const COVERAGE_R = 215;
const BEACON_INTERVAL_S = 0.1; // real cadence: ~100ms per beacon
const DETAIL_INTERVAL_S = 5; // how often a focused entity's beacon gets the slow walkthrough

const RSUS: (Pt & { label: string; ctrl: number })[] = [
  { x: 250, y: ROAD_Y, label: "RSU A", ctrl: 0 },
  { x: 650, y: ROAD_Y, label: "RSU B", ctrl: 1 },
];
const CONTROLLERS: (Pt & { label: string })[] = [
  { x: 250, y: 40, label: "Controller 0" },
  { x: 650, y: 40, label: "Controller 1" },
];
const BUILDINGS: (Pt & { w: number; h: number })[] = [
  { x: 90, y: 175, w: 34, h: 24 },
  { x: 420, y: 178, w: 28, h: 20 },
  { x: 470, y: 172, w: 22, h: 26 },
  { x: 780, y: 176, w: 36, h: 22 },
  { x: 160, y: 60, w: 26, h: 18 },
];

const CARS = [
  { speed: 16, offset: 0 },
  { speed: 11, offset: 260 },
  { speed: 20, offset: 520 },
];
const ATTACKED_IDX = 1; // "V2" — fixed and simple to reason about

function carX(t: number, i: number): number {
  const d = (((t * CARS[i].speed + CARS[i].offset) % ROAD_LEN) + ROAD_LEN) % ROAD_LEN;
  return ROAD_X0 + d;
}

function bondedRsu(x: number, current: number): number {
  const dist = (r: number) => Math.abs(x - RSUS[r].x);
  if (current >= 0 && dist(current) <= COVERAGE_R) return current; // hysteresis: keep current
  for (let r = 0; r < RSUS.length; r++) if (dist(r) <= COVERAGE_R) return r;
  return -1;
}

type Focus = { kind: "vehicle"; i: number } | { kind: "rsu"; i: number } | { kind: "controller"; i: number };

function sameFocus(a: Focus | null, b: Focus): boolean {
  return !!a && a.kind === b.kind && a.i === b.i;
}

function relevantCar(carIdx: number, rsuIdx: number, focus: Focus | null): boolean {
  if (!focus) return true;
  if (rsuIdx === -1) return focus.kind === "vehicle" && focus.i === carIdx;
  if (focus.kind === "vehicle") return carIdx === focus.i;
  if (focus.kind === "rsu") return rsuIdx === focus.i;
  return RSUS[rsuIdx].ctrl === focus.i; // controller
}

const PIPELINE_STEPS = ["Rules ψ̂", "GAT Ŝ", "LSTM-AE ε̂", "Fusion Φ"] as const;

type Stage = { carIdx: number; rsuIdx: number; step: number; flagged: boolean; done: boolean };

let evId = 0;
type FlowEvent = {
  id: number;
  kind: "fast" | "uplink" | "downlink" | "vote";
  fromX: number;
  fromY: number;
  toX: number;
  toY: number;
  start: number;
  duration: number;
  color: string;
};

function PipelineNode({ label, status, sub }: { label: string; status: SemanticStatus; sub?: string }) {
  const semantic = useSemanticTokens();
  const color = semantic[status];
  return (
    <div
      className="flex min-w-[86px] flex-1 flex-col items-center gap-0.5 rounded-md border p-2 text-center"
      style={{ borderColor: `${color}55`, background: status === "inactive" ? "transparent" : `${color}14` }}
    >
      <span className="text-[9px] font-semibold uppercase tracking-wide text-ink-muted">{label}</span>
      <span className="text-[10px] font-medium" style={{ color }}>
        {sub ?? "—"}
      </span>
    </div>
  );
}

export default function SdvnConceptAnimation() {
  const { SERIES, INK, SURFACE, ENTITY, STATUS } = useTokens();
  const [, forceRender] = useState(0);
  const [attacked, setAttacked] = useState(false);
  const [focus, setFocus] = useState<Focus | null>(null);
  const [stage, setStage] = useState<Stage | null>(null);
  const [events, setEvents] = useState<FlowEvent[]>([]);
  const [votes, setVotes] = useState<Record<number, number>>({});
  const [revoked, setRevoked] = useState<Record<number, boolean>>({});

  const timeRef = useRef(0);
  const lastRef = useRef<number | null>(null);
  const bondRef = useRef<number[]>(CARS.map(() => -1));
  const nextFastRef = useRef<number[]>(CARS.map(() => 0));
  const nextDetailedRef = useRef<number[]>(CARS.map((_, i) => 1.5 + i * 0.6));
  const stageBusyRef = useRef(false);
  const queueRef = useRef<{ carIdx: number; rsuIdx: number; color: string }[]>([]);
  const attackedRef = useRef(attacked);
  const focusRef = useRef<Focus | null>(focus);
  const rafRef = useRef<number>();

  useEffect(() => {
    attackedRef.current = attacked;
  }, [attacked]);
  useEffect(() => {
    focusRef.current = focus;
  }, [focus]);

  const enqueue = (carIdx: number, rsuIdx: number, color: string) => {
    if (queueRef.current.some((q) => q.carIdx === carIdx)) return; // already pending
    const entry = { carIdx, rsuIdx, color };
    if (attackedRef.current && carIdx === ATTACKED_IDX) queueRef.current.unshift(entry);
    else queueRef.current.push(entry);
  };

  const runPipeline = (carIdx: number, rsuIdx: number, carColor: string) => {
    stageBusyRef.current = true;
    const isAttack = attackedRef.current && carIdx === ATTACKED_IDX;
    const rsu = RSUS[rsuIdx];
    const ctrl = CONTROLLERS[rsu.ctrl];

    // uplink packet: vehicle -> RSU (real: unicast) — pulled out of the fast stream for inspection
    setEvents((prev) => [
      ...prev,
      { id: evId++, kind: "uplink", fromX: carX(timeRef.current, carIdx), fromY: ROAD_Y, toX: rsu.x, toY: rsu.y - 26, start: performance.now(), duration: 900, color: carColor },
    ]);

    setStage({ carIdx, rsuIdx, step: 0, flagged: false, done: false });
    const stepDelay = 850;
    PIPELINE_STEPS.forEach((_, i) => {
      window.setTimeout(() => {
        setStage((prev) => (prev ? { ...prev, step: i } : prev));
      }, i * stepDelay);
    });
    window.setTimeout(() => {
      setStage((prev) => (prev ? { ...prev, flagged: isAttack, done: true } : prev));
      // downlink reply: RSU -> ALL vehicles in its cell (real: broadcast, not just the sender)
      setEvents((prev) => [
        ...prev,
        { id: evId++, kind: "downlink", fromX: rsu.x, fromY: rsu.y - 26, toX: rsu.x, toY: ROAD_Y, start: performance.now(), duration: 800, color: ENTITY.rsu },
      ]);
      if (isAttack) {
        setEvents((prev) => [
          ...prev,
          { id: evId++, kind: "vote", fromX: rsu.x, fromY: rsu.y - 26, toX: ctrl.x, toY: ctrl.y + 16, start: performance.now(), duration: 900, color: STATUS.missed },
        ]);
        setVotes((v) => {
          const nv = (v[carIdx] ?? 0) + 1;
          if (nv >= 3) {
            window.setTimeout(() => {
              setRevoked((r) => ({ ...r, [carIdx]: true }));
              window.setTimeout(() => {
                setRevoked((r) => ({ ...r, [carIdx]: false }));
                setVotes((v2) => ({ ...v2, [carIdx]: 0 }));
              }, 2800);
            }, 700);
          }
          return { ...v, [carIdx]: nv };
        });
      }
      window.setTimeout(() => {
        setStage(null);
        stageBusyRef.current = false;
      }, 1600);
    }, PIPELINE_STEPS.length * stepDelay);
  };

  useEffect(() => {
    const tick = (now: number) => {
      if (lastRef.current == null) lastRef.current = now;
      const dt = (now - lastRef.current) / 1000;
      lastRef.current = now;
      timeRef.current += dt;
      const t = timeRef.current;
      const f = focusRef.current;

      CARS.forEach((_, i) => {
        const x = carX(t, i);
        const prevBond = bondRef.current[i];
        const bond = bondedRsu(x, prevBond);
        bondRef.current[i] = bond;
        if (bond === -1) return;

        // real ~100ms beacon cadence — only drawn when relevant to the current focus
        if (t >= nextFastRef.current[i]) {
          nextFastRef.current[i] = Math.max(t, nextFastRef.current[i]) + BEACON_INTERVAL_S;
          if (relevantCar(i, bond, f)) {
            const color = SERIES[i % SERIES.length];
            const rsu = RSUS[bond];
            const ctrl = CONTROLLERS[rsu.ctrl];
            const now2 = performance.now();
            setEvents((prev) => [
              ...prev,
              { id: evId++, kind: "fast", fromX: x, fromY: ROAD_Y, toX: rsu.x, toY: rsu.y - 26, start: now2, duration: 240, color },
              { id: evId++, kind: "fast", fromX: rsu.x, fromY: rsu.y - 26, toX: ctrl.x, toY: ctrl.y + 16, start: now2 + 120, duration: 240, color: ENTITY.rsu },
            ]);
          }
        }

        // slow, readable walkthrough — only for a focused, relevant vehicle
        if (f && relevantCar(i, bond, f) && (bond !== prevBond || t >= nextDetailedRef.current[i])) {
          nextDetailedRef.current[i] = t + DETAIL_INTERVAL_S;
          enqueue(i, bond, SERIES[i % SERIES.length]);
        }
      });

      if (!stageBusyRef.current && queueRef.current.length > 0) {
        const next = queueRef.current.shift()!;
        runPipeline(next.carIdx, next.rsuIdx, next.color);
      }

      setEvents((prev) => prev.filter((e) => now - e.start < e.duration));
      forceRender((v) => (v + 1) % 1000000);
      rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const t = timeRef.current;
  const now = performance.now();
  const carPositions = useMemo(() => CARS.map((_, i) => ({ x: carX(t, i), i })), [t]);
  const focusedVehicleBond = focus?.kind === "vehicle" ? bondRef.current[focus.i] : null;

  const vehicleDimmed = (i: number) => {
    if (!focus) return false;
    if (focus.kind === "vehicle") return focus.i !== i;
    if (focus.kind === "rsu") return bondRef.current[i] !== focus.i;
    return !(bondRef.current[i] !== -1 && RSUS[bondRef.current[i]].ctrl === focus.i);
  };
  const rsuDimmed = (i: number) => {
    if (!focus) return false;
    if (focus.kind === "rsu") return focus.i !== i;
    if (focus.kind === "vehicle") return focusedVehicleBond !== i;
    return RSUS[i].ctrl !== focus.i;
  };
  const ctrlDimmed = (i: number) => {
    if (!focus) return false;
    if (focus.kind === "controller") return focus.i !== i;
    if (focus.kind === "rsu") return RSUS[focus.i].ctrl !== i;
    return !(focusedVehicleBond != null && focusedVehicleBond !== -1 && RSUS[focusedVehicleBond].ctrl === i);
  };

  const clickFocus = (f: Focus) => (e: React.MouseEvent) => {
    e.stopPropagation();
    setFocus((prev) => (sameFocus(prev, f) ? null : f));
  };

  const focusCaption = !focus
    ? "Global view — every vehicle beacons roughly every 100ms. Click a vehicle, RSU, or controller to focus on just its traffic and watch its detection pipeline."
    : focus.kind === "vehicle"
    ? `Inspecting Vehicle ${focus.i + 1} — its 100ms beacon stream, and one beacon every ~${DETAIL_INTERVAL_S}s walked through the pipeline below.`
    : focus.kind === "rsu"
    ? `Inspecting ${RSUS[focus.i].label} — beacons from whichever vehicles are currently in its cell.`
    : `Inspecting ${CONTROLLERS[focus.i].label} — traffic relayed via ${RSUS.filter((r) => r.ctrl === focus.i)
        .map((r) => r.label)
        .join(", ")}.`;

  return (
    <div className="rounded-lg border border-surface-hairline bg-surface-raised p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="text-[10px] text-ink-muted">{focusCaption}</p>
        <button
          onClick={() => setAttacked((v) => !v)}
          className={`shrink-0 rounded-md border px-2.5 py-1 text-[10px] font-semibold transition-colors ${
            attacked ? "border-status-missed bg-status-missed/15 text-status-missed" : "border-surface-hairline2 text-ink-secondary hover:text-ink-primary"
          }`}
        >
          {attacked ? "Attack staged on V2 — click to stop" : "Stage an attack on V2"}
        </button>
      </div>

      <svg
        viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
        className="w-full"
        role="img"
        aria-label="Diagram of infrastructure and the detection/mitigation pipeline"
        onClick={() => setFocus(null)}
      >
        {/* buildings */}
        {BUILDINGS.map((b, i) => (
          <rect key={i} x={b.x} y={b.y} width={b.w} height={b.h} fill={SURFACE.hairlineStrong} opacity={0.35} rx={2} />
        ))}
        {/* backhaul links */}
        {RSUS.map((r, i) => (
          <line
            key={i}
            x1={r.x}
            y1={r.y - 40}
            x2={CONTROLLERS[r.ctrl].x}
            y2={CONTROLLERS[r.ctrl].y + 18}
            stroke={SURFACE.hairlineStrong}
            strokeWidth={2}
            strokeDasharray="4 4"
            opacity={rsuDimmed(i) && ctrlDimmed(r.ctrl) ? 0.25 : 1}
          />
        ))}
        {/* road */}
        <line x1={ROAD_X0} y1={ROAD_Y} x2={ROAD_X1} y2={ROAD_Y} stroke={SURFACE.hairlineStrong} strokeWidth={3} strokeLinecap="round" />
        {/* RSU coverage */}
        {RSUS.map((r, i) => (
          <circle key={i} cx={r.x} cy={r.y} r={COVERAGE_R} fill="none" stroke={ENTITY.rsu} strokeOpacity={rsuDimmed(i) ? 0.12 : 0.3} strokeDasharray="5 5" />
        ))}
        {/* controllers */}
        {CONTROLLERS.map((c, i) => (
          <g key={i} onClick={clickFocus({ kind: "controller", i })} style={{ cursor: "pointer" }} opacity={ctrlDimmed(i) ? 0.3 : 1}>
            <rect x={c.x - 13} y={c.y - 13} width={26} height={26} fill={ENTITY.controller} transform={`rotate(45 ${c.x} ${c.y})`} rx={3} />
            <text x={c.x} y={c.y - 22} textAnchor="middle" fontSize={10} fill={INK.secondary} fontWeight={600}>
              {c.label}
            </text>
          </g>
        ))}
        {/* RSUs */}
        {RSUS.map((r, i) => (
          <g key={i} onClick={clickFocus({ kind: "rsu", i })} style={{ cursor: "pointer" }} opacity={rsuDimmed(i) ? 0.3 : 1}>
            <rect x={r.x - 11} y={r.y - 40} width={22} height={22} fill={ENTITY.rsu} rx={3} />
            <line x1={r.x} y1={r.y - 18} x2={r.x} y2={r.y} stroke={ENTITY.rsu} strokeWidth={3} />
            <text x={r.x} y={r.y - 48} textAnchor="middle" fontSize={10} fill={INK.secondary} fontWeight={600}>
              {r.label}
            </text>
          </g>
        ))}
        {/* cars */}
        {carPositions.map(({ x, i }) => {
          const color = SERIES[i % SERIES.length];
          const isAttacked = attacked && i === ATTACKED_IDX;
          return (
            <g key={i} onClick={clickFocus({ kind: "vehicle", i })} style={{ cursor: "pointer" }} opacity={vehicleDimmed(i) ? 0.3 : 1}>
              <circle cx={x} cy={ROAD_Y} r={9} fill={isAttacked ? STATUS.missed : color} stroke={SURFACE.raised} strokeWidth={1.5} />
              <text x={x} y={ROAD_Y + 22} textAnchor="middle" fontSize={9} fill={INK.muted}>
                V{i + 1}
                {isAttacked ? " ⚠" : ""}
              </text>
            </g>
          );
        })}
        {/* in-flight packets */}
        {events.map((e) => {
          const frac = Math.min(1, Math.max(0, (now - e.start) / e.duration));
          const x = e.fromX + (e.toX - e.fromX) * frac;
          const y = e.fromY + (e.toY - e.fromY) * frac;
          const r = e.kind === "fast" ? 2.5 : e.kind === "vote" ? 5 : 4;
          const baseOpacity = e.kind === "fast" ? 0.75 : 1;
          return now >= e.start ? <circle key={e.id} cx={x} cy={y} r={r} fill={e.color} opacity={baseOpacity * (1 - frac * 0.3)} /> : null;
        })}
      </svg>

      {/* pipeline strip */}
      <div className="mt-2 flex items-stretch gap-1">
        {stage ? (
          <>
            <PipelineNode label="Vehicle" status="inactive" sub={`V${stage.carIdx + 1} → ${RSUS[stage.rsuIdx].label}`} />
            <ArrowRight size={13} className="mx-0.5 mt-3 shrink-0 text-ink-muted" aria-hidden />
            {PIPELINE_STEPS.map((label, i) => (
              <PipelineNode
                key={label}
                label={label}
                status={stage.step < i ? "inactive" : stage.done && i === PIPELINE_STEPS.length - 1 ? (stage.flagged ? "compromised" : "safe") : "informational"}
                sub={stage.step < i ? "—" : stage.done && i === PIPELINE_STEPS.length - 1 ? (stage.flagged ? "FLAGGED" : "clean") : "checking…"}
              />
            ))}
            <ArrowRight size={13} className="mx-0.5 mt-3 shrink-0 text-ink-muted" aria-hidden />
            <PipelineNode
              label="Ledger"
              status={stage.done && stage.flagged ? "warning" : "inactive"}
              sub={stage.done && stage.flagged ? `vote ${votes[stage.carIdx] ?? 0}/3` : "—"}
            />
          </>
        ) : (
          <p className="flex-1 py-2 text-center text-[10px] text-ink-muted">
            {focus == null
              ? "Click a vehicle, RSU, or controller above to inspect its detection pipeline."
              : revoked[focus.kind === "vehicle" ? focus.i : ATTACKED_IDX]
              ? "Threshold reached — vehicle revoked (illustrative)."
              : "Watching for the next beacon from this focus to reach an RSU…"}
          </p>
        )}
      </div>
      <p className="mt-1.5 text-center text-[10px] text-ink-muted">
        Illustrative loop, not simulated data — beacon cadence, pipeline order, and the unicast-up/broadcast-down
        asymmetry match this project's real ns-3 source; a flagged beacon casts a vote (real threshold = 3), not
        an instant revoke.
      </p>
    </div>
  );
}
