import { ArrowRight } from "lucide-react";
import { AttackEvidenceDto } from "../api";
import { useSemanticTokens } from "../design/tokens";
import { SemanticStatus } from "./StatusPill";

/** value in [0,1] -> the same "how strongly did this layer engage" read
 * MetricCard uses elsewhere in this screen, kept consistent rather than
 * inventing a second banding scheme for the same three numbers. */
function signalTone(value: number | undefined): { status: SemanticStatus; label: string } {
  if (value == null) return { status: "inactive", label: "no data" };
  if (value > 0.6) return { status: "informational", label: "strong" };
  if (value > 0.3) return { status: "warning", label: "moderate" };
  return { status: "safe", label: "weak" };
}

function fusionTone(rate: number | undefined): { status: SemanticStatus; label: string } {
  if (rate == null) return { status: "inactive", label: "no data" };
  if (rate >= 0.9) return { status: "safe", label: "mostly caught" };
  if (rate >= 0.5) return { status: "warning", label: "partly caught" };
  return { status: "compromised", label: "mostly missed" };
}

function Node({
  eyebrow,
  value,
  sub,
  status,
}: {
  eyebrow: string;
  value: string;
  sub: string;
  status: SemanticStatus;
}) {
  const semantic = useSemanticTokens();
  const color = semantic[status];
  return (
    <div
      className="flex min-w-[132px] flex-1 flex-col items-center gap-1 rounded-lg border p-3 text-center"
      style={{ borderColor: `${color}55`, background: `${color}14` }}
    >
      <span className="text-badge font-semibold uppercase tracking-wide text-ink-muted">{eyebrow}</span>
      <span className="font-mono text-lg font-bold" style={{ color }}>
        {value}
      </span>
      <span className="text-[10px] leading-snug text-ink-secondary">{sub}</span>
    </div>
  );
}

function Connector() {
  return <ArrowRight size={16} className="mx-0.5 shrink-0 text-ink-muted" aria-hidden />;
}

/**
 * High-level, single-glance pipeline: attack -> each detection layer's real
 * engagement -> the fused decision -> real mitigation-vote activity. Every
 * number is the same one already used elsewhere in this modal (MetricCard,
 * EvidenceBody) — this is a different arrangement of the same real data, not
 * a new measurement.
 */
export default function AttackFlowDiagram({
  actorGlyph,
  attackLabel,
  evidence,
}: {
  actorGlyph: string;
  attackLabel: string;
  evidence: AttackEvidenceDto;
}) {
  const rules = signalTone(evidence.mean_psi_fuse);
  const gat = signalTone(evidence.mean_gat_score);
  const ae = signalTone(evidence.mean_ae_norm);
  const fusion = fusionTone(evidence.detection_rate);

  const m = evidence.mitigation;
  const mitigation: { status: SemanticStatus; value: string; sub: string } = !m || m.vehicles_with_votes === 0
    ? { status: "inactive", value: "—", sub: "no revoke-votes recorded for this attack's vehicles here" }
    : m.any_crossed_threshold
    ? { status: "safe", value: `${m.vehicles_with_votes} veh.`, sub: `${m.total_votes_cast} votes cast — threshold crossed` }
    : { status: "warning", value: `${m.vehicles_with_votes} veh.`, sub: `${m.total_votes_cast} votes cast, threshold not yet crossed` };

  const topSig = evidence.top_signatures?.[0];

  return (
    <div className="flex items-stretch gap-1 overflow-x-auto pb-1">
      <Node eyebrow="Attack" value={actorGlyph} sub={attackLabel} status="inactive" />
      <Connector />
      <Node
        eyebrow="Rules (ψ̂)"
        value={evidence.mean_psi_fuse != null ? evidence.mean_psi_fuse.toFixed(2) : "—"}
        sub={topSig ? `${rules.label} · ${topSig.name}` : rules.label}
        status={rules.status}
      />
      <Connector />
      <Node
        eyebrow="GAT (Ŝ)"
        value={evidence.mean_gat_score != null ? evidence.mean_gat_score.toFixed(2) : "—"}
        sub={`${gat.label} spatial signal`}
        status={gat.status}
      />
      <Connector />
      <Node
        eyebrow="LSTM-AE (ε̂)"
        value={evidence.mean_ae_norm != null ? evidence.mean_ae_norm.toFixed(2) : "—"}
        sub={`${ae.label} time-pattern signal`}
        status={ae.status}
      />
      <Connector />
      <Node
        eyebrow="Fusion Φ"
        value={evidence.detection_rate != null ? `${(evidence.detection_rate * 100).toFixed(0)}%` : "—"}
        sub={fusion.label}
        status={fusion.status}
      />
      <Connector />
      <Node eyebrow="Mitigation" value={mitigation.value} sub={mitigation.sub} status={mitigation.status} />
    </div>
  );
}
