import { AlertCircle, CheckCircle2, CircleDashed, Info, XCircle, LucideIcon } from "lucide-react";
import { ReactNode } from "react";
import { SemanticTokens, useSemanticTokens } from "../design/tokens";

/**
 * The one status-indicator language for the whole app (replaces the mix of
 * dots/squares/triangles/colour-only text that used to vary screen to
 * screen). Five roles only — safe/compromised/warning/informational/
 * inactive — each a fixed icon AND colour, always together. Never used for
 * "series 4" or anything outside these five meanings.
 */
export type SemanticStatus = keyof SemanticTokens;

const ICON: Record<SemanticStatus, LucideIcon> = {
  safe: CheckCircle2,
  compromised: XCircle,
  warning: AlertCircle,
  informational: Info,
  inactive: CircleDashed,
};

export default function StatusPill({
  status,
  children,
  compact = false,
}: {
  status: SemanticStatus;
  children: ReactNode;
  compact?: boolean;
}) {
  const semantic = useSemanticTokens();
  const Icon = ICON[status];
  const color = semantic[status];
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border text-badge ${
        compact ? "px-2 py-0.5" : "px-2.5 py-1"
      }`}
      style={{ color, borderColor: `${color}55`, background: `${color}18` }}
    >
      <Icon size={compact ? 12 : 14} strokeWidth={2.5} aria-hidden />
      {children}
    </span>
  );
}

export const STATUS_LABEL: Record<SemanticStatus, string> = {
  safe: "Safe / detected",
  compromised: "Compromised / missed",
  warning: "Warning",
  informational: "Informational",
  inactive: "Inactive",
};

export { ICON as STATUS_ICON };
