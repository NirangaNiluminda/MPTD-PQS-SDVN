import { ReactNode } from "react";

/** Click-point offset from viewport centre — feeds the modal's grow-from-
 * origin animation (--fx/--fy, see index.css's .anim-panel-in) so it
 * visibly originates from the card that opened it. */
export function originFromEvent(e: React.MouseEvent<HTMLElement>): { dx: number; dy: number } {
  const r = e.currentTarget.getBoundingClientRect();
  return {
    dx: r.left + r.width / 2 - window.innerWidth / 2,
    dy: r.top + r.height / 2 - window.innerHeight / 2,
  };
}

/**
 * Shared floating-window chrome for every "drill into this" flow — first
 * built for the Attack Explainer, now the one modal implementation reused
 * everywhere a summary card expands into full detail. Backdrop click and
 * Escape both close it (Escape via the caller's own key handler, since
 * only the caller knows whether other UI should also react to it).
 */
export default function DrillModal({
  open,
  onClose,
  origin,
  title,
  subtitle,
  badge,
  maxWidth = "max-w-2xl",
  children,
}: {
  open: boolean;
  onClose: () => void;
  origin: { dx: number; dy: number };
  title: string;
  subtitle?: string;
  badge?: ReactNode;
  maxWidth?: string;
  children: ReactNode;
}) {
  if (!open) return null;
  return (
    <>
      <div
        onClick={onClose}
        className="anim-fadein fixed inset-0 z-20 bg-black/60 backdrop-blur-[3px]"
      />
      <div className="pointer-events-none fixed inset-0 z-30 flex items-start justify-center overflow-y-auto p-[5vh_16px_4vh]">
        <div
          className={`pointer-events-auto my-[5vh] w-full ${maxWidth} overflow-hidden rounded-xl border border-surface-hairline2 bg-surface-panel shadow-2xl`}
          style={
            {
              "--fx": `${origin.dx}px`,
              "--fy": `${origin.dy}px`,
            } as React.CSSProperties
          }
        >
          <div className="anim-panel-in">
            <div className="sticky top-0 z-10 flex items-start gap-3 border-b border-surface-hairline bg-surface-panel p-5">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2.5">
                  <h2 className="text-section-title text-ink-primary">{title}</h2>
                  {badge}
                </div>
                {subtitle && (
                  <p className="mt-1.5 text-xs leading-relaxed text-ink-secondary">{subtitle}</p>
                )}
              </div>
              <button
                onClick={onClose}
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-surface-hairline2 bg-surface-raised text-sm text-ink-secondary hover:text-ink-primary"
              >
                ✕
              </button>
            </div>
            <div className="flex flex-col gap-3.5 p-5">{children}</div>
          </div>
        </div>
      </div>
    </>
  );
}
