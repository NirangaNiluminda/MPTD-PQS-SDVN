import { ReactNode } from "react";

/**
 * Shared collapse mechanics for every click-to-expand row in the app
 * (Defence Stack Inspector's signal cards, Blockchain Ledger rows,
 * Ablation breakdowns). A fixed max-height cap + overflow:hidden, not a
 * JS-measured height — the same technique the SENTINEL mockup uses, and it
 * sidesteps a real layout-thrash bug that a ResizeObserver approach would
 * invite in a list that can hold hundreds of rows (Ledger).
 */
export default function Accordion({
  open,
  onToggle,
  header,
  children,
  bodyMaxHeight = 420,
  className = "",
}: {
  open: boolean;
  onToggle: () => void;
  header: ReactNode;
  children: ReactNode;
  bodyMaxHeight?: number;
  className?: string;
}) {
  return (
    <div className={`overflow-hidden rounded-lg border border-surface-hairline bg-surface-panel ${className}`}>
      <button
        onClick={onToggle}
        className="flex w-full items-center gap-2.5 px-3.5 py-3 text-left font-sans text-ink-primary transition-colors hover:bg-surface-raised/60"
      >
        <span
          aria-hidden
          className="font-mono text-[10px] text-ink-muted transition-transform duration-300"
          style={{ transform: open ? "rotate(90deg)" : "rotate(0deg)", transitionTimingFunction: "var(--ease)" }}
        >
          ▸
        </span>
        {header}
      </button>
      <div
        style={{
          maxHeight: open ? bodyMaxHeight : 0,
          opacity: open ? 1 : 0,
          overflow: "hidden",
          transition: "max-height .38s var(--ease), opacity .28s ease",
        }}
      >
        <div className={open ? "anim-rise" : ""}>{children}</div>
      </div>
    </div>
  );
}

export function AccordionChevron({ open }: { open: boolean }) {
  return (
    <span
      aria-hidden
      className="font-mono text-[10px] text-ink-muted transition-transform duration-300"
      style={{ transform: open ? "rotate(90deg)" : "rotate(0deg)", transitionTimingFunction: "var(--ease)" }}
    >
      ▸
    </span>
  );
}
