import { useEffect, useState } from "react";
import { api, BlockCommitDto, ChainHeightDto } from "../api";

const POLL_MS = 2000;

function timeAgo(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

function blockLogTsToMs(logTs: string | null): number | null {
  if (!logTs) return null;
  const ms = Date.parse(logTs.replace(" ", "T") + "Z");
  return Number.isNaN(ms) ? null : ms;
}

/**
 * The real-time part of "connect the explorer with live ledger state" —
 * "Committed block [N]" lines tailed straight off the Fabric peer
 * container's own log (backend parsers/block_feed.py), not a chaincode
 * query and not the ns-3 process. This is the one place block CREATION
 * itself, as it happens, is directly observable.
 *
 * Shared between LedgerScreen (the network-wide view) and RunConsoleScreen's
 * live run modal (where it's the same real chain, scoped by context rather
 * than by a filter that doesn't exist — see the caption prop).
 *
 * Polled, not SSE: Cloudflare Quick Tunnels (what this demo gets shared
 * through) buffer SSE-over-GET until the connection closes, which for a
 * live stream never happens — confirmed directly (instant on localhost,
 * zero bytes over the tunnel after 8s; tracked upstream as
 * cloudflare/cloudflared#1449). Polling has no dependency on how the
 * transport in between handles a long-lived connection.
 */
export default function BlockFeedPanel({
  title = "Live block feed",
  caption,
}: {
  title?: string;
  caption?: string;
}) {
  const [status, setStatus] = useState<"connecting" | "live" | "error">("connecting");
  const [container, setContainer] = useState<string | null>(null);
  const [height, setHeight] = useState<ChainHeightDto | null>(null);
  const [blocks, setBlocks] = useState<BlockCommitDto[]>([]);
  const [, forceTick] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const poll = () => {
      api
        .blocksRecent()
        .then((d) => {
          if (cancelled) return;
          setContainer(d.container);
          setHeight(d.height);
          setBlocks(d.recent);
          setStatus("live");
        })
        .catch(() => {
          if (!cancelled) setStatus("error");
        });
    };
    poll();
    const interval = setInterval(poll, POLL_MS);
    // Re-render every few seconds purely so "Xs ago" timestamps stay fresh —
    // independent of the data poll's own cadence.
    const tick = setInterval(() => forceTick((n) => n + 1), 3000);
    return () => {
      cancelled = true;
      clearInterval(interval);
      clearInterval(tick);
    };
  }, []);

  const latest = blocks[blocks.length - 1];
  const latestMs = latest ? blockLogTsToMs(latest.log_ts) : null;
  const spanMs =
    blocks.length >= 2
      ? (blockLogTsToMs(blocks[blocks.length - 1].log_ts) ?? 0) - (blockLogTsToMs(blocks[0].log_ts) ?? 0)
      : 0;
  const blocksPerMin = blocks.length >= 2 && spanMs > 0 ? ((blocks.length - 1) / (spanMs / 60000)).toFixed(1) : null;

  return (
    <div className="rounded-xl border border-surface-hairline bg-surface-raised p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className={`h-2 w-2 shrink-0 rounded-full ${
              status === "live" ? "animate-pulse bg-status-good" : status === "error" ? "bg-status-missed" : "bg-ink-muted"
            }`}
          />
          <h2 className="text-sm font-semibold text-ink-primary">{title}</h2>
          <span className="text-[10px] text-ink-muted">
            {status === "live" && container && `tailing ${container}'s own commit log`}
            {status === "connecting" && "connecting…"}
            {status === "error" && "stream unavailable — docker/peer unreachable from the backend"}
          </span>
        </div>
        {height && (
          <span className="text-[11px] text-ink-secondary">
            height <span className="font-mono font-semibold text-ink-primary">{height.height.toLocaleString()}</span>
            {latestMs != null && <> · latest block {timeAgo(Date.now() - latestMs)}</>}
            {blocksPerMin && <> · {blocksPerMin} blocks/min recently</>}
          </span>
        )}
      </div>
      {caption && <p className="mt-1 text-[10px] text-ink-muted">{caption}</p>}

      {blocks.length === 0 ? (
        <div className="mt-3 flex h-24 items-center justify-center rounded-md border border-dashed border-surface-hairline2 bg-surface-page text-[11px] text-ink-muted">
          {status === "error" ? "Could not reach the peer container." : "Waiting for the first block…"}
        </div>
      ) : (
        <div className="mt-3 max-h-56 overflow-y-auto rounded-md border border-surface-hairline bg-surface-page">
          <table className="w-full text-left text-[11px]">
            <thead className="sticky top-0 bg-surface-page text-[9px] uppercase tracking-wide text-ink-muted">
              <tr>
                <th className="px-2 py-1">Block</th>
                <th className="px-2 py-1">Txs</th>
                <th className="px-2 py-1">Commit time</th>
                <th className="px-2 py-1">Hash</th>
                <th className="px-2 py-1 text-right">When</th>
              </tr>
            </thead>
            <tbody>
              {[...blocks].reverse().map((b) => {
                const ms = blockLogTsToMs(b.log_ts);
                return (
                  <tr key={b.block} className="border-t border-surface-hairline/60">
                    <td className="px-2 py-1 font-mono text-ink-primary">{b.block}</td>
                    <td className="px-2 py-1 font-mono text-ink-secondary">{b.tx_count}</td>
                    <td className="px-2 py-1 font-mono text-ink-secondary">{b.commit_ms.toFixed(0)}ms</td>
                    <td className="px-2 py-1 font-mono text-ink-muted">{b.hash}</td>
                    <td className="px-2 py-1 text-right text-ink-muted">
                      {ms != null ? timeAgo(Date.now() - ms) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
