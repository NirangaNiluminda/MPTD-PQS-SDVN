import { useEffect, useState } from "react";
import {
  api,
  ControllerFlagDto,
  CryptoSummaryDto,
  LedgerSummaryDto,
  ReassignmentDto,
  RevocationDto,
  TrustRecordDto,
} from "../api";
import { useTokens } from "../design/tokens";

function formatBytes(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)} MB`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)} KB`;
  return `${n} B`;
}

function KpiCard({
  label,
  value,
  sub,
  tone = "neutral",
}: {
  label: string;
  value: string | number;
  sub?: string;
  tone?: "neutral" | "missed" | "caught";
}) {
  const toneClass =
    tone === "missed"
      ? "text-status-missed"
      : tone === "caught"
      ? "text-status-caught"
      : "text-ink-primary";
  return (
    <div className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
      <div className="text-[10px] uppercase tracking-wider text-ink-muted">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${toneClass}`}>{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-ink-secondary">{sub}</div>}
    </div>
  );
}

function TrustBar({ score }: { score: number }) {
  const { STATUS } = useTokens();
  const pct = Math.max(0, Math.min(1, score)) * 100;
  const color = score < 0.3 ? STATUS.missed : score < 0.7 ? STATUS.caught : STATUS.good;
  return (
    <div className="h-1.5 w-24 overflow-hidden rounded-full bg-surface-page">
      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
    </div>
  );
}

function Section({
  title,
  count,
  children,
}: {
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-lg border border-surface-hairline bg-surface-panel">
      <header className="flex items-center justify-between border-b border-surface-hairline px-4 py-2.5">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
          {title}
        </h2>
        <span className="rounded bg-surface-raised px-1.5 py-0.5 text-[10px] text-ink-muted">
          {count}
        </span>
      </header>
      <div className="max-h-72 overflow-y-auto">{children}</div>
    </section>
  );
}

const Row = ({ children }: { children: React.ReactNode }) => (
  <div className="flex items-center gap-3 border-b border-surface-hairline/60 px-4 py-2 text-xs last:border-0">
    {children}
  </div>
);

export default function LedgerScreen() {
  const [summary, setSummary] = useState<LedgerSummaryDto | null>(null);
  const [rsuTrust, setRsuTrust] = useState<TrustRecordDto[]>([]);
  const [vehicleTrust, setVehicleTrust] = useState<TrustRecordDto[]>([]);
  const [revocations, setRevocations] = useState<RevocationDto[]>([]);
  const [flags, setFlags] = useState<ControllerFlagDto[]>([]);
  const [reassignments, setReassignments] = useState<ReassignmentDto[]>([]);
  const [crypto, setCrypto] = useState<CryptoSummaryDto | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api.ledgerSummary(),
      api.ledgerTrust("rsu"),
      api.ledgerTrust("vehicle"),
      api.ledgerRevocations(),
      api.ledgerFlags(),
      api.ledgerReassignments(),
    ])
      .then(([s, rsu, veh, rev, fl, ra]) => {
        setSummary(s);
        setRsuTrust(rsu);
        setVehicleTrust(veh.filter((v) => v.UpdateCount > 0));
        setRevocations(rev);
        setFlags(fl);
        setReassignments(ra);
      })
      .catch((e) => setError(String(e)));
    // Separate call, separate failure domain: the crypto/IPFS panel is a
    // bonus on top of the core ledger view, not a reason to blank the page
    // if the capture log happens to be unavailable.
    api.captureCryptoSummary().then(setCrypto).catch(() => setCrypto(null));
  }, []);

  if (error) {
    return (
      <div className="flex h-full items-center justify-center p-8">
        <div className="max-w-md rounded-lg border border-status-missed/40 bg-status-missed/10 p-5 text-sm text-status-missed">
          {error}
          <p className="mt-2 text-xs text-ink-secondary">
            No ledger snapshot found. From demo_ui/backend:{" "}
            <code className="text-ink-primary">
              python3 scripts/snapshot_ledger.py
            </code>
          </p>
        </div>
      </div>
    );
  }

  const demotedRsu = rsuTrust.filter((r) => r.State !== "TRUSTED");

  return (
    <div className="h-full overflow-y-auto p-5">
      <div className="mx-auto max-w-5xl space-y-5">
        <header>
          <h1 className="text-lg font-semibold text-ink-primary">
            Blockchain ledger
          </h1>
          <p className="text-xs text-ink-secondary">
            A point-in-time snapshot of the Hyperledger Fabric ledger
            {summary && (
              <> — captured {new Date(summary.captured_at).toLocaleString()}</>
            )}
            . Not live: re-run{" "}
            <code className="text-ink-primary">snapshot_ledger.py</code> to
            refresh, so the demo never depends on Fabric being reachable at
            presentation time.
          </p>
        </header>

        {summary && (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <KpiCard
              label="RSUs demoted"
              value={summary.rsus.demoted}
              sub={`of ${summary.rsus.total}`}
              tone={summary.rsus.demoted > 0 ? "missed" : "neutral"}
            />
            <KpiCard
              label="Vehicles trust-decayed"
              value={summary.vehicles.decayed}
              sub={`of ${summary.vehicles.total}`}
              tone={summary.vehicles.decayed > 0 ? "missed" : "neutral"}
            />
            <KpiCard
              label="Revocation votes"
              value={summary.revocations}
              tone={summary.revocations > 0 ? "caught" : "neutral"}
            />
            <KpiCard
              label="Controller reassignments"
              value={summary.reassignments}
              sub={`${summary.controller_flags} flags raised`}
              tone={summary.reassignments > 0 ? "caught" : "neutral"}
            />
          </div>
        )}

        {crypto && (
          <section className="rounded-lg border border-surface-hairline bg-surface-panel">
            <header className="border-b border-surface-hairline px-4 py-2.5">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                Post-quantum crypto cost &amp; off-chain storage
              </h2>
            </header>
            <div className="grid grid-cols-1 gap-4 p-4 sm:grid-cols-2">
              <div>
                <h3 className="mb-2 text-[11px] font-medium text-ink-secondary">
                  Per-epoch crypto latency ({crypto.pq_crypto_cost_ms.epochs_sampled} epochs)
                </h3>
                <dl className="space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <dt className="text-ink-muted">Ring signature (TRS)</dt>
                    <dd className="font-mono text-ink-primary">
                      {crypto.pq_crypto_cost_ms.trs_sign.toFixed(2)} ms
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-ink-muted">Homomorphic aggregate (FHE)</dt>
                    <dd className="font-mono text-ink-primary">
                      {crypto.pq_crypto_cost_ms.fhe_aggregate.toFixed(1)} ms
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-ink-muted">Key distribution (DKG)</dt>
                    <dd className="font-mono text-ink-primary">
                      {crypto.pq_crypto_cost_ms.dkg.toFixed(1)} ms
                    </dd>
                  </div>
                  <div className="flex justify-between border-t border-surface-hairline pt-1.5">
                    <dt className="text-ink-secondary">Epoch total</dt>
                    <dd className="font-mono font-medium text-ink-primary">
                      {crypto.pq_crypto_cost_ms.epoch_total.toFixed(0)} ms
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-ink-muted">TRS signature verification</dt>
                    <dd className="font-mono text-status-good">
                      {crypto.trs_verify.ok} ok / {crypto.trs_verify.fail} fail
                    </dd>
                  </div>
                </dl>
              </div>

              <div>
                <h3 className="mb-2 text-[11px] font-medium text-ink-secondary">
                  Bandwidth overhead — {crypto.bandwidth_overhead.ratio_vs_baseline.toFixed(1)}×
                  baseline
                </h3>
                <dl className="space-y-1.5 text-xs">
                  <div className="flex justify-between">
                    <dt className="text-ink-muted">Baseline (plain beacons)</dt>
                    <dd className="font-mono text-ink-primary">
                      {formatBytes(crypto.bandwidth_overhead.baseline_bytes)}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-ink-muted">+ HMAC auth</dt>
                    <dd className="font-mono text-ink-primary">
                      {formatBytes(crypto.bandwidth_overhead.hmac_bytes)}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-ink-muted">+ FHE ciphertext</dt>
                    <dd className="font-mono text-status-caught">
                      {formatBytes(crypto.bandwidth_overhead.fhe_bytes)}
                    </dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-ink-muted">+ TRS signatures</dt>
                    <dd className="font-mono text-ink-primary">
                      {formatBytes(crypto.bandwidth_overhead.trs_bytes)}
                    </dd>
                  </div>
                </dl>
                <p className="mt-2 text-[10px] leading-relaxed text-ink-muted">
                  FHE ciphertext dominates the overhead — this is the
                  measured cost of computing regional aggregates (e.g. mean
                  speed) without any RSU ever decrypting an individual
                  vehicle's data.
                </p>
              </div>
            </div>

            <div className="border-t border-surface-hairline p-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-[11px] font-medium text-ink-secondary">
                    Off-chain beacon-window store (IPFS)
                  </h3>
                  <p className="mt-1 text-xs text-ink-primary">
                    {crypto.ipfs.windows_stored.toLocaleString()} windows
                    stored off-chain, {crypto.ipfs.hashes_on_chain.toLocaleString()}{" "}
                    hashes committed on-chain
                  </p>
                </div>
                <span className="shrink-0 rounded bg-status-serious/20 px-2 py-1 text-[10px] font-medium text-status-serious">
                  SIMULATED — not a real IPFS daemon
                </span>
              </div>
              <p className="mt-2 rounded bg-surface-page px-2.5 py-2 text-[10px] leading-relaxed text-ink-muted">
                {crypto.ipfs.note}
              </p>
            </div>

            <div className="border-t border-surface-hairline p-4 text-xs">
              <div className="flex justify-between">
                <span className="text-ink-muted">Chaincode confirm latency</span>
                <span className="font-mono text-ink-primary">
                  {crypto.chaincode_latency_ms.confirm.toFixed(0)} ms (
                  {crypto.chaincode_latency_ms.confirm_invokes} invokes)
                </span>
              </div>
              <div className="mt-1 flex justify-between">
                <span className="text-ink-muted">Controller reassign latency</span>
                <span className="font-mono text-ink-primary">
                  {crypto.chaincode_latency_ms.reassign.toFixed(0)} ms (
                  {crypto.chaincode_latency_ms.reassign_rollovers} rollovers)
                </span>
              </div>
              <div className="mt-1 flex justify-between">
                <span className="text-ink-muted">Time-to-detect (mean)</span>
                <span className="font-mono text-ink-primary">
                  {crypto.ttd_seconds.toFixed(2)} s
                </span>
              </div>
            </div>
          </section>
        )}

        <Section title="RSU trust — demoted / under suspicion" count={demotedRsu.length}>
          {demotedRsu.length === 0 && (
            <div className="px-4 py-3 text-xs text-ink-muted">
              No RSU has left the TRUSTED state.
            </div>
          )}
          {demotedRsu.map((r) => (
            <Row key={r.ID}>
              <span className="w-20 font-mono text-ink-primary">{r.RSUID}</span>
              <span className="rounded bg-status-missed/20 px-1.5 py-0.5 text-[10px] font-medium text-status-missed">
                {r.State}
              </span>
              <TrustBar score={r.TrustScore} />
              <span className="font-mono text-ink-secondary">{r.TrustScore.toFixed(4)}</span>
              <span className="ml-auto text-ink-muted">
                {r.ConsecutiveLowEpochs} low epochs · updated {r.UpdateCount}×
              </span>
            </Row>
          ))}
        </Section>

        <Section title="Vehicle trust — decayed from baseline" count={vehicleTrust.length}>
          {vehicleTrust
            .sort((a, b) => a.TrustScore - b.TrustScore)
            .map((v) => (
              <Row key={v.ID}>
                <span className="w-20 font-mono text-ink-primary">{v.VehicleID}</span>
                {v.Probationary && (
                  <span className="rounded bg-status-caught/20 px-1.5 py-0.5 text-[10px] font-medium text-status-caught">
                    PROBATION
                  </span>
                )}
                <TrustBar score={v.TrustScore} />
                <span className="font-mono text-ink-secondary">{v.TrustScore.toFixed(3)}</span>
                <span className="ml-auto text-ink-muted">updated {v.UpdateCount}×</span>
              </Row>
            ))}
        </Section>

        <Section title="Revocation votes" count={revocations.length}>
          {revocations.map((r) => (
            <Row key={r.ID}>
              <span className="w-20 font-mono text-ink-primary">
                {r.RSUID ?? r.VehicleID}
              </span>
              <span className="text-ink-secondary">{r.Reason}</span>
              <span className="ml-auto text-ink-muted">
                {new Date(r.RevokedAt).toLocaleTimeString()}
              </span>
            </Row>
          ))}
        </Section>

        <Section title="Controller flags (CP-DETECT)" count={flags.length}>
          {flags.map((f) => (
            <Row key={f.ID}>
              <span className="w-16 font-mono text-ink-primary">{f.ControllerID}</span>
              <span className="text-ink-secondary">re: {f.VehicleID}</span>
              <span className="rounded bg-surface-raised px-1.5 py-0.5 text-[10px] text-ink-muted">
                {f.Epoch}
              </span>
              <span className="ml-auto text-ink-muted">
                {f.ConflictCount} conflict{f.ConflictCount !== 1 ? "s" : ""} /{" "}
                {f.NumRSUs} RSU{f.NumRSUs !== 1 ? "s" : ""}
              </span>
            </Row>
          ))}
        </Section>

        <Section title="Controller reassignments" count={reassignments.length}>
          {reassignments.map((r) => (
            <Row key={r.ID}>
              <span className="font-mono text-status-missed">{r.ExcludedController}</span>
              <span className="text-ink-muted">excluded →</span>
              <span className="font-mono text-status-good">{r.SuccessorController}</span>
              <span className="rounded bg-surface-raised px-1.5 py-0.5 text-[10px] text-ink-muted">
                {r.Epoch}
              </span>
              <span className="ml-auto text-ink-muted">{r.Reason}</span>
            </Row>
          ))}
        </Section>
      </div>
    </div>
  );
}
