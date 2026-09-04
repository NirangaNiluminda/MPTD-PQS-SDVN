import { useEffect, useRef, useState } from "react";
import { ExternalLink } from "lucide-react";
import {
  api,
  ControllerFlagDto,
  LedgerRefreshStatusDto,
  LedgerSummaryDto,
  ReassignmentDto,
  RevocationDto,
  TrustRecordDto,
} from "../api";
import { useTokens } from "../design/tokens";
import Accordion from "../components/Accordion";
import BlockFeedPanel from "../components/BlockFeedPanel";
import SummaryCard from "../components/SummaryCard";
import DrillModal, { originFromEvent } from "../components/DrillModal";
import StatusPill, { SemanticStatus } from "../components/StatusPill";
import StatusLegend from "../components/StatusLegend";

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function KpiCard({
  label,
  value,
  sub,
  status,
}: {
  label: string;
  value: string | number;
  sub?: string;
  status?: SemanticStatus;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-surface-hairline bg-surface-raised p-5">
      <div className="text-badge uppercase tracking-wider text-ink-muted">{label}</div>
      <div className="text-hero text-ink-primary">{value}</div>
      {sub && <div className="text-body text-ink-secondary">{sub}</div>}
      {status && (
        <div>
          <StatusPill status={status} compact>
            {status === "compromised" ? "Action taken" : status === "warning" ? "Under watch" : "Clean"}
          </StatusPill>
        </div>
      )}
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

function ListBody({ children }: { children: React.ReactNode }) {
  return <div className="flex max-h-[60vh] flex-col gap-1 overflow-y-auto">{children}</div>;
}

type Section = "rsu" | "vehicle" | "revocations" | "flags" | "reassignments";

export default function LedgerScreen() {
  const [summary, setSummary] = useState<LedgerSummaryDto | null>(null);
  const [rsuTrust, setRsuTrust] = useState<TrustRecordDto[]>([]);
  const [vehicleTrust, setVehicleTrust] = useState<TrustRecordDto[]>([]);
  const [revocations, setRevocations] = useState<RevocationDto[]>([]);
  const [flags, setFlags] = useState<ControllerFlagDto[]>([]);
  const [reassignments, setReassignments] = useState<ReassignmentDto[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [openRsu, setOpenRsu] = useState<string | null>(null);
  const [openVeh, setOpenVeh] = useState<string | null>(null);
  const [openRev, setOpenRev] = useState<string | null>(null);
  const [openFlag, setOpenFlag] = useState<string | null>(null);
  const [openReassign, setOpenReassign] = useState<string | null>(null);
  const [openSection, setOpenSection] = useState<Section | null>(null);
  const originRef = useRef<{ dx: number; dy: number }>({ dx: 0, dy: 0 });
  const [refreshState, setRefreshState] = useState<LedgerRefreshStatusDto | null>(null);
  const pollRef = useRef<number | null>(null);
  // Explorer runs on its own port/tunnel, separate from this app's — see
  // /api/explorer_url's own docstring. null just means "no link configured
  // right now" (file missing or that second tunnel isn't up), not an error.
  const [explorerUrl, setExplorerUrl] = useState<string | null>(null);

  const openCard = (section: Section) => (e: React.MouseEvent<HTMLButtonElement>) => {
    originRef.current = originFromEvent(e);
    setOpenSection(section);
  };

  const loadAll = () =>
    Promise.all([
      api.ledgerSummary(),
      api.ledgerTrust("rsu"),
      api.ledgerTrust("vehicle"),
      api.ledgerRevocations(),
      api.ledgerFlags(),
      api.ledgerReassignments(),
    ]).then(([s, rsu, veh, rev, fl, ra]) => {
      setSummary(s);
      setRsuTrust(rsu);
      setVehicleTrust(veh.filter((v) => v.UpdateCount > 0));
      setRevocations(rev);
      setFlags(fl);
      setReassignments(ra);
    });

  useEffect(() => {
    loadAll().catch((e) => setError(String(e)));
    api.ledgerRefreshStatus().then(setRefreshState).catch(() => {});
    api.explorerUrl().then((r) => setExplorerUrl(r.url)).catch(() => {});
  }, []);

  const startLiveRefresh = () => {
    if (refreshState?.status === "running") return;
    api
      .ledgerRefresh()
      .then(() => {
        const startedFinishedAt = refreshState?.finished_at ?? null;
        pollRef.current = window.setInterval(() => {
          api.ledgerRefreshStatus().then((st) => {
            setRefreshState(st);
            if (st.status === "idle" && st.finished_at !== startedFinishedAt) {
              if (pollRef.current) window.clearInterval(pollRef.current);
              pollRef.current = null;
              if (!st.error) loadAll().catch((e) => setError(String(e)));
            }
          });
        }, 1500);
      })
      .catch(() => {});
  };

  useEffect(() => () => {
    if (pollRef.current) window.clearInterval(pollRef.current);
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
    <div className="h-full overflow-y-auto p-6">
      <div className="mx-auto max-w-5xl space-y-6">
        <header className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-page-title text-ink-primary">
              Blockchain ledger
            </h1>
            <p className="mt-1 text-body text-ink-secondary">
              {summary?.is_live ? (
                <>
                  A <span className="font-medium text-status-good">live</span> query against the real Hyperledger
                  Fabric ledger — queried {new Date(summary.captured_at).toLocaleString()}.
                </>
              ) : (
                <>
                  A point-in-time snapshot of the Hyperledger Fabric ledger
                  {summary && <> — captured {new Date(summary.captured_at).toLocaleString()}</>}. Defaults to this
                  file so the demo never depends on Fabric being reachable at presentation time — click "Refresh
                  live" for the real current state.
                </>
              )}
            </p>
          </div>
          <div className="flex flex-col items-end gap-2">
            <StatusLegend only={["safe", "warning", "compromised"]} />
            <div className="flex items-center gap-2">
              {refreshState?.error && (
                <span className="max-w-xs text-right text-[10px] text-status-missed">{refreshState.error}</span>
              )}
              {explorerUrl && (
                <a
                  href={explorerUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  title="Opens the full Hyperledger Explorer dashboard in a new tab — its own tunnel, separate from this demo's"
                  className="flex items-center gap-1.5 rounded border border-surface-hairline bg-surface-raised px-3 py-1.5 text-xs font-medium text-ink-secondary transition-colors hover:text-ink-primary"
                >
                  <ExternalLink size={13} /> Hyperledger Explorer
                </a>
              )}
              <button
                onClick={startLiveRefresh}
                disabled={refreshState?.status === "running"}
                className="rounded bg-entity-rsu px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-entity-rsu/90 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {refreshState?.status === "running" ? "Querying the live ledger…" : "Refresh live"}
              </button>
            </div>
          </div>
        </header>

        <BlockFeedPanel />

        {summary && (
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <KpiCard
              label="RSUs demoted"
              value={summary.rsus.demoted}
              sub={`of ${summary.rsus.total}`}
              status={summary.rsus.demoted > 0 ? "compromised" : "safe"}
            />
            <KpiCard
              label="Vehicles trust-decayed"
              value={summary.vehicles.decayed}
              sub={`of ${summary.vehicles.total}`}
              status={summary.vehicles.decayed > 0 ? "compromised" : "safe"}
            />
            <KpiCard
              label="Revocation votes"
              value={summary.revocations}
              status={summary.revocations > 0 ? "warning" : "safe"}
            />
            <KpiCard
              label="Controller reassignments"
              value={summary.reassignments}
              sub={`${summary.controller_flags} flags raised`}
              status={summary.reassignments > 0 ? "warning" : "safe"}
            />
          </div>
        )}

        <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
          <SummaryCard
            label="RSU trust"
            value={demotedRsu.length}
            caption="Demoted or under suspicion, out of the full RSU roster"
            onClick={openCard("rsu")}
          />
          <SummaryCard
            label="Vehicle trust"
            value={vehicleTrust.length}
            caption="Decayed from the clean-slate baseline score"
            onClick={openCard("vehicle")}
          />
          <SummaryCard
            label="Revocation votes"
            value={revocations.length}
            caption="Committed revocations, RSU or vehicle"
            onClick={openCard("revocations")}
          />
          <SummaryCard
            label="Controller flags"
            value={flags.length}
            caption="CP-DETECT conflicts raised against a controller"
            onClick={openCard("flags")}
          />
          <SummaryCard
            label="Controller reassignments"
            value={reassignments.length}
            caption="Controllers excluded and replaced"
            onClick={openCard("reassignments")}
          />
        </div>

        <DrillModal
          open={openSection === "rsu"}
          onClose={() => setOpenSection(null)}
          origin={originRef.current}
          title="RSU trust — demoted / under suspicion"
          maxWidth="max-w-2xl"
        >
          <ListBody>
            {demotedRsu.length === 0 && (
              <div className="px-1 py-3 text-xs text-ink-muted">
                No RSU has left the TRUSTED state.
              </div>
            )}
            {demotedRsu.map((r) => (
              <Accordion
                key={r.ID}
                open={openRsu === r.ID}
                onToggle={() => setOpenRsu((v) => (v === r.ID ? null : r.ID))}
                bodyMaxHeight={100}
                header={
                  <div className="flex flex-1 items-center gap-3 text-xs">
                    <span className="w-20 font-mono text-ink-primary">{r.RSUID}</span>
                    <StatusPill status="compromised" compact>{r.State}</StatusPill>
                    <TrustBar score={r.TrustScore} />
                    <span className="font-mono text-ink-secondary">{r.TrustScore.toFixed(4)}</span>
                    <span className="ml-auto text-ink-muted">
                      {r.ConsecutiveLowEpochs} low epochs · updated {r.UpdateCount}×
                    </span>
                  </div>
                }
              >
                <div className="border-t border-surface-hairline px-4 pb-3 pt-2 text-[11px] text-ink-secondary">
                  Crossed into <span className="text-ink-primary">{r.State}</span> after{" "}
                  {r.ConsecutiveLowEpochs} consecutive below-floor epochs, out of{" "}
                  {r.UpdateCount} ledger updates on record. Last epoch{" "}
                  {fmtTime(r.LastEpochTimestamp)}; trust record last written{" "}
                  {fmtTime(r.UpdatedAt)}.
                </div>
              </Accordion>
            ))}
          </ListBody>
        </DrillModal>

        <DrillModal
          open={openSection === "vehicle"}
          onClose={() => setOpenSection(null)}
          origin={originRef.current}
          title="Vehicle trust — decayed from baseline"
          maxWidth="max-w-2xl"
        >
          <ListBody>
            {vehicleTrust
              .sort((a, b) => a.TrustScore - b.TrustScore)
              .map((v) => (
                <Accordion
                  key={v.ID}
                  open={openVeh === v.ID}
                  onToggle={() => setOpenVeh((val) => (val === v.ID ? null : v.ID))}
                  bodyMaxHeight={100}
                  header={
                    <div className="flex flex-1 items-center gap-3 text-xs">
                      <span className="w-20 font-mono text-ink-primary">{v.VehicleID}</span>
                      {v.Probationary && (
                        <StatusPill status="warning" compact>PROBATION</StatusPill>
                      )}
                      <TrustBar score={v.TrustScore} />
                      <span className="font-mono text-ink-secondary">{v.TrustScore.toFixed(3)}</span>
                      <span className="ml-auto text-ink-muted">updated {v.UpdateCount}×</span>
                    </div>
                  }
                >
                  <div className="border-t border-surface-hairline px-4 pb-3 pt-2 text-[11px] text-ink-secondary">
                    {v.ConsecutiveLowEpochs > 0
                      ? `${v.ConsecutiveLowEpochs} consecutive below-floor epochs recorded. `
                      : ""}
                    Last epoch {fmtTime(v.LastEpochTimestamp)}; trust record last written{" "}
                    {fmtTime(v.UpdatedAt)}.
                  </div>
                </Accordion>
              ))}
          </ListBody>
        </DrillModal>

        <DrillModal
          open={openSection === "revocations"}
          onClose={() => setOpenSection(null)}
          origin={originRef.current}
          title="Revocation votes"
          maxWidth="max-w-2xl"
        >
          <ListBody>
            {revocations.map((r) => (
              <Accordion
                key={r.ID}
                open={openRev === r.ID}
                onToggle={() => setOpenRev((v) => (v === r.ID ? null : r.ID))}
                bodyMaxHeight={100}
                header={
                  <div className="flex flex-1 items-center gap-3 text-xs">
                    <span className="w-20 font-mono text-ink-primary">
                      {r.RSUID ?? r.VehicleID}
                    </span>
                    <span className="text-ink-secondary">{r.Reason}</span>
                    <span className="ml-auto text-ink-muted">
                      {new Date(r.RevokedAt).toLocaleTimeString()}
                    </span>
                  </div>
                }
              >
                <div className="border-t border-surface-hairline px-4 pb-3 pt-2 text-[11px] text-ink-secondary">
                  Vote recorded {fmtTime(r.Timestamp)}, committed to the ledger{" "}
                  {fmtTime(r.RevokedAt)}. Target: {r.RSUID ? `RSU ${r.RSUID}` : `vehicle ${r.VehicleID}`}.
                </div>
              </Accordion>
            ))}
          </ListBody>
        </DrillModal>

        <DrillModal
          open={openSection === "flags"}
          onClose={() => setOpenSection(null)}
          origin={originRef.current}
          title="Controller flags (CP-DETECT)"
          maxWidth="max-w-2xl"
        >
          <ListBody>
            {flags.map((f) => (
              <Accordion
                key={f.ID}
                open={openFlag === f.ID}
                onToggle={() => setOpenFlag((v) => (v === f.ID ? null : f.ID))}
                bodyMaxHeight={100}
                header={
                  <div className="flex flex-1 items-center gap-3 text-xs">
                    <span className="w-16 font-mono text-ink-primary">{f.ControllerID}</span>
                    <StatusPill status="warning" compact>flagged</StatusPill>
                    <span className="text-ink-secondary">re: {f.VehicleID}</span>
                    <span className="rounded bg-surface-raised px-1.5 py-0.5 text-[10px] text-ink-muted">
                      {f.Epoch}
                    </span>
                    <span className="ml-auto text-ink-muted">
                      {f.ConflictCount} conflict{f.ConflictCount !== 1 ? "s" : ""} /{" "}
                      {f.NumRSUs} RSU{f.NumRSUs !== 1 ? "s" : ""}
                    </span>
                  </div>
                }
              >
                <div className="border-t border-surface-hairline px-4 pb-3 pt-2 text-[11px] text-ink-secondary">
                  {f.ConflictCount} of {f.NumRSUs} RSUs disagreed on vehicle{" "}
                  {f.VehicleID}'s position, against this quorum's FP1 threshold
                  of {f.ThresholdFP1.toFixed(3)}. Flagged {fmtTime(f.FlaggedAt)}.
                </div>
              </Accordion>
            ))}
          </ListBody>
        </DrillModal>

        <DrillModal
          open={openSection === "reassignments"}
          onClose={() => setOpenSection(null)}
          origin={originRef.current}
          title="Controller reassignments"
          maxWidth="max-w-2xl"
        >
          <ListBody>
            {reassignments.map((r) => (
              <Accordion
                key={r.ID}
                open={openReassign === r.ID}
                onToggle={() => setOpenReassign((v) => (v === r.ID ? null : r.ID))}
                bodyMaxHeight={100}
                header={
                  <div className="flex flex-1 items-center gap-3 text-xs">
                    <StatusPill status="compromised" compact>{r.ExcludedController}</StatusPill>
                    <span className="text-ink-muted">excluded →</span>
                    <StatusPill status="safe" compact>{r.SuccessorController}</StatusPill>
                    <span className="rounded bg-surface-raised px-1.5 py-0.5 text-[10px] text-ink-muted">
                      {r.Epoch}
                    </span>
                    <span className="ml-auto text-ink-muted">{r.Reason}</span>
                  </div>
                }
              >
                <div className="border-t border-surface-hairline px-4 pb-3 pt-2 text-[11px] text-ink-secondary">
                  {r.ExcludedController} excluded at epoch {r.Epoch}, duties handed to{" "}
                  {r.SuccessorController}. Committed {fmtTime(r.At)}.
                </div>
              </Accordion>
            ))}
          </ListBody>
        </DrillModal>
      </div>
    </div>
  );
}
