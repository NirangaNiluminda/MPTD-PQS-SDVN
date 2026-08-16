import { useEffect, useRef, useState } from "react";
import {
  api,
  ControllerFlagDto,
  LedgerSummaryDto,
  ReassignmentDto,
  RevocationDto,
  TrustRecordDto,
} from "../api";
import { useTokens } from "../design/tokens";
import Accordion from "../components/Accordion";
import SummaryCard from "../components/SummaryCard";
import DrillModal, { originFromEvent } from "../components/DrillModal";

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
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

  const openCard = (section: Section) => (e: React.MouseEvent<HTMLButtonElement>) => {
    originRef.current = originFromEvent(e);
    setOpenSection(section);
  };

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
                    <span className="rounded bg-status-missed/20 px-1.5 py-0.5 text-[10px] font-medium text-status-missed">
                      {r.State}
                    </span>
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
                        <span className="rounded bg-status-caught/20 px-1.5 py-0.5 text-[10px] font-medium text-status-caught">
                          PROBATION
                        </span>
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
                    <span className="font-mono text-status-missed">{r.ExcludedController}</span>
                    <span className="text-ink-muted">excluded →</span>
                    <span className="font-mono text-status-good">{r.SuccessorController}</span>
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
