import { useMemo, useRef, useState } from "react";
import { ArrowRight } from "lucide-react";
import { usePlayback } from "../store/playback";
import { currentBeaconAt } from "./vehicleTrack";
import { originFromEvent } from "./DrillModal";
import VehicleAnalysisModal from "./VehicleAnalysisModal";

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 py-1">
      <span className="text-xs text-ink-muted">{label}</span>
      <span className="text-right text-xs font-medium text-ink-primary">{value}</span>
    </div>
  );
}

/**
 * The lightweight content that appears inline under a selected row in
 * DetectionFeed — quick facts only. Anything chart-heavy lives one click
 * away in VehicleAnalysisModal, which needs real width to be readable and
 * this sidebar deliberately doesn't have.
 */
export default function VehicleEventDetail() {
  const { selectedVehicle, vehicleTrack, loadingVehicle, t } = usePlayback();
  const [modalOpen, setModalOpen] = useState(false);
  const originRef = useRef<{ dx: number; dy: number }>({ dx: 0, dy: 0 });

  const current = useMemo(() => currentBeaconAt(vehicleTrack, t), [vehicleTrack, t]);

  if (selectedVehicle === null) return null;

  const decisionText = current
    ? current.is_poisoned
      ? current.detected
        ? "Lying — caught"
        : "Lying — missed"
      : "Honest"
    : "No beacon at this time";
  const decisionTone = current
    ? current.is_poisoned
      ? current.detected
        ? "text-status-caught"
        : "text-status-missed"
      : "text-status-good"
    : "text-ink-muted";

  const topAccusation = current?.accusations[0];

  if (loadingVehicle) {
    return <div className="p-4 text-xs text-ink-muted">Loading trajectory…</div>;
  }
  if (!vehicleTrack) return null;

  const openAnalysis = (e: React.MouseEvent<HTMLButtonElement>) => {
    originRef.current = originFromEvent(e);
    setModalOpen(true);
  };

  return (
    <div className="space-y-3 border-t border-surface-hairline bg-surface-page/60 p-3.5">
      <section className="rounded-lg border border-surface-hairline bg-surface-raised p-3">
        <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
          Vehicle summary at t = {t.toFixed(1)}s
        </h3>
        {current ? (
          <>
            <Row label="Status" value={<span className={decisionTone}>{decisionText}</span>} />
            <Row label="Attacker type" value={current.attacker_class_plain} />
            <Row label="Speed" value={`${current.speed.toFixed(1)} m/s`} />
            <Row
              label="Position error"
              value={current.drift_m == null ? "n/a (fabricated ID)" : `${current.drift_m.toFixed(1)} m`}
            />
            <Row label="ψ score" value={current.psi_score.toFixed(3)} />
          </>
        ) : (
          <p className="text-xs text-ink-muted">No beacon at this time.</p>
        )}
      </section>

      <section className="rounded-lg border border-surface-hairline bg-surface-raised p-3">
        <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
          Why it was flagged
        </h3>
        {topAccusation ? (
          <p className="text-xs leading-relaxed text-ink-secondary">
            <span className="font-medium text-ink-primary">{topAccusation.name}.</span> {topAccusation.detail}
          </p>
        ) : (
          <p className="text-xs text-ink-muted">
            {current?.is_poisoned
              ? "No rule signature fired — this lie went unnoticed by the signature tier."
              : "No signatures tripped."}
          </p>
        )}
      </section>

      <button
        onClick={openAnalysis}
        className="flex w-full items-center justify-center gap-1.5 rounded-md bg-entity-rsu py-2 text-xs font-semibold text-white transition-opacity hover:opacity-90"
      >
        View full analysis
        <ArrowRight size={13} strokeWidth={2.5} aria-hidden />
      </button>

      <VehicleAnalysisModal open={modalOpen} onClose={() => setModalOpen(false)} origin={originRef.current} />
    </div>
  );
}
