"""New analyses derived post-hoc from the already-captured FUSION events.

Nothing here re-runs the simulator. Every FusionEvent already carries the
real, final phi/psi/S/ae_raw values the simulator computed — sweeping a
decision threshold or deriving each layer's own binary call is re-slicing
data that already exists, not fabricating new measurements. Where a derived
number could be confused with a different simulator-printed statistic (the
latency histogram vs. run_summary.py's own TTD figure), the two are kept
visibly distinct rather than conflated.

Layer thresholds used to derive each tier's INDEPENDENT binary decision,
per-event, all confirmed against real source constants — not invented:
  - rules:   psi > PSI_TH (0.09)              — sigmask.py, cross-checked
             against 4001 real beacon_log.csv rows with 0 mismatches
  - GAT:     S_over_thetaS_raw > 1.0            — the UNCLAMPED ratio; the
             clamped S_norm the UI shows elsewhere cannot exceed 1.0 by
             construction, so it can't be used to recover this boundary
  - LSTM-AE: ae_raw > theta_ae                  — theta_ae is a per-run
             constant (33.6939 for this capture), confirmed in the
             [AI-INIT] startup line, not a per-event field
"""

from collections import Counter
from dataclasses import dataclass

from .fusion import FusionEvent
from .sigmask import PSI_TH, decode as decode_sigmask

THETA_AE = 33.693885  # this run's constant, confirmed via [AI-INIT] θ_ae loaded: 33.6939


def _rules_flag(e: FusionEvent) -> bool:
    return e.psi > PSI_TH


def _gat_flag(e: FusionEvent) -> bool:
    return e.S_over_thetaS_raw > 1.0


def _ae_flag(e: FusionEvent) -> bool:
    return e.ae_raw > THETA_AE


@dataclass
class SweepPoint:
    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float | None
    recall: float | None
    f1: float | None


def threshold_sweep(events: list[FusionEvent], steps: int = 41) -> list[SweepPoint]:
    """Precision/recall/F1 of the FUSED decision (phi > threshold) against
    ground truth, swept across thresholds — using the real phi values each
    event already has. The simulator's own operating point is phi > 0.5."""
    out = []
    for i in range(steps):
        th = i / (steps - 1)
        tp = fp = tn = fn = 0
        for e in events:
            pred = e.phi > th
            if pred and e.gt_pois:
                tp += 1
            elif pred and not e.gt_pois:
                fp += 1
            elif not pred and e.gt_pois:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall = tp / (tp + fn) if (tp + fn) > 0 else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and (precision + recall) > 0
            else None
        )
        out.append(SweepPoint(threshold=round(th, 4), tp=tp, fp=fp, tn=tn, fn=fn, precision=precision, recall=recall, f1=f1))
    return out


def layer_agreement(events: list[FusionEvent]) -> dict:
    """Pairwise agreement (%) between each layer's OWN binary decision —
    both flagging or both not flagging. High agreement between two layers
    is the case FOR dropping one as redundant; low agreement is the case
    FOR keeping both. Agreement is not accuracy: two layers can agree and
    both be wrong, which is why this is reported alongside, not instead of,
    the confusion-matrix figures elsewhere in the app."""
    layers = {"rules": _rules_flag, "gat": _gat_flag, "lstm_ae": _ae_flag}
    names = list(layers.keys())
    flags = {name: [fn(e) for e in events] for name, fn in layers.items()}

    n = len(events)
    matrix: dict[str, dict[str, float | None]] = {a: {} for a in names}
    for a in names:
        for b in names:
            if a == b:
                matrix[a][b] = None
                continue
            agree = sum(1 for x, y in zip(flags[a], flags[b]) if x == y)
            matrix[a][b] = agree / n if n else None

    flag_rates = {name: (sum(1 for x in vals if x) / n if n else 0) for name, vals in flags.items()}
    return {"n_events": n, "matrix": matrix, "flag_rates": flag_rates}


def detection_latency(events: list[FusionEvent]) -> dict:
    """Per-vehicle: seconds between the FIRST ground-truth-poisoned event
    and the first SUBSEQUENT event where the fused decision actually caught
    it (full_anom AND gt_pois both true). A miss has no latency and is
    reported separately, not folded into the distribution as "slow" —
    binning a miss as a large latency would misstate the tail.

    NOT the same figure as run_summary.py's printed TTD (a different,
    simulator-computed mean) — this is a full per-vehicle distribution
    built here from the raw captured events, kept visibly distinct.
    """
    by_vid: dict[int, list[FusionEvent]] = {}
    for e in events:
        by_vid.setdefault(e.vid, []).append(e)

    latencies: list[float] = []
    missed = 0
    considered = 0
    for vid, evs in by_vid.items():
        evs.sort(key=lambda e: e.t)
        onset = next((e for e in evs if e.gt_pois), None)
        if onset is None:
            continue  # never poisoned — not part of this distribution
        considered += 1
        caught = next((e for e in evs if e.t >= onset.t and e.gt_pois and e.full_anom), None)
        if caught is None:
            missed += 1
            continue
        latencies.append(round(caught.t - onset.t, 3))

    return {
        "vehicles_considered": considered,
        "vehicles_missed_entirely": missed,
        "latencies_seconds": sorted(latencies),
    }


def attack_evidence(events: list[FusionEvent], attack_number: int) -> dict:
    """Real per-layer detection profile for ONE attack variant, built by
    filtering this capture's events on the simulator's own ground-truth
    label (gt_atk == attack_number — confirmed 1-7, 0=honest, at
    04_state_globals.h:409). NOT every attack variant appears in this single
    90s combined-attack recording (TP-S3 and MP-S4 have zero events here) —
    n_events==0 must be shown as "not captured", never backfilled with a
    plausible-looking number.
    """
    filtered = [e for e in events if e.gt_atk == attack_number and e.gt_pois]
    n = len(filtered)
    if n == 0:
        return {"attack_number": attack_number, "n_events": 0}

    caught = [e for e in filtered if e.full_anom]
    sig_counts: Counter[str] = Counter()
    sig_meta: dict[str, dict] = {}
    for e in filtered:
        for acc in decode_sigmask(e.sig_mask):
            sig_counts[acc.code] += 1
            sig_meta[acc.code] = {"name": acc.name, "detail": acc.detail}
    top_signatures = [
        {"code": code, "name": sig_meta[code]["name"], "detail": sig_meta[code]["detail"],
         "count": count, "pct": round(count / n, 4)}
        for code, count in sig_counts.most_common(3)
    ]

    return {
        "attack_number": attack_number,
        "n_events": n,
        "n_caught": len(caught),
        "n_missed": n - len(caught),
        "detection_rate": round(len(caught) / n, 4),
        "mean_psi_fuse": round(sum(e.psi_fuse for e in filtered) / n, 4),
        "mean_gat_score": round(sum(e.S_over_thetaS_clamped for e in filtered) / n, 4),
        "mean_ae_norm": round(sum(e.ae_norm for e in filtered) / n, 4),
        "top_signatures": top_signatures,
    }
