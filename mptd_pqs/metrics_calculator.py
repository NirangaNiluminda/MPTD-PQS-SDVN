"""
Metrics Calculator — All evaluation metrics from the paper
===========================================================
Implements Section 3.7 metrics:

  Classification metrics:
    MCC   Matthews Correlation Coefficient (Eq 3.68)
    FPR   False Positive Rate             (Eq 3.69)

  Attack-specific metrics:
    PARR  Poisoned Attack Record Rate     (Eq 3.70)
    CDER  Cumulative Deviation Error Rate (Eq 3.71)

  System performance metrics:
    TDEE  Trajectory Deviation Error Energy (Eq 3.72)
    TPE   Trajectory Poisoning Effectiveness (Eq 3.73)
    PBPO  Poisoned Blockchain Persistence Offset (Eq 3.74)

Baseline comparisons: B1 (Ghaleb 2014), B2 (Vishwanath 2026), B3 (Somma 2025)
Ablation variants:    A1-A5, FULL
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ConfusionMatrix:
    TP: int = 0
    FP: int = 0
    TN: int = 0
    FN: int = 0

    @property
    def total(self) -> int:
        return self.TP + self.FP + self.TN + self.FN

    @property
    def precision(self) -> float:
        denom = self.TP + self.FP
        return self.TP / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.TP + self.FN
        return self.TP / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        return (self.TP + self.TN) / self.total if self.total > 0 else 0.0


@dataclass
class MetricsResult:
    """All computed metrics for one experiment condition."""
    variant: str
    attack_percentage: int

    # Confusion matrix
    cm: ConfusionMatrix = field(default_factory=ConfusionMatrix)

    # Core metrics
    mcc: float = 0.0
    fpr: float = 0.0

    # Attack metrics
    parr: float = 0.0
    cder: float = 0.0

    # System metrics
    tdee: float = 0.0
    tpe: float = 0.0
    pbpo: float = 0.0

    # Derived
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    accuracy: float = 0.0


class MetricsCalculator:
    """
    Computes all paper metrics from detection results and trajectory data.
    """

    # ── Classification metrics ─────────────────────────────────────────────────

    @staticmethod
    def compute_mcc(cm: ConfusionMatrix) -> float:
        """
        Matthews Correlation Coefficient (Eq 3.68):
          MCC = (TP·TN - FP·FN) / √((TP+FP)(TP+FN)(TN+FP)(TN+FN))
        Range: [-1, +1]; +1 = perfect, 0 = random, -1 = inverse
        """
        tp, fp, tn, fn = cm.TP, cm.FP, cm.TN, cm.FN
        numerator = tp * tn - fp * fn
        denom_sq = (tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)
        if denom_sq <= 0:
            return 0.0
        return numerator / math.sqrt(denom_sq)

    @staticmethod
    def compute_fpr(cm: ConfusionMatrix) -> float:
        """
        False Positive Rate (Eq 3.69):
          FPR = FP / (FP + TN)
        Proportion of clean trajectories incorrectly flagged.
        """
        denom = cm.FP + cm.TN
        return cm.FP / denom if denom > 0 else 0.0

    # ── Attack-specific metrics ────────────────────────────────────────────────

    @staticmethod
    def compute_parr(n_poisoned_detected: int, n_poisoned_total: int) -> float:
        """
        Poisoned Attack Record Rate (Eq 3.70):
          PARR = N_poisoned_detected / N_poisoned_total
        Proportion of poisoned records that were detected.
        """
        if n_poisoned_total <= 0:
            return 0.0
        return n_poisoned_detected / n_poisoned_total

    @staticmethod
    def compute_cder(deviations: List[float], threshold: float = 10.0) -> float:
        """
        Cumulative Deviation Error Rate (Eq 3.71):
          CDER = (1/N) · Σ |δᵢ| · 1[|δᵢ| > θ_dev]
        Mean absolute deviation for trajectories that exceed the threshold.
        deviations: list of position deviations (meters)
        """
        if not deviations:
            return 0.0
        exceeded = [abs(d) for d in deviations if abs(d) > threshold]
        if not exceeded:
            return 0.0
        return sum(exceeded) / len(deviations)

    # ── System performance metrics ─────────────────────────────────────────────

    @staticmethod
    def compute_tdee(deviations: List[float]) -> float:
        """
        Trajectory Deviation Error Energy (Eq 3.72):
          TDEE = Σ δᵢ²  (total squared deviation energy)
        High TDEE indicates large cumulative poisoning impact.
        """
        return sum(d * d for d in deviations)

    @staticmethod
    def compute_tpe(n_poisoned_injected: int, n_total_trajectories: int) -> float:
        """
        Trajectory Poisoning Effectiveness (Eq 3.73):
          TPE = N_poisoned_injected / N_total_trajectories
        Fraction of all trajectories that were successfully poisoned by attacker.
        """
        if n_total_trajectories <= 0:
            return 0.0
        return n_poisoned_injected / n_total_trajectories

    @staticmethod
    def compute_pbpo(n_poisoned_on_chain: int, n_total_on_chain: int,
                     n_detected_before_store: int = 0) -> float:
        """
        Poisoned Blockchain Persistence Offset (Eq 3.74):
          PBPO = N_poisoned_on_chain / N_total_on_chain
        Proportion of blockchain records that are poisoned.
        Lower is better (mitigation should reduce this).
        """
        if n_total_on_chain <= 0:
            return 0.0
        return n_poisoned_on_chain / n_total_on_chain

    # ── Full metrics computation ───────────────────────────────────────────────

    def compute_all(self, fusion_results: list, deviations: List[float],
                    n_poisoned_injected: int, n_total_trajectories: int,
                    n_poisoned_on_chain: int, n_total_on_chain: int,
                    variant: str = "FULL",
                    attack_percentage: int = 0) -> MetricsResult:
        """
        Compute all metrics from a list of fusion results.

        fusion_results: list of FusionResult objects (or dicts with
                        'flagged' and 'ground_truth_poisoned' keys)
        deviations:     list of per-trajectory position deviations (m)
        """
        cm = ConfusionMatrix()
        n_detected_poisoned = 0

        for r in fusion_results:
            if hasattr(r, 'flagged'):
                flagged = r.flagged
                gt = r.ground_truth_poisoned
            else:
                flagged = r.get('flagged', False)
                gt = r.get('ground_truth_poisoned', False)

            if flagged and gt:
                cm.TP += 1
                n_detected_poisoned += 1
            elif flagged and not gt:
                cm.FP += 1
            elif not flagged and gt:
                cm.FN += 1
            else:
                cm.TN += 1

        mcc  = self.compute_mcc(cm)
        fpr  = self.compute_fpr(cm)
        parr = self.compute_parr(n_detected_poisoned, cm.TP + cm.FN)
        cder = self.compute_cder(deviations)
        tdee = self.compute_tdee(deviations)
        tpe  = self.compute_tpe(n_poisoned_injected, n_total_trajectories)
        pbpo = self.compute_pbpo(n_poisoned_on_chain, n_total_on_chain)

        result = MetricsResult(
            variant=variant,
            attack_percentage=attack_percentage,
            cm=cm,
            mcc=mcc,
            fpr=fpr,
            parr=parr,
            cder=cder,
            tdee=tdee,
            tpe=tpe,
            pbpo=pbpo,
            precision=cm.precision,
            recall=cm.recall,
            f1=cm.f1,
            accuracy=cm.accuracy,
        )
        return result

    def print_report(self, result: MetricsResult):
        """Pretty-print metrics report."""
        print(f"\n{'='*60}")
        print(f"  Metrics Report — {result.variant} | Attack {result.attack_percentage}%")
        print(f"{'='*60}")
        print(f"  Confusion Matrix: TP={result.cm.TP}  FP={result.cm.FP}  "
              f"TN={result.cm.TN}  FN={result.cm.FN}")
        print(f"  MCC      : {result.mcc:+.4f}  (range [-1,+1]; higher=better)")
        print(f"  FPR      : {result.fpr:.4f}   (lower=better)")
        print(f"  Precision: {result.precision:.4f}")
        print(f"  Recall   : {result.recall:.4f}")
        print(f"  F1       : {result.f1:.4f}")
        print(f"  Accuracy : {result.accuracy:.4f}")
        print(f"  ---")
        print(f"  PARR     : {result.parr:.4f}  (detection rate of poisoned records)")
        print(f"  CDER     : {result.cder:.4f}  m (cumulative deviation error rate)")
        print(f"  TDEE     : {result.tdee:.4f}  m² (total squared deviation energy)")
        print(f"  TPE      : {result.tpe:.4f}   (attacker poisoning effectiveness)")
        print(f"  PBPO     : {result.pbpo:.4f}  (poisoned blockchain proportion)")
        print(f"{'='*60}")

    def to_dict(self, result: MetricsResult) -> dict:
        return {
            "variant": result.variant,
            "attack_percentage": result.attack_percentage,
            "TP": result.cm.TP, "FP": result.cm.FP,
            "TN": result.cm.TN, "FN": result.cm.FN,
            "mcc": round(result.mcc, 6),
            "fpr": round(result.fpr, 6),
            "precision": round(result.precision, 6),
            "recall": round(result.recall, 6),
            "f1": round(result.f1, 6),
            "accuracy": round(result.accuracy, 6),
            "parr": round(result.parr, 6),
            "cder": round(result.cder, 6),
            "tdee": round(result.tdee, 6),
            "tpe": round(result.tpe, 6),
            "pbpo": round(result.pbpo, 6),
        }


# ── Baseline values from literature (Table 4.x in paper) ──────────────────────
BASELINES = {
    "B1_Ghaleb2014": {
        "mcc": 0.61, "fpr": 0.18, "parr": 0.72, "cder": 8.3,
        "note": "Ghaleb et al. 2014 — rule-based RSU detection"
    },
    "B2_Vishwanath2026": {
        "mcc": 0.74, "fpr": 0.12, "parr": 0.81, "cder": 5.7,
        "note": "Vishwanath & Reddy 2026 — ML-based detection"
    },
    "B3_Somma2025": {
        "mcc": 0.78, "fpr": 0.09, "parr": 0.85, "cder": 4.2,
        "note": "Somma 2025 — blockchain-based trajectory integrity"
    },
}


if __name__ == "__main__":
    from mptd_pqs.fusion import FusionResult

    calc = MetricsCalculator()

    # Synthetic results
    class _FR:
        def __init__(self, flagged, gt):
            self.flagged = flagged
            self.ground_truth_poisoned = gt

    results = [
        _FR(True, True),   # TP
        _FR(True, True),   # TP
        _FR(False, True),  # FN
        _FR(True, False),  # FP
        _FR(False, False), # TN
        _FR(False, False), # TN
        _FR(False, False), # TN
    ]

    deviations = [0.0, 0.0, 15.2, 23.8, 0.0, 0.0, 0.0]

    m = calc.compute_all(results, deviations,
                         n_poisoned_injected=3, n_total_trajectories=7,
                         n_poisoned_on_chain=2, n_total_on_chain=7,
                         variant="FULL", attack_percentage=50)
    calc.print_report(m)

    print("\nBaseline comparison:")
    for name, vals in BASELINES.items():
        print(f"  {name}: MCC={vals['mcc']:.2f}  FPR={vals['fpr']:.2f}  "
              f"PARR={vals['parr']:.2f}")
    print(f"  MPTD-PQS:       MCC={m.mcc:+.4f}  FPR={m.fpr:.4f}  PARR={m.parr:.4f}")
