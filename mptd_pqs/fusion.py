"""
Fusion Module — Combined detection score
=========================================
Implements Equation 3.54–3.57 from Section 3.4.4 of the paper.

Combined score:
  Φᵢ(t) = λ₁ · ψᵢ(t) + λ₂ · Sᵢ(t) + λ₃ · (εᵢ(t) / θ_ae)

Where:
  ψᵢ(t)       - lightweight signature score [0,1]   (LW-DETECT)
  Sᵢ(t)       - GAT spatial anomaly score [0,1]     (GAT Detector)
  εᵢ(t)/θ_ae  - normalized AE reconstruction error  (Temporal AE)
  λ₁=0.40, λ₂=0.35, λ₃=0.25 (weights from Table 3.4)

Decision threshold: Φᵢ(t) ≥ θ_fuse → ATTACK DETECTED
Revocation trigger: consecutive flags ≥ N_revoke → SC-Revoke
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


# ── Fusion weights (Table 3.4) ────────────────────────────────────────────────
LAMBDA_1   = 0.40   # LW-DETECT weight
LAMBDA_2   = 0.35   # GAT weight
LAMBDA_3   = 0.25   # Temporal AE weight
THETA_FUSE = 0.50   # final fusion threshold
THETA_AE   = 5.0    # AE reconstruction error normalizer
N_REVOKE   = 3      # consecutive flags before revocation


# ── Ablation variant weights ───────────────────────────────────────────────────
ABLATION_WEIGHTS = {
    "A1": (1.00, 0.00, 0.00),   # Lightweight only
    "A2": (0.00, 1.00, 0.00),   # GAT only
    "A3": (0.00, 0.00, 1.00),   # Temporal AE only
    "A4": (0.40, 0.35, 0.25),   # Full AI, no TRS/FHE
    "A5": (0.40, 0.35, 0.25),   # Full mode, no blockchain
    "FULL": (LAMBDA_1, LAMBDA_2, LAMBDA_3),  # Complete MPTD-PQS
}


@dataclass
class FusionResult:
    vehicle_id: str
    rsu_id: str
    timestamp: float
    phi: float                      # combined score Φᵢ(t)
    flagged: bool                   # Φᵢ(t) ≥ θ_fuse
    psi: float = 0.0                # LW-DETECT score
    gat_score: float = 0.0         # GAT score
    ae_score_norm: float = 0.0     # normalized AE score
    ground_truth_poisoned: bool = False
    revocation_triggered: bool = False
    variant: str = "FULL"


class FusionEngine:
    """
    Combines scores from LW-DETECT, GAT, and Temporal AE into Φᵢ(t).
    Tracks consecutive flags per vehicle for revocation decision.
    """

    def __init__(self, lambda1: float = LAMBDA_1, lambda2: float = LAMBDA_2,
                 lambda3: float = LAMBDA_3, theta_fuse: float = THETA_FUSE,
                 theta_ae: float = THETA_AE, n_revoke: int = N_REVOKE,
                 variant: str = "FULL"):
        l1, l2, l3 = ABLATION_WEIGHTS.get(variant, (lambda1, lambda2, lambda3))
        self.lambda1  = l1
        self.lambda2  = l2
        self.lambda3  = l3
        self.theta_fuse = theta_fuse
        self.theta_ae   = theta_ae
        self.n_revoke   = n_revoke
        self.variant    = variant

        # Normalize weights so they sum to 1
        total = self.lambda1 + self.lambda2 + self.lambda3
        if total > 0:
            self.lambda1 /= total
            self.lambda2 /= total
            self.lambda3 /= total

        # Per-vehicle consecutive flag counter
        self._consec_flags: Dict[str, int] = defaultdict(int)
        self.results: List[FusionResult] = []

    def fuse(self, vehicle_id: str, rsu_id: str, timestamp: float,
             psi: float = 0.0, gat_score: float = 0.0, ae_score: float = 0.0,
             ground_truth_poisoned: bool = False) -> FusionResult:
        """
        Compute Φᵢ(t) = λ₁·ψ + λ₂·S + λ₃·(ε/θ_ae)   (Eq 3.54)
        """
        ae_norm = min(1.0, ae_score / self.theta_ae) if self.theta_ae > 0 else 0.0

        phi = (self.lambda1 * psi +
               self.lambda2 * gat_score +
               self.lambda3 * ae_norm)
        phi = min(1.0, max(0.0, phi))

        flagged = phi >= self.theta_fuse

        # Track consecutive flags for revocation
        if flagged:
            self._consec_flags[vehicle_id] += 1
        else:
            self._consec_flags[vehicle_id] = 0

        revocation = self._consec_flags[vehicle_id] >= self.n_revoke

        result = FusionResult(
            vehicle_id=vehicle_id,
            rsu_id=rsu_id,
            timestamp=timestamp,
            phi=phi,
            flagged=flagged,
            psi=psi,
            gat_score=gat_score,
            ae_score_norm=ae_norm,
            ground_truth_poisoned=ground_truth_poisoned,
            revocation_triggered=revocation,
            variant=self.variant,
        )
        self.results.append(result)
        return result

    def fuse_from_dicts(self, lw_result: dict, gat_result: Optional[dict],
                         ae_result: Optional[dict]) -> FusionResult:
        """Convenience method: fuse from detector result dicts."""
        vid = lw_result.get("vehicle_id", "V?")
        rid = lw_result.get("rsu_id", "RSU?")
        t   = lw_result.get("timestamp", 0.0)
        psi = lw_result.get("psi", 0.0)
        gat = gat_result.get("gat_score", 0.0) if gat_result else 0.0
        ae  = ae_result.get("ae_score", 0.0) if ae_result else 0.0
        gt  = lw_result.get("ground_truth_poisoned", False)
        return self.fuse(vid, rid, t, psi=psi, gat_score=gat,
                         ae_score=ae, ground_truth_poisoned=gt)

    def summary(self) -> dict:
        """Return detection summary counts."""
        tp = sum(1 for r in self.results if r.flagged and r.ground_truth_poisoned)
        fp = sum(1 for r in self.results if r.flagged and not r.ground_truth_poisoned)
        tn = sum(1 for r in self.results if not r.flagged and not r.ground_truth_poisoned)
        fn = sum(1 for r in self.results if not r.flagged and r.ground_truth_poisoned)
        return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
                "total": len(self.results), "variant": self.variant}

    def reset(self):
        self._consec_flags.clear()
        self.results.clear()


def run_ablation(lw_results: list, gat_results: list, ae_results: list) -> Dict[str, dict]:
    """
    Run all 5 ablation variants + FULL and return summaries.
    All three result lists should be same length and aligned by vehicle/timestamp.
    """
    ablation_summaries = {}
    for variant in ["A1", "A2", "A3", "A4", "A5", "FULL"]:
        engine = FusionEngine(variant=variant)
        for lw, gat, ae in zip(lw_results, gat_results, ae_results):
            engine.fuse_from_dicts(lw, gat, ae)
        ablation_summaries[variant] = engine.summary()
    return ablation_summaries


if __name__ == "__main__":
    # Quick test
    engine = FusionEngine(variant="FULL")

    test_cases = [
        # (psi, gat, ae, poisoned)
        (0.1, 0.05, 0.3, False),    # clean — low scores
        (0.8, 0.7, 12.0, True),     # attack — high scores
        (0.5, 0.4, 8.0, True),      # borderline attack
        (0.0, 0.0, 0.0, False),     # perfectly clean
        (1.0, 1.0, 20.0, True),     # severe attack
    ]

    print("Fusion Engine Test:")
    for psi, gat, ae, gt in test_cases:
        r = engine.fuse("V0", "RSU0", 0.0, psi=psi, gat_score=gat,
                        ae_score=ae, ground_truth_poisoned=gt)
        label = "ATTACK" if r.flagged else "clean"
        true_l = "POISONED" if gt else "clean"
        print(f"  ψ={psi:.2f} S={gat:.2f} ε={ae:.1f} -> Φ={r.phi:.3f} [{label}] gt={true_l}")

    print("\nSummary:", engine.summary())
