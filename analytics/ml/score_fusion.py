"""
score_fusion.py — MPTD-PQS Score Fusion Module
Paper §3.4.4, Eq. 3.46-3.48

Fused score:  Φ_i(t) = λ₁·ψ_i(t) + λ₂·S_i(t) + λ₃·(ε_i(t) / θ_ae)
Decision:     anomalous if Φ_i(t) > Φ_threshold (default 0.5)

Default weights (paper Table III):
  λ₁ = 0.3  — rule-based lightweight detection score (ψ, from NS-3)
  λ₂ = 0.4  — GAT spatial anomaly score (S_i)
  λ₃ = 0.3  — LSTM-AE normalised reconstruction error (ε_i / θ_ae)
"""

from dataclasses import dataclass

LAMBDA_1     = 0.3   # rule-based weight
LAMBDA_2     = 0.4   # GAT weight
LAMBDA_3     = 0.3   # LSTM-AE weight
PHI_THRESHOLD = 0.5  # decision boundary


@dataclass
class FusionResult:
    phi_score:    float
    is_anomalous: bool
    psi_score:    float   # rule-based score from NS-3
    gat_score:    float   # S_i from GATDetector
    ae_error:     float   # ε_i raw reconstruction error
    ae_norm:      float   # ε_i / θ_ae  (normalised)


def fuse(psi: float, gat_score: float, ae_error: float,
         theta_ae: float,
         lam1: float = LAMBDA_1,
         lam2: float = LAMBDA_2,
         lam3: float = LAMBDA_3,
         phi_thresh: float = PHI_THRESHOLD) -> FusionResult:
    """
    Compute fused anomaly score Φ_i(t).

    Args:
        psi       : rule-based lightweight score ∈ [0,1] (from NS-3 beacon handler)
        gat_score : spatial anomaly score S_i ∈ [0,1] from GATDetector
        ae_error  : raw LSTM-AE reconstruction error ε_i (MSE, ≥ 0)
        theta_ae  : adaptive threshold θ_ae (calibrated on clean data)
    Returns:
        FusionResult with phi_score and anomaly decision
    """
    ae_norm  = min(ae_error / max(theta_ae, 1e-9), 1.0)  # clamp to [0,1]
    phi      = lam1 * psi + lam2 * gat_score + lam3 * ae_norm
    return FusionResult(
        phi_score    = phi,
        is_anomalous = phi > phi_thresh,
        psi_score    = psi,
        gat_score    = gat_score,
        ae_error     = ae_error,
        ae_norm      = ae_norm,
    )


def fuse_batch(psi_arr, gat_arr, ae_arr, theta_ae: float,
               **kwargs) -> list:
    """
    Vectorised fusion for a list/array of vehicle scores in one snapshot.
    All inputs must be same length (N vehicles).
    Returns list of FusionResult.
    """
    return [
        fuse(float(p), float(g), float(e), theta_ae, **kwargs)
        for p, g, e in zip(psi_arr, gat_arr, ae_arr)
    ]
