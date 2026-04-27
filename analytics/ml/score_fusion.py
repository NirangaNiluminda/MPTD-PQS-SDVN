"""
score_fusion.py — MPTD-PQS Score Fusion Module
Paper §3.4.4, Eq. 3.46-3.48, §3.4.6

Fused score:  Φ_i(t) = λ₁·ψ_i(t) + λ₂·S_i(t) + λ₃·(ε_i(t) / θ_ae)
Decision:     anomalous if Φ_i(t) > Φ_threshold (default 0.5)

Default weights — paper §3.4.6 (Table III), reported optimal values:
  λ₁ = 0.3  — rule-based lightweight detection score (ψ, from NS-3)
  λ₂ = 0.4  — GAT spatial anomaly score (S_i)
  λ₃ = 0.3  — LSTM-AE normalised reconstruction error (ε_i / θ_ae)

Paper §3.4.6 states: "λ₁,λ₂,λ₃ are learned by minimising weighted
cross-entropy loss over the training set, subject to Σλ_k=1, λ_k>0."
Use learn_weights() to fit them on a labelled dataset; fall back to the
defaults (paper's converged values) when data is insufficient.
"""

from dataclasses import dataclass
import numpy as np

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


# ---------------------------------------------------------------------------
# λ Weight Learning (paper §3.4.6)
# ---------------------------------------------------------------------------

def learn_weights(psi_arr, gat_arr, ae_norm_arr, labels,
                  init: tuple = (LAMBDA_1, LAMBDA_2, LAMBDA_3),
                  min_samples: int = 50,
                  verbose: bool = True) -> tuple:
    """
    Learn optimal λ₁,λ₂,λ₃ by minimising weighted cross-entropy over labelled data.
    Paper §3.4.6: "weights learned by minimising cross-entropy, s.t. Σλ_k=1, λ_k>0."

    Args:
        psi_arr     : array-like (N,)  rule-based scores ψ_i ∈ [0,1]
        gat_arr     : array-like (N,)  GAT scores S_i ∈ [0,1]
        ae_norm_arr : array-like (N,)  normalised AE errors ε_i/θ_ae ∈ [0,1]
        labels      : array-like (N,)  ground-truth binary labels (is_poisoned)
        init        : initial (λ₁,λ₂,λ₃) — paper's optimal values as warm start
        min_samples : minimum labelled samples required; returns init if not met
        verbose     : print learned weights

    Returns:
        (lam1, lam2, lam3) — learned weights summing to 1.0
    """
    try:
        from scipy.optimize import minimize
    except ImportError:
        if verbose:
            print("[score_fusion] scipy not available — using default λ values")
        return init

    psi  = np.asarray(psi_arr,     dtype=float)
    gat  = np.asarray(gat_arr,     dtype=float)
    ae   = np.asarray(ae_norm_arr, dtype=float)
    y    = np.asarray(labels,      dtype=float)

    if len(y) < min_samples:
        if verbose:
            print(f"[score_fusion] Only {len(y)} samples < {min_samples} required — "
                  f"keeping default λ = {init}")
        return init

    eps = 1e-9  # numerical stability for log

    def _weighted_cross_entropy(lam):
        """Weighted BCE: Φ_i = λ₁ψ + λ₂S + λ₃ae, positive class weight = 2."""
        l1, l2, l3 = lam
        phi = np.clip(l1 * psi + l2 * gat + l3 * ae, eps, 1 - eps)
        # pos_weight = 2 to penalise false negatives more (attack detection)
        bce = -(2.0 * y * np.log(phi) + (1 - y) * np.log(1 - phi))
        return bce.mean()

    # Constraints: Σλ_k = 1 and λ_k ≥ 0.05 (prevent degenerate solutions)
    constraints = [{"type": "eq", "fun": lambda lam: lam.sum() - 1.0}]
    bounds = [(0.05, 0.90)] * 3

    result = minimize(
        _weighted_cross_entropy,
        x0     = np.array(init),
        method = "SLSQP",
        bounds = bounds,
        constraints = constraints,
        options = {"ftol": 1e-8, "maxiter": 500},
    )

    if result.success:
        l1, l2, l3 = result.x
        if verbose:
            print(f"[score_fusion] Learned λ: λ₁={l1:.4f}  λ₂={l2:.4f}  λ₃={l3:.4f}"
                  f"  (loss={result.fun:.6f}, {len(y)} samples)")
        return float(l1), float(l2), float(l3)
    else:
        if verbose:
            print(f"[score_fusion] Optimisation did not converge ({result.message})"
                  f" — keeping init λ = {init}")
        return init
