"""
MPTD-PQS: Mobility Pattern Trajectory Detection with Post-Quantum Security
==========================================================================
Dual-mode detection framework for Software Defined Vehicular Networks (SDVN).

Modules:
  lightweight_detector  - RSU-side: HMAC + 9 rule-based attack signatures
  gat_detector          - Controller-side: Graph Attention Network spatial anomaly
  temporal_autoencoder  - Controller-side: LSTM AE with mobility-constrained loss
  fusion                - Combined score Φᵢ(t) = λ₁ψᵢ + λ₂Sᵢ + λ₃(εᵢ/θ_ae)
  blockchain_sim        - SC-Trust EMA + SC-Revoke BFT simulation
  metrics_calculator    - MCC, FPR, PARR, CDER, TDEE, TPE, PBPO
  metrics_visualization - 8-panel chart + ablation comparison
"""
