"""
MPTD-PQS: Mobility Pattern Trajectory Detection with Post-Quantum Security
==========================================================================
Dual-mode detection framework for Software Defined Vehicular Networks (SDVN).

Modules:
  lightweight_detector  - RSU-side: HMAC + 9 rule-based attack signatures
  gat_detector          - Controller-side: Graph Attention Network spatial anomaly
  temporal_autoencoder  - Controller-side: LSTM AE with mobility-constrained loss
  fusion                - Combined score Φᵢ(t) = λ₁ψᵢ + λ₂Sᵢ + λ₃(εᵢ/θ_ae)
  metrics_calculator    - MCC, FPR, PARR, CDER, TDEE, TPE, PBPO

Note: the in-memory `blockchain_sim` module was deleted in Phase R8.5
(2026-05-30). SC-Trust / SC-Revoke / CP-DETECT now run on the real
Hyperledger Fabric chaincode at chaincode/chaincode/smartcontract.go
(Eq 3.55/3.58/3.59), invoked from NS-3 RSU code in
scratch/mptd_pqs_sdvn/06c_blockchain_api.h.
  metrics_visualization - 8-panel chart + ablation comparison
"""
# mptd_pqs/__init__.py
# Expose key classes so the package can be used as:
#   from mptd_pqs import GhalebB1Detector
from mptd_pqs.ghaleb_b1_detector import (
    GhalebB1Detector,
)