# MPTD-PQS — HPC Session Handoff / Context Transfer

**Date:** 2026-06-28. **Purpose:** bridge context to a fresh Claude Code session on
the HPC so it can continue without re-deriving everything. The auto-memory on the
laptop is machine-local and does **not** travel here — this file is the bridge.

---

## 0. FIRST — get the code + context onto the HPC

The handoff doc alone is not enough; the HPC needs the branches too.

| Branch | State | Action needed |
|---|---|---|
| `master` | has ML PR #27 (gat_detector + lstm_detector + fusion) + CSV segmentation #28; synced to origin | `git pull` on HPC |
| `feature/csv-scenario-segmentation` | **merged** (#28) | nothing — it's in master |
| `ml-review-fixes` | **NOT merged, NOT pushed** — GAT L2-norm fix, LSTM median+MAD fix, artifact untrack, `ML_REVIEW_FIXES.md` | **push from laptop + open PR / merge**, else HPC lacks these fixes |
| `docs/hpc-handoff` | this file | push so HPC can read it (or merge to master) |

On the laptop: `git push -u origin ml-review-fixes` and `git push -u origin docs/hpc-handoff`.
On the HPC: `git fetch --all`, then read this file, then pull the branch you need.

---

## 1. Working rules (in case CLAUDE.md / memory aren't on the HPC)

- **The paper is the only authority.** Verify every design choice against the paper
  (`progress report/…pdf` / the Overleaf `main.tex`), not against what the code asserts.
- **No co-author / attribution tag** on commits. Logical, conventional commits.
- **Branch per task** off `master`. The user handles push/PR.
- **Don't commit unless explicitly asked.**
- The **ML detectors are another group member's** component — flag deviations, don't
  silently rewrite (the user has authorized the specific fixes already made).

---

## 2. What was done this session (laptop)

- **GAT review (PR #26→#27).** Algorithm is sound. Fix applied on `ml-review-fixes`:
  spatial score `S_i` now uses the **L2 norm** `‖z‖₂` (was squared) to match Eq.
  `gat_score`. Still-open (flagged, not fixed): **RSU nodes missing** (paper graph is
  vehicle–RSU, code is vehicle-only), **τ_i (trust) dropped** from node features
  (code uses sin/cos heading), **z-score path underperforms** (MCC ≈ −0.16 vs head
  ≈ 0.64 — supervisor decision), **suburban/highway data is synthetic**.
- **LSTM review.** Fix applied on `ml-review-fixes`: `θ_ae` now **median + κ·MAD**
  (was mean+std) per Eq. `ta_threshold`; model docstring 6-dim. Still-open: committed
  **checkpoints are 5-dim but code is 6-dim → won't load → need retrain** (blocked:
  rural/highway training CSVs not in repo), **τ_i is a constant 1.0** (no trust column).
- **Fusion.** `analytics/ml/score_fusion.py` is paper-correct (weighted-CE λ learning,
  Σλ=1, Φ_th=0.5). But `analytics/ml/train_fusion.py` still imports the **legacy**
  `analytics/ml/gat_detector.py` + `lstm_ae.py`, **not** the new `gat_detector/` /
  `lstm_detector/` packages — rewire only after the retrain.
- **CSV per-scenario segmentation (merged #28).** Live-sim CSVs now write under
  `analytics/results/<scenario>/` keyed on `mobility_scenario` (0/1/2). See
  `CSV_SCENARIO_SEGMENTATION.md`. Downstream readers still point at the old fixed
  path — update them (`train.py`, `evaluate_all.py`, `run_evaluation.sh`, …).
- **Blockchain reviewed — paper-conformant.** SC-Register/Trust/Revoke + CP-DETECT +
  RSU lifecycle match the paper (2f+1 distinct-RSU, EMA `α τ + (1−α)(1−mean ψ)`,
  directional conflict f+1). Identity/evidence/vote sigs = **classical ECDSA P-256**;
  TRS = **ML-DSA-87** + FHE = **256-bit** = the NIST Level-5 part.

---

## 3. PRIMARY NEXT TASK — PQC ledger-payload upgrade (do on HPC)

**Goal (supervisor: keep project at NIST Level 5):** upgrade the **application-payload**
on-chain signatures from **ECDSA P-256 → ML-DSA-87** (Dilithium5, FIPS 204, Level 5):
`σ_j^sub` (RSU evidence), `σ_c^sub` (controller evidence), revoke votes, and SC-Register
endorsements — i.e. everything the **chaincode verifies**.

**Hard limit (state honestly in the report):** stock **Hyperledger Fabric's own crypto
(MSP transaction signing, peer/client TLS, Raft ordering) stays classical ECDSA** — it
cannot be made post-quantum without forking Fabric's BCCSP (out of scope). So the
accurate claim is: *"post-quantum (Level 5) on the application payload we control;
classical at the Fabric platform layer."* Do NOT claim "the whole blockchain is Level 5."

### Why this must run on the HPC (not the laptop session)
- Chaincode needs a **Go PQ verifier** → `go get github.com/cloudflare/circl` +
  `go mod vendor` (**network**), then a Fabric/CCAAS rebuild + redeploy + round-trip
  test — none doable in the laptop sandbox.

### C++ side — `06c_blockchain_api.h` / `11_blockchain_setup.h`
- Replace `ec_p256_keygen()`, `ec_pubkey_uncompressed_hex()`, `node_sign_hex()` and the
  three signers (`mptd_sign_evidence_hex`, `mptd_sign_controller_evidence_hex`,
  `mptd_sign_revoke_vote_hex`) with **ML-DSA-87** via **liboqs** — reuse the OQS
  integration already present for the TRS (`06b1_trs_backend.h`), use
  `OQS_SIG_alg_ml_dsa_87` (keypair / sign / verify).
- `g_node_ec_keys` (`std::map<id, EC_KEY*>`) → store ML-DSA secret-key bytes per id.
- Keep the digest rule identical (SHA-256 over the same ordered concat) so signed
  bytes still equal transmitted bytes.
- Suggest a build flag (e.g. `MPTD_LEDGER_SIG=mldsa|ecdsa`) to keep an ECDSA fallback
  for ablation/compat.

### Go chaincode — `chaincode/chaincode/smartcontract.go`
- Replace `parseP256PubKey` / `verifyECDSAP256` with ML-DSA-87 verify via `circl`
  (`github.com/cloudflare/circl/sign/mldsa/mldsa87`).
- `go get` it, `go mod vendor` (the repo vendors chaincode deps), update comments
  ("EC-ECDSA P-256" → "ML-DSA-87"). The `PkHex`/`SigHex` fields stay hex strings,
  just longer.
- Rebuild the CCAAS image (`fabric_net/deploy_cc.sh`), redeploy.

### Size impact (expect + report it — this is the RQ5 overhead story)
| | ECDSA P-256 (now) | ML-DSA-87 (after) |
|---|---|---|
| public key (`PkHex`) | 65 B (130 hex) | **2,592 B (~5,184 hex)** |
| signature (`SigHex`) | ~70 B (~140 hex) | **4,627 B (~9,254 hex)** |
| secret key (off-chain) | 32 B | 4,896 B |
| per-vehicle `REG_` record | few hundred B | **~2.7 kB** |

→ ~40× bigger keys, ~65× bigger signatures. Every `REG_`/`SUBM_`/`CSUBM_`/`VOTE_`
record grows. Measure and report the signing-latency + storage overhead (RQ5).

### Test before declaring done
1. `go test ./chaincode/ -cover` (sign↔verify round-trip green).
2. Bring up `fabric_net`, deploy CC, run NS-3 with `--skip_blockchain=false` and a real
   register → submit-evidence → finalize → revoke-vote flow; confirm chaincode accepts
   ML-DSA-87 sigs and rejects forged ones.
3. Update the NIST-scope wording in `BLOCKCHAIN_IMPLEMENTATION.md` + the paper.

---

## 4. Other pending tasks (with blockers)

1. **LSTM retrain → 6-dim consistency.** Blocked: rural/highway training CSVs missing
   (only `urban_*` in repo). Get them from the ML owner, retrain all three so
   meta/scaler/θ_ae/.pt agree on `feature_dim=6`.
2. **Fusion rewire** `train_fusion.py` → new `gat_detector/`+`lstm_detector/` packages
   (after #1; new GAT `S_i` must be normalised to [0,1] for fusion).
3. **Full-mode ONNX + IPFS.** Today the controller scores GAT/LSTM from **in-memory**
   beacon buffers and loads **legacy** `analytics/ml/models/` ONNX — the paper says
   retrieve windows from **IPFS by on-chain hash** then run ONNX. After #1: export new
   models to ONNX into the paths `12_main.h` loads, fix the 5↔6 feature contract,
   and decide IPFS-faithful retrieval vs the in-memory shortcut.
4. **Per-scenario reader updates** for the new CSV paths (Section 2).

---

## 5. Key files
- NS-3↔Fabric bridge: `scratch/mptd_pqs_sdvn/06c_blockchain_api.h` (`CallSC*`, AF_UNIX
  socket), `fabric_gateway_daemon/main.go` (Go gateway, Fabric Gateway SDK).
- Chaincode: `chaincode/chaincode/smartcontract.go`; network: `fabric_net/`.
- Crypto backends: `06b1_trs_backend.h` (ML-DSA-87 TRS), `06b2_fhe_backend.h` (FHE).
- ML detectors: `gat_detector/`, `lstm_detector/`; fusion: `analytics/ml/{score_fusion,train_fusion}.py`.
- Sim CSV writers: `scratch/mptd_pqs_sdvn/10_metrics_csv.h`.
- Reviews/specs: `ML_REVIEW_FIXES.md`, `CSV_SCENARIO_SEGMENTATION.md`, this file.

---

## 6. HPC first-steps checklist
1. `git fetch --all`; pull `master`; pull/merge `ml-review-fixes` (GAT/LSTM fixes).
2. Read this file + `ML_REVIEW_FIXES.md`.
3. New branch `feature/pqc-ledger-mldsa` off master.
4. Do the C++ ML-DSA-87 edits (reuse liboqs) → Go chaincode verify (circl) → `go mod vendor`.
5. `go test` + Fabric deploy + live round-trip test.
6. Document the NIST scope honestly (app-payload Level 5; Fabric platform classical).
7. Logical commits, no attribution tag; user pushes/PRs.
