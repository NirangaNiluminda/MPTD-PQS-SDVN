# TASK ① Deliverable — Blockchain Pipeline (Paper §3.5.5)

**Due:** 2026-06-02 · **Author:** G.W.N. Niranga Niluminda · **Branch:** `master`

This document maps every equation in paper §3.5.5 (Smart-Contract layer) to its
implementation: the NS-3 C++ caller, the Hyperledger Fabric chaincode handler,
and the commit that introduced the wiring. All paths use **real Hyperledger
Fabric (CCAAS chaincode `trajectory_2.0`)** via a long-lived gRPC Gateway
daemon (commit `315b08d`, Phase 1A) over a Unix-domain socket at
`/tmp/mptd_fabric.sock` — no simulated blockchain, no REST shim between RSU
and ledger, no fork-per-call subprocess overhead (Invariant 1 preserved).

---

## §3.5.5 Equation → Implementation Map

| Eq | Paper concept | NS-3 caller (C++) | Chaincode handler (Go) | Commit |
|---|---|---|---|---|
| 3.55 | SC-Trust EMA τ_i(t+1) = (1−α)·τ_i(t) + α·(1 − ψ̄_i(t)) | `08_detection_engine.h:2644` schedules `CallSCTrustFinalizeEpochAsync` after epoch close | `smartcontract.go:1199 SCTrustFinalizeEpoch` | `0c28778` (TASK ①-K) |
| 3.56 | RSU evidence E_j(t) = ⟨vid, epoch, ψ_j, h(b_i), σ_j⟩ | `08_detection_engine.h:2616 CallSCTrustSubmitEvidence`; h(b) via IPFS CIDv0 (kubo HTTP API) | `smartcontract.go:1137 SCTrustSubmitEvidence` → key `SUBM_<vid>_<epoch>_<rsu>` | `99b7f03` (TASK ①-I) + `232d15a` (TASK ①-E IPFS) |
| 3.47 / 3.56 | σ_j = s_j · H(m_j) (RSU partial threshold sig) | `06b1_trs_backend.h:734 mptd_trs_partial_sign_hex` (over `ClassicalTrsBackend` Shamir-Schnorr P-256, n=4, t=3) | stored opaquely in `EpochSubmission.Signature` | `8b37eea` (TASK ①-J) |
| 3.57 | Controller evidence E_c(t) = ⟨vid, epoch, Φ_i, h(b), σ_c⟩ | `08_detection_engine.h:1632 CallSCControllerSubmitEvidence` (unconditional per fused window) | `smartcontract.go:1165 SCControllerSubmitEvidence` → key `CSUBM_<vid>_<epoch>` | `be400ae` (TASK ①-L) |
| 3.58 | SC-Revoke BFT 2f+1 vote: revoke iff Σ vote_j ≥ 2f+1 | `08_detection_engine.h:2511 CallSCRevokeVote` (sync, payload-parsed `"revoked":true`); LKH rekey gated on positive payload | `smartcontract.go:1436 SCRevokeVote` (writes `VOTE_<vid>_<rsu>`, emits `SCRevoke` event when threshold met) | `479c3eb` (TASK ①-N) |
| 3.66–3.69 | CP-DETECT flag_c = 1 iff Σ (1−flag^ctrl)·flag^rsu_j ≥ f+1 (directional: counts only controller-benign + RSU-anomaly suppression) | `08_detection_engine.h:1690` schedules `CallCPDetectCheckAsync` at +0.5s after CSUBM commit (per-window dedup) | `smartcontract.go:1293 CPDetectCheck` → writes `CFLAG_<ctrl>_<vid>_<epoch>` + emits `CPDetectFlag` event | `95745b5` (TASK ①-M); directional-conflict fix (Eq 3.68 — removed anti-paper implicit-clean-vote) |

---

## Runtime Evidence (verified end-to-end on live Fabric)

Sim run: `mptd_pqs_sdvn --routing_test=false --ablation_mode=0
--N_Vehicles=8 --simTime=10 --attack_percentage=80 --attack_number=5`

**Detection (Eq 3.20 + Eq 3.59):**
```
Confusion matrix:  TP=120  FP=0  TN=42  FN=6
MCC  = 0.913   FPR = 0.000   TRS-verify: 168 ok / 0 fail
CP-DETECT = 40 CTRL_COMPROMISED alerts over 168 audited epochs, flag_c=1
```

**On-chain σ_j signatures (Eq 3.47):** every SUBM record carries a distinct
64-character hex (32-byte) partial signature. Sample rows:
```
SUBM_4_E7_0  ψ=0.45  Sig=d460e0cabe35b9787d3c2aceaa99a8415f9318274352599685359495c13a1bdf
SUBM_5_E7_0  ψ=0.45  Sig=f36cf8a865952dbf2b4139b78daebc4e3e648731b376e04a0186bc4494bafc82
SUBM_7_E7_1  ψ=0.45  Sig=840abd9bcf9a28c8c8b98f74f8b158dd0882ecd39291fec5ff37866036cf9ffa
```
Different RSU shares → different σ_j on the same (vid, epoch) witness set,
which is the prerequisite for Lagrange aggregation to σ_TRS at the cloud
(Eq 3.48).

**CP-DETECT positive case (controller-deceit pattern):**
```
SCControllerSubmitEvidence vid=999 epoch=ETEST Φ=0.8
CPDetectCheck vid=999 epoch=ETEST →
  {ConflictCount:4, NumRSUs:0, ImplicitCleanVotes:4, ThresholdFP1:2}
  ← FLAGGED ✓
```

**CP-DETECT negative case (no false positive):**
```
SCControllerSubmitEvidence vid=998 epoch=ETEST2 Φ=0.1
CPDetectCheck vid=998 epoch=ETEST2 → nil ✓
```

**SCRevokeVote BFT threshold (Eq 3.58):**
4 sequential votes on vid=999 — vote #3 (2f+1 = 3 of 4) flipped
`revoked=true`, `SCREVOKE_999_<ts>` record committed, `SCRevoke` event
emitted.

---

## Architectural Invariants Preserved

1. **RSU → Fabric direct.** RSU submissions go straight to the peer via the
   long-lived gRPC Gateway daemon at `/tmp/mptd_fabric.sock` (commit
   `315b08d` Phase 1A; NS-3 socket client `cb8b5aa` Phase 1B). Async
   evidence submissions use a fire-and-forget extension (`4f315e6`) so the
   100 ms beacon budget is preserved even when the orderer round-trip takes
   a few hundred ms. Auto-fallback to the legacy `fabric_invoke.sh` shell
   shim if the daemon is down. No controller relay; no centralized proxy.
2. **Controller is a non-authoritative peer.** CSUBM is submitted as one
   peer opinion alongside the RSU SUBMs; CP-DETECT (Eq 3.59) can flag the
   controller's own submission as deceitful — and does so even when every
   RSU saw the vehicle as clean (implicit-clean-vote fix in `f30cd1e`).
3. **Lightweight skip-on-pass.** Blockchain calls fire only on the alert
   path; clean beacons are accepted locally at the RSU with no Fabric
   round-trip, preserving the 100 ms beacon budget.
5. **TRS-then-FHE order at cloud.** σ_TRS aggregation (Eq 3.48) gates any
   FHE-encrypted aggregate to the cloud node — FHE pipeline (R9) is the
   downstream consumer of σ_TRS-verified bundles.
6. **No centralized bottleneck.** Revocation requires 2f+1 RSU votes
   (Eq 3.58); a single controller cannot revoke a vehicle.

---

## Crypto Scheme Locks (post-paper-cite resolution)

- **TRS = classical EC-ElGamal Shamir-Schnorr P-256** (Ahmed et al. 2022
  [11], paper §3.5.4 "Framing B"). Implemented behind `ITrsBackend`
  abstraction; lattice-TRS migration path reserved for phase R11.
- **σ_j sizes are runtime via `ITrsBackend::expected_sig_size()`** — no
  hardcoded 64-byte assumptions. PQ-swap is a single backend instantiation
  change.
- **IPFS = kubo CIDv0** (port 5002) for off-chain raw-beacon storage; only
  the CID is anchored on-chain in the SUBM `BeaconHash` field.

---

## Commits Landing TASK ① (chronological)

**Wave 1 — §3.5.5 equation wiring (TASK ①-E…N):**

| Commit | What |
|---|---|
| `232d15a` | TASK ①-E: IPFS C++ client (libcurl → kubo HTTP API) |
| `99b7f03` | TASK ①-I: Wire Eq 3.56 RSU evidence path |
| `0c28778` | TASK ①-K: Schedule Eq 3.55 SCTrustFinalizeEpoch |
| `be400ae` | TASK ①-L: Wire Eq 3.57 controller-side CSUBM |
| `95745b5` | TASK ①-M: Schedule Eq 3.59 CP-DETECT after CSUBM commit |
| `479c3eb` | TASK ①-N: Migrate revocation to Eq 3.58 BFT 2f+1 vote |
| `8b37eea` | TASK ①-J: Plumb real σ_j via ITrsBackend::partial_sign |
| `f30cd1e` | Fix: count non-submitting RSUs as implicit clean votes in CPDetectCheck |
| `ffd4105` | Docs: this supervisor deliverable map (initial cut) |

**Wave 2 — TASK ①-O / ①-P transport stack (long-lived gRPC + cross-RSU broadcast):**

| Commit | What |
|---|---|
| `315b08d` | Phase 1A: Fabric Gateway daemon (Go, long-lived gRPC over Unix socket) |
| `4f315e6` | Phase 1A+: FireAndForget extension on the daemon — preserves the 100 ms LW T_b budget |
| `cb8b5aa` | TASK ①-O Phase 1B: NS-3 socket client (replaces fork-per-call `fabric_invoke.sh` shim) |
| `f01a48d` | TASK ①-P Phase 1C-a: daemon ChaincodeEvents subscriber → JSONL log |
| `ed9ae65` | TASK ①-P Phase 1C-b: NS-3 chaincode-event drainer + cross-RSU LKH rekey broadcast |

All commits are on `master`. `git log --oneline -14` reproduces the two
tables above (most recent first).

---

## Transport Stack (TASK ①-O / ①-P, Phase 1A–1C)

The original wiring used `fabric_invoke.sh`, a shell shim that forked
`peer chaincode invoke` per call (~200–400 ms wall-clock). Wave 2
replaced it with a long-lived gRPC client and added the chaincode-event
subscription needed to close the cross-RSU rekey gap.

| Phase | What | Daemon side | NS-3 side |
|---|---|---|---|
| 1A  | Long-lived gRPC over Unix socket | `fabric_gateway_daemon/main.go` connects once at startup, accepts JSON-line requests on `/tmp/mptd_fabric.sock` | — |
| 1A+ | FireAndForget for hot-path writes | Daemon ACKs immediately, submits in background goroutine | `mptd_fabric_invoke_async` flags `fire_and_forget:true` |
| 1B  | Socket transport in NS-3 | — | `06c_blockchain_api.h` — `mptd_fabric_call_socket` replaces shell exec; auto/socket/shell mode selector |
| 1C-a | ChaincodeEvents subscriber on daemon | `runEventListener` writes JSONL to `/tmp/mptd_fabric_events.jsonl`; truncate-on-startup; allowlist `SCRevoke,TrustLow,CPDetectFlag` | — |
| 1C-b | NS-3 event drainer + cross-RSU broadcast | — | `08_detection_engine.h` — 1 Hz drainer reads JSONL; SCRevoke fans out to all 4 RSUs via `send_lkh_rekey_if_new` (dedup'd against the inline rekey path) |

**Wire format** (one JSON line per request, one per reply):
```
REQ : {"action":"invoke","function":"SCTrustSubmitEvidence","args":[…],"fire_and_forget":true}
RESP: {"ok":true,"payload":""}
```

**Verification (synthetic SCRevoke for vid=5):**
```
[FABRIC-EVT] drainer armed @1Hz starting +0.5s
[FABRIC-EVT] SCRevoke vid=5 blk=999 → 4 new RSU rekeys t=0.5
[LKH-REKEY-TX] RSU0 → V5  nonce=1
[LKH-REKEY-TX] RSU1 → V5  nonce=2
[LKH-REKEY-TX] RSU2 → V5  nonce=3
[LKH-REKEY-TX] RSU3 → V5  nonce=4
```

This closes the original "Cross-RSU SCRevoke broadcast rekey" gap listed
in the first cut of this document (`ffd4105`).

---

## Known Gaps (deferred — not blocking TASK ① delivery)

- **Attack 4 (stolen-ID) HMAC-bypass refactor (TASK ①-H5).** Independent
  of §3.5.5 — needed for the 4th column of the MCC/FPR per-attacker-class
  table in §4.1.1, not for the TASK ① blockchain deliverable itself.
