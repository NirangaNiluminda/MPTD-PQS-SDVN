# MPTD-PQS — Blockchain Implementation Reference

Permissioned Hyperledger Fabric realisation of paper §3.5.5 (Eq 3.55–3.67,
Algorithms 7–8, Fig 3.9). This document is the single reference for the
chaincode contracts, the signature scheme, the multi-controller `C_trusted`
logic, how NS-3 drives the chain, and how on-chain evidence is exported.

- **Network topology / bring-up** → `fabric_net/README.md`
- **Chaincode source** → `chaincode/chaincode/smartcontract.go` (canonical;
  the deploy copy at `$FAB_ROOT/trajectory-chaincode/chaincode/smartcontract.go`
  must be kept byte-identical — `deploy_cc.sh` builds the CCAAS image from it)
- **Unit tests** → `chaincode/chaincode/smartcontract_test.go` (26 tests, 86.5%
  stmt coverage, in-memory fake ledger; `go test ./chaincode/ -cover`)

---

## 1. Roles, identities and the ID scheme

Every participant is registered on-chain with a P-256 (`secp256r1`) public key
and a role. IDs follow the locked prefix scheme (`06c_blockchain_api.h`
`MakeVehId/MakeRsuId/MakeCtrlId`):

| Role | ID form | Registered by | Authoritative? |
|------|---------|---------------|----------------|
| `VEHICLE` | `VEH_<ns3_node_id>` | `SCRegister` (needs 2f+1 RSU endorsements) | — (subject) |
| `RSU` | `RSU_<idx>` | `SCBootstrapRSU` (genesis) | **yes** — endorsing peer, evidence + votes |
| `CONTROLLER` | `CTRL_<idx>` | `SCRegister` | **no** — non-authoritative client (invariant 2) |

`RegistrationRecord` fields: `ID, Role, PkHex, HKuHex, TauInit, Status,
RegisteredAt`. `Status ∈ {ACTIVE, REVOKED, EXCLUDED}`.

---

## 2. Signature scheme — ECDSA P-256 over the registered key

**Decision (locked).** The evidence/vote signatures `σ_j^sub` (RSU), `σ_c^sub`
(controller) and revoke-vote sigs are **ECDSA P-256 over each node's registered
Fabric-MSP key** — *not* TRS partials.

*Rationale.* SC-Trust evidence is keyed by submitter ID on-chain
(`SUBM_<veh>_<epoch>_<rsuID>`), so there is **no signer anonymity to protect** —
the correct `σ` is the submitting node's identity signature. This is consistent
with the SC-Register endorsement gate (`project_sc_register_decisions.md`). The
privacy-preserving threshold-ring `σ_TRS` (Eq 3.48) is a **separate** construct
over the FHE cloud aggregate (`06b1_trs_backend.h` / the 06b1 pipeline) and is
untouched by this.

### Canonical digest rule (must be byte-identical C++ ↔ Go)

> SHA-256 over **ordered raw-UTF-8 string concatenation, NO separators.** The
> chaincode receives the exact strings the C++ `Call*` wrapper transmits; signing
> is folded **into** the wrappers so the signed bytes == the transmitted bytes.

| Construct | Eq | Digest = SHA-256( … ) | Go helper / C++ signer |
|-----------|-----|----------------------|------------------------|
| Endorsement | 3.63 | `vehicleID ‖ pkHex ‖ hKuHex` | `endorsementDigest` |
| RSU evidence `σ_j^sub` | 3.61 | `vehicleID ‖ rsuID ‖ epoch ‖ psiStr ‖ beaconHash` | `evidenceDigest` / `mptd_sign_evidence_hex` |
| Controller evidence `σ_c^sub` | 3.62 | `vehicleID ‖ controllerID ‖ epoch ‖ phiStr ‖ beaconHash` | `controllerEvidenceDigest` / `mptd_sign_controller_evidence_hex` |
| Revoke vote | 3.63 | `vehicleID ‖ rsuID ‖ reason ‖ timestamp` | `revokeVoteDigest` / `mptd_sign_revoke_vote_hex` |

On the C++ side the digest is built by `mptd_scregister::concat_digest({...})`
and signed by `mptd_scregister::node_sign_hex(id, digest)`, which looks up the
node's key in `g_node_ec_keys[id]` (returns `""` if absent → chaincode rejects).
`beaconHash` carries `h(b_i(t))` (Eq 3.56), or in the full-mode TRS path the FHE
ciphertext digest `h(Enc(A_ring))` so the signature binds the ciphertext.

Every gated write verifies the signature with `verifyECDSAP256(pkHex, sig,
digest)` against the submitter's **registered** key and **strict-rejects** on
failure (mirrors the SC-Register endorsement gate). Crypto-agility: key/sig
sizes are runtime values, never hardcoded.

---

## 3. Chaincode contracts

### 3.1 SC-Register (Algorithm 7, Eq 3.63)

- `SCInitNetworkConfig(numRSUs, alpha, tauTh, tRev, psiTh)` — network params
  (`NumRSUs ≥ 4` enforced). Read via `GetNetworkConfig` (defaults if absent).
- `SCBootstrapRSU(rsuID, pkHex, hKuHex, t)` — genesis RSU registration (no
  endorsements; RSUs must exist before they can endorse anyone).
- `SCRegister(id, role, pkHex, hKuHex, t, endorsersJSON)` — vehicle/controller
  registration. Counts **distinct** RSU endorsers whose sig verifies over
  `endorsementDigest`; requires **≥ 2f+1**. Bad role, off-curve key, malformed
  `hKuHex` (must be 64 hex chars), duplicate ID, and insufficient/forged
  endorsements all reject. Vehicles get an initial `SCTrustScore = τ_init`.
- Reads: `GetRegistration`, `IsRegistered`, `GetAllRegistrations`.

### 3.2 SC-Trust (Eq 3.55 / 3.59)

- `SCTrustSubmitEvidence(vehicleID, rsuID, epoch, psiStr, beaconHash, signature)`
  — registration-gated (`requireActive` on both vehicle & RSU) **then** σ_j^sub
  verified against the RSU's key. Writes `SUBM_<veh>_<epoch>_<rsu>`.
- `SCControllerSubmitEvidence(vehicleID, controllerID, epoch, phiStr, beaconHash,
  signature)` — same shape, controller key, writes `CSUBM_<veh>_<epoch>`. The
  controller writes as a **non-authoritative client**: recorded and fed to
  CP-DETECT, but a forged/unsigned submission is rejected before it can skew the
  conflict count (invariant 2).
- `SCTrustFinalizeEpoch(vehicleID, epoch)` — EMA `τ = α·τ_prev + (1−α)·(1−mean ψ)`
  over the epoch's distinct RSU witnesses. Maintains `ConsecutiveLowEpochs`
  (the T_rev consecutive-low-trust gate); trust recovery resets it.
- Reads: `GetTrustScore`, `GetAllTrustScores`, `GetEpochSubmissions`,
  `GetControllerSubmission`.

### 3.2.1 RSU SC-Trust lifecycle (paper §3.5.1, Eq rsu_trust / rsu_misbehave)

Paper §3.5.1 mandates that a persistently anomalous **RSU**'s SC-Trust score
decays and triggers BFT revocation — closing the gap where the old §3.5.5 text
defined the trust EMA only for vehicles and controllers. Each RSU carries
`RSUTRUST_<id>` (`τ_{r_j}`, seeded `τ_init = 1.0` at registration) and a
`RegistrationRecord.RSUState ∈ {TRUSTED, CLIENT}`.

- **Misbehaviour signal `m_j(t)`** — a compromised RSU is an endorser, not a
  monitored vehicle, so its evidence is scored against its honest peers, not an
  external detector. For each vehicle `r_j` reported on this epoch, its binary
  flag is compared with the quorum verdict `q_i` (1 iff ≥ 2f+1 **distinct
  TRUSTED** RSUs flagged that vehicle). `m_j(t)` = mean disagreement over those
  vehicles. Computing `q_i` over the trusted set **only** is the anti-collusion
  rule: a coalition of demoted RSUs can never form the quorum that scores its
  peers.
- **EMA** (reuses the vehicle form, Eq 3.55):
  `τ_{r_j}(t) = α·τ_{r_j}(t−1) + (1−α)·(1 − m_j(t))`.
- **Three-state machine** (reuses the vehicle `τ_th` / `T_rev`):
  `TRUSTED` (endorses + carries quorum weight) → below `τ_th` demote to
  `CLIENT` (may still submit evidence so it can recover, but **zero quorum
  weight**, cannot endorse) → recover ≥ `τ_th` promote back to `TRUSTED`; below
  `τ_th` for `T_rev` consecutive epochs → terminal `SC-Revoke` (`SCREVOKE_<rsu>`,
  `Status → REVOKED`, event `RSURevoke`). Demote/promote emit `RSUDemoted` /
  `RSUPromoted`.
- **BFT floor guard** (paper §3.5.1, `|R_trusted(t)| ≥ 3f+1` at all times) —
  a demotion/revocation that would drop the trusted-RSU count below `3f+1`
  is blocked: the RSU is retained as a **probationary**
  `TRUSTED` member (`Probationary=true`, event `RSUProbationHold`) so it keeps
  its quorum weight. `ConsecutiveLowEpochs` is preserved (not reset), so the
  pending transition resumes once a replacement registers and lifts the count
  back above the floor. `CLIENT` RSUs are already outside `R_trusted`, so their
  revocation is never floor-blocked. `countTrustedRSUs()` supplies the live
  count (same-transaction writes are visible, so a finalize loop that demotes
  RSUs one at a time sees the shrinking set). **Fault bound `f` is FIXED at 1**
  by framework design (paper `tab:set-blockchain`: `f=1`, `2f+1=3`, `n=4` ring),
  so the floor is a constant `3f+1 = 4` in **every** deployment. The 64/44/23-RSU
  grids (urban/rural/highway) are *mobility-coverage* topology, **not** the
  consensus committee size — `f` does not scale with the grid. A constant floor
  of 4 leaves ample slack against demotions in all grids, and keeps SC-Revoke's
  `2f+1 = 3` trajectory-witness requirement reachable (a vehicle does contact 3
  RSUs along its path within a window; it would never contact a grid-sized 43).
- **`SCRSUFinalizeEpoch(epoch)`** — channel-wide, one call per epoch; rebuilds
  `q_i` + `m_j` from the on-chain `SUBM_*` set and applies the lifecycle to every
  RSU. Idempotent over the epoch. Reads: `GetRSUTrustScore`,
  `GetAllRSUTrustScores`.
- **Quorum gating** — `isTrustedRSU()` excludes `CLIENT` RSUs from **every**
  quorum count: SC-Register endorsements, SC-Revoke `2f+1` votes, CP-DETECT
  `f+1` conflicts, and the vehicle-trust `mean ψ`. This is the chaincode-only
  (option a) enforcement of trusted-only endorsement; the Fabric endorsement
  policy stays `OR('RSUMSP.peer')`.
- **Known limitation** — NS-3 RSUs emit `SUBM` only on anomaly, so `m_j`
  currently captures **over-reporting** (flagging vehicles the quorum cleared).
  **Under-reporting** (a missed detection the quorum caught) needs a per-vehicle
  clean-verdict hook on the NS-3 side — documented follow-up.

### 3.3 CP-DETECT (Algorithm 8, Eq 3.64–3.67)

`CPDetectCheck(vehicleID, epoch)` — compares the controller's anomaly verdict
(`Φ > ψ_th`) against the RSU verdicts for the same epoch. RSUs with no submission
count as **implicit clean** votes. If `conflict ≥ f+1` it:
1. writes a `CFLAG_<ctrl>_<veh>_<epoch>` flag, **and**
2. calls `excludeAndReassignController` (see §4), **and**
3. emits exactly one event — `ControllerReassign` if a new exclusion happened,
   else `CPDetectFlag` (Fabric allows one `SetEvent` per TX).

Reads: `IsControllerFlagged`, `GetAllControllerFlags`.

### 3.4 SC-Revoke (Eq 3.58 / 3.61)

`SCRevokeVote(vehicleID, rsuID, reason, signature, timestamp)` — registration-
gated, then the vote sig is verified against the voting RSU's key. Votes are
idempotent per RSU; on **≥ 2f+1 distinct** RSU votes it commits `SCREVOKE_<veh>`
and flips the vehicle's `Status → REVOKED`. A vote after revocation bounces at
the `requireActive` gate (`status=REVOKED`). The set of `SCREVOKE_` records **is
the CRL**. Reads: `SCRevokeStatus`, `IsRevoked`, `GetRevokeVotes`,
`GetAllRevokeRecords`.

BFT constant (shared C++ ↔ Go): `fByzantine(n) = (n−1)/3` (0 if n<4); revoke
needs `2f+1`, CP-Detect / controller exclusion needs `f+1`.

### 3.5 Trust-ranked endorsing-peer selection (Sir Task-4 revision, 2026-06-16)

Supervisor directive: *"peer selection occasionally at runtime based on trust
score rather than selecting everyone as peers, which is computationally
expensive and suboptimal."* Implemented as **Option A** — change **which**
trusted RSUs are asked to endorse, **not** which RSUs are Fabric peers (Option B,
live channel reconfig, deliberately **not** taken; see caveat below).

Paper alignment: the notation table defines the endorser set as
`R_trusted(t)` ("trusted-RSU endorser set at time `t`"), so drawing the `2f+1`
endorsers from the highest-trust members of the on-chain trusted set is a
refinement of an underspecified selection rule, **not** a contradiction (SC-Register
text says "neighbouring `2f+1`"; this ranks within the trusted set). Flagged to
the supervisor per his "inform me if your modeling differs" instruction.

- **Selection** (`select_endorsers_trust_ranked`, `11_blockchain_setup.h`) — top
  `2f+1` TRUSTED RSUs by descending `τ`, with a pre-shuffle + `stable_sort` so
  equal scores break **uniformly at random**. CLIENT/REVOKED RSUs are excluded.
- **Bootstrap rule** (Sir: *"initially … as nodes trust scores are just
  initialized"*) — before the first live snapshot / at boot every RSU carries
  `τ_init` (all equal), so the selector falls back to `random_endorser_sample`
  (uniform random). Registration is boot-time, so it uses this fallback; the
  ranking takes effect as the lifecycle spreads the scores at runtime.
- **Runtime refresh** (`refresh_endorsement_committee`, ~1 Hz, control-path
  only) — queries live scores via `CallSCGetAllRSUTrustScores` (evaluate-only,
  no orderer round-trip), rebuilds `g_rsu_trusted_set` + `g_rsu_trust_cache`,
  recomputes the top-`2f+1` committee, and logs it as `[PEER-SELECT] … committee[2f+1]={…}`.
- **Endorser count fixed to paper `f=1`** — `register_all_nodes` now sends
  `2f+1 = 3` endorsers (was `2·(N−1)/3+1`, i.e. 43 in the 64-RSU urban grid —
  the "selecting everyone" waste Sir flagged). Chaincode SCRegister threshold is
  `2·fByzantine(NumRSUs)+1 = 3` at the default `NumRSUs=4`, so 3 satisfies it.
- **Ablation toggle** — `g_trust_peer_selection` (default `true`); set `false`
  for the A4/baseline run → uniform random endorsers, no refresh loop.

> **Caveat (open question for supervisor).** Option A ranks **who endorses**;
> it does **not** gate runtime evidence/revoke votes to a global committee.
> Doing so (a literal "only the committee are peers" reading) would break the
> `2f+1` SC-Revoke **trajectory-witness reachability** — a vehicle is flagged by
> whichever RSUs it physically passes, not a globally-fixed top-trust set — which
> is exactly the reachability the fixed `f=1` realignment restored. That heavier
> change is held pending supervisor confirmation.

---

## 4. Multi-controller `C_trusted` set (Eq 3.1 / 3.60, invariant 2)

The paper defines a **set** of trusted controllers, not a single one. We register
`CTRL_0..CTRL_4` (config `N_Controllers = 5`). The **head** of `C_trusted` is the
lowest-numbered `ACTIVE` controller.

- `GetActiveController()` → current head (errors if none active).
- `GetTrustedControllers()` → full set incl. `EXCLUDED` members.
- `excludeAndReassignController(...)` — flips a CP-DETECT-flagged controller to
  `EXCLUDED`, finds the next `ACTIVE` successor, and writes a
  `CTRLREASSIGN_<excluded>_<epoch>` record. **Idempotent** (a non-ACTIVE
  controller yields no new record).
- `GetControllerReassignments()` → audit list of all handoffs.

An `EXCLUDED` controller's evidence bounces at `requireActive`, so it is removed
from consensus exactly as invariant 2 requires. The exclusion is driven by **RSU
consensus** (the conflict count), never by the controller itself (invariant 6).

> **Sim-only note.** The physical NS-3 `controller_Node` stays single; only the
> *logical* `C_trusted` identity is chain-authoritative. NS-3 tracks the active
> controller via a 1 Hz `GetActiveController` query
> (`mptd_active_controller_refresh_loop`, control-path only, never the per-beacon
> hot path), updating `g_active_controller_idx` so controller evidence submits
> under the current head after a reassignment.

---

## 5. NS-3 ↔ chaincode wiring

| Phase | Code | What happens |
|-------|------|--------------|
| Boot | `register_all_nodes()` (`11_blockchain_setup.h`) | RSUs (`SCBootstrapRSU`) → vehicles → controllers (`SCRegister`, 2f+1 endorsements). EC keys stored in `g_node_ec_keys[id]`. |
| Lightweight alert path | `08_detection_engine.h` ~2930 | `CallSCTrustSubmitEvidence(vid, rsu_idx, epoch, psi, h_b)` (signs internally) |
| Controller evidence | `08_detection_engine.h` ~1936 | `CallSCControllerSubmitEvidence(vid, g_active_controller_idx, epoch, phi, h_X)` |
| Cross-RSU revoke | `08_detection_engine.h` ~2840 | `CallSCRevokeVote(vid, rsu_idx, reason, ts)` |
| Vehicle epoch finalize | `08_detection_engine.h` ~2958 | `CallSCTrustFinalizeEpochAsync(vid, epoch)` (+1 s, deduped per `vid\|epoch`) |
| RSU epoch finalize | `08_detection_engine.h` ~2970 | `CallSCRSUFinalizeEpochAsync(epoch)` (+2 s, deduped per `epoch` — channel-wide RSU trust lifecycle) |
| Shutdown | `mptd_export_blockchain_evidence()` | dump committed ledger → JSON (see §6) |

The `Call*` wrappers (`06c_blockchain_api.h`) **drop any external signature
param and sign internally**, formatting the exact strings transmitted so
`signed-bytes == transmitted-bytes`. Transport is `mptd_fabric_call_socket` to a
local fabric proxy (not the Fabric SDK in C++). All of this is bypassed when
`skip_blockchain==true` or `ablation_mode==5` (A5).

> Include order in the single TU: `06b1` → `06c` → `08` → `11`. The signers are
> *declared* (global, extern) in 06c and *defined* in 11; same-TU linkage
> resolves them. `node_sign_hex` lives in `namespace mptd_scregister`; the three
> global signers delegate to it.

---

## 6. On-chain evidence export (audit trail)

After `Simulator::Destroy()`, `mptd_export_blockchain_evidence()` queries the
committed ledger (evaluate-only; safe post-Destroy) and writes
`analytics/results/blockchain_evidence.json` — one consolidated, valid-JSON
snapshot:

```
active_controller · trusted_controllers · controller_reassignments ·
controller_flags · registrations · trust_scores · revoke_records (= CRL)
```

Each section is the **raw chaincode JSON** (no lossy C++ re-parse). The same
ledger is browsable live in **Hyperledger Explorer**; off-chain raw beacons
referenced by `h(b_i(t))` live in **IPFS** (`06c` IPFS channel, kubo on `:5002`).
No-op under `skip_blockchain` / A5.

---

## 7. Invariant compliance

| Invariant | Where enforced |
|-----------|----------------|
| 1 — RSU→blockchain direct | RSU `Call*` wrappers submit directly; CRL = on-chain `SCREVOKE_` records read direct, never controller-relayed |
| 2 — controller non-authoritative | controller registered as `CONTROLLER`, only a Raft orderer in the topology; CP-DETECT `f+1` excludes it; its evidence never overrides RSU consensus |
| 3 — LW skip-on-pass | unchanged; blockchain only on the alert path |
| 5 — FHE before TRS | separate 06b1 pipeline; this doc's σ are identity ECDSA, not σ_TRS |
| 6 — distributed trust | N-way ledger replication; 2f+1 RSU consensus is authoritative; no single controller secret gates anything |

---

## 8. Testing & verification status

- **Chaincode unit tests**: `go test ./chaincode/ -cover` → 26 tests pass, 86.5%
  statement coverage. Covers happy paths, every rejection path (bad role/key,
  insufficient/forged endorsements, invalid evidence/vote signatures, EXCLUDED
  bounce), CP-DETECT exclusion + reassignment + idempotence, and infra-failure
  paths (ledger I/O errors, corrupt state, range/iterator failures).
- **NS-3 build**: compiles clean with the signing wrappers + evidence export.
- **Live end-to-end run** (real beacons driving SC-Trust/SC-Revoke/CP-Detect with
  `--skip_blockchain=false`): performed on the **HPC node** (Docker + Explorer +
  IPFS). See `HPC_RUN_GUIDE.md` §1b and `fabric_net/README.md`.
