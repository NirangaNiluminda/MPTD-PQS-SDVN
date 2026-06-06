# TASK ② — Cryptographic Layer: Updated Implementation Plan

**Status date:** 2026-06-06  (Algorithm 6/7 wired end-to-end — see §7)
**Owner:** G.W.N. Niluminda
**Scope:** Task ② "Implement all cryptographic content including key sharing (LKH),
authentication, etc." — now re-planned against the **revised paper** (the supervisor's
FHE/TRS redesign of 04–05 June 2026 is already merged into the paper PDF, so the paper
is the authoritative spec).

> **Ground rules (carried from `feedback_paper_first.md`):**
> 1. Paper-only decisions. Where the paper is silent/ambiguous → STOP and ask.
> 2. No simulation of security primitives — real OpenFHE, real liboqs/Dilithium, real Fabric.
> Both prerequisites are installed (see P0); Rule 2 is satisfiable.

---

## 1. What changed in the redesign (now official in the paper)

| Aspect | Old design | New design (paper) |
|--------|------------|--------------------|
| FHE↔TRS order | TRS-then-FHE (FHE post-detection) | **FHE pre-TRS-coordination** — Table 3.1 (p43) |
| Who encrypts | Cloud/RSU encrypt validated aggregate | **Each RSU FHE-encrypts its own zone aggregate `A_j(t)` before ring sharing** — Eq 3.46 |
| TRS signs | plaintext aggregate | **the ciphertext** `m=(Enc(A_ring),t,ID_S,h(S))` — Eq 3.48 |
| TRS scheme | classical EC (defer PQ to R11) | **PQ — lattice Dilithium secret key** — Eq 3.49 |
| FHE key | single key | **threshold `(t, n+1)` incl. Cloud** — Eq 3.54 |
| Decryption | single holder | **cloud partial + ≥t−1 RSU partials → ThDec** — Eq 3.53–3.56 |
| FHE share dist. | n/a | **via the LKH ring channel** — new sentence under Eq 3.25 |

This **supersedes** the CLAUDE.md "Crypto Scheme Locks" (which said classical-TRS-now /
PQ-deferred-to-R11, single-key BFV). CLAUDE.md + memory must be updated once the design is
locked (deferred until P3/P4 decisions are signed off).

---

## 2. P0 verification findings (2026-06-05)

- **OpenFHE 1.5.1** in `~/.local` (core/pke/binfhe). Multiparty API present
  (`MultipartyKeyGen`, `MultipartyDecryptLead/Main/Fusion`) **and** "Threshold FHE with
  aborts" secret-sharing (`cryptocontext.h:3462`, param `threshold` = parties needed to
  reconstruct). → **Genuine t-of-n is supported.** The "with aborts" model maps directly to
  Algorithm 7 `abort if |D| < t−1`. **Gap 2 RESOLVED.**
- **liboqs 0.15.0** with **ML-DSA 44/65/87** (`OQS_SIG_ml_dsa_*`). Single-signer only — no
  threshold/ring/aggregate. **Gap 1 (Eq 3.50 Aggregate) still open — needs design decision.**
- **wscript** already wired for both libs (lines 26–86); anticipates `DilithiumTrsBackend`.
- Current code state:
  - `06b2_fhe_backend.h` — **real OpenFHE BFV**, but **single-key** (one KeyPair = full
    `sk_FHE`). Covers Eq 3.46/3.47/3.52(sum). Violates new threshold model. Stale header
    (old eq-numbers, old TRS-then-FHE note).
  - `00_lkh_keys.h` — **real** HMAC-SHA256 + LKH. Covers Eq 3.21–3.25/3.37. Gaps: stale
    eq-numbers (file "3.33/3.36" → paper 3.22/3.25); **no FHE-share-over-LKH**; no `N_ring`
    rekey (Eq 3.24); RSU ring-key uses `root XOR idx` shortcut.
  - `06b1_trs_backend.h` — only `ClassicalTrsBackend` (Shamir-Schnorr-P256). No
    `DilithiumTrsBackend` yet.
  - `06b3_crypto_selftest.h` — selftest harness present.

---

## 3. Equation → file → status map

| Eq | Meaning | File | Status |
|----|---------|------|--------|
| 3.21–3.25 | LKH tree, K_i, ring sk_j, **FHE-share dist.** | `00_lkh_keys.h` | Real; fix eq-#s, add FHE-share channel, add N_ring |
| 3.37 | HMAC beacon auth | `00_lkh_keys.h` | Real ✓ (re-verify wiring) |
| 3.45 | RSU local plaintext aggregate A_j(t) | `06b1` EvidenceMessage | Present ✓ |
| 3.46 | FHE-encrypt local aggregate (pre-coord) | `06b2` | Real (single-key) — re-key to threshold pk |
| 3.47 | Homomorphic ring addition ⊕c_j | `06b2` `add_many` | Real ✓ |
| 3.48 | TRS message binds **ciphertext** | `06b1` serialize_evidence | Change: sign Enc(A_ring), not plaintext |
| 3.49 | PQ partial sign (Dilithium) | `06b1` **new** DilithiumTrsBackend | **TODO (Gap 1)** |
| 3.50 | Aggregate partials → σ_TRS | `06b1` | **TODO (Gap 1 decision)** |
| 3.51 | TRS verify | `06b1` | TODO |
| 3.52 | Cloud blind global aggregate | `06b2` | Partial (single-key sum) — re-key to threshold |
| 3.53 | Cloud partial decrypt | `06b2` **new** | **TODO (Gap 2 resolved → buildable)** |
| 3.54 | Threshold keygen ThGen(1^λ,n+1,t) | `06b2` **new** | **TODO** |
| 3.55 | RSU partial decrypt | `06b2` **new** | **TODO** |
| 3.56 | ThDec combine | `06b2` **new** | **TODO** |

Cross-cutting: crypto-agility (runtime sig/key sizes — already in `ITrsBackend`); ECDSA
baseline for PBPO TRS-vs-ECDSA (Eq 4.7 / RQ5); PARR counter (Eq 4.3); cloud-side pieces
(Eq 3.52/3.53) intersect the `cloud_Node` R9 wiring (currently a stub per CLAUDE.md).

---

## 4. Phased plan

- **P0 — Verify & decide (DONE).** OpenFHE t-of-n confirmed (Gap 2 resolved); ML-DSA
  confirmed; current code mapped. Outstanding: Gap 1 decision.
- **P1 — LKH/HMAC/aggregate conformance (UNGATED, no paper-claim risk).**
  Fix eq-numbers in `00_lkh_keys.h` (→3.22/3.23/3.25); add FHE-share-over-LKH channel
  (new Eq 3.25); add `N_ring` (Eq 3.24); re-verify HMAC (Eq 3.37) wiring; confirm A_j(t)
  (Eq 3.45).
- **P2 — Threshold-pk pre-coordination FHE (Eq 3.46–3.47) — DONE.** `06b2`
  `ThresholdBfvBackend` uses a threshold joined public key (`MultipartyKeyGen` chain over
  n+1 = 5 parties, NOISE_FLOODING_MULTIPARTY, ShareKeys "with aborts"); EvalAdd kept via
  `add_many`. Integer-quantize (×100 speeds, ×1000 positions). Round-trip validated by
  selftest THFHE-1/2 (encrypt→⊕→threshold-decrypt).
- **P3 — PQ-TRS via Dilithium (Eq 3.48–3.51) — DONE (D1 = option (c)).**
  `DilithiumTrsBackend` (liboqs ML-DSA-44) signs the **ciphertext** m = Enc(A_ring)‖t‖ID_S‖h(S).
  `aggregate` = bundle of t partial sigs; `verify_threshold` = "≥t distinct valid".
  `ClassicalTrsBackend` retained for the ECDSA/A4 baseline (RQ5) behind `--trs_classical`.
  Validated by selftest TRS-2a/2c/2e/2f, PIPE-1/2.
- **P4 — Threshold FHE decryption (Eq 3.53–3.56) — DONE.** `threshold_decrypt_vec`
  assembles cloud (mandatory lead, Eq 3.53) + ≥t−1 RSU partials (Eq 3.55) via
  MultipartyDecryptLead/Main/Fusion (Eq 3.56), with Shamir abort-recovery. Wired into the
  Algorithm 6/7 orchestrator (`run_full_mode_crypto_pipeline`, 08_detection_engine.h).
- **P5 — Selftest + metrics hooks — DONE.** `06b3` covers both backends (19 steps);
  PARR via `g_trs_rejected_count`/`g_trs_verified_count`; PBPO timing via
  `g_fullcrypto_time_sum_ms`/`g_fullcrypto_runs`; crypto-agility sizes from
  `expected_*_size()`. Build clean; selftest green (see §7).

---

## 5. Open decisions — RESOLVED

**D1 (Gap 1) — Dilithium `Aggregate` construction (Eq 3.50). LOCKED = option (c).**
t independent ML-DSA sigs + verifier policy "≥t distinct valid". Real, liboqs-backed,
satisfies PARR (sound t-of-n predicate) + PBPO (real PQ latency).
- **Caveat (needs paper-text correction):** σ_TRS is a bundle, **not** the *compact,
  anonymous* sig Eq 3.50 prose claims (size grows with t; signer IDs visible). No installed
  library has a compact lattice threshold-ring sig. **None of the 7 eval metrics depend on
  compactness/anonymity.** A supervisor note documenting this was delivered.
- (a) real lattice threshold sig (research-grade, not in liboqs) and (b) lattice ring sig +
  separate threshold (not in liboqs) — both out of timeline; rejected.

**D2 — ML-DSA security level. LOCKED = ML-DSA-44** (lightest; matches the 100 ms-budget
framing; pk=1312B sig=2420B). 65/87 stronger but slower → would hurt PBPO. User confirmed
2026-06-06.

**D3 — CLAUDE.md + memory update. DONE.** Invariant 5 rewritten to FHE-before-TRS; crypto
locks rewritten for threshold (t,n+1) BFV + PQ-Dilithium bundle. Memory
`project_crypto_redesign.md` carries the same.

---

## 6. Definition of done (Task ②)

- Eq 3.21–3.25, 3.37, 3.45–3.56 implemented with **real** OpenFHE + liboqs (no stubs).
- A1/A4/A5 ablation toggles intact (classical-TRS / no-TRS-FHE / no-blockchain paths).
- `06b3` selftest green for LKH, HMAC, BFV-threshold round-trip, Dilithium TRS.
- PBPO TRS-vs-ECDSA and PARR measurable from sim state.
- Build clean (`python3 waf build`); evidence captured for supervisor.

---

## 7. Implementation status (2026-06-06) — HANDOFF FOR NEXT CLAUDE ACCOUNT

**Algorithm 6 (PQ-FHE-TRS) and Algorithm 7 (THRESH-DEC) are wired end-to-end. Build clean,
selftest 19/19. No stubs, no hardcoded crypto, no simulated primitives — all OpenFHE 1.5.1
BFV-RNS + liboqs 0.15.0 ML-DSA-44 + LKH HMAC-SHA256.**

### 7.1 Where each piece lives
- **`06b2_fhe_backend.h`** — `ThresholdBfvBackend`. New primitives:
  - `encrypt_vector_int(vec)` — packed BFV encrypt under the joined threshold pk (Eq 3.46).
  - `add_many(cts)` — homomorphic ring ⊕ (Eq 3.47).
  - `serialize_ciphertext(ct)` — binary OpenFHE serialization → bytes for the TRS message
    (Eq 3.48). Deterministic.
  - `threshold_decrypt_vec(ct, present_rsus, len, out)` — cloud mandatory lead (Eq 3.53) +
    ≥t−1 RSU partials (Eq 3.55) → MultipartyDecryptLead/Main/Fusion (Eq 3.56), Shamir
    abort-recovery. `threshold_decrypt_int` now delegates to it.
  - Quantization constants: `SPEED_SCALE=100`, `POS_SCALE=1000`.
- **`06b1_trs_backend.h`** — `DilithiumTrsBackend` (ML-DSA-44, D1 bundle) +
  `ClassicalTrsBackend` (Shamir-Schnorr-P256, RQ5 baseline). Both behind `ITrsBackend`.
- **`08_detection_engine.h`** — the orchestrator:
  - `struct FullModeCryptoResult` + globals `g_fullcrypto_runs`, `g_fullcrypto_time_sum_ms`.
  - `run_full_mode_crypto_pipeline(closing_rsu, epoch, res)` — runs the whole Algorithm 6/7
    chain at the **controller window-close hook** (NOT the per-beacon RSU hot path — that
    would blow T_b=100ms and would sign plaintext). RSU 0 = ring coordinator; reads each
    RSU's `rsu_last_window[]` snapshot (in-process realization of Alg 6 lines 4-5
    broadcast/receive — transport-only simplification, crypto is real).
  - Call site: window-close hook (~line 1721, after `[CTRL-WIN-]`, before GAT), gated
    `if (use_pq_crypto && ablation_mode != 1 && ablation_mode != 6)`.
  - The old per-beacon plaintext-signing block (old R8.4) was **removed** — replaced by the
    window-close ciphertext pipeline (paper-correct).
- **`11_blockchain_setup.h`** — `initialize_crypto_backends`: live path now
  `init_trs_backend(4, 3, Dilithium)` (or Classical if `g_trs_classical_baseline`) +
  `init_threshold_fhe_backend(4, 3, 65537, 1)`. Single-key `init_fhe_backend` kept ONLY for
  the legacy 06b3 FHE-1..4 selftest.
- **`02_config_globals.h`** — `bool g_trs_classical_baseline = false;` (RQ5 toggle).
- **`12_main.h`** — CLI `--trs_classical`.
- **`06b3_crypto_selftest.h`** — env-gated `MPTD_CRYPTO_SELFTEST=1`. 19 steps: TRS-1*/2*/3/4,
  FHE-1..4, THFHE-1/2/3, PIPE-1/2. TRS-1c and TRS-2a are scheme-agnostic (bundle size ≥ one
  sig, not == ).

### 7.2 How to run the selftest (reproducible evidence)
```
export LD_LIBRARY_PATH="$(pwd)/build/lib:/home/niranga/.local/lib:/home/niranga/src/liboqs/build/lib:$LD_LIBRARY_PATH"
MPTD_CRYPTO_SELFTEST=1 ./build/scratch/mptd_pqs_sdvn/mptd_pqs_sdvn --mobility_source=0 --skip_blockchain=true --simTime=1
```
Expect: `[CRYPTO/SELFTEST] done: 19 passed, 0 failed.`

### 7.3 Mapping to the 7 metrics (instrumentation already present)
- **PARR (Eq 4.3):** `g_trs_rejected_count` / (`g_trs_verified_count`+`g_trs_rejected_count`)
  from the orchestrator's verify gate.
- **PBPO_Full (Eq 4.7):** `g_fullcrypto_time_sum_ms` / `g_fullcrypto_runs` (wall-clock per
  window). TRS-vs-ECDSA latency comparison via `--trs_classical` (RQ5).
- Crypto-agility sizes are runtime via `ITrsBackend::expected_*_size()`.

### 7.4 What is NOT yet done (next steps for the continuing account)
- **Full sim validation with SUMO** (`mobility_source` real, blockchain on) to capture
  PARR/PBPO_Full numbers under an attack scenario — the selftest proves the primitives, not
  the end-to-end metric numbers.
- **Cloud `cloud_Node` R9 wiring**: Eq 3.52 cloud-side *global* aggregate over multiple ring
  aggregates is currently realized in-process; if R9 splits the cloud into a real NS-3 node
  the partial-decrypt transport moves onto the LKH channel.
- **PBPO_Full budget check**: confirm per-window wall-clock fits `W = L·T_b` once SUMO load
  is realistic (ring_dim=16384 threshold ctx is heavier than the 8192 single-key ctx).
- **Paper-text correction** for Eq 3.50 compactness/anonymity (supervisor note delivered;
  not yet merged into the PDF).
