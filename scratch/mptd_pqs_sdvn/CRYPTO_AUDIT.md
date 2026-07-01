# Cryptography Audit — real vs. simulated, and what must be tested on the HPC

**Branch:** `feature/dkg-ring-keys`. **Date:** 2026-07-01.
**Why:** before finalising the DKG work, confirm each cryptographic primitive is
a *real* implementation (not a simulation/stub), and record exactly what has to
be verified on the HPC build. Method: read of `00_lkh_keys.h`, `06b1`, `06b2`,
`06b3` (self-test), `11_blockchain_setup.h`, `06c`, plus a standalone
compile+run of the new DKG.

---

## 1. Verdict table

| Primitive | Real? | Library / basis | Proven by | Caveats |
|---|---|---|---|---|
| HMAC-SHA256 beacon tag | **Real** | inline FIPS 180-4 / RFC 2104 | code + used every beacon | truncated to 64-bit tag (by design) |
| LKH KDF / key tree | **Real** | HMAC-SHA256 (HKDF-style) | code | leaf **first-delivery** is abstracted (D-LKH-1) |
| TRS — Classical (RQ5 baseline) | **Real** | Shamir-Schnorr on P-256 (OpenSSL EC) | self-test TRS-1..4 | σ_j linear ⇒ single-obs key leak; no FROST nonce |
| **DKG** (Classical ring keys) | **Real math** | Joint-Feldman VSS (OpenSSL EC) | standalone compile+run; in-tree build **pending HPC** | in-process (see §3) |
| TRS — Dilithium (paper full mode) | **Real** | ML-DSA-87 via liboqs | self-test PIPE-1/2 | **"bundle", not a compact anonymous TRS** (see §2) |
| FHE threshold | **Real** | OpenFHE 1.5.1 multiparty BFV | self-test THFHE-1..3 | **silent Mock fallback if header missing** (see §4) |
| FHE multiparty keygen (= FHE-DKG) | **Real** | OpenFHE `MultipartyKeyGen` | self-test | in-process; shares over ring channel |
| Ledger signatures (evidence/vote/reg) | **Real** | ML-DSA-87 (or ECDSA) | round-trips in chaincode | silent ECDSA fallback if liboqs missing |

**Bottom line:** every primitive is backed by a real library and round-trips in
the self-test — there are **no fake/hardcoded crypto values**. The gaps are (a)
two honest *design* limitations (Dilithium bundle; Classical σ_j leak), (b)
the *distribution/transport* being in-process, and (c) two **silent build
fallbacks** that must be ruled out on the HPC.

---

## 2. Honest design limitations (paper-conformance, not bugs)

- **PQ-TRS is a "bundle", not a compact anonymous threshold-ring signature.**
  `DilithiumTrsBackend` ([06b1:590-605](scratch/mptd_pqs_sdvn/06b1_trs_backend.h#L590))
  aggregates `t` independent ML-DSA signatures + signer-ids and accepts iff ≥ `t`
  distinct verify. The paper's Eq `trs_aggregate` prose says the aggregate is
  *"compact and conceals which specific t members signed"* — liboqs has no such
  primitive, so this is a real, **already-flagged** deviation. It affects **none
  of the 7 evaluation metrics** (PARR/CP-DETECT only need a sound `t`-of-`n`
  predicate), but it must be stated in the report/viva.
- **Classical TRS σ_j leaks the share.** `σ_j = s_j·H(m)` is linear, so one
  `(m, σ_j)` reveals `s_j` ([06b1:55-67](scratch/mptd_pqs_sdvn/06b1_trs_backend.h#L55)).
  Production Shamir-Schnorr needs a FROST-style per-signature nonce. This is the
  **baseline** backend only (RQ5); the default paper path is Dilithium, which is
  non-linear and unaffected.

## 3. Simulated / abstracted (transport, not the math)

- **DKG runs in-process.** One NS-3 process plays all `n` ring members. The
  polynomial sampling, Feldman commitments, share verification and summation are
  **real**, but commitment publication to the on-chain **bulletin board** and the
  **encrypted point-to-point** share exchange are **not wired** — same realism
  level as OpenFHE's in-process multiparty keygen. (Detail in `DKG_RING_KEYS.md`.)
  Scope note: the Joint-Feldman DKG applies to the **Classical** ring (which has a
  shared secret `x`); the **Dilithium** ring is independent per-member keypairs, so
  "no dealer" holds there by construction.
- **LKH leaf-key first-delivery (D-LKH-1)** ([00_lkh_keys.h:44](scratch/mptd_pqs_sdvn/00_lkh_keys.h#L44)):
  the joining vehicle and RSU share `K_{u_i}` in-process; a real deployment would
  wrap it under the vehicle's public key.
- **IPFS content hash falls back to FNV-1a** when IPFS is down
  ([06c:504](scratch/mptd_pqs_sdvn/06c_blockchain_api.h#L504)) — content
  addressing, not core crypto, but note it.
- **Blockchain writes are async/fire-and-forget** and the Fabric network is a
  separate peer net reached over a bridge; the on-chain path is exercised only
  with `--routing_algorithm=4` and a live Fabric (the paper's "under
  implementation" item).

## 4. ⚠️ Silent build fallbacks — the #1 thing to rule out on the HPC

Both are compile-time `#if __has_include(...)` guards that **do not fail the
build** — they quietly swap in a weaker path:

| If missing at build | Silent result | How to detect |
|---|---|---|
| `openfhe.h` | **Mock FHE** (`"Mock Threshold FHE BFV-RNS"`, [06b2:489](scratch/mptd_pqs_sdvn/06b2_fhe_backend.h#L489)) — no real encryption; round-trips still "pass" | self-test `[LEVEL5] FHE backend:` banner must **not** say "Mock" |
| `<oqs/oqs.h>` | PQ-TRS silently becomes **Classical** ([06b1:747](scratch/mptd_pqs_sdvn/06b1_trs_backend.h#L747)) | banner `[LEVEL5] TRS backend:` must say **ML-DSA-87**, not Shamir-Schnorr |
| `<oqs/oqs.h>` (ledger) | ledger sigs default to **ECDSA** ([11:78-82](scratch/mptd_pqs_sdvn/11_blockchain_setup.h#L78)) | `pk`/`sig` sizes ≈ ML-DSA (2592/4627 B), not 65/70 B |

A passing self-test is **necessary but not sufficient** — you must read the
banner to confirm the *real* backends compiled.

---

## 5. HPC test plan (ordered)

1. **Build** NS-3 with OpenFHE + liboqs headers discoverable: `python3 waf build`.
2. **Self-test + banner check:**
   `MPTD_CRYPTO_SELFTEST=1 python3 waf --run "mptd_pqs_sdvn --simTime=2"`
   - Confirm banner: TRS = **ML-DSA-87**, FHE = **BFV-RNS** (not "Mock").
   - Confirm all `TRS-1..4`, `FHE-1..4`, `THFHE-1..3`, `PIPE-1/2` = **PASS**.
     `PIPE-1/2` is the FHE→TRS pipeline (TRS signs `Enc(A_ring)`), Eq 3.46-3.51.
3. **DKG in-tree confirmation** (my change only touches the Classical backend):
   run the Classical path so `ClassicalTrsBackend::generate_keys` (the new DKG) is
   exercised in the NS-3 build, e.g. `--trs_classical=1`, and confirm `TRS-1..4`
   still PASS. (Standalone it already compiles + runs + round-trips; this just
   confirms the ns3/OpenSSL include chain.)
4. **Live ledger round-trip:** bring up `fabric_net`, `--routing_algorithm=4
   --skip_blockchain=false`, run register → submit-evidence → revoke; confirm
   chaincode accepts real signatures and rejects forged ones.
5. **(Later, real-DKG follow-up)** wire on-chain commitment publication +
   encrypted P2P share exchange (removes the §3 in-process abstraction).

## 6. What did NOT change and is safe
- `partial_sign` / `aggregate` / `verify_threshold` are untouched by the DKG; the
  DKG output is an identical `(t,n)` Shamir sharing, so all TRS self-tests keep
  their meaning. `generate_keys` runs **once** at init (guarded by `g_trs_ready`)
  and no code re-derives TRS shares, so fresh per-run randomness is safe.

---

## 7. NIST Level 5 coverage — where it holds and where it does NOT

Is every cryptographic operation at NIST PQ Category 5? **No.** Level 5 holds on
the core post-quantum path (ML-DSA-87 + FHE-256), but several primitives sit
below it. Categories: L5 = AES-256 key search; L4 = SHA-384 collision;
L2 = SHA-256 collision.

| Primitive | Effective PQ strength | Level 5? |
|---|---|---|
| ML-DSA-87 TRS (default full mode) | Cat 5 | ✅ |
| ML-DSA-87 ledger signatures (default) | Cat 5 | ✅ |
| OpenFHE BFV @ `HEStd_256_quantum` (enc / multiparty keygen / thresh. dec) | Cat 5 (256-bit) | ✅ |
| 256-bit LKH symmetric keys (HMAC/KDF key material) | AES-256-equiv | ✅ |
| **SHA-256** (HMAC, KDF, ledger digest, beacon hash, `h(K_u)`, TRS challenge) | collision ≈ **Cat 2** | ⚠️ no |
| **Beacon HMAC tag — truncated to 64 bits** | 64-bit forgery resistance | ⚠️ no |
| **Joint-Feldman DKG on P-256** (classical TRS ring keys only) | ECDLP — **classical** | ❌ no |
| Classical Shamir-Schnorr TRS (RQ5 baseline) | ECDLP — classical | ❌ by design |
| Fabric MSP / TLS / ordering (ECDSA) | ECDLP — classical | ❌ documented ceiling |
| Silent fallback: no liboqs → ECDSA; no OpenFHE → Mock | classical / none | ❌ build risk (§4) |

### Flags (below Level 5)
1. **The DKG is NOT post-quantum.** The Joint-Feldman DKG runs on the P-256 curve
   — its security is ECDLP (broken by Shor), so it is **classical, not Level 5**.
   It keys **only the classical TRS baseline**. The Level-5 ring (ML-DSA-87) does
   **not** use it — each RSU independently generates its own ML-DSA-87 keypair. So
   "no dealer" on the PQ path comes from *independent keygen*, and **there is no
   post-quantum (Level-5) shared-secret DKG** in the system (no lattice
   threshold-DKG primitive exists in the linked libraries). Do NOT claim "the DKG
   is Level 5."
2. **SHA-256 caps collision-dependent operations at Category 2.** Every field-set
   that is SHA-256-hashed then ML-DSA-signed (ledger evidence/vote/registration
   digests) inherits ~128-bit collision resistance (Cat 2), even though ML-DSA-87
   is Cat 5. Strict Level 5 would pre-hash with SHA-512/SHA-384. (HMAC/KDF *as a
   MAC/PRF* are fine — that relies on PRF security, not collision resistance.)
3. **Beacon HMAC tag is 64-bit.** Truncated for airtime; 64-bit forgery resistance
   per beacon — far below Level 5. Acceptable engineering tradeoff, but state it.
4. **Classical TRS baseline + Fabric platform** are classical by design/necessity
   (RQ5 comparison point; Fabric BCCSP can't be made PQ without forking it).
5. **Silent build fallbacks (§4)** drop the whole stack below Level 5 if the PQ
   libraries aren't linked — confirm via the self-test `[LEVEL5]` banner.

### If strict "Level 5 everywhere" is required
- Pre-hash ledger digests with **SHA-512** instead of SHA-256 (coordinated C++/Go
  change — both sides must agree on the signed bytes).
- Widen the beacon tag (costs airtime), or accept 64-bit and document it.
- State plainly that the DKG (classical, baseline-only) and the Fabric platform
  sit outside the Level-5 boundary.
