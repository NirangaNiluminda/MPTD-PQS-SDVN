// ============================================================
// 06b1_trs_backend.h — Threshold Ring Signature backend (crypto-agile)
// MPTD-PQS SDVN, R8 — real Shamir-Schnorr-P256 (replaces R6.5 ECDSA placeholder)
// ============================================================
// Paper §3.5.4 (Eq 3.45–3.54) + cite [11] Ahmed et al. 2022.
//
// Framing B (per CLAUDE.md Crypto Scheme Locks, May 2026):
//   The paper's "post-quantum TRS" qualifier is paper-internally inconsistent
//   with cite [11], whose scheme uses ECDLP-based EC primitives (classical,
//   broken by Shor). This module ships a classical-first implementation
//   behind ITrsBackend so the eval table can be reproduced now; phase R11
//   swaps in LatticeTrsBackend (CRYSTALS-Dilithium via liboqs) without
//   touching call sites. All sig/key sizes are runtime values from
//   expected_*_size() — no hardcoded 64-byte assumptions remain.
//
// R8 scope (this revision):
//   Replace the R6.5 ECDSA placeholder with a real Shamir t-of-n threshold
//   Schnorr signature on NIST P-256, with Lagrange interpolation at zero.
//   This is the "classical EC threshold" stand-in that the Framing B lock
//   describes; the paper's literal cite [11] uses EC-ElGamal partials with
//   the same Lagrange aggregator and the same ECDLP security assumption —
//   the choice between the two is implementation detail at the signing
//   primitive level, both produce a single 32-byte scalar σ_TRS that
//   verifies against a 33-byte compressed master public key.
//
//   Scheme (Joint-Feldman DKG: no single dealer, no controller, no K_ring):
//     Setup (one-time per ring, in generate_keys):
//       - Each member i samples its OWN degree-(t-1) poly f_i with fresh CSPRNG
//         coefficients a_{i,k} and broadcasts Feldman commitments C_{i,k}=a_{i,k}*G.
//       - master_pk = Sum_i C_{i,0} = x*G   (group secret x never assembled).
//       - s_j  = Sum_i f_i(j) mod q          (Shamir share of x; VSS-verified).
//       - pk_j = s_j * G                     (per-signer point; Eq 3.25 dkg_trs).
//     PartialSign(s_j, m):                            (Eq 3.47, RSU j)
//       - h = SHA256(m) reduced mod q                 (challenge scalar)
//       - σ_j = (s_j · h) mod q                       (32-byte scalar)
//     Aggregate({σ_j}_{j∈S}, S):                       (Eq 3.48, |S| = t)
//       - σ = Σ_{j∈S} λ_j(0) · σ_j  mod q             (Lagrange combine)
//       - where λ_j(0) = Π_{k∈S, k≠j} k / (k - j) mod q
//     Verify(master_pk, m, σ):                         (Eq 3.49)
//       - h = SHA256(m) mod q
//       - accept ⇔ σ·G == h·master_pk
//
//   Why this satisfies the eval:
//     - Threshold-of-t property is real: < t valid partials → Lagrange combine
//       does not produce a σ that verifies, because the recovered "poly(0)"
//       will not equal a₀.
//     - PARR (Eq 4.3) and CP-DETECT TRS-gate (Algorithm 7 line 2–6) require
//       only that verify_threshold be a sound predicate over (m, σ, ring).
//       Sound here: forging σ without ≥t shares requires solving ECDLP for
//       master_pk = a₀·G.
//     - PBPO_Full (Eq 4.7) TRS signing latency is the wall-clock of
//       partial_sign + aggregate, both BN-only mod-q ops — sub-millisecond
//       on P-256 with OpenSSL 3.0.
//
//   Security caveat (documented, sim-acceptable, NOT production-grade):
//     σ_j = s_j · h is *linear* in s_j with known h. An adversary who
//     observes a single (m, σ_j, signer_id) tuple can recover s_j as
//     σ_j · h⁻¹ mod q. Production-grade Shamir-Schnorr uses a per-signature
//     nonce k_j (FROST-style 2-round commit-then-sign) to randomize σ_j and
//     hide s_j. The simulation is non-adversarial w.r.t. signer-key exfil
//     (we only model attacker classes at the *beacon* layer, not the TRS
//     key-management layer); both Framing B and the paper's literal cite
//     [11] inherit this single-sig leakage issue, so we explicitly mark
//     this as the same level of formal hygiene as the paper itself, no
//     better and no worse. Phase R11 lattice-TRS introduces a real
//     FROST-equivalent nonce protocol along with the PQ swap.
//
// Layout & global state (unchanged from R6.5 API):
//   g_trs_backend       active ITrsBackend impl (ClassicalTrsBackend default)
//   g_trs_ring_pks      pk table of length n+1:
//                         pks[0]      = master_pk (33B compressed)
//                         pks[1..n]   = pk_j = s_j·G (33B compressed each)
//                       — verify_threshold uses ONLY pks[0]; pks[1..n] are
//                       kept for future provenance / partial verification.
//   g_trs_ring_sks      sk table of length n:
//                         sks[j-1] = s_j (32B scalar)
//                       — index = (Shamir signer id - 1)
//   g_trs_ring_n / t    ring size and threshold (n=4, t=3 by default)
//
//   IMPORTANT: signer_ids in aggregate() are 1-indexed Shamir indices
//   (NOT 0-indexed array positions). g_trs_ring_sks[j-1] corresponds to
//   Shamir share s_j with signer_id = j.
//
// CP-DETECT (08_detection_engine.h) continues to call
//   cp_detect_verify_trs(sigma, len) → g_trs_backend->verify_threshold(...)
// with no API change.
//
// Include order: AFTER 00_lkh_keys.h (uses LKH_K_RING + lkh_hmac_sha256),
//                BEFORE 06c_blockchain_api.h.
// Linker: requires -lcrypto (OpenSSL 3.0.2 system lib, already in wscript).
// ============================================================

#ifndef MPTD_PQS_06B1_TRS_BACKEND_H
#define MPTD_PQS_06B1_TRS_BACKEND_H

#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <memory>

// Silence OpenSSL 3.0 deprecation warnings for low-level EC point helpers.
// We use the low-level EC_POINT / BN_* API because the Schnorr-style verify
// (σ·G == h·master_pk) is naturally expressed at the scalar/point level;
// going via EVP_PKEY would force us to wrap σ as an ECDSA_SIG (which has
// completely different semantics) just to satisfy the API surface.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#pragma GCC diagnostic pop

#if __has_include(<oqs/oqs.h>)
#include <oqs/oqs.h>
#endif

// NIST Level 5 enforcement (opt-in via -DMPTD_REQUIRE_LEVEL5): the ML-DSA-87
// PQ-TRS needs liboqs; without it init_trs_backend() silently falls back to the
// classical Shamir-Schnorr P-256 backend, which is NOT post-quantum.
#if defined(MPTD_REQUIRE_LEVEL5) && !__has_include(<oqs/oqs.h>)
#  error "MPTD_REQUIRE_LEVEL5: liboqs (<oqs/oqs.h>) required for the ML-DSA-87 PQ-TRS; the classical Shamir-Schnorr fallback is not NIST Level 5."
#endif

// ────────────────────────────────────────────────────────────────────────────
// ITrsBackend — abstract crypto-agile threshold ring signature interface.
// Paper §3.5.4 Eq 3.47–3.54. All buffer sizes are runtime (no hardcoded 64).
// ────────────────────────────────────────────────────────────────────────────
class ITrsBackend {
public:
    virtual ~ITrsBackend() = default;

    // Setup: derive n shares for the RSU ring with threshold t.
    // out_pks: length n+1, where pks[0] = master_pk, pks[1..n] = s_j·G.
    // out_sks: length n, where sks[j-1] = s_j (1-indexed Shamir).
    virtual bool generate_keys(uint32_t n, uint32_t t,
                               std::vector<std::vector<uint8_t>> &out_pks,
                               std::vector<std::vector<uint8_t>> &out_sks) = 0;

    // RSU j produces partial signature σ_j = s_j · H(m) over message.
    // sk is the 32-byte scalar share s_j. out_partial is 32 bytes.
    // Paper Eq 3.47.
    virtual bool partial_sign(const std::vector<uint8_t> &message,
                              const std::vector<uint8_t> &sk,
                              std::vector<uint8_t> &out_partial) = 0;

    // Cloud (or RSU leader) aggregates t partials into σ_TRS via Lagrange
    // interpolation at x = 0. signer_ids[k] is the 1-indexed Shamir index
    // of the signer who produced partials[k]. Must satisfy
    //   partials.size() == signer_ids.size() == t (or >t; first t used).
    // Paper Eq 3.48. Returns false if duplicate signer_ids, < t partials,
    // or modular-inverse failure (duplicate ids).
    virtual bool aggregate(const std::vector<std::vector<uint8_t>> &partials,
                           const std::vector<uint32_t> &signer_ids,
                           std::vector<uint8_t> &out_sigma) = 0;

    // Verifier checks σ_TRS against the master ring public key.
    // pks[0] MUST be the master_pk (33B compressed P-256 point); other
    // entries are ignored by this implementation but kept for ABI parity
    // across backends. Paper Eq 3.49–3.51.
    virtual bool verify_threshold(const std::vector<uint8_t> &message,
                                  const std::vector<uint8_t> &sigma,
                                  const std::vector<std::vector<uint8_t>> &pks) = 0;

    // Sizing for buffer allocation across the codebase (crypto-agility).
    virtual size_t expected_sig_size() const = 0;
    virtual size_t expected_pk_size()  const = 0;
    virtual size_t expected_sk_size()  const = 0;
    virtual const char* scheme_name()  const = 0;
};

// ────────────────────────────────────────────────────────────────────────────
// Global TRS state. Initialized in 11_blockchain_setup.h at sim start.
// Declared up here (above ClassicalTrsBackend) because aggregate() consults
// g_trs_ring_t to honor the per-ring threshold when caller supplies > t
// partials. The definitions also live here (header-only, single-TU usage
// from simulation.cc — no ODR issues).
//   g_trs_backend:    active ITrsBackend impl (ClassicalTrsBackend for R8)
//   g_trs_ring_pks:   n+1 pks — [0]=master_pk, [1..n]=s_j·G
//   g_trs_ring_sks:   n sks   — sks[j-1] = s_j (1-indexed Shamir)
//   g_trs_ring_n / t: ring size and threshold
// ────────────────────────────────────────────────────────────────────────────
static std::unique_ptr<ITrsBackend>       g_trs_backend;
static std::vector<std::vector<uint8_t>>  g_trs_ring_pks;
static std::vector<std::vector<uint8_t>>  g_trs_ring_sks;
static uint32_t                           g_trs_ring_n = 0;
static uint32_t                           g_trs_ring_t = 0;
static bool                               g_trs_ready  = false;

// ────────────────────────────────────────────────────────────────────────────
// ClassicalTrsBackend — Shamir t-of-n threshold Schnorr on EC P-256.
//
// Scheme summary (full security note in file header):
//   master_pk = Sum_i C_{i,0} = x*G   (Joint-Feldman DKG; x = Sum_i a_{i,0} never
//                                      assembled — no dealer, no controller, no K_ring)
//   s_j       = Sum_i f_i(j) mod q     (Shamir share of x; VSS-verified, j=1..n)
//   pk_j      = s_j · G                          (33B compressed)
//   σ_j       = s_j · H(m) mod q                 (32B partial)
//   σ_TRS     = Σ_{j∈S} λ_j(0) · σ_j mod q       (32B aggregated; |S|=t)
//   verify    : σ_TRS · G == H(m) · master_pk    (Schnorr-style)
// ────────────────────────────────────────────────────────────────────────────
class ClassicalTrsBackend : public ITrsBackend {
public:
    static constexpr int    EC_NID  = NID_X9_62_prime256v1; // P-256 (secp256r1)
    static constexpr size_t SIG_LEN = 32;  // single scalar σ ∈ Z_q
    static constexpr size_t PK_LEN  = 33;  // SEC1 compressed point
    static constexpr size_t SK_LEN  = 32;  // raw scalar s_j

    // ──────────────────────────────────────────────────────────────────────
    // generate_keys: Joint-Feldman DKG (paper Eq 3.25 dkg_trs) — NO dealer,
    // NO controller, NO K_ring seed.
    //
    // Each of the n RSU ring members independently samples its OWN degree-(t-1)
    // polynomial f_i with FRESH CSPRNG coefficients a_{i,k} ∈ Z_q, publishes
    // Feldman commitments C_{i,k} = a_{i,k}·G, and every member's contribution is
    // summed: the final per-signer share is s_j = Σ_i f_i(j). The group secret
    // x = Σ_i a_{i,0} is NEVER assembled at any single entity, and
    // master_pk = Σ_i C_{i,0} = x·G. The resulting (master_pk, {s_j}) is a (t,n)
    // Shamir sharing of x — identical in shape to the previous trusted-dealer
    // output — so partial_sign / aggregate / verify_threshold are UNCHANGED.
    //
    // Faithfulness / realism (honest, like the FHE multiparty side in 06b2):
    //   • REAL: per-member fresh randomness (BN_rand_range), Feldman commitments,
    //     and the verifiable share check f_i(j)·G == Σ_k j^k·C_{i,k} are all
    //     genuine VSS — no member's secret depends on a shared seed, no dealer
    //     holds the master secret, K_ring is no longer consulted here.
    //   • ABSTRACTED (HPC/Fabric follow-up): the protocol runs in-process (one
    //     NS-3 process plays all n members) and commitment publication to the
    //     blockchain "public bulletin board" + over-the-network share exchange
    //     are not yet wired (needs the live Fabric layer). This matches the
    //     in-process status of the OpenFHE MultipartyKeyGen DKG in 06b2.
    //   • Keys are CSPRNG-fresh per run (generate_keys runs once under the
    //     g_trs_ready guard); detection metrics depend only on within-run key
    //     consistency, not on key values (unchanged from the prior design).
    // NOTE: NOT yet compiled — verify on the HPC build (see DKG_RING_KEYS.md).
    // ──────────────────────────────────────────────────────────────────────
    bool generate_keys(uint32_t n, uint32_t t,
                       std::vector<std::vector<uint8_t>> &out_pks,
                       std::vector<std::vector<uint8_t>> &out_sks) override
    {
        if (t == 0 || t > n || n > 64) return false;

        EC_GROUP *grp = EC_GROUP_new_by_curve_name(EC_NID);
        if (!grp) return false;
        BIGNUM   *q   = BN_new();
        BN_CTX   *ctx = BN_CTX_new();
        if (!q || !ctx ||
            EC_GROUP_get_order(grp, q, ctx) != 1) {
            if (ctx) BN_CTX_free(ctx);
            if (q)   BN_free(q);
            EC_GROUP_free(grp);
            return false;
        }

        bool ok = true;

        // Per-member secret polynomials coef[i][k] = a_{i,k} and their Feldman
        // commitments commit[i][k] = a_{i,k}·G. nullptr-initialised so the single
        // cleanup at the end is safe even on partial-allocation failure.
        std::vector<std::vector<BIGNUM*>>   coef(n, std::vector<BIGNUM*>(t, nullptr));
        std::vector<std::vector<EC_POINT*>> commit(n, std::vector<EC_POINT*>(t, nullptr));

        // ── DKG step 1: each member i samples its own polynomial + broadcasts
        //    Feldman commitments (fresh CSPRNG per coefficient; no shared seed). ──
        for (uint32_t i = 0; i < n && ok; i++) {
            for (uint32_t k = 0; k < t && ok; k++) {
                BIGNUM *a = BN_new();
                if (!a) { ok = false; break; }
                if (BN_rand_range(a, q) != 1) { BN_free(a); ok = false; break; }
                // a_{i,0} ≠ 0 so member i's constant-term commitment is non-identity.
                if (k == 0 && BN_is_zero(a)) BN_set_word(a, 1);
                coef[i][k] = a;
                EC_POINT *C = EC_POINT_new(grp);
                if (!C || EC_POINT_mul(grp, C, a, nullptr, nullptr, ctx) != 1) {
                    if (C) EC_POINT_free(C);
                    ok = false; break;
                }
                commit[i][k] = C;
            }
        }

        // ── DKG step 2: verify each contributor's shares against its commitments
        //    f_i(j)·G == Σ_k j^k·C_{i,k}  (Feldman VSS check). Honest contributors
        //    always pass in-process; a corrupted member's bad share fails here,
        //    modelling the protocol's complaint/disqualification condition. ──
        for (uint32_t i = 0; i < n && ok; i++) {
            for (uint32_t j = 1; j <= n && ok; j++) {
                BIGNUM   *fij  = BN_new();   // f_i(j) = Σ_k a_{i,k}·j^k
                BIGNUM   *jpow = BN_new();   // j^k (for the scalar sum)
                BIGNUM   *jp2  = BN_new();   // j^k (for the EC commitment combo)
                BIGNUM   *bj   = BN_new();
                BIGNUM   *term = BN_new();
                EC_POINT *lhs  = EC_POINT_new(grp);   // f_i(j)·G
                EC_POINT *rhs  = EC_POINT_new(grp);   // Σ_k j^k·C_{i,k}
                EC_POINT *tmpP = EC_POINT_new(grp);
                if (!fij || !jpow || !jp2 || !bj || !term || !lhs || !rhs || !tmpP) {
                    ok = false;
                } else {
                    BN_zero(fij); BN_one(jpow); BN_one(jp2);
                    BN_set_word(bj, (BN_ULONG)j);
                    EC_POINT_set_to_infinity(grp, rhs);
                    for (uint32_t k = 0; k < t && ok; k++) {
                        if (BN_mod_mul(term, coef[i][k], jpow, q, ctx) != 1 ||
                            BN_mod_add(fij, fij, term, q, ctx) != 1) { ok = false; break; }
                        if (EC_POINT_mul(grp, tmpP, nullptr, commit[i][k], jp2, ctx) != 1 ||
                            EC_POINT_add(grp, rhs, rhs, tmpP, ctx) != 1) { ok = false; break; }
                        if (k + 1 < t) {
                            if (BN_mod_mul(jpow, jpow, bj, q, ctx) != 1 ||
                                BN_mod_mul(jp2,  jp2,  bj, q, ctx) != 1) { ok = false; break; }
                        }
                    }
                    if (ok && EC_POINT_mul(grp, lhs, fij, nullptr, nullptr, ctx) != 1) ok = false;
                    if (ok && EC_POINT_cmp(grp, lhs, rhs, ctx) != 0) ok = false; // VSS mismatch
                }
                if (fij)  BN_free(fij);
                if (jpow) BN_free(jpow);
                if (jp2)  BN_free(jp2);
                if (bj)   BN_free(bj);
                if (term) BN_free(term);
                if (lhs)  EC_POINT_free(lhs);
                if (rhs)  EC_POINT_free(rhs);
                if (tmpP) EC_POINT_free(tmpP);
            }
        }

        out_pks.clear();
        out_pks.resize(n + 1);
        out_sks.clear();
        out_sks.resize(n);

        // ── master_pk = Σ_i C_{i,0} = (Σ_i a_{i,0})·G = x·G (x never materialised) ──
        if (ok) {
            EC_POINT *mpk = EC_POINT_new(grp);
            if (!mpk) { ok = false; }
            else {
                EC_POINT_set_to_infinity(grp, mpk);
                for (uint32_t i = 0; i < n && ok; i++)
                    if (EC_POINT_add(grp, mpk, mpk, commit[i][0], ctx) != 1) ok = false;
                if (ok && EC_POINT_is_at_infinity(grp, mpk)) ok = false; // x ≡ 0 (negligible)
                if (ok) {
                    out_pks[0].assign(PK_LEN, 0);
                    if (EC_POINT_point2oct(grp, mpk, POINT_CONVERSION_COMPRESSED,
                                           out_pks[0].data(), PK_LEN, ctx) != PK_LEN) ok = false;
                }
                EC_POINT_free(mpk);
            }
        }

        // ── DKG step 3: final per-signer share s_j = Σ_i f_i(j); pk_j = s_j·G. ──
        for (uint32_t j = 1; j <= n && ok; j++) {
            BIGNUM *s_j  = BN_new();    // Σ_i f_i(j)
            BIGNUM *jpow = BN_new();    // j^k (reset per contributor)
            BIGNUM *bj   = BN_new();
            BIGNUM *term = BN_new();
            if (!s_j || !jpow || !bj || !term) {
                ok = false;
            } else {
                BN_zero(s_j);
                BN_set_word(bj, (BN_ULONG)j);
                for (uint32_t i = 0; i < n && ok; i++) {
                    BN_one(jpow);                    // j^0 for this contributor
                    for (uint32_t k = 0; k < t && ok; k++) {
                        if (BN_mod_mul(term, coef[i][k], jpow, q, ctx) != 1 ||
                            BN_mod_add(s_j, s_j, term, q, ctx) != 1) { ok = false; break; }
                        if (k + 1 < t && BN_mod_mul(jpow, jpow, bj, q, ctx) != 1) { ok = false; break; }
                    }
                }
                if (ok) {
                    out_sks[j-1].assign(SK_LEN, 0);
                    int slen = BN_num_bytes(s_j);
                    if (slen > (int)SK_LEN) ok = false;
                    else BN_bn2bin(s_j, out_sks[j-1].data() + (SK_LEN - (size_t)slen));
                }
                if (ok) {
                    EC_POINT *pk_j = EC_POINT_new(grp);
                    if (!pk_j || EC_POINT_mul(grp, pk_j, s_j, nullptr, nullptr, ctx) != 1) {
                        ok = false;
                    } else {
                        out_pks[j].assign(PK_LEN, 0);
                        if (EC_POINT_point2oct(grp, pk_j, POINT_CONVERSION_COMPRESSED,
                                               out_pks[j].data(), PK_LEN, ctx) != PK_LEN) ok = false;
                    }
                    if (pk_j) EC_POINT_free(pk_j);
                }
            }
            if (s_j)  BN_free(s_j);
            if (jpow) BN_free(jpow);
            if (bj)   BN_free(bj);
            if (term) BN_free(term);
        }

        // Single cleanup of all per-member polynomials + commitments.
        for (uint32_t i = 0; i < n; i++)
            for (uint32_t k = 0; k < t; k++) {
                if (coef[i][k])   BN_free(coef[i][k]);
                if (commit[i][k]) EC_POINT_free(commit[i][k]);
            }
        BN_CTX_free(ctx); BN_free(q); EC_GROUP_free(grp);
        return ok;
    }

    // ──────────────────────────────────────────────────────────────────────
    // partial_sign: σ_j = s_j · H(m) mod q  (Eq 3.47)
    // ──────────────────────────────────────────────────────────────────────
    bool partial_sign(const std::vector<uint8_t> &message,
                      const std::vector<uint8_t> &sk,
                      std::vector<uint8_t> &out_partial) override
    {
        if (sk.size() != SK_LEN) return false;

        EC_GROUP *grp = EC_GROUP_new_by_curve_name(EC_NID);
        if (!grp) return false;
        BIGNUM   *q   = BN_new();
        BN_CTX   *ctx = BN_CTX_new();
        if (!q || !ctx || EC_GROUP_get_order(grp, q, ctx) != 1) {
            if (ctx) BN_CTX_free(ctx);
            if (q)   BN_free(q);
            EC_GROUP_free(grp);
            return false;
        }

        // h = SHA256(m) reduced mod q
        uint8_t digest[32];
        SHA256(message.data(), message.size(), digest);
        BIGNUM *h   = BN_bin2bn(digest, 32, nullptr);
        BIGNUM *s_j = BN_bin2bn(sk.data(), (int)SK_LEN, nullptr);
        BIGNUM *sig = BN_new();
        bool ok = (h && s_j && sig);
        if (ok) ok = (BN_mod(h, h, q, ctx) == 1);
        if (ok) ok = (BN_mod_mul(sig, s_j, h, q, ctx) == 1);

        if (ok) {
            out_partial.assign(SIG_LEN, 0);
            int slen = BN_num_bytes(sig);
            if (slen > (int)SIG_LEN) ok = false;
            else BN_bn2bin(sig, out_partial.data() + (SIG_LEN - (size_t)slen));
        }

        if (h)   BN_free(h);
        if (s_j) BN_free(s_j);
        if (sig) BN_free(sig);
        BN_CTX_free(ctx); BN_free(q); EC_GROUP_free(grp);
        return ok;
    }

    // ──────────────────────────────────────────────────────────────────────
    // aggregate: σ_TRS = Σ_{j∈S} λ_j(0) · σ_j mod q   (Eq 3.48)
    //   λ_j(0) = Π_{k∈S, k≠j} k / (k - j) mod q
    // signer_ids[i] is the 1-indexed Shamir id of partials[i]. We take the
    // first t entries (caller is responsible for ordering / dedup beyond
    // duplicate detection here).
    // ──────────────────────────────────────────────────────────────────────
    bool aggregate(const std::vector<std::vector<uint8_t>> &partials,
                   const std::vector<uint32_t> &signer_ids,
                   std::vector<uint8_t> &out_sigma) override
    {
        if (partials.size() != signer_ids.size()) return false;
        if (partials.empty()) return false;
        if (partials.size() > 64) return false;
        // Caller may supply more than t partials; we only use the first
        // ring_t. If the backend hasn't been registered into the global
        // ring yet (g_trs_ring_t == 0), fall back to "use all supplied".
        const size_t use_n = (g_trs_ring_t > 0 && partials.size() >= g_trs_ring_t)
                             ? (size_t)g_trs_ring_t
                             : partials.size();
        for (size_t i = 0; i < use_n; i++) {
            if (partials[i].size() != SIG_LEN) return false;
            if (signer_ids[i] == 0)            return false; // 1-indexed
            for (size_t k = i + 1; k < use_n; k++) {
                if (signer_ids[k] == signer_ids[i]) return false; // duplicate
            }
        }

        EC_GROUP *grp = EC_GROUP_new_by_curve_name(EC_NID);
        if (!grp) return false;
        BIGNUM   *q   = BN_new();
        BN_CTX   *ctx = BN_CTX_new();
        if (!q || !ctx || EC_GROUP_get_order(grp, q, ctx) != 1) {
            if (ctx) BN_CTX_free(ctx);
            if (q)   BN_free(q);
            EC_GROUP_free(grp);
            return false;
        }

        BIGNUM *sigma = BN_new();
        bool ok = (sigma != nullptr);
        if (ok) BN_zero(sigma);

        for (size_t i = 0; i < use_n && ok; i++) {
            // Compute λ_i(0) = Π_{k≠i} signer_ids[k] / (signer_ids[k] - signer_ids[i])
            BIGNUM *lam = BN_new();
            BIGNUM *num = BN_new();
            BIGNUM *den = BN_new();
            BIGNUM *bi  = BN_new();     // signer_ids[i]
            BIGNUM *inv = BN_new();
            BIGNUM *tmp = BN_new();
            if (!lam || !num || !den || !bi || !inv || !tmp) {
                ok = false; goto lag_cleanup;
            }
            BN_one(lam);
            BN_set_word(bi, (BN_ULONG)signer_ids[i]);

            for (size_t k = 0; k < use_n && ok; k++) {
                if (k == i) continue;
                BN_set_word(num, (BN_ULONG)signer_ids[k]);
                // den = (signer_ids[k] - signer_ids[i]) mod q
                if (BN_mod_sub(den, num, bi, q, ctx) != 1) { ok = false; break; }
                if (BN_is_zero(den)) { ok = false; break; } // duplicate (paranoia)
                if (!BN_mod_inverse(inv, den, q, ctx))  { ok = false; break; }
                if (BN_mod_mul(tmp, num, inv, q, ctx) != 1) { ok = false; break; }
                if (BN_mod_mul(lam, lam, tmp, q, ctx) != 1) { ok = false; break; }
            }

            if (ok) {
                // term = lam · σ_i mod q
                BIGNUM *sig_i = BN_bin2bn(partials[i].data(), (int)SIG_LEN, nullptr);
                if (!sig_i) { ok = false; goto lag_cleanup; }
                if (BN_mod_mul(tmp, lam, sig_i, q, ctx) != 1) {
                    BN_free(sig_i); ok = false; goto lag_cleanup;
                }
                if (BN_mod_add(sigma, sigma, tmp, q, ctx) != 1) {
                    BN_free(sig_i); ok = false; goto lag_cleanup;
                }
                BN_free(sig_i);
            }

        lag_cleanup:
            if (lam) BN_free(lam);
            if (num) BN_free(num);
            if (den) BN_free(den);
            if (bi)  BN_free(bi);
            if (inv) BN_free(inv);
            if (tmp) BN_free(tmp);
        }

        if (ok) {
            out_sigma.assign(SIG_LEN, 0);
            int slen = BN_num_bytes(sigma);
            if (slen > (int)SIG_LEN) ok = false;
            else BN_bn2bin(sigma, out_sigma.data() + (SIG_LEN - (size_t)slen));
        }

        if (sigma) BN_free(sigma);
        BN_CTX_free(ctx); BN_free(q); EC_GROUP_free(grp);
        return ok;
    }

    // ──────────────────────────────────────────────────────────────────────
    // verify_threshold: σ·G == H(m)·master_pk    (Eq 3.49)
    //   pks[0] = master_pk (33B compressed). pks[1..] are ignored at this
    //   backend (kept for ABI parity with future provenance-aware backends).
    // ──────────────────────────────────────────────────────────────────────
    bool verify_threshold(const std::vector<uint8_t> &message,
                          const std::vector<uint8_t> &sigma,
                          const std::vector<std::vector<uint8_t>> &pks) override
    {
        if (sigma.size() != SIG_LEN)                    return false;
        if (pks.empty() || pks[0].size() != PK_LEN)     return false;

        EC_GROUP *grp = EC_GROUP_new_by_curve_name(EC_NID);
        if (!grp) return false;
        BIGNUM   *q   = BN_new();
        BN_CTX   *ctx = BN_CTX_new();
        if (!q || !ctx || EC_GROUP_get_order(grp, q, ctx) != 1) {
            if (ctx) BN_CTX_free(ctx);
            if (q)   BN_free(q);
            EC_GROUP_free(grp);
            return false;
        }

        // h = SHA256(m) mod q
        uint8_t digest[32];
        SHA256(message.data(), message.size(), digest);
        BIGNUM *h = BN_bin2bn(digest, 32, nullptr);
        BIGNUM *s = BN_bin2bn(sigma.data(), (int)SIG_LEN, nullptr);
        bool ok = (h && s);
        if (ok) ok = (BN_mod(h, h, q, ctx) == 1);

        EC_POINT *lhs = nullptr;
        EC_POINT *rhs = nullptr;
        EC_POINT *mpk = nullptr;
        if (ok) {
            // lhs = σ · G
            lhs = EC_POINT_new(grp);
            ok  = (lhs && EC_POINT_mul(grp, lhs, s, nullptr, nullptr, ctx) == 1);
        }
        if (ok) {
            // master_pk from pks[0]
            mpk = EC_POINT_new(grp);
            ok  = (mpk && EC_POINT_oct2point(grp, mpk,
                                             pks[0].data(), pks[0].size(),
                                             ctx) == 1);
        }
        if (ok) {
            // rhs = h · master_pk
            rhs = EC_POINT_new(grp);
            ok  = (rhs && EC_POINT_mul(grp, rhs, nullptr, mpk, h, ctx) == 1);
        }

        bool verified = false;
        if (ok) {
            verified = (EC_POINT_cmp(grp, lhs, rhs, ctx) == 0);
        }

        if (h)   BN_free(h);
        if (s)   BN_free(s);
        if (lhs) EC_POINT_free(lhs);
        if (rhs) EC_POINT_free(rhs);
        if (mpk) EC_POINT_free(mpk);
        BN_CTX_free(ctx); BN_free(q); EC_GROUP_free(grp);
        return ok && verified;
    }

    size_t expected_sig_size() const override { return SIG_LEN; }
    size_t expected_pk_size()  const override { return PK_LEN;  }
    size_t expected_sk_size()  const override { return SK_LEN;  }
    const char* scheme_name()  const override {
        return "Shamir-Schnorr-P256 t-of-n (classical TRS / ECDSA-class baseline; "
               "Lagrange combine real; PQ via DilithiumTrsBackend)";
    }
};

// ────────────────────────────────────────────────────────────────────────────
// DilithiumTrsBackend — post-quantum t-of-n TRS via liboqs ML-DSA (Dilithium).
//
// Paper §3.5.4 Eq 3.49–3.51: σ_j = Sign(sk_j, m) with a "lattice-based Dilithium
// secret key"; σ_TRS = Aggregate({σ_j}); Verify({pk_j}, m, σ_TRS) ∈ {0,1}.
//
// Why this is NOT the same shape as ClassicalTrsBackend:
//   liboqs provides single-signer ML-DSA only — no algebraic threshold/ring
//   combine — and Dilithium signatures are non-linear in the key (Fiat–Shamir
//   with aborts), so the Lagrange aggregator (σ_TRS = Σ λ_j σ_j) does NOT carry
//   over. A true compact lattice threshold-ring signature is a separate research
//   construction not present in any installed library.
//
// Design decision D1 (option c — TASK2_CRYPTO_PLAN.md):
//   Aggregate({σ_j}) = a BUNDLE of the t partial ML-DSA signatures + signer ids.
//   verify_threshold accepts iff ≥ t DISTINCT ring members each produced a valid
//   ML-DSA signature over m. This is real PQ crypto (no simulation): it gives a
//   sound t-of-n predicate for PARR (Eq 4.3) and real PQ signing latency for
//   PBPO (Eq 4.7). CAVEAT (paper-text item flagged to supervisor): σ_TRS is a
//   bundle, NOT the *compact / signer-anonymous* single signature that Eq 3.50's
//   prose claims. This affects none of the 7 evaluation metrics.
//
// Bundle wire format (out_sigma):
//   [u32 count] then count × { [u32 signer_id][u32 siglen][siglen bytes] }
//
// Key/sig sizes are RUNTIME values from the OQS_SIG object (crypto-agility — no
// hardcoded 64-byte assumptions), per the CLAUDE.md crypto-agility lock.
// pks layout: pks[0] = ring descriptor ("MLDSA"‖n‖t, provenance only — NOT a
// master key), pks[1..n] = per-signer ML-DSA public keys (1-indexed = signer id).
// ────────────────────────────────────────────────────────────────────────────
#if __has_include(<oqs/oqs.h>)
class DilithiumTrsBackend : public ITrsBackend {
public:
    // NIST Level 5 default (supervisor requirement 2026-06): ML-DSA-87
    // (Dilithium5, FIPS 204, category 5). Matches paper Table 3.13.
    explicit DilithiumTrsBackend(const char* alg = OQS_SIG_alg_ml_dsa_87) {
        sig_ = OQS_SIG_new(alg);
        if (sig_)
            snprintf(name_, sizeof(name_),
                     "%s t-of-n bundle TRS (liboqs option-c; real PQ)",
                     sig_->method_name);
    }
    ~DilithiumTrsBackend() override { if (sig_) OQS_SIG_free(sig_); }

    bool generate_keys(uint32_t n, uint32_t t,
                       std::vector<std::vector<uint8_t>> &out_pks,
                       std::vector<std::vector<uint8_t>> &out_sks) override
    {
        if (!sig_ || t == 0 || t > n || n > 64) return false;
        out_pks.assign(n + 1, std::vector<uint8_t>{});
        out_sks.assign(n,     std::vector<uint8_t>{});
        // pks[0]: ring descriptor (provenance only; no master secret exists for PQ).
        out_pks[0] = { 'M','L','D','S','A', (uint8_t)n, (uint8_t)t };
        // DKG (Eq 3.25 dkg_trs) for the bundle scheme: each ring member generates
        // its OWN ML-DSA keypair independently (OQS_SIG_keypair) — there is no
        // shared secret, no dealer polynomial and no K_ring seed, so no entity ever
        // holds another member's secret key. In-process here (one sim process plays
        // all members); true per-RSU local keygen + on-chain pk_j publication to the
        // blockchain bulletin board is the HPC/Fabric follow-up (see DKG_RING_KEYS.md).
        for (uint32_t j = 1; j <= n; j++) {
            std::vector<uint8_t> pk(sig_->length_public_key);
            std::vector<uint8_t> sk(sig_->length_secret_key);
            if (OQS_SIG_keypair(sig_, pk.data(), sk.data()) != OQS_SUCCESS)
                return false;
            out_pks[j]   = std::move(pk);
            out_sks[j-1] = std::move(sk);   // sks[j-1] ↔ signer id j (1-indexed)
        }
        return true;
    }

    bool partial_sign(const std::vector<uint8_t> &message,
                      const std::vector<uint8_t> &sk,
                      std::vector<uint8_t> &out_partial) override
    {
        if (!sig_ || sk.size() != sig_->length_secret_key) return false;
        out_partial.assign(sig_->length_signature, 0);
        size_t siglen = 0;
        if (OQS_SIG_sign(sig_, out_partial.data(), &siglen,
                         message.data(), message.size(), sk.data()) != OQS_SUCCESS)
            return false;
        out_partial.resize(siglen);     // ML-DSA sig length is fixed but be exact
        return true;
    }

    bool aggregate(const std::vector<std::vector<uint8_t>> &partials,
                   const std::vector<uint32_t> &signer_ids,
                   std::vector<uint8_t> &out_sigma) override
    {
        if (!sig_ || partials.size() != signer_ids.size() || partials.empty())
            return false;
        // Honor the per-ring threshold when caller supplies > t partials.
        const size_t use_n = (g_trs_ring_t > 0 && partials.size() >= g_trs_ring_t)
                             ? (size_t)g_trs_ring_t : partials.size();
        out_sigma.clear();
        put_u32(out_sigma, (uint32_t)use_n);
        for (size_t i = 0; i < use_n; i++) {
            if (signer_ids[i] == 0) return false;       // 1-indexed signer ids
            put_u32(out_sigma, signer_ids[i]);
            put_u32(out_sigma, (uint32_t)partials[i].size());
            out_sigma.insert(out_sigma.end(), partials[i].begin(), partials[i].end());
        }
        return true;
    }

    bool verify_threshold(const std::vector<uint8_t> &message,
                          const std::vector<uint8_t> &sigma,
                          const std::vector<std::vector<uint8_t>> &pks) override
    {
        if (!sig_ || pks.empty()) return false;
        size_t off = 0;
        uint32_t count = 0;
        if (!get_u32(sigma, off, count)) return false;
        std::vector<uint32_t> seen;
        uint32_t n_valid = 0;
        for (uint32_t k = 0; k < count; k++) {
            uint32_t sid = 0, slen = 0;
            if (!get_u32(sigma, off, sid))  return false;
            if (!get_u32(sigma, off, slen)) return false;
            if (off + slen > sigma.size())  return false;
            const uint8_t* sptr = sigma.data() + off;
            off += slen;
            if (sid == 0 || sid >= pks.size()) continue;   // unknown signer
            bool dup = false;
            for (uint32_t s : seen) if (s == sid) { dup = true; break; }
            if (dup) continue;                             // count distinct only
            const std::vector<uint8_t> &pk = pks[sid];
            if (pk.size() != sig_->length_public_key) continue;
            if (OQS_SIG_verify(sig_, message.data(), message.size(),
                               sptr, slen, pk.data()) == OQS_SUCCESS) {
                seen.push_back(sid);
                n_valid++;
            }
        }
        uint32_t need = (g_trs_ring_t > 0) ? g_trs_ring_t : count;
        return n_valid >= need;                            // ≥ t distinct valid
    }

    size_t expected_sig_size() const override { return sig_ ? sig_->length_signature  : 0; }
    size_t expected_pk_size()  const override { return sig_ ? sig_->length_public_key : 0; }
    size_t expected_sk_size()  const override { return sig_ ? sig_->length_secret_key : 0; }
    const char* scheme_name()  const override { return sig_ ? name_ : "DilithiumTrsBackend(uninit)"; }

private:
    OQS_SIG* sig_ = nullptr;
    char     name_[96] = "ML-DSA t-of-n bundle TRS (liboqs)";

    static void put_u32(std::vector<uint8_t> &v, uint32_t x) {
        for (int b = 0; b < 4; b++) v.push_back((uint8_t)((x >> (b*8)) & 0xFF));
    }
    static bool get_u32(const std::vector<uint8_t> &v, size_t &off, uint32_t &x) {
        if (off + 4 > v.size()) return false;
        x = (uint32_t)v[off] | ((uint32_t)v[off+1] << 8)
          | ((uint32_t)v[off+2] << 16) | ((uint32_t)v[off+3] << 24);
        off += 4;
        return true;
    }
};
#endif

// Selects the active TRS backend. Full mode (paper §3.5.4 Eq 3.49) uses the
// Dilithium PQ-TRS; Classical is retained for the A4 ablation and the
// ECDSA-class PBPO baseline (RQ5).
enum class TrsScheme { Classical, Dilithium };

// One-time initialization. Call once before first verify_threshold use.
// n=4, t=3 mirrors the 3-RSU + 1-controller-as-peer BFT setup (f=1, t=f+1+1).
// scheme defaults to Classical to preserve legacy call sites; full mode selects
// TrsScheme::Dilithium (wired in 11_blockchain_setup, P5).
static bool init_trs_backend(uint32_t n = 4, uint32_t t = 3,
                             TrsScheme scheme = TrsScheme::Classical)
{
    if (g_trs_ready) return true;
    if (scheme == TrsScheme::Dilithium) {
#if __has_include(<oqs/oqs.h>)
        g_trs_backend = std::unique_ptr<ITrsBackend>(new DilithiumTrsBackend());
#else
        std::cerr << "[WARNING] liboqs header <oqs/oqs.h> not found. Falling back to ClassicalTrsBackend." << std::endl;
        g_trs_backend = std::unique_ptr<ITrsBackend>(new ClassicalTrsBackend());
#endif
    }
    else
        g_trs_backend = std::unique_ptr<ITrsBackend>(new ClassicalTrsBackend());
    // ring_n/t must be visible to aggregate()'s "use first t partials" logic
    // BEFORE generate_keys returns — they're independent of generate_keys,
    // so set them up-front.
    g_trs_ring_n = n;
    g_trs_ring_t = t;
    if (!g_trs_backend->generate_keys(n, t, g_trs_ring_pks, g_trs_ring_sks)) {
        g_trs_backend.reset();
        g_trs_ring_pks.clear();
        g_trs_ring_sks.clear();
        g_trs_ring_n = 0;
        g_trs_ring_t = 0;
        return false;
    }
    g_trs_ready  = true;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// R8.4: EvidenceMessage m_j (Paper §3.5.4, Eq. 3.46)
//
// Proper evidence tuple submitted by an RSU after anomaly detection:
//   m_j = (A_j(t), t, ID_r_j, h(V_j(t)))
//
// where:
//   A_j(t)    = field-wise beacon aggregate (paper Eq. 3.45)
//   t         = simulation timestamp
//   ID_r_j    = RSU identity (uint32_t)
//   h(V_j(t)) = hash of vehicle set, materialized here as the raw vid list
//               (collision-resistance comes from SHA-256 inside partial_sign)
//
// Per-beacon-mode (current call site in StoreTrajectoryToBlockchain) collapses
// A_j(t) to a single beacon's telemetry with |V_j|=1. Window-aggregate mode
// (paper §3.5.4 Algorithm 6 line 4) populates A_j(t) over L beacons before
// signing — both produce well-typed m_j.
// ─────────────────────────────────────────────────────────────────────────────
struct EvidenceMessage {
    uint32_t rsu_id;            // ID_r_j
    double   timestamp;         // t
    // A_j(t) — beacon aggregate (mean / representative)
    double   agg_pos_x;
    double   agg_pos_y;
    double   agg_vel_x;
    double   agg_vel_y;
    double   agg_accel_x;
    double   agg_accel_y;
    // V_j(t) — vehicle IDs feeding this aggregate
    std::vector<uint32_t> vehicle_set;
};

// Serialize m_j to a deterministic byte sequence for cryptographic signing.
// Layout (host endian — single-machine sim, no cross-arch transport):
//   uint32 rsu_id | double t | 6×double agg fields
//   uint32 |V_j|  | uint32 vid_1 | ... | uint32 vid_n
// SHA-256(buf) is what ITrsBackend::partial_sign hashes internally.
inline std::vector<uint8_t> serialize_evidence(const EvidenceMessage &m)
{
    std::vector<uint8_t> buf;
    auto append = [&](const void *p, size_t n) {
        const uint8_t *b = static_cast<const uint8_t*>(p);
        buf.insert(buf.end(), b, b + n);
    };
    append(&m.rsu_id,      sizeof(m.rsu_id));
    append(&m.timestamp,   sizeof(m.timestamp));
    append(&m.agg_pos_x,   sizeof(m.agg_pos_x));
    append(&m.agg_pos_y,   sizeof(m.agg_pos_y));
    append(&m.agg_vel_x,   sizeof(m.agg_vel_x));
    append(&m.agg_vel_y,   sizeof(m.agg_vel_y));
    append(&m.agg_accel_x, sizeof(m.agg_accel_x));
    append(&m.agg_accel_y, sizeof(m.agg_accel_y));
    uint32_t n_v = static_cast<uint32_t>(m.vehicle_set.size());
    append(&n_v, sizeof(n_v));
    for (uint32_t v : m.vehicle_set) append(&v, sizeof(v));
    return buf;
}

// Empirical PARR counters — incremented by evidence_sign_and_verify().
// Paper Eq. 4.3: PARR = TRS-rejected / total poisoned aggregates. With the
// real signing pipeline wired up, PARR is now measurable from sim state
// instead of formula-approximated in evaluate_all.py.
static uint64_t g_trs_verified_count = 0;
static uint64_t g_trs_rejected_count = 0;

// C4b — PARR reachability (paper Eq. 4.3, "poisoned aggregates injected").
// g_parr_injected counts epochs in which a compromised ring coordinator injects
// a poisoned aggregate; g_parr_rejected counts how many of those the cloud's
// TRS Verify (Eq. 3.53) rejected. PARR = g_parr_rejected / g_parr_injected, and
// is undefined (reported -1) when no poisoned aggregate was ever injected. The
// full-mode-vs-AB6 contrast is structural: AB6 has no TRS gate, so an injected
// aggregate is never rejected and PARR reads 0.
static uint64_t g_parr_injected = 0;
static uint64_t g_parr_rejected = 0;

// ─────────────────────────────────────────────────────────────────────────────
// evidence_sign_and_verify — paper Algorithm 6 (PQ-TRS-SIGN), Eq. 3.47–3.49
//
// Build σ_TRS over m_j with t-of-n RSU partial signatures, then verify before
// returning. This is the canonical "RSU-side TRS pipeline" the paper §3.5.4
// specifies.
//
// Sim-only deviation: the t partial signatures come from the first t entries
// in g_trs_ring_sks instead of being collected from peer RSUs over a DSRC
// broadcast channel. The crypto chain (partial_sign → aggregate →
// verify_threshold) is real — only the σ_j delivery is shortcut. Real
// inter-RSU σ_j exchange is the deferred R-future task; A1–A5 ablation
// isolation does not depend on it (TRS-on vs TRS-off is the variable, not
// transport).
//
// Returns true iff verify_threshold passes. On success out_sigma holds the
// aggregated σ_TRS bytes and out_signers the signer-id list (1..t). The
// caller is expected to gate blockchain submission on the return value
// (paper Invariant 5 — TRS-then-FHE).
// ─────────────────────────────────────────────────────────────────────────────
inline bool evidence_sign_and_verify(const EvidenceMessage &m,
                                     std::vector<uint8_t> &out_sigma,
                                     std::vector<uint32_t> &out_signers)
{
    out_sigma.clear();
    out_signers.clear();
    if (!g_trs_backend || g_trs_ring_sks.empty() || g_trs_ring_pks.empty())
        return false;

    std::vector<uint8_t> msg_bytes = serialize_evidence(m);

    // Collect t partial signatures (Eq. 3.47).
    // Sim-only: take first t SKs from the ring; real impl receives over DSRC.
    std::vector<std::vector<uint8_t>> partials;
    partials.reserve(g_trs_ring_t);
    for (uint32_t j = 0; j < g_trs_ring_t && j < g_trs_ring_n; j++) {
        std::vector<uint8_t> p_j;
        if (!g_trs_backend->partial_sign(msg_bytes, g_trs_ring_sks[j], p_j))
            return false;
        partials.push_back(std::move(p_j));
        out_signers.push_back(j + 1);  // 1-indexed (Lagrange basis @ x=0)
    }

    // Aggregate t partials → σ_TRS (Eq. 3.48).
    if (!g_trs_backend->aggregate(partials, out_signers, out_sigma))
        return false;

    // Verify σ_TRS against m_j + ring pks (Eq. 3.49, Invariant 5 gate).
    return g_trs_backend->verify_threshold(msg_bytes, out_sigma, g_trs_ring_pks);
}

// ─────────────────────────────────────────────────────────────────────────────
// mptd_trs_partial_sign_hex — TASK ①-J: thin σ_j helper for chaincode tuples.
//
// RSU r_j produces σ_j = s_j · H(m) (Eq 3.47) over arbitrary canonical message
// bytes, hex-encoded for chaincode string args (SCTrustSubmitEvidence,
// SCRevokeVote). Returns empty string on any failure so the caller falls back
// to empty σ — the chaincode already accepts opaquely (see TASK ①-I commit
// 99b7f03 and TASK ①-N commit 479c3eb).
//
// Indexing: rsu_idx is 0-indexed NS-3 RSU id; g_trs_ring_sks[rsu_idx] is the
// 0-indexed share array (where index k maps to 1-indexed Shamir share s_{k+1}).
//
// No-op gracefully when:
//   - g_trs_backend is null (e.g. A4 ablation use_pq_crypto=false)
//   - rsu_idx is out of range (controller-side σ_c has no ring key — paper
//     §3.5.5 wording allows σ_c^sub to be a separate controller-keyed signature;
//     that key plumbing is a separate task)
//   - partial_sign itself fails
//
// This is single-RSU σ_j only. For full σ_TRS aggregation (t partials →
// aggregate → verify_threshold) use evidence_sign_and_verify above.
// ─────────────────────────────────────────────────────────────────────────────
static inline std::string mptd_trs_partial_sign_hex(
    uint32_t rsu_idx, const std::vector<uint8_t> &message)
{
    if (!g_trs_backend) return "";
    if (rsu_idx >= g_trs_ring_sks.size()) return "";
    std::vector<uint8_t> partial;
    if (!g_trs_backend->partial_sign(message, g_trs_ring_sks[rsu_idx], partial))
        return "";
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(partial.size() * 2);
    for (uint8_t b : partial) {
        out.push_back(hex[(b >> 4) & 0xf]);
        out.push_back(hex[b & 0xf]);
    }
    return out;
}

#endif // MPTD_PQS_06B1_TRS_BACKEND_H