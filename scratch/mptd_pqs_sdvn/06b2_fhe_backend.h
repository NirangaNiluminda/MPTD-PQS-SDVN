// ============================================================
// 06b2_fhe_backend.h — Fully Homomorphic Encryption backend (real OpenFHE BFV)
// MPTD-PQS SDVN, R6.5-C-4 + R6.5-C-7 (merged: OpenFHE built early)
// ============================================================
// Paper §3.5.4 (Eq 3.52–3.54) + cite [13] Al Mamun et al. 2025.
//
// Crypto Scheme Lock (CLAUDE.md, May 2026):
//   FHE scheme = BFV (NOT CKKS). Per [13] empirical eval, BFV achieves sub-5s
//   latency on intersection-level analytics, matching MPTD-PQS Full-mode
//   window W = L·T_b. CKKS at 21–32s is too slow. Mobility data is
//   integer-quantized (×100 for speeds in cm·s⁻¹, ×1000 for positions in mm)
//   before BFV encryption.
//
// R6.5 scope:
//   - BfvBackend concrete class on OpenFHE 1.5.1 (CryptoContextBFVRNS)
//   - Single-output (sum and average) homomorphic aggregate over vehicle
//     telemetry submitted by RSUs to Cloud/ITS Server (paper Fig 3.13)
//   - Integer quantization helpers (encrypt_speed_mps / decrypt_to_speed_mps)
//   - Global g_fhe_backend pointer (lazy init at first use)
//
// R9 wires this into the Cloud node ingest path:
//   1. RSU j collects vehicle speeds in current window W = L·T_b
//   2. TRS-verify gate (§3.5.4 Eq 3.51) gates aggregation — invariant 5
//   3. Speeds × 100 → int64_t, BFV-encrypt per vehicle
//   4. Cloud receives ciphertexts, homomorphic-sum, divide-by-N at decrypt
//   5. Decrypt → reconstruct average speed for downstream analytics
//
// Linker: requires -lOPENFHEpke -lOPENFHEcore -fopenmp
//         + -Wl,-rpath,$HOME/.local/lib for runtime resolution.
//
// Include order: AFTER 06b1_trs_backend.h, BEFORE 06c_blockchain_api.h.
// ============================================================

#ifndef MPTD_PQS_06B2_FHE_BACKEND_H
#define MPTD_PQS_06B2_FHE_BACKEND_H

#include <vector>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <set>
#include <string>
#include <unordered_map>

// OpenFHE master header. Pulls in DCRTPoly, CryptoContext, KeyPair, etc.
// All under namespace lbcrypto.
#include "openfhe.h"

// Serialization headers — needed to bind Enc(A_ring) into the TRS message
// (paper Eq 3.48). We serialize a ciphertext to deterministic BINARY bytes that
// the PQ-TRS hashes/signs; the bytes are never deserialized here (sign-only), so
// only the ciphertext + bfvrns scheme registrations are required.
#include "ciphertext-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include <sstream>

// ────────────────────────────────────────────────────────────────────────────
// BfvBackend — concrete OpenFHE BFV-RNS backend for MPTD-PQS Full-mode FHE.
//
// Single-context model: one CryptoContext + one KeyPair for the whole sim.
// Plaintext modulus 65537 (Fermat prime, widely tested for BFV packing).
// Multiplicative depth 1 (we only do EvalAdd for averaging; no multiplies).
// Stays well inside [13]'s 5-second latency envelope.
//
// Thread-safety: OpenFHE's CryptoContext is safe for concurrent encrypt /
// decrypt under the same KeyPair. NS-3 simulator is single-threaded so this
// is a non-issue at the sim layer.
// ────────────────────────────────────────────────────────────────────────────
class BfvBackend {
public:
    using Ctx        = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;
    using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
    using KeyPair    = lbcrypto::KeyPair<lbcrypto::DCRTPoly>;
    using Plaintext  = lbcrypto::Plaintext;

    // Quantization factors. Speeds are reported in m/s (double); positions in m.
    // Multiply by these constants to convert to integer plaintext for BFV.
    static constexpr int64_t SPEED_SCALE = 100;    // m/s → cm/s
    static constexpr int64_t POS_SCALE   = 1000;   // m   → mm

    // One-time setup. Returns false on failure.
    bool init(uint32_t plaintext_modulus = 65537,
              uint32_t mult_depth        = 1)
    {
        try {
            lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> params;
            params.SetPlaintextModulus(plaintext_modulus);
            params.SetMultiplicativeDepth(mult_depth);
            // NIST Level 5 (supervisor requirement 2026-06): 256-bit
            // post-quantum security, consistent with the threshold backend.
            params.SetSecurityLevel(lbcrypto::HEStd_256_quantum);

            ctx_ = lbcrypto::GenCryptoContext(params);
            ctx_->Enable(lbcrypto::PKE);
            ctx_->Enable(lbcrypto::KEYSWITCH);
            ctx_->Enable(lbcrypto::LEVELEDSHE);

            keys_ = ctx_->KeyGen();
            // Relinearization key for EvalMult (not strictly needed for sum-only,
            // but cheap and lets R9 do scalar-mult prep without re-keying).
            ctx_->EvalMultKeyGen(keys_.secretKey);

            ring_dim_ = ctx_->GetRingDimension();
            pt_mod_   = plaintext_modulus;
            ready_    = true;
            return true;
        }
        catch (const std::exception &e) {
            last_error_ = e.what();
            ready_      = false;
            return false;
        }
    }

    // Encrypt a single integer scalar. Packs into slot 0 of a length-1 vector
    // (BFV is SIMD-packed; we only use slot 0 for scalar aggregation).
    Ciphertext encrypt_scalar_int(int64_t value) const
    {
        require_ready();
        std::vector<int64_t> vec{value};
        Plaintext pt = ctx_->MakePackedPlaintext(vec);
        return ctx_->Encrypt(keys_.publicKey, pt);
    }

    // Encrypt a vector of integers (one ciphertext, packed slots).
    Ciphertext encrypt_vector_int(const std::vector<int64_t> &values) const
    {
        require_ready();
        Plaintext pt = ctx_->MakePackedPlaintext(values);
        return ctx_->Encrypt(keys_.publicKey, pt);
    }

    // Homomorphic add — returns Enc(a + b).
    Ciphertext add(const Ciphertext &a, const Ciphertext &b) const
    {
        require_ready();
        return ctx_->EvalAdd(a, b);
    }

    // Homomorphic add-many — returns Enc(sum(cts)). Empty input → throws.
    Ciphertext add_many(const std::vector<Ciphertext> &cts) const
    {
        require_ready();
        if (cts.empty())
            throw std::runtime_error("BfvBackend::add_many on empty list");
        if (cts.size() == 1) return cts[0];
        Ciphertext acc = cts[0];
        for (size_t i = 1; i < cts.size(); i++) {
            acc = ctx_->EvalAdd(acc, cts[i]);
        }
        return acc;
    }

    // Decrypt to scalar (slot 0).
    int64_t decrypt_to_int(const Ciphertext &ct) const
    {
        require_ready();
        Plaintext pt;
        ctx_->Decrypt(keys_.secretKey, ct, &pt);
        pt->SetLength(1);
        const auto &vec = pt->GetPackedValue();
        return vec.empty() ? 0 : vec[0];
    }

    // Decrypt and return up to `length` slots.
    std::vector<int64_t> decrypt_to_vector(const Ciphertext &ct, size_t length) const
    {
        require_ready();
        Plaintext pt;
        ctx_->Decrypt(keys_.secretKey, ct, &pt);
        pt->SetLength(length);
        return pt->GetPackedValue();
    }

    // ── Convenience: quantized speed (m/s) ↔ ciphertext ────────────────────
    // Encrypt speed in m/s: value × 100 → cm/s integer → BFV.
    Ciphertext encrypt_speed_mps(double speed_mps) const
    {
        int64_t q = static_cast<int64_t>(speed_mps * (double)SPEED_SCALE);
        return encrypt_scalar_int(q);
    }
    // Decrypt and reconstruct mean speed in m/s: sum / n / 100.
    double decrypt_mean_speed_mps(const Ciphertext &ct_sum, size_t n) const
    {
        if (n == 0) return 0.0;
        int64_t s = decrypt_to_int(ct_sum);
        return ((double)s) / ((double)SPEED_SCALE * (double)n);
    }

    // ── Convenience: quantized position (m) ↔ ciphertext ───────────────────
    Ciphertext encrypt_pos_m(double pos_m) const
    {
        int64_t q = static_cast<int64_t>(pos_m * (double)POS_SCALE);
        return encrypt_scalar_int(q);
    }
    double decrypt_mean_pos_m(const Ciphertext &ct_sum, size_t n) const
    {
        if (n == 0) return 0.0;
        int64_t s = decrypt_to_int(ct_sum);
        return ((double)s) / ((double)POS_SCALE * (double)n);
    }

    // Diagnostics.
    bool        ready()        const { return ready_;       }
    uint32_t    ring_dim()     const { return ring_dim_;    }
    uint32_t    plaintext_modulus() const { return pt_mod_; }
    const char* scheme_name()  const { return "OpenFHE BFV-RNS (HEStd_256_quantum NIST L5, mult_depth=1)"; }
    const std::string& last_error() const { return last_error_; }

private:
    void require_ready() const {
        if (!ready_)
            throw std::runtime_error("BfvBackend: init() not called or failed");
    }

    Ctx         ctx_;
    KeyPair     keys_;
    uint32_t    ring_dim_   = 0;
    uint32_t    pt_mod_     = 0;
    bool        ready_      = false;
    std::string last_error_;
};

// ────────────────────────────────────────────────────────────────────────────
// Global FHE state. Initialized in 11_blockchain_setup.h at sim start.
// Lazy init: caller can also do init_fhe_backend() explicitly to surface any
// failure early rather than at first encrypt.
// ────────────────────────────────────────────────────────────────────────────
static std::unique_ptr<BfvBackend> g_fhe_backend;

static bool init_fhe_backend(uint32_t plaintext_modulus = 65537,
                             uint32_t mult_depth        = 1)
{
    if (g_fhe_backend && g_fhe_backend->ready()) return true;
    g_fhe_backend = std::unique_ptr<BfvBackend>(new BfvBackend());
    return g_fhe_backend->init(plaintext_modulus, mult_depth);
}

// ════════════════════════════════════════════════════════════════════════════
// ThresholdBfvBackend — (t, n+1) threshold FHE via OpenFHE multiparty BFV.
// MPTD-PQS SDVN, TASK ② (2026-06 redesign). Paper §3.5.4 Eq 3.46–3.47, 3.52–3.56.
//
// Implements the supervisor's redesign: the FHE secret key is split across
// n RSUs + the Cloud under a (t, n+1) threshold scheme so NO single entity —
// including the Cloud (control-plane threat boundary) — can decrypt unilaterally.
//
// Party indexing: 0..n-1 = RSU ring members, n = Cloud (the mandatory LEAD party
// at decryption, Eq 3.53). Decryption coalition D must include the Cloud plus
// ≥ t-1 RSUs (Eq 3.55–3.56); absent RSUs' secret keys are reconstructed from ≥ t
// Shamir shares (OpenFHE "Threshold FHE with aborts, HEStd_256_quantum (NIST L5)", Eq 3.54).
//
// Equation map:
//   Eq 3.54  ThGen(1^λ, n+1, t)  → init(): chained MultipartyKeyGen + ShareKeys
//   Eq 3.46  c_j = Enc(pk_FHE, A_j)         → encrypt_scalar_int / encrypt_speed_mps
//   Eq 3.47  Enc(A_ring) = ⊕ c_j            → add / add_many   (no secret key)
//   Eq 3.52  Enc(X_global) = ⊕ ring aggs    → add / add_many   (cloud, blind)
//   Eq 3.53  pd_cloud = PDec(sk_cloud, ·)   → MultipartyDecryptLead (cloud)
//   Eq 3.55  pd_j     = PDec(sk_j, ·)       → MultipartyDecryptMain  (RSUs)
//   Eq 3.56  X_global = ThDec(pd_cloud,{pd_j}) → MultipartyDecryptFusion
//
// Real crypto only (no simulation): all operations are OpenFHE 1.5.1 multiparty
// BFV with NOISE_FLOODING_MULTIPARTY mode (required for BFV/BGV threshold).
// ════════════════════════════════════════════════════════════════════════════
class ThresholdBfvBackend {
public:
    using Ctx        = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;
    using Ciphertext = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
    using PrivKey    = lbcrypto::PrivateKey<lbcrypto::DCRTPoly>;
    using PubKey     = lbcrypto::PublicKey<lbcrypto::DCRTPoly>;
    using Plaintext  = lbcrypto::Plaintext;
    using Element    = lbcrypto::DCRTPoly;

    static constexpr int64_t SPEED_SCALE = 100;    // m/s → cm/s
    static constexpr int64_t POS_SCALE   = 1000;   // m   → mm

    // Eq 3.54: ThGen(1^λ, n+1, t). n_rsus RSUs + 1 Cloud; threshold t.
    bool init(uint32_t n_rsus, uint32_t threshold,
              uint32_t plaintext_modulus = 65537, uint32_t mult_depth = 1)
    {
        try {
            if (threshold == 0 || threshold > n_rsus + 1) {
                last_error_ = "invalid (t, n+1) threshold parameters";
                return false;
            }
            n_parties_ = n_rsus + 1;
            threshold_ = threshold;
            cloud_idx_ = n_rsus;                  // last party = Cloud = lead

            lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> params;
            params.SetPlaintextModulus(plaintext_modulus);
            params.SetMultiplicativeDepth(mult_depth);
            // BFV/BGV threshold FHE requires noise-flooding multiparty mode, sized
            // to the number of parties (extra modulus headroom for flooding noise).
            params.SetMultipartyMode(lbcrypto::NOISE_FLOODING_MULTIPARTY);
            params.SetThresholdNumOfParties(n_parties_);
            params.SetSecurityLevel(lbcrypto::HEStd_256_quantum);
            // NIST Level 5 (supervisor requirement 2026-06): 256-bit
            // post-quantum security. Paper Table 3.13. OpenFHE auto-selects
            // a ring dimension large enough to meet HEStd_256_quantum.
            params.SetSecurityLevel(lbcrypto::HEStd_256_quantum);

            ctx_ = lbcrypto::GenCryptoContext(params);
            ctx_->Enable(lbcrypto::PKE);
            ctx_->Enable(lbcrypto::KEYSWITCH);
            ctx_->Enable(lbcrypto::LEVELEDSHE);
            ctx_->Enable(lbcrypto::MULTIPARTY);

            // Chained joined-key generation across the n+1 parties (Eq 3.54).
            secret_.resize(n_parties_);
            auto kp0 = ctx_->KeyGen();
            secret_[0] = kp0.secretKey;
            PubKey joined = kp0.publicKey;
            for (uint32_t i = 1; i < n_parties_; i++) {
                auto kp   = ctx_->MultipartyKeyGen(joined);
                secret_[i] = kp.secretKey;
                joined     = kp.publicKey;
            }
            joined_pk_ = joined;                  // pk_FHE used for all encryption

            // "With aborts": each party Shamir-shares its secret key (Eq 3.54), so
            // an absent party's key can be recovered from ≥ t shares. Best-effort:
            // if unsupported the all-present decryption path still works.
            shares_ok_ = true;
            try {
                share_db_.resize(n_parties_);
                for (uint32_t owner = 0; owner < n_parties_; owner++)
                    share_db_[owner] = ctx_->ShareKeys(secret_[owner], n_parties_,
                                                       threshold_, owner + 1, "shamir");
            } catch (const std::exception &e) {
                shares_ok_  = false;
                last_error_ = std::string("ShareKeys: ") + e.what();
            }

            ring_dim_ = ctx_->GetRingDimension();
            ready_    = true;
            return true;
        }
        catch (const std::exception &e) { last_error_ = e.what(); ready_ = false; return false; }
    }

    // ── Encryption under the joined threshold public key (Eq 3.46) ───────────
    Ciphertext encrypt_scalar_int(int64_t v) const {
        std::vector<int64_t> vec{v};
        return ctx_->Encrypt(joined_pk_, ctx_->MakePackedPlaintext(vec));
    }
    Ciphertext encrypt_speed_mps(double s) const {
        return encrypt_scalar_int(static_cast<int64_t>(s * (double)SPEED_SCALE));
    }
    Ciphertext encrypt_pos_m(double p) const {
        return encrypt_scalar_int(static_cast<int64_t>(p * (double)POS_SCALE));
    }
    // Vector form (Eq 3.46): pack a field-wise RSU aggregate A_j into the SIMD
    // slots of one ciphertext. Ring add (Eq 3.47) then combines slot-wise, so a
    // single ciphertext carries the whole aggregate vector through the pipeline.
    Ciphertext encrypt_vector_int(const std::vector<int64_t> &v) const {
        return ctx_->Encrypt(joined_pk_, ctx_->MakePackedPlaintext(v));
    }

    // Deterministic BINARY serialization of Enc(A_ring) for the TRS message
    // m = (Enc(A_ring), t, ID_S, h(S)) (paper Eq 3.48). The PQ-TRS signs these
    // bytes directly — they are never deserialized here, so binding the exact
    // ciphertext into the signed message is all that is required.
    std::vector<uint8_t> serialize_ciphertext(const Ciphertext &ct) const {
        std::ostringstream oss(std::ios::binary);
        lbcrypto::Serial::Serialize(ct, oss, lbcrypto::SerType::BINARY);
        const std::string &s = oss.str();
        return std::vector<uint8_t>(s.begin(), s.end());
    }

    // ── Homomorphic addition — no secret key (Eq 3.47 ring, Eq 3.52 cloud) ───
    Ciphertext add(const Ciphertext &a, const Ciphertext &b) const { return ctx_->EvalAdd(a, b); }
    Ciphertext add_many(const std::vector<Ciphertext> &cts) const {
        if (cts.empty()) throw std::runtime_error("ThresholdBfvBackend::add_many empty");
        Ciphertext acc = cts[0];
        for (size_t i = 1; i < cts.size(); i++) acc = ctx_->EvalAdd(acc, cts[i]);
        return acc;
    }

    // ── Threshold decryption (Eq 3.53 lead / 3.55 main / 3.56 fusion) ────────
    // present_rsus: RSU indices contributing their own partial. Cloud (lead) is
    // mandatory and added automatically. Absent RSUs' keys are recovered from
    // ≥ t shares. Requires |present_rsus ∪ {cloud}| ≥ ... enough to reconstruct.
    bool threshold_decrypt_int(const Ciphertext &ct,
                               const std::vector<uint32_t> &present_rsus,
                               int64_t &out) const
    {
        std::vector<int64_t> v;
        if (!threshold_decrypt_vec(ct, present_rsus, 1, v)) return false;
        out = v.empty() ? 0 : v[0];
        return true;
    }

    // Vector form of threshold decryption (Eq 3.53 lead / 3.55 main / 3.56
    // fusion) — recovers the first `len` packed SIMD slots of Enc(A_ring), the
    // field-wise aggregate vector. Single decryption path shared with the scalar
    // helper above. present_rsus: RSU indices contributing their own partial;
    // Cloud (lead) is added automatically and is mandatory (Eq 3.53). Absent
    // RSUs' keys are recovered from ≥ t Shamir shares (Algorithm 7 "with aborts, HEStd_256_quantum (NIST L5)").
    bool threshold_decrypt_vec(const Ciphertext &ct,
                               const std::vector<uint32_t> &present_rsus,
                               size_t len, std::vector<int64_t> &out) const
    {
        try {
            std::set<uint32_t> present(present_rsus.begin(), present_rsus.end());
            present.insert(cloud_idx_);           // Cloud mandatory (Eq 3.53)

            // Assemble a usable secret key per party: own if present, else recover.
            std::vector<PrivKey> sk(n_parties_);
            for (uint32_t i = 0; i < n_parties_; i++) {
                if (present.count(i)) { sk[i] = secret_[i]; continue; }
                if (!shares_ok_) { last_error_ = "abort path needs ShareKeys"; return false; }
                std::unordered_map<uint32_t, Element> sh;
                for (uint32_t h : present) {
                    auto it = share_db_[i].find(h + 1);
                    if (it != share_db_[i].end()) sh[h + 1] = it->second;
                    if (sh.size() >= threshold_) break;
                }
                if (sh.size() < threshold_) { last_error_ = "insufficient shares to recover"; return false; }
                PrivKey rec = std::make_shared<lbcrypto::PrivateKeyImpl<Element>>(ctx_);
                ctx_->RecoverSharedKey(rec, sh, n_parties_, threshold_, "shamir");
                sk[i] = rec;
            }

            auto partials = ctx_->MultipartyDecryptLead({ct}, sk[cloud_idx_]);   // pd_cloud
            for (uint32_t i = 0; i < n_parties_; i++) {
                if (i == cloud_idx_) continue;
                auto pm = ctx_->MultipartyDecryptMain({ct}, sk[i]);              // pd_j
                partials.push_back(pm[0]);
            }
            Plaintext pt;
            ctx_->MultipartyDecryptFusion(partials, &pt);                        // ThDec
            pt->SetLength(len);
            const auto &v = pt->GetPackedValue();
            out.assign(len, 0);
            for (size_t k = 0; k < len && k < v.size(); k++) out[k] = v[k];
            return true;
        }
        catch (const std::exception &e) { last_error_ = e.what(); return false; }
    }

    // Convenience: mean speed (m/s) from an encrypted sum over nveh vehicles.
    bool threshold_decrypt_mean_speed(const Ciphertext &ct_sum, size_t nveh,
                                      const std::vector<uint32_t> &present,
                                      double &out_mps) const {
        int64_t s = 0;
        if (!threshold_decrypt_int(ct_sum, present, s)) return false;
        out_mps = (nveh == 0) ? 0.0 : (double)s / ((double)SPEED_SCALE * (double)nveh);
        return true;
    }

    PubKey      joined_public_key()  const { return joined_pk_; }
    bool        ready()              const { return ready_;      }
    bool        shares_available()   const { return shares_ok_;  }
    uint32_t    ring_dim()           const { return ring_dim_;   }
    uint32_t    num_parties()        const { return n_parties_;  }
    uint32_t    threshold()          const { return threshold_;  }
    const char* scheme_name()        const { return "OpenFHE BFV-RNS threshold (t,n+1) with aborts, HEStd_256_quantum (NIST L5)"; }
    const std::string& last_error()  const { return last_error_; }

private:
    Ctx        ctx_;
    PubKey     joined_pk_;
    std::vector<PrivKey>                                 secret_;     // per-party sk
    std::vector<std::unordered_map<uint32_t, Element>>   share_db_;   // [owner][holderID]=share
    uint32_t   n_parties_ = 0, threshold_ = 0, cloud_idx_ = 0, ring_dim_ = 0;
    bool       ready_ = false, shares_ok_ = false;
    mutable std::string last_error_;
};

// Global threshold-FHE backend. Initialized in 11_blockchain_setup.h (P5 wiring).
static std::unique_ptr<ThresholdBfvBackend> g_thfhe_backend;

static bool init_threshold_fhe_backend(uint32_t n_rsus = 4, uint32_t threshold = 3,
                                       uint32_t plaintext_modulus = 65537,
                                       uint32_t mult_depth = 1)
{
    if (g_thfhe_backend && g_thfhe_backend->ready()) return true;
    g_thfhe_backend.reset(new ThresholdBfvBackend());
    return g_thfhe_backend->init(n_rsus, threshold, plaintext_modulus, mult_depth);
}

#endif // MPTD_PQS_06B2_FHE_BACKEND_H