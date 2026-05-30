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

// OpenFHE master header. Pulls in DCRTPoly, CryptoContext, KeyPair, etc.
// All under namespace lbcrypto.
#include "openfhe.h"

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
            // Default security: HEStd_128_classic. Default ring dim auto-selected.

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
    const char* scheme_name()  const { return "OpenFHE BFV-RNS (HEStd_128_classic, mult_depth=1)"; }
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

#endif // MPTD_PQS_06B2_FHE_BACKEND_H
