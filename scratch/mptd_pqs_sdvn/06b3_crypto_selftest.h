// ============================================================
// 06b3_crypto_selftest.h — TRS + BFV round-trip self-tests
// MPTD-PQS SDVN, R6.5-C-8
// ============================================================
// Validates that 06b1_trs_backend.h and 06b2_fhe_backend.h work end-to-end
// against real OpenSSL EC and OpenFHE BFV-RNS, not just compile cleanly.
//
// Gated by env var MPTD_CRYPTO_SELFTEST=1 (read at sim start). Off by
// default so production runs aren't slowed by self-tests. When on, prints
// per-test PASS/FAIL plus a one-line summary; never aborts the sim.
//
// Tests (R8 — updated for Shamir-Schnorr-P256 TRS):
//   TRS-1: generate_keys produces n+1 pks (master + n shares) of right size
//   TRS-2: partial_sign → aggregate (t-of-n Lagrange) → verify_threshold = PASS
//   TRS-2e: alternate signer subset {1,2,4} (skipping 3) ALSO verifies
//   TRS-2f: sub-threshold (only 1 partial when t=3) → aggregate produces σ
//           but verify_threshold REJECTS (no a_0 recovery from < t shares)
//   TRS-3: tampered message → verify_threshold = REJECT
//   TRS-4: wrong-ring pks (different n → different K_ring-seeded poly) → REJECT
//   FHE-1: encrypt single int → decrypt = same int (single-key BFV)
//   FHE-2: Σ EvalAdd(Enc(x_i)) → Decrypt = Σ x_i
//   FHE-3: encrypt_speed_mps round-trip with ×100 quantization
//
// Threshold-FHE + full ciphertext-signing pipeline (paper §3.5.4 Alg 6/7):
//   THFHE-1: packed-vector encrypt → threshold (cloud + t−1 RSU) decrypt round-trip
//            (exercises the Shamir "with aborts" key-recovery path, Algorithm 7)
//   THFHE-2: ring homomorphic ⊕ of 3 packed aggregates → decrypt = slot-wise sums (Eq 3.47)
//   THFHE-3: serialize_ciphertext non-empty + deterministic (binds Enc(A_ring), Eq 3.48)
//   PIPE-1:  TRS signs the SERIALIZED CIPHERTEXT (not plaintext) → verify accepts (Eq 3.48-3.51)
//   PIPE-2:  tampered ciphertext message rejected by TRS
//
// NOTE: with the Jun-2026 redesign the active g_trs_backend defaults to PQ
// Dilithium and the live FHE path uses g_thfhe_backend (threshold). Single-key
// g_fhe_backend remains only for the FHE-1..4 legacy checks above.
// ============================================================

#ifndef MPTD_PQS_06B3_CRYPTO_SELFTEST_H
#define MPTD_PQS_06B3_CRYPTO_SELFTEST_H

#include <cstdlib>
#include <iostream>
#include <vector>
#include <cstdint>
#include <cmath>

static bool crypto_selftest_enabled()
{
    const char *v = std::getenv("MPTD_CRYPTO_SELFTEST");
    return v && v[0] == '1';
}

static void crypto_selftest_run()
{
    if (!crypto_selftest_enabled()) return;

    std::cout << "\n[CRYPTO/SELFTEST] starting — set MPTD_CRYPTO_SELFTEST=0 to disable\n";
    int passed = 0, failed = 0;
    auto step = [&](const char* name, bool ok) {
        std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << name << "\n";
        if (ok) passed++; else failed++;
    };

    // ── TRS tests (R8 — Shamir-Schnorr-P256 t-of-n) ───────────────────────
    if (g_trs_backend && !g_trs_ring_pks.empty()) {
        // TRS-1: expect n+1 pks (master_pk at [0], n share-points at [1..n])
        //        and n sks (one per Shamir share, 1-indexed).
        step("TRS-1a: pk table size == n+1",
             g_trs_ring_pks.size() == (size_t)g_trs_ring_n + 1);
        step("TRS-1b: sk table size == n",
             g_trs_ring_sks.size() == (size_t)g_trs_ring_n);
        // pks[1] is a real per-signer public key in BOTH backends (classical
        // s_j·G, or a Dilithium ML-DSA public key), so it always matches
        // expected_pk_size(). pks[0] differs by scheme (classical master_pk vs
        // Dilithium ring descriptor), so it is not size-checked here.
        step("TRS-1c: signer pk size matches scheme",
             g_trs_ring_pks[1].size() == g_trs_backend->expected_pk_size());
        step("TRS-1d: share sk size matches scheme",
             g_trs_ring_sks[0].size() == g_trs_backend->expected_sk_size());

        const std::string msg_text = "MPTD-PQS R8 self-test message v1";
        std::vector<uint8_t> msg(msg_text.begin(), msg_text.end());

        // TRS-2: t-of-n round-trip with signers {1, 2, 3} (indices 0,1,2 in sks).
        auto sign_subset = [&](const std::vector<uint32_t> &ids,
                               std::vector<uint8_t> &sigma_out) -> bool {
            std::vector<std::vector<uint8_t>> partials;
            for (uint32_t id : ids) {
                if (id == 0 || id > g_trs_ring_n) return false;
                std::vector<uint8_t> p;
                if (!g_trs_backend->partial_sign(msg, g_trs_ring_sks[id - 1], p))
                    return false;
                if (p.size() != g_trs_backend->expected_sig_size()) return false;
                partials.push_back(std::move(p));
            }
            return g_trs_backend->aggregate(partials, ids, sigma_out);
        };

        std::vector<uint8_t> sigma_123;
        bool sign_ok_123 = sign_subset({1, 2, 3}, sigma_123);
        // Scheme-agnostic size check: classical aggregate == one scalar sig;
        // Dilithium bundle (D1) carries t partial sigs so it is >= one sig.
        step("TRS-2a: partial_sign × 3 + aggregate produced σ_TRS (signers 1,2,3)",
             sign_ok_123 && sigma_123.size() >= g_trs_backend->expected_sig_size());

        bool verify_ok_123 = sign_ok_123 &&
            g_trs_backend->verify_threshold(msg, sigma_123, g_trs_ring_pks);
        step("TRS-2c: verify_threshold accepts σ_TRS from {1,2,3}", verify_ok_123);

        // TRS-2e: alternate t-subset {1,2,4} — Lagrange coefficients differ,
        // but reconstructed poly(0) is the same a_0, so verify must accept.
        std::vector<uint8_t> sigma_124;
        bool sign_ok_124 = (g_trs_ring_n >= 4) && sign_subset({1, 2, 4}, sigma_124);
        bool verify_ok_124 = sign_ok_124 &&
            g_trs_backend->verify_threshold(msg, sigma_124, g_trs_ring_pks);
        step("TRS-2e: alternate signer subset {1,2,4} also verifies",
             verify_ok_124);

        // TRS-2f: sub-threshold — only 1 partial when t=3. aggregate() will
        // refuse to "use first 3" because it requires partials.size() >= t,
        // and falls back to use_n = partials.size() = 1. The resulting σ
        // is just λ_1(0)·σ_1 (with empty signer set → λ_1=1), which is
        // σ_1 = s_1·h. Verify must REJECT because σ·G = s_1·h·G ≠ h·a_0·G.
        std::vector<uint8_t> sigma_1only;
        std::vector<std::vector<uint8_t>> p_one(1);
        bool one_sign_ok = g_trs_backend->partial_sign(msg,
                                                       g_trs_ring_sks[0],
                                                       p_one[0]);
        std::vector<uint32_t> ids_one{1};
        bool one_agg_ok = one_sign_ok &&
            g_trs_backend->aggregate(p_one, ids_one, sigma_1only);
        bool sub_threshold_rejected = one_agg_ok &&
            !g_trs_backend->verify_threshold(msg, sigma_1only, g_trs_ring_pks);
        step("TRS-2f: sub-threshold σ (1 of t=3 partials) rejected",
             sub_threshold_rejected);

        // TRS-3: tamper message → reject genuine σ
        std::vector<uint8_t> msg_tamper = msg;
        msg_tamper[0] ^= 0x01;
        bool tamper_rejected = verify_ok_123 &&
            !g_trs_backend->verify_threshold(msg_tamper, sigma_123,
                                             g_trs_ring_pks);
        step("TRS-3: tampered message rejected", tamper_rejected);

        // TRS-4: wrong ring. Using a different ring size (n+1 instead of n)
        // changes the seed (since seed includes n and t), so the resulting
        // master_pk is different from the global ring's. σ from global ring
        // must not verify against wrong ring's pks.
        ClassicalTrsBackend tmp;
        std::vector<std::vector<uint8_t>> wrong_pks, wrong_sks;
        bool wrong_ring_ok = tmp.generate_keys(g_trs_ring_n + 1,
                                               g_trs_ring_t,
                                               wrong_pks, wrong_sks);
        bool wrong_ring_rejected = wrong_ring_ok && verify_ok_123 &&
            !g_trs_backend->verify_threshold(msg, sigma_123, wrong_pks);
        step("TRS-4: σ from ring A rejected by ring B (different n → different master_pk)",
             wrong_ring_rejected);
    } else {
        step("TRS: backend not initialized — skipping all TRS tests", false);
    }

    // ── FHE tests ─────────────────────────────────────────────────────────
    if (g_fhe_backend && g_fhe_backend->ready()) {
        try {
            // FHE-1: integer scalar round-trip.
            int64_t x = 4242;
            auto ct = g_fhe_backend->encrypt_scalar_int(x);
            int64_t y = g_fhe_backend->decrypt_to_int(ct);
            step("FHE-1: encrypt_scalar_int(4242) → decrypt = 4242", y == x);

            // FHE-2: homomorphic sum of three ciphertexts.
            std::vector<int64_t> vals{100, 250, -50};
            std::vector<BfvBackend::Ciphertext> cts;
            for (auto v : vals) cts.push_back(g_fhe_backend->encrypt_scalar_int(v));
            auto sum_ct = g_fhe_backend->add_many(cts);
            int64_t sum_dec  = g_fhe_backend->decrypt_to_int(sum_ct);
            int64_t expected = 100 + 250 - 50;
            step("FHE-2: Σ EvalAdd round-trip = 300", sum_dec == expected);

            // FHE-3: quantized speed round-trip (×100, m/s ↔ cm/s).
            double s_true = 13.89;  // ~50 km/h
            auto sct = g_fhe_backend->encrypt_speed_mps(s_true);
            double s_back = g_fhe_backend->decrypt_mean_speed_mps(sct, 1);
            double err = std::fabs(s_back - s_true);
            step("FHE-3: encrypt_speed_mps round-trip (err < 0.011 m/s)", err < 0.011);

            // FHE-4: BFV mean speed over 3 ciphertexts.
            std::vector<double> speeds{10.0, 20.0, 30.0};
            std::vector<BfvBackend::Ciphertext> sctv;
            for (double s : speeds) sctv.push_back(g_fhe_backend->encrypt_speed_mps(s));
            auto sct_sum = g_fhe_backend->add_many(sctv);
            double mean_back = g_fhe_backend->decrypt_mean_speed_mps(sct_sum, speeds.size());
            step("FHE-4: BFV mean of {10,20,30} m/s ≈ 20.0", std::fabs(mean_back - 20.0) < 0.011);
        }
        catch (const std::exception &e) {
            std::cout << "  [FAIL] FHE tests threw: " << e.what() << "\n";
            failed++;
        }
    } else {
        step("FHE: backend not initialized — skipping all FHE tests", false);
    }

    // ── Threshold (t,n+1) FHE tests (paper §3.5.4 Eq 3.54–3.56) ─────────────
    if (g_thfhe_backend && g_thfhe_backend->ready()) {
        try {
            using TCt = ThresholdBfvBackend::Ciphertext;
            // Present set = first t−1 RSUs; Cloud (lead) is auto-added by the
            // backend. Absent RSUs' keys are recovered from Shamir shares
            // (Algorithm 7 "with aborts") — this exercises the recovery path.
            std::vector<uint32_t> present;
            for (uint32_t j = 0; j + 1 < g_thfhe_backend->threshold(); j++)
                present.push_back(j);

            // THFHE-1: packed-vector encrypt → threshold decrypt round-trip.
            std::vector<int64_t> vec{ 12345, -678, 9001, 7 };
            TCt cv = g_thfhe_backend->encrypt_vector_int(vec);
            std::vector<int64_t> back;
            bool dec_ok = g_thfhe_backend->threshold_decrypt_vec(cv, present, vec.size(), back);
            bool vec_match = dec_ok && back.size() == vec.size();
            for (size_t k = 0; vec_match && k < vec.size(); k++)
                if (back[k] != vec[k]) vec_match = false;
            step("THFHE-1: packed-vector threshold round-trip (cloud + t-1 RSUs, aborts recovery)",
                 vec_match);

            // THFHE-2: ring homomorphic add (Eq 3.47) of 3 vectors → decrypt = slot-wise Σ.
            std::vector<std::vector<int64_t>> rows{
                { 100, 10, 1, 2 }, { 200, 20, 2, 3 }, { 300, 30, 3, 4 } };
            std::vector<TCt> cts;
            for (auto &r : rows) cts.push_back(g_thfhe_backend->encrypt_vector_int(r));
            TCt ring = g_thfhe_backend->add_many(cts);
            std::vector<int64_t> ring_back;
            bool ring_ok = g_thfhe_backend->threshold_decrypt_vec(ring, present, 4, ring_back);
            bool ring_match = ring_ok &&
                ring_back.size() == 4 &&
                ring_back[0] == 600 && ring_back[1] == 60 &&
                ring_back[2] == 6   && ring_back[3] == 9;
            step("THFHE-2: ring ⊕ of 3 packed aggregates → threshold decrypt = slot sums",
                 ring_match);

            // THFHE-3: serialize_ciphertext is non-empty and deterministic for a
            // fixed ciphertext object (required to bind Enc(A_ring) into the TRS
            // message, Eq 3.48 — same ct must hash to the same bytes).
            std::vector<uint8_t> b1 = g_thfhe_backend->serialize_ciphertext(ring);
            std::vector<uint8_t> b2 = g_thfhe_backend->serialize_ciphertext(ring);
            step("THFHE-3: serialize_ciphertext non-empty + deterministic",
                 !b1.empty() && b1 == b2);

            // ── PIPE: full Algorithm 6 ciphertext-signing path (Eq 3.46–3.51) ──
            // Sign the SERIALIZED CIPHERTEXT (not plaintext) with t partial
            // Dilithium sigs, aggregate, then verify — the paper-correct gate.
            if (g_trs_backend && g_trs_ready &&
                g_trs_ring_t > 0 && g_trs_ring_sks.size() >= g_trs_ring_t) {
                std::vector<uint8_t> msg = b1;                 // Enc(A_ring) bytes
                msg.push_back((uint8_t)g_trs_ring_t);          // bind t
                std::vector<std::vector<uint8_t>> parts;
                std::vector<uint32_t> ids;
                bool sign_all = true;
                for (uint32_t j = 0; j < g_trs_ring_t; j++) {
                    std::vector<uint8_t> p;
                    if (!g_trs_backend->partial_sign(msg, g_trs_ring_sks[j], p)) {
                        sign_all = false; break;
                    }
                    parts.push_back(std::move(p));
                    ids.push_back(j + 1);
                }
                std::vector<uint8_t> sigma;
                bool agg_ok = sign_all && g_trs_backend->aggregate(parts, ids, sigma);
                bool pipe_verified = agg_ok &&
                    g_trs_backend->verify_threshold(msg, sigma, g_trs_ring_pks);
                step("PIPE-1: TRS signs Enc(A_ring) ciphertext → verify accepts (Eq 3.48-3.51)",
                     pipe_verified);

                std::vector<uint8_t> msg_t = msg;
                msg_t[0] ^= 0x01;                              // tamper ciphertext byte
                bool pipe_tamper_rej = agg_ok &&
                    !g_trs_backend->verify_threshold(msg_t, sigma, g_trs_ring_pks);
                step("PIPE-2: tampered ciphertext message rejected by TRS",
                     pipe_tamper_rej);
            } else {
                step("PIPE: TRS backend unavailable — skipping ciphertext-sign tests", false);
            }
        }
        catch (const std::exception &e) {
            std::cout << "  [FAIL] Threshold-FHE/PIPE tests threw: " << e.what() << "\n";
            failed++;
        }
    } else {
        step("THFHE: threshold backend not initialized — skipping threshold-FHE tests", false);
    }

    std::cout << "[CRYPTO/SELFTEST] done: " << passed << " passed, "
              << failed << " failed.\n\n";
}

#endif // MPTD_PQS_06B3_CRYPTO_SELFTEST_H
