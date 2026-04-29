// ============================================================
// 06b_pq_crypto.h — Post-Quantum Cryptography: TRS + Simulated CKKS FHE
// MPTD-PQS SDVN (split from 06_mrtpa_attack.h, Stage 10B cleanup)
// ============================================================
// Paper §3.3.2 (TRS, Eq. 3.58–3.60) and §3.3.3 (FHE, Eq. 3.61–3.65)
//
// Contents:
//   TRSSignature struct + generate_trs_aggregate() + verify_trs()
//   FHECiphertext struct + fhe_encrypt_scalar() + fhe_aggregate() + fhe_decrypt_scalar()
//
// Include order: 06b_pq_crypto.h BEFORE 06c_blockchain_api.h
//   (StoreTrajectoryToBlockchain in 06c calls generate_trs_aggregate + fhe_encrypt_scalar)
// ============================================================

// ── Threshold Ring Signatures (TRS) ─────────────────────────────────────────
// Paper §3.3.2: RSU consortium signs trajectory aggregates using a
// threshold t-of-n scheme. Any t RSUs can jointly verify without
// exposing individual keys. Simulated here using deterministic hash.
struct TRSSignature {
    std::string           aggregate_hash;
    std::vector<uint32_t> signers;
    bool                  verified;
    double                timestamp;
};

static uint32_t trs_fnv1a(const std::string &s)
{
    uint32_t h = 2166136261u;
    for (char c : s) { h ^= (uint8_t)c; h *= 16777619u; }
    return h;
}

TRSSignature generate_trs_aggregate(uint32_t rsu_id,
    double agg_pos_x, double agg_pos_y,
    double agg_speed, double /*agg_heading*/,
    double timestamp, uint32_t n_rsus = 4)
{
    TRSSignature sig;
    sig.aggregate_hash = "RSU"  + std::to_string(rsu_id)
                       + "_spd" + std::to_string((int)(agg_speed * 100))
                       + "_t"   + std::to_string((int)(timestamp  * 10));
    sig.timestamp = timestamp;
    (void)agg_pos_x; (void)agg_pos_y;

    int threshold = (int)(n_rsus / 2) + 1;
    uint32_t seed = trs_fnv1a(sig.aggregate_hash);
    std::vector<uint32_t> ring;
    ring.reserve(n_rsus);
    for (uint32_t r = 0; r < n_rsus; r++) ring.push_back(r);
    for (int i = (int)ring.size() - 1; i > 0; i--) {
        seed = seed * 1664525u + 1013904223u;
        int j = (int)(seed % (uint32_t)(i + 1));
        std::swap(ring[i], ring[j]);
    }
    for (int i = 0; i < threshold && i < (int)ring.size(); i++)
        sig.signers.push_back(ring[i]);

    sig.verified = false;
    return sig;
}

bool verify_trs(TRSSignature &sig, uint32_t n_rsus = 4)
{
    int threshold = (int)(n_rsus / 2) + 1;
    sig.verified  = ((int)sig.signers.size() >= threshold);
    return sig.verified;
}

// ── Simulated CKKS FHE ───────────────────────────────────────────────────────
// Paper §3.3.3: Vehicles encrypt scalar telemetry (speed) before forwarding
// to RSU. RSU aggregates ciphertexts homomorphically. Simulated with
// Gaussian noise at std=1e-6 (negligible for practical detection thresholds).
struct FHECiphertext {
    double noisy_value;
    bool   valid;
};

static const double FHE_CKKS_NOISE_STD = 1e-6;

FHECiphertext fhe_encrypt_scalar(double value)
{
    static uint32_t fhe_seed = 987654321u;
    fhe_seed = fhe_seed * 1664525u + 1013904223u;
    double u1 = (double)((fhe_seed >> 8) & 0xFFFF) / 65536.0 + 1e-9;
    fhe_seed = fhe_seed * 1664525u + 1013904223u;
    double u2 = (double)((fhe_seed >> 8) & 0xFFFF) / 65536.0 + 1e-9;
    double noise = FHE_CKKS_NOISE_STD
                 * std::sqrt(-2.0 * std::log(u1))
                 * std::cos(2.0 * M_PI * u2);
    return FHECiphertext{value + noise, true};
}

FHECiphertext fhe_aggregate(const std::vector<FHECiphertext> &cts)
{
    if (cts.empty()) return FHECiphertext{0.0, false};
    double sum = 0.0;
    for (const auto &ct : cts) sum += ct.noisy_value;
    return FHECiphertext{sum / (double)cts.size(), true};
}

double fhe_decrypt_scalar(const FHECiphertext &ct)
{
    return ct.valid ? ct.noisy_value : 0.0;
}
