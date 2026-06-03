// ============================================================
// 11_blockchain_setup.h — MPTD-PQS Blockchain & SC-Register Setup
// ============================================================
// Active entry points:
//   initialize_blockchain()      — start Hyperledger Fabric test-network
//                                   (deferred to FAB_ROOT scripts; idempotent).
//   initialize_crypto_backends() — init OpenSSL EC TRS + OpenFHE BFV backends.
//   assign_controllers()         — assign node→controller + RSU malicious flags
//                                   (paper §3.4 MRTPA attacker seeding).
//   register_all_nodes()         — paper §3.5.5 Algorithm 7 / Algorithm 7:
//                                   SCBootstrapRSU for the initial RSU set,
//                                   then SCRegister for vehicles + controllers
//                                   with 2f+1 EC-ECDSA P-256 endorsements.
//   test_boolean()               — debug: dump per-node attack state.
//
// Stage 10B cleanup removed: generate_adjacency_matrix(), generate_B_matrix(),
// initialize_bmatrix(), CallBWTRCBFromNS3(), BCTES(), the centralized
// DSRC broadcast/unicast stubs, vehicle_send_to_nearest_rsu(),
// send_dsrc_data_unicast(), assign_basic_keys(), initialize_server().
// Stage SC-Register (TASK ②) removed: StoreControllerAssignmentToBlockchain
// call from assign_controllers() — controller-assignment metadata is no
// longer mirrored to chaincode (controllers register through SCRegister
// like every other peer; their attacker flag is sim-only and never crosses
// the chaincode boundary per invariant 2).
// ============================================================

#ifndef MPTD_PQS_BLOCKCHAIN_SETUP_H
#define MPTD_PQS_BLOCKCHAIN_SETUP_H

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <algorithm>
#include <random>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <cstdint>

// Paper Fig 3.9 / invariant 2: exactly one SDN controller. The chaincode side
// uses N_RSUs (NetworkConfig) for the 2f+1 / f+1 BFT math; controllers are
// treated as a single non-authoritative peer regardless.
static constexpr uint32_t N_Controllers = 1;

// ── initialize_blockchain() — start Hyperledger Fabric (§3.3.4) ──────────────
void initialize_blockchain()
{
    cout << "Initializing blockchain (Hyperledger Fabric test-network with CCAAS)" << endl;
    const char* fabric_dir   = FAB_ROOT "/test-network";

    std::string check_cmd = "docker ps --filter name=peer0.org1 --format '{{.Names}}' 2>/dev/null";
    std::string result    = execCmd(check_cmd);

    if (result.find("peer0.org1") != std::string::npos) {
        cout << "[BLOCKCHAIN] Fabric test-network already running." << endl;
    } else {
        cout << "[BLOCKCHAIN] Starting Fabric test-network..." << endl;
        std::string cmd_down = "bash -c 'cd " + std::string(fabric_dir) + " && ./network.sh down'";
        system(cmd_down.c_str());
        std::string cmd_up = "bash -c 'cd " + std::string(fabric_dir) +
                             " && ./network.sh up createChannel -c mychannel -ca'";
        system(cmd_up.c_str());
        std::string cmd_cc = "bash -c 'cd " + std::string(fabric_dir) +
                             " && ./network.sh deployCCAAS -ccn trajectory -ccp ../trajectory-chaincode'";
        system(cmd_cc.c_str());
    }
    cout << "[BLOCKCHAIN] Initialization complete." << endl;
}

// ── escapeQuotes() — helper for JSON REST calls ───────────────────────────────
std::string escapeQuotes(const std::string& input)
{
    std::string out;
    for (char c : input) {
        if (c == '"') out += '\\';
        out += c;
    }
    return out;
}

// ── initialize_crypto_backends() — R6.5: TRS (OpenSSL EC) + FHE (OpenFHE BFV) ─
// Idempotent. Call once at sim start before any CP-DETECT or FHE aggregate
// path runs. Failure prints a diagnostic and lets the sim continue (CP-DETECT
// gate (a) fails closed if g_trs_backend is null on a non-empty σ; gate (b) is
// unaffected; FHE aggregates are only consumed by R9 which isn't wired yet).
void initialize_crypto_backends()
{
    // TRS: ring size n=4, threshold t=3 (matches 3-RSU + 1-ctrl peer setup).
    if (init_trs_backend(/*n=*/4, /*t=*/3)) {
        std::cout << "[CRYPTO/TRS] " << g_trs_backend->scheme_name()
                  << " ready (n=" << g_trs_ring_n
                  << " t=" << g_trs_ring_t
                  << " pk=" << g_trs_backend->expected_pk_size() << "B"
                  << " sig=" << g_trs_backend->expected_sig_size() << "B)\n";
    } else {
        std::cerr << "[CRYPTO/TRS] init FAILED — CP-DETECT σ_TRS path disabled\n";
    }

    // FHE: BFV-RNS, plaintext modulus 65537, mult depth 1 (sum-only).
    if (init_fhe_backend(/*ptmod=*/65537, /*depth=*/1)) {
        std::cout << "[CRYPTO/FHE] " << g_fhe_backend->scheme_name()
                  << " ready (ring_dim=" << g_fhe_backend->ring_dim()
                  << " ptmod=" << g_fhe_backend->plaintext_modulus() << ")\n";
    } else {
        std::cerr << "[CRYPTO/FHE] init FAILED"
                  << (g_fhe_backend ? (": " + g_fhe_backend->last_error()) : "")
                  << " — R9 FHE aggregate channel will be disabled\n";
    }

    // R6.5-C-8: optional self-test (env MPTD_CRYPTO_SELFTEST=1).
    // Off by default; one-shot run that prints PASS/FAIL summary and
    // continues — never aborts the sim even on failure.
    crypto_selftest_run();
}

// ── assign_controllers() — assign node→controller + RSU malicious flags ──────
void assign_controllers()
{
    cout << "DEBUG: assign_controllers called. attack_number=" << attack_number << endl;
    for (uint32_t i = 0; i < total_size; i++) {
        if      (i < uint32_t(0.25 * total_size)) { node_controller_ID[i] = 0; assigned_consortium_ID[i] = 0; }
        else if (i < uint32_t(0.50 * total_size)) { node_controller_ID[i] = 1; assigned_consortium_ID[i] = 1; }
        else if (i < uint32_t(0.75 * total_size)) { node_controller_ID[i] = 2; assigned_consortium_ID[i] = 2; }
        else                                       { node_controller_ID[i] = 3; assigned_consortium_ID[i] = 3; }

        // RSU nodes: malicious status from attack_percentage
        if (i >= N_Vehicles && i < (N_Vehicles + N_RSUs)) {
            trajectory_poisoning_malicious_nodes[i] = GetBooleanWithProbability(attack_percentage, i);
            cout << "[MRTPA] RSU node " << i << " malicious="
                 << trajectory_poisoning_malicious_nodes[i]
                 << " (attack_percentage=" << attack_percentage << "%)" << endl;
        } else {
            trajectory_poisoning_malicious_nodes[i] = false;
        }

        cout << "node " << i << " controller id " << node_controller_ID[i]
             << " consortium id " << assigned_consortium_ID[i] << endl;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SC-Register (paper §3.5.5 Algorithm 7) — boot-time node registration
// ─────────────────────────────────────────────────────────────────────────────
//
// Each vehicle / RSU / controller is provisioned with a fresh EC-ECDSA P-256
// keypair at boot. RSUs are seeded via SCBootstrapRSU (genesis path, no
// endorsements needed). Vehicles and controllers register via SCRegister with
// 2f+1 RSU endorsements signed over sha256(id || pkHex || hKuHex) (chaincode
// endorsementDigest format — must stay byte-identical to smartcontract.go).
//
// Deviations from paper §3.5.5 + locked design decisions
// (memory project_sc_register_decisions.md):
//   - Fabric-CA enrollment (decision #1) is PAUSED — keys are generated in
//     this file rather than read from MSP x509 certs. Same chaincode
//     accepts either: the on-chain record just stores `PkHex` opaquely.
//     Switching to Fabric-CA on Phase 4 only changes how secret keys are
//     loaded; the chaincode side is unchanged.
//   - 2f+1 RSU endorsement set is sampled uniformly at random from the
//     active RSU set (decision #2).
//   - Endorsements use EC-ECDSA P-256 ASN.1-DER (decision #3).
//   - τ_init = 1.0 (decision #4, hard-coded in chaincode TauInit constant).
//   - Strict reject + retry on <2f+1 reachable endorsers (decision #5).
//     In sim all RSUs come up before vehicles so the retry path is dead
//     code — left in for production parity.
// ─────────────────────────────────────────────────────────────────────────────

namespace mptd_scregister {

// Per-node keypair store. Keyed by full SC-Register ID ("VEH_<nid>",
// "RSU_<idx>", "CTRL_<idx>"). RSU keys are needed AFTER bootstrap to sign
// endorsements for the vehicle/controller registration phase, so the
// vector outlives register_all_nodes(); leaked at process exit (acceptable
// for an NS-3 sim, matches existing OpenFHE/TRS lifetime).
static std::map<std::string, EC_KEY*> g_node_ec_keys;
static std::map<std::string, std::string> g_node_pk_hex;

// hex_encode — byte buffer → lowercase hex string.
static inline std::string hex_encode(const uint8_t* data, size_t len)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[2*i    ] = kHex[(data[i] >> 4) & 0xF];
        out[2*i + 1] = kHex[ data[i]       & 0xF];
    }
    return out;
}

// sha256_hex — SHA-256(data) as 64-char lowercase hex (matches chaincode
// `hKuHex` length check of exactly 64 chars).
static inline std::string sha256_hex(const uint8_t* data, size_t len)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    return hex_encode(digest, SHA256_DIGEST_LENGTH);
}

// ec_p256_keygen — generate a fresh EC P-256 keypair using OpenSSL low-level
// API. The deprecation warning is silenced project-wide via wscript's
// -Wno-deprecated-declarations.
static EC_KEY* ec_p256_keygen()
{
    EC_KEY* k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!k) return nullptr;
    if (EC_KEY_generate_key(k) != 1) {
        EC_KEY_free(k);
        return nullptr;
    }
    return k;
}

// ec_pubkey_uncompressed_hex — serialize the public key as a 65-byte
// uncompressed point (0x04 || X32 || Y32) → 130 lowercase hex chars.
// MUST match chaincode parseP256PubKey expectations.
static std::string ec_pubkey_uncompressed_hex(EC_KEY* k)
{
    const EC_GROUP* grp = EC_KEY_get0_group(k);
    const EC_POINT* pub = EC_KEY_get0_public_key(k);
    BN_CTX* ctx = BN_CTX_new();

    size_t pub_len = EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
                                        nullptr, 0, ctx);
    std::vector<uint8_t> buf(pub_len);
    EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
                       buf.data(), pub_len, ctx);
    BN_CTX_free(ctx);
    return hex_encode(buf.data(), buf.size());
}

// ecdsa_sign_hex — sign `digest` (typically the 32-byte SHA-256
// endorsementDigest) with EC-ECDSA P-256 and return the ASN.1-DER
// signature as lowercase hex. Matches chaincode `verifyECDSAP256` which
// expects `ecdsa.VerifyASN1` input format.
static std::string ecdsa_sign_hex(EC_KEY* k,
                                   const uint8_t* digest, size_t digest_len)
{
    ECDSA_SIG* sig = ECDSA_do_sign(digest, (int)digest_len, k);
    if (!sig) return "";

    int der_len = i2d_ECDSA_SIG(sig, nullptr);
    if (der_len <= 0) {
        ECDSA_SIG_free(sig);
        return "";
    }
    std::vector<uint8_t> der(der_len);
    unsigned char* p = der.data();
    i2d_ECDSA_SIG(sig, &p);
    ECDSA_SIG_free(sig);
    return hex_encode(der.data(), der.size());
}

// endorsement_digest — must stay byte-identical to chaincode endorsementDigest
// (smartcontract.go endorsementDigest): SHA-256(id || pkHex || hKuHex), with
// the string args concatenated as raw UTF-8 bytes (no separators).
static std::vector<uint8_t> endorsement_digest(const std::string& id,
                                                const std::string& pkHex,
                                                const std::string& hKuHex)
{
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, id.data(),     id.size());
    SHA256_Update(&c, pkHex.data(),  pkHex.size());
    SHA256_Update(&c, hKuHex.data(), hKuHex.size());
    uint8_t out[SHA256_DIGEST_LENGTH];
    SHA256_Final(out, &c);
    return std::vector<uint8_t>(out, out + SHA256_DIGEST_LENGTH);
}

// derive_controller_k_u — paper §3.5.5 / Algorithm 7 hKuHex source for the
// controller. Algorithm 7's text mentions only vehicles and RSUs; controllers
// have no LKH leaf in 00_lkh_keys.h. We mirror the lkh_init_rsu_ring_keys
// pattern (Eq 3.36) to derive a controller-specific K_u from LKH_K_RING +
// a controller-tag ID, then hash it. This is a sim-only construction;
// production flows would source K_u from the controller's Fabric-CA leaf.
static std::string derive_controller_h_ku(uint32_t ctrl_idx)
{
    uint8_t k_u[LKH_KEY_BYTES];
    uint8_t id_c[8] = { 'C','T','R','L', (uint8_t)ctrl_idx, 0, 0, 0 };
    lkh_kdf(LKH_K_RING, LKH_KEY_BYTES,
            LKH_K_RING, LKH_KEY_BYTES,
            id_c,       sizeof(id_c),
            k_u);
    return sha256_hex(k_u, LKH_KEY_BYTES);
}

// random_endorser_sample — uniformly draw 2f+1 distinct RSU indices from
// [0, n_rsus). Returns empty vector when n_rsus < 2f+1 (caller should
// surface the registration failure per decision #5).
static std::vector<uint32_t> random_endorser_sample(uint32_t n_rsus,
                                                     uint32_t need,
                                                     uint64_t seed)
{
    std::vector<uint32_t> all;
    all.reserve(n_rsus);
    for (uint32_t i = 0; i < n_rsus; ++i) all.push_back(i);
    if (need > all.size()) return {};

    std::mt19937_64 rng(seed);
    std::shuffle(all.begin(), all.end(), rng);
    all.resize(need);
    return all;
}

// build_endorsements_json — for the registering node, ask `need` RSUs to
// each ECDSA-sign the endorsement digest. Returns the JSON array string
// expected by SCRegister.endorsersJSON (smartcontract.go Endorser type).
static std::string build_endorsements_json(const std::string& target_id,
                                            const std::string& target_pk_hex,
                                            const std::string& target_h_ku_hex,
                                            uint32_t n_rsus,
                                            uint32_t need,
                                            uint64_t seed)
{
    auto sample = random_endorser_sample(n_rsus, need, seed);
    if (sample.empty()) return "";

    std::vector<uint8_t> digest = endorsement_digest(target_id, target_pk_hex,
                                                      target_h_ku_hex);

    std::ostringstream js;
    js << "[";
    bool first = true;
    for (uint32_t rsu_idx : sample) {
        std::string rsu_id = MakeRsuId(rsu_idx);
        auto it = g_node_ec_keys.find(rsu_id);
        if (it == g_node_ec_keys.end() || !it->second) continue;
        std::string sig_hex = ecdsa_sign_hex(it->second,
                                              digest.data(), digest.size());
        if (sig_hex.empty()) continue;
        if (!first) js << ",";
        first = false;
        js << "{\"rsuID\":\"" << rsu_id
           << "\",\"sigHex\":\"" << sig_hex << "\"}";
    }
    js << "]";
    return js.str();
}

// register_one — generate keypair + chaincode register call for one node.
// Returns true on commit (chaincode payload contains no "rejected:" prefix).
// Wraps decision #5: strict-reject + bounded retry. RSU bootstrap path is
// unconditional (no endorsers exist yet); vehicle/controller path samples
// 2f+1 RSUs and retries on "rejected: insufficient endorsements" only.
static bool register_one(const std::string& id, const std::string& role,
                          const std::string& h_ku_hex, double t_reg,
                          uint32_t n_rsus, uint32_t need_endorsers,
                          uint32_t max_retries)
{
    // Generate per-node keypair (kept alive in g_node_ec_keys so RSUs can
    // later sign endorsements).
    EC_KEY* k = ec_p256_keygen();
    if (!k) {
        std::cerr << "[SC-REGISTER] " << id << ": EC keygen FAILED\n";
        return false;
    }
    g_node_ec_keys[id] = k;
    std::string pk_hex = ec_pubkey_uncompressed_hex(k);
    g_node_pk_hex[id] = pk_hex;

    // RSU genesis path: SCBootstrapRSU (no endorsers).
    if (role == "RSU") {
        // SC-Register chaincode role string is "RSU"; CallSCBootstrapRSU
        // takes the raw rsu_idx and re-builds the prefixed ID internally.
        // We extract the numeric suffix from `id` ("RSU_<idx>" → <idx>).
        uint32_t rsu_idx = 0;
        if (id.rfind("RSU_", 0) == 0) {
            try { rsu_idx = (uint32_t)std::stoul(id.substr(4)); }
            catch (...) { return false; }
        }
        SCResult r = CallSCBootstrapRSU(rsu_idx, pk_hex, h_ku_hex, t_reg);
        if (!r.ok) {
            // Daemon/transport failure (empty msg) OR chaincode-side reject
            // ("rejected: …"). Both are fatal here — the RSU is not on chain
            // and cannot endorse downstream SCRegister calls.
            std::cerr << "[SC-REGISTER] " << id
                      << " bootstrap FAILED: "
                      << (r.msg.empty() ? "transport error (daemon down?)" : r.msg)
                      << std::endl;
            return false;
        }
        std::cout << "[SC-REGISTER] " << id << " bootstrap OK (pk="
                  << pk_hex.substr(0, 16) << "..)\n";
        return true;
    }

    // Vehicle / Controller path: 2f+1 endorsements via SCRegister.
    for (uint32_t attempt = 0; attempt < max_retries; ++attempt) {
        // Re-sample endorsers on each retry so we don't loop on the same
        // unresponsive subset (production: if one peer is partitioned the
        // next attempt picks a different sample; sim: all RSUs up so
        // attempt 0 always succeeds).
        uint64_t seed = (uint64_t)std::chrono::steady_clock::now()
                            .time_since_epoch().count()
                       ^ (uint64_t)attempt
                       ^ std::hash<std::string>{}(id);

        std::string endorsersJSON = build_endorsements_json(
            id, pk_hex, h_ku_hex, n_rsus, need_endorsers, seed);
        if (endorsersJSON.empty() || endorsersJSON == "[]") {
            std::cerr << "[SC-REGISTER] " << id
                      << " no endorsers available (attempt " << attempt
                      << ")\n";
            continue;
        }

        SCResult r = CallSCRegister(id, role, pk_hex, h_ku_hex,
                                     t_reg, endorsersJSON);
        if (r.ok) {
            std::cout << "[SC-REGISTER] " << id << " " << role
                      << " OK (endorsers=" << need_endorsers
                      << " pk=" << pk_hex.substr(0, 16) << "..)\n";
            return true;
        }
        const std::string& m = r.msg;
        std::cerr << "[SC-REGISTER] " << id << " attempt " << attempt
                  << " FAILED: "
                  << (m.empty() ? "transport error (daemon down?)" : m)
                  << std::endl;

        // Transport-level failure (empty msg) — retry, daemon may recover.
        if (m.empty()) continue;

        // Chaincode-side failure: only retry on transient endorsement-set
        // mismatch ("rejected: insufficient endorsements …"). Deterministic
        // rejects (duplicate-ID, bad pk, bad hKuHex) won't change on retry.
        if (m.find("insufficient endorsements") == std::string::npos)
            break;
    }
    return false;
}

} // namespace mptd_scregister

// ── register_all_nodes() — paper §3.5.5 Algorithm 7 boot-time registration ───
// Run ONCE, after lkh_init_all() and before Simulator::Run(). Skips silently
// when skip_blockchain=true (training-sweep mode).
//
// Order:
//   1. RSUs (genesis: SCBootstrapRSU). Each RSU's EC keypair must be stored
//      BEFORE vehicle/controller registration so RSUs can sign endorsements.
//   2. Vehicles (SCRegister with 2f+1 RSU endorsements).
//   3. Controllers (SCRegister, same path as vehicles).
//
// hKuHex source per role:
//   Vehicle    → SHA-256(g_vehicle_session_key[veh_idx])  — LKH leaf (Eq 3.33).
//   RSU        → SHA-256(g_rsu_ring_key[rsu_idx])         — LKH ring (Eq 3.36).
//   Controller → SHA-256(KDF(LKH_K_RING || "CTRL" || idx)) — sim-only deriv.
void register_all_nodes()
{
    using namespace mptd_scregister;

    if (skip_blockchain) {
        std::cout << "[SC-REGISTER] skip_blockchain=true — registration bypassed\n";
        return;
    }

    const uint32_t n_rsus = N_RSUs;
    // Eq 3.58 / chaincode fByzantine: f = (n_rsus - 1) / 3, threshold = 2f+1.
    const uint32_t f             = (n_rsus > 0) ? (n_rsus - 1) / 3 : 0;
    const uint32_t need_endorsers = 2 * f + 1;
    const uint32_t max_retries    = 3;
    const double   t_reg          = Simulator::Now().GetSeconds();

    std::cout << "[SC-REGISTER] starting boot-time registration: N_RSUs="
              << n_rsus << " (f=" << f << " 2f+1=" << need_endorsers
              << ") N_Vehicles=" << N_Vehicles
              << " N_Controllers=" << N_Controllers
              << " t_reg=" << t_reg << "\n";

    // ── 1. RSUs first (genesis bootstrap) ─────────────────────────────────────
    uint32_t rsu_ok = 0;
    for (uint32_t rsu_idx = 0; rsu_idx < n_rsus; ++rsu_idx) {
        std::string id = MakeRsuId(rsu_idx);
        // hKuHex: SHA-256 over the RSU ring key sk_j (paper Eq 3.36 output).
        std::string h_ku_hex;
        if (rsu_idx < 4) {
            h_ku_hex = sha256_hex(g_rsu_ring_key[rsu_idx], LKH_KEY_BYTES);
        } else {
            // LKH_MAX_RSU is 4 in the test topology; surface the limit.
            std::cerr << "[SC-REGISTER] " << id
                      << " skipped (rsu_idx >= LKH ring slots)\n";
            continue;
        }
        if (register_one(id, "RSU", h_ku_hex, t_reg,
                         n_rsus, /*endorsers=*/0, max_retries))
            rsu_ok++;
    }
    std::cout << "[SC-REGISTER] RSUs registered: " << rsu_ok << "/"
              << n_rsus << "\n";
    if (rsu_ok < need_endorsers) {
        std::cerr << "[SC-REGISTER] FATAL: only " << rsu_ok
                  << " RSUs registered, need " << need_endorsers
                  << " endorsers for vehicle/controller registration\n";
        return;
    }

    // ── 2. Vehicles ──────────────────────────────────────────────────────────
    // Vehicle NS-3 NodeIDs start at g_first_vehicle_node_id (=2 in routing_test
    // topology). The chaincode ID is MakeVehId(nid) so it matches the
    // CallSCTrustSubmitEvidence call site downstream.
    uint32_t veh_ok = 0;
    for (uint32_t v = 0; v < N_Vehicles; ++v) {
        uint32_t nid = g_first_vehicle_node_id + v;
        std::string id = MakeVehId(nid);
        // hKuHex: SHA-256 over the LKH leaf session key K_i (Eq 3.33).
        std::string h_ku_hex;
        if ((int)v < LKH_MAX_VEH) {
            h_ku_hex = sha256_hex(g_vehicle_session_key[v], LKH_KEY_BYTES);
        } else {
            std::cerr << "[SC-REGISTER] " << id
                      << " skipped (veh_idx >= LKH_MAX_VEH)\n";
            continue;
        }
        if (register_one(id, "VEHICLE", h_ku_hex, t_reg,
                         n_rsus, need_endorsers, max_retries)) {
            veh_ok++;
            // P6: populate detection-engine gate cache. Raw nid is what the
            // BsmBeaconTag carries and what handle_readone reads as `vid`.
            g_registered_vids.insert(nid);
        }
    }
    std::cout << "[SC-REGISTER] vehicles registered: " << veh_ok << "/"
              << N_Vehicles
              << " (gate cache size: " << g_registered_vids.size() << ")\n";

    // ── 3. Controllers ───────────────────────────────────────────────────────
    uint32_t ctrl_ok = 0;
    for (uint32_t c = 0; c < N_Controllers; ++c) {
        std::string id = MakeCtrlId(c);
        std::string h_ku_hex = derive_controller_h_ku(c);
        if (register_one(id, "CONTROLLER", h_ku_hex, t_reg,
                         n_rsus, need_endorsers, max_retries))
            ctrl_ok++;
    }
    std::cout << "[SC-REGISTER] controllers registered: " << ctrl_ok << "/"
              << N_Controllers << "\n";

    std::cout << "[SC-REGISTER] boot-time registration complete: "
              << rsu_ok << " RSUs + " << veh_ok << " vehicles + "
              << ctrl_ok << " controllers\n";
}

// ── test_boolean() — debug: print per-node attack state ──────────────────────
void test_boolean()
{
    for (uint32_t i = 0; i < 101; i++) {
        for (uint32_t j = 0; j < 20; j++) {
            bool s = GetBooleanWithProbability(i, j);
            cout << "probability is " << i << " attack state is " << s
                 << " for source node " << j << endl;
        }
    }
    for (uint32_t j = 0; j < total_size; j++) {
        cout << "For " << j << "th node, tp_vehicle attack state is "         << tp_vehicle_nodes[j]        << endl;
        cout << "For " << j << "th node, heading_spoof attack state is "     << heading_spoof_nodes[j]     << endl;
        cout << "For " << j << "th node, rsu_fabrication attack state is "   << rsu_fabrication_nodes[j]   << endl;
        cout << "For " << j << "th node, sybil_mitm attack state is "        << sybil_mitm_nodes[j]        << endl;
        cout << "For " << j << "th node, beacon_suppression attack state is " << beacon_suppression_nodes[j] << endl;
        cout << "Node " << j << " controller ID " << node_controller_ID[j] << endl;
    }
}

#endif // MPTD_PQS_BLOCKCHAIN_SETUP_H
