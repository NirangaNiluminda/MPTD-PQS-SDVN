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
#include <set>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <fstream>

// Paper C_trusted set (Eq 3.1 / 3.60): the trusted-controller set. Fig 3.9
// draws a single SDN controller for clarity, but the framework defines a SET of
// trusted controllers so that a controller compromised per CP-DETECT (f+1 RSU
// conflict, Eq 3.64–3.67) can be EXCLUDED and a successor activated — the
// blockchain-authoritative reassignment owned by the chaincode (GetActive-
// Controller / CTRLREASSIGN records). N_Controllers registers that logical set
// on chain (CTRL_0..CTRL_{N-1}); CTRL_0 is the initial active controller.
//
// This is distinct from the 5 Raft *orderer* nodes (gen_network.sh) — those are
// the ledger ordering service; C_trusted is the control-plane decision set.
// The physical NS-3 controller_Node remains a single sim-only relay (CLAUDE.md
// known deviation); the controller IDENTITY it submits under is the chain-
// authoritative active controller (see node-side active-controller tracking).
static constexpr uint32_t N_Controllers = 5;

// ── initialize_blockchain() — start Hyperledger Fabric (§3.3.4) ──────────────
void initialize_blockchain()
{
    cout << "Initializing blockchain (Hyperledger Fabric)" << endl;
    const char* fabric_dir   = FAB_ROOT "/test-network";

    // Prefer the dynamic paper-scale network (fabric_net/gen_network.sh: 64 RSU
    // peers + 5 controller-orderers, org rsu.example.com). When it is already up,
    // the gateway daemon is pointed at it and node registration / SC-invokes go
    // through the AF_UNIX socket — there is NOTHING to bring up here, and shelling
    // out to the legacy org1 test-network would build the WRONG network and clash
    // on the shared ports. So detect peer0.rsu.example.com and no-op.
    std::string gen_cmd = "docker ps --filter name=peer0.rsu.example.com --format '{{.Names}}' 2>/dev/null";
    if (execCmd(gen_cmd).find("peer0.rsu.example.com") != std::string::npos) {
        cout << "[BLOCKCHAIN] gen_network (peer0.rsu.example.com) already running — "
                "using existing 64-RSU network; legacy test-network bring-up skipped." << endl;
        cout << "[BLOCKCHAIN] Initialization complete." << endl;
        return;
    }

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
    // Ensure LKH master keys (K_root, K_ring) are CSPRNG-generated BEFORE the TRS
    // backend seeds its ring polynomial from K_ring. This path runs before
    // lkh_init_all() in 12_main.h, so generate here (idempotent).  [P1b-1]
    lkh_init_master_keys();

    // TRS: ring size n=4, threshold t=3 (matches 3-RSU + 1-ctrl peer setup).
    // Full-mode default is the paper-correct PQ scheme Dilithium / ML-DSA-87,
    // Eq 3.49); --trs_classical=1 selects the classical Shamir-Schnorr-P256
    // signing-latency baseline for RQ5 (paper §3.5.4, behind ITrsBackend).
    const TrsScheme trs_scheme = g_trs_classical_baseline
                               ? TrsScheme::Classical : TrsScheme::Dilithium;
    if (init_trs_backend(/*n=*/4, /*t=*/3, trs_scheme)) {
        std::cout << "[CRYPTO/TRS] " << g_trs_backend->scheme_name()
                  << " ready (n=" << g_trs_ring_n
                  << " t=" << g_trs_ring_t
                  << " pk=" << g_trs_backend->expected_pk_size() << "B"
                  << " sig=" << g_trs_backend->expected_sig_size() << "B)\n";
    } else {
        std::cerr << "[CRYPTO/TRS] init FAILED — CP-DETECT σ_TRS path disabled\n";
    }

    // FHE: threshold (t, n+1) BFV-RNS — the paper-correct Full-mode scheme
    // (Eq 3.54 ThGen, multiparty key gen + Shamir ShareKeys "with aborts").
    // n_rsus=4, threshold=3; Cloud is the mandatory (n+1)-th lead party.
    if (init_threshold_fhe_backend(/*n_rsus=*/4, /*threshold=*/3,
                                   /*ptmod=*/65537, /*depth=*/1)) {
        std::cout << "[CRYPTO/THFHE] " << g_thfhe_backend->scheme_name()
                  << " ready (ring_dim=" << g_thfhe_backend->ring_dim()
                  << " parties=" << g_thfhe_backend->num_parties()
                  << " t=" << g_thfhe_backend->threshold()
                  << " shares=" << (g_thfhe_backend->shares_available() ? "yes" : "no")
                  << ")\n";
    } else {
        std::cerr << "[CRYPTO/THFHE] init FAILED"
                  << (g_thfhe_backend ? (": " + g_thfhe_backend->last_error()) : "")
                  << " — Full-mode FHE-TRS pipeline (Alg 6/7) will be disabled\n";
    }

    // Single-key BFV retained ONLY for the 06b3 selftest's legacy sum/mean
    // checks; the live Full-mode aggregate path uses g_thfhe_backend above.
    if (init_fhe_backend(/*ptmod=*/65537, /*depth=*/1)) {
        std::cout << "[CRYPTO/FHE] " << g_fhe_backend->scheme_name()
                  << " ready (ring_dim=" << g_fhe_backend->ring_dim()
                  << " ptmod=" << g_fhe_backend->plaintext_modulus() << ")\n";
    } else {
        std::cerr << "[CRYPTO/FHE] init FAILED"
                  << (g_fhe_backend ? (": " + g_fhe_backend->last_error()) : "")
                  << " — single-key selftest path disabled\n";
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
    // Bound on N_Vehicles (active count), not total_size (capacity=256): the
    // quarter-split must divide the ACTUAL fleet across the 4 consortia. Using
    // the capacity here would lump every real vehicle into consortium 0.
    // (In the test net N_Vehicles==16, so this is bit-for-bit the old behaviour.)
    for (uint32_t i = 0; i < N_Vehicles; i++) {
        if      (i < uint32_t(0.25 * N_Vehicles)) { node_controller_ID[i] = 0; assigned_consortium_ID[i] = 0; }
        else if (i < uint32_t(0.50 * N_Vehicles)) { node_controller_ID[i] = 1; assigned_consortium_ID[i] = 1; }
        else if (i < uint32_t(0.75 * N_Vehicles)) { node_controller_ID[i] = 2; assigned_consortium_ID[i] = 2; }
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
//   - Fabric-CA enrollment (decision #1) is LIVE as of P4 — but operates at
//     TWO distinct layers, kept deliberately separate:
//       (a) Application keypair: the EC-ECDSA P-256 (id, pk, h(K_u)) tuple
//           registered ON CHAIN is still generated here (g_node_ec_keys).
//           This is the LKH/endorsement key the chaincode stores in PkHex.
//       (b) Fabric submitting identity: WHICH Fabric MSP x509 cert SIGNS the
//           transaction. Pre-P4 every node submitted as the shared User1;
//           P4 makes each node submit under its OWN CA-enrolled identity
//           (rsu<idx>/ctrl<idx>, or a leased pool<slot> for vehicles), set
//           via the `submit_identity` arg threaded into CallSC* below.
//     The chaincode is unchanged — it stores PkHex opaquely and (per
//     smartcontract.go:423) does not yet enforce an admin-OU check on the
//     submitting identity. See P4_FABRIC_CA_ENROLLMENT.md for the full model.
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

// ── P4 — leased Fabric-CA identity pool (see P4_FABRIC_CA_ENROLLMENT.md) ──────
// Selects WHICH enrolled wallet identity signs each SC-Register submission.
// RSUs/controllers use stable names (rsu<idx>/ctrl<idx>); vehicles LEASE a slot
// from a bounded pool (pool<slot>) so the model scales to SUMO (lease on spawn,
// release on depart) and degrades to unique-per-vehicle identities whenever
// pool_size >= vehicle count. The names MUST match those enrolled by
// enroll_pool.sh and loaded by the gateway daemon's wallet.

// Toggle: env MPTD_CA_IDENTITY=0 disables identity stamping (every submit goes
// through the daemon's default User1 — pre-P4 behaviour). Useful when the
// wallet has not been enrolled (enroll_pool.sh not run). Default ON.
static inline bool ca_identity_enabled()
{
    static bool on = []() {
        const char* e = std::getenv("MPTD_CA_IDENTITY");
        return !(e && e[0] == '0');
    }();
    return on;
}

// Pool size — mirrors enroll_pool.sh's FABRIC_CA_POOL_SIZE (default 32).
static inline int ca_pool_size()
{
    static int n = []() {
        const char* e = std::getenv("FABRIC_CA_POOL_SIZE");
        int v = (e && *e) ? std::atoi(e) : 32;
        return v > 0 ? v : 32;
    }();
    return n;
}

// Vehicle lease table: vid → pool slot, with free-list semantics so a released
// slot (SUMO arrival) can be re-leased. The static topology never departs, so
// today every vehicle holds its slot for the whole run.
static std::map<uint32_t, int> g_veh_pool_lease;
static std::vector<bool>       g_pool_slot_busy;

// LeasePoolIdentity — return "pool<slot>" for vid, assigning a free slot. When
// the pool is exhausted (SUMO scale) reuse slot (vid % pool_size) — the V2X
// pseudonym-pool reuse path; per-vehicle attribution still comes from the
// VEH_<nid> chaincode arg, not the (now shared) cert.
static std::string LeasePoolIdentity(uint32_t vid)
{
    auto it = g_veh_pool_lease.find(vid);
    if (it != g_veh_pool_lease.end())
        return "pool" + std::to_string(it->second);

    const int n = ca_pool_size();
    if ((int)g_pool_slot_busy.size() < n) g_pool_slot_busy.resize(n, false);
    for (int s = 0; s < n; ++s) {
        if (!g_pool_slot_busy[s]) {
            g_pool_slot_busy[s] = true;
            g_veh_pool_lease[vid] = s;
            return "pool" + std::to_string(s);
        }
    }
    int s = (int)(vid % (uint32_t)n);   // pool exhausted → pseudonym reuse
    g_veh_pool_lease[vid] = s;
    return "pool" + std::to_string(s);
}

// ReleasePoolIdentity — free vid's slot (call on SUMO vehicle departure).
// Unused by the static topology; wired so the SUMO integration has the hook.
[[maybe_unused]] static void ReleasePoolIdentity(uint32_t vid)
{
    auto it = g_veh_pool_lease.find(vid);
    if (it == g_veh_pool_lease.end()) return;
    if (it->second >= 0 && it->second < (int)g_pool_slot_busy.size())
        g_pool_slot_busy[it->second] = false;
    g_veh_pool_lease.erase(it);
}

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

// concat_digest — SHA-256 over the ordered raw-UTF-8 concatenation of `parts`
// (no separators). The one canonical hashing rule shared with chaincode
// concatDigest(); every signed payload below uses it so both sides agree.
static std::vector<uint8_t> concat_digest(std::initializer_list<std::string> parts)
{
    SHA256_CTX c;
    SHA256_Init(&c);
    for (const std::string& p : parts) SHA256_Update(&c, p.data(), p.size());
    uint8_t out[SHA256_DIGEST_LENGTH];
    SHA256_Final(out, &c);
    return std::vector<uint8_t>(out, out + SHA256_DIGEST_LENGTH);
}

// endorsement_digest — must stay byte-identical to chaincode endorsementDigest
// (smartcontract.go endorsementDigest): SHA-256(id || pkHex || hKuHex).
static std::vector<uint8_t> endorsement_digest(const std::string& id,
                                                const std::string& pkHex,
                                                const std::string& hKuHex)
{
    return concat_digest({id, pkHex, hKuHex});
}

// node_sign_hex — sign `digest` with node `id`'s registered P-256 key from
// g_node_ec_keys. Returns "" if the key is absent (node not registered) so the
// chaincode's strict verify rejects the submission rather than silently
// accepting forged evidence.
static std::string node_sign_hex(const std::string& id,
                                 const std::vector<uint8_t>& digest)
{
    auto it = g_node_ec_keys.find(id);
    if (it == g_node_ec_keys.end() || !it->second) return "";
    return ecdsa_sign_hex(it->second, digest.data(), digest.size());
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
    lkh_init_master_keys();   // ensure K_ring is CSPRNG-ready before deriving
    lkh_kdf(g_lkh_k_ring_current, LKH_KEY_BYTES,
            g_lkh_k_ring_current, LKH_KEY_BYTES,
            id_c,                 sizeof(id_c),
            k_u);
    return sha256_hex(k_u, LKH_KEY_BYTES);
}

// random_endorser_sample — uniformly draw 2f+1 distinct RSU indices from
// [0, n_rsus). Returns empty vector when n_rsus < 2f+1 (caller should
// surface the registration failure per decision #5). This is the BOOTSTRAP
// path (Sir 2026-06-16: "initially you can have everyone as peers … as nodes
// trust scores are just initialized") and the A4/ablation fallback when
// trust-ranked selection is disabled.
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

// ── Trust-ranked endorsing-peer selection (Sir Task-4 revision, 2026-06-16) ───
// Paper-aligned with the notation-table endorser set R_trusted(t): pick the
// 2f+1 endorsers from the HIGHEST-trust members of the on-chain trusted set
// rather than uniformly at random over every RSU. This is "Option A" — it
// changes WHICH trusted RSUs are asked to endorse; it does NOT remove peers
// from the Fabric network (that is the heavier Option B, deliberately not
// taken because gating runtime evidence/votes to a global committee would
// break the 2f+1 SC-Revoke trajectory-witness reachability — flagged to the
// supervisor as the open architectural question). Toggleable for ablation.
static bool     g_trust_peer_selection      = true;  // false → uniform random
static double   g_committee_refresh_interval = 1.0;  // seconds between refreshes
// Live snapshot maintained by refresh_endorsement_committee(); read by the
// selector. Empty before the first refresh / at boot → selector falls back to
// random_endorser_sample (correct bootstrap behaviour).
static std::map<uint32_t, double> g_rsu_trust_cache;   // rsu_idx → τ
static std::set<uint32_t>         g_rsu_trusted_set;    // rsu_idx with State==TRUSTED
static std::vector<uint32_t>      g_endorsement_committee;  // last selected top-2f+1

// select_endorsers_trust_ranked — top-`need` TRUSTED RSUs by descending trust,
// with a deterministic random tie-break among equal scores (so the all-equal
// boot case degrades to a uniform random pick, exactly the bootstrap rule).
// Falls back to random_endorser_sample when trust ranking is disabled or no
// live trust snapshot exists yet.
static std::vector<uint32_t> select_endorsers_trust_ranked(uint32_t n_rsus,
                                                           uint32_t need,
                                                           uint64_t seed)
{
    if (!g_trust_peer_selection || g_rsu_trusted_set.empty())
        return random_endorser_sample(n_rsus, need, seed);

    // Candidate pool: trusted RSUs within the addressable index range.
    std::vector<uint32_t> pool;
    pool.reserve(g_rsu_trusted_set.size());
    for (uint32_t idx : g_rsu_trusted_set)
        if (idx < n_rsus) pool.push_back(idx);
    if (pool.size() < need)
        return random_endorser_sample(n_rsus, need, seed);  // not enough trusted

    // Shuffle first so equal-trust ties break uniformly, then stable-sort by
    // trust descending. std::sort is not stable, so pre-shuffle + stable_sort.
    std::mt19937_64 rng(seed);
    std::shuffle(pool.begin(), pool.end(), rng);
    std::stable_sort(pool.begin(), pool.end(),
                     [](uint32_t a, uint32_t b) {
                         double ta = g_rsu_trust_cache.count(a) ? g_rsu_trust_cache[a] : 0.0;
                         double tb = g_rsu_trust_cache.count(b) ? g_rsu_trust_cache[b] : 0.0;
                         return ta > tb;
                     });
    pool.resize(need);
    return pool;
}

// refresh_endorsement_committee — query live on-chain RSU trust scores, rebuild
// the trusted-set snapshot, and recompute the top-2f+1 endorsement committee.
// Logged each cycle as the "active endorsing peer set" (Sir: peer selection
// occasionally at runtime based on trust score). Cheap read (evaluate); no-op
// under skip_blockchain or when trust selection is disabled. Reschedules itself.
static void refresh_endorsement_committee()
{
    if (skip_blockchain || !g_trust_peer_selection) return;

    auto views = CallSCGetAllRSUTrustScores();
    if (!views.empty()) {
        g_rsu_trust_cache.clear();
        g_rsu_trusted_set.clear();
        for (const auto& v : views) {
            g_rsu_trust_cache[v.rsu_idx] = v.trust;
            if (v.trusted) g_rsu_trusted_set.insert(v.rsu_idx);
        }
        const uint32_t need = 2 * /*paper fixed f=*/1u + 1u;   // 2f+1 = 3
        g_endorsement_committee = select_endorsers_trust_ranked(
            N_RSUs, need, (uint64_t)(Simulator::Now().GetNanoSeconds()));

        std::ostringstream cs;
        for (size_t i = 0; i < g_endorsement_committee.size(); ++i) {
            uint32_t idx = g_endorsement_committee[i];
            cs << (i ? "," : "") << MakeRsuId(idx)
               << "(" << g_rsu_trust_cache[idx] << ")";
        }
        std::cout << "[PEER-SELECT] t=" << Simulator::Now().GetSeconds()
                  << " trusted=" << g_rsu_trusted_set.size() << "/" << views.size()
                  << " committee[2f+1]={" << cs.str() << "}\n";
    }

    Simulator::Schedule(Seconds(g_committee_refresh_interval),
                        &refresh_endorsement_committee);
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
    // Trust-ranked endorser pick from R_trusted(t) (Sir Task-4 revision); falls
    // back to uniform random at boot / when disabled (see selector).
    auto sample = select_endorsers_trust_ranked(n_rsus, need, seed);
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
                          uint32_t max_retries,
                          const std::string& submit_identity)
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
        SCResult r = CallSCBootstrapRSU(rsu_idx, pk_hex, h_ku_hex, t_reg,
                                        submit_identity);
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
                                     t_reg, endorsersJSON, submit_identity);
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

// ── G1 evidence/vote signers (global scope) ──────────────────────────────────
// Produce σ over the EXACT strings the Call* wrappers transmit, hashed
// identically to the chaincode digest helpers (smartcontract.go evidenceDigest
// / controllerEvidenceDigest / revokeVoteDigest), signed with the node's
// registered P-256 key. Forward-declared in 06c_blockchain_api.h so the
// wrappers can sign without header-order coupling; defined here because they
// need g_node_ec_keys (populated at SC-Register time). They delegate to the
// namespaced concat_digest / node_sign_hex helpers.

// σ_j^sub (Eq 3.61): RSU `rsuId` signs SHA-256(vehId‖rsuId‖epoch‖psiStr‖beaconHash).
std::string mptd_sign_evidence_hex(const std::string& vehId,
                                   const std::string& rsuId,
                                   const std::string& epoch,
                                   const std::string& psiStr,
                                   const std::string& beaconHash)
{
    return mptd_scregister::node_sign_hex(rsuId,
        mptd_scregister::concat_digest({vehId, rsuId, epoch, psiStr, beaconHash}));
}

// σ_c^sub (Eq 3.62): controller `ctrlId` signs SHA-256(vehId‖ctrlId‖epoch‖phiStr‖beaconHash).
std::string mptd_sign_controller_evidence_hex(const std::string& vehId,
                                              const std::string& ctrlId,
                                              const std::string& epoch,
                                              const std::string& phiStr,
                                              const std::string& beaconHash)
{
    return mptd_scregister::node_sign_hex(ctrlId,
        mptd_scregister::concat_digest({vehId, ctrlId, epoch, phiStr, beaconHash}));
}

// revoke vote sig (Eq 3.63): RSU `rsuId` signs SHA-256(vehId‖rsuId‖reason‖tsStr).
std::string mptd_sign_revoke_vote_hex(const std::string& vehId,
                                      const std::string& rsuId,
                                      const std::string& reason,
                                      const std::string& tsStr)
{
    return mptd_scregister::node_sign_hex(rsuId,
        mptd_scregister::concat_digest({vehId, rsuId, reason, tsStr}));
}

// mptd_active_controller_refresh_loop — self-rescheduling C_trusted refresh.
// Re-reads the on-chain active controller every `period` seconds so node-side
// evidence follows a CP-DETECT reassignment during the run. Queries are
// evaluate-only (no ordering round-trip), so a ~1 Hz cadence is cheap and never
// touches the per-beacon hot path.
static void mptd_active_controller_refresh_loop(double period)
{
    if (skip_blockchain) return;
    uint32_t prev = g_active_controller_idx;
    mptd_refresh_active_controller();
    if (g_active_controller_idx != prev) {
        std::cout << "[C-TRUSTED] active controller reassigned CTRL_" << prev
                  << " → CTRL_" << g_active_controller_idx
                  << " @t=" << Simulator::Now().GetSeconds() << "s\n";
    }
    Simulator::Schedule(Seconds(period),
                        &mptd_active_controller_refresh_loop, period);
}

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
    // BFT fault bound f is FIXED at 1 by framework design (paper
    // tab:set-blockchain: f=1, 2f+1=3, n=4 ring) across ALL deployments — the
    // 64/44/23-RSU grids are mobility-coverage topology, NOT the consensus
    // committee size. The chaincode SCRegister threshold is
    // 2·fByzantine(NumRSUs)+1 = 3 at the default NumRSUs=4, so sending exactly 3
    // endorsers satisfies it. Previously this derived f=(n_rsus-1)/3 locally,
    // which gathered 2f+1=43 endorsers in the urban grid — "selecting [nearly]
    // everyone as peers", the computational waste Sir flagged (2026-06-16).
    const uint32_t f             = 1;
    const uint32_t need_endorsers = 2 * f + 1;   // = 3
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
        if (rsu_idx < MAX_RSUS) {
            h_ku_hex = sha256_hex(g_rsu_ring_key[rsu_idx], LKH_KEY_BYTES);
        } else {
            // Ring-key slots are capped at MAX_RSUS; surface the limit.
            std::cerr << "[SC-REGISTER] " << id
                      << " skipped (rsu_idx >= LKH ring slots)\n";
            continue;
        }
        // P4: bootstrap under this RSU's own enrolled identity (rsu<idx>).
        std::string submit_id = ca_identity_enabled()
                                    ? ("rsu" + std::to_string(rsu_idx)) : "";
        if (register_one(id, "RSU", h_ku_hex, t_reg,
                         n_rsus, /*endorsers=*/0, max_retries, submit_id))
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
        // P4: vehicle leases a pool identity (pool<slot>) for the whole run.
        std::string submit_id = ca_identity_enabled()
                                    ? LeasePoolIdentity(nid) : "";
        if (register_one(id, "VEHICLE", h_ku_hex, t_reg,
                         n_rsus, need_endorsers, max_retries, submit_id)) {
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
        // P4: controller submits under its own enrolled identity (ctrl<idx>).
        std::string submit_id = ca_identity_enabled()
                                    ? ("ctrl" + std::to_string(c)) : "";
        if (register_one(id, "CONTROLLER", h_ku_hex, t_reg,
                         n_rsus, need_endorsers, max_retries, submit_id))
            ctrl_ok++;
    }
    std::cout << "[SC-REGISTER] controllers registered: " << ctrl_ok << "/"
              << N_Controllers << "\n";

    std::cout << "[SC-REGISTER] boot-time registration complete: "
              << rsu_ok << " RSUs + " << veh_ok << " vehicles + "
              << ctrl_ok << " controllers (C_trusted size " << ctrl_ok << ")\n";

    // Seed the active-controller cache from C_trusted's on-chain head so the
    // detection engine submits controller evidence under the authoritative
    // active identity (CTRL_0 initially; advances on CP-DETECT reassignment).
    mptd_refresh_active_controller();
    std::cout << "[C-TRUSTED] active controller = CTRL_"
              << g_active_controller_idx << "\n";

    // Track reassignments during the run (1 Hz, control-path only).
    Simulator::Schedule(Seconds(1.0), &mptd_active_controller_refresh_loop, 1.0);

    // Trust-ranked endorsing-peer selection (Sir Task-4 revision, 2026-06-16):
    // start the periodic committee refresh so the active endorser set tracks the
    // on-chain trust scores as the lifecycle demotes/promotes RSUs at runtime.
    // No-op when trust selection is disabled (A4/ablation) or skip_blockchain.
    if (g_trust_peer_selection) {
        std::cout << "[PEER-SELECT] trust-ranked endorser selection ENABLED "
                  << "(refresh every " << g_committee_refresh_interval << "s)\n";
        Simulator::Schedule(Seconds(g_committee_refresh_interval),
                            &refresh_endorsement_committee);
    } else {
        std::cout << "[PEER-SELECT] trust-ranked selection DISABLED "
                  << "— uniform random endorsers (ablation)\n";
    }
}

// ── mptd_export_blockchain_evidence() — paper §3.5.5 audit-trail dump ─────────
// Run ONCE after Simulator::Destroy(), before process exit. Queries the
// committed ledger for every authoritative on-chain artifact and writes a
// single consolidated JSON evidence file. This is the off-line audit trail the
// paper's trust/revocation analysis (Eq 3.55–3.63) is computed from, and the
// hand-off point for Hyperledger Explorer (which reads the same ledger) and
// IPFS (which holds the off-chain raw beacons referenced by h(b_i(t))).
//
// Each section is the RAW chaincode JSON response (the GetAll* queries return
// JSON arrays via contractapi marshalling), embedded verbatim so the file is a
// faithful snapshot of ledger state — no lossy C++ re-parsing. The queries are
// evaluate-only (no ordering round-trip) so this is safe to run post-Destroy
// against the still-live Fabric peers.
//
// Sections (paper mapping):
//   registrations          — SC-Register identities (Alg 7, Eq 3.63)
//   active_controller       — current head of C_trusted (Eq 3.1/3.60)
//   trusted_controllers     — full C_trusted set incl. EXCLUDED members
//   controller_reassignments— CP-DETECT exclusions (Eq 3.64–3.67, invariant 2)
//   controller_flags        — CP-DETECT f+1 conflict flags
//   trust_scores            — SC-Trust EMA τ_i(t) (Eq 3.55/3.59)
//   revoke_records          — SC-Revoke 2f+1 commits = the CRL (Eq 3.58/3.61)
static void mptd_export_blockchain_evidence(const std::string& out_path)
{
    if (skip_blockchain) {
        std::cout << "[BC-EXPORT] skip_blockchain=true — no on-chain evidence to export\n";
        return;
    }

    // Query helper: returns the raw JSON payload, or "null"/"[]" defaults so the
    // emitted file is always valid JSON even when a query fails or is empty.
    auto q = [](const std::string& fn,
                const std::vector<std::string>& args,
                const std::string& empty_default) -> std::string {
        std::string out = mptd_fabric_invoke_sync("query", fn, args);
        // Trim whitespace; treat an empty/whitespace reply as the default.
        size_t a = out.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) return empty_default;
        size_t b = out.find_last_not_of(" \t\r\n");
        return out.substr(a, b - a + 1);
    };

    const std::string active     = q("GetActiveController",        {}, "\"\"");
    const std::string trustedCs  = q("GetTrustedControllers",      {}, "[]");
    const std::string reassigns  = q("GetControllerReassignments", {}, "[]");
    const std::string flags      = q("GetAllControllerFlags",      {}, "[]");
    const std::string regs       = q("GetAllRegistrations",        {}, "[]");
    const std::string trust      = q("GetAllTrustScores",          {}, "[]");
    const std::string revokes    = q("GetAllRevokeRecords",        {}, "[]");

    std::ofstream f(out_path, std::ios::trunc);
    if (!f.is_open()) {
        std::cerr << "[BC-EXPORT] FATAL: cannot open " << out_path << " for writing\n";
        return;
    }
    f << "{\n";
    f << "  \"exported_at_sim_seconds\": " << Simulator::Now().GetSeconds() << ",\n";
    f << "  \"n_rsus\": "        << N_RSUs        << ",\n";
    f << "  \"n_vehicles\": "    << N_Vehicles    << ",\n";
    f << "  \"n_controllers\": " << N_Controllers << ",\n";
    f << "  \"active_controller\": "        << active    << ",\n";
    f << "  \"trusted_controllers\": "      << trustedCs << ",\n";
    f << "  \"controller_reassignments\": " << reassigns << ",\n";
    f << "  \"controller_flags\": "         << flags     << ",\n";
    f << "  \"registrations\": "            << regs      << ",\n";
    f << "  \"trust_scores\": "             << trust     << ",\n";
    f << "  \"revoke_records\": "           << revokes   << "\n";
    f << "}\n";
    f.close();

    std::cout << "[BC-EXPORT] on-chain evidence written → " << out_path << "\n";
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
    for (uint32_t j = 0; j < N_Vehicles; j++) {  // active count, not capacity
        cout << "For " << j << "th node, tp_vehicle attack state is "         << tp_vehicle_nodes[j]        << endl;
        cout << "For " << j << "th node, heading_spoof attack state is "     << heading_spoof_nodes[j]     << endl;
        cout << "For " << j << "th node, rsu_fabrication attack state is "   << rsu_fabrication_nodes[j]   << endl;
        cout << "For " << j << "th node, sybil_mitm attack state is "        << sybil_mitm_nodes[j]        << endl;
        cout << "For " << j << "th node, beacon_suppression attack state is " << beacon_suppression_nodes[j] << endl;
        cout << "Node " << j << " controller ID " << node_controller_ID[j] << endl;
    }
}

#endif // MPTD_PQS_BLOCKCHAIN_SETUP_H
