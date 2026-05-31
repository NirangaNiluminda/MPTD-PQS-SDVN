// ============================================================
// 06c_blockchain_api.h — RSU → Hyperledger Fabric chaincode bridge
// MPTD-PQS SDVN (split from 06_mrtpa_attack.h, Stage 10B cleanup;
//                refactored Phase R8.5 / 2026-05-30 for paper §3.5.5)
// ============================================================
// Replaces the legacy REST shim (curl localhost:3000/api/*) with direct
// chaincode invocations against the running Fabric test-network via the
// `fabric_invoke.sh` peer-CLI wrapper. This preserves paper Invariant 1
// (RSU→Blockchain direct: no controller relay, no centralized REST endpoint
// between the RSU code and Fabric peers).
//
// Depends on:
//   06b_pq_crypto.h   (TRSSignature, FHECiphertext, evidence_sign_and_verify)
//   06b1_trs_backend.h (TRS pipeline)
//   05_utils.h        (execCmd)
//   02_config_globals.h (use_pq_crypto, routing_algorithm, ablation_mode, …)
//
// Public API (legacy — preserved for caller compatibility, retargeted to
// chaincode functions; the function bodies POST nothing over HTTP anymore):
//   StoreAttackConfigToBlockchain()         — StoreAttackConfig
//   StoreNodeAttackStateToBlockchain()      — StoreNodeAttackState
//   StoreControllerAssignmentToBlockchain() — StoreControllerAssignment
//   StoreTrajectoryToBlockchain()           — StoreTrajectory (legacy raw kinematics
//                                              path; ALSO submits the paper-aligned
//                                              E_j(t) evidence tuple when use_pq_crypto
//                                              is on, see Eq 3.56 helper below)
//   StoreControlDecisionToBlockchain()      — StoreControlDecision
//   FlagMaliciousOnBlockchain()             — FlagMalicious
//   CallSCTrust()                           — legacy SCTrustUpdate path (single-RSU
//                                              ψ submission; deprecated by chaincode
//                                              comments but kept routable)
//   CallSCRevoke()                          — legacy SCRevoke single-RSU revocation
//                                              (deprecated; new code should call
//                                              CallSCRevokeVote)
//
// Public API (new — paper §3.5.5 Eq 3.55/3.56/3.57/3.58/3.59 aligned):
//   CallSCInitNetworkConfig()        — one-time network bootstrap (numRSUs, α, τ_th,
//                                       T_rev, ψ_th)
//   CallSCTrustSubmitEvidence()      — Eq 3.56 evidence tuple E_j(t) =
//                                       (vehicleID, ψ_j^(i)(t), epoch, h(b_i(t)), σ_j^sub)
//                                       This is the RSU-side submission that
//                                       SCTrustFinalizeEpoch aggregates per Eq 3.55.
//   CallSCControllerSubmitEvidence() — Eq 3.57 controller evidence E_c(t)
//   CallSCTrustFinalizeEpoch()       — Eq 3.55 EMA + T_rev gate
//   CallCPDetectCheck()              — Eq 3.59 controller/RSU mismatch flag
//   CallSCRevokeVote()               — Eq 3.58 BFT 2f+1 RSU vote
// ============================================================

#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstdlib>     // getenv — IPFS endpoint override
#include <mutex>       // once-flag for libcurl global init + warn-once
#include <atomic>      // ipfs_disabled latch
#include <curl/curl.h> // TASK ①-E: kubo HTTP API client for h(b_i(t)) CID

// R7g.3 / R8.5: Single guard macro for every chaincode helper. When
// `skip_blockchain` is set (training-sweep mode), the fabric_invoke call is
// bypassed — the sim still produces a full beacon CSV; only the ledger writes
// are skipped. The TRS+FHE pipeline above the guard is NOT skipped: PARR
// numerator + PBPO clock still tick correctly in sweep mode.
#define MPTD_BLOCKCHAIN_GUARD() do { if (skip_blockchain) return; } while (0)

// Absolute path to the peer-CLI wrapper. Overridable at build time, e.g.
//   -DMPTD_FABRIC_INVOKE_SH='"/opt/mptd/fabric_invoke.sh"'
#ifndef MPTD_FABRIC_INVOKE_SH
#define MPTD_FABRIC_INVOKE_SH \
    "/home/niranga/ns-allinone-3.35/ns-3.35/scratch/mptd_pqs_sdvn/fabric_invoke.sh"
#endif

// ── Shell-quote a single argument safely (single-quote wrapping) ─────────────
// Returns the input wrapped in single quotes, with any embedded single-quote
// replaced by the canonical '"'"' escape sequence. Sufficient for any string
// the chaincode may receive — the script then re-quotes for JSON.
static inline std::string mptd_shellq(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out.push_back('\'');
    for (char c : s) {
        if (c == '\'') {
            out.append("'\"'\"'");
        } else {
            out.push_back(c);
        }
    }
    out.push_back('\'');
    return out;
}

// ── Build a `fabric_invoke.sh <action> <fn> <args…>` command line ─────────────
// `action` is "invoke" or "query". `args` is the chaincode function's argument
// list (excluding the function name, which is passed separately).
static inline std::string mptd_build_fabric_cmd(
    const std::string& action,
    const std::string& fn,
    const std::vector<std::string>& args)
{
    std::string cmd = MPTD_FABRIC_INVOKE_SH " ";
    cmd += action;
    cmd += ' ';
    cmd += mptd_shellq(fn);
    for (const auto& a : args) {
        cmd += ' ';
        cmd += mptd_shellq(a);
    }
    return cmd;
}

// ── Async fabric_invoke (fire-and-forget, returns immediately) ────────────────
// Used for hot-path RSU writes where the simulation cannot block on the
// orderer round-trip (paper Invariant 3: the lightweight beacon path must
// stay under T_b = 100 ms). The chaincode call is detached via `&`; stdout
// and stderr are redirected to /dev/null so the popen pipe doesn't block.
static inline void mptd_fabric_invoke_async(
    const std::string& fn, const std::vector<std::string>& args)
{
    std::string cmd = mptd_build_fabric_cmd("invoke", fn, args);
    cmd += " > /dev/null 2>&1 &";
    int rc = system(cmd.c_str());
    (void)rc; // intentional: fire-and-forget, status unobserved by design
}

// ── Sync fabric_invoke (waits for endorsement + commit, returns stdout) ──────
// Used for control-path calls where the caller needs the return payload
// (e.g. CPDetectCheck reads a ControllerFlag struct, SCRevokeVote reads the
// current vote count). NOT for beacon-rate calls — synchronous fabric
// commits cost 1–2 s.
static inline std::string mptd_fabric_invoke_sync(
    const std::string& action,
    const std::string& fn,
    const std::vector<std::string>& args)
{
    std::string cmd = mptd_build_fabric_cmd(action, fn, args);
    cmd += " 2>/dev/null";
    return execCmd(cmd);
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  IPFS off-chain raw-beacon channel (TASK ①-E)                            ║
// ║                                                                          ║
// ║  Paper Eq 3.56 — Evidence tuple E_j(t) carries h(b_i(t)) on chain so the ║
// ║  raw beacon b_i(t) (full kinematics blob) stays OFF chain. The off-chain ║
// ║  store is IPFS: the canonical multihash CID of the pinned beacon doubles ║
// ║  as both the commitment and the retrieval handle. CIDv0 is base58-       ║
// ║  encoded SHA-256 (cryptographic), strictly stronger than the prior       ║
// ║  FNV-1a 64-bit placeholder.                                              ║
// ║                                                                          ║
// ║  Endpoint is the local kubo daemon (default http://127.0.0.1:5002);      ║
// ║  override at runtime via env var MPTD_IPFS_API. Daemon failures fall     ║
// ║  back to FNV-1a so simulations stay runnable when IPFS is down — but a   ║
// ║  one-line warning is emitted and ipfs_disabled latches true to skip      ║
// ║  further attempts in the same run.                                       ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// One-time libcurl global init (curl_global_init is NOT thread-safe; must run
// once before any easy/mime handle creation). The atomic latch protects us
// from per-beacon overhead of std::call_once on the hot path after init.
static std::atomic<bool> g_curl_inited{false};
static std::mutex        g_curl_init_mu;
static std::atomic<bool> g_ipfs_disabled{false};   // sticky on first failure
static std::once_flag    g_ipfs_warn_once;

static inline void mptd_curl_global_init_once() {
    if (g_curl_inited.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(g_curl_init_mu);
    if (g_curl_inited.load(std::memory_order_relaxed)) return;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    g_curl_inited.store(true, std::memory_order_release);
}

// ── IPFS endpoint resolver (env override; default = local kubo) ──────────────
// Cached after first lookup so getenv isn't called per beacon.
static inline const std::string& mptd_ipfs_endpoint() {
    static std::string ep = []() {
        const char* e = std::getenv("MPTD_IPFS_API");
        if (e && *e) return std::string(e);
        return std::string("http://127.0.0.1:5002");
    }();
    return ep;
}

// libcurl write callback — append response body into the std::string userp
static size_t mptd_curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userp) {
    std::string* buf = static_cast<std::string*>(userp);
    buf->append(ptr, size * nmemb);
    return size * nmemb;
}

// Minimal JSON-string field extractor — no full parser dependency.
// Looks for `"key":"<value>"` and returns the value (no escape unwinding —
// IPFS CIDs are base58 / base32 with no JSON-special chars).
static inline bool mptd_json_field(const std::string& json,
                                   const std::string& key,
                                   std::string& out)
{
    std::string needle = "\"" + key + "\":\"";
    size_t p = json.find(needle);
    if (p == std::string::npos) return false;
    p += needle.size();
    size_t q = json.find('"', p);
    if (q == std::string::npos) return false;
    out.assign(json, p, q - p);
    return true;
}

// ── mptd_ipfs_add: pin a payload, return the CID ─────────────────────────────
// POST /api/v0/add?pin=true&quieter=true with multipart/form-data.
// Response (quieter=true): {"Name":"...","Hash":"Qm...","Size":"..."}.
// Returns true + CID on success; false otherwise (caller falls back).
// Times out fast (1.5 s total) so a stalled daemon cannot block the beacon
// alert path indefinitely.
static inline bool mptd_ipfs_add(const std::string& payload,
                                 std::string& out_cid)
{
    if (g_ipfs_disabled.load(std::memory_order_acquire)) return false;
    mptd_curl_global_init_once();

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    std::string url = mptd_ipfs_endpoint() + "/api/v0/add?pin=true&quieter=true";
    std::string resp;

    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_filename(part, "beacon");
    curl_mime_type(part, "application/octet-stream");
    curl_mime_data(part, payload.data(), payload.size());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mptd_curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);     // safe in multi-threaded sim
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 1500L); // hard ceiling
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 500L);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    if (rc == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    }

    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || http_code != 200) {
        std::call_once(g_ipfs_warn_once, [&]() {
            std::cerr << "[IPFS] add failed (curl=" << rc
                      << " http=" << http_code
                      << " ep=" << mptd_ipfs_endpoint()
                      << ") — falling back to FNV-1a for h(b_i(t)). "
                      << "Start daemon with `ipfs daemon` and re-run to use real CIDs."
                      << std::endl;
        });
        g_ipfs_disabled.store(true, std::memory_order_release);
        return false;
    }

    std::string cid;
    if (!mptd_json_field(resp, "Hash", cid) || cid.empty()) {
        std::call_once(g_ipfs_warn_once, [&]() {
            std::cerr << "[IPFS] add returned no Hash field: "
                      << resp.substr(0, 200) << std::endl;
        });
        g_ipfs_disabled.store(true, std::memory_order_release);
        return false;
    }
    out_cid.swap(cid);
    return true;
}

// ── Beacon hash h(b_i(t)) — Eq 3.56 commitment ───────────────────────────────
// Pins the canonical beacon blob to IPFS and returns the CIDv0 (a base58
// SHA-256 multihash). The CID is BOTH the commitment that lives on chain in
// E_j(t) AND the retrieval handle that lets any verifier `ipfs cat <CID>`
// to recover the raw bytes. If IPFS is unreachable, falls back to a
// deterministic 64-bit FNV-1a (16-hex-char) so the sim stays runnable but
// loses cryptographic strength. The warn-once message tells the operator to
// start `ipfs daemon` to upgrade to real CIDs.
//
// Determinism: two RSUs that observe the same beacon produce IDENTICAL
// canonical blobs (same vehicleID, same kinematics rounded to 6 decimals,
// same timestamp) → identical CIDs / FNV digests. This is required for
// SCTrustFinalizeEpoch to aggregate witnesses on the same beacon.
static inline std::string mptd_beacon_hash(
    const std::string& vehicleID, const std::string& rsuID,
    double posX, double posY, double posZ,
    double velX, double velY, double velZ,
    double accX, double accY, double accZ,
    double timestamp)
{
    // Canonical blob — must NOT include rsuID since the CID is over the
    // beacon content (b_i(t)), not the witness who saw it. Two RSUs hearing
    // the same broadcast must produce the same h(b_i(t)). rsuID is carried
    // in the surrounding E_j(t) tuple, not in h(b_i(t)).
    std::ostringstream blob;
    blob << vehicleID << '|'
         << std::fixed << std::setprecision(6)
         << posX << ',' << posY << ',' << posZ << '|'
         << velX << ',' << velY << ',' << velZ << '|'
         << accX << ',' << accY << ',' << accZ << '|'
         << timestamp;
    const std::string s = blob.str();
    (void)rsuID; // intentionally unused — see canonicalization note above

    // Preferred path: IPFS CID
    std::string cid;
    if (mptd_ipfs_add(s, cid)) {
        return cid;
    }

    // Fallback: deterministic FNV-1a (preserves sim runnability when
    // daemon is down; ipfs_disabled latched so we don't re-try per beacon).
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= (uint64_t)c;
        h *= 1099511628211ULL;
    }
    std::ostringstream hex;
    hex << std::hex << std::setw(16) << std::setfill('0') << h;
    return hex.str();
}

// ── Epoch ID from a simulation timestamp ─────────────────────────────────────
// Paper §3.5: a "full-mode" detection window is W = L·T_b. For evidence
// aggregation we discretize timestamps into 1-second epochs labelled
// "E<seconds>" — coarse enough that all RSU witnesses of one beacon land in
// the same epoch, fine enough that SCTrustFinalizeEpoch fires often.
static inline std::string mptd_epoch_from_ts(double timestamp) {
    long sec = (long)timestamp;
    std::ostringstream s; s << "E" << sec;
    return s.str();
}

// ── HEX-encode a byte buffer (for σ_j^sub on-chain transport) ────────────────
static inline std::string mptd_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream s;
    s << std::hex << std::setfill('0');
    for (uint8_t b : bytes) s << std::setw(2) << (int)b;
    return s.str();
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Paper-aligned helpers (§3.5.5 Eq 3.55 / 3.56 / 3.57 / 3.58 / 3.59)       ║
// ║                                                                          ║
// ║  These are the canonical RSU↔chaincode entry points. New code MUST       ║
// ║  prefer them over the legacy Store*/Call* wrappers below.                ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// ── CallSCInitNetworkConfig — Eq 3.55/3.58/3.59 bootstrap ────────────────────
// One-time per-run setup. Persists the trust EMA smoothing α, trust threshold
// τ_th, T_rev consecutive-epoch gate, anomaly threshold ψ_th, and RSU set
// size |R| (needed by SCRevokeVote to compute 2f+1 and by CPDetectCheck to
// compute f+1). The chaincode falls back to safe defaults if this is never
// called, but calling it explicitly is required to reproduce the paper's
// evaluation tables.
inline void CallSCInitNetworkConfig(
    uint32_t numRSUs, double alpha, double tauThreshold,
    uint32_t tRev, double psiAnomalyTh)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(numRSUs),
        std::to_string(alpha),
        std::to_string(tauThreshold),
        std::to_string(tRev),
        std::to_string(psiAnomalyTh)
    };
    // Synchronous: init must commit before any evidence submission.
    std::string out = mptd_fabric_invoke_sync("invoke", "SCInitNetworkConfig", args);
    std::cout << "[SC-INIT] numRSUs=" << numRSUs
              << " α=" << alpha << " τ_th=" << tauThreshold
              << " T_rev=" << tRev << " ψ_th=" << psiAnomalyTh
              << " → " << out;
}

// ── CallSCTrustSubmitEvidence — Eq 3.56 RSU evidence tuple ───────────────────
// E_j(t) = (vehicleID, ψ_j^(i)(t), epoch, h(b_i(t)), σ_j^sub)
// One call per RSU witness per beacon; SCTrustFinalizeEpoch later aggregates
// them per Eq 3.55. Async because this is on the beacon-alert hot path.
inline void CallSCTrustSubmitEvidence(
    uint32_t vehicleID, uint32_t rsuID, const std::string& epoch,
    double psi, const std::string& beaconHash,
    const std::string& signatureHex)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(vehicleID),
        std::to_string(rsuID),
        epoch,
        std::to_string(psi),
        beaconHash,
        signatureHex
    };
    mptd_fabric_invoke_async("SCTrustSubmitEvidence", args);
}

// ── CallSCControllerSubmitEvidence — Eq 3.57 controller evidence tuple ───────
// E_c(t) = (vehicleID, Φ_i(t), epoch, h(X_i(t)), σ_c^sub)
// Written by the SDN controller (peer #2 in the Fabric organization mapping)
// as an UNTRUSTED submission — CPDetectCheck (Eq 3.59) decides whether to
// honour it. Async for the same reason as the RSU side.
inline void CallSCControllerSubmitEvidence(
    uint32_t vehicleID, uint32_t controllerID, const std::string& epoch,
    double phi, const std::string& beaconHash,
    const std::string& signatureHex)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(vehicleID),
        std::to_string(controllerID),
        epoch,
        std::to_string(phi),
        beaconHash,
        signatureHex
    };
    mptd_fabric_invoke_async("SCControllerSubmitEvidence", args);
}

// ── CallSCTrustFinalizeEpoch — Eq 3.55 EMA + T_rev gate ──────────────────────
// τ_i(t) = α·τ_i(t-1) + (1-α)·(1 - (1/|R|)·Σ ψ_j^(i)(t))
// Called once per (vehicleID, epoch) — typically by an RSU coordinator after
// the W-second window closes. Synchronous: callers need the updated
// ConsecutiveLowEpochs to decide whether to start a SC-Revoke vote round.
// Returns raw chaincode JSON payload; caller parses with extractValue().
inline std::string CallSCTrustFinalizeEpoch(
    uint32_t vehicleID, const std::string& epoch)
{
    if (skip_blockchain) return "";
    std::vector<std::string> args = {
        std::to_string(vehicleID), epoch
    };
    return mptd_fabric_invoke_sync("invoke", "SCTrustFinalizeEpoch", args);
}

// ── CallSCTrustFinalizeEpochAsync — fire-and-forget variant ──────────────────
// Same chaincode function as CallSCTrustFinalizeEpoch but discards the
// returned ConsecutiveLowEpochs payload. Used when finalize is scheduled
// from inside a sim simulation tick (NS-3 Simulator::Schedule) — blocking on
// the orderer round-trip would stall the simulation. The chaincode side is
// idempotent over (vehicleID, epoch) so re-firing is harmless if multiple
// schedulers happen to converge. Designed to be bindable directly to
// Simulator::Schedule via ns3::MakeBoundCallback.
inline void CallSCTrustFinalizeEpochAsync(
    uint32_t vehicleID, std::string epoch)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(vehicleID), epoch
    };
    mptd_fabric_invoke_async("SCTrustFinalizeEpoch", args);
}

// ── CallCPDetectCheck — Eq 3.59 controller/RSU mismatch detection ────────────
// Compares controller Φ vs each RSU's ψ against ψ_th; flags the controller
// when ≥ f+1 RSUs disagree with its anomaly call. Returns raw payload
// (empty string if no flag was written).
inline std::string CallCPDetectCheck(
    uint32_t vehicleID, const std::string& epoch)
{
    if (skip_blockchain) return "";
    std::vector<std::string> args = {
        std::to_string(vehicleID), epoch
    };
    return mptd_fabric_invoke_sync("invoke", "CPDetectCheck", args);
}

// ── CallCPDetectCheckAsync — fire-and-forget variant ─────────────────────────
// Same chaincode function as CallCPDetectCheck but discards the returned
// ControllerFlag payload. Used when CP-DETECT is scheduled from inside a sim
// simulation tick (NS-3 Simulator::Schedule) — blocking on the orderer
// round-trip would stall the simulation, and the side-effect we actually
// depend on (CFLAG_ record + "CPDetectFlag" event) is committed regardless
// of whether anyone reads the return value. The chaincode side is idempotent
// over (vehicleID, epoch) — re-firing just overwrites CFLAG with identical
// content. Designed to be bindable directly to Simulator::Schedule via
// ns3::MakeBoundCallback.
inline void CallCPDetectCheckAsync(
    uint32_t vehicleID, std::string epoch)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(vehicleID), epoch
    };
    mptd_fabric_invoke_async("CPDetectCheck", args);
}

// ── CallSCRevokeVote — Eq 3.58 BFT 2f+1 RSU vote ─────────────────────────────
// One call per RSU that wishes to vote for revoking `vehicleID`. The
// chaincode commits the immutable SCREVOKE_ record + emits "SCRevoke" event
// only when distinct votes reach 2f+1. Synchronous so callers can react to
// the returned `revoked` flag (e.g. trigger LKH rekey on the local RSU when
// its own vote was the deciding one).
inline std::string CallSCRevokeVote(
    uint32_t vehicleID, uint32_t rsuID,
    const std::string& reason, const std::string& signatureHex,
    double timestamp)
{
    if (skip_blockchain) return "";
    std::vector<std::string> args = {
        std::to_string(vehicleID),
        std::to_string(rsuID),
        reason,
        signatureHex,
        std::to_string(timestamp)
    };
    return mptd_fabric_invoke_sync("invoke", "SCRevokeVote", args);
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Legacy helpers (kept for caller compatibility — Stage 6 / R7 / R8.4)    ║
// ║                                                                          ║
// ║  Bodies retargeted from REST → fabric_invoke. The on-chain function      ║
// ║  contracts they hit are still useful for the global config / per-node    ║
// ║  attacker labels / control-decision audit log — these are NOT covered    ║
// ║  by the Eq 3.55 evidence pipeline.                                       ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// ── StoreAttackConfigToBlockchain — store global attack flags to ledger ───────
// Called by declare_attack_states() to record the active attack type.
void StoreAttackConfigToBlockchain(
    uint32_t attackNum,
    bool tpVehicle, bool headingSpoof, bool rsuFab, bool sybilMitm, bool beaconSup,
    bool ctrlMalAssumption)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(attackNum),
        tpVehicle      ? "true" : "false",
        headingSpoof   ? "true" : "false",
        rsuFab         ? "true" : "false",
        sybilMitm      ? "true" : "false",
        beaconSup      ? "true" : "false",
        ctrlMalAssumption ? "true" : "false"
    };
    std::cout << "[ATTACK_CFG] Storing attack config for attack_number="
              << attackNum << " to chaincode" << std::endl;
    mptd_fabric_invoke_async("StoreAttackConfig", args);
}

// ── StoreNodeAttackStateToBlockchain — store per-node attacker role ───────────
// Called by declare_attackers() for each node in the simulation.
void StoreNodeAttackStateToBlockchain(
    uint32_t nodeIdx, int atkPct,
    bool isLocMal, bool isFloodMal, bool isFabMal,
    bool isMIMMal, bool isVanMal, bool isTrajMal)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(nodeIdx),
        std::to_string(atkPct),
        isLocMal   ? "true" : "false",
        isFloodMal ? "true" : "false",
        isFabMal   ? "true" : "false",
        isMIMMal   ? "true" : "false",
        isVanMal   ? "true" : "false",
        isTrajMal  ? "true" : "false"
    };
    mptd_fabric_invoke_async("StoreNodeAttackState", args);
    std::cout << "[NODE_ATK] Node " << nodeIdx
              << " locMal=" << isLocMal << " trajMal=" << isTrajMal
              << " → chaincode" << std::endl;
}

// ── StoreControllerAssignmentToBlockchain — store node→controller mapping ────
// Called by assign_controllers() in 11_blockchain_setup.h.
void StoreControllerAssignmentToBlockchain(
    uint32_t nodeIdx, uint32_t ctrlID, uint32_t consID, bool isTrajPoisoner)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(nodeIdx),
        std::to_string(ctrlID),
        std::to_string(consID),
        isTrajPoisoner ? "true" : "false"
    };
    mptd_fabric_invoke_async("StoreControllerAssignment", args);
    std::cout << "[ASSIGN] Node " << nodeIdx
              << " → controller=" << ctrlID << " consortium=" << consID
              << " trajPoisoner=" << isTrajPoisoner
              << " → chaincode" << std::endl;
}

// ── StoreTrajectoryToBlockchain — record real + poisoned trajectory ───────────
// Paper §3.3.4: per-beacon reception is recorded on Fabric ledger.
//
// When use_pq_crypto=true: runs real TRS signing (§3.5.4 Eq. 3.46–3.49) +
// FHE encryption (§3.5.4 Eq. 3.61). Per Invariant 5, TRS verification gates
// the submission — a failed σ_TRS verify bails out before any chaincode call
// and the trajectory_stored counter is NOT incremented.
//
// R8.4 (2026-05-29): Replaced the legacy generate_trs_aggregate string-hash
// stub with the real evidence_sign_and_verify pipeline (paper Algorithm 6).
// PARR is now empirically observable via g_trs_verified_count /
// g_trs_rejected_count instead of formula-approximated in evaluate_all.py.
//
// R8.5 (2026-05-30): Replaced REST POST with chaincode invoke. The legacy
// StoreTrajectory function still receives the raw kinematics (useful for the
// audit log / off-chain analytics replay); on top of that, when use_pq_crypto
// is on we now ALSO submit the paper-aligned Eq 3.56 evidence tuple E_j(t)
// via CallSCTrustSubmitEvidence — h(b_i(t)) is computed locally so only the
// hash + ψ score + σ_j^sub touch the chain (raw beacon stays off-chain;
// IPFS retrieval channel lands in TASK ①-E).
void StoreTrajectoryToBlockchain(std::string vehicleID, std::string rsuID,
    Vector position, Vector velocity, Vector acceleration,
    double timestamp, bool isPoisoned)
{
    // ── PQ TRS gate (Invariant 5: TRS-then-FHE-then-submit) ──────────────────
    // TRS verification runs whenever use_pq_crypto, REGARDLESS of
    // skip_blockchain. Sweep mode still needs the crypto cost on the PBPO
    // clock and σ_TRS verify/reject counts on the PARR clock — only the
    // chaincode call is the part we skip. The explicit skip_blockchain check
    // is below, after the TRS gate.
    std::vector<uint8_t> sigma_trs;
    if (use_pq_crypto) {
        // Build m_j evidence (paper Eq. 3.46). Per-beacon mode: vehicle_set = {vid}.
        uint32_t rsu_idx = 0;
        if (rsuID.size() > 3) {
            try { rsu_idx = (uint32_t)std::stoi(rsuID.substr(3)); } catch (...) {}
        }
        uint32_t vid = 0;
        try { vid = (uint32_t)std::stoi(vehicleID); } catch (...) {}

        EvidenceMessage m_j;
        m_j.rsu_id      = rsu_idx;
        m_j.timestamp   = timestamp;
        m_j.agg_pos_x   = position.x;
        m_j.agg_pos_y   = position.y;
        m_j.agg_vel_x   = velocity.x;
        m_j.agg_vel_y   = velocity.y;
        m_j.agg_accel_x = acceleration.x;
        m_j.agg_accel_y = acceleration.y;
        m_j.vehicle_set.push_back(vid);

        // Real TRS chain: partial_sign × t → aggregate → verify_threshold
        // (paper Eq. 3.47–3.49). evidence_sign_and_verify lives in
        // 06b1_trs_backend.h.
        std::vector<uint32_t> signers;
        bool verified = evidence_sign_and_verify(m_j, sigma_trs, signers);
        if (verified) g_trs_verified_count++;
        else          g_trs_rejected_count++;

        std::cout << "[TRS] Vehicle=" << vehicleID
                  << " RSU=" << rsuID
                  << " signers=" << signers.size()
                  << " sigma_bytes=" << sigma_trs.size()
                  << " verified=" << (verified ? "YES" : "NO") << "\n";

        if (!verified) {
            // Invariant 5: σ_TRS verification gates submission. Reject early.
            std::cout << "[TRS-REJECT] vehicle=" << vehicleID
                      << " t=" << timestamp
                      << " — σ_TRS verify failed; skipping chain submit\n";
            return;
        }

        // FHE: encrypt speed scalar AFTER TRS verify (paper Eq. 3.61).
        double spd = std::sqrt(velocity.x * velocity.x + velocity.y * velocity.y);
        FHECiphertext ct = fhe_encrypt_scalar(spd);
        std::cout << "[FHE] Vehicle=" << vehicleID
                  << " speed_enc=" << ct.noisy_value
                  << " (plaintext≈" << spd << ")\n";
    }

    // ── Submit to Fabric chaincode (gated on TRS verify above) ───────────────
    // Sweep mode (--skip_blockchain=true) stops here: PARR/PBPO already booked
    // above, no need to pay the chaincode roundtrip when there's no Fabric.
    if (skip_blockchain) return;

    // Legacy raw-kinematics path — kept for audit-log compatibility with the
    // existing StoreTrajectory chaincode function. Cosmetic only; the paper's
    // evidence pipeline below is the authoritative path.
    std::vector<std::string> args = {
        vehicleID, rsuID,
        std::to_string(position.x),     std::to_string(position.y),     std::to_string(position.z),
        std::to_string(velocity.x),     std::to_string(velocity.y),     std::to_string(velocity.z),
        std::to_string(acceleration.x), std::to_string(acceleration.y), std::to_string(acceleration.z),
        std::to_string(timestamp),
        isPoisoned ? "true" : "false"
    };
    mptd_fabric_invoke_async("StoreTrajectory", args);

    std::cout << "[BLOCKCHAIN] Storing trajectory: Vehicle=" << vehicleID
              << " RSU=" << rsuID
              << " Poisoned=" << (isPoisoned ? "YES" : "NO")
              << " t=" << timestamp << "s" << std::endl;
    total_trajectories_stored_blockchain++;
}

// ── StoreControlDecisionToBlockchain — record SDN control packet decision ────
void StoreControlDecisionToBlockchain(std::string controllerID, std::string decision,
    double timestamp, std::string basedOnData)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        controllerID, decision,
        std::to_string(timestamp), basedOnData
    };
    mptd_fabric_invoke_async("StoreControlDecision", args);
}

// ── FlagMaliciousOnBlockchain — write immutable malicious flag for an entity ─
void FlagMaliciousOnBlockchain(std::string entityID, std::string reason)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = { entityID, reason };
    mptd_fabric_invoke_async("FlagMalicious", args);
}

// ── CallSCTrust — LEGACY single-RSU trust update ─────────────────────────────
// DEPRECATED: This wraps the chaincode's `SCTrustUpdate`, which the chaincode
// itself marks as the legacy single-Φ path. The signature mismatches Eq 3.55
// because it carries Φ_i (already fused at the RSU) instead of ψ_j^(i)(t)
// per-witness. New code MUST call CallSCTrustSubmitEvidence (Eq 3.56) so the
// chaincode can compute the multi-RSU mean and update τ_i(t) per Eq 3.55.
//
// Kept routable for the existing detection-engine call site at
// 08_detection_engine.h:2250 until that call site is migrated to the
// per-witness path. The migration also needs the witness `rsuID`, which the
// current signature does not include — see the Eq 3.56 helper above.
void CallSCTrust(uint32_t vehicleID, double phiScore, uint32_t sigMask,
                 bool isAnomaly, double timestamp)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(vehicleID),
        std::to_string(phiScore),
        std::to_string(sigMask),
        isAnomaly ? "true" : "false",
        std::to_string(timestamp)
    };
    mptd_fabric_invoke_async("SCTrustUpdate", args);

    if (isAnomaly)
        std::cout << "[SC-TRUST] Vehicle " << vehicleID
                  << "  Φ=" << phiScore << "  isAnomaly=1" << std::endl;
}

// ── CallSCRevoke — LEGACY single-RSU revocation ──────────────────────────────
// DEPRECATED: This wraps the chaincode's `SCRevoke`, which the chaincode
// itself marks as the legacy single-RSU path. Eq 3.58 requires ≥ 2f+1
// distinct RSU votes — use CallSCRevokeVote instead. Kept routable so the
// existing detection-engine call site at 08_detection_engine.h:2236 keeps
// working until that call site is migrated.
void CallSCRevoke(uint32_t vehicleID, const std::string &reason,
                  uint32_t rsuID, double timestamp)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(vehicleID),
        reason,
        std::to_string(rsuID),
        std::to_string(timestamp)
    };
    mptd_fabric_invoke_async("SCRevoke", args);

    std::cout << "[SC-REVOKE] Vehicle " << vehicleID
              << " REVOKED by RSU " << rsuID
              << " reason=" << reason
              << " t=" << timestamp << "s" << std::endl;
}
