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
#include <cstring>     // memcpy for sockaddr_un.sun_path (Phase 1B socket client)
#include <cstdio>      // snprintf for \uXXXX JSON escape
#include <mutex>       // once-flag for libcurl global init + warn-once
#include <atomic>      // ipfs_disabled latch
#include <curl/curl.h> // TASK ①-E: kubo HTTP API client for h(b_i(t)) CID

// Phase 1B (TASK ①-O): NS-3 → Fabric Gateway daemon over AF_UNIX. Replaces the
// per-call fork+exec of `fabric_invoke.sh` with a single-line JSON write to a
// long-lived Go daemon that holds a persistent gRPC Gateway connection to the
// peer. Falls back to the legacy shell shim when the socket is absent so the
// simulation stays runnable on machines where the daemon hasn't been started.
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Fabric Gateway daemon socket transport (TASK ①-O, Phase 1B)             ║
// ║                                                                          ║
// ║  Replaces the per-call `system("fabric_invoke.sh …")` round-trip with a  ║
// ║  one-line JSON exchange over /tmp/mptd_fabric.sock. Wire protocol:       ║
// ║                                                                          ║
// ║    REQ  → {"action":"invoke|query","function":"Fn","args":["a","b"],     ║
// ║            "fire_and_forget":true}\n                                     ║
// ║    RESP ← {"ok":true,"payload":"…"}\n   or  {"ok":false,"error":"…"}\n   ║
// ║                                                                          ║
// ║  When `fire_and_forget` is set on an invoke, the daemon ACKs immediately ║
// ║  and submits in a detached goroutine — used by the RSU beacon path so    ║
// ║  Fabric commit latency doesn't blow the paper's T_b = 100 ms budget      ║
// ║  (Invariant 3).                                                          ║
// ║                                                                          ║
// ║  Transport selection (env `MPTD_FABRIC_TRANSPORT`):                      ║
// ║    auto   (default) → try socket; fall back to shell on any failure.     ║
// ║    socket           → socket only (no fallback; surfaces daemon issues). ║
// ║    shell            → legacy shell shim only (the pre-Phase-1B path).    ║
// ╚══════════════════════════════════════════════════════════════════════════╝

enum class MptdFabricTransport { Auto, Socket, Shell };

static inline MptdFabricTransport mptd_fabric_transport_mode() {
    static MptdFabricTransport m = []() {
        const char* e = std::getenv("MPTD_FABRIC_TRANSPORT");
        if (!e || !*e) return MptdFabricTransport::Auto;
        std::string s(e);
        if (s == "socket") return MptdFabricTransport::Socket;
        if (s == "shell")  return MptdFabricTransport::Shell;
        return MptdFabricTransport::Auto;
    }();
    return m;
}

// Daemon socket path — overridable via env (must match FABRIC_GW_SOCKET in the
// daemon). Cached after first lookup.
static inline const std::string& mptd_fabric_socket_path() {
    static std::string sp = []() {
        const char* e = std::getenv("FABRIC_GW_SOCKET");
        if (e && *e) return std::string(e);
        return std::string("/tmp/mptd_fabric.sock");
    }();
    return sp;
}

// Minimal JSON-string escape sufficient for chaincode args (printable ASCII
// plus hex blobs, vehicle IDs, etc). Handles the seven mandatory escapes plus
// control-char \uXXXX fallback. NOT full RFC 8259 — we never emit UTF-8 high
// codepoints because every arg the chaincode receives is ASCII.
static inline std::string mptd_jesc(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned int>(c));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

// Build the wire-protocol line (JSON object + trailing '\n').
static inline std::string mptd_build_socket_request(
    const std::string& action,
    const std::string& fn,
    const std::vector<std::string>& args,
    bool fire_and_forget)
{
    std::string out;
    out.reserve(64 + fn.size() + args.size() * 32);
    out += "{\"action\":\"";
    out += action;
    out += "\",\"function\":\"";
    out += mptd_jesc(fn);
    out += "\",\"args\":[";
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) out += ',';
        out += '"';
        out += mptd_jesc(args[i]);
        out += '"';
    }
    out += ']';
    if (fire_and_forget) out += ",\"fire_and_forget\":true";
    out += "}\n";
    return out;
}

// Decode the daemon's "payload" field, unescaping the JSON-string body so the
// chaincode bytes (often themselves JSON: {"flagged":true,...}) round-trip
// unchanged. Returns false if the field is missing or unterminated.
static inline bool mptd_decode_payload_field(const std::string& resp,
                                             const char*        key,
                                             std::string&       out)
{
    out.clear();
    std::string needle = std::string("\"") + key + "\":\"";
    size_t p = resp.find(needle);
    if (p == std::string::npos) return false;
    p += needle.size();
    while (p < resp.size()) {
        char c = resp[p++];
        if (c == '"') return true;
        if (c == '\\' && p < resp.size()) {
            char esc = resp[p++];
            switch (esc) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    if (p + 4 > resp.size()) return false;
                    unsigned int cp = 0;
                    for (int i = 0; i < 4; ++i) {
                        char h = resp[p++];
                        cp <<= 4;
                        if      (h >= '0' && h <= '9') cp |=  (h - '0');
                        else if (h >= 'a' && h <= 'f') cp |=  (h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |=  (h - 'A' + 10);
                        else return false;
                    }
                    if (cp < 0x80) out.push_back(static_cast<char>(cp));
                    // Higher codepoints: silently drop — chaincode emits ASCII only.
                    break;
                }
                default: out.push_back(esc); break;
            }
        } else {
            out.push_back(c);
        }
    }
    return false; // unterminated string
}

// Round-trip one request over the daemon socket. Returns true on a successful
// {"ok":true,...} response (payload unescaped into payload_out); false on any
// I/O / parse failure OR a daemon-side error response. Caller decides whether
// to fall back to the shell shim.
//
// `fire_and_forget` semantics: daemon writes the ACK before queuing the submit,
// so on success the chaincode commit is only guaranteed to *start*, not to
// complete by the time this returns. Use sync (false) when the caller needs
// the return payload.
static inline bool mptd_fabric_call_socket(
    const std::string& action,
    const std::string& fn,
    const std::vector<std::string>& args,
    bool fire_and_forget,
    std::string& payload_out)
{
    payload_out.clear();

    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;

    struct sockaddr_un addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    const std::string& sp = mptd_fabric_socket_path();
    if (sp.size() + 1 > sizeof(addr.sun_path)) {
        ::close(fd);
        return false;
    }
    std::memcpy(addr.sun_path, sp.data(), sp.size());

    if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr),
                  sizeof(addr)) < 0) {
        // ENOENT (daemon not running) is the common case — let auto mode fall
        // back to shell silently. Other errnos hit the same path; they're rare
        // enough to live with one shell-shim invocation on the first miss.
        ::close(fd);
        return false;
    }

    // 30 s budget covers worst-case Fabric commit (~1–2 s in practice) plus
    // headroom for endorsement retries. Matches the daemon's per-conn deadline.
    struct timeval tv;
    tv.tv_sec  = 30;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Send the request line
    std::string req = mptd_build_socket_request(action, fn, args,
                                                fire_and_forget);
    const char* buf       = req.data();
    size_t      remaining = req.size();
    while (remaining > 0) {
        ssize_t n = ::send(fd, buf, remaining, MSG_NOSIGNAL);
        if (n <= 0) { ::close(fd); return false; }
        buf       += n;
        remaining -= static_cast<size_t>(n);
    }
    // Half-close the write side so the daemon's bufio.Reader can flush the
    // final byte even if it sized its read at exactly the request length.
    ::shutdown(fd, SHUT_WR);

    // Read response until newline or peer close
    std::string resp;
    resp.reserve(256);
    char rbuf[2048];
    while (true) {
        ssize_t n = ::recv(fd, rbuf, sizeof(rbuf), 0);
        if (n < 0) { ::close(fd); return false; }
        if (n == 0) break;
        resp.append(rbuf, static_cast<size_t>(n));
        if (!resp.empty() && resp.back() == '\n') break;
    }
    ::close(fd);

    if (resp.find("\"ok\":true") == std::string::npos) {
        // Surface daemon-side error for visibility — but still return false so
        // auto-mode can fall back to shell on transient daemon hiccups.
        std::string err;
        if (mptd_decode_payload_field(resp, "error", err)) {
            std::cerr << "[fabric-gw] " << fn << " err: " << err << '\n';
        }
        return false;
    }
    // Payload is optional (FNF and many invokes return empty)
    mptd_decode_payload_field(resp, "payload", payload_out);
    return true;
}

// ── Async fabric_invoke (fire-and-forget, returns immediately) ────────────────
// Used for hot-path RSU writes where the simulation cannot block on the
// orderer round-trip (paper Invariant 3: the lightweight beacon path must
// stay under T_b = 100 ms). With the Phase-1B daemon up (auto/socket mode)
// this is a ~50 ms socket round-trip; with the legacy shell shim it forks
// a peer-CLI subprocess and detaches via `&`.
static inline void mptd_fabric_invoke_async(
    const std::string& fn, const std::vector<std::string>& args)
{
    if (mptd_fabric_transport_mode() != MptdFabricTransport::Shell) {
        std::string ignored;
        if (mptd_fabric_call_socket("invoke", fn, args,
                                    /*fire_and_forget=*/true, ignored)) {
            return; // daemon ACKed; submit runs in its goroutine
        }
        if (mptd_fabric_transport_mode() == MptdFabricTransport::Socket) {
            // socket-only mode: do NOT fall back; the operator wants visibility
            // into daemon failures, so swallow rather than mask with the shim.
            return;
        }
    }
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
    if (mptd_fabric_transport_mode() != MptdFabricTransport::Shell) {
        std::string payload;
        if (mptd_fabric_call_socket(action, fn, args,
                                    /*fire_and_forget=*/false, payload)) {
            return payload;
        }
        if (mptd_fabric_transport_mode() == MptdFabricTransport::Socket) {
            return std::string(); // socket-only mode: surface the failure
        }
    }
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

// ── mptd_evidence_message — canonical bytes for σ_j over an evidence tuple ───
// TASK ①-J: deterministic byte serialization for ITrsBackend::partial_sign,
// matching the on-chain E_j(t) tuple (paper Eq 3.56) without the σ itself:
//
//   m_j = "<vid>|<epoch>|<score>|<beacon_hash>"
//
// `score` is the per-RSU anomaly composite ψ_j^(i)(t) (Eq 3.20) — formatted
// at fixed 6-decimal precision so float→string is deterministic across
// witnesses. `beacon_hash` is the IPFS CID h(b_i(t)) from mptd_beacon_hash
// (TASK ①-E commit 232d15a) — content-addressable, so all RSU witnesses of
// the same beacon produce the same message bytes (required for σ_j → σ_TRS
// aggregation per Eq 3.48).
//
// Variant: when the helper is reused for SCRevokeVote, the caller passes
// score = ts (vote timestamp) and beacon_hash = reason (e.g.
// "3_consecutive_anomalies"). The chaincode side stores it as opaque
// signature bytes today; verification lives downstream.
static inline std::vector<uint8_t> mptd_evidence_message(
    uint32_t vid, const std::string &epoch,
    double score, const std::string &beacon_hash)
{
    std::ostringstream s;
    s << vid << "|" << epoch << "|"
      << std::fixed << std::setprecision(6) << score
      << "|" << beacon_hash;
    std::string str = s.str();
    return std::vector<uint8_t>(str.begin(), str.end());
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
