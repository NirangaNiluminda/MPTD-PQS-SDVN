// ============================================================
// 06c_blockchain_api.h — NS-3 ↔ Hyperledger Fabric chaincode bridge
// MPTD-PQS SDVN (paper §3.5.5 — SC-Register / SC-Trust / SC-Revoke)
// ============================================================
// Direct chaincode invocations over AF_UNIX to the Fabric Gateway daemon at
// /tmp/mptd_fabric.sock (see fabric_gateway_daemon/). Preserves paper
// Invariant 1 (RSU→Blockchain direct: no controller relay, no centralized
// REST endpoint between the RSU code and Fabric peers).
//
// Depends on:
//   06b1_trs_backend.h (TRS pipeline)
//   05_utils.h        (execCmd)
//   02_config_globals.h (use_pq_crypto, routing_algorithm, ablation_mode, …)
//
// Public API — paper §3.5.5 aligned:
//   CallSCInitNetworkConfig()        — one-time network bootstrap (numRSUs, α,
//                                       τ_warn, τ_min, T_rev, ψ_th)
//   CallSCBootstrapRSU()             — Algorithm 7 genesis path for first RSUs
//                                       (admin-only; no endorsement)
//   CallSCRegister()                 — Algorithm 7 SC-Register: vehicle/RSU/controller
//                                       submits identity + public key + LKH leaf
//                                       hash with 2f+1 RSU endorsements
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
#if __has_include(<curl/curl.h>)
#include <curl/curl.h> // TASK ①-E: kubo HTTP API client for h(b_i(t)) CID
#endif

// NS-3 → Fabric Gateway daemon over AF_UNIX. A single-line JSON write to a
// long-lived Go daemon that holds a persistent gRPC Gateway connection to the
// peer.
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>  // fstat (event drainer)
#include <fcntl.h>     // open + O_RDONLY (event drainer)
#include <unistd.h>

// R7g.3 / R8.5: Single guard macro for every chaincode helper. When
// `skip_blockchain` is set (training-sweep mode), the fabric_invoke call is
// bypassed — the sim still produces a full beacon CSV; only the ledger writes
// are skipped. The TRS+FHE pipeline above the guard is NOT skipped: PARR
// numerator + PBPO clock still tick correctly in sweep mode.
#define MPTD_BLOCKCHAIN_GUARD() do { if (skip_blockchain) return; } while (0)

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Fabric Gateway daemon socket transport                                  ║
// ║                                                                          ║
// ║  One-line JSON exchange over /tmp/mptd_fabric.sock. Wire protocol:       ║
// ║                                                                          ║
// ║    REQ  → {"action":"invoke|query","function":"Fn","args":["a","b"],     ║
// ║            "fire_and_forget":true}\n                                     ║
// ║    RESP ← {"ok":true,"payload":"…"}\n   or  {"ok":false,"error":"…"}\n   ║
// ║                                                                          ║
// ║  When `fire_and_forget` is set on an invoke, the daemon ACKs immediately ║
// ║  and submits in a detached goroutine — used by the RSU beacon path so    ║
// ║  Fabric commit latency doesn't blow the paper's T_b = 100 ms budget      ║
// ║  (Invariant 3).                                                          ║
// ╚══════════════════════════════════════════════════════════════════════════╝

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
    bool fire_and_forget,
    const std::string& identity = "")
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
    // P4 — per-node Fabric-CA identity selector. When non-empty the daemon
    // submits under this enrolled wallet identity (pool0../rsu0../ctrl0..);
    // empty → daemon's default User1 identity (pre-P4 behaviour).
    if (!identity.empty()) {
        out += ",\"id\":\"";
        out += mptd_jesc(identity);
        out += '"';
    }
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
    std::string& payload_out,
    const std::string& identity = "")
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
                                                fire_and_forget, identity);
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
        // Propagate the error text into payload_out so callers like
        // register_one() in 11_blockchain_setup.h can distinguish a
        // chaincode-side "rejected: …" from a true transport failure
        // (empty payload_out + false return).
        std::string err;
        if (mptd_decode_payload_field(resp, "error", err)) {
            std::cerr << "[fabric-gw] " << fn << " err: " << err << '\n';
            payload_out = err;
        }
        return false;
    }
    // Payload is optional (FNF and many invokes return empty)
    mptd_decode_payload_field(resp, "payload", payload_out);
    return true;
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║  Fabric chaincode-event drainer (TASK ①-P, Phase 1C-b)                   ║
// ║                                                                          ║
// ║  The daemon (Phase 1C-a) tails the gateway's ChaincodeEvents stream into ║
// ║  /tmp/mptd_fabric_events.jsonl (one JSON line per event). This reader    ║
// ║  drains *new* lines since the last call and returns them as structured   ║
// ║  events the RSU code can dispatch on. Stateful: keeps the file FD + last ║
// ║  read offset across calls, so on each invocation we only re-read deltas. ║
// ║                                                                          ║
// ║  Used by the cross-RSU LKH rekey path in 08_detection_engine.h to close  ║
// ║  the Eq 3.58 known gap (only the voting RSU rekeyed today; remote RSUs   ║
// ║  miss the revocation without the event channel).                         ║
// ╚══════════════════════════════════════════════════════════════════════════╝

struct MptdFabricEvent {
    std::string name;       // "SCRevoke" | "TrustLow" | "CPDetectFlag"
    std::string tx;         // chaincode tx id (truncatable hex)
    uint64_t    blk = 0;    // commit block number
    std::string payload;    // raw chaincode-emitted JSON payload
    uint32_t    vehicle_id = 0;   // parsed from payload "vehicleID":"<N>" (0 if absent)
};

// Events path — overridable; must match FABRIC_GW_EVENTS_PATH on the daemon.
static inline const std::string& mptd_fabric_events_path() {
    static std::string ep = []() {
        const char* e = std::getenv("FABRIC_GW_EVENTS_PATH");
        if (e && *e) return std::string(e);
        return std::string("/tmp/mptd_fabric_events.jsonl");
    }();
    return ep;
}

// Pull one JSON-string field from a single response/event line. Walks escapes
// so the value comes out unescaped (same convention as mptd_decode_payload_field
// above, but operating on a single line instead of the wire response wrapper).
static inline bool mptd_jsonl_field(const std::string& line,
                                    const std::string& key,
                                    std::string&       out)
{
    out.clear();
    std::string needle = "\"" + key + "\":\"";
    size_t p = line.find(needle);
    if (p == std::string::npos) return false;
    p += needle.size();
    while (p < line.size()) {
        char c = line[p++];
        if (c == '"') return true;
        if (c == '\\' && p < line.size()) {
            char esc = line[p++];
            switch (esc) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                default:   out.push_back(esc); break;
            }
        } else {
            out.push_back(c);
        }
    }
    return false;
}

// Numeric JSON field extractor — finds `"key":<number>` (no quotes, integer).
static inline bool mptd_jsonl_uint_field(const std::string& line,
                                         const std::string& key,
                                         uint64_t&          out)
{
    std::string needle = "\"" + key + "\":";
    size_t p = line.find(needle);
    if (p == std::string::npos) return false;
    p += needle.size();
    // skip leading whitespace (defensive — the daemon emits compact JSON)
    while (p < line.size() && (line[p] == ' ' || line[p] == '\t')) ++p;
    uint64_t v = 0;
    bool any = false;
    while (p < line.size() && line[p] >= '0' && line[p] <= '9') {
        v = v * 10 + static_cast<uint64_t>(line[p] - '0');
        ++p;
        any = true;
    }
    if (!any) return false;
    out = v;
    return true;
}

// Drain any new events from the JSONL file. Returns true on a clean read
// (even if zero events were appended); false on I/O error (file missing,
// permission, etc — caller should log and continue).
//
// Idempotent and cheap when the file hasn't grown: lseek+empty-read costs
// microseconds, safe to call from a 1 Hz Simulator schedule.
static inline bool mptd_fabric_drain_events(std::vector<MptdFabricEvent>& out)
{
    static int      ev_fd = -1;
    static off_t    ev_off = 0;
    static std::string carry; // partial line tail across reads

    if (ev_fd < 0) {
        ev_fd = ::open(mptd_fabric_events_path().c_str(), O_RDONLY);
        if (ev_fd < 0) {
            // Not an error — daemon may not be up yet. Caller retries next tick.
            return false;
        }
        ev_off = 0;
    }

    // Seek to where we left off, in case some other process truncated the file
    // between calls. If the file is shorter than our offset, the daemon was
    // restarted (truncate-on-startup) — reset and re-read from the top.
    struct stat st;
    if (::fstat(ev_fd, &st) == 0 && static_cast<off_t>(st.st_size) < ev_off) {
        ev_off = 0;
        carry.clear();
    }
    if (::lseek(ev_fd, ev_off, SEEK_SET) < 0) return false;

    char buf[4096];
    std::string chunk;
    while (true) {
        ssize_t n = ::read(ev_fd, buf, sizeof(buf));
        if (n < 0)  return false;
        if (n == 0) break; // EOF
        chunk.append(buf, static_cast<size_t>(n));
        ev_off += n;
    }
    if (chunk.empty()) return true; // no new bytes

    std::string all = carry + chunk;
    carry.clear();

    size_t start = 0;
    while (true) {
        size_t nl = all.find('\n', start);
        if (nl == std::string::npos) {
            // Save the trailing partial line for the next call.
            carry.assign(all, start, all.size() - start);
            break;
        }
        std::string line = all.substr(start, nl - start);
        start = nl + 1;
        if (line.empty()) continue;

        MptdFabricEvent ev;
        mptd_jsonl_field(line, "name",    ev.name);
        mptd_jsonl_field(line, "tx",      ev.tx);
        mptd_jsonl_field(line, "payload", ev.payload);
        uint64_t blk = 0;
        if (mptd_jsonl_uint_field(line, "blk", blk)) ev.blk = blk;
        // Best-effort vehicleID extraction from the payload (chaincode wraps
        // it as "vehicleID":"<N>" for SCRevoke / TrustLow / CPDetectFlag).
        std::string vidStr;
        if (mptd_jsonl_field(ev.payload, "vehicleID", vidStr) && !vidStr.empty()) {
            try { ev.vehicle_id = static_cast<uint32_t>(std::stoul(vidStr)); }
            catch (...) { ev.vehicle_id = 0; }
        }
        out.push_back(std::move(ev));
    }
    return true;
}

// ── Async fabric_invoke (fire-and-forget, returns immediately) ────────────────
// Used for hot-path RSU writes where the simulation cannot block on the
// orderer round-trip (paper Invariant 3: the lightweight beacon path must
// stay under T_b = 100 ms).
static inline void mptd_fabric_invoke_async(
    const std::string& fn, const std::vector<std::string>& args,
    const std::string& identity = "")
{
    std::string ignored;
    mptd_fabric_call_socket("invoke", fn, args,
                            /*fire_and_forget=*/true, ignored, identity);
}

// ── Sync fabric_invoke (waits for endorsement + commit, returns payload) ─────
// Used for control-path calls where the caller needs the return payload
// (e.g. CPDetectCheck reads a ControllerFlag struct, SCRevokeVote reads the
// current vote count). NOT for beacon-rate calls — synchronous fabric
// commits cost 1–2 s. Returns empty string on transport error.
static inline std::string mptd_fabric_invoke_sync(
    const std::string& action,
    const std::string& fn,
    const std::vector<std::string>& args,
    const std::string& identity = "")
{
    std::string payload;
    mptd_fabric_call_socket(action, fn, args,
                            /*fire_and_forget=*/false, payload, identity);
    return payload;
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
#if __has_include(<curl/curl.h>)
    if (g_curl_inited.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(g_curl_init_mu);
    if (g_curl_inited.load(std::memory_order_relaxed)) return;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    g_curl_inited.store(true, std::memory_order_release);
#endif
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

#if __has_include(<curl/curl.h>)
// libcurl write callback — append response body into the std::string userp
static size_t mptd_curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userp) {
    std::string* buf = static_cast<std::string*>(userp);
    buf->append(ptr, size * nmemb);
    return size * nmemb;
}
#endif

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
#if __has_include(<curl/curl.h>)
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
#else
    (void)payload;
    (void)out_cid;
    return false;
#endif
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

// ── Identity prefix helpers (SC-Register key disambiguation) ─────────────────
// SC-Register stores REG_<id> records keyed by an opaque string. Numerically
// identical roles (e.g. rsu_idx=0 vs controller_idx=0) would collide on the
// raw uint→string conversion, so every chaincode-facing helper builds a
// role-prefixed string via these wrappers. Call sites continue to pass raw
// numeric IDs; the prefix is added once at the call boundary.
//
// Convention (locked, see memory project_sc_register_decisions.md):
//   Vehicle      → "VEH_<nid>"   (nid = NS-3 node ID, 2..N_Vehicles+1)
//   RSU          → "RSU_<idx>"   (idx = 0..N_RSUs-1, NOT nid)
//   Controller   → "CTRL_<idx>"  (idx = 0..N_Controllers-1)
inline std::string MakeVehId(uint32_t nid)        { return "VEH_"  + std::to_string(nid); }
inline std::string MakeRsuId(uint32_t rsu_idx)    { return "RSU_"  + std::to_string(rsu_idx); }
inline std::string MakeCtrlId(uint32_t ctrl_idx)  { return "CTRL_" + std::to_string(ctrl_idx); }

// ── Active controller in C_trusted (paper Eq 3.1 / 3.60) ─────────────────────
// The node submits controller evidence under the chain-authoritative ACTIVE
// controller, not a hardcoded index. Starts at 0 (CTRL_0 = initial head of
// C_trusted); a CP-DETECT exclusion + chaincode reassignment advances it, and
// mptd_refresh_active_controller() re-reads the on-chain head so the next
// submission uses the successor. An excluded controller's submissions would
// otherwise bounce at requireActive — refreshing keeps the control plane live.
static uint32_t g_active_controller_idx = 0;

// mptd_refresh_active_controller — query GetActiveController and update the
// cached index from the returned "CTRL_<idx>" string. No-op under
// skip_blockchain. Cheap enough for periodic (≈1 Hz) refresh; never on the
// per-beacon hot path.
inline void mptd_refresh_active_controller()
{
    if (skip_blockchain) return;
    std::string out = mptd_fabric_invoke_sync("query", "GetActiveController", {});
    // Payload is the raw chaincode string (possibly JSON-quoted). Pull the
    // integer suffix after the LAST "CTRL_".
    auto pos = out.rfind("CTRL_");
    if (pos == std::string::npos) return;
    pos += 5;
    uint32_t v = 0; bool any = false;
    while (pos < out.size() && out[pos] >= '0' && out[pos] <= '9') {
        v = v * 10 + (uint32_t)(out[pos] - '0'); any = true; ++pos;
    }
    if (any) g_active_controller_idx = v;
}

// ── CallSCInitNetworkConfig — Eq 3.55/3.58/3.59 bootstrap ────────────────────
// One-time per-run setup. Persists the trust EMA smoothing α, probation
// threshold τ_warn, revocation/demotion threshold τ_min, T_rev consecutive-epoch
// gate, anomaly threshold ψ_th, and RSU set
// size |R| (needed by SCRevokeVote to compute 2f+1 and by CPDetectCheck to
// compute f+1). The chaincode falls back to safe defaults if this is never
// called, but calling it explicitly is required to reproduce the paper's
// evaluation tables.
inline void CallSCInitNetworkConfig(
    uint32_t numRSUs, double alpha, double tauWarn, double tauMin,
    uint32_t tRev, double psiAnomalyTh)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = {
        std::to_string(numRSUs),
        std::to_string(alpha),
        std::to_string(tauWarn),
        std::to_string(tauMin),
        std::to_string(tRev),
        std::to_string(psiAnomalyTh)
    };
    // Synchronous: init must commit before any evidence submission.
    std::string out = mptd_fabric_invoke_sync("invoke", "SCInitNetworkConfig", args);
    std::cout << "[SC-INIT] numRSUs=" << numRSUs
              << " α=" << alpha << " τ_warn=" << tauWarn << " τ_min=" << tauMin
              << " T_rev=" << tRev << " ψ_th=" << psiAnomalyTh
              << " → " << out;
}

// SCResult — registration-call outcome (ok flag + error/payload string).
// `ok=true`  → chaincode committed; `msg` is the chaincode-returned payload
//             (empty when chaincode returns nil, e.g. SCRegister on success).
// `ok=false` → submission failed. `msg` carries the daemon's error text when
//             available — chaincode-side rejects start with "rejected:" so
//             callers can distinguish them from transport failures (empty
//             msg). See register_one() in 11_blockchain_setup.h.
struct SCResult {
    bool        ok;
    std::string msg;
};

// ── CallSCBootstrapRSU — Algorithm 7 genesis path (admin-only) ───────────────
// Registers the initial RSU set without endorsement checks. Run once per RSU
// at network bootstrap, before any SCRegister flow can have valid 2f+1
// endorsers. Returns SCResult{ok, msg} — see SCResult docs above.
inline SCResult CallSCBootstrapRSU(
    uint32_t rsuID, const std::string& pkHex,
    const std::string& hKuHex, double tReg,
    const std::string& identity = "")
{
    if (skip_blockchain) return {true, ""};   // bypass path
    std::vector<std::string> args = {
        MakeRsuId(rsuID),
        pkHex,
        hKuHex,
        std::to_string(tReg)
    };
    std::string payload;
    bool ok = mptd_fabric_call_socket("invoke", "SCBootstrapRSU", args,
                                       /*fire_and_forget=*/false, payload,
                                       identity);
    return {ok, payload};
}

// ── CallSCRegister — Algorithm 7 SC-Register (paper §3.5.5 page 64) ──────────
// Submits identity (id, role, pk, h(K_u)) with 2f+1 distinct RSU endorsements
// signed over sha256(id || pkHex || hKuHex) using EC-ECDSA P-256 ASN.1-DER.
// endorsementsJSON is a JSON array of {"rsuID":"...","sigHex":"..."}.
// Synchronous: caller must know whether registration committed before any
// downstream SCTrustSubmitEvidence / SCRevokeVote will be accepted by the
// chaincode (gated on Status==ACTIVE via requireActive).
// Returns SCResult{ok, msg} — see SCResult docs above.
inline SCResult CallSCRegister(
    const std::string& id, const std::string& role,
    const std::string& pkHex, const std::string& hKuHex,
    double tReg, const std::string& endorsementsJSON,
    const std::string& identity = "")
{
    if (skip_blockchain) return {true, ""};   // bypass path
    std::vector<std::string> args = {
        id, role, pkHex, hKuHex,
        std::to_string(tReg),
        endorsementsJSON
    };
    std::string payload;
    bool ok = mptd_fabric_call_socket("invoke", "SCRegister", args,
                                       /*fire_and_forget=*/false, payload,
                                       identity);
    return {ok, payload};
}

// ── G1 evidence/vote signers (defined in 11_blockchain_setup.h) ──────────────
// Forward-declared here so the Call* wrappers can sign σ over the SAME string
// args they transmit. The signer hashes (id‖…) identically to the chaincode
// digest helpers (smartcontract.go evidenceDigest / controllerEvidenceDigest /
// revokeVoteDigest) and signs with the node's registered P-256 key. Defining
// them in 11 (which owns g_node_ec_keys, populated at SC-Register time) keeps
// this header free of the EC keystore while still letting the wrapper produce a
// chaincode-verifiable signature in one place — eliminating any risk that the
// signed bytes drift from the transmitted bytes.
std::string mptd_sign_evidence_hex(const std::string& vehId,
                                   const std::string& rsuId,
                                   const std::string& epoch,
                                   const std::string& psiStr,
                                   const std::string& beaconHash);
std::string mptd_sign_controller_evidence_hex(const std::string& vehId,
                                              const std::string& ctrlId,
                                              const std::string& epoch,
                                              const std::string& phiStr,
                                              const std::string& beaconHash);
std::string mptd_sign_revoke_vote_hex(const std::string& vehId,
                                      const std::string& rsuId,
                                      const std::string& reason,
                                      const std::string& tsStr);

// ── CallSCTrustSubmitEvidence — Eq 3.56/3.61 RSU evidence tuple ──────────────
// E_j(t) = (vehicleID, ψ_j^(i)(t), epoch, h(b_i(t)), σ_j^sub)
// One call per RSU witness per beacon; SCTrustFinalizeEpoch later aggregates
// them per Eq 3.55. Async because this is on the beacon-alert hot path.
//
// σ_j^sub is now produced HERE with the submitting RSU's registered P-256 key
// over the exact transmitted strings (Eq 3.61) — the chaincode verifies it on
// submit (smartcontract.go SCTrustSubmitEvidence). No caller-supplied sig.
inline void CallSCTrustSubmitEvidence(
    uint32_t vehicleID, uint32_t rsuID, const std::string& epoch,
    double psi, const std::string& beaconHash)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::string vehId  = MakeVehId(vehicleID);
    std::string rsuId  = MakeRsuId(rsuID);
    std::string psiStr = std::to_string(psi);
    std::string sig = mptd_sign_evidence_hex(vehId, rsuId, epoch,
                                             psiStr, beaconHash);
    std::vector<std::string> args = {
        vehId, rsuId, epoch, psiStr, beaconHash, sig
    };
    mptd_fabric_invoke_async("SCTrustSubmitEvidence", args);
}

// ── CallSCControllerSubmitEvidence — Eq 3.57 controller evidence tuple ───────
// E_c(t) = (vehicleID, Φ_i(t), epoch, h(X_i(t)), σ_c^sub)
// Written by the SDN controller (peer #2 in the Fabric organization mapping)
// as an UNTRUSTED submission — CPDetectCheck (Eq 3.59) decides whether to
// honour it. Async for the same reason as the RSU side.
// σ_c^sub is now produced HERE with the controller's registered P-256 key over
// the exact transmitted strings (Eq 3.62) — verified on submit by the chaincode
// (smartcontract.go SCControllerSubmitEvidence). The controller still writes as
// a non-authoritative client (invariant 2); the signature only proves the
// submission genuinely came from a registered controller identity.
inline void CallSCControllerSubmitEvidence(
    uint32_t vehicleID, uint32_t controllerID, const std::string& epoch,
    double phi, const std::string& beaconHash)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::string vehId  = MakeVehId(vehicleID);
    std::string ctrlId = MakeCtrlId(controllerID);
    std::string phiStr = std::to_string(phi);
    std::string sig = mptd_sign_controller_evidence_hex(vehId, ctrlId, epoch,
                                                        phiStr, beaconHash);
    std::vector<std::string> args = {
        vehId, ctrlId, epoch, phiStr, beaconHash, sig
    };
    mptd_fabric_invoke_async("SCControllerSubmitEvidence", args, "ctrl" + std::to_string(controllerID));
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
        MakeVehId(vehicleID), epoch
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
        MakeVehId(vehicleID), epoch
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
        MakeVehId(vehicleID), epoch
    };
    return mptd_fabric_invoke_sync("invoke", "CPDetectCheck", args, "ctrl" + std::to_string(node_controller_ID[vehicleID]));
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
        MakeVehId(vehicleID), epoch
    };
    mptd_fabric_invoke_async("CPDetectCheck", args, "ctrl" + std::to_string(node_controller_ID[vehicleID]));
}

// ── CallSCRSUFinalizeEpoch — RSU SC-Trust EMA (Eq rsu_trust / rsu_misbehave) ──
// τ_{r_j}(t) = α·τ_{r_j}(t-1) + (1-α)·(1 - m_j(t)), where m_j is each RSU's
// mean disagreement with the 2f+1 TRUSTED-quorum verdict over the vehicles it
// reported on this epoch. Channel-wide: one call per epoch evaluates EVERY RSU
// from the on-chain SUBM_<vid>_<epoch>_<rsu> records, applies the demote /
// promote / revoke lifecycle, and is idempotent over the epoch. Synchronous;
// returns the raw chaincode JSON (array of updated RSUTrustScore records).
inline std::string CallSCRSUFinalizeEpoch(const std::string& epoch)
{
    if (skip_blockchain) return "";
    std::vector<std::string> args = { epoch };
    return mptd_fabric_invoke_sync("invoke", "SCRSUFinalizeEpoch", args);
}

// ── CallSCRSUFinalizeEpochAsync — fire-and-forget variant ────────────────────
// Same chaincode function as CallSCRSUFinalizeEpoch but discards the returned
// records. Scheduled once per epoch from inside the sim tick (after the
// per-vehicle SUBM submissions for that epoch have landed) so blocking on the
// orderer round-trip never stalls the simulation. Idempotent over the epoch —
// re-firing just re-evaluates the same SUBM set. Bindable to
// Simulator::Schedule via ns3::MakeBoundCallback.
inline void CallSCRSUFinalizeEpochAsync(std::string epoch)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::vector<std::string> args = { epoch };
    mptd_fabric_invoke_async("SCRSUFinalizeEpoch", args);
}

// ── RsuTrustView / CallSCGetAllRSUTrustScores — live on-chain RSU trust read ──
// Supports trust-ranked endorsing-peer selection (Sir's Task-4 revision,
// 2026-06-16): rather than treating every RSU as an endorsing peer (expensive),
// the registration/endorsement path draws its 2f+1 endorsers from the highest-
// trust members of the on-chain trusted set R_trusted(t) (paper notation table;
// endorser set = R_trusted(t)). This is a READ (EvaluateTransaction) — peer-
// local, no orderer round-trip — so it is cheap enough for periodic (~1 Hz)
// refresh. Returns one entry per registered RSU; `trusted` is false for
// demoted CLIENT / revoked peers, which are excluded from selection.
struct RsuTrustView {
    uint32_t rsu_idx;   // parsed from "RSU_<idx>"
    double   trust;     // τ_{r_j} ∈ [0,1]
    bool     trusted;   // State == "TRUSTED" (CLIENT/REVOKED → false)
};

// Pull the quoted string value of `key` starting at/after `from` in `s`.
// Returns "" when not found. Minimal scanner (no JSON lib in tree, matching the
// hand-parse style of mptd_refresh_active_controller).
inline std::string mptd_json_str_after(const std::string& s,
                                        const std::string& key, size_t from)
{
    auto k = s.find(key, from);
    if (k == std::string::npos) return "";
    auto q1 = s.find('"', k + key.size());
    if (q1 == std::string::npos) return "";
    auto q2 = s.find('"', q1 + 1);
    if (q2 == std::string::npos) return "";
    return s.substr(q1 + 1, q2 - q1 - 1);
}

// Pull the numeric value of `key` (e.g. "TrustScore":) at/after `from`.
inline double mptd_json_num_after(const std::string& s,
                                  const std::string& key, size_t from)
{
    auto k = s.find(key, from);
    if (k == std::string::npos) return 0.0;
    size_t p = k + key.size();
    return std::strtod(s.c_str() + p, nullptr);
}

inline std::vector<RsuTrustView> CallSCGetAllRSUTrustScores()
{
    std::vector<RsuTrustView> out;
    if (skip_blockchain) return out;
    std::string js = mptd_fabric_invoke_sync("query", "GetAllRSUTrustScores", {});
    if (js.empty() || js == "null" || js == "[]") return out;

    // Chaincode marshals RSUTrustScore in field order: ID, RSUID, TrustScore,
    // State, … — so for each "RSUID":"RSU_<idx>" the matching TrustScore/State
    // are the next occurrences. Scan object-by-object on the RSUID anchor.
    size_t pos = 0;
    while (true) {
        auto idAnchor = js.find("\"RSUID\":\"RSU_", pos);
        if (idAnchor == std::string::npos) break;
        std::string rsuId = mptd_json_str_after(js, "\"RSUID\":", idAnchor);
        RsuTrustView v{};
        // parse idx from "RSU_<idx>"
        auto us = rsuId.rfind('_');
        v.rsu_idx = (us != std::string::npos)
                        ? (uint32_t)std::strtoul(rsuId.c_str() + us + 1, nullptr, 10)
                        : 0;
        v.trust   = mptd_json_num_after(js, "\"TrustScore\":", idAnchor);
        v.trusted = (mptd_json_str_after(js, "\"State\":", idAnchor) == "TRUSTED");
        out.push_back(v);
        pos = idAnchor + 12;   // advance past this anchor
    }
    return out;
}

// ── CallSCRevokeVote — Eq 3.58 BFT 2f+1 RSU vote ─────────────────────────────
// One call per RSU that wishes to vote for revoking `vehicleID`. The
// chaincode commits the immutable SCREVOKE_ record + emits "SCRevoke" event
// only when distinct votes reach 2f+1. Synchronous so callers can react to
// the returned `revoked` flag (e.g. trigger LKH rekey on the local RSU when
// its own vote was the deciding one).
// The vote signature is now produced HERE with the voting RSU's registered
// P-256 key over (vehId‖rsuId‖reason‖tsStr) (Eq 3.63) — verified on submit by
// the chaincode (smartcontract.go SCRevokeVote) so a forged identity cannot
// pad the 2f+1 tally.
inline std::string CallSCRevokeVote(
    uint32_t vehicleID, uint32_t rsuID,
    const std::string& reason, double timestamp)
{
    if (skip_blockchain) return "";
    std::string vehId = MakeVehId(vehicleID);
    std::string rsuId = MakeRsuId(rsuID);
    std::string tsStr = std::to_string(timestamp);
    std::string sig = mptd_sign_revoke_vote_hex(vehId, rsuId, reason, tsStr);
    std::vector<std::string> args = {
        vehId, rsuId, reason, sig, tsStr
    };
    return mptd_fabric_invoke_sync("invoke", "SCRevokeVote", args);
}


