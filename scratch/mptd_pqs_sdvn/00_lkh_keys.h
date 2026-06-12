// ============================================================
// 00_lkh_keys.h — LKH Group Key Management + HMAC Utilities
// MPTD-PQS: §3.5.2 Group Key Management via Logical Key Hierarchy
// ============================================================
// Paper Equations implemented here:
//   Eq.3.22: K_i = KDF(K_{u_i}, η_i, ID_i)     — vehicle session key
//   Eq.3.23: N_rekey = log₂|V_j|               — rekey cost on vehicle leave
//   Eq.3.24: N_ring  = (n-1)                    — RSU ring rekey cost
//   Eq.3.25: sk_j = KDF(K_{u_j}, K_ring, ID_rj) — RSU ring key; the same
//            authenticated ring channel also distributes the FHE key shares
//            {sk_j^share} produced by ThGen (Eq 3.54) — 2026-06 revision.
//   Eq.3.37: MAC_i(t) = HMAC_{K_i}(b_i(t)‖t‖ID_i) — beacon tag
//
//   NOTE: §3.5.2 was renumbered in the 2026-06 paper revision (prior numbering
//   3.33/3.34/3.36 → now 3.22/3.23/3.25). Underlying math is unchanged.
//
// Key derivation: HMAC-SHA256 used as KDF (HMAC-based KDF)
//   KDF(master, salt, info) = HMAC-SHA256(master, salt ‖ info)
//   This is the Extract step of HKDF — produces 32 bytes, cryptographically
//   indistinguishable from random given secure master key.
//
// Topology (per-zone, paper §3.5.2 — P1b-C):
//   • One LKH subtree PER RSU coverage zone (g_lkh_zone[rsu]), managed by the
//     RSU. Balanced binary heap: node k → children 2k+1, 2k+2; leaf slot s at
//     heap index (first_leaf + s). Each zone has its own CSPRNG group key K_root.
//   • A SEPARATE RSU-ring subtree (g_lkh_ring_tree), managed by the SDN
//     controller, from which sk_j is derived (Eq 3.25).
//   • Vehicles are NOT statically placed: they JOIN a zone on first RSU contact
//     and HAND OFF as they move (lkh_on_beacon_at_rsu), with K_i re-derived from
//     the new zone's leaf key (per-RSU-contact keys, Eq 3.22).
//
// Dynamic membership / rekeying (§3.5.2, Eq 3.22–3.24):
//   • Join  : allocate a leaf slot in the zone subtree, derive K_{u_i} + K_i.
//   • Handoff: free old-zone slot (rotate that zone's path = forward secrecy of
//             K_root), join new zone. Benign → no unicast rekey storm.
//   • Revoke: zone-scoped — rekey the revoked leaf's path, nonce-bump + RekeyTag
//             only the SURVIVING members of THAT zone (Eq 3.23 N_rekey=log₂|V_j|,
//             the zone population, NOT the global count).
//
// Real vs not-real:
//   REAL: HMAC-SHA256 (inline FIPS), per-zone/ring subtree key derivation, CSPRNG
//         master/zone/ring roots, unicast NS-3 RekeyTag packets, dynamic join/leave.
//   ABSTRACTED (tracked, D-LKH-1): secure first-delivery of a leaf key to a
//         joining vehicle. The single-process sim shares g_vehicle_session_key
//         between vehicle-TX and RSU-verify (implicit authenticated delivery); a
//         real deployment would wrap K_{u_i} under the vehicle's certificate.
// ============================================================

#ifndef MPTD_PQS_LKH_KEYS_H
#define MPTD_PQS_LKH_KEYS_H

// Pure C++ SHA-256 + HMAC-SHA-256 implementation (no external library required).
// Algorithm is identical to FIPS 180-4 / RFC 2104 — real cryptography, just
// compiled inline rather than linked from libcrypto.  This avoids waf/linker
// complications with the NS-3.35 build system while keeping the implementation
// fully correct.  If OpenSSL is later integrated, this block can be swapped
// for a one-line HMAC() call.
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <vector>
#include <cmath>
#include <random>          // std::random_device fallback CSPRNG
#include <sys/random.h>    // getrandom(2) — kernel CSPRNG for master key material

// ── Constants ─────────────────────────────────────────────────────────────────
#define LKH_KEY_BYTES   32          // 256-bit keys throughout
#define LKH_HMAC_TRUNC  8           // 8-byte (64-bit) truncated MAC on beacon tag
#define LKH_MAX_VEH     1024        // max vehicles in the LKH tree (SUMO-scale ceiling;
                                    // ~150 KB static, raise if a scenario needs more)
#define LKH_MAX_NODES   2048        // ≥ 2 * next_pow2(LKH_MAX_VEH) heap nodes
#define LKH_REKEY_PORT  5555        // UDP port: RSU → vehicle key update messages

// ── LKH Tree Node ─────────────────────────────────────────────────────────────
struct LkhNode {
    uint8_t  key[LKH_KEY_BYTES];   // key material for this node
    uint32_t vehicle_id;           // non-zero for leaf nodes only (NS-3 node ID)
    bool     revoked;              // true if this leaf's vehicle was revoked
    bool     valid;                // false for unused nodes
};

// ── Global LKH State (per-zone topology, P1b-C, paper §3.5.2) ─────────────────
// Paper model: a SEPARATE LKH subtree per RSU coverage zone (managed by the RSU),
// plus a SEPARATE RSU-ring subtree (managed by the SDN controller). Vehicles join
// a zone on entry, leave/handoff on exit, with forward-secrecy rekey on leave
// (N_rekey = log₂|V_j|, the *zone* population — Eq 3.23). This replaces the old
// single flat global tree, which deviated from the paper (one tree for everyone,
// rekey cost log₂(total) not log₂|V_j|, no dynamic membership).

// Per-RSU-zone vehicle subtree. Heap-indexed (node k → children 2k+1, 2k+2);
// leaf slot s lives at heap index (first_leaf + s). `root` is the zone group key
// K_root (CSPRNG, mutable — rotated on leave/revoke for forward secrecy).
struct LkhZone {
    std::vector<LkhNode> nodes;          // heap tree, size = 2*cap - 1
    int      cap        = 0;             // leaf capacity (power of 2), grows on demand
    int      first_leaf = 0;             // = cap - 1
    int      n_members  = 0;             // current |V_j|
    uint8_t  root[LKH_KEY_BYTES];        // zone group key K_root
    std::vector<int> slot_owner;         // slot → veh_idx, -1 if free
};
static std::vector<LkhZone> g_lkh_zone;              // one per RSU (index = rsu_idx)

// Controller-managed RSU-ring subtree (separate from zone trees, paper §3.5.2).
struct LkhRingTree {
    std::vector<LkhNode> nodes;
    int cap = 0, first_leaf = 0;
};
static LkhRingTree g_lkh_ring_tree;

// Per-vehicle current membership + key state (indexed by veh_idx = nid-2).
static int      g_vehicle_zone[LKH_MAX_VEH];         // current zone (rsu_idx), -1 = limbo
static int      g_vehicle_slot[LKH_MAX_VEH];         // current slot within that zone, -1
static uint8_t  g_vehicle_leaf_key[LKH_MAX_VEH][LKH_KEY_BYTES]; // current K_{u_i}

// Affected-member scratch list filled by lkh_rekey_on_revoke() (zone members that
// must receive a rekey packet) — consumed by send_lkh_rekey_to_vehicles() in 08.
static std::vector<int> g_lkh_affected_members;

// Per-vehicle session keys K_i (Eq.3.22) — K_i = KDF(K_{u_i}, η_i, ID_i).
static uint8_t  g_vehicle_session_key[LKH_MAX_VEH][LKH_KEY_BYTES];
// Per-vehicle nonce η_i — incremented on every rekey/handoff for forward secrecy.
static uint32_t g_vehicle_nonce   [LKH_MAX_VEH];
// Per-vehicle DSRC IP recorded the first time RSU receives a beacon from that vehicle
// Used to unicast RekeyTag packets. Filled in handle_readone() / HandleBeaconReceived().
static ns3::Ipv4Address g_vehicle_dsrc_ip[LKH_MAX_VEH];
static bool             g_vehicle_ip_known[LKH_MAX_VEH];

// RSU ring keys sk_j (Eq.3.25) — one per RSU, used by TRS partial signing.
static uint8_t  g_rsu_ring_key[MAX_RSUS][LKH_KEY_BYTES];

// Back-compat: total active leaves, kept only for legacy log lines.
static int      g_lkh_n_leaves    = 0;

// Mutable current ring group key K_ring (Eq.3.25). Filled from the OS CSPRNG by
// lkh_init_master_keys() at setup (NOT hardcoded); rotated by lkh_ring_rekey()
// on RSU revocation (Eq.3.24) so a revoked
// RSU whose leaf key was updated can no longer derive a valid sk_j.
static uint8_t  g_lkh_k_ring_current[LKH_KEY_BYTES];

// ── Authenticated LKH ring channel for FHE key-share distribution (Eq.3.25) ──
// The FHE threshold shares {sk_j^share} from ThGen (Eq 3.54, 06b2) are deposited
// here per party (RSU 0..n-1, cloud = n) with an HMAC-SHA256 tag under K_ring, and
// retrieved with tag verification. Transport is in-process (single NS-3 process);
// the AUTHENTICATION (real HMAC under K_ring) models the paper's "authenticated
// ring key synchronisation channel". Share bytes = serialized OpenFHE PrivateKey.
#define LKH_RING_PARTIES (4 + 1)   // n RSUs (≤4) + 1 cloud — the (t, n+1) party set
struct LkhRingShareSlot {
    std::vector<uint8_t> bytes;          // serialized FHE secret-key share
    uint8_t              tag[LKH_KEY_BYTES];
    bool                 present = false;
};
static LkhRingShareSlot g_lkh_ring_share[LKH_RING_PARTIES];

// ── Master key material — generated at runtime, NOT hardcoded (P1b-1, 2026-06) ─
// Paper §3.5.2: K_root is the *current group key* (mutable, rekeyed on membership)
// and K_ring is the RSU ring group key — neither is a compile-time constant. Both
// are filled from the OS CSPRNG (getrandom(2) = kernel /dev/urandom pool) at boot,
// exactly as a real RSU / SDN-controller KDC would provision them. No secret key
// material lives in the source tree.  (Prior code hardcoded ASCII seed strings
// here — a simulation shortcut; removed.)
//
// Reproducibility: keys are fresh per run by design. Detection metrics
// (MCC/FPR/…) depend only on key *consistency* within a run, not on key values,
// and mobility/attack randomness is the independent NS-3 RngSeedManager — so
// run-to-run metric reproducibility is unaffected by per-run key freshness.
static uint8_t g_lkh_root_seed[LKH_KEY_BYTES];   // K_root master seed (was LKH_ROOT_SEED)
static bool    g_lkh_master_ready = false;

// Fill `len` bytes from the OS CSPRNG. getrandom() for ≤256 bytes is atomic and
// won't short-read once the pool is seeded; std::random_device (also
// /dev/urandom-backed on glibc) is the fallback if the syscall is unavailable.
static void lkh_fill_random(uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t r = getrandom(buf + off, len - off, 0);
        if (r <= 0) break;            // error → fall through to fallback
        off += (size_t)r;
    }
    if (off < len) {                  // fallback CSPRNG
        std::random_device rd;
        for (; off < len; off++) buf[off] = (uint8_t)(rd() & 0xFF);
    }
}

// Generate LKH master key material once per run (idempotent). MUST run before any
// consumer of g_lkh_root_seed / g_lkh_k_ring_current — i.e. before the LKH tree
// build AND before the TRS backend (which seeds its ring polynomial from K_ring,
// Eq 3.25). Called from both lkh_init_all() and initialize_crypto_backends() so
// it is ready whichever fires first. Never prints the key bytes.
static void lkh_init_master_keys()
{
    if (g_lkh_master_ready) return;
    lkh_fill_random(g_lkh_root_seed,      LKH_KEY_BYTES);   // K_root
    lkh_fill_random(g_lkh_k_ring_current, LKH_KEY_BYTES);   // K_ring (Eq 3.25)
    g_lkh_master_ready = true;
    printf("[LKH] Master key material generated from OS CSPRNG "
           "(K_root + K_ring, %d bytes each; not hardcoded)\n", LKH_KEY_BYTES);
}

// ── Pure C++ SHA-256 (FIPS 180-4) ────────────────────────────────────────────
// Standard round constants and initial hash values.
static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

struct Sha256Ctx {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buf[64];
    uint32_t buflen;
};

static inline uint32_t sha256_rotr(uint32_t x, int n) { return (x >> n) | (x << (32-n)); }

static void sha256_transform(Sha256Ctx &ctx, const uint8_t block[64])
{
    uint32_t w[64], a,b,c,d,e,f,g,h, t1,t2;
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4+0] << 24) | ((uint32_t)block[i*4+1] << 16)
             | ((uint32_t)block[i*4+2] <<  8) |  (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = sha256_rotr(w[i-15],7)^sha256_rotr(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = sha256_rotr(w[i-2],17)^sha256_rotr(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    a=ctx.state[0]; b=ctx.state[1]; c=ctx.state[2]; d=ctx.state[3];
    e=ctx.state[4]; f=ctx.state[5]; g=ctx.state[6]; h=ctx.state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1   = sha256_rotr(e,6)^sha256_rotr(e,11)^sha256_rotr(e,25);
        uint32_t ch   = (e&f)^(~e&g);
        t1 = h+S1+ch+SHA256_K[i]+w[i];
        uint32_t S0   = sha256_rotr(a,2)^sha256_rotr(a,13)^sha256_rotr(a,22);
        uint32_t maj  = (a&b)^(a&c)^(b&c);
        t2 = S0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx.state[0]+=a; ctx.state[1]+=b; ctx.state[2]+=c; ctx.state[3]+=d;
    ctx.state[4]+=e; ctx.state[5]+=f; ctx.state[6]+=g; ctx.state[7]+=h;
}

static void sha256_init(Sha256Ctx &ctx) {
    ctx.state[0]=0x6a09e667; ctx.state[1]=0xbb67ae85;
    ctx.state[2]=0x3c6ef372; ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f; ctx.state[5]=0x9b05688c;
    ctx.state[6]=0x1f83d9ab; ctx.state[7]=0x5be0cd19;
    ctx.bitcount=0; ctx.buflen=0;
}

static void sha256_update(Sha256Ctx &ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx.buf[ctx.buflen++] = data[i];
        if (ctx.buflen == 64) { sha256_transform(ctx, ctx.buf); ctx.buflen=0; }
        ctx.bitcount += 8;
    }
}

static void sha256_final(Sha256Ctx &ctx, uint8_t out[32]) {
    uint64_t bits = ctx.bitcount;
    ctx.buf[ctx.buflen++] = 0x80;
    if (ctx.buflen > 56) {
        while (ctx.buflen < 64) ctx.buf[ctx.buflen++] = 0;
        sha256_transform(ctx, ctx.buf); ctx.buflen=0;
    }
    while (ctx.buflen < 56) ctx.buf[ctx.buflen++] = 0;
    for (int i = 7; i >= 0; i--) { ctx.buf[56+(7-i)] = (uint8_t)(bits >> (i*8)); }
    sha256_transform(ctx, ctx.buf);
    for (int i = 0; i < 8; i++) {
        out[i*4+0]=(uint8_t)(ctx.state[i]>>24); out[i*4+1]=(uint8_t)(ctx.state[i]>>16);
        out[i*4+2]=(uint8_t)(ctx.state[i]>>8);  out[i*4+3]=(uint8_t)(ctx.state[i]);
    }
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    Sha256Ctx ctx; sha256_init(ctx); sha256_update(ctx,data,len); sha256_final(ctx,out);
}

// ── HMAC-SHA-256 (RFC 2104) ───────────────────────────────────────────────────
// Computes HMAC-SHA256(key, message) → 32 bytes output.
// Returns true always (pure implementation, no allocation failures).
static bool lkh_hmac_sha256(const uint8_t *key,  size_t key_len,
                             const uint8_t *msg,  size_t msg_len,
                             uint8_t        out[LKH_KEY_BYTES])
{
    // If key longer than block size (64), hash it first
    uint8_t k[64] = {};
    if (key_len > 64) {
        sha256(key, key_len, k);
    } else {
        std::memcpy(k, key, key_len);
    }

    // Inner pad: k XOR 0x36
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    // inner = SHA256(ipad ‖ message)
    uint8_t inner[32];
    {
        Sha256Ctx ctx; sha256_init(ctx);
        sha256_update(ctx, ipad, 64);
        sha256_update(ctx, msg,  msg_len);
        sha256_final(ctx, inner);
    }

    // outer = SHA256(opad ‖ inner)
    {
        Sha256Ctx ctx; sha256_init(ctx);
        sha256_update(ctx, opad,  64);
        sha256_update(ctx, inner, 32);
        sha256_final(ctx, out);
    }
    return true;
}

// ── KDF (Eq.3.22/3.25): KDF(master, salt, info) = HMAC-SHA256(master, salt‖info) ─
// master : the input key material (K_{u_i} or K_{u_j})
// salt   : nonce η_i (4 bytes, little-endian) or K_ring bytes
// info   : identity bytes (vehicle ID or RSU ID)
// out    : 32-byte derived key
static bool lkh_kdf(const uint8_t *master, size_t master_len,
                    const uint8_t *salt,   size_t salt_len,
                    const uint8_t *info,   size_t info_len,
                    uint8_t        out[LKH_KEY_BYTES])
{
    // Concatenate salt ‖ info into a single message buffer
    size_t msg_len = salt_len + info_len;
    uint8_t msg[128];
    if (msg_len > sizeof(msg)) return false;
    if (salt_len > 0) std::memcpy(msg,            salt, salt_len);
    if (info_len > 0) std::memcpy(msg + salt_len, info, info_len);
    return lkh_hmac_sha256(master, master_len, msg, msg_len, out);
}

// ── Derive a tree node key from a given subtree root (zone or ring) ───────────
// node_key = KDF(root, node_index_bytes, depth_bytes). Parameterised on `root`
// so each zone subtree and the ring subtree derive from their OWN group key
// (paper §3.5.2: per-zone K_root + separate ring root), not one global seed.
static void lkh_derive_node_key_from(const uint8_t *root, int idx,
                                     uint8_t out[LKH_KEY_BYTES])
{
    uint8_t index_bytes[4];
    index_bytes[0] = (uint8_t)( idx        & 0xFF);
    index_bytes[1] = (uint8_t)((idx >>  8) & 0xFF);
    index_bytes[2] = (uint8_t)((idx >> 16) & 0xFF);
    index_bytes[3] = (uint8_t)((idx >> 24) & 0xFF);

    uint8_t depth_byte[1] = { 0 };
    for (int tmp = idx + 1; tmp > 1; tmp >>= 1) depth_byte[0]++;  // floor(log2(idx+1))

    lkh_kdf(root,        LKH_KEY_BYTES,
            index_bytes, 4,
            depth_byte,  1,
            out);
}

// ── (Re)build a zone subtree of capacity `cap` from its current root ──────────
// Caller sets z.root first. Derives all node keys; clears membership.
static void lkh_zone_build_nodes(LkhZone &z, int cap)
{
    if (cap < 1) cap = 1;
    z.cap        = cap;
    z.first_leaf = cap - 1;
    int total    = 2 * cap - 1;
    z.nodes.assign((size_t)total, LkhNode{});
    for (int i = 0; i < total; i++) {
        lkh_derive_node_key_from(z.root, i, z.nodes[i].key);
        z.nodes[i].valid = true; z.nodes[i].revoked = false; z.nodes[i].vehicle_id = 0;
    }
    z.slot_owner.assign((size_t)cap, -1);
    z.n_members = 0;
}

// Regenerate one node key inside a zone (time-mixed) — forward secrecy on rekey.
static void lkh_zone_regen_node(LkhZone &z, int node_idx, double sim_time)
{
    if (node_idx < 0 || node_idx >= (int)z.nodes.size()) return;
    uint8_t time_bytes[8];
    uint64_t ti = (uint64_t)(sim_time * 1e6);
    for (int b = 0; b < 8; b++) time_bytes[b] = (uint8_t)((ti >> (b*8)) & 0xFF);
    uint8_t nk[LKH_KEY_BYTES];
    lkh_kdf(z.nodes[node_idx].key, LKH_KEY_BYTES, time_bytes, 8,
            (const uint8_t*)"rekey", 5, nk);
    std::memcpy(z.nodes[node_idx].key, nk, LKH_KEY_BYTES);
}

// Rekey the root path of leaf `slot` (forward secrecy of the zone group key).
// Returns the number of internal nodes rekeyed = tree depth.
static int lkh_zone_rekey_path(LkhZone &z, int slot, double sim_time)
{
    int depth = 0; for (int c = z.cap; c > 1; c >>= 1) depth++;
    if (slot < 0 || slot >= z.cap) return depth;
    int cur = z.first_leaf + slot;
    lkh_zone_regen_node(z, cur, sim_time + 0.001);           // dead leaf
    while (cur > 0) { cur = (cur - 1) / 2; lkh_zone_regen_node(z, cur, sim_time); }
    return depth;
}

// Forward declaration (defined after lkh_compute_session_key).
static void lkh_compute_session_key(int veh_idx);

// Grow a full zone subtree to 2× capacity, preserving members in-place. The
// rebuild re-derives leaf keys from z.root, so members get fresh K_{u_i}/K_i
// (a structural rekey — fine in the single-process sim where TX/RX share state).
static void lkh_zone_grow(LkhZone &z)
{
    std::vector<int> owners = z.slot_owner;     // snapshot slot→veh
    lkh_zone_build_nodes(z, z.cap * 2);          // rebuild bigger from same root
    for (int s = 0; s < (int)owners.size(); s++) {
        int v = owners[s];
        if (v < 0) continue;
        z.slot_owner[s] = v; z.n_members++;
        g_vehicle_slot[v] = s;
        std::memcpy(g_vehicle_leaf_key[v], z.nodes[z.first_leaf + s].key, LKH_KEY_BYTES);
        g_vehicle_nonce[v]++;
        lkh_compute_session_key(v);
    }
    printf("[LKH] Zone grown to cap=%d (rekeyed %d members)\n", z.cap, z.n_members);
}

// ── Initialise per-zone subtrees (one per RSU) at simulation start ────────────
// Each zone gets a fresh CSPRNG group key K_root and a base-capacity subtree.
// Vehicles are NOT yet placed — they join via lkh_on_beacon_at_rsu() on first
// contact (dynamic membership). Base cap doubles on demand (lkh_zone_grow).
#define LKH_ZONE_BASE_CAP 16
static void lkh_zones_init(int n_rsus)
{
    if (n_rsus < 1) n_rsus = 1;
    g_lkh_zone.clear();
    g_lkh_zone.resize((size_t)n_rsus);
    for (int r = 0; r < n_rsus; r++) {
        lkh_fill_random(g_lkh_zone[r].root, LKH_KEY_BYTES);   // per-zone K_root (CSPRNG)
        lkh_zone_build_nodes(g_lkh_zone[r], LKH_ZONE_BASE_CAP);
    }
    for (int i = 0; i < LKH_MAX_VEH; i++) { g_vehicle_zone[i] = -1; g_vehicle_slot[i] = -1; }
    printf("[LKH] %d per-RSU-zone subtrees initialised (base cap=%d, CSPRNG roots)\n",
           n_rsus, LKH_ZONE_BASE_CAP);
}

// ── Derive vehicle session key K_i (Eq.3.22) ─────────────────────────────────
// K_i = KDF(K_{u_i}, η_i, ID_i)
// K_{u_i} = g_vehicle_leaf_key[i]   (current zone-leaf key, or limbo key pre-join)
// η_i     = g_vehicle_nonce[i]      (4 bytes, incremented on rekey/handoff)
// ID_i    = NS-3 node ID of vehicle i (4 bytes)
static void lkh_compute_session_key(int veh_idx)
{
    if (veh_idx < 0 || veh_idx >= LKH_MAX_VEH) return;

    const uint8_t *k_leaf = g_vehicle_leaf_key[veh_idx];

    // nonce η_i as 4 little-endian bytes
    uint32_t nonce = g_vehicle_nonce[veh_idx];
    uint8_t nonce_bytes[4];
    nonce_bytes[0] = (uint8_t)( nonce        & 0xFF);
    nonce_bytes[1] = (uint8_t)((nonce >>  8) & 0xFF);
    nonce_bytes[2] = (uint8_t)((nonce >> 16) & 0xFF);
    nonce_bytes[3] = (uint8_t)((nonce >> 24) & 0xFF);

    // ID_i = NS-3 node ID = veh_idx + 2
    uint32_t nid = (uint32_t)(veh_idx + 2);
    uint8_t id_bytes[4];
    id_bytes[0] = (uint8_t)( nid        & 0xFF);
    id_bytes[1] = (uint8_t)((nid >>  8) & 0xFF);
    id_bytes[2] = (uint8_t)((nid >> 16) & 0xFF);
    id_bytes[3] = (uint8_t)((nid >> 24) & 0xFF);

    lkh_kdf(k_leaf,      LKH_KEY_BYTES,
            nonce_bytes, 4,
            id_bytes,    4,
            g_vehicle_session_key[veh_idx]);
}

// ── Initialise vehicle bootstrap (limbo) session keys ─────────────────────────
// Before a vehicle joins any RSU zone it is in "limbo" (g_vehicle_zone=-1) with a
// bootstrap leaf key K_{u_i}=KDF(K_root, i, "limbo") — analogous to a long-term
// credential held before obtaining a zone session key. This guarantees a valid K_i
// from t=0 (so the first beacon HMAC verifies), and the vehicle is migrated to a
// real per-zone key on its first RSU contact via lkh_on_beacon_at_rsu().
static void lkh_init_session_keys(int n_vehicles)
{
    std::memset(g_vehicle_nonce,       0, sizeof(g_vehicle_nonce));
    std::memset(g_vehicle_session_key, 0, sizeof(g_vehicle_session_key));
    std::memset(g_vehicle_ip_known,    0, sizeof(g_vehicle_ip_known));
    g_lkh_n_leaves = (n_vehicles < LKH_MAX_VEH) ? n_vehicles : LKH_MAX_VEH;

    for (int i = 0; i < n_vehicles && i < LKH_MAX_VEH; i++) {
        uint8_t idx_b[4] = { (uint8_t)(i & 0xFF), (uint8_t)((i>>8)&0xFF),
                             (uint8_t)((i>>16)&0xFF), (uint8_t)((i>>24)&0xFF) };
        lkh_kdf(g_lkh_root_seed, LKH_KEY_BYTES, idx_b, 4,
                (const uint8_t*)"limbo", 5, g_vehicle_leaf_key[i]);
        lkh_compute_session_key(i);
    }
    printf("[LKH] Bootstrap (limbo) session keys initialised for %d vehicles\n", n_vehicles);
}

// ── Build the controller-managed RSU-ring subtree ─────────────────────────────
// Paper §3.5.2: "The n RSUs in the TRS signing ring form a separate LKH subtree
// managed by the SDN controller." Each RSU r_j is a leaf; its leaf key K_{u_j}
// is the ring-subtree leaf node key (derived from K_ring), replacing the prior
// `root XOR idx` shortcut.
static void lkh_ring_build(int n_rsus)
{
    int cap = 1; while (cap < n_rsus) cap <<= 1; if (cap < 1) cap = 1;
    g_lkh_ring_tree.cap        = cap;
    g_lkh_ring_tree.first_leaf = cap - 1;
    int total = 2 * cap - 1;
    g_lkh_ring_tree.nodes.assign((size_t)total, LkhNode{});
    for (int i = 0; i < total; i++)
        lkh_derive_node_key_from(g_lkh_k_ring_current, i, g_lkh_ring_tree.nodes[i].key);
}

// ── Derive RSU ring signing keys sk_j (Eq.3.25): sk_j = KDF(K_{u_j}, K_ring, ID) ─
static void lkh_init_rsu_ring_keys(int n_rsus)
{
    // K_ring generated from the OS CSPRNG by lkh_init_master_keys() (idempotent).
    lkh_init_master_keys();
    lkh_ring_build(n_rsus);

    for (int j = 0; j < n_rsus && j < MAX_RSUS; j++) {
        const uint8_t *k_u_j = g_lkh_ring_tree.nodes[g_lkh_ring_tree.first_leaf + j].key;
        uint8_t id_rj[4] = { (uint8_t)j, 0, 0, 0 };
        lkh_kdf(k_u_j,                LKH_KEY_BYTES,
                g_lkh_k_ring_current, LKH_KEY_BYTES,
                id_rj,                4,
                g_rsu_ring_key[j]);
        printf("[LKH] RSU ring key sk_%d derived from ring subtree leaf (Eq.3.25)\n", j);
    }
}

// ── FHE share distribution over the authenticated ring channel (Eq.3.25) ──────
// Deposit party `party_idx`'s serialized FHE secret-key share with an HMAC-SHA256
// tag under the current ring key. party_idx: 0..n-1 = RSU, n = cloud.
static bool lkh_ring_distribute_share(int party_idx,
                                      const uint8_t *share, size_t len)
{
    if (party_idx < 0 || party_idx >= LKH_RING_PARTIES) return false;
    LkhRingShareSlot &slot = g_lkh_ring_share[party_idx];
    slot.bytes.assign(share, share + len);

    // tag = HMAC_{K_ring}( party_idx(4B) ‖ share_bytes )
    std::vector<uint8_t> msg;
    msg.reserve(4 + len);
    uint32_t pid = (uint32_t)party_idx;
    for (int b = 0; b < 4; b++) msg.push_back((uint8_t)((pid >> (b*8)) & 0xFF));
    msg.insert(msg.end(), share, share + len);
    lkh_hmac_sha256(g_lkh_k_ring_current, LKH_KEY_BYTES,
                    msg.data(), msg.size(), slot.tag);
    slot.present = true;
    return true;
}

// Retrieve + authenticate party `party_idx`'s FHE share. Returns false on
// absence or HMAC-tag mismatch (rejects an unauthenticated/forged share).
static bool lkh_ring_retrieve_share(int party_idx, std::vector<uint8_t> &out)
{
    if (party_idx < 0 || party_idx >= LKH_RING_PARTIES) return false;
    const LkhRingShareSlot &slot = g_lkh_ring_share[party_idx];
    if (!slot.present) return false;

    std::vector<uint8_t> msg;
    msg.reserve(4 + slot.bytes.size());
    uint32_t pid = (uint32_t)party_idx;
    for (int b = 0; b < 4; b++) msg.push_back((uint8_t)((pid >> (b*8)) & 0xFF));
    msg.insert(msg.end(), slot.bytes.begin(), slot.bytes.end());

    uint8_t expect[LKH_KEY_BYTES];
    lkh_hmac_sha256(g_lkh_k_ring_current, LKH_KEY_BYTES,
                    msg.data(), msg.size(), expect);
    uint8_t diff = 0;
    for (int i = 0; i < LKH_KEY_BYTES; i++) diff |= (expect[i] ^ slot.tag[i]);
    if (diff != 0) return false;

    out = slot.bytes;
    return true;
}

// ── RSU ring rekey on RSU revocation (Eq.3.24): N_ring = (n-1) ────────────────
// Rotates the current ring key and re-derives sk_j for all surviving RSUs, so a
// revoked RSU (whose leaf key is updated) can no longer derive a valid sk_j and
// is excluded from subsequent TRS signing rounds (Eq.3.49). Returns N_ring=(n-1).
static int lkh_ring_rekey(int n_rsus, double sim_time, int revoked_rsu_idx)
{
    if (n_rsus <= 0 || n_rsus > 4) return 0;

    // Rotate K_ring: K_ring' = KDF(K_ring, time, "ring-rekey")
    uint8_t time_bytes[8];
    uint64_t ti = (uint64_t)(sim_time * 1e6);
    for (int b = 0; b < 8; b++) time_bytes[b] = (uint8_t)((ti >> (b*8)) & 0xFF);
    uint8_t new_ring[LKH_KEY_BYTES];
    lkh_kdf(g_lkh_k_ring_current, LKH_KEY_BYTES,
            time_bytes,           8,
            (const uint8_t*)"ring-rekey", 10,
            new_ring);
    std::memcpy(g_lkh_k_ring_current, new_ring, LKH_KEY_BYTES);

    // Rebuild the ring subtree from the rotated K_ring, then re-derive sk_j for
    // survivors (revoked RSU is skipped → loses signing power, Eq.3.49).
    lkh_ring_build(n_rsus);
    for (int j = 0; j < n_rsus && j < MAX_RSUS; j++) {
        if (j == revoked_rsu_idx) {
            std::memset(g_rsu_ring_key[j], 0, LKH_KEY_BYTES);
            continue;
        }
        const uint8_t *k_u_j = g_lkh_ring_tree.nodes[g_lkh_ring_tree.first_leaf + j].key;
        uint8_t id_rj[4] = { (uint8_t)j, 0, 0, 0 };
        lkh_kdf(k_u_j, LKH_KEY_BYTES, g_lkh_k_ring_current, LKH_KEY_BYTES,
                id_rj, 4, g_rsu_ring_key[j]);
    }
    int n_ring = n_rsus - 1;   // Eq.3.24
    printf("[LKH] Ring rekey (revoked RSU %d): N_ring=(n-1)=%d msgs (Eq.3.24)\n",
           revoked_rsu_idx, n_ring);
    return n_ring;
}

// ── Zone membership: join (paper §3.5.2 "vehicle registers with RSU r_j") ─────
// Assign veh_idx a free leaf slot in RSU `rsu`'s zone subtree, derive its zone
// leaf key K_{u_i} + session key K_i (Eq 3.22) with a fresh nonce. Grows on demand.
static bool lkh_zone_join(int rsu, int veh_idx)
{
    if (rsu < 0 || rsu >= (int)g_lkh_zone.size()) return false;
    if (veh_idx < 0 || veh_idx >= LKH_MAX_VEH)    return false;
    LkhZone &z = g_lkh_zone[rsu];
    if (z.n_members >= z.cap) lkh_zone_grow(z);
    int slot = -1;
    for (int s = 0; s < z.cap; s++) if (z.slot_owner[s] < 0) { slot = s; break; }
    if (slot < 0) return false;
    z.slot_owner[slot] = veh_idx; z.n_members++;
    z.nodes[z.first_leaf + slot].vehicle_id = (uint32_t)(veh_idx + 2);
    z.nodes[z.first_leaf + slot].revoked    = false;
    g_vehicle_zone[veh_idx] = rsu;
    g_vehicle_slot[veh_idx] = slot;
    std::memcpy(g_vehicle_leaf_key[veh_idx],
                z.nodes[z.first_leaf + slot].key, LKH_KEY_BYTES);
    g_vehicle_nonce[veh_idx]++;                          // fresh η_i on registration
    lkh_compute_session_key(veh_idx);
    return true;
}

// ── Zone membership: benign handoff-leave (no rekey storm) ────────────────────
// Vehicle exits its current zone. Free its slot and rotate the zone group key
// along its path (forward secrecy of K_root). Surviving members keep their K_i
// (their leaf keys are unchanged), so NO unicast rekey packets are needed for a
// benign departure — the costly all-member rekey is reserved for SECURITY
// revocation (lkh_rekey_on_revoke). Returns N_rekey depth for accounting.
static int lkh_zone_handoff_leave(int veh_idx, double sim_time)
{
    int rsu = g_vehicle_zone[veh_idx];
    if (rsu < 0 || rsu >= (int)g_lkh_zone.size()) return 0;
    LkhZone &z = g_lkh_zone[rsu];
    int slot = g_vehicle_slot[veh_idx];
    if (slot >= 0 && slot < z.cap && z.slot_owner[slot] == veh_idx) {
        z.slot_owner[slot] = -1; z.n_members--;
        z.nodes[z.first_leaf + slot].vehicle_id = 0;
    }
    g_vehicle_zone[veh_idx] = -1; g_vehicle_slot[veh_idx] = -1;
    return lkh_zone_rekey_path(z, slot, sim_time);
}

// ── Membership trigger from RSU beacon reception (call from 08 AFTER verify) ──
// first contact → join; contact at a different RSU → handoff; same zone → no-op.
// Verify the beacon HMAC with the CURRENT K_i BEFORE calling this, so the
// in-flight beacon validates against the key it was actually signed with.
static void lkh_on_beacon_at_rsu(int rsu, int veh_idx, double sim_time)
{
    if (veh_idx < 0 || veh_idx >= LKH_MAX_VEH) return;
    if (rsu < 0 || rsu >= (int)g_lkh_zone.size()) return;
    int cur = g_vehicle_zone[veh_idx];
    if (cur == rsu) return;
    if (cur >= 0) lkh_zone_handoff_leave(veh_idx, sim_time);   // moving on
    lkh_zone_join(rsu, veh_idx);
}

// Vehicle-side: install a leaf key delivered in a RekeyTag (used by 07).
static void lkh_vehicle_install_leaf(int veh_idx, const uint8_t *new_leaf)
{
    if (veh_idx < 0 || veh_idx >= LKH_MAX_VEH) return;
    std::memcpy(g_vehicle_leaf_key[veh_idx], new_leaf, LKH_KEY_BYTES);
}

// Current zone population |V_j| (for metrics/logging).
static int lkh_zone_population(int rsu)
{
    if (rsu < 0 || rsu >= (int)g_lkh_zone.size()) return 0;
    return g_lkh_zone[rsu].n_members;
}

// ── Rekey on vehicle revocation (security) — zone-scoped (§3.5.2, Eq.3.23) ────
// Marks veh_idx revoked, frees its slot, rekeys its zone path for forward
// secrecy, and fills g_lkh_affected_members with the SURVIVING members of THAT
// ZONE — the only vehicles that share path keys with the revoked one. This is
// the paper improvement: N_rekey = log₂|V_j| (zone population), not log₂(total).
// 08 unicasts a fresh-key (nonce-bumped) RekeyTag to each affected member.
static int lkh_rekey_on_revoke(int veh_idx, double sim_time)
{
    g_lkh_affected_members.clear();
    if (veh_idx < 0 || veh_idx >= LKH_MAX_VEH) return 0;
    int rsu = g_vehicle_zone[veh_idx];
    if (rsu < 0 || rsu >= (int)g_lkh_zone.size()) {
        printf("[LKH] Revoke veh_idx=%d: not registered to any zone (limbo), "
               "no zone rekey needed\n", veh_idx);
        return 0;
    }
    LkhZone &z = g_lkh_zone[rsu];
    int slot = g_vehicle_slot[veh_idx];
    if (slot >= 0 && slot < z.cap && z.slot_owner[slot] == veh_idx) {
        z.nodes[z.first_leaf + slot].revoked = true;
        z.slot_owner[slot] = -1; z.n_members--;
    }
    g_vehicle_zone[veh_idx] = -1; g_vehicle_slot[veh_idx] = -1;

    lkh_zone_rekey_path(z, slot, sim_time);             // forward secrecy

    for (int s = 0; s < z.cap; s++)
        if (z.slot_owner[s] >= 0) g_lkh_affected_members.push_back(z.slot_owner[s]);

    int vj = z.n_members;                               // survivors |V_j|
    int n_rekey = 0; for (int c = (vj > 0 ? vj : 1); c > 1; c >>= 1) n_rekey++;
    printf("[LKH] Revoke veh_idx=%d from zone %d: %zu surviving zone members to "
           "rekey (Eq.3.23 N_rekey=log2|V_j|=log2(%d)≈%d)\n",
           veh_idx, rsu, g_lkh_affected_members.size(), vj, n_rekey);
    return n_rekey;
}

// ── Compute beacon HMAC-SHA256 (Eq.3.37) ─────────────────────────────────────
// MAC_i(t) = HMAC_{K_i}(b_i(t) ‖ t ‖ ID_i)
// message = pos_x(8B) ‖ pos_y(8B) ‖ speed(8B) ‖ heading(8B) ‖ accel(8B) ‖ t(8B) ‖ ID_i(4B)
// Output: first LKH_HMAC_TRUNC bytes of the 32-byte HMAC (truncated tag for beacon overhead)
static void lkh_compute_beacon_hmac(int veh_idx,
                                     double px, double py,
                                     double speed, double heading, double accel,
                                     double t,
                                     uint32_t nid,
                                     uint8_t out_mac[LKH_HMAC_TRUNC])
{
    if (veh_idx < 0 || veh_idx >= LKH_MAX_VEH) {
        std::memset(out_mac, 0, LKH_HMAC_TRUNC);
        return;
    }

    // Build message: 6 doubles (48 bytes) + 1 uint32 (4 bytes) = 52 bytes
    uint8_t msg[52];
    std::memcpy(msg +  0, &px,      8);
    std::memcpy(msg +  8, &py,      8);
    std::memcpy(msg + 16, &speed,   8);
    std::memcpy(msg + 24, &heading, 8);
    std::memcpy(msg + 32, &accel,   8);
    std::memcpy(msg + 40, &t,       8);
    std::memcpy(msg + 48, &nid,     4);

    uint8_t full_mac[LKH_KEY_BYTES];
    bool ok = lkh_hmac_sha256(g_vehicle_session_key[veh_idx], LKH_KEY_BYTES,
                               msg, sizeof(msg),
                               full_mac);
    if (ok) {
        std::memcpy(out_mac, full_mac, LKH_HMAC_TRUNC);
    } else {
        std::memset(out_mac, 0, LKH_HMAC_TRUNC);
    }
}

// ── Verify beacon HMAC at RSU ─────────────────────────────────────────────────
// Returns true if the MAC in the tag matches what the RSU recomputes.
static bool lkh_verify_beacon_hmac(int veh_idx,
                                    double px, double py,
                                    double speed, double heading, double accel,
                                    double t,
                                    uint32_t nid,
                                    const uint8_t recv_mac[LKH_HMAC_TRUNC])
{
    if (veh_idx < 0 || veh_idx >= LKH_MAX_VEH) return false;

    uint8_t expected[LKH_HMAC_TRUNC];
    lkh_compute_beacon_hmac(veh_idx, px, py, speed, heading, accel, t, nid, expected);

    // Constant-time comparison (avoid timing oracle)
    uint8_t diff = 0;
    for (int i = 0; i < LKH_HMAC_TRUNC; i++)
        diff |= (expected[i] ^ recv_mac[i]);
    return (diff == 0);
}

// ── Convenience: veh_idx from NS-3 node ID ───────────────────────────────────
static inline int lkh_veh_idx(uint32_t nid) {
    return (nid >= 2) ? (int)(nid - 2) : -1;
}

// ── Master init (call once from 12_main.h before Simulator::Run) ─────────────
// n_vehicles = N_Vehicles, n_rsus = N_RSUs
static void lkh_init_all(int n_vehicles, int n_rsus)
{
    lkh_init_master_keys();          // CSPRNG K_root + K_ring (must precede subtree build)
    lkh_zones_init(n_rsus);          // per-RSU-zone vehicle subtrees (paper §3.5.2)
    lkh_init_session_keys(n_vehicles); // bootstrap/limbo K_i until first RSU contact
    lkh_init_rsu_ring_keys(n_rsus);  // controller-managed RSU ring subtree + sk_j
    printf("[LKH] Full init complete (per-zone topology). HMAC-SHA256 beacon "
           "tagging active (Eq.3.37); vehicles join zones on first RSU contact.\n");
}

#endif // MPTD_PQS_LKH_KEYS_H
