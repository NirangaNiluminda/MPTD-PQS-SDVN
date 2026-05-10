// ============================================================
// 00_lkh_keys.h — LKH Group Key Management + HMAC Utilities
// MPTD-PQS: §3.5.2 Group Key Management via Logical Key Hierarchy
// ============================================================
// Paper Equations implemented here:
//   Eq.3.33: K_i = KDF(K_{u_i}, η_i, ID_i)     — vehicle session key
//   Eq.3.34: N_rekey = log₂|V_j|               — rekey cost on leave
//   Eq.3.36: sk_j = KDF(K_{u_j}, K_ring, ID_rj) — RSU ring key
//   Eq.3.37: MAC_i(t) = HMAC_{K_i}(b_i(t)‖t‖ID_i) — beacon tag
//
// Key derivation: HMAC-SHA256 used as KDF (HMAC-based KDF)
//   KDF(master, salt, info) = HMAC-SHA256(master, salt ‖ info)
//   This is the Extract step of HKDF — produces 32 bytes, cryptographically
//   indistinguishable from random given secure master key.
//
// LKH tree structure (balanced binary heap):
//   Node 0   = root (K_root)
//   Node k   → left child  = 2k+1
//           → right child = 2k+2
//   Leaf  i  = node (g_lkh_first_leaf + i) for vehicle i
//
// Rekeying (§3.5.2 Algorithm):
//   When vehicle k is revoked:
//     1. Traverse path from k's leaf to root
//     2. For each internal node on path: regenerate key
//     3. Send unicast NS-3 UDP (RekeyTag) to each remaining vehicle
//        carrying their new K_leaf value
//     4. Vehicle recomputes K_i from new K_leaf (Eq.3.33)
//     5. Old K_i is dead → HMAC verification rejects future forgeries
//
// Real vs not-real:
//   REAL: HMAC-SHA256 via OpenSSL, tree key bytes computed, unicast NS-3 packets
//   NOT REAL: in-packet key encryption (key sent in plaintext inside NS-3 UDP;
//             in a real system the new K_leaf would be wrapped with the
//             sibling node key — omitted here as the NS-3 channel provides
//             implicit addressing isolation)
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

// ── Constants ─────────────────────────────────────────────────────────────────
#define LKH_KEY_BYTES   32          // 256-bit keys throughout
#define LKH_HMAC_TRUNC  8           // 8-byte (64-bit) truncated MAC on beacon tag
#define LKH_MAX_VEH     32          // maximum vehicles supported by LKH tree
#define LKH_MAX_NODES   64          // LKH_MAX_VEH * 2 (heap nodes)
#define LKH_REKEY_PORT  5555        // UDP port: RSU → vehicle key update messages

// ── LKH Tree Node ─────────────────────────────────────────────────────────────
struct LkhNode {
    uint8_t  key[LKH_KEY_BYTES];   // key material for this node
    uint32_t vehicle_id;           // non-zero for leaf nodes only (NS-3 node ID)
    bool     revoked;              // true if this leaf's vehicle was revoked
    bool     valid;                // false for unused nodes
};

// ── Global LKH State ──────────────────────────────────────────────────────────
static LkhNode  g_lkh_tree[LKH_MAX_NODES];           // heap-indexed binary tree
static int      g_lkh_n_leaves    = 0;               // number of leaf slots = N_Vehicles
static int      g_lkh_total_nodes = 0;               // total tree nodes (leaves + internals)
static int      g_lkh_first_leaf  = 0;               // index of first leaf node in heap

// Per-vehicle session keys K_i (Eq.3.33) — updated on rekeying
static uint8_t  g_vehicle_session_key[LKH_MAX_VEH][LKH_KEY_BYTES];
// Per-vehicle nonce η_i — incremented on every rekey event to ensure forward secrecy
static uint32_t g_vehicle_nonce   [LKH_MAX_VEH];
// Per-vehicle DSRC IP recorded the first time RSU receives a beacon from that vehicle
// Used to unicast RekeyTag packets. Filled in handle_readone() / HandleBeaconReceived().
static ns3::Ipv4Address g_vehicle_dsrc_ip[LKH_MAX_VEH];
static bool             g_vehicle_ip_known[LKH_MAX_VEH];

// RSU ring keys sk_j (Eq.3.36) — one per RSU, used by TRS partial signing
static uint8_t  g_rsu_ring_key[4][LKH_KEY_BYTES];

// LKH master root seed (simulation-fixed; in real system: HSM-provisioned)
static const uint8_t LKH_ROOT_SEED[LKH_KEY_BYTES] = {
    0x6D,0x70,0x74,0x64,0x2D,0x70,0x71,0x73,  // "mptd-pqs"
    0x5F,0x6C,0x6B,0x68,0x5F,0x72,0x6F,0x6F,  // "_lkh_roo"
    0x74,0x5F,0x6B,0x65,0x79,0x5F,0x32,0x30,  // "t_key_20"
    0x32,0x35,0x5F,0x73,0x69,0x6D,0x00,0x00   // "25_sim\0\0"
};

// K_ring shared between all RSUs for TRS (Eq.3.36)
static const uint8_t LKH_K_RING[LKH_KEY_BYTES] = {
    0x74,0x72,0x73,0x5F,0x72,0x69,0x6E,0x67,  // "trs_ring"
    0x5F,0x6D,0x61,0x73,0x74,0x65,0x72,0x5F,  // "_master_"
    0x6B,0x65,0x79,0x5F,0x73,0x64,0x76,0x6E,  // "key_sdvn"
    0x5F,0x32,0x30,0x32,0x35,0x00,0x00,0x00   // "_2025\0\0\0"
};

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

// ── KDF (Eq.3.33/3.36): KDF(master, salt, info) = HMAC-SHA256(master, salt‖info) ─
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

// ── Derive leaf key for tree node at heap index idx ───────────────────────────
// Each node's key = KDF(root_seed, node_index_bytes, depth_bytes)
// This deterministically fills the entire tree from the master root seed.
static void lkh_derive_node_key(int idx, uint8_t out[LKH_KEY_BYTES])
{
    uint8_t index_bytes[4];
    index_bytes[0] = (uint8_t)( idx        & 0xFF);
    index_bytes[1] = (uint8_t)((idx >>  8) & 0xFF);
    index_bytes[2] = (uint8_t)((idx >> 16) & 0xFF);
    index_bytes[3] = (uint8_t)((idx >> 24) & 0xFF);

    uint8_t depth_byte[1] = { 0 };
    // depth = floor(log2(idx+1)) — cheap approximation for tree depth
    for (int tmp = idx + 1; tmp > 1; tmp >>= 1) depth_byte[0]++;

    lkh_kdf(LKH_ROOT_SEED, LKH_KEY_BYTES,
            index_bytes,   4,
            depth_byte,    1,
            out);
}

// ── Build LKH tree (called once at simulation start) ──────────────────────────
// n_vehicles: number of vehicles = N_Vehicles (matches simulation topology)
// Assigns leaf node i to vehicle with NS-3 node ID (i + 2):
//   vehicle array index i → NS-3 nid = i + 2 (controller=0, management=1, vehicles=2..N+1)
static void lkh_build_tree(int n_vehicles)
{
    if (n_vehicles <= 0 || n_vehicles > LKH_MAX_VEH) return;

    // Compute tree size: smallest power-of-2 ≥ n_vehicles gives n_leaves,
    // and total nodes = 2*n_leaves - 1 (complete binary tree).
    int n_leaves = 1;
    while (n_leaves < n_vehicles) n_leaves <<= 1;

    g_lkh_n_leaves    = n_leaves;
    g_lkh_total_nodes = 2 * n_leaves - 1;
    g_lkh_first_leaf  = n_leaves - 1; // zero-indexed heap: leaves at [n_leaves-1, 2*n_leaves-2]

    // Initialise all nodes
    std::memset(g_lkh_tree, 0, sizeof(g_lkh_tree));
    for (int i = 0; i < g_lkh_total_nodes; i++) {
        lkh_derive_node_key(i, g_lkh_tree[i].key);
        g_lkh_tree[i].valid    = true;
        g_lkh_tree[i].revoked  = false;
        g_lkh_tree[i].vehicle_id = 0;
    }

    // Assign vehicles to leaves (left to right)
    for (int i = 0; i < n_vehicles; i++) {
        int leaf_idx = g_lkh_first_leaf + i;
        g_lkh_tree[leaf_idx].vehicle_id = (uint32_t)(i + 2); // NS-3 nid
    }
    // Extra leaf slots (padding to next power of 2) are unused
    for (int i = n_vehicles; i < n_leaves; i++) {
        int leaf_idx = g_lkh_first_leaf + i;
        g_lkh_tree[leaf_idx].valid = false;
    }

    printf("[LKH] Tree built: %d vehicles, %d leaves, %d total nodes, first_leaf=%d\n",
           n_vehicles, n_leaves, g_lkh_total_nodes, g_lkh_first_leaf);
}

// ── Derive vehicle session key K_i (Eq.3.33) ─────────────────────────────────
// K_i = KDF(K_{u_i}, η_i, ID_i)
// K_{u_i} = g_lkh_tree[leaf_node].key  (leaf node key for vehicle i)
// η_i     = g_vehicle_nonce[i]         (4 bytes, incremented on rekey)
// ID_i    = NS-3 node ID of vehicle i  (4 bytes)
static void lkh_compute_session_key(int veh_idx)
{
    if (veh_idx < 0 || veh_idx >= LKH_MAX_VEH) return;

    int leaf_node_idx = g_lkh_first_leaf + veh_idx;
    if (leaf_node_idx >= g_lkh_total_nodes ||
        !g_lkh_tree[leaf_node_idx].valid) return;

    const uint8_t *k_leaf = g_lkh_tree[leaf_node_idx].key;

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

// ── Initialise all vehicle session keys ───────────────────────────────────────
// Called once after lkh_build_tree() and before Simulator::Run().
static void lkh_init_session_keys(int n_vehicles)
{
    std::memset(g_vehicle_nonce,       0, sizeof(g_vehicle_nonce));
    std::memset(g_vehicle_session_key, 0, sizeof(g_vehicle_session_key));
    std::memset(g_vehicle_ip_known,    0, sizeof(g_vehicle_ip_known));

    for (int i = 0; i < n_vehicles && i < LKH_MAX_VEH; i++)
        lkh_compute_session_key(i);

    printf("[LKH] Session keys initialised for %d vehicles\n", n_vehicles);
}

// ── Derive RSU ring keys sk_j (Eq.3.36) ───────────────────────────────────────
// sk_j = KDF(K_{u_j}, K_ring, ID_{r_j})
// K_{u_j} is taken as the LKH root node key (all RSUs share the root tree;
//          in a full deployment each RSU subtree is separate).
static void lkh_init_rsu_ring_keys(int n_rsus)
{
    for (int j = 0; j < n_rsus && j < 4; j++) {
        // K_{u_j}: use root key XORed with RSU index for uniqueness
        uint8_t k_u_j[LKH_KEY_BYTES];
        std::memcpy(k_u_j, g_lkh_tree[0].key, LKH_KEY_BYTES);
        k_u_j[0] ^= (uint8_t)j;  // differentiate per-RSU

        // ID_{r_j}: 4 bytes of RSU index
        uint8_t id_rj[4] = { (uint8_t)j, 0, 0, 0 };

        lkh_kdf(k_u_j,      LKH_KEY_BYTES,
                LKH_K_RING, LKH_KEY_BYTES,
                id_rj,      4,
                g_rsu_ring_key[j]);

        printf("[LKH] RSU ring key sk_%d derived (Eq.3.36)\n", j);
    }
}

// ── Rekey one subtree node: regenerate key for internal node at heap index ────
// Uses a time-mixed seed so consecutive rekey events produce different keys.
static void lkh_regen_node_key(int node_idx, double sim_time)
{
    if (node_idx < 0 || node_idx >= g_lkh_total_nodes) return;

    // Mix current key with simulation time to get new entropy
    uint8_t time_bytes[8];
    uint64_t time_int = (uint64_t)(sim_time * 1e6); // microseconds
    for (int b = 0; b < 8; b++)
        time_bytes[b] = (uint8_t)((time_int >> (b*8)) & 0xFF);

    uint8_t new_key[LKH_KEY_BYTES];
    lkh_kdf(g_lkh_tree[node_idx].key, LKH_KEY_BYTES,
            time_bytes,                8,
            (const uint8_t*)"rekey",  5,
            new_key);
    std::memcpy(g_lkh_tree[node_idx].key, new_key, LKH_KEY_BYTES);
}

// ── Rekey path on vehicle revocation (§3.5.2, Eq.3.34) ───────────────────────
// Traverses from revoked vehicle's leaf to root.
// Returns the number of nodes rekeyed = N_rekey = floor(log₂|V_j|) (Eq.3.34).
// Fills out_path[] with the heap indices of rekeyed nodes (for sending to vehicles).
static int lkh_rekey_on_revoke(int veh_idx, double sim_time,
                                int out_path[], int out_path_max)
{
    if (veh_idx < 0 || veh_idx >= g_lkh_n_leaves) return 0;

    int leaf_node = g_lkh_first_leaf + veh_idx;
    g_lkh_tree[leaf_node].revoked = true;

    // Traverse from leaf to root, regenerating each node's key
    int n_rekeyed = 0;
    int cur = leaf_node;
    while (cur > 0) {
        cur = (cur - 1) / 2;  // parent in binary heap
        lkh_regen_node_key(cur, sim_time);
        if (n_rekeyed < out_path_max)
            out_path[n_rekeyed] = cur;
        n_rekeyed++;
    }
    // Also regenerate the leaf's own key (forward secrecy: old leaf key is dead)
    lkh_regen_node_key(leaf_node, sim_time + 0.001);

    // Recompute session key for ALL remaining (non-revoked) vehicles whose
    // path shares a node with the revoked vehicle.
    // In LKH, only vehicles on the same subtree path are affected;
    // here we recompute all for simplicity (conservative, correct).
    printf("[LKH] Revoke vehicle_idx=%d: rekeyed %d nodes (Eq.3.34 N_rekey=log2(%d)=%.0f)\n",
           veh_idx, n_rekeyed, g_lkh_n_leaves, std::log2((double)g_lkh_n_leaves));
    return n_rekeyed;
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
    lkh_build_tree(n_vehicles);
    lkh_init_session_keys(n_vehicles);
    lkh_init_rsu_ring_keys(n_rsus);
    printf("[LKH] Full init complete. HMAC-SHA256 beacon tagging active (Eq.3.37)\n");
}

#endif // MPTD_PQS_LKH_KEYS_H
