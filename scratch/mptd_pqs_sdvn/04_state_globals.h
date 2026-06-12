// ============================================================
// SECTION 4: Runtime State Variables
// MPTD-PQS: Dual-Mode Detection for MP and TP Attacks in SDVN
// ============================================================
// Contents:
//   - Network timing/utilization: dsrc, lte, packet delay
//   - MPTD-PQS trajectory state: position/velocity history per vehicle
//   - Drift score buffers for TP-S4/TP-S5 detection
//   - Sybil identity tracker per RSU for MP-S1 detection
// ============================================================

#ifndef NS3_UDP_ARQ_APPLICATION_H
#define NS3_UDP_ARQ_APPLICATION_H

#include <set>     // SC-Register registered-vid cache (P6 detection gate)

// ── Network Performance Timing (kept from original) ───────────────────────
double dsrc_utilization_time        = 0.0;
double lte_utilization_time         = 0.0;
double dsrc_total_received_packets  = 0.0;

double packet_delay[total_size + 2];
double packet_delay_dsrc[total_size + 2];

double dsrc_packet_initial_timestamp[total_size + 2];
double dsrc_packet_final_timestamp[total_size + 2];
double dsrc_initial_timestamp;
double dsrc_final_timestamp;

double lte_initial_timestamp;
double lte_final_timestamp;

double aodv_initial_timestamp[total_size + 2];
double aodv_final_timestamp[total_size + 2];

double max_distance[total_size + 2];

// ── MPTD-PQS: Per-Vehicle Beacon State ────────────────────────────────────
// Stores the last N beacons per vehicle for temporal detection algorithms.
// Used by TP-DETECT (Algorithm 1) and SYB-DETECT (Algorithm 2).

#define BEACON_HISTORY 20   // window size for drift score (k in paper)

struct VehicleBeaconState {
    double pos_x[BEACON_HISTORY];   // p_i(t) x-coordinate history
    double pos_y[BEACON_HISTORY];   // p_i(t) y-coordinate history
    double speed[BEACON_HISTORY];   // s_i(t) speed history (m/s)
    double heading[BEACON_HISTORY]; // θ_i(t) heading history (rad)
    double accel[BEACON_HISTORY];   // a_i(t) acceleration history (m/s²)
    double timestamp[BEACON_HISTORY]; // beacon timestamp history
    int    head;                    // circular buffer head index
    int    count;                   // number of valid entries
    double drift_score;             // D_i(k): cumulative drift (Eq. 3.15)
    bool   is_malicious;            // ground truth for this vehicle
};

VehicleBeaconState vehicle_state[total_size];

// ── Pre-registered Sybil flags (Attack 3 enhanced mode) ──────────────────────
// pre_registered_sybil[i] = true means vehicle i was designated as Sybil
// BEFORE the simulation starts — it has a valid, registered pool ID.
// Set by declare_pre_registered_sybils() in 06a_attack_models.h.
// Used by declare_attackers() to gate sybil_mitm_nodes[] assignment:
//   sybil_mitm_nodes[i] = present_sybil_mitm_attack && attack_pct_gate && pre_registered_sybil[i]
// This ensures only pre-registered vehicles can be active Sybil in attack 3 enhanced mode.
bool pre_registered_sybil[total_size];

// Initialise all vehicle beacon state buffers
void init_vehicle_states() {
    for (int i = 0; i < total_size; i++) {
        vehicle_state[i].head  = 0;
        vehicle_state[i].count = 0;
        vehicle_state[i].drift_score  = 0.0;
        vehicle_state[i].is_malicious = false;
        pre_registered_sybil[i]       = false;  // cleared; set by declare_pre_registered_sybils()
        for (int j = 0; j < BEACON_HISTORY; j++) {
            vehicle_state[i].pos_x[j]     = 0.0;
            vehicle_state[i].pos_y[j]     = 0.0;
            vehicle_state[i].speed[j]     = 0.0;
            vehicle_state[i].heading[j]   = 0.0;
            vehicle_state[i].accel[j]     = 0.0;
            vehicle_state[i].timestamp[j] = 0.0;
        }
    }
}

// Push a new beacon reading into the circular buffer for vehicle vid
void push_beacon(int vid, double px, double py, double sp,
                 double hd, double ac, double ts) {
    if (vid < 0 || vid >= total_size) return;
    VehicleBeaconState &vs = vehicle_state[vid];
    vs.pos_x[vs.head]     = px;
    vs.pos_y[vs.head]     = py;
    vs.speed[vs.head]     = sp;
    vs.heading[vs.head]   = hd;
    vs.accel[vs.head]     = ac;
    vs.timestamp[vs.head] = ts;
    vs.head = (vs.head + 1) % BEACON_HISTORY;
    if (vs.count < BEACON_HISTORY) vs.count++;
}

// Pop the MOST RECENTLY pushed beacon from the circular buffer.
// Used by the controller (HandleBeaconReceived) before re-running LW-DETECT
// on a controller-poisoned beacon (attacks 5/7 = TP-S3 / MP-S4). The RSU has
// already pushed the unmodified beacon during its own LW-DETECT pass; we pop
// that entry so the re-push (with controller-modified kinematics) lands in the
// same logical slot — avoiding double-counting in TP-DETECT velocity/drift checks.
void pop_last_beacon(int vid) {
    if (vid < 0 || vid >= total_size) return;
    VehicleBeaconState &vs = vehicle_state[vid];
    if (vs.count == 0) return;
    // step head back one slot (wrap around)
    vs.head = (vs.head + BEACON_HISTORY - 1) % BEACON_HISTORY;
    vs.count--;
    // zero the popped slot to avoid stale read on next push
    vs.pos_x[vs.head]     = 0.0;
    vs.pos_y[vs.head]     = 0.0;
    vs.speed[vs.head]     = 0.0;
    vs.heading[vs.head]   = 0.0;
    vs.accel[vs.head]     = 0.0;
    vs.timestamp[vs.head] = 0.0;
}

// ── MPTD-PQS: Per-RSU Sybil Identity Tracker (MP-S1) ─────────────────────
// Tracks distinct vehicle IDs seen per RSU for identity density check.
#define MAX_IDS_PER_RSU 64

struct RsuIdentitySet {
    uint32_t ids[MAX_IDS_PER_RSU];
    int      count;
    double   window_start; // time window start for density check
    bool     ghost_seen;   // true if ANY ghost packet (vid>=10000) registered this window
                           // Set by compromised RSU ghost injection (MP-S1 attack 3 only)
                           // Cleared on window reset. Used for CSMA-order-robust detection.
};

RsuIdentitySet rsu_id_set[total_size]; // indexed by RSU node id

// ── RSU compromise flags (TP-S1, MP-S1) ──────────────────────────────────────
// compromised_rsu[i] = true means RSU i intercepts+modifies vehicle data.
// Set by declare_compromised_rsus() in 11_blockchain_transmission.h.
bool compromised_rsu[MAX_RSUS] = {};

// ── SC-Register: registered-vehicle cache (paper §3.5.5 Algorithm 7) ─────────
// Populated by register_all_nodes() in 11_blockchain_setup.h on each successful
// vehicle SCRegister commit. Read by the unregistered-vehicle gate in
// 08_detection_engine.h::handle_readone() before any detection-pipeline work
// runs for an arriving beacon.
//
// Cache key = vehicle NS-3 NodeID (raw nid, == BsmBeaconTag::GetVehicleId()).
// This matches the cache check site in handle_readone, where vid is already
// available as a uint32_t. The chaincode-facing prefixed string ID
// ("VEH_<nid>") is *not* used here — the gate is a pure local lookup so
// invariant 3 (lightweight skip-on-pass at RSU, no blockchain call on the
// fast path) holds.
//
// Gate bypass: when skip_blockchain=true or ablation_mode==5 (A5: no-BC) the
// set is empty / not populated, and the gate falls through. The detection
// pipeline then runs over every beacon as if SC-Register were absent — this
// is what A5 ablation requires for RQ6 (paper §4.1.1, blockchain isolation).
std::set<uint32_t> g_registered_vids;

// ── Counter for end-of-run metrics print ─────────────────────────────────────
// Incremented once per gate-rejected beacon (vid not in g_registered_vids).
// Distinct from cm_FN: a rejected beacon is *not* counted as a detection event
// — it never enters the LW-DETECT / TP-DETECT / MITM-DETECT pipeline, so
// MCC/FPR/PARR/CDER are not inflated by unregistered-vid noise.
uint64_t unregistered_beacon_reject_count = 0;

// ── Option B: DSRC-RSU relay globals ──────────────────────────────────────────
// Set by 12_main.h after node creation + IP assignment, before Simulator::Run().
// When g_option_b_active=true, vehicle beacons flow:
//   Vehicle → DSRC unicast → RSU (HandleBeaconAtRSU) → CSMA → management_node
// When false: legacy LTE path (Vehicle → LTE → management_node directly).
Ipv4Address g_management_csma_ip;            // management_node CSMA IP (10.1.1.6)
Ipv4Address g_rsu_dsrc_ip[MAX_RSUS];                // RSU DSRC IPs from dsrc_interfaces (3.x.x.x)
Ipv4Address g_rsu_csma_ip[MAX_RSUS];               // RSU CSMA IPs for management → RSU downlink (10.1.1.x)
uint32_t    g_first_rsu_node_id = 0;         // NS-3 NodeID of RSU_Nodes.Get(0)
uint32_t    g_first_vehicle_node_id = 0;     // NS-3 NodeID of Vehicle_Nodes.Get(0)
                                             //   (R7e.4: needed to convert raw NodeID
                                             //   carried in BsmBeaconTag back to the
                                             //   local vehicle index 0..N_Vehicles-1
                                             //   used by IMobilityProvider::get_gt_position
                                             //   and the per-vehicle state arrays)
uint32_t    g_num_active_rsus   = 0;         // = N_RSUs when routing_test=true
bool        g_option_b_active   = false;     // set true by 12_main.h when relay is ready
Ptr<Socket>  g_mgmt_downlink_socket;         // management node's downlink send socket (set in StartApplication)

void init_rsu_id_sets() {
    for (int i = 0; i < total_size; i++) {
        rsu_id_set[i].count        = 0;
        rsu_id_set[i].window_start = 0.0;
        rsu_id_set[i].ghost_seen   = false;
        for (int j = 0; j < MAX_IDS_PER_RSU; j++)
            rsu_id_set[i].ids[j] = 0;
    }
}

// Register a vehicle ID seen at RSU; returns true if new in window
bool register_vehicle_at_rsu(int rsu_id, uint32_t vehicle_id, double now) {
    if (rsu_id < 0 || rsu_id >= total_size) return false;
    RsuIdentitySet &rs = rsu_id_set[rsu_id];
    // Reset window every second
    if (now - rs.window_start > 1.0) {
        rs.count      = 0;
        rs.window_start = now;
        rs.ghost_seen = false;  // clear ghost flag for new window
    }
    for (int i = 0; i < rs.count; i++)
        if (rs.ids[i] == vehicle_id) return false;
    if (rs.count < MAX_IDS_PER_RSU)
        rs.ids[rs.count++] = vehicle_id;
    return true;
}

// ── R3: Controller-side window aggregator (paper §3.5.3 Algorithm 1, Full mode) ─
// The controller is a NON-AUTHORITATIVE peer per architectural invariant #2.
// After R1 (LW-DETECT moved to RSU) and R2 (DSRC downlink emitted by RSU
// directly), the controller no longer drives the per-beacon decision pipeline.
// What remains here is aggregation/statistics + a window buffer for the
// not-yet-implemented Full-mode GAT + LSTM-AE pipeline (paper §3.5.3).
//
// Paper §3.5.3 describes a windowed approach where beacons are batched into
// W = L · T_b windows (L beacons per RSU per window). For now we store:
//   • per-RSU beacon count and anomaly count within the current window
//   • per-RSU running ψ sum for window-mean overlay metrics
//   • per-RSU window start time and a monotonic epoch counter
//
// When GAT/LSTM-AE land (Phase R7+), try_controller_window_rollover() will
// dispatch the accumulated kinematics to the spatial graph (GAT) and temporal
// autoencoder (LSTM-AE) modules; for now the rollover is a logging-only stub
// that proves the cadence is right.
#define WINDOW_L_BEACONS 10   // L: beacons per window (paper §3.5.3, Algorithm 1)
// W = L · T_b → with T_b=0.1 s this gives a 1.0 s window cadence.

struct ControllerWindow {
    uint32_t beacon_count;       // beacons aggregated in current window
    uint32_t anomalous_count;    // beacons with cached LW-DETECT anomalous=true
    uint32_t poisoned_count;     // beacons with ground-truth IsPoisoned=true
    double   psi_sum;            // running ψ accumulator for window mean
    double   window_start;       // current window start time (s)
    uint32_t window_epoch;       // monotonic window counter (rollovers seen)
};

// Indexed by RSU cell id 0..N_RSUs-1 (sized for capacity MAX_RSUS).
ControllerWindow ctrl_window[MAX_RSUS] = {};

// ── R4.c: IPFS Off-Chain Beacon Store (paper §3.5.3 Eq 3.56, Fig 3.9) ─────────
// RSUs accumulate L beacons per window, compute a cryptographic hash of the
// window, and "store" the {window, hash} off-chain in IPFS. The hash is then
// stored on-chain (RSU → blockchain direct per invariant #1). The Controller
// retrieves the window from IPFS using the hash to run GAT spatial + LSTM-AE
// temporal anomaly detection in Full mode (paper §3.5.3, pending phase R7+).
//
// Paper text (§3.5.3 around Fig 3.9):
//   "Beacon windows are stored off-chain in the IPFS Off-Chain Beacon Store
//    together with their cryptographic hashes, decoupling real-time RSU
//    processing from controller-side deep learning analysis."
//
// Simulation stub: no real IPFS daemon; we log [IPFS-STORE-RSUx] and
// [IPFS-HASH-CHAIN-RSUx] lines and increment counters. The hash is a
// deterministic FNV-1a digest of the concatenated beacon kinematics.
// Swap to OpenSSL EVP_sha3_256 for published runs.

#define IPFS_WINDOW_L 10   // L beacons per IPFS window (paper §3.5.3 Algorithm 1)

struct RsuBeaconWindow {
    uint32_t vid       [IPFS_WINDOW_L];
    double   pos_x     [IPFS_WINDOW_L];
    double   pos_y     [IPFS_WINDOW_L];
    double   speed     [IPFS_WINDOW_L];
    double   heading   [IPFS_WINDOW_L];
    double   accel     [IPFS_WINDOW_L];
    double   timestamp [IPFS_WINDOW_L];
    bool     anomalous [IPFS_WINDOW_L]; // cached LW-DETECT result per beacon
    bool     is_poisoned[IPFS_WINDOW_L];// ground-truth poison label per beacon
                                        // (Eq 4.1/4.2 GT for full-mode MCC/FPR)
    uint32_t beacon_count;              // filled slots in current window
    double   window_start;              // first beacon time of current window
    uint32_t window_epoch;              // monotonic window counter
};

RsuBeaconWindow rsu_window[MAX_RSUS] = {};

// ── R7e: Per-vehicle LSTM-AE ring buffer + ψ cache (paper §3.5.3 Eq 3.43–3.46) ─
// Full-mode temporal anomaly detection runs LSTM-AE over a 20-beacon sliding
// window per vehicle (gat_detector.py/lstm_ae.py WINDOW_SIZE=20). At every
// beacon the RSU-side handle_readone pushes the current kinematics into this
// ring; when ≥ 20 samples are present we can reconstruct + score.
//
// last_psi[vid] caches the most recent lightweight composite score ψ_i(t)
// (paper Eq 3.20) so the controller-side fusion step (Eq 3.46) can mix it with
// the per-window GAT spatial score and the LSTM-AE temporal score.
//
// Indexed by vehicle id (vid = nid - 2, range [0..total_size)) to match the
// pattern used by vehicle_state[] / pre_registered_sybil[] above.
#define LSTM_RING_SIZE 20    // matches WINDOW_SIZE in lstm_ae.py
struct VehicleLstmRing {
    float    pos_x   [LSTM_RING_SIZE];
    float    pos_y   [LSTM_RING_SIZE];
    float    speed   [LSTM_RING_SIZE];
    float    heading [LSTM_RING_SIZE];
    float    accel   [LSTM_RING_SIZE];
    uint32_t count     = 0;      // total samples ever pushed (filled+wrapped)
    uint32_t head      = 0;      // next write index (wraps at LSTM_RING_SIZE)
};

VehicleLstmRing vehicle_lstm_ring[total_size] = {};
double          last_psi_per_vehicle[total_size] = {};

// ── R7e.4: Controller TPE predictor state (paper Eq 4.6) ──────────────────────
// TPE = mean Euclidean displacement between controller's PREDICTED position
// p̂_ctrl(t) and SUMO ground-truth p_sumo(t). The predictor here is a
// dead-reckoning linear extrapolation from the controller's last *observed*
// (beacon-reported) kinematics:
//   p̂(t_new) = p(t_prev) + v(t_prev) · (t_new − t_prev)
// where v is decomposed via heading: v_x = speed·cos(h), v_y = speed·sin(h).
//
// Why this is honest TPE per paper §4.1.2:
//   • The input to the predictor is the BEACON-REPORTED state (possibly
//     poisoned), so for TP attacks {1,2,5} the predictor is biased exactly as
//     the controller's view would be biased in deployment.
//   • The comparison target is the MOBILITY-MODEL position read via
//     g_mobility_provider->get_gt_position() — for sumo_trace mode this is
//     genuine SUMO ground truth; for hardcoded mode it's the unpoisoned
//     hand-placed scenario state (still a valid GT for the sim, though paper
//     conformance asks for sumo_trace).
//
// State per vehicle: last observed (px, py, speed, heading, t).
// has_obs guards the very first beacon (no prior to extrapolate from).
struct TpeObs {
    double px = 0.0;
    double py = 0.0;
    double speed = 0.0;
    double heading = 0.0;
    double t = -1.0;
    bool   has_obs = false;
};
TpeObs   tpe_last_obs[total_size] = {};
double   tpe_disp_sum  = 0.0;   // Σ √((p̂_x−gt_x)² + (p̂_y−gt_y)²)
uint64_t tpe_disp_cnt  = 0;     // # comparisons accumulated

// Push a 5-feature sample into vehicle vid's ring. Returns true when ring has
// at least LSTM_RING_SIZE samples (i.e., a full window is available).
static inline bool lstm_ring_push(uint32_t vid,
                                  float px, float py, float sp,
                                  float hd, float ac) {
    if (vid >= (uint32_t)total_size) return false;
    VehicleLstmRing &r = vehicle_lstm_ring[vid];
    const uint32_t i = r.head;
    r.pos_x  [i] = px;
    r.pos_y  [i] = py;
    r.speed  [i] = sp;
    r.heading[i] = hd;
    r.accel  [i] = ac;
    r.head = (r.head + 1) % LSTM_RING_SIZE;
    r.count++;
    return r.count >= LSTM_RING_SIZE;
}

// Copy the ring into a row-major (LSTM_RING_SIZE × 5) buffer in chronological
// order so the LSTM-AE sees the oldest sample first. Returns false if ring is
// not yet full.
static inline bool lstm_ring_dump(uint32_t vid, float *out_buf) {
    if (vid >= (uint32_t)total_size) return false;
    const VehicleLstmRing &r = vehicle_lstm_ring[vid];
    if (r.count < LSTM_RING_SIZE) return false;
    // Oldest sample is at index head (wraps around) once count >= size.
    for (uint32_t k = 0; k < LSTM_RING_SIZE; ++k) {
        const uint32_t idx = (r.head + k) % LSTM_RING_SIZE;
        out_buf[k * 5 + 0] = r.pos_x  [idx];
        out_buf[k * 5 + 1] = r.pos_y  [idx];
        out_buf[k * 5 + 2] = r.speed  [idx];
        out_buf[k * 5 + 3] = r.heading[idx];
        out_buf[k * 5 + 4] = r.accel  [idx];
    }
    return true;
}

// R7d: "Last flushed window" snapshot per RSU. rsu_window[rsu_id] resets to
// beacon_count=0 immediately after IPFS flush, but the controller-side
// HandleBeaconReceived() callback (08_detection_engine.h CTRL-WIN block) needs
// the just-flushed kinematics to run Full-mode GAT spatial inference. The
// snapshot lives until the next flush overwrites it, so the controller can
// always read the most recent complete L-beacon window for any RSU.
// epoch_valid=0 means "no flush yet for this RSU" — controller skips GAT then.
RsuBeaconWindow rsu_last_window[MAX_RSUS] = {};
bool             rsu_last_window_valid[MAX_RSUS] = {};

// Statistics surfaced in the end-of-run metrics block (10_metrics_csv.h).
uint32_t ipfs_upload_count     = 0;  // total windows flushed to IPFS off-chain
uint32_t ipfs_hash_chain_count = 0;  // total hashes anchored on-chain

// Deterministic FNV-1a digest of the window — paper says "cryptographic hash",
// we use FNV-1a as the SHA3-256 stand-in. For final published runs, swap to
// OpenSSL EVP_sha3_256.
static std::string ipfs_window_hash(const RsuBeaconWindow &w, uint32_t rsu_id) {
    uint32_t h = 2166136261u;
    auto mix = [&](uint64_t v) {
        for (int b = 0; b < 8; b++) {
            h ^= (uint8_t)((v >> (b * 8)) & 0xFF);
            h *= 16777619u;
        }
    };
    mix((uint64_t)rsu_id);
    mix((uint64_t)w.window_epoch);
    for (uint32_t i = 0; i < w.beacon_count; i++) {
        mix((uint64_t)w.vid[i]);
        mix((uint64_t)(w.pos_x[i]     * 1000.0));
        mix((uint64_t)(w.pos_y[i]     * 1000.0));
        mix((uint64_t)(w.speed[i]     * 1000.0));
        mix((uint64_t)(w.heading[i]   * 1000.0));
        mix((uint64_t)(w.accel[i]     * 1000.0));
        mix((uint64_t)(w.timestamp[i] * 1.0e6));
        mix((uint64_t)(w.anomalous[i] ? 1 : 0));
    }
    char buf[24];
    std::snprintf(buf, sizeof(buf), "ipfs_%08x", h);
    return std::string(buf);
}

// Push one beacon into RSU rsu_id's window buffer. When L beacons accumulate
// the window is flushed: hash computed, "IPFS upload" logged, on-chain hash
// anchored (RSU → blockchain direct per invariant #1), and the buffer reset.
// A5 ablation (ablation_mode==5) skips the on-chain anchor since blockchain
// is disabled in that variant — the off-chain store still runs so downstream
// GAT/LSTM-AE retrieval semantics (R7+) remain testable.
void ipfs_push_and_maybe_flush(uint32_t rsu_id, uint32_t vid,
                               double px, double py, double sp,
                               double hd, double ac, double ts,
                               bool anomalous_flag,
                               bool is_poisoned_flag = false) {
    if (rsu_id >= N_RSUs || rsu_id >= MAX_RSUS) return;
    RsuBeaconWindow &w = rsu_window[rsu_id];
    if (w.beacon_count == 0) w.window_start = ts;
    if (w.beacon_count < IPFS_WINDOW_L) {
        uint32_t i = w.beacon_count;
        w.vid[i]         = vid;
        w.pos_x[i]       = px;
        w.pos_y[i]       = py;
        w.speed[i]       = sp;
        w.heading[i]     = hd;
        w.accel[i]       = ac;
        w.timestamp[i]   = ts;
        w.anomalous[i]   = anomalous_flag;
        w.is_poisoned[i] = is_poisoned_flag;
        w.beacon_count++;
    }
    if (w.beacon_count >= IPFS_WINDOW_L) {
        std::string hash = ipfs_window_hash(w, rsu_id);
        uint32_t anomalous_in_win = 0;
        for (uint32_t i = 0; i < w.beacon_count; i++)
            if (w.anomalous[i]) anomalous_in_win++;

        // Off-chain IPFS store — paper §3.5.3 Eq 3.56, Fig 3.9 (RSU→IPFS arrow).
        std::cout << "[IPFS-STORE-RSU" << rsu_id << "] epoch=" << w.window_epoch
                  << " beacons=" << w.beacon_count
                  << " anomalous=" << anomalous_in_win
                  << " hash=" << hash
                  << " t_start=" << std::fixed << std::setprecision(3) << w.window_start
                  << " t_end="   << std::fixed << std::setprecision(3) << ts
                  << " (Fig 3.9 RSU→IPFS, controller retrieves for GAT/LSTM-AE R7+)"
                  << std::endl;
        ipfs_upload_count++;

        // On-chain hash anchor — paper §3.5.3 Fig 3.9 (RSU→Blockchain arrow,
        // invariant #1: RSU → blockchain DIRECT, no controller relay).
        // A5 ablation: skip blockchain to isolate BC contribution (RQ6).
        if (ablation_mode != 5) {
            std::cout << "[IPFS-HASH-CHAIN-RSU" << rsu_id << "] epoch=" << w.window_epoch
                      << " hash=" << hash
                      << " (paper invariant #1: RSU→BC direct)"
                      << std::endl;
            ipfs_hash_chain_count++;
        }

        // R7d: snapshot the just-flushed window so the controller-side
        // GAT/LSTM-AE pipeline (08_detection_engine.h CTRL-WIN block) can read
        // it even though we're about to zero `w`. The copy is a struct
        // assignment — kinematics arrays are POD so this is one memcpy.
        rsu_last_window[rsu_id]       = w;
        rsu_last_window_valid[rsu_id] = true;

        // Reset window buffer for next L beacons.
        w.beacon_count = 0;
        w.window_epoch++;
    }
}

#endif // NS3_UDP_ARQ_APPLICATION_H
