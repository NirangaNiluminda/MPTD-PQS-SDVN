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
bool compromised_rsu[4] = {false, false, false, false};

// ── Option B: DSRC-RSU relay globals ──────────────────────────────────────────
// Set by 12_main.h after node creation + IP assignment, before Simulator::Run().
// When g_option_b_active=true, vehicle beacons flow:
//   Vehicle → DSRC unicast → RSU (HandleBeaconAtRSU) → CSMA → management_node
// When false: legacy LTE path (Vehicle → LTE → management_node directly).
Ipv4Address g_management_csma_ip;            // management_node CSMA IP (10.1.1.6)
Ipv4Address g_rsu_dsrc_ip[4];                // RSU DSRC IPs from dsrc_interfaces (3.x.x.x)
Ipv4Address g_rsu_csma_ip[4];               // RSU CSMA IPs for management → RSU downlink (10.1.1.x)
uint32_t    g_first_rsu_node_id = 0;         // NS-3 NodeID of RSU_Nodes.Get(0)
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

#endif // NS3_UDP_ARQ_APPLICATION_H
