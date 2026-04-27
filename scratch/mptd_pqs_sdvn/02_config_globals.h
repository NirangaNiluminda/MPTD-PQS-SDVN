// ============================================================
// SECTION 2: Simulation Configuration & Global Variables
// MPTD-PQS: Dual-Mode Detection for Mobility Pattern and
// Trajectory Poisoning Attacks in SDVN
// ============================================================
// Paper: "MPTD-PQS: Signature-Characterized Dual-Mode GAT-Temporal
//         Autoencoder with Blockchain-Enforced Post-Quantum TRS for
//         Detection and Mitigation of MP and TP Attacks in SDVN"
// University of Ruhuna, Sri Lanka — FYP 2024/2025
// ============================================================
// Contents:
//   - Portable path macros (NS3_ROOT, FAB_ROOT)
//   - SDVN topology: N_Vehicles, N_RSUs, simTime
//   - Attack scenario: attack_number (1-7), attack_percentage
//   - BSM beacon parameters and detection thresholds (§3.4.4)
//   - MRTPA attack parameters: poisoning_intensity, deviations
//   - Malicious node flags per scenario
//   - LTE callbacks
// ============================================================

// ── Portable Path Configuration ────────────────────────────────────────────
// CHANGE THESE TWO LINES when moving to a different machine.
// Usage in code: NS3_ROOT "/analytics/data/file.csv"
//                FAB_ROOT "/test-network/..."
#define NS3_ROOT "/home/niranga/ns-allinone-3.35/ns-3.35"
#define FAB_ROOT "/home/niranga/fabric-samples"
// ───────────────────────────────────────────────────────────────────────────

using namespace std::chrono;

// ── SDVN Topology ──────────────────────────────────────────────────────────
#define MAX_NODES 40

const int total_size = 16;
uint32_t N_RSUs     = 0;
uint32_t N_Vehicles = 16;

uint16_t N_eNodeBs = 1 + N_Vehicles / 40;
int      var       = N_Vehicles + N_RSUs;

// ── Simulation Time & Mobility ─────────────────────────────────────────────
double simTime              = 13.7;
int    mobility_scenario    = 0;   // 0=urban, 1=non-urban, 2=highway
int    maxspeed             = 60;  // km/h max vehicle speed

double data_transmission_frequency = 2.0;    // 2 Hz → 0.5s per beacon round (was 0.33 Hz)
double data_transmission_period    = 1.0 / data_transmission_frequency;
double link_lifetime_threshold     = 0.400;

// ── Attack Scenario Selection (maps to paper §3.4) ─────────────────────────
//   1 = TP-S1 : Malicious RSU trajectory poisoning          (Fig 3.1)
//   2 = TP-S2 : Malicious vehicle trajectory poisoning      (Fig 3.2)
//   3 = TP-S3 : Control-plane trajectory poisoning          (Fig 3.3)
//   4 = MP-S1 : Sybil-based via compromised RSU             (Fig 3.4)
//   5 = MP-S2 : Sybil-based via vehicle impersonation       (Fig 3.5)
//   6 = MP-S3 : MitM data-plane mobility pattern poisoning  (Fig 3.6)
//   7 = MP-S4 : Control-plane mobility pattern poisoning    (Fig 3.7)
int attack_number    = 1;
int attack_percentage = 40;  // % of nodes that are malicious (0-100, avoid 100)

const char* attack_scenario_name[] = {
    "",                                                    // 0 unused
    "TP-S1:MaliciousRSU-TrajectoryPoisoning",             // 1
    "TP-S2:MaliciousVehicle-TrajectoryPoisoning",         // 2
    "TP-S3:ControlPlane-TrajectoryPoisoning",             // 3
    "MP-S1:Sybil-CompromisedRSU",                        // 4
    "MP-S2:Sybil-VehicleImpersonation",                  // 5
    "MP-S3:MitM-DataPlane-MobilityPattern",              // 6
    "MP-S4:ControlPlane-MobilityPattern"                 // 7
};

bool controller_malicious_assumption = true; // used by TP-S3 and MP-S4

// ── Stage 7: Post-Quantum Crypto flag ──────────────────────────────────────
// Set to false for ablation study A4 (disables TRS + FHE)
// Paper §3.3.2-3.3.3; Eq. 3.58-3.65
bool use_pq_crypto = true;

// ── BSM Beacon Parameters (IEEE 802.11p, §3.4.4 Eq. 3.9) ──────────────────
// b_i(t) = (p_i(t), s_i(t), θ_i(t), a_i(t), t, ID_i)
double T_b = 0.1;           // Beacon broadcast interval: 100ms (IEEE 802.11p)
double R_max_comm = 300.0;  // Max V2V/V2I communication range (m)

// ── Trajectory Poisoning Detection Thresholds (§3.4.4) ────────────────────
// TP-S1: Kinematic position feasibility
double s_max = 33.33;       // Max road speed ~120 km/h (m/s)

// TP-S2: Heading rate deviation
double omega_max = 0.5236;  // Max angular velocity (rad/s) = 30 deg/s

// TP-S3: Acceleration bound
double a_max = 4.0;         // Max vehicle acceleration (m/s²)

// TP-S4/TP-S5: Dead-reckoning and drift
double delta_th = 10.0;     // Dead-reckoning residual threshold (m)
int    drift_window_k = 10; // Window size k for cumulative drift score

// ── Mobility Pattern Detection Thresholds (§3.4.4) ────────────────────────
// MP-S1: Sybil identity density (Eq. 3.7)
double K_sybil = 5.0;       // Max ghost identities per RSU coverage area
double d_min   = 10.0;      // Minimum inter-vehicle spacing (m)
double rho_v   = 0.01;      // Vehicle density (vehicles/m²)

// MP-S2: Synchronized beacon timing (Eq. 3.17)
// Beacons are staggered T_b/N apart in 12_main.h (≈6.25ms for 16 vehicles).
// tau_sync=1ms < 6.25ms stagger → honest vehicles are NOT flagged.
// Attacker colluders who send within 1ms of each other ARE flagged.
double tau_sync  = 0.001;   // 1ms synchronization detection window (s)
double rho_sync  = 0.8;     // Co-occurrence rate threshold

// MP-S3: Regional speed distribution shift (Eq. 3.18)
// kappa_th = 1.5: speed must deviate > 150% of regional mean to be flagged.
// Lower value (e.g., 0.5) caused stationary honest vehicles near fast malicious
// vehicles to be falsely flagged (legitimate zero-speed near 8 m/s mean gives kl=1.0).
double kappa_th  = 1.5;     // KL divergence threshold

// Composite rule-based anomaly threshold (Eq. 3.20)
double psi_th    = 0.3;     // Lightweight mode isolation threshold

// ── MRTPA Attack Injection Parameters ─────────────────────────────────────
double poisoning_intensity_theta  = 0.5;   // θ ∈ [0,1] deviation magnitude
double max_position_deviation     = 50.0;  // Max position offset (m)
double max_velocity_deviation     = 15.0;  // Max velocity offset (m/s)
double max_acceleration_deviation = 5.0;   // Max acceleration offset (m/s²)

// Simulation area bounds
double min_position_x = 0.0;
double max_position_x = 2000.0;
double min_position_y = 0.0;
double max_position_y = 2000.0;

// ── Malicious Node Flags ───────────────────────────────────────────────────
bool trajectory_poisoning_malicious_nodes[total_size]; // TP-S1, TP-S2
bool sybil_malicious_nodes[total_size];                // MP-S1, MP-S2
bool mitm_malicious_nodes[total_size];                 // MP-S3
// TP-S3 and MP-S4 are controller-level (use controller_malicious_assumption)

// ── Counters for [METRICS] / [MRTPA_SUMMARY] logging ──────────────────────
uint32_t total_trajectories_received         = 0;
uint32_t total_trajectories_poisoned         = 0;
uint32_t total_trajectories_stored_blockchain = 0;

// ── TDEE / TPE displacement error accumulators (populated in 09_send_lte.h) ──
// TDEE: mean |reported_pos - real_pos| over all beacons (m)
double   tdee_error_sum   = 0.0;
uint32_t tdee_error_cnt   = 0;
// TPE: RMSE of |reported_pos - real_pos| for malicious-vehicle beacons only (m)
double   tpe_sq_sum       = 0.0;
uint32_t tpe_cnt          = 0;
// PBPO: mean beacon processing time per receive-side call (ms)
double   pbpo_time_sum_ms = 0.0;
uint32_t pbpo_cnt         = 0;

// ── Send-side speed/time history — separate from receive-side vehicle_state ──
// Used only in send_LTE_metadata_uplink_alone() to compute accel at send time.
// Indexed by vid = nid - 2 (0..N_Vehicles-1), never written by receive side.
double send_prev_speed[MAX_NODES] = {};
double send_prev_time [MAX_NODES] = {};

// ── Node/consortium assignment ─────────────────────────────────────────────
uint32_t node_controller_ID[total_size];
uint32_t assigned_consortium_ID[total_size];

// ── LTE state ─────────────────────────────────────────────────────────────
double uplink_last[total_size];
double downlink_last = 0.0;
double last_downlink[total_size];

std::vector<bool> ueBusy;
std::vector<bool> ueDLBusy;

using namespace std;
using namespace ns3;

void UeTxStartCallback(uint32_t ueId, Ptr<const Packet> p)
{
    ueBusy[ueId]   = true;
    ueDLBusy[ueId] = true;
    std::cout << Simulator::Now().GetSeconds()
              << " : UE " << ueId << " TX started\n";
}

void UeTxEndCallback(uint32_t ueId, Ptr<const Packet> p)
{
    ueBusy[ueId]   = false;
    ueDLBusy[ueId] = false;
    std::cout << Simulator::Now().GetSeconds()
              << " : UE " << ueId << " TX ended\n";
}

// ── Helper: probabilistic malicious assignment ─────────────────────────────
// Seed depends ONLY on nodeID so that increasing probabilityPercent
// monotonically includes more nodes (superset property preserved across sweeps).
bool GetBooleanWithProbability(double probabilityPercent, int nodeID) {
    // Hash nodeID with a prime to spread values uniformly across [0,100).
    uint32_t seed = 7919u * (uint32_t)nodeID + 3571u;
    srand(seed);
    double randomValue = 1.0 * (rand() % 100);
    return randomValue < probabilityPercent;
}

// ── Aliases for renamed variables (06_mrtpa_attack.h, 07_security.h) ──────
// These old names are used in 06/07 — will be cleaned in Stage 5.
#define max_realistic_speed         s_max
#define max_realistic_acceleration  a_max
bool training_delay = false;  // legacy flag used in 07_security.h

// ── Legacy variable stubs (07_security.h, 08_lldp_handlers.h) ─────────────
// Removed from original config; stubs keep 07_security.h compiling.
// Remove when 07_security.h and 08_lldp_handlers.h are cleaned in Stages 4+.
int routing_algorithm = 0;
bool vanishing_malicious_nodes[total_size]    = {};
bool flooding_malicious_nodes[total_size]     = {};
bool fabrication_malicious_nodes[total_size]  = {};
bool blocked_port_state[total_size][total_size][2] = {};

// Minimal Link struct hierarchy used by TrySendUplink/Downlink in 07_security.h
struct LegacyLinkVal { double Link_values[MAX_NODES]; };
struct LegacyLinkFi  { LegacyLinkVal Link_fi_inst[MAX_NODES]; };
struct LegacyLinkF   { LegacyLinkFi  Link_f_inst[2]; };
LegacyLinkF Link_at_controller_inst[2];
LegacyLinkF LLDP_timestamp_at_controller_inst[2];
LegacyLinkF Link_duplicates_at_controller_inst[2];
LegacyLinkF Link_duplicates_SecondTime_uplink_at_controller_inst[2];
LegacyLinkF Link_duplicates_downlink_at_controller_inst[2];
LegacyLinkF Link_duplicates_SecondTime_downlink_at_controller_inst[2];

// ── Temporary: legacy constants needed by 05_utils.h/08/11 ───────────────
// These will be removed progressively in Stages 4 and 6 when 08_lldp_handlers.h
// and 11_routing_blockchain_transmission.h are rewritten.
#define max 40               // array size for neighbor tables in 05_utils.h
const int flows = 1;         // flow count — only 05_utils struct arrays use this
uint32_t large = 50000;      // sentinel value used in clear_data_at_nodes()
// max1..max25 removed in Stage 9 — no references found after Stage 2 cleanup

// ── Legacy controller delta / L structs (09_send_lte.h / 12_main.h) ───────
struct DeltaLegacyVal { double delta_values[MAX_NODES]; };
struct DeltaLegacyFi  { DeltaLegacyVal delta_fi_inst[MAX_NODES]; };

struct LLegacyVal { double L_values[MAX_NODES]; };
struct LLegacyFi  { LLegacyVal L_fi_inst[MAX_NODES]; };

DeltaLegacyFi delta_at_controller_inst[2]; // 2*flows elements (flows=1)
LLegacyFi     L_at_controller_inst[2];

void clear_delta_at_controller(DeltaLegacyFi* df) {
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < MAX_NODES; j++)
            for (int k = 0; k < MAX_NODES; k++)
                df[i].delta_fi_inst[j].delta_values[k] = 0.0;
}

// ── Legacy timing / packet size globals (09/10/11/12) ─────────────────────
double ethernet_initial_timestamp = 0.0;
double LLDP_initial_timestamp     = 0.0;
double HELLO_final_timestamp      = 0.0;
double packet_initial_timestamp[total_size + 2];
// dsrc/ethernet/lte_total_packet_size declared as long in 06_mrtpa_attack.h

// ── Experiment / architecture selector globals (10/11/12) ─────────────────
int    architecture        = 0;   // 0=centralized, 1=distributed, 2=hybrid
int    experiment_number   = 0;   // sub-experiment index
int    paper               = 0;   // paper variant selector
int    qf                  = 0;   // QoS flag

// ── Frequency / threshold experiment globals (10/11/12) ───────────────────
double routing_frequency      = 1.0;
double optimization_frequency = 1.0;
double optimization_period    = 1.0;   // recomputed in main as 1/optimization_frequency
double entropy_threshold      = 0.0;
double contention_threshold   = 0.0;
int    lambda                 = 10;    // flow size selector (used in switch statements)

// ── Flow size constant (10_metrics_csv.h array dimensions) ─────────────────
#define Flow_size 40   // matches max neighbor array size

// ── Legacy QoS and VANET MAC parameters (12_main.h) ───────────────────────
uint32_t flow_packet_size = 64;
uint32_t CW_max = 1023;
uint32_t AIFSN  = 2;
double   B_max  = 6.0;
double   latency_max = 1.0;
double   loss_max    = 0.1;
double   AIFS        = 0.0;

// ── Malicious node flags for location-based attacks (11_routing) ──────────
bool location_malicious_nodes[total_size] = {};

NS_LOG_COMPONENT_DEFINE ("mptd_pqs_sdvn");

// ── Additional timing globals (11_routing_blockchain_transmission.h) ───────
double current_channel_utilization  = 0.0;
double average_channel_utilization  = 0.0;
double dsrc_LLDP_initial_timestamp  = 0.0;
double dsrc_LLDP_final_timestamp    = 0.0;
double ethernet_final_timestamp     = 0.0;
double ethernet_LLDP_initial_timestamp = 0.0;
double ethernet_utilization_time    = 0.0;
double HELLO_initial_timestamp      = 0.0;
double LLDP_final_timestamp         = 0.0;
double packet_final_timestamp[total_size + 2];
double flow_initiation_time         = 0.0;

// ── Malicious controller/node flags (11_routing) ──────────────────────────
bool flooding_malicious_controllers[total_size]    = {};
bool vanishing_malicious_controllers[total_size]   = {};
bool fabrication_malicious_controllers[total_size] = {};
bool MIM_malicious_controllers[total_size]         = {};
bool MIM_malicious_nodes[total_size]               = {}; // mitm alias

// ── Present-attack status flags (11_routing) ──────────────────────────────
bool present_location_attack_nodes      = false;
bool present_flooding_attack_nodes      = false;
bool present_flooding_attack_controllers = false;
bool present_vanishing_attack_nodes     = false;
bool present_vanishing_attack_controllers = false;
bool present_fabrication_attack_nodes   = false;
bool present_fabrication_attack_controllers = false;
bool present_MIM_attack_nodes           = false;
bool present_MIM_attack_controllers     = false;

// mu1/mu2/mu3 removed in Stage 10 — LDA Lagrangian multipliers, no references found

// ── Controller state matrices (Q, Y, Omega, W, T, t) ─────────────────────
// All follow the same nested struct pattern as LLegacyFi / DeltaLegacyFi.
struct QVal   { double Q_values[MAX_NODES]; };
struct QFi    { QVal   Q_fi_inst[MAX_NODES]; };
QFi Q_at_controller_inst[2];

struct YVal   { double Y_values[MAX_NODES]; };
struct YFi    { YVal   Y_fi_inst[MAX_NODES]; };
YFi Y_at_controller_inst[2];

struct OmegaVal { double Omega_values[MAX_NODES]; };
struct OmegaFi  { OmegaVal Omega_fi_inst[MAX_NODES]; };
OmegaFi Omega_at_controller_inst[2];

struct WVal   { double W_values[MAX_NODES]; };
struct WFi    { WVal   W_fi_inst[MAX_NODES]; };
WFi W_at_controller_inst[2];

struct TVal   { double T_values[MAX_NODES]; };
struct TFi    { TVal   T_fi_inst[MAX_NODES]; };
TFi T_at_controller_inst[2];

struct tVal   { double t_values[MAX_NODES]; };
struct tFi    { tVal   t_fi_inst[MAX_NODES]; };
tFi t_at_controller_inst[2];

// ── Routing matrices E (3D) and F (2D) ──────────────────────────────────
// int (not bool) because code does E_mat[c][n][f] < 2 and += 1 comparisons
int E_mat[MAX_NODES][MAX_NODES][2] = {};
int F_mat[MAX_NODES][2]            = {};

// ── Per-node delta / load structs (11_routing) ────────────────────────────
struct DeltaNodeVal {
    double   delta_values[MAX_NODES];
};
struct DeltaNodeFi {
    DeltaNodeVal delta_fi_inst[MAX_NODES];
    uint32_t     source_f      = 0;
    uint32_t     destination_f = 0;
    uint32_t     flow_id       = 0;
};
DeltaNodeFi delta_at_nodes_inst[2];

struct LoadNode { double load_f[MAX_NODES]; };
LoadNode load_at_nodes[2];

// ── Stub functions referenced by 12_main.h ────────────────────────────────
void generate_F_and_E() {
    // Stub: full F/E matrix generation is part of Stage 6 cleanup
}

void clear_delta_at_nodes(DeltaNodeFi* df) {
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < MAX_NODES; j++) {
            df[i].delta_fi_inst[j] = DeltaNodeVal{};
            df[i].source_f = 0;
            df[i].destination_f = 0;
            df[i].flow_id = 0;
        }
}
