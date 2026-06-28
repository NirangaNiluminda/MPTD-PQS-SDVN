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
#define NS3_ROOT "/home/vboxuser/ns-allinone-3.35/ns-3.35"
#define FAB_ROOT "/home/vboxuser/fabric-samples"
// DATASET_ROOT = the git repo working tree (committable). The additive
// per-attack/per-percentage dataset export (export_run_dataset() in
// 10_metrics_csv.h) writes here, separate from NS3_ROOT analytics output.
#define DATASET_ROOT "/home/vboxuser/Desktop/MPTD-PQS-SDVN"
// ───────────────────────────────────────────────────────────────────────────

using namespace std::chrono;

// ── SDVN Topology ──────────────────────────────────────────────────────────
// Test network (routing_test=true):  16 vehicles, 4 RSUs, 1 controller, 1 management node
// Full network (routing_test=false): N_Vehicles/N_RSUs set via command-line args
// ── Capacity constants (NOT the active counts) ────────────────────────────
// MAX_NODES / total_size are COMPILE-TIME ARRAY CAPACITIES, sized for the
// largest supported run (SUMO ~200 vehicles), NOT the active node count.
// The ACTIVE counts are the runtime globals N_Vehicles / N_RSUs below.
//   • test net   (--mobility_source=0): N_Vehicles=16, N_RSUs=4
//   • SUMO trace (--mobility_source=1): N_Vehicles up to ~200, N_RSUs (keep ≤4
//     until the deferred RSU-subsystem scale-up; see memory project_dynamic_scaleup)
// Loops that iterate ACTUAL vehicles must bound on N_Vehicles, not total_size.
// Most per-vehicle loops self-guard (skip vehicle_state[i].count==0), so they
// stay correct at this larger capacity; the non-self-guarding consortium split
// in 11_blockchain_setup.h uses N_Vehicles explicitly.
#define MAX_NODES 320

// MAX_RSUS = per-RSU array CAPACITY (compile-time). The ACTIVE RSU count is the
// runtime global N_RSUs below. Test net uses N_RSUs=4; SUMO urban uses an 8×8 =
// 64-RSU uniform grid (rsu_positions_urban.csv; supervisor-mandated 2026-06-12,
// 250 m spacing). All per-RSU arrays are sized [MAX_RSUS]; every loop / gate
// over actual RSUs bounds on N_RSUs (NOT the literal 4 or MAX_RSUS).
#define MAX_RSUS 64

const int total_size = 256;  // vehicle-array CAPACITY (was 16; now sized for SUMO 200-veh runs)
uint32_t N_RSUs     = 4;    // ACTIVE RSU count (test net=4; SUMO urban 8×8 grid=64)
uint32_t N_Vehicles = 16;   // 4 vehicles per RSU cluster
uint32_t N_Controllers = 4;
uint32_t g_first_rsu_node_id = 0;
uint32_t g_first_vehicle_node_id = 0;

uint16_t N_eNodeBs = 1 + N_Vehicles / 40;
int      var       = N_Vehicles + N_RSUs;

// ── Simulation Time & Mobility ─────────────────────────────────────────────
double simTime              = 15.0;
int    mobility_scenario    = 0;   // 0=urban, 1=non-urban, 2=highway
int    maxspeed             = 60;  // km/h max vehicle speed

// ── R7a: Mobility source selector (--mobility_source CLI arg) ─────────────
// 0 = hardcoded 16-vehicle ConstantVelocity scenario (default, fast smoke tests,
//     NOT paper-conformant — TDEE/TPE values are not SUMO-derived).
// 1 = sumo_trace: Ns2MobilityHelper consumes a .tcl file exported from SUMO
//     via traceExporter.py (paper §4.1.3 + Eq 4.5/4.6 conformant).
// 2 = sumo_live: RESERVED for future live TraCI bridge (R7a-B, not implemented).
// See 09b_mobility_provider.h for the IMobilityProvider abstraction.
int g_mobility_source = 0;  // MOBILITY_SRC_HARDCODED

// ── RSU Compromise Seed (TP-S1 / MP-S1 random selection) ──────────────────
// 0 = different random RSUs each run  (uses system clock)
// N = fixed seed N → same RSUs compromised every run (reproducible)
// Example: --rsu_seed=42 --attack_percentage=40 → always same 2 RSUs
uint32_t rsu_seed = 0;

// Paper §3.4.4 IEEE 802.11p BSM rate: 10 Hz → T_b = 100 ms (Eq 3.9).
// Detection gate s_max·T_b = 3.33 m is keyed to this; do not change without
// re-calibrating all per-beacon thresholds (TP-S1..S5, ε_max stealth/abrupt).
double data_transmission_frequency = 10.0;
double data_transmission_period    = 1.0 / data_transmission_frequency;
double link_lifetime_threshold     = 0.400;

// ── Attack Scenario Selection (maps to paper §3.4) ─────────────────────────
//   1 = TP-S1 : Malicious RSU trajectory poisoning          (Fig 3.1)
//   2 = TP-S2 : Malicious vehicle trajectory poisoning      (Fig 3.2)
//   3 = MP-S1 : Sybil via compromised RSU                   (Fig 3.4)
//   4 = MP-S2 : Sybil via vehicle impersonation             (Fig 3.5)
//   5 = TP-S3 : Control-plane trajectory poisoning          (Fig 3.3)
//   6 = MP-S3 : MitM data-plane mobility pattern poisoning  (Fig 3.6)
//   7 = MP-S4 : Control-plane global mobility model poisoning (Fig 3.7)
int attack_number    = 1;
int attack_percentage = 40;  // % of nodes that are malicious (0-100, avoid 100)

// ── Sybil Pre-Registration (MP-S1 enhanced, Attack 3 only) ────────────────
// 0 = original mode: compromised RSU injects ghost IDs post-registration
//     → detection is trivial (ghost IDs clearly outside the registered pool)
//     → metrics are flat at 1.0 regardless of attack_percentage
// >0 = enhanced mode: floor(N_Vehicles * X/100) vehicles are pre-registered
//     as Sybil at startup with VALID pool IDs.
//     Detection must use behavioural analysis (MP-S3 KL divergence).
//     As attack_percentage increases, Sybil collectively raise the regional
//     speed mean → KL check degrades naturally → non-trivial MCC/DR curves.
// Recommended: 30–50 for meaningful metric variation across attack sweeps.
int sybil_registration_pct = 0;

const char* attack_scenario_name[] = {
    "",                                                    // 0 unused
    "TP-S1:MaliciousRSU-TrajectoryPoisoning",             // 1
    "TP-S2:MaliciousVehicle-TrajectoryPoisoning",         // 2
    "MP-S1:Sybil-CompromisedRSU",                        // 3
    "MP-S2:Sybil-VehicleImpersonation",                  // 4
    "TP-S3:ControlPlane-TrajectoryPoisoning",             // 5
    "MP-S3:MitM-DataPlane-MobilityPattern",              // 6
    "MP-S4:ControlPlane-MobilityPatternPoisoning"         // 7
};

// ── R7b: Attacker class enum (paper §4.1.2 MCC slicing) ───────────────────
// The paper requires MCC/FPR to be reported "by attack variant × 4 attacker
// classes" (Eq 4.1). Each beacon is tagged with the class of entity producing
// the poisoned data, so eval scripts can group rows accordingly.
enum AttackerClass {
    ATTACKER_NONE                 = 0,   // clean beacon (is_poisoned=false)
    ATTACKER_MALICIOUS_VEHICLE    = 1,   // TP-S2 (2), MP-S2 (4)
    ATTACKER_COMPROMISED_RSU      = 2,   // TP-S1 (1), MP-S1 (3)
    ATTACKER_MITM                 = 3,   // MP-S3 (6)
    ATTACKER_MALICIOUS_CONTROLLER = 4,   // TP-S3 (5), MP-S4 (7)
};

// Map attack_number (1..7) to the entity class responsible for the poisoning.
// Returns ATTACKER_NONE for invalid attack_number — caller should only invoke
// when is_poisoned==true. Mirror this in any new attack model added.
inline int attacker_class_for(int attack_num)
{
    switch (attack_num) {
        case 1: return ATTACKER_COMPROMISED_RSU;       // TP-S1
        case 2: return ATTACKER_MALICIOUS_VEHICLE;     // TP-S2
        case 3: return ATTACKER_COMPROMISED_RSU;       // MP-S1
        case 4: return ATTACKER_MALICIOUS_VEHICLE;     // MP-S2
        case 5: return ATTACKER_MALICIOUS_CONTROLLER;  // TP-S3
        case 6: return ATTACKER_MITM;                  // MP-S3
        case 7: return ATTACKER_MALICIOUS_CONTROLLER;  // MP-S4
        default: return ATTACKER_NONE;
    }
}

bool controller_malicious_assumption = true; // used by TP-S3 and MP-S4

// ── R4.b: backup-controller flag removed (paper has no backup controller) ──
// The paper specifies CP-DETECT (Algorithm 7, §3.5.5) — when ≥f+1 RSUs disagree
// with the controller's submission, the controller is excluded from consensus
// and the RSU rule-based fallback takes over. There is no "backup controller"
// in the paper architecture. The flag and node were a non-paper implementation
// artifact; both removed in R4.b. CP-DETECT itself lands in phase R6.

// ── Ablation study selector (paper §4.1, mind.md §11) ─────────────────────
// Controls which MPTD-PQS components are active for ablation comparison.
// Pass via --ablation_mode=N on the command line.
//   1 = A1  Lightweight only : Rules + HMAC, no GAT, no AE, no TRS/FHE  ← DEFAULT
//   2 = A2  GAT only         : Rules + HMAC + GAT spatial (no LSTM-AE)
//   3 = A3  AE only          : Rules + HMAC + LSTM-AE temporal (no GAT)
//   4 = A4  Full, no PQ      : Rules + HMAC + GAT + AE, TRS/FHE disabled (use_pq_crypto=false)
//   5 = A5  Full, no BC      : Rules + HMAC + GAT + AE, blockchain SC calls skipped
//   6 = B1  Ghaleb (2014)    : LTT baseline — speed plausibility + cross-RSU reachability only
//   0 = Full (no ablation)   : every component active
int ablation_mode = 1;

// ── R7f: AI component toggles (paper §4.1.1 A2/A3 ablation) ────────────────
// Independently enable the GAT spatial detector and the LSTM-AE temporal detector.
// Defaults are derived from `ablation_mode` in 12_main.h after cmd.Parse():
//   A1 → both false (lightweight only)
//   A2 → gat=true,  ae=false
//   A3 → gat=false, ae=true
//   A4/A5/Full → both true
// Explicit --enable_gat / --enable_lstm_ae CLI args override the ablation defaults
// (use values 0/1; default -1 means "follow ablation_mode").
int g_enable_gat_cli      = -1;   // -1 = follow ablation_mode, 0/1 = explicit
int g_enable_lstm_ae_cli  = -1;   // -1 = follow ablation_mode, 0/1 = explicit
bool g_enable_gat         = true; // effective value after dispatch (R7f)
bool g_enable_lstm_ae     = true; // effective value after dispatch (R7f)

// ── Stage 7: Post-Quantum Crypto flag ──────────────────────────────────────
// Forced false automatically when ablation_mode == 4 (set in 12_main.h after cmd.Parse).
// Paper §3.3.2-3.3.3; Eq. 3.58-3.65
bool use_pq_crypto = true;

// ── TRS scheme selector (paper §3.5.4 Eq 3.49; RQ5 PBPO baseline) ───────────
// false (default) = real PQ CRYSTALS-Dilithium / ML-DSA-87 (DilithiumTrsBackend, NIST Level 5),
//                   the paper-correct full-mode threshold ring signature.
// true            = classical Shamir-Schnorr-P256 (ClassicalTrsBackend), kept ONLY
//                   as the ECDSA-class signing-latency baseline for RQ5 (TRS-vs-ECDSA
//                   PBPO comparison) and the A4 framing. Pass --trs_classical=1.
// This is a signing-primitive swap behind ITrsBackend — call sites are unchanged.
bool g_trs_classical_baseline = false;

// ── BSM Beacon Parameters (IEEE 802.11p, §3.4.4 Eq. 3.9) ──────────────────
// b_i(t) = (p_i(t), s_i(t), θ_i(t), a_i(t), t, ID_i)
double T_b = 0.1;           // Beacon broadcast interval: 100ms (IEEE 802.11p)
double R_max_comm = 270.0;  // Max V2V/V2I communication range (m); 41 dBm DSRC link-lifetime calibration

// ── Trajectory Poisoning Detection Thresholds (§3.4.4) ────────────────────
// TP-S1: Kinematic position feasibility
double s_max = 33.33;       // Max road speed ~120 km/h (m/s)

// TP-S2: Heading rate deviation
double omega_max = 0.5236;  // Max angular velocity (rad/s) = 30 deg/s

// TP-S3: Acceleration bound
double a_max = 4.0;         // Max vehicle acceleration (m/s²)

// TP-S4/TP-S5: Dead-reckoning and drift
double delta_th = 10.0;     // Dead-reckoning residual threshold (m)
// Calibration: delta_th=10.0m accommodates honest direction changes in the random-waypoint
// mobility model (90° turn at 50 km/h gives residual ~9.8m; must stay below delta_th).
static bool g_save_restore_context = false;  // unused placeholder
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

// MP-S3: Regional speed distribution KL divergence (Eq. 3.18)
// D_KL(P_t || P_hist) > kappa_th
// P_hist: historical speed distribution per RSU cell (exponential moving average)
// P_t:    current speed distribution built from all vehicles in RSU cell this window
// Histogram: KL_BINS uniform bins over [0, s_max]; each bin = fraction of vehicles
// Update:  P_hist ← (1−KL_ALPHA)·P_hist + KL_ALPHA·P_t  (slow drift adaptation)
// kappa_th = 0.1: calibrated so that:
//   Honest fleet (uniform spread) → KL ≈ 0 (P_t ≈ P_hist → no flag)
//   MitM/Sybil (speed shifted by >30%) → KL > 0.1 (detected)
static const int    KL_BINS  = 10;    // speed histogram resolution
static const double KL_ALPHA = 0.05;  // P_hist adaptation rate (slow: ~20 beacons to update)
double kl_hist[MAX_RSUS][KL_BINS] = {};  // per-RSU historical speed distribution P_hist
bool   kl_hist_ready[MAX_RSUS]    = {};  // true once P_hist has been initialised
double kappa_th              = 0.1;   // KL divergence detection threshold (Eq. 3.18)

// Composite rule-based anomaly threshold (Eq. 3.20)
// Calibration: psi_th = 0.09 ensures any single medium/high-confidence signature
// (weight ≥ 0.10: TP-S1..S5, MP-S1, MP-S3) independently triggers detection.
// Only the two lowest-confidence signatures (MP-S2=0.05, MP-S4=0.05) require
// corroboration — both their attacks (4 and 7) fire additional flags or use
// the CP-DETECT oracle, so no attack scenario is left undetected.
// Previous value 0.30 was set for a fully-trained GAT+LSTM-AE system (not yet
// implemented); 0.09 is calibrated to the rule-based branch's weight distribution.
double psi_th    = 0.09;    // Lightweight mode isolation threshold (rule-based branch)

// ── MRTPA Attack Injection Parameters ─────────────────────────────────────
double poisoning_intensity_theta  = 0.5;   // θ ∈ [0,1] deviation magnitude
double max_position_deviation     = 50.0;  // Max position offset (m)
double max_velocity_deviation     = 15.0;  // Max velocity offset (m/s)
double max_acceleration_deviation = 5.0;   // Max acceleration offset (m/s²)

// ── Bounded random-walk attack model (paper §3.4.3 Eq 3.5/3.6) ─────────────
// Eq 3.5: per-beacon drift increment bound  ‖δ(t) − δ(t−T_b)‖ ≤ ε_max
// Eq 3.6: cumulative drift after k beacons  ‖δ(t₀ + k·T_b)‖ ≤ k · ε_max
//
// Paper §3.4.3 leaves ε_max as a speed/handover-dependent quantity without
// fixed numerics. We adopt a hybrid attacker model parameterised by two
// branches (stealth + abrupt) so the A1-vs-full-mode ablation (RQ2 vs RQ3)
// shows non-degenerate MCC:
//
//   STEALTH branch (drawn with prob θ_s):
//     inc_step ∈ [0, ε_max_stealth] →  scaled by theta, stays BELOW the LW
//     kinematic gate (s_max·T_b = 3.33 m) for theta ≤ 1, so a single stealth
//     beacon NEVER trips TP-S1. Cumulative drift over k beacons (Eq 3.6) is
//     what GAT + LSTM-AE must catch in full mode.
//
//   ABRUPT branch (drawn with prob 1 − θ_s):
//     inc_step ∈ [ε_min_abrupt, ε_max_abrupt] → scaled by theta, designed so
//     that at theta = 0.5 the floor ε_min_abrupt·theta exceeds s_max·T_b.
//     Every abrupt beacon trips TP-S1 kinematic in LW mode → A1 detection
//     rate ≈ (1 − θ_s) at baseline intensity.
//
//   Defaults (calibrated for theta=0.5 baseline, s_max=33.33 m/s, T_b=0.1 s):
//   Paper §3.4.4 IEEE 802.11p: T_b = 100 ms → LW kinematic gate = s_max·T_b = 3.33 m.
//
//     epsilon_max_stealth  = 0.5   → max stealth step 0.5·1   = 0.5 m  < 3.33 m gate
//     epsilon_min_abrupt   = 7.0   → min abrupt step 7.0·0.5  = 3.5 m  > 3.33 m gate
//     epsilon_max_abrupt   = 12.0  → max abrupt step 12.0·1   = 12.0 m
//     stealth_fraction_θ_s = 0.7   → ~70% stealth, ~30% abrupt → A1 catches ~30% via
//                                    TP-S1 single-beacon + extra via TP-S4/S5 cumulative
//     k_max                = 50    → accumulator reset every 50 beacons (~5 s at 10 Hz),
//                                    approximating handover stitch (Eq 3.4 W_s).
double epsilon_max_stealth           = 0.5;   // m per beacon (Eq 3.5 stealth bound, < gate)
double epsilon_min_abrupt            = 7.0;   // m per beacon (above gate at theta=0.5)
double epsilon_max_abrupt            = 12.0;  // m per beacon (abrupt ceiling)
double stealth_fraction_theta_s      = 0.7;   // fraction of beacons drawn from stealth
int    cumulative_drift_budget_k_max = 50;    // reset accumulator every k beacons

// Per-vehicle bounded-random-walk state (Eq 3.6 accumulator)
double drift_accum_x       [MAX_NODES] = {};  // cumulative x-drift since last reset
double drift_accum_y       [MAX_NODES] = {};  // cumulative y-drift since last reset
int    drift_beacon_count  [MAX_NODES] = {};  // k counter (resets at k_max)
double drift_direction_x   [MAX_NODES] = {};  // unit vector for directional bias
double drift_direction_y   [MAX_NODES] = {};
bool   drift_direction_set [MAX_NODES] = {};  // initialised on first call per vid

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

// ── TDEE: per-RSU beacon density accumulators (paper Eq. 4.5, dimensionless) ──
// Populated by HandleBeaconReceived() in 08_detection_engine.h.
// gt_count[j]  = beacons received via RSU j  (ground-truth: vehicle is near RSU j)
// est_count[j] = beacons whose REPORTED position maps into RSU j's cell
// TDEE_j = |est_j − gt_j| / gt_j  →  TDEE = mean_j(TDEE_j)
uint32_t tdee_gt_count [MAX_RSUS] = {};
uint32_t tdee_est_count[MAX_RSUS] = {};

// ── PARR: TRS blockchain rejection accumulators (paper Eq. 4.3) ─────────────
// parr_trs_rejected  = poisoned beacons flagged by the RSU lightweight detector
//                      (flag=1, Eq 3.67 → counted as a TRS-layer rejection)
// parr_poisoned_total = total poisoned beacons submitted to the blockchain ledger
// PARR = parr_trs_rejected / parr_poisoned_total   (distinct from DR = TP/(TP+FN))
uint32_t parr_trs_rejected   = 0;
uint32_t parr_poisoned_total = 0;

// ── TPE displacement error accumulators (populated in 09_vehicle_beacon_tx.h) ──
// TPE: RMSE of |reported_pos - real_pos| for malicious-vehicle beacons only (m)
double   tpe_sq_sum       = 0.0;
uint32_t tpe_cnt          = 0;
// PBPO_Full: mean beacon processing time per receive-side call (controller pipeline, ms)
double   pbpo_time_sum_ms = 0.0;
uint32_t pbpo_cnt         = 0;
// CDER: control-decision level tracking (Eq.4.4 at downlink control plane)
// Tracks correctness of each DownlinkControlTag sent by management node.
// WRONG_ROUTING always wrong; CLEAN for poisoned = FN; ATTACK_DETECTED for clean = FP.
uint32_t ctrl_decisions_total = 0;
uint32_t ctrl_decisions_wrong = 0;
// PBPO_LW: RSU-side lightweight HMAC gate processing time (Eq.4.7, lightweight mode)
// Separate from PBPO_Full (controller-side full detection pipeline).
double   pbpo_lw_time_sum_ms = 0.0;
uint32_t pbpo_lw_cnt         = 0;

// ── CP-DETECT (paper §3.5.5 / Algorithm 7 / Eq 3.59) accumulators ──────────
// Detects compromised SDN controller via RSU peer consensus.
// Algorithm 7 has two gates:
//   (a) TRS-verify gate (lines 2–6): controller-submitted aggregate must carry
//       a valid σ_TRS; if invalid → immediate CTRL_COMPROMISED alert.
//       Implementation note: real TRS verification arrives in phase R8; until
//       then the gate is a no-op stub returning valid=true (g_cp_detect_trs_fails
//       therefore stays 0 in current code — flag is reserved for R8 wiring).
//   (b) Conflict-detection gate (lines 7–15 / Eq 3.59): if ≥ f+1 RSU peers
//       disagree with the controller's binary decision for the same vehicle in
//       the same epoch, set flag_c = 1, emit CTRL_COMPROMISED, exclude
//       controller from consensus for the rest of the window, and fall back
//       to RSU rule-based decisions. f = 1 in the 3-RSU + 1-controller setup
//       (BFT bound n ≥ 3f+1), so the conflict threshold is 2 RSU disagreements.
// Honors invariant #2 (controller is a non-authoritative peer).
uint32_t g_cp_detect_alerts_total      = 0;  // total CTRL_COMPROMISED alerts emitted
uint32_t g_cp_detect_trs_fails         = 0;  // TRS-verify gate failures (R8-active)
uint32_t g_cp_detect_conflict_fires    = 0;  // Eq 3.59 conflict-gate firings
uint32_t g_cp_detect_epochs_evaluated  = 0;  // number of controller decisions audited
bool     g_flag_c_active               = false;  // RSU fallback mode currently active

// ── Send-side speed/time history — separate from receive-side vehicle_state ──
// Used only in send_LTE_metadata_uplink_alone() to compute accel at send time.
// Indexed by vid = nid - 2 (0..N_Vehicles-1), never written by receive side.
double send_prev_speed[MAX_NODES] = {};
double send_prev_time [MAX_NODES] = {};

// ── Node/consortium assignment ─────────────────────────────────────────────
// node_controller_ID: VEHICLE→controller for the SDN data plane (flow routing,
// 12_main.h routing_algorithm==4). This is the control-plane flow mapping and
// is NOT the evidence/trust attribution.
uint32_t node_controller_ID[total_size];
uint32_t assigned_consortium_ID[total_size];

// rsu_controller_ID: c_assigned(r_j) — paper §3.1 / Table 3.2. The controller
// each RSU is assigned to (over RSUs, NOT vehicles). Indexed by RSU index
// (0..N_RSUs-1). Defines the controller observation set
// R^obs_ck(t) = {r_j ∈ R_trusted(t) : c_assigned(r_j)=c_k} (Eq 3.60) and the
// identity under which an RSU's window evidence E_c(t) (Eq 3.64) is submitted.
// Mutable: a CP-DETECT/EMA controller revocation reassigns the orphaned RSUs to
// a trusted controller (paper p.75, "no manual failover").
uint32_t rsu_controller_ID[total_size];

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
// ── Attack flag variables (active — used by 06a_attack_models.h) ─────────────
int routing_algorithm = 0;
// R7g.3: skip Hyperledger Fabric + REST API bring-up during training-data
// sweeps. When true, initialize_blockchain() is a no-op and every Call* in
// 06c_blockchain_api.h short-circuits before contacting the Fabric daemon;
// detection, attack injection, and beacon CSV logging still run normally so
// the master training CSV can be built without a working Fabric environment.
// Defaults to false (production behaviour preserved).
bool skip_blockchain                           = false;
bool beacon_suppression_nodes[total_size]     = {};  // reserved: beacon vanishing/drop attack
bool heading_spoof_nodes[total_size]          = {};  // TP-S2: heading/velocity exaggeration
bool rsu_fabrication_nodes[total_size]        = {};  // reserved: RSU fabrication

// ── Temporary: legacy constants needed by 05_utils.h/08/11 ───────────────
// These will be removed progressively in Stages 4 and 6 when 08_lldp_handlers.h
// and 11_routing_blockchain_transmission.h are rewritten.
#define MPTD_MAX_NEIGHBORS 40  // array size for neighbor tables in 05_utils.h
// NOTE: Was previously `#define max 40` — renamed in R6.5 because the bare
// macro `max` shadows OpenFHE / std::max identifiers and broke compilation
// once 06b2_fhe_backend.h pulled in <openfhe.h>. Identifiers containing
// "max" as a substring (s_max, k_max, B_max, etc.) are unaffected.
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
bool tp_vehicle_nodes[total_size]         = {};  // TP-S2: malicious vehicle trajectory poisoning

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

bool sybil_mitm_nodes[total_size]                  = {}; // MP-S2: identity theft / MP-S3: MitM relay

// ── Present-attack gateway flags — one per vehicle attack role (paper §3.4) ──
// These control which per-node arrays are populated in declare_attackers().
// RSU-level attacks (TP-S1, MP-S1) and controller attacks (TP-S3, MP-S4)
// leave ALL flags false — their poisoning is applied directly in
// HandleBeaconReceived() without going through the vehicle send path.
bool present_tp_vehicle_attack          = false;  // TP-S2: vehicle sends poisoned trajectory
bool present_heading_spoof_attack       = false;  // TP-S2: heading/velocity exaggeration component
bool present_sybil_mitm_attack          = false;  // MP-S2: identity theft / MP-S3: MitM relay
bool present_rsu_fabrication_attack     = false;  // reserved — RSU fabrication (unused currently)
bool present_beacon_suppression_attack  = false;  // reserved — beacon vanishing (unused currently)

// mu1/mu2/mu3 removed in Stage 10 — LDA Lagrangian multipliers, no references found

// ── Per-node delta struct (cleared in 12_main.h beacon scheduling) ───────────
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

// ── Stub functions referenced by 12_main.h ────────────────────────────────────
void generate_F_and_E() {}   // called inside !routing_test guard only

void clear_delta_at_nodes(DeltaNodeFi* df) {
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < MAX_NODES; j++) {
            df[i].delta_fi_inst[j] = DeltaNodeVal{};
            df[i].source_f      = 0;
            df[i].destination_f = 0;
            df[i].flow_id       = 0;
        }
}
