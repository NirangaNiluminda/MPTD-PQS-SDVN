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
#define NS3_ROOT "/home/sdvn_mobility_flooding/ns-allinone-3.35/ns-3.35"
#define FAB_ROOT "/home/sdvn_mobility_flooding/fabric-samples"
// DATASET_ROOT = the git repo working tree (committable). The additive
// per-attack/per-percentage dataset export (export_run_dataset() in
// 10_metrics_csv.h) writes here, separate from NS3_ROOT analytics output.
#define DATASET_ROOT "/home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN"
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
#define MAX_RSUS 256

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

// Unified multi-seed control (2026-07-20). --seed=N sets run_seed=N, which:
//   (1) seeds the ns-3 RNG via RngSeedManager::SetRun(N) in 12_main.h, and
//   (2) is mixed into the attack randomness (attacker selection, stealth drift,
//       RSU-compromise shuffle) so that different --seed values produce genuinely
//       different runs (mean±std over ≥3 seeds). Default 1 = reproducible baseline.
// Without this, the attack seeds were fixed per-vehicle (12345*vid) → every run
// identical → multi-seed std≈0.
uint32_t run_seed = 1;

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
    "COMBINED:All7AttackTypes",                            // 0 combined-attack mode
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
// STEALTHY control-plane mode (a5 = TP-S3, a7 = MP-S4) — DEFAULT.
//   The malicious controller leaves the vehicle→RSU beacon PLAUSIBLE (unchanged):
//   the attack lives entirely in its control-plane WRONG_ROUTING decisions.
//   → Beacon-level detectors (ψ, Ercan, Sharma) are BLIND by construction
//     (poisoned beacons are feature-identical to honest).
//   → Only CP-DETECT (controller-vs-RSU consensus, Algorithm 7) catches it,
//     because the compromised controller keeps issuing WRONG_ROUTING that the
//     honest RSUs disagree with.
//   This is the realistic control-plane threat and the intended default.
//
//   Set --stealthy_control_plane=false for the legacy "LOUD" variant, where the
//   controller injects a large per-beacon drift (a5: ~16 m position; a7: +25-50%
//   speed) that leaks into the beacon so ANY beacon detector catches the symptom
//   (used only to show the contrast — beacon baselines then also "detect" a5/a7).
//   NOTE: only affects attack_number 5 and 7; other attacks are unchanged.
bool stealthy_control_plane = true;

// Verbose per-beacon stdout ([DSRC-TX], [LL-SEL]) — OFF by default. These fire
// once per vehicle per beacon interval; at 200 vehicles over a 300 s run they
// balloon the log to ~280 MB and make the run I/O-bound (~2.3 h). Gated so long
// sweeps stay fast/small; set --verbose_tx=true to re-enable for debugging.
bool g_verbose_tx = false;

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
//   7 = B2  Standalone GAT   : SOTA GAT baseline — decision purely S_i > θ_S, NO ψ tier
//   8 = B3  Standalone AE    : SOTA LSTM-AE baseline — decision purely ε_i > θ_ae, NO ψ tier
//   0 = Full (no ablation)   : every component active
// NOTE: modes 2/3 keep the ψ composite tier active inside fuse_scores() (lp always
// on), so "A2 GAT-only"/"A3 AE-only" are really ψ+GAT / ψ+AE ablations. Modes 7/8
// are the GENUINE standalone SOTA baselines: the scored full-mode confusion matrix
// is driven by the single detector's native threshold alone (08_detection_engine.h),
// with no ψ contamination — the correct control for a "superior to SOTA" claim.
int ablation_mode = 1;

// ── C10: paper ablation variants AB1–AB11 (§4.1.2) ─────────────────────────
// The paper's 11-way ablation removes ONE mechanism at a time from FULL mode.
// --ablation_ab=N (1..11) selects the variant; 0 (default) = selector off,
// legacy --ablation_mode governs alone. Dispatch in 12_main.h after Parse():
//   AB1  rule signatures off (ψ TP-S1..MP-S4 zeroed)   → enable_rule_signatures=false
//   AB2  HMAC+nonce beacon gate off                     → enable_hmac_gate=false
//   AB3  GAT off                                        → g_enable_gat_cli=0
//   AB4  LSTM-AE off                                    → g_enable_lstm_ae_cli=0
//   AB5  full AI off (lightweight only)                 ≡ legacy ablation_mode=1
//   AB6  TRS gate off (FHE stays on)                    → enable_trs=false
//   AB7  FHE off (TRS signs plaintext aggregates)       → enable_fhe=false
//   AB8  RSU 3-state lifecycle off (always trusted)     → enable_rsu_lifecycle=false
//   AB9  multi-controller off (single fixed controller) → enable_ctrl_rotation=false
//   AB10 blockchain off                                 ≡ legacy ablation_mode=5 + skip_blockchain
//   AB11 LKH tree off (per-member unicast rekey)        → use_lkh_tree=false
// All AB modes except AB5/AB10 force ablation_mode=0 (full baseline minus one).
// Each toggle is also individually CLI-exposed for combined ablations.
int  ablation_ab            = 0;
bool enable_rule_signatures = true;   // AB1
bool enable_hmac_gate       = true;   // AB2

// ── a6 (MP-S3) faithful in-transit modification ──────────────────────────────
// Default false = legacy a6 behaviour (fabricate a fresh unauthenticated beacon
// addressed to the ATTACKER's RSU). That model never reaches the HMAC gate: the
// RSU geographic filter (08_detection_engine.h) drops it because the claimed
// victim position belongs to another RSU zone, so HMAC is never consulted.
//
// When true, a6 models a real man-in-the-middle per the paper threat model:
//   (1) the relayed beacon is addressed to the RSU serving the CLAIMED position,
//       so it survives the geographic filter, and
//   (2) it carries the victim's HMAC computed over the victim's ORIGINAL
//       kinematics, then the payload is modified → MAC no longer matches →
//       lkh_verify_beacon_hmac() fails (in-transit modification detected).
// The attacker never obtains K_i, so it cannot mint a fresh valid MAC; it only
// replays the original MAC over altered content — exactly a real MitM's power.
//
// Kept OFF by default so combined-attack runs (AB1, E1–E5) are byte-identical
// to previously collected results. Enable per-run with --faithful_mitm=1.
bool g_faithful_mitm        = false;

// a6 stealth regime (paper gamma=1.0, Eq 3.5). Default false = abrupt/blatant
// forgery, which trips the psi speed bound on 100% of beacons and makes the HMAC
// gate redundant. When true the forged kinematics stay INSIDE the feasibility
// envelope (speed <= 0.9*s_max, position step <= epsilon_max_stealth = 0.5 m <
// the 3.33 m gate), so psi cannot fire and HMAC is the only instant detector.
// Requires --faithful_mitm=1 to be meaningful (the stale MAC is what HMAC catches).
bool g_mitm_stealth         = false;

// Per-run isolation of the shared live-results dir (analytics/results/<scenario>/).
// The per-beacon logs (beacon_log.csv, ghost_identity_log.csv, …) are written to
// that ONE dir and only copied to the per-attack dataset folder at run end, so two
// CONCURRENT sims of different attacks clobber each other's beacon_log (MCC is safe
// — it comes from in-memory counters — but beacon-level analysis is corrupted).
// With --per_pid_results=1 the live dir becomes <scenario>_pid<PID>/, isolating each
// process so its beacon_log is clean even under parallel sweeps. Default OFF so the
// running sweep's paths are byte-identical. (2026-07-25)
bool g_per_pid_results      = false;

// AB3 sweep variable: n_coord — the number of COORDINATED Sybil identities a
// compromised RSU fabricates per intercepted vehicle (paper Fig 3.4 Steps 4-5,
// previously the hardcoded N_ghost=4 in 08_detection_engine.h). GAT's unique
// contribution is spatial relational detection of coordinated attacks, so this
// is the variable that stresses it. Default 4 = the previous hardcoded value,
// so every already-collected result is byte-identical.
int  g_n_coord              = 4;

// AB5 / E2 uniform-speed traces (--uniform_speed_trace). The default traces use
// REALISTIC per-road OSM speed limits, so a vehicle's actual speed is set by map
// topology, not by --maxspeed (measured: mobility_urban_60.tcl has 2234 distinct
// speeds, max 29.98 m/s). That is correct for E1/E5/AB1-AB4, but it confounds a
// SPEED sweep: v would not be a clean experimental variable.
// build_sumo_trace.sh UNIFORM_SPEED_MS=<m/s> emits a companion trace where every
// vType maxSpeed, speedFactor=1, speedDev=0 AND every road edge speed is pinned to
// the target. Those live under the "<tag>_uniform" tag so they sit BESIDE the
// realistic ones — mobility_urban_60.tcl (used by the completed AB1 + running AB2
// sweeps) is never overwritten. RSU layout is speed-independent and keeps the base
// tag. Default false = existing behaviour for every other experiment.
bool g_uniform_speed_trace  = false;

// AB3 Phase 1: paper-faithful MP-S1 identity-density signature (--honest_mp_s1).
// The legacy MP-S1 (08_detection_engine.h) ANDs the density check with two
// non-paper shortcuts: (a) ghost_seen_flag — fires on the synthetic ghost ID
// marker vid>=10000, and (b) tag.GetIsPoisoned() — the GROUND-TRUTH poison label.
// Together these make MP-S1 a label-assisted oracle: FP=0 by construction and every
// ghost trivially caught, so GAT can never contribute (AB3 anti-informative). When
// true, MP-S1 implements ONLY paper Eq. mp_s1 — the identity-density check on
// OBSERVABLE beacon data (count > threshold) — with no synthetic-ID flag and no
// ground-truth gate. Default false so all existing single/combined results are
// byte-identical; enable for AB3 and the paper-faithful redo.
bool g_honest_mp_s1         = false;
// Honest-MP-S1 density threshold multiplier: threshold = ceil((N_v/N_r) * k). The
// naive k=1 (mean density) flags ~48% of clean urban traffic; k≈2.3 lifts the
// threshold to the clean 95th-pct (~7) so honest clustering doesn't false-positive.
double g_mp_s1_density_k    = 2.3;

// AB3 Phase 2: GAT-evasive distributed Sybil (--sybil_gat_evasive). The legacy a3
// clusters n_coord ghosts at ONE RSU (density spike → MP-S1 trivially fires) and never
// routes them through the GAT scoring path (0 fusion entries), so GAT cannot contribute.
// When true, each ghost is instead: (1) placed near a DISTINCT RSU so per-RSU density
// stays ≤1 (evades even paper-faithful MP-S1), (2) given plausible kinematics — speed
// ≤ s_max, constant heading so no TP-S1/S2/S3 fire — but a heading INCONSISTENT with
// local flow (spatial-relational outlier), (3) de-synced in time (evades MP-S2), and
// (4) ROUTED through ipfs_push_and_maybe_flush() so the GAT actually scores it. Goal:
// rules can no longer catch the Sybils (FN>0 in lightweight) but GAT can (spatial
// anomaly) — the configuration that isolates GAT's contribution. Requires
// --honest_mp_s1=1 to be meaningful. Default false: legacy a3 is byte-identical.
bool g_sybil_gat_evasive    = false;
bool enable_trs             = true;   // AB6
// AB6 f/n sweep: force exactly F of the n signing-ring members compromised so
// PARR degrades along the BFT tolerance boundary. -1 = off (legacy behaviour:
// f_actual emerges randomly from attack_percentage/rsu_seed). 0..n = controlled.
int  g_trs_compromised_f    = -1;
bool enable_fhe             = true;   // AB7
bool enable_rsu_lifecycle   = true;   // AB8
bool enable_ctrl_rotation   = true;   // AB9
bool use_lkh_tree           = true;   // AB11

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
// AB4: per-run override of the GLOBAL fusion lambda_ae (--lambda_ae). -1 = off,
// i.e. use fusion_weights.json as-is. Rescales psi/gat to 1-lambda_ae keeping
// their ratio. Exists because the deployed lambda_ae=0.3071 caps the AE's vote
// below phi_th=0.5, so on stealth drift it cannot move any decision; the
// per-attack lambda_sets can't be used instead because k_hat is -1 on every
// decision. Per-run so AB4 needs no change to the shared JSON.
double g_lambda_ae_cli    = -1.0;

// AB3: per-run override of the GLOBAL fusion lambda_gat (--lambda_gat). -1 = off.
// Mirrors --lambda_ae above (rescales psi/ae to 1-lambda_gat keeping their ratio).
// Exists because the deployed lambda_gat=0.1857 (and every per-attack k-set, max
// 0.3) caps GAT's vote below phi_th=0.5. The AB3 evasive Sybil (--sybil_gat_evasive)
// is deliberately engineered so psi and the LSTM-AE stay ~0 (plausible kinematics,
// no temporal signature) — GAT is meant to be the SOLE discriminator (see
// g_sybil_gat_evasive comment above) — but with the deployed weights, a perfectly
// discriminative GAT (S >> theta_S) still can't cross Phi_th alone: verified
// 2026-07-27, GAT-on vs GAT-off gave BYTE-IDENTICAL fused confusion matrices
// (TP=0/FN=79 both ways) even after fixing GAT's stale calibration. Same
// k_hat=-1 caveat as lambda_ae — the per-attack sets are dead at deploy.
double g_lambda_gat_cli   = -1.0;

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
double g_s_max_cli_kmh = -1.0;  // --s_max_kmh override (km/h); -1 = keep default s_max. Decoupled from --maxspeed (which drives the SUMO trace file).

// TP-S2: Heading rate deviation
double omega_max = 0.5236;  // Max angular velocity (rad/s) = 30 deg/s

// TP-S3: Acceleration bound
double a_max = 4.0;         // Max vehicle acceleration (m/s²)

// TP-S4/TP-S5: Dead-reckoning and drift
double delta_th = 5.0;      // Dead-reckoning residual threshold (m)
// Calibration (2026-07-20, sir Step 5): swept δ_th∈{5,7.5,10,12.5,15} offline on the
// G50 SUMO drift attack (our a2). δ_th=5.0 is the max-MCC value with FPR≤0.05: it lifts
// the drift-signature recall on poisoned beacons hugely (TP-S5 0.18→0.96) at ZERO honest
// FP cost — SUMO honest trajectories are smooth (0.1s beacons), so honest dead-reckoning
// residual ≈0 even at highway speed (verified urban/rural/highway: honest fire 0/15077).
// Old value 10.0 was tuned for the random-waypoint model (large honest turn residuals);
// under SUMO it was needlessly high and missed the stealth drift. a2 MCC 0.945→0.948.
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
// Calibration (2026-07-20, sir Step 6): swept τ_sync∈{1,2,5,10}ms × ρ_sync∈{0.6..0.9}
// on the G50 impersonation attack (our a4). KEPT τ_sync=1ms — widening is
// COUNTERPRODUCTIVE: with 200 SUMO vehicles at 0.1s beacons, honest beacons routinely
// coincide within a few ms, so honest MP-S2 fire explodes 0.00→0.09→0.40→0.67 at
// τ=1→2→5→10ms. τ=1ms already gives clean separation (0.21/0.00). a4 is caught by
// MP-S1 (0.96/0.00) regardless, so τ_sync has ~zero leverage on a4's overall MCC.
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
float  g_theta_s = 8.560697f;  // Option A (Eq 3.46): GAT spatial calibration θ_S (95th pctl of clean S_i). Overridden from models/shared/theta_s.txt at AI init.
double g_phi_max_graph = 1.5707963267948966;  // π/2 — GAT edge heading-divergence bound φmax (#9 sensitivity; runtime override of mptd_ai::PHI_MAX_GRAPH, set via --phi_max)
uint32_t g_fhe_ring_dim = 0;  // #12 sensitivity: 0=auto (OpenFHE picks N for L5); >0 forces params.SetRingDim(N), e.g. 32768/65536. Set via --fhe_ring_dim.

// ── H5: HMAC replay protection (paper HMAC gate: freshness Δ_HMAC + cluster nonce cache) ──
// Δ_HMAC: max age of an authentic beacon at the RSU. Beacons are sent every
// T_b=100 ms with ~sub-ms propagation, so 0.5 s accepts all honest traffic with
// wide margin while bounding the replay window to 5 beacon periods. The paper
// leaves Δ_HMAC symbolic; value is CLI-overridable (--delta_hmac).
double delta_hmac = 0.5;    // Δ_HMAC freshness window (s)

// ── H6: TRS message freshness (paper trs_message/trs_fresh: ring nonce ν_S + Δ_TRS) ──
// Δ_TRS: max age of a σ_TRS bundle at the cloud verify gate. The pipeline runs
// once per IPFS window (L=10 beacons × T_b=100 ms = 1 s), so 2 s covers honest
// sign→verify latency with margin. Paper leaves Δ_TRS symbolic; CLI-overridable.
double delta_trs = 2.0;     // Δ_TRS freshness window (s)

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
double epsilon_max_stealth           = 0.5;   // AB4 sweep variable (--eps_max)   // m per beacon (Eq 3.5 stealth bound, < gate)
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

// ── Lightweight detection-revoke accumulators (NOT PARR) ────────────────────
// These count the LW detection-revoke path, reported as "RevRate". PARR (Eq 4.3)
// is the CRYPTOGRAPHIC TRS-verify rejection rate and uses g_trs_rejected_count /
// (g_trs_verified_count + g_trs_rejected_count) in compute_PARR() instead.
// parr_trs_rejected   = poisoned beacons revoked by the RSU lightweight detector
//                       (flag=1, Eq 3.67)
// parr_poisoned_total = total poisoned beacons submitted to the blockchain ledger
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
// CDER_full (additive, AB4/AB5): the per-beacon RSU CDER above is LIGHTWEIGHT by
// architecture — the RSU emits its control decision immediately, before the
// window-close fusion verdict exists, so ctrl_decisions_* can never reflect the
// AI layer and comes out identical for FULL vs an ML-tier ablation. CDER_full
// scores the controller's RETROSPECTIVE fusion verdict (full_flag) against ground
// truth at the fusion site, so the control-plane error responds to GAT+AE. Stays
// 0 in lightweight modes (1/6) where no fusion runs → compute_CDER_full()
// returns -1 there, and the lightweight run's own ctrl_decisions_* (LW) is used.
uint32_t ctrl_full_total = 0;
uint32_t ctrl_full_wrong = 0;
// AB6 f/n sweep: aggregate-plane control decisions. The controller issues one
// ring-level (macro) control decision per TRS epoch from the verified aggregate;
// when TRS ADMITS a poisoned aggregate (forge), that decision — affecting the
// ring's total_count vehicles — is wrong. Folded into compute_CDER() so CDER
// degrades as f rises (CDER_agg ≈ 1−PARR). Only booked when g_trs_compromised_f>=0,
// so zero effect on non-AB6 runs. Vehicle-weighted (total_count) for visibility
// against the per-beacon CDER denominator.
uint64_t g_agg_ctrl_total = 0;
uint64_t g_agg_ctrl_wrong = 0;
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

// ── Tiered blockchain commit strategy (paper §3.5.5, tab:set-blockchain) ──────
// Per-beacon SYNCHRONOUS Fabric commits are impractical at the 100 ms beacon
// rate (each consensus round-trip blocks the RSU pipeline). Four tiers:
//   T1 immediate  — revocation / controller reassignment (kept synchronous)
//   T2 per-epoch  — trust threshold crossings, TRS sigs, RSU lifecycle
//   T3 batched    — ordinary anomaly evidence E_j(t): buffered per-RSU, flushed
//                   as ONE batched tx every g_t_batch s OR g_n_commit entries
//   T4 off-chain  — raw beacon windows + per-beacon scores → IPFS, hash only
// Security invariant preserved: BFT revocation (eq:bft_revoke_rsu) counts
// distinct RSU submissions within T_w; g_t_batch << T_w so all batches land
// inside the window. Values chosen: T_batch=10 s (≪ T_w≈60 s, 6 batches/window,
// 10× fewer commits than per-second), N_commit=50 (flushes before T_batch under
// high-penetration bursts → no buffer overflow; T_batch dominates at low load).
bool   g_tiered_commit = true;   // enable Tier-3 batched evidence commit
double g_t_batch       = 10.0;   // Tier-3 batch interval (s)  {5,10,20,30}, ≪ T_w
int    g_n_commit      = 50;     // Tier-3 batch size (entries) {10,25,50,100}
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

// ── Combined-attack mode (--attack_number=0): all 7 attack types active in ONE
// run, the "combined attack" default sir specifies for the ablation and E1–E4.
// g_veh_attack[i] = the attack type assigned to malicious vehicle i (0 = honest;
// else 2/4/6 for the vehicle-level TP-S2/MP-S2/MP-S3). The RSU-level (a1,a3) and
// controller-level (a5,a7) attacks are activated globally alongside. This lets a
// single run yield every metric (TPE from TP attacks, TDEE from MP attacks,
// CP-DETECT from the controller attacks). Set after cmd.Parse() in 12_main.h.
bool g_combined_attack = false;
int  g_veh_attack[total_size] = {};
// Effective attack type for a vehicle: per-node in combined mode, else the global.
inline int veh_atk(uint32_t vid, int global_atk) {
    return (g_combined_attack && vid < (uint32_t)total_size) ? g_veh_attack[vid] : global_atk;
}

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
