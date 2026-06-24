// ============================================================
// MPTD-PQS: SDVN Mobility Pattern & Trajectory Defense Simulation
// FYP Project: Mobility Pattern and Trajectory Poisoning Attacks
// Framework: Blockchain + GAT + Temporal Autoencoder (MPTD-PQS)
// ============================================================
//
// This file ties together all logical modules of the simulation.
// Open each numbered header file to study that part of the code:
//
//   01_includes.h          - NS-3 and standard library includes
//   02_config_globals.h    - Simulation parameters and attack configuration
//   03_packet_tags.h       - BsmBeaconTag and custom NS-3 packet tag classes
//   04_state_globals.h     - Runtime state: vehicle beacon history buffers
//   05_utils.h             - Utility and initialization functions
//   06b1/06b2_*.h          - Real PQ crypto backends: TRS (OpenSSL EC) + FHE (OpenFHE BFV)
//   06c_blockchain_api.h   - Blockchain REST API calls (Store*/Call* functions)
//   06a_attack_models.h    - Attack models: PoisonTrajectory*, declare_* (§3.4)
//   07_socket_layer.h      - UDP socket layer: SimpleUdpApplication class
//   08_detection_engine.h  - Detection engine: TP-DETECT + SYB-DETECT (§3.4.4)
//   09_vehicle_beacon_tx.h - Vehicle beacon transmit: BSM uplink + MP-S2 injection
//   10_metrics_csv.h       - Paper metrics: MCC, FPR, PARR, CDER, TDEE, TPE, PBPO
//   11_blockchain_setup.h  - Blockchain setup: initialize_blockchain + assign_controllers
//   12_main.h              - main(): topology setup and simulation scheduling
//
// Build and run:
//   cd /home/niranga/ns-allinone-3.35/ns-3.35
//   python3 waf build
//   python3 waf --run "mptd_pqs_sdvn --attack_number=1 --routing_algorithm=4 --routing_test=true --attack_percentage=20 --simTime=15"
//
// Attack scenarios (attack_number):
//   1=TP-S1 Compromised RSU    2=TP-S2 Malicious Vehicle
//   3=MP-S1 Sybil via RSU      4=MP-S2 Vehicle Identity Theft
//   5=Vanishing                6=MP-S4 Combined   7=Coordinated
// ============================================================

#include "01_includes.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wsign-compare"

#include "02_config_globals.h"
#include "00_lkh_keys.h"   // LKH tree + HMAC-SHA256 (Eq.3.33–3.37) — must come before 03
#include "03_packet_tags.h"
// 03c_generated_tags.h REMOVED - legacy LDA tag classes (replaced by BsmBeaconTag)
#include "04_state_globals.h"
#include "05_utils.h"
// Section 6 split (Stage 10B cleanup) — include in dependency order:
//   06b1/06b2: real PQ crypto backends (TRS via OpenSSL EC, FHE via OpenFHE BFV)
//   06c: Blockchain API (Store*/Call* REST calls)
//   06a: Attack models (PoisonTrajectory*, declare_*) — depends on 06c Store* calls
#include "06b1_trs_backend.h"   // R6.5: ITrsBackend + ClassicalTrsBackend (OpenSSL EC)
#include "06b2_fhe_backend.h"   // R6.5: BfvBackend (OpenFHE BFV)
#include "06b3_crypto_selftest.h" // R6.5: TRS + BFV round-trip self-tests (env-gated)
#include "06c_blockchain_api.h"
#include "06d_ai_inference.h"   // R7d: ONNX Runtime GAT + LSTM-AE wrapper
#include "06a_attack_models.h"
// 08_lldp_handlers.h REMOVED - legacy LLDP state machine (replaced by 08_detection_engine.h)
#include "07_socket_layer.h"
#include "09b_mobility_provider.h"   // R7a: IMobilityProvider + Hardcoded/FCD backends
                                     //      (must precede 08 — TPE predictor in
                                     //      08_detection_engine.h uses g_mobility_provider
                                     //      for GT side-channel, Eq.4.6, R7e.4)
#include "08b_baseline_ltt.h"   // B1: Ghaleb (2014) LTT baseline (ablation_mode=6)
#include "08_detection_engine.h"
#include "09_vehicle_beacon_tx.h"
#include "10_metrics_csv.h"
#include "11_blockchain_setup.h"
#include "12_main.h"

#pragma GCC diagnostic pop
