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
//   06b_pq_crypto.h        - Post-quantum crypto: TRS + simulated CKKS FHE (§3.3.2-3.3.3)
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
#include "02_config_globals.h"
#include "03_packet_tags.h"
// 03c_generated_tags.h REMOVED - legacy LDA tag classes (replaced by BsmBeaconTag)
#include "04_state_globals.h"
#include "05_utils.h"
// Section 6 split (Stage 10B cleanup) — include in dependency order:
//   06b: PQ crypto (TRS + FHE) — no external deps
//   06c: Blockchain API (Store*/Call* REST calls) — depends on 06b TRS/FHE types
//   06a: Attack models (PoisonTrajectory*, declare_*) — depends on 06c Store* calls
#include "06b_pq_crypto.h"
#include "06c_blockchain_api.h"
#include "06a_attack_models.h"
// 08_lldp_handlers.h REMOVED - legacy LLDP state machine (replaced by 08_detection_engine.h)
#include "07_socket_layer.h"
#include "08_detection_engine.h"
#include "09_vehicle_beacon_tx.h"
#include "10_metrics_csv.h"
#include "11_blockchain_setup.h"
#include "12_main.h"
