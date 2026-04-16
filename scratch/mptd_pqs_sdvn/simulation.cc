// ============================================================
// MPTD-PQS: SDVN Mobility Pattern & Trajectory Defense Simulation
// FYP Project: Mobility Pattern and Trajectory Poisoning Attacks
// Framework: Blockchain + GAT + Temporal Autoencoder (MPTD-PQS)
// ============================================================
//
// This file ties together all logical modules of the simulation.
// Open each numbered header file to study that part of the code:
//
//   01_includes.h                - NS-3 and standard library includes
//   02_config_globals.h          - Simulation parameters and attack configuration
//   03_packet_tags.h             - BsmBeaconTag and custom NS-3 packet tag classes
//   04_state_globals.h           - Runtime state: vehicle beacon history buffers
//   05_utils.h                   - Utility and initialization functions
//   06_mrtpa_attack.h            - Attack algorithms: PoisonTrajectory, EnforceRealism
//   07_security.h                - Security: HMAC, digital signatures, TRS, FHE
//   08_beacon_handlers.h         - Detection: TP-DETECT (Alg 1), SYB-DETECT (Alg 2)
//   09_send_lte.h                - LTE beacon uplink functions
//   10_metrics_csv.h             - Paper metrics: MCC, FPR, PARR, CDER, TDEE, TPE, PBPO
//   11_blockchain_transmission.h - Blockchain transmission + MPTD-PQS core
//   12_main.h                    - main(): topology setup and simulation scheduling
//
// Build and run:
//   cd /home/niranga/ns-allinone-3.35/ns-3.35
//   python3 waf build
//   python3 waf --run "mptd_pqs_sdvn --attack_number=1 --routing_algorithm=4 --routing_test=true --attack_percentage=20 --simTime=15"
//
// Attack scenarios (attack_number):
//   1=Malicious RSU (TP-S1)    2=Malicious Vehicle (TP-S2)
//   3=Control-plane TP (TP-S3) 4=Sybil via RSU (MP-S1)
//   5=Sybil Impersonation (MP-S2) 6=MitM (MP-S3) 7=Control-plane MP (MP-S4)
// ============================================================

#include "01_includes.h"
#include "02_config_globals.h"
#include "03_packet_tags.h"
// 03c_generated_tags.h REMOVED - legacy LDA tag classes (replaced by BsmBeaconTag)
#include "04_state_globals.h"
#include "05_utils.h"
#include "06_mrtpa_attack.h"
#include "07_security.h"
// 08_lldp_handlers.h REMOVED - legacy LLDP state machine (replaced by 08_beacon_handlers.h)
#include "08_beacon_handlers.h"
#include "09_send_lte.h"
#include "10_metrics_csv.h"
#include "11_blockchain_transmission.h"
#include "12_main.h"
