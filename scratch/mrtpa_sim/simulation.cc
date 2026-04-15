// ============================================================
// VANET Trajectory Poisoning Attack Simulation
// FYP Project: Mobility Pattern and Trajectory Poisoning Attacks
// ============================================================
//
// This file ties together all logical modules of the simulation.
// Open each numbered header file to study that part of the code:
//
//   01_includes.h       - NS-3 and standard library includes
//   02_config_globals.h - Simulation parameters and MRTPA configuration
//   03_packet_tags.h    - Custom NS-3 packet tag classes (~746 classes)
//   04_state_globals.h  - Runtime state variables and flow structs
//   05_utils.h          - Utility and initialization functions
//   06_mrtpa_attack.h   - MRTPA Algorithm 1: PoisonTrajectory, EnforceRealism
//   07_security.h       - Security: HMAC, digital signatures, LDA
//   08_lldp_handlers.h  - LLDP protocol and network handlers
//   09_send_lte.h       - LTE metadata/delta send functions
//   10_metrics_csv.h    - Performance metrics and CSV output
//   11_routing_blockchain_transmission.h - Routing + blockchain + transmission
//   12_main.h           - main(): topology setup and simulation scheduling
//
// Build and run:
//   cd /home/niranga/ns-allinone-3.35/ns-3.35
//   python3 waf build
//   python3 waf --run "mrtpa_sim --attack_number=1 --routing_algorithm=4 --routing_test=true --attack_percentage=80 --simTime=15"
// ============================================================

#include "01_includes.h"
#include "02_config_globals.h"
#include "03_packet_tags.h"
#include "04_state_globals.h"
#include "05_utils.h"
#include "06_mrtpa_attack.h"
#include "07_security.h"
#include "08_lldp_handlers.h"
#include "09_send_lte.h"
#include "10_metrics_csv.h"
#include "11_routing_blockchain_transmission.h"
#include "12_main.h"
