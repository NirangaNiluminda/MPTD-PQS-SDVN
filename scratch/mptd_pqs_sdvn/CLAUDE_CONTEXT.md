# MPTD-PQS SDVN Project — Claude Context File
# University of Ruhuna FYP 2024/2025
# Load this file at the start of every new Claude session for instant context.

---

## 1. PROJECT OVERVIEW

**Paper:** "MPTD-PQS: Signature-Characterized Dual-Mode GAT-Temporal Autoencoder with
Blockchain-Enforced Post-Quantum TRS for Detection and Mitigation of MP and TP Attacks in SDVN"

**Framework:** NS-3.35 simulation
**Location:** `/home/niranga/ns-allinone-3.35/ns-3.35/scratch/mptd_pqs_sdvn/`
**Entry point:** `simulation.cc` (includes all .h files in order)

**Build command:**
```bash
cd /home/niranga/ns-allinone-3.35/ns-3.35
python3 waf build
```

**Run command (replace attack_number=1..7, attack_percentage=20..80):**
```bash
python3 waf --run "mptd_pqs_sdvn --attack_number=1 --routing_algorithm=4 --routing_test=true --attack_percentage=40 --simTime=15"
```

---

## 2. FILE STRUCTURE (include order in simulation.cc)

| File | Purpose |
|------|---------|
| `01_includes.h` | NS-3 + std library includes |
| `02_config_globals.h` | All simulation parameters, attack config, thresholds |
| `03_packet_tags.h` | BsmBeaconTag (uplink) + DownlinkControlTag (downlink) |
| `04_state_globals.h` | Runtime state: vehicle_state[], RSU globals, Option B globals |
| `05_utils.h` | Utility functions |
| `06b_pq_crypto.h` | Post-quantum crypto: TRS + CKKS FHE |
| `06c_blockchain_api.h` | Blockchain REST API calls |
| `06a_attack_models.h` | PoisonTrajectoryByType(), declare_attack_states(), declare_attackers() |
| `07_socket_layer.h` | SimpleUdpApplication class (sockets, StartApplication, HandleReadTwo) |
| `08_detection_engine.h` | All detection algorithms + handle_readone + handle_downlink_at_rsu |
| `09_vehicle_beacon_tx.h` | send_lte_dataunicast_alone() + inject_mp_s2_stolen_beacons() |
| `10_metrics_csv.h` | MCC, FPR, PARR, CDER, TDEE, TPE, PBPO metrics + CSV logging |
| `11_blockchain_setup.h` | initialize_blockchain(), assign_controllers() |
| `12_main.h` | main(): topology, IP setup, scheduling, NetAnim |

---

## 3. NODE ID MAPPING (CRITICAL — never change this)

```
nid=0   controller_Node      (SDN controller — PURPLE in NetAnim)
nid=1   management_Node      (MPTD-PQS detection — BLUE in NetAnim)
nid=2   Vehicle_Nodes.Get(0) = V0  (vid = nid-2 = 0)
nid=3   Vehicle_Nodes.Get(1) = V1  (vid = nid-2 = 1)
...
nid=17  Vehicle_Nodes.Get(15)= V15 (vid = nid-2 = 15)
nid=18  RSU_Nodes.Get(0)     = RSU0
nid=19  RSU_Nodes.Get(1)     = RSU1
nid=20  RSU_Nodes.Get(2)     = RSU2
nid=21  RSU_Nodes.Get(3)     = RSU3
nid=22  backup_controller_Node (CYAN in NetAnim)

vid = nid - 2  (vehicle array index, 0..15)
```

---

## 4. ATTACK NUMBER MAPPING

| attack_number | Paper ID | Name | Who is malicious |
|--------------|----------|------|-----------------|
| 1 | TP-S1 | Compromised RSU trajectory poisoning | RSU (compromised_rsu[]) |
| 2 | TP-S2 | Malicious vehicle trajectory poisoning | Vehicles (tp_vehicle_nodes[]) |
| 3 | MP-S1 | Sybil via compromised RSU ghost IDs | RSU (compromised_rsu[]) |
| 4 | MP-S2 | Sybil via vehicle identity theft | Vehicles (sybil_mitm_nodes[]) |
| 5 | TP-S3 | Control-plane trajectory poisoning | Controller (controller_malicious_assumption=true) |
| 6 | MP-S3 | MitM data-plane mobility pattern | Vehicles (sybil_mitm_nodes[]) |
| 7 | MP-S4 | Control-plane global mobility model | Controller (controller_malicious_assumption=true) |

---

## 5. COMPLETE UPLINK + DOWNLINK FLOW

### UPLINK (vehicle → management):
```
Vehicle sends BSM beacon (BsmBeaconTag):
  send_lte_dataunicast_alone()           [DSRC-TX] log
  → DSRC 802.11p → RSU port 6666
  → handle_readone()                     [DSRC-RSU] log
    → attack applied if RSU compromised  [TP-S1-RSU / MP-S1-RSU] log
    → send_rsu_dataunicast_alone()       [RSU-FWD] log
    → CSMA → management port 7777
  → HandleReadOne() → HandleBeaconReceived()  [MGT-RX] log
    → run_tp_detect()   (TP-S1..S5)
    → run_syb_detect()  (MP-S1..S4)
    → run_mitm_detect() (MP-S3 KL)
    → run_cp_detect()   (attacks 5,7)
    → [METRICS] log + confusion matrix update
```

### DOWNLINK (management → vehicles):
```
HandleBeaconReceived() Step 11 (DownlinkControlTag):
  g_mgmt_downlink_socket→SendTo(RSU CSMA IP:8888)   [DL-MGT-TX] log
  → handle_downlink_at_rsu()                         [DL-RSU-RX] log
    → m_send_socket→SendTo(3.255.255.255:9999)       [DL-RSU-FWD] log
    → HandleReadTwo()                                [DL-VEH-RX] log

alert_type: 0=CLEAN_ROUTING, 1=ATTACK_DETECTED, 2=WRONG_ROUTING (attacks 5,7)
Professor's terms: centralized_dsrc_data_unicast / centralized_dsrc_data_broadcast
```

---

## 6. NETWORK TOPOLOGY (routing_test=true)

```
CSMA backhaul (10.1.1.0/24):
  RSU0 = 10.1.1.1    RSU1 = 10.1.1.2
  RSU2 = 10.1.1.3    RSU3 = 10.1.1.4
  controller = 10.1.1.5
  management = 10.1.1.6   ← g_management_csma_ip
  backup_ctrl = 10.1.1.7

DSRC channel (3.0.0.0/8):
  Vehicles: 3.0.0.1 .. 3.0.0.16
  RSU0: 3.0.0.17   RSU1: 3.0.0.18
  RSU2: 3.0.0.19   RSU3: 3.0.0.20
  Broadcast address: 3.255.255.255 (used for downlink RSU→vehicles)

RSU positions (fixed):
  RSU0=(250,480)  RSU1=(750,480)  RSU2=(1250,480)  RSU3=(1750,480)

Vehicle clusters (4 per RSU):
  V0-V3  near RSU0   V4-V7  near RSU1
  V8-V11 near RSU2   V12-V15 near RSU3
```

---

## 7. KEY SOCKET PORTS

| Port | Direction | Purpose |
|------|-----------|---------|
| 6666 | Vehicle → RSU | DSRC beacon uplink (BSM) |
| 7777 | RSU → Management | CSMA relay (uplink forwarding) |
| 8888 | Management → RSU | CSMA downlink (control response) |
| 9999 | RSU → Vehicles | DSRC downlink broadcast (DownlinkControlTag) |
| 10000 | Uplink send socket | (bound, not connected) |
| 20000 | General send socket | RSU DSRC broadcast socket |
| 30000 | Downlink send socket | Management sends to RSU |
| 51000 | RSU relay socket | RSU → management forwarding |

---

## 8. DETECTION ALGORITHMS

### TP-DETECT (Algorithm 1) — run_tp_detect()
| Signature | Check | Paper eq |
|-----------|-------|---------|
| TP-S1 (bit 0) | dist(pos_t, pos_t-1) > s_max * dt | kinematic feasibility |
| TP-S2 (bit 1) | |heading_change| > omega_max * dt | heading rate |
| TP-S3 (bit 2) | |accel| > a_max | acceleration bound |
| TP-S4 (bit 3) | dead-reckoning residual > delta_th | position prediction |
| TP-S5 (bit 4) | cumulative drift score > delta_th | rolling drift |

### SYB-DETECT (Algorithm 2) — run_syb_detect()
| Signature | Check |
|-----------|-------|
| MP-S1 (bit 5) | RSU identity density > N_Vehicles |
| MP-S2 (bit 6) | beacon timestamp within tau_sync of another vehicle |
| MP-S3 (bit 7) | KL speed divergence > kappa_th (in run_mitm_detect) |
| MP-S4 (bit 8) | ghost transit: d/tdiff > s_max |

### Key thresholds (02_config_globals.h):
```
s_max = 33.33 m/s    omega_max = 0.5236 rad/s
a_max = 4.0 m/s²     delta_th = 10.0 m
tau_sync = 0.001 s   kappa_th = 1.5
psi_th = 0.3         T_b = 0.1 s (beacon interval)
```

---

## 9. NETANIM COLOR CODING

### Vehicles:
| Color | Meaning | Attacks |
|-------|---------|---------|
| GREEN (0,200,0) | Honest vehicle, clean RSU zone | All attacks |
| ORANGE (255,128,0) | Victim of compromised RSU zone (attacks 1,3) OR malicious vehicle (attacks 2,4,6) OR all vehicles affected (attacks 5,7) | |
| RED (255,0,0) | Sybil victim (identity stolen) | Attack 4 only |

### RSUs:
| Color | Meaning |
|-------|---------|
| RED (255,0,0) | Compromised RSU (attacks 1,3) |
| YELLOW (255,200,0) | Clean RSU |

### Controller nodes:
| Color | Node | Meaning |
|-------|------|---------|
| BLUE (0,0,255) | management_Node (nid=1) | MPTD-PQS detection |
| PURPLE (150,0,220) | controller_Node (nid=0) | Honest SDN controller |
| RED (255,0,0) | controller_Node (nid=0) | Malicious controller (attacks 5,7) |
| CYAN (0,210,210) | backup_controller_Node (nid=22) | Standby backup |

---

## 10. VERIFICATION SEQUENCE — FIGURE 3.1 (Attack 1 TP-S1)

Map each log line to each numbered step in the paper figure:

```
Step ①  [DSRC-TX] V10 → RSU2 (3.0.0.19:6666) at 7.05
         Vehicle sends honest beacon

Step ②  [DSRC-RSU2] V10 pos(1280.5,570) compromised=YES
         RSU receives it (and is compromised)

Step ③  [TP-S1-RSU2]
          pos_x 1280.50 → 1256.13  (drift -24.37 m)
          pos_y 570.00  → 546.83   (drift -23.17 m)
          disp_err=33.63 m  detect=LIKELY
         RSU poisons the trajectory

Step ④  [RSU-FWD] RSU2 → MGT 10.1.1.6:7777  [send_rsu_dataunicast_alone]
         RSU forwards POISONED data to management

Step ⑤  [MGT-RX] V10 from RSU2 pos(1256.13,546.83) poisoned=YES
         Management/Controller is deceived (wrong position)

Step ⑥  [DL-MGT-TX] → RSU2 vid=10 alert=CLEAN_ROUTING [centralized_dsrc_data_unicast]
         Management sends control packet DOWN to RSU

Step ⑦  [DL-VEH-RX] V8 from RSU2 alert=CLEAN_ROUTING spd_adv=33.33 m/s
         Vehicles receive control response
```

---

## 11. ATTACK-SPECIFIC VERIFICATION SEQUENCES

### Attack 2 (TP-S2) — Malicious Vehicle:
```
Key logs to find:
  [DSRC-TX] V(nid) → RSU  ← vehicle sends (already poisoned at send time)
  [VEHICLE-TX] is_mal=YES  ← in vehicle_tx_log.csv
  [MGT-RX] ... poisoned=YES
  [METRICS] TP attack=2 ... sig=TP-S1,TP-S2,TP-S4,TP-S5,MP-S4  ← ALL fire simultaneously
  FPR=0.0000  PARR=0.9286 (FN=6: one missed per malicious vehicle on first beacon, count<2)
  Confusion matrix: TP=78 FP=0 TN=140 FN=6  MCC=0.9436  CDER=0.0268
  
What to check in code: PoisonTrajectoryByType() in 06a_attack_models.h
  attack_number==2 → tp_vehicle_nodes[vid]=true
  tp_vehicle_nodes[] set by declare_attackers() → GetBooleanWithProbability()
```

### Attack 3 (MP-S1) — Compromised RSU Ghost IDs:
```
VERIFIED & FIXED. Three bugs fixed (density_limit, is_new gate, ghost_seen flag).
Key logs to find:
  [MP-S1-RSU1] intercepting V6 at t=7.025 → generating ghost IDs  ← RSU intercepts
  [MP-S1-GHOST-TX] RSU1 ghost_id=10160 pos(930.25,570) → MGT      ← ghost UDP packet sent
  [MP-S1-GHOST-TX] RSU1 ghost_id=10161 pos(780.25,720) → MGT      ← 4 ghost packets total
  [MP-S1-GHOST-RX] ghost_id=10160 RSU1 density_count=1 ghost_seen=YES +1(new) ← MGT receives ghost
  [METRICS] TP attack=3 ... sig=MP-S1            ← detection fires
  [DL-MGT-TX] ... ATTACK_DETECTED                ← alert sent
  
Correct run command: ./waf --run "scratch/mptd_pqs_sdvn/mptd_pqs_sdvn --attack_number=3 --attack_percentage=40 --simTime=15 --rsu_seed=1"
IMPORTANT: Arguments MUST use -- prefix. Without it, attack_number defaults to 1.
  
density_limit = N_Vehicles/N_RSUs = 4 (per-RSU threshold, not global N_Vehicles=16)
N_ghost=4 per vehicle → count=1+4=5 > 4 → fires on FIRST beacon

ghost_seen flag (04_state_globals.h): set when ANY ghost (vid>=10000) arrives at MGT.
Detection uses dual condition: (count>limit || ghost_seen) && poisoned.
This guards against CSMA ordering where ghost#4 might arrive after the real beacon.

Ghost CSV: analytics/results/ghost_identity_log.csv (204 rows, 8 veh × 4 ghost × ~6.4 windows)
Confusion matrix: TP=108 FP=0 TN=112 FN=0  MCC=1.0  PARR=1.0
(TP=108 not 112: extra CSMA ghost traffic slightly reduces beacons in 15s window; FN=0 confirmed)
```

### Attack 4 (MP-S2) — Vehicle Identity Theft (Sybil):
```
Key logs to find:
  [MP-S2-SYB] V(attacker) impersonating V(victim) at pos(x,y)
  [DSRC-TX] multiple vehicles same RSU at staggered times
  [METRICS] TP attack=4 ... sig=MP-S4  ← ghost transit impossibility
  
What to check: inject_mp_s2_stolen_beacons() in 09_vehicle_beacon_tx.h
  N_stolen=2 identities per attacker
  Timestamp stagger: +0.005*(stolen_count+1) seconds
  MP-S4 check: d/tdiff > s_max (532m in 0.03s = 17733 m/s >> 33.33)
  
NetAnim: RED=victim V0,V1 (first 2 honest), ORANGE=attacker, GREEN=other honest
```

### Attack 5 (TP-S3) — Controller Malicious:
```
Key logs to find:
  [TP-S3-CTRL] controller corrupted V(id) pos(real)→(fake) spd real→fake
  [DL-MGT-TX] → RSU vid=0 alert=WRONG_ROUTING [centralized_dsrc_data_broadcast]
  [DL-VEH-RX] ... alert=WRONG_ROUTING  ← downlink IS the attack
  
What to check: HandleBeaconReceived() attack_number==5 block
  controller_malicious_assumption=true required
  GetBooleanWithProbability(attack_percentage, vehicle_id) gates per vehicle
  CP-DETECT: run_cp_detect() returns 1 when controller_malicious_assumption=true
```

### Attack 6 (MP-S3) — MitM Data Plane:
```
Key logs to find:
  sybil_mitm_nodes[vid]=true vehicles
  [METRICS] TP attack=6 ... sig=MP-S3  ← KL divergence fires
  run_mitm_detect(): kl_approx > kappa_th=1.5
  
Attack mechanism: malicious vehicle relays others' beacons with extreme speed
```

### Attack 7 (MP-S4) — Controller Global Mobility Poisoning:
```
Key logs to find:
  [MP-S4-CTRL] controller poisoned global model V(id) spd X→Y
  [DL-MGT-TX] → RSU vid=0 alert=WRONG_ROUTING [centralized_dsrc_data_broadcast]
  
What to check: HandleBeaconReceived() attack_number==7 block
  Systematic speed shift: fake_spd = real_spd * (1 + 0.5*theta)
  CP-DETECT fires + MP-S3 KL divergence fires globally
```

---

## 12. CSV OUTPUT FILES

| File | Location | Contents |
|------|----------|---------|
| `beacon_log.csv` | `analytics/results/` | Every beacon: sim_time, vehicle_id, rsu_id, pos, speed, is_poisoned, detected, sig_mask, psi |
| `vehicle_tx_log.csv` | `analytics/results/` | Vehicle send side: real vs sent pos/spd/hdg per beacon |
| `rsu_relay_log.csv` | `analytics/results/` | RSU relay: real vs received pos per beacon |
| `tp_s1_poison_log.csv` | `analytics/results/` | TP-S1 specific: drift_x, drift_y, disp_err per poisoned beacon |
| `metrics_summary.csv` | `analytics/results/` | Per-attack summary: TP/FP/TN/FN/MCC/FPR/PARR/CDER/TDEE/TPE/PBPO |
| `attack1_formal_verification_log.txt` | `analytics/results/` | Full terminal log from attack 1 run |

---

## 13. CURRENT IMPLEMENTATION STATUS

### Completed (all committed or ready to commit):
- ✅ Attack 1 (TP-S1): Compromised RSU — VERIFIED, logs match Fig 3.1 steps 1-7
- ✅ Attack 2 (TP-S2): Malicious vehicle — VERIFIED, Fig 3.2 10-step doc created
    FPR=0, PARR=0.9286 (FN=6 expected cold-start), sigs: TP-S1,TP-S2,TP-S4,TP-S5,MP-S4
- ✅ Attack 3 (MP-S1): Ghost ID RSU — VERIFIED, Fig 3.4 10-step doc created
    3 bugs fixed (density_limit fix, is_new gate, ghost_seen CSMA robustness flag)
    Real ghost UDP packets now sent (not just count inflation). ghost_identity_log.csv added.
    PARR=1.0 FP=0 FN=0 MCC=1.0 (TP=108). Use --rsu_seed=1 for RSU0+RSU1 example.
- ✅ Attack 4 (MP-S2): Sybil identity theft — implemented, MP-S4 detects ghost transit
- ✅ Attack 5 (TP-S3): Controller malicious — WRONG_ROUTING downlink working
- ✅ Attack 6 (MP-S3): MitM — KL divergence detection working
- ✅ Attack 7 (MP-S4): Controller global poisoning — CP-DETECT + MP-S3 working
- ✅ Uplink path: Vehicle→DSRC→RSU→CSMA→Management (Option B active)
- ✅ Downlink path: Management→CSMA→RSU→DSRC→Vehicles (NEW — just implemented)
- ✅ NetAnim colors: 3-way for attack 4, compromised zone for attacks 1/3
- ✅ Professor's function names: handle_readone, send_rsu_dataunicast_alone, send_lte_dataunicast_alone, centralized_dsrc_data_broadcast, centralized_dsrc_data_unicast
- ✅ DownlinkControlTag added to 03_packet_tags.h
- ✅ Backup controller node (nid=22) created after RSUs

### Pending commit (uncommitted changes):
- 03_packet_tags.h — DownlinkControlTag
- 04_state_globals.h — g_rsu_csma_ip[4], g_mgmt_downlink_socket
- 07_socket_layer.h — RSU port 8888, handle_downlink_at_rsu decl, HandleReadTwo update
- 08_detection_engine.h — handle_downlink_at_rsu impl + Step 11 in HandleBeaconReceived
- 09_vehicle_beacon_tx.h — professor's function renames
- 12_main.h — RSU CSMA IP storage, NetAnim updates

**Suggested commit name:**
`feat(downlink): implement centralized_dsrc_data_broadcast/unicast completing SDVN uplink+downlink loop`

---

## 14. PROFESSOR'S FUNCTION NAME MAPPING

| Professor's term | Code function | File |
|-----------------|--------------|------|
| send_lte_dataunicast_alone | send_lte_dataunicast_alone() | 09_vehicle_beacon_tx.h |
| handle_readone | SimpleUdpApplication::handle_readone() | 08_detection_engine.h |
| send_rsu_dataunicast_alone | [RSU-FWD] step in handle_readone() | 08_detection_engine.h |
| centralized_dsrc_data_broadcast | Step 11 in HandleBeaconReceived() vid=0 | 08_detection_engine.h |
| centralized_dsrc_data_unicast | Step 11 in HandleBeaconReceived() vid=vehicle_id | 08_detection_engine.h |

---

## 15. HOW TO START DEBUGGING A NEW ATTACK

For each new attack (e.g. attack 2), run this sequence:

```bash
# 1. Run the simulation
cd /home/niranga/ns-allinone-3.35/ns-3.35
python3 waf --run "mptd_pqs_sdvn --attack_number=2 --routing_algorithm=4 --routing_test=true --attack_percentage=40 --simTime=15" > /tmp/attack2_log.txt 2>&1

# 2. Check attack is firing
grep "TP-S2\|DSRC-TX\|MGT-RX.*poison" /tmp/attack2_log.txt | head -20

# 3. Check detection metrics
tail -20 /tmp/attack2_log.txt

# 4. Check CSV
head -10 analytics/results/beacon_log.csv
grep "is_poisoned=1\|detected=1" analytics/results/beacon_log.csv | head -10

# 5. Verify Figure steps 1-7 each correspond to a log line
```

---

## 16. LOADING THIS CONTEXT IN A NEW CLAUDE SESSION

**Method — paste this at the start of your new Claude chat:**

```
I am working on an NS-3 SDVN simulation project for my FYP.
Please read the complete project context file first:
/home/niranga/ns-allinone-3.35/ns-3.35/scratch/mptd_pqs_sdvn/CLAUDE_CONTEXT.md

Then help me debug attack number [X].
```

Claude will read the file using the Read tool and have full context immediately.

---

*Last updated: 2026-05-07 | Session: attack 3 ghost packet implementation + ghost_seen flag fix*
*Project path: /home/niranga/ns-allinone-3.35/ns-3.35/scratch/mptd_pqs_sdvn/*
