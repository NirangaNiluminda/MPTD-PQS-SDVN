// ============================================================
// 06a_attack_models.h — MRTPA Attack Models (§3.4)
// MPTD-PQS SDVN (split from 06_mrtpa_attack.h, Stage 10B cleanup)
// ============================================================
// Implements the 7-attack taxonomy from paper §3.4:
//
//   Trajectory Poisoning (TP) attacks:
//     TP-S1 (attack_number=1): Compromised RSU — position drift (Fig 3.1)
//     TP-S2 (attack_number=2): Malicious vehicle — heading/speed exaggeration (Fig 3.2)
//     TP-S3 (attack_number=5): Controller-level interception — position+speed (Fig 3.3)
//
//   Mobility Pattern (MP) attacks:
//     MP-S1 (attack_number=3): Sybil via compromised RSU — ghost IDs (Fig 3.4)
//     MP-S2 (attack_number=4): Vehicle impersonation — identity theft beacons (Fig 3.5)
//     MP-S3 (attack_number=6): MitM relay — amplified speed distribution shift (Fig 3.6)
//     MP-S4 (attack_number=7): Coordinated multi-vector — TP-S2+MP-S2+MP-S3 (Fig 3.7)
//
// Core functions:
//   PoisonTrajectory()          — generic field modification (Algorithm 1, Line 22)
//   PoisonTrajectoryByType()    — per-attack differentiated injection (§3.4.1-3.4.2)
//   EnforceRealism()            — clamp to physical limits (Algorithm 1, Line 23)
//   declare_attack_states()     — map attack_number → LDA flags + blockchain log
//   declare_attackers()         — assign per-node malicious status
//   declare_compromised_rsus()  — set which RSUs are compromised (TP-S1, MP-S1)
//
// Depends on: 06c_blockchain_api.h (Store* functions called by declare_* functions)
// ============================================================

// ── Packet-size counter (used by 09_vehicle_beacon_tx.h) ─────────────────────
// lte_initial_timestamp is declared in 02_config_globals.h
long lte_total_packet_size   = 0;

// ── Simulation node/app containers (used by 12_main.h) ───────────────────────
ApplicationContainer apps;
ApplicationContainer RSU_apps;
NodeContainer controller_Node;
NodeContainer management_Node;
NodeContainer Vehicle_Nodes;
NodeContainer RSU_Nodes;

// ── PoisonTrajectory — generic field modification (Algorithm 1, Line 22) ──────
// Applies sinusoidal deviation to all trajectory fields simultaneously.
// Prefer PoisonTrajectoryByType() for per-attack differentiated injection.
void PoisonTrajectory(Vector &position, Vector &velocity, Vector &acceleration, double theta)
{
    double t = Simulator::Now().GetSeconds();
    position.x    += theta * max_position_deviation     * sin(t * 0.7);
    position.y    += theta * max_position_deviation     * cos(t * 0.5);
    velocity.x    += theta * max_velocity_deviation     * sin(t * 1.3);
    velocity.y    += theta * max_velocity_deviation     * cos(t * 0.9);
    acceleration.x += theta * max_acceleration_deviation * cos(t * 1.7);
    acceleration.y += theta * max_acceleration_deviation * sin(t * 1.1);
}

// ── PoisonTrajectoryByType — per-attack differentiated injection (§3.4.1-3.4.2) ──
// Each attack_number manipulates a DIFFERENT BSM field so distinct detection
// signatures (TP-S1..MP-S4) fire per attack type. Ensures attack signals are
// separable by the detection engine in 08_detection_engine.h.
//
//  attack 1 TP-S1 Location Spoofing  → position drift at RSU (honest vehicles)
//                                       fires: TP-S1 (kinematic), TP-S4/S5 (drift)
//  attack 2 TP-S2 Flooding            → velocity/heading exaggeration by vehicle
//                                       fires: TP-S2 (heading rate), TP-S4 (DR residual)
//  attack 3 MP-S1 Sybil RSU           → position drift + ghost ID inflation at RSU
//                                       fires: MP-S1 (identity density)
//  attack 4 MP-S2 Impersonation       → identity theft + stolen beacon injection
//                                       fires: MP-S4 (ghost transit impossibility)
//  attack 5 TP-S3 Control-plane       → controller intercepts+modifies honest beacons
//                                       fires: CP-DETECT + TP-S1/S4/S5 via drift
//  attack 6 MP-S3 MitM Relay          → malicious vehicle amplifies speed beyond KL-th
//                                       fires: MP-S3 (KL divergence > kappa_th=1.5)
//  attack 7 MP-S4 Coordinated         → combines TP-S2 + MP-S2 + MP-S3 simultaneously
//                                       fires: TP-S1/S2/S4, MP-S3, MP-S4 (multi-vector)
void PoisonTrajectoryByType(Vector &position, Vector &velocity, Vector &acceleration,
                             double theta, int atk_num)
{
    double t = Simulator::Now().GetSeconds();

    switch (atk_num)
    {
        case 1:
            // TP-S1: Location Spoofing — position drift only (Eq. 3.10)
            // Triggers: TP-S1 (kinematic), TP-S4 (dead-reckoning), TP-S5 (drift)
            position.x += theta * max_position_deviation * sin(t * 0.7);
            position.y += theta * max_position_deviation * cos(t * 0.5);
            break;

        case 2:
            // TP-S2: Flooding — abrupt heading + speed exaggeration (Eq. 3.11)
            // Triggers: TP-S2 (|Δθ| > ω_max·T_b), also TP-S4 via large velocity jump
            velocity.x += theta * max_velocity_deviation * 2.0 * sin(t * 3.1);
            velocity.y += theta * max_velocity_deviation * 2.0 * cos(t * 2.7);
            // Position also drifts in velocity direction (vehicle claims to be ahead)
            {
                double spd = std::sqrt(velocity.x * velocity.x + velocity.y * velocity.y);
                if (spd > 1e-6) {
                    position.x += theta * max_position_deviation * (velocity.x / spd);
                    position.y += theta * max_position_deviation * (velocity.y / spd);
                }
            }
            break;

        case 3:
            // TP-S3: Fabrication — extreme acceleration injection (Eq. 3.12)
            // Triggers: TP-S3 (|a_i| > a_max = 4 m/s²) — inject 2.5× the limit
            acceleration.x = theta * a_max * 2.5 * cos(t * 1.7);
            acceleration.y = theta * a_max * 2.5 * sin(t * 1.1);
            // Also slightly offset position so dead-reckoning diverges
            position.x += theta * max_position_deviation * 0.3 * sin(t * 0.4);
            break;

        case 4:
            // MP-S1: Sybil via RSU — position drift to inflate RSU density count
            // The RSU identity density check (Eq. 3.16) fires when too many
            // IDs appear in the coverage area. Position drift moves attacker
            // beacons across RSU boundaries, appearing as multiple identities.
            position.x += theta * max_position_deviation * 1.5 * sin(t * 0.3);
            position.y += theta * max_position_deviation * 1.5 * cos(t * 0.4);
            break;

        case 5:
            // TP-S3: Control-plane trajectory poisoning (§3.4.1, Figure 3.3)
            // Vehicles are HONEST — no vehicle-level modification here.
            // The controller (management node) applies poisoning in HandleBeaconReceived().
            // This case should never be reached (is_mal=false for attack 5).
            break;

        case 6:
            // MP-S3: MitM relay — amplified speed to exceed KL-divergence threshold (Eq. 3.18)
            // Malicious vehicle sends a beacon with speed >> regional mean.
            // With theta=0.5, target ≈ 3×s_max = 100 m/s → kl_approx = (100-mean)/(mean+3.3) >> 1.5
            // EnforceRealism is SKIPPED for attack 6 in 09_vehicle_beacon_tx.h so the
            // extreme speed value reaches the detection engine intact.
            {
                double spd_now = std::sqrt(velocity.x * velocity.x + velocity.y * velocity.y);
                double target_spd = s_max * 3.0 * (0.5 + theta); // 75–150 m/s range
                if (spd_now > 1e-6) {
                    double scale = target_spd / spd_now;
                    velocity.x *= scale;
                    velocity.y *= scale;
                } else {
                    velocity.x = target_spd;
                    velocity.y = 0.0;
                }
                // Slight position mismatch: relay re-broadcasts from slightly wrong position
                position.x += theta * max_position_deviation * 0.4 * sin(t * 0.9);
                position.y += theta * max_position_deviation * 0.4 * cos(t * 0.7);
            }
            break;

        case 7:
            // MP-S4: Coordinated multi-vector (§3.2.4, Figure 3.7)
            // Combines TP-S2 (heading exaggeration) + MP-S3 (speed amplification).
            // MP-S2 stolen-beacon injection handled separately in send_LTE_metadata_uplink_alone().
            // TP-S1 position drift (phase-locked across attackers, offset π/2):
            position.x += theta * max_position_deviation * sin(t * 0.7 + 1.5708);
            position.y += theta * max_position_deviation * cos(t * 0.5 + 1.5708);
            // TP-S2 heading/speed exaggeration:
            velocity.x += theta * max_velocity_deviation * 2.0 * sin(t * 3.1);
            velocity.y += theta * max_velocity_deviation * 2.0 * cos(t * 2.7);
            // MP-S3 speed amplification (after TP-S2 delta applied):
            {
                double spd = std::sqrt(velocity.x * velocity.x + velocity.y * velocity.y);
                if (spd > 1e-6) {
                    double target = s_max * 2.5 * theta;
                    if (target > spd) {
                        double scale = target / spd;
                        velocity.x *= scale;
                        velocity.y *= scale;
                    }
                }
            }
            break;

        default:
            // Fallback: generic full-field poisoning
            PoisonTrajectory(position, velocity, acceleration, theta);
            break;
    }
}

// ── EnforceRealism — clamp poisoned values to physical limits (Algorithm 1, Line 23) ──
// Ensures poisoned data doesn't trigger simple anomaly detectors that check
// for physically impossible values. Attack 3 (TP-S3 Fabrication) bypasses
// this — caller must NOT apply EnforceRealism for attack_number==3.
void EnforceRealism(Vector &position, Vector &velocity, Vector &acceleration)
{
    // Clamp position to simulation area bounds
    position.x = (position.x < min_position_x) ? min_position_x :
                 ((position.x > max_position_x) ? max_position_x : position.x);
    position.y = (position.y < min_position_y) ? min_position_y :
                 ((position.y > max_position_y) ? max_position_y : position.y);

    // Clamp velocity magnitude to realistic vehicle speed
    double speed = sqrt(velocity.x * velocity.x + velocity.y * velocity.y + velocity.z * velocity.z);
    if (speed > max_realistic_speed)
    {
        double scale = max_realistic_speed / speed;
        velocity.x *= scale;
        velocity.y *= scale;
        velocity.z *= scale;
    }

    // Clamp acceleration magnitude
    double accel_mag = sqrt(acceleration.x * acceleration.x +
                            acceleration.y * acceleration.y +
                            acceleration.z * acceleration.z);
    if (accel_mag > max_realistic_acceleration)
    {
        double scale = max_realistic_acceleration / accel_mag;
        acceleration.x *= scale;
        acceleration.y *= scale;
        acceleration.z *= scale;
    }
}

// ============================================================
// ATTACK MODEL: State Declaration Functions (§3.4)
// Call order in 12_main.h:
//   declare_attack_states()    → which attack flags are active
//   declare_attackers()        → which nodes are malicious
//   declare_compromised_rsus() → which RSUs are compromised (TP-S1, MP-S1 only)
// ============================================================

// ── declare_attack_states() — map attack_number → LDA flags + blockchain log ──
void declare_attack_states()
{
    if (attack_number == 6) {
        present_location_attack_nodes      = true;
        present_flooding_attack_nodes      = true;
        present_fabrication_attack_nodes   = true;
        present_MIM_attack_nodes           = true;
        present_vanishing_attack_nodes     = true;
        if (controller_malicious_assumption) {
            present_flooding_attack_controllers    = true;
            present_fabrication_attack_controllers = true;
            present_MIM_attack_controllers         = true;
            present_vanishing_attack_controllers   = true;
        }
    } else if (attack_number == 1) {
        // TP-S1: Compromised RSU trajectory poisoning (§3.4.1, Figure 3.1)
        // Attacker = RSU; all vehicles are honest
        present_location_attack_nodes    = false;
        present_flooding_attack_nodes    = false;
        present_fabrication_attack_nodes = false;
        present_MIM_attack_nodes         = false;
        present_vanishing_attack_nodes   = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
    } else if (attack_number == 2) {
        // TP-S2: Malicious vehicle sends fake but realistic trajectory (§3.4.1, Figure 3.2)
        present_location_attack_nodes    = true;
        present_flooding_attack_nodes    = false;
        present_fabrication_attack_nodes = false;
        present_MIM_attack_nodes         = false;
        present_vanishing_attack_nodes   = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
    } else if (attack_number == 3) {
        // MP-S1: Sybil via compromised RSU — ghost vehicle ID injection (§3.4.2, Figure 3.4)
        // Attacker = RSU; all vehicles are honest
        present_location_attack_nodes      = false;
        present_flooding_attack_nodes      = false;
        present_fabrication_attack_nodes   = false;
        present_MIM_attack_nodes           = false;
        present_vanishing_attack_nodes     = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
    } else if (attack_number == 4) {
        // MP-S2: Sybil via malicious vehicle impersonation (§3.4.2, Figure 3.5)
        // Attacker = vehicle; sends extra beacons with stolen vehicle IDs
        present_location_attack_nodes    = false;
        present_flooding_attack_nodes    = false;
        present_fabrication_attack_nodes = false;
        present_MIM_attack_nodes         = true;   // MIM flag used for identity theft
        present_vanishing_attack_nodes   = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
    } else if (attack_number == 5) {
        // TP-S3: Control-plane trajectory poisoning (§3.4.1, Figure 3.3)
        // Vehicles are honest; the SDN controller (management node) is compromised.
        // Poisoning applied at HandleBeaconReceived() in 08_detection_engine.h.
        // CP-DETECT fires via run_cp_detect() when controller_malicious_assumption=true.
        present_location_attack_nodes      = false;
        present_flooding_attack_nodes      = false;
        present_fabrication_attack_nodes   = false;
        present_MIM_attack_nodes           = false;
        present_vanishing_attack_nodes     = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
        // controller_malicious_assumption remains true (set globally in 02_config_globals.h)
    } else if (attack_number == 6) {
        // MP-S3: MitM data-plane mobility pattern poisoning (§3.4.2, Figure 3.6)
        // Malicious vehicles act as relay nodes: intercept and re-broadcast with
        // amplified speed to exceed KL-divergence threshold (kappa_th=1.5, Eq. 3.18).
        // MIM_malicious_nodes = true → is_mal=true → PoisonTrajectoryByType(case 6) fires.
        present_location_attack_nodes      = false;
        present_flooding_attack_nodes      = false;
        present_fabrication_attack_nodes   = false;
        present_MIM_attack_nodes           = true;   // MitM relay attackers
        present_vanishing_attack_nodes     = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
    } else if (attack_number == 7) {
        // MP-S4: Coordinated multi-vector attack (§3.2.4, Figure 3.7)
        // Combines TP-S2 (heading/position drift) + MP-S2 (identity theft beacons)
        // + MP-S3 (speed amplification for KL divergence).
        // Multiple detection signatures fire simultaneously (TP-S1/S2/S4 + MP-S3/S4).
        present_location_attack_nodes      = true;   // TP-S2: position drift
        present_flooding_attack_nodes      = true;   // TP-S2: heading exaggeration
        present_fabrication_attack_nodes   = false;
        present_MIM_attack_nodes           = true;   // MP-S2: identity theft + MP-S3: relay
        present_vanishing_attack_nodes     = false;
        if (controller_malicious_assumption) {
            present_flooding_attack_controllers    = true;
            present_fabrication_attack_controllers = false;
            present_MIM_attack_controllers         = true;
            present_vanishing_attack_controllers   = false;
        }
    }

    if (routing_algorithm == 4) {
        StoreAttackConfigToBlockchain(
            attack_number,
            present_location_attack_nodes,
            present_flooding_attack_nodes,
            present_fabrication_attack_nodes,
            present_MIM_attack_nodes,
            present_vanishing_attack_nodes,
            present_flooding_attack_controllers,
            present_fabrication_attack_controllers,
            present_MIM_attack_controllers,
            present_vanishing_attack_controllers,
            controller_malicious_assumption);
    }
}

// ── declare_attackers() — assign per-node malicious status ───────────────────
void declare_attackers()
{
    for (uint32_t i = 0; i < total_size; i++) {
        bool attacking_state = GetBooleanWithProbability(attack_percentage, i);

        location_malicious_nodes[i]    = present_location_attack_nodes    ? attacking_state : false;
        flooding_malicious_nodes[i]    = present_flooding_attack_nodes    ? attacking_state : false;
        fabrication_malicious_nodes[i] = present_fabrication_attack_nodes ? attacking_state : false;
        MIM_malicious_nodes[i]         = present_MIM_attack_nodes         ? attacking_state : false;
        vanishing_malicious_nodes[i]   = present_vanishing_attack_nodes   ? attacking_state : false;

        if (routing_algorithm == 4) {
            StoreNodeAttackStateToBlockchain(
                i, attack_percentage,
                location_malicious_nodes[i],
                flooding_malicious_nodes[i],
                fabrication_malicious_nodes[i],
                MIM_malicious_nodes[i],
                vanishing_malicious_nodes[i],
                trajectory_poisoning_malicious_nodes[i]);
        }
    }

    // Controller malicious assignment (by attack_percentage threshold)
    auto set_ctrl = [&](bool* arr, bool flag) {
        bool v0 = false, v1 = false, v2 = false;
        if (flag) {
            if      (attack_percentage >= 10)  v0 = true;
            if      (attack_percentage >= 35)  v1 = true;
            if      (attack_percentage >= 67)  v2 = true;
        }
        arr[0] = v0; arr[1] = v1; arr[2] = v2; arr[3] = false;
    };
    set_ctrl(flooding_malicious_controllers,    present_flooding_attack_controllers);
    set_ctrl(fabrication_malicious_controllers, present_fabrication_attack_controllers);
    set_ctrl(MIM_malicious_controllers,         present_MIM_attack_controllers);
    set_ctrl(vanishing_malicious_controllers,   present_vanishing_attack_controllers);
}

// ── declare_compromised_rsus() — set which RSUs are compromised ───────────────
// Called for attack_number 1 (TP-S1) and 3 (MP-S1) where the RSU is attacker.
// Uses attack_percentage to determine how many of the 4 RSUs are compromised:
//   10–33%  → 1 RSU (RSU 0)
//   34–66%  → 2 RSUs (RSU 0, 1)
//   67–100% → 3 RSUs (RSU 0, 1, 2)
void declare_compromised_rsus()
{
    compromised_rsu[0] = compromised_rsu[1] = compromised_rsu[2] = compromised_rsu[3] = false;

    if (attack_number != 1 && attack_number != 3) return; // only RSU-level attacks

    if (attack_percentage >= 10)  compromised_rsu[0] = true;
    if (attack_percentage >= 34)  compromised_rsu[1] = true;
    if (attack_percentage >= 67)  compromised_rsu[2] = true;

    for (int r = 0; r < 4; r++) {
        if (compromised_rsu[r])
            cout << "[RSU-COMPROMISE] RSU " << r << " is COMPROMISED"
                 << " (attack=" << attack_number
                 << " pct=" << attack_percentage << "%)" << endl;
    }
}

// ── End of 06a_attack_models.h ───────────────────────────────────────────────
