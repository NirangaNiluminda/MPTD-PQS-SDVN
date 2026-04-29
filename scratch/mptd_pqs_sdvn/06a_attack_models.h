// ============================================================
// 06a_attack_models.h — MRTPA Attack Models (§3.4)
// MPTD-PQS SDVN (split from 06_mrtpa_attack.h, Stage 10B cleanup)
// ============================================================
// Implements the 7-attack taxonomy from paper §3.4:
//
//   Trajectory Poisoning (TP) attacks:
//     TP-S1 (attack_number=1): Compromised RSU — position drift
//     TP-S2 (attack_number=2): Malicious vehicle — heading/speed exaggeration
//     TP-S3 (attack_number=3): Fabrication — extreme acceleration injection
//
//   Mobility Pattern (MP) attacks:
//     MP-S1 (attack_number=3 old / 4 in declare):  Sybil via RSU — ghost IDs
//     MP-S2 (attack_number=4): Vehicle impersonation — identity theft beacons
//     MP-S4 (attack_number=6): Combined all-type attack
//     Coordinated (attack_number=7): Phase-locked multi-source
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
//  attack 1 TP-S1 Location Spoofing  → position drift only
//                                       fires: TP-S1 (kinematic), TP-S4/S5 (drift)
//  attack 2 TP-S2 Flooding            → velocity/heading exaggeration
//                                       fires: TP-S2 (heading rate)
//  attack 3 TP-S3 Fabrication         → extreme acceleration injection
//                                       fires: TP-S3 (|a|>a_max)
//  attack 4 MP-S1 Sybil RSU           → position drift (density inflation by RSU)
//                                       fires: MP-S1 (identity density)
//  attack 5 MP-S2 Vanishing           → suppressed at send level in 09_vehicle_beacon_tx.h
//                                       effect: FN — vehicle sends nothing
//  attack 6 MP-S4 Combined            → position + heading + acceleration together
//                                       fires: TP-S1, TP-S2, TP-S3, TP-S4/S5
//  attack 7 Coordinated Multi-Source  → phase-locked position drift across attackers
//                                       fires: TP-S1 + MP-S2 (sync timing)
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
            // MP-S2: Vanishing — NO trajectory modification here.
            // Beacon suppression is handled at send level in 09_vehicle_beacon_tx.h:
            // vanishing attackers skip sending every alternate beacon (50% drop).
            // Effect on metrics: FN increase (poisoned beacons not sent → not detected)
            break;

        case 6:
            // MP-S4: Combined / All-type attack (Eq. 3.19)
            // Simultaneously triggers TP-S1, TP-S2, TP-S3, TP-S4/S5
            position.x    += theta * max_position_deviation     * sin(t * 0.7);
            position.y    += theta * max_position_deviation     * cos(t * 0.5);
            velocity.x    += theta * max_velocity_deviation     * 1.5 * sin(t * 2.9);
            velocity.y    += theta * max_velocity_deviation     * 1.5 * cos(t * 2.3);
            acceleration.x = theta * a_max * 2.0               * cos(t * 1.7);
            acceleration.y = theta * a_max * 2.0               * sin(t * 1.1);
            break;

        case 7:
            // Coordinated Multi-Source — phase-locked drift across all attackers
            // All attacker vehicles use the SAME sinusoidal phase → identical
            // fake positions → triggers MP-S2 (sync timing) + TP-S1 (drift)
            // Phase offset = π/2 to distinguish from attack 1
            position.x += theta * max_position_deviation * sin(t * 0.7 + 1.5708);
            position.y += theta * max_position_deviation * cos(t * 0.5 + 1.5708);
            velocity.x += theta * max_velocity_deviation * 0.5 * sin(t * 0.7 + 1.5708);
            velocity.y += theta * max_velocity_deviation * 0.5 * cos(t * 0.5 + 1.5708);
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
        present_location_attack_nodes    = false;
        present_flooding_attack_nodes    = false;
        present_fabrication_attack_nodes = false;
        present_MIM_attack_nodes         = false;
        present_vanishing_attack_nodes   = true;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        if (controller_malicious_assumption) present_vanishing_attack_controllers = true;
    } else if (attack_number == 7) {
        // MP-S4: Coordinated multi-source — all attack types simultaneously (§3.2.4)
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
