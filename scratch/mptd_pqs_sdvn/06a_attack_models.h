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
//     MP-S3 (attack_number=6): MitM data-plane — moderate speed shift (Fig 3.6)
//     MP-S4 (attack_number=7): Controller-malicious global mobility model poisoning (Fig 3.7)
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
NodeContainer controller_Node;         // primary SDN controller (Node index 0)
// R4.b: backup_controller_Node removed — paper uses CP-DETECT (Alg 7) via RSU
// consensus instead of a backup controller. CP-DETECT itself lands in phase R6.
NodeContainer management_Node;
NodeContainer Vehicle_Nodes;
NodeContainer RSU_Nodes;
// Cloud/ITS Server placeholder for paper Fig 3.9 conformance (sits outside both
// the lightweight and full mode boundaries; receives FHE-encrypted aggregates
// gated by σ_TRS per invariant #5). No behaviour, no networking, no application
// until phase R9 wires the FHE channel; until then this is a netanim-only stub.
NodeContainer cloud_Node;

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
//  attack 3 MP-S1 Sybil RSU           → RSU-level attack only; is_mal=false for all
//                                       vehicles → case 3 is never reached (no-op)
//                                       fires: MP-S1 (identity density) via RSU handler
//  attack 4 MP-S2 Impersonation       → position drift on own beacon + stolen beacons
//                                       injected via inject_mp_s2_stolen_beacons()
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
            // TP-S1 (attack_number=1): Compromised RSU — position drift (Fig 3.1)
            // NEVER REACHED: for attack=1 all vehicle flags are false → is_mal=false
            // for every vehicle, so PoisonTrajectoryByType() is never called.
            // The actual TP-S1 poisoning happens at the RSU level inside
            // HandleBeaconReceived() (08_detection_engine.h), which intercepts the
            // honest vehicle beacon and overwrites its position field directly.
            // This case exists only as a reference; it has no runtime effect.
            break;

        case 2:
            // TP-S2 (attack_number=2): Malicious vehicle — heading/speed exaggeration (Fig 3.2)
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
            // MP-S1 (attack_number=3): Two modes depending on sybil_registration_pct:
            //
            // ORIGINAL mode (sybil_registration_pct == 0):
            //   Attacker = RSU; all vehicle flags are false → this case NEVER REACHED.
            //   MP-S1 attack implemented at RSU level (HandleBeaconReceived ghost IDs).
            //
            // ENHANCED mode (sybil_registration_pct > 0):
            //   Attacker = pre-registered Sybil vehicle (valid pool ID).
            //   is_mal=true → this case IS reached.
            //   (1) Speed amplification → MP-S3 KL detection (Eq. 3.18)
            //       target ≈ 66 m/s >> s_max → fires when few Sybil active (mean low).
            //       Detection DEGRADES as attack_percentage rises because more active
            //       Sybil elevate the regional mean → kl_approx drops below kappa_th.
            //       This produces non-trivial, varying MCC/DR curves. (*)
            //   (2) Small position drift (≤ 1m) → stays below TP-S1 threshold
            //       (s_max * T_b = 3.33m), so kinematic checks do NOT fire.
            //       Detection relies solely on KL divergence.
            // (*) Degradation threshold: kl = |66 - mean| / (mean + 3.33) = 1.5
            //     → mean ≈ 24.7 m/s → ~3 active Sybil in 16-vehicle simulation.
            if (sybil_registration_pct > 0) {
                // Speed amplification: triggers MP-S3 KL divergence at low Sybil count,
                // degrades naturally as regional mean rises with more active Sybil.
                double spd_now = std::sqrt(velocity.x * velocity.x + velocity.y * velocity.y);
                double target_spd = s_max * 2.0 * (0.5 + theta);  // 33–66 m/s (θ=0..1)
                if (spd_now > 1e-6) {
                    double scale = target_spd / spd_now;
                    velocity.x *= scale;
                    velocity.y *= scale;
                } else {
                    velocity.x = target_spd;
                    velocity.y = 0.0;
                }
                // Small position drift: ≤ 1m per beacon → below s_max*T_b=3.33m threshold
                // TP-S1, TP-S4, TP-S5 do NOT fire; detection is purely behavioural (MP-S3).
                position.x += theta * 2.0 * std::sin(t * 1.3);
                position.y += theta * 2.0 * std::cos(t * 0.9);
            }
            break;

        case 4:
            // MP-S2 (attack_number=4): Sybil via malicious vehicle impersonation (Fig 3.5)
            // Paper §3.4.2: malicious vehicle forges multiple mobility packets using stolen
            // vehicle identities. The primary attack vector is inject_mp_s2_stolen_beacons()
            // (called after this in send_LTE_metadata_uplink_alone()) which sends extra
            // beacons claiming stolen vehicle IDs but carrying the attacker's position.
            //
            // The position drift here is intentional: inject_mp_s2_stolen_beacons() uses
            // tx_px/tx_py AFTER this drift is applied. This means stolen-ID beacons appear
            // at a shifted position, while the real vehicle whose ID was stolen is at its
            // honest position → spatial gap triggers MP-S4 ghost-transit-impossibility
            // (Eq. 3.19): d(r_j,r_k)/|t_j−t_k| > s_max → ghost identity flagged.
            position.x += theta * max_position_deviation * 1.5 * sin(t * 0.3);
            position.y += theta * max_position_deviation * 1.5 * cos(t * 0.4);
            break;

        case 5:
            // TP-S3 (attack_number=5): Controller-level interception — position+speed (Fig 3.3)
            // TP-S3: Control-plane trajectory poisoning (§3.4.1, Figure 3.3)
            // Vehicles are HONEST — no vehicle-level modification here.
            // The controller (management node) applies poisoning in HandleBeaconReceived().
            // This case should never be reached (is_mal=false for attack 5).
            break;

        case 6:
            // MP-S3 (attack_number=6): MitM data-plane — moderate speed shift (Fig 3.6)
            // MP-S3: MitM data-plane mobility pattern poisoning (§3.4.2, Figure 3.6)
            // Paper: attacker fabricates mobility reports with modified speed/location
            // while keeping values "realistic to avoid basic detection" (format checks pass)
            // but shifted enough to corrupt the regional speed distribution → D_KL > κ_th.
            // Target ≈ 2×s_max ≈ 66 m/s (physically plausible for emergency vehicles / highway)
            // kl_approx = |66-mean|/(mean+s_max*0.1) ≈ (66-15)/18.3 ≈ 2.8 > κ_th=1.5 ✓
            // EnforceRealism is SKIPPED for attack 6 in 09_vehicle_beacon_tx.h so the
            // elevated speed value (> max_realistic_speed=s_max) reaches the detection engine.
            {
                double spd_now = std::sqrt(velocity.x * velocity.x + velocity.y * velocity.y);
                double target_spd = s_max * 2.0 * (0.5 + theta); // 33–66 m/s range (θ=0..1)
                if (spd_now > 1e-6) {
                    double scale = target_spd / spd_now;
                    velocity.x *= scale;
                    velocity.y *= scale;
                } else {
                    velocity.x = target_spd;
                    velocity.y = 0.0;
                }
                // Small position offset: relay re-broadcasts from slightly wrong location
                position.x += theta * max_position_deviation * 0.3 * sin(t * 0.9);
                position.y += theta * max_position_deviation * 0.3 * cos(t * 0.7);
            }
            break;

        case 7:
            // MP-S4 (attack_number=7): Controller-malicious global mobility model poisoning (Fig 3.7)
            // MP-S4: Control-plane mobility pattern poisoning (§3.4.2, Figure 3.7)
            // The SDVN controller itself is malicious and corrupts its global mobility model.
            // Vehicles and RSU are HONEST — no vehicle-level trajectory modification here.
            // Controller-side poisoning applied in HandleBeaconReceived() (08_detection_engine.h).
            // This case is never reached (is_mal=false for all vehicles in attack_number=7).
            break;

        default:
            // Fallback: generic full-field poisoning
            PoisonTrajectory(position, velocity, acceleration, theta);
            break;
    }
}

// ── SampleBoundedDrift — paper §3.4.3 Eq 3.5/3.6 bounded random walk ──────
// Produces per-beacon position drift increment that respects the paper's
// mobility-induced threat amplification model:
//   Eq 3.5: ‖δ(t) − δ(t−T_b)‖ ≤ ε_max   (per-beacon bound)
//   Eq 3.6: ‖δ(t₀ + k·T_b)‖ ≤ k · ε_max (cumulative budget)
//
// Hybrid mode (controlled by stealth_fraction_theta_s):
//   - With prob θ_s        : stealthy increment ∈ [0, ε_max_stealth] (below kinematic gate)
//   - With prob (1 − θ_s)  : abrupt   increment ∈ [ε_max_stealth, ε_max_abrupt] (above s_max·T_b)
//
// Direction is fixed per-vehicle at first call (uniform random angle) so the
// drift is directional, not zero-mean noise. Accumulator resets every
// cumulative_drift_budget_k_max beacons (mimics handover stitching boundary,
// Eq 3.4 W_s(v) approximation).
//
// Returns: (drift_x, drift_y) cumulative drift to apply to honest position.
// Out-params:
//   is_abrupt    — true if this beacon used the abrupt branch (LW-detectable)
//   inc_mag_step — per-beacon increment magnitude (Eq 3.5 quantity; the value
//                  that determines whether single-beacon TP-S1 kinematic fires)
void SampleBoundedDrift(int vid, double &drift_x, double &drift_y,
                        bool &is_abrupt, double &inc_mag_step)
{
    if (vid < 0 || vid >= MAX_NODES) {
        drift_x = drift_y = 0.0; is_abrupt = false; inc_mag_step = 0.0; return;
    }

    // Deterministic per-(vid, beacon_count) RNG → reproducible across runs
    uint32_t seed = 12345u * (uint32_t)vid + (uint32_t)drift_beacon_count[vid] + 7919u;
    std::mt19937 rng(seed);
    std::uniform_real_distribution<double> uni01(0.0, 1.0);

    // Initialise per-vehicle drift direction on first call
    if (!drift_direction_set[vid]) {
        double angle = 2.0 * M_PI * uni01(rng);
        drift_direction_x[vid] = std::cos(angle);
        drift_direction_y[vid] = std::sin(angle);
        drift_direction_set[vid] = true;
    }

    // Reset accumulator at handover boundary (Eq 3.4 W_s(v) approximation)
    if (drift_beacon_count[vid] >= cumulative_drift_budget_k_max) {
        drift_accum_x[vid] = 0.0;
        drift_accum_y[vid] = 0.0;
        drift_beacon_count[vid] = 0;
        double angle = 2.0 * M_PI * uni01(rng);
        drift_direction_x[vid] = std::cos(angle);
        drift_direction_y[vid] = std::sin(angle);
    }

    // Branch: stealth vs abrupt
    double r = uni01(rng);
    if (r < stealth_fraction_theta_s) {
        inc_mag_step = uni01(rng) * epsilon_max_stealth;                                  // Eq 3.5 stealth
        is_abrupt    = false;
    } else {
        inc_mag_step = epsilon_min_abrupt + uni01(rng) * (epsilon_max_abrupt - epsilon_min_abrupt);  // abrupt
        is_abrupt    = true;
    }

    // Apply directional bias, accumulate (Eq 3.6 cumulative budget)
    drift_accum_x[vid] += inc_mag_step * drift_direction_x[vid];
    drift_accum_y[vid] += inc_mag_step * drift_direction_y[vid];
    drift_beacon_count[vid]++;

    drift_x = drift_accum_x[vid];
    drift_y = drift_accum_y[vid];
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
    if (attack_number == 1) {
        // TP-S1: Compromised RSU trajectory poisoning (§3.4.1, Figure 3.1)
        // Attacker = RSU; all vehicles are honest
        present_tp_vehicle_attack         = false;
        present_heading_spoof_attack      = false;
        present_rsu_fabrication_attack    = false;
        present_sybil_mitm_attack         = false;
        present_beacon_suppression_attack = false;
    } else if (attack_number == 2) {
        // TP-S2: Malicious vehicle sends fake but realistic trajectory (§3.4.1, Figure 3.2)
        present_tp_vehicle_attack         = true;
        present_heading_spoof_attack      = false;
        present_rsu_fabrication_attack    = false;
        present_sybil_mitm_attack         = false;
        present_beacon_suppression_attack = false;
    } else if (attack_number == 3) {
        // MP-S1: Two modes selected by sybil_registration_pct (§3.4.2, Figure 3.4)
        //
        // ORIGINAL mode (sybil_registration_pct == 0):
        //   Attacker = compromised RSU; all vehicles are honest.
        //   present_sybil_mitm_attack=false → no vehicle-level poisoning.
        //   Detection: trivial pool-lookup + IsPoisoned tag from RSU.
        //
        // ENHANCED mode (sybil_registration_pct > 0):
        //   Attacker = pre-registered Sybil vehicles (valid pool IDs).
        //   present_sybil_mitm_attack=true → PoisonTrajectoryByType(case 3) fires.
        //   RSUs remain honest; detection must use behavioural analysis (MP-S3 KL).
        present_tp_vehicle_attack         = false;
        present_heading_spoof_attack      = false;
        present_rsu_fabrication_attack    = false;
        present_sybil_mitm_attack         = (sybil_registration_pct > 0); // enhanced mode only
        present_beacon_suppression_attack = false;
    } else if (attack_number == 4) {
        // MP-S2: Sybil via malicious vehicle impersonation (§3.4.2, Figure 3.5)
        // Attacker = vehicle; sends extra beacons with stolen vehicle IDs
        present_tp_vehicle_attack         = false;
        present_heading_spoof_attack      = false;
        present_rsu_fabrication_attack    = false;
        present_sybil_mitm_attack         = true;   // identity theft
        present_beacon_suppression_attack = false;
    } else if (attack_number == 5) {
        // TP-S3: Control-plane trajectory poisoning (§3.4.1, Figure 3.3)
        // Vehicles are honest; the SDN controller (management node) is compromised.
        // Poisoning applied at HandleBeaconReceived() in 08_detection_engine.h.
        // CP-DETECT fires via run_cp_detect() when controller_malicious_assumption=true.
        present_tp_vehicle_attack         = false;
        present_heading_spoof_attack      = false;
        present_rsu_fabrication_attack    = false;
        present_sybil_mitm_attack         = false;
        present_beacon_suppression_attack = false;
        // controller_malicious_assumption remains true (set globally in 02_config_globals.h)
    } else if (attack_number == 6) {
        // MP-S3: MitM data-plane mobility pattern poisoning (§3.4.2, Figure 3.6)
        // Malicious vehicles act as relay nodes: intercept and re-broadcast with
        // amplified speed to exceed KL-divergence threshold (kappa_th=1.5, Eq. 3.18).
        // sybil_mitm_nodes = true → is_mal=true → PoisonTrajectoryByType(case 6) fires.
        present_tp_vehicle_attack         = false;
        present_heading_spoof_attack      = false;
        present_rsu_fabrication_attack    = false;
        present_sybil_mitm_attack         = true;   // MitM relay attackers
        present_beacon_suppression_attack = false;
    } else if (attack_number == 7) {
        // MP-S4: Control-plane mobility pattern poisoning (§3.4.2, Figure 3.7)
        // The SDVN controller itself is malicious and corrupts the global mobility model
        // despite receiving correct mobility data from honest vehicles and RSUs.
        // Vehicles and RSU operate correctly — NO vehicle-level attack flags set.
        // Controller-side poisoning (global speed distribution shift) is applied in
        // HandleBeaconReceived() in 08_detection_engine.h for ALL vehicle beacons.
        present_tp_vehicle_attack         = false;  // vehicles are honest
        present_heading_spoof_attack      = false;
        present_rsu_fabrication_attack    = false;
        present_sybil_mitm_attack         = false;  // no identity theft
        present_beacon_suppression_attack = false;
        // controller_malicious_assumption=true (set in 02_config_globals.h) handles the attack
    }

    if (routing_algorithm == 4) {
        StoreAttackConfigToBlockchain(
            attack_number,
            present_tp_vehicle_attack,
            present_heading_spoof_attack,
            present_rsu_fabrication_attack,
            present_sybil_mitm_attack,
            present_beacon_suppression_attack,
            controller_malicious_assumption);
    }
}

// ── declare_pre_registered_sybils() — mark Sybil vehicles at registration time ──
// Called BEFORE declare_attack_states() + declare_attackers() in 12_main.h.
//
// Assigns pre_registered_sybil[i]=true to a fraction (sybil_registration_pct%)
// of N_Vehicles nodes.  These vehicles get valid pool IDs — RSU cannot reject
// them by ID lookup alone.  Runtime attack_percentage then controls how many
// of these pre-registered nodes are actively poisoning in any given run.
//
// Uses a different seed offset (+500) from declare_attackers() so that
// the "registered" and "active" draws are statistically independent.
//
// Only effective when attack_number==3 and sybil_registration_pct > 0.
// For all other attacks, clears pre_registered_sybil[] and returns.
void declare_pre_registered_sybils()
{
    for (int i = 0; i < total_size; i++)
        pre_registered_sybil[i] = false;

    if (attack_number != 3 || sybil_registration_pct <= 0) return;

    int count = 0;
    for (int i = 0; i < (int)N_Vehicles; i++) {
        pre_registered_sybil[i] = GetBooleanWithProbability(sybil_registration_pct, i + 500);
        if (pre_registered_sybil[i]) count++;
    }

    cout << "\n[PRE-REG-SYBIL] ══════════════════════════════════════════════" << endl;
    cout << "  sybil_registration_pct=" << sybil_registration_pct << "%"
         << "  attack_percentage=" << attack_percentage << "%" << endl;
    cout << "  Pre-registered Sybil: " << count << "/" << N_Vehicles
         << " vehicles have VALID pool IDs but are secretly Sybil" << endl;
    cout << "  (Detection cannot use ID lookup — must rely on MP-S3 KL divergence)" << endl;
    for (int i = 0; i < (int)N_Vehicles; i++) {
        cout << "  V" << i << " (NodeID " << i+2 << ") → "
             << (pre_registered_sybil[i] ? "SYBIL  (valid ID, malicious)"
                                         : "LEGIT  (genuine vehicle)")
             << endl;
    }
    cout << "[PRE-REG-SYBIL] ══════════════════════════════════════════════\n" << endl;
}

// ── declare_attackers() — assign per-node malicious status ───────────────────
void declare_attackers()
{
    for (uint32_t i = 0; i < total_size; i++) {
        bool attacking_state = GetBooleanWithProbability(attack_percentage, i);

        tp_vehicle_nodes[i]         = present_tp_vehicle_attack         ? attacking_state : false;
        heading_spoof_nodes[i]      = present_heading_spoof_attack      ? attacking_state : false;
        rsu_fabrication_nodes[i]    = present_rsu_fabrication_attack    ? attacking_state : false;
        sybil_mitm_nodes[i]         = present_sybil_mitm_attack         ? attacking_state : false;
        beacon_suppression_nodes[i] = present_beacon_suppression_attack ? attacking_state : false;

        // Attack 3 enhanced mode: only pre-registered Sybil nodes may be active attackers.
        // This gates the attack_percentage draw: a Sybil is active only if it was BOTH
        // pre-registered at startup AND passes the runtime attack_percentage probability.
        // Prevents any legitimate vehicle from accidentally becoming Sybil via the gate.
        if (attack_number == 3 && sybil_registration_pct > 0) {
            sybil_mitm_nodes[i] = sybil_mitm_nodes[i] && pre_registered_sybil[i];
        }

        if (routing_algorithm == 4) {
            StoreNodeAttackStateToBlockchain(
                i, attack_percentage,
                tp_vehicle_nodes[i],
                heading_spoof_nodes[i],
                rsu_fabrication_nodes[i],
                sybil_mitm_nodes[i],
                beacon_suppression_nodes[i],
                trajectory_poisoning_malicious_nodes[i]);
        }
    }

}

// ── declare_compromised_rsus() — randomly select which RSUs are compromised ───
// Called for attack_number 1 (TP-S1) and 3 (MP-S1) where the RSU is the attacker.
//
// Number of compromised RSUs = round(N_RSUs * attack_percentage / 100)
//   attack_percentage=25 → 1 of 4 RSUs  (25%)
//   attack_percentage=50 → 2 of 4 RSUs  (50%)
//   attack_percentage=75 → 3 of 4 RSUs  (75%)
//
// WHICH RSUs are compromised is chosen by random shuffle:
//   rsu_seed=0  → random each run (seeded from system clock)
//   rsu_seed=N  → same RSUs every run (reproducible, pass --rsu_seed=N)
//
// The resulting compromised_rsu[] array drives:
//   - HandleBeaconAtRSU()  (poisoning gate)
//   - NetAnim colors        (RED vs YELLOW RSUs, ORANGE vs GREEN vehicles)
//   - rsu_relay_log.csv     (is_poisoned column)
void declare_compromised_rsus()
{
    compromised_rsu[0] = compromised_rsu[1] = compromised_rsu[2] = compromised_rsu[3] = false;

    if (attack_number != 1 && attack_number != 3) return; // only RSU-level attacks

    // Attack 3 enhanced mode: attack is vehicle-level (pre-registered Sybil),
    // NOT RSU-level.  RSUs remain honest — skip RSU compromise selection.
    if (attack_number == 3 && sybil_registration_pct > 0) {
        cout << "[RSU-SELECTION] attack=3 enhanced mode (sybil_registration_pct="
             << sybil_registration_pct << "%) — RSUs remain HONEST, no compromise." << endl;
        return;
    }

    // How many RSUs to compromise
    int n_active = (int)N_RSUs;
    if (n_active > 4) n_active = 4;
    int n_comp = (int)std::round((double)n_active * attack_percentage / 100.0);
    if (n_comp < 0) n_comp = 0;
    if (n_comp > n_active) n_comp = n_active;

    // Build candidate list [0, 1, 2, ..., n_active-1]
    std::vector<int> candidates;
    for (int r = 0; r < n_active; r++) candidates.push_back(r);

    // Seed the RNG
    uint32_t actual_seed = (rsu_seed == 0)
        ? (uint32_t)std::chrono::system_clock::now().time_since_epoch().count()
        : rsu_seed;
    std::mt19937 rng(actual_seed);
    std::shuffle(candidates.begin(), candidates.end(), rng);

    // Mark first n_comp entries as compromised
    for (int i = 0; i < n_comp; i++)
        compromised_rsu[candidates[i]] = true;

    // Report
    cout << "\n[RSU-SELECTION] attack=" << attack_number
         << "  pct=" << attack_percentage << "%"
         << "  compromising " << n_comp << "/" << n_active << " RSUs"
         << "  seed=" << actual_seed << endl;
    for (int r = 0; r < n_active; r++)
    {
        if (compromised_rsu[r])
            cout << "  [RSU-COMPROMISE] RSU" << r << " → COMPROMISED (will poison beacons)" << endl;
        else
            cout << "  [RSU-CLEAN]      RSU" << r << " → CLEAN       (passes beacons untouched)" << endl;
    }
    cout << endl;
}

// ── End of 06a_attack_models.h ───────────────────────────────────────────────
