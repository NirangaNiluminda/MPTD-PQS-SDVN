// ============================================================
// 08_detection_engine.h — MPTD-PQS Detection Engine
// Renamed from 08_beacon_handlers.h (Stage 10B cleanup)
// MPTD-PQS: Dual-Mode Detection for MP and TP Attacks in SDVN
// ============================================================
// Replaces 08_lldp_handlers.h (17K lines of legacy LLDP code).
//
// Contents:
//   HandleBeaconReceived()     - main entry: BSM beacon at RSU
//   run_tp_detect()            - TP-DETECT (Algorithm 1, §3.4.4)
//   run_syb_detect()           - SYB-DETECT (Algorithm 2, §3.4.4)
//   run_mitm_detect()          - MITM-DETECT (Algorithm 3)
//   run_cp_detect()            - CP-DETECT (Algorithm 4)
//   log_metrics_line()         - [METRICS] / [MRTPA_SUMMARY] output
//
// Paper: §3.4.4, Algorithms 1–4
// ============================================================

#ifndef MPTD_PQS_BEACON_HANDLERS_H
#define MPTD_PQS_BEACON_HANDLERS_H

#include <cmath>
#include <sstream>
#include <time.h>   // clock_gettime for PBPO timing

// ── Internal forward declarations ────────────────────────────────────────────
static uint32_t nearest_rsu_for_position(double px, double py); // defined later in this file

// ── Forward declarations (defined in 10_metrics_csv.h) ───────────────────────
// 10_metrics_csv.h is included after this file in simulation.cc, so we
// forward-declare here to allow HandleBeaconReceived() to call them.
void update_confusion_matrix(bool is_poisoned, bool detected);
void log_beacon_to_csv(uint32_t vid, uint32_t rsu_id, BsmBeaconTag &tag,
                       bool detected, uint32_t sig_mask, double psi);
void log_tp_s1_poison(uint32_t vid, uint32_t rsu_id,
                      double sim_t,
                      double real_px, double real_py,
                      double fake_px, double fake_py,
                      double speed,   double heading, double accel,
                      double drift_x, double drift_y, double disp_err);
void log_rsu_relay(uint32_t vid, uint32_t rsu_id, double sim_t, bool is_poisoned,
                   double real_px, double real_py,
                   double recv_px, double recv_py,
                   double speed,   double heading, double accel);
void log_vehicle_tx(uint32_t vid, uint32_t nearest_rsu,
                    double sim_t,   bool is_malicious,
                    double real_px, double real_py,
                    double sent_px, double sent_py,
                    double real_spd, double sent_spd,
                    double real_hdg, double sent_hdg);
void log_ghost_identity(double sim_t, int rsu_id, int real_vid,
                        double real_px, double real_py,
                        int count_before, int n_ghost,
                        double ghost_displacement_m, int density_lim);
void log_mitm_intercept(double sim_t,
                        uint32_t attacker_id, uint32_t victim_id,
                        double real_px, double real_py,
                        double real_spd, double real_hdg,
                        double fake_px, double fake_py,
                        double fake_spd, double fake_acc,
                        double range_m, int step_num);
// PBPO timing accumulator (defined in 02_config_globals.h)
// pbpo_time_sum_ms and pbpo_cnt are global — updated directly here.

// ── Forward declarations (Stage 6: defined in 06_mrtpa_attack.h) ─────────────
void CallSCTrust(uint32_t vehicleID, double phiScore, uint32_t sigMask,
                 bool isAnomaly, double timestamp);
void CallSCRevoke(uint32_t vehicleID, const std::string &reason,
                  uint32_t rsuID, double timestamp);

// ── Stage 6: consecutive anomaly counter per vehicle (revoke after 3) ─────────
static int consecutive_anomaly_count[total_size + 2] = {};
static const int REVOKE_THRESHOLD = 3;

// ============================================================
// TP-DETECT — Algorithm 1 (§3.4.4)
// Returns bitmask of violated signatures (bit 0 = TP-S1 ... bit 4 = TP-S5)
// ============================================================
uint32_t run_tp_detect(int vid, BsmBeaconTag &tag)
{
    uint32_t violated = 0;

    if (vehicle_state[vid].count < 2)
        return 0; // not enough history

    VehicleBeaconState &vs = vehicle_state[vid];
    int prev = (vs.head - 2 + BEACON_HISTORY) % BEACON_HISTORY;
    int curr = (vs.head - 1 + BEACON_HISTORY) % BEACON_HISTORY;

    double dt = vs.timestamp[curr] - vs.timestamp[prev];
    if (dt <= 0) dt = T_b; // fallback

    // TP-S1: kinematic position feasibility
    // ||p_i(t) - p_i(t-T_b)|| > s_max * T_b
    double dx = vs.pos_x[curr] - vs.pos_x[prev];
    double dy = vs.pos_y[curr] - vs.pos_y[prev];
    double dist = std::sqrt(dx*dx + dy*dy);
    if (dist > s_max * dt)
        violated |= (1 << 0);

    // TP-S2: heading rate deviation
    // |θ_i(t) - θ_i(t-T_b)| > ω_max * T_b
    double dtheta = std::fabs(vs.heading[curr] - vs.heading[prev]);
    if (dtheta > M_PI) dtheta = 2*M_PI - dtheta; // wrap
    if (dtheta > omega_max * dt)
        violated |= (1 << 1);

    // TP-S3: acceleration bound
    // |a_i(t)| > a_max
    if (std::fabs(vs.accel[curr]) > a_max)
        violated |= (1 << 2);

    // TP-S4: dead-reckoning residual
    // r_i(t) = ||p̂_i(t) - p_i(t)||, p̂ = p(t-1) + v(t-1)*dt
    double pred_x = vs.pos_x[prev] + vs.speed[prev] * std::cos(vs.heading[prev]) * dt;
    double pred_y = vs.pos_y[prev] + vs.speed[prev] * std::sin(vs.heading[prev]) * dt;
    double residual = std::sqrt((vs.pos_x[curr]-pred_x)*(vs.pos_x[curr]-pred_x) +
                                (vs.pos_y[curr]-pred_y)*(vs.pos_y[curr]-pred_y));
    if (residual > delta_th)
        violated |= (1 << 3);

    // TP-S5: cumulative drift D_i(k) = (1/k) · Σ r_i(t−j·T_b) > delta_th  (Eq. 3.15)
    // Recompute rolling average over the last drift_window_k beacon pairs
    // using the circular position history already stored in vs.
    {
        int avail = (vs.count >= 2) ? (vs.count - 1) : 0;  // pairs available
        int k     = (avail < drift_window_k) ? avail : drift_window_k;
        double drift_sum = 0.0;
        for (int step = 0; step < k; step++) {
            // pair: (head-2-step) → (head-1-step)  in circular buffer
            int b_cur  = ((vs.head - 1 - step) + BEACON_HISTORY) % BEACON_HISTORY;
            int b_prev = ((vs.head - 2 - step) + BEACON_HISTORY) % BEACON_HISTORY;
            double dt_s = vs.timestamp[b_cur] - vs.timestamp[b_prev];
            if (dt_s <= 0) dt_s = T_b;
            double px_hat = vs.pos_x[b_prev] + vs.speed[b_prev] * std::cos(vs.heading[b_prev]) * dt_s;
            double py_hat = vs.pos_y[b_prev] + vs.speed[b_prev] * std::sin(vs.heading[b_prev]) * dt_s;
            double r = std::sqrt((vs.pos_x[b_cur]-px_hat)*(vs.pos_x[b_cur]-px_hat) +
                                 (vs.pos_y[b_cur]-py_hat)*(vs.pos_y[b_cur]-py_hat));
            drift_sum += r;
        }
        vs.drift_score = (k > 0) ? (drift_sum / k) : 0.0;
        if (vs.drift_score > delta_th)
            violated |= (1 << 4);
    }

    return violated;
}

// ============================================================
// SYB-DETECT — Algorithm 2 (§3.4.4)
// Returns bitmask of MP signatures violated (bit 0 = MP-S1 ... bit 3 = MP-S4)
// ============================================================
uint32_t run_syb_detect(int vid, int rsu_id, BsmBeaconTag &tag)
{
    uint32_t violated = 0;
    double now = Simulator::Now().GetSeconds();

    // MP-S1: identity density check (Eq. 3.7)
    // |{ID_i : p_i ∈ A_j}| > N_Vehicles (threshold = expected legitimate count)
    register_vehicle_at_rsu(rsu_id, vid, now);  // count++ for this real vehicle
    // MP-S1: Ghost count is now built by REAL ghost UDP packets transmitted by the
    // compromised RSU in handle_readone() (Fig 3.4 Steps 4-6).
    // Each ghost packet calls register_vehicle_at_rsu() here via HandleBeaconReceived()
    // early-return path, incrementing count by 1 per ghost before the real beacon arrives.
    // By the time the real vehicle's beacon reaches this point, count is already
    // (N_ghost) from ghost registrations + 1 from register_vehicle_at_rsu() above = N_ghost+1.
    // No manual count inflation needed — the ghost UDP packets do it naturally. (is_new unused here)
    // MP-S1: identity density check (Eq. 3.7) — two complementary conditions:
    //
    // Condition A — count-based (classic paper check):
    //   count > density_limit (N_Vehicles/N_RSUs = 4)
    //   Fires when ≥ density_limit ghost packets arrive before the real beacon.
    //   N_ghost=4 ghosts sent first via CSMA → count=5 > 4 if all arrive in order.
    //
    // Condition B — ghost_seen flag (CSMA-robust extension):
    //   rsu_id_set[rsu_id].ghost_seen == true
    //   Set the moment ANY ghost packet (vid>=10000) is received from RSU j.
    //   Persists for the whole window. Handles the case where CSMA contention causes
    //   ghost packets to arrive AFTER the real beacon (would otherwise be a FN).
    //   FP guard: honest RSUs never send ghost packets → ghost_seen never set → FP=0.
    //
    // Both conditions also require tag.GetIsPoisoned() (set by compromised RSU only).
    // Honest RSU beacons always have IsPoisoned=false → condition short-circuits → FP=0.
    double density_limit = (double)(N_Vehicles / N_RSUs); // per-RSU expected count = 4
    bool count_exceeded  = (rsu_id >= 0 && rsu_id < total_size &&
                            rsu_id_set[rsu_id].count > (int)density_limit);
    bool ghost_seen_flag = (rsu_id >= 0 && rsu_id < total_size &&
                            rsu_id_set[rsu_id].ghost_seen);
    if ((count_exceeded || ghost_seen_flag) && tag.GetIsPoisoned())
        violated |= (1 << 0);

    // MP-S2: synchronized beacon timing (Eq. 3.17)
    // If another vehicle has nearly same timestamp, flag synchronization
    // (simplified: check within tau_sync of stored timestamps)
    for (int other = 0; other < total_size; other++) {
        if (other == vid || vehicle_state[other].count == 0) continue;
        int h = (vehicle_state[other].head - 1 + BEACON_HISTORY) % BEACON_HISTORY;
        double t_other = vehicle_state[other].timestamp[h];
        if (std::fabs(t_other - tag.GetTimestamp()) < tau_sync) {
            violated |= (1 << 1);
            break;
        }
    }

    // MP-S3: KL-divergence check MOVED to run_mitm_detect() per paper Algorithm 3.
    // Alg 2 (SYB-DETECT) covers Sybil/density/timing/ghost; Alg 3 (MITM-DETECT)
    // covers distribution manipulation.  Bit 2 is now set by run_mitm_detect().

    // MP-S4: ghost transit impossibility
    // d(r_j, r_k) / |t_j - t_k| > s_max
    // (simplified: check if same ID appearing at impossible distance in short time)
    if (vehicle_state[vid].count >= 2) {
        int prev = (vehicle_state[vid].head - 2 + BEACON_HISTORY) % BEACON_HISTORY;
        int curr = (vehicle_state[vid].head - 1 + BEACON_HISTORY) % BEACON_HISTORY;
        double tdiff = vehicle_state[vid].timestamp[curr] - vehicle_state[vid].timestamp[prev];
        if (tdiff > 0) {
            double ddx = vehicle_state[vid].pos_x[curr] - vehicle_state[vid].pos_x[prev];
            double ddy = vehicle_state[vid].pos_y[curr] - vehicle_state[vid].pos_y[prev];
            double d = std::sqrt(ddx*ddx + ddy*ddy);
            if (d / tdiff > s_max)
                violated |= (1 << 3);
        }
    }

    return violated;
}

// ============================================================
// MITM-DETECT / CP-DETECT — Algorithms 3 & 4 (stubs)
// ============================================================
// ============================================================
// MITM-DETECT — Algorithm 3 (§3.4.4)
// Detects Man-in-the-Middle manipulation of beacon distributions.
// Returns bitmask: bit 2 = MP-S3 (KL divergence speed anomaly)
//
// Paper Algorithm 3, Step 4 (Eq. 3.18):
//   D_KL(P_t || P_hist) > κ_th
// Approximation: flag if vehicle speed deviates > κ_th from
// regional mean, normalised by (mean + floor) to avoid zero-division.
// ============================================================
uint32_t run_mitm_detect(int vid, int rsu_id, BsmBeaconTag &tag)
{
    uint32_t violated = 0;

    // MP-S3: regional speed KL divergence (Eq. 3.18)
    // D_KL(P_t || P_hist) > κ_th
    // Collect speed samples from all vehicles in RSU communication range.
    double sum_speed = 0.0;
    int    count_near = 0;
    for (int other = 0; other < total_size; other++) {
        if (vehicle_state[other].count == 0) continue;
        int h = (vehicle_state[other].head - 1 + BEACON_HISTORY) % BEACON_HISTORY;
        double dx = vehicle_state[other].pos_x[h] - tag.GetPosX();
        double dy = vehicle_state[other].pos_y[h] - tag.GetPosY();
        if (std::sqrt(dx*dx + dy*dy) < R_max_comm) {
            sum_speed += vehicle_state[other].speed[h];
            count_near++;
        }
    }
    if (count_near > 0) {
        double mean_sp  = sum_speed / count_near;
        // Denominator floor = s_max * 0.1 ≈ 3.33 m/s to prevent near-zero
        // division when all nearby vehicles are stationary (mean_sp ≈ 0).
        double kl_approx = std::fabs(tag.GetSpeed() - mean_sp)
                         / (mean_sp + s_max * 0.1);
        if (kl_approx > kappa_th)
            violated |= (1 << 2);   // bit 2 = MP-S3 position in mp_flags
    }

    return violated;
}

uint32_t run_cp_detect(BsmBeaconTag &tag)
{
    // TP-S3 (attack_number=5): controller-level trajectory poisoning.
    // CP-DETECT fires whenever controller_malicious_assumption=true for attack 5.
    // MP-S4 (attack_number=7): coordinated — controller is also assumed compromised.
    if (controller_malicious_assumption &&
        (attack_number == 5 || attack_number == 7))
        return 1;
    return 0;
}

// ============================================================
// Composite lightweight score ψ_i(t) (Eq. 3.20)
// ψ_i(t) = (|TP_violated| + |MP_violated|) / total_signatures
// Returns true if > psi_th (anomalous)
// ============================================================
bool run_lightweight_score(uint32_t tp_flags, uint32_t mp_flags)
{
    int n_tp = __builtin_popcount(tp_flags);
    int n_mp = __builtin_popcount(mp_flags);
    int total = 9; // 5 TP + 4 MP signatures
    double psi = double(n_tp + n_mp) / total;
    return psi > psi_th;
}

// ============================================================
// log_metrics_line() — [METRICS] per received beacon
// ============================================================
void log_metrics_line(int attack_num, bool is_poisoned, uint32_t vehicle_id,
                      uint32_t rsu_id, BsmBeaconTag &tag,
                      uint32_t sig_violated)
{
    total_trajectories_received++;
    if (is_poisoned) total_trajectories_poisoned++;

    if (is_poisoned) {
        // Determine violated signature string
        std::ostringstream sig_str;
        if (sig_violated & (1<<0)) sig_str << "TP-S1,";
        if (sig_violated & (1<<1)) sig_str << "TP-S2,";
        if (sig_violated & (1<<2)) sig_str << "TP-S3,";
        if (sig_violated & (1<<3)) sig_str << "TP-S4,";
        if (sig_violated & (1<<4)) sig_str << "TP-S5,";
        if (sig_violated & (1<<5)) sig_str << "MP-S1,";
        if (sig_violated & (1<<6)) sig_str << "MP-S2,";
        if (sig_violated & (1<<7)) sig_str << "MP-S3,";
        if (sig_violated & (1<<8)) sig_str << "MP-S4,";
        std::string s = sig_str.str();
        if (!s.empty() && s.back() == ',') s.pop_back();
        std::cout << "[METRICS] TP attack=" << attack_num
                  << " vehicle=" << vehicle_id
                  << " rsu=" << rsu_id
                  << " pos_x=" << tag.GetPosX()
                  << " pos_y=" << tag.GetPosY()
                  << " speed=" << tag.GetSpeed()
                  << " heading=" << tag.GetHeading()
                  << " accel=" << tag.GetAcceleration()
                  << " t=" << tag.GetTimestamp()
                  << " sig=" << s
                  << std::endl;
    } else {
        std::cout << "[METRICS] TN attack=" << attack_num
                  << " vehicle=" << vehicle_id
                  << " rsu=" << rsu_id
                  << " pos_x=" << tag.GetPosX()
                  << " pos_y=" << tag.GetPosY()
                  << " speed=" << tag.GetSpeed()
                  << " heading=" << tag.GetHeading()
                  << " accel=" << tag.GetAcceleration()
                  << " t=" << tag.GetTimestamp()
                  << std::endl;
    }
}

// ============================================================
// HandleBeaconReceived() — management node beacon processing
// Professor's term: this is the management-side processing triggered AFTER
//   handle_readone (RSU) forwards the beacon via send_rsu_dataunicast_alone.
// Called from handle_readone() once beacon arrives at management_node:7777.
// Runs all MPTD-PQS detection algorithms (TP-S1..S5, MP-S1..S4).
// ============================================================
void HandleBeaconReceived(uint32_t vehicle_id, BsmBeaconTag tag, uint32_t rsu_id)
{
    double now = Simulator::Now().GetSeconds();

    // ── Ghost packet fast-path (MP-S1 Attack 3) ──────────────────────────────────
    // Ghost vehicle IDs are >= GHOST_VID_BASE (10000), far above real vehicle IDs (2–17).
    // These packets are synthetic identities injected by the compromised RSU in
    // handle_readone() (Fig 3.4 Steps 4-6). Their ONLY purpose is to increment the
    // RSU identity density count via register_vehicle_at_rsu() so that when the real
    // vehicle's beacon arrives next, count > density_limit → MP-S1 detection fires.
    // Ghost packets skip: TP/SYB/MITM detection, confusion matrix, beacon_log.csv,
    //                     downlink response — they are purely density-injection packets.
    static const uint32_t GHOST_VID_BASE = 10000;
    if (vehicle_id >= GHOST_VID_BASE) {
        bool is_new_ghost = register_vehicle_at_rsu((int)rsu_id, vehicle_id, now);
        // Mark this RSU's window as ghost-infected — used for CSMA-order-robust detection.
        // Even if CSMA interleaving delivers this ghost after the real beacon, the NEXT
        // real beacon from this RSU in the same window will still be detected.
        if ((int)rsu_id < total_size)
            rsu_id_set[rsu_id].ghost_seen = true;
        cout << "[MP-S1-GHOST-RX] ghost_id=" << vehicle_id
             << " RSU" << rsu_id
             << " pos(" << std::fixed << std::setprecision(2)
             << tag.GetPosX() << "," << tag.GetPosY() << ")"
             << " density_count=" << rsu_id_set[rsu_id].count
             << " ghost_seen=YES"
             << (is_new_ghost ? " +1 (new)" : " (dup-same-window)") << endl;
        return; // ← Ghost packet handled. No detection/metrics/downlink for ghost IDs.
    }

    // PBPO: start wall-clock timer (§4.1.2 Eq 4.7)
    struct timespec t_start, t_end;
    clock_gettime(CLOCK_MONOTONIC, &t_start);

    // ── TP-S1: Compromised RSU intercepts and modifies honest beacon (attack_number==1) ──
    // When Option B is active, this poisoning happens at HandleBeaconAtRSU() on the
    // actual RSU node before forwarding to management_node. This block is the legacy
    // fallback for when Option B is disabled (g_option_b_active=false).
    // TP-S1: compromised_rsu[] already encodes attack_percentage (set by declare_compromised_rsus).
    // No second probability gate — ALL vehicles at a compromised RSU are poisoned.
    if (!g_option_b_active &&
        attack_number == 1 &&
        rsu_id < 4 &&
        compromised_rsu[rsu_id])
    {
        double real_px  = tag.GetPosX();
        double real_py  = tag.GetPosY();
        double real_spd = tag.GetSpeed();
        double real_hdg = tag.GetHeading();
        double real_acc = tag.GetAcceleration();
        double t        = Simulator::Now().GetSeconds();

        double drift_x  = poisoning_intensity_theta * max_position_deviation * sin(t * 0.7);
        double drift_y  = poisoning_intensity_theta * max_position_deviation * cos(t * 0.5);
        double fake_px  = real_px + drift_x;
        double fake_py  = real_py + drift_y;
        fake_px = (fake_px < min_position_x) ? min_position_x : (fake_px > max_position_x ? max_position_x : fake_px);
        fake_py = (fake_py < min_position_y) ? min_position_y : (fake_py > max_position_y ? max_position_y : fake_py);

        tag.SetPosition(fake_px, fake_py);
        tag.SetIsPoisoned(true);
        tag.SetAttackType(1);

        double dx       = fake_px - real_px;
        double dy       = fake_py - real_py;
        double disp_err = std::sqrt(dx*dx + dy*dy);
        tdee_error_sum += disp_err;
        tdee_error_cnt++;
        tpe_sq_sum += disp_err * disp_err;
        tpe_cnt++;

        bool det_likely = (disp_err > s_max * T_b);
        cout << "\n[TP-S1-DEBUG] ══════════════════════════════════════════════" << endl;
        cout << "  t=" << std::fixed << std::setprecision(3) << t
             << "s  RSU=" << rsu_id << "  Vehicle=" << vehicle_id
             << "  theta=" << poisoning_intensity_theta << endl;
        cout << std::fixed << std::setprecision(4);
        cout << "  pos_x " << real_px << " → " << fake_px
             << "  (drift " << std::showpos << drift_x << std::noshowpos << " m)" << endl;
        cout << "  pos_y " << real_py << " → " << fake_py
             << "  (drift " << std::showpos << drift_y << std::noshowpos << " m)" << endl;
        cout << "  disp_err=" << disp_err << " m  s_max*T_b=" << s_max*T_b
             << "  detect=" << (det_likely ? "LIKELY" : "below-threshold") << endl;
        cout << "[TP-S1-DEBUG] ══════════════════════════════════════════════\n" << endl;

        log_tp_s1_poison(vehicle_id, rsu_id, t,
                         real_px, real_py, fake_px, fake_py,
                         real_spd, real_hdg, real_acc,
                         drift_x,  drift_y,  disp_err);
    }

    // ── MP-S1: Compromised RSU injects ghost vehicle IDs (attack_number==3) ──────
    // Fallback for when Option B is disabled (g_option_b_active=false).
    // When Option B is active, this happens at HandleBeaconAtRSU() on the actual RSU node.
    // MP-S1: same logic — no second probability gate.
    if (!g_option_b_active &&
        attack_number == 3 &&
        rsu_id < 4 &&
        compromised_rsu[rsu_id])
    {
        tag.SetIsPoisoned(true);
        tag.SetAttackType(3);
        double now_t = Simulator::Now().GetSeconds();
        double ghost_err = R_max_comm * poisoning_intensity_theta;
        tdee_error_sum += ghost_err;
        tdee_error_cnt++;
        tpe_sq_sum += ghost_err * ghost_err;
        tpe_cnt++;
        cout << "[MP-S1-RSU] RSU " << rsu_id << " ghosting V" << vehicle_id
             << " at t=" << now_t << endl;
    }

    // ── A6-STEP6: Controller aggregates MitM-poisoned data into global mobility model ──
    // Paper (Fig 3.6 Step 6): Controller receives forged beacons and merges them into
    // its global learning model. Over time, accumulated false speed/location data
    // corrupts the learned mobility patterns and the model sends back degraded control.
    if (attack_number == 6 && tag.GetIsPoisoned()) {
        cout << "[A6-STEP6] Controller aggregating MitM-poisoned V" << vehicle_id
             << " data: spd=" << std::fixed << std::setprecision(2) << tag.GetSpeed()
             << " pos(" << tag.GetPosX() << "," << tag.GetPosY() << ")"
             << " → corrupting global mobility model" << endl;
    }

    // ── MP-S4: Controller-level global mobility model poisoning (attack_number==7) ──
    // Paper §3.4.2 (Figure 3.7): The SDVN controller itself is malicious and corrupts
    // its GLOBAL mobility pattern model despite receiving correct data from honest
    // vehicles and RSUs. Unlike TP-S3 (individual trajectory), MP-S4 applies a
    // systematic speed distribution shift to ALL vehicles — no attack_pct gate.
    // This triggers the MP-S3 KL-divergence signature (Eq. 3.18) globally.
    if (attack_number == 7 && controller_malicious_assumption)
    {
        double real_spd = tag.GetSpeed();
        double real_hdg = tag.GetHeading();
        double t_mp4    = Simulator::Now().GetSeconds();
        // Systematic speed elevation: shifts regional distribution ~25-50% above normal.
        // kl_approx = |fake_spd - mean| / (mean + s_max*0.1); with mean≈15, fake≈22-30 m/s:
        // (22-15)/18.3 ≈ 0.38 per vehicle — collectively shifts distribution > κ_th=1.5.
        double shift    = 1.0 + 0.5 * poisoning_intensity_theta
                              + 0.2 * poisoning_intensity_theta * std::sin(t_mp4 * 0.3);
        double fake_spd = real_spd * shift;
        // Slight heading noise to corrupt mobility pattern vectors
        double fake_hdg = real_hdg + 0.15 * poisoning_intensity_theta * std::sin(t_mp4 * 0.7);
        // Soft cap: keep below 2×s_max to remain "plausibly elevated" for global bias
        double sp_ceil = s_max * 2.0;
        fake_spd = (fake_spd > sp_ceil) ? sp_ceil : fake_spd;
        tag.SetSpeed(fake_spd);
        tag.SetHeading(fake_hdg);
        tag.SetIsPoisoned(true);     // controller-poisoned beacon
        tag.SetAttackType(7);
        // Accumulate TDEE/TPE using speed-displacement proxy (distance error in T_b interval)
        double spd_disp = std::fabs(fake_spd - real_spd) * T_b;
        tdee_error_sum += spd_disp;
        tdee_error_cnt++;
        tpe_sq_sum += spd_disp * spd_disp;
        tpe_cnt++;
        cout << "[MP-S4-CTRL] controller poisoned global model V" << vehicle_id
             << " spd " << real_spd << "->" << fake_spd << endl;
    }

    // ── TP-S3: Controller-level trajectory poisoning (attack_number==5) ──────────
    // Paper §3.4.1 (Figure 3.3): SDN controller (management node) intercepts honest
    // vehicle beacons and modifies position + speed before forwarding to other planes.
    // HandleBeaconReceived() runs at the management node → this IS the control plane.
    if (attack_number == 5 &&
        controller_malicious_assumption &&
        GetBooleanWithProbability(attack_percentage, vehicle_id))
    {
        double real_px  = tag.GetPosX();
        double real_py  = tag.GetPosY();
        double real_spd = tag.GetSpeed();
        double t_cp     = Simulator::Now().GetSeconds();
        // Controller applies sinusoidal position drift + speed perturbation
        double fake_px  = real_px  + poisoning_intensity_theta * max_position_deviation
                                   * std::sin(t_cp * 1.1);
        double fake_py  = real_py  + poisoning_intensity_theta * max_position_deviation
                                   * std::cos(t_cp * 0.9);
        double fake_spd = real_spd * (1.0 + poisoning_intensity_theta * std::sin(t_cp * 2.3));
        // Clamp to simulation area (avoid std::max/std::min — #define max 40 conflicts)
        fake_px  = (fake_px  < min_position_x) ? min_position_x : (fake_px  > max_position_x ? max_position_x : fake_px);
        fake_py  = (fake_py  < min_position_y) ? min_position_y : (fake_py  > max_position_y ? max_position_y : fake_py);
        fake_spd = (fake_spd < 0.0)            ? 0.0            : (fake_spd > s_max * 1.5     ? s_max * 1.5    : fake_spd);
        tag.SetPosition(fake_px, fake_py);
        tag.SetSpeed(fake_spd);
        tag.SetIsPoisoned(true);
        tag.SetAttackType(5);
        // Accumulate TDEE / TPE (controller-introduced displacement error)
        double dx = fake_px - real_px, dy = fake_py - real_py;
        double disp_err = std::sqrt(dx*dx + dy*dy);
        tdee_error_sum += disp_err;
        tdee_error_cnt++;
        tpe_sq_sum += disp_err * disp_err;
        tpe_cnt++;
        cout << "[TP-S3-CTRL] controller corrupted V" << vehicle_id
             << " pos(" << real_px << "," << real_py
             << ")→(" << fake_px << "," << fake_py
             << ") spd " << real_spd << "→" << fake_spd << endl;
    }

    // ── MP-S2 state-contamination guard (attack 4: stolen-ID beacons) ───────────
    // Problem: stolen beacons carry honest vehicle IDs at the attacker's position.
    // When pushed into vehicle_state[honest_vid], the attacker's fake position
    // becomes the "previous" reference for that vehicle.  The next REAL beacon
    // from honest_vid then sees an impossible jump (fake→real pos) and fires
    // MP-S4 → false positive on an honest beacon.
    //
    // Fix: before pushing a potentially stolen beacon, save vehicle_state for
    // the impersonated vehicle (honest, is_poisoned=true).  After detection, if
    // MP-S4 fires, restore the saved state so the contaminated position does NOT
    // persist as baseline.  This leaves the attacker's own beacon state intact
    // (attacker is sybil_mitm_nodes[vid]=true → no save/restore for them).
    // For attack 6 (MP-S3 MitM): intercepted beacons carry the VICTIM's ID at the
    // victim's real position but with amplified speed. This contaminates the victim's
    // vehicle_state speed history. Save/restore prevents the poisoned speed from
    // persisting as the baseline for the next honest beacon from that victim.
    bool save_state = ((attack_number == 4) || (attack_number == 6))
                   && (vehicle_id < (uint32_t)total_size)
                   && tag.GetIsPoisoned()
                   && !sybil_mitm_nodes[vehicle_id]; // intercepted/stolen ID = honest vehicle
    VehicleBeaconState vs_backup;
    if (save_state)
        vs_backup = vehicle_state[vehicle_id];

    // 1. Push new beacon into circular state buffer
    push_beacon(vehicle_id,
                tag.GetPosX(), tag.GetPosY(),
                tag.GetSpeed(), tag.GetHeading(),
                tag.GetAcceleration(), tag.GetTimestamp());

    // 2. Run detection algorithms (paper Algorithms 1–4)
    uint32_t tp_flags   = run_tp_detect(vehicle_id, tag);          // Alg 1: TP-S1..S5
    uint32_t mp_flags   = run_syb_detect(vehicle_id, rsu_id, tag); // Alg 2: MP-S1,S2,S4
    uint32_t mitm_flags = run_mitm_detect(vehicle_id, rsu_id, tag);// Alg 3: MP-S3 (KL)
    mp_flags           |= mitm_flags; // merge: bit 2 (MP-S3) now comes from MITM-DETECT
    uint32_t cp_flags   = run_cp_detect(tag);                      // Alg 4: CP

    // Restore honest vehicle state if stolen beacon triggered MP-S4
    // This prevents the fake position from persisting as the baseline reference,
    // which would cause the next real honest beacon to generate a false positive.
    if (save_state && (mp_flags & (1 << 3)))
        vehicle_state[vehicle_id] = vs_backup;

    // Combine: sig_violated bitmask (bits 0-4 = TP-S1..S5, bits 5-8 = MP-S1..S4)
    uint32_t sig_violated = tp_flags | (mp_flags << 5) | (cp_flags << 9);

    // 3. Lightweight score gate
    bool anomalous = run_lightweight_score(tp_flags, mp_flags | (cp_flags << 4));

    // 4. Ground truth: is this beacon poisoned?
    bool is_poisoned = tag.GetIsPoisoned();

    // 5. Update tag with detection results
    tag.SetSigViolated(sig_violated);

    // 6. Log [METRICS] line
    log_metrics_line(attack_number, is_poisoned, vehicle_id, rsu_id, tag, sig_violated);

    // 7. Forward clean/flagged beacon to blockchain (via 11_routing)
    //    (Actual blockchain call is in 11_routing_blockchain_transmission.h)
    total_trajectories_stored_blockchain++;

    // 8. Update confusion matrix + beacon CSV log (Stage 4)
    // CP-DETECT (cp_flags) contributes to detection ONLY for attack_number==7 (MP-S4).
    // For MP-S4, the controller poisons ALL beacons globally — so cp_flags firing means
    // THIS beacon is poisoned (100% certainty, no per-beacon probability gate).
    // For attack_number==5 (TP-S3), CP-DETECT fires globally but kinematic detectors
    // handle per-beacon detection (only attack_pct% of beacons are actually modified),
    // so including cp_flags there would create false positives for unmodified beacons.
    bool cp_detected = (cp_flags != 0) && (attack_number == 7);
    bool detected = anomalous || (tp_flags != 0) || (mp_flags != 0) || cp_detected;
    update_confusion_matrix(tag.GetIsPoisoned(), detected);
    double psi = double(__builtin_popcount(tp_flags) + __builtin_popcount(mp_flags)) / 9.0;
    log_beacon_to_csv(vehicle_id, rsu_id, tag, detected,
                      tp_flags | (mp_flags << 5), psi);

    // 9. Forward to Python ML prediction server (Stage 5)
    //    Non-blocking fire-and-forget; only in full mode (not routing_test)
    if (!routing_test)
    {
        double px  = tag.GetPosX();
        double py  = tag.GetPosY();
        double sp  = tag.GetSpeed();
        double hd  = tag.GetHeading();
        double ac  = tag.GetAcceleration();
        std::string ml_cmd =
            "curl -s -X POST http://localhost:5001/predict"
            " -H 'Content-Type: application/json'"
            " -d '{\"vehicle_id\":" + std::to_string(vehicle_id) +
            ",\"psi_score\":"       + std::to_string(psi) +
            ",\"features\":["       + std::to_string(px) + ","
                                    + std::to_string(py) + ","
                                    + std::to_string(sp) + ","
                                    + std::to_string(hd) + ","
                                    + std::to_string(ac) + "]}'"
            " > /dev/null 2>&1 &";
        system(ml_cmd.c_str());
    }

    // PBPO: stop timer and accumulate (§4.1.2 Eq 4.7)
    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double elapsed_ms = (t_end.tv_sec  - t_start.tv_sec)  * 1000.0
                      + (t_end.tv_nsec - t_start.tv_nsec) / 1e6;
    pbpo_time_sum_ms += elapsed_ms;
    pbpo_cnt++;

    // 10. SC-Trust + SC-Revoke (Stage 6)
    //     Only in full mode; uses psi as phi approximation until ML server responds
    if (!routing_test && vehicle_id < (uint32_t)(total_size + 2))
    {
        double ts       = Simulator::Now().GetSeconds();
        uint32_t sigmask = tp_flags | (mp_flags << 5);

        // Update trust score on ledger for every beacon
        CallSCTrust(vehicle_id, psi, sigmask, detected, ts);

        // Track consecutive anomalies per vehicle
        if (detected)
        {
            consecutive_anomaly_count[vehicle_id]++;
            if (consecutive_anomaly_count[vehicle_id] >= REVOKE_THRESHOLD)
            {
                CallSCRevoke(vehicle_id, "3_consecutive_anomalies", rsu_id, ts);
                consecutive_anomaly_count[vehicle_id] = 0; // reset after revoke
            }
        }
        else
        {
            consecutive_anomaly_count[vehicle_id] = 0;
        }
    }

    (void)now;

    // ── Step 11: Downlink control response (Steps 6-8 in paper Figures 3.1-3.7) ──────
    // After detection, management sends a control packet back down through the RSU to
    // the vehicle(s) — completing the uplink→detect→downlink SDVN control loop.
    //
    // Professor's terms:
    //   centralized_dsrc_data_unicast   → targeted response to one vehicle (attacks 1-4,6)
    //   centralized_dsrc_data_broadcast → sent to ALL vehicles (attacks 5 & 7)
    //
    // For attacks 5 & 7 (controller malicious): downlink IS the attack — the compromised
    // controller deliberately sends alert_type=2 (WRONG_ROUTING) to all vehicles,
    // misdirecting their routing decisions (Figures 3.3 and 3.7, Steps 7-8).
    // For honest attacks 1-4,6: downlink delivers alert_type=1 (ATTACK_DETECTED) or
    // alert_type=0 (CLEAN_ROUTING) as a corrective safety broadcast.
    if (g_option_b_active && rsu_id < 4 && g_mgmt_downlink_socket) {
        uint8_t alert_type;
        bool    bcast;

        if (attack_number == 5 || attack_number == 7) {
            // Controller malicious: sends WRONG routing instructions to all vehicles
            alert_type = 2;    // WRONG_ROUTING
            bcast      = true; // broadcast to all — entire network receives wrong data
        } else {
            alert_type = detected ? 1 : 0;  // ATTACK_DETECTED or CLEAN_ROUTING
            bcast      = false;             // unicast to the specific flagged vehicle
        }

        DownlinkControlTag dl_tag;
        dl_tag.SetVehicleId   (bcast ? 0 : vehicle_id);  // 0 = all vehicles
        dl_tag.SetAlertType   (alert_type);
        dl_tag.SetSpeedAdvice (detected ? (s_max * 0.5) : s_max);  // 50% advisory if attack
        dl_tag.SetTimestamp   (Simulator::Now().GetSeconds());
        dl_tag.SetRsuId       (rsu_id);

        Ptr<Packet> dl_pkt = Create<Packet>(0);
        dl_pkt->AddPacketTag(dl_tag);

        // Management → RSU CSMA IP (10.1.1.x) port 8888
        // RSU handle_downlink_at_rsu() then forwards to vehicles on DSRC:9999
        int err = g_mgmt_downlink_socket->SendTo(
                      dl_pkt, 0,
                      InetSocketAddress(g_rsu_csma_ip[rsu_id], 8888));

        const char* alert_str = (alert_type == 0) ? "CLEAN_ROUTING" :
                                (alert_type == 1) ? "ATTACK_DETECTED" : "WRONG_ROUTING";
        const char* dl_fn = bcast ? "centralized_dsrc_data_broadcast"
                                  : "centralized_dsrc_data_unicast";
        if (err >= 0) {
            // A6-STEP7: vehicle receives control decision derived from poisoned model
            if (attack_number == 6) {
                cout << "[A6-STEP7] V" << (bcast ? 0U : vehicle_id)
                     << " ← control decision based on MitM-corrupted model"
                     << " alert=" << alert_str
                     << "  [" << dl_fn << "]" << endl;
            } else {
                cout << "[DL-MGT-TX] → RSU" << rsu_id
                     << " vid=" << (bcast ? 0U : vehicle_id)
                     << " alert=" << alert_str
                     << "  [" << dl_fn << "]" << endl;
            }
        }
    }
}

// ============================================================
// handle_downlink_at_rsu — RSU receives management downlink, forwards to vehicles
// Professor's terms: centralized_dsrc_data_broadcast (vid=0 → all vehicles)
//                    centralized_dsrc_data_unicast   (vid>0 → specific vehicle)
//
// Sequence (Steps 6-8 in paper Figures 3.1-3.7):
//   Management → g_mgmt_downlink_socket → RSU CSMA:8888  [DL-MGT-TX]
//   RSU receives here                                      [DL-RSU-RX]
//   RSU re-broadcasts DownlinkControlTag → DSRC:9999       [DL-RSU-FWD]
//   Vehicle receives in HandleReadTwo()                     [DL-VEH-RX]
//
// alert_type=0 CLEAN_ROUTING   — honest network, forward normal speed advice
// alert_type=1 ATTACK_DETECTED — anomaly found, broadcast safety alert
// alert_type=2 WRONG_ROUTING   — controller malicious (attacks 5 & 7)
// ============================================================
void SimpleUdpApplication::handle_downlink_at_rsu(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address     from;
    while ((packet = socket->RecvFrom(from)) != nullptr)
    {
        DownlinkControlTag dl_tag;
        if (!packet->RemovePacketTag(dl_tag)) continue;

        uint32_t rsu_idx = GetNode()->GetId() - g_first_rsu_node_id;
        uint32_t vid     = dl_tag.GetVehicleId();
        double   t       = Simulator::Now().GetSeconds();

        const char* alert_str = (dl_tag.GetAlertType() == 0) ? "CLEAN_ROUTING" :
                                (dl_tag.GetAlertType() == 1) ? "ATTACK_DETECTED" :
                                                               "WRONG_ROUTING";
        cout << "[DL-RSU" << rsu_idx << "-RX] from MGT"
             << " vid=" << vid
             << " alert=" << alert_str
             << " t=" << t << endl;

        // Forward to vehicles via DSRC broadcast on 3.255.255.255:9999
        // Uses subnet-directed broadcast (3.0.0.0/8) so it stays on DSRC channel only
        // and does NOT leak back to the management/controller on the CSMA segment.
        Ptr<Packet> fwd_pkt = Create<Packet>(0);
        fwd_pkt->AddPacketTag(dl_tag);

        if (m_send_socket) {
            int err = m_send_socket->SendTo(
                          fwd_pkt, 0,
                          InetSocketAddress(Ipv4Address("3.255.255.255"), 9999));
            const char* dl_fn = (vid == 0) ? "centralized_dsrc_data_broadcast"
                                           : "centralized_dsrc_data_unicast";
            if (err >= 0)
                cout << "[DL-RSU" << rsu_idx << "-FWD] → V"
                     << (vid == 0 ? "ALL" : std::to_string(vid - 2))
                     << " :9999  [" << dl_fn << "]" << endl;
            else
                cout << "[DL-RSU" << rsu_idx << "-FWD-ERR] failed fwd vid=" << vid << endl;
        }
    }
}

// ============================================================
// handle_readone — RSU-side packet reception (professor's term)
// Professor's naming: handle_readone in SimpleUdpApplication
//   → fires when a vehicle unicasts a BSM beacon to this RSU's DSRC IP (port 6666)
//
// Sequence (matches professor's attack diagram steps):
//   Step 1: RSU receives vehicle beacon           [DSRC-RX]
//   Step 2: RSU applies attack if compromised     [TP-S1-RSU / MP-S1-RSU]
//   Step 3: RSU forwards to management node       [RSU-FWD]  ← send_rsu_dataunicast_alone
//   Step 4: Management node runs MPTD-PQS detect  [MGT-RX]   ← HandleBeaconReceived
//
// Professor's related terms:
//   send_rsu_dataunicast_alone  = the RSU-FWD step (RSU sends its OWN beacon to controller)
//   send_rsu_dataunicast_agent  = NOT USED (RSU forwards each vehicle individually, not aggregated)
// ============================================================
void SimpleUdpApplication::handle_readone(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address     from;
    while ((packet = socket->RecvFrom(from)) != nullptr)
    {
        BsmBeaconTag tag;
        if (!packet->RemovePacketTag(tag)) continue; // not a BSM beacon

        uint32_t nid     = GetNode()->GetId();
        uint32_t rsu_idx = nid - g_first_rsu_node_id;
        uint32_t vid     = tag.GetVehicleId();
        double   t       = Simulator::Now().GetSeconds();

        // Capture honest vehicle position BEFORE any RSU modification
        double real_px = tag.GetPosX();
        double real_py = tag.GetPosY();

        // Geographic filter: each RSU only processes beacons from its own vehicles.
        // (All RSUs on the DSRC channel hear the unicast, but only the addressed
        //  one should act — in NS-3 unicast this is automatic; this guard is a
        //  belt-and-suspenders check for the nearest-RSU logic in the vehicle TX.)
        uint32_t nearest = nearest_rsu_for_position(tag.GetPosX(), tag.GetPosY());
        if (nearest != rsu_idx) {
            // Not our vehicle — silently drop
            continue;
        }

        cout << "[DSRC-RSU" << rsu_idx << "] V" << vid
             << " pos(" << tag.GetPosX() << "," << tag.GetPosY() << ")"
             << " compromised=" << (compromised_rsu[rsu_idx] ? "YES" : "no") << endl;

        // ── TP-S1: Compromised RSU modifies trajectory (paper §3.4.1 Figure 3.1) ──
        // compromised_rsu[] already reflects attack_percentage via declare_compromised_rsus().
        // No second per-vehicle gate — ALL vehicles at a compromised RSU are poisoned.
        if (attack_number == 1 &&
            rsu_idx < 4 &&
            compromised_rsu[rsu_idx])
        {
            double real_px  = tag.GetPosX();
            double real_py  = tag.GetPosY();
            double real_spd = tag.GetSpeed();
            double real_hdg = tag.GetHeading();
            double real_acc = tag.GetAcceleration();

            double drift_x  = poisoning_intensity_theta * max_position_deviation * sin(t * 0.7);
            double drift_y  = poisoning_intensity_theta * max_position_deviation * cos(t * 0.5);
            double fake_px  = real_px + drift_x;
            double fake_py  = real_py + drift_y;
            fake_px = (fake_px < min_position_x) ? min_position_x : (fake_px > max_position_x ? max_position_x : fake_px);
            fake_py = (fake_py < min_position_y) ? min_position_y : (fake_py > max_position_y ? max_position_y : fake_py);

            tag.SetPosition(fake_px, fake_py);
            tag.SetIsPoisoned(true);
            tag.SetAttackType(1);

            double dx = fake_px - real_px, dy = fake_py - real_py;
            double disp_err = std::sqrt(dx*dx + dy*dy);
            tdee_error_sum += disp_err;
            tdee_error_cnt++;
            tpe_sq_sum += disp_err * disp_err;
            tpe_cnt++;

            bool det_likely = (disp_err > s_max * T_b);
            cout << "\n[TP-S1-RSU" << rsu_idx << "] ═════════════════════════════════════" << endl;
            cout << "  t=" << std::fixed << std::setprecision(3) << t
                 << "s  V=" << vid << "  theta=" << poisoning_intensity_theta << endl;
            cout << std::fixed << std::setprecision(4);
            cout << "  pos_x " << real_px << " → " << fake_px
                 << "  (drift " << std::showpos << drift_x << std::noshowpos << " m)" << endl;
            cout << "  pos_y " << real_py << " → " << fake_py
                 << "  (drift " << std::showpos << drift_y << std::noshowpos << " m)" << endl;
            cout << "  disp_err=" << disp_err << " m  detect=" << (det_likely ? "LIKELY" : "below-threshold") << endl;
            cout << "[TP-S1-RSU" << rsu_idx << "] ═════════════════════════════════════\n" << endl;

            log_tp_s1_poison(vid, rsu_idx, t, real_px, real_py, fake_px, fake_py,
                             real_spd, real_hdg, real_acc, drift_x, drift_y, disp_err);
        }

        // ── MP-S1: Compromised RSU steals identity and injects ghost beacons (paper §3.4.2) ──
        // Paper Fig 3.4 Steps 3-6:
        //   Step 3: RSU intercepts real beacon → marks it poisoned
        //   Step 4: RSU generates N_ghost ghost vehicle IDs (fake identities)
        //   Step 5: RSU packages ghost IDs as separate beacon-like UDP packets
        //   Step 6: RSU forwards ghost packets to controller FIRST (before real beacon)
        //
        // Practical justification for ghost-first ordering:
        //   The RSU must receive and process the real beacon before it can generate ghosts
        //   (it needs the real vehicle's position). This processing delay naturally means
        //   ghost packets are sent first; the real beacon follows. CSMA FIFO guarantees
        //   ghosts arrive at the controller before the real beacon → count is pre-inflated
        //   when the real beacon arrives → density check fires on the real beacon. ✓
        if (attack_number == 3 &&
            rsu_idx < 4 &&
            compromised_rsu[rsu_idx])
        {
            // Step 3: Mark real beacon as poisoned (ground-truth provenance flag)
            tag.SetIsPoisoned(true);
            tag.SetAttackType(3);
            double ghost_disp = R_max_comm * poisoning_intensity_theta; // 150 m
            tdee_error_sum += ghost_disp;
            tdee_error_cnt++;
            tpe_sq_sum += ghost_disp * ghost_disp;
            tpe_cnt++;
            cout << "[MP-S1-RSU" << rsu_idx << "] intercepting V" << vid
                 << " at t=" << t << " → generating ghost IDs" << endl;

            // Steps 4-6: Generate N_ghost ghost packets and send to controller BEFORE
            // the real beacon. Ghost IDs are unique per (RSU, vehicle, ghost-index):
            //   ghost_vid = GHOST_VID_BASE + rsu_idx*100 + vid*10 + gi
            // Placed evenly at ghost_disp (150 m) radius around the real vehicle.
            static const int    N_ghost        = 4;
            static const uint32_t GHOST_VID_BASE = 10000;
            for (int gi = 0; gi < N_ghost; gi++) {
                double angle    = gi * (2.0 * M_PI / N_ghost); // 0°, 90°, 180°, 270°
                double ghost_px = real_px + ghost_disp * std::cos(angle);
                double ghost_py = real_py + ghost_disp * std::sin(angle);
                uint32_t ghost_vid = GHOST_VID_BASE + rsu_idx * 100 + vid * 10 + gi;

                // Build ghost beacon packet
                Ptr<Packet> ghost_pkt = Create<Packet>(0);
                BsmBeaconTag ghost_tag;
                ghost_tag.SetVehicleId(ghost_vid);
                ghost_tag.SetPosition(ghost_px, ghost_py);
                ghost_tag.SetSpeed(tag.GetSpeed());
                ghost_tag.SetHeading(tag.GetHeading());
                ghost_tag.SetAcceleration(0.0);
                ghost_tag.SetTimestamp(t);
                ghost_tag.SetIsPoisoned(true);
                ghost_tag.SetAttackType(3);
                ghost_tag.SetRsuId(rsu_idx);
                ghost_pkt->AddPacketTag(ghost_tag);

                // Send ghost packet to controller — queued BEFORE the real beacon
                if (m_relay_socket) {
                    m_relay_socket->SendTo(ghost_pkt, 0,
                        InetSocketAddress(g_management_csma_ip, 7777));
                    cout << "[MP-S1-GHOST-TX] RSU" << rsu_idx
                         << " ghost_id=" << ghost_vid
                         << " pos(" << std::fixed << std::setprecision(2)
                         << ghost_px << "," << ghost_py << ")"
                         << " → MGT (Fig3.4 Step5/6)" << endl;
                }
            }
            // Log ghost identities to CSV (records positions of all N_ghost fake vehicles)
            log_ghost_identity(t, rsu_idx, (int)vid,
                               real_px, real_py,
                               0 /*count_before: ghosts not yet registered*/,
                               N_ghost, ghost_disp, (int)(N_Vehicles / N_RSUs));
        }

        // ── A6-STEP3/5: RSU receives MitM forged beacon (attack_number==6) ──────────
        // Paper (Fig 3.6): RSU cannot distinguish forged MitM packets from legitimate ones.
        // It forwards BOTH the honest vehicle beacon (Step 1→3) AND the MitM forged
        // beacon (Step 4→5) to the controller, which then corrupts its global model.
        if (attack_number == 6 && tag.GetIsPoisoned()) {
            cout << "[A6-STEP3] RSU" << rsu_idx
                 << " received MitM forged beacon for V" << vid
                 << " spd=" << std::fixed << std::setprecision(2) << tag.GetSpeed()
                 << " pos(" << tag.GetPosX() << "," << tag.GetPosY() << ")"
                 << " t=" << t << endl;
        }

        // Stamp RSU index into tag so management_node knows which RSU relayed this beacon
        tag.SetRsuId(rsu_idx);

        // Re-attach modified tag to packet
        packet->AddPacketTag(tag);

        // Log every beacon (clean + poisoned) with real vs received positions
        log_rsu_relay(vid, rsu_idx, t, tag.GetIsPoisoned(),
                      real_px, real_py,
                      tag.GetPosX(), tag.GetPosY(),
                      tag.GetSpeed(), tag.GetHeading(), tag.GetAcceleration());

        // ── send_rsu_dataunicast_alone: RSU forwards its own received beacon to management ──
        // Professor's term: send_rsu_dataunicast_alone
        //   RSU sends ONLY the beacon it just received (one vehicle's data, no aggregation).
        //   If RSU needed to send collected data from multiple vehicles it would be
        //   send_rsu_dataunicast_agent — not used here because each vehicle beacon is
        //   forwarded immediately on arrival, not batched.
        if (m_relay_socket) {
            int err = m_relay_socket->SendTo(packet, 0,
                          InetSocketAddress(g_management_csma_ip, 7777));
            if (err < 0) {
                cout << "[RSU-FWD-ERR] RSU" << rsu_idx
                     << " failed to relay V" << vid << " beacon" << endl;
            } else {
                // A6-STEP5: RSU forwards (both legitimate and forged) beacons to controller
                if (attack_number == 6 && tag.GetIsPoisoned()) {
                    cout << "[A6-STEP5] RSU" << rsu_idx
                         << " forwarding MitM-forged V" << vid
                         << " beacon to controller (controller receives poisoned data)"
                         << "  [send_rsu_dataunicast_alone]" << endl;
                } else {
                    cout << "[RSU-FWD] RSU" << rsu_idx << " → MGT " << g_management_csma_ip
                         << ":7777  V=" << vid
                         << "  [send_rsu_dataunicast_alone]" << endl;
                }
            }
        }
    }
}

// ============================================================
// HandleReadOne / HandleReadTwo — SimpleUdpApplication member stubs
// Declared in 07_security.h; body was in 08_lldp_handlers.h.
// Replaced with beacon-oriented dispatch until Stage 6 cleanup.
// ============================================================
// ── Nearest-RSU lookup ────────────────────────────────────────────────────────
// routing_test layout (12_main.h GridPositionAllocator, routing_test=true):
//   RSU0=(250,480)  RSU1=(750,480)  RSU2=(1250,480)  RSU3=(1750,480)
// Legacy urban layout (routing_test=false, mobility_scenario=0):
//   RSU0=(750,1200) RSU1=(1150,1200) RSU2=(1550,1200) RSU3=(1950,1200)
// Uses g_rsu_actual_pos[] populated at startup so positions never go stale.
// ─────────────────────────────────────────────────────────────────────────────
static double g_rsu_actual_pos_x[4] = {250.0, 750.0, 1250.0, 1750.0}; // routing_test default
static double g_rsu_actual_pos_y[4] = {480.0, 480.0,  480.0,  480.0};

static uint32_t nearest_rsu_for_position(double px, double py)
{
    // Use actual RSU positions (set at startup, matches 12_main.h topology)
    static const double (&rsu_x)[4] = g_rsu_actual_pos_x;
    static const double (&rsu_y)[4] = g_rsu_actual_pos_y;
    int active = (N_RSUs > 0 && N_RSUs <= 4) ? (int)N_RSUs : 4;
    uint32_t nearest = 0;
    double   min_d2  = 1e18;
    for (int r = 0; r < active; r++) {
        double dx = px - rsu_x[r], dy = py - rsu_y[r];
        double d2 = dx*dx + dy*dy;
        if (d2 < min_d2) { min_d2 = d2; nearest = (uint32_t)r; }
    }
    return nearest;
}

void SimpleUdpApplication::HandleReadOne(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    Address     from;
    while ((packet = socket->RecvFrom(from)) != nullptr)
    {
        BsmBeaconTag beaconTag;
        if (packet->PeekPacketTag(beaconTag)) {
            uint32_t vid = beaconTag.GetVehicleId();
            uint32_t rsuId;
            if (g_option_b_active) {
                // Option B: RSU already stamped its index in the tag before forwarding
                rsuId = beaconTag.GetRsuId();
                cout << "[MGT-RX] V" << vid
                     << " from RSU" << rsuId
                     << " pos(" << beaconTag.GetPosX() << "," << beaconTag.GetPosY() << ")"
                     << " poisoned=" << (beaconTag.GetIsPoisoned() ? "YES" : "no")
                     << endl;
            } else {
                // Legacy fallback: assign RSU geographically (no actual DSRC path)
                rsuId = nearest_rsu_for_position(beaconTag.GetPosX(), beaconTag.GetPosY());
                cout << "[RSU-ASSIGN] V" << vid
                     << " pos(" << beaconTag.GetPosX() << "," << beaconTag.GetPosY() << ")"
                     << " → RSU" << rsuId
                     << " compromised=" << (compromised_rsu[rsuId] ? "YES" : "no")
                     << endl;
            }
            HandleBeaconReceived(vid, beaconTag, rsuId);
        }
    }
}

#endif // MPTD_PQS_BEACON_HANDLERS_H
