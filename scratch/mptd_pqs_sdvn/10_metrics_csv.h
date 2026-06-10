// ============================================================
// SECTION 10: MPTD-PQS Paper Metrics + CSV Output (Stage 4)
// ============================================================
// Implements evaluation metrics from §4.1 of the paper:
//   MCC       - Matthews Correlation Coefficient
//   FPR       - False Positive Rate
//   PARR      - Poisoning Attack Rejection Rate (TRS blockchain, Eq. 4.3)
//   CDER      - Control Decision Error Rate (Eq.4.4, ctrl-plane; lower=better)
//               Measured from actual DownlinkControlTag sends, not beacon CM.
//               Attacks 5&7 (malicious controller) → CDER→1.0 (all decisions wrong).
//   TDEE      - Traffic Density Estimation Error (Eq.4.5) = -1 (requires SUMO ρ_gt(t))
//   TPE       - Trajectory Poisoning Exposure (Eq.4.6) = -1 (requires SUMO + ctrl predictor)
//   PBPO_LW   - Per-Beacon Processing Overhead, lightweight RSU HMAC gate (Eq.4.7)
//   PBPO_Full - Per-Beacon Processing Overhead, full controller pipeline (Eq.4.7)
//
// Globals (updated by update_confusion_matrix() each beacon):
//   cm_TP, cm_FP, cm_TN, cm_FN
// Globals (updated by downlink block in 08_detection_engine.h):
//   ctrl_decisions_total, ctrl_decisions_wrong  (CDER)
// Globals (updated by HMAC gate in 08_detection_engine.h handle_readone()):
//   pbpo_lw_time_sum_ms, pbpo_lw_cnt            (PBPO_LW)
//
// Called from 08_detection_engine.h (via forward decls):
//   update_confusion_matrix(bool is_poisoned, bool detected)
//   log_beacon_to_csv(vid, rsu_id, tag, detected, sig_mask, psi)
//
// Called from 12_main.h after Simulator::Run():
//   write_mptd_results_csv()
//
// Output paths (NS3_ROOT = /home/niranga/ns-allinone-3.35/ns-3.35):
//   analytics/results/beacon_log.csv                        — per-beacon rows
//   analytics/results/sweep/metrics_a{N}_p{P}_s{S}.csv     — per-run summary
//     N=attack_number, P=attack_pct, S=maxspeed_kmh
// ============================================================

#ifndef MPTD_PQS_METRICS_CSV_H
#define MPTD_PQS_METRICS_CSV_H

#include <fstream>
#include <cmath>
#include <sstream>
#include <unordered_set>
#include <sys/stat.h>
#include <sys/types.h>

// ── Confusion matrix counters ─────────────────────────────────────────────────
// TN: not poisoned AND not detected
// FP: not poisoned BUT detected (false alarm)
// FN: poisoned BUT not detected (missed attack)
// TP: poisoned AND detected correctly
uint32_t cm_TP = 0;
uint32_t cm_FP = 0;
uint32_t cm_TN = 0;
uint32_t cm_FN = 0;

// ── C1: Full-mode (Fusion) confusion matrix ───────────────────────────────────
// The lightweight matrix above scores the per-beacon LW-DETECT decision (A1).
// These counters score the FULL-mode decision — the Fusion verdict Φ_i > Φ_th
// (paper Eq 3.44 fusion, Eq 3.45 flag) computed at window close from
// ψ + GAT spatial + LSTM-AE temporal. Without this, ablations A2/A3/A4/A5/Full
// had no MCC/FPR (Eq 4.1/4.2) because only the LW decision was ever scored.
// Populated only when full mode is the active variant (ablation_mode ∉ {1,6});
// for A1/B1 these stay zero and the lightweight matrix is authoritative.
uint32_t cm_full_TP = 0;
uint32_t cm_full_FP = 0;
uint32_t cm_full_TN = 0;
uint32_t cm_full_FN = 0;

// ── R7a: TDEE estimator state (Eq 4.5) ────────────────────────────────────────
// ρ̂(t) = number of distinct vehicle IDs whose beacons were *accepted* by an RSU
// (i.e. passed detection, so they reach the controller and inflate its density
// estimate). Inserted from log_beacon_to_csv() when detected==false.
//
// Under Sybil attacks (MP-S1/S2) that bypass detection, ghost vids land in this
// set → ρ̂ > N_Vehicles → TDEE > 0. Under TP attacks (S1/S2/S5) detection
// doesn't generally add or remove vids → ρ̂ ≈ N_Vehicles → TDEE ≈ 0 (correct
// per paper, TP attacks corrupt trajectory not density).
//
// Reset implicitly per process — first sim run starts with empty set.
std::unordered_set<uint32_t> g_ctrl_seen_vids;

// ── Helper: create directory (no-op if exists) ────────────────────────────────
static void ensure_analytics_dir(const char *path)
{
    mkdir(path, 0755);
}

// ── Confusion matrix update ────────────────────────────────────────────────────
// Called by HandleBeaconReceived() in 08_beacon_handlers.h after each beacon.
void update_confusion_matrix(bool is_poisoned, bool detected)
{
    if  (is_poisoned &&  detected) cm_TP++;
    else if (!is_poisoned &&  detected) cm_FP++;
    else if (!is_poisoned && !detected) cm_TN++;
    else                                cm_FN++; // poisoned, not detected
}

// ── C1: Full-mode confusion matrix update ─────────────────────────────────────
// Scores one full-mode (Fusion) decision against the per-beacon ground-truth
// poison label. `full_flag` is FusionScore::anomalous (Φ_i > Φ_th, Eq 3.45).
// Called per beacon row at window close in 08_detection_engine.h, gated so it
// only fires for full-mode ablations (A2/A3/A4/A5/Full).
void update_confusion_matrix_full(bool is_poisoned, bool full_flag)
{
    if      ( is_poisoned &&  full_flag) cm_full_TP++;
    else if (!is_poisoned &&  full_flag) cm_full_FP++;
    else if (!is_poisoned && !full_flag) cm_full_TN++;
    else                                 cm_full_FN++; // poisoned, missed
}

// ── Per-beacon CSV log ─────────────────────────────────────────────────────────
// Appends one row per beacon for downstream ML pipeline training/evaluation.
// Columns: sim_time, vehicle_id, rsu_id, pos_x, pos_y, speed, heading, accel,
//          is_poisoned, detected, sig_mask, psi_score, attack_number, attack_pct,
//          attacker_class, gt_pos_x, gt_pos_y, gt_speed
//
// R7b additions:
//   attacker_class — paper §4.1.2 MCC slicing (0=NONE, 1=MAL_VEH, 2=COMP_RSU,
//                    3=MITM, 4=MAL_CTRL); derived from is_poisoned + attack_number
//   gt_pos_x/y     — ns-3 MobilityModel position (SUMO ground truth when
//                    mobility_source=sumo_trace; provider-defined otherwise)
//   gt_speed       — ns-3 MobilityModel speed magnitude (sqrt(vx²+vy²+vz²))
// Eval scripts compute displacement error = sqrt((pos_x-gt_pos_x)² + (pos_y-gt_pos_y)²)
// → TPE training labels + LSTM-AE reconstruction targets.
void log_beacon_to_csv(uint32_t vid, uint32_t rsu_id, BsmBeaconTag &tag,
                       bool detected, uint32_t sig_mask, double psi)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    // OVERWRITE each run: truncate on first call so the canonical CSV always
    // reflects the current run only. Use a static flag (reset each process run).
    static bool beacon_first_call = true;
    const std::string path = NS3_ROOT "/analytics/results/beacon_log.csv";

    // P0 (data persistence) — beacon_log.csv is truncated every run, so a manual
    // single `waf --run` would clobber the previous run's data. Mirror every row
    // into a permanent per-run archive keyed on this run's attack params so no
    // run is ever lost regardless of how the sim is launched. (The sweep also
    // archives via run_evaluation.sh; this protects ad-hoc invocations too.)
    ensure_analytics_dir(NS3_ROOT "/analytics/results/runs");
    static const std::string run_path = [] {
        std::ostringstream o;
        o << NS3_ROOT "/analytics/results/runs/beacon_a" << attack_number
          << "_p" << attack_percentage << "_s" << maxspeed << ".csv";
        return o.str();
    }();
    static const char *kBeaconHeader =
        "sim_time,vehicle_id,rsu_id,pos_x,pos_y,speed,heading,accel,"
        "is_poisoned,detected,sig_mask,psi_score,attack_number,attack_pct,"
        "attacker_class,gt_pos_x,gt_pos_y,gt_speed\n";

    // R7b: derive attacker_class — only meaningful for poisoned beacons.
    const int aclass = tag.GetIsPoisoned()
                     ? attacker_class_for((int)tag.GetAttackType())
                     : ATTACKER_NONE;

    // R7b: read ground-truth pose from mobility provider (== ns-3 MobilityModel).
    // Falls back to reported pose if provider is absent (shouldn't happen post-R7a).
    double gt_x = tag.GetPosX(), gt_y = tag.GetPosY(), gt_spd = tag.GetSpeed();
    if (g_mobility_provider) {
        Vector p = g_mobility_provider->get_gt_position(vid);
        Vector v = g_mobility_provider->get_gt_velocity(vid);
        gt_x   = p.x;
        gt_y   = p.y;
        gt_spd = std::sqrt(v.x*v.x + v.y*v.y + v.z*v.z);
    }

    // Build the row once, then write it to BOTH the canonical CSV (truncate on
    // first call) and the permanent per-run archive (P0).
    std::ostringstream row;
    row << tag.GetTimestamp()      << ","
        << vid                     << ","
        << rsu_id                  << ","
        << tag.GetPosX()           << ","
        << tag.GetPosY()           << ","
        << tag.GetSpeed()          << ","
        << tag.GetHeading()        << ","
        << tag.GetAcceleration()   << ","
        << (tag.GetIsPoisoned() ? 1 : 0) << ","
        << (detected            ? 1 : 0) << ","
        << sig_mask                << ","
        << psi                     << ","
        << attack_number           << ","
        << attack_percentage       << ","
        << aclass                  << ","
        << gt_x                    << ","
        << gt_y                    << ","
        << gt_spd                  << "\n";
    const std::string row_str = row.str();
    const std::ios::openmode mode = beacon_first_call
        ? (std::ios::out | std::ios::trunc)
        : (std::ios::out | std::ios::app);
    {
        std::ofstream fout(path, mode);
        if (beacon_first_call) fout << kBeaconHeader;
        fout << row_str;
    }
    {
        std::ofstream farch(run_path, mode);
        if (beacon_first_call) farch << kBeaconHeader;
        farch << row_str;
    }
    beacon_first_call = false;

    // R7a: feed TDEE estimator. A beacon that PASSES detection (detected==false)
    // reaches the controller and contributes to its density estimate ρ̂(t).
    if (!detected) g_ctrl_seen_vids.insert(vid);
}

// ── TP-S1 Before/After Poison Log ─────────────────────────────────────────────
// Writes one row per poisoned beacon showing honest vs RSU-modified values.
// Output: analytics/results/tp_s1_poison_log.csv
void log_tp_s1_poison(uint32_t vid, uint32_t rsu_id,
                      double sim_t,
                      double real_px, double real_py,
                      double fake_px, double fake_py,
                      double speed,   double heading, double accel,
                      double drift_x, double drift_y, double disp_err,
                      bool   is_abrupt, double step_scaled)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    std::string path = NS3_ROOT "/analytics/results/tp_s1_poison_log.csv";
    static bool poison_first_call = true;
    std::ofstream fout;
    if (poison_first_call) {
        fout.open(path, std::ios::out | std::ios::trunc);
        fout << "sim_time,vehicle_id,rsu_id,attack_pct,"
             << "real_pos_x,real_pos_y,"
             << "fake_pos_x,fake_pos_y,"
             << "drift_x,drift_y,disp_err_m,"
             << "speed_ms,heading_rad,accel_ms2,"
             << "is_abrupt,step_scaled_m\n";   // §3.4.3 Eq 3.5 hybrid-mix labels
        poison_first_call = false;
    } else {
        fout.open(path, std::ios::out | std::ios::app);
    }

    fout << std::fixed << std::setprecision(4)
         << sim_t          << ","
         << vid            << ","
         << rsu_id         << ","
         << attack_percentage << ","
         << real_px        << ","
         << real_py        << ","
         << fake_px        << ","
         << fake_py        << ","
         << drift_x        << ","
         << drift_y        << ","
         << disp_err       << ","
         << speed          << ","
         << heading        << ","
         << accel          << ","
         << (is_abrupt ? 1 : 0) << ","
         << step_scaled    << "\n";
    fout.close();
}

// ── Ghost Identity Log — MP-S1 (Attack 3) ghost vehicle records ───────────────
// Writes one row per GHOST VEHICLE ID generated by a compromised RSU.
// In the paper (Fig 3.4 Steps 4-5), the RSU creates N_ghost fake identities per
// real vehicle arrival. This CSV makes those ghost IDs visible as distinct records.
//
// Columns:
//   sim_time        — simulation time when real beacon arrived at RSU
//   rsu_id          — compromised RSU that generated the ghost
//   real_vehicle_id — the honest vehicle whose arrival triggered ghost creation
//   ghost_id        — synthetic ghost identity string "G{rsu}_{vid}_{i}"
//   ghost_pos_x/y   — ghost vehicle position (real pos + angular displacement)
//   displacement_m  — Euclidean distance from real vehicle (= R_max*θ = 150 m)
//   count_after     — density count in RSU identity set after this ghost added
//   density_limit   — per-RSU threshold (N_Vehicles/N_RSUs = 4)
//   exceeds_limit   — 1 if count_after > density_limit (triggers MP-S1 detection)
//
// Output: analytics/results/ghost_identity_log.csv
void log_ghost_identity(double sim_t, int rsu_id, int real_vid,
                        double real_px, double real_py,
                        int count_before, int n_ghost,
                        double ghost_displacement_m, int density_lim)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    std::string path = NS3_ROOT "/analytics/results/ghost_identity_log.csv";
    static bool ghost_first_call = true;
    std::ofstream fout;
    if (ghost_first_call) {
        fout.open(path, std::ios::out | std::ios::trunc);
        fout << "sim_time,rsu_id,real_vehicle_id,ghost_id,"
             << "ghost_pos_x,ghost_pos_y,displacement_m,"
             << "count_after,density_limit,exceeds_limit\n";
        ghost_first_call = false;
    } else {
        fout.open(path, std::ios::out | std::ios::app);
    }

    // Place N_ghost ghost vehicles evenly around the real vehicle at
    // displacement_m radius (= R_max_comm * poisoning_intensity_theta = 150 m).
    // Directions: 0°, 90°, 180°, 270°  (East, North, West, South).
    for (int i = 0; i < n_ghost; i++) {
        double angle_rad  = i * (2.0 * M_PI / n_ghost);
        double ghost_px   = real_px + ghost_displacement_m * std::cos(angle_rad);
        double ghost_py   = real_py + ghost_displacement_m * std::sin(angle_rad);
        int    cnt_after  = count_before + (i + 1);   // one ghost ID at a time
        bool   exceeds    = (cnt_after > density_lim);

        // ghost_id format: G{rsu_id}_{real_vid}_{ghost_index}
        std::string ghost_id = "G" + std::to_string(rsu_id)
                             + "_V" + std::to_string(real_vid)
                             + "_" + std::to_string(i);

        fout << std::fixed << std::setprecision(4)
             << sim_t       << ","
             << rsu_id      << ","
             << real_vid    << ","
             << ghost_id    << ","
             << ghost_px    << ","
             << ghost_py    << ","
             << ghost_displacement_m << ","
             << cnt_after   << ","
             << density_lim << ","
             << (exceeds ? 1 : 0) << "\n";
    }
    fout.close();
}

// ── MitM Intercept Log — Attack 6 (MP-S3) interception events ─────────────────
// One row per MitM interception: honest data intercepted vs forged data injected.
// Paper Fig 3.6 Steps 2-4: attacker intercepts victim beacon, fabricates forged
// report with modified location/speed/acceleration, forwards under victim's ID.
// Output: analytics/results/mitm_intercept_log.csv
void log_mitm_intercept(double sim_t,
                        uint32_t attacker_id, uint32_t victim_id,
                        double real_px, double real_py,
                        double real_spd, double real_hdg,
                        double fake_px, double fake_py,
                        double fake_spd, double fake_acc,
                        double range_m, int step_num)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    std::string path = NS3_ROOT "/analytics/results/mitm_intercept_log.csv";
    static bool mitm_first_call = true;
    std::ofstream fout;
    if (mitm_first_call) {
        fout.open(path, std::ios::out | std::ios::trunc);
        fout << "sim_time,attacker_id,victim_id,step_num,attack_pct,"
             << "real_pos_x,real_pos_y,real_speed_ms,real_heading_rad,"
             << "fake_pos_x,fake_pos_y,fake_speed_ms,fake_accel_ms2,"
             << "spd_delta_ms,pos_drift_m,range_to_victim_m\n";
        mitm_first_call = false;
    } else {
        fout.open(path, std::ios::out | std::ios::app);
    }

    double pos_drift = std::sqrt((fake_px - real_px) * (fake_px - real_px) +
                                 (fake_py - real_py) * (fake_py - real_py));
    double spd_delta = fake_spd - real_spd;

    fout << std::fixed << std::setprecision(4)
         << sim_t           << ","
         << attacker_id     << ","
         << victim_id       << ","
         << step_num        << ","
         << attack_percentage << ","
         << real_px         << ","
         << real_py         << ","
         << real_spd        << ","
         << real_hdg        << ","
         << fake_px         << ","
         << fake_py         << ","
         << fake_spd        << ","
         << fake_acc        << ","
         << spd_delta       << ","
         << pos_drift       << ","
         << range_m         << "\n";
    fout.close();
}

// ── RSU Relay Log — every beacon at RSU level (clean + poisoned) ──────────────
// Writes one row per beacon processed by an RSU node (Option B path).
// Shows real_pos (what vehicle sent) vs recv_pos (what management_node receives).
// For clean beacons: real_pos == recv_pos, drift=0, disp_err=0.
// Output: analytics/results/rsu_relay_log.csv
void log_rsu_relay(uint32_t vid, uint32_t rsu_id, double sim_t, bool is_poisoned,
                   double real_px, double real_py,   // honest vehicle position
                   double recv_px, double recv_py,   // position after RSU relay (poisoned or same)
                   double speed,   double heading, double accel)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    std::string path = NS3_ROOT "/analytics/results/rsu_relay_log.csv";
    static bool relay_first_call = true;
    std::ofstream fout;
    if (relay_first_call) {
        fout.open(path, std::ios::out | std::ios::trunc);
        fout << "sim_time,vehicle_id,rsu_id,attack_pct,is_poisoned,"
             << "real_pos_x,real_pos_y,"
             << "recv_pos_x,recv_pos_y,"
             << "drift_x,drift_y,disp_err_m,"
             << "speed_ms,heading_rad,accel_ms2\n";
        relay_first_call = false;
    } else {
        fout.open(path, std::ios::out | std::ios::app);
    }

    double drift_x   = recv_px - real_px;
    double drift_y   = recv_py - real_py;
    double disp_err  = std::sqrt(drift_x*drift_x + drift_y*drift_y);

    fout << std::fixed << std::setprecision(4)
         << sim_t          << ","
         << vid            << ","
         << rsu_id         << ","
         << attack_percentage << ","
         << (is_poisoned ? 1 : 0) << ","
         << real_px        << ","
         << real_py        << ","
         << recv_px        << ","
         << recv_py        << ","
         << drift_x        << ","
         << drift_y        << ","
         << disp_err       << ","
         << speed          << ","
         << heading        << ","
         << accel          << "\n";
    fout.close();
}

// ── Vehicle TX Log — one row per beacon at the moment the vehicle sends it ────
// Shows real position + what the vehicle actually transmitted (poisoned or honest).
// For honest vehicles: sent_pos == real_pos, drift == 0.
// For malicious vehicles: sent_pos reflects PoisonTrajectoryByType() output.
// Output: analytics/results/vehicle_tx_log.csv
void log_vehicle_tx(uint32_t vid, uint32_t nearest_rsu,
                    double sim_t,   bool is_malicious,
                    double real_px, double real_py,
                    double sent_px, double sent_py,
                    double real_spd, double sent_spd,
                    double real_hdg, double sent_hdg)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    std::string path = NS3_ROOT "/analytics/results/vehicle_tx_log.csv";
    static bool tx_first_call = true;
    std::ofstream fout;
    if (tx_first_call) {
        fout.open(path, std::ios::out | std::ios::trunc);
        fout << "sim_time,vehicle_id,nearest_rsu,attack_number,attack_pct,is_malicious,"
             << "real_pos_x,real_pos_y,sent_pos_x,sent_pos_y,"
             << "drift_x,drift_y,disp_err_m,"
             << "real_speed_ms,sent_speed_ms,speed_delta_ms,"
             << "real_heading_rad,sent_heading_rad,heading_delta_rad\n";
        tx_first_call = false;
    } else {
        fout.open(path, std::ios::out | std::ios::app);
    }

    double drift_x      = sent_px  - real_px;
    double drift_y      = sent_py  - real_py;
    double disp_err     = std::sqrt(drift_x*drift_x + drift_y*drift_y);
    double spd_delta    = sent_spd - real_spd;
    double hdg_delta    = sent_hdg - real_hdg;

    fout << std::fixed << std::setprecision(4)
         << sim_t          << ","
         << vid            << ","
         << nearest_rsu    << ","
         << attack_number  << ","
         << attack_percentage << ","
         << (is_malicious ? 1 : 0) << ","
         << real_px        << ","
         << real_py        << ","
         << sent_px        << ","
         << sent_py        << ","
         << drift_x        << ","
         << drift_y        << ","
         << disp_err       << ","
         << real_spd       << ","
         << sent_spd       << ","
         << spd_delta      << ","
         << real_hdg       << ","
         << sent_hdg       << ","
         << hdg_delta      << "\n";
    fout.close();
}

// ── P6: SC-Register Unregistered-Beacon Reject Log ───────────────────────────
// One row per beacon dropped by the SC-Register authorisation gate in
// 08_detection_engine.h::handle_readone(). Lets analysts inspect *which*
// vids leaked beacons without a valid REG_VEH_<nid> record — typically the
// result of (a) registration failure (e.g., daemon down, <2f+1 endorsers),
// or (b) an attacker injecting beacons under a vid that was never SC-Registered.
//
// Important: rejected beacons are NOT counted in MCC/FPR/PARR/CDER — those
// metrics measure detection-pipeline behaviour over valid peers only
// (paper §4.1.2). This separate log avoids polluting the confusion matrix.
//
// Output: analytics/results/unregistered_beacon_log.csv
// Columns: sim_time, vehicle_id, rsu_id, pos_x, pos_y, attack_number,
//          attack_pct, ablation_mode
void log_unregistered_beacon_reject(uint32_t vid, uint32_t rsu_id, double sim_t,
                                    double pos_x, double pos_y)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    std::string path = NS3_ROOT "/analytics/results/unregistered_beacon_log.csv";
    static bool ureg_first_call = true;
    std::ofstream fout;
    if (ureg_first_call) {
        fout.open(path, std::ios::out | std::ios::trunc);
        fout << "sim_time,vehicle_id,rsu_id,pos_x,pos_y,"
             << "attack_number,attack_pct,ablation_mode\n";
        ureg_first_call = false;
    } else {
        fout.open(path, std::ios::out | std::ios::app);
    }

    fout << std::fixed << std::setprecision(4)
         << sim_t            << ","
         << vid              << ","
         << rsu_id           << ","
         << pos_x            << ","
         << pos_y            << ","
         << attack_number    << ","
         << attack_percentage << ","
         << ablation_mode    << "\n";
    fout.close();
}

// ── Controller Poison Log — Attack 7 (MP-S4): one row per beacon poisoned ────
// Shows real speed from honest vehicle vs the poisoned speed the controller used.
// Controller receives correct data but intentionally shifts distribution upward.
// Output: analytics/results/controller_poison_log.csv
void log_controller_poison(double sim_t,
                           uint32_t vehicle_id, uint32_t rsu_id,
                           double real_spd, double fake_spd,
                           double shift_factor,
                           double real_hdg,  double fake_hdg,
                           uint8_t alert_type, double spd_adv)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    std::string path = NS3_ROOT "/analytics/results/controller_poison_log.csv";
    static bool cp_first_call = true;
    std::ofstream fout;
    if (cp_first_call) {
        fout.open(path, std::ios::out | std::ios::trunc);
        fout << "sim_time,vehicle_id,rsu_id,attack_pct,"
             << "real_speed_ms,poisoned_speed_ms,speed_shift_factor,"
             << "spd_delta_ms,"
             << "real_heading_rad,poisoned_heading_rad,hdg_delta_rad,"
             << "alert_type,spd_adv_ms\n";
        cp_first_call = false;
    } else {
        fout.open(path, std::ios::out | std::ios::app);
    }

    double spd_delta = fake_spd - real_spd;
    double hdg_delta = fake_hdg - real_hdg;

    fout << std::fixed << std::setprecision(4)
         << sim_t            << ","
         << vehicle_id       << ","
         << rsu_id           << ","
         << attack_percentage << ","
         << real_spd         << ","
         << fake_spd         << ","
         << shift_factor     << ","
         << spd_delta        << ","
         << real_hdg         << ","
         << fake_hdg         << ","
         << hdg_delta        << ","
         << (int)alert_type  << ","
         << spd_adv          << "\n";
    fout.close();
}

// ── 7 Paper Metric Computations (§3.5) ───────────────────────────────────────

// MCC: Matthews Correlation Coefficient
// (TP·TN − FP·FN) / sqrt((TP+FP)(TP+FN)(TN+FP)(TN+FN))
double compute_MCC()
{
    double tp = cm_TP, fp = cm_FP, tn = cm_TN, fn = cm_FN;
    double denom = std::sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn));
    if (denom < 1e-9) return 0.0;
    return (tp*tn - fp*fn) / denom;
}

// FPR: False Positive Rate  —  FP / (FP + TN)
double compute_FPR()
{
    double fp = cm_FP, tn = cm_TN;
    if (fp + tn < 1e-9) return 0.0;
    return fp / (fp + tn);
}

// C1: MCC / FPR on the FULL-mode (Fusion) confusion matrix (Eq 4.1/4.2).
// These are the reportable detection metrics for ablations A2/A3/A4/A5/Full;
// the LW compute_MCC()/compute_FPR() above remain authoritative for A1/B1.
double compute_MCC_full()
{
    double tp = cm_full_TP, fp = cm_full_FP, tn = cm_full_TN, fn = cm_full_FN;
    double denom = std::sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn));
    if (denom < 1e-9) return 0.0;
    return (tp*tn - fp*fn) / denom;
}

double compute_FPR_full()
{
    double fp = cm_full_FP, tn = cm_full_TN;
    if (fp + tn < 1e-9) return 0.0;
    return fp / (fp + tn);
}

// PARR: Poisoning Attack Rejection Rate (Eq. 4.3)
// Fraction of poisoned blockchain submissions correctly rejected by the TRS layer.
// A "TRS rejection" occurs when a vehicle accumulates ≥ REVOKE_THRESHOLD (3)
// consecutive detection events — the ring signature quorum refuses to countersign.
// Unlike DR = TP/(TP+FN) (per-beacon detection rate), PARR measures the blockchain
// enforcement outcome: an attacker must sustain 3+ catches before being revoked.
// In short simulations PARR < DR; over longer runs PARR approaches DR.
double compute_PARR()
{
    if (parr_poisoned_total == 0) return 0.0;
    return (double)parr_trs_rejected / (double)parr_poisoned_total;
}

// CDER: Control Decision Error Rate (paper §4.1.2, Eq. 4.4)
// Eq. 4.4: CDER = wrong_ctrl_decisions / total_ctrl_decisions (lower=better)
// Measured at the DOWNLINK control plane (DownlinkControlTag sends by management node):
//   WRONG_ROUTING (alert_type=2): always wrong — malicious controller output
//   CLEAN_ROUTING (alert_type=0) for poisoned beacon: FN at control-plane level
//   ATTACK_DETECTED (alert_type=1) for clean beacon:  FP at control-plane level
// Attacks 5 & 7: controller is malicious → alert_type=2 for every beacon → CDER→1.0
// Fallback (Option B inactive / no downlink decisions): beacon-level (FP+FN)/total.
double compute_CDER()
{
    if (ctrl_decisions_total > 0)
        return (double)ctrl_decisions_wrong / (double)ctrl_decisions_total;
    // Fallback: beacon-level confusion matrix (FP+FN)/total
    double total = (double)(cm_TP + cm_FP + cm_TN + cm_FN);
    if (total < 1e-9) return 0.0;
    return (double)(cm_FP + cm_FN) / total;
}

// TDEE: Traffic Density Estimation Error (Eq. 4.5, dimensionless)
// Paper Eq. 4.5: TDEE = |ρ̂(t) − ρ_gt(t)| / ρ_gt(t)
//   ρ_gt(t)  = SUMO ground-truth vehicle density at time t (from provider)
//   ρ̂(t)    = controller's estimated density from accepted beacons
//             (g_ctrl_seen_vids tracked in log_beacon_to_csv())
//
// R7a implementation:
//   ρ_gt = N_Vehicles (count of real vehicles — provider gives the same value
//          since the mobility model IS the source of truth for vehicle count)
//   ρ̂    = |g_ctrl_seen_vids| (distinct vids whose beacons passed detection)
//
// Returns -1 only if the active mobility provider is NOT SUMO-derived
// (paper §4.1.3 requires SUMO ground truth). For sumo_trace runs the value is
// paper-conformant; for hardcoded runs it's reported as -1 to avoid
// misinterpretation of non-conformant values.
//
// Applicable metric for MP attacks {3,4,6,7} per paper §4.1.2 — Sybil attacks
// inflate ρ̂ above N_Vehicles; TP attacks generally leave ρ̂ ≈ N_Vehicles.
double compute_TDEE()
{
    if (!g_mobility_provider || !g_mobility_provider->is_sumo_derived()) {
        return -1.0;  // not paper-conformant under hardcoded mobility
    }
    const double rho_gt = (double)N_Vehicles;
    if (rho_gt < 1e-9) return 0.0;
    const double rho_hat = (double)g_ctrl_seen_vids.size();
    return std::fabs(rho_hat - rho_gt) / rho_gt;
}

// TPE: Trajectory Poisoning Exposure (Eq. 4.6)
// Paper Eq. 4.6: TPE = mean Euclidean displacement( p̂_ctrl(t) − p_sumo(t) )
//   p̂_ctrl(t) = controller's predicted vehicle position (here: dead-reckoning predictor
//               using the most-recent *beacon-reported* (x, y, speed, heading); the
//               beacon may be poisoned, which is exactly what TPE is supposed to expose)
//   p_sumo(t)  = SUMO ground-truth vehicle position at time t, fetched from
//               IMobilityProvider::get_gt_position() (live when --mobility_source=sumo_trace,
//               degenerate when hardcoded since GT==internal estimate)
//
// Accumulators (tpe_disp_sum / tpe_disp_cnt) are updated in 08_detection_engine.h at
// HandleBeaconReceived(): for each beacon after the first we extrapolate
//   p̂(t_now) = p_prev + v_prev·dt
// from the previous observation, then accumulate the Euclidean residual against the
// SUMO ground truth at t_now. Returns -1 only if no samples have been collected yet
// (e.g. simulation aborted before the second beacon for any vehicle).
// Applicable for TP attacks {1,2,5} per paper §4.1.2.
double compute_TPE()
{
    if (tpe_disp_cnt == 0) return -1.0;
    return tpe_disp_sum / (double)tpe_disp_cnt;
}

// PBPO_Full: Per-Beacon Processing Overhead — full controller-side pipeline (ms)
// Mean wall-clock time from beacon arrival at HandleBeaconReceived() to detection
// decision. Measured with clock_gettime(CLOCK_MONOTONIC) in 08_detection_engine.h.
// Covers: TP-DETECT (Alg 1) + SYB-DETECT (Alg 2) + MITM-DETECT (Alg 3) + CP-DETECT (Alg 4)
// + confusion matrix update + beacon CSV log + downlink packet construction.
double compute_PBPO()
{
    if (pbpo_cnt == 0) return 0.0;
    return pbpo_time_sum_ms / (double)pbpo_cnt;
}

// PBPO_LW: RSU-side lightweight HMAC gate overhead (ms) — Eq.4.7, lightweight mode
// Mean wall-clock time of the HMAC verification step at the RSU (before forwarding
// to the controller). This is the per-beacon cost of the first-line authentication gate.
// Measured separately from PBPO_Full so both modes are independently characterised.
double compute_PBPO_LW()
{
    if (pbpo_lw_cnt == 0) return 0.0;
    return pbpo_lw_time_sum_ms / (double)pbpo_lw_cnt;
}

// ── Print all metrics to stdout ────────────────────────────────────────────────
void print_mptd_metrics()
{
    std::cout << "\n── MPTD-PQS Detection Metrics ────────────────────────" << std::endl;
    std::cout << "  Attack: " << attack_number
              << " (" << attack_scenario_name[attack_number] << ")"
              << "  pct=" << attack_percentage
              << "%  speed=" << maxspeed << " km/h" << std::endl;
    std::cout << "  Confusion matrix (LW / A1):"
              << "  TP=" << cm_TP
              << "  FP=" << cm_FP
              << "  TN=" << cm_TN
              << "  FN=" << cm_FN << std::endl;
    std::cout << "  MCC  = " << compute_MCC()  << "  (Matthews Correlation Coefficient, LW)" << std::endl;
    std::cout << "  FPR  = " << compute_FPR()  << "  (False Positive Rate, LW)" << std::endl;
    // C1: full-mode (Fusion) detection metrics — authoritative for A2/A3/A4/A5/Full.
    if (ablation_mode != 1 && ablation_mode != 6) {
        std::cout << "  Confusion matrix (Full/Fusion):"
                  << "  TP=" << cm_full_TP
                  << "  FP=" << cm_full_FP
                  << "  TN=" << cm_full_TN
                  << "  FN=" << cm_full_FN << std::endl;
        std::cout << "  MCC_full = " << compute_MCC_full()
                  << "  (Fusion Φ>Φ_th, Eq 3.45/4.1)" << std::endl;
        std::cout << "  FPR_full = " << compute_FPR_full()
                  << "  (Fusion, Eq 4.2)" << std::endl;
    }
    std::cout << "  PARR = " << compute_PARR()
              << "  (TRS blockchain rejection; "
              << parr_trs_rejected << "/" << parr_poisoned_total << " poisoned revoked)" << std::endl;
    // R8.4: per-beacon TRS verify outcomes (Paper §3.5.4 Algorithm 6).
    // Distinct from PARR (which is REVOKE_THRESHOLD-driven, post-3-strikes).
    // These counters reflect the real Shamir-Schnorr partial_sign+aggregate+verify chain
    // booked into the PBPO_Full window per evidence message m_j (Eq. 3.46).
    std::cout << "  TRS-verify: " << g_trs_verified_count << " ok / "
              << g_trs_rejected_count << " fail  (Paper §3.5.4 Eq.3.47–3.49, per-beacon σ_j+aggregate)"
              << std::endl;
    // CDER: show source (control-plane decisions or fallback)
    if (ctrl_decisions_total > 0)
        std::cout << "  CDER = " << compute_CDER()
                  << "  (ctrl-plane decisions: " << ctrl_decisions_wrong
                  << "/" << ctrl_decisions_total
                  << " wrong, Eq.4.4, lower=better)" << std::endl;
    else
        std::cout << "  CDER = " << compute_CDER()
                  << "  (beacon-level (FP+FN)/total fallback, Eq.4.4, lower=better)" << std::endl;
    // TDEE: live when --mobility_source=sumo_trace; otherwise -1 per paper conformance.
    // TPE:  live dead-reckoning predictor (08_detection_engine.h) vs SUMO ground truth.
    {
        const double tdee = compute_TDEE();
        const bool   sumo = g_mobility_provider && g_mobility_provider->is_sumo_derived();
        std::cout << "  TDEE = " << tdee << "  ("
                  << (sumo ? "SUMO-derived, |ρ̂−ρ_gt|/ρ_gt" : "not sumo_derived → -1")
                  << ", Eq.4.5; ρ̂=" << g_ctrl_seen_vids.size()
                  << " ρ_gt=" << N_Vehicles << ")" << std::endl;
    }
    {
        const double tpe  = compute_TPE();
        const bool   sumo = g_mobility_provider && g_mobility_provider->is_sumo_derived();
        std::cout << "  TPE  = " << tpe << "  ("
                  << tpe_disp_cnt << " samples, dead-reckoning vs "
                  << (sumo ? "SUMO ground-truth" : "internal GT (degenerate — use --mobility_source=sumo_trace)")
                  << ", Eq.4.6; applicable for TP attacks {1,2,5})" << std::endl;
    }
    // PBPO: separate lightweight (RSU) and full (controller) modes
    std::cout << "  PBPO_LW   = " << compute_PBPO_LW()
              << " ms (" << pbpo_lw_cnt << " beacons, RSU HMAC gate, Eq.4.7 LW)" << std::endl;
    std::cout << "  PBPO_Full = " << compute_PBPO()
              << " ms (" << pbpo_cnt << " beacons, controller pipeline, Eq.4.7 Full)" << std::endl;
    // R4.c: IPFS off-chain windows + on-chain hash anchors (paper §3.5.3 Eq 3.56)
    std::cout << "  IPFS      = " << ipfs_upload_count
              << " windows off-chain, " << ipfs_hash_chain_count
              << " hashes on-chain (paper §3.5.3 Eq 3.56, RSU→BC direct)" << std::endl;
    // R6: CP-DETECT (paper §3.5.5 / Algorithm 7 / Eq 3.59) — controller peer-consensus audit
    std::cout << "  CP-DETECT = " << g_cp_detect_alerts_total
              << " CTRL_COMPROMISED alerts ("
              << g_cp_detect_conflict_fires << " conflict, "
              << g_cp_detect_trs_fails << " TRS-fail) over "
              << g_cp_detect_epochs_evaluated << " audited epochs,"
              << " flag_c=" << (g_flag_c_active ? "1" : "0")
              << " (paper §3.5.5 Algorithm 7, Eq 3.59)" << std::endl;
    // P6: SC-Register authorisation gate — dropped beacons (forensics only;
    // not in MCC/FPR/PARR/CDER). registered_vids = vehicles that have a
    // legal REG_VEH_<nid> record on chain (paper §3.5.5 Algorithm 7).
    std::cout << "  SC-Register gate = " << unregistered_beacon_reject_count
              << " beacons rejected (unregistered vid), "
              << g_registered_vids.size() << "/" << N_Vehicles
              << " vehicles on-chain (paper §3.5.5 Algorithm 7)" << std::endl;
    std::cout << "──────────────────────────────────────────────────────" << std::endl;
}

// ── Master results CSV — one row per simulation run ───────────────────────────
// Output: analytics/results/sweep/metrics_a{N}_p{P}_s{S}.csv
//   N = attack_number (1-7)
//   P = attack_percentage (5,10,20,30)
//   S = maxspeed km/h (20,50,100)
// Scheduled from 12_main.h after Simulator::Run().
//
// TDEE column is -1 unless --mobility_source=sumo_trace (paper conformance — see compute_TDEE).
// TPE  column is live dead-reckoning residual vs the active mobility provider (see compute_TPE);
//   the residual is meaningful only when GT differs from the beacon-reported state, i.e.
//   under --mobility_source=sumo_trace OR when poisoning attacks rewrite the beacon.
// CDER uses control-plane decision counters when Option B is active (Eq.4.4).
// PBPO_LW = RSU HMAC gate overhead; PBPO_Full = controller detection pipeline.
void write_mptd_results_csv()
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");
    ensure_analytics_dir(NS3_ROOT "/analytics/results/sweep");

    // Filename: metrics_a{attack}_p{pct}_s{speed}_m{ablation}.csv
    // Each dimension is encoded so sweeps never overwrite each other.
    std::ostringstream fname;
    fname << NS3_ROOT "/analytics/results/sweep/metrics_a"
          << attack_number << "_p" << attack_percentage
          << "_s" << maxspeed
          << "_m" << ablation_mode << ".csv";

    std::ofstream fout(fname.str(), std::ios::out | std::ios::trunc);

    // C2: explicit slice keys (attacker_class) + full-mode (Fusion) confusion
    // matrix and MCC/FPR alongside the lightweight ones. Each run injects a
    // single attack variant (attack_number) → one attacker_class; the sweep over
    // attack_number × ablation_mode plus these columns lets the post-processor
    // build the paper's "MCC/FPR per attack variant × 4 attacker classes" table
    // for BOTH decision layers (LW = cm_*/MCC/FPR; Full = cm_full_*/MCC_full/FPR_full).
    const int run_attacker_class = attacker_class_for((int)attack_number);

    // Header — note: TDEE=-1, TPE=-1 (SUMO required); CDER from ctrl-plane decisions
    fout << "attack_number,attacker_class,attack_pct,maxspeed_kmh,ablation_mode,"
         << "cm_TP,cm_FP,cm_TN,cm_FN,"
         << "MCC,FPR,"
         << "cm_full_TP,cm_full_FP,cm_full_TN,cm_full_FN,"
         << "MCC_full,FPR_full,"
         << "PARR,"
         << "CDER,ctrl_decisions_total,ctrl_decisions_wrong,"
         << "TDEE,TPE,"
         << "PBPO_LW_ms,PBPO_Full_ms,"
         << "total_received,total_poisoned,total_stored,"
         << "trs_verified_count,trs_rejected_count,"   // R8.4: per-beacon σ_j outcomes
         << "sc_register_rejects,sc_register_active\n"; // P6: SC-Register gate outcomes

    // Values
    fout << attack_number              << ","
         << run_attacker_class         << ","
         << attack_percentage          << ","
         << maxspeed                   << ","
         << ablation_mode              << ","
         << cm_TP                      << ","
         << cm_FP                      << ","
         << cm_TN                      << ","
         << cm_FN                      << ","
         << compute_MCC()              << ","
         << compute_FPR()              << ","
         << cm_full_TP                 << ","
         << cm_full_FP                 << ","
         << cm_full_TN                 << ","
         << cm_full_FN                 << ","
         << compute_MCC_full()         << ","
         << compute_FPR_full()         << ","
         << compute_PARR()             << ","
         << compute_CDER()             << ","
         << ctrl_decisions_total       << ","
         << ctrl_decisions_wrong       << ","
         << compute_TDEE()             << ","   // -1 unless --mobility_source=sumo_trace
         << compute_TPE()              << ","   // live: dead-reckoning residual (R7e.4)
         << compute_PBPO_LW()          << ","
         << compute_PBPO()             << ","
         << total_trajectories_received          << ","
         << total_trajectories_poisoned          << ","
         << total_trajectories_stored_blockchain << ","
         << g_trs_verified_count                 << ","   // R8.4
         << g_trs_rejected_count                 << ","   // R8.4
         << unregistered_beacon_reject_count     << ","   // P6
         << g_registered_vids.size()             << "\n"; // P6
    fout.close();

    // Also print to stdout and note the file written
    print_mptd_metrics();
    std::cout << "  Results CSV : " << fname.str() << std::endl;
    std::cout << "  Beacon log  : " NS3_ROOT "/analytics/results/beacon_log.csv" << std::endl;
}

#endif // MPTD_PQS_METRICS_CSV_H
