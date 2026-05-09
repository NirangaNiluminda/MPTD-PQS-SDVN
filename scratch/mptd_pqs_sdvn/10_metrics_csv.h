// ============================================================
// SECTION 10: MPTD-PQS Paper Metrics + CSV Output (Stage 4)
// ============================================================
// Implements the 7 evaluation metrics from §3.5 of the paper:
//   MCC  - Matthews Correlation Coefficient
//   FPR  - False Positive Rate
//   PARR - Poisoning Attack Rejection Rate (TRS blockchain revocation rate, Eq. 4.3)
//   CDER - Correct Detection-to-Error Ratio (Accuracy = (TP+TN)/total, higher=better)
//   TDEE - Traffic Density Estimation Error (dimensionless per-RSU relative error, Eq. 4.5)
//   TPE  - Trajectory Poisoning Exposure
//   PBPO - Post-Blockchain Poisoning Offset
//
// Globals (updated by update_confusion_matrix() each beacon):
//   cm_TP, cm_FP, cm_TN, cm_FN
//
// Called from 08_beacon_handlers.h (via forward decls):
//   update_confusion_matrix(bool is_poisoned, bool detected)
//   log_beacon_to_csv(vid, rsu_id, tag, detected, sig_mask, psi)
//
// Called from 12_main.h after Simulator::Run():
//   write_mptd_results_csv()
//
// Output paths (NS3_ROOT = /home/niranga/ns-allinone-3.35/ns-3.35):
//   analytics/results/beacon_log.csv          — per-beacon rows
//   analytics/results/sweep/metrics_a{N}_p{P}.csv — per-run summary
// ============================================================

#ifndef MPTD_PQS_METRICS_CSV_H
#define MPTD_PQS_METRICS_CSV_H

#include <fstream>
#include <cmath>
#include <sstream>
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

// ── Per-beacon CSV log ─────────────────────────────────────────────────────────
// Appends one row per beacon for downstream ML pipeline training/evaluation.
// Columns: sim_time, vehicle_id, rsu_id, pos_x, pos_y, speed, heading, accel,
//          is_poisoned, detected, sig_mask, psi_score, attack_number, attack_pct
void log_beacon_to_csv(uint32_t vid, uint32_t rsu_id, BsmBeaconTag &tag,
                       bool detected, uint32_t sig_mask, double psi)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    // OVERWRITE each run: truncate on first call so CSV always reflects current run only.
    // Use static flag (reset to true each new process) to detect first call per run.
    static bool beacon_first_call = true;
    std::ofstream fout;
    std::string path = NS3_ROOT "/analytics/results/beacon_log.csv";

    if (beacon_first_call) {
        fout.open(path, std::ios::out | std::ios::trunc);
        fout << "sim_time,vehicle_id,rsu_id,pos_x,pos_y,speed,heading,accel,"
             << "is_poisoned,detected,sig_mask,psi_score,attack_number,attack_pct\n";
        beacon_first_call = false;
    } else {
        fout.open(path, std::ios::out | std::ios::app);
    }

    fout << tag.GetTimestamp()      << ","
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
         << attack_percentage       << "\n";
    fout.close();
}

// ── TP-S1 Before/After Poison Log ─────────────────────────────────────────────
// Writes one row per poisoned beacon showing honest vs RSU-modified values.
// Output: analytics/results/tp_s1_poison_log.csv
void log_tp_s1_poison(uint32_t vid, uint32_t rsu_id,
                      double sim_t,
                      double real_px, double real_py,
                      double fake_px, double fake_py,
                      double speed,   double heading, double accel,
                      double drift_x, double drift_y, double disp_err)
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
             << "speed_ms,heading_rad,accel_ms2\n";
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
         << accel          << "\n";
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

// CDER: Correct Detection-to-Error Ratio (paper §4.1.2, Eq. 4.4)
// Fraction of all beacon processing decisions that were correct.
// = (TP + TN) / (TP + FP + TN + FN) = Accuracy
// Higher value = better (more correct control decisions).
// Previous code computed (FP+FN)/total = 1−Accuracy (error rate, lower-better):
// corrected here to match the paper's "correct ratio" naming and direction.
double compute_CDER()
{
    double tp = cm_TP, fp = cm_FP, tn = cm_TN, fn = cm_FN;
    double total = tp + fp + tn + fn;
    if (total < 1e-9) return 0.0;
    return (tp + tn) / total;
}

// TDEE: Traffic Density Estimation Error (Eq. 4.5, dimensionless)
// Measures relative error in per-RSU vehicle count estimation.
// Paper: TDEE = |ρ̂(t) − ρ_gt(t)| / ρ_gt(t)  (avoids SUMO by using RSU beacon counts)
//
// Implementation (no SUMO needed):
//   tdee_gt_count[j]  = beacons received via RSU j  (ground-truth: vehicle is near RSU j)
//   tdee_est_count[j] = beacons whose reported position maps to RSU j's cell
//   TDEE_j = |est_j − gt_j| / gt_j  (0 when positions are honest, rises when forged)
//   TDEE   = mean over active RSU cells (j with gt_count > 0)
//
// Behaviour per attack type:
//   TP-S1/S3: forged position maps to wrong RSU cell → TDEE rises
//   MP-S1:    ghost beacons arrive at same RSU → inflate est_count for that cell
//   TP-S2/MP-S2/MP-S3/MP-S4: positions honest or same cell → TDEE ≈ 0
double compute_TDEE()
{
    double sum   = 0.0;
    int    valid = 0;
    for (int j = 0; j < 4; j++) {
        if (tdee_gt_count[j] == 0) continue;
        sum += std::fabs((double)tdee_est_count[j] - (double)tdee_gt_count[j])
               / (double)tdee_gt_count[j];
        valid++;
    }
    return (valid > 0) ? (sum / valid) : 0.0;
}

// TPE: Trajectory Poisoning Error  —  RMSE of injection error for malicious beacons (m)
// Paper Eq. 4.6 defines TPE as: mean displacement between the controller's predicted
// position and SUMO ground truth (requires an internal Kalman/DR prediction model).
// Implementation proxy: RMSE of |poisoned_pos − real_pos| over malicious-vehicle beacons,
// i.e. measures the magnitude of position/speed manipulation the attacker introduced.
// This correlates with the paper's definition (larger injection → larger prediction error)
// but is not identical — it measures attack injection magnitude, not controller prediction
// residual. True TPE would require comparing controller state estimates vs SUMO truth.
double compute_TPE()
{
    if (tpe_cnt == 0) return 0.0;
    return std::sqrt(tpe_sq_sum / (double)tpe_cnt);
}

// PBPO: Per-Beacon Processing Overhead  —  mean detection time per beacon (ms)
// Measures real-time feasibility: mean wall-clock time from beacon arrival
// to detection decision, measured with clock_gettime() in 08_beacon_handlers.h.
double compute_PBPO()
{
    if (pbpo_cnt == 0) return 0.0;
    return pbpo_time_sum_ms / (double)pbpo_cnt;
}

// ── Print all 7 metrics to stdout ─────────────────────────────────────────────
void print_mptd_metrics()
{
    std::cout << "\n── MPTD-PQS Detection Metrics ────────────────────────" << std::endl;
    std::cout << "  Confusion matrix:"
              << "  TP=" << cm_TP
              << "  FP=" << cm_FP
              << "  TN=" << cm_TN
              << "  FN=" << cm_FN << std::endl;
    std::cout << "  MCC  = " << compute_MCC()  << "  (Matthews Correlation Coefficient)" << std::endl;
    std::cout << "  FPR  = " << compute_FPR()  << "  (False Positive Rate)" << std::endl;
    std::cout << "  PARR = " << compute_PARR() << "  (TRS blockchain rejection rate; " << parr_trs_rejected << "/" << parr_poisoned_total << " poisoned submissions revoked)" << std::endl;
    std::cout << "  CDER = " << compute_CDER() << "  (Correct Detection-to-Error Ratio = Accuracy = (TP+TN)/total)" << std::endl;
    std::cout << "  TDEE = " << compute_TDEE() << "    (traffic density estimation error, dimensionless)" << std::endl;
    std::cout << "  TPE  = " << compute_TPE()  << " m  (RMSE position error, malicious vehicles only)" << std::endl;
    std::cout << "  PBPO = " << compute_PBPO() << " ms (mean per-beacon detection overhead)" << std::endl;
    std::cout << "──────────────────────────────────────────────────────" << std::endl;
}

// ── Master results CSV — one row per simulation run ───────────────────────────
// Output: analytics/results/sweep/metrics_a{attack_number}_p{attack_percentage}.csv
// Scheduled from 12_main.h after Simulator::Run().
void write_mptd_results_csv()
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");
    ensure_analytics_dir(NS3_ROOT "/analytics/results/sweep");

    std::ostringstream fname;
    fname << NS3_ROOT "/analytics/results/sweep/metrics_a"
          << attack_number << "_p" << attack_percentage << ".csv";

    std::ofstream fout(fname.str(), std::ios::out | std::ios::trunc);

    // Header
    fout << "attack_number,attack_pct,"
         << "cm_TP,cm_FP,cm_TN,cm_FN,"
         << "MCC,FPR,PARR,CDER,TDEE,TPE,PBPO,"
         << "total_received,total_poisoned,total_stored\n";

    // Values
    fout << attack_number        << ","
         << attack_percentage    << ","
         << cm_TP                << ","
         << cm_FP                << ","
         << cm_TN                << ","
         << cm_FN                << ","
         << compute_MCC()        << ","
         << compute_FPR()        << ","
         << compute_PARR()       << ","
         << compute_CDER()       << ","
         << compute_TDEE()       << ","
         << compute_TPE()        << ","
         << compute_PBPO()       << ","
         << total_trajectories_received         << ","
         << total_trajectories_poisoned         << ","
         << total_trajectories_stored_blockchain << "\n";
    fout.close();

    // Also print to stdout and note the file written
    print_mptd_metrics();
    std::cout << "  Results CSV: " << fname.str() << std::endl;
    std::cout << "  Beacon log : " NS3_ROOT "/analytics/results/beacon_log.csv" << std::endl;
}

#endif // MPTD_PQS_METRICS_CSV_H
