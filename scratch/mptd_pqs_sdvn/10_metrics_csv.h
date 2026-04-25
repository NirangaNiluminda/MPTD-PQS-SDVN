// ============================================================
// SECTION 10: MPTD-PQS Paper Metrics + CSV Output (Stage 4)
// ============================================================
// Implements the 7 evaluation metrics from §3.5 of the paper:
//   MCC  - Matthews Correlation Coefficient
//   FPR  - False Positive Rate
//   PARR - Poisoning Attack Rejection Rate
//   CDER - Correct Detection-to-Error Ratio
//   TDEE - Trajectory Data Error Exposure
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

    static bool header_written = false;
    std::ofstream fout;

    if (!header_written) {
        fout.open(NS3_ROOT "/analytics/results/beacon_log.csv",
                  std::ios::out | std::ios::trunc);
        fout << "sim_time,vehicle_id,rsu_id,pos_x,pos_y,speed,heading,accel,"
             << "is_poisoned,detected,sig_mask,psi_score,attack_number,attack_pct\n";
        header_written = true;
    } else {
        fout.open(NS3_ROOT "/analytics/results/beacon_log.csv",
                  std::ios::out | std::ios::app);
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

// PARR: Poisoning Attack Rejection Rate  —  TP / (TP + FN)  [= Recall]
double compute_PARR()
{
    double tp = cm_TP, fn = cm_FN;
    if (tp + fn < 1e-9) return 0.0;
    return tp / (tp + fn);
}

// CDER: Control Decision Error Rate  —  (FP + FN) / (TP + FP + TN + FN)
// Fraction of all beacons where the detection decision was wrong.
// (1 − Accuracy). High CDER = many wrong control decisions.
double compute_CDER()
{
    double tp = cm_TP, fp = cm_FP, tn = cm_TN, fn = cm_FN;
    double total = tp + fp + tn + fn;
    if (total < 1e-9) return 0.0;
    return (fp + fn) / total;
}

// TDEE: Traffic Density Estimation Error  —  mean |reported_pos − real_pos| (m)
// Measures how far received beacon positions deviate from NS-3 ground truth.
// Accumulated in 09_send_lte.h at send time; zero for honest vehicles.
double compute_TDEE()
{
    if (tdee_error_cnt == 0) return 0.0;
    return tdee_error_sum / (double)tdee_error_cnt;
}

// TPE: Trajectory Prediction Error  —  RMSE of position error for malicious beacons (m)
// Captures the magnitude of trajectory manipulation for attacker vehicles.
// sqrt(mean(|poisoned_pos − real_pos|²)) over malicious-vehicle beacons.
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
    std::cout << "  PARR = " << compute_PARR() << "  (Poisoning Attack Rejection Rate = Recall)" << std::endl;
    std::cout << "  CDER = " << compute_CDER() << "  (Control Decision Error Rate = 1 - Accuracy)" << std::endl;
    std::cout << "  TDEE = " << compute_TDEE() << " m  (mean beacon position error, all vehicles)" << std::endl;
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
