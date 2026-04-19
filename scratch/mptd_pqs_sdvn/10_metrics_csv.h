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

// CDER: Correct Detection-to-Error Ratio  —  TP / (TP + FP + FN)
double compute_CDER()
{
    double tp = cm_TP, fp = cm_FP, fn = cm_FN;
    if (tp + fp + fn < 1e-9) return 0.0;
    return tp / (tp + fp + fn);
}

// TDEE: Trajectory Data Error Exposure  —  FN / total_received
double compute_TDEE()
{
    double fn = (double)cm_FN;
    double total = (double)total_trajectories_received;
    if (total < 1.0) return 0.0;
    return fn / total;
}

// TPE: Trajectory Poisoning Exposure  —  total_poisoned / total_received
double compute_TPE()
{
    double poisoned = (double)total_trajectories_poisoned;
    double total    = (double)total_trajectories_received;
    if (total < 1.0) return 0.0;
    return poisoned / total;
}

// PBPO: Post-Blockchain Poisoning Offset
// (poisoned_stored − flagged_stored) / total_stored
// Interpreted as: FN / total_stored_blockchain
// (undetected poisoned entries remaining on ledger without a flag)
double compute_PBPO()
{
    double fn    = (double)cm_FN;
    double total = (double)total_trajectories_stored_blockchain;
    if (total < 1.0) return 0.0;
    return fn / total;
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
    std::cout << "  MCC  = " << compute_MCC()  << std::endl;
    std::cout << "  FPR  = " << compute_FPR()  << std::endl;
    std::cout << "  PARR = " << compute_PARR() << std::endl;
    std::cout << "  CDER = " << compute_CDER() << std::endl;
    std::cout << "  TDEE = " << compute_TDEE() << std::endl;
    std::cout << "  TPE  = " << compute_TPE()  << std::endl;
    std::cout << "  PBPO = " << compute_PBPO() << std::endl;
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
