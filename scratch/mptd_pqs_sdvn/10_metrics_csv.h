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
#include <filesystem>   // export_run_dataset(): per-attack committable dataset copy

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
// C3: per-RSU-cell accepted-vehicle sets for spatial TDEE (ρ̂_cell, Eq 4.5).
// A vehicle is attributed to the Voronoi cell of its REPORTED position, so a
// poisoned position lands the vehicle in the wrong cell → spatial density
// distortion, which TDEE must expose.
std::unordered_set<uint32_t> g_ctrl_seen_cell[MAX_RSUS];
// C3: ground-truth counterpart (ρ_gt_cell) — vehicles attributed to the cell
// of their SUMO true position, sampled at the SAME beacon instants as ρ̂.
// Sampled during the sim because ns-3 mobility models assert if queried after
// Simulator::Destroy() (metrics-print time).
std::unordered_set<uint32_t> g_gt_seen_cell[MAX_RSUS];

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
// ── Per-scenario results directory (option A) ────────────────────────────────
// Every live-sim CSV is written under analytics/results/<scenario>/ so the three
// SUMO scenarios never overwrite each other across runs. The scenario name is
// read from the global mobility_scenario (0=urban, 1=rural, 2=highway), set from
// the --mobility_scenario CLI arg in 12_main.h.
static inline const char* mptd_scenario_name() {
    switch (mobility_scenario) {
        case 1:  return "rural";
        case 2:  return "highway";
        default: return "urban";
    }
}
static inline std::string mptd_results_dir() {
    return std::string(NS3_ROOT "/analytics/results/") + mptd_scenario_name() + "/";
}

void log_beacon_to_csv(uint32_t vid, uint32_t rsu_id, BsmBeaconTag &tag,
                       bool detected, uint32_t sig_mask, double psi)
{
    ensure_analytics_dir(NS3_ROOT "/analytics");
    ensure_analytics_dir(NS3_ROOT "/analytics/results");

    // OVERWRITE each run: truncate on first call so the canonical CSV always
    // reflects the current run only. Use a static flag (reset each process run).
    static bool beacon_first_call = true;
    ensure_analytics_dir(mptd_results_dir().c_str());   // per-scenario folder (option A)
    const std::string path = mptd_results_dir() + "beacon_log.csv";

    // P0 (data persistence) — beacon_log.csv is truncated every run, so a manual
    // single `waf --run` would clobber the previous run's data. Mirror every row
    // into a permanent per-run archive keyed on this run's attack params so no
    // run is ever lost regardless of how the sim is launched. (The sweep also
    // archives via run_evaluation.sh; this protects ad-hoc invocations too.)
    ensure_analytics_dir((mptd_results_dir() + "runs").c_str());
    static const std::string run_path = [] {
        std::ostringstream o;
        o << mptd_results_dir() << "runs/beacon_a" << attack_number
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
    //
    // INDEX FIX (2026-07-19): `vid` here is the beacon tag's vehicle_id, which is set
    // to the ns-3 NodeID (`tag.SetVehicleId(nid)` in 09_vehicle_beacon_tx.h). But
    // get_gt_position() indexes the Vehicle_Nodes container by 0-based vehicle index
    // (NodeID − 2; nodes 0/1 are management/other). Passing the NodeID read a DIFFERENT
    // (often unstepped/static) node → gt_pos decoupled ~900m from the reporting vehicle
    // and gt_speed≈0 in the 200-node SUMO config. Convert to the container index first.
    const uint32_t v_idx = (vid >= 2) ? (vid - 2) : 0;
    double gt_x = tag.GetPosX(), gt_y = tag.GetPosY(), gt_spd = tag.GetSpeed();
    if (g_mobility_provider) {
        Vector p = g_mobility_provider->get_gt_position(v_idx);
        Vector v = g_mobility_provider->get_gt_velocity(v_idx);
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
    if (!detected)
    {
        g_ctrl_seen_vids.insert(vid);
        // C3: attribute the vehicle to the Voronoi cell of its REPORTED
        // position — a poisoned position places it in the wrong cell, which
        // is exactly the spatial distortion TDEE (Eq 4.5) must expose.
        uint32_t cell = nearest_rsu_for_position((double)tag.GetPosX(),
                                                 (double)tag.GetPosY());
        if (cell < MAX_RSUS) g_ctrl_seen_cell[cell].insert(vid);
    }
    // C3: ρ_gt_cell sample — the vehicle's TRUE cell at this instant. Booked
    // for every beacon (detected or not: the vehicle physically exists either
    // way). Sybil-forged vids ≥ N_Vehicles are excluded (no real vehicle).
    if (v_idx < N_Vehicles && g_mobility_provider
        && g_mobility_provider->is_sumo_derived())
    {
        const Vector gt = g_mobility_provider->get_gt_position(v_idx);   // container index, not NodeID
        uint32_t gcell = nearest_rsu_for_position(gt.x, gt.y);
        if (gcell < MAX_RSUS) g_gt_seen_cell[gcell].insert(v_idx);
    }
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

    ensure_analytics_dir(mptd_results_dir().c_str());   // per-scenario folder (option A)
    std::string path = mptd_results_dir() + "tp_s1_poison_log.csv";
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

    ensure_analytics_dir(mptd_results_dir().c_str());   // per-scenario folder (option A)
    std::string path = mptd_results_dir() + "ghost_identity_log.csv";
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
    // displacement_m radius (= R_max_comm * poisoning_intensity_theta = 135 m).
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

    ensure_analytics_dir(mptd_results_dir().c_str());   // per-scenario folder (option A)
    std::string path = mptd_results_dir() + "mitm_intercept_log.csv";
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

    ensure_analytics_dir(mptd_results_dir().c_str());   // per-scenario folder (option A)
    std::string path = mptd_results_dir() + "rsu_relay_log.csv";
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

    ensure_analytics_dir(mptd_results_dir().c_str());   // per-scenario folder (option A)
    std::string path = mptd_results_dir() + "vehicle_tx_log.csv";
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

    ensure_analytics_dir(mptd_results_dir().c_str());   // per-scenario folder (option A)
    std::string path = mptd_results_dir() + "unregistered_beacon_log.csv";
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

    ensure_analytics_dir(mptd_results_dir().c_str());   // per-scenario folder (option A)
    std::string path = mptd_results_dir() + "controller_poison_log.csv";
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
    // Eq 4.1: ε-smoothed MCC — removes the undefined 0/0 when a class is absent
    // (e.g. ρ_a=0 → no attackers → TP=FN=0). ε=1e-12 is negligible for any
    // non-degenerate confusion matrix, so real MCC values are unchanged.
    const double e = 1e-12;
    double num   = (tp+e)*(tn+e) - (fp+e)*(fn+e);
    double denom = std::sqrt((tp+fp+e)*(tp+fn+e)*(tn+fp+e)*(tn+fn+e));
    return num / denom;
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
    // Eq 4.1: ε-smoothed MCC (see compute_MCC) — defined at class absence.
    const double e = 1e-12;
    double num   = (tp+e)*(tn+e) - (fp+e)*(fn+e);
    double denom = std::sqrt((tp+fp+e)*(tp+fn+e)*(tn+fp+e)*(tn+fn+e));
    return num / denom;
}

double compute_FPR_full()
{
    double fp = cm_full_FP, tn = cm_full_TN;
    if (fp + tn < 1e-9) return 0.0;
    return fp / (fp + tn);
}

// PARR: Poisoning Attack Rejection Rate (Eq. 4.3)
// Paper definition: TRS-rejected poisoned aggregates / total poisoned aggregates
// INJECTED. C4b wires a natural injector — a compromised ring coordinator that
// tampers its signed aggregate post-signing (08_detection_engine.h) — so the
// numerator g_parr_rejected and denominator g_parr_injected are booked only when
// such an attacker is actually present and closing the ring. Returns -1 (N/A)
// when no poisoned aggregate was injected (honest ring, or coordinator not
// compromised), consistent with the other C5–C9 metrics. Full mode → ~1.0
// (every tampered aggregate rejected at the TRS gate); AB6 (TRS off) → 0.0 (no
// gate, injections pass). The raw crypto-gate tally g_trs_verified_count /
// g_trs_rejected_count is still emitted separately for reference.
double compute_PARR()
{
    if (g_parr_injected == 0) return -1.0;
    return (double)g_parr_rejected / (double)g_parr_injected;
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
// C3 implementation (per-cell spatial density, Voronoi RSU cells):
//   ρ̂_cell    = |g_ctrl_seen_cell[r]| — distinct accepted vids attributed to
//               cell r by the nearest-RSU of their REPORTED position
//               (log_beacon_to_csv). Poisoned positions land in wrong cells.
//   ρ_gt_cell = |g_gt_seen_cell[r]| — distinct REAL vehicles attributed to
//               cell r by the nearest-RSU of their SUMO true position, sampled
//               at the same beacon instants (booked in log_beacon_to_csv;
//               post-Destroy get_gt_position calls assert in ns-3).
//   TDEE      = mean over cells with ρ_gt_cell > 0 of
//               |ρ̂_cell − ρ_gt_cell| / ρ_gt_cell
//
// Returns -1 only if the active mobility provider is NOT SUMO-derived
// (paper §4.1.3 requires SUMO ground truth). For sumo_trace runs the value is
// paper-conformant; for hardcoded runs it's reported as -1 to avoid
// misinterpretation of non-conformant values.
//
// Applicable metric for MP attacks {3,4,6,7} per paper §4.1.2 — Sybil attacks
// inflate ρ̂_cell; TP position-poisoning shifts vehicles across cell borders.
static uint32_t g_tdee_cells_scored = 0;  // for the print line

double compute_TDEE()
{
    if (!g_mobility_provider || !g_mobility_provider->is_sumo_derived()) {
        return -1.0;  // not paper-conformant under hardcoded mobility
    }
    const uint32_t active = (N_RSUs > 0 && N_RSUs <= MAX_RSUS) ? N_RSUs : MAX_RSUS;

    double err_sum = 0.0;
    uint32_t scored = 0;
    for (uint32_t r = 0; r < active; ++r) {
        if (g_gt_seen_cell[r].empty()) continue;  // empty cell: no GT density to compare
        const double rho_gt  = (double)g_gt_seen_cell[r].size();
        const double rho_hat = (double)g_ctrl_seen_cell[r].size();
        err_sum += std::fabs(rho_hat - rho_gt) / rho_gt;
        scored++;
    }
    g_tdee_cells_scored = scored;
    if (scored == 0) return 0.0;
    return err_sum / (double)scored;
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

// ── C5–C9: paper §4.2 metric additions (TTD/FRR/COO/BWO/TCL) ──────────────────
// All emit −1 when the producing mechanism never ran in this configuration
// (e.g. TCL without live Fabric, COO in LW-only ablation).

// C5 TTD (s): mean over detected attackers of (first alert ≥ onset) − onset.
// Same semantics as analytics/compute_ttd.py; undetected attackers excluded.
double compute_TTD()
{
    double sum = 0.0; int cnt = 0;
    for (int i = 0; i < total_size; i++)
        if (g_ttd_first_poison[i] >= 0 && g_ttd_first_alert[i] >= 0) {
            sum += g_ttd_first_alert[i] - g_ttd_first_poison[i];
            cnt++;
        }
    return cnt > 0 ? sum / cnt : -1.0;
}

// C6 FRR_revoke: honest vehicles falsely revoked / honest vehicle population.
double compute_FRR_revoke()
{
    uint32_t honest = 0;
    for (uint32_t i = 0; i < N_Vehicles && i < (uint32_t)total_size; i++)
        if (!mptd_vehicle_is_malicious_gt((int)i)) honest++;
    return honest > 0 ? (double)g_frr_false_revokes / (double)honest : -1.0;
}

// C6 FRR_demote: honest RSUs falsely demoted from TRUSTED / honest RSU count.
double compute_FRR_demote()
{
    if (!g_frr_demote_data) return -1.0;   // no on-chain lifecycle reads (skip_blockchain)
    uint32_t honest = 0;
    for (uint32_t j = 0; j < N_RSUs && j < MAX_RSUS; j++)
        if (!compromised_rsu[j]) honest++;
    return honest > 0 ? (double)g_frr_false_demotes / (double)honest : -1.0;
}

// C7 COO: mean per-epoch crypto wall-clock (ms), plus the Δt_TRS/Δt_FHE split.
double compute_COO_epoch()
{
    return g_coo_epochs > 0
         ? (g_coo_trs_ms_sum + g_coo_fhe_ms_sum) / (double)g_coo_epochs : -1.0;
}
double compute_COO_trs()
{ return g_coo_epochs > 0 ? g_coo_trs_ms_sum / (double)g_coo_epochs : -1.0; }
double compute_COO_fhe()
{ return g_coo_epochs > 0 ? g_coo_fhe_ms_sum / (double)g_coo_epochs : -1.0; }

// C8 BWO_ratio: security bytes (HMAC + FHE ct + σ_TRS + LKH rekey) over plain
// BSM payload bytes. BWO_scale = LKH rekey messages sent this run (the
// N_rekey-vs-|V_j| scaling curve comes from sweeping runs).
double compute_BWO_ratio()
{
    if (g_bwo_base_bytes == 0) return -1.0;
    const uint64_t sec = g_bwo_hmac_bytes + g_bwo_fhe_bytes
                       + g_bwo_trs_bytes  + g_bwo_rekey_bytes;
    return (double)sec / (double)g_bwo_base_bytes;
}

// C9 TCL (ms): mean Fabric sync-invoke submit→commit-ack; mean post-revocation
// c_assigned reassignment commit.
double compute_TCL_confirm()
{ return g_tcl_confirm_cnt  > 0 ? g_tcl_confirm_ms_sum  / (double)g_tcl_confirm_cnt  : -1.0; }
double compute_TCL_reassign()
{ return g_tcl_reassign_cnt > 0 ? g_tcl_reassign_ms_sum / (double)g_tcl_reassign_cnt : -1.0; }

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
              << "  (Eq 4.3, poisoned-rejected/injected; "
              << g_parr_rejected << "/" << g_parr_injected
              << " poisoned aggregates rejected; -1 = none injected)"
              << "  [TRS-gate tally " << g_trs_rejected_count << " rej / "
              << g_trs_verified_count << " ok]" << std::endl;
    // Separate (non-PARR) revocation-rate signal: poisoned beacons revoked via the
    // lightweight detection path (Eq 3.67). Kept for reference — NOT the crypto PARR.
    std::cout << "  RevRate = "
              << (parr_poisoned_total ? (double)parr_trs_rejected / (double)parr_poisoned_total : 0.0)
              << "  (LW detection-revoke; "
              << parr_trs_rejected << "/" << parr_poisoned_total << " poisoned revoked)" << std::endl;
    // R8.4: per-beacon TRS verify outcomes (Paper §3.5.4 Algorithm 6).
    // Distinct from PARR (per-flagged-poisoned-beacon, Eq 3.67 / 4.3).
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
                  << (sumo ? "SUMO-derived, per-cell mean |ρ̂−ρ_gt|/ρ_gt" : "not sumo_derived → -1")
                  << ", Eq.4.5; cells scored=" << g_tdee_cells_scored
                  << "/" << N_RSUs
                  << " distinct ρ̂ vids=" << g_ctrl_seen_vids.size() << ")" << std::endl;
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
    // C5–C9 (paper §4.2 additions): −1 = mechanism did not run in this config
    std::cout << "  TTD       = " << compute_TTD() << " s (first alert − onset,"
              << " per detected attacker mean)" << std::endl;
    std::cout << "  FRR       = revoke " << compute_FRR_revoke()
              << " (" << g_frr_false_revokes << " false / "
              << g_frr_revoked_total << " total revokes),"
              << " demote " << compute_FRR_demote()
              << " (" << g_frr_false_demotes << " false / "
              << g_frr_demoted_total << " total demotes)" << std::endl;
    std::cout << "  COO       = epoch " << compute_COO_epoch()
              << " ms (TRS " << compute_COO_trs()
              << " + FHE " << compute_COO_fhe()
              << " over " << g_coo_epochs << " epochs),"
              << " DKG " << g_coo_dkg_ms << " ms" << std::endl;
    std::cout << "  BWO       = ratio " << compute_BWO_ratio()
              << " (hmac=" << g_bwo_hmac_bytes << "B fhe=" << g_bwo_fhe_bytes
              << "B trs=" << g_bwo_trs_bytes << "B rekey=" << g_bwo_rekey_bytes
              << "B / base=" << g_bwo_base_bytes << "B),"
              << " scale=" << g_bwo_rekey_pkts << " rekey msgs" << std::endl;
    std::cout << "  TCL       = confirm " << compute_TCL_confirm()
              << " ms (" << g_tcl_confirm_cnt << " invokes),"
              << " reassign " << compute_TCL_reassign()
              << " ms (" << g_tcl_reassign_cnt << " rollovers)" << std::endl;
    std::cout << "──────────────────────────────────────────────────────" << std::endl;
}

// ── Additive per-attack dataset export (committable) ──────────────────────────
// PURPOSE: the NS3_ROOT/analytics/results/*.csv files are TRUNCATED each run, so
// looping all 7 attacks leaves only the last attack's logs. This function copies
// the *current run's* relevant CSVs into a per-run folder under the git repo
// (DATASET_ROOT) so each attack×percentage combination is preserved AND committable.
//
// Layout:  DATASET_ROOT/analytics/datasets/a{N}_p{P}/
//   beacon_log.csv            — ALWAYS (universal clean-vs-poison per-beacon rows)
//   <attacker-type file>.csv  — only the file relevant to this attack's attacker class
//   metrics.csv               — this run's summary (copy of the sweep metrics_* file)
//
// Attacker-class → relevant detail file (see attacker_class_for() in 02_config_globals.h):
//   1 TP-S1 (compromised RSU)      → tp_s1_poison_log.csv
//   2 TP-S2 (malicious vehicle)    → vehicle_tx_log.csv
//   3 MP-S1 (compromised RSU)      → ghost_identity_log.csv
//   4 MP-S2 (malicious vehicle)    → vehicle_tx_log.csv
//   5 TP-S3 (malicious controller) → (none — captured in beacon_log.csv only)
//   6 MP-S3 (MITM)                 → mitm_intercept_log.csv
//   7 MP-S4 (malicious controller) → controller_poison_log.csv
//
// Reason files are filtered: e.g. a malicious-vehicle attack leaves RSU-side logs
// clean/irrelevant, so we only copy the file that shows that attacker poisoning
// its own data. This keeps each folder focused on the attack it represents.
//
// Uses std::filesystem (C++17, enabled by the scratch wscript -std=c++17). Each
// copy is guarded by exists() so a missing log never aborts the run.
static void export_run_dataset(const std::string &metrics_src)
{
    namespace fs = std::filesystem;

    // Per-attack detail file relevant to this run's attacker class. Empty = none.
    std::string detail;
    switch (attack_number) {
        case 1: detail = "tp_s1_poison_log.csv";     break;  // TP-S1, compromised RSU
        case 2: detail = "vehicle_tx_log.csv";        break;  // TP-S2, malicious vehicle
        case 3: detail = "ghost_identity_log.csv";    break;  // MP-S1, compromised RSU
        case 4: detail = "vehicle_tx_log.csv";        break;  // MP-S2, malicious vehicle
        case 5: detail = "";                          break;  // TP-S3, controller (beacon_log only)
        case 6: detail = "mitm_intercept_log.csv";    break;  // MP-S3, MITM
        case 7: detail = "controller_poison_log.csv"; break;  // MP-S4, malicious controller
        default: detail = "";                         break;
    }

    // per-scenario folder (option A); no trailing slash so the existing
    // `results + "/..."` joins below stay correct.
    const std::string results = std::string(NS3_ROOT "/analytics/results/") + mptd_scenario_name();

    // NOTE: the folder key includes _m{ablation_mode}. Without it, two ablation
    // variants at the same scenario/attack/pct (e.g. AB5 lightweight vs full mode)
    // would archive into the SAME aN_pP folder and silently overwrite each other's
    // beacon_log.csv / metrics.csv. Keeping the mode in the path lets an AB1–AB11
    // sweep coexist on disk.
    std::ostringstream dir;
    dir << DATASET_ROOT "/analytics/datasets/" << mptd_scenario_name() << "/a"
        << attack_number << "_p" << attack_percentage << "_m" << ablation_mode;
    // C10: AB variants run with ablation_mode=0 internally, so without the _ab
    // suffix an AB sweep would overwrite the true full-mode folder.
    if (ablation_ab != 0) dir << "_ab" << ablation_ab;
    const std::string dest = dir.str();

    std::error_code ec;
    fs::create_directories(dest, ec);
    if (ec) {
        std::cout << "  Dataset     : SKIPPED (mkdir failed: " << ec.message()
                  << ") " << dest << std::endl;
        return;
    }

    const auto cp = [&](const std::string &src, const std::string &dst) {
        std::error_code e;
        if (fs::exists(src)) {
            fs::copy_file(src, dst, fs::copy_options::overwrite_existing, e);
        }
    };

    // 1) Universal per-beacon log (clean + poisoned rows) — always.
    cp(results + "/beacon_log.csv", dest + "/beacon_log.csv");
    // 2) Attacker-type-specific detail log — only when one applies.
    if (!detail.empty())
        cp(results + "/" + detail, dest + "/" + detail);
    // 3) This run's summary metrics, stored under a stable name inside the folder.
    cp(metrics_src, dest + "/metrics.csv");

    std::cout << "  Dataset     : " << dest << std::endl;
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
          << "_m" << ablation_mode;
    if (ablation_ab != 0) fname << "_ab" << ablation_ab;   // C10: keep AB sweeps distinct
    fname << ".csv";

    std::ofstream fout(fname.str(), std::ios::out | std::ios::trunc);

    // C2: explicit slice keys (attacker_class) + full-mode (Fusion) confusion
    // matrix and MCC/FPR alongside the lightweight ones. Each run injects a
    // single attack variant (attack_number) → one attacker_class; the sweep over
    // attack_number × ablation_mode plus these columns lets the post-processor
    // build the paper's "MCC/FPR per attack variant × 4 attacker classes" table
    // for BOTH decision layers (LW = cm_*/MCC/FPR; Full = cm_full_*/MCC_full/FPR_full).
    const int run_attacker_class = attacker_class_for((int)attack_number);

    // Header — note: TDEE=-1, TPE=-1 (SUMO required); CDER from ctrl-plane decisions
    fout << "attack_number,attacker_class,attack_pct,maxspeed_kmh,ablation_mode,ablation_ab,"
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
         << "sc_register_rejects,sc_register_active,"  // P6: SC-Register gate outcomes
         << "TTD,FRR_revoke,FRR_demote,"                // C5/C6 (paper §4.2)
         << "COO_epoch,COO_trs,COO_fhe,COO_dkg,"        // C7 (ms)
         << "BWO_ratio,BWO_scale,"                      // C8
         << "TCL_confirm,TCL_reassign\n";               // C9 (ms; −1 w/o Fabric)

    // Values
    fout << attack_number              << ","
         << run_attacker_class         << ","
         << attack_percentage          << ","
         << maxspeed                   << ","
         << ablation_mode              << ","
         << ablation_ab                << ","
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
         << g_registered_vids.size()             << ","   // P6
         << compute_TTD()                        << ","   // C5
         << compute_FRR_revoke()                 << ","   // C6
         << compute_FRR_demote()                 << ","   // C6
         << compute_COO_epoch()                  << ","   // C7
         << compute_COO_trs()                    << ","   // C7
         << compute_COO_fhe()                    << ","   // C7
         << g_coo_dkg_ms                         << ","   // C7
         << compute_BWO_ratio()                  << ","   // C8
         << g_bwo_rekey_pkts                     << ","   // C8 BWO_scale
         << compute_TCL_confirm()                << ","   // C9
         << compute_TCL_reassign()               << "\n"; // C9
    fout.close();

    // Also print to stdout and note the file written
    print_mptd_metrics();
    std::cout << "  Results CSV : " << fname.str() << std::endl;
    std::cout << "  Beacon log  : " << (mptd_results_dir() + "beacon_log.csv") << std::endl;

    // Additive, committable per-attack dataset snapshot (keeps every attack×pct run).
    export_run_dataset(fname.str());
}

#endif // MPTD_PQS_METRICS_CSV_H
