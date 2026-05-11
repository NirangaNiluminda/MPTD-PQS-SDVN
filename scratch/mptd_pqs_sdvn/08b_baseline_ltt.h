// ============================================================
// 08b_baseline_ltt.h — Ghaleb (2014) LTT Baseline Detector (B1)
// ============================================================
// Implements the Location Time Table (LTT) misbehavior detection
// method from:
//   Ghaleb et al. (2014) "Misbehavior detection in vehicular
//   ad hoc networks using location time tables"
//
// Activated when --ablation_mode=6
//
// Two detection checks derived from the paper's Algorithm 1 & 2:
//
//   Check 1 — Speed Plausibility (Alg.1 Eq.1):
//     dist(p_curr, p_prev) / dt > s_max  → MISBEHAVIOR
//     A vehicle cannot physically travel faster than the road
//     speed limit between two consecutive beacon intervals.
//
//   Check 2 — Cross-RSU Reachability (Alg.2 mobility analysis):
//     If vehicle's RSU changes between beacons, verify that the
//     RSU-to-RSU distance / time gap ≤ s_max.
//     A vehicle cannot teleport between non-adjacent RSU cells.
//
// Known limitations of Ghaleb B1 vs MPTD-PQS:
//   ✗ Cannot detect Sybil attacks (MP-S1, MP-S2) — no identity checks
//   ✗ Cannot detect MitM distribution shift (MP-S3) — no KL divergence
//   ✗ Cannot detect slow cumulative drift (TP-S5) — no history window
//   ✗ No crypto layer (no HMAC, no TRS)
//   ✗ No formal metrics in original paper (21 vehicles, qualitative only)
//
// These gaps are exactly what MPTD-PQS addresses — the performance
// difference shown in figures directly answers RQ2, RQ3.
// ============================================================

#ifndef MPTD_PQS_BASELINE_LTT_H
#define MPTD_PQS_BASELINE_LTT_H

#include <cmath>

// ── LTT entry: last known state per vehicle ───────────────────────────────────
struct LttEntry {
    double   pos_x     = 0.0;   // last reported position x (m)
    double   pos_y     = 0.0;   // last reported position y (m)
    double   timestamp = -1.0;  // last beacon time (s); -1 = not yet seen
    uint32_t rsu_id    = 0;     // RSU that last forwarded this vehicle's beacon
};

// Global LTT — one entry per vehicle (indexed by vehicle_id, max total_size+2)
static LttEntry g_ltt[MAX_NODES + 2];

// ── RSU grid positions (matches topology in 12_main.h routing_test layout) ────
// RSU0=(250,480) RSU1=(750,480) RSU2=(1250,480) RSU3=(1750,480)
static const double LTT_RSU_X[4] = {250.0, 750.0, 1250.0, 1750.0};
static const double LTT_RSU_Y[4] = {480.0, 480.0,  480.0,  480.0};

// ── Helper: Euclidean distance between two RSUs ───────────────────────────────
static double ltt_rsu_dist(uint32_t r1, uint32_t r2)
{
    if (r1 >= 4 || r2 >= 4) return 0.0;
    double dx = LTT_RSU_X[r1] - LTT_RSU_X[r2];
    double dy = LTT_RSU_Y[r1] - LTT_RSU_Y[r2];
    return std::sqrt(dx*dx + dy*dy);
}

// ============================================================
// run_ltt_detect() — Ghaleb (2014) two-check detector
//
// Returns true  → misbehavior detected (FLAGGED)
//         false → behaviour plausible   (CLEAN)
//
// Called from HandleBeaconReceived() when ablation_mode == 6.
// ============================================================
bool run_ltt_detect(uint32_t vehicle_id, uint32_t rsu_id, BsmBeaconTag &tag)
{
    if (vehicle_id >= (uint32_t)(MAX_NODES + 2)) return false;

    double curr_px = tag.GetPosX();
    double curr_py = tag.GetPosY();
    double curr_t  = tag.GetTimestamp();

    LttEntry &entry = g_ltt[vehicle_id];

    // First beacon from this vehicle — populate LTT, no detection yet
    if (entry.timestamp < 0.0) {
        entry.pos_x     = curr_px;
        entry.pos_y     = curr_py;
        entry.timestamp = curr_t;
        entry.rsu_id    = rsu_id;
        return false;
    }

    double dt = curr_t - entry.timestamp;
    if (dt <= 0.0) dt = T_b;  // guard against same-timestamp beacons

    bool flagged = false;

    // ── Check 1: Speed Plausibility (Alg.1 Eq.1) ─────────────────────────────
    // dist(p_curr, p_prev) / dt > s_max → physically impossible movement
    double dx   = curr_px - entry.pos_x;
    double dy   = curr_py - entry.pos_y;
    double dist = std::sqrt(dx*dx + dy*dy);
    if (dist / dt > s_max)
        flagged = true;

    // ── Check 2: Cross-RSU Reachability (Alg.2 mobility analysis) ────────────
    // If the vehicle's serving RSU changed, verify the inter-RSU distance
    // is physically traversable in the elapsed time.
    // Ghaleb: "location outside reachable area given previous position" → flag
    if (!flagged && rsu_id != entry.rsu_id && rsu_id < 4 && entry.rsu_id < 4) {
        double rsu_dist = ltt_rsu_dist(entry.rsu_id, rsu_id);
        if (rsu_dist / dt > s_max)
            flagged = true;
    }

    // Update LTT with current observation
    entry.pos_x     = curr_px;
    entry.pos_y     = curr_py;
    entry.timestamp = curr_t;
    entry.rsu_id    = rsu_id;

    return flagged;
}

#endif // MPTD_PQS_BASELINE_LTT_H
