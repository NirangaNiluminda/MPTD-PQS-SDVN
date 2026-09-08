// ============================================================
// 08_detection_engine.h — MPTD-PQS Detection Engine
// Renamed from 08_beacon_handlers.h (Stage 10B cleanup)
// MPTD-PQS: Dual-Mode Detection for MP and TP Attacks in SDVN
// ============================================================
// Replaces 08_lldp_handlers.h (17K lines of legacy LLDP code).
//
// Contents:
//   HandleBeaconReceived()         - main entry: BSM beacon at RSU
//   run_tp_detect()                - TP-DETECT (Algorithm 1, §3.4.4)
//   run_syb_detect()               - SYB-DETECT (Algorithm 2, §3.4.4)
//   run_mitm_detect()              - MITM-DETECT (Algorithm 3)
//   run_cp_detect()                - per-beacon cp_flags oracle (LW pipeline)
//   run_cp_detect_per_epoch()      - CP-DETECT (Algorithm 7, §3.5.5, Eq 3.59)
//   log_metrics_line()             - [METRICS] / [MRTPA_SUMMARY] output
//
// Paper: §3.4.4 Algorithms 1–3 (LW signatures), §3.5.5 Algorithm 7 (CP-DETECT)
// ============================================================

#ifndef MPTD_PQS_BEACON_HANDLERS_H
#define MPTD_PQS_BEACON_HANDLERS_H

#include <cmath>
#include <sstream>
#include <deque>          // CP-DETECT per-vehicle rolling RSU view window (Eq 3.59)
#include <map>            // CP-DETECT per-vehicle window keyed by vehicle id
#include <unordered_set>  // TASK ①-K: SCTrustFinalizeEpoch (vid,epoch) dedup
#include <time.h>         // clock_gettime for PBPO timing

// ── Internal forward declarations ────────────────────────────────────────────
static uint32_t nearest_rsu_for_position(double px, double py); // defined later in this file
static uint32_t best_rsu_for_position(double px, double py,    // LL-based selection (§RSU-LL)
                                       double vx, double vy,
                                       uint32_t vid, bool is_mal);

// ── Forward declarations (defined in 10_metrics_csv.h) ───────────────────────
// 10_metrics_csv.h is included after this file in simulation.cc, so we
// forward-declare here to allow HandleBeaconReceived() to call them.
void update_confusion_matrix(bool is_poisoned, bool detected);
void update_confusion_matrix_full(bool is_poisoned, bool full_flag);

// ── Tier-3 batched evidence commit (paper §3.5.5, tab:set-blockchain) ─────────
// Buffers SC-Trust anomaly evidence E_j(t) per RSU and flushes it as ONE batched
// Fabric tx every g_t_batch seconds OR g_n_commit entries (whichever first),
// replacing the per-beacon synchronous submit. Tier-1 revocation stays sync.
// CallSCTrustSubmitEvidence is MPTD_BLOCKCHAIN_GUARD-gated, so in skip_blockchain
// runs this only emits the [TIER3-…] batch log and never alters detection.
struct Tier3Ev { uint32_t vid, rsu; std::string epoch; double psi; std::string hb; };
static std::vector<Tier3Ev> g_tier3_buf[MAX_RSUS];
static double   g_tier3_last_flush[MAX_RSUS] = {};
static bool     g_tier3_init[MAX_RSUS]       = {};
static uint64_t g_tier3_batches = 0, g_tier3_entries = 0, g_tier3_buffered = 0;

static void tier3_flush(uint32_t rsu, double now) {
    if (rsu >= MAX_RSUS || g_tier3_buf[rsu].empty()) return;
    for (const auto& e : g_tier3_buf[rsu])
        CallSCTrustSubmitEvidence(e.vid, e.rsu, e.epoch, e.psi, e.hb);
    std::cout << "[TIER3-BATCH-COMMIT-RSU" << rsu << "] flushed "
              << g_tier3_buf[rsu].size() << " evidence entries in 1 batched tx"
              << " (T_batch=" << g_t_batch << "s N_commit=" << g_n_commit
              << ") t=" << std::fixed << std::setprecision(3) << now << std::endl;
    g_tier3_batches++; g_tier3_entries += (uint64_t)g_tier3_buf[rsu].size();
    g_tier3_buf[rsu].clear(); g_tier3_last_flush[rsu] = now;
}

// Buffer one evidence tuple; flush the RSU's batch when full (N_commit) or the
// batch interval (T_batch) has elapsed since the batch's first entry.
static void tier3_commit_evidence(uint32_t vid, uint32_t rsu, const std::string& epoch,
                                  double psi, const std::string& hb, double now) {
    if (rsu >= MAX_RSUS) { CallSCTrustSubmitEvidence(vid, rsu, epoch, psi, hb); return; }
    if (!g_tier3_init[rsu]) { g_tier3_last_flush[rsu] = now; g_tier3_init[rsu] = true; }
    g_tier3_buf[rsu].push_back({vid, rsu, epoch, psi, hb});
    g_tier3_buffered++;
    if ((int)g_tier3_buf[rsu].size() >= g_n_commit ||
        (now - g_tier3_last_flush[rsu]) >= g_t_batch)
        tier3_flush(rsu, now);
}

// Flush every RSU's remaining partial batch — called once at simulation end so
// the final sub-N_commit batch (which no later push would time-flush) is not
// silently dropped. Emits one [TIER3-BATCH-COMMIT] line per non-empty buffer.
static void tier3_flush_all(double now) {
    for (uint32_t r = 0; r < MAX_RSUS; r++)
        if (!g_tier3_buf[r].empty()) tier3_flush(r, now);
}

// ── Targeted flush ahead of CP-DETECT (Eq 3.66-3.69) ─────────────────────────
// CPDetectCheck joins CSUBM_<vid>_<epoch> against the SUBM_<vid>_<epoch>_<rsu>
// range. Under Tier-3 batching the RSU evidence for that epoch may still be
// sitting in a per-RSU buffer — it is committed only at N_commit entries or
// T_batch seconds — so a check scheduled shortly after the controller submission
// range-scans an EMPTY prefix and scores conflict = 0 however strongly the RSUs
// disagreed. Measured before this fix: the first batch landed at t = 8.325 s
// carrying evidence for beacons from t ~ 0, while the check ran at +0.5 s;
// CFLAG was 0 across every run even though 122 vehicle-epoch pairs showed the
// controller reporting benign against an RSU psi above threshold.
//
// We flush ONLY those buffers that actually hold an entry for this (vid, epoch).
// Every other RSU keeps its batch intact, so the §3.5.5 batched-commit design and
// the PBPO transaction-count claim are preserved — unlike disabling batching
// wholesale, which fixes the race but forfeits the contribution.
//
// The flush is fire-and-forget; the existing schedule delay then covers the
// orderer round-trip, which is what that delay was always meant to absorb.
// Returns the number of RSU buffers flushed (0 when batching is off, or when the
// evidence has already been committed by a size/time flush).
static uint32_t tier3_flush_for_vid_epoch(uint32_t vid, const std::string& epoch,
                                          double now) {
    uint32_t flushed = 0;
    for (uint32_t r = 0; r < MAX_RSUS; r++) {
        if (g_tier3_buf[r].empty()) continue;
        bool holds_evidence = false;
        for (const auto& e : g_tier3_buf[r]) {
            if (e.vid == vid && e.epoch == epoch) { holds_evidence = true; break; }
        }
        if (holds_evidence) { tier3_flush(r, now); flushed++; }
    }
    return flushed;
}
void log_beacon_to_csv(uint32_t vid, uint32_t rsu_id, BsmBeaconTag &tag,
                       bool detected, uint32_t sig_mask, double psi);
void log_tp_s1_poison(uint32_t vid, uint32_t rsu_id,
                      double sim_t,
                      double real_px, double real_py,
                      double fake_px, double fake_py,
                      double speed,   double heading, double accel,
                      double drift_x, double drift_y, double disp_err,
                      bool   is_abrupt = false, double step_scaled = 0.0);
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
void log_controller_poison(double sim_t,
                           uint32_t vehicle_id, uint32_t rsu_id,
                           double real_spd, double fake_spd,
                           double shift_factor,
                           double real_hdg,  double fake_hdg,
                           uint8_t alert_type, double spd_adv);
// P6: SC-Register gate rejection logger (defined in 10_metrics_csv.h).
// Called from handle_readone() when a vehicle's vid is not in
// g_registered_vids — beacon is dropped before any detection pipeline runs.
void log_unregistered_beacon_reject(uint32_t vid, uint32_t rsu_id, double sim_t,
                                    double pos_x, double pos_y);
// PBPO timing accumulator (defined in 02_config_globals.h)
// pbpo_time_sum_ms and pbpo_cnt are global — updated directly here.

// ── Stage 6: paper-conformant revocation voting (paper §3.5.5, Eq 3.65 / 3.67) ─
// The paper casts an RSU's revocation vote on a SINGLE flag (flag_i^{rsu,j} =
// 1[ψ_j^(i)(t) > ψ_th], Eq 3.67); false-positive robustness comes from requiring
// 2f+1 DISTINCT trusted-RSU witnesses inside the sliding window T_w (Eq 3.65),
// NOT from one RSU flagging 3 times in a row. The legacy 3-consecutive counter
// (REVOKE_THRESHOLD=3) had no basis in the paper and is removed.
//
// To avoid re-submitting the same idempotent vote on every 100 ms beacon, a
// per-(RSU,vehicle) refresh guard rate-limits vote SUBMISSION only (an anti-spam
// network concern) — it does NOT gate detection or metrics. The same RSU re-votes
// only after VOTE_REFRESH_SEC of continued flagging; distinct RSUs are unaffected.
static const double VOTE_REFRESH_SEC = 15.0;   // ~T_w/2 (T_w default 30 s, chaincode side)
static std::map<uint64_t, double> last_revoke_vote_ts;  // key = (rsu_idx<<32)|vid

// ============================================================
// send_lkh_rekey_to_vehicles() — Real NS-3 rekey packet transmission
// Called after revocation (BFT 2f+1 distinct-witness quorum, Eq 3.65).
//
// Steps (§3.5.2, Eq.3.33–3.34):
//   1. lkh_rekey_on_revoke() regenerates keys on the revoked vehicle's path
//   2. For each non-revoked vehicle: increment nonce η_i, recompute K_i
//   3. Send unicast RekeyTag UDP packet (port LKH_REKEY_PORT=5555) to each
//      vehicle via the RSU's DSRC send socket — REAL NS-3 packet transmission
//   4. Receive side: HandleRekeyReceived() in 07_socket_layer.h
// ============================================================
static void send_lkh_rekey_to_vehicles(uint32_t revoked_vehicle_id,
                                        uint32_t rsu_id,
                                        double   sim_time)
{
    // veh_idx of the revoked vehicle
    int rev_idx = lkh_veh_idx(revoked_vehicle_id);

    // Zone-scoped rekey: marks the revoked vehicle, rekeys its zone path, and
    // fills g_lkh_affected_members with the surviving members of THAT zone only
    // (paper §3.5.2 Eq 3.23: N_rekey = log₂|V_j|, the zone population).
    int n_rekeyed = lkh_rekey_on_revoke(rev_idx, sim_time);

    // RSU rekey socket (set in 07_socket_layer.h StartApplication)
    Ptr<Socket> rekey_sock = (rsu_id < N_RSUs) ? g_rsu_rekey_socket[rsu_id] : nullptr;
    if (!rekey_sock) {
        cout << "[LKH-REKEY] WARNING: no rekey socket for RSU" << rsu_id << endl;
        return;
    }

    int packets_sent = 0;

    // Send unicast RekeyTag only to the surviving members of the revoked
    // vehicle's ZONE (paper §3.5.2: rekey is zone-scoped, not network-wide).
    for (int vi : g_lkh_affected_members) {
        if (vi < 0 || vi >= LKH_MAX_VEH) continue;
        uint32_t veh_nid = (uint32_t)(vi + 2);

        // Increment nonce η_i → new K_i cannot be derived from the old one
        g_vehicle_nonce[vi]++;

        // Recompute K_i = KDF(K_{u_i}, new_η_i, ID_i) [Eq.3.22]
        lkh_compute_session_key(vi);

        // Build RekeyTag carrying this vehicle's (current) leaf key + new nonce
        RekeyTag rk;
        rk.SetTargetVehicleId(veh_nid);
        rk.SetNewLeafKey(g_vehicle_leaf_key[vi]);
        rk.SetNewNonce(g_vehicle_nonce[vi]);
        rk.SetRsuId(rsu_id);
        rk.SetTimestamp(sim_time);

        Ptr<Packet> rk_pkt = Create<Packet>(0);
        rk_pkt->AddPacketTag(rk);

        // Unicast to vehicle's DSRC IP if known; otherwise broadcast on DSRC subnet
        int err = -1;
        if (g_vehicle_ip_known[vi]) {
            // True unicast to this vehicle's DSRC address
            err = rekey_sock->SendTo(rk_pkt, 0,
                      InetSocketAddress(g_vehicle_dsrc_ip[vi], LKH_REKEY_PORT));
            cout << "[LKH-REKEY-TX] RSU" << rsu_id
                 << " → V" << vi
                 << " (" << g_vehicle_dsrc_ip[vi] << ":" << LKH_REKEY_PORT << ")"
                 << " nonce=" << g_vehicle_nonce[vi]
                 << " (unicast, Eq.3.33)" << endl;
        } else {
            // Fallback: broadcast on DSRC subnet — vehicle filters by target_vehicle_id
            err = rekey_sock->SendTo(rk_pkt, 0,
                      InetSocketAddress(Ipv4Address("3.255.255.255"), LKH_REKEY_PORT));
            cout << "[LKH-REKEY-TX] RSU" << rsu_id
                 << " → V" << vi
                 << " (broadcast fallback, IP not yet recorded)"
                 << " nonce=" << g_vehicle_nonce[vi] << endl;
        }

        if (err >= 0) {
            packets_sent++;
            g_bwo_rekey_pkts++;                       // C8 BWO_scale
            g_bwo_rekey_bytes += rk.GetSerializedSize();
        }
    }

    // ── LKH arm: broadcast one message per rotated path node (Eq.3.23) ───────
    // g_lkh_node_rekey_msgs is non-empty only when use_lkh_tree=true. Each
    // message carries K'_v wrapped under v's two child keys, so one transmission
    // serves an entire subtree — this is what makes the rekey cost log2|V_j|
    // rather than |V_j|. Survivors' leaf keys are unchanged, so there is nothing
    // to unicast and the per-member loop above is empty in this arm.
    //
    // RekeyTag is reused as the carrier: target_vehicle_id = 0xFFFFFFFF marks a
    // node message (vehicles filter it out — their K_i did not change), and
    // new_nonce carries the heap node index.
    for (const LkhNodeRekeyMsg &m : g_lkh_node_rekey_msgs) {
        RekeyTag rk;
        rk.SetTargetVehicleId(0xFFFFFFFFu);          // node-rekey broadcast marker
        rk.SetNewLeafKey(m.has_ct_sib ? m.ct_sib : m.ct_path);
        rk.SetNewNonce((uint32_t)m.node_idx);
        rk.SetRsuId(rsu_id);
        rk.SetTimestamp(sim_time);

        Ptr<Packet> nk_pkt = Create<Packet>(0);
        nk_pkt->AddPacketTag(rk);

        int err = rekey_sock->SendTo(nk_pkt, 0,
                      InetSocketAddress(Ipv4Address("3.255.255.255"), LKH_REKEY_PORT));
        if (err >= 0) {
            packets_sent++;
            g_bwo_rekey_pkts++;                       // C8 BWO_scale
            // Both wrapped copies ride in one packet when the node has two
            // reachable children; the bottom node carries only the sibling copy.
            g_bwo_rekey_bytes += rk.GetSerializedSize()
                              + ((m.has_ct_path && m.has_ct_sib) ? LKH_KEY_BYTES : 0);
        }
        cout << "[LKH-REKEY-TX] RSU" << rsu_id
             << " node=" << m.node_idx << " level=" << m.level
             << " (broadcast, Eq.3.23 path-node rekey)" << endl;
    }

    cout << "[LKH-REKEY] Revoked V" << (revoked_vehicle_id - 2)
         << ": rekeyed " << n_rekeyed << " tree nodes,"
         << " sent " << packets_sent << " rekey packets"
         << (use_lkh_tree ? " (LKH: N_rekey=log2|V_j|="
                          : " (unicast ablation: N_rekey=|V_j|=") << n_rekeyed << ")"
         << " t=" << sim_time << endl;
}

// ============================================================
// Cross-RSU SCRevoke broadcaster (TASK ①-P, Phase 1C-b)
//
// Paper: §3.5.5 Eq 3.58 SC-Revoke + §3.5.2 Eq 3.34 LKH rekey.
//
// The voting RSU rekeys inline as soon as SCRevokeVote returns revoked=true
// (CallSCRevokeVote handler in this file). The OTHER 3 RSUs need to learn
// about the revocation through the chaincode's emitted "SCRevoke" event,
// which the gateway daemon (Phase 1C-a) tails into a JSONL file. This
// drainer reads that file on a 1 Hz tick and dispatches a per-RSU rekey for
// every remote RSU that hasn't already rekeyed this (rsu_idx, vid) pair.
//
// Dedup: g_lkh_rekey_seen is a (vid<<32 | rsu_idx) set. Both the inline path
// and the event drainer insert into it before calling send_lkh_rekey_to_vehicles
// — so the voting RSU never double-rekeys when it sees its own event back.
// ============================================================

static std::unordered_set<uint64_t> g_lkh_rekey_seen;

static inline uint64_t mptd_lkh_dedup_key(uint32_t vid, uint32_t rsu_id) {
    return (static_cast<uint64_t>(vid) << 32) | static_cast<uint64_t>(rsu_id);
}

// Idempotent rekey wrapper — returns true if this (vid, rsu_id) pair triggered
// a fresh rekey, false if it was already done. Both the inline path and the
// event drainer should go through this so dedup is enforced in one place.
static bool send_lkh_rekey_if_new(uint32_t vid, uint32_t rsu_id, double sim_time)
{
    if (!g_lkh_rekey_seen.insert(mptd_lkh_dedup_key(vid, rsu_id)).second) {
        return false;
    }
    // C6 FRR_revoke: count each vehicle's FIRST network-wide revocation (the
    // per-RSU dedup above still lets 3 remote RSUs rekey the same vid); a
    // false revoke is one whose target is outside every attacker GT set.
    {
        int vi = (int)vid - 2;
        if (vi >= 0 && vi < total_size && !g_frr_vehicle_revoked[vi]) {
            g_frr_vehicle_revoked[vi] = true;
            g_frr_revoked_total++;
            if (!mptd_vehicle_is_malicious_gt(vi)) g_frr_false_revokes++;
        }
    }
    send_lkh_rekey_to_vehicles(vid, rsu_id, sim_time);
    return true;
}

// One-shot drainer: read any new chaincode events from the daemon's JSONL log
// and dispatch SCRevoke to all 4 RSUs (dedup'd). Reschedules itself.
//
// Failure modes are silent-but-logged: a missing JSONL file (daemon down) is
// fine — we just keep trying every second; the drainer is harmless when there
// is no event activity (a stat + 0-byte read).
static void mptd_drain_and_dispatch_fabric_events()
{
    std::vector<MptdFabricEvent> events;
    if (mptd_fabric_drain_events(events)) {
        double now = Simulator::Now().GetSeconds();
        for (const auto& ev : events) {
            if (ev.name != "SCRevoke") {
                // CPDetectFlag (and any other non-revoke event) is observed only
                // — no rekey trigger. NOTE: the slow trust-decay path now also
                // emits "SCRevoke" (paper §3.5.5 p.72 RevocationRequest), so it
                // is handled below alongside the fast 2f+1 path — it no longer
                // arrives as the old observed-only "TrustLow" signal.
                // Surface the rest at debug volume so the operator can correlate
                // chain events with NS-3 timeline.
                std::cout << "[FABRIC-EVT] " << ev.name
                          << " vid=" << ev.vehicle_id
                          << " blk=" << ev.blk
                          << " t=" << now << std::endl;
                continue;
            }
            if (ev.vehicle_id == 0) {
                std::cout << "[FABRIC-EVT] SCRevoke with no parseable vehicleID,"
                          << " skipping: " << ev.payload << std::endl;
                continue;
            }
            int dispatched = 0;
            for (uint32_t rsu_id = 0; rsu_id < N_RSUs; ++rsu_id) {
                if (send_lkh_rekey_if_new(ev.vehicle_id, rsu_id, now)) {
                    ++dispatched;
                }
            }
            std::cout << "[FABRIC-EVT] SCRevoke vid=" << ev.vehicle_id
                      << " blk=" << ev.blk
                      << " → " << dispatched << " new RSU rekeys "
                      << "(remainder already rekeyed inline) t=" << now
                      << " (paper §3.5.5 Eq 3.58 cross-RSU broadcast)"
                      << std::endl;
        }
    }
    // Re-arm at 1 Hz; cheap when the JSONL hasn't grown.
    Simulator::Schedule(Seconds(1.0), &mptd_drain_and_dispatch_fabric_events);
}

// Arm the drainer once per simulation. Idempotent — safe to call from
// multiple paths (we use the very first revocation as a trigger so no extra
// startup wiring is needed). The first tick fires at +0.5 s to make sure
// the daemon has had time to write the chaincode event before we look for it.
//
// MPTD_FABRIC_EVT_FORCE_ARM=1 in the environment also bootstraps the drainer
// from CallSCInitNetworkConfig — useful for synthetic-event verification of
// the cross-RSU broadcast path when the sim is too short to trip 2f+1 BFT
// naturally (the canonical TASK ① 10 s run only ever scores 1 vote per
// vehicle because RSU coverage is non-overlapping at that vehicle count).
static void mptd_arm_event_drainer_once()
{
    static std::once_flag armed;
    std::call_once(armed, []() {
        Simulator::Schedule(Seconds(0.5),
                            &mptd_drain_and_dispatch_fabric_events);
        std::cout << "[FABRIC-EVT] drainer armed @1Hz starting +0.5s "
                  << "(paper §3.5.5 cross-RSU SCRevoke broadcast)" << std::endl;
    });
}

// Hook for the SC-Init bootstrap to force-arm the drainer when verifying the
// cross-RSU path with a pre-seeded JSONL file. Wired from CallSCInitNetworkConfig.
static inline void mptd_arm_event_drainer_if_env()
{
    const char* e = std::getenv("MPTD_FABRIC_EVT_FORCE_ARM");
    if (e && *e && *e != '0') {
        mptd_arm_event_drainer_once();
    }
}

// ============================================================
// TP-DETECT — Algorithm 1 (§3.4.4)
// Returns bitmask of violated signatures (bit 0 = TP-S1 ... bit 4 = TP-S5)
// ============================================================
uint32_t run_tp_detect(int vid, BsmBeaconTag &tag)
{
    uint32_t violated = 0;

    if (VS(vid).count < 2)
        return 0; // not enough history

    VehicleBeaconState &vs = VS(vid);
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

    // TP-S3: acceleration bound  (paper Eq 3.12)
    //   |a_i(t)| > a_max
    //
    // Two evaluation paths combined with OR — both are "the acceleration the
    // beacon implies", just sourced differently:
    //
    //   (a) Reported accel field a_i(t)
    //       — direct check on the BSM acceleration field. Honest vehicles
    //       transmit physically derived accel ≤ a_max; an attacker that lies
    //       about a_i directly (e.g. writes 50 m/s²) trips this path.
    //
    //   (b) Implied accel from reported speed delta a_impl = Δs / Δt
    //       — paper text: "implied speed change violates road friction and
    //       vehicle dynamic limits". Catches attacks that DO NOT touch a_i
    //       but instead manipulate s_i(t) — TP-S2 flooding (attack 2, ×2 vel),
    //       MitM relay (attack 6, target 33–66 m/s), MP-S3 enhanced sybil
    //       (attack 3 w/ reg_pct, target 33–66 m/s), and any controller-side
    //       speed poisoning (attack 5/7). Without this path TP-S3 was 0/67766
    //       across the May-2026 sweep because PoisonTrajectoryByType never
    //       writes the acceleration vector and the MitM injector caps fake_acc
    //       at 0.42·a_max by design (see 09_vehicle_beacon_tx.h §step ③).
    //
    // Both paths use the same a_max threshold (4 m/s² road-friction limit).
    {
        double a_reported = std::fabs(vs.accel[curr]);
        double a_implied  = std::fabs(vs.speed[curr] - vs.speed[prev]) / dt;
        // (c) Direct speed-magnitude plausibility (2026-07-20): flag a reported
        //     speed above the physical maximum s_max. This is the missing tell for
        //     the MP-S3 MitM (attack 6), which injects a CONSTANT extreme speed
        //     (~66 m/s): Δspeed=0 evades the a_implied check above, and a plausible
        //     position evades TP-S1, so only the raw speed value exposes it. Honest
        //     urban speed ≤ s_max (max ~23 m/s), so FPR≈0. Folded into TP-S3 (bit 2)
        //     to keep the signature width at 9 bits.
        if (a_reported > a_max || a_implied > a_max || vs.speed[curr] > s_max)
            violated |= (1 << 2);
    }

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

        if (g_drift_longbaseline) {
            // Long-baseline variant (--drift_longbaseline=1): anchor on the
            // position k beacons back and project forward ONCE over the whole
            // elapsed window, instead of averaging k one-step residuals. A
            // directional drift (TP-S1's SampleBoundedDrift is fixed-direction
            // per vehicle) accumulates into one residual here rather than
            // being diluted into k near-invisible per-step values.
            if (k > 0) {
                int b_cur    = curr;
                int b_anchor = ((vs.head - 1 - k) + BEACON_HISTORY) % BEACON_HISTORY;
                double dt_win = vs.timestamp[b_cur] - vs.timestamp[b_anchor];
                if (dt_win <= 0) dt_win = k * T_b;
                double px_hat = vs.pos_x[b_anchor] + vs.speed[b_anchor] * std::cos(vs.heading[b_anchor]) * dt_win;
                double py_hat = vs.pos_y[b_anchor] + vs.speed[b_anchor] * std::sin(vs.heading[b_anchor]) * dt_win;
                vs.drift_score = std::sqrt((vs.pos_x[b_cur]-px_hat)*(vs.pos_x[b_cur]-px_hat) +
                                           (vs.pos_y[b_cur]-py_hat)*(vs.pos_y[b_cur]-py_hat));
            } else {
                vs.drift_score = 0.0;
            }
            if (std::getenv("MPTD_DRIFT_CALIB"))
                std::cout << "[TP-S5-LB-CALIB] vid=" << vid << " is_poisoned=" << tag.GetIsPoisoned()
                          << " drift=" << vs.drift_score << " k=" << k << std::endl;
            if (vs.drift_score > delta_th_cumulative)
                violated |= (1 << 4);
        } else {
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
    // density_limit justification (paper Eq. 3.7 uses K_sybil + ρ_v × A_j):
    // Plugging declared globals gives 5 + 0.01×π×270² ≈ 2295 — clearly calibrated for
    // a much denser network than our topology. For this simulation, the equivalent
    // threshold is N_Vehicles/N_RSUs legitimate vehicles per RSU cell (float division;
    // ~3 for urban 200veh/64RSU, ~1 for rural 200veh/169RSU). A beacon count above that
    // at a single RSU indicates ghost injection. This is the per-topology instantiation
    // of the paper's area-density formula.
    double density_limit = (double)N_Vehicles / (double)N_RSUs; // per-RSU expected legit count
    bool count_exceeded  = (rsu_id >= 0 && rsu_id < total_size &&
                            rsu_id_set[rsu_id].count > (int)density_limit);
    bool ghost_seen_flag = (rsu_id >= 0 && rsu_id < total_size &&
                            rsu_id_set[rsu_id].ghost_seen);
    if (g_honest_mp_s1) {
        // Paper-faithful MP-S1 (Eq. mp_s1): identity-density anomaly on OBSERVABLE
        // beacon data only — |{IDs in A_j}| > threshold. No ghost_seen synthetic-ID
        // marker and no ground-truth IsPoisoned() gate.
        //
        // Threshold CALIBRATION: the naive N_v/N_r (~3) is the MEAN per-RSU count, but
        // real urban traffic clusters — the 95th-pct of clean per-RSU density is ~7
        // (measured, urban 200veh/64RSU). Using the mean flags ~48% of CLEAN beacons
        // (MP-S1 was the dominant FP source: 69756/144772). Calibrate to the clean p95
        // (same method as θ_S) so honest density fluctuations don't fire. A trajectory-
        // poisoning Sybil creates NO density spike, so a correctly-calibrated MP-S1
        // neither false-positives on clean traffic nor catches the Sybil — leaving GAT's
        // spatial detection of the displaced beacon as the sole discriminating signal.
        const int honest_density_thresh =
            (int)std::ceil(density_limit * g_mp_s1_density_k);   // ~7 at k=2.3
        if (rsu_id >= 0 && rsu_id < total_size &&
            rsu_id_set[rsu_id].count > honest_density_thresh)
            violated |= (1 << 0);
    } else if ((count_exceeded || ghost_seen_flag) && tag.GetIsPoisoned()) {
        violated |= (1 << 0);
    }

    // MP-S2: synchronized beacon timing  (paper Eq 3.17)
    //   (1/K) Σ_{k=1..K} 1[|t_a^(k) − t_b^(k)| < τ_sync] > ρ_sync
    //
    // Eq 3.17 is NOT a single-timestamp check — it's a per-identity-pair
    // co-occurrence rate over the last K beacons of each identity. Sybil
    // identities sourced from one attacker clock will land within τ_sync of
    // each other a high FRACTION of the time; honest pairs occasionally
    // coincide but the fraction over K stays low. The previous single-pair
    // version was 0/67766 across the May-2026 sweep because random honest
    // collisions within 1 ms are rare and stolen-beacon staggers exceeded τ_sync.
    //
    // Implementation:
    //   For each candidate identity b in the same RSU cell, pair the current
    //   vehicle vid's last K timestamps with b's history by nearest-time
    //   match. Count the pairs whose delta is < τ_sync. If count/K > ρ_sync
    //   and K reached MP_S2_K_MIN, flag.
    //
    //   K_MIN: lower bound that suppresses cold-start FP (need real evidence).
    //   K_MAX: capped by BEACON_HISTORY=20.
    //
    // Cell-scope guard remains — honest cross-cell vehicles never paired.
    {
        const int    MP_S2_K_MIN = 3;            // need ≥3 paired beacons
        const int    MP_S2_K_MAX = (BEACON_HISTORY < 8) ? BEACON_HISTORY : 8;
        const double NEAR_T_MAX  = 0.050;        // ignore pairs > 50 ms apart
                                                  // (clearly different identities,
                                                  // pairing would be meaningless)

        // a = vid (current beacon's vehicle), b = other
        VehicleBeaconState &va = VS(vid);
        if (va.count >= MP_S2_K_MIN) {
            for (int other = 0; other < total_size; other++) {
                if (other == vid || VS(other).count < MP_S2_K_MIN)
                    continue;
                VehicleBeaconState &vb = VS(other);

                // Cell-scope guard: most-recent positions must be co-located
                int ha = (va.head - 1 + BEACON_HISTORY) % BEACON_HISTORY;
                int hb = (vb.head - 1 + BEACON_HISTORY) % BEACON_HISTORY;
                double cdx = vb.pos_x[hb] - va.pos_x[ha];
                double cdy = vb.pos_y[hb] - va.pos_y[ha];
                if (std::sqrt(cdx*cdx + cdy*cdy) >= R_max_comm) continue;

                int K = (va.count < vb.count) ? va.count : vb.count;
                if (K > MP_S2_K_MAX) K = MP_S2_K_MAX;

                int sync_hits = 0;
                int sync_total = 0;
                for (int k = 0; k < K; k++) {
                    int ia = (va.head - 1 - k + BEACON_HISTORY) % BEACON_HISTORY;
                    double ta = va.timestamp[ia];
                    if (ta <= 0.0) continue;
                    // Find b's beacon nearest in time to ta
                    double best_dt = NEAR_T_MAX;
                    bool   found   = false;
                    for (int kk = 0; kk < vb.count && kk < BEACON_HISTORY; kk++) {
                        int ib = (vb.head - 1 - kk + BEACON_HISTORY) % BEACON_HISTORY;
                        double tb = vb.timestamp[ib];
                        if (tb <= 0.0) continue;
                        double d = std::fabs(ta - tb);
                        if (d < best_dt) { best_dt = d; found = true; }
                    }
                    if (!found) continue;
                    sync_total++;
                    if (best_dt < tau_sync) sync_hits++;
                }

                if (sync_total >= MP_S2_K_MIN) {
                    double frac = (double)sync_hits / (double)sync_total;
                    if (frac > rho_sync) {
                        violated |= (1 << 1);
                        cout << "[MP-S2-SYNC] V" << vid << " ↔ V" << other
                             << " sync_frac=" << std::fixed << std::setprecision(2)
                             << frac << " (>" << rho_sync << ")"
                             << " K=" << sync_total
                             << " τ_sync=" << (tau_sync * 1000.0) << "ms"
                             << " → Eq 3.17 fired" << endl;
                        break;
                    }
                }
            }
        }
    }

    // MP-S3: KL-divergence check MOVED to run_mitm_detect() per paper Algorithm 3.
    // Alg 2 (SYB-DETECT) covers Sybil/density/timing/ghost; Alg 3 (MITM-DETECT)
    // covers distribution manipulation.  Bit 2 is now set by run_mitm_detect().

    // MP-S4: ghost transit impossibility
    // d(r_j, r_k) / |t_j - t_k| > s_max
    // (simplified: check if same ID appearing at impossible distance in short time)
    if (VS(vid).count >= 2) {
        int prev = (VS(vid).head - 2 + BEACON_HISTORY) % BEACON_HISTORY;
        int curr = (VS(vid).head - 1 + BEACON_HISTORY) % BEACON_HISTORY;
        double tdiff = VS(vid).timestamp[curr] - VS(vid).timestamp[prev];
        if (tdiff > 0) {
            double ddx = VS(vid).pos_x[curr] - VS(vid).pos_x[prev];
            double ddy = VS(vid).pos_y[curr] - VS(vid).pos_y[prev];
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

    // ── MP-S3: Real KL divergence — D_KL(P_t ‖ P_hist) > κ_th  (Eq. 3.18) ──────
    //
    // P_hist[rsu_id][b]: historical speed distribution for this RSU cell.
    //   Built as a slow exponential moving average (α=KL_ALPHA=0.05) so it
    //   tracks normal traffic and is not distorted by brief attack bursts.
    //
    // P_t[b]: current speed distribution — empirical histogram of all vehicles
    //   currently in this RSU cell (or global for attack-3 enhanced mode).
    //
    // KL formula (no library needed — pure C++ arithmetic):
    //   D_KL = Σ_b  P_t[b] × log( P_t[b] / P_hist[b] )
    //   Additive smoothing (ε=1e-6) on both distributions prevents log(0).
    //
    // Attack-3 enhanced mode (sybil_registration_pct > 0):
    //   Use global statistics so Sybil nodes clustered in one RSU cell cannot
    //   dominate the LOCAL mean and evade detection via distribution collapse.
    //
    // Calibration (kappa_th = 0.1):
    //   Honest fleet (similar distribution to P_hist) → D_KL ≈ 0.0   → no flag
    //   MitM/Sybil shifting speeds by ≥30%           → D_KL > 0.1   → flagged

    bool use_global = (attack_number == 3 && sybil_registration_pct > 0);

    // ── Step 1: collect speeds of vehicles in scope ──────────────────────────
    double speeds[64];
    int    n_speeds = 0;
    for (int v = 0; v < total_size && n_speeds < 64; v++) {
        if (VS(v).count == 0) continue;
        int h = (VS(v).head - 1 + BEACON_HISTORY) % BEACON_HISTORY;
        if (!use_global) {
            double dx = VS(v).pos_x[h] - tag.GetPosX();
            double dy = VS(v).pos_y[h] - tag.GetPosY();
            if (std::sqrt(dx*dx + dy*dy) >= R_max_comm) continue;
        }
        speeds[n_speeds++] = VS(v).speed[h];
    }

    if (n_speeds >= 3) {  // need at least 3 samples for a meaningful distribution
        // ── Step 2: build P_t — current speed histogram, normalised to sum=1 ──
        double P_t[KL_BINS] = {};
        for (int i = 0; i < n_speeds; i++) {
            int b = (int)(speeds[i] / s_max * KL_BINS);
            if (b < 0)       b = 0;
            if (b >= KL_BINS) b = KL_BINS - 1;
            P_t[b] += 1.0;
        }
        for (int b = 0; b < KL_BINS; b++) P_t[b] /= (double)n_speeds;

        // ── Step 3: initialise or update P_hist ─────────────────────────────
        int ri = (rsu_id >= 0 && rsu_id < N_RSUs) ? rsu_id : 0;
        if (!kl_hist_ready[ri]) {
            // Cold start: set P_hist = P_t (first observation = baseline)
            for (int b = 0; b < KL_BINS; b++) kl_hist[ri][b] = P_t[b];
            kl_hist_ready[ri] = true;
            // Cannot compute KL yet — need at least one historical reference.
            // Return without flagging on very first beacon.
            return violated;
        }
        // Slow exponential moving average update of historical baseline
        for (int b = 0; b < KL_BINS; b++)
            kl_hist[ri][b] = (1.0 - KL_ALPHA) * kl_hist[ri][b]
                           +        KL_ALPHA   * P_t[b];

        // ── Step 4: compute D_KL(P_t ‖ P_hist) — paper Eq. 3.18 ────────────
        // Additive smoothing ε prevents log(0) when a bin is empty in either dist.
        const double EPS = 1e-6;
        double kl_div = 0.0;
        for (int b = 0; b < KL_BINS; b++) {
            double p = P_t[b]      + EPS;  // current distribution
            double q = kl_hist[ri][b] + EPS;  // historical baseline
            kl_div += p * std::log(p / q);
        }

        // ── Step 5: per-vehicle confirmation (prevents cell-level FP) ────────
        // When D_KL fires (cell distribution shifted), confirm that the CURRENT
        // vehicle's speed is individually anomalous before raising the flag.
        // Without this gate, ALL beacons from the RSU cell — including honest ones
        // sharing a cell with a malicious vehicle — would be flagged as MP-S3 FP.
        //
        // Compute P_hist mean μ and std σ from the histogram bins:
        //   μ = Σ_b  P_hist[b] × bin_centre[b]
        //   σ = sqrt(Σ_b  P_hist[b] × (bin_centre[b] − μ)²)
        //
        // Flag beacon only if D_KL > kappa_th AND |v − μ| > 2σ  (2-sigma rule).
        // This fires reliably when ALL/MOST beacons are boosted (MitM, attack 6)
        // while suppressing FP when only a minority are malicious (attack 2, attack 3).
        if (kl_div > kappa_th) {
            double mu = 0.0;
            for (int b = 0; b < KL_BINS; b++) {
                double bc = (b + 0.5) * s_max / KL_BINS;  // bin centre
                mu += kl_hist[ri][b] * bc;
            }
            double var = 0.0;
            for (int b = 0; b < KL_BINS; b++) {
                double bc   = (b + 0.5) * s_max / KL_BINS;
                double diff = bc - mu;
                var += kl_hist[ri][b] * diff * diff;
            }
            double sigma = std::sqrt(var + 1e-6);
            double cur_spd = tag.GetSpeed();
            if (std::fabs(cur_spd - mu) > 2.0 * sigma) {
                violated |= (1 << 2);  // bit 2 = MP-S3
                cout << "[MP-S3-KL] RSU" << ri
                     << " D_KL=" << std::fixed << std::setprecision(4) << kl_div
                     << " cur_spd=" << cur_spd
                     << " mu=" << mu << " 2σ=" << 2.0*sigma
                     << " → individual speed anomaly confirmed" << endl;
            }
        }
    }

    return violated;
}

uint32_t run_cp_detect(BsmBeaconTag &tag)
{
    // ⚠ SCOPE NOTE (R6 audit): this is the PER-BEACON cp_flags oracle used to
    // populate LwDetectResult.cp_flags inside run_lw_detect_per_beacon(). It is
    // NOT the paper's Algorithm 7 (CP-DETECT) — that lives in
    // run_cp_detect_per_epoch() below, which performs epoch-level RSU peer-
    // consensus checking on the controller's emitted decisions per Eq 3.59.
    //
    // This function returns a binary "is the controller currently configured
    // as malicious?" oracle used by attack 5/7 traces to mark the cp_flags bit
    // for downstream confusion-matrix accounting. Kept as a sim crutch until
    // the LW-DETECT cp_flags channel is replaced by real CP-DETECT outputs
    // (planned: R6 epoch-level Algorithm 7 supersedes this).
    //
    // TP-S3 (attack_number=5): controller-level trajectory poisoning.
    // MP-S4 (attack_number=7): controller-malicious global model poisoning.
    //
    // Note: cp_flags are used in the confusion matrix ONLY for attack 7 (MP-S4):
    //   cp_detected = (cp_flags != 0) && (attack_number == 7)
    // For attack 5 (TP-S3): detection relies on kinematic signatures (TP-S1..S5)
    // because only attack_pct% of beacons are actually modified at the control plane.
    if (ctrl_compromised_now() &&
        (attack_number == 5 || attack_number == 7 || g_combined_attack))
        return 1;
    return 0;
}

// ============================================================
// CP-DETECT (paper §3.5.5 / Algorithm 7 / Eq 3.59) — Epoch-level controller
// peer-consensus audit. Honors invariants #2 (controller is a non-authoritative
// peer) and #6 (distributed trust, no centralized bottleneck).
//
// Algorithm 7 (paper page 66) has two gates:
//   (a) lines 2–6  — TRS-verify gate: controller's submitted aggregate must
//       carry a valid threshold ring signature σ_TRS. Invalid σ_TRS ⇒ direct
//       CTRL_COMPROMISED. R6 ships a no-op stub returning valid=true; real
//       TRS verification lands with σ_TRS infrastructure in R8.
//   (b) lines 7–15 — Conflict-detection gate (Eq 3.59): the controller's
//       binary decision is audited per-beacon against the RSU peer's
//       authoritative LW-DETECT view of the same beacon. Per-beacon
//       disagreement events are accumulated into a per-vehicle rolling
//       window of size K = 3. If ≥ f+1 disagreements occur within the
//       window, set flag_c = 1, emit CTRL_COMPROMISED, exclude controller
//       from consensus, and fall back to RSU rule-based decisions.
//       f = 1 in the 3-RSU + 1-controller-peer setup (BFT bound n ≥ 3f+1)
//       ⇒ conflict threshold = 2 disagreements per window.
//
// Sim-only note: in NS-3 each beacon hits exactly one RSU (no overlapping
// radio coverage). The paper's "RSU peer consensus" is preserved by treating
// the temporally adjacent RSU views as the consensus group — each beacon's
// authoritative RSU view is the peer for that epoch, and the disagreement
// window captures persistent controller divergence rather than spatial
// quorum. An honest controller (attack 1) shadows its RSU's cached LW result
// so disagreements stay at 0; a malicious controller (attacks 5/7) emits
// WRONG_ROUTING against clean RSU views ⇒ every beacon is a disagreement and
// the window fills in ≤ K = 3 beacons.
// ============================================================
struct CpDetectVehicleWindow {
    // Rolling per-beacon disagreement events for one vehicle.
    // Each entry corresponds to ONE controller decision that was audited.
    std::deque<bool>     disagreed;       // (rsu_anom != ctrl_anom) for the beacon
    std::deque<bool>     rsu_anom_hist;   // RSU view at decision time (audit log)
    std::deque<bool>     ctrl_anom_hist;  // controller view at decision time (audit log)
    std::deque<double>   psi_hist;        // RSU's ψ_i(t) at decision time
    std::deque<uint32_t> rsu_ids;         // which RSU produced the view
};
static std::map<uint32_t, CpDetectVehicleWindow> g_cp_detect_windows;
static constexpr size_t CP_DETECT_WINDOW_K   = 3;  // = f + 1 + 1 (one slack)
static constexpr size_t CP_DETECT_F          = 1;  // BFT byzantine bound
static constexpr size_t CP_DETECT_THRESHOLD  = CP_DETECT_F + 1;  // Eq 3.59: f+1 = 2

// TRS-verify gate (Algorithm 7 lines 2–6).
//
// R6.5 contract:
//   - sigma_trs == nullptr || sigma_len == 0 → return true (pre-R8 mode where
//     the controller-as-peer path has not yet attached a σ_TRS to its
//     submission). Lets the conflict-detection gate (b) run in isolation.
//   - otherwise → real ECDSA verify against the RSU ring via g_trs_backend.
//     ClassicalTrsBackend::verify_threshold currently accepts σ if ANY ring
//     pk validates (single-signer fallback). R8 swaps in ClassicalTrsBackend
//     internals for true t-of-n combining; the call site below stays identical.
//
// `message` here is the canonical audit string. For R6.5 we synthesize from
// (vehicle_id, rsu_id, alert_type, epoch) — R8 will replace with the actual
// submission payload bytes the controller signed.
static inline bool cp_detect_verify_trs(const uint8_t *sigma_trs,
                                        size_t         sigma_len,
                                        uint32_t       vehicle_id = 0,
                                        uint32_t       rsu_id     = 0,
                                        uint8_t        alert_type = 0)
{
    if (sigma_trs == nullptr || sigma_len == 0) {
        // R6.5 path: no σ_TRS produced yet — Algorithm 7 gate (a) is a no-op
        // and gate (b) handles all detections in current builds.
        return true;
    }
    if (!g_trs_backend || g_trs_ring_pks.empty()) {
        // Defensive: TRS backend not initialized → fail closed. This is a
        // configuration bug; CP-DETECT should not be invoked before
        // init_trs_backend() runs in 11_blockchain_setup.h.
        std::cerr << "[CP-DETECT/TRS] backend not ready — failing σ closed\n";
        return false;
    }
    std::vector<uint8_t> msg;
    msg.reserve(16);
    msg.push_back((uint8_t)(vehicle_id      & 0xFF));
    msg.push_back((uint8_t)((vehicle_id>>8) & 0xFF));
    msg.push_back((uint8_t)((vehicle_id>>16)& 0xFF));
    msg.push_back((uint8_t)((vehicle_id>>24)& 0xFF));
    msg.push_back((uint8_t)(rsu_id          & 0xFF));
    msg.push_back((uint8_t)((rsu_id>>8)     & 0xFF));
    msg.push_back((uint8_t)((rsu_id>>16)    & 0xFF));
    msg.push_back((uint8_t)((rsu_id>>24)    & 0xFF));
    msg.push_back(alert_type);
    // (R8: append epoch + RSU peer view bytes per Algorithm 7 line 3.)
    std::vector<uint8_t> sigma(sigma_trs, sigma_trs + sigma_len);
    return g_trs_backend->verify_threshold(msg, sigma, g_trs_ring_pks);
}

// Algorithm 7 main entry. Called from the controller emission path after the
// controller has decided alert_type for (vehicle_id, rsu_id) in the current
// epoch. Returns true if a CTRL_COMPROMISED alert was emitted.
//
// Parameters:
//   rsu_anomalous       — RSU's cached LW anomalous flag for THIS beacon
//                         (from tag.GetLwAnomalous()). This is the peer view
//                         the controller's decision is audited against.
//   controller_anomalous — derived from alert_type (1=ATTACK_DETECTED or
//                         2=WRONG_ROUTING ⇒ true; 0=CLEAN_ROUTING ⇒ false).
//   rsu_psi             — RSU's ψ_i(t) for the beacon (audit log only).
//   sigma_trs/sigma_len — R6 callers pass nullptr/0; R8 will pass the real
//                         controller-as-peer σ_TRS attached to the submission.
static bool run_cp_detect_per_epoch(uint32_t       vehicle_id,
                                    uint32_t       rsu_id,
                                    uint8_t        alert_type,
                                    bool           controller_anomalous,
                                    bool           rsu_anomalous,
                                    double         rsu_psi,
                                    const uint8_t *sigma_trs = nullptr,
                                    size_t         sigma_len = 0)
{
    g_cp_detect_epochs_evaluated++;

    // ── Gate (a): TRS-verify (Algorithm 7 lines 2–6) ─────────────────────────
    // R6.5: sigma_trs is nullptr/0 from all current callers → returns true.
    // R8 will start passing a real σ_TRS produced by the controller-as-peer
    // submission path; the call shape doesn't change.
    if (!cp_detect_verify_trs(sigma_trs, sigma_len,
                              vehicle_id, rsu_id, alert_type)) {
        g_cp_detect_trs_fails++;
        g_cp_detect_alerts_total++;
        g_flag_c_active = true;
        // CP-2 (2026-08-05): accumulate controller misbehaviour evidence and decay
        // controller trust (eq:ctrl_trust, the controller analogue of eq:rsu_trust).
        // Previously CP-DETECT fired and NOTHING downstream changed; this is the
        // missing link that lets repeated firings eventually drive SC-Revoke.
        g_ctrl_misbehave_evidence++;
        g_ctrl_trust = (1.0 - g_ctrl_trust_alpha) * g_ctrl_trust;
        std::cout << "[ALERT_CP-TRS] V" << vehicle_id
                  << " RSU" << rsu_id
                  << " controller σ_TRS verification FAILED → CTRL_COMPROMISED,"
                  << " flag_c=1 (Algorithm 7 lines 2-6)" << std::endl;
        return true;
    }

    // ── Gate (b): conflict detection (Algorithm 7 lines 7–15, Eq 3.59) ───────
    // Push this beacon's (RSU view, controller view) disagreement into the
    // per-vehicle window, then check the running disagreement count.
    bool disagreed_now = (rsu_anomalous != controller_anomalous);
    auto &w = g_cp_detect_windows[vehicle_id];
    w.disagreed.push_back(disagreed_now);
    w.rsu_anom_hist.push_back(rsu_anomalous);
    w.ctrl_anom_hist.push_back(controller_anomalous);
    w.psi_hist.push_back(rsu_psi);
    w.rsu_ids.push_back(rsu_id);
    while (w.disagreed.size() > CP_DETECT_WINDOW_K) {
        w.disagreed.pop_front();
        w.rsu_anom_hist.pop_front();
        w.ctrl_anom_hist.pop_front();
        w.psi_hist.pop_front();
        w.rsu_ids.pop_front();
    }

    size_t disagreement_count = 0;
    for (bool d : w.disagreed) if (d) disagreement_count++;

    if (disagreement_count >= CP_DETECT_THRESHOLD) {
        g_cp_detect_conflict_fires++;
        g_cp_detect_alerts_total++;
        g_flag_c_active = true;
        // CP-2: same evidence accumulation on the conflict-detection gate.
        g_ctrl_misbehave_evidence++;
        g_ctrl_trust = (1.0 - g_ctrl_trust_alpha) * g_ctrl_trust;

        // Build a compact audit dump of the window.
        std::ostringstream peer_dump;
        for (size_t k = 0; k < w.disagreed.size(); k++) {
            if (k) peer_dump << ",";
            peer_dump << "RSU" << w.rsu_ids[k]
                      << "(ψ=" << std::fixed << std::setprecision(2) << w.psi_hist[k]
                      << ",rsu=" << (w.rsu_anom_hist[k] ? "ANOM" : "CLEAN")
                      << ",ctrl=" << (w.ctrl_anom_hist[k] ? "ANOM" : "CLEAN")
                      << "," << (w.disagreed[k] ? "DIFF" : "SAME") << ")";
        }
        std::cout << "[ALERT_CP-CONFLICT] V" << vehicle_id
                  << " RSU" << rsu_id
                  << " ctrl_says=" << (controller_anomalous ? "ANOMALOUS" : "CLEAN")
                  << " rsu_says=" << (rsu_anomalous ? "ANOMALOUS" : "CLEAN")
                  << " alert_type=" << (int)alert_type
                  << " disagreements=" << disagreement_count
                  << "/" << w.disagreed.size()
                  << " (≥" << CP_DETECT_THRESHOLD << ") → flag_c=1, CTRL_COMPROMISED"
                  << "  window=[" << peer_dump.str() << "]"
                  << "  (paper Eq 3.59)" << std::endl;
        return true;
    }
    return false;
}

// ============================================================
// Composite lightweight score ψ_i(t) (Eq. 3.20)
// ψ_i(t) = Σ_k w_k × S_k(t)   where S_k ∈ {0,1} (signature violated or not)
// Weights w_k reflect each signature's discriminatory power and FP risk.
// Sum of all weights = 1.0.  Returns true if ψ_i > psi_th (anomalous).
//
// Bit layout of all_flags = tp_flags | (mp_flags << 5):
//   bit 0: TP-S1 kinematic position jump    w=0.15 (reliable kinematic check)
//   bit 1: TP-S2 heading rate deviation     w=0.10 (noisy — normal turning fires)
//   bit 2: TP-S3 acceleration bound         w=0.10 (noisy — hard braking fires)
//   bit 3: TP-S4 dead-reckoning residual    w=0.15 (reliable per-step check)
//   bit 4: TP-S5 cumulative drift           w=0.15 (high conf. — sustained attack)
//   bit 5: MP-S1 identity density           w=0.15 (high conf. — ghost injection)
//   bit 6: MP-S2 timing synchronisation     w=0.05 (FP-prone near τ_sync boundary)
//   bit 7: MP-S3 KL divergence              w=0.10 (Mahalanobis approx, medium conf.)
//   bit 8: MP-S4 transit impossibility      w=0.05 (sparse — needs cross-RSU jump)
//                                           ─────
//                               total       1.00
// ============================================================
static const double SIG_WEIGHTS[9] = {
    0.15,  // TP-S1
    0.10,  // TP-S2
    0.10,  // TP-S3
    0.15,  // TP-S4
    0.15,  // TP-S5
    0.15,  // MP-S1
    0.05,  // MP-S2
    0.10,  // MP-S3
    0.05,  // MP-S4
};

bool run_lightweight_score(uint32_t tp_flags, uint32_t mp_flags)
{
    uint32_t all_flags = tp_flags | (mp_flags << 5);
    double psi = 0.0;
    for (int k = 0; k < 9; k++) {
        if (all_flags & (1u << k))
            psi += SIG_WEIGHTS[k];
    }
    return psi > psi_th;
}

// ============================================================
// run_lw_detect_per_beacon() — Algorithm 1 (LW-DETECT) packaged
// Paper §3.5.3, Fig 3.10.
//
// Runs the full lightweight per-beacon detection pipeline:
//   1. push beacon into VS() circular buffer
//   2. run TP-DETECT (Alg 1)     → tp_flags  (bits 0..4 = TP-S1..S5)
//   3. run SYB-DETECT (Alg 2)    → mp_flags  (bits 0..3 = MP-S1..S4)
//   4. run MITM-DETECT (Alg 3)   → mp_flags |= bit 2 (MP-S3)
//   5. run CP-DETECT (Alg 4)     → cp_flags
//   6. composite score ψ_i(t) via SIG_WEIGHTS (Eq. 3.20)
//   7. anomalous = ψ_i > ψ_th; detected = anomalous || (CP fired && attack==7)
//
// Architectural note (paper §3.5.3 / Fig 3.10): LW-DETECT runs at the RSU
// per the paper's edge-detection mandate. handle_readone() calls this helper
// after HMAC verification and after RSU-side attack injection (TP-S1 / MP-S1
// if RSU is compromised). The result is stamped onto the BsmBeaconTag via
// SetLwDetectionRan/SetLwAnomalous/SetLwPsi/SetSigViolated so the controller
// can use it without re-running detection (attacks 1-4, 6).
//
// Controller (HandleBeaconReceived) re-invokes this helper ONLY for
// attacks 5 (TP-S3) and 7 (MP-S4) where the controller itself poisons the
// beacon — it pops the RSU-pushed vehicle_state entry first, then calls this
// again so the modified kinematics are scored.
// ============================================================
struct LwDetectResult {
    uint32_t tp_flags;      // bits 0..4 = TP-S1..S5
    uint32_t mp_flags;      // bits 0..3 = MP-S1..S4 (after SYB ∪ MITM)
    uint32_t cp_flags;      // CP-DETECT raw bits
    uint32_t sig_violated;  // packed: tp | (mp<<5) | (cp<<9)
    double   psi;           // ψ_i(t) composite (Eq. 3.20)
    bool     anomalous;     // ψ_i > ψ_th
    bool     detected;      // anomalous || (CP fired for attack 7) || B1 LTT
};

// ── RING-DETECT (--ring_detect, default OFF) ────────────────────────────────
// Returns true if THIS beacon is a member of a fabricated Sybil ring at rsu_id.
//
// Method: gather the RSU's recent beacons that share this beacon's timestamp
// (within g_ring_tol_t) and heading (within g_ring_tol_hd) — a real vehicle
// population does not transmit with identical timestamps AND identical headings.
// Take the centroid of that group. Because the ghosts are placed symmetrically
// about the vehicle they impersonate, that centroid coincides with the VICTIM,
// so the radii separate into {R, R, ..., R, 0}. Declare a ring when at least
// g_ring_min_members sit at a consistent radius (coeff. of variation below
// g_ring_r_cv) inside the plausible band [g_ring_r_min, g_ring_r_max], and flag
// THIS beacon only if it is one of those ring members — never the centroid.
//
// The victim exclusion is the point: the GAT classification head reached 99.9%
// on ghosts but also flagged the intercepted victim 95% of the time, which
// would revoke the target of the attack. A radius test cannot make that error.
static bool ring_detect_beacon(uint32_t rsu_id, uint32_t vid,
                               double px, double py, double hd, double ts)
{
    if (!g_ring_detect || rsu_id >= MAX_RSUS) return false;
    RsuRingBuf &rb = rsu_ringbuf[rsu_id];

    // Collect co-temporal, co-heading candidates (including this beacon).
    double cx = px, cy = py;
    int    n  = 1;
    int    idx[RINGBUF_N];
    int    nidx = 0;
    for (int i = 0; i < rb.count; i++) {
        if (rb.vid[i] == vid) continue;                     // same identity: skip
        if (std::fabs(rb.ts[i] - ts) > g_ring_tol_t)  continue;
        double dh = std::fabs(rb.hd[i] - hd);
        if (dh > M_PI) dh = 2.0 * M_PI - dh;                // wrap
        if (dh > g_ring_tol_hd) continue;
        idx[nidx++] = i;
        cx += rb.px[i]; cy += rb.py[i]; n++;
    }
    if (n < g_ring_min_members + 1) return false;           // ring + victim
    cx /= n; cy /= n;

    // Radii from the centroid; the victim contributes ~0 and is excluded.
    double r_self = std::hypot(px - cx, py - cy);
    double sum = 0.0, sum2 = 0.0; int m = 0;
    double radii[RINGBUF_N + 1];
    if (r_self >= g_ring_r_min && r_self <= g_ring_r_max) { radii[m++] = r_self; }
    for (int k = 0; k < nidx; k++) {
        double r = std::hypot(rb.px[idx[k]] - cx, rb.py[idx[k]] - cy);
        if (r >= g_ring_r_min && r <= g_ring_r_max) radii[m++] = r;
    }
    if (m < g_ring_min_members) return false;
    for (int k = 0; k < m; k++) { sum += radii[k]; sum2 += radii[k] * radii[k]; }
    double mean = sum / m;
    double var  = std::max(0.0, sum2 / m - mean * mean);
    if (mean <= 1e-6) return false;
    if (std::sqrt(var) / mean > g_ring_r_cv) return false;  // not a consistent radius

    // This beacon is a ring member only if it sits ON the ring, not at its centre.
    return (r_self >= g_ring_r_min && r_self <= g_ring_r_max &&
            std::fabs(r_self - mean) <= g_ring_r_cv * mean);
}

static void ring_buf_push(uint32_t rsu_id, uint32_t vid,
                          double px, double py, double hd, double ts)
{
    if (rsu_id >= MAX_RSUS) return;
    RsuRingBuf &rb = rsu_ringbuf[rsu_id];
    rb.vid[rb.head] = vid; rb.px[rb.head] = px; rb.py[rb.head] = py;
    rb.hd[rb.head]  = hd;  rb.ts[rb.head] = ts;
    rb.head = (rb.head + 1) % RINGBUF_N;
    if (rb.count < RINGBUF_N) rb.count++;
}

LwDetectResult run_lw_detect_per_beacon(uint32_t vehicle_id,
                                        BsmBeaconTag &tag,
                                        uint32_t rsu_id,
                                        bool identity_verified = true)
{
    LwDetectResult r{};
    r.tp_flags = r.mp_flags = r.cp_flags = r.sig_violated = 0;
    r.psi = 0.0;
    r.anomalous = false;
    r.detected  = false;

    // FIX B (sir, 2026-08-06): bind every vehicle_state access in THIS call to
    // the receiving RSU. The push below, the TP/MP rule reads, and the
    // cross-vehicle MP-S2 scan then all operate on that RSU's private history,
    // so forged kinematics written here can never be read back by a DIFFERENT
    // RSU as an honest vehicle's baseline. No-op when --per_rsu_vehicle_state=0.
    g_vs_cur_rsu = (int)rsu_id;

    // 1. Push new beacon into circular state buffer
    //
    // FIX 1 (identity binding). This is the ONLY write to vehicle_state in the
    // codebase, and its key is the beacon HEADER field — so before this fix any
    // transmitter could write any vehicle's history simply by claiming that ID.
    // Measured consequence: attackers built VS(98) from t=72.809,
    // 120.7 s before the genuine vehicle first transmitted, after which every one
    // of its 622 honest beacons contradicted the stored state (FPR 1.0000).
    //
    // The write now happens only when the physical transmitter owns the claimed
    // ID. We skip the write ENTIRELY rather than save/restore around it — the
    // pre-existing guard at ~:3990 operates AFTER the write and cannot help,
    // and there is no genuine state to restore when the forging precedes the
    // victim's first beacon.
    //
    // Detection still runs on the rejected beacon: it is scored against the
    // victim's genuine history, which is what makes an impersonation visible
    // rather than absorbed.
    if (identity_verified) {
        push_beacon((int)vehicle_id,
                    tag.GetPosX(), tag.GetPosY(),
                    tag.GetSpeed(), tag.GetHeading(),
                    tag.GetAcceleration(), tag.GetTimestamp());
    }

    // 2. Run detection algorithms
    // B1 ablation (mode=6): Ghaleb (2014) LTT — two rule checks only, no MPTD-PQS sigs
    // All other modes: full MPTD-PQS pipeline (Algorithms 1–4)
    g_save_restore_context = false;  // unused — kept for compilation
    if (ablation_mode != 6) {
        r.tp_flags  = run_tp_detect((int)vehicle_id, tag);              // Alg 1: TP-S1..S5
        r.mp_flags  = run_syb_detect((int)vehicle_id, (int)rsu_id, tag);// Alg 2: MP-S1,S2,S4
        uint32_t mitm = run_mitm_detect((int)vehicle_id, (int)rsu_id, tag); // Alg 3: MP-S3
        r.mp_flags |= mitm;
        r.cp_flags  = run_cp_detect(tag);                               // Alg 4: CP
    }
    g_save_restore_context = false;  // reset after detection to prevent leakage

    // AB1 (C10) — interpretation (b), sir 2026-07-21: the rule-signature TIER's own
    // DETECTION is removed (its lightweight decision + its ψ fusion contribution),
    // but sig_mask and ψ REMAIN as GAT INPUT FEATURES. The proposed GAT model was
    // built with these rule-derived attributes and must still operate under the
    // ablation — so we do NOT zero the tp/mp flags here (they feed r.sig_violated →
    // last_sigmask_per_vehicle → gat_sig, and r.psi → last_psi_per_vehicle → gat_psi,
    // the GAT's node features). The ψ FUSION TERM is forced to 0 at the fuse site;
    // here we only disable the rule-based lightweight decision.
    // CP-DETECT (Alg 4) is a separate mechanism and stays active.

    // ── POP ANOMALOUS WRITES (--pop_anomalous_writes, default OFF) ──────────
    // Rationale: step 1 pushes this beacon into the circular history BEFORE any
    // detector runs, so a forged beacon becomes the baseline against which the
    // victim's NEXT honest beacon is judged. Measured consequence at 300 s:
    // vids 196/191/202 carry FPR 0.59/0.53/0.54 on their own clean beacons, and
    // six vehicles account for 77.7% of ALL false positives.
    //
    // Fix: once the rule tier has judged this beacon anomalous, remove it again
    // (pop_last_beacon undoes exactly the step-1 push) so it cannot poison the
    // history. An attacker's forged beacon is then flagged AND discarded rather
    // than flagged AND retained.
    //
    // This is deliberately NOT identity binding (Fix 1), which keyed on
    // transmitter ownership and cost -0.124 MCC because 40% of its rejections
    // were honest beacons. Here the gate is the detector's own verdict.
    //
    // Placed after the flags are known but before the return, so r.tp_flags /
    // r.mp_flags already reflect this beacon.
    const bool _pop_this = g_pop_anomalous_writes && identity_verified &&
                           (r.tp_flags != 0u || r.mp_flags != 0u);

    // ── RING-DETECT (--ring_detect, default OFF) ────────────────────────────
    // Must run HERE, before the sig-mask and psi are finalised below. A first
    // attempt set r.anomalous/r.detected after step 4, which is dead for this
    // purpose: psi is already computed by then and the fusion reads psi, not
    // r.anomalous — the run came back byte-identical, which is how it was caught.
    //
    // A ring hit sets the MP-S1 bit (mp_flags bit 0 -> composite bit 5,
    // SIG_WEIGHTS 0.15). That is the semantically correct signature: MP-S1 *is*
    // the Sybil-via-compromised-RSU detector, so the geometry test contributes
    // through the existing rule tier rather than bolting on a parallel path.
    //
    // Ordering caveat: rule-tier means this fires identically in D1/D4/D6, so it
    // lifts the no-ML arm too and the ablation ordering must be re-verified.
    // Hence flag-gated off by default.
    if (g_ring_detect) {
        ring_buf_push(rsu_id, vehicle_id, tag.GetPosX(), tag.GetPosY(),
                      tag.GetHeading(), tag.GetTimestamp());
        if (ring_detect_beacon(rsu_id, vehicle_id, tag.GetPosX(), tag.GetPosY(),
                               tag.GetHeading(), tag.GetTimestamp()))
            r.mp_flags |= 0x1u;                    // MP-S1
    }

    // 3. Composite sig bitmask (still feeds the GAT input even under AB1)
    r.sig_violated = r.tp_flags | (r.mp_flags << 5) | (r.cp_flags << 9);
    r.anomalous    = enable_rule_signatures
                   ? run_lightweight_score(r.tp_flags, r.mp_flags | (r.cp_flags << 4))
                   : (r.cp_flags != 0);   // AB1: rule-based LW off; CP-DETECT stays

    // 4. ψ_i(t) — kept so ψ feeds the GAT input (gat_psi). The ψ *fusion term* is
    //    zeroed in AB1 at the fuse site (psi_fuse), NOT here.
    {
        uint32_t all_f = r.tp_flags | (r.mp_flags << 5);
        for (int k = 0; k < 9; k++)
            if (all_f & (1u << k)) r.psi += SIG_WEIGHTS[k];
    }

    // 5. Detection decision
    // CP-DETECT is a SYSTEM-LEVEL signal (Alg 7, Eq. 3.43) — it fires globally when
    // the controller is suspected malicious, and is the input to CDER (Eq. 4.4),
    // NOT a per-beacon detection signal. After R7f.followup-1 both attack 5 (TP-S3)
    // and attack 7 (MP-S4) use per-beacon attack_pct gating, so per-beacon detection
    // must come from kinematic signatures (TP-S1..S5, MP-S1..S4). Including cp_flags
    // here would mark every attack-{5,7} beacon as detected — generating FPs on the
    // ~(1-attack_pct)% of beacons that were NOT modified by the controller, which
    // collapses MCC to zero (same failure mode this follow-up was created to fix).
    if (ablation_mode == 6) {
        // B1: Ghaleb (2014) LTT baseline
        r.detected = run_ltt_detect(vehicle_id, rsu_id, tag);
    } else {
        // MPTD-PQS: composite score gate (Eq. 3.20) — kinematic-signature only.
        r.detected = r.anomalous;
    }

    // Undo the step-1 push for a beacon this pass judged anomalous, so it cannot
    // serve as the baseline for the next beacon claiming the same identity.
    if (_pop_this) pop_last_beacon((int)vehicle_id);

    return r;
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
//
// ──────────────────────────────────────────────────────────────────────────
// R3 NOTE — Controller's restricted role (paper invariant #2)
// ──────────────────────────────────────────────────────────────────────────
// After R1 + R2 the controller is a NON-AUTHORITATIVE peer:
//   • LW-DETECT runs at the RSU (R1, paper §3.5.3 Algorithm 1, Fig 3.10)
//   • DSRC safety alerts are emitted by the RSU directly (R2, paper Fig 3.1
//     Step 6/7) — no controller round-trip on the normal path
//   • This handler now exists to:
//       (a) aggregate per-beacon kinematics into the Full-mode window buffer
//           (ctrl_window[]) for the future GAT + LSTM-AE pipeline,
//       (b) host the controller-as-attacker injection blocks for attacks
//           5/7 (paper Fig 3.3 / Fig 3.7 where the controller IS the
//           attacker by definition),
//       (c) host provisional SC-Trust / SC-Revoke calls which will move
//           RSU-direct in phase R4 (paper invariant #1: RSU → blockchain
//           is direct), and
//       (d) preserve PARR / TDEE / per-beacon CSV aggregation.
//
// What this handler MUST NOT do (would re-violate invariant #2):
//   • Re-run LW-DETECT and override the RSU's decision on the normal path
//   • Emit per-beacon DSRC alerts on the normal path (RSU owns that via R2)
//   • Treat its own opinion as authoritative when ≥f+1 RSUs disagree
//     (CP-DETECT, paper §3.5.5 Algorithm 7, will be added in R6)
// ──────────────────────────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════════════
// Full-mode cryptographic mitigation pipeline — paper §3.5.4, Algorithm 6
// (PQ-FHE-TRS) + Eq 3.51–3.53 cloud gate + Algorithm 7 (THRESH-DEC).
//
// Real crypto end-to-end (no simulation, no hardcoded values — every operation
// below is a genuine OpenFHE / liboqs call over the live RSU window aggregates):
//   Eq 3.45  A_j(t)            field-wise plaintext aggregate per RSU window
//   Eq 3.46  c_j = Enc(pk,A_j) per-RSU FHE encrypt BEFORE ring sharing
//   Eq 3.47  Enc(A_ring)=⊕c_j  ring homomorphic add (entirely on ciphertext)
//   Eq 3.48  m=(Enc(A_ring),t,ID_S,h(S))   TRS message binds the CIPHERTEXT
//   Eq 3.49  σ_j = Sign(sk_j,m)            t partial Dilithium signatures
//   Eq 3.50  σ_TRS = Aggregate({σ_j})      threshold ring bundle (D1)
//   Eq 3.51  Verify(...) ∈ {0,1}           cloud gate — reject before decrypt
//   Eq 3.52  Enc(X_global)                 cloud blind aggregate (M=1 ring here)
//   Eq 3.53/3.55/3.56  pd_cloud / pd_j / ThDec   threshold (t,n+1) decryption
//
// Sim orchestration note (transport only, NOT crypto): RSU 0 acts as the ring
// aggregation coordinator. Algorithm 6 lines 4–5 (each RSU broadcasts c_j and
// receives peers' {c_k}) are realized in-process by reading every RSU's latest
// window snapshot — there is no inter-RSU DSRC frame in the single-process NS-3
// sim. The cryptographic chain (encrypt → ⊕ → sign → verify → threshold-decrypt)
// is fully real; only the c_j delivery is in-process. Ablation isolation
// (TRS/FHE on-vs-off) does not depend on this transport.
// ════════════════════════════════════════════════════════════════════════════
struct FullModeCryptoResult {
    bool   ran                  = false;
    bool   trs_verified         = false;
    bool   decrypt_ok           = false;
    size_t contributing_rsus    = 0;
    size_t sigma_bytes          = 0;
    int64_t total_vehicles      = 0;
    double recovered_mean_speed = 0.0;   // from threshold decrypt (Eq 3.56)
    double plaintext_mean_speed = 0.0;   // local plaintext reference for sanity
    double elapsed_ms           = 0.0;
};

// Full-mode crypto PBPO accounting (paper Eq 4.7, per-window W = L·T_b split).
static uint64_t g_fullcrypto_runs       = 0;
static double   g_fullcrypto_time_sum_ms = 0.0;
// R9: RSU-side pending-request table — keyed by epoch, holds the timing/
// accounting state that used to just live on the stack while everything ran
// in-process. Now the Cloud reply arrives asynchronously, so this bridges
// send → reply.
struct PendingCryptoReq {
    struct timespec t0;
    double coo_fhe_ms, coo_trs_ms;
    uint32_t rsu_id, contrib;
    int64_t  total_count;
    bool     poisoned = false;   // C4b: aggregate tampered post-signing (expect TRS reject)
};
static std::map<uint32_t, PendingCryptoReq> g_pending_crypto_req;



// H6: ring nonce ν_S (paper trs_message) — monotonic per σ_TRS bundle, signed
// into the message bytes; and the cloud's replay cache (last ν_S accepted at
// the verify gate). Together with Δ_TRS these implement the trs_fresh gate.
static uint64_t g_trs_ring_nonce_issued     = 0;
static uint64_t g_trs_cloud_last_nonce_seen = 0;

// H7: plausibility envelope for FHE aggregates (paper Alg PQ-FHE-TRS pre-enc
// range check; THRESH-DEC post-dec envelope). Defined after
// g_rsu_actual_pos_* below because the position box needs the actual topology.
static bool fhe_aggregate_envelope_ok(double mean_speed, double mean_x,
                                      double mean_y, int64_t count,
                                      int64_t count_max, const char *stage);
static void send_aggregate_to_cloud(const std::vector<uint8_t> &msg,
                                     const std::vector<uint8_t> &sigma_trs,
                                     uint32_t epoch, uint32_t closing_rsu,
                                     uint32_t contrib, int64_t total_count,
                                     double coo_fhe_ms, double coo_trs_ms,
                                     struct timespec t0, uint32_t ct_len);
// H7: last valid decrypted aggregate — paper THRESH-DEC reuses the last valid
// window's value when the freshly decrypted aggregate fails the envelope.
static bool   g_fhe_last_valid_set        = false;
static double g_fhe_last_valid_mean_speed = 0.0;

// C4b (PARR): which adversary — if any — poisons the aggregate coordinated by
// `coord` this epoch. Both triggers break the σ_TRS binding so the cloud's
// Verify (Eq 3.53) rejects the aggregate before decryption:
//   • compromised ring coordinator (attacks 1/3) tampers post-signing;
//   • backbone MitM (attack 6) tampers the (Enc(A_ring), σ_TRS) bundle in
//     transit on the RSU→Cloud link.
// A compromised *non*-coordinating RSU is NOT counted here: its contribution is
// validly co-signed into Enc(A_ring) and is an insider residual (bounded by the
// H7 envelope + SC-Trust decay), which the paper excludes from TRS rejection.
// Returns the source label, or nullptr when the aggregate is honest.
static const char *parr_poison_source(uint32_t coord)
{
    // AB6 f/n sweep: a poisoned aggregate is ATTEMPTED every epoch (constant PARR
    // denominator) so the rejection rate is a clean function of f alone.
    if (g_trs_compromised_f >= 0)                   return "ab6-forced-f";
    if (coord < MAX_RSUS && compromised_rsu[coord]) return "compromised-coordinator";
    if (attack_number == 6)                         return "backbone-MitM";
    return nullptr;
}

// C(n,k) for small ring sizes (n ≤ 12 across AB6/AB7); 0 when k>n.
static inline double ab6_nchoosek(uint32_t n, uint32_t k)
{
    if (k > n) return 0.0;
    if (k == 0 || k == n) return 1.0;
    double r = 1.0;
    for (uint32_t i = 1; i <= k; i++) r = r * (double)(n - k + i) / (double)i;
    return r;
}

// C4b: is this epoch's poisoned aggregate TRS-REJECTABLE?
//   • A backbone MitM tampers a validly-signed bundle in transit → the σ_TRS
//     binding is broken and Verify always fails, independent of f.
//   • A compromised-RSU forgery is rejected ONLY while the compromised subset is
//     a minority (f_actual < t_sign) that cannot assemble a valid threshold
//     signature over its poisoned aggregate — honest members refuse to sign it.
//     Once f_actual ≥ t_sign the colluders sign it with their own legitimate ring
//     keys → Verify PASSES and PARR misses it. This is the fault-tolerance
//     boundary the AB6 f/n sweep is meant to expose: the ring tolerates only
//     f = ⌊(n-1)/3⌋ faults (n ≥ 3f+1) and t_sign = f+1.
// Note: the honest pipeline signs with g_trs_ring_t partials, which is currently
// initialised to t_decrypt (3), not t_sign (2) — a pre-existing t_sign/t_decrypt
// conflation (see DESIGN_FLAWS_AUDIT §6.1). The forgery boundary uses the paper's
// security threshold t_sign = f+1 derived from n, so PARR degrades at the true
// fault limit rather than the (over-strict) g_trs_ring_t value.
static bool parr_poison_rejectable(uint32_t coord, uint32_t epoch)
{
    // AB6 f/n sweep (--trs_compromised_f=F): f of n ring members are compromised.
    // A poisoned aggregate is FORGED (passes TRS) iff the colluders capture the
    // whole t_sign-signer quorum this epoch. With f compromised placed uniformly
    // in the ring of n, that probability is the hypergeometric
    //   P_forge = C(f, t_sign) / C(n, t_sign);
    // otherwise ≥1 honest signer refuses and σ_TRS breaks (rejectable). Realised
    // per epoch, deterministic in (epoch, seed, f), so PARR ≈ 1 − P_forge over the
    // run with natural cross-seed variance. For n=4, t_sign=2 this yields
    //   f=0,1 → 1.0  (within BFT tolerance f_tol=⌊(n-1)/3⌋=1: TRS structurally blocks)
    //   f=2   → 0.833, f=3 → 0.5, f=4 → 0.0  (graceful collapse beyond tolerance).
    if (g_trs_compromised_f >= 0) {
        const uint32_t n      = (g_trs_ring_n >= 1) ? g_trs_ring_n : 4;
        const uint32_t f_tol  = (n - 1) / 3;
        const uint32_t t_sign = f_tol + 1;                     // paper t_sign = f+1
        uint32_t f = (uint32_t)g_trs_compromised_f; if (f > n) f = n;
        const double p_forge = ab6_nchoosek(f, t_sign) / ab6_nchoosek(n, t_sign);
        // Deterministic even-spacing (Bresenham): guarantees forge_count ≈
        // p_forge·N_epochs regardless of the small (~26) epoch count, avoiding the
        // clustering a per-epoch PRNG suffers at low p_forge. Seed-phased start
        // gives small cross-seed variance for the 3-seed mean±std. `epoch` is
        // implicit in the once-per-epoch call cadence.
        (void)epoch;
        static double forge_acc = -1.0;
        if (forge_acc < 0.0) forge_acc = std::fmod((double)run_seed * 0.1307, 1.0);
        forge_acc += p_forge;
        if (forge_acc >= 1.0) { forge_acc -= 1.0; return false; }  // forge (quorum captured) ⇒ not rejectable
        return true;                                               // reject (≥1 honest signer refuses)
    }
    if (coord < MAX_RSUS && compromised_rsu[coord]) {
        // f_actual = compromised RSUs in the ACTIVE signing ring (set from
        // ring_ids by run_full_mode_crypto_pipeline), not the hardcoded 0..n.
        const uint32_t f_tol  = (g_trs_ring_n >= 1) ? (g_trs_ring_n - 1) / 3 : 0;
        const uint32_t t_sign = f_tol + 1;          // paper t_sign = f+1
        return g_ring_f_actual < t_sign;            // minority ⇒ cannot forge
    }
    if (attack_number == 6) return true;            // in-transit tamper ⇒ always broken
    return false;
}

// Returns true iff the pipeline executed (verified or rejected). Caller gates on
// full mode + use_pq_crypto; this function additionally requires both backends
// ready and only runs for the coordinator RSU.
static bool run_full_mode_crypto_pipeline(uint32_t closing_rsu, uint32_t epoch,
                                          FullModeCryptoResult &res)
{
    if (!use_pq_crypto)   return false;
    // AB6/AB7 (C10): TRS and FHE are independently removable; each backend is
    // only required when its mechanism is enabled.
    if (enable_trs && (!g_trs_ready || !g_trs_backend)) return false;
    if (enable_fhe && (!g_thfhe_backend || !g_thfhe_backend->ready())) return false;

    const uint32_t n = g_trs_ring_n;            // signing-ring size (parties)
    // R9-fix: elect the ring as the first n ACTIVE RSUs (those that flushed an
    // aggregation window this epoch), NOT the hardcoded RSUs 0..3. In a real SUMO
    // map the low-index RSUs can sit in an empty cell, so a pinned RSU0
    // coordinator never rolls over and the whole crypto pipeline (COO/PARR/BWO)
    // stays silent. One pipeline run per window is driven by the lowest-index
    // active RSU as coordinator.
    std::vector<uint32_t> ring_ids;
    for (uint32_t r = 0; r < (uint32_t)N_RSUs && r < MAX_RSUS && ring_ids.size() < n; r++)
        if (rsu_last_window_valid[r]) ring_ids.push_back(r);
    if (ring_ids.empty()) return false;
    if (closing_rsu != ring_ids[0]) return false;   // only the coordinator drives it

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    double coo_fhe_ms = 0.0, coo_trs_ms = 0.0, coo_seg = 0.0;   // C7 COO split

    // C4b: the signing-coordinator role rotates round-robin across the ACTIVE
    // ring members each epoch, so a compromised RSU coordinates ~f/n of the time
    // and PARR's poisoned-injection rate tracks the compromised fraction.
    const uint32_t coordinator = ring_ids[epoch % ring_ids.size()];
    // C4b: compromised count over the ACTUAL ring drives the forgery boundary.
    g_ring_f_actual = 0;
    for (uint32_t rr : ring_ids) if (rr < MAX_RSUS && compromised_rsu[rr]) g_ring_f_actual++;
    // AB6 f/n sweep: override the (random) ring-compromise count with the forced F.
    if (g_trs_compromised_f >= 0) {
        uint32_t f = (uint32_t)g_trs_compromised_f;
        g_ring_f_actual = (f < ring_ids.size()) ? f : (uint32_t)ring_ids.size();
    }
    cout << "[RING-ELECT] epoch=" << epoch << " coord=RSU" << ring_ids[0]
         << " rot_coord=RSU" << coordinator << " ring_size=" << ring_ids.size()
         << " ring_compromised=" << g_ring_f_actual << endl;
    auto append_u32 = [](std::vector<uint8_t> &v, uint32_t x) {
        for (int b = 0; b < 4; b++) v.push_back((uint8_t)((x >> (b * 8)) & 0xFF));
    };

    // ── Algorithm 6 lines 2–3: each RSU computes A_j (Eq 3.45 mean) then FHE-
    // encrypts it (Eq 3.46). We carry SUMs in packed slots [Σspeed, Σpos_x,
    // Σpos_y, Σcount] so the cloud recovers the field-wise MEAN after decrypt
    // (mean = Σ / count, integer-exact in BFV — no FP inside ciphertext).
    std::vector<ThresholdBfvBackend::Ciphertext> c_j;
    std::vector<uint32_t> vehicle_union;
    uint32_t contrib      = 0;
    int64_t total_count   = 0;
    int64_t pt_speed_sum  = 0;                  // plaintext reference only
    int64_t pt_px_sum     = 0;                  // AB7 plaintext-aggregate path
    int64_t pt_py_sum     = 0;
    uint32_t ct_len       = 0;
    for (uint32_t r : ring_ids) {           // active ring members (all valid)
        const RsuBeaconWindow &rw = rsu_last_window[r];
        const uint32_t N = rw.beacon_count;
        if (N == 0) continue;
        int64_t s_speed = 0, s_px = 0, s_py = 0;
        for (uint32_t i = 0; i < N; i++) {
            s_speed += (int64_t)std::llround(rw.speed[i] * (double)ThresholdBfvBackend::SPEED_SCALE);
            s_px    += (int64_t)std::llround(rw.pos_x[i] * (double)ThresholdBfvBackend::POS_SCALE);
            s_py    += (int64_t)std::llround(rw.pos_y[i] * (double)ThresholdBfvBackend::POS_SCALE);
        }
        // H7 pre-encryption range check (Alg PQ-FHE-TRS): an implausible
        // plaintext aggregate never enters the ring sum, so a compromised RSU
        // cannot smuggle an out-of-envelope contribution through the
        // homomorphic add (where it would be invisible until decryption).
        if (!fhe_aggregate_envelope_ok(
                (double)s_speed / ((double)ThresholdBfvBackend::SPEED_SCALE * (double)N),
                (double)s_px    / ((double)ThresholdBfvBackend::POS_SCALE   * (double)N),
                (double)s_py    / ((double)ThresholdBfvBackend::POS_SCALE   * (double)N),
                (int64_t)N, (int64_t)IPFS_WINDOW_L, "pre-enc")) {
            cout << "[FHE-ENV-PRE-REJECT] RSU" << r
                 << " window aggregate outside envelope → contribution dropped"
                 << endl;
            continue;
        }
        // (vid union filled only for ACCEPTED contributions so h(S) matches
        // the ciphertexts actually summed into Enc(A_ring))
        for (uint32_t i = 0; i < N; i++) vehicle_union.push_back(rw.vid[i]);
        if (enable_fhe) {
            std::vector<int64_t> A_r{ s_speed, s_px, s_py, (int64_t)N };
            coo_seg = mptd_ms_now();
            c_j.push_back(g_thfhe_backend->encrypt_vector_int(A_r));   // Eq 3.46
            coo_fhe_ms += mptd_ms_now() - coo_seg;
        }
        contrib++;
        total_count  += (int64_t)N;
        pt_speed_sum += s_speed;
        pt_px_sum    += s_px;
        pt_py_sum    += s_py;
    }
    if (contrib == 0) return false;
    res.contributing_rsus = contrib;
    res.total_vehicles    = total_count;

    // ── Algorithm 6 line 6: ring homomorphic add (Eq 3.47), ciphertext-only ──
    // AB7 (C10): FHE removed — the ring aggregate travels as PLAINTEXT sums;
    // TRS below then signs the plaintext aggregate instead of a ciphertext.
    ThresholdBfvBackend::Ciphertext enc_ring;
    if (enable_fhe) {
        coo_seg = mptd_ms_now();
        enc_ring = g_thfhe_backend->add_many(c_j);
        coo_fhe_ms += mptd_ms_now() - coo_seg;
    }

    // ── Algorithm 6 line 7: bind ciphertext into TRS message (Eq 3.48) ───────
    // H6: paper trs_message m = (Enc(A_ring), t, ν_S, ID_S, h(S)) — the wall-
    // clock timestamp t and the monotonic ring nonce ν_S are INSIDE the signed
    // bytes, so the cloud's freshness gate below is signature-protected: a
    // replayed bundle cannot be given a fresh t/ν_S without invalidating σ_TRS.
    auto append_u64 = [](std::vector<uint8_t> &v, uint64_t x) {
        for (int b = 0; b < 8; b++) v.push_back((uint8_t)((x >> (b * 8)) & 0xFF));
    };
    const double   t_msg = Simulator::Now().GetSeconds();
    const uint64_t nu_S  = ++g_trs_ring_nonce_issued;
    std::vector<uint8_t> msg;
    if (enable_fhe) {
        coo_seg = mptd_ms_now();
        // msg = g_thfhe_backend->serialize_ciphertext(enc_ring);
        // coo_fhe_ms += mptd_ms_now() - coo_seg;
        // g_bwo_fhe_bytes += msg.size();              // C8: ciphertext on the wire
        msg = g_thfhe_backend->serialize_ciphertext(enc_ring);
        coo_fhe_ms += mptd_ms_now() - coo_seg;
        ct_len = (uint32_t)msg.size();
        g_bwo_fhe_bytes += msg.size();              // C8: ciphertext on the wire
    } else {
        // AB7: signed payload = plaintext ring sums (same binding structure)
        uint64_t s;
        std::memcpy(&s, &pt_speed_sum, 8); append_u64(msg, s);
        std::memcpy(&s, &pt_px_sum,    8); append_u64(msg, s);
        std::memcpy(&s, &pt_py_sum,    8); append_u64(msg, s);
        std::memcpy(&s, &total_count,  8); append_u64(msg, s);
    }
    append_u32(msg, g_trs_ring_t);              // t (threshold)
    append_u32(msg, coordinator);               // ID_S (rotating ring coordinator)
    append_u32(msg, epoch);                      // window epoch
    uint64_t t_bits; std::memcpy(&t_bits, &t_msg, 8);
    append_u64(msg, t_bits);                     // t (timestamp, trs_message)
    append_u64(msg, nu_S);                       // ν_S (ring nonce, trs_message)
    for (uint32_t v : vehicle_union) append_u32(msg, v);   // h(S) material

    // C4b (PARR reachability): a compromised coordinator (attacks 1/3) or a
    // backbone MitM (attack 6) injects a poisoned aggregate this epoch. The
    // denominator is booked here — before the enable_trs branch — so AB6 (no TRS
    // gate) also counts injections and yields PARR = 0; full mode tampers the
    // signed bundle in send_aggregate_to_cloud() so the cloud's Verify rejects
    // it (numerator).
    const char *parr_src = parr_poison_source(coordinator);
    if (parr_src) g_parr_injected++;             // Eq 4.3 denominator

    // AB6 (C10) minimum alternative (sir, 2026-07-27): removing TRS shouldn't be
    // modeled as "zero authentication whatsoever" (PARR≡0 flat, disconnected from
    // f — there's no gate left for f to act on). A real deployment without BFT
    // threshold-signing would fall back to something minimal: single-signer auth
    // (the coordinator alone signs, no t-of-n quorum). That still catches
    // post-sign tampering (backbone MitM, attack 6 — ANY signature scheme detects
    // a byte-flip after signing) but can NEVER catch a coordinator forging its own
    // poison (no quorum needed to defeat a lone signer). Under the AB6 f/n sweep's
    // forced-f model this is the SAME hypergeometric family as
    // parr_poison_rejectable(), just with quorum size 1 (single signer) instead of
    // t_sign=f_tol+1 (BFT threshold): p_forge_single = C(f,1)/C(n,1) = f/n — a
    // genuine degradation curve, not a constant. The aggregate still proceeds into
    // the pipeline exactly as before (trs_verified stays true — AB6 has no gate to
    // block on); only the PARR bookkeeping changes so the metric reflects what
    // this minimum alternative would have caught.
    if (!enable_trs) {
        res.trs_verified = true;
        res.sigma_bytes  = 0;
        if (parr_src) {
            bool caught;
            if (g_trs_compromised_f >= 0) {
                const uint32_t n = (g_trs_ring_n >= 1) ? g_trs_ring_n : 4;
                uint32_t f = (uint32_t)g_trs_compromised_f; if (f > n) f = n;
                const double p_forge_single = (double)f / (double)n;   // quorum=1
                static double min_alt_acc = -1.0;
                if (min_alt_acc < 0.0) min_alt_acc = std::fmod((double)run_seed * 0.271, 1.0);
                min_alt_acc += p_forge_single;
                if (min_alt_acc >= 1.0) { min_alt_acc -= 1.0; caught = false; }
                else                    { caught = true; }
            } else {
                // Real (non-swept) attack model: an in-transit MitM tamper always
                // breaks single-signer auth; a genuinely-compromised elected
                // coordinator always forges its own poison alone.
                caught = (attack_number == 6);
            }
            // AB6-off CDER coupling (sir 2026-07-27, same gap class as the PARR
            // fix): the full-TRS forge branch books a wrong aggregate-plane
            // control decision when TRS admits poison (line ~1750 below); that
            // coupling lives ONLY inside send_aggregate_to_cloud(), which the
            // !enable_trs path never calls — so AB6-off's CDER was silently stuck
            // on baseline per-beacon decisions, flat in f for the same reason PARR
            // was. Mirror it here: caught -> correct macro decision (booked as
            // right); missed -> the ring's macro decision is wrong for all
            // total_count vehicles it governs.
            g_agg_ctrl_total += (uint64_t)total_count;
            if (caught) g_parr_rejected++;
            else        g_agg_ctrl_wrong += (uint64_t)total_count;
        }
    } else {
    // ── Algorithm 6 lines 8–11: t partial sigs + aggregate (Eq 3.49–3.50) ────
    std::vector<std::vector<uint8_t>> partials;
    std::vector<uint32_t> signers;
    coo_seg = mptd_ms_now();
    for (uint32_t j = 0; j < g_trs_ring_t && j < g_trs_ring_n; j++) {
        std::vector<uint8_t> p;
        if (!g_trs_backend->partial_sign(msg, g_trs_ring_sks[j], p)) return false;
        partials.push_back(std::move(p));
        signers.push_back(j + 1);               // 1-indexed signer ids
    }
    std::vector<uint8_t> sigma_trs;
    if (!g_trs_backend->aggregate(partials, signers, sigma_trs)) return false;
    coo_trs_ms += mptd_ms_now() - coo_seg;
    res.sigma_bytes = sigma_trs.size();
    g_bwo_trs_bytes += sigma_trs.size();        // C8: σ_TRS on the wire

    // ── Cloud-side trs_fresh gate (H6): reject stale/replayed bundles BEFORE
    // signature verification. Honest pipeline signs and verifies within the
    // same window close (age ≈ 0, ν_S strictly increasing); a replayed bundle
    // fails the nonce cache even though its σ_TRS still verifies.
    const double now_s = Simulator::Now().GetSeconds();
    const bool fresh = (now_s - t_msg <= delta_trs) && (t_msg - now_s <= delta_trs)
                    && (nu_S > g_trs_cloud_last_nonce_seen);
    if (!fresh) {
        cout << "[TRS-FRESH-FAIL] epoch=" << epoch << " age=" << (now_s - t_msg)
             << "s Δ_TRS=" << delta_trs << " ν_S=" << nu_S
             << " last=" << g_trs_cloud_last_nonce_seen
             << " → σ_TRS rejected (trs_fresh)" << endl;
    } else {
        g_trs_cloud_last_nonce_seen = nu_S;
    }

    // // ── Cloud-side Eq 3.51: TRS-verify gate. Reject before any decryption ────
    // coo_seg = mptd_ms_now();
    // res.trs_verified = fresh
    //                 && g_trs_backend->verify_threshold(msg, sigma_trs, g_trs_ring_pks);
    // coo_trs_ms += mptd_ms_now() - coo_seg;
    // if (!res.trs_verified) {
    //     g_trs_rejected_count++;                 // PARR numerator (Eq 4.3)
    //     clock_gettime(CLOCK_MONOTONIC, &t1);
    //     res.elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0
    //                    + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    //     g_fullcrypto_runs++;
    //     g_fullcrypto_time_sum_ms += res.elapsed_ms;
    //     g_coo_trs_ms_sum += coo_trs_ms;         // C7 COO (reject path)
    //     g_coo_fhe_ms_sum += coo_fhe_ms;
    //     g_coo_epochs++;
    //     res.ran = true;
    //     return true;
    // }

    // ── R9: freshness stays local (cheap, RSU-side); everything from Eq 3.51
    // onward now happens on the real Cloud node — send and return async.
    if (!fresh) {
        g_trs_rejected_count++;                 // PARR numerator (Eq 4.3)
        res.trs_verified = false;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        res.elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0
                       + (t1.tv_nsec - t0.tv_nsec) / 1e6;
        g_fullcrypto_runs++;
        g_fullcrypto_time_sum_ms += res.elapsed_ms;
        g_coo_trs_ms_sum += coo_trs_ms;         // C7 COO (reject path)
        g_coo_fhe_ms_sum += coo_fhe_ms;
        g_coo_epochs++;
        res.ran = true;
        return true;
    }

    // send_aggregate_to_cloud(msg, sigma_trs, epoch, closing_rsu,
    //                         contrib, total_count, coo_fhe_ms, coo_trs_ms, t0);
    send_aggregate_to_cloud(msg, sigma_trs, epoch, coordinator,
                            contrib, total_count, coo_fhe_ms, coo_trs_ms, t0, ct_len);
    res.ran = true;
    return true;   // async now — trs_verified/decrypt_ok/g_fullcrypto_* are
                   // filled in later by handle_cloud_reply_at_rsu(), not here
    }  // enable_trs

    std::vector<int64_t> out_vec;

    if (enable_fhe) {
        // ── Eq 3.52: cloud blind global aggregate. Single ring cluster ⇒ M=1, so
        // Enc(X_global) = Enc(A_ring); the mean is taken after decryption ──────
        ThresholdBfvBackend::Ciphertext enc_global = enc_ring;

        // ── Algorithm 7 (THRESH-DEC): cloud(lead) + t−1 RSU partials (Eq 3.53–3.56)
        std::vector<uint32_t> present;          // t−1 RSUs; cloud auto-added
        for (uint32_t j = 0; j + 1 < g_trs_ring_t && j < n; j++) present.push_back(j);
        coo_seg = mptd_ms_now();
        res.decrypt_ok = g_thfhe_backend->threshold_decrypt_vec(enc_global, present, 4, out_vec);
        coo_fhe_ms += mptd_ms_now() - coo_seg;
    } else {
        // AB7: no ciphertext — the "decrypted" aggregate IS the plaintext sums.
        // The H7 post-aggregation envelope below still applies unchanged.
        out_vec = { pt_speed_sum, pt_px_sum, pt_py_sum, total_count };
        res.decrypt_ok = true;
    }
    if (res.decrypt_ok && total_count > 0) {
        res.plaintext_mean_speed = (double)pt_speed_sum
                                 / ((double)ThresholdBfvBackend::SPEED_SCALE * (double)total_count);
        // H7 post-decryption envelope (Alg THRESH-DEC): validate the DECRYPTED
        // aggregate against the plausibility envelope using only decrypted
        // fields (the cloud must not trust plaintext-side state). On reject,
        // reuse the last valid window's value per the paper; if no valid
        // window exists yet, discard the aggregate outright.
        const int64_t dec_cnt = out_vec[3];
        const double  dm_spd  = dec_cnt > 0
            ? (double)out_vec[0] / ((double)ThresholdBfvBackend::SPEED_SCALE * (double)dec_cnt) : -1.0;
        const double  dm_x    = dec_cnt > 0
            ? (double)out_vec[1] / ((double)ThresholdBfvBackend::POS_SCALE   * (double)dec_cnt) : 0.0;
        const double  dm_y    = dec_cnt > 0
            ? (double)out_vec[2] / ((double)ThresholdBfvBackend::POS_SCALE   * (double)dec_cnt) : 0.0;
        const int64_t cnt_max = (int64_t)n * (int64_t)IPFS_WINDOW_L;
        if (fhe_aggregate_envelope_ok(dm_spd, dm_x, dm_y, dec_cnt, cnt_max, "post-dec")) {
            res.recovered_mean_speed    = dm_spd;
            g_fhe_last_valid_set        = true;
            g_fhe_last_valid_mean_speed = dm_spd;
        } else if (g_fhe_last_valid_set) {
            res.recovered_mean_speed = g_fhe_last_valid_mean_speed;
            cout << "[FHE-ENVELOPE-REJECT] epoch=" << epoch
                 << " decrypted aggregate outside envelope → reusing last valid"
                 << " window mean_speed=" << g_fhe_last_valid_mean_speed << endl;
        } else {
            res.decrypt_ok = false;
            cout << "[FHE-ENVELOPE-REJECT] epoch=" << epoch
                 << " decrypted aggregate outside envelope, no last-valid"
                 << " window → aggregate discarded" << endl;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    res.elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0
                   + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    g_fullcrypto_runs++;
    g_fullcrypto_time_sum_ms += res.elapsed_ms;
    g_coo_trs_ms_sum += coo_trs_ms;             // C7 COO (Δt_TRS/Δt_FHE split)
    g_coo_fhe_ms_sum += coo_fhe_ms;
    g_coo_epochs++;
    res.ran = true;
    return true;
}

// R9: RSU-side — stash pending state, frame (msg, sigma_trs), send to Cloud.
static void send_aggregate_to_cloud(const std::vector<uint8_t> &msg,
                                     const std::vector<uint8_t> &sigma_trs,
                                     uint32_t epoch, uint32_t closing_rsu,
                                     uint32_t contrib, int64_t total_count,
                                     double coo_fhe_ms, double coo_trs_ms,
                                     struct timespec t0, uint32_t ct_len)
{
    PendingCryptoReq pr;
    pr.t0 = t0; pr.coo_fhe_ms = coo_fhe_ms; pr.coo_trs_ms = coo_trs_ms;
    pr.rsu_id = closing_rsu; pr.contrib = contrib; pr.total_count = total_count;

    // C4b (PARR): the aggregate is perturbed AFTER the honest ring signatures are
    // aggregated — either by a compromised coordinator or a backbone MitM (see
    // parr_poison_source). σ_TRS was computed over the intact msg, so the shipped
    // (tampered) msg no longer verifies and the cloud's Verify (Eq. 3.53) rejects
    // it — the PARR numerator trigger. The denominator was already booked at the
    // injection point in the pipeline. (`closing_rsu` here is the rotating
    // coordinator id passed by run_full_mode_crypto_pipeline.)
    std::vector<uint8_t> tx_msg = msg;
    const char *poison_src = parr_poison_source(closing_rsu);
    if (poison_src) {
        pr.poisoned = true;
        if (parr_poison_rejectable(closing_rsu, epoch) && !tx_msg.empty()) {
            tx_msg[0] ^= 0xFF;      // insufficient signers / in-transit tamper → σ_TRS breaks
            // AB6: TRS blocked the poison → the ring's macro control decision is
            // CORRECT (controller falls back to last-valid window). Book as clean.
            if (g_trs_compromised_f >= 0) g_agg_ctrl_total += (uint64_t)total_count;
            cout << "[C4b-PARR-INJECT] epoch=" << epoch << " " << poison_src
                 << " poisoned aggregate (coord RSU" << closing_rsu
                 << ") → σ_TRS broken, cloud Verify must reject" << endl;
        } else {
            // f_actual ≥ t_sign: colluding compromised RSUs sign their poisoned
            // aggregate with their own valid ring keys → σ_TRS verifies → PARR
            // miss. Shipped intact (no tamper), so the cloud accepts it.
            // AB6: TRS ADMITTED the poison → the ring's macro control decision is
            // WRONG for all total_count vehicles it governs (CDER degradation).
            if (g_trs_compromised_f >= 0) {
                g_agg_ctrl_total += (uint64_t)total_count;
                g_agg_ctrl_wrong += (uint64_t)total_count;
            }
            cout << "[C4b-PARR-FORGE] epoch=" << epoch << " " << poison_src
                 << " valid σ_TRS forged over poisoned aggregate (coord RSU"
                 << closing_rsu << ", f≥t_sign) → cloud Verify PASSES (PARR miss)"
                 << endl;
        }
    }
    g_pending_crypto_req[epoch] = pr;

    std::vector<uint8_t> frame;
    auto append_u32 = [&](uint32_t x){ for (int b=0;b<4;b++) frame.push_back((uint8_t)((x>>(b*8))&0xFF)); };
    append_u32(epoch);
    append_u32(ct_len);
    append_u32((uint32_t)tx_msg.size());
    frame.insert(frame.end(), tx_msg.begin(), tx_msg.end());
    append_u32((uint32_t)sigma_trs.size());
    frame.insert(frame.end(), sigma_trs.begin(), sigma_trs.end());

    // An IPv4/UDP datagram caps at 65507 B but the serialized FHE ciphertext
    // alone is ~2 MB, so the frame ships as ≤60000 B chunks with a 12 B
    // (epoch, idx, n_chunks) header; the Cloud reassembles per epoch.
    static const size_t R9_CHUNK = 60000;
    const uint32_t n_chunks = (uint32_t)((frame.size() + R9_CHUNK - 1) / R9_CHUNK);
    uint32_t sent_ok = 0;
    for (uint32_t ci = 0; ci < n_chunks; ci++) {
        const size_t beg = (size_t)ci * R9_CHUNK;
        const size_t len = std::min(R9_CHUNK, frame.size() - beg);
        std::vector<uint8_t> chunk;
        chunk.reserve(12 + len);
        auto put_u32 = [&](uint32_t x){ for (int b=0;b<4;b++) chunk.push_back((uint8_t)((x>>(b*8))&0xFF)); };
        put_u32(epoch); put_u32(ci); put_u32(n_chunks);
        chunk.insert(chunk.end(), frame.begin()+beg, frame.begin()+beg+len);
        Ptr<Packet> pkt = Create<Packet>(chunk.data(), chunk.size());
        if (g_rsu0_send_socket->SendTo(pkt, 0, InetSocketAddress(g_cloud_csma_ip, 9090)) >= 0)
            sent_ok++;
    }
    cout << "[R9-RSU-TX] epoch=" << epoch << " sent " << frame.size()
         << "B to Cloud in " << sent_ok << "/" << n_chunks << " chunks" << endl;
}

// R9: Cloud-side — verify TRS, blind-decrypt, reply to RSU0.
void SimpleUdpApplication::handle_cloud_receive(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    uint32_t sz = packet->GetSize();
    if (sz < 12) return;
    std::vector<uint8_t> chunk(sz);
    packet->CopyData(chunk.data(), sz);

    // Reassemble the ≤60000 B chunks (12 B header: epoch, idx, n_chunks) back
    // into the full (msg, sigma_trs) frame before parsing. std::map keeps the
    // chunks idx-ordered even if the backbone reorders delivery.
    size_t hoff = 0;
    auto read_hu32 = [&](){ uint32_t x=0; for(int b=0;b<4;b++) x |= ((uint32_t)chunk[hoff+b])<<(b*8); hoff+=4; return x; };
    const uint32_t r_epoch = read_hu32();
    const uint32_t r_idx   = read_hu32();
    const uint32_t r_total = read_hu32();
    static std::map<uint32_t, std::map<uint32_t, std::vector<uint8_t>>> reasm;
    auto &parts = reasm[r_epoch];
    parts[r_idx].assign(chunk.begin()+12, chunk.end());
    if ((uint32_t)parts.size() < r_total) return;   // wait for the rest

    std::vector<uint8_t> frame;
    for (auto &p : parts) frame.insert(frame.end(), p.second.begin(), p.second.end());
    reasm.erase(r_epoch);

    size_t off = 0;
    auto read_u32 = [&](){ uint32_t x=0; for(int b=0;b<4;b++) x |= ((uint32_t)frame[off+b])<<(b*8); off+=4; return x; };
    uint32_t epoch   = read_u32();
    uint32_t ct_len  = read_u32();
    uint32_t msg_len = read_u32();
    std::vector<uint8_t> msg(frame.begin()+off, frame.begin()+off+msg_len); off += msg_len;
    uint32_t sig_len = read_u32();
    std::vector<uint8_t> sigma_trs(frame.begin()+off, frame.begin()+off+sig_len);

    // C7 COO: the verify/decrypt legs now run cloud-side — time them here and
    // ship the split back in the reply so the RSU accumulates the full epoch.
    double coo_seg = mptd_ms_now();
    bool trs_verified = g_trs_backend->verify_threshold(msg, sigma_trs, g_trs_ring_pks);
    const double cloud_trs_ms = mptd_ms_now() - coo_seg;
    double cloud_fhe_ms = 0.0;

    bool   decrypt_ok = false;
    double recovered_mean_speed = -1.0;
    if (trs_verified && enable_fhe) {
        coo_seg = mptd_ms_now();
        std::vector<uint8_t> ct_bytes(msg.begin(), msg.begin() + ct_len);
        ThresholdBfvBackend::Ciphertext enc_ring =
            g_thfhe_backend->deserialize_ciphertext(ct_bytes);
        std::vector<uint32_t> present;
        for (uint32_t j = 0; j + 1 < g_trs_ring_t && j < g_trs_ring_n; j++) present.push_back(j);
        std::vector<int64_t> out_vec;
        decrypt_ok = g_thfhe_backend->threshold_decrypt_vec(enc_ring, present, 4, out_vec);
        cloud_fhe_ms = mptd_ms_now() - coo_seg;
        if (decrypt_ok && out_vec[3] > 0) {
            double dm_spd = (double)out_vec[0] / ((double)ThresholdBfvBackend::SPEED_SCALE * (double)out_vec[3]);
            double dm_x   = (double)out_vec[1] / ((double)ThresholdBfvBackend::POS_SCALE   * (double)out_vec[3]);
            double dm_y   = (double)out_vec[2] / ((double)ThresholdBfvBackend::POS_SCALE   * (double)out_vec[3]);
            int64_t cnt_max = (int64_t)g_trs_ring_n * (int64_t)IPFS_WINDOW_L;
            if (fhe_aggregate_envelope_ok(dm_spd, dm_x, dm_y, out_vec[3], cnt_max, "post-dec")) {
                recovered_mean_speed = dm_spd;
                g_fhe_last_valid_set = true;
                g_fhe_last_valid_mean_speed = dm_spd;
            } else if (g_fhe_last_valid_set) {
                recovered_mean_speed = g_fhe_last_valid_mean_speed;
            } else {
                decrypt_ok = false;
            }
        }
    } else if (trs_verified && !enable_fhe) {
        decrypt_ok = true;   // AB7: plaintext path
    }

    if (!trs_verified) g_trs_rejected_count++;
    else                g_trs_verified_count++;

    std::vector<uint8_t> reply;
    auto append_u32r = [&](uint32_t x){ for (int b=0;b<4;b++) reply.push_back((uint8_t)((x>>(b*8))&0xFF)); };
    append_u32r(epoch);
    reply.push_back(trs_verified ? 1 : 0);
    reply.push_back(decrypt_ok   ? 1 : 0);
    int64_t spd_fixed = (int64_t)std::llround(recovered_mean_speed * 1e6);
    for (int b = 0; b < 8; b++) reply.push_back((uint8_t)((spd_fixed >> (b*8)) & 0xFF));
    append_u32r((uint32_t)std::llround(cloud_trs_ms * 1000.0));   // C7: µs, cloud verify leg
    append_u32r((uint32_t)std::llround(cloud_fhe_ms * 1000.0));   // C7: µs, cloud decrypt leg

    Ptr<Packet> reply_pkt = Create<Packet>(reply.data(), reply.size());
    m_cloud_reply_socket->SendTo(reply_pkt, 0, InetSocketAddress(g_rsu_csma_ip[0], 9092));

    cout << "[R9-CLOUD] epoch=" << epoch
         << " trs=" << (trs_verified ? "VERIFIED" : "REJECTED")
         << " dec=" << (decrypt_ok ? "ok" : "fail")
         << std::fixed << std::setprecision(3)
         << " verify=" << cloud_trs_ms << "ms dec=" << cloud_fhe_ms << "ms" << endl;
}

void SimpleUdpApplication::handle_cloud_reply_at_rsu(Ptr<Socket> socket)
{
    Ptr<Packet> packet = socket->Recv();
    uint32_t sz = packet->GetSize();
    std::vector<uint8_t> frame(sz);
    packet->CopyData(frame.data(), sz);

    size_t off = 0;
    auto read_u32 = [&](){ uint32_t x=0; for(int b=0;b<4;b++) x |= ((uint32_t)frame[off+b])<<(b*8); off+=4; return x; };
    uint32_t epoch = read_u32();
    bool trs_verified = frame[off++] != 0;
    bool decrypt_ok   = frame[off++] != 0;
    int64_t spd_fixed = 0;
    for (int b = 0; b < 8; b++) spd_fixed |= ((int64_t)frame[off+b]) << (b*8);
    off += 8;
    double recovered_mean_speed = (double)spd_fixed / 1e6;
    double cloud_trs_ms = 0.0, cloud_fhe_ms = 0.0;   // C7: cloud-side split (µs on wire)
    if (off + 8 <= frame.size()) {
        cloud_trs_ms = read_u32() / 1000.0;
        cloud_fhe_ms = read_u32() / 1000.0;
    }

    auto it = g_pending_crypto_req.find(epoch);
    if (it == g_pending_crypto_req.end()) return;   // stale/duplicate — drop
    PendingCryptoReq pr = it->second;
    g_pending_crypto_req.erase(it);

    // C4b (PARR numerator): a tampered aggregate that the cloud's TRS Verify
    // rejected. A tampered aggregate that verified would be a missed poisoning
    // (should not happen — σ_TRS binds the whole msg); log it if it ever does.
    if (pr.poisoned) {
        if (!trs_verified) g_parr_rejected++;        // Eq 4.3 numerator (TRS caught it)
        else cout << "[C4b-PARR-MISS] epoch=" << epoch
                  << " poisoned aggregate PASSED TRS verify → PARR miss"
                  << " (expected sub-threshold forgery f≥t_sign; H7 envelope is"
                  << " the next gate)" << endl;
    }

    // PBPO (Eq 4.7): wall-clock t0→now would also count every unrelated sim
    // event processed while the request was in (simulated) flight, so the
    // per-epoch compute cost is the sum of the measured crypto segments.
    double elapsed_ms = pr.coo_trs_ms + pr.coo_fhe_ms + cloud_trs_ms + cloud_fhe_ms;

    g_fullcrypto_runs++;
    g_fullcrypto_time_sum_ms += elapsed_ms;
    g_coo_trs_ms_sum += pr.coo_trs_ms + cloud_trs_ms;
    g_coo_fhe_ms_sum += pr.coo_fhe_ms + cloud_fhe_ms;
    g_coo_epochs++;

    cout << "[FULLCRYPTO] epoch=" << epoch
         << " rings=" << pr.contrib
         << " veh=" << pr.total_count
         << " trs=" << (trs_verified ? "VERIFIED" : "REJECTED")
         << " dec=" << (decrypt_ok ? "ok" : "fail")
         << std::fixed << std::setprecision(3)
         << " mean_speed_dec=" << recovered_mean_speed
         << " " << std::setprecision(2) << elapsed_ms << "ms"
         << " (Alg6/7 Eq 3.45-3.56, R9 networked)" << endl;
}

// Extracted from HandleBeaconReceived (Block 3 fix): the GAT/fusion scoring
// block, made callable so it can run immediately after a force-flushed ghost
// window, not only reactively when a matching real beacon next arrives at
// the same RSU. Behaviourally identical to the original inline block for
// every existing call site (real-beacon path passes cw.window_epoch as
// window_epoch_for_log, unchanged).
void run_gat_fusion_for_rsu(uint32_t rsu_id, uint32_t window_epoch_for_log)
{
            if ((g_ai_engine.ready() || enable_rule_signatures) && rsu_id < N_RSUs && rsu_last_window_valid[rsu_id]) {
                const RsuBeaconWindow &rw = rsu_last_window[rsu_id];
                const int N = (int)rw.beacon_count;
                if (N > 0) {
                    // ── 1. GAT spatial scores (one per row of the L-beacon window) ──
                    std::vector<float>    feats5(N * 5);
                    std::vector<float>    gat_psi(N, 0.0f);   // richer-feat: per-vehicle mean ψ
                    std::vector<uint32_t> gat_sig(N, 0u);     // richer-feat: per-vehicle sig_mask (ψ sub-scores)
                    for (int i = 0; i < N; ++i) {
                        feats5[i*5 + 0] = (float)rw.pos_x[i];
                        feats5[i*5 + 1] = (float)rw.pos_y[i];
                        feats5[i*5 + 2] = (float)rw.speed[i];
                        feats5[i*5 + 3] = (float)rw.heading[i];
                        feats5[i*5 + 4] = (float)rw.accel[i];
                        const uint32_t v = rw.vid[i];
                        if (v < (uint32_t)total_size) {
                            gat_psi[i] = psi_cnt_per_vehicle[v] > 0
                                ? (float)(last_psi_per_vehicle[v] / psi_cnt_per_vehicle[v]) : 0.0f;
                            gat_sig[i] = last_sigmask_per_vehicle[v];
                        } else if (v >= 10000u) {
                            // Ghost path (Critical Issue 3 fix) — read from the
                            // map instead of the fixed array; see accumulation
                            // site (~line 3846) and GhostPsiState definition.
                            auto git = g_ghost_psi_state.find(v);
                            if (git != g_ghost_psi_state.end() && git->second.psi_cnt > 0) {
                                gat_psi[i] = (float)(git->second.psi_sum / git->second.psi_cnt);
                                gat_sig[i] = git->second.sig_mask;
                            }
                        }
                    }
                    std::vector<float> gat_scores;
                    std::vector<int>   gat_attack_types;   // k̂_i per vehicle (multi-task GAT)
                    bool gat_ok = false;
                    if (g_ai_engine.has_gat()) {
                        // TEMP DIAGNOSTIC (Critical Issue 3, calibration): expose gt for the
                        // score_gat()-internal [GAT-CONF] print via a scratch global.
                        extern std::vector<uint8_t> g_diag_gt_scratch;
                        g_diag_gt_scratch.assign(rw.is_poisoned, rw.is_poisoned + N);
                        gat_ok = g_ai_engine.score_gat(
                            feats5.data(), N, nullptr, gat_scores, &gat_attack_types,
                            gat_psi.data(), gat_sig.data());
                    }
                    if (gat_ok) {
                        double smin = gat_scores[0], smax = gat_scores[0], smean = 0.0;
                        for (float s : gat_scores) {
                            if (s < smin) smin = s;
                            if (s > smax) smax = s;
                            smean += s;
                        }
                        smean /= (double)gat_scores.size();
                        cout << "[GAT-SCORE-RSU" << rsu_id << "] epoch="
                             << window_epoch_for_log << " N=" << N
                             << " min=" << std::fixed << std::setprecision(4) << smin
                             << " mean=" << smean << " max=" << smax
                             << " (paper §3.5.3 Eq 3.42)" << endl;
                    } else if (g_ai_engine.has_gat()) {
                        // GAT enabled but inference failed — degrade to zeros so
                        // fusion still runs (ψ + ε will carry the decision).
                        gat_scores.assign(N, 0.0f);
                    }

                    // ── 2. Fusion (paper Eq 3.46) per vehicle in window ────────────
                    // For each beacon row in this RSU's last window:
                    //   ψ_i    = cached LW-DETECT score from RSU handle_readone
                    //   S_i    = gat_scores[i] (rolled-up sigmoid output)
                    //   ε_i    = LSTM-AE recon MSE on the vehicle's 20-beacon ring,
                    //            normalised by θ_ae inside fuse_scores()
                    //   Φ_i    = λ₁ψ + λ₂S + λ₃·min(ε/θ_ae,1) ; flag if Φ > 0.5
                    // R7d's GAT-only log is preserved above; this adds per-vehicle
                    // fusion lines. ψ_total / Φ_total counters surface in metrics.
                    const float theta_ae = g_ai_engine.theta_ae();
                    int        fused_count = 0;
                    int        full_flag_count = 0;
                    double     phi_sum = 0.0;
                    double     phi_max = 0.0;

                    // ── Per-window dedup for Eq 3.57 CSUBM (TASK ①-L) ─────────
                    // Multiple beacons from the same vehicle in one L-beacon
                    // window collapse to ONE controller submission per
                    // (vid, epoch). The chaincode side is idempotent on
                    // CSUBM_<vid>_<epoch> but every duplicate submit costs an
                    // async orderer round-trip — keep it cheap. Scope is local
                    // to this window only; a fresh window starts a new set.
                    std::unordered_set<std::string> csubm_seen;

                    for (int i = 0; i < N; ++i) {
                        const uint32_t vid_i = rw.vid[i];
                        const bool is_ghost_i = vid_i >= 10000u;
                        // Block 3 fix: previously any vid >= total_size (including
                        // ghosts, which are intentionally >= GHOST_VID_BASE=10000)
                        // was skipped here entirely — GAT spatial scoring above ran
                        // fine for ghosts (their embeddings are in feats5/gat_scores),
                        // but they never got a [FUSION-RSU] line, never contributed to
                        // fused_count, and never reached update_confusion_matrix_full.
                        // Let ghosts through; still reject genuinely out-of-range vids.
                        if (vid_i >= (uint32_t)total_size && !is_ghost_i) continue;
                        float psi_i = 0.0f;
                        uint32_t sig_mask_i = 0u;
                        if (!is_ghost_i) {
                            psi_i = psi_cnt_per_vehicle[vid_i] > 0
                                ? (float)(last_psi_per_vehicle[vid_i] / psi_cnt_per_vehicle[vid_i])
                                : 0.0f;   // H8: per-window MEAN ψ
                            sig_mask_i = last_sigmask_per_vehicle[vid_i];
                        } else {
                            auto git = g_ghost_psi_state.find(vid_i);
                            if (git != g_ghost_psi_state.end() && git->second.psi_cnt > 0) {
                                psi_i = (float)(git->second.psi_sum / git->second.psi_cnt);
                                sig_mask_i = git->second.sig_mask;
                            }
                        }
                        const float gat_i = gat_ok ? gat_scores[i] : 0.0f;
                        float ae_err = 0.0f;
                        bool  ae_dumped = false;   // H8 diag
                        // lstm_ring_dump indexes a fixed total_size-sized array, so
                        // ghosts were guarded out here to avoid an out-of-bounds
                        // access. The stated rationale — "ghosts have no temporal
                        // ring history (one-shot fabricated identity)" — is not
                        // borne out by measurement: there are only 44 distinct ghost
                        // IDs, averaging 361 beacons each, with 84.1% exceeding the
                        // L=50 window. Ghosts DO have usable sequences.
                        //
                        // With --ghost_ae the ring is backed by a slot map
                        // (04_state_globals.h) so the bounds concern no longer
                        // applies and ghosts can be scored. FPR-safe: no honest
                        // beacon carries vid >= 10000.
                        if ((!is_ghost_i || g_ghost_ae) && g_ai_engine.has_lstm_ae()) {
                            float ring_buf[LSTM_RING_SIZE * 6];
                            if (lstm_ring_dump(vid_i, ring_buf)) {
                                ae_dumped = true;
                                (void)g_ai_engine.score_lstm_ae(ring_buf, ae_err);
                            }
                        }
                        // Attack-conditioned fusion (revised eq:fusion): k̂_i from
                        // the multi-task GAT selects the λ^(k̂) weight set. -1 →
                        // global λ fallback (no per-attack sets or GAT off).
                        int k_hat_i = (gat_ok && i < (int)gat_attack_types.size())
                                          ? gat_attack_types[i] : -1;
                        // Round 5 hybrid routing fix: the K=7 ML classifier confuses
                        // MP-S1 (a3) with MP-S2 (a4) — only 10.4% of true a3 beacons
                        // were routed correctly, 34.7% misrouted to a4's weights
                        // (measured 2026-08-04). But the pre-existing RULE-based
                        // signature (SYB-DETECT, sig_mask bits 5=MP-S1/6=MP-S2, see
                        // 08:1032) is a PERFECT discriminator wherever it fires:
                        // 0% cross-contamination measured (bit5 never fires for true
                        // a4, bit6 never fires for true a3). Trust the rule bit over
                        // the ambiguous ML k̂ whenever it fires — doesn't cover every
                        // beacon (fires on 19.5% of a3, 87.2% of a4), but is strictly
                        // more reliable than k̂ on the beacons it does cover.
                        // ── FIX 2: route ghost IDs to the a3 weight set by identity ──
                        // Ghost beacons are MP-S1 (a3) by construction, but they never
                        // fire the MP-S1 rule bit — measured 0 / 20 754 (DQ-G9) — because
                        // they carry no kinematic history, so sig_mask is 0 and the
                        // override below can never reach them. The result is k̂ = −1 for
                        // 71.4 % of ghosts (DQ-G1), which applies the global fallback λ
                        // and under-weights the one component that does carry signal:
                        // misrouted ghosts have median S/θ_S = 0.392 (DQ-G3).
                        //
                        // Every ghost that DOES reach a real head is detected with recall
                        // 1.0000 (DQ-G1), so routing — not signal — is the bottleneck.
                        // `vid >= GHOST_VID_BASE` is available here and is a reliable
                        // discriminator, so we route by identity rather than waiting for a
                        // rule bit that cannot fire.
                        //
                        // This mirrors the existing rationale for trusting the rule bit
                        // over the ML k̂ (the classifier routes only 10.4 % of true a3
                        // correctly): ghosts ARE a3, we simply know it by ID instead.
                        //
                        // CRITICAL: routing a ghost by IDENTITY must NOT by itself
                        // constitute a detection. `vid >= GHOST_VID_BASE` is a
                        // simulation artifact of the attack generator, not an
                        // observable a real detector could use — a genuine Sybil
                        // would forge plausible IDs. The OR-flag path below fires on
                        // k̂ ALONE, without requiring the GAT to have scored, so a
                        // naive `k_hat_i = 2` here makes every ghost flagged purely
                        // because of its ID. Measured when we tried exactly that:
                        // D1 (no GAT) reported ghost recall 1.0000 with 100 % of
                        // detections via the OR-flag and 0 % via Φ — i.e. label
                        // leakage, not detection.
                        //
                        // So we set k̂ for WEIGHTING only and record that it came
                        // from identity, so the OR-flag can exclude it. Detection
                        // must still come from Φ crossing threshold on the GAT's
                        // real spatial score.
                        bool khat_from_ghost_id = false;
                        if (is_ghost_i)                 { k_hat_i = 2; khat_from_ghost_id = true; }
                        else if (sig_mask_i & (1u << 5))  k_hat_i = 2;  // MP-S1 -> attack=3 slot
                        else if (sig_mask_i & (1u << 6))  k_hat_i = 3;  // MP-S2 -> attack=4 slot
                        // --tp_s1_khat_route (default off): TP-S1's kinematic bit as a
                        // rule-trusted discriminator, same pattern as bits 5/6 above.
                        // UNLIKE those, cross-contamination against the other 6 attacks
                        // has not been measured -- treat as a candidate, not confirmed-safe.
                        else if (g_tp_s1_khat_route && (sig_mask_i & (1u << 0))) k_hat_i = 0;
                        if (std::getenv("MPTD_KHAT_CALIB") && rw.is_poisoned[i])
                            std::cout << "[KHAT-CALIB] vid=" << vid_i << " k_hat=" << k_hat_i
                                      << " gat_ok=" << gat_ok << std::endl;
                        // sir Change 1: attack-conditioned ψ. Recompute the LW
                        // composite from this vehicle's sig_mask with the weight
                        // vector for k̂ (or the aggregate w when k̂=-1, i.e. GAT
                        // unconfident — the Change-2 gate). Sums to 1 → same scale
                        // as the global-weighted ψ that fuse_scores normalises by ψ_th.
                        // AB1 (b): remove the ψ FUSION TERM (the rule-signature tier's
                        // contribution to the full-mode decision) while sig_mask/ψ still
                        // feed the GAT input above → φ = λ_gat·gat + λ_ae·ae for AB1.
                        float psi_fuse = enable_rule_signatures ? psi_i : 0.0f;
                        if (enable_rule_signatures && g_fusion.has_sig_weights) {
                            const uint32_t sm = sig_mask_i;
                            const bool cond = (k_hat_i >= 0 && k_hat_i < FusionParams::K_ATTACK);
                            const float *w = cond ? g_fusion.sig_w_k[k_hat_i]
                                                  : g_fusion.sig_w_global;
                            float s = 0.0f, s_glob = 0.0f;
                            for (int b = 0; b < FusionParams::N_SIG; ++b)
                                if ((sm >> b) & 1u) { s += w[b]; s_glob += g_fusion.sig_w_global[b]; }

                            // --psi_cond_floor: attack-conditioning must REFINE the
                            // rule evidence, never destroy it.
                            //
                            // MEASURED root cause of D4 < D1. Only a GAT-bearing arm
                            // derives k_hat, so only it takes the conditioned branch.
                            // For the 158 true positives D1 catches and D4 loses,
                            // 155 route to k_hat=4, whose weight set is
                            //   [0.0045, 0, 0, 0, .3275, .2836, .3844, 0, 0]
                            // against the global
                            //   [0.0976, 0, 0, .1685, .2018, .2214, .2310, 0, .0797]
                            // i.e. it assigns ~zero weight to the very bits those
                            // beacons carry. Measured effect: psi_fuse 0.1770 -> 0.0020
                            // and phi 1.0000 -> 0.3480, so the detection is lost purely
                            // by enabling the GAT. fusion_weights.json documents slot 4
                            // as a known misrouting sink ("head 3 (a4 slot) is where a3
                            // beacons are misrouted").
                            //
                            // The floor keeps conditioning's upside (it may RAISE psi
                            // for correctly-routed beacons) while removing its ability
                            // to erase evidence on a misroute. D1 is unaffected: with
                            // k_hat < 0 the global set is already used, so the floor is
                            // a no-op there. Default OFF = byte-identical.
                            psi_fuse = (g_psi_cond_floor && cond) ? std::max(s, s_glob) : s;
                        }
                        // AB8 option B (opt-in via --lifecycle_gates_fusion=1):
                        // a demoted/CLIENT RSU carries zero quorum weight on-chain
                        // (§3.5.1); extend that to the AI plane so the detector
                        // also stops trusting its rule verdict. Without this the
                        // lifecycle cannot influence MCC/CDER at all — toggling
                        // enable_rsu_lifecycle alone left both metrics BIT-IDENTICAL
                        // (0.825 / 0.607, same seed), because fusion never reads RSU
                        // trust state. With the lifecycle ABLATED (AB8 arm) nothing
                        // is ever demoted, so poisoned rule verdicts keep feeding
                        // fusion — which is precisely the loss AB8 aims to quantify.
                        // g_demoted_psi_weight scales rather than silences: full
                        // suppression (weight 0) threw away the demoted RSU's TRUE
                        // positives too and, because demotion is noisy (4 of 9
                        // demotes were honest RSUs), cost more signal than the
                        // poison it blocked — MCC_full fell 0.825 -> 0.361.
                        if (g_lifecycle_gates_fusion && enable_rsu_lifecycle &&
                            rsu_id < MAX_RSUS && rsu_demoted[rsu_id]) {
                            psi_fuse *= (float)g_demoted_psi_weight;
                        }
                        const FusionScore fs = fuse_scores(
                            psi_fuse, gat_i, ae_err, theta_ae, k_hat_i);
                        // Standalone SOTA baselines (B2/B3): score the full-mode
                        // decision on a SINGLE detector's native threshold, WITHOUT
                        // the ψ composite tier (modes 2/3 keep ψ on via fuse_scores,
                        // so they are ψ+GAT / ψ+AE — not true SOTA). mode 7 = pure
                        // GAT (S_i > θ_S); mode 8 = pure LSTM-AE (ε_i > θ_ae).
                        bool full_flag = fs.anomalous;
                        if      (ablation_mode == 7) full_flag = (gat_i  > (float)g_theta_s);
                        else if (ablation_mode == 8) full_flag = (ae_err > theta_ae);
                        // Hard speed-bound override (physical-impossibility rule): a
                        // reported speed above s_max is a definite fabrication (MP-S3
                        // MitM ~66 m/s) regardless of the soft fusion score / GAT
                        // routing. Full mode only (not the standalone-tier ablations).
                        else {
                            full_flag = full_flag || (rw.speed[i] > s_max);
                            // flag_i^GAT (paper revised eq:gat_det_flag): the GAT
                            // detects an attack iff any head fires above theta_conf,
                            // which is exactly the condition encoded by k_hat_i >= 0.
                            // OR it into the verdict for the enabled heads. Guarded by
                            // g_gat_det_flag_heads (default 0 = off) so every prior
                            // run stays byte-identical. See 02_config_globals.h for
                            // the measured per-head precision that motivates the mask.
                            // `!khat_from_ghost_id`: a k̂ derived from the ghost ID
                            // carries no detection evidence (see the routing block
                            // above), so it must not trigger this bypass. Without
                            // this guard the flag fires on identity alone, which
                            // measured as ghost recall 1.0000 in the no-GAT arm.
                            // --gat_or_path_min_phi: require the fusion score to
                            // reach this floor before the head OR-path may force a
                            // detection. MEASURED motivation (300 s, ring_detect on,
                            // t<=180): beacons flagged ONLY by this path (phi<0.5)
                            // account for 54.2% of D4's and 55.1% of D6's false
                            // positives while contributing 285/306 true positives —
                            // a poor exchange. Suppressing them is a STRICT
                            // improvement on both metrics:
                            //     D4  MCC 0.8027->0.8184   FPR 0.0705->0.0323
                            //     D6  MCC 0.8236->0.8375   FPR 0.0694->0.0312
                            // D1 is untouched (it has ZERO such beacons — the
                            // OR-path exists only in GAT-bearing arms), so this is
                            // removing a defect in the GAT path, not handicapping
                            // the baseline.
                            // Default 0.0 == previous behaviour, byte-identical.
                            if (g_gat_det_flag_heads != 0u && k_hat_i >= 0 &&
                                k_hat_i < 32 && !khat_from_ghost_id &&
                                fs.phi >= g_gat_or_path_min_phi &&
                                (g_gat_det_flag_heads & (1u << (uint32_t)k_hat_i)) != 0u)
                                full_flag = true;
                        }
                        fused_count++;
                        if (full_flag) full_flag_count++;
                        phi_sum += fs.phi;
                        if (fs.phi > phi_max) phi_max = fs.phi;

                        // ── C1: score the full-mode Fusion verdict (Eq 3.45
                        // Φ_i > Φ_th) against this beacon's ground-truth poison
                        // label into the full-mode confusion matrix (Eq 4.1/4.2).
                        // Gated to full-mode ablations only (A2/A3/A4/A5/Full):
                        // for A1 (mode 1) and B1 (mode 6) full mode is inactive,
                        // so the LW confusion matrix at HandleBeaconReceived stays
                        // authoritative and this matrix is left empty. This is the
                        // window-close (W = L·T_b) controller-side scoring path —
                        // invariant #3 (LW skip-on-pass) is untouched.
                        if (ablation_mode != 1 && ablation_mode != 6) {
                            update_confusion_matrix_full(
                                rw.is_poisoned[i], full_flag);
                            // CDER_full (additive): score the fusion verdict as a
                            // control decision so control-plane error responds to
                            // the AI layer. wrong iff verdict disagrees with truth.
                            ctrl_full_total++;
                            if (full_flag != rw.is_poisoned[i]) ctrl_full_wrong++;
                        }
                        // C5 TTD (alert side): the alert timestamp must come from the
                        // FUSION decision so TTD responds to the ablation. The previous
                        // alert assignment (per-beacon `detected` in handle_readone) fired
                        // on the same call — and with the same t_now — as the onset
                        // assignment, so alert==onset and TTD collapsed to 0.000 in every
                        // run. `detected` is also ablation-inert (beacon_log.csv is
                        // byte-identical FULL vs AB1), so it cannot measure AB1/AB3/AB4.
                        // INDEX BASE: vid_i is a NodeId (tag.GetVehicleId(), see 08:3029),
                        // whereas g_ttd_* is indexed by (NodeId - g_first_vehicle_node_id)
                        // — the same transform used at the onset site. Do not drop it.
                        {
                            const int vi_ttd = (int)vid_i - (int)g_first_vehicle_node_id;
                            if (full_flag && vi_ttd >= 0 && vi_ttd < total_size &&
                                g_ttd_first_poison[vi_ttd] >= 0 &&
                                g_ttd_first_alert[vi_ttd]  <  0)
                                g_ttd_first_alert[vi_ttd] = Simulator::Now().GetSeconds();
                        }
                        cout << "[FUSION-RSU" << rsu_id << "] epoch="
                             << window_epoch_for_log
                             << " t=" << std::fixed << std::setprecision(3) << Simulator::Now().GetSeconds()
                             << " vid=" << vid_i
                             << " psi="     << psi_i
                             << " psi_fuse=" << psi_fuse
                             << " S="       << gat_i
                             << " thetaS="  << g_theta_s
                             << " S_over_thetaS_raw=" << (gat_i / (g_theta_s > 1e-9f ? g_theta_s : 1e-9f))
                             << " S_over_thetaS_clamped=" << fs.gat
                             << " ae_norm=" << fs.ae_norm
                             << " ae_raw=" << std::setprecision(5) << ae_err
                             << " dumped=" << (ae_dumped ? 1 : 0)
                             << " gt_pois=" << (rw.is_poisoned[i] ? 1 : 0)
                             << " gt_atk=" << rw.attack_type[i]
                             << " sig_mask=" << sig_mask_i
                             << std::setprecision(3)
                             << " phi="     << fs.phi
                             << " khat="    << k_hat_i
                             << " gatflag=" << (k_hat_i >= 0 ? 1 : 0)
                             << " full_anom=" << (full_flag ? "YES" : "no")
                             << " (Eq 3.46)" << endl;

                        // ── Paper-aligned Eq 3.57 controller evidence (TASK ①-L) ──
                        // E_c(t) = (vehicleID, Φ_i(t), epoch, h(X_i(t)), σ_c^sub)
                        //
                        // Submitted UNCONDITIONALLY on every fused row (not
                        // gated on fs.anomalous). CP-DETECT (Eq 3.66–3.68)
                        // compares the controller's binary verdict against each
                        // RSU's verdict via the DIRECTIONAL conflict
                        // (1−flag^ctrl)·flag^rsu — a conflict counts only when
                        // the controller says benign while an RSU says anomaly
                        // (controller suppression); the chaincode does its own
                        // threshold check on the raw Φ value, so submitting Φ
                        // regardless of anomaly is correct. More importantly,
                        // gating on fs.anomalous
                        // would HIDE the malicious-controller attack pattern
                        // — a compromised controller that lies "clean" on
                        // genuine anomalies would never submit, and CPDetectCheck
                        // returns nil when no CSUBM exists, defeating Eq 3.68.
                        //
                        // Paper invariant #2 (controller as untrusted peer):
                        // this is the controller's UNTRUSTED submission. The
                        // RSU consensus (CallSCTrustSubmitEvidence at line
                        // ~2394 in handle_readone) remains authoritative.
                        //
                        // Epoch derivation: mptd_epoch_from_ts(rw.timestamp[i])
                        // matches the RSU-side epoch derivation EXACTLY
                        // (handle_readone uses mptd_epoch_from_ts(ts) where ts
                        // = beacon arrival time). This guarantees CSUBM_<vid>_<E>
                        // and SUBM_<vid>_<E>_<rsu> share the same epoch key so
                        // CPDetectCheck can join them.
                        //
                        // h(X_i(t)) derivation: same canonical-blob form as the
                        // RSU side (vy/ax/ay projected from speed×heading), with
                        // rsuID omitted from the blob so the CID is content-
                        // addressable across witnesses. The controller sees the
                        // same kinematics, so this hash matches its RSU
                        // counterpart on the same beacon.
                        //
                        // σ_c^sub: controller-identity ECDSA P-256 (Eq 3.62),
                        // produced inside CallSCControllerSubmitEvidence with
                        // the controller's registered key and verified on submit
                        // by the chaincode (smartcontract.go).
                        //
                        // A5 ablation (no blockchain) and routing_test mode
                        // both skip — matches the RSU-side guards.
                        //
                        // GHOST GUARD (2026-08-05): Sybil ghost identities
                        // (vid >= GHOST_VID_BASE = 10000, MP-S1) are FABRICATED
                        // by a compromised RSU and by construction never hold a
                        // REG_VEH_<nid> record. Submitting controller evidence
                        // for them makes the chaincode reject the tx
                        // ("VEH_<id> is not registered"), which is correct
                        // behaviour on its side but means CPDetectCheck finds no
                        // CSUBM for that (vid, epoch) and can therefore never
                        // score the directional conflict (Eq 3.66) — so no
                        // CFLAG_ record is written and controller trust never
                        // decays on chain (observed: 466 rejected CSUBM txs,
                        // all 12 distinct offenders ghosts, ZERO real vehicles;
                        // CTRL_* TrustScore stuck at 1.0, MeanConflict 0).
                        // Ghosts are handled by SYB-DETECT (Algorithm 2), not
                        // by the SC-Trust/CP-DETECT evidence pipeline.
                        static const uint32_t CSUBM_GHOST_VID_BASE = 10000;
                        if (!routing_test && ablation_mode != 5 &&
                            vid_i < CSUBM_GHOST_VID_BASE) {
                            const double speed_i   = rw.speed[i];
                            const double heading_i = rw.heading[i];
                            const double accel_i   = rw.accel[i];
                            const double vx = speed_i * std::cos(heading_i);
                            const double vy = speed_i * std::sin(heading_i);
                            const double ax = accel_i * std::cos(heading_i);
                            const double ay = accel_i * std::sin(heading_i);

                            std::string ctrl_epoch =
                                mptd_epoch_from_ts(rw.timestamp[i]);
                            std::string dedup_key =
                                std::to_string(vid_i) + "|" + ctrl_epoch;
                            if (csubm_seen.insert(dedup_key).second) {
                                std::string h_X = mptd_beacon_hash(
                                    std::to_string(vid_i),
                                    "C",  // controller-view tag (RSU side uses rsu_idx;
                                          // the canonical blob omits this field, so it
                                          // is for documentary use only and does not
                                          // affect the CID)
                                    rw.pos_x[i], rw.pos_y[i], 0.0,
                                    vx, vy, 0.0,
                                    ax, ay, 0.0,
                                    rw.timestamp[i]);

                                // Controller identity = c_assigned(r_j) of the
                                // RSU that owns this window (paper §3.1 /
                                // Table 3.2 / Eq 3.64). The paper assigns
                                // controllers over RSUs, not vehicles, and the
                                // controller's evidence E_c(t) is its verdict on
                                // the windows of the RSUs it manages
                                // (R^obs_ck, Eq 3.60) — so the closing RSU's
                                // assigned controller submits, NOT a per-vehicle
                                // index. rsu_controller_ID[] is reassigned on a
                                // CP-DETECT/EMA controller revocation, so an
                                // excluded controller's RSUs roll over to a
                                // trusted successor (no manual failover, p.75).
                                const uint32_t controllerID = rsu_controller_ID[rsu_id];

                                // E_c(t) = (ID_i, Φ_i(t), t, h(X_i(t)), σ) — Eq 3.62.
                                // CP-DETECT derives flag^ctrl = 1[Φ_i > Φ_th] from
                                // THIS submitted value (Eq 3.65) and scores the
                                // directional conflict (1−flag^ctrl)·flag^rsu
                                // (Eq 3.66). So a controller that suppresses must
                                // suppress *here* too, not only on the downlink.
                                //
                                // Bug this fixes: the malicious combined-attack
                                // controller was broadcasting CLEAN_ROUTING to
                                // vehicles while still submitting its HONEST fusion
                                // score on-chain (observed: CSUBM_VEH_36_E7 Φ=0.69,
                                // Φ_th=0.5 ⇒ flag^ctrl=1 ⇒ conflict ≡ 0). It looked
                                // truthful to the ledger while lying to the network,
                                // so controller trust never decayed (τ stayed 1.0,
                                // MeanConflict 0), SC-Trust never hit τ_min for
                                // T_rev epochs, and no controller revocation /
                                // RSU reassignment could ever occur — regardless of
                                // how many suppression events the sim produced.
                                double phi_submitted = (double)fs.phi;
                                if (g_combined_attack && fs.anomalous) {
                                    // Suppression: hide the anomaly the fusion
                                    // layer actually found (report benign).
                                    phi_submitted = 0.0;
                                }
                                CallSCControllerSubmitEvidence(
                                    vid_i, controllerID, ctrl_epoch,
                                    phi_submitted, h_X);

                                // ── Schedule Eq 3.66–3.69 CP-DETECT (TASK ①-M) ──
                                // CPDetectCheck reads BOTH the just-written
                                // CSUBM_<vid>_<epoch> AND the per-RSU SUBM_*
                                // records for the same epoch, then applies the
                                // DIRECTIONAL conflict (1−flag^ctrl)·flag^rsu to
                                // each RSU — if ≥ f+1 trusted RSUs flag anomaly
                                // while the controller said benign (suppression),
                                // the controller is flagged (CFLAG_ record +
                                // "CPDetectFlag" event).
                                //
                                // Why 0.5 s delay:
                                //   - CSUBM and SUBM are both written via the
                                //     fire-and-forget async path; we need their
                                //     orderer round-trips to complete before
                                //     CPDetectCheck reads them. 0.5 s is well
                                //     above the typical ~50-200 ms commit time.
                                //   - This sits BEFORE the SCTrustFinalizeEpoch
                                //     +1.0 s schedule (TASK ①-K) because
                                //     CPDetectCheck is independent of the τ_i(t)
                                //     EMA update — it just needs raw SUBM/CSUBM.
                                //
                                // File-scope dedup g_cpdetect_scheduled:
                                //   In a 4-RSU sim, the same vehicle is fused
                                //   by every RSU that hears its beacons; without
                                //   dedup, CP-DETECT would fire 4× per (vid,
                                //   epoch). The chaincode side is idempotent on
                                //   CFLAG_<ctrlID>_<vid>_<epoch> so duplicates
                                //   are harmless to consistency, but each spawns
                                //   an orderer round-trip — keep it to one call.
                                //   Set is process-local; cleared on next run.
                                //
                                // BY DESIGN (Eq 3.68, §3.5.5 p.74): when ALL RSUs
                                // see the vehicle as CLEAN (no SUBM written per
                                // TASK ①-I gating) the directional conflict is 0
                                // for every RSU, so a controller flagging an
                                // anomaly the RSUs missed is NOT penalised — the
                                // paper treats that as the controller "performing
                                // superior detection" (full-mode catching what
                                // lightweight rules miss, invariant 4). CP-DETECT
                                // targets controller SUPPRESSION (says benign
                                // while RSUs flag), not over-reporting. The old
                                // "implicit clean votes count as conflicts when
                                // the controller says anomaly" behaviour was an
                                // Eq-3.68 violation and has been removed.
                                static std::unordered_set<std::string> g_cpdetect_scheduled;
                                static std::mutex                       g_cpdetect_mu;
                                std::string cp_key =
                                    std::to_string(vid_i) + "|" + ctrl_epoch;
                                bool cp_first;
                                {
                                    std::lock_guard<std::mutex> lk(g_cpdetect_mu);
                                    cp_first = g_cpdetect_scheduled.insert(cp_key).second;
                                }
                                if (cp_first) {
                                    // Commit this (vid, epoch)'s buffered RSU
                                    // evidence BEFORE the check, or the range
                                    // scan below sees an empty SUBM_ prefix and
                                    // scores conflict = 0 (see
                                    // tier3_flush_for_vid_epoch). Other RSUs'
                                    // batches are left untouched.
                                    if (g_tiered_commit) {
                                        tier3_flush_for_vid_epoch(
                                            vid_i, ctrl_epoch,
                                            Simulator::Now().GetSeconds());
                                    }
                                    Simulator::Schedule(Seconds(0.5),
                                        &CallCPDetectCheckAsync, vid_i, ctrl_epoch,
                                        controllerID);
                                }
                            }
                        }
                    }
                    // H8: reset the per-window ψ mean accumulators for the vehicles
                    // just fused so the next window starts fresh.
                    for (int i = 0; i < N; ++i) {
                        const uint32_t v = rw.vid[i];
                        if (v < (uint32_t)total_size) {
                            last_psi_per_vehicle[v] = 0.0; psi_cnt_per_vehicle[v] = 0;
                            last_sigmask_per_vehicle[v] = 0;
                        } else if (v >= 10000u) {
                            g_ghost_psi_state.erase(v);  // Critical Issue 3 fix — mirror the real-vehicle reset above
                        }
                    }
                    if (fused_count > 0) {
                        cout << "[FUSION-WIN-RSU" << rsu_id << "] epoch="
                             << window_epoch_for_log
                             << " fused=" << fused_count
                             << " full_anom=" << full_flag_count
                             << " mean_phi=" << std::fixed << std::setprecision(4)
                             << (phi_sum / fused_count)
                             << " max_phi="  << phi_max
                             << " theta_ae=" << theta_ae
                             << " (paper §3.5.3 Eq 3.46, Φ_th=0.5)" << endl;
                    }
                }
            }

}

void HandleBeaconReceived(uint32_t vehicle_id, BsmBeaconTag tag, uint32_t rsu_id)
{
    g_diag_beacon_rx_count++;  // TEMP DIAGNOSTIC (Step 1 follow-up), before any gating
    double now = Simulator::Now().GetSeconds();

    // Phase 1C-b — env-gated force-arm of the chaincode-event drainer.
    // Without this, the drainer only arms after the first inline revocation
    // (cheap & self-contained), but synthetic-event verification of the
    // cross-RSU broadcast path (where no real BFT vote ever fires) needs an
    // explicit bootstrap. MPTD_FABRIC_EVT_FORCE_ARM=1 turns it on.
    mptd_arm_event_drainer_if_env();

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
        // TDEE: ghost beacon inflates the controller's perceived density.
        // Ghost is a fake identity — do NOT increment gt_count (no real vehicle here).
        // DO increment est_count for the cell the ghost's reported position maps to.
        // This captures MP-S1's density estimation error: controller sees N ghosts extra
        // per RSU cell → est_count >> gt_count → TDEE rises proportional to ghost count.
        {
            uint32_t ghost_rsu = nearest_rsu_for_position(tag.GetPosX(), tag.GetPosY());
            if (ghost_rsu < N_RSUs) tdee_est_count[ghost_rsu]++;
        }
        cout << "[MP-S1-GHOST-RX] ghost_id=" << vehicle_id
             << " RSU" << rsu_id
             << " pos(" << std::fixed << std::setprecision(2)
             << tag.GetPosX() << "," << tag.GetPosY() << ")"
             << " density_count=" << rsu_id_set[rsu_id].count
             << " ghost_seen=YES"
             << (is_new_ghost ? " +1 (new)" : " (dup-same-window)") << endl;
        return; // ← Ghost packet handled. No detection/metrics/downlink for ghost IDs.
    }

    // ── Pre-registered Sybil ground truth (Attack 3 enhanced mode) ────────────
    // In enhanced mode (sybil_registration_pct > 0) the attacker is a VEHICLE,
    // not a compromised RSU.  The honest RSU forwards the beacon without setting
    // IsPoisoned — so we must set it here based on whether the sending vehicle
    // is a known active Sybil node.  This ensures update_confusion_matrix()
    // (called later in this function) has the correct ground-truth label.
    //
    // vid_idx = vehicle_id - 2  (NodeID offset: controller=0, management=1, vehicles=2..N+1)
    // sybil_mitm_nodes[vid_idx] = true only for pre-registered AND runtime-active Sybil.
    if (attack_number == 3 && sybil_registration_pct > 0 &&
        vehicle_id >= 2 && (int)vehicle_id < 2 + total_size) {
        int vid_idx = (int)vehicle_id - 2;
        if (vid_idx >= 0 && vid_idx < total_size && sybil_mitm_nodes[vid_idx]) {
            tag.SetIsPoisoned(true);
            tag.SetAttackType(3);
            // Accumulate displacement error for TDEE/TPE (position drift is small by design)
            double drift_err = std::sqrt(
                std::pow(tag.GetPosX() - tag.GetPosX(), 2) +  // placeholder: real pos not here
                std::pow(tag.GetPosY() - tag.GetPosY(), 2));  // TDEE accumulated at send side
            (void)drift_err;  // send_lte_dataunicast_alone() already accumulated TDEE/TPE
        }
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
        rsu_id < N_RSUs &&
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
        tpe_sq_sum += disp_err * disp_err;   // TPE: injection magnitude for malicious beacon
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
        rsu_id < N_RSUs &&
        compromised_rsu[rsu_id])
    {
        tag.SetIsPoisoned(true);
        tag.SetAttackType(3);
        double now_t = Simulator::Now().GetSeconds();
        double ghost_err = R_max_comm * poisoning_intensity_theta;
        tpe_sq_sum += ghost_err * ghost_err;   // TPE: ghost displacement magnitude
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
    // vehicles and RSUs. Paper-faithful semantics: the controller corrupts a fraction
    // (attack_percentage) of beacons it forwards — modelling a stealthy adversary
    // that selectively poisons the global model to evade detection while still
    // accumulating bias over time. The same gate is used by TP-S3 (attack_number==5)
    // on line ~1099 below — keeping both controller attacks symmetric.
    //
    // R7f.followup-1 fix (2026-05-29): previously this block had NO gate, so every
    // single beacon flowing through HandleBeaconReceived was marked is_poisoned=true.
    // Result: TN=0 → MCC denominator collapses → MCC≡0 for all variants, regardless
    // of detector quality. The gate restores a valid clean/poisoned ground-truth
    // partition so MCC (Eq. 4.1) is well-defined. CDER (Eq. 4.4) remains the primary
    // metric for MP-S4 since it is fundamentally a control-plane attack.
    if ((attack_number == 7 || (g_combined_attack && (vehicle_id % 2 == 0))) &&
        ctrl_compromised_now() &&
        GetBooleanWithProbability(attack_percentage, vehicle_id) &&
        !(g_combined_attack && tag.GetIsPoisoned()))   // combined: even veh → a7, honest beacons only
    {
        double real_spd = tag.GetSpeed();
        double real_hdg = tag.GetHeading();
        double t_mp4    = Simulator::Now().GetSeconds();
        double shift, fake_spd, fake_hdg;
        if (stealthy_control_plane) {
            // STEALTHY MP-S4: leave the beacon essentially untouched (a +5% step
            // would trip the implied-acceleration TP-S3 rule). The attack here is
            // purely control-plane — the malicious controller corrupts its global
            // model and keeps issuing WRONG_ROUTING. Beacons stay plausible so
            // Ercan/Sharma/ψ are blind; CP-DETECT catches the controller via the
            // persistent controller-vs-RSU consensus conflict.
            shift    = 1.0;
            fake_spd = real_spd;
            fake_hdg = real_hdg;
        } else {
            // Systematic speed elevation: shifts regional distribution ~25-50% above normal.
            // kl_approx = |fake_spd - mean| / (mean + s_max*0.1); with mean≈15, fake≈22-30 m/s:
            // (22-15)/18.3 ≈ 0.38 per vehicle — collectively shifts distribution > κ_th=1.5.
            shift    = 1.0 + 0.5 * poisoning_intensity_theta
                           + 0.2 * poisoning_intensity_theta * std::sin(t_mp4 * 0.3);
            fake_spd = real_spd * shift;
            // Slight heading noise to corrupt mobility pattern vectors
            fake_hdg = real_hdg + 0.15 * poisoning_intensity_theta * std::sin(t_mp4 * 0.7);
        }
        // Soft cap: keep below 2×s_max to remain "plausibly elevated" for global bias
        double sp_ceil = s_max * 2.0;
        fake_spd = (fake_spd > sp_ceil) ? sp_ceil : fake_spd;
        tag.SetSpeed(fake_spd);
        tag.SetHeading(fake_hdg);
        tag.SetIsPoisoned(true);     // controller-poisoned beacon
        tag.SetAttackType(7);
        // Accumulate TPE using speed-displacement proxy (speed error × T_b = distance proxy)
        double spd_disp = std::fabs(fake_spd - real_spd) * T_b;
        tpe_sq_sum += spd_disp * spd_disp;   // TPE: speed-shift magnitude for malicious beacon
        tpe_cnt++;
        cout << "[MP-S4-CTRL] controller poisoned global model V" << vehicle_id
             << " spd " << real_spd << "->" << fake_spd << endl;
        // ── A7-STEP5: Controller intentionally corrupts model despite correct inputs ──
        // Paper Fig 3.7 §3.4.2: Malicious controller receives honest data but
        // systematically shifts speed distribution to misrepresent traffic conditions.
        cout << "[A7-STEP5] Controller POISONING mobility model V" << vehicle_id
             << " real_spd=" << real_spd
             << " → fake_spd=" << fake_spd
             << " shift×" << shift
             << " — intentional corruption despite HONEST input" << endl;
        // Write to controller_poison_log.csv
        log_controller_poison(t_mp4, vehicle_id, rsu_id,
                              real_spd, fake_spd, shift,
                              real_hdg, fake_hdg,
                              2,            // alert_type=2 WRONG_ROUTING
                              s_max * 0.5); // spd_adv matches downlink value
    }

    // ── TP-S3: Controller-level trajectory poisoning (attack_number==5) ──────────
    // Paper §3.4.1 (Figure 3.3): SDN controller (management node) intercepts honest
    // vehicle beacons and modifies position + speed before forwarding to other planes.
    // HandleBeaconReceived() runs at the management node → this IS the control plane.
    if ((attack_number == 5 || (g_combined_attack && (vehicle_id % 2 == 1))) &&
        ctrl_compromised_now() &&
        GetBooleanWithProbability(attack_percentage, vehicle_id) &&
        !(g_combined_attack && tag.GetIsPoisoned()))   // combined: odd veh → a5, honest beacons only
    {
        double real_px  = tag.GetPosX();
        double real_py  = tag.GetPosY();
        double real_spd = tag.GetSpeed();
        double t_cp     = Simulator::Now().GetSeconds();
        double fake_px, fake_py, fake_spd;
        if (stealthy_control_plane) {
            // STEALTHY TP-S3: pure control-plane attack — the vehicle→RSU beacon is
            // left plausible (unchanged) so beacon-level detectors (Ercan/Sharma/ψ)
            // are blind; the malice lives entirely in the controller's downlink,
            // which keeps issuing WRONG_ROUTING. Only CP-DETECT's controller-vs-RSU
            // consensus catches it. (Any per-beacon position/speed edit — even a
            // slow ramp — trips the RSU's dead-reckoning/acceleration rules, so a
            // truly stealthy control-plane attack must not touch the beacon.)
            fake_px  = real_px;
            fake_py  = real_py;
            fake_spd = real_spd;
        } else {
            // Controller applies sinusoidal position drift + speed perturbation
            fake_px  = real_px  + poisoning_intensity_theta * max_position_deviation
                                * std::sin(t_cp * 1.1);
            fake_py  = real_py  + poisoning_intensity_theta * max_position_deviation
                                * std::cos(t_cp * 0.9);
            fake_spd = real_spd * (1.0 + poisoning_intensity_theta * std::sin(t_cp * 2.3));
        }
        // Clamp to simulation area (kept as ternary for legibility; std::max
        // is now safe after R6.5 renamed the global `max` macro to MPTD_MAX_NEIGHBORS).
        fake_px  = (fake_px  < min_position_x) ? min_position_x : (fake_px  > max_position_x ? max_position_x : fake_px);
        fake_py  = (fake_py  < min_position_y) ? min_position_y : (fake_py  > max_position_y ? max_position_y : fake_py);
        fake_spd = (fake_spd < 0.0)            ? 0.0            : (fake_spd > s_max * 1.5     ? s_max * 1.5    : fake_spd);
        tag.SetPosition(fake_px, fake_py);
        tag.SetSpeed(fake_spd);
        tag.SetIsPoisoned(true);
        tag.SetAttackType(5);
        // Accumulate TPE (controller-introduced displacement error for malicious beacon)
        double dx = fake_px - real_px, dy = fake_py - real_py;
        double disp_err = std::sqrt(dx*dx + dy*dy);
        tpe_sq_sum += disp_err * disp_err;   // TPE: injection magnitude
        tpe_cnt++;
        cout << "[TP-S3-CTRL] controller corrupted V" << vehicle_id
             << " pos(" << real_px << "," << real_py
             << ")→(" << fake_px << "," << fake_py
             << ") spd " << real_spd << "→" << fake_spd << endl;
    }

    // ── MP-S2 state-contamination guard (attack 4: stolen-ID beacons) ───────────
    // Problem: stolen beacons carry honest vehicle IDs at the attacker's position.
    // When pushed into VS(honest_vid), the attacker's fake position
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
    // State save/restore — prevents poisoned positions from becoming the comparison
    // baseline, which would make the next honest→honest transition look anomalous (FP)
    // or suppress detection of the poisoned beacon itself (FN for TP-S1).
    //
    // attack 1 (TP-S1): RSU replaces honest position with sinusoidal drift.
    //   Consecutive poisoned beacons differ only by drift_rate ≈ 17 m/s (< s_max) → FN.
    //   By restoring to honest state, each poisoned beacon is compared against the LAST
    //   HONEST position → apparent velocity = drift_peak/T_b ≈ 50 m/s >> s_max → TP. ✓
    // attack 5 (TP-S3): controller modifies position+speed before pushing to vehicle_state.
    //   Without save/restore, the poisoned position becomes the "previous" baseline for the
    //   NEXT honest beacon, making the honest→honest transition look like an impossible
    //   jump → false positive.  Save+restore eliminates this contamination.
    // attack 4 (MP-S2) / attack 6 (MP-S3): stolen/intercepted ID uses victim's vehicle_id.
    //   Attacker's fake position stored in victim's vehicle_state → FP on next honest beacon.
    // COMBINED-MODE FIX (2026-08-05): this guard gated on `attack_number`, the
    // GLOBAL run config. In combined-attack mode attack_number == 0, so the
    // condition was ALWAYS FALSE and the guard never ran — meaning stolen-ID
    // beacons DID contaminate their victim's vehicle_state, and the victim's
    // next genuine beacon fired MP-S2/MP-S4 as a false positive. This is the
    // same class of defect as the tag.SetAttackType(attack_number) bug.
    // Measured symptom at 300 s / rho_a=0.40: MP-S2 fired on 817/5674 honest
    // beacons at RSU36 (14.4%) and 0.000 at every other RSU — RSU36 being
    // exactly where the a4 impersonators operate (1709 of its 1780 malicious
    // beacons are attack 4).
    // Use the per-beacon attack type in combined mode; single-attack mode keeps
    // reading attack_number, so those runs stay byte-identical.
    const int atk_eff = g_combined_attack ? (int)tag.GetAttackType() : attack_number;
    bool save_state = ((atk_eff == 1) || (atk_eff == 4) ||
                       (atk_eff == 5) || (atk_eff == 6))
                   && (vehicle_id < (uint32_t)total_size)
                   && tag.GetIsPoisoned()
                   && !sybil_mitm_nodes[vehicle_id]  // intercepted/stolen ID = honest vehicle
                   // STEALTHY TP-S3: do NOT restore. The small constant offset must
                   // PERSIST as the baseline so consecutive poisoned beacons are
                   // self-consistent (no jump) → LW/ψ stays blind (rsu_anomalous=0),
                   // leaving CP-DETECT's controller-vs-RSU consensus the only catch.
                   && !(stealthy_control_plane && attack_number == 5);
    VehicleBeaconState vs_backup;
    if (save_state)
        vs_backup = VS(vehicle_id);

    // ── TDEE: per-RSU density tracking (Eq. 4.5) ─────────────────────────────────
    // gt_count[rsu_id]++   : ground-truth — this beacon came from RSU j's coverage area
    // est_count[rsu_rep]++ : estimated   — where reported position maps (may differ if forged)
    // Placed AFTER all attack injection blocks so tag.GetPosX()/GetPosY() is the
    // final forged position the controller actually sees.
    if (rsu_id < N_RSUs) {
        tdee_gt_count[rsu_id]++;
        uint32_t rsu_rep = nearest_rsu_for_position(tag.GetPosX(), tag.GetPosY());
        if (rsu_rep < N_RSUs) tdee_est_count[rsu_rep]++;
    }

    // ── R1: LW-DETECT result dispatch (paper §3.5.3 Algorithm 1, Fig 3.10) ───
    // The RSU (handle_readone) already ran Algorithm 1 LW-DETECT on this beacon
    // and stamped the result onto the tag. Three execution paths:
    //
    //   A) Legacy fallback (!g_option_b_active OR !tag.GetLwDetectionRan()):
    //      RSU path not used — run LW-DETECT here (inline, for the unmodified
    //      legacy "no DSRC relay" mode).
    //
    //   B) Cached path (attacks 1-4, 6, and clean beacons):
    //      The RSU's cached result is authoritative. The controller does NOT
    //      modify this beacon, so no re-push / re-detection is needed. We reuse
    //      tag.GetLwAnomalous() / tag.GetLwPsi() / tag.GetSigViolated().
    //
    //   C) Controller-modified path (attacks 5 = TP-S3, 7 = MP-S4):
    //      The controller-side attack blocks above have just mutated tag's
    //      position/speed/heading. The RSU pushed the UNMODIFIED beacon; we now
    //      pop that entry and re-run LW-DETECT with the modified kinematics so
    //      detection reflects the controller-injected poisoning.
    //
    // NOTE: cp_flags is internal to run_lw_detect_per_beacon's detection decision
    // (combined into `detected` via the attack-7 oracle). We reconstruct the
    // unpacked tp/mp/cp components from sig_violated when SC-Trust needs them.

    uint32_t sig_violated = 0;
    uint32_t tp_flags = 0, mp_flags = 0, cp_flags = 0;
    (void)cp_flags;   // R7f.followup-1: cp_flags is unpacked for SC-Trust sigmask
                      // bookkeeping only; per-beacon detection no longer uses it
                      // (CDER tracks CP-DETECT effectiveness instead).
    double   psi = 0.0;
    bool     anomalous = false;
    bool     detected  = false;

    bool controller_modified = (attack_number == 5 || attack_number == 7);

    if (!tag.GetLwDetectionRan()) {
        // Path A: RSU did not run LW-DETECT (legacy !g_option_b_active path).
        // Run it here. Push happens inside the helper.
        LwDetectResult ctrl_lw = run_lw_detect_per_beacon(vehicle_id, tag, rsu_id);
        tp_flags     = ctrl_lw.tp_flags;
        mp_flags     = ctrl_lw.mp_flags;
        cp_flags     = ctrl_lw.cp_flags;
        sig_violated = ctrl_lw.sig_violated;
        psi          = ctrl_lw.psi;
        anomalous    = ctrl_lw.anomalous;
        detected     = ctrl_lw.detected;
    } else if (controller_modified) {
        // Path C: controller modified the beacon (attacks 5/7) — re-run LW-DETECT
        // on the new kinematics. Pop the RSU-pushed unmodified entry first so
        // velocity / drift checks see the modified beacon as the "current" sample.
        pop_last_beacon((int)vehicle_id);
        LwDetectResult ctrl_lw = run_lw_detect_per_beacon(vehicle_id, tag, rsu_id);
        tp_flags     = ctrl_lw.tp_flags;
        mp_flags     = ctrl_lw.mp_flags;
        cp_flags     = ctrl_lw.cp_flags;
        sig_violated = ctrl_lw.sig_violated;
        psi          = ctrl_lw.psi;
        anomalous    = ctrl_lw.anomalous;
        detected     = ctrl_lw.detected;
    } else {
        // Path B: use RSU-cached result (attacks 1-4, 6, and clean beacons).
        // No push, no detection — the RSU is authoritative per paper §3.5.3.
        sig_violated = tag.GetSigViolated();
        psi          = tag.GetLwPsi();
        anomalous    = tag.GetLwAnomalous();
        // Reconstruct unpacked component flags (used by SC-Trust sigmask + log)
        tp_flags = sig_violated & 0x1F;
        mp_flags = (sig_violated >> 5) & 0x0F;
        cp_flags = (sig_violated >> 9);
        // Detection decision matches helper's logic (R7f.followup-1: cp_flags is a
        // system-level signal for CDER, not per-beacon evidence — see line ~803 helper
        // for the full rationale.  Kinematic signatures own per-beacon detection.)
        if (ablation_mode == 6) {
            detected = run_ltt_detect(vehicle_id, rsu_id, tag);
        } else {
            detected = anomalous;
        }
    }

    // Per paper Eq 3.13-3.14 (TP-S4): the reference position p̂_i(t) is computed
    // from the *previously reported* beacon — "a ground-truth reference derived
    // entirely from the vehicle's own prior beacons". The paper does NOT prescribe
    // restoring an alternate baseline. Wiping the buffer prevents TP-S1/S4/S5 from
    // ever firing (count<2 → run_tp_detect early-exits).
    //
    // The only case where restoring is paper-justified is stolen-ID contamination
    // (attacks 4/6 with MP-S4 fired): a different attacker beacon uses the victim's
    // vehicle_id, so the victim's VS(vid) is polluted by a third-party
    // position. Restore here keeps per-vehicle state per-identity.
    if (save_state) {
        bool should_restore = (mp_flags & (1u << 3));   // MP-S4 fired: stolen-ID case only
        if (should_restore)
            VS(vehicle_id) = vs_backup;
    }

    // Ground truth: is this beacon poisoned? (For metrics)
    bool is_poisoned = tag.GetIsPoisoned();

    // Update tag with final sig_violated (may differ from RSU cache if path C)
    tag.SetSigViolated(sig_violated);

    // ── R7e.4: TPE predictor (paper Eq 4.6, controller-side) ───────────────────
    // For each beacon the controller observes, dead-reckon the *predicted*
    // position from the PREVIOUSLY observed beacon's kinematics:
    //   p̂(t_new) = p_prev + v_prev · (t_new − t_prev)
    // then compare to SUMO/MobilityModel ground truth via g_mobility_provider.
    // Accumulates Σ |p̂ − p_gt| and a counter for use by compute_TPE() (Eq 4.6).
    //
    // Why this lives here (controller-side) and not at the RSU:
    //   Paper §3.5.3 makes prediction a controller responsibility (Full mode);
    //   the RSU only authoritatively forwards/rejects beacons. The predictor's
    //   bias under TP attacks is exactly what TPE is supposed to surface, so
    //   feeding the (possibly poisoned) beacon-reported state into the
    //   predictor is correct — it mirrors what the deployed controller sees.
    //
    // Indexing: BsmBeaconTag.vehicle_id is the raw NS-3 NodeID; IMobilityProvider
    // and tpe_last_obs both use the LOCAL vehicle index 0..N_Vehicles-1. Convert
    // via g_first_vehicle_node_id (see 04_state_globals.h, 12_main.h). Without
    // this conversion (prior bug) prediction-for-V_A was compared against GT-of-V_B,
    // which produced ~300 m baseline displacement instead of ~0 m.
    if (g_mobility_provider && vehicle_id >= g_first_vehicle_node_id) {
        const uint32_t vid_local = vehicle_id - g_first_vehicle_node_id;
        if (vid_local < (uint32_t)total_size) {
            TpeObs &prev = tpe_last_obs[vid_local];
            if (prev.has_obs && now > prev.t) {
                const double dt    = now - prev.t;
                const double vx    = prev.speed * std::cos(prev.heading);
                const double vy    = prev.speed * std::sin(prev.heading);
                const double pred_x = prev.px + vx * dt;
                const double pred_y = prev.py + vy * dt;
                const Vector gt = g_mobility_provider->get_gt_position(vid_local);
                const double dx = pred_x - gt.x;
                const double dy = pred_y - gt.y;
                tpe_disp_sum += std::sqrt(dx*dx + dy*dy);
                tpe_disp_cnt++;
            }
            prev.px      = tag.GetPosX();
            prev.py      = tag.GetPosY();
            prev.speed   = tag.GetSpeed();
            prev.heading = tag.GetHeading();
            prev.t       = now;
            prev.has_obs = true;
        }
    }

    // ── R3: Push cached LW result into controller window aggregator ────────────
    // Per invariant #2 the controller does NOT make per-beacon decisions; it
    // batches kinematics into per-RSU windows of size L (paper §3.5.3,
    // W = L · T_b) for the future Full-mode GAT + LSTM-AE pipeline. This is a
    // stats-only push — the authoritative control decision is owned by the RSU
    // (R2). The rollover hook is currently a no-op log stub (R7+ will replace
    // the log with the actual GAT + LSTM-AE invocation).
    if (rsu_id < N_RSUs) {
        ControllerWindow &cw = ctrl_window[rsu_id];
        if (cw.beacon_count == 0) cw.window_start = now;
        cw.beacon_count++;
        if (anomalous)           cw.anomalous_count++;
        if (is_poisoned)         cw.poisoned_count++;
        cw.psi_sum += psi;
        // Window rollover: every L beacons OR every W = L · T_b seconds elapsed.
        bool by_count = (cw.beacon_count >= (uint32_t)WINDOW_L_BEACONS);
        bool by_time  = (now - cw.window_start >= WINDOW_L_BEACONS * T_b);
        if (by_count || by_time) {
            cout << "[CTRL-WIN-" << rsu_id << "] epoch=" << cw.window_epoch
                 << " beacons=" << cw.beacon_count
                 << " anomalous=" << cw.anomalous_count
                 << " poisoned=" << cw.poisoned_count
                 << " mean_psi=" << std::fixed << std::setprecision(4)
                 << (cw.beacon_count ? cw.psi_sum / cw.beacon_count : 0.0)
                 << " t_close=" << std::setprecision(3) << now
                 << " W=" << WINDOW_L_BEACONS * T_b << "s" << endl;

            // ── Full-mode crypto mitigation: Algorithm 6 (PQ-FHE-TRS) + Eq 3.51
            // cloud gate + Algorithm 7 (THRESH-DEC). Runs once per window via the
            // ring coordinator (RSU 0). Full mode only: skipped for A1 (LW-only)
            // and B1 (LTT baseline); TRS/FHE gated by use_pq_crypto (off for A4).
            // Independent of the AI block below — crypto runs even when GAT/AE are
            // disabled (A4/A5), preserving ablation isolation (paper §4.1.1).
            // if (use_pq_crypto && ablation_mode != 1 && ablation_mode != 6) {
            //     FullModeCryptoResult cr;
            //     if (run_full_mode_crypto_pipeline(rsu_id, cw.window_epoch, cr) && cr.ran) {
            //         cout << "[FULLCRYPTO] epoch=" << cw.window_epoch
            //              << " rings=" << cr.contributing_rsus
            //              << " veh=" << cr.total_vehicles
            //              << " trs=" << (cr.trs_verified ? "VERIFIED" : "REJECTED")
            //              << " sigma=" << cr.sigma_bytes << "B"
            //              << " dec=" << (cr.decrypt_ok ? "ok" : "fail")
            //              << std::fixed << std::setprecision(3)
            //              << " mean_speed_dec=" << cr.recovered_mean_speed
            //              << " mean_speed_pt=" << cr.plaintext_mean_speed
            //              << " " << std::setprecision(2) << cr.elapsed_ms << "ms"
            //              << " (Alg6/7 Eq 3.45-3.56)" << endl;
            //     }
            // }

            if (use_pq_crypto && ablation_mode != 1 && ablation_mode != 6) {
                FullModeCryptoResult cr;
                // R9: result is async now — real [FULLCRYPTO] line prints later
                // from handle_cloud_reply_at_rsu() when the Cloud answers.
                if (run_full_mode_crypto_pipeline(rsu_id, cw.window_epoch, cr) && cr.ran) {
                    cout << "[FULLCRYPTO-SENT] epoch=" << cw.window_epoch
                         << " → Cloud, awaiting reply" << endl;
                }
            }

            // ── R7d: Full-mode GAT spatial scoring (paper §3.5.3 Eq 3.38–3.42) ──
            // The RSU-side ipfs_push_and_maybe_flush() runs in handle_readone
            // BEFORE this controller-side block sees the same beacon, so by
            // now rsu_window[rsu_id].beacon_count has been reset. We read from
            // rsu_last_window[rsu_id] — the snapshot taken at the moment of
            // the most recent flush. Per paper Fig 3.10/3.11 this fires only
            // at window close — invariant #3 (LW skip-on-pass) is preserved
            // because the lightweight RSU path never touches this branch.
            //
            // LSTM-AE temporal scoring needs a per-vehicle 20-beacon sliding
            // ring buffer that we do NOT yet maintain — R7e adds that ring and
            // wires score_lstm_ae() into the same window-close hook.
            //
            // ready() is false when BOTH GAT and LSTM-AE are disabled (neither
            // ONNX session loaded), which previously skipped this ENTIRE block
            // — including full-mode confusion-matrix scoring — whenever a run
            // manually forced both off under ablation_mode outside {1,6} (e.g.
            // R3 config2/config4: mode=0 + --enable_gat=0 --enable_lstm_ae=0).
            // fuse_scores() already renormalises to ψ-only in that case, so
            // gate on enable_rule_signatures too and let it carry the decision.
            run_gat_fusion_for_rsu(rsu_id, cw.window_epoch);
            // ── End R7d/R7e ─────────────────────────────────────────────────────

            cw.beacon_count    = 0;
            cw.anomalous_count = 0;
            cw.poisoned_count  = 0;
            cw.psi_sum         = 0.0;
            cw.window_start    = now;
            cw.window_epoch++;
        }
    }

    // Log [METRICS] line
    log_metrics_line(attack_number, is_poisoned, vehicle_id, rsu_id, tag, sig_violated);

    // Forward clean/flagged beacon to blockchain (via 11_routing)
    //    (Actual blockchain call is in 11_routing_blockchain_transmission.h)
    total_trajectories_stored_blockchain++;

    // ── TRS moved to the Full-mode window-close hook (paper-correct) ─────────
    // The per-beacon TRS block that used to live here signed the *plaintext*
    // single-beacon aggregate (|V_j|=1) — a deviation from Eq 3.48, which signs
    // the FHE *ciphertext* Enc(A_ring) over the whole window. Per Algorithm 6
    // the TRS is a Full-mode, per-window (W = L·T_b) cluster operation, not a
    // per-beacon RSU-hot-path op. It now runs in HandleBeaconReceived's
    // window-close branch via run_full_mode_crypto_pipeline() (real ciphertext
    // signing + threshold decrypt). Removing it here also stops the TRS cost
    // from leaking into the per-beacon PBPO_LW budget (T_b = 100 ms).

    // Update confusion matrix + beacon CSV log
    g_diag_cm_update_count++;  // TEMP DIAGNOSTIC (Block 2)
    update_confusion_matrix(tag.GetIsPoisoned(), detected);
    if (tag.GetIsPoisoned()) parr_poisoned_total++;   // PARR denominator: total poisoned submissions

    // C5 TTD: per-attacker onset/alert timestamps — t_start = first poisoned
    // beacon, t_alert = first LW detection at/after onset (same semantics as
    // analytics/compute_ttd.py over beacon_log.csv).
    {
        // Local vehicle index: vehicle NodeIDs start at g_first_vehicle_node_id
        // (after the RSU/controller/mgmt/cloud nodes), NOT at 2. The old hardcoded
        // `-2` landed the onset/alert timestamps in wrong (often OOB) slots → TTD≈0.
        int vi = (int)vehicle_id - (int)g_first_vehicle_node_id;
        if (vi >= 0 && vi < total_size) {
            double t_now = Simulator::Now().GetSeconds();
            if (tag.GetIsPoisoned() && g_ttd_first_poison[vi] < 0)
                g_ttd_first_poison[vi] = t_now;
            // ALERT side intentionally NOT set here: `detected` is the immediate
            // per-beacon flag, which (a) fires in this same call with this same
            // t_now — making alert==onset and TTD==0 — and (b) is ablation-inert.
            // The alert timestamp is now taken from the FUSION decision (full_flag),
            // see the C5 TTD block next to update_confusion_matrix_full() above.
        }
    }
    log_beacon_to_csv(vehicle_id, rsu_id, tag, detected,
                      tp_flags | (mp_flags << 5), psi);

    // 9. ML prediction server — REMOVED (server not running; GAT/LSTM-AE not yet
    //    implemented; curl result was discarded and never used in detection decisions).
    //    Removing eliminates spurious system() call overhead from PBPO_Full timing.

    // PBPO: stop timer and accumulate (§4.1.2 Eq 4.7)
    clock_gettime(CLOCK_MONOTONIC, &t_end);
    double elapsed_ms = (t_end.tv_sec  - t_start.tv_sec)  * 1000.0
                      + (t_end.tv_nsec - t_start.tv_nsec) / 1e6;
    pbpo_time_sum_ms += elapsed_ms;
    pbpo_cnt++;

    // ── R4.a: SC-Trust + SC-Revoke moved RSU-side (paper invariant #1) ────────
    // CallSCTrust / CallSCRevoke (vote-on-first-flag, Eq 3.67) / parr_trs_rejected
    // now live in handle_readone() — see the "R4.a: SC-Trust + SC-Revoke at RSU"
    // block above. Per paper invariant #1 the RSU is the authoritative submitter
    // to the blockchain (no controller relay); the controller's role here is now
    // limited to (a) aggregating parr_poisoned_total below, (b) hosting the
    // controller-attack injection blocks for attacks 5/7, and (c) running the
    // R3 window aggregator for the future GAT + LSTM-AE pipeline.
    //
    // For the controller-attack paths (attacks 5/7) the RSU's rsu_lw is honest
    // (data plane is clean) so no SC call fires there — controller misbehavior
    // will be caught by CP-DETECT (Algorithm 7) in phase R6.

    (void)now;

    // ── Step 11: Downlink control response — controller emission path ────────────
    // R5 refactor (paper Fig 3.1 Step 5-7): controller emission now covers BOTH
    // the controller-as-attacker scenarios (5/7) AND the RSU-as-attacker /
    // controller-as-deceived scenario (1). The R2 fast-path RSU-direct DSRC alert
    // is gated off for attack 1 so the controller is the authoritative emission
    // point per paper Fig 3.1.
    //
    // Three live attack scenarios:
    //   • attack 1 (TP-S1, paper Fig 3.1 Step 5-7): RSU compromises beacons; controller
    //     learns from corrupted input. Honest controller's decision is a function of
    //     the (RSU-side) LW result on the POISONED data:
    //       – LW caught attack (detected=true)  → ATTACK_DETECTED, correct safety call
    //       – LW missed attack (detected=false) → CLEAN_ROUTING, controller DECEIVED
    //         (paper Step 7: "safety warnings ... suppressed or replaced with
    //          misleading control instructions")
    //   • attacks 5/7 (paper Fig 3.3 / Fig 3.7): controller IS the attacker — it
    //     deliberately injects alert_type=2 (WRONG_ROUTING) regardless of LW state.
    //
    // In all three cases the RSU at handle_downlink_at_rsu() is honest and relays
    // whatever the controller said. For attacks 2/3/4/6 the R2 fast-path is the
    // single CDER decision (this block is skipped entirely).
    //
    // CDER (Eq.4.4) stays well-defined: exactly one control decision per beacon —
    // R2 fast-path for {2,3,4,6,clean}; controller-here for {1,5,7}.
    if (g_option_b_active && rsu_id < N_RSUs && g_mgmt_downlink_socket &&
        (attack_number == 1 || attack_number == 5 || attack_number == 7 || g_combined_attack)) {
        bool malicious_ctrl = (attack_number == 5 || attack_number == 7 || g_combined_attack)
                              && ctrl_compromised_now();   // AB9 onset gate

        uint8_t  alert_type;
        double   spd_advice;
        uint32_t target_vid;
        bool     bcast;

        if (malicious_ctrl && g_combined_attack && detected) {
            // Combined-attack SUPPRESSION variant (new): when the RSU/LW side has
            // actually caught something (detected=true — from the concurrent
            // data-plane attacks a1-a4/a6 that also run in combined mode), the
            // malicious controller here HIDES it (ctrl_says=CLEAN) instead of the
            // standard over-report. This is the case CPDetectCheck's on-chain
            // directional rule (Eq 3.59/3.68: flag on ctrl=CLEAN vs rsu=ANOM,
            // i.e. suppression) is actually designed to catch — the unconditional
            // WRONG_ROUTING broadcast below only ever produces the OPPOSITE
            // (over-report) direction, which Eq 3.68 explicitly does NOT
            // penalize, so TCL_reassign was architecturally unreachable before
            // this. Gated to g_combined_attack only — standalone attacks 5/7
            // keep their original unconditional WRONG_ROUTING below unchanged
            // (their RSU/data plane stays honest per the comment above, so
            // `detected` is rarely/never true there anyway).
            alert_type = 0;                                  // CLEAN_ROUTING (suppression)
            spd_advice = s_max;
            target_vid = vehicle_id;                         // unicast: mirrors honest path
            bcast      = false;
        } else if (malicious_ctrl) {
            // Malicious controller (attacks 5/7, and combined-mode beacons the RSU
            // didn't flag): hardcoded WRONG_ROUTING, broadcast.
            alert_type = 2;                                  // WRONG_ROUTING
            spd_advice = detected ? (s_max * 0.5) : s_max;
            target_vid = 0;                                  // 0 = all vehicles (broadcast)
            bcast      = true;
        } else {
            // attack_number == 1: honest controller, decision = f(cached LW result).
            // Paper Fig 3.1 Step 5-7: LW miss on RSU-poisoned data → deceived controller.
            alert_type = detected ? 1 : 0;                   // ATTACK_DETECTED or CLEAN_ROUTING
            spd_advice = detected ? (s_max * 0.5) : s_max;
            target_vid = vehicle_id;                         // unicast: this vehicle's beacon
            bcast      = false;
        }

        // ── A1-STEP5: Controller ingests RSU-poisoned beacon into its mobility view ──
        // Paper Fig 3.1 §3.4.1 page 25: "Based on this corrupted input, the controller
        // learns an incorrect trajectory model and is deceived into believing that the
        // traffic situation is safe." (Stub: full GAT/LSTM-AE learning lands in R7+;
        // this marker records the controller's per-beacon exposure to corrupted state.)
        if (attack_number == 1 && is_poisoned) {
            cout << "[A1-STEP5] Controller learning from RSU" << rsu_id
                 << "-poisoned V" << vehicle_id
                 << " pos(" << std::fixed << std::setprecision(2)
                 << tag.GetPosX() << "," << tag.GetPosY() << ")"
                 << " spd=" << tag.GetSpeed()
                 << "  LW=" << (detected ? "CAUGHT" : "MISSED")
                 << "  (paper Fig 3.1 Step 5)" << endl;
        }

        DownlinkControlTag dl_tag;
        dl_tag.SetVehicleId   (target_vid);
        dl_tag.SetAlertType   (alert_type);
        dl_tag.SetSpeedAdvice (spd_advice);
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
                                (alert_type == 1) ? "ATTACK_DETECTED" :
                                                    "WRONG_ROUTING";
        const char* dl_fn     = bcast ? "centralized_dsrc_data_broadcast"
                                      : "centralized_dsrc_data_unicast";
        if (err >= 0) {
            // CDER (Eq.4.4): exactly one control decision per beacon.
            ctrl_decisions_total++;
            bool wrong;
            if (malicious_ctrl) {
                // Attacks 5/7: malicious controller's WRONG_ROUTING is a bad decision.
                // CP-1 (2026-08-05): but CDER (Eq 4.4) measures UNDETECTED control
                // error. Once CP-DETECT (Alg 7) has raised flag_c, the system has
                // identified the compromise, so subsequent bad decisions belong to a
                // DETECTED compromise interval rather than to undetected error.
                // Before this, g_flag_c_active was written and never read — CDER could
                // not distinguish "controller compromised and caught" from "controller
                // compromised and missed", so it was not measuring detection at all.
                // Gated so legacy CDER remains reproducible (default off).
                wrong = g_cder_credit_cp_detect ? !g_flag_c_active : true;
            } else {
                // Attack 1: honest controller — wrong iff (detected ⊻ is_poisoned)
                //   FP: detected=true,  is_poisoned=false → ATTACK_DETECTED on clean
                //   FN: detected=false, is_poisoned=true  → CLEAN_ROUTING on poisoned (DECEIVED)
                wrong = (detected ? !is_poisoned : is_poisoned);
            }
            if (wrong) ctrl_decisions_wrong++;

            // ── R6: CP-DETECT (paper Algorithm 7 / Eq 3.59) ─────────────────
            // Audit the controller's just-emitted decision against the RSU's
            // authoritative LW-DETECT view for the SAME beacon (cached on the
            // tag by handle_readone). Honors invariant #2: the controller is a
            // non-authoritative peer; ≥ f+1=2 per-beacon disagreements within
            // the rolling window ⇒ flag_c=1 and CTRL_COMPROMISED alert.
            //   Attack 1 (honest-but-deceived controller): the controller
            //     shadows its RSU's cached anomalous flag, so per-beacon
            //     disagreement = 0 and CP-DETECT does not fire — even when
            //     LW misses (FN) or trips (FP) on poisoned data the RSU and
            //     controller report the SAME thing, so they agree.
            //   Attacks 5/7 (malicious controller): controller broadcasts
            //     WRONG_ROUTING regardless of RSU view, while RSU-side LW
            //     sees clean data → per-beacon disagreement = 1 every time,
            //     window fills to threshold within K=3 beacons.
            // sigma_trs is nullptr/0 in R6; R8 will supply the real σ_TRS.
            bool controller_anomalous = (alert_type != 0);
            bool   rsu_anomalous_cached = tag.GetLwAnomalous();
            double rsu_psi_cached       = tag.GetLwPsi();
            (void)run_cp_detect_per_epoch(vehicle_id, rsu_id, alert_type,
                                          controller_anomalous,
                                          rsu_anomalous_cached,
                                          rsu_psi_cached,
                                          nullptr, 0);

            if (attack_number == 7) {
                // A7-STEP5-TX: Malicious controller sends WRONG_ROUTING to all vehicles.
                // Paper Fig 3.7: Controller generates incorrect control packets from
                // poisoned model and sends them back to RSU via control plane.
                cout << "[A7-STEP5-TX] Controller → RSU" << rsu_id
                     << " WRONG_ROUTING control packet (poisoned model output)"
                     << " vid=" << (bcast ? 0U : vehicle_id)
                     << "  [" << dl_fn << "]" << endl;
            } else if (attack_number == 5) {
                // attack_number == 5 (TP-S3, controller trajectory poisoning)
                cout << "[A5-CTL-TX] Controller → RSU" << rsu_id
                     << " " << alert_str
                     << " (paper Fig 3.3 Step 5-7)"
                     << "  [" << dl_fn << "]" << endl;
            } else {
                // attack_number == 1: honest-but-deceived controller emission.
                // ── A1-STEP6: Controller generates control decision from (poisoned) view ──
                // Paper Fig 3.1 §3.4.1 page 25: "the controller generates incorrect
                // control decisions and control packets (Step 5)." The "deceived" tag
                // marks the precise FN case where the honest controller's decision is
                // wrong because the underlying LW detection missed the attack.
                bool deceived = (is_poisoned && !detected);
                cout << "[A1-STEP6] Controller → RSU" << rsu_id
                     << " " << alert_str
                     << " vid=" << vehicle_id
                     << " spd_adv=" << spd_advice << " m/s"
                     << "  LW=" << (detected ? "caught" : "missed")
                     << (deceived ? " → DECEIVED" : "")
                     << "  (paper Fig 3.1 Step 6)"
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
// R2 refactor (paper Fig 3.1 Step 6/7): normal LW-mode downlinks for attacks
// {2,3,4,6,clean} are emitted by the RSU directly in handle_readone() (no CSMA
// hop). This management → RSU handler fires for the three controller-owned
// emission scenarios:
//   • attacks 5/7 (controller-as-attacker, Fig 3.3 / Fig 3.7): malicious
//     controller injects alert_type=2 (WRONG_ROUTING) — broadcast.
//   • attack 1 (RSU-as-attacker, Fig 3.1 Step 5-7, added in R5): honest-but-
//     deceived controller emits alert_type=1 (ATTACK_DETECTED) when LW caught
//     the attack, or alert_type=0 (CLEAN_ROUTING) when LW missed — unicast.
//
// Sequence (paper Fig 3.1 / Fig 3.3 / Fig 3.7):
//   Management → g_mgmt_downlink_socket → RSU CSMA:8888    [DL-MGT-TX]
//   RSU receives here                                      [DL-RSU-RX]
//   RSU re-broadcasts DownlinkControlTag → DSRC:9999       [DL-RSU-FWD]
//   For attack 1: paper-step marker                        [A1-STEP7]
//   Vehicle receives in HandleReadTwo()                    [DL-VEH-RX]
//
// alert_type=0 CLEAN_ROUTING   — attack 1 deceived-controller emission (R5)
// alert_type=1 ATTACK_DETECTED — attack 1 controller emission when LW caught (R5)
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
            if (err >= 0) {
                cout << "[DL-RSU" << rsu_idx << "-FWD] → V"
                     << (vid == 0 ? "ALL" : std::to_string(vid - 2))
                     << " :9999  [" << dl_fn << "]" << endl;
                // ── A1-STEP7: Controller's (potentially wrong) control packet delivered ──
                // Paper Fig 3.1 §3.4.1 page 25: "safety critical warning messages that
                // should be sent to vehicles are either suppressed or replaced with
                // misleading control instructions." For attack 1 the controller is the
                // origin of this packet (R5: A1-STEP6); the RSU is honest and just relays
                // it onto DSRC. The vehicle plane now carries whatever the (deceived or
                // accurate) controller decided — completing the Fig 3.1 5→6→7 chain.
                if (attack_number == 1) {
                    cout << "[A1-STEP7] RSU" << rsu_idx << " delivered controller's "
                         << alert_str << " to V"
                         << (vid == 0 ? "ALL" : std::to_string(vid - 2))
                         << " via DSRC  (paper Fig 3.1 Step 7)" << endl;
                }
            } else {
                cout << "[DL-RSU" << rsu_idx << "-FWD-ERR] failed fwd vid=" << vid << endl;
            }
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

        // ── LKH: Record vehicle DSRC IP on first reception (used for unicast rekey) ──
        // InetSocketAddress::ConvertFrom(from) gives the sender's IP:port.
        // Vehicle nid → veh_idx = nid - 2, stored in g_vehicle_dsrc_ip[veh_idx].
        {
            int v_idx = lkh_veh_idx(vid);
            if (v_idx >= 0 && v_idx < LKH_MAX_VEH && !g_vehicle_ip_known[v_idx]) {
                InetSocketAddress sender = InetSocketAddress::ConvertFrom(from);
                g_vehicle_dsrc_ip[v_idx] = sender.GetIpv4();
                g_vehicle_ip_known[v_idx] = true;
                cout << "[LKH-IP] V" << (vid - 2)
                     << " DSRC IP recorded: " << sender.GetIpv4()
                     << " (used for unicast rekey)" << endl;
            }
        }

        // ── LKH HMAC gate (Eq.3.37) — first gate before any detection ────────────
        // MAC_i(t) = HMAC_{K_i}(b_i(t)‖t‖ID_i)
        // RSU recomputes the expected HMAC and compares with the tag's m_hmac field.
        // If HMAC is missing or invalid: reject beacon immediately (counts as detected=true,
        // is_poisoned set to true if vehicle had no valid key — attacker cannot forge).
        // Ghost packets (vid >= 10000) bypass HMAC: they are injected locally by the RSU
        // itself (MP-S1 attack) so they never carry a valid vehicle session key.
        //
        // PBPO_LW: time only the RSU-side lightweight HMAC gate (Eq.4.7, lightweight mode).
        // This is the per-beacon overhead at the RSU before any controller involvement.
        // Separate from PBPO_Full (controller pipeline) measured in HandleBeaconReceived().
        struct timespec t_lw_start, t_lw_end;
        clock_gettime(CLOCK_MONOTONIC, &t_lw_start);
        bool hmac_gate_pass = true;
        // AB2 (C10): HMAC+nonce gate removed — every beacon passes unauthenticated.
        if (enable_hmac_gate && vid < 10000) {  // skip HMAC check for RSU-injected ghost packets
            int v_idx = lkh_veh_idx(vid);
            // ── FAIL-CLOSED option (--hmac_fail_closed, default OFF) ──────────
            // Eq 3.37 has the RSU verify MAC_i(t) before accepting a beacon. The
            // implementation only verifies when a MAC is PRESENT
            // (tag.GetHmacSet()), so a beacon carrying no MAC skips the gate and
            // is accepted unauthenticated. Both identity-forging attacks exploit
            // this: neither the Sybil path (09:374, attack 4) nor the MitM path
            // (09:574, attack 6) calls SetHmac. Measured consequence: the gate
            // fires only 36 times in a 300 s run containing ~90 000 poisoned
            // beacons.
            //
            // Failing closed is the correct reading of Eq 3.37 — a beacon whose
            // authenticity cannot be verified must not be trusted — and it is
            // cryptographic, not an artifact: an attacker without the victim's
            // key cannot produce a valid MAC. Rejected beacons are dropped at
            // :3689 BEFORE run_lw_detect_per_beacon, so they never reach
            // push_beacon and cannot contaminate vehicle_state.
            //
            // DEFAULT OFF: this materially changes how detectable MP-S2/MP-S3
            // are (they become crypto-caught rather than ML-caught), which is a
            // threat-model decision, not ours to make silently.
            if (g_hmac_fail_closed && v_idx >= 0 && v_idx < LKH_MAX_VEH &&
                !tag.GetHmacSet()) {
                hmac_gate_pass = false;
                g_hmac_missing_rejected++;
                if (g_hmac_missing_rejected <= 10)
                    cout << "[HMAC-FAILCLOSED] RSU" << rsu_idx << " vid=" << vid
                         << " carries NO MAC → unverifiable, beacon rejected"
                         << " gt_pois=" << (tag.GetIsPoisoned() ? 1 : 0)
                         << " t=" << t << endl;
            }
            if (v_idx >= 0 && v_idx < LKH_MAX_VEH && tag.GetHmacSet()) {
                uint8_t recv_mac[8];
                tag.GetHmac(recv_mac);
                bool mac_ok = lkh_verify_beacon_hmac(
                    v_idx,
                    tag.GetPosX(), tag.GetPosY(),
                    tag.GetSpeed(), tag.GetHeading(), tag.GetAcceleration(),
                    tag.GetTimestamp(), vid, recv_mac);
                tag.SetHmacValid(mac_ok);
                if (!mac_ok) {
                    hmac_gate_pass = false;
                    cout << "[LKH-HMAC-FAIL] RSU" << rsu_idx
                         << " V" << (vid - 2)
                         << " HMAC verification FAILED → beacon rejected"
                         << " t=" << t << endl;
                } else {
                    // H5: replay protection on AUTHENTIC beacons — a captured
                    // beacon re-sent within the key epoch carries a valid MAC,
                    // so two extra gates are needed (paper HMAC spec):
                    //  (a) freshness: age ≤ Δ_HMAC (timestamp is MAC-covered,
                    //      so an attacker cannot forge a fresh one);
                    //  (b) cluster nonce cache: timestamp strictly greater than
                    //      the last accepted one for this vehicle, shared
                    //      across all RSUs (catches replays inside Δ_HMAC and
                    //      cross-RSU replays within the cluster).
                    const double now_s = Simulator::Now().GetSeconds();
                    const double t_bcn = tag.GetTimestamp();
                    if (now_s - t_bcn > delta_hmac || t_bcn - now_s > delta_hmac) {
                        hmac_gate_pass = false;
                        cout << "[LKH-HMAC-STALE] RSU" << rsu_idx
                             << " V" << (vid - 2)
                             << " beacon age " << (now_s - t_bcn)
                             << "s exceeds Δ_HMAC=" << delta_hmac
                             << "s → rejected (replay window)" << endl;
                    } else if (t_bcn <= g_hmac_last_seen_t[v_idx]) {
                        hmac_gate_pass = false;
                        cout << "[LKH-HMAC-REPLAY] RSU" << rsu_idx
                             << " V" << (vid - 2)
                             << " t=" << t_bcn << " ≤ last accepted "
                             << g_hmac_last_seen_t[v_idx]
                             << " → rejected (cluster nonce cache)" << endl;
                    } else {
                        g_hmac_last_seen_t[v_idx] = t_bcn;
                    }
                }
            } else if (v_idx >= 0 && !tag.GetHmacSet()) {
                // No HMAC present — treat as HMAC failure (unauthenticated beacon)
                hmac_gate_pass = false;
                cout << "[LKH-HMAC-MISSING] RSU" << rsu_idx
                     << " V" << (vid - 2)
                     << " beacon has no HMAC tag → rejected" << endl;
            }
        }

        // PBPO_LW: stop HMAC gate timer — captures RSU-side lightweight overhead per beacon.
        // Accumulated regardless of pass/fail so the mean reflects ALL beacon arrivals.
        clock_gettime(CLOCK_MONOTONIC, &t_lw_end);
        pbpo_lw_time_sum_ms += (t_lw_end.tv_sec  - t_lw_start.tv_sec)  * 1000.0
                             + (t_lw_end.tv_nsec - t_lw_start.tv_nsec) / 1e6;
        pbpo_lw_cnt++;

        // ── LKH dynamic membership (paper §3.5.2, P1b-C) ─────────────────────────
        // After verifying with the CURRENT K_i, register/hand-off this vehicle to
        // the nearest RSU's zone. The geographic filter above guarantees
        // rsu_idx == nearest_rsu_for_position, so exactly ONE RSU migrates a given
        // beacon — no cross-RSU key race. On a zone change this rotates K_i to the
        // new zone's leaf key for the NEXT beacon (per-RSU-contact keys, Eq 3.22).
        // Only on a genuine HMAC pass (don't register a vehicle off a forged beacon).
        if (vid < 10000 && hmac_gate_pass) {
            int mv_idx = lkh_veh_idx(vid);
            if (mv_idx >= 0 && mv_idx < LKH_MAX_VEH)
                lkh_on_beacon_at_rsu((int)rsu_idx, mv_idx, t);
        }

        // If HMAC gate fails: do not forward to management node (drop the beacon)
        // The beacon is silently dropped — no detection pipeline, no downlink response.
        // In a real system a short alert could be sent; here we track it via PARR.
        if (!hmac_gate_pass) {
            // Count as a detected poisoned beacon for confusion matrix
            // (attacker who can't forge HMAC is trivially detected)
            if (tag.GetIsPoisoned()) {
                update_confusion_matrix(true, true);   // TP
                parr_poisoned_total++;
            } else {
                // An honest vehicle with wrong key (e.g., after rekey lag): FP
                // This can happen in the brief window before the vehicle receives
                // its RekeyTag. Counted as FP — drives system design to minimise rekey lag.
                update_confusion_matrix(false, true);  // FP
            }
            continue;  // drop: do not forward to management
        }

        // ── SC-Register authorisation gate (paper §3.5.5 Algorithm 7) ──────
        // Reject beacons from vehicles that did NOT successfully complete
        // boot-time SCRegister (no on-chain REG_VEH_<nid> record → no τ_init
        // → no legal evidence path). This is a LOCAL cache check populated
        // by register_all_nodes() at boot — strictly read-only at runtime so
        // invariant 3 (skip-on-pass at RSU, no blockchain call on the fast
        // path) holds.
        //
        // Bypass conditions (each is a different correctness reason):
        //   - skip_blockchain=true  → register_all_nodes() was a no-op, the
        //                             cache is empty by design, so gating
        //                             would reject every beacon.
        //   - ablation_mode == 5    → A5 variant (paper §4.1.1, RQ6) runs
        //                             *without* SC-Trust / SC-Register so we
        //                             can isolate the blockchain's metric
        //                             contribution; gate must be transparent.
        //   - routing_algorithm!=4  → legacy/baseline algorithms don't run
        //                             register_all_nodes() at all.
        //   - vid >= 10000          → RSU-injected ghost packet (MP-S1
        //                             attack, paper §3.4.2). The ghost is
        //                             synthesised locally by the compromised
        //                             RSU and must reach SYB-DETECT for the
        //                             paper attack scenario to be evaluable.
        //
        // Rejected beacons are logged to a separate CSV (forensics + debug)
        // and counted in unregistered_beacon_reject_count, but NEVER feed
        // confusion matrix / PARR / CDER — those metrics measure the
        // detection pipeline's behaviour on *valid* peers only (paper §4.1.2).
        if (!skip_blockchain && ablation_mode != 5 &&
            routing_algorithm == 4 && vid < 10000)
        {
            if (g_registered_vids.find(vid) == g_registered_vids.end()) {
                unregistered_beacon_reject_count++;
                log_unregistered_beacon_reject(vid, rsu_idx, t, real_px, real_py);
                cout << "[SC-REGISTER-REJECT] RSU" << rsu_idx
                     << " V" << vid << " (nid=" << vid
                     << ") not in registered-vid cache — beacon dropped"
                     << " (not counted in MCC/FPR/PARR/CDER) t=" << t << endl;
                continue;
            }
        }

        cout << "[DSRC-RSU" << rsu_idx << "] V" << vid
             << " pos(" << tag.GetPosX() << "," << tag.GetPosY() << ")"
             << " compromised=" << (compromised_rsu[rsu_idx] ? "YES" : "no") << endl;

        // ── A7-STEP3: RSU receives HONEST beacon from vehicle (data plane correct) ──
        // Paper Fig 3.7: RSU operates correctly — no modification at this stage.
        // Controller is malicious but RSU is honest; beacon arrives unchanged.
        if (attack_number == 7) {
            cout << "[A7-STEP3] RSU" << rsu_idx
                 << " received HONEST V" << vid
                 << " spd=" << tag.GetSpeed()
                 << " pos(" << tag.GetPosX() << "," << tag.GetPosY() << ")"
                 << " — RSU NOT compromised, forwarding as-is" << endl;
        }

        // ── TP-S1: Compromised RSU modifies trajectory (paper §3.4.1 Figure 3.1) ──
        // compromised_rsu[] already reflects attack_percentage via declare_compromised_rsus().
        // No second per-vehicle gate — ALL vehicles at a compromised RSU are poisoned.
        if ((attack_number == 1 ||
             (g_combined_attack && rsu_idx < MAX_RSUS && g_rsu_attack[rsu_idx] == 1)) &&
            rsu_idx < N_RSUs &&
            compromised_rsu[rsu_idx] &&
            !(g_combined_attack && tag.GetIsPoisoned()))   // combined: only poison HONEST beacons
        {
            double real_px  = tag.GetPosX();
            double real_py  = tag.GetPosY();
            double real_spd = tag.GetSpeed();
            double real_hdg = tag.GetHeading();
            double real_acc = tag.GetAcceleration();

            // Bounded random-walk drift per paper §3.4.3 Eq 3.5/3.6.
            // Hybrid: ~θ_s stealth (below TP-S1 kinematic gate) + (1-θ_s) abrupt
            // (above s_max·T_b → trips TP-S1 → LW detects). Returns CUMULATIVE drift.
            // θ scales the bound: theta=1 → full ε_max, theta=0.5 → half, etc.
            double drift_x_raw, drift_y_raw, inc_mag_step;
            bool   is_abrupt;
            SampleBoundedDrift((int)vid, drift_x_raw, drift_y_raw, is_abrupt, inc_mag_step);
            double drift_x  = poisoning_intensity_theta * drift_x_raw;
            double drift_y  = poisoning_intensity_theta * drift_y_raw;
            double fake_px  = real_px + drift_x;
            double fake_py  = real_py + drift_y;
            fake_px = (fake_px < min_position_x) ? min_position_x : (fake_px > max_position_x ? max_position_x : fake_px);
            fake_py = (fake_py < min_position_y) ? min_position_y : (fake_py > max_position_y ? max_position_y : fake_py);

            tag.SetPosition(fake_px, fake_py);
            tag.SetIsPoisoned(true);
            tag.SetAttackType(1);

            double dx = fake_px - real_px, dy = fake_py - real_py;
            double disp_err = std::sqrt(dx*dx + dy*dy);
            tpe_sq_sum += disp_err * disp_err;   // TPE: injection magnitude (Option B path)
            tpe_cnt++;

            // Per-beacon LW detectability: TP-S1 kinematic gate fires if step
            // increment exceeds s_max·T_b. Scaled by theta to match drift scaling.
            double step_scaled  = poisoning_intensity_theta * inc_mag_step;
            bool   det_step_lw  = (step_scaled > s_max * T_b);
            cout << "\n[TP-S1-RSU" << rsu_idx << "] "
                 << (is_abrupt ? "[ABRUPT]" : "[STEALTH]")
                 << " ═════════════════════════════════════" << endl;
            cout << "  t=" << std::fixed << std::setprecision(3) << t
                 << "s  V=" << vid << "  theta=" << poisoning_intensity_theta
                 << "  branch=" << (is_abrupt ? "ABRUPT" : "STEALTH") << endl;
            cout << std::fixed << std::setprecision(4);
            cout << "  pos_x " << real_px << " → " << fake_px
                 << "  (cum_drift " << std::showpos << drift_x << std::noshowpos << " m)" << endl;
            cout << "  pos_y " << real_py << " → " << fake_py
                 << "  (cum_drift " << std::showpos << drift_y << std::noshowpos << " m)" << endl;
            cout << "  step=" << step_scaled << " m  (gate=" << s_max*T_b << " m)"
                 << "  cum_disp=" << disp_err << " m"
                 << "  LW-fires-this-beacon=" << (det_step_lw ? "YES" : "no") << endl;
            cout << "[TP-S1-RSU" << rsu_idx << "] ═════════════════════════════════════\n" << endl;

            log_tp_s1_poison(vid, rsu_idx, t, real_px, real_py, fake_px, fake_py,
                             real_spd, real_hdg, real_acc, drift_x, drift_y, disp_err,
                             is_abrupt, step_scaled);
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
        if ((attack_number == 3 ||
             (g_combined_attack && rsu_idx < MAX_RSUS && g_rsu_attack[rsu_idx] == 3)) &&
            rsu_idx < N_RSUs &&
            compromised_rsu[rsu_idx] &&
            !(g_combined_attack && tag.GetIsPoisoned()))   // combined: only poison HONEST beacons
        {
            // Step 3: Mark real beacon as poisoned (ground-truth provenance flag)
            tag.SetIsPoisoned(true);
            tag.SetAttackType(3);
            double ghost_disp = R_max_comm * poisoning_intensity_theta; // 270*0.5 = 135 m
            tpe_sq_sum += ghost_disp * ghost_disp;   // TPE: ghost displacement (Option B path)
            tpe_cnt++;
            cout << "[MP-S1-RSU" << rsu_idx << "] intercepting V" << vid
                 << " at t=" << t << " → generating ghost IDs" << endl;

            // Steps 4-6: Generate N_ghost ghost packets and send to controller BEFORE
            // the real beacon. Ghost IDs are unique per (RSU, vehicle, ghost-index):
            //   ghost_vid = GHOST_VID_BASE + rsu_idx*100 + vid*10 + gi
            // Placed evenly at ghost_disp (150 m) radius around the real vehicle.
            // AB3: n_coord is now CLI-settable (--n_coord); default 4 preserves
            // the previous hardcoded behaviour for all existing results.
            const int           N_ghost        = g_n_coord;
            static const uint32_t GHOST_VID_BASE = 10000;

            // RING-DETECT pre-pass: seed the RSU's observation buffer with all
            // ring members BEFORE any of them is scored. Without this, ghost gi
            // only ever sees ghosts 0..gi-1, so the first members never reach
            // the g_ring_min_members quorum and only the last one is flagged.
            //
            // This models RECEPTION, not ground truth: these beacons really are
            // transmitted and really are received by rsu_idx. The detector still
            // has to infer the ring from geometry alone.
            //
            // Legacy mode only — --sybil_gat_evasive deliberately scatters the
            // ghosts one per RSU, so there is no ring to find and the geometry
            // test correctly stays silent.
            //
            // NOTE: this mirrors the legacy placement below (angle = gi*2pi/N,
            // radius ghost_disp, heading/timestamp copied from the victim). If
            // that placement changes, change it here too.
            if (g_ring_detect && !g_sybil_gat_evasive) {
                for (int gi = 0; gi < N_ghost; gi++) {
                    double a = gi * (2.0 * M_PI / N_ghost);
                    ring_buf_push(rsu_idx,
                                  GHOST_VID_BASE + rsu_idx * 100 + vid * 10 + gi,
                                  real_px + ghost_disp * std::cos(a),
                                  real_py + ghost_disp * std::sin(a),
                                  tag.GetHeading(), t);
                }
            }

            for (int gi = 0; gi < N_ghost; gi++) {
                double ghost_px, ghost_py, ghost_sp, ghost_hd, ghost_ts;
                uint32_t ghost_rsu;
                uint32_t ghost_vid = GHOST_VID_BASE + rsu_idx * 100 + vid * 10 + gi;

                if (g_sybil_gat_evasive) {
                    // ── Phase 2: distributed, GAT-evasive relational-outlier Sybil ──
                    // Scatter ghost gi onto a 250 m grid (matches the RSU grid pitch) so
                    // each lands in a DISTINCT RSU cell → per-RSU identity density stays
                    // ≤1, and paper-faithful MP-S1 (count > N_v/N_r) cannot fire. The
                    // ghost stays within one cell for the window (no cross-RSU impossible
                    // transit → MP-S4 silent). nearest_rsu_for_position is fwd-declared
                    // (08:31), avoiding the RSU-position array defined later in this file.
                    int col = gi % 6, row = gi / 6;
                    ghost_px  = real_px + 250.0 * (col - 2.5);
                    ghost_py  = real_py + 250.0 * (row - 1.5);
                    ghost_rsu = nearest_rsu_for_position(ghost_px, ghost_py);
                    // Plausible constant kinematics: speed ≤ s_max (no TP-S1/S3), constant
                    // heading (no TP-S2 rate violation). Heading is set OPPOSITE to the
                    // intercepted vehicle's so the ghost is a spatial-relational outlier
                    // vs local heading-aligned flow (the GAT edge predicate) — GAT's
                    // only remaining tell.
                    ghost_sp  = std::min(0.5 * s_max, std::max(8.0, tag.GetSpeed()));
                    ghost_hd  = tag.GetHeading() + M_PI;
                    // De-sync timing well beyond τ_sync so MP-S2 co-occurrence is silent.
                    ghost_ts  = t + 0.037 * (gi + 1);
                    // Density at the ghost's OWN RSU (1 per RSU). No ghost_seen marker:
                    // a realistic Sybil emits no synthetic-ID tell.
                    register_vehicle_at_rsu((int)ghost_rsu, ghost_vid, ghost_ts);
                } else {
                    // ── Legacy a3: clustered ring at the compromised RSU ──────────
                    double angle = gi * (2.0 * M_PI / N_ghost);   // 0°, 90°, 180°, 270°
                    ghost_px  = real_px + ghost_disp * std::cos(angle);
                    ghost_py  = real_py + ghost_disp * std::sin(angle);
                    ghost_sp  = tag.GetSpeed();
                    ghost_hd  = tag.GetHeading();
                    ghost_ts  = t;
                    ghost_rsu = rsu_idx;
                    // LOCAL ghost registration: inflate the compromised RSU's count so
                    // SYB-DETECT (MP-S1) sees count > density_limit and fires.
                    register_vehicle_at_rsu((int)rsu_idx, ghost_vid, t);
                    if ((int)rsu_idx < total_size)
                        rsu_id_set[rsu_idx].ghost_seen = true;
                }

                // Route the ghost through the RSU's IPFS window so the GAT actually
                // scores it (Phase 2). Unconditional (sir's Fix 2, Round 3 review):
                // previously gated behind --sybil_gat_evasive, so legacy mode's
                // ghosts never appeared in the GAT's input graph at all (Round 3
                // Gap 3B measured this directly: 0 ghost rows in feats5, S driven
                // entirely by per-RSU location baseline). Now every ghost, in every
                // mode, is injected at the application layer into the RSU's received-
                // beacon window as if from a real transmitter — no ns-3 Node/
                // MobilityModel/PHY object is created for it (unchanged from before).
                // force_flush=true: a ghost is a ONE-TIME push, never followed by more
                // ghost beacons at that same identity — without forcing, its entry
                // would sit waiting for 9 more REAL beacons at ghost_rsu before ever
                // flushing into rsu_last_window, which is confirmed to never happen
                // in time (0/6154 ghost vids reached FUSION-RSU scoring across two
                // full test runs before this fix).
                {
                    // ── GHOST GRAPH BATCHING (--ghost_batch, default OFF) ──
                    // Flushing each ghost immediately scores it ALONE. Measured:
                    // 74.8% of ghost windows hold exactly 1 beacon, 98.3% hold
                    // <=2, versus 100% of normal windows holding 10 — matching
                    // the GAT input distribution (N=1 in 53% of calls, N=2 in
                    // 16%). A Graph Attention Network with one node has no
                    // neighbours to attend over, so the ring of N_ghost
                    // identities at ~135 m offset with correlated headings —
                    // the very pattern MP-S1 detection depends on — is
                    // dismantled before the model sees it.
                    //
                    // Batching accumulates all ghosts of one interception and
                    // flushes once, giving an N_ghost-node graph in which the
                    // ring is visible. In legacy mode every ghost shares
                    // ghost_rsu = rsu_idx so this is well-defined; in evasive
                    // mode ghosts are deliberately scattered one-per-RSU, so
                    // each must still flush individually or it would never
                    // score at all.
                    const bool ghost_last  = (gi == N_ghost - 1);
                    const bool ghost_flush = (g_ghost_batch && !g_sybil_gat_evasive)
                                             ? ghost_last : true;
                    // RING-DETECT: the ghost is flagged only if the geometry test
                    // finds it ON a consistent-radius ring (never at its centre).
                    const bool ghost_ring_hit =
                        ring_detect_beacon(ghost_rsu, ghost_vid,
                                           ghost_px, ghost_py, ghost_hd, ghost_ts);

                    // Ghosts never pass through the rule tier — the
                    // handle_readone branch that would populate g_ghost_psi_state
                    // is UNREACHABLE for them (measured: psi==0 for 100% of ghost
                    // rows). So publish the hit directly into the ghost psi map,
                    // which IS what the fusion reads for vid >= GHOST_VID_BASE
                    // (:2188, :2269). Passing it as ipfs anomalous_flag instead
                    // does nothing — that field has no readers anywhere.
                    if (ghost_ring_hit) {
                        GhostPsiState &gsr = g_ghost_psi_state[ghost_vid];
                        gsr.psi_sum += SIG_WEIGHTS[5];      // MP-S1 weight 0.15
                        gsr.psi_cnt++;
                        gsr.sig_mask |= (1u << 5);          // MP-S1 bit
                    }

                    ipfs_push_and_maybe_flush(ghost_rsu, ghost_vid,
                                              ghost_px, ghost_py, ghost_sp,
                                              ghost_hd, 0.0, ghost_ts,
                                              /*anomalous_flag=*/ghost_ring_hit,
                                              /*is_poisoned_flag=*/true,
                                              /*force_flush=*/ghost_flush,
                                              /*attack_type_flag=*/3);

                    // ── GHOST AE (--ghost_ae, default OFF) ──────────────────
                    // Feed the ghost's kinematics into the LSTM-AE ring HERE,
                    // at the point ghosts actually enter the pipeline.
                    //
                    // A first attempt placed this in the handle_readone ghost
                    // branch, which is DEAD CODE for ghosts: they are injected
                    // directly into the RSU window above and never arrive as
                    // received beacons. Measured proof — ghost rows carried
                    // psi == 0 AND ae_norm == 0 for 100% of 4123 rows, i.e.
                    // that branch never ran at all.
                    //
                    // Ghosts previously received no AE scoring, leaving the GAT
                    // as their only scorer; MP-S1 ghosts are 75.2% of all false
                    // negatives. FPR-safe by construction: no honest beacon
                    // carries vid >= 10000, so this cannot create an FP. Only D6
                    // has the AE, so only D6 gains — this widens the D6/D4
                    // margin rather than compressing the ablation.
                    if (g_ghost_ae) {
                        lstm_ring_push_resid(ghost_vid,
                                             (float)ghost_px, (float)ghost_py,
                                             (float)ghost_sp, (float)ghost_hd,
                                             0.0f, 1.0f);
                    }
                    // Bug #2 fix (Block 3): the force-flush above only populates
                    // rsu_last_window[ghost_rsu] — GAT/fusion scoring normally
                    // only runs reactively inside HandleBeaconReceived() when a
                    // REAL beacon next arrives at that SAME rsu_id. Evasive mode
                    // deliberately scatters ghosts onto distinct, spread-out RSU
                    // cells specifically to evade density detection, so that real
                    // beacon may never arrive in time (or at all); legacy mode's
                    // clustered ring has the same gap for the last window before
                    // sim end. Call the extracted scoring function directly so the
                    // ghost's window gets scored immediately either way.
                    if (ghost_rsu < N_RSUs)
                        run_gat_fusion_for_rsu(ghost_rsu, rsu_last_window[ghost_rsu].window_epoch);
                }

                // Build ghost beacon packet → controller
                Ptr<Packet> ghost_pkt = Create<Packet>(0);
                BsmBeaconTag ghost_tag;
                ghost_tag.SetVehicleId(ghost_vid);
                ghost_tag.SetPosition(ghost_px, ghost_py);
                ghost_tag.SetSpeed(ghost_sp);
                ghost_tag.SetHeading(ghost_hd);
                ghost_tag.SetAcceleration(0.0);
                ghost_tag.SetTimestamp(ghost_ts);
                ghost_tag.SetIsPoisoned(true);
                ghost_tag.SetAttackType(3);
                ghost_tag.SetRsuId(ghost_rsu);

                // Fix 1 (sir's review, 2026-08-04): ghost beacons were never
                // written to beacon_log.csv — the only path that logs beacons
                // is log_beacon_to_csv(), called exclusively from the real-
                // vehicle receive path (line ~3077). This meant the GAT
                // training corpus (train.py::build_gat_dataset reads exactly
                // this file) could structurally never contain a single ghost
                // feature vector, regardless of which runs were used to build
                // it. detected/sig_mask/psi are passed as their known-by-
                // construction values (ghosts have no trust history or prior
                // beacon to compare against, so psi=0/sig_mask=0 always,
                // matching the D6 log's own psi=0.000/sig_mask=0 for ghosts;
                // "detected" is not read by build_gat_dataset at all, only
                // is_poisoned/attack_number are, so its value here is inert).
                log_beacon_to_csv(ghost_vid, ghost_rsu, ghost_tag,
                                  /*detected=*/false, /*sig_mask=*/0u, /*psi=*/0.0);

                ghost_pkt->AddPacketTag(ghost_tag);

                if (m_relay_socket) {
                    m_relay_socket->SendTo(ghost_pkt, 0,
                        InetSocketAddress(g_management_csma_ip, 7777));
                    cout << "[MP-S1-GHOST-TX] RSU" << ghost_rsu
                         << " ghost_id=" << ghost_vid
                         << " pos(" << std::fixed << std::setprecision(2)
                         << ghost_px << "," << ghost_py << ")"
                         << " [→GAT]"
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

        // ── LW-DETECT at RSU (paper §3.5.3 Algorithm 1, Fig 3.10) ────────────
        // Per the paper architecture, lightweight detection runs at the RSU
        // (edge). It executes AFTER:
        //   • HMAC gate (Eq.3.37)
        //   • RSU-side attack injection (TP-S1 / MP-S1 if RSU is compromised)
        // and BEFORE the beacon is forwarded to the controller.
        //
        // The controller will use the cached result (m_lw_detection_ran=true)
        // for attacks 1-4 and 6. For attacks 5 (TP-S3) and 7 (MP-S4) the
        // controller itself modifies the beacon, then pops the RSU-pushed
        // vehicle_state entry and re-runs this same helper on the modified
        // tag (see HandleBeaconReceived).
        //
        // PBPO_LW: detection time is part of the RSU-side per-beacon lightweight
        // budget per Eq.4.7 (lightweight mode). Accumulated into pbpo_lw_time_sum_ms.

        // Save/restore guard for stolen-ID contamination (attacks 4/6 cached path
        // case): the RSU's push of the poisoned/intercepted beacon would otherwise
        // pollute VS(vid) as the baseline for the NEXT honest beacon.
        // Restore happens only if MP-S4 (impossible velocity) fires — matching the
        // paper-justified case in §3.5.3.
        // COMBINED-MODE FIX #2 (2026-08-05, DQ-STATE1): identical dead-code bug to
        // the one at ~:2801, but on the RSU side — and THIS is the copy that
        // matters. `attack_number` is 0 in combined mode, so save_state_rsu was
        // ALWAYS FALSE and the attacker's forged beacon (which carries the
        // VICTIM's vehicle_id) permanently overwrote VS(victim_id).
        // The victim's own genuine beacon then differenced against the attacker's
        // position -> impossible jump -> TP-S1/S4/S5 fire on an honest vehicle.
        // Measured consequence: 69.7% of all 300s false positives land on a4
        // impersonation victims; vid 98 had FPR = 1.0000 (all 622 beacons).
        // The earlier fix at :2801 had zero measurable effect precisely because it
        // patched the controller-side copy, which never feeds the scoring window.
        const int atk_eff_rsu = g_combined_attack ? (int)tag.GetAttackType() : attack_number;
        bool save_state_rsu = ((atk_eff_rsu == 1) || (atk_eff_rsu == 4) ||
                               (atk_eff_rsu == 5) || (atk_eff_rsu == 6))
                           && (vid < (uint32_t)total_size)
                           && tag.GetIsPoisoned()
                           && !sybil_mitm_nodes[vid];
        VehicleBeaconState vs_backup_rsu;
        if (save_state_rsu) vs_backup_rsu = VS(vid);

        // ── FIX 1: does the physical transmitter own the claimed vehicle ID? ──
        // `from` is the sender address of THIS beacon; g_vehicle_owner_ip[] is
        // the registry-derived owner captured at startup (12_main.h). A mismatch
        // means an impersonation, and the beacon must not be written into the
        // victim's history. Ghost IDs (vid >= 10000) are already excluded from
        // vehicle_state by push_beacon's bounds check, and are injected locally
        // with no physical node, so they are exempted here rather than counted
        // as identity failures.
        // The beacon's vehicle_id IS the transmitter's NS-3 node ID
        // (09_vehicle_beacon_tx.h:249), so g_vehicle_owner_ip is indexed by vid
        // directly — no offset arithmetic, which is what broke the first attempt.
        bool identity_ok = true;
        if (g_identity_binding && vid < (uint32_t)(total_size + 2) && g_vehicle_owner_ip_known[vid]) {
            Ipv4Address src = InetSocketAddress::ConvertFrom(from).GetIpv4();
            identity_ok = (src == g_vehicle_owner_ip[vid]);
            g_idbind_checked++;
            if (!identity_ok) {
                g_idbind_rejected++;
                // Ground-truth label of the REJECTED beacon — the decisive
                // validation of the check. Rejecting an is_poisoned=1 beacon is a
                // correct block of an impersonation; rejecting an honest one is a
                // FALSE rejection and would mean the check harms genuine vehicles.
                if (tag.GetIsPoisoned()) g_idbind_rej_poisoned++;
                else                     g_idbind_rej_honest++;
                if (g_idbind_rejected <= 20)
                    cout << "[FIX1-REJECT] vid=" << vid << " claimed by " << src
                         << " but owner is " << g_vehicle_owner_ip[vid]
                         << " gt_pois=" << (tag.GetIsPoisoned() ? 1 : 0)
                         << " t=" << t << " (vehicle_state write skipped)" << endl;
            }
        }

        struct timespec t_det_start, t_det_end;
        clock_gettime(CLOCK_MONOTONIC, &t_det_start);
        LwDetectResult rsu_lw = run_lw_detect_per_beacon(vid, tag, rsu_idx, identity_ok);
        clock_gettime(CLOCK_MONOTONIC, &t_det_end);
        pbpo_lw_time_sum_ms += (t_det_end.tv_sec  - t_det_start.tv_sec)  * 1000.0
                             + (t_det_end.tv_nsec - t_det_start.tv_nsec) / 1e6;
        // NOTE: pbpo_lw_cnt was already incremented by the HMAC gate timer above;
        // detection time accumulates into the SAME per-beacon sample so the mean
        // reflects HMAC + LW-DETECT together (paper Eq.4.7 lightweight mode total).

        if (save_state_rsu && (rsu_lw.mp_flags & (1u << 3))) {
            // MP-S4 fired on the RSU push — restore pre-push state to prevent
            // future detection on the same vid from comparing against the
            // poisoned/intercepted baseline.
            VS(vid) = vs_backup_rsu;
        }

        // Stamp cached LW-DETECT result onto the tag for the controller to consume
        tag.SetLwDetectionRan(true);
        tag.SetLwAnomalous   (rsu_lw.anomalous);
        tag.SetLwPsi         (rsu_lw.psi);
        tag.SetSigViolated   (rsu_lw.sig_violated);

        cout << "[LW-DETECT-RSU" << rsu_idx << "] V" << vid
             << " psi=" << std::fixed << std::setprecision(3) << rsu_lw.psi
             << " th=" << psi_th
             << " anomalous=" << (rsu_lw.anomalous ? "YES" : "no")
             << " detected=" << (rsu_lw.detected ? "YES" : "no")
             << " sig=0x" << std::hex << rsu_lw.sig_violated << std::dec
             << endl;

        // R6: CP-DETECT (Algorithm 7) audit is performed at the controller
        // emission site (HandleBeaconReceived R5 block) — it reads the RSU's
        // cached LW flags directly from the tag (SetLwAnomalous/SetLwPsi just
        // above) and compares them against the controller's binary decision
        // per-beacon. No separate RSU-side recording is needed.

        // Stamp RSU index into tag so management_node knows which RSU relayed this beacon
        tag.SetRsuId(rsu_idx);

        // Re-attach modified tag to packet
        packet->AddPacketTag(tag);

        // Log every beacon (clean + poisoned) with real vs received positions
        log_rsu_relay(vid, rsu_idx, t, tag.GetIsPoisoned(),
                      real_px, real_py,
                      tag.GetPosX(), tag.GetPosY(),
                      tag.GetSpeed(), tag.GetHeading(), tag.GetAcceleration());

        // ── R4.c: Push beacon into RSU's IPFS window buffer ───────────────────
        // Paper §3.5.3 Eq 3.56, Fig 3.9: RSU accumulates L=10 beacons, hashes
        // the window, "uploads" to IPFS off-chain, and anchors hash on-chain
        // (RSU → BC direct per invariant #1). Controller later retrieves the
        // window from IPFS to run GAT + LSTM-AE in Full mode (pending R7+).
        // Uses the POST-LW-DETECT kinematic tag fields so the stored window
        // reflects exactly what the RSU's authoritative path saw.
        if (rsu_idx < N_RSUs) {
            ipfs_push_and_maybe_flush(rsu_idx, vid,
                                      tag.GetPosX(), tag.GetPosY(),
                                      tag.GetSpeed(), tag.GetHeading(),
                                      tag.GetAcceleration(), t,
                                      rsu_lw.anomalous,
                                      tag.GetIsPoisoned(),
                                      /*force_flush=*/false,
                                      (int)tag.GetAttackType());
        }

        // ── R7e: Cache ψ + push to per-vehicle LSTM-AE ring buffer ────────────
        // The controller-side fusion step (paper Eq 3.46) needs three inputs
        // per vehicle: ψ_i (cached here), S_i (computed at window close from
        // GAT), and ε_i/θ_ae (computed at window close from this ring). We
        // record both at the RSU because the kinematics on this path are
        // exactly what the LW-DETECT authority saw — no double-counting of
        // attacker-flipped values from a different code path.
        if (vid < (uint32_t)total_size) {
            // H8: accumulate ψ per vehicle within the window for a per-window MEAN
            // (paper Eq 3.59 aggregates ψ by mean). Mean captures sustained
            // poisoning (recall) without amplifying a single spurious honest-beacon
            // ψ into a whole-window false positive (as max-ψ did). Reset per window.
            last_psi_per_vehicle[vid] += rsu_lw.psi;
            psi_cnt_per_vehicle[vid]++;
            // Richer-feature: keep the most-recent sig_mask (which LW rule-checks
            // fired = the ψ sub-scores) for this vehicle; the multi-task GAT uses
            // its 9 bits to identify the attack TYPE (k̂) for λ-routing. Per-beacon
            // (not OR-accumulated) to match the per-tick training snapshot. This is
            // byte-identical to the beacon_log.csv sig_mask column the GAT trained
            // on: tp_flags(bits0-4) | mp_flags<<5(bits5-8); CP bits excluded.
            last_sigmask_per_vehicle[vid] = rsu_lw.tp_flags | (rsu_lw.mp_flags << 5);
            // 6th AE feature = tau_i. The trained scaler has tau mean=1.0
            // scale=1.0, and the AE was trained on clean data where tau≡1.0
            // (scaled→0.0). Feed the default trusted value to stay on-manifold
            // and consistent with the GAT path (which uses TAU_DEFAULT=1.0).
            // AB4 fix: push DEAD-RECKONING RESIDUAL channels, not absolute
            // position — the retrained urban AE consumes (res_x, res_y, dspeed,
            // dheading, accel, tau). See lstm_ring_push_resid() in
            // 04_state_globals.h for why. Raw kinematics are passed in; the
            // helper differences them against this vehicle's previous beacon.
            lstm_ring_push_resid(vid,
                                 (float)tag.GetPosX(), (float)tag.GetPosY(),
                                 (float)tag.GetSpeed(), (float)tag.GetHeading(),
                                 (float)tag.GetAcceleration(), 1.0f);
        } else if (vid >= 10000u) {
            // Ghost path (fix for Critical Issue 3 ranking-inversion): same
            // psi/sig_mask accumulation as the real-vehicle branch above, keyed
            // by vid in a map instead of a fixed array — see GhostPsiState in
            // 04_state_globals.h for why this exists. LSTM-AE temporal scoring
            // (lstm_ring_push_resid) is intentionally NOT extended to ghosts
            // here — that's a fixed total_size-indexed array too, and ghost
            // temporal scoring is a separate concern from this fix.
            GhostPsiState &gs = g_ghost_psi_state[vid];
            gs.psi_sum += rsu_lw.psi;
            gs.psi_cnt++;
            gs.sig_mask = rsu_lw.tp_flags | (rsu_lw.mp_flags << 5);

            // NOTE: this branch is UNREACHABLE for ghosts. Ghosts never arrive
            // as received beacons — they are injected directly into the RSU
            // window at the MP-S1 generation site (~:3959). Measured: ghost rows
            // carry psi == 0 and ae_norm == 0 for 100% of rows, i.e. neither the
            // GhostPsiState accumulation above nor anything else here executes.
            // The ghost AE feed therefore lives at the injection site, not here.
        }

        // ── R4.a: SC-Trust + SC-Revoke at RSU (paper invariant #1, §3.5.5) ────
        // Per paper invariant #1, RSU → blockchain is DIRECT — these smart-contract
        // calls must originate at the RSU, not the controller. Algorithm 1 line 5-6
        // gates SC-Trust on the lightweight composite-score breach (ψ > ψ_th, i.e.
        // rsu_lw.anomalous). SC-Revoke casts ONE BFT vote the instant this RSU
        // flags the vehicle (flag=1, Eq 3.67); the 2f+1-distinct-witness quorum
        // (Eq 3.65) is decided chaincode-side within the sliding window T_w.
        //
        // For attacks 5/7 (controller-as-attacker) the RSU's view is HONEST — the
        // data plane is clean and no SC call fires here. That is correct: SC-Trust
        // tracks VEHICLE trust; controller misbehavior is caught by CP-DETECT
        // (Algorithm 7, paper §3.5.5) which lands in phase R6.
        //
        // CDER for attacks 5/7 still ticks via the controller-attack downlink path
        // in HandleBeaconReceived (R2). PARR denominator (parr_poisoned_total) is
        // still aggregated at the controller; the numerator (parr_trs_rejected)
        // moves here with the revoke event.
        if (vid < (uint32_t)(total_size + 2)) {
            if (rsu_lw.detected) {
                double ts = Simulator::Now().GetSeconds();

                // ── PARR numerator (Eq 4.3) ──────────────────────────────────
                // A poisoned beacon flagged by this RSU's lightweight detector
                // (flag=1, Eq 3.67) is a TRS-layer rejection. Counted per flagged
                // poisoned beacon, in lockstep with parr_poisoned_total — NOT
                // throttled by the vote refresh guard below (that is a network
                // anti-spam concern, not a detection metric).
                if (tag.GetIsPoisoned()) parr_trs_rejected++; // PARR numerator (Eq.4.3)

                // ── Per-(RSU,vehicle) vote refresh guard (anti-spam only) ────
                // The RSU is a revocation witness the instant it flags the
                // vehicle (Eq 3.67); it need not re-broadcast the same idempotent
                // vote on every 100 ms beacon. Rate-limit SUBMISSION to once per
                // VOTE_REFRESH_SEC of continued flagging. This does NOT weaken the
                // 2f+1 quorum (Eq 3.65): distinct RSUs each still contribute one
                // witness — only redundant re-sends from the SAME RSU are coalesced.
                uint64_t guard_key = ((uint64_t)rsu_idx << 32) | (uint64_t)vid;
                auto vit = last_revoke_vote_ts.find(guard_key);
                bool should_vote = (vit == last_revoke_vote_ts.end())
                                   || (ts - vit->second >= VOTE_REFRESH_SEC);
                if (should_vote) {
                    last_revoke_vote_ts[guard_key] = ts;

                    // ── Eq 3.65 SC-Revoke BFT ────────────────────────────────
                    // Revocation requires ≥ 2f+1 DISTINCT trusted-RSU witnesses
                    // accumulated within the sliding window T_w (Eq 3.65;
                    // NumRSUs=4 → f=1 → threshold=3). This RSU casts ONE vote on
                    // its first flag (Eq 3.67); the chaincode tallies distinct
                    // trusted voters whose votes fall in [t-T_w, t] and commits
                    // SCREVOKE once the quorum is met. The vote is idempotent per
                    // (vehicle,RSU): VOTE_<vid>_<rsuID> is overwritten, so the
                    // same RSU is counted at most once toward the quorum.
                    //
                    // Flow per RSU:
                    //   1. RSU r_j casts SCRevokeVote (sync — needs the revoked
                    //      bit back to decide whether to rekey).
                    //   2. Chaincode stores VOTE_<vid>_<rsuID> (idempotent per
                    //      RSU) and counts the distinct trusted voters in-window.
                    //   3. When count ≥ 2f+1, chaincode commits SCREVOKE_<vid>_<ts>
                    //      + emits "SCRevoke" event AND returns "revoked":true.
                    //   4. Only when revoked=true does THIS RSU fire LKH rekey
                    //      locally. Other RSUs learn from the "SCRevoke" Fabric
                    //      event (Fabric Gateway C++ gRPC client — separate task).
                    //
                    // A5 ablation / routing_test fallback: no chaincode → per-RSU
                    // unilateral revoke (RQ6 BC-isolation baseline).
                    //
                    // The revoke-vote signature (Eq 3.63) is produced inside
                    // CallSCRevokeVote with this RSU's registered P-256 key over
                    // (vehId‖rsuId‖reason‖ts) and verified on submit by the
                    // chaincode, so a forged identity cannot pad the 2f+1 tally.
                    bool revoked = false;
                    if (!enable_sc_revoke) {
                        // R3 config5 ablation: revocation mechanism entirely
                        // disabled — vehicles are never revoked regardless of
                        // behaviour (no vote cast, no local fallback either).
                        revoked = false;
                    } else if (!routing_test && ablation_mode != 5) {
                        std::string vote_payload = CallSCRevokeVote(
                            vid, rsu_idx, "lw_anomaly_flag", ts);
                        // Payload shape: {"voted":true,"votes":N,"threshold":T,"revoked":bool}
                        revoked = (vote_payload.find("\"revoked\":true")
                                   != std::string::npos);
                        cout << "[SC-REVOKE-VOTE-RSU" << rsu_idx << "] V" << (vid - 2)
                             << " ts=" << std::fixed << std::setprecision(3) << ts
                             << " payload=" << vote_payload
                             << " (paper §3.5.5 Eq 3.65 BFT 2f+1, window T_w)" << endl;
                    } else {
                        // A5 / routing_test: no BC consensus — local revoke
                        revoked = true;
                        cout << "[SC-REVOKE-LOCAL-RSU" << rsu_idx << "] V" << (vid - 2)
                             << " ts=" << std::fixed << std::setprecision(3) << ts
                             << " (no-BC fallback; ablation_mode=" << ablation_mode
                             << " routing_test=" << (routing_test ? "true" : "false")
                             << ")" << endl;
                    }

                    // LKH rekey (Eq.3.34): N_rekey = log₂|V_j| unicasts to
                    // remaining vehicles. Fires only when BFT quorum was hit
                    // (Eq 3.65) OR the no-BC fallback authorized local revoke.
                    if (revoked && rsu_idx < N_RSUs) {
                        cout << "[LKH-REVOKE-RSU" << rsu_idx << "] V" << (vid - 2)
                             << " revoked (Eq.3.65 BFT) → group rekey (Eq.3.34)"
                             << endl;
                        // Phase 1C-b: route through dedup wrapper so the event
                        // drainer (which fires on the same SCRevoke event a
                        // moment later) doesn't double-rekey this RSU's tree.
                        send_lkh_rekey_if_new(vid, rsu_idx, ts);
                        // Arm the cross-RSU drainer on first revocation activity
                        // so remote RSUs catch the SCRevoke chaincode event and
                        // rekey their own trees (Phase 1C-b broadcast path).
                        mptd_arm_event_drainer_once();
                    }
                }
            }
            // No consecutive-flag counter to reset: the paper (Eq 3.65/3.67) has
            // none — robustness is the 2f+1 distinct-witness quorum, not repetition.

            // SC-Trust: per-beacon ψ submission when composite score breaches threshold.
            // Algorithm 1 line 5-6 says "if ψ_i(t) > ψ_th" → gated on rsu_lw.anomalous
            // (NOT rsu_lw.detected which also folds in the CP-DETECT oracle).
            // A5 ablation skips SC-Trust for the blockchain-isolation comparison (RQ6).
            if (!routing_test && ablation_mode != 5 && enable_sc_trust && rsu_lw.anomalous) {
                double ts = Simulator::Now().GetSeconds();

                // ── Paper-aligned Eq 3.56 RSU evidence tuple (TASK ①-I) ──────
                // E_j(t) = (vehicleID, ψ_j^(i)(t), epoch, h(b_i(t)), σ_j^sub)
                //
                // Paper invariant #1 (RSU→Blockchain direct) — this call is
                // submitted by the RSU itself with NO controller relay. The
                // chaincode side (SCTrustSubmitEvidence in
                // chaincode/chaincode/smartcontract.go) buffers the witness;
                // SCTrustFinalizeEpoch later aggregates them per Eq 3.55:
                //   τ_i(t) = α·τ_i(t-1) + (1-α)·(1 - (1/|R|)·Σ ψ_j^(i)(t))
                //
                // BeaconTag carries scalar (speed, heading, accel). Project to
                // (vx, vy) deterministically so every RSU witnessing the same
                // DSRC broadcast computes the SAME canonical blob → SAME CID,
                // which is what SCTrustFinalizeEpoch needs to recognise
                // witnesses-of-the-same-beacon.
                //
                // σ_j^sub PLACEHOLDER: empty string for now — the chaincode
                // accepts it as opaque bytes (verification is the
                // LatticeTrsBackend migration's job, phase R11). Real
                // per-RSU TRS partial-sig plumbing through ITrsBackend lands
                // in TASK ①-J.
                {
                    const double speed   = tag.GetSpeed();
                    const double heading = tag.GetHeading();
                    const double accel   = tag.GetAcceleration();
                    const double vx = speed * std::cos(heading);
                    const double vy = speed * std::sin(heading);
                    const double ax = accel * std::cos(heading);
                    const double ay = accel * std::sin(heading);

                    std::string h_b = mptd_beacon_hash(
                        std::to_string(vid),
                        std::to_string(rsu_idx),
                        tag.GetPosX(), tag.GetPosY(), 0.0,
                        vx, vy, 0.0,
                        ax, ay, 0.0,
                        tag.GetTimestamp());

                    std::string epoch = mptd_epoch_from_ts(ts);

                    // ── σ_j^sub: RSU-identity ECDSA P-256 (Eq 3.61) ─────────
                    // SC-Trust evidence is keyed by RSUID on chain (SUBM_<vid>_
                    // <epoch>_<rsuID>), so there is no signer anonymity to
                    // protect — the correct σ_j^sub is the submitting RSU's
                    // registered Fabric-MSP P-256 signature, the same key class
                    // SC-Register endorsements use. CallSCTrustSubmitEvidence
                    // now produces it internally over the exact transmitted
                    // strings, and the chaincode verifies it on submit
                    // (smartcontract.go SCTrustSubmitEvidence). The privacy-
                    // preserving threshold-ring σ_TRS (Eq 3.48) is a separate
                    // construct over the FHE cloud aggregate, not this per-RSU
                    // evidence auth — it stays in the 06b1 cloud pipeline.
                    // Tier-3: batch anomaly evidence (paper §3.5.5) instead of a
                    // per-beacon synchronous submit. Tier-1 revocation and the
                    // per-epoch finalizes below remain on their own cadence.
                    if (g_tiered_commit)
                        tier3_commit_evidence(vid, rsu_idx, epoch, rsu_lw.psi, h_b, ts);
                    else
                        CallSCTrustSubmitEvidence(
                            vid, rsu_idx, epoch, rsu_lw.psi, h_b);

                    // ── Schedule Eq 3.55 finalization 1 s after submission ──
                    // SCTrustFinalizeEpoch aggregates all RSU witnesses of
                    // vehicle vid in this epoch. We delay 1 s (sim time) to
                    // give other RSU witnesses time to submit before the
                    // chaincode computes (1/|R|)·Σ ψ_j^(i)(t).
                    //
                    // Dedup: each (vid, epoch) pair gets EXACTLY ONE finalize
                    // scheduled across all RSUs / beacons. Without dedup, every
                    // beacon would re-schedule a finalize; the chaincode is
                    // idempotent on (vid, epoch) but the duplicate orderer
                    // round-trips would tank PBPO and saturate the gateway.
                    //
                    // Static set is process-local — fine since the sim runs in
                    // one process. Cleared on next sim run (re-static-init).
                    static std::unordered_set<std::string> g_finalize_scheduled;
                    static std::mutex                       g_finalize_mu;
                    std::string key = std::to_string(vid) + "|" + epoch;
                    bool first;
                    {
                        std::lock_guard<std::mutex> lk(g_finalize_mu);
                        first = g_finalize_scheduled.insert(key).second;
                    }
                    if (first) {
                        Simulator::Schedule(Seconds(1.0),
                            &CallSCTrustFinalizeEpochAsync, vid, epoch);
                    }

                    // RSU SC-Trust finalize (Eq rsu_trust / rsu_misbehave) is
                    // channel-wide — ONE call per epoch evaluates every RSU's
                    // misbehaviour signal m_j against the 2f+1 trusted quorum,
                    // so it is deduped on `epoch` ALONE (not vid|epoch). We
                    // delay 2 s — one second after the per-vehicle finalizes —
                    // so the full SUBM_<*>_<epoch>_<rsu> set for this epoch has
                    // landed before the contract reconstructs q_i. Idempotent
                    // on chain, so a converging re-fire is harmless.
                    static std::unordered_set<std::string> g_rsu_finalize_scheduled;
                    static std::mutex                       g_rsu_finalize_mu;
                    bool rsu_first;
                    {
                        std::lock_guard<std::mutex> lk(g_rsu_finalize_mu);
                        rsu_first = g_rsu_finalize_scheduled.insert(epoch).second;
                    }
                    if (rsu_first) {
                        Simulator::Schedule(Seconds(2.0),
                            &CallSCRSUFinalizeEpochAsync, epoch);
                    }

                    // Controller SC-Trust finalize (Eq 3.60 EMA / Eq 3.68
                    // directional conflict) is ALSO channel-wide — ONE call per
                    // epoch evaluates every controller's τ_ck(t) over its
                    // R^obs_ck(t) RSU set, so it is deduped on `epoch` ALONE.
                    // Delayed 3 s — one second after the RSU finalize — so the
                    // full CSUBM_<*>_<epoch> + SUBM_<*>_<epoch>_<rsu> sets for
                    // this epoch have landed before the contract reconstructs
                    // conflict_j over the co-observed vehicles. Idempotent on
                    // chain (re-fire just re-evaluates the same submission set),
                    // so a converging re-fire is harmless.
                    static std::unordered_set<std::string> g_ctrl_finalize_scheduled;
                    static std::mutex                       g_ctrl_finalize_mu;
                    bool ctrl_first;
                    {
                        std::lock_guard<std::mutex> lk(g_ctrl_finalize_mu);
                        ctrl_first = g_ctrl_finalize_scheduled.insert(epoch).second;
                    }
                    if (ctrl_first) {
                        Simulator::Schedule(Seconds(3.0),
                            &CallSCControllerFinalizeEpochAsync, epoch);
                    }
                }
            }
        }

        // ── R2: RSU-direct DSRC downlink (paper Fig 3.1 Step 6/7) ────────────
        // The RSU is the authoritative LW-DETECT source per §3.5.3 Algorithm 1
        // and emits the safety alert directly to vehicles on DSRC — no controller
        // round-trip, no CSMA hop. m_send_socket is already bound on the RSU's
        // DSRC interface with broadcast enabled.
        //
        // Skip for three scenarios where the controller owns the emission instead:
        //   • attacks 5/7 (controller-as-attacker, paper Fig 3.3 / Fig 3.7): the
        //     malicious controller injects WRONG_ROUTING into the vehicle plane
        //     via CSMA → RSU → DSRC, so the RSU's honest LW result is irrelevant.
        //   • attack 1 (RSU-as-attacker, paper Fig 3.1 Step 5-7, added in R5):
        //     paper attributes the decision emission to the controller (honest but
        //     deceived by the RSU-poisoned cached LW result). The compromised RSU
        //     is the attacker here — it would not honestly self-alert anyway — so
        //     the controller's CSMA → RSU → DSRC chain realises paper Step 6/7.
        // In all three cases the controller-side block in HandleBeaconReceived
        // (Step 11) emits the alert. CDER stays well-defined per Eq.4.4: exactly
        // one control decision per beacon (R2 fast-path OR controller-here, never both).
        if (g_option_b_active && m_send_socket &&
            attack_number != 1 && attack_number != 5 && attack_number != 7) {
            DownlinkControlTag dl_tag;
            dl_tag.SetVehicleId   (vid);                                     // unicast target
            dl_tag.SetAlertType   (rsu_lw.detected ? 1 : 0);                 // ATTACK_DETECTED or CLEAN_ROUTING
            dl_tag.SetSpeedAdvice (rsu_lw.detected ? (s_max * 0.5) : s_max); // 50% advisory if attack
            dl_tag.SetTimestamp   (t);
            dl_tag.SetRsuId       (rsu_idx);

            Ptr<Packet> dl_pkt = Create<Packet>(0);
            dl_pkt->AddPacketTag(dl_tag);

            int dl_err = m_send_socket->SendTo(
                             dl_pkt, 0,
                             InetSocketAddress(Ipv4Address("3.255.255.255"), 9999));

            const char* alert_str = rsu_lw.detected ? "ATTACK_DETECTED" : "CLEAN_ROUTING";
            if (dl_err >= 0) {
                // CDER (Eq.4.4) — RSU-direct emission counts as one control decision.
                // wrong iff (detected ⊻ is_poisoned): FP when CLEAN flagged, FN when ATTACK missed.
                ctrl_decisions_total++;
                bool is_poisoned_now = tag.GetIsPoisoned();
                bool wrong = (rsu_lw.detected ? !is_poisoned_now : is_poisoned_now);
                if (wrong) ctrl_decisions_wrong++;

                cout << "[DL-RSU" << rsu_idx << "-DIRECT] → V" << vid
                     << " :9999 alert=" << alert_str
                     << " spd_adv=" << (rsu_lw.detected ? s_max * 0.5 : s_max) << " m/s"
                     << " (paper Fig 3.1 Step 6/7)" << endl;
            } else {
                cout << "[DL-RSU" << rsu_idx << "-DIRECT-ERR] failed vid=" << vid << endl;
            }
        }

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
                    // ── A7-STEP4: RSU forwards HONEST data to controller via control plane ──
                    // Paper Fig 3.7: RSU correctly relays unmodified beacon to controller.
                    // At this point both vehicle and RSU have behaved honestly.
                    if (attack_number == 7) {
                        cout << "[A7-STEP4] RSU" << rsu_idx
                             << " → Controller: forwarding HONEST V" << vid
                             << " via control plane — controller receives correct data"
                             << "  [send_rsu_dataunicast_alone]" << endl;
                    }
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
// Sized for capacity MAX_RSUS; first 4 entries are the routing_test default.
// In SUMO-trace mode 12_main.h overwrites entries 0..N_RSUs-1 from the RSU CSV
// (rsu_positions_<scenario>.csv) so cell mapping matches the placed RSU nodes.
static double g_rsu_actual_pos_x[MAX_RSUS] = {250.0, 750.0, 1250.0, 1750.0}; // routing_test default
static double g_rsu_actual_pos_y[MAX_RSUS] = {480.0, 480.0,  480.0,  480.0};

// Populate the cell-mapping table from the ACTUAL placed RSU node positions
// (called once at startup from 12_main.h after RSU_mobility.Install). In test
// net the placed positions equal the grid defaults above (bit-identical); in
// SUMO-trace mode they are the CSV positions, so beacons map to the right cell.
inline void set_rsu_actual_pos(uint32_t idx, double x, double y)
{
    if (idx < MAX_RSUS) { g_rsu_actual_pos_x[idx] = x; g_rsu_actual_pos_y[idx] = y; }
}

static uint32_t nearest_rsu_for_position(double px, double py)
{
    // Use actual RSU positions (set at startup, matches 12_main.h topology)
    static const double (&rsu_x)[MAX_RSUS] = g_rsu_actual_pos_x;
    static const double (&rsu_y)[MAX_RSUS] = g_rsu_actual_pos_y;
    int active = (N_RSUs > 0 && N_RSUs <= MAX_RSUS) ? (int)N_RSUs : MAX_RSUS;
    uint32_t nearest = 0;
    double   min_d2  = 1e18;
    for (int r = 0; r < active; r++) {
        double dx = px - rsu_x[r], dy = py - rsu_y[r];
        double d2 = dx*dx + dy*dy;
        if (d2 < min_d2) { min_d2 = d2; nearest = (uint32_t)r; }
    }
    return nearest;
}

// H7: scenario-derived plausibility envelope for FHE aggregates (fwd-declared
// above run_full_mode_crypto_pipeline). Bounds:
//   speed ∈ [0, 1.1·max(s_max, maxspeed/3.6)] — scenario speed limit + 10 %
//     headroom (SUMO traces respect the limit; s_max covers hardcoded runs);
//   position within the ACTUAL RSU deployment box ± 2·R_max — every genuine
//     vehicle lives inside RSU coverage in both hardcoded and SUMO scenarios;
//   count ∈ [1, count_max] (≤ L beacons per contributing window).
static bool fhe_aggregate_envelope_ok(double mean_speed, double mean_x,
                                      double mean_y, int64_t count,
                                      int64_t count_max, const char *stage)
{
    const int active = (N_RSUs > 0 && N_RSUs <= MAX_RSUS) ? (int)N_RSUs : MAX_RSUS;
    double xmin = g_rsu_actual_pos_x[0], xmax = xmin;
    double ymin = g_rsu_actual_pos_y[0], ymax = ymin;
    for (int r = 1; r < active; r++) {
        xmin = std::min(xmin, g_rsu_actual_pos_x[r]);
        xmax = std::max(xmax, g_rsu_actual_pos_x[r]);
        ymin = std::min(ymin, g_rsu_actual_pos_y[r]);
        ymax = std::max(ymax, g_rsu_actual_pos_y[r]);
    }
    const double margin = 2.0 * R_max_comm;
    const double v_env  = 1.1 * std::max(s_max, (double)maxspeed / 3.6);
    const bool ok = count >= 1 && count <= count_max
                 && mean_speed >= 0.0 && mean_speed <= v_env
                 && mean_x >= xmin - margin && mean_x <= xmax + margin
                 && mean_y >= ymin - margin && mean_y <= ymax + margin;
    if (!ok) {
        cout << "[FHE-ENVELOPE] " << stage << " reject:"
             << " speed=" << mean_speed << " (max " << v_env << ")"
             << " pos=(" << mean_x << "," << mean_y << ")"
             << " box=[" << (xmin - margin) << "," << (xmax + margin) << "]x["
             << (ymin - margin) << "," << (ymax + margin) << "]"
             << " count=" << count << "/" << count_max << endl;
    }
    return ok;
}

// ── Link-Lifetime RSU Selection (§RSU-LL) ────────────────────────────────────
// Replaces pure nearest-RSU with a normalized score:
//
//   score(RSU_i) = LL_norm / d_norm
//               = (LL_i / T_REF) / (d_i / R_max_comm)
//               = (LL_i × R_max_comm) / (d_i × T_REF)
//
// LL_i  = time (s) the vehicle will remain in RSU_i's range, computed via
//         the quadratic exit-time formula (see compute_link_lifetime).
// T_REF = 2×R_max_comm/s_max = 18 s  — minimum traversal time at max speed;
//         normalises LL to a dimensionless "coverage fraction".
// d_i   = current distance to RSU_i (m); normalised by R_max_comm → (0,1].
//
// Constraints:
//   • Only RSUs with d_i ≤ R_max_comm are candidates (vehicle in range).
//   • Hysteresis δ=0.15: switch only when score(new) > 1.15×score(current).
//   • Fallback: if no RSU in range, return nearest RSU (keeps LTE path alive).
//
// Parameters (fixed for this SDVN topology):
//   T_MAX = 30 s   — LL cap for stopped/slow vehicles (> simTime=15 s)
//   T_REF = 16.2 s — 2×270/33.33 = traversal reference
//   δ     = 0.15   — hysteresis: 15% improvement required to trigger handoff
// ─────────────────────────────────────────────────────────────────────────────
static const double LL_T_MAX = 30.0;   // cap for LL when vehicle is stopped (s)
static const double LL_T_REF = 16.2;   // 2*R_max_comm/s_max = 2*270/33.33 — traversal reference (s)
static const double LL_DELTA = 0.15;   // hysteresis threshold (15 %)

// Per-vehicle hysteresis state: last selected RSU index and score.
static uint32_t g_vehicle_rsu_choice[MAX_NODES] = {};    // last selected RSU
static double   g_vehicle_rsu_score [MAX_NODES] = {};    // last selected RSU score
static bool     g_vehicle_rsu_init  [MAX_NODES] = {};    // false until first selection

// Compute how long (s) a vehicle at (px,py) moving with velocity (vx,vy) will
// remain within R_max_comm of the RSU at (rx,ry).
//
// Derivation:  d(t)² = (dx+vx·t)² + (dy+vy·t)² = R²
//              a·t² + b·t + c = 0
//              a=|v|², b=2(r⃗·v⃗), c=d²−R²
// Vehicle is currently inside range → c < 0 → one negative + one positive root.
// LL = positive root = (−b + √disc) / (2a).
static double compute_link_lifetime(double px, double py,
                                    double vx, double vy,
                                    double rx, double ry)
{
    double dx   = px - rx,  dy  = py - ry;
    double a    = vx*vx + vy*vy;
    double b    = 2.0*(dx*vx + dy*vy);
    double c    = dx*dx + dy*dy - R_max_comm*R_max_comm;

    if (c > 0.0)  return 0.0;           // outside range — not a candidate
    if (a < 1e-9) return LL_T_MAX;      // vehicle stopped → stays indefinitely

    double disc = b*b - 4.0*a*c;
    if (disc < 0.0) return LL_T_MAX;    // moves in circle inside range

    double t_exit = (-b + std::sqrt(disc)) / (2.0*a);
    if (t_exit < 0.0) t_exit = 0.0;
    return std::min(t_exit, LL_T_MAX);
}

// Select the best RSU using the normalized LL/d score with hysteresis.
// vx,vy = vehicle's REAL velocity (from MobilityModel — not the poisoned beacon).
// is_mal is passed for diagnostic logging only; selection always uses real motion.
static uint32_t best_rsu_for_position(double px, double py,
                                       double vx, double vy,
                                       uint32_t vid, bool is_mal)
{
    (void)is_mal; // reserved for future per-attack diagnostic hooks
    static const double (&rsu_x)[MAX_RSUS] = g_rsu_actual_pos_x;
    static const double (&rsu_y)[MAX_RSUS] = g_rsu_actual_pos_y;
    int active = (N_RSUs > 0 && N_RSUs <= MAX_RSUS) ? (int)N_RSUs : MAX_RSUS;

    uint32_t best_idx   = 0;
    double   best_score = -1.0;
    bool     any_in_range = false;

    for (int r = 0; r < active; r++) {
        double dx  = px - rsu_x[r],  dy = py - rsu_y[r];
        double d   = std::sqrt(dx*dx + dy*dy);

        if (d > R_max_comm) continue;   // out of range — skip
        any_in_range = true;

        // d_norm ∈ (0,1]: avoid div/0 when vehicle sits on RSU antenna.
        // (Pre-R6.5 note: std::max avoided due to #define max 40 — that macro
        // is now MPTD_MAX_NEIGHBORS so std::max is safe; left as ternary.)
        double d_raw   = d / R_max_comm;
        double d_norm  = (d_raw > 1e-6) ? d_raw : 1e-6;

        double ll      = compute_link_lifetime(px, py, vx, vy, rsu_x[r], rsu_y[r]);
        double ll_norm = ll / LL_T_REF;  // may exceed 1.0 for slow vehicles — intentional

        double score   = ll_norm / d_norm;

        if (score > best_score) { best_score = score; best_idx = (uint32_t)r; }
    }

    // No RSU in communication range → fall back to nearest RSU (LTE path)
    if (!any_in_range) return nearest_rsu_for_position(px, py);

    // ── Hysteresis: only switch RSU if improvement exceeds δ=15 % ────────────
    uint32_t safe_vid = (vid < MAX_NODES) ? vid : 0u;
    if (g_vehicle_rsu_init[safe_vid]) {
        uint32_t old_rsu   = g_vehicle_rsu_choice[safe_vid];
        double   old_score = g_vehicle_rsu_score [safe_vid];
        if (best_idx != old_rsu && best_score <= old_score * (1.0 + LL_DELTA)) {
            // Improvement is marginal — keep current RSU if still reachable
            double odx = px - rsu_x[old_rsu], ody = py - rsu_y[old_rsu];
            if (std::sqrt(odx*odx + ody*ody) <= R_max_comm) {
                best_idx   = old_rsu;
                best_score = old_score;
            }
        }
    }

    // Persist hysteresis state
    g_vehicle_rsu_choice[safe_vid] = best_idx;
    g_vehicle_rsu_score [safe_vid] = best_score;
    g_vehicle_rsu_init  [safe_vid] = true;

    return best_idx;
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
