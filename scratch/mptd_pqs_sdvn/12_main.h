// ============================================================
// SECTION 12: main() - Simulation Topology Setup and Scheduling
// ============================================================
// This is the simulation entry point. It:
//
// 1. Parses command-line arguments:
//      --attack_number=1..6    (which attack to simulate)
//      --attack_percentage=0..100 (% of malicious RSUs)
//      --routing_algorithm=0..5  (which routing protocol)
//      --routing_test=true/false (use small test topology)
//      --simTime=15            (simulation duration in seconds)
//      --maxspeed=60           (vehicle max speed in km/h)
//
// 2. Creates the network topology:
//      Vehicle_Nodes (16 by default)
//      RSU_Nodes (4 RSUs for routing_test=true)
//      controller_Node (4 SDN controllers)
//      management_Node (1 management node)
//      WiFi DSRC links (vehicles ↔ RSUs, 802.11p)
//      CSMA Ethernet backhaul (RSUs ↔ controllers)
//      LTE links (vehicles ↔ eNodeB)
//
// 3. Assigns IP addresses and installs internet stack
//
// 4. Schedules simulation events:
//      MRTPA Phase 1: vehicles send trajectory data to RSU
//      MRTPA Phase 2: RSU processes/poisons/forwards (in MacRx callback)
//      Optimization events (every 3 seconds)
//      LLDP discovery (at t=0.5s, 1.0s, ...)
//      Data transmission (periodic)
//
// Run with:
//   python3 waf --run "lda_attack --attack_number=1 --routing_algorithm=4
//     --routing_test=true --attack_percentage=80 --simTime=15"
// ============================================================
// TEMP DIAGNOSTIC (Step 1, RSU coverage check + time-varying follow-up):
// sample geometric coverage at multiple timestamps, not just once, to tell
// whether a single snapshot is representative. Additive-only, no behavior change.
void mptd_coverage_diag_check(double t_label)
{
    uint32_t within_range = 0;
    std::vector<Vector> rsu_pos;
    for (uint32_t r = 0; r < RSU_Nodes.GetN(); r++) {
        rsu_pos.push_back(RSU_Nodes.Get(r)->GetObject<MobilityModel>()->GetPosition());
    }
    for (uint32_t v = 0; v < Vehicle_Nodes.GetN(); v++) {
        Vector vp = Vehicle_Nodes.Get(v)->GetObject<MobilityModel>()->GetPosition();
        double mind = 1e18;
        for (auto &rp : rsu_pos) {
            double dx = vp.x - rp.x, dy = vp.y - rp.y;
            double d = std::sqrt(dx*dx + dy*dy);
            if (d < mind) mind = d;
        }
        if (mind <= R_max_comm) within_range++;
    }
    std::cout << "[COVERAGE-DIAG] t=" << t_label << "s vehicles_within_" << R_max_comm << "m_of_any_RSU="
              << within_range << "/" << Vehicle_Nodes.GetN()
              << " (" << (100.0*within_range/Vehicle_Nodes.GetN()) << "%)" << std::endl;
}

int main(int argc, char *argv[])
{
    CommandLine cmd;
    cmd.AddValue ("N_RSUs", "N_RSUs", N_RSUs);
    cmd.AddValue ("N_Vehicles", "N_Vehicles", N_Vehicles);
    cmd.AddValue ("N_Controllers", "N_Controllers", N_Controllers);
    cmd.AddValue ("data_transmission_frequency", "data_transmission_frequency", data_transmission_frequency);
    cmd.AddValue ("link_lifetime_threshold", "link_lifetime_threshold", link_lifetime_threshold);
    cmd.AddValue ("simTime", "simTime", simTime);
    cmd.AddValue ("mobility_scenario", "mobility_scenario", mobility_scenario);
    cmd.AddValue ("architecture", "architecture", architecture);
    cmd.AddValue ("maxspeed", "maxspeed", maxspeed);
    // Sensitivity-analysis knobs (paper §4.3.4 grid-search tables). Each maps to
    // the LW-detector global it calibrates; swept one-at-a-time by run_sensitivity.sh.
    cmd.AddValue ("psi_th",         "composite alert threshold psi_th (Eq 3.21)",        psi_th);
    cmd.AddValue ("kappa_th",       "MP-S3 KL-divergence threshold kappa_th (Eq 3.18)",  kappa_th);
    cmd.AddValue ("delta_th",       "TP-S5 drift threshold delta_th, m (Eq 3.20)",       delta_th);
    cmd.AddValue ("drift_window_k", "TP-S5 drift observation window, beacons",           drift_window_k);
    cmd.AddValue ("k_sybil",        "MP-S1 Sybil density factor K_sybil (Eq 3.8)",       K_sybil);
    cmd.AddValue ("s_max_kmh",      "TP-S1/MP-S4 detection speed bound (km/h); overrides s_max, decoupled from --maxspeed/trace", g_s_max_cli_kmh);
    cmd.AddValue ("lambda", "lambda", lambda);
    cmd.AddValue ("delta_hmac", "H5 Delta_HMAC beacon freshness window (s)", delta_hmac);
    cmd.AddValue ("delta_trs", "H6 Delta_TRS sigma_TRS freshness window (s)", delta_trs);
    cmd.AddValue ("attack_number", "attack_number", attack_number);
    cmd.AddValue ("stealthy_control_plane", "TP-S3/MP-S4 stealthy mode: small plausible controller falsification (beacon detectors blind, CP-DETECT still catches)", stealthy_control_plane);
    cmd.AddValue ("verbose_tx", "verbose per-beacon [DSRC-TX]/[LL-SEL] stdout (off by default; bloats long runs)", g_verbose_tx);
    cmd.AddValue ("experiment_number", "experiment_number", experiment_number);
    cmd.AddValue ("routing_test", "routing_test", routing_test);
    cmd.AddValue ("routing_algorithm", "routing_algorithm", routing_algorithm);
    cmd.AddValue ("qf", "qf", qf);
    cmd.AddValue ("attack_percentage", "attack_percentage", attack_percentage);
    cmd.AddValue ("stealth_fraction",
                  "Exp1 attack intensity gamma: fraction of injected beacons using the "
                  "stealth (low-magnitude) perturbation vs abrupt. {1.0 stealth-only, "
                  "0.70 mixed(default), 0.0 abrupt-only}",
                  stealth_fraction_theta_s);
    cmd.AddValue ("phi_max",
                  "#9 sensitivity: GAT edge heading-divergence bound (radians); two "
                  "vehicles are graph neighbours only if heading diff <= phi_max "
                  "(default pi/2=1.5708)",
                  g_phi_max_graph);
    cmd.AddValue ("fhe_ring_dim",
                  "#12 sensitivity: force FHE ring dimension N (0=auto for L5; "
                  "e.g. 32768 or 65536). Larger N = safer but slower crypto (COO_fhe).",
                  g_fhe_ring_dim);
    cmd.AddValue ("rsu_seed", "RSU compromise random seed (0=random each run)", rsu_seed);
    cmd.AddValue ("seed", "Unified run seed (ns-3 RngRun + attack randomness) for multi-seed mean±std runs", run_seed);
    cmd.AddValue ("sybil_registration_pct",
                  "Attack 3 enhanced mode: % of vehicles pre-registered as Sybil at startup "
                  "(0=original ghost-ID mode, >0=behavioural detection via MP-S3 KL)",
                  sybil_registration_pct);
    cmd.AddValue ("ablation_mode",
                  "Ablation variant: 0=Full, 1=A1 LW-only, 2=A2 GAT-only, 3=A3 AE-only, "
                  "4=A4 no-PQ, 5=A5 no-blockchain, 6=B1 Ghaleb-LTT baseline (default=1)",
                  ablation_mode);
    cmd.AddValue ("ablation_ab",
                  "C10: paper ablation AB1..AB11 (0=off). Full mode minus one mechanism: "
                  "1=rules, 2=HMAC gate, 3=GAT, 4=LSTM-AE, 5=all AI (=mode 1), 6=TRS, "
                  "7=FHE, 8=RSU lifecycle, 9=controller rotation, 10=blockchain (=mode 5), "
                  "11=LKH tree (unicast rekey)",
                  ablation_ab);
    cmd.AddValue ("enable_rule_signatures", "AB1 toggle: 0=disable TP/MP rule scoring", enable_rule_signatures);
    cmd.AddValue ("enable_hmac_gate", "AB2 toggle: 0=disable HMAC+nonce beacon gate", enable_hmac_gate);
    cmd.AddValue ("sybil_gat_evasive",
                  "AB3 Phase 2: 0=legacy a3 (ghosts clustered at one RSU, bypass GAT). "
                  "1=distributed GAT-evasive Sybil (1 ghost/RSU, plausible kinematics, "
                  "de-synced, relational-outlier heading, routed through GAT). Use with "
                  "--honest_mp_s1=1 to isolate GAT's contribution.",
                  g_sybil_gat_evasive);
    cmd.AddValue ("ghost_batch",
                  "Batch all ghosts of one interception into ONE RSU window so the GAT sees the ring (1=on, default 0)",
                  g_ghost_batch);
    cmd.AddValue ("ghost_ae",
                  "Extend LSTM-AE temporal scoring to ghost IDs (vid>=10000) (1=on, default 0)",
                  g_ghost_ae);
    cmd.AddValue ("hmac_fail_closed",
                  "Eq 3.37 fail-closed: reject beacons carrying NO HMAC (1=on, default 0)",
                  g_hmac_fail_closed);
    cmd.AddValue ("identity_binding",
                  "FIX 1: reject vehicle_state writes whose transmitter does not own the claimed ID (1=on)",
                  g_identity_binding);
    cmd.AddValue ("gat_or_path_min_phi",
                  "Minimum fusion phi before the GAT head OR-path may force a detection "
                  "(0.0 = legacy no-floor; 0.5 suppresses the OR-only beacons)",
                  g_gat_or_path_min_phi);
    cmd.AddValue ("pop_anomalous_writes",
                  "Remove a beacon from the vehicle kinematic history if the rule tier judged "
                  "it anomalous, so a forged beacon cannot become the baseline for the victim's "
                  "next honest beacon (1=on, default 0)",
                  g_pop_anomalous_writes);
    cmd.AddValue ("psi_cond_floor",
                  "Floor the attack-conditioned psi at the global-weight psi so k_hat "
                  "misrouting cannot erase rule evidence (1=on, default 0)",
                  g_psi_cond_floor);
    cmd.AddValue ("ring_detect",
                  "Deterministic Sybil-ring geometry test: flag identities sitting on a "
                  "consistent-radius ring about a common centroid, excluding the centroid "
                  "(the victim). RULE-TIER — re-verify ablation ordering (1=on, default 0)",
                  g_ring_detect);
    cmd.AddValue ("per_rsu_vehicle_state",
                  "FIX B: give each RSU its own vehicle_state history so one RSU's forged "
                  "kinematics cannot be read back by another as a clean baseline (1=on, default 0)",
                  g_per_rsu_vehicle_state);
    cmd.AddValue ("honest_mp_s1",
                  "AB3 Phase 1: 0=legacy MP-S1 (default; density OR ghost-ID marker, "
                  "gated on ground-truth poison label). 1=paper-faithful MP-S1 (Eq. mp_s1: "
                  "identity-density check on observable data only, no label leakage).",
                  g_honest_mp_s1);
    cmd.AddValue ("uniform_speed_trace",
                  "AB5/E2: load the uniform-speed trace mobility_<tag>_uniform_<v>.tcl "
                  "(every vType + road edge pinned to v; speedFactor=1, speedDev=0) "
                  "instead of the realistic per-road-limit trace. Default 0.",
                  g_uniform_speed_trace);
    cmd.AddValue ("n_coord",
                  "AB3 sweep: coordinated Sybil identities per compromised RSU "
                  "(paper Fig 3.4 N_ghost; default 4). Use with --attack_number=3 "
                  "(= sir's a4, Sybil-via-compromised-RSU).",
                  g_n_coord);
    cmd.AddValue ("streak_sigma",
                  "E4 TL composite: malicious vehicle injects for sigma consecutive "
                  "beacons then goes honest for sigma beacons, repeating; -1=off "
                  "(continuous injection, default, byte-identical to every prior run).",
                  g_streak_sigma);
    cmd.AddValue ("eps_max",
                  "AB4 sweep: stealth drift bound epsilon_max in m per beacon "
                  "(Eq 3.5; default 0.5, must stay < the s_max*T_b = 3.33 m gate). "
                  "Use with --attack_number=2 (= sir's a1, TP-via-malicious-vehicle).",
                  epsilon_max_stealth);
    cmd.AddValue ("lambda_ae",
                  "AB4: per-run override of the GLOBAL fusion lambda_ae in [0,1] "
                  "(default -1 = use fusion_weights.json unchanged). psi/gat are "
                  "rescaled to 1-lambda_ae keeping their ratio. Needed because the "
                  "deployed lambda_ae=0.3071 caps the AE's vote below phi_th=0.5, so "
                  "on sub-gate stealth drift it cannot move any decision; the "
                  "per-attack lambda_sets don't apply because k_hat is -1 always.",
                  g_lambda_ae_cli);
    cmd.AddValue ("lambda_gat",
                  "AB3: per-run override of the GLOBAL fusion lambda_gat in [0,1] "
                  "(default -1 = use fusion_weights.json unchanged). psi/ae are "
                  "rescaled to 1-lambda_gat keeping their ratio. Needed because the "
                  "deployed lambda_gat=0.1857 caps GAT's vote below phi_th=0.5, so on "
                  "the evasive Sybil (--sybil_gat_evasive, psi/ae~0 by design) GAT "
                  "alone can never move a fused decision no matter how well-calibrated; "
                  "the per-attack lambda_sets don't apply because k_hat is -1 always.",
                  g_lambda_gat_cli);
    cmd.AddValue ("poison_theta",
                  "AB4 sweep: attack deviation scale theta in [0,1] (default 0.5). "
                  "Scales max_position_deviation / max_velocity_deviation in "
                  "PoisonTrajectoryByType(); LOWER = stealthier, so the per-beacon "
                  "psi rules and the spatial GAT stop saturating and the temporal "
                  "LSTM-AE becomes the discriminating tier.",
                  poisoning_intensity_theta);
    cmd.AddValue ("mitm_stealth",
                  "a6 stealth regime: 0=abrupt (default, trips psi speed bound), "
                  "1=kinematically-plausible drift (psi cannot fire; HMAC sole detector)",
                  g_mitm_stealth);
    cmd.AddValue ("faithful_mitm",
                  "a6 model: 0=legacy injection (default, preserves combined-attack results), "
                  "1=faithful in-transit modification (relay to claimed-position RSU + stale victim MAC)",
                  g_faithful_mitm);
    cmd.AddValue ("per_pid_results",
                  "1=isolate the live results dir per PID (analytics/results/<scenario>_pid<PID>/) so "
                  "concurrent sims don't clobber each other's beacon_log.csv; default 0 (shared)",
                  g_per_pid_results);
    cmd.AddValue ("enable_trs", "AB6 toggle: 0=skip TRS sign/verify in crypto pipeline", enable_trs);
    cmd.AddValue ("trs_compromised_f", "AB6 f/n sweep: force F of n ring members compromised (0..n); -1=off", g_trs_compromised_f);
    cmd.AddValue ("enable_fhe", "AB7 toggle: 0=plaintext aggregates (TRS still signs)", enable_fhe);
    cmd.AddValue ("ab7_ring_n", "AB7 x-axis: TRS/FHE signing-ring size n (BFT bound n>=4 at f=1; threshold t held fixed at 3); -1=off, default n=4", g_ab7_ring_n);
    cmd.AddValue ("enable_rsu_lifecycle", "AB8 toggle: 0=RSUs permanently trusted", enable_rsu_lifecycle);
    cmd.AddValue ("enable_sc_trust", "R3 config5: 0=skip vehicle SC-Trust evidence submission/finalize (Eq 3.55/3.56) — vehicle trust never decays off its initial value", enable_sc_trust);
    cmd.AddValue ("enable_sc_revoke", "R3 config5: 0=skip vehicle SC-Revoke vote (Eq 3.58/3.65) — vehicles are never revoked regardless of behaviour", enable_sc_revoke);
    cmd.AddValue ("rsu_malicious_fraction", "AB8 f/n sweep: malicious RSU fraction 0..1 (f/4 ring members ≈ f*16 RSUs), decoupled from attack_percentage; -1=off", g_rsu_malicious_frac);
    cmd.AddValue ("lifecycle_gates_fusion", "AB8 option B: 1=a demoted RSU's psi is discounted in fusion (lets the lifecycle affect MCC/CDER_full); 0=off, default, all other sweeps unaffected", g_lifecycle_gates_fusion);
    cmd.AddValue ("ctrl_compromise_onset", "AB9 x-axis: controller compromise onset as fraction of simTime (0=from first beacon/default, 1=never within run)", g_ctrl_compromise_onset);
    cmd.AddValue ("rsu_trust_quorum", "AB8: override q_i quorum in SCRSUFinalizeEpoch (0=2f+1 default; 2=reachable at 30s, weakens BFT)", g_rsu_trust_quorum);
    cmd.AddValue ("t_window", "AB8: override T_w SC-Revoke witness sliding window seconds (Eq 3.65); -1=off, chaincode keeps 30s default", g_t_window);
    cmd.AddValue ("rsu_t_rev", "AB8: override T_rev consecutive low-trust epoch gate before permanent RSU demotion (default 3; races against T_w quorum-accumulation at short horizons)", g_rsu_t_rev);
    cmd.AddValue ("rsu_trust_alpha", "AB8: override RSU trust EMA smoothing alpha (Eq eq:rsu_trust; default 0.3 -- THIS is the actual CLIENT-demotion gate, tau<tau_min=0.3; T_rev only gates the later revoke escalation)", g_rsu_trust_alpha);
    cmd.AddValue ("demoted_psi_weight", "AB8 option B: multiplier on a demoted RSU's psi in fusion (0=silence, 1=no effect, default 0.5)", g_demoted_psi_weight);
    cmd.AddValue ("enable_ctrl_rotation", "AB9 toggle: 0=single fixed controller", enable_ctrl_rotation);
    cmd.AddValue ("use_lkh_tree", "AB11 toggle: 0=per-member unicast rekey instead of LKH tree", use_lkh_tree);
    cmd.AddValue ("enable_gat",
                  "R7f: force GAT spatial detector on(1)/off(0); -1=follow ablation_mode",
                  g_enable_gat_cli);
    cmd.AddValue ("enable_lstm_ae",
                  "R7f: force LSTM-AE temporal detector on(1)/off(0); -1=follow ablation_mode",
                  g_enable_lstm_ae_cli);
    cmd.AddValue ("cder_credit_cp_detect",
                  "CP-1: credit CP-DETECT in CDER — once flag_c is raised, a malicious "
                  "controller's decisions count as a DETECTED compromise interval rather "
                  "than undetected control error. 0=legacy (default), 1=enabled",
                  g_cder_credit_cp_detect);
    cmd.AddValue ("gat_det_flag_heads",
                  "flag_i^GAT (eq:gat_det_flag) head bitmask: bit k => head k's detection "
                  "verdict is OR-ed into the fusion decision. 0=off (default, legacy). "
                  "46 = heads 1,2,3,5 (excludes head 6, precision 0.52)",
                  g_gat_det_flag_heads);
    cmd.AddValue ("trs_classical",
                  "TRS scheme: 0=PQ Dilithium/ML-DSA-87 (default, paper Eq 3.49, NIST L5), "
                  "1=classical Shamir-Schnorr-P256 ECDSA-class baseline for RQ5 PBPO",
                  g_trs_classical_baseline);
    cmd.AddValue ("skip_blockchain",
                  "R7g.3: skip Hyperledger Fabric + REST API bring-up "
                  "(for training-data sweeps without a working Fabric env); "
                  "default=false",
                  skip_blockchain);
    cmd.AddValue ("tiered_commit",
                  "Tiered blockchain commit (paper §3.5.5): 1=Tier-3 batch anomaly "
                  "evidence (default), 0=per-beacon synchronous submit",
                  g_tiered_commit);
    cmd.AddValue ("t_batch",
                  "Tier-3 batch commit interval seconds (<< T_w); default 10",
                  g_t_batch);
    cmd.AddValue ("n_commit",
                  "Tier-3 batch commit size in evidence entries; default 50",
                  g_n_commit);
    cmd.AddValue ("mobility_source",
                  "Mobility provider: 0=hardcoded 16-veh ConstantVelocity (default, "
                  "fast smoke tests), 1=sumo_trace (Ns2MobilityHelper on .tcl from "
                  "SUMO FCD; paper-conformant), 2=sumo_live (TraCI; reserved)",
                  g_mobility_source);
    cmd.Parse (argc, argv);
    // AB7 ring-size sweep: n=3 violates the BFT bound n>=3f+1=4 at f=1 (paper
    // §4.1.2 AB7). Fail fast rather than silently running an invalid ring.
    if (g_ab7_ring_n != -1 && g_ab7_ring_n < 4) {
        std::cerr << "[ABLATION] invalid --ab7_ring_n=" << g_ab7_ring_n
                  << " (BFT bound requires n>=4 at f=1; -1=off)" << std::endl;
        return 1;
    }
    // Combined-attack mode: --attack_number=0 activates all attack types in one run
    // (sir's ablation/E1–E4 default). Vehicle attacks (a2/a4/a6) are assigned per-node
    // in declare_attackers(); RSU (a1/a3) + controller (a5/a7) layers activate alongside.
    g_combined_attack = (attack_number == 0);
    // AB3 (attack 3 = RSU ghost injection / trajectory poisoning) MUST use the
    // paper-faithful, density-calibrated MP-S1. The legacy MP-S1 path (count>N_v/N_r,
    // ~3) flags ~48% of honest beacons at ghost-inflated RSU cells, burying GAT's
    // signal under false positives. Force the honest path on for attack 3 so the
    // ablation reads GAT's true spatial contribution to the 60m-displaced Sybils.
    // (--honest_mp_s1 still overrides for other attacks.)  (2026-07-24)
    if (attack_number == 3) g_honest_mp_s1 = true;
    // Multi-seed: drive the ns-3 global RNG from --seed so stochastic ns-3 elements
    // (channel, propagation, jitter) vary per seed. The attack-side randomness is
    // additionally mixed with run_seed in 06a_attack_models.h. (2026-07-20)
    ns3::RngSeedManager::SetSeed (1);
    ns3::RngSeedManager::SetRun (run_seed > 0 ? run_seed : 1);
    // --s_max_kmh: detection speed bound, decoupled from --maxspeed (which drives
    // the SUMO trace filename mobility_<tag>_<speed>.tcl). km/h → m/s for TP-S1/MP-S4/MP-S3.
    if (g_s_max_cli_kmh > 0.0) s_max = g_s_max_cli_kmh / 3.6;

    // ── C10: dispatch paper ablation AB1..AB11 onto the fine-grained toggles ──
    // AB variants are "full mode minus one mechanism", so every AB except
    // AB5 (≡ legacy mode 1) and AB10 (≡ legacy mode 5) forces ablation_mode=0.
    if (ablation_ab != 0) {
        ablation_mode = 0;
        switch (ablation_ab) {
            case 1:  enable_rule_signatures = false; break;
            case 2:  enable_hmac_gate       = false; break;
            case 3:  g_enable_gat_cli       = 0;     break;
            case 4:  g_enable_lstm_ae_cli   = 0;     break;
            case 5:  ablation_mode = 1;              break;
            case 6:  enable_trs             = false; break;
            case 7:  enable_fhe             = false; break;
            case 8:  enable_rsu_lifecycle   = false; break;
            case 9:  enable_ctrl_rotation   = false; break;
            case 10: ablation_mode = 5; skip_blockchain = true; break;
            case 11: use_lkh_tree           = false; break;
            default:
                std::cerr << "[ABLATION] invalid --ablation_ab=" << ablation_ab
                          << " (valid 0..11)" << std::endl;
                return 1;
        }
        std::cout << "[ABLATION] Paper variant AB" << ablation_ab << " active" << std::endl;
    }

    // ── Apply ablation mode overrides ─────────────────────────────────────────
    // A4: disable TRS + FHE to measure cryptographic mitigation contribution (RQ5)
    if (ablation_mode == 4) {
        use_pq_crypto = false;
        std::cout << "[ABLATION] Mode A4: PQ crypto (TRS+FHE) DISABLED" << std::endl;
    }
    if (ablation_mode == 5) {
        std::cout << "[ABLATION] Mode A5: Blockchain SC calls DISABLED" << std::endl;
    }

    // ── GUARD: forcing an AI detector ON is incompatible with A1 scoring ─────
    // ablation_mode defaults to 1 (A1 = lightweight), and A1 scores the
    // confusion matrix from the LIGHTWEIGHT tier only. The R7f --enable_gat /
    // --enable_lstm_ae overrides below act on the detector toggles
    // INDEPENDENTLY of ablation_mode, so a run that forces the detectors on
    // while leaving ablation_mode at its default computes a full-mode fusion
    // verdict for every beacon and then never scores it: the printed MCC/FPR
    // come out lightweight-only and IDENTICAL across arms, and CDER_full is
    // -1 (0/0 decisions).
    //
    // The D1/D4/D6 300 s runs of 2026-08-05 were produced exactly this way.
    // Their per-beacon [FUSION-RSU] verdicts did differ by arm (MP-S1 recall
    // 0.19/0.35/0.35), so the ablation ordering was real — but it had to be
    // recomputed by hand from the logs because the simulator's own scored
    // output could not show it. That is a silent failure, and this guard exists
    // so it cannot recur.
    //
    // Promote to A0 (full) and say so loudly. Only A1 is promoted: mode 6 (B1)
    // is a deliberately AI-free baseline, so it warns instead of being
    // rewritten, which would destroy the baseline's meaning.
    if (ablation_mode == 1 &&
        (g_enable_gat_cli > 0 || g_enable_lstm_ae_cli > 0)) {
        std::cout << "[ABLATION][GUARD] --enable_gat/--enable_lstm_ae forced ON "
                     "but ablation_mode=A1 scores the LIGHTWEIGHT tier only "
                     "(MCC/FPR would be LW-only and identical across arms, "
                     "CDER_full=-1). PROMOTING ablation_mode A1 -> A0 (full) so "
                     "the fusion verdict is actually scored."
                  << std::endl;
        ablation_mode = 0;
    } else if (ablation_mode == 6 &&
               (g_enable_gat_cli > 0 || g_enable_lstm_ae_cli > 0)) {
        std::cout << "[ABLATION][GUARD][WARN] ablation_mode=A6 (B1 baseline) is "
                     "AI-free by design, but --enable_gat/--enable_lstm_ae was "
                     "forced ON. NOT promoting: the scored matrix stays "
                     "lightweight. This combination is almost certainly a "
                     "mistake." << std::endl;
    }

    // ── R7f: derive AI-component toggles from ablation_mode (paper §4.1.1) ───
    // Default (CLI not set, cli == -1) follows the ablation table:
    //   A1 → no AI (lightweight only)
    //   A2 → GAT only
    //   A3 → LSTM-AE only
    //   A4/A5/Full → both AI components on
    //   B1 → no AI (LTT baseline doesn't use the MPTD-PQS AI stack)
    bool ab_gat_default = true;
    bool ab_ae_default  = true;
    switch (ablation_mode) {
        case 1: ab_gat_default = false; ab_ae_default = false; break;   // A1
        case 2: ab_gat_default = true;  ab_ae_default = false; break;   // A2
        case 3: ab_gat_default = false; ab_ae_default = true;  break;   // A3
        case 6: ab_gat_default = false; ab_ae_default = false; break;   // B1
        case 7: ab_gat_default = true;  ab_ae_default = false; break;   // B2 standalone GAT (ψ excluded in scoring)
        case 8: ab_gat_default = false; ab_ae_default = true;  break;   // B3 standalone AE  (ψ excluded in scoring)
        case 4: case 5: case 0: default: /* both true */          break;
    }
    g_enable_gat     = (g_enable_gat_cli     >= 0) ? (g_enable_gat_cli     != 0) : ab_gat_default;
    g_enable_lstm_ae = (g_enable_lstm_ae_cli >= 0) ? (g_enable_lstm_ae_cli != 0) : ab_ae_default;
    // Mirror toggles into the fusion parameter block so fuse_scores() can
    // renormalise λ-weights for A2/A3 (R7f, paper Eq 3.46 / §4.1.1).
    g_fusion.use_gat = g_enable_gat;
    g_fusion.use_ae  = g_enable_lstm_ae;
    std::cout << "[ABLATION] Active mode: A" << ablation_mode
              << "  use_pq_crypto=" << (use_pq_crypto ? "YES" : "NO")
              << "  enable_gat="    << (g_enable_gat     ? "YES" : "NO")
              << "  enable_lstm_ae="<< (g_enable_lstm_ae ? "YES" : "NO")
              << std::endl;

    // ── R7d: Initialize ONNX Runtime AI inference engine ──────────────────────
    // Loads GAT + LSTM-AE .onnx models trained by analytics/ml/train.py.
    // R7f: empty path skips loading the corresponding session, so has_gat()
    // / has_lstm_ae() return false and the call sites in 08_detection_engine.h
    // bypass that component. Fusion (06d_ai_inference.h) renormalises the
    // surviving λ weights so Φ_th = 0.5 keeps its meaning across A2/A3/Full.
    {
        std::string scenario_sub = "urban";
        if (mobility_scenario == 1) scenario_sub = "rural";
        else if (mobility_scenario == 2) scenario_sub = "highway";
        // Combined-attack mode (--attack_number=0) uses a SEPARATE calibration
        // (θ_S/θ_ae/fusion_weights re-derived on the heavily-attacked combined graph,
        // where clean beacons sit at higher GAT-S). The single-attack calibration in
        // models/urban/ is left untouched. Only urban has a combined set for now;
        // rural/highway fall through to their standard calibration.
        if (g_combined_attack && mobility_scenario == 0) {
            std::string cdir = std::string(NS3_ROOT) + "/analytics/ml/models/urban_combined/gat_model.onnx";
            std::ifstream ctest(cdir);
            if (ctest.good()) { scenario_sub = "urban_combined";
                std::cout << "[AI-INIT] combined-attack calibration → models/urban_combined/" << std::endl; }
        }
        // AB3 / single-attack a3 (MP-S1 Sybil-via-compromised-RSU): the single-attack
        // θ_S=8.31 in models/urban/ is ~70x too low — clean in-sim S p95≈18, poisoned
        // S≈360-720, so 8.31 saturates the GAT term for 43% of CLEAN beacons → GAT
        // becomes anti-informative (removing it IMPROVES MCC_full). urban_a3/ re-derives
        // θ_S=18.4 (95th pct of clean in-sim S; same method as urban_combined) while
        // symlinking the untouched model. Selected only when attack_number==3 so every
        // other single-attack run is byte-identical.
        else if (attack_number == 3 && mobility_scenario == 0) {
            std::string a3dir = std::string(NS3_ROOT) + "/analytics/ml/models/urban_a3/gat_model.onnx";
            std::ifstream a3test(a3dir);
            if (a3test.good()) { scenario_sub = "urban_a3";
                std::cout << "[AI-INIT] a3 Sybil calibration → models/urban_a3/ (θ_S recalibrated)" << std::endl; }
        }

        // GAT is now per-scenario (Phase-1b clean stats + θ_S re-derived on each
        // scenario's clean SUMO traces — recalibrate_gat_per_scenario.py). The
        // shared urban-only GAT mis-scored fast rural/highway motion (inflated
        // FPR). θ_S auto-loads from the same directory (see below), so pointing
        // gat_path at models/<scenario>/ swaps the threshold too. Fall back to
        // the shared model if a scenario file is absent.
        std::string gat_scen_path = NS3_ROOT "/analytics/ml/models/" + scenario_sub + "/gat_model.onnx";
        {
            std::ifstream gtest(gat_scen_path);
            if (!gtest.good())
                gat_scen_path = NS3_ROOT "/analytics/ml/models/shared/gat_model.onnx";
        }
        const std::string gat_path     = g_enable_gat ? gat_scen_path : std::string();
        const std::string lstm_ae_path = g_enable_lstm_ae
                                         ? NS3_ROOT "/analytics/ml/models/" + scenario_sub + "/lstm_ae_model.onnx"
                                         : std::string();
        const std::string scaler_path  = NS3_ROOT "/analytics/ml/models/" + scenario_sub + "/scaler.json";
        const std::string theta_path   = NS3_ROOT "/analytics/ml/models/" + scenario_sub + "/theta_ae.txt";
        const std::string weights_path = NS3_ROOT "/analytics/ml/models/" + scenario_sub + "/fusion_weights.json";
        // 2026-07-27 fix (urban_a3), extended 2026-08-03 to the shared urban
        // model: scaler.json (shared with the LSTM-AE) was overwritten by the
        // AB4 dead-reckoning-residual fix — incompatible with GAT's absolute-position
        // inputs (measured |z| in the thousands, saturating GAT for clean and poisoned
        // beacons alike). <scenario>/gat_scaler.json, where present, holds the original
        // absolute-position stats (mean/scale ~ pos_x 1755±545 etc.) dedicated to GAT
        // only; the LSTM-AE keeps using scaler_path unaffected. Confirmed live: the
        // shared urban model (a1/a2/a4/a5/a6/a7) showed mean_S~250,000 for BOTH clean
        // and malicious populations before this fix (θ_S=8.305) — same bug as urban_a3
        // had, never previously fixed for the other six attack types. Generalized to
        // check any scenario_sub's own gat_scaler.json; scenarios without one (rural,
        // highway, urban_combined) pass "" and are byte-identical to before.
        std::string gat_scaler_path;
        {
            std::string gspath = NS3_ROOT "/analytics/ml/models/" + scenario_sub + "/gat_scaler.json";
            std::ifstream gstest(gspath);
            if (gstest.good()) gat_scaler_path = gspath;
        }
        const bool ai_ok = g_ai_engine.init(gat_path, lstm_ae_path,
                                            scaler_path, theta_path, weights_path,
                                            gat_scaler_path);
        std::cout << "[AI-INIT] engine ready=" << (ai_ok ? "YES" : "NO")
                  << " gat=" << (g_ai_engine.has_gat() ? "YES" : "NO")
                  << " lstm_ae=" << (g_ai_engine.has_lstm_ae() ? "YES" : "NO")
                  << " theta_ae=" << g_ai_engine.theta_ae() << std::endl;
    }

    if (routing_test == true)
    {
        // Enforce minimum topology for evaluation (can be overridden via --N_Vehicles=N)
        if (N_Vehicles < 16) N_Vehicles = 16;
        if (N_RSUs    <  4) N_RSUs    = 4;
    }

    // Clamp to compile-time array capacities (all modes) — prevents OOB if the
    // CLI passes counts larger than total_size / MAX_RSUS.
    if (N_Vehicles > (uint32_t)total_size) {
        std::cerr << "[CONFIG] N_Vehicles " << N_Vehicles << " > capacity "
                  << total_size << " — clamped.\n";
        N_Vehicles = (uint32_t)total_size;
    }
    if (N_RSUs > MAX_RSUS) {
        std::cerr << "[CONFIG] N_RSUs " << N_RSUs << " > capacity " << MAX_RSUS
                  << " — clamped.\n";
        N_RSUs = MAX_RSUS;
    }
    
    ueBusy.resize(total_size, false);
    ueDLBusy.resize(total_size, false);
	
    
    routing_frequency = data_transmission_frequency;
    N_eNodeBs = 1 + N_Vehicles/320;
    var = N_Vehicles+N_RSUs;
    large=50000;
    optimization_period = 1.0/optimization_frequency;
    data_transmission_period = 1.0/data_transmission_frequency;
    //APB apb(memblock_key);
    //std::cout << a << "+" << b << "=" << apb.Func(a, b) << std::endl;
    //std::cout << a+2 << "+" << b+2 << "=" << apb.Func(a+2, b+2) << std::endl;
    
    //LogComponentEnable ("vanet", LOG_LEVEL_INFO); // removed: component not registered
    LogComponentEnable ("UdpClient", LOG_LEVEL_INFO);
    LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_INFO);
    LogComponentEnable ("PacketSink", LOG_LEVEL_INFO);
    
    clear_RQY();

    for (int i = 0; i < total_size+2; i++)
    {
        clear_data_at_nodes(data_at_nodes_inst+i);
        clear_routing_data_at_nodes(routing_data_at_nodes_inst+i-2);
    }
    clear_delta_at_controller(delta_at_controller_inst);
  
  controller_Node.Create(N_Controllers);
  management_Node.Create(1);
  // R4.b: backup_controller_Node removed. Paper architecture has no backup
  // controller; CP-DETECT (Alg 7, §3.5.5) via RSU consensus replaces it in R6.
  // Cloud/ITS Server (paper Fig 3.9) — placeholder only. Receives σ_TRS-gated
  // FHE-encrypted aggregates from the RSU cluster (invariant #5). R9 wires the
  // real FHE channel; until then this node has no networking and no app.
  cloud_Node.Create(1);
  // R7f.followup-1b (2026-05-29): IMobilityProvider was previously installed
  // ONLY in the routing_test=true branch. The routing_test=false branch (the
  // sweep path) relied on the legacy vehicle_mobility.Install at line ~706,
  // which I removed because it overwrote the provider in routing_test=true.
  // Now both branches use IMobilityProvider directly — single source of truth.
  if (N_Vehicles > 0)
  {
      Vehicle_Nodes.Create(N_Vehicles);
      // R7e.4: record first vehicle NodeID so detectors can convert
      // raw BsmBeaconTag.vehicle_id → local vehicle index for
      // IMobilityProvider::get_gt_position() (Eq.4.6).
      g_first_vehicle_node_id = Vehicle_Nodes.Get(0)->GetId();

      // R7a: vehicle mobility install is delegated to the IMobilityProvider
      // abstraction (see 09b_mobility_provider.h). Selected via
      // --mobility_source CLI arg:
      //   0 (default) = HardcodedMobilityProvider — 16-vehicle ConstantVelocity
      //                 scenario at y≈580 paired with RSUs at y=480 (V2I ≈100m).
      //   1           = FcdTraceMobilityProvider — Ns2MobilityHelper on .tcl
      //                 exported from SUMO via traceExporter.py (paper-conformant).
      std::string trace_path;
      if (g_mobility_source == MOBILITY_SRC_SUMO_TRACE) {
          trace_path = default_sumo_trace_path(mobility_scenario, maxspeed);
          if (trace_path.empty()) {
              std::cerr << "[MOBILITY] no .tcl found for scenario="
                        << mobility_scenario << " speed=" << maxspeed
                        << " km/h — falling back to HARDCODED.\n"
                        << "  To use SUMO traces: generate via\n"
                        << "    sumo --fcd-output fcd.xml && "
                        << "traceExporter.py --fcd-input=fcd.xml "
                        << "--ns2mobility-output=$NS3_ROOT/mobility/"
                        << "mobility_<scenario>_<speed>.tcl\n";
              g_mobility_source = MOBILITY_SRC_HARDCODED;
          }
      }
      // ── Derive the map bounds from the trace (was hardcoded 0..2000) ────────
      // min/max_position_* clamp poisoned coordinates in EnforceRealism() and at
      // the TP-S1/MP-S1 injection sites. They were fixed at a 2000x2000 synthetic
      // map, but every SUMO scenario has its own frame (urban x 664..2663,
      // rural x 2842..5848, autobahn x 2755..3086). A stale bound silently pins
      // out-of-range poisoned beacons to the boundary: it replaces the intended
      // attack with a teleport AND hands the LSTM-AE a frozen (trivially
      // reconstructable) coordinate, inverting its anomaly score. Derive per run
      // so the clamp only rejects genuinely off-map fabrication.
      if (!trace_path.empty()) {
          std::ifstream bfin(trace_path);
          if (bfin.is_open()) {
              double xmn=1e18, xmx=-1e18, ymn=1e18, ymx=-1e18;
              std::string bl;
              while (std::getline(bfin, bl)) {
                  std::size_t sp;
                  if ((sp = bl.find(" set X_ ")) != std::string::npos) {
                      double v = std::atof(bl.c_str() + sp + 8);
                      if (v < xmn) xmn = v;
                      if (v > xmx) xmx = v;
                  } else if ((sp = bl.find(" set Y_ ")) != std::string::npos) {
                      double v = std::atof(bl.c_str() + sp + 8);
                      if (v < ymn) ymn = v;
                      if (v > ymx) ymx = v;
                  } else if ((sp = bl.find("setdest ")) != std::string::npos) {
                      double x = 0.0, y = 0.0, sv = 0.0;
                      if (std::sscanf(bl.c_str() + sp + 8, "%lf %lf %lf", &x, &y, &sv) >= 2) {
                          if (x < xmn) xmn = x;
                          if (x > xmx) xmx = x;
                          if (y < ymn) ymn = y;
                          if (y > ymx) ymx = y;
                      }
                  }
              }
              if (xmn <= xmx && ymn <= ymx) {
                  const double bmargin = 100.0;   // headroom: never bind on sub-gate drift
                  min_position_x = xmn - bmargin;  max_position_x = xmx + bmargin;
                  min_position_y = ymn - bmargin;  max_position_y = ymx + bmargin;
                  std::cout << "[MAP-BOUNDS] derived from trace: x ["
                            << min_position_x << ", " << max_position_x << "]  y ["
                            << min_position_y << ", " << max_position_y
                            << "]  (trace extent x " << xmn << ".." << xmx
                            << "  y " << ymn << ".." << ymx << ")" << std::endl;
              } else {
                  std::cout << "[MAP-BOUNDS] no coordinates parsed from "
                            << trace_path << " — keeping defaults" << std::endl;
              }
          } else {
              std::cout << "[MAP-BOUNDS] cannot open " << trace_path
                        << " — keeping defaults" << std::endl;
          }
      }

      g_mobility_provider = create_mobility_provider(g_mobility_source, trace_path);
      std::cout << "[MOBILITY] provider=" << g_mobility_provider->provider_name()
                << " sumo_derived="
                << (g_mobility_provider->is_sumo_derived() ? "YES" : "NO")
                << "  (TDEE/TPE paper-conformance requires sumo_derived=YES)\n";
      g_mobility_provider->install(Vehicle_Nodes);
  }
  

 
  //Install and configure the RSUs
  if(N_RSUs > 0)
  {
  	RSU_Nodes.Create (N_RSUs);
  	// ── Option B: record first RSU node ID for StartApplication() ──────────────
  	g_first_rsu_node_id = RSU_Nodes.Get(0)->GetId();
  	g_num_active_rsus   = N_RSUs;
  }

  // R4.b: backup_controller_Node creation removed. NodeID layout (current):
  //   nid=0: controller | nid=1: management | nid=2: cloud (Fig 3.9 placeholder)
  //   nid=3..(2+N_Vehicles): vehicles | nid=(3+N_Vehicles)..(2+N_Vehicles+N_RSUs): RSUs
  // (Older `nid - 2 = vehicle_index` convention is OFF-BY-ONE since cloud_Node
  // was added — use g_first_vehicle_node_id for new code, see 04_state_globals.h.)
  // Paper has no backup controller; CP-DETECT via RSU consensus (R6) replaces it.


  //configuring the CSMA interface    
  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", StringValue ("1000Mbps"));
  csma.SetChannelAttribute ("Delay", TimeValue (MicroSeconds (10)));
  // R9: one crypto epoch ships a ~2 MB frame RSU0→Cloud as ~36 UDP chunks
  // (~1500 IP fragments) enqueued at the same sim instant — the default
  // 100-packet DropTail queue would drop most of them. Likewise ARP holds only
  // 3 pending packets while resolving, which silently ate epoch 0's burst.
  csma.SetQueue ("ns3::DropTailQueue<Packet>", "MaxSize", StringValue ("16384p"));
  Config::SetDefault ("ns3::ArpCache::PendingQueueSize", UintegerValue (4096));
  
  NodeContainer csma_nodes;
  Ipv4AddressHelper address;
  Ipv4InterfaceContainer csmaInterfaces;
  NetDeviceContainer csmaDevices;
  InternetStackHelper stack;
  
  if (architecture != 1)
  {
	  csma_nodes.Add(RSU_Nodes);
	  csma_nodes.Add(controller_Node);
	  csma_nodes.Add(management_Node);
	  // R4.b: backup_controller_Node no longer joins the CSMA backhaul.
      csma_nodes.Add(cloud_Node);	  
      // CSMA order: RSU0..RSU(N_RSUs-1), controller, management
	  //   → management index = N_RSUs + 1 (unchanged from prior layout)
	  csmaDevices = csma.Install (csma_nodes);
  	  address.SetBase ("10.1.0.0", "255.255.0.0");   // /16: CSMA backbone must hold up to 256 RSUs + controllers + mgmt (a /24's 254 hosts overflow at N_RSUs=256)
  	  stack.Install (csma_nodes);
  	  csmaInterfaces = address.Assign (csmaDevices);
  	  // ── Option B: management_node is the last entry in csma_nodes ─────────
  	  // Order: RSU0..RSU(N_RSUs-1), controller_0..N_Controllers-1, management
  	  //   → management index = N_RSUs + N_Controllers
  	  g_management_csma_ip = csmaInterfaces.GetAddress(N_RSUs + N_Controllers);
  	  cout << "[OPT-B] management CSMA IP  = " << g_management_csma_ip << endl;
      g_cloud_csma_ip = csmaInterfaces.GetAddress(N_RSUs + N_Controllers + 1);
      cout << "[OPT-B] cloud CSMA IP = " << g_cloud_csma_ip << endl;

  	  // ── Store RSU CSMA IPs for management → RSU downlink (port 8888) ──────────────
  	  // CSMA order: RSU0..RSU(N_RSUs-1), controller, management
  	  // RSU r is at csmaInterfaces index r → IPs 10.1.1.1 .. 10.1.1.4
  	  for (uint32_t r = 0; r < N_RSUs && r < MAX_RSUS; r++) {
  	      g_rsu_csma_ip[r] = csmaInterfaces.GetAddress(r);
  	      cout << "[OPT-B] RSU" << r << " CSMA IP = " << g_rsu_csma_ip[r] << endl;
  	  }
  }
  
  AodvHelper aodv;
  InternetStackHelper stack_AODV;
  stack_AODV.SetRoutingHelper(aodv);
  if (architecture == 1)
  {
  	if (paper == 1)
  	{
  		stack_AODV.Install(RSU_Nodes);
  	}
  	if (paper == 0)
  	{
  		stack.Install(RSU_Nodes);
  	}
  }
  
  //configuring the point to point interfaces
  if (N_RSUs > 0)
  {
	  uint32_t length = (N_RSUs-1)/20;
	  PointToPointHelper p2p_horizontal[N_RSUs-length];
	  NetDeviceContainer p2pdevices_horizontal[N_RSUs-length];
	  Ipv4InterfaceContainer p2p_horizontal_interfaces[N_RSUs-length];
	  
	  
	  uint32_t width;
	  if (N_RSUs >20)
	  {
	  	width = N_RSUs - 20;
	  }
	  else
	  {
	  	width = 0;
	  }
	  PointToPointHelper p2p_vertical[width];
	  NetDeviceContainer p2pdevices_vertical[width];
	  Ipv4InterfaceContainer p2p_vertical_interfaces[width];
	  
	   
	   uint32_t z = 0;
	   for (uint32_t i=0; i<N_RSUs; i++)
	   {
		  uint32_t x = (i+1)%20;
		  if ((x != 0) and (i < (N_RSUs-1)))
		  {
		  	p2p_horizontal[z].SetDeviceAttribute ("DataRate", StringValue ("1000Mbps"));
		  	p2p_horizontal[z].SetChannelAttribute ("Delay", TimeValue (MicroSeconds (10)));
		  	p2pdevices_horizontal[z] = p2p_horizontal[z].Install (RSU_Nodes.Get(i), RSU_Nodes.Get(i+1));
		 	string part1 = "20.1.";
		  	string st = to_string(z);
		  	string part3 = ".0";
		  	string baseaddress = part1 + st + part3;
		  	char const * baseaddress_converted = baseaddress.c_str();
		  	Ipv4AddressHelper address;
		 	address.SetBase (Ipv4Address(baseaddress_converted), "255.255.255.0");
		 	p2p_horizontal_interfaces[z] = address.Assign (p2pdevices_horizontal[z]);
		 	z++;
		 }
		 
		 if (i < width)
		 {
		 	p2p_vertical[i].SetDeviceAttribute ("DataRate", StringValue ("1000Mbps"));
		  	p2p_vertical[i].SetChannelAttribute ("Delay", TimeValue (MicroSeconds (10)));
		  	p2pdevices_vertical[i] = p2p_vertical[i].Install (RSU_Nodes.Get(i), RSU_Nodes.Get(i+20));
		 	string part1 = "30.1.";
		  	string st = to_string(i);
		  	string part3 = ".0";
		  	string baseaddress = part1 + st + part3;
		  	char const * baseaddress_converted = baseaddress.c_str();
		  	Ipv4AddressHelper address;
		 	address.SetBase (Ipv4Address(baseaddress_converted), "255.255.255.0");
		 	p2p_vertical_interfaces[i] = address.Assign (p2pdevices_vertical[i]);
		 }	  
	   }
	   

  }
  
  //installing udp applications in RSUs

  for (uint32_t u=0; u<Vehicle_Nodes.GetN(); u++)
  {
	// Guard: skip if RSU_Nodes doesn't have this index (routing_test=true)
	if (u >= RSU_Nodes.GetN()) { break; }
	Ptr <SimpleUdpApplication> udp_app = Create <SimpleUdpApplication> ();
	RSU_Nodes.Get(u)->AddApplication(udp_app);
	RSU_apps.Add(udp_app);
  }
  RSU_apps.Start(Seconds(0.00));
  RSU_apps.Stop(Seconds(simTime));

  // R9: install the socket app on the Cloud node too
  Ptr <SimpleUdpApplication> cloud_app = Create <SimpleUdpApplication> ();
  cloud_Node.Get(0)->AddApplication(cloud_app);
  cloud_app->SetStartTime(Seconds(0.00));
  cloud_app->SetStopTime(Seconds(simTime));

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
  Config::SetDefault("ns3::Ipv4GlobalRouting::RespondToInterfaceEvents", BooleanValue(true));
  NodeContainer enbnodes;
  NodeContainer remotehostcontainer;
  Ptr<Node> pgw;
  Ptr<PointToPointEpcHelper> epchelper;
  Ptr<Node> remotehost;
  Ptr<LteHelper> ltehelper;
  InternetStackHelper internet;

  if (N_Vehicles > 0)
  {
  	if (architecture != 1)
  	{
		  ltehelper = CreateObject<LteHelper> ();
		  ltehelper->SetAttribute("FadingModel",StringValue("ns3::TraceFadingLossModel"));
		  std::ifstream TraceFile;
		  TraceFile.open(NS3_ROOT "/src/lte/model/fading-traces/fading_trace_EVA_60kmph.fad", std::ifstream::in);
		  if(TraceFile.good())
		  {
		  	ltehelper->SetFadingModelAttribute("TraceFilename", StringValue(NS3_ROOT "/src/lte/model/fading-traces/fading_trace_EVA_60kmph.fad"));
		  }
		  
		  ltehelper->SetFadingModelAttribute("TraceLength",TimeValue(Seconds(10.0)));
		  ltehelper->SetFadingModelAttribute("SamplesNum",UintegerValue(10000));
		  ltehelper->SetFadingModelAttribute("WindowSize",TimeValue(Seconds(0.5)));
		  ltehelper->SetFadingModelAttribute("RbNum",UintegerValue(100));
		  ltehelper->SetEnbDeviceAttribute("DlEarfcn",UintegerValue(100));
		  ltehelper->SetEnbDeviceAttribute("UlEarfcn",UintegerValue(18100));
		  ltehelper->SetSchedulerType("ns3::RrFfMacScheduler");
		  //ltehelper->SetSpectrumChannelAttribute ("Bandwidth", UintegerValue (10000000));
  		  
		  
		  //epc-evolved packet core for LTE
		  epchelper = CreateObject<PointToPointEpcHelper> ();
		  ltehelper->SetEpcHelper(epchelper);
		  pgw = epchelper->GetPgwNode();
		  
		  //creating remote-host
		  remotehostcontainer.Create(1);
		  remotehost = remotehostcontainer.Get(0);
		  internet.Install(remotehostcontainer);
		  
		  Config::SetDefault("ns3::LteHelper::PathlossModel",StringValue("ns3::FriisPropagationLossModel"));
		  //Config::SetDefault("ns3::LteHelper::PathlossModel",StringValue("ns3::Cost231PropagationLossModel"));
		  Config::SetDefault("ns3::LteHelper::UseIdealRrc",BooleanValue(true));
		  Config::SetDefault("ns3::LteHelper::UsePdschForCqiGeneration",BooleanValue(true));
		  Config::SetDefault("ns3::LteSpectrumPhy::CtrlErrorModelEnabled",BooleanValue(true));
		  Config::SetDefault("ns3::LteSpectrumPhy::DataErrorModelEnabled",BooleanValue(true));
		  
		  ltehelper->SetEnbDeviceAttribute("DlBandwidth", UintegerValue(100));
          ltehelper->SetEnbDeviceAttribute("UlBandwidth", UintegerValue(100));
          // Ensure HARQ is enabled
		  //Config::SetDefault ("ns3::LteSpectrumPhy::HarqEnabled", BooleanValue (true));

		  // Use AM bearer (with retransmission)
		   Config::SetDefault ("ns3::LteEnbRrc::EpsBearerToRlcMapping", StringValue ("RlcAmAlways"));

			// Don’t use ideal RRC with EPC
			Config::SetDefault("ns3::LteHelper::UseIdealRrc", BooleanValue(false));

		  Config::SetDefault ("ns3::LteRlcAm::PollRetransmitTimer", TimeValue (MilliSeconds (5)));
		  Config::SetDefault ("ns3::LteRlcAm::ReorderingTimer", TimeValue (MilliSeconds (4)));
		  Config::SetDefault ("ns3::LteRlcAm::StatusProhibitTimer", TimeValue (MilliSeconds (3)));
		  Config::SetDefault ("ns3::LteRlcAm::MaxTxBufferSize", UintegerValue (999999));
		  Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(999999));

		  LogComponentEnable("LteRlc", LOG_LEVEL_INFO);

		  Config::SetDefault("ns3::LteUePhy::TxPower",DoubleValue(33));//maximum ue transmit power of 33 dBm
		  Config::SetDefault("ns3::LteUePhy::EnableUplinkPowerControl",BooleanValue(true));
		  Config::SetDefault("ns3::LteUePowerControl::ClosedLoop",BooleanValue(true));
		  Config::SetDefault("ns3::LteUePowerControl::AccumulationEnabled",BooleanValue(false));
		  //Config::SetDefault ("ns3::LteEnbRrc::EpsBearerToRlcMapping", StringValue ("RlcUmAlways"));
		  //Config::Set ("/NodeList/*/DeviceList/*/LteEnbNetDevice/LteEnbPhy/LteSpectrumPhy/HarqEnabled",BooleanValue (false));

		  
		  /*
		  if ((N_Vehicles+5) < 2)
		  {
		  	Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(2));
		  }
		  else if ((N_Vehicles+5) < 5)
		  {
		  	Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(5));
		  }
		  else if ((N_Vehicles+5) < 10)
		  {
		  	Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(10));
		  }
		    else if ((N_Vehicles+8) < 20)
		  {
		  	Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(20));
		  }
		    else if ((N_Vehicles+20) < 40)
		  {
		  	Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(40));
		  }
		    else if ((N_Vehicles+25) < 80)
		  {
		  	Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(80));
		  }
		    else if ((N_Vehicles+30) < 160)
		  {
		  	Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(160));
		  }
		  else
		  {
		  	Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(320));
		  }
		  */
		  Config::SetDefault("ns3::LteEnbRrc::SrsPeriodicity",UintegerValue(320));
		  
		  Config::SetDefault("ns3::LteAmc::AmcModel", EnumValue(LteAmc::PiroEW2010));
		  Config::SetDefault("ns3::LteAmc::Ber", DoubleValue(0.00005));
		  enbnodes.Create(N_eNodeBs); 
  	}
  	dsrc_Nodes.Add(Vehicle_Nodes);
  }
  if (N_RSUs > 0)
  {
  	dsrc_Nodes.Add(RSU_Nodes);
  }
  
  if (routing_test == false)
  {
  // Vehicle trace selection now lives in default_sumo_trace_path()
  // (09b_mobility_provider.h, used at the IMobilityProvider setup above).
  // The old per-(scenario,maxspeed) switch that filled an unused `trace_file`
  // (its only consumer was a commented-out Ns2MobilityHelper) was dead code
  // and has been removed.
  MobilityHelper vehicle_mobility2;
  vehicle_mobility2.SetMobilityModel ("ns3::ConstantVelocityMobilityModel");
  if (N_Vehicles > 0)
  {
  	
  	if (experiment_number != 5)
  	{
  		//vehicle_mobility.Install(Vehicle_Nodes.Begin(),Vehicle_Nodes.End());
  	}
  	else if (experiment_number == 5)
  	{
  		vehicle_mobility2.SetPositionAllocator ("ns3::GridPositionAllocator","MinX", DoubleValue (0.0),"MinY", DoubleValue (0.0),"DeltaX", DoubleValue (260.0),"DeltaY", DoubleValue (1000),"GridWidth", UintegerValue (2),"LayoutType", StringValue ("RowFirst"));
  		vehicle_mobility2.Install(Vehicle_Nodes);
  		vehicle_mobility2.Install(RSU_Nodes);
  		
  		for (uint32_t i=0; i<Vehicle_Nodes.GetN(); i++)
	  	{
	  		Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (Vehicle_Nodes.Get(i)->GetObject<MobilityModel>());
	  		if (i%2 == 1)
	  		{
	  			mdl->SetVelocity(Vector(1, 0, 0));
	  		}
	  	}
  	}
  }
  }
  
 
  
  int x = ((N_RSUs)/12) + 1;
  double delta_x;
  double delta_y; 
  int lte_base_posx;
  int lte_base_posy;
  int man_base_posx;
  int man_base_posy;
  int con_base_posx;
  int con_base_posy;
  MobilityHelper RSU_mobility;
  RSU_mobility.SetMobilityModel ("ns3::ConstantVelocityMobilityModel");
  MobilityHelper vehicle_mobility;
  vehicle_mobility.SetMobilityModel ("ns3::ConstantVelocityMobilityModel");
  if (mobility_scenario == 0)//urban mobility
  {
  	man_base_posx = 1700;
  	man_base_posy = 1700;
  	con_base_posx = 1600;
  	con_base_posy = 1600;
  	lte_base_posx = 1500;
  	lte_base_posy = 1500;
  	
  	//delta_y = 800/x;
  	delta_y = 400;
  	//delta_x = 1600/5;
  	delta_x = 400;
	  	// R7f.followup-1b (2026-05-29): align urban RSU layout with the
	  	// HardcodedMobilityProvider's expected positions (250/750/1250/1750, y=480),
	  	// matching the routing_test=true branch below. Previous layout placed
	  	// RSUs at y=1200 while vehicles (from IMobilityProvider) live at y≈580
	  	// → 620 m gap, far beyond DSRC range → only ~3 vehicles ever reached
	  	// an RSU and emitted beacons. RSU0=(250,480) RSU1=(750,480)
	  	// RSU2=(1250,480) RSU3=(1750,480), V2I gap ≈ 100 m (urban-realistic).
	  	if (N_RSUs < 13)
	  	{
	  		RSU_mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
	  			"MinX",      DoubleValue (250.0),
	  			"MinY",      DoubleValue (480.0),
	  			"DeltaX",    DoubleValue (500.0),
	  			"DeltaY",    DoubleValue (0.0),
	  			"GridWidth", UintegerValue (4),
	  			"LayoutType",StringValue ("RowFirst"));
	  	}
	  	else
	  	{
	  		RSU_mobility.SetPositionAllocator ("ns3::GridPositionAllocator","MinX", DoubleValue (750.0),"MinY", DoubleValue (900.0),"DeltaX", DoubleValue (delta_x),"DeltaY", DoubleValue (delta_y),"GridWidth", UintegerValue (7),"LayoutType", StringValue ("RowFirst"));
	  	}
  }
  // R7f.followup-1b (2026-05-29): legacy `vehicle_mobility.Install(Vehicle_Nodes)`
  // here was a pre-R7a relic that OVERWROTE the IMobilityProvider's install at
  // line ~231 with a stationary grid layout. Removed so the abstraction works.
  // The companion `vehicle_mobility.Install(RSU_Nodes)` was also wrong — RSU
  // mobility is installed at line ~763 via RSU_mobility. Net effect of removal:
  // (a) HardcodedMobilityProvider's 16-vehicle ±8–11 m/s scenario is preserved;
  // (b) FcdTraceMobilityProvider (--mobility_source=1) drives positions from
  // the SUMO .tcl trace; both paths now satisfy paper Eq 4.5/4.6 GT.
  
 
  
   if (mobility_scenario == 1)//non-urban mobility
  {

  	man_base_posx = 4600;
  	man_base_posy = 4600;
  	con_base_posx = 4700;
  	con_base_posy = 4700;
  	lte_base_posx = 4500;
  	lte_base_posy = 4500;
  	delta_x = 7000/9;
  	delta_y = 6500/(2*x);
  	RSU_mobility.SetPositionAllocator ("ns3::GridPositionAllocator","MinX", DoubleValue (1000.0),"MinY", DoubleValue (2000.0),"DeltaX", DoubleValue (delta_x),"DeltaY", DoubleValue (delta_y),"GridWidth", UintegerValue (10),"LayoutType", StringValue ("RowFirst"));  	
  }
  
  if (mobility_scenario == 2)//autobahn mobility
  {
  	man_base_posx = 2200;
  	man_base_posy = 3700;
  	con_base_posx = 2100;
  	con_base_posy = 3600;
  	lte_base_posx = 2000;
  	lte_base_posy = 3500;
  	delta_x = 4000/9;
  	delta_y = 7500/(2*x);
  	RSU_mobility.SetPositionAllocator ("ns3::GridPositionAllocator","MinX", DoubleValue (0),"MinY", DoubleValue (500),"DeltaX", DoubleValue (delta_x),"DeltaY", DoubleValue (delta_y),"GridWidth", UintegerValue (10),"LayoutType", StringValue ("RowFirst"));  	
  }
  
  if (routing_test == true)//routing_test
  {
    // Layout: road at y=600, RSUs above road at y=300, mgmt/ctrl at top-centre
    man_base_posx = 1000;
    man_base_posy = 50;
    con_base_posx = 850;
    con_base_posy = 50;
    lte_base_posx = 925;
    lte_base_posy = 50;
    // Override urban RSU allocator: 4 RSUs evenly spaced just above the road.
    // Vehicles are at y≈570-610; RSUs at y=480 → ~100 m gap (realistic V2I).
    // RSU0=(250,480) RSU1=(750,480) RSU2=(1250,480) RSU3=(1750,480)
    RSU_mobility.SetPositionAllocator(
      "ns3::GridPositionAllocator",
      "MinX",      DoubleValue(250.0),
      "MinY",      DoubleValue(480.0),
      "DeltaX",    DoubleValue(500.0),
      "DeltaY",    DoubleValue(0.0),
      "GridWidth", UintegerValue(4),
      "LayoutType",StringValue("RowFirst"));
  }
  
  // ── SUMO-trace RSU placement override ───────────────────────────────────
  // The hardcoded grid allocators above are anchored to the legacy small-map
  // coordinates (e.g. urban: 4 RSUs in a line at y=480). When mobility is
  // driven from a SUMO trace the vehicles span that city's full extent, so
  // those fixed RSUs fall outside DSRC range and emit ZERO beacons. Instead we
  // load the realistic, coverage-aware layout produced offline by
  // sumo/place_rsus.py (mobility/rsu_positions_{urban,rural,autobahn}.csv),
  // which places RSUs on real road intersections spread to cover the travelled
  // roads, and put RSU_i at CSV row i. Falls back to the hardcoded grid if the
  // CSV is missing or has fewer rows than N_RSUs, so a stale/absent CSV never
  // crashes the run (it just reverts to the old behaviour with a warning).
  if (g_mobility_source == MOBILITY_SRC_SUMO_TRACE && N_RSUs > 0)
  {
      std::string rsu_csv = default_rsu_positions_path(mobility_scenario);
      std::vector<std::pair<double,double>> rsu_xy = load_rsu_positions(rsu_csv);
      if (rsu_xy.size() >= (size_t)N_RSUs)
      {
          Ptr<ListPositionAllocator> rsuAlloc = CreateObject<ListPositionAllocator>();
          for (uint32_t i = 0; i < (uint32_t)N_RSUs; i++)
              rsuAlloc->Add(Vector(rsu_xy[i].first, rsu_xy[i].second, 0.0));
          RSU_mobility.SetPositionAllocator(rsuAlloc);
          std::cout << "[RSU/PLACEMENT] SUMO-trace mode: placed " << N_RSUs
                    << " RSUs from " << rsu_csv << "\n";
      }
      else
      {
          std::cerr << "[RSU/PLACEMENT] WARNING: need " << N_RSUs
                    << " RSU positions but CSV has " << rsu_xy.size()
                    << " (path='" << rsu_csv << "'). Keeping hardcoded grid — "
                    << "regenerate with: python3 sumo/place_rsus.py --n_rsus "
                    << N_RSUs << " --net sumo/<city>/<city>.net.xml --trace <trace> "
                    << "--out " << (rsu_csv.empty() ? "mobility/rsu_positions_<city>.csv" : rsu_csv) << "\n";
      }
  }

  if (N_RSUs > 0)
  {
  	RSU_mobility.Install(RSU_Nodes);
  	// Sync the detection-engine cell-mapping table to the ACTUAL placed RSU
  	// positions (grid defaults in test net; CSV positions in SUMO-trace mode).
  	for (uint32_t i = 0; i < (uint32_t)N_RSUs && i < RSU_Nodes.GetN(); i++)
  	{
  		Ptr<MobilityModel> mm = RSU_Nodes.Get(i)->GetObject<MobilityModel>();
  		if (mm) { Vector p = mm->GetPosition(); set_rsu_actual_pos(i, p.x, p.y); set_ltt_rsu_pos(i, p.x, p.y); }
  	}
  }

  Ptr <Node> nd;
  NodeContainer other_stationary_LTE_nodes;
  if (N_Vehicles > 0)
  {
  	if (architecture != 1)
  	{
	  nd = ns3::NodeList::GetNode(N_Vehicles+N_RSUs+4);
	  other_stationary_LTE_nodes.Add(enbnodes);
	  other_stationary_LTE_nodes.Add(remotehostcontainer);
	  other_stationary_LTE_nodes.Add(pgw);
	  other_stationary_LTE_nodes.Add(epchelper->GetSgwNode());
	  other_stationary_LTE_nodes.Add(nd);
	}
  }
  
  if (architecture != 1)
  {
  
	  MobilityHelper other_stationary_mobility;
	  other_stationary_mobility.SetMobilityModel ("ns3::ConstantVelocityMobilityModel");
	  other_stationary_mobility.Install(controller_Node);
	  // R4.b: backup_controller_Node mobility removed (node no longer created).
	  other_stationary_mobility.Install(management_Node);
	  // cloud_Node (Fig 3.9 Cloud/ITS Server placeholder) — stationary, off to the
	  // far edge to visually indicate it sits outside both mode boundaries. R9
	  // will install the FHE-encrypted aggregate channel here.
	  other_stationary_mobility.Install(cloud_Node);
	  if (N_Vehicles > 0)
	  {
	  	other_stationary_mobility.Install(other_stationary_LTE_nodes);
	  }
	  
	  //srand(time(0));
	  //int lte_base_posx = rand()%3000;
	  //int lte_base_posy = rand()%3000;
	  
	  if (N_Vehicles > 0)
	  {
		  for (uint32_t i=0; i<other_stationary_LTE_nodes.GetN(); i++)
		  {
		  	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (other_stationary_LTE_nodes.Get(i)->GetObject<MobilityModel>());
		  	mdl->SetPosition(Vector(lte_base_posx+10*i, lte_base_posy+10*i, 0));
		  	mdl->SetVelocity(Vector(0, 0, 0));//other stationary LTE nodes
		  }
	  }
  }
  
  if (N_RSUs > 0)
  {
	  for (uint32_t i=0; i<RSU_Nodes.GetN(); i++)
	  {
	  	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (RSU_Nodes.Get(i)->GetObject<MobilityModel>());
	  	mdl->SetVelocity(Vector(0, 0, 0));//RSUs nodes are stationary. Their position is already defined
	  }
  }
  
  //setting the position of controller node 
  //int con_base_posx = rand()%3000;
  //int con_base_posy = rand()%3000;

   if (architecture != 1)
   {
	   for (uint32_t c = 0; c < N_Controllers; ++c) {
	       Ptr<ConstantVelocityMobilityModel> mdl_controller = DynamicCast <ConstantVelocityMobilityModel> (controller_Node.Get(c)->GetObject<MobilityModel>());
	       mdl_controller->SetPosition(Vector(con_base_posx + c * 50.0, con_base_posy, 0));
	       mdl_controller->SetVelocity(Vector(0, 0, 0));
	   }

	   // R4.b: backup_controller_Node mobility removed (node no longer created).
	   // Paper has no backup; CP-DETECT (Alg 7) provides controller-misbehavior
	   // fallback via RSU peer consensus instead. See invariant #2.

	  //setting the position of management node
	  //int man_base_posx = rand()%3000;
	  //int man_base_posy = ;

	   Ptr<ConstantVelocityMobilityModel> mdl_management = DynamicCast <ConstantVelocityMobilityModel> (management_Node.Get(0)->GetObject<MobilityModel>());
	   mdl_management->SetPosition(Vector(man_base_posx, man_base_posy, 0));
	   mdl_management->SetVelocity(Vector(0, 0, 0));//centralized management server placement

	   // cloud_Node (Fig 3.9 Cloud/ITS Server placeholder): offset from
	   // management by +200 in both axes so it visually sits outside the
	   // controller/management cluster, indicating its "outside both mode
	   // boundaries" position in Fig 3.9. R9 may relocate this once the FHE
	   // backhaul topology is finalised.
	   Ptr<ConstantVelocityMobilityModel> mdl_cloud = DynamicCast <ConstantVelocityMobilityModel> (cloud_Node.Get(0)->GetObject<MobilityModel>());
	   mdl_cloud->SetPosition(Vector(man_base_posx + 200, man_base_posy + 200, 0));
	   mdl_cloud->SetVelocity(Vector(0, 0, 0));// Cloud/ITS Server is stationary
   }
  
  Ipv4StaticRoutingHelper ipv4routinghelper_con;
  if (N_Vehicles > 0)
  {
  	if (architecture != 1)
  	{
		  //point to point connection for pgw and remotehost 
		  PointToPointHelper p2ph;
		  p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("1000Mb/s")));
		  p2ph.SetDeviceAttribute("Mtu", UintegerValue(1500));
		  p2ph.SetChannelAttribute("Delay", TimeValue(MicroSeconds(10)));
		  NetDeviceContainer internetdevices = p2ph.Install(pgw,remotehost);
		  Ipv4AddressHelper ipv4h;
		  ipv4h.SetBase("1.0.0.0","255.0.0.0");
		  Ipv4InterfaceContainer internetipfaces = ipv4h.Assign(internetdevices);
		  //Ipv4Address remoteHostAddr = internetipfaces.GetAddress (1);
		  
		  //point to point connection for controllers
		  PointToPointHelper p2p_controllers;
		  p2p_controllers.SetDeviceAttribute("DataRate", DataRateValue(DataRate("1000Mb/s")));
		  p2p_controllers.SetChannelAttribute("Delay", TimeValue(MicroSeconds(10)));
		  std::vector<Ipv4InterfaceContainer> controller_interfaces(N_Controllers);
		  for (uint32_t c = 0; c < N_Controllers; ++c) {
		      NetDeviceContainer p2pcontroller_devices = p2p_controllers.Install(pgw, controller_Node.Get(c));
		      Ipv4AddressHelper ipv4helper;
		      std::string subnet = "40.1." + std::to_string(c + 1) + ".0";
		      ipv4helper.SetBase(subnet.c_str(), "255.255.255.0");
		      controller_interfaces[c] = ipv4helper.Assign(p2pcontroller_devices);
		  }
		  
		  //point to point connection for management server
		  PointToPointHelper p2p_management;
		  p2p_management.SetDeviceAttribute("DataRate", DataRateValue(DataRate("1000Mb/s")));
		  p2p_management.SetChannelAttribute("Delay", TimeValue(MicroSeconds(10)));
		  NetDeviceContainer p2pmanagement_devices = p2p_management.Install(pgw,management_Node.Get(0));
		  Ipv4AddressHelper ipv4helper2;
		  ipv4helper2.SetBase("80.1.1.0","255.255.255.0");
		  Ipv4InterfaceContainer management_interfaces = ipv4helper2.Assign(p2pmanagement_devices);
		  
		  
		  Ipv4StaticRoutingHelper ipv4routinghelper;
		  Ptr<Ipv4StaticRouting> remotehoststaticrouting = ipv4routinghelper.GetStaticRouting(remotehost->GetObject<Ipv4>());
		  remotehoststaticrouting->AddNetworkRouteTo (Ipv4Address("7.0.0.0"),Ipv4Mask("255.0.0.0"),1);

		  for (uint32_t c = 0; c < N_Controllers; ++c) {
		      Ptr<Ipv4StaticRouting> controller_staticrouting = ipv4routinghelper_con.GetStaticRouting(controller_Node.Get(c)->GetObject<Ipv4>());
		      controller_staticrouting->AddNetworkRouteTo (Ipv4Address("7.0.0.0"),Ipv4Mask("255.0.0.0"),2);
		  }

		  Ipv4StaticRoutingHelper ipv4routinghelper_man;
		  Ptr<Ipv4StaticRouting> management_staticrouting = ipv4routinghelper_man.GetStaticRouting(management_Node.Get(0)->GetObject<Ipv4>());
		  management_staticrouting->AddNetworkRouteTo (Ipv4Address("7.0.0.0"),Ipv4Mask("255.0.0.0"),2);
	}
}

  //broadcast data in RSU nodes
  /*
  for (uint32_t t=0 ; t<simTime-1; t++)
  {
	  for (uint32_t u=0; u<RSU_Nodes.GetN(); u++)
	  {
	  	Ptr <Node> nu = DynamicCast <Node> (RSU_Nodes.Get(u));	
	  	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(u));
		Simulator::Schedule(Seconds(t+1+0.0001*u),p2p_data_broadcast, udp_app, nu);
   	  }
  }
  */
  
  //broadcast metadata in RSU nodes
  /*
  for (uint32_t t=0 ; t<simTime-1; t++)
  {
	  for (uint32_t u=0; u<RSU_Nodes.GetN(); u++)
	  {
	  	Ptr <Node> nu = DynamicCast <Node> (RSU_Nodes.Get(u));	
	  	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(u));
		Simulator::Schedule(Seconds(t+1+0.0001*u),p2p_metadata_broadcast, udp_app, nu);
   	  }
  }
  */
 
  //YansWifiHelper to create WifiNetDevice
  
  switch(qf)
  {
  	//Background
  	case (0):
 
		flow_packet_size = 750;
		CW_min = 15;
		CW_max = 1023;
		SIFS = 12;
		T_slot = 20.0;
		AIFSN = 9;
		B_max = log2(1+(CW_max/CW_min));
		latency_max = 0.100;
		loss_max = 0.001;
		AIFS = SIFS + (AIFSN*T_slot);
  		break;
  	//Best effort	
  	case (1):
  		flow_packet_size = 750;
		CW_min = 15;
		CW_max = 127;
		SIFS = 12;
		T_slot = 20.0;
		AIFSN = 6;
		B_max = log2(1+(CW_max/CW_min));
		latency_max = 0.050;
		loss_max = 0.001;
		AIFS = SIFS + (AIFSN*T_slot);
  		break;
  	//Video
  	case (2):
  		flow_packet_size = 750;
		CW_min = 7;
		CW_max = 31;
		SIFS = 12;
		T_slot = 20.0;
		AIFSN = 3;
		B_max = log2(1+(CW_max/CW_min));
		latency_max = 0.025;
		loss_max = 0.005;
		AIFS = SIFS + (AIFSN*T_slot);
  		break;
  	//Audio
 	case (3):
  		flow_packet_size = 750;
		CW_min = 3;
		CW_max = 7;
		SIFS = 12;
		T_slot = 20.0;
		AIFSN = 2;
		B_max = log2(1+(CW_max/CW_min));
		latency_max = 0.0125;
		loss_max = 0.005;
		AIFS = SIFS + (AIFSN*T_slot);
  		break;
 
 	default:
 		break;
  }
  
  YansWifiChannelHelper channel;
  YansWifiChannelHelper channel_172;
  YansWifiChannelHelper channel_174;
  YansWifiChannelHelper channel_176;
  YansWifiChannelHelper channel_180;
  YansWifiChannelHelper channel_182;
  YansWifiChannelHelper channel_184;
  
  channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");//set propagation delay model as constant speed
  channel_172.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");//set propagation delay model as constant speed
  channel_174.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");//set propagation delay model as constant speed
  channel_176.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");//set propagation delay model as constant speed
  channel_180.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");//set propagation delay model as constant speed
  channel_182.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");//set propagation delay model as constant speed
  channel_184.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");//set propagation delay model as constant speed

  
  if(mobility_scenario == 0)
  {
  	channel.AddPropagationLoss("ns3::Cost231PropagationLossModel");//For urban -v2v
  	channel_172.AddPropagationLoss("ns3::Cost231PropagationLossModel");//For urban -v2v
  	channel_174.AddPropagationLoss("ns3::Cost231PropagationLossModel");//For urban -v2v
  	channel_176.AddPropagationLoss("ns3::Cost231PropagationLossModel");//For urban -v2v
  	channel_180.AddPropagationLoss("ns3::Cost231PropagationLossModel");//For urban -v2v
  	channel_182.AddPropagationLoss("ns3::Cost231PropagationLossModel");//For urban -v2v
  	channel_184.AddPropagationLoss("ns3::Cost231PropagationLossModel");//For urban -v2v
  	//channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	//channel.AddPropagationLoss("ns3::FriisPropagationLossModel");
  }
  if (mobility_scenario == 1)//non-urban / rural mobility → LogDistance
  {
  	// COST231-Hata is urban-only (supervisor 2026-06-15: "cost231 intended only
  	// for urban"). LogDistance (NS-3 default path-loss exponent 3.0) is the
  	// standard suburban/rural model. TxPower stays 41 dBm and the logical comm
  	// range stays R_max_comm = 270 m (02_config_globals.h), so neighbour/LL/
  	// detection gating and the 250 m RSU grid remain comparable across scenarios.
  	// The model only reshapes path loss (SNR/PER realism); it is NOT an RF cutoff
  	// — at 41 dBm with RxSensitivity −105 dBm the physical range is ~2 km, far
  	// beyond the 270 m logical range, so no per-model TxPower re-tune is required.
  	channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_172.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_174.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_176.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_180.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_182.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_184.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  }
  if (mobility_scenario == 2)//open-highway mobility → LogDistance (supervisor 2026-07-02)
  {
  	// CHANGED 2026-07-02 (Nilmantha Sir): TwoRayGround was too ideal for the open
  	// highway. At 41 dBm its low path loss gave a ~2 km *physical* radio range, so
  	// with 200 vehicles over ~6.3 km each PHY node sensed ~145 concurrent
  	// transmitters (vs ~17 in urban/Cost231). That overloaded the ns-3.35 WiFi PHY
  	// into a non-advancing zero-time event loop (simulation froze at t≈13 s).
  	// LogDistance (path-loss exponent 3.0 — the same model rural/scenario-1 uses)
  	// has much higher path loss, shrinking the physical range and the concurrent-
  	// reception load. TxPower stays 41 dBm and R_max_comm stays 270 m (logical
  	// range) so coverage/detection gating stays comparable across scenarios.
  	// Original (kept for provenance): TwoRayGround @ 5.9 GHz, HeightAboveZ = 1.5 m.
  	channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_172.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_174.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_176.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_180.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_182.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  	channel_184.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  }
  
  //Physical layer helper for wave
  YansWifiPhyHelper Phy;
  YansWifiPhyHelper Phy_172;
  YansWifiPhyHelper Phy_174;
  YansWifiPhyHelper Phy_176;
  YansWifiPhyHelper Phy_180;
  YansWifiPhyHelper Phy_182;
  YansWifiPhyHelper Phy_184;
  
  Phy.SetErrorRateModel("ns3::NistErrorRateModel");
  Phy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  Phy.Set("TxPowerLevels", UintegerValue(2));//number of transmission power levels
  Phy_172.SetErrorRateModel("ns3::NistErrorRateModel");
  Phy_172.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  Phy_172.Set("TxPowerLevels", UintegerValue(2));//number of transmission power levels
  Phy_174.SetErrorRateModel("ns3::NistErrorRateModel");
  Phy_174.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  Phy_174.Set("TxPowerLevels", UintegerValue(2));//number of transmission power levels
  Phy_176.SetErrorRateModel("ns3::NistErrorRateModel");
  Phy_176.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  Phy_176.Set("TxPowerLevels", UintegerValue(2));//number of transmission power levels
  Phy_180.SetErrorRateModel("ns3::NistErrorRateModel");
  Phy_180.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  Phy_180.Set("TxPowerLevels", UintegerValue(2));//number of transmission power levels
  Phy_182.SetErrorRateModel("ns3::NistErrorRateModel");
  Phy_182.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  Phy_182.Set("TxPowerLevels", UintegerValue(2));//number of transmission power levels
  Phy_184.SetErrorRateModel("ns3::NistErrorRateModel");
  Phy_184.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
  Phy_184.Set("TxPowerLevels", UintegerValue(2));//number of transmission power levels
  if (mobility_scenario == 0)
  {
  	Phy.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_172.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_172.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_174.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_174.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_176.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_176.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_180.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_180.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_182.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_182.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_184.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_184.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  }
  if (mobility_scenario == 1)
  {
  	Phy.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = non-urban
  	Phy_172.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_172.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_174.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_174.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_176.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_176.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_180.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_180.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_182.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_182.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_184.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_184.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  }
  if (mobility_scenario == 2)
  {
  	Phy.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 44 dBm = highway
  	Phy_172.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_172.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_174.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_174.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_176.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_176.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_180.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_180.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_182.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_182.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  	Phy_184.Set ("TxPowerStart", DoubleValue (41));//TxPowerStart is the minimum power
  	Phy_184.Set ("TxPowerEnd", DoubleValue (41));//TxPowerEnd is the maximum power. 41 dBm = urban
  }
  Phy.Set ("Frequency", UintegerValue(5890));//center frequency
  Phy.Set ("ChannelNumber", UintegerValue(178));//channel number
  Phy_172.Set ("Frequency", UintegerValue(5860));//center frequency
  Phy_172.Set ("ChannelNumber", UintegerValue(172));//channel number
  Phy_174.Set ("Frequency", UintegerValue(5870));//center frequency
  Phy_174.Set ("ChannelNumber", UintegerValue(174));//channel number
  Phy_176.Set ("Frequency", UintegerValue(5880));//center frequency
  Phy_176.Set ("ChannelNumber", UintegerValue(176));//channel number
  Phy_180.Set ("Frequency", UintegerValue(5900));//center frequency
  Phy_180.Set ("ChannelNumber", UintegerValue(180));//channel number
  Phy_182.Set ("Frequency", UintegerValue(5910));//center frequency
  Phy_182.Set ("ChannelNumber", UintegerValue(182));//channel number
  Phy_184.Set ("Frequency", UintegerValue(5920));//center frequency
  Phy_184.Set ("ChannelNumber", UintegerValue(184));//channel number
  
  Phy.Set ("ChannelWidth", UintegerValue(10));//channel width
  //Phy.Set ("Primary20MHzIndex", UintegerValue(3));//0 for least
  Phy.Set ("RxSensitivity", DoubleValue(-105));//
  Phy.Set ("TxGain", DoubleValue(0));//
  Phy.Set ("RxGain", DoubleValue(0));//
  Phy.Set ("RxNoiseFigure", DoubleValue(0));//
  Phy.Set ("Antennas", UintegerValue(1));//
  Phy.Set ("PowerDensityLimit", DoubleValue(100));// 
  Phy.Set ("Slot", ns3::TimeValue(ns3::MicroSeconds(T_slot)));//set slot time
  Phy.Set ("Sifs", ns3::TimeValue(ns3::MicroSeconds(SIFS)));//set SIFS
 
  Phy_172.Set ("ChannelWidth", UintegerValue(10));//channel width
  //Phy_172.Set ("Primary20MHzIndex", UintegerValue(0));//0 for least
  Phy_172.Set ("RxSensitivity", DoubleValue(-105));//
  Phy_172.Set ("TxGain", DoubleValue(0));//
  Phy_172.Set ("RxGain", DoubleValue(0));//
  Phy_172.Set ("RxNoiseFigure", DoubleValue(0));//
  Phy_172.Set ("Antennas", UintegerValue(1));//
  Phy_172.Set ("PowerDensityLimit", DoubleValue(100));// 
  Phy_172.Set ("Slot", ns3::TimeValue(ns3::MicroSeconds(T_slot)));//set slot time
  Phy_172.Set ("Sifs", ns3::TimeValue(ns3::MicroSeconds(SIFS)));//set SIFS
  
  Phy_174.Set ("ChannelWidth", UintegerValue(10));//channel width
  //Phy_174.Set ("Primary20MHzIndex", UintegerValue(1));//0 for least
  Phy_174.Set ("RxSensitivity", DoubleValue(-105));//
  Phy_174.Set ("TxGain", DoubleValue(0));//
  Phy_174.Set ("RxGain", DoubleValue(0));//
  Phy_174.Set ("RxNoiseFigure", DoubleValue(0));//
  Phy_174.Set ("Antennas", UintegerValue(1));//
  Phy_174.Set ("PowerDensityLimit", DoubleValue(100));// 
  Phy_174.Set ("Slot", ns3::TimeValue(ns3::MicroSeconds(T_slot)));//set slot time
  Phy_174.Set ("Sifs", ns3::TimeValue(ns3::MicroSeconds(SIFS)));//set SIFS
 
  Phy_176.Set ("ChannelWidth", UintegerValue(10));//channel width
  //Phy_176.Set ("Primary20MHzIndex", UintegerValue(2));//0 for least
  Phy_176.Set ("RxSensitivity", DoubleValue(-105));//
  Phy_176.Set ("TxGain", DoubleValue(0));//
  Phy_176.Set ("RxGain", DoubleValue(0));//
  Phy_176.Set ("RxNoiseFigure", DoubleValue(0));//
  Phy_176.Set ("Antennas", UintegerValue(1));//
  Phy_176.Set ("PowerDensityLimit", DoubleValue(100));// 
  Phy_176.Set ("Slot", ns3::TimeValue(ns3::MicroSeconds(T_slot)));//set slot time
  Phy_176.Set ("Sifs", ns3::TimeValue(ns3::MicroSeconds(SIFS)));//set SIFS
  
  Phy_180.Set ("ChannelWidth", UintegerValue(10));//channel width
  //Phy_180.Set ("Primary20MHzIndex", UintegerValue(4));//0 for least
  Phy_180.Set ("RxSensitivity", DoubleValue(-105));//
  Phy_180.Set ("TxGain", DoubleValue(0));//
  Phy_180.Set ("RxGain", DoubleValue(0));//
  Phy_180.Set ("RxNoiseFigure", DoubleValue(0));//
  Phy_180.Set ("Antennas", UintegerValue(1));//
  Phy_180.Set ("PowerDensityLimit", DoubleValue(100));// 
  Phy_180.Set ("Slot", ns3::TimeValue(ns3::MicroSeconds(T_slot)));//set slot time
  Phy_180.Set ("Sifs", ns3::TimeValue(ns3::MicroSeconds(SIFS)));//set SIFS
  
  Phy_182.Set ("ChannelWidth", UintegerValue(10));//channel width
  //Phy_182.Set ("Primary20MHzIndex", UintegerValue(5));//0 for least
  Phy_182.Set ("RxSensitivity", DoubleValue(-105));//
  Phy_182.Set ("TxGain", DoubleValue(0));//
  Phy_182.Set ("RxGain", DoubleValue(0));//
  Phy_182.Set ("RxNoiseFigure", DoubleValue(0));//
  Phy_182.Set ("Antennas", UintegerValue(1));//
  Phy_182.Set ("PowerDensityLimit", DoubleValue(100));// 
  Phy_182.Set ("Slot", ns3::TimeValue(ns3::MicroSeconds(T_slot)));//set slot time
  Phy_182.Set ("Sifs", ns3::TimeValue(ns3::MicroSeconds(SIFS)));//set SIFS
  
  Phy_184.Set ("ChannelWidth", UintegerValue(10));//channel width
  //Phy_184.Set ("Primary20MHzIndex", UintegerValue(6));//0 for least
  Phy_184.Set ("RxSensitivity", DoubleValue(-105));//
  Phy_184.Set ("TxGain", DoubleValue(0));//
  Phy_184.Set ("RxGain", DoubleValue(0));//
  Phy_184.Set ("RxNoiseFigure", DoubleValue(0));//
  Phy_184.Set ("Antennas", UintegerValue(1));//
  Phy_184.Set ("PowerDensityLimit", DoubleValue(100));// 
  Phy_184.Set ("Slot", ns3::TimeValue(ns3::MicroSeconds(T_slot)));//set slot time
  Phy_184.Set ("Sifs", ns3::TimeValue(ns3::MicroSeconds(SIFS)));//set SIFS
  
  
  //Phy.Set ("ChannelSettings", StringValue ("{176, 10, BAND_5GHZ, 0}"));
  //Config::SetDefault ("ns3::WifiPhy::ChannelSettings", StringValue ("{176, 10, BAND_5GHZ, 0}"));
  Phy.SetChannel (channel.Create ());
  Phy_172.SetChannel (channel_172.Create ());
  Phy_174.SetChannel (channel_174.Create ());
  Phy_176.SetChannel (channel_176.Create ());
  Phy_180.SetChannel (channel_180.Create ());
  Phy_182.SetChannel (channel_182.Create ());
  Phy_184.SetChannel (channel_184.Create ());
  
  
  //Set the number of power levels.
  
  //Config::Set("/NodeList/*/DeviceList/*/$ns3::WaveNetDevice/PhyEntities/*/TxPowerLevels", ns3::UintegerValue(7)); 

  
  //setting up the MAC layer
  
  Ssid ssid = Ssid ("ns-3-ssid");
  WifiMacHelper Mac;
  Mac.SetType("ns3::AdhocWifiMac","Ssid", SsidValue (ssid),"QosSupported", BooleanValue(true));
  

  WifiHelper wifi;
  wifi.SetStandard (WIFI_STANDARD_80211p);
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
  						"DataMode", StringValue ("OfdmRate12MbpsBW10MHz"),
  						"ControlMode",StringValue ("OfdmRate12MbpsBW10MHz"),
  						"NonUnicastMode", StringValue ("Invalid-WifiMode"),
						"MaxSsrc",UintegerValue(B_max),
						"MaxSlrc",UintegerValue(B_max),
						"RtsCtsThreshold",UintegerValue(1000));
						
  Ssid ssid_172 = Ssid ("ns-3-ssid-172");
  WifiMacHelper Mac_172;
  Mac_172.SetType("ns3::AdhocWifiMac","Ssid", SsidValue (ssid_172),"QosSupported", BooleanValue(true));
  

  WifiHelper wifi_172;
  wifi_172.SetStandard (WIFI_STANDARD_80211p);
  wifi_172.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
  						"DataMode", StringValue ("OfdmRate12MbpsBW5MHz"),
  						"ControlMode",StringValue ("OfdmRate12MbpsBW5MHz"),
  						"NonUnicastMode", StringValue ("Invalid-WifiMode"),
						"MaxSsrc",UintegerValue(B_max),
						"MaxSlrc",UintegerValue(B_max),
						"RtsCtsThreshold",UintegerValue(1000));
						
  Ssid ssid_174 = Ssid ("ns-3-ssid-174");
  WifiMacHelper Mac_174;
  Mac_174.SetType("ns3::AdhocWifiMac","Ssid", SsidValue (ssid_174),"QosSupported", BooleanValue(true));
  

  WifiHelper wifi_174;
  wifi_174.SetStandard (WIFI_STANDARD_80211p);
  wifi_174.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
  						"DataMode", StringValue ("OfdmRate12MbpsBW10MHz"),
  						"ControlMode",StringValue ("OfdmRate12MbpsBW10MHz"),
  						"NonUnicastMode", StringValue ("Invalid-WifiMode"),
						"MaxSsrc",UintegerValue(B_max),
						"MaxSlrc",UintegerValue(B_max),
						"RtsCtsThreshold",UintegerValue(1000));
 
  Ssid ssid_176 = Ssid ("ns-3-ssid-176");
  WifiMacHelper Mac_176;
  Mac_176.SetType("ns3::AdhocWifiMac","Ssid", SsidValue (ssid_176),"QosSupported", BooleanValue(true));
  

  WifiHelper wifi_176;
  wifi_176.SetStandard (WIFI_STANDARD_80211p);
  wifi_176.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
  						"DataMode", StringValue ("OfdmRate12MbpsBW10MHz"),
  						"ControlMode",StringValue ("OfdmRate12MbpsBW10MHz"),
  						"NonUnicastMode", StringValue ("Invalid-WifiMode"),
						"MaxSsrc",UintegerValue(B_max),
						"MaxSlrc",UintegerValue(B_max),
						"RtsCtsThreshold",UintegerValue(1000));

  Ssid ssid_180 = Ssid ("ns-3-ssid-180");
  WifiMacHelper Mac_180;
  Mac_180.SetType("ns3::AdhocWifiMac","Ssid", SsidValue (ssid_180),"QosSupported", BooleanValue(true));
  

  WifiHelper wifi_180;
  wifi_180.SetStandard (WIFI_STANDARD_80211p);
  wifi_180.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
  						"DataMode", StringValue ("OfdmRate12MbpsBW10MHz"),
  						"ControlMode",StringValue ("OfdmRate12MbpsBW10MHz"),
  						"NonUnicastMode", StringValue ("Invalid-WifiMode"),
						"MaxSsrc",UintegerValue(B_max),
						"MaxSlrc",UintegerValue(B_max),
						"RtsCtsThreshold",UintegerValue(1000));
  
  Ssid ssid_182 = Ssid ("ns-3-ssid-182");
  WifiMacHelper Mac_182;
  Mac_182.SetType("ns3::AdhocWifiMac","Ssid", SsidValue (ssid_182),"QosSupported", BooleanValue(true));
  

  WifiHelper wifi_182;
  wifi_182.SetStandard (WIFI_STANDARD_80211p);
  wifi_182.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
  						"DataMode", StringValue ("OfdmRate12MbpsBW10MHz"),
  						"ControlMode",StringValue ("OfdmRate12MbpsBW10MHz"),
  						"NonUnicastMode", StringValue ("Invalid-WifiMode"),
						"MaxSsrc",UintegerValue(B_max),
						"MaxSlrc",UintegerValue(B_max),
						"RtsCtsThreshold",UintegerValue(1000));

  Ssid ssid_184 = Ssid ("ns-3-ssid-184");
  WifiMacHelper Mac_184;
  Mac_184.SetType("ns3::AdhocWifiMac","Ssid", SsidValue (ssid_184),"QosSupported", BooleanValue(true));
  

  WifiHelper wifi_184;
  wifi_184.SetStandard (WIFI_STANDARD_80211p);
  wifi_184.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
  						"DataMode", StringValue ("OfdmRate12MbpsBW10MHz"),
  						"ControlMode",StringValue ("OfdmRate12MbpsBW10MHz"),
  						"NonUnicastMode", StringValue ("Invalid-WifiMode"),
						"MaxSsrc",UintegerValue(B_max),
						"MaxSlrc",UintegerValue(B_max),
						"RtsCtsThreshold",UintegerValue(1000));
						

  //MaxSsrc - maximum retransmission for packets lower than RTSCTS threshold.
  //MaxSlrc - maximum retransmissions for packets larger than RTSCTS threshold.
  
 
 
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::AdhocWifiMac/DcaTxop/Queue/Mode",EnumValue(1000000*qf));
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::AdhocWifiMac/DcaTxop/Queue/MaxPackets",UintegerValue(50000));
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::AdhocWifiMac/DcaTxop/Queue/MaxBytes",UintegerValue(5000000));
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::AdhocWifiMac/DcaTxop/Queue/MaxDelay",TimeValue(MilliSeconds(500000)));
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::AdhocWifiMac/DcaTxop/MinCw",UintegerValue(CW_min));//set minimum contention window
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::AdhocWifiMac/DcaTxop/MaxCw",UintegerValue(CW_max));//set maximum contention window
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::AdhocWifiMac/DcaTxop/Aifsn",UintegerValue(AIFSN));//set AIFSN
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::AdhocWifiMac/DcaTxop/TxopLimit",TimeValue(NanoSeconds(5000000)));
  Config::SetDefault ("ns3::WifiMacQueue::MaxSize", QueueSizeValue (QueueSize ("10000p")));
  Config::SetDefault ("ns3::WifiMacQueue::MaxDelay", TimeValue (Seconds (100)));
  //Config::SetDefault("ns3::QueueBase::MaxPackets", UintegerValue(1000));
  //Config::SetDefault("ns3::QueueBase::MaxBytes", UintegerValue(1 << 20)); // 1 MB

  
  //Mac.SetAifs(ns3::UintegerValue(AIFS));//set AIFS
 
  wifidevices = wifi.Install (Phy, Mac, dsrc_Nodes);
  wifidevices_172 = wifi_172.Install (Phy_172, Mac_172, dsrc_Nodes);
  wifidevices_174 = wifi_174.Install (Phy_174, Mac_174, dsrc_Nodes);
  wifidevices_176 = wifi_176.Install (Phy_176, Mac_176, dsrc_Nodes);
  wifidevices_180 = wifi_180.Install (Phy_180, Mac_180, dsrc_Nodes);
  wifidevices_182 = wifi_182.Install (Phy_182, Mac_182, dsrc_Nodes);
  wifidevices_184 = wifi_184.Install (Phy_184, Mac_184, dsrc_Nodes);
  
  NetDeviceContainer enbdevices;
  NetDeviceContainer uedevices;
  NodeContainer LTE_Nodes;
  LTE_Nodes.Add(controller_Node);
  LTE_Nodes.Add(management_Node);
  
  if (N_Vehicles >0)
  {
  	if (architecture != 1)
  	{
	  	  enbdevices = ltehelper->InstallEnbDevice(enbnodes);
		  uedevices = ltehelper->InstallUeDevice(Vehicle_Nodes);
		  
		  
		  
	  	  internet.Install(Vehicle_Nodes);
	  	  Ipv4InterfaceContainer ueIpinterface;
	  	  ueIpinterface = epchelper->AssignUeIpv4Address(uedevices);

	  	  //Assign default gateway of the UEs, attach ues to enodebs.
		  for(uint32_t i=0; i<uedevices.GetN();i++)
		  {
		  	Ptr <Node> uenode = Vehicle_Nodes.Get(i);
		  	Ptr <Ipv4StaticRouting> ueStaticRouting = ipv4routinghelper_con.GetStaticRouting(uenode->GetObject<Ipv4>());//get the ip
		  	ueStaticRouting->SetDefaultRoute (epchelper->GetUeDefaultGatewayAddress(),1);  	
		  	uint32_t x = N_Vehicles/N_eNodeBs;
		  	uint32_t index = i/x;
		  	ltehelper->Attach (uedevices.Get(i), enbdevices.Get(index));
		  }
		  //tft stands for traffic flow template
		  Ptr <EpcTft> tft = Create <EpcTft> ();
		  EpcTft::PacketFilter pf;
		  pf.localPortStart =1234;
		  pf.localPortEnd = 1234;
		  tft->Add(pf);
		  ltehelper->ActivateDedicatedEpsBearer(uedevices, EpsBearer(EpsBearer::NGBR_VIDEO_TCP_DEFAULT), tft); 
	  	  //Install UDP applications in the  controller, management node, vehicular nodes,
	  	  LTE_Nodes.Add(Vehicle_Nodes);
		  
		  //uint16_t protocolip = 0x86DD;//ethertype for Ipv4 is set here.
		  
		  ltehelper->EnablePhyTraces();
		  ltehelper->EnableMacTraces();
		  ltehelper->EnableRlcTraces();
		  
		  //Phy.EnablePcap ("WaveTest", wifidevices);
	}
	if (architecture == 1)
	{
		if (paper == 1)
		{
			stack_AODV.Install(Vehicle_Nodes);
		}
		if (paper == 0)
		{
			stack.Install(Vehicle_Nodes);
		}
	}
}

  Ipv4AddressHelper address_dsrc;
  Ipv4AddressHelper address_dsrc_172;
  Ipv4AddressHelper address_dsrc_174;
  Ipv4AddressHelper address_dsrc_176;
  Ipv4AddressHelper address_dsrc_180;
  Ipv4AddressHelper address_dsrc_182;
  Ipv4AddressHelper address_dsrc_184;
 
  Ipv4InterfaceContainer dsrc_interfaces;
  Ipv4InterfaceContainer dsrc_interfaces_172;
  Ipv4InterfaceContainer dsrc_interfaces_174;
  Ipv4InterfaceContainer dsrc_interfaces_176;
  Ipv4InterfaceContainer dsrc_interfaces_180;
  Ipv4InterfaceContainer dsrc_interfaces_182;
  Ipv4InterfaceContainer dsrc_interfaces_184;
  address_dsrc.SetBase ("3.0.0.0", "255.0.0.0");
  dsrc_interfaces = address_dsrc.Assign (wifidevices);
  // ── Option B: record RSU DSRC IPs for vehicle → RSU unicast ─────────────────
  // dsrc_Nodes order: Vehicle_Nodes(0..N_Vehicles-1), RSU_Nodes(0..N_RSUs-1)
  // So RSU r's DSRC IP is at dsrc_interfaces index (N_Vehicles + r).
  if (N_RSUs > 0) {
      for (uint32_t r = 0; r < N_RSUs && r < MAX_RSUS; r++) {
          g_rsu_dsrc_ip[r] = dsrc_interfaces.GetAddress(N_Vehicles + r);
          cout << "[OPT-B] RSU" << r << " DSRC IP = " << g_rsu_dsrc_ip[r] << endl;
      }
      g_option_b_active = true;  // all Option B globals are now set
      cout << "[OPT-B] DSRC-RSU relay ACTIVE (routing_test=" << routing_test << ")" << endl;
  }

  // ── FIX 1: bind each vehicle ID to its TRUE physical DSRC address ───────────
  // Same container order as above: vehicle v's DSRC interface is index v. This
  // is the registry-derived ground truth used by handle_readone to reject
  // vehicle_state writes from a transmitter that does not own the claimed ID.
  // Keyed by NS-3 NODE ID, which is exactly what a vehicle writes into the beacon
  // (09_vehicle_beacon_tx.h:249, tag.SetVehicleId(nid) with nid = node->GetId()).
  // Do NOT key this by any assumed offset: an earlier revision indexed via
  // lkh_veh_idx() and was systematically 3 entries off, which rejected GENUINE
  // beacons — every rejection showed owner == claimed + 3, a constant that no
  // attack could produce (victim selection is a per-attacker std::shuffle).
  //
  // CORRECTED LOOKUP. Two earlier revisions inferred the DSRC interface index
  // from the node ID (`GetAddress(v)` with v from container order, and via
  // lkh_veh_idx()). Both were wrong: instrumentation showed checked=3912
  // rejected=3912 — EVERY beacon failed, honest ones included — because the
  // observed source address is 3.0.0.(vid-8) while those maps produced
  // 3.0.0.(vid-5). The index inference does not hold.
  //
  // We therefore read each vehicle's address from its OWN node object and take
  // whichever interface carries the DSRC subnet (3.x). No offset arithmetic, so
  // no assumption to get wrong.
  {
      uint32_t bound = 0, skipped = 0;
      for (uint32_t v = 0; v < Vehicle_Nodes.GetN(); v++) {
          Ptr<Node> nd = Vehicle_Nodes.Get(v);
          uint32_t node_id = nd->GetId();
          if (node_id >= (uint32_t)(total_size + 2)) { skipped++; continue; }
          Ptr<Ipv4> ip4 = nd->GetObject<Ipv4>();
          if (!ip4) { skipped++; continue; }
          bool found = false;
          for (uint32_t ifc = 0; ifc < ip4->GetNInterfaces() && !found; ifc++) {
              for (uint32_t ad = 0; ad < ip4->GetNAddresses(ifc) && !found; ad++) {
                  Ipv4Address a = ip4->GetAddress(ifc, ad).GetLocal();
                  // DSRC subnet is 3.0.0.0/8 (address_dsrc.SetBase above).
                  if ((a.Get() >> 24) == 3u) {
                      g_vehicle_owner_ip[node_id]       = a;
                      g_vehicle_owner_ip_known[node_id] = true;
                      bound++; found = true;
                  }
              }
          }
          if (!found) skipped++;
      }
      cout << "[FIX1-IDBIND] bound " << bound << " vehicle node-IDs from their OWN Ipv4 objects"
           << " (skipped=" << skipped << ")";
      if (Vehicle_Nodes.GetN()) {
          uint32_t n0 = Vehicle_Nodes.Get(0)->GetId();
          cout << "  node" << n0 << " -> "
               << (g_vehicle_owner_ip_known[n0] ? g_vehicle_owner_ip[n0] : Ipv4Address());
      }
      cout << endl;
  }
  address_dsrc_172.SetBase ("4.0.0.0", "255.0.0.0");
  dsrc_interfaces_172 = address_dsrc_172.Assign (wifidevices_172);
  address_dsrc_174.SetBase ("5.0.0.0", "255.0.0.0");
  dsrc_interfaces_174 = address_dsrc_174.Assign (wifidevices_174);
  address_dsrc_176.SetBase ("6.0.0.0", "255.0.0.0");
  dsrc_interfaces_176 = address_dsrc_176.Assign (wifidevices_176);
  address_dsrc_180.SetBase ("11.0.0.0", "255.0.0.0");
  dsrc_interfaces_180 = address_dsrc_180.Assign (wifidevices_180);
  address_dsrc_182.SetBase ("8.0.0.0", "255.0.0.0");
  dsrc_interfaces_182 = address_dsrc_182.Assign (wifidevices_182);
  address_dsrc_184.SetBase ("9.0.0.0", "255.0.0.0");
  dsrc_interfaces_184 = address_dsrc_184.Assign (wifidevices_184);
 
 reset_LLDP_counters();
 Simulator::Schedule(Seconds(0.90), connect_to_uplink);
 Simulator::Schedule(Seconds(0.90), connect_to_uplink_RSU);
 Simulator::Schedule(Seconds(0.90), connect_to_downlink);
 Simulator::Schedule(Seconds(0.90), connect_to_downlink_RSU);
 
uint32_t ue0_index = 0;                   // Node index of UE0
uint32_t dest_index = 0;                  // Controller node index
uint32_t port_id   = 7777;                // Or whichever port you use for uplink
Ptr<Packet> testPkt = Create<Packet>(100); // 100-byte test packet


Simulator::Schedule(Seconds(0.93), &send_LTE_LLDP_packetin_uplink_alone,
                    ue0_index,
                    dest_index,
                    port_id,
                    testPkt);
                    
Simulator::Schedule(Seconds(0.95), &send_Ethernet_LLDP_packetin_uplink_alone,
                    ue0_index,
                    dest_index,
                    port_id,
                    testPkt);
                    
                   
Simulator::Schedule(Seconds(0.97), &Trysend_Ethernet_LLDP_packetout_downlink_alone,
                    ue0_index,
                    dest_index,
                    port_id,
                    testPkt);
                    
Simulator::Schedule(Seconds(1.0), &Trysend_LTE_LLDP_packetout_downlink_alone,
                    ue0_index,
                    dest_index,
                    port_id,
                    testPkt);
                    
                    
cout<<"Routing algorithm is "<<routing_algorithm<<"experiment number is "<<experiment_number<<"attack number is "<<attack_number<<"attack percentage is"<<attack_percentage<<endl;
 
 if (architecture != 1)
 {
	 for (uint32_t u=0; u<LTE_Nodes.GetN(); u++)
	 {
	  	Ptr <SimpleUdpApplication> udp_app = Create <SimpleUdpApplication> ();
		LTE_Nodes.Get(u)->AddApplication(udp_app);
		apps.Add(udp_app);
	 }
	 apps.Start(Seconds(0.00));
	 apps.Stop(Seconds(simTime)); 
 }
 
 if (architecture == 1)
 {
	 for (uint32_t u=0; u<Vehicle_Nodes.GetN(); u++)
	 {
	  	Ptr <SimpleUdpApplication> udp_app = Create <SimpleUdpApplication> ();
		Vehicle_Nodes.Get(u)->AddApplication(udp_app);
		apps.Add(udp_app);
	 }
	 apps.Start(Seconds(0.00));
	 apps.Stop(Seconds(simTime)); 
 }

 if (architecture == 0)//centralized architecture
 { 
		Simulator::Schedule(Seconds(0.0), update_mobility);
///*
	  //unicast its own data packets to management node from vehicles.
	    for (uint32_t i=0;i<total_size;i++)
		{
			uplink_last[i] = 0.0;
			last_downlink[i] = 0.0;
		}
        
	 
	  	//Set initial true location
	  	 for (uint32_t i=0; i<Vehicle_Nodes.GetN() ; i++) // Guard: only iterate over vehicle nodes
		 {     
				 Ptr <Node> node_copy = DynamicCast <Node> (Vehicle_Nodes.Get(i));
				 Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node_copy->GetObject<MobilityModel>());
				 Vector posi = mdl->GetPosition();
				 Simulator::Schedule (Seconds(1.0), set_last_true_location_and_timestamp, i, posi);
		 }
//*/	  	
		for (double t=6.70; t<simTime-1; t=t+data_transmission_period)//All official data transmissions begin at t=0
		{	
			//Go over all the wifi devices
			//if (routing_algorithm != 5)
	  		//{   
	  		      
///*			  
				  //if(routing_algorithm == 4)
				  //{
					  for (uint32_t i=0; i<wifidevices.GetN() ; i++)
					  {
						if (i >= dsrc_Nodes.GetN()) { continue; }
						if (i < N_Vehicles) { // Only vehicle nodes broadcast location; RSUs do not
						     Simulator::Schedule (Seconds(t-0.0001), setting_last_true_location_and_timestamp, i);
						}
					  }
			      //}
				  Simulator::Schedule (Seconds (t), set_dsrc_initial_timestamp);
				  if(routing_algorithm == 4)
				  {
					Simulator::Schedule(Seconds(t+0.25), verify_location);
				  }
				  Simulator::Schedule(Seconds(t-0.002), update_mobility);
				  
//*/
			//}
			  
		}		
///*		
		
	  	for (double t=6.707 ; t<simTime-1; t=t+data_transmission_period)
	  	{
			  for (uint32_t u=0; u<Vehicle_Nodes.GetN(); u++) //RSU_Nodes.GetN()
			  {
					Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(u+2));
					Simulator::Schedule(Seconds(t+0.000025*u),send_LTE_data_alone,udp_app,Vehicle_Nodes.Get(u),management_Node.Get(0), u);	//send_RSU_data_alone
			  }
			  Simulator::Schedule (Seconds (t), set_lte_initial_timestamp);	  
	  	}
  
//*/	  	
	  	/*
	  	//unicast data from RSU nodes alone to management server
	  	if (N_RSUs > 0)
	  	{
			for (double t=6.707 ; t<simTime-1; t=t+data_transmission_period)
			{
				  //if (routing_algorithm != 5)
	  			  //{
					  for (uint32_t u=0; u<RSU_Nodes.GetN(); u++)
					  {
					  	Ptr <Node> nu = DynamicCast <Node> (RSU_Nodes.Get(u));	
					  	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(u));
						Simulator::Schedule(Seconds(t+0.000050*u),RSU_dataunicast_alone, udp_app, nu, management_Node.Get(0));
				   	  }
				   	  Simulator::Schedule (Seconds (t), set_ethernet_initial_timestamp);
				  //}
			   	  
			 }
		 }
		 */
		 
	  
	  //else
	  //{
///*
	  	if (experiment_number != 5)
	  	{			
		  	//DSRC flow instantiation
		  	
		  	double t0 = 6.000;
		  	cout<<t0<<endl;			
		       //unicast metadata from RSU nodes to management server - only in the first data cycle
			declare_pre_registered_sybils(); // Attack 3 enhanced: pre-register Sybil in pool
			declare_attack_states();
			declare_attackers();
			declare_compromised_rsus(); // TP-S1, MP-S1: set which RSUs are compromised

			// R6.5: initialize TRS (OpenSSL EC P-256) + FHE (OpenFHE BFV)
			// backends BEFORE any sim event runs. CP-DETECT depends on
			// g_trs_backend being non-null when σ_TRS verify is invoked.
			initialize_crypto_backends();

			double t_assign = t0 + 0.001 * (time(NULL) % 1000);
			Simulator::Schedule(Seconds(t_assign), assign_controllers);
			test_boolean();			
			
			if(routing_algorithm == 4)
			{
				if (skip_blockchain) {
					std::cout << "[BLOCKCHAIN] skip_blockchain=true — Fabric init bypassed "
					             "(R7g.3 training-sweep mode). Detection + CSV logging "
					             "still active." << std::endl;
				} else {
					initialize_blockchain();
				}
			}
			
			//Simulator::Schedule (Seconds (7.400), reset_packet_timestamps);
			//Simulator::Schedule(Seconds(7.400),generate_F_and_E);
			
			Simulator::Schedule(Seconds(0.0010),generate_F_and_E);
//*/
///*			
			if (N_Vehicles > 0)
			{
	
			  	for (double t=t0+1.000 ; t<simTime-1; t=t+data_transmission_period)
			  	{	
			  		  Simulator::Schedule(Seconds(t),clear_delta_at_nodes, delta_at_nodes_inst);
			  		  
//*/			  		  
			  		  // ── Vehicle beacon transmission (MPTD-PQS §3.4) ──────────────────────
					  for (uint32_t u=0; u<Vehicle_Nodes.GetN(); u++)
					  {
					  	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(u+2));
						// Stagger = T_b/N per vehicle (≈6.25ms for 16 vehicles), so MP-S2 tau_sync=1ms
							// does not fire on normal beacons (honest vehicles 6.25ms apart >> 1ms threshold).
							double stagger = T_b / (double)Vehicle_Nodes.GetN();
							Simulator::Schedule(Seconds(t + stagger * u),send_lte_dataunicast_alone,udp_app,Vehicle_Nodes.Get(u),management_Node.Get(0), u);
					  }
					  //calculate the routing solution
					  //unicast the solution back to nodes
					  
///*					  
				  if (!routing_test) { // Skip link-discovery/LLDP/crypto when routing_test=true
				      Simulator::Schedule(Seconds(t), generate_F_and_E);
					  Simulator::Schedule(Seconds(t+0.034500),run_optimization_link_lifetime);
					  Simulator::Schedule(Seconds(t+0.034800),update_flows);
					  
					  Simulator::Schedule(Seconds(t+0.034900+(2*(flows+1)*0.000050)),filter_flows);
					  Simulator::Schedule(Seconds(t+0.034900), reset_LLDP_received_count);
///*					  
					  switch(routing_algorithm)
				   	  {
				   	  	//port-based
				   	  	case (0):
				   	  		Simulator::Schedule(Seconds(t+0.035900),run_port_based);
				   	  		break;
				   	  	//normal_LLDP
				   	  	case (1):
				   	  		Simulator::Schedule(Seconds(t+0.035900),run_normal_LLDP);
				   	  		break;
				   	  	//Pure-crypto
				   	  	case (2):
				   	  		Simulator::Schedule(Seconds(t+0.035900),run_pure_crypto);
				   	  		break;
				   	  	//Link guard.
				   	 	case (3):
				   	  		Simulator::Schedule(Seconds(t+0.035900),run_link_guard);
				   	  		break;
				   	  	//proposed
				   	  	case (4):
				   	  		Simulator::Schedule(Seconds(t+0.035900),run_proposed_LLDP);
				   	  		break;
				   	  	//HELLO packets
				   	  	case (5):
				   	  		Simulator::Schedule(Seconds(t+0.035900),run_HELLO);
				   	  		break;
					 	default:
					 		break;
					  }
					 
					  if(routing_algorithm != 5)
					  {
					  	Simulator::Schedule(Seconds(t+0.036000),transmit_delta_values);
					  }

					  //Simulator::Schedule(Seconds(t+0.099500),initialize_flow_counters);
					  //Simulator::Schedule(Seconds(t+0.100000),initiate_all_flows); 
					  Simulator::Schedule(Seconds(t+data_transmission_period-0.002-0.3),calculate_performance_evaluation_metricsLLDP);
					  Simulator::Schedule(Seconds(t+data_transmission_period-0.001-0.3),reset_LLDP_counters);
					  Simulator::Schedule (Seconds (t), reset_packet_timestamps);
					  Simulator::Schedule (Seconds (t), reset_confusion_matrix); 
					  Simulator::Schedule (Seconds (t), set_lte_initial_timestamp);
					  Simulator::Schedule (Seconds (t), set_ethernet_initial_timestamp);
					  Simulator::Schedule (Seconds (t+0.035900), set_LLDP_initial_timestamp);
				  } // end if (!routing_test)
//*/
			  	}
		  	}
//*/
	  	
///*
		        //DSRC nodes data unicast 
	    
	  		double t_check;
	  		if((routing_algorithm == 5))
	  		{
				t_check = 7.80;
			}
			else
			{
				t_check = 9.30;
			}
			
			
			for (double t=t_check; t<simTime-1; t=t+data_transmission_period)//All official data transmissions begin at t=0
			{	
				  //Go over all the wifi devices
				 
				 for (uint32_t i=0; i<total_size; i++)
				 {  
					// Guard: skip node indices that don't exist in dsrc_Nodes (e.g. routing_test=true)
					if (i >= dsrc_Nodes.GetN()) continue;
					if(routing_algorithm == 4)
					{
						std::string controller_str;
						std::string consortium_str;
						switch(node_controller_ID[i])
						{
							case (0):
								controller_str = "C0";
								break;
							case (1):
								controller_str = "C1";
								break;
							case (2):
								controller_str = "C2";
								break;
							case (3):
								controller_str = "C3";
								break;
							default:
								controller_str = "C0";
								break;
						
						}
						
						switch(assigned_consortium_ID[i])
						{
							case (0):
								consortium_str = "consortium0";
								break;
							case (1):
								consortium_str = "consortium1";
								break;
							case (2):
								consortium_str = "consortium2";
								break;
							case (3):
								consortium_str = "consortium3";
								break;
							default:
								consortium_str = "consortium0";
								break;
						
						}    
				 }
			}	
//*/	
	}
	
 
 }
} // end if (architecture == 0)
 

 
  
 
  
  for (double t=0; t< simTime-1;t=t+1)
  {
  	Simulator::Schedule (Seconds (t), print_time);
  }
 
  Config::ConnectFailSafe("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/MonitorSnifferRx", MakeCallback (&Rx) );
  Config::ConnectFailSafe("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/$ns3::RegularWifiMac/MacRx", MakeCallback (&MacRx) );
  Config::ConnectFailSafe("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/$ns3::RegularWifiMac/MacTx", MakeCallback (&MacTx) );
  Config::ConnectFailSafe("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::RegularWifiMac/DcaTxop/Queue/Enqueue",MakeCallback (&Enqueue));
  for (uint32_t i = 0; i < uedevices.GetN(); ++i)
	{
		 Ptr<LteUeNetDevice> ueDev = uedevices.Get(i)->GetObject<LteUeNetDevice>();
		 Ptr<LteUeMac> ueMac = ueDev->GetMac();
		 ueMac->TraceConnectWithoutContext("UlScheduling", MakeBoundCallback(&UeTxStartCallback, i));

	}
  //Config::ConnectFailSafe("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/ns3::RegularWifiMac/DcaTxop/Queue/Dequeue",MakeCallback (&Dequeue)); 
  
  // ── NetAnim: MPTD-PQS attack-aware visualization ─────────────────────────────
  // Color legend:
  //   RED    (255,  0,  0) — compromised RSU (TP-S1/MP-S1) OR malicious controller (TP-S3/MP-S4)
  //                          OR malicious vehicle (attacker) — sends poisoned/stolen beacons
  //   YELLOW (255,200,  0) — clean RSU
  //   ORANGE (255,128,  0) — vehicle in compromised RSU zone (attacks 1,3) OR Sybil victim (attack 4)
  //   GREEN  (  0,200,  0) — honest / unaffected vehicle
  //   BLUE   (  0,  0,255) — management node (SDN control plane)
  //   PURPLE (150,  0,220) — honest SDN controller
  //   CYAN   (  0,210,210) — backup controller (STANDBY, not yet active)
  //
  // Attack 4 (MP-S2) 3-way vehicle coloring:
  //   ORANGE = attacker vehicle (sybil_mitm_nodes=true):   sends N_stolen stolen-ID beacons
  //   RED    = victim vehicle (first N_stolen=2 honest):   identity is stolen by ALL attackers
  //   GREEN  = other honest vehicles:                      not targeted in this interval

  // Pre-compute which honest vehicles are Sybil victims (attack 4 only).
  // Replicates the RANDOMIZED selection in inject_mp_s2_stolen_beacons():
  // each attacker uses a per-attacker seed (attacker_nid * 7919) to shuffle
  // the eligible honest vehicle list, then steals the first N_stolen=2.
  // Running the same shuffle here ensures NetAnim ORANGE colors match runtime.
  static const int NETANIM_N_STOLEN = 2;
  bool sybil_victim_nodes[MAX_NODES] = {};
  if (attack_number == 4 && N_Vehicles > 0)
  {
      for (uint32_t attacker_nid = 2; attacker_nid < (uint32_t)(N_Vehicles + 2); attacker_nid++)
      {
          uint32_t attacker_vid = attacker_nid - 2;
          if (!sybil_mitm_nodes[attacker_vid]) continue; // only process attacker nodes

          // Build same eligible list as inject_mp_s2_stolen_beacons()
          std::vector<uint32_t> eligible;
          for (uint32_t nid = 2; nid < (uint32_t)(N_Vehicles + 2); nid++) {
              if (nid == attacker_nid) continue;
              if (sybil_mitm_nodes[nid - 2]) continue;
              eligible.push_back(nid);
          }
          // Same per-attacker seed → identical victim selection as runtime
          std::mt19937 rng(attacker_nid * 7919u);
          std::shuffle(eligible.begin(), eligible.end(), rng);

          int count = 0;
          for (uint32_t nid : eligible) {
              if (count >= NETANIM_N_STOLEN) break;
              sybil_victim_nodes[nid - 2] = true;
              count++;
          }
      }
      std::cout << "[ANIM-DBG] MP-S2 Sybil victims (ORANGE): ";
      for (uint32_t vid = 0; vid < (uint32_t)N_Vehicles; vid++)
          if (sybil_victim_nodes[vid]) std::cout << "V" << vid << " ";
      std::cout << std::endl;
  }
  // Pre-compute MitM victim vehicles for Attack 6 (MP-S3) NetAnim coloring.
  // A vehicle is an initial MitM victim if it lies within R_max_comm of any
  // attacker at simulation start.  Provides 3-way coloring:
  //   RED    = MitM attacker (actively intercepts & forges beacons)
  //   ORANGE = honest vehicle within interception range (initial victim)
  //   GREEN  = honest vehicle outside all attacker ranges
  bool mitm_victim_nodes[MAX_NODES] = {};
  if (attack_number == 6 && N_Vehicles > 0)
  {
      for (uint32_t atk_vid = 0; atk_vid < (uint32_t)N_Vehicles; atk_vid++) {
          if (!sybil_mitm_nodes[atk_vid]) continue;
          Ptr<Node> atk_node = Vehicle_Nodes.Get(atk_vid);
          if (!atk_node) continue;
          Ptr<MobilityModel> atk_mob = atk_node->GetObject<MobilityModel>();
          if (!atk_mob) continue;
          Vector atk_pos = atk_mob->GetPosition();

          for (uint32_t vic_vid = 0; vic_vid < (uint32_t)N_Vehicles; vic_vid++) {
              if (vic_vid == atk_vid) continue;
              if (sybil_mitm_nodes[vic_vid]) continue; // other attackers not victims
              Ptr<Node> vic_node = Vehicle_Nodes.Get(vic_vid);
              if (!vic_node) continue;
              Ptr<MobilityModel> vic_mob_n = vic_node->GetObject<MobilityModel>();
              if (!vic_mob_n) continue;
              Vector vic_pos = vic_mob_n->GetPosition();
              double ddx = atk_pos.x - vic_pos.x, ddy = atk_pos.y - vic_pos.y;
              if (std::sqrt(ddx*ddx + ddy*ddy) <= R_max_comm)
                  mitm_victim_nodes[vic_vid] = true;
          }
      }
      std::cout << "[ANIM-DBG] MP-S3 MitM initial victims (ORANGE): ";
      for (uint32_t v = 0; v < (uint32_t)N_Vehicles; v++)
          if (mitm_victim_nodes[v]) std::cout << "V" << v << " ";
      std::cout << std::endl;
  }

  ensure_analytics_dir(NS3_ROOT "/analytics");
  ensure_analytics_dir(NS3_ROOT "/analytics/results");
  // Filename keyed by scenario + attack + pct + ablation_mode. The old name used
  // only attack+pct, so runs that differed solely in scenario (urban/rural/highway)
  // or ablation mode (AB5 lightweight vs full) all wrote to the SAME xml and clobbered
  // each other. Tag all four so an AB1–AB11 × 3-scenario sweep keeps distinct animations.
  std::string anim_path = std::string(NS3_ROOT "/analytics/results/mptd_netanim_")
                         + mptd_scenario_name()
                         + "_a" + std::to_string(attack_number)
                         + "_p" + std::to_string(attack_percentage)
                         + "_m" + std::to_string(ablation_mode) + ".xml";
  AnimationInterface anim(anim_path);
  // NOTE: EnablePacketMetadata(true) is intentionally omitted — NS-3 3.35 requires
  // it to be called before ANY packet is created (before scheduling), otherwise it
  // triggers SIGIOT.  Packet-level animation data is not needed for topology colours.
  //
  // Raise the per-file packet cap.  AnimationInterface's default m_maxPktsPerFile
  // is 100 000; once exceeded it stops writing packet/mobility records and closes
  // the trace.  At SUMO scale (200 vehicles × 25 RSUs) the DSRC beacon + control
  // traffic hits 100 000 records in only ~7.4 sim-seconds, so a 60 s run would
  // otherwise animate just the first 7 s.  Lift the cap so the full sim duration
  // is captured (≈13.5 k records/sim-sec → ~0.8 M for 60 s; ~65 MB XML).
  anim.SetMaxPktsPerTraceFile(50000000);
  std::cout << "[ANIM-DBG] architecture=" << architecture
            << " N_RSUs=" << N_RSUs << " N_Vehicles=" << N_Vehicles << std::endl;

  // ── Management node — BLUE ──────────────────────────────────────────────────
  if (architecture != 1)
  {
      std::cout << "[ANIM-DBG] coloring management node " << management_Node.Get(0)->GetId() << std::endl;
      anim.UpdateNodeColor(management_Node.Get(0), 0, 0, 255);
      anim.UpdateNodeSize(management_Node.Get(0)->GetId(), 35.0, 35.0);
      anim.UpdateNodeDescription(management_Node.Get(0),
          routing_test ? "MANAGEMENT\nMPTD-PQS Detection\n(DSRC-RSU relay)"
                       : "MANAGEMENT\n(SDN control)");

      // ── Controllers: RED if malicious (attacks 5/7), PURPLE if honest ──
      bool ctrl_malicious = (attack_number == 5 || attack_number == 7);
      for (uint32_t c = 0; c < N_Controllers; ++c) {
          if (ctrl_malicious) {
              anim.UpdateNodeColor(controller_Node.Get(c), 255, 0, 0);  // RED = compromised
              anim.UpdateNodeDescription(controller_Node.Get(c),
                  routing_test ? ("SDN CTRL " + std::to_string(c) + "\n[COMPROMISED]\nTP-S3/MP-S4") : ("CTRL " + std::to_string(c) + " [COMPROMISED]"));
          } else {
              anim.UpdateNodeColor(controller_Node.Get(c), 150, 0, 220); // PURPLE = honest
              anim.UpdateNodeDescription(controller_Node.Get(c),
                  routing_test ? ("SDN CONTROLLER " + std::to_string(c) + "\n(MPTD-PQS)") : ("CONTROLLER " + std::to_string(c)));
          }
          anim.UpdateNodeSize(controller_Node.Get(c)->GetId(), 35.0, 35.0);
      }

      // R4.b: backup_controller_Node coloring removed (node no longer created).
      // Paper has no backup; CP-DETECT (Alg 7) provides controller-misbehavior
      // fallback via RSU peer consensus instead. See invariant #2.

      // ── Cloud/ITS Server (paper Fig 3.9) — CYAN placeholder ────────────────
      // Sits outside both lightweight and full mode boundaries; receives
      // σ_TRS-gated FHE-encrypted aggregates from the RSU cluster (invariant #5).
      // No behaviour wired yet — phase R9 will activate the FHE channel.
      anim.UpdateNodeColor(cloud_Node.Get(0), 150, 200, 255);  // light cyan
      anim.UpdateNodeSize(cloud_Node.Get(0)->GetId(), 35.0, 35.0);
      anim.UpdateNodeDescription(cloud_Node.Get(0),
          routing_test ? "CLOUD / ITS SERVER\n(FHE aggregate sink — R9)"
                       : "CLOUD / ITS SERVER");
  }

  // ── RSU nodes — RED if compromised, YELLOW if clean ────────────────────────
  if (N_RSUs > 0)
  {
      for (uint32_t i = 0; i < RSU_Nodes.GetN(); i++)
      {
          bool comp = (i < N_RSUs) && compromised_rsu[i];
          if (comp)
              anim.UpdateNodeColor(RSU_Nodes.Get(i), 255, 0, 0);    // RED = attacker RSU
          else
              anim.UpdateNodeColor(RSU_Nodes.Get(i), 255, 200, 0);  // YELLOW = clean RSU
          anim.UpdateNodeSize(RSU_Nodes.Get(i)->GetId(), 40.0, 40.0);
          std::string label = "RSU" + std::to_string(i)
                            + (comp ? "\n[COMPROMISED]" : "\n[CLEAN]");
          anim.UpdateNodeDescription(RSU_Nodes.Get(i), label);
      }
  }

  // ── Vehicle nodes — attack-aware coloring ────────────────────────────────────
  // Color legend per attack type:
  //   Attacks 1,3 (RSU-level): ORANGE = vehicle in compromised RSU zone
  //   Attacks 2,6 (vehicle-level): RED = this vehicle is malicious (attacker)
  //   Attack 4 (MP-S2 Sybil): RED = attacker, ORANGE = Sybil victim (identity stolen)
  //   Attacks 5,7 (controller-level): ORANGE = all vehicles affected
  //   GREEN = honest / unaffected vehicle
  // routing_test layout: V0-V3→RSU0, V4-V7→RSU1, V8-V11→RSU2, V12-V15→RSU3
  if (N_Vehicles > 0)
  {
      for (uint32_t i = 0; i < Vehicle_Nodes.GetN(); i++)
      {
          uint32_t rsu_zone = i / 4;  // 4 vehicles per RSU cluster
          bool affected = false;
          std::string reason = "CLEAN";

          // node colour: 0=green, 1=orange(attacker), 2=red(victim)
          int colour_class = 0;

          if (attack_number == 1 || attack_number == 3) {
              // RSU-level attack: vehicle affected if its RSU zone is compromised
              affected = (rsu_zone < N_RSUs) && compromised_rsu[rsu_zone];
              reason   = affected ? "COMPROMISED ZONE" : "CLEAN ZONE";
              colour_class = affected ? 1 : 0;
          } else if (attack_number == 2) {
              // TP-S2: vehicle is the attacker — RED
              affected = (i < (uint32_t)total_size) && tp_vehicle_nodes[i];
              reason   = affected ? "MALICIOUS" : "HONEST";
              colour_class = affected ? 2 : 0;  // RED = attacker
          } else if (attack_number == 4) {
              // MP-S2 Sybil: 3-way coloring
              //   RED    = attacker (sends stolen-ID beacons)
              //   ORANGE = victim honest vehicle (identity stolen by attackers)
              //   GREEN  = other honest vehicles
              bool is_attacker = (i < (uint32_t)total_size) && sybil_mitm_nodes[i];
              bool is_victim   = (i < (uint32_t)total_size) && sybil_victim_nodes[i];
              if (is_attacker) {
                  colour_class = 2;  // RED = attacker
                  reason = "ATTACKER\n(sends stolen IDs)";
              } else if (is_victim) {
                  colour_class = 1;  // ORANGE = victim
                  reason = "VICTIM\n(ID stolen by all\nattackers)";
              } else {
                  colour_class = 0;  // GREEN
                  reason = "HONEST";
              }
          } else if (attack_number == 6) {
              // MP-S3 MitM: 3-way coloring (mirrors Attack 4 pattern)
              //   RED    = MitM attacker  (intercepts + forges speed/location/accel)
              //   ORANGE = initial victim (honest vehicle in attacker's DSRC range)
              //   GREEN  = other honest vehicles (outside all attacker ranges)
              bool is_atk = (i < (uint32_t)total_size) && sybil_mitm_nodes[i];
              bool is_vic = (i < (uint32_t)total_size) && mitm_victim_nodes[i];
              if (is_atk) {
                  colour_class = 2;  // RED
                  reason = "MitM ATTACKER\n(forges speed/loc/acc)";
              } else if (is_vic) {
                  colour_class = 1;  // ORANGE
                  reason = "MitM VICTIM\n(in interception range)";
              } else {
                  colour_class = 0;  // GREEN
                  reason = "HONEST\n(outside range)";
              }
              affected = is_atk || is_vic;
          } else if (attack_number == 5 || attack_number == 7) {
              // TP-S3 / MP-S4: controller-level — ALL vehicles' beacons are corrupted
              affected = true;
              reason   = "CTRL-AFFECTED";
              colour_class = 1;
          }

          switch (colour_class) {
              case 2:  anim.UpdateNodeColor(Vehicle_Nodes.Get(i), 255,   0,   0); break; // RED
              case 1:  anim.UpdateNodeColor(Vehicle_Nodes.Get(i), 255, 128,   0); break; // ORANGE
              default: anim.UpdateNodeColor(Vehicle_Nodes.Get(i),   0, 200,   0); break; // GREEN
          }
          anim.UpdateNodeSize(Vehicle_Nodes.Get(i)->GetId(), 35.0, 35.0);
          std::string vlabel = "V" + std::to_string(i)
                             + "\nRSU" + std::to_string(rsu_zone)
                             + "\n" + reason;
          anim.UpdateNodeDescription(Vehicle_Nodes.Get(i), vlabel);
      }

      if (architecture != 1)
      {
          for (uint32_t i = 0; i < other_stationary_LTE_nodes.GetN(); i++)
          {
              if (routing_test)
              {
                  // Paper's proposed architecture (DSRC-RSU relay) has NO LTE core.
                  // Hide eNodeB / PGW / SGW / remote-host nodes: white + 1×1 = invisible.
                  anim.UpdateNodeColor(other_stationary_LTE_nodes.Get(i), 255, 255, 255);
                  anim.UpdateNodeSize(other_stationary_LTE_nodes.Get(i)->GetId(), 1.0, 1.0);
                  anim.UpdateNodeDescription(other_stationary_LTE_nodes.Get(i), "");
              }
              else
              {
                  // Legacy LTE architecture — show as light-blue
                  anim.UpdateNodeColor(other_stationary_LTE_nodes.Get(i), 100, 100, 255);
                  anim.UpdateNodeSize(other_stationary_LTE_nodes.Get(i)->GetId(), 20.0, 20.0);
              }
          }
      }
  }

  std::cout << "[NETANIM] XML → " << anim_path << std::endl;
  std::cout << "[NETANIM] Open with: netanim " << anim_path << std::endl;
  
  // ── LKH: initialise tree + session keys + RSU ring keys before simulation ────
  // Must be called AFTER N_Vehicles and N_RSUs are finalised (set in cmd args above)
  // and BEFORE Simulator::Run() so all vehicles have valid K_i for HMAC on first beacon.
  lkh_init_all((int)N_Vehicles, (int)N_RSUs);

  // ── SC-Register: paper §3.5.5 Algorithm 7 boot-time node registration ───────
  // Must run AFTER lkh_init_all() (h(K_u_i) is taken from g_vehicle_session_key
  // and g_rsu_ring_key) and BEFORE Simulator::Run() so every node has a
  // committed REG_<id> entry on-chain before any SCTrustSubmitEvidence /
  // SCControllerSubmitEvidence / SCRevokeVote fires. No-op when
  // skip_blockchain=true or routing_algorithm != 4.
  if (routing_algorithm == 4) {
    // Wipe any world state left over from a previous run so each simulation
    // (every attack × percentage) starts from a clean ledger. No-op under
    // skip_blockchain. Must precede register_all_nodes() so the fresh
    // registrations are not rejected as duplicates of the prior run.
    CallSCResetLedger();

    // Push the simulation's ACTUAL detection threshold into the ledger config.
    // Without this the chaincode silently uses its fallback PsiAnomalyTh=0.5
    // while RSUs decide anomalies at psi_th=0.09 — the same symbol ψ_th holding
    // two different values in two components. Effect: an RSU submits evidence it
    // considers anomalous (median ψ=0.15; 57% of beacons exceed 0.09), the
    // chaincode recomputes flag^rsu = 1[ψ > 0.5] and gets 0 (only 11% qualify),
    // so the directional conflict (1−flag^ctrl)·flag^rsu (Eq 3.66) collapses to
    // 0, controller trust never decays off 1.0, and CP-DETECT / SC-Revoke can
    // never fire regardless of attack intensity.
    //
    // NumRSUs stays 4 ON PURPOSE: fByzantine(n)=(n-1)/3, so n=4 ⇒ f=1 ⇒
    // 2f+1=3, matching the 3 endorsements register_one() actually collects.
    // Passing the true 64 would demand 2f+1=43 endorsements and break every
    // registration.
    CallSCInitNetworkConfig(/*numRSUs=*/4, /*alpha=*/g_rsu_trust_alpha,
                            /*tauWarn=*/0.5, /*tauMin=*/0.3,
                            /*tRev=*/(uint32_t)g_rsu_t_rev, /*psiAnomalyTh=*/psi_th,
                            /*rsuTrustQuorum=*/g_rsu_trust_quorum,
                            /*tWindowSec=*/(g_t_window > 0 ? g_t_window : 0.0));

    register_all_nodes();
  }

  // ── Phase 1C-b: unconditional drainer arm when MPTD_FABRIC_EVT_FORCE_ARM=1 ──
  // The beacon-path hook only fires if a beacon actually arrives; a synthetic-
  // event verification run with simTime≈5 s never reaches HandleBeaconReceived.
  // Wiring the env-gated arm here guarantees the +0.5s drainer tick regardless
  // of attack/percentage selection. Paper §3.5.5 Eq 3.58 cross-RSU broadcast.
  mptd_arm_event_drainer_if_env();

  // C5 TTD: seed the onset/alert sentinels to -1. These are file-scope globals, so
  // C++ zero-initialises them to 0.0 — and compute_TTD() treats ">= 0" as "recorded".
  // Without this every one of the total_size slots looks recorded with onset==alert,
  // so TTD collapsed to exactly 0.0000 in every run ever produced. init_vehicle_states()
  // in 04_state_globals.h seeds these, but it is DEFINED AND NEVER CALLED; only these
  // two arrays actually differ from zero-init, so we seed them here rather than call
  // it (calling it would also clear pre_registered_sybil[] and clobber attacker setup).
  for (int i = 0; i < total_size; i++) {
      g_ttd_first_poison[i] = -1.0;
      g_ttd_first_alert[i]  = -1.0;
  }

  // TEMP DIAGNOSTIC (Step 1 follow-up): sample coverage at multiple timestamps
  // via a named free function (mptd_coverage_diag_check, declared above main).
  for (double t = 2.0; t < simTime; t += 2.0) {
      Simulator::Schedule(Seconds(t), &mptd_coverage_diag_check, t);
  }

  Simulator::Stop(Seconds(simTime));
  Simulator::Run();

  // TEMP DIAGNOSTIC (Step 1 follow-up): raw TX vs RX beacon counts, to localize
  // the beacon-count gap. Compare against the confusion matrix total printed
  // separately (cm_TP+cm_FP+cm_TN+cm_FN).
  std::cout << "[COVERAGE-DIAG] beacon TX attempts=" << g_diag_beacon_tx_count
            << "  RX at RSU (HandleBeaconReceived calls)=" << g_diag_beacon_rx_count
            << "  RX/TX=" << (g_diag_beacon_tx_count > 0 ? (100.0*g_diag_beacon_rx_count/g_diag_beacon_tx_count) : 0.0)
            << "%" << std::endl;
  std::cout << "[COVERAGE-DIAG] confusion-matrix update() calls=" << g_diag_cm_update_count
            << "  CM/RX=" << (g_diag_beacon_rx_count > 0 ? (100.0*g_diag_cm_update_count/g_diag_beacon_rx_count) : 0.0)
            << "%  (Block 2: gap between RX and CM update means a filter exists between them)"
            << std::endl;

  // ── Tier-3 batched-commit: flush trailing partial batches + summary ──────
  // (paper §3.5.5) The time-flush only fires on a subsequent same-RSU push, so
  // each RSU's final sub-N_commit batch is drained here. The summary reports how
  // much anomaly evidence was buffered vs committed as batched Fabric txs.
  if (g_tiered_commit) {
      tier3_flush_all(simTime);
      std::cout << "[TIER3-SUMMARY] evidence_buffered=" << g_tier3_buffered
                << " batches_committed=" << g_tier3_batches
                << " entries_committed=" << g_tier3_entries
                << " (T_batch=" << g_t_batch << "s N_commit=" << g_n_commit << ")"
                << std::endl;
  }

  Simulator::Destroy();

  // ── Write MPTD-PQS metrics CSV (Stage 4) ─────────────────────────────────
  write_mptd_results_csv();

  // ── Export on-chain trust/revoke/CRL audit trail (paper §3.5.5) ──────────
  // Consolidated JSON snapshot of committed ledger state — the off-line
  // evidence the trust/revocation analysis is computed from, and the hand-off
  // for Hyperledger Explorer / IPFS. No-op under skip_blockchain / A5.
  mptd_export_blockchain_evidence(
      std::string(NS3_ROOT "/analytics/results/blockchain_evidence.json"));

  // ── MRTPA Attack Summary ──────────────────────────────────────────────────
  std::cout << "\n========================================" << std::endl;
  std::cout << " ATTACK SUMMARY" << std::endl;
  std::cout << "========================================" << std::endl;
  std::cout << "  Attack number        : " << attack_number << std::endl;
  std::cout << "  Attack percentage    : " << attack_percentage << "%" << std::endl;
  std::cout << "  Trajectories received: " << total_trajectories_received << std::endl;
  std::cout << "  Trajectories poisoned: " << total_trajectories_poisoned << std::endl;
  std::cout << "  Blockchain records   : " << total_trajectories_stored_blockchain << std::endl;
  if (total_trajectories_received > 0) {
      double poison_rate = 100.0 * total_trajectories_poisoned / total_trajectories_received;
      std::cout << "  Actual poison rate   : " << poison_rate << "%" << std::endl;
      // FIX 1 (identity binding) — DQ-FP4 answer + validation of the check itself.
      if (g_hmac_fail_closed)
          std::cout << "  [HMAC-FAILCLOSED] beacons rejected for missing MAC: "
                    << g_hmac_missing_rejected << std::endl;
      std::cout << "  [FIX1] idbind checked=" << g_idbind_checked
                << " rejected=" << g_idbind_rejected
                << "  of which poisoned=" << g_idbind_rej_poisoned
                << " HONEST=" << g_idbind_rej_honest;
      if (g_idbind_rejected)
          std::cout << "  (precision=" 
                    << (100.0 * g_idbind_rej_poisoned / g_idbind_rejected) << "%)";
      std::cout << std::endl;
  }
  std::cout << "========================================" << std::endl;
  // ─────────────────────────────────────────────────────────────────────────

  //apb.SetFinish();
  return 0;
}

































