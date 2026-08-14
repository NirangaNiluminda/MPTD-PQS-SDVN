// ============================================================
// 09_vehicle_beacon_tx.h — Vehicle Beacon Transmit Functions (MPTD-PQS)
// Renamed + cleaned from 09_send_lte.h (Stage 10B cleanup)
// ============================================================
// Professor's function naming convention (mapped to this file):
//
//   Professor term                  | This file's function
//   --------------------------------|---------------------------------------------
//   send_lte_dataunicast_alone()    | send_lte_dataunicast_alone()   ← vehicle BSM
//   (vehicle → controller, no agg) |   DSRC 802.11p → RSU:6666 → Management:7777
//   send_lte_dataunicast_agent()    | NOT USED — no per-vehicle aggregation needed
//   (vehicle → controller, agg)    |
//
// Note: professor uses "LTE" in the function name generically to mean
// "vehicle uplink to controller". In this project the actual transport
// is 802.11p DSRC (Option B relay via RSU), not cellular LTE.
//
// Contents:
//   send_lte_dataunicast_alone()    — vehicle BSM beacon uplink (§3.4.3)
//   inject_mp_s2_stolen_beacons()  — MP-S2 identity theft injection (§3.4.2)
//
// Removed vs 09_send_lte.h:
//   routing_time, average_* metric globals (LDA routing artifacts)
//   clear_solution() — Gurobi reset stub
//   7 empty downlink stubs (send_LTE_metadata_downlink_alone, etc.)
//   sent_IDS[][][] array (LDA IDS state, never used in MPTD-PQS path)
// ============================================================

// Forward declaration — inject_mp_s2_stolen_beacons() is defined later in this file
void inject_mp_s2_stolen_beacons(Ptr<SimpleUdpApplication>, uint32_t,
                                  double, double, double, double, double, Ipv4Address);

// Forward declaration — inject_mp_s3_mitm_beacons() is defined later in this file
// MP-S3 (attack_number=6): true MitM — intercept nearby honest vehicle beacons,
// modify speed to corrupt regional KL distribution, forward under victim's identity.
void inject_mp_s3_mitm_beacons(Ptr<SimpleUdpApplication>, uint32_t,
                                double, double, Ipv4Address);

// ── send_lte_dataunicast_alone() — Vehicle → Management Node beacon uplink ──
// Professor's term: send_lte_dataunicast_alone
//   Vehicle sends its own BSM beacon data directly to the controller/management
//   node without aggregating other vehicles' data (alone = this node's data only).
// Implementation: DSRC 802.11p unicast → nearest RSU (port 6666) → CSMA backhaul
//   → Management node (port 7777). When Option B inactive: direct UDP to management.
// Sends a BsmBeaconTag packet carrying the vehicle's latest
// position, speed, heading, acceleration, and attack state.
void send_lte_dataunicast_alone(Ptr<SimpleUdpApplication> udp_app,
                                Ptr<Node> node_source,
                                Ptr<Node> destination_node,
                                uint32_t node_index)
{
	// ── Option B: send to nearest RSU's DSRC IP (port 6666) ─────────────────────
	// When g_option_b_active=true, the beacon travels via 802.11p DSRC through
	// an actual NS-3 RSU node (HandleBeaconAtRSU) before reaching management_node.
	// Fallback: legacy LTE path to management_node when Option B is not active.
	Ipv4Address dest_ip;
	uint16_t    dest_port;
	uint32_t    nearest_rsu_idx = 0; // used for log output below

	uint32_t nid = node_source->GetId();
	uint32_t vid = (nid >= 2) ? (nid - 2) : 0; // VS() index

	g_diag_beacon_tx_count++;  // TEMP DIAGNOSTIC (Step 1 follow-up)

	if (nid == 2)
	{
		lte_total_packet_size = 0;
		lte_initial_timestamp = Simulator::Now().GetSeconds();
	}

	// ── Read NS-3 MobilityModel → compute beacon payload ───────────────────
	// NOTE: we do NOT push to VS() at send time.
	// VS(nid) is populated ONLY by HandleBeaconReceived() on the
	// RSU receive side. This avoids the send-vs-receive index collision
	// (send side would use vid=nid-2, receive side uses nid directly).
	double tx_px = 0.0, tx_py = 0.0, tx_spd = 0.0, tx_hdg = 0.0, tx_acc = 0.0;
	double real_px = 0.0, real_py = 0.0;
	double real_vx = 0.0, real_vy = 0.0;   // real velocity for LL-based RSU selection
	bool   is_mal  = false;
	bool   in_streak = true;  // E4 TL composite streak gate (--streak_sigma); declared here so it outlives the scoping block below
	{
		Ptr<MobilityModel> mob = node_source->GetObject<MobilityModel>();
		double real_spd = 0.0, real_hdg = 0.0, real_acc = 0.0;
		if (mob) {
			Vector pos = mob->GetPosition();
			Vector vel = mob->GetVelocity();
			real_px  = pos.x;
			real_py  = pos.y;
			real_vx  = vel.x;   // stored for LL-based RSU selection below
			real_vy  = vel.y;
			real_spd = std::sqrt(vel.x * vel.x + vel.y * vel.y);
			real_hdg = (real_spd > 1e-6) ? std::atan2(vel.y, vel.x) : 0.0;
			// Accel: approximate from separate send-side speed history (not vehicle_state)
			double prev_spd = send_prev_speed[vid];
			double prev_ts  = send_prev_time [vid];
			double dt = Simulator::Now().GetSeconds() - prev_ts;
			real_acc = (dt > 1e-9 && send_prev_time[vid] > 0.0) ?
			           (real_spd - prev_spd) / dt : 0.0;
			// Update send-side history
			send_prev_speed[vid] = real_spd;
			send_prev_time [vid] = Simulator::Now().GetSeconds();
		}

		// Determine if this vehicle is malicious (any active attack flag)
		is_mal = tp_vehicle_nodes[vid]
		      || heading_spoof_nodes[vid]
		      || rsu_fabrication_nodes[vid]
		      || sybil_mitm_nodes[vid]
		      || beacon_suppression_nodes[vid];

		tx_px = real_px;  tx_py = real_py;
		tx_spd = real_spd; tx_hdg = real_hdg; tx_acc = real_acc;

		// Now that real_px/real_py are known, resolve destination
		if (g_option_b_active && g_num_active_rsus > 0) {
			// ── LL-based RSU selection: score = (LL/T_REF) / (d/R_max_comm) ────────
			// Uses vehicle's REAL velocity (from MobilityModel) — not the poisoned
			// beacon value — so the vehicle's own navigation remains accurate.
			// Hysteresis δ=0.15 prevents ping-pong at RSU coverage boundaries.
			uint32_t ll_rsu  = best_rsu_for_position(real_px, real_py,
			                                          real_vx, real_vy,
			                                          vid, is_mal);
			uint32_t geo_rsu = nearest_rsu_for_position(real_px, real_py);
			nearest_rsu_idx  = ll_rsu;
			if (g_verbose_tx && ll_rsu != geo_rsu) {
				cout << "[LL-SEL] V" << nid
				     << " LL→RSU" << ll_rsu
				     << " (nearest=RSU" << geo_rsu << ")"
				     << " score=" << std::fixed << std::setprecision(3)
				     << g_vehicle_rsu_score[(vid < MAX_NODES) ? vid : 0]
				     << " t=" << Simulator::Now().GetSeconds() << endl;
			}
			dest_ip   = g_rsu_dsrc_ip[nearest_rsu_idx];
			dest_port = 6666;
		} else {
			// Fallback: direct LTE to management_node interface 2
			Ptr<Ipv4> ipv4 = destination_node->GetObject<Ipv4>();
			dest_ip   = ipv4->GetAddress(2, 0).GetLocal();
			dest_port = 7777;
		}

		// E4 TL composite: streak gate σ (--streak_sigma). Mirrors the
		// vanish_counter pattern below — per-vehicle beacon counter cycling
		// ON for σ beacons, OFF for σ beacons. -1 (default) = always on,
		// byte-identical to every existing result. Gates BOTH the poisoning
		// application below and the ground-truth IsPoisoned label, since a
		// vehicle in its "honest" phase is genuinely transmitting real
		// kinematics this beacon and must not be mislabeled as poisoned.
		if (is_mal && g_streak_sigma > 0) {
			static uint32_t streak_counter[MAX_NODES] = {};
			uint32_t cycle_pos = streak_counter[vid] % (2u * (uint32_t)g_streak_sigma);
			in_streak = cycle_pos < (uint32_t)g_streak_sigma;
			streak_counter[vid]++;
		}

		if (is_mal && in_streak) {
			// ── MP-S2 Vanishing: suppress beacon on alternate calls (50% drop) ──
			// Vehicle appears to "vanish" from the network intermittently.
			// Effect: poisoned beacons are never received → FN rate increases.
			if (beacon_suppression_nodes[vid]) {
				static uint32_t vanish_counter[MAX_NODES] = {};
				vanish_counter[vid]++;
				if (vanish_counter[vid] % 2 == 0) {
					// Skip this beacon — do NOT send, do NOT accumulate errors
					// (TDEE/TPE only count beacons that ARE sent)
					cout << "[VANISH] node " << nid
					     << " suppressed beacon at "
					     << Simulator::Now().GetSeconds() << endl;
					return;
				}
			}

			// Apply attack-type-specific trajectory poisoning (§3.4.1–3.4.2)
			// Each attack_number manipulates different BSM beacon fields so
			// distinct detection signatures (TP-S1..MP-S4) fire per type.
			Vector fpos(real_px, real_py, 0.0);
			double vx = real_spd * std::cos(real_hdg);
			double vy = real_spd * std::sin(real_hdg);
			Vector fvel(vx, vy, 0.0);
			Vector facc(0.0, 0.0, 0.0);
			// Combined mode: each malicious vehicle runs its OWN assigned attack
			// type (g_veh_attack[vid]); single-attack mode uses the global.
			int eatk = veh_atk(vid, attack_number);
			PoisonTrajectoryByType(fpos, fvel, facc, poisoning_intensity_theta,
			                       eatk);
			// attack 3 (MP-S1 Sybil): no vehicle-level modification (is_mal=false), skip.
			// attack 5 (TP-S3 Control-plane): vehicles are honest, case not reached.
			// attack 6 (MP-S3 MitM): extreme speed must reach detector unclamped.
			// attack 7 (MP-S4 Coordinated): speed amplification must reach detector unclamped.
			// All other attacks maintain plausible-looking trajectories via EnforceRealism.
			// Skip EnforceRealism for attacks that intentionally exceed physical speed bounds:
			//   attack 6 (MP-S3 MitM):         speed ~66 m/s for KL detection
			//   attack 7 (MP-S4 Coordinated):   speed amplification for distribution corruption
			//   attack 3 + sybil_reg_pct > 0:   speed ~66 m/s for MP-S3 KL detection (enhanced mode)
			// EnforceRealism would clamp velocity to s_max=33.33 m/s and nullify the signal.
			if (eatk != 6 && eatk != 7 &&
			    !(eatk == 3 && sybil_registration_pct > 0)) {
				EnforceRealism(fpos, fvel, facc);
			}
			tx_px  = fpos.x;
			tx_py  = fpos.y;
			tx_spd = std::sqrt(fvel.x * fvel.x + fvel.y * fvel.y);
			tx_hdg = (tx_spd > 1e-6) ? std::atan2(fvel.y, fvel.x) : 0.0;
			tx_acc = std::sqrt(facc.x * facc.x + facc.y * facc.y);
		}

		// ── Poisoned-velocity RSU divergence log ──────────────────────────────────
		// Log when the poisoned beacon velocity would have selected a DIFFERENT RSU
		// than the real velocity.  Selection still uses real velocity (correct design);
		// this log exposes the discrepancy as a detectable side-effect of the attack.
		if (is_mal && g_option_b_active) {
			double tx_vx_p = tx_spd * std::cos(tx_hdg);
			double tx_vy_p = tx_spd * std::sin(tx_hdg);
			uint32_t poison_rsu = nearest_rsu_for_position(tx_px, tx_py);
			// Quick geo check using poisoned position (no hysteresis side-effect)
			(void)tx_vx_p; (void)tx_vy_p;
			if (poison_rsu != nearest_rsu_idx) {
				cout << "[LL-POISON] V" << nid
				     << " poisoned-pos→RSU" << poison_rsu
				     << " real-LL-sel→RSU" << nearest_rsu_idx
				     << " tx_spd=" << std::fixed << std::setprecision(1) << tx_spd
				     << " real_spd=" << std::sqrt(real_vx*real_vx + real_vy*real_vy)
				     << " t=" << Simulator::Now().GetSeconds() << endl;
			}
		}

		// Accumulate TPE metric — injection error for malicious vehicle beacons only (§4.1.2)
		// TDEE is now computed at the management node in 08_detection_engine.h (density-based).
		if (is_mal) {
			double dx = tx_px - real_px, dy = tx_py - real_py;
			double disp_err = std::sqrt(dx * dx + dy * dy);
			tpe_sq_sum += disp_err * disp_err;
			tpe_cnt++;
		}

		// ── Vehicle TX log: record real vs sent fields for every beacon ───────────
		// Shows which vehicles are malicious and exactly what they transmitted.
		// For honest vehicles: sent == real, all deltas == 0.
		// For malicious vehicles: sent reflects PoisonTrajectoryByType() output.
		log_vehicle_tx(nid, nearest_rsu_idx,
		               Simulator::Now().GetSeconds(), is_mal,
		               real_px, real_py, tx_px, tx_py,
		               real_spd, tx_spd,
		               real_hdg, tx_hdg);
	}

	// Build BsmBeaconTag directly from computed tx values
	BsmBeaconTag tag;
	tag.SetVehicleId(nid);
	tag.SetPosition(tx_px, tx_py);
	tag.SetSpeed(tx_spd);
	tag.SetHeading(tx_hdg);
	tag.SetAcceleration(tx_acc);
	tag.SetTimestamp(Simulator::Now().GetSeconds());
	tag.SetIsPoisoned(is_mal && in_streak);
	// Round 6 (DQ5/DQ-followup) fix: in combined mode the run-level attack_number
	// is 0, so this previously stamped EVERY vehicle-level attack (a2/a4/a6) with
	// type 0 — folding them into the "honest" bucket for any per-type breakdown
	// and making class-balanced Phase 2 calibration impossible. veh_atk() returns
	// this vehicle's actually-assigned type in combined mode (g_veh_attack[vid],
	// set in declare_attackers()) and falls through to attack_number otherwise, so
	// single-attack runs are byte-identical to before.
	tag.SetAttackType(static_cast<uint32_t>(veh_atk(vid, attack_number)));
	tag.SetSigViolated(0); // sig_violated set by detector (08_detection_engine.h)

	// ── LKH HMAC beacon tag (Eq.3.37): MAC_i(t) = HMAC_{K_i}(b_i(t)‖t‖ID_i) ──
	// Honest vehicles compute HMAC with their current session key K_i.
	// Malicious vehicles (attackers) also compute HMAC with their K_i —
	// but their K_i changes after revocation → future beacons rejected at RSU gate.
	// A completely external attacker (no valid K_i) cannot forge a valid HMAC.
	{
		int v_idx = lkh_veh_idx(nid);
		if (v_idx >= 0 && v_idx < LKH_MAX_VEH) {
			double tx_t = Simulator::Now().GetSeconds();
			uint8_t mac[LKH_HMAC_TRUNC];
			lkh_compute_beacon_hmac(v_idx,
			                        tx_px, tx_py, tx_spd, tx_hdg, tx_acc,
			                        tx_t, nid, mac);
			tag.SetHmac(mac);
		}
	}

	Ptr<Packet> packet1 = Create<Packet>(0);
	packet1->AddPacketTag(tag);
	lte_total_packet_size += packet1->GetSerializedSize();
	g_bwo_base_bytes += tag.GetSerializedSize() - 8;   // C8 BWO: plain BSM payload
	g_bwo_hmac_bytes += 8;                             //          + 8 B HMAC overhead
	Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
	                    udp_app, packet1, dest_ip, dest_port);

	if (g_option_b_active) {
		if (g_verbose_tx)
			cout << "[DSRC-TX] V" << nid << " → RSU" << nearest_rsu_idx
			     << " (" << dest_ip << ":" << dest_port << ") at "
			     << Simulator::Now().GetSeconds() << endl;
		// ── A7-STEP1/STEP2: All vehicles transmit HONEST beacons (data plane clean) ──
		// Paper Fig 3.7 §3.4.2: Vehicles and RSUs operate correctly — no data-plane
		// poisoning. Even vehicles alternate Step 1, odd vehicles alternate Step 2.
		if (attack_number == 7) {
			int step_label = (nid % 2 == 0) ? 1 : 2;
			cout << "[A7-STEP" << step_label << "] V" << nid
			     << " → RSU" << nearest_rsu_idx
			     << " HONEST beacon: spd=" << tx_spd
			     << " pos(" << tx_px << "," << tx_py << ")"
			     << " — data plane correct" << endl;
		}
	} else {
		cout << "[LTE-UP] V" << nid << " → MGT (" << dest_ip << ") at "
		     << Simulator::Now().GetSeconds() << endl;
	}

	// ── MP-S2 Attack Injection (§3.4.2, Figure 3.5) ─────────────────────────────
	// Attack model defined in 06a_attack_models.h (declare_attack_states, attack_number==4).
	// Execution: malicious vehicle calls inject_mp_s2_stolen_beacons() to send
	// extra beacon packets claiming stolen vehicle identities at this vehicle's position.
	if (veh_atk(vid, attack_number) == 4 && is_mal)
		inject_mp_s2_stolen_beacons(udp_app, nid, tx_px, tx_py,
		                             tx_spd, tx_hdg, tx_acc, dest_ip);

	// ── MP-S3 MitM Injection (§3.4.2, Figure 3.6) ───────────────────────────────
	// True MitM: attacker intercepts nearby honest vehicle beacons on the DSRC
	// channel (all 802.11p broadcasts are receivable by nearby nodes), modifies
	// the speed field to corrupt the regional speed distribution, then forwards
	// the packet to the RSU under the victim's original identity.
	// Paper steps: ①honest sends → ②MitM intercepts → ④MitM forwards modified
	// beacon to RSU with victim's ID but amplified speed → ⑤RSU sends both
	// legitimate and poisoned data to controller → ⑥controller model corrupted.
	if (veh_atk(vid, attack_number) == 6 && is_mal)
		inject_mp_s3_mitm_beacons(udp_app, nid, real_px, real_py, dest_ip);

	// MP-S4 (attack_number=7): controller-malicious-only attack — vehicles are honest.
	// No vehicle-level injection here. Controller applies global mobility model
	// poisoning in HandleBeaconReceived() (08_detection_engine.h). is_mal=false always.
}

// ── inject_mp_s2_stolen_beacons() — MP-S2 identity theft beacon injection ────
// Paper §3.4.2 (Figure 3.5): Malicious vehicle transmits N_stolen additional
// beacons per interval, each claiming to be a different honest vehicle's ID
// but carrying the attacker's own current position. This causes the RSU to
// record the same honest vehicle ID appearing simultaneously at two impossible
// locations → triggers MP-S4 ghost-transit-impossibility check (§3.4.4).
//
// Attack model definition: 06a_attack_models.h → declare_attack_states() case 4
// Detection logic:         08_detection_engine.h → run_syb_detect() bit 3 (MP-S4)
void inject_mp_s2_stolen_beacons(Ptr<SimpleUdpApplication> udp_app,
                                  uint32_t attacker_nid,
                                  double tx_px, double tx_py,
                                  double tx_spd, double tx_hdg, double tx_acc,
                                  Ipv4Address dest_ip)
{
	static const int N_stolen = 2; // identities stolen per beacon interval (paper §3.4.2)

	// ── Realistic random victim selection ────────────────────────────────────────
	// Build list of all eligible honest vehicle node IDs (not self, not attacker).
	// Then shuffle with a per-attacker deterministic seed so:
	//   • Every attacker steals from a DIFFERENT pair of victims (realistic spread)
	//   • Same attacker steals the same pair every beacon interval (consistent identity)
	//   • Seed = attacker_nid * prime → unique permutation per attacker across runs
	std::vector<uint32_t> eligible;
	for (uint32_t nid = 2; nid < (uint32_t)(N_Vehicles + 2); nid++) {
		if (nid == attacker_nid) continue;              // don't steal own ID
		if (sybil_mitm_nodes[nid - 2]) continue;        // only steal from honest vehicles
		eligible.push_back(nid);
	}
	// Per-attacker deterministic seed → each attacker gets a unique victim pair
	std::mt19937 rng(attacker_nid * 7919u);
	std::shuffle(eligible.begin(), eligible.end(), rng);

	int stolen_count = 0;
	for (uint32_t other_nid : eligible) {
		if (stolen_count >= N_stolen) break;

		BsmBeaconTag fake_tag;
		fake_tag.SetVehicleId(other_nid);           // stolen identity
		fake_tag.SetPosition(tx_px, tx_py);         // attacker's real position
		fake_tag.SetSpeed(tx_spd);
		fake_tag.SetHeading(tx_hdg);
		fake_tag.SetAcceleration(tx_acc);
		// Timestamp: Sybil identities forged by ONE attacker share a single hardware
		// clock (paper §3.4.2 / MP-S2 "Synchronized Beacon Timing", Eq 3.17), so the
		// stolen-ID beacons are emitted near-SIMULTANEOUSLY — a sub-millisecond clock
		// jitter, NOT a 5–10ms stagger. This keeps |t_a − t_b| < τ_sync (=1ms) so the
		// MP-S2 synchronized-timing signature (08_detection_engine.h:464) fires as the
		// paper intends (the primary detector for impersonation), while the small
		// POSITIVE offset still gives tdiff > 0 for the MP-S4 ghost-transit guard
		// (d/tdiff > s_max holds — d is large). The previous 5–10ms stagger exceeded
		// τ_sync and silently bypassed the paper's MP-S2 detector → ~33% recall.
		double fake_ts = Simulator::Now().GetSeconds() + 0.0002 * (stolen_count + 1);
		fake_tag.SetTimestamp(fake_ts);
		fake_tag.SetIsPoisoned(true);               // impersonation beacon = poisoned
		fake_tag.SetAttackType(4);
		fake_tag.SetSigViolated(0);

		// ── §3.4.2 stolen-identity threat: attacker possesses K_victim (Eq.3.37) ──
		// Paper §3.4.2 explicitly enumerates "stolen or learned identities" as the
		// MP-S2 capability — so the attacker can compute a valid HMAC over the
		// stolen ID using the victim's session key K_victim. Without this, the
		// beacon is trivially rejected at the RSU HMAC gate (Eq.3.37) and never
		// reaches the behavioral SYB-DETECT / MP-S4 ghost-transit check (Eq.3.19),
		// which violates paper §3.5.1 "cryptography alone cannot mitigate". We
		// stamp using the victim's v_idx so the RSU recomputes the same MAC →
		// beacon passes HMAC gate → MP-S4 catches it via impossible displacement.
		int victim_v_idx = lkh_veh_idx(other_nid);
		if (victim_v_idx >= 0 && victim_v_idx < LKH_MAX_VEH) {
			uint8_t fake_mac[LKH_HMAC_TRUNC];
			lkh_compute_beacon_hmac(victim_v_idx,
			                        tx_px, tx_py, tx_spd, tx_hdg, tx_acc,
			                        fake_ts, other_nid, fake_mac);
			fake_tag.SetHmac(fake_mac);
		}

		Ptr<Packet> fake_pkt = Create<Packet>(0);
		fake_pkt->AddPacketTag(fake_tag);
		lte_total_packet_size += fake_pkt->GetSerializedSize();
		g_bwo_base_bytes += fake_tag.GetSerializedSize() - 8;   // C8 BWO
		g_bwo_hmac_bytes += 8;

		// Stagger 5ms per stolen beacon so RSU sees distinct receive events
		uint16_t stolen_port = g_option_b_active ? 6666 : 7777;
		Simulator::Schedule(Seconds(0.005 * (stolen_count + 1)),
		                    &SimpleUdpApplication::SendPacket,
		                    udp_app, fake_pkt, dest_ip, stolen_port);

		cout << "[MP-S2-SYB] V" << attacker_nid << " impersonating V" << other_nid
		     << " at pos(" << tx_px << "," << tx_py << ")" << endl;
		stolen_count++;
	}
}

// ── inject_mp_s3_mitm_beacons() — MP-S3 true MitM interception (Figure 3.6) ──
// Paper §3.4.2 (Figure 3.6) 7-step attack model:
//
//   Step ①: Honest vehicles transmit correct mobility data to RSU (data plane)
//   Step ②: MitM attacker intercepts packets; learns valid vehicle identities
//            and mobility formats from observed legitimate messages
//   Step ③: Attacker FABRICATES new mobility reports by modifying:
//            - location  (small realistic GPS drift ±10-30% of max_pos_deviation)
//            - speed     (progressive escalation over time to exceed D_KL > κ_th)
//            - acceleration (positive, consistent with speed escalation pattern)
//            Keeps values "realistic to avoid detection" — generated over MULTIPLE
//            time steps to mimic normal driving behaviour
//   Step ④: Poisoned packets forwarded to RSU as if sent by legitimate vehicles
//   Step ⑤: RSU forwards both legitimate AND poisoned mobility to controller
//   Step ⑥: Controller aggregates poisoned data into global learning model
//   Step ⑦: Vehicles receive incorrect control decisions from corrupted model
//
// Key difference vs MP-S2 (attack 4):
//   MP-S2: attacker places VICTIM'S ID at ATTACKER'S position  (identity theft)
//   MP-S3: attacker places VICTIM'S ID at VICTIM'S (slightly drifted) position,
//          escalates SPEED + ACCELERATION to corrupt KL distribution
//
// Detection target: D_KL(P_t || P_hist) > κ_th=1.5  →  MP-S3 fires (Eq. 3.18)
void inject_mp_s3_mitm_beacons(Ptr<SimpleUdpApplication> udp_app,
                                uint32_t attacker_nid,
                                double atk_px, double atk_py,
                                Ipv4Address dest_ip)
{
	static const int N_intercept = 2; // max victims intercepted per beacon interval

	// Per-attacker-victim step counter for progressive escalation tracking.
	// step_count[attacker_vid][victim_vid] = number of interceptions so far.
	// Starts at 0; incremented each beacon interval — mimics "multiple time steps".
	static uint32_t step_count[MAX_NODES][MAX_NODES] = {};

	int intercepted = 0;
	double t = Simulator::Now().GetSeconds();
	uint32_t attacker_vid = (attacker_nid >= 2) ? (attacker_nid - 2) : 0;

	// [A6-STEP2] MitM attacker actively scans DSRC channel for interceptable beacons
	cout << "[A6-STEP2] V" << attacker_nid << " (MitM) scanning DSRC channel"
	     << " pos(" << std::fixed << std::setprecision(1) << atk_px << "," << atk_py << ")"
	     << " t=" << t << endl;

	for (uint32_t vid = 0; vid < (uint32_t)N_Vehicles; vid++) {
		if (intercepted >= N_intercept) break;

		uint32_t victim_nid = vid + 2;
		if (victim_nid == attacker_nid) continue;   // skip self
		if (sybil_mitm_nodes[vid]) continue;         // only intercept honest vehicles

		// ── Step ②: Intercept — read victim's real beacon from NS-3 mobility model
		// In real DSRC, all 802.11p broadcasts are receivable by nearby nodes.
		// In NS-3 we read MobilityModel directly (equivalent to overhearing the frame).
		Ptr<Node> victim_node = NodeList::GetNode(victim_nid);
		if (!victim_node) continue;
		Ptr<MobilityModel> vic_mob = victim_node->GetObject<MobilityModel>();
		if (!vic_mob) continue;

		Vector vic_pos = vic_mob->GetPosition();
		Vector vic_vel = vic_mob->GetVelocity();

		// DSRC range guard: attacker must be within R_max_comm of victim
		double dx = atk_px - vic_pos.x;
		double dy = atk_py - vic_pos.y;
		double dist = std::sqrt(dx*dx + dy*dy);
		if (dist > R_max_comm) continue;

		double real_spd = std::sqrt(vic_vel.x*vic_vel.x + vic_vel.y*vic_vel.y);
		double real_hdg = (real_spd > 1e-6) ? std::atan2(vic_vel.y, vic_vel.x) : 0.0;

		// [A6-STEP2] Attacker observed victim's identity and mobility format
		uint32_t av = (attacker_vid < (uint32_t)MAX_NODES) ? attacker_vid : 0u;
		uint32_t vv = (vid          < (uint32_t)MAX_NODES) ? vid          : 0u;
		step_count[av][vv]++;
		uint32_t step = step_count[av][vv];

		// ── Step ③: Fabricate forged mobility report ─────────────────────────────
		//
		// Speed — progressive escalation over simulation time:
		//   Phase 1 (t < 5 s): mild elevation (×1.3–1.7) — "realistic" range,
		//                       attacker mimics normal driving while building cover
		//   Phase 2 (t ≥ 5 s): ramps to ×2.5–3.0 to reliably exceed D_KL > κ_th
		// This models the paper's "multiple time steps to mimic normal driving".
		double phase    = std::min(t / 5.0, 1.0);    // 0→1 over first 5 seconds
		double base_amp = 1.3 + poisoning_intensity_theta * 0.4;  // 1.3 – 1.7×
		double peak_amp = 2.5 + poisoning_intensity_theta * 0.5;  // 2.5 – 3.0×
		double amp      = base_amp + (peak_amp - base_amp) * phase;
		double mitm_spd = real_spd * amp;
		// Hard floor: ensures D_KL > κ_th=1.5 even if real_spd is very low.
		// With regional mean ≈ 15 m/s, detection fires when mitm_spd > 42.5 m/s.
		double spd_floor = 35.0 + poisoning_intensity_theta * 10.0;
		if (mitm_spd < spd_floor) mitm_spd = spd_floor;

		// Location — small realistic GPS-level drift (±10–25 m):
		//   Paper: "modifying attributes such as location … keeping values realistic"
		//   Effect: pos passes basic range/format checks but accumulates positioning error
		double drift_scale = (0.10 + 0.10 * poisoning_intensity_theta);
		double fake_px = vic_pos.x + drift_scale * max_position_deviation
		                           * std::sin(t * 0.9 + (double)vid);
		double fake_py = vic_pos.y + drift_scale * max_position_deviation
		                           * std::cos(t * 0.7 + (double)vid);

		// Acceleration — positive value consistent with the speed escalation trend:
		//   Reporting positive acceleration alongside elevated speed makes the
		//   fabricated trajectory coherent; otherwise a_i(t) = 0 with high v looks odd.
		double fake_acc = poisoning_intensity_theta * 0.35 * a_max
		                * (1.0 + 0.2 * std::sin(t * 1.3 + (double)vid));

		// ── Stealth regime (--mitm_stealth=1, default OFF) ───────────────────────
		// The abrupt values above are kinematically IMPOSSIBLE: spd_floor (35-45 m/s)
		// exceeds s_max=33.33, and the position drift (0.10-0.20 x 50 m = 5-10 m per
		// beacon) exceeds the s_max*T_b = 3.33 m gate. Measured consequence: the psi
		// rule tier flags 100% of forged beacons on the speed bound alone, so the HMAC
		// gate is fully redundant and AB2 cannot show its contribution.
		//
		// The stealth regime is the paper's own gamma=1.0 case (Eq 3.5,
		// epsilon_max_stealth = 0.5 m < 3.33 m gate). Every perturbation stays INSIDE
		// the kinematic feasibility envelope, so psi cannot fire — the modification is
		// physically plausible and only the cryptographic MAC check can detect it.
		// This makes the adversary STRONGER, not weaker; it is the honest threat model
		// for "HMAC is the only mechanism that catches in-transit modification".
		if (g_mitm_stealth) {
			// Speed: modest perturbation, hard-capped below s_max so the speed-bound
			// signature cannot trip. No spd_floor.
			mitm_spd = real_spd * (1.0 + 0.25 * poisoning_intensity_theta);
			const double spd_cap = 0.90 * s_max;
			if (mitm_spd > spd_cap) mitm_spd = spd_cap;
			// Position: drift accumulates over interception steps, but each beacon's
			// increment is epsilon_max_stealth (0.5 m) — well under the per-beacon gate.
			// Cumulative offset is what poisons the trajectory; the per-step delta is
			// what keeps it invisible to the rule tier.
			double drift = epsilon_max_stealth * (double)step;
			if (drift > max_position_deviation) drift = max_position_deviation;
			fake_px = vic_pos.x + drift * std::sin(t * 0.9 + (double)vid);
			fake_py = vic_pos.y + drift * std::cos(t * 0.7 + (double)vid);
			// Acceleration: keep well inside a_max so the accel signature stays quiet.
			fake_acc = 0.10 * a_max;
		}

		// ── Step ④: Forward poisoned packet to RSU under victim's identity ────────
		double mitm_ts = t + 0.005 * (intercepted + 1);

		BsmBeaconTag mitm_tag;
		mitm_tag.SetVehicleId(victim_nid);          // ← victim's identity (preserved)
		mitm_tag.SetPosition(fake_px, fake_py);     // ← slight location drift
		mitm_tag.SetSpeed(mitm_spd);                // ← progressively escalated speed
		mitm_tag.SetHeading(real_hdg);              // ← victim's real heading (believable)
		mitm_tag.SetAcceleration(fake_acc);         // ← positive accel (coherent with spd)
		// Stagger timestamp: 5ms per victim so RSU sees distinct receive events
		mitm_tag.SetTimestamp(mitm_ts);
		mitm_tag.SetIsPoisoned(true);
		mitm_tag.SetAttackType(6);
		mitm_tag.SetSigViolated(0);

		// ── Faithful in-transit modification (--faithful_mitm=1, default OFF) ────
		// Legacy behaviour sends an UNAUTHENTICATED beacon to the attacker's own
		// RSU. It is discarded by the RSU geographic filter before the HMAC gate
		// (claimed victim position maps to a different RSU zone), so HMAC never
		// sees the attack. Both defects are corrected here:
		//   (1) attach the victim's MAC computed over the victim's ORIGINAL
		//       kinematics; the payload above is already the MODIFIED content, so
		//       lkh_verify_beacon_hmac() recomputes over the forged values and the
		//       MAC mismatches → in-transit modification is detected (HMAC-FAIL).
		//       K_i is never disclosed to the attacker: it replays the captured
		//       MAC, it cannot mint a fresh valid one.
		//   (2) address the relayed frame to the RSU serving the CLAIMED position
		//       so it survives the geographic filter, as a real MitM relaying into
		//       the victim's neighbourhood would.
		if (g_faithful_mitm) {
			int vic_idx = lkh_veh_idx(victim_nid);
			if (vic_idx >= 0 && vic_idx < LKH_MAX_VEH) {
				uint8_t stale_mac[LKH_HMAC_TRUNC];
				// Sign the victim's UNMODIFIED kinematics (pre-tamper state).
				lkh_compute_beacon_hmac(vic_idx,
				                        vic_pos.x, vic_pos.y,
				                        real_spd, real_hdg, 0.0,
				                        mitm_ts, victim_nid, stale_mac);
				mitm_tag.SetHmac(stale_mac);
			}
		}

		Ptr<Packet> mitm_pkt = Create<Packet>(0);
		mitm_pkt->AddPacketTag(mitm_tag);
		lte_total_packet_size += mitm_pkt->GetSerializedSize();
		g_bwo_base_bytes += mitm_tag.GetSerializedSize() - 8;   // C8 BWO
		g_bwo_hmac_bytes += 8;

		Ipv4Address mitm_dest = dest_ip;
		uint16_t mitm_port = g_option_b_active ? 6666 : 7777;
		if (g_faithful_mitm && g_option_b_active && g_num_active_rsus > 0) {
			uint32_t claim_rsu = nearest_rsu_for_position(fake_px, fake_py);
			if (claim_rsu < (uint32_t)g_num_active_rsus)
				mitm_dest = g_rsu_dsrc_ip[claim_rsu];
		}
		Simulator::Schedule(Seconds(0.005 * (intercepted + 1)),
		                    &SimpleUdpApplication::SendPacket,
		                    udp_app, mitm_pkt, mitm_dest, mitm_port);

		// TPE: speed-displacement proxy for MitM injection beacons (speed error × T_b)
		// TDEE is computed at management node via density counts; no send-side accumulation.
		double spd_err = std::fabs(mitm_spd - real_spd) * T_b;
		tpe_sq_sum += spd_err * spd_err;
		tpe_cnt++;

		cout << "[A6-STEP4] V" << attacker_nid << " → RSU forged beacon"
		     << " claiming V" << victim_nid
		     << " pos(" << std::fixed << std::setprecision(1) << fake_px << "," << fake_py << ")"
		     << " real_spd=" << real_spd
		     << " mitm_spd=" << mitm_spd
		     << " fake_acc=" << std::setprecision(2) << fake_acc
		     << " step#" << step
		     << " dist=" << std::setprecision(1) << dist << "m" << endl;

		// Log interception event to dedicated MitM CSV (Step 2→4 record)
		log_mitm_intercept(t, attacker_nid, victim_nid,
		                   vic_pos.x, vic_pos.y, real_spd, real_hdg,
		                   fake_px, fake_py, mitm_spd, fake_acc,
		                   dist, (int)step);

		intercepted++;
	}
}

