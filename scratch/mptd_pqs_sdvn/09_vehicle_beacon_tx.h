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
	uint32_t vid = (nid >= 2) ? (nid - 2) : 0; // vehicle_state[] index

	if (nid == 2)
	{
		lte_total_packet_size = 0;
		lte_initial_timestamp = Simulator::Now().GetSeconds();
	}

	// ── Read NS-3 MobilityModel → compute beacon payload ───────────────────
	// NOTE: we do NOT push to vehicle_state[] at send time.
	// vehicle_state[nid] is populated ONLY by HandleBeaconReceived() on the
	// RSU receive side. This avoids the send-vs-receive index collision
	// (send side would use vid=nid-2, receive side uses nid directly).
	double tx_px = 0.0, tx_py = 0.0, tx_spd = 0.0, tx_hdg = 0.0, tx_acc = 0.0;
	double real_px = 0.0, real_py = 0.0;
	bool   is_mal  = false;
	{
		Ptr<MobilityModel> mob = node_source->GetObject<MobilityModel>();
		double real_spd = 0.0, real_hdg = 0.0, real_acc = 0.0;
		if (mob) {
			Vector pos = mob->GetPosition();
			Vector vel = mob->GetVelocity();
			real_px  = pos.x;
			real_py  = pos.y;
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
			nearest_rsu_idx = nearest_rsu_for_position(real_px, real_py);
			dest_ip   = g_rsu_dsrc_ip[nearest_rsu_idx];
			dest_port = 6666;
		} else {
			// Fallback: direct LTE to management_node interface 2
			Ptr<Ipv4> ipv4 = destination_node->GetObject<Ipv4>();
			dest_ip   = ipv4->GetAddress(2, 0).GetLocal();
			dest_port = 7777;
		}

		if (is_mal) {
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
			PoisonTrajectoryByType(fpos, fvel, facc, poisoning_intensity_theta,
			                       attack_number);
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
			if (attack_number != 6 && attack_number != 7 &&
			    !(attack_number == 3 && sybil_registration_pct > 0)) {
				EnforceRealism(fpos, fvel, facc);
			}
			tx_px  = fpos.x;
			tx_py  = fpos.y;
			tx_spd = std::sqrt(fvel.x * fvel.x + fvel.y * fvel.y);
			tx_hdg = (tx_spd > 1e-6) ? std::atan2(fvel.y, fvel.x) : 0.0;
			tx_acc = std::sqrt(facc.x * facc.x + facc.y * facc.y);
		}

		// Accumulate displacement error for TDEE / TPE metrics (§4.1.2)
		double dx = tx_px - real_px, dy = tx_py - real_py;
		double disp_err = std::sqrt(dx * dx + dy * dy);
		tdee_error_sum += disp_err;
		tdee_error_cnt++;
		if (is_mal) {
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
	tag.SetIsPoisoned(is_mal);
	tag.SetAttackType(static_cast<uint32_t>(attack_number));
	tag.SetSigViolated(0); // sig_violated set by detector (08_detection_engine.h)

	Ptr<Packet> packet1 = Create<Packet>(0);
	packet1->AddPacketTag(tag);
	lte_total_packet_size += packet1->GetSerializedSize();
	Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
	                    udp_app, packet1, dest_ip, dest_port);

	if (g_option_b_active) {
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
	if (attack_number == 4 && is_mal)
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
	if (attack_number == 6 && is_mal)
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
		// Timestamp = scheduled send time (not NOW) so that when the management node
		// pushes this beacon into vehicle_state[honest_vid], the stored timestamp
		// reflects the 5ms stagger and tdiff > 0 in the MP-S4 transit-impossibility
		// check (d/tdiff > s_max).  Using Now() here (same as the real vehicle's
		// beacon) would give tdiff=0 → guard fails → MP-S4 never fires on stolen beacon.
		fake_tag.SetTimestamp(Simulator::Now().GetSeconds() + 0.005 * (stolen_count + 1));
		fake_tag.SetIsPoisoned(true);               // impersonation beacon = poisoned
		fake_tag.SetAttackType(4);
		fake_tag.SetSigViolated(0);

		Ptr<Packet> fake_pkt = Create<Packet>(0);
		fake_pkt->AddPacketTag(fake_tag);
		lte_total_packet_size += fake_pkt->GetSerializedSize();

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

		// ── Step ④: Forward poisoned packet to RSU under victim's identity ────────
		BsmBeaconTag mitm_tag;
		mitm_tag.SetVehicleId(victim_nid);          // ← victim's identity (preserved)
		mitm_tag.SetPosition(fake_px, fake_py);     // ← slight location drift
		mitm_tag.SetSpeed(mitm_spd);                // ← progressively escalated speed
		mitm_tag.SetHeading(real_hdg);              // ← victim's real heading (believable)
		mitm_tag.SetAcceleration(fake_acc);         // ← positive accel (coherent with spd)
		// Stagger timestamp: 5ms per victim so RSU sees distinct receive events
		mitm_tag.SetTimestamp(t + 0.005 * (intercepted + 1));
		mitm_tag.SetIsPoisoned(true);
		mitm_tag.SetAttackType(6);
		mitm_tag.SetSigViolated(0);

		Ptr<Packet> mitm_pkt = Create<Packet>(0);
		mitm_pkt->AddPacketTag(mitm_tag);
		lte_total_packet_size += mitm_pkt->GetSerializedSize();

		uint16_t mitm_port = g_option_b_active ? 6666 : 7777;
		Simulator::Schedule(Seconds(0.005 * (intercepted + 1)),
		                    &SimpleUdpApplication::SendPacket,
		                    udp_app, mitm_pkt, dest_ip, mitm_port);

		// TDEE/TPE: use speed-displacement proxy (speed error × T_b = distance error)
		double spd_err = std::fabs(mitm_spd - real_spd) * T_b;
		tdee_error_sum += spd_err;
		tdee_error_cnt++;
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

