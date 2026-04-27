// ============================================================
// SECTION 9: LTE Uplink/Downlink Send Functions (MPTD-PQS)
// ============================================================
// send_LTE_metadata_uplink_alone() — Vehicle sends BsmBeaconTag
//   payload to management node via LTE uplink (replaces legacy
//   25-variant CustomMetaDataUnicastTag switch).
// All other routing-mode LTE functions are stubbed (never called
// when routing_test=true).
// ============================================================

// Forward declaration — inject_mp_s2_stolen_beacons() is defined later in this file
// (after send_LTE_metadata_uplink_alone which calls it).
void inject_mp_s2_stolen_beacons(Ptr<SimpleUdpApplication>, uint32_t,
                                  double, double, double, double, double, Ipv4Address);

bool routing_time = false;
double average_cost = 0.0;
double average_lte_utilization = 0.0;
double average_ethernet_utilization = 0.0;
double average_dsrc_utilization = 0.0;
double average_computational_complexity = 0.0;
double average_routing_latency = 0.0;
double average_latency = 0.0;
double average_latency_dsrc = 0.0;


void clear_solution()
{
	for (int i = 0; i < (total_size+2); i++)
	{
		Z_gurobi[i] = 1;
		X_gurobi[i] = 1;
		Z_nodes[i] = 1;
		X_nodes[i] = 1;
	}
}


// ── Vehicle → Management Node: beacon state via LTE uplink ──────────────────
// Replaces legacy 25-variant switch(size){case 0:..case 25:}.
// Sends a BsmBeaconTag packet carrying the vehicle's latest
// position, speed, heading, acceleration, and attack state.
void send_LTE_metadata_uplink_alone(Ptr<SimpleUdpApplication> udp_app,
                                    Ptr<Node> node_source,
                                    Ptr<Node> destination_node,
                                    uint32_t node_index)
{
	Ptr<Ipv4> ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(2, 0); // LTE uplink interface
	Ipv4Address dest_ip = iaddr.GetLocal();

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
		is_mal = location_malicious_nodes[vid]
		      || flooding_malicious_nodes[vid]
		      || fabrication_malicious_nodes[vid]
		      || MIM_malicious_nodes[vid]
		      || vanishing_malicious_nodes[vid];

		tx_px = real_px;  tx_py = real_py;
		tx_spd = real_spd; tx_hdg = real_hdg; tx_acc = real_acc;

		if (is_mal) {
			// ── MP-S2 Vanishing: suppress beacon on alternate calls (50% drop) ──
			// Vehicle appears to "vanish" from the network intermittently.
			// Effect: poisoned beacons are never received → FN rate increases.
			if (vanishing_malicious_nodes[vid]) {
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
			// Attack 3 (TP-S3 Fabrication) deliberately injects values ABOVE
			// physical limits — the attacker fabricates impossible acceleration.
			// Applying EnforceRealism would clamp it back, defeating TP-S3 detection.
			// All other attacks maintain plausible-looking trajectories.
			if (attack_number != 3) {
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
	tag.SetSigViolated(0); // sig_violated set by detector (08_beacon_handlers.h)

	Ptr<Packet> packet1 = Create<Packet>(0);
	packet1->AddPacketTag(tag);
	lte_total_packet_size += packet1->GetSerializedSize();
	Simulator::Schedule(Seconds(0), &SimpleUdpApplication::SendPacket,
	                    udp_app, packet1, dest_ip, 7777);

	cout << "[LTE-UP] node " << nid << " BsmBeacon sent at "
	     << Simulator::Now().GetSeconds() << endl;

	// ── MP-S2 Attack Injection (§3.4.2, Figure 3.5) ─────────────────────────────
	// Attack model defined in 06_mrtpa_attack.h (declare_attack_states, attack_number==4).
	// Execution: malicious vehicle calls inject_mp_s2_stolen_beacons() to send
	// extra beacon packets claiming stolen vehicle identities at this vehicle's position.
	if (attack_number == 4 && is_mal)
		inject_mp_s2_stolen_beacons(udp_app, nid, tx_px, tx_py,
		                             tx_spd, tx_hdg, tx_acc, dest_ip);
}

// ── inject_mp_s2_stolen_beacons() — MP-S2 identity theft beacon injection ────
// Paper §3.4.2 (Figure 3.5): Malicious vehicle transmits N_stolen additional
// beacons per interval, each claiming to be a different honest vehicle's ID
// but carrying the attacker's own current position. This causes the RSU to
// record the same honest vehicle ID appearing simultaneously at two impossible
// locations → triggers MP-S4 ghost-transit-impossibility check (§3.4.4).
//
// Attack model definition: 06_mrtpa_attack.h → declare_attack_states() case 4
// Detection logic:         08_beacon_handlers.h → run_syb_detect() bit 3 (MP-S4)
void inject_mp_s2_stolen_beacons(Ptr<SimpleUdpApplication> udp_app,
                                  uint32_t attacker_nid,
                                  double tx_px, double tx_py,
                                  double tx_spd, double tx_hdg, double tx_acc,
                                  Ipv4Address dest_ip)
{
	static const int N_stolen = 2; // identities stolen per beacon interval (paper §3.4.2)
	int stolen_count = 0;

	for (uint32_t other_nid = 2;
	     other_nid < (uint32_t)(N_Vehicles + 2) && stolen_count < N_stolen;
	     other_nid++)
	{
		if (other_nid == attacker_nid) continue; // don't steal own ID
		uint32_t other_vid = other_nid - 2;
		if (MIM_malicious_nodes[other_vid]) continue; // only steal from honest vehicles

		BsmBeaconTag fake_tag;
		fake_tag.SetVehicleId(other_nid);           // stolen identity
		fake_tag.SetPosition(tx_px, tx_py);         // attacker's real position
		fake_tag.SetSpeed(tx_spd);
		fake_tag.SetHeading(tx_hdg);
		fake_tag.SetAcceleration(tx_acc);
		fake_tag.SetTimestamp(Simulator::Now().GetSeconds());
		fake_tag.SetIsPoisoned(true);               // impersonation beacon = poisoned
		fake_tag.SetAttackType(4);
		fake_tag.SetSigViolated(0);

		Ptr<Packet> fake_pkt = Create<Packet>(0);
		fake_pkt->AddPacketTag(fake_tag);
		lte_total_packet_size += fake_pkt->GetSerializedSize();

		// Stagger 5ms per stolen beacon so RSU sees distinct receive events
		Simulator::Schedule(Seconds(0.005 * (stolen_count + 1)),
		                    &SimpleUdpApplication::SendPacket,
		                    udp_app, fake_pkt, dest_ip, 7777);

		cout << "[MP-S2-SYB] V" << attacker_nid << " impersonating V" << other_nid
		     << " at pos(" << tx_px << "," << tx_py << ")" << endl;
		stolen_count++;
	}
}


// ── Routing-mode stubs (never called when routing_test=true) ────────────────

void send_LTE_metadata_downlink_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>, uint32_t) {}

void send_LTE_deltavalues_downlink_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>, uint32_t) {}

void compute_controller_packet_out_cryptography(uint32_t, uint32_t, uint32_t) {}

void send_LTE_LLDP_packetout_downlink_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, uint32_t, uint32_t, uint32_t) {}

void RSU_deltavalues_downlink_unicast(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>) {}

void RSU_metadata_uplink_unicast(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>) {}

// ── IDS send-flag array (used in MacRx routing path) ────────────────────────
bool sent_IDS[2*flows][total_size][Flow_size+2];

void RSU_metadata_downlink_unicast(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>) {}
