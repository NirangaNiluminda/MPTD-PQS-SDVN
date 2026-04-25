// ============================================================
// SECTION 9: LTE Uplink/Downlink Send Functions (MPTD-PQS)
// ============================================================
// send_LTE_metadata_uplink_alone() — Vehicle sends BsmBeaconTag
//   payload to management node via LTE uplink (replaces legacy
//   25-variant CustomMetaDataUnicastTag switch).
// All other routing-mode LTE functions are stubbed (never called
// when routing_test=true).
// ============================================================

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
			// Apply trajectory poisoning (Algorithm 1, §3.3.1)
			Vector fpos(real_px, real_py, 0.0);
			double vx = real_spd * std::cos(real_hdg);
			double vy = real_spd * std::sin(real_hdg);
			Vector fvel(vx, vy, 0.0);
			Vector facc(0.0, 0.0, 0.0);
			PoisonTrajectory(fpos, fvel, facc, poisoning_intensity_theta);
			EnforceRealism(fpos, fvel, facc);
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
