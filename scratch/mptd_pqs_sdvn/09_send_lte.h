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

	// Build BsmBeaconTag from latest vehicle_state entry
	BsmBeaconTag tag;
	VehicleBeaconState &vs = vehicle_state[vid];
	uint32_t h = vs.head; // index of most-recent entry
	tag.SetVehicleId(nid);
	tag.SetPosition(vs.pos_x[h], vs.pos_y[h]);
	tag.SetSpeed(vs.speed[h]);
	tag.SetHeading(vs.heading[h]);
	tag.SetAcceleration(vs.accel[h]);
	tag.SetTimestamp(Simulator::Now().GetSeconds());
	// is_malicious flag comes from vehicle_state (set by 06_mrtpa_attack.h)
	tag.SetIsPoisoned(vs.is_malicious);
	tag.SetAttackType(static_cast<uint32_t>(attack_number)); // global from 02_config_globals.h
	tag.SetSigViolated(0); // sig_violated is set by the detector (08_beacon_handlers.h)

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
