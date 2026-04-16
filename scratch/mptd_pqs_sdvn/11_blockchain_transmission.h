// ============================================================
// 11_blockchain_transmission.h
// MPTD-PQS: Blockchain Transmission + MPTD-PQS Core Functions
//
// Replaces 11_routing_blockchain_transmission.h (28,823 lines).
// Routing algorithms stubbed; legacy LTE agent code removed.
// ============================================================

// ── Forward declarations needed by stub function signatures ─────────────────
struct custom_struct { uint32_t p_size; uint32_t channel; uint32_t CW; };

// ── Routing-only stubs (never called when routing_test=true) ─────────────────
void run_port_based() {}
void run_normal_LLDP() {}
void run_pure_crypto() {}
void run_link_guard() {}
void run_proposed_LLDP() {}
void run_optimization_link_lifetime() {}
void run_optimization_subsequent() {}
void run_DNN_link_lifetime() {}
void run_DNN_delay() {}
void filter_flows() {}
void calculate_performance_evaluation_metricsLLDP() {}
void reset_LLDP_received_count() {}
void initialize_flow_counters() {}
void initiate_all_flows() {}
void begin_sending_LTE_data_agent() {}
void RSU_dataunicast_agent(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>) {}
void run_ECMP() {}
void run_DCMR() {}
void run_QRSDN() {}
void run_RLMR() {}
void dijkstra_stable(uint32_t) {}
void write_csv_results_routing() { std::cout << "[CSV] routing (stub)\n"; }
void write_csv_results_LLDP() {}
void calculate_average_latency_routing() {}
void calculate_average_packet_delivery_ratio_routing() {}
void calculate_average_packet_delivery_ratio_routingLLDP() {}
void calculate_average_jitter_routing() {}
void calculate_average_load_balance_routing() {}
void calculate_average_channel_utilization_routingLLDP() {}
void calculate_average_computation_complexity_routingLLDP() {}
void calculate_average_latency_routingLLDP() {}
void calculate_performance_evaluation_metrics() {}
void calculate_centralized_metrics() {}
void calculate_centralized_metrics_routing() {}
void calculate_distributed_metrics() {}
void calculate_aodv_metrics() {}
void calculate_hybrid_metrics_routing() {}
void calculate_aodv_latency() {}
void calculate_aodv_packet_delivery_ratio() {}
void calculate_normalized_mobility() {}
void calculate_network_contention() {}
void calculate_average_cost_with_solution() {}
void calculate_average_cost_without_solution() {}
void calculate_average_cost_without_solution_dsrc() {}
void calculate_average_latency() {}
void calculate_average_channel_utilization() {}
void calculate_packet_delivery_ratio() {}
void calculate_packet_delivery_ratio_dsrc() {}
void calculate_packet_delivery_ratio_dsrc_hybrid() {}
void calculate_average_latency_hybrid() {}
void calculate_average_latency_dsrc() {}
void calculate_average_channel_utilization_with_solution() {}
void calculate_percentage() {}
void transmit_solution() {}
void transmit_delta_values() {}
void convert_delay() {}
void convert_link_lifetimes_dsrc() {}
void convert_link_lifetimes() {}
void predict_DNN_link_lifetime() {}
void predict_DNN_delay() {}
void read_delay_from_csv() {}
void generate_linklifetime_matrix() {}
void generate_delay_matrix() {}
void write_distance_metrics() {}
void dijkstra(vector<vector<double>>, uint32_t) {}
void printPath(uint32_t) {}
void printSolution(int) {}
void update_stable(uint32_t, uint32_t) {}
void run_stable_path_finding(uint32_t) {}
void update_unstable(uint32_t, uint32_t) {}
void run_distance_path_finding(uint32_t) {}
void update_flows() {}
void read_lifetime_from_csv() {}
void run_optimization_first_time() {}
void run_HELLO() {}
void send_hybrid_packets(uint32_t) {}
void send_centralized_packets(uint32_t) {}
void send_distributed_packets(uint32_t) {}
void distributed_dsrc_data_broadcast(Ptr<NetDevice>, Ptr<Node>, uint32_t) {}
void dsrc_metadata_broadcast(Ptr<NetDevice>, Ptr<Node>, uint32_t) {}
void dsrc_metadata_broadcast_subsequent(Ptr<NetDevice>, Ptr<Node>, uint32_t) {}
void AODV_dataunicast_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>) {}
void hybrid_data_unicast_stub(Ptr<NetDevice>, Ptr<Node>, uint32_t, uint32_t) {}
void routing_dsrc_data_unicast(Ptr<NetDevice>, Ptr<Node>, uint32_t, uint32_t, struct custom_struct, uint32_t) {}
void compute_RandQ(uint32_t) {}
void print_RandQ() {}
void p2p_data_broadcast(Ptr<SimpleUdpApplication>, Ptr<Node>) {}
void p2p_metadata_broadcast(Ptr<SimpleUdpApplication>, Ptr<Node>) {}
void check_and_transmit(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, struct custom_struct) {}
void send_LTE_data_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>, uint32_t) {}
void send_LTE_data_agent(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>, uint32_t) {}
void send_LTE_routing_data_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>, uint32_t) {}
void RSU_routing_statusdataunicast_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>) {}
void RSU_flowdata_unicast_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>) {}
void call_testBC() {}
void Rx(std::string, Ptr<const Packet>, uint16_t, WifiTxVector, MpduInfo, SignalNoiseDbm, uint16_t) {}
void decrypt_routing_packet(uint32_t, uint32_t, uint32_t) {}
bool is_number(const std::string&) { return false; }
void proceed_routing_packet(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, CustomDataUnicastTag_Routing) {}
void check_delivery_and_retransmit(uint32_t, uint32_t, uint32_t, uint32_t, Time, struct custom_struct) {}
void updateTxop(uint32_t, uint32_t, uint32_t, uint32_t, bool, struct custom_struct) {}
void updateTxop_self(uint32_t, uint32_t, uint32_t, bool, struct custom_struct) {}
void proposed_check_link_state(uint32_t) {}

// ── Confusion matrix counters ─────────────────────────────────────────────────
uint32_t Expected0Actual0 = 0;
uint32_t Expected0Actual1 = 0;
uint32_t Expected1Actual0 = 0;
uint32_t Expected1Actual1 = 0;

// ── Jitter / latency globals ──────────────────────────────────────────────────
double previous_cumulative_jitter_ratio = 0.0;
double current_jitter_ratio = 0.0;
double previous_cumulative_latency = 0.0;
double average_jitter_routing = 0.0;
double current_load_imbalance = 0.0;
double current_load_balance = 0.0;
double average_load_balance = 0.0;
double previous_cumulative_load_imbalance = 0.0;

// ── Adjacency matrix globals ──────────────────────────────────────────────────
vector<vector<double>> I;
vector<vector<double>> D_old(total_size, vector<double>(total_size, 0.0));
vector<vector<double>> D(total_size, vector<double>(total_size, 0.0));
vector<vector<double>> old_adjacencyMatrix(total_size, vector<double>(total_size, 0.0));
vector<vector<double>> adjacencyMatrix;
vector<double> node_distance[total_size];
vector<double> exp_link_state[total_size];
vector<double> exp_link_state_difference[total_size];

// ── B/D/I 4D matrices ────────────────────────────────────────────────────────
vector<vector<vector<vector<double>>>> B_mat;
vector<vector<vector<vector<double>>>> D_mat;
vector<vector<vector<vector<double>>>> I_mat;

// Z_nodes / X_nodes: declared in 07_security.h — do NOT redeclare here

double R_max = 278;

// Forward declaration for vehicle_send_to_nearest_rsu
void centralized_dsrc_data_unicast(Ptr<Node>, uint32_t, uint32_t, uint32_t);

// ============================================================
// EXTRACTED FUNCTIONS (in source-file order)
// ── Routing-path structs (used inside MacRx routing branches; never reached in routing_test=true) ──
struct transmit_opportunity { Time last_set_timestamp[185][total_size]; bool busy[185][total_size]; uint32_t pending_packets[185][total_size]; };
struct transmit_opportunity txop_inst[2*flows];
struct packet_delivery { bool pending[185][Flow_size+2]; bool delivery[185][Flow_size+2]; uint32_t attempts[185][Flow_size+2]; };
struct pd_all { struct packet_delivery pd_inst[total_size]; };
struct pd_all pd_all_inst[2*flows];
uint32_t destination_counter[2*flows];
vector<vector<vector<tuple<double,uint32_t,uint32_t>>>> all_sorted_delta_next_hop_flow_size;

// ============================================================
vector<double> calculate_distance_to_each_node(uint32_t source_node)
{
	vector<double> x;
	/*
	Vector source_position = data_at_manager_inst[source_node].position;
	for (uint32_t index = 2; index < (total_size + 2); index++)
	{
		double dis = get_length(source_position, data_at_manager_inst[index].position);
		x.push_back(dis);
	}
	*/
	Ptr <Node> reference_node;
	Ptr <Node> other_node;
	if ((source_node-2) < N_Vehicles)
	{	
		reference_node = DynamicCast <Node> (Vehicle_Nodes.Get(source_node-2));
	}
	else
	{
		reference_node = DynamicCast <Node> (RSU_Nodes.Get(source_node-N_Vehicles-2));
	}
	
	Ptr<ConstantVelocityMobilityModel> mdl1 = DynamicCast <ConstantVelocityMobilityModel> (reference_node->GetObject<MobilityModel>());
        Vector posi_reference = mdl1->GetPosition();
        for (uint32_t index = 2; index < (total_size + 2); index++)
	{
		if ((index-2) < N_Vehicles)
		{	
			other_node = DynamicCast <Node> (Vehicle_Nodes.Get(index-2));
		}
		else
		{
			other_node = DynamicCast <Node> (RSU_Nodes.Get(index-N_Vehicles-2));
		}
		Ptr<ConstantVelocityMobilityModel> mdl2 = DynamicCast <ConstantVelocityMobilityModel> (other_node->GetObject<MobilityModel>());
        	Vector posi_other = mdl2->GetPosition();	
		double dis = get_length(posi_reference, posi_other);
		x.push_back(dis);
	}
       
	return x;
}
vector<double> calculate_distance_to_each_node_revised(uint32_t i)
{
	vector<double> x;
	cout<<"Calculating distance from "<<i<<endl;
    for (uint32_t index = 0; index < (total_size); index++)
	{	
		double dis;
		if((using_location_approximate[i] == true)&&(using_location_approximate[index] == true))
		{
			dis = get_length(location_approximate[i], location_approximate[index]);
		}
		else if(using_location_approximate[i] == true)
		{
			dis = get_length(location_approximate[i], last_true_location[index]);
		}
		else if(using_location_approximate[index] == true)
		{
			dis = get_length(last_true_location[i], location_approximate[index]);
		}
		else
		{
			dis = get_length(last_true_location[i], last_true_location[index]);
		}
		x.push_back(dis);
	}
       
	return x;
}
double unit_step(double number, double step)
{
	if(number <= step)
	{
		return 0.0;
	}
	else
	{
		return 1.0;
	}
}
vector<double> calculate_link_expectancy_to_each_node(vector<double> x)
{
	vector<double> y;
        for (uint32_t index = 0; index < size(x); index++)
	{
		double difference = R_max - x[index];
		double res = unit_step(difference, 0);
		y.push_back(res);
	}
	return y;
}
vector<double> calculate_link_expectancy_difference_each_node(vector<double> x, vector<double> y)
{
	vector<double> z;
        for (uint32_t index = 0; index < size(x); index++)
	{
		cout<<"D[i] is "<<y[index]<<endl;
		cout<<"D_old[i] is "<<x[index]<<endl;
		double difference = y[index] - x[index];
		z.push_back(difference);
	}
	return z;
}
void generate_adjacency_matrix()
{

	for(uint32_t i=0;i<total_size;i++)
	{
		//node_distance[i] = calculate_distance_to_each_node(i+2);
		node_distance[i] = calculate_distance_to_each_node_revised(i);
		cout<<"1"<<endl;	
		exp_link_state[i] = calculate_link_expectancy_to_each_node(node_distance[i]);
		cout<<"2"<<endl;
		exp_link_state_difference[i] = calculate_link_expectancy_difference_each_node(D_old[i], D[i]);
		cout<<"3"<<endl;
		
	}
	cout<<"1"<<endl;
	/*
	double large_new = large;
	node_distance[0] =  {0.0, 400.0, large_new, large_new, large_new, large_new, large_new, 800, large_new};
	node_distance[1] =  { 400.0, 0.0, 800.0, large_new, large_new, large_new, large_new, 1100, large_new};
	node_distance[2] =  { large_new, 800.0, 0.0, 700.0, large_new, 400.0, large_new, large_new, 200.0};
	node_distance[3] =  { large_new, large_new, 700.0, 0.0, 900.0, 1400.0, large_new, large_new, large_new};
	node_distance[4] =  { large_new, large_new, large_new, 900.0, 0.0, 1000.0, large_new, large_new, large_new};
	node_distance[5] =  { large_new, large_new, 400, large_new, 1000.0, 0.0, 200.0, large_new, large_new};
	node_distance[6]  =  { large_new, large_new, large_new, 1400.0, large_new, 200.0, 0.0, 100.0, 600.0};
	node_distance[7]  =  { 800.0, 1100.0, large_new, large_new, large_new, large_new, 100.0, 0.0, 700.0};
	node_distance[8]  =  { large_new, large_new, 2.0, large_new, large_new, large_new, 600.0, 700.0, 0.0};
	*/
	
	vector<vector<double>> new_adjacencyMatrix;
	vector<vector<double>> new_expLSMatrix;
	vector<vector<double>> I_new;
	cout<<"1"<<endl;
	for(uint32_t i=0;i<total_size;i++)
	//for(uint32_t i=0;i<9;i++)
	{
		new_adjacencyMatrix.push_back(node_distance[i]);
		new_expLSMatrix.push_back(exp_link_state[i]);
		I_new.push_back(exp_link_state_difference[i]);
	}
	adjacencyMatrix = new_adjacencyMatrix;
	D = new_expLSMatrix;
	I = I_new;
	cout<<"1"<<endl;
	/*	VISUALIZE ADJACENCY MATRIX-----------------------
	for (uint32_t i=0;i<total_size;i++)
	//for (uint32_t i=0;i<9;i++)
	{
		
		for (uint32_t j=0;j<total_size;j++)
		//for (uint32_t j=0;j<9;j++)
		{
			cout<<"distance from source node"<<(i)<<"to node "<<(j)<<"is "<<adjacencyMatrix[i][j]<<endl;
		}
	}
	*/
	cout<<"1"<<endl;
	old_adjacencyMatrix = adjacencyMatrix;
	cout<<"1"<<endl;
	D_old = D;		
	//cout<<"adjacency matrix size"<<adjacencyMatrix.size()<<endl;
	cout<<"adjacency matrix generated"<<"at timestampt "<<Now().GetSeconds()<<endl;
}
void generate_B_matrix()
{
	/*
	vector<double> B_temp[total_size];
	for(uint32_t i=0;i<total_size;i++)
	{
		for(uint32_t j=0;j<total_size;i++)
		{
			B_temp[i].push_back(0.0);	
		}
		
	}
	*/
	vector<vector<double>> B_init1(2, vector<double>(2, 0.0));
	vector<vector<double>> D_init1(2, vector<double>(2, 0.0));
	vector<vector<double>> I_init1(2, vector<double>(2, 0.0));
	vector<vector<vector<double>>> B_init2(total_size, B_init1);
	vector<vector<vector<double>>> D_init2(total_size, D_init1);
	vector<vector<vector<double>>> I_init2(total_size, I_init1);
	vector<vector<vector<vector<double>>>> B_temp(total_size, B_init2);
	vector<vector<vector<vector<double>>>> D_temp(total_size, D_init2);
	vector<vector<vector<vector<double>>>> I_temp(total_size, I_init2);
	
	for(uint32_t i=0;i<total_size;i++)
	//for(uint32_t i=0;i<9;i++)
	{
		B_mat.push_back(B_temp[i]);
		D_mat.push_back(D_temp[i]);
		I_mat.push_back(I_temp[i]);
	}
	
	
	/*	VISUALIZE ADJACENCY MATRIX-----------------------
	for (uint32_t i=0;i<total_size;i++)
	//for (uint32_t i=0;i<9;i++)
	{
		
		for (uint32_t j=0;j<total_size;j++)
		//for (uint32_t j=0;j<9;j++)
		{
			cout<<"distance from source node"<<(i)<<"to node "<<(j)<<"is "<<adjacencyMatrix[i][j]<<endl;
		}
	}
	*/
		
	//cout<<"adjacency matrix size"<<adjacencyMatrix.size()<<endl;
	cout<<"B matrix generated"<<"at timestamp "<<Now().GetSeconds()<<endl;
}
void initialize_bmatrix()
{
	for(uint32_t i=0;i<total_size; i++)
    {
		for(uint32_t j=0; j<total_size; j++)
		{
			for(uint32_t k=0; k<2; k++)
			{
				cout<<"Distance between nodes "<<i<<" and "<<j<<"is "<<adjacencyMatrix[i][j]<<endl;
				if(i != j)
				{
					B_mat[i][j][k][k] = unit_step(270 - adjacencyMatrix[i][j], 0);
					(Link_at_controller_inst+k)->Link_f_inst[0].Link_fi_inst[i].Link_values[j] = unit_step(270 - adjacencyMatrix[i][j], 0);
					(Link_at_controller_inst+k)->Link_f_inst[1].Link_fi_inst[i].Link_values[j] = unit_step(270 - adjacencyMatrix[i][j], 0);
					cout<<"Link state is "<<B_mat[i][j][k][k]<<endl;
				}
				else
				{
					B_mat[i][j][k][k] = 0;
					(Link_at_controller_inst+k)->Link_f_inst[0].Link_fi_inst[i].Link_values[j] = 0;
					(Link_at_controller_inst+k)->Link_f_inst[1].Link_fi_inst[i].Link_values[j] = 0;
					cout<<"Link state is "<<B_mat[i][j][k][k]<<endl;
				}
			}
		}
	}
	
}
void centralized_dsrc_data_unicast(Ptr <Node> source_node, uint32_t node_index, uint32_t destination, uint32_t port_id);

// ============================================================
// V2RSU GLOBAL FUNCTIONS
// find_nearest_rsu(): returns dsrc_Nodes index of the RSU
//   closest to a given vehicle. RSUs occupy dsrc_Nodes indices
//   [N_Vehicles .. N_Vehicles+N_RSUs-1].
// vehicle_send_to_nearest_rsu(): global entry point — vehicle
//   sends its trajectory packet to its nearest RSU via DSRC.
//   This is the standard communication path for ALL attack scenarios.
// ============================================================

uint32_t find_nearest_rsu(uint32_t vehicle_index) {
	if (N_RSUs == 0 || (N_Vehicles + N_RSUs) > dsrc_Nodes.GetN()) {
		cout << "[V2RSU] No RSUs available, fallback V2V for vehicle " << vehicle_index << endl;
		return vehicle_index; // fallback: no RSUs
	}
	Ptr<MobilityModel> vmdl = dsrc_Nodes.Get(vehicle_index)->GetObject<MobilityModel>();
	Vector vpos = vmdl->GetPosition();

	uint32_t best_rsu_dsrc_idx = N_Vehicles;
	double   best_dist = 1e18;
	for (uint32_t r = 0; r < N_RSUs; r++) {
		uint32_t rsu_dsrc_idx = N_Vehicles + r;
		Ptr<MobilityModel> rmdl = dsrc_Nodes.Get(rsu_dsrc_idx)->GetObject<MobilityModel>();
		Vector rpos = rmdl->GetPosition();
		double dist = std::sqrt((vpos.x-rpos.x)*(vpos.x-rpos.x) +
		                        (vpos.y-rpos.y)*(vpos.y-rpos.y));
		if (dist < best_dist) {
			best_dist = dist;
			best_rsu_dsrc_idx = rsu_dsrc_idx;
		}
	}
	cout << "[V2RSU] Vehicle " << vehicle_index
	     << " nearest RSU dsrc_idx=" << best_rsu_dsrc_idx
	     << " (dist=" << best_dist << "m)"
	     << (trajectory_poisoning_malicious_nodes[best_rsu_dsrc_idx] ? " [MALICIOUS]" : " [HONEST]")
	     << endl;
	return best_rsu_dsrc_idx;
}
void vehicle_send_to_nearest_rsu(uint32_t vehicle_index, double scheduled_time) {
	if (N_RSUs == 0) return;
	uint32_t rsu_dsrc_idx = find_nearest_rsu(vehicle_index);
	Simulator::Schedule(
		Seconds(scheduled_time),
		centralized_dsrc_data_unicast,
		dsrc_Nodes.Get(vehicle_index), // source Ptr<Node>
		vehicle_index,                  // sender node_index
		rsu_dsrc_idx,                   // destination = nearest RSU dsrc index
		0                               // port_id = 0
	);
}
void encrypt_dsrc_data_unicast(uint32_t node_index, uint32_t destination, uint32_t port_id)
{
	 std::ostringstream oss6;
			   oss6 << " is_controller=true create_security_manager_con=true netsize=1 "
					<< " sign_FALCON=false verify_FALCON=false generate_FALCON=false "
					<< " encrypt_ASCON=false decrypt_ASCON=false generate_ASCON_key=false "
					<< " node_id="<< node_index << " port_id="  << port_id << " other_node_id=" << destination << ""
					<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false generate_own_aes_key=false "
					<< " encrypt_ECDH=false decrypt_ECDH=false "
					<< " sign_data=false verify_signature=false "
					<< " initiate_session1=false initiate_session2=false "
					<< " create_hmac_global=false "
					<< " encrypt_ECDH=false decrypt_ECDH=false "
					<< " create_hmac_set1=false create_hmac_set2=false "
					<< " verify_key_expiry=false is_node=false pid=1 "
					<< " get_rsa_keys=false encrypt_rsa=false set_aes_key_for_pair=false "
					<< " encrypt_controller_data=false decrypt_controller_data=false "
					<< " generate_global_HMAC_secret_key=false get_digital_public_key=false "
					<< " get_session_HMAC_1=false get_session_HMAC_2=false "
					<< " create_global_HMAC_node=false "
					<< " decrypt_rsa=false "
					<< " get_aes_keys=false "
					<< " encrypt_aes_node_pair=true decrypt_aes_node_pair=false "
					<< " message=" << node_index +port_id+destination << " signature=" << "" << " msg_type=2 ";
			   
			   std::string command_str6 = oss6.str();
			   Simulator::Schedule(Seconds(0), LDA_security, command_str6);
}
void calculate_HMAC_for_location(uint32_t node_index, uint32_t port_index, Vector posi)
{
	
	if(routing_algorithm == 4)
	{
	   std::ostringstream oss4;
	   oss4 << " is_controller=true create_security_manager_con=true netsize=1 "
			<< " node_id=" << node_index  << " port_id=" << port_index  << " other_node_id=" << 0<< " "
			<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
			<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
			<< " sign_data=false verify_signature=false initiate_session1=false "
			<< " initiate_session2=false create_hmac_global=true encrypt_ECDH=false "
			<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
			<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
			<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
			<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
			<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
			<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
			<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
			<< " message=" << static_cast<int>(posi.x) +static_cast<int>(posi.y)  << " ";
	    cout<<"location x is "<<static_cast<int>(posi.x)<<"location y is "<<static_cast<int>(posi.y)<<"for node "<<node_index<<endl;
	    
	    std::string command_str4 = oss4.str();
		Simulator::Schedule(Seconds(0), LDA_security, command_str4);
		
	}
	
}
void continue_data_broadcasting(Ptr <NetDevice> nd, Ptr <Node> node, uint32_t node_index, uint32_t port_index, Vector posi)
{
	routing_time = false;
	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node->GetObject<MobilityModel>());
	//uint32_t nid = node->GetId();
	Mac48Address dest = Mac48Address::GetBroadcast();
  	uint16_t protocolwave = 0x88dc;//ethertype for WAVE is set here.
	Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (nd);
	Ptr <Node> ni = DynamicCast <Node> (node);
	CustomDataTag tag;
	uint32_t nid = uint32_t(ni->GetId());
	packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	cout<<"DSRC data Broadcasting from node "<<nid<<endl;

	if((routing_algorithm == 5)&&(fabrication_malicious_nodes[node_index]))
	{
		nid = rand()%total_size + 2;
	}
	
	if((routing_algorithm == 5)&&(MIM_malicious_nodes[node_index]))
	{
		port_index = rand()%2;
	}
	Vector current_velocity = mdl->GetVelocity();
	double delta_t = data_transmission_period;
	Vector acceleration = calculate_acceleration(previous_velocity_dsrc[node_index],current_velocity,delta_t);
	Time ti = Seconds(Simulator::Now().GetSeconds());
	Ptr <Packet> packet_i = Create<Packet> (0);
	tag.SetNodeId(nid);
	tag.SetPortId(port_index);
	tag.SetPosition(posi);
	tag.SetVelocity(current_velocity);
	tag.SetAcceleration(acceleration);
	tag.SetTimestamp(ti);
	
	uint32_t size_nei = getNeighborsize((neighbordata_inst+nid));
	uint32_t neighborid[size_nei];
	for (uint32_t i=0;i<size_nei;i++)
	{
		neighborid[i] = large;
	}
	
	uint32_t j=0;
	for (uint32_t i=0;i<max;i++)
	{
		if ((((neighbordata_inst+nid)->neighborid[i]) != large) and (j<size_nei))
		{
			neighborid[j] = (neighbordata_inst+nid)->neighborid[i];
	  		j++;
	  	}
	}
	
	string HMAC_string;
	if(routing_algorithm == 4)
	{
		std::string filename_HMAC = NS3_ROOT "/analytics/data/security_global_HMAC_data.csv";
	    HMAC_string = read_other_other_item_from_csv(filename_HMAC, std::to_string(node_index),std::to_string(0), std::to_string(port_index), 3);
	}
	else
	{
		HMAC_string = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	}
	
	cout<<"HMAC global string is "<<HMAC_string<<endl;
	uint8_t * HMAC1 = new uint8_t[64];
	HexStringToBytes(HMAC_string, HMAC1, 64);
	tag.SetHMAC1(HMAC1);
	add_received_data_at_nodes(data_at_nodes_inst+nid, HMAC1, posi, current_velocity, acceleration, nid, neighborid, size_nei, 0);
	
	packet_i->AddPacketTag(tag);
	
	dsrc_total_packet_size = dsrc_total_packet_size/1000.0 + packet_i->GetSerializedSize();
	if(((routing_algorithm == 5)||(routing_algorithm==4))&&(!vanishing_malicious_nodes[node_index]))
	{
		Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);	
	}
	Ptr <Packet> packet_copy[6];
	if((routing_algorithm == 5)&&(flooding_malicious_nodes[node_index]))
	{
		
		for(uint32_t i=0;i<6;i++)
		{
			packet_copy[i] = packet_i->Copy();
			Simulator::Schedule (Seconds(0.010*i+0.010) , &WifiNetDevice::Send, wdi, packet_copy[i], dest, protocolwave);	
		}
	}
	cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
	previous_velocity_dsrc[node_index] = current_velocity;
	
}
void centralized_dsrc_data_broadcast(Ptr <NetDevice> nd, Ptr <Node> node, uint32_t node_index, uint32_t port_index)
{
	Ptr <NetDevice> nd_copy = wifidevices.Get(node_index);
	Ptr <Node> node_copy = DynamicCast <Node> (Vehicle_Nodes.Get(node_index));
	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node_copy->GetObject<MobilityModel>());
	Vector posi = mdl->GetPosition();
	cout<<"Location for node id "<<node_index<< " is "<<posi<<endl;
	srand(Simulator::Now().GetSeconds()+double(node_index));
	if(location_malicious_nodes[node_index])
	{
		posi.x = posi.x + rand()%100;
		posi.y = posi.y + rand()%100;
	
	} 
	Simulator::Schedule(Seconds(0.0001), calculate_HMAC_for_location, node_index, port_index, posi);
	Simulator::Schedule(Seconds(0.00025), continue_data_broadcasting, nd_copy, node_copy, node_index, port_index, posi); 
}
void set_dsrc_initial_timestamp()
{
	dsrc_initial_timestamp = Simulator::Now().GetSeconds();
}
void block_port(uint32_t cid, uint32_t nid, uint32_t pid)
{
	blocked_port_state[cid][nid][pid] =  true;	
}
void initialize_blockchain()
{
	cout<<"Initializing blockchain (Hyperledger Fabric test-network with CCAAS)"<<endl;
	const char* fabric_dir = FAB_ROOT "/test-network";
	const char* rest_api_dir = FAB_ROOT "/trajectory-rest-api";

	// Check if network is already running
	std::string check_cmd = "docker ps --filter name=peer0.org1 --format '{{.Names}}' 2>/dev/null";
	std::string result = execCmd(check_cmd);

	if (result.find("peer0.org1") != std::string::npos)
	{
		cout << "[BLOCKCHAIN] Fabric test-network already running." << endl;
	}
	else
	{
		cout << "[BLOCKCHAIN] Starting Fabric test-network..." << endl;
		// Bring down any existing network
		std::string cmd_down = "bash -c 'cd " + std::string(fabric_dir) + " && ./network.sh down'";
		system(cmd_down.c_str());

		// Bring up network with CA and create channel
		std::string cmd_up = "bash -c 'cd " + std::string(fabric_dir) + " && ./network.sh up createChannel -c mychannel -ca'";
		system(cmd_up.c_str());

		// Deploy trajectory chaincode via CCAAS
		std::string cmd_cc = "bash -c 'cd " + std::string(fabric_dir) + " && ./network.sh deployCCAAS -ccn trajectory -ccp ../trajectory-chaincode'";
		system(cmd_cc.c_str());
	}

	// Start REST API server if not already running
	std::string check_api = "curl -s http://localhost:3000/health 2>/dev/null";
	std::string api_result = execCmd(check_api);

	if (api_result.find("ok") != std::string::npos)
	{
		cout << "[BLOCKCHAIN] REST API already running on port 3000." << endl;
	}
	else
	{
		cout << "[BLOCKCHAIN] Starting REST API server..." << endl;
		std::string cmd_api = "bash -c 'cd " + std::string(rest_api_dir) + " && python3 server.py &'";
		system(cmd_api.c_str());
		// Wait for server to start
		sleep(2);
	}

	cout << "[BLOCKCHAIN] Initialization complete." << endl;
}
void declare_attack_states()
{
	if(attack_number == 6)//combined attack
	{
		present_location_attack_nodes = true;
		present_flooding_attack_nodes = true;
		present_fabrication_attack_nodes = true;
		present_MIM_attack_nodes = true;
		present_vanishing_attack_nodes = true;

		if(controller_malicious_assumption == true)
		{
			present_flooding_attack_controllers = true;
			present_fabrication_attack_controllers = true;
			present_MIM_attack_controllers = true;
			present_vanishing_attack_controllers = true;	
		}
	}
	
	else if(attack_number ==1)//Attack 1
	{
		present_location_attack_nodes = true;
		present_flooding_attack_nodes = false;
		present_fabrication_attack_nodes = false;
		present_MIM_attack_nodes = false;
		present_vanishing_attack_nodes = false;
		if(controller_malicious_assumption == true)
		{
			present_flooding_attack_controllers = true;
		}
		present_fabrication_attack_controllers = false;
		present_MIM_attack_controllers = false;
		present_vanishing_attack_controllers = false;	
	}
	
	else if(attack_number ==2)//Attack 2
	{
		present_location_attack_nodes = false;
		present_flooding_attack_nodes = true;
		present_fabrication_attack_nodes = false;
		present_MIM_attack_nodes = false;
		present_vanishing_attack_nodes = false;

		if(controller_malicious_assumption == true)
		{
			present_flooding_attack_controllers = true;
		}
		present_fabrication_attack_controllers = false;
		present_MIM_attack_controllers = false;
		present_vanishing_attack_controllers = false;	
	}
	
	else if(attack_number ==3)//Attack 3
	{
		present_location_attack_nodes = false;
		present_flooding_attack_nodes = false;
		present_fabrication_attack_nodes = true;
		present_MIM_attack_nodes = false;
		present_vanishing_attack_nodes = false;

		present_flooding_attack_controllers = false;
		if(controller_malicious_assumption == true)
		{
			present_fabrication_attack_controllers = true;
		}
		present_MIM_attack_controllers = false;
		present_vanishing_attack_controllers = false;	
	}
	
	else if(attack_number ==4)//Attack 4
	{
		present_location_attack_nodes = false;
		present_flooding_attack_nodes = false;
		present_fabrication_attack_nodes = false;
		present_MIM_attack_nodes = true;
		present_vanishing_attack_nodes = false;

		present_flooding_attack_controllers = false;
		present_fabrication_attack_controllers = false;
		if(controller_malicious_assumption == true)
		{
			present_MIM_attack_controllers = true;
		}
		present_vanishing_attack_controllers = false;	
	}
	
	else if(attack_number ==5)//Attack 5
	{
		present_location_attack_nodes = false;
		present_flooding_attack_nodes = false;
		present_fabrication_attack_nodes = false;
		present_MIM_attack_nodes = false;
		present_vanishing_attack_nodes = true;

		present_flooding_attack_controllers = false;
		present_fabrication_attack_controllers = false;
		present_MIM_attack_controllers = false;
		if(controller_malicious_assumption == true)
		{
			present_vanishing_attack_controllers = true;
		}
	}

	// Store attack configuration flags to blockchain
	if (routing_algorithm == 4)
	{
		StoreAttackConfigToBlockchain(
			attack_number,
			present_location_attack_nodes,
			present_flooding_attack_nodes,
			present_fabrication_attack_nodes,
			present_MIM_attack_nodes,
			present_vanishing_attack_nodes,
			present_flooding_attack_controllers,
			present_fabrication_attack_controllers,
			present_MIM_attack_controllers,
			present_vanishing_attack_controllers,
			controller_malicious_assumption
		);
	}
}
void declare_attackers()
{
	
	for(uint32_t i=0;i<total_size;i++)
	{
		bool attacking_state = GetBooleanWithProbability(attack_percentage, i);
		if (present_location_attack_nodes == true)
		{
			location_malicious_nodes[i] = attacking_state;
		}
		else if (present_location_attack_nodes == false)
		{
			location_malicious_nodes[i] = false;
		}
		//cout<<"Location malicious state of node "<<i<<" is "<<location_malicious_nodes[i]<<endl;
		
		if (present_flooding_attack_nodes == true)
		{
			flooding_malicious_nodes[i] = attacking_state;
		}
		else if (present_flooding_attack_nodes == false)
		{
			flooding_malicious_nodes[i] = false;
		}
		//cout<<"Flooding malicious state of node "<<i<<" is "<<flooding_malicious_nodes[i]<<endl;
		
		if (present_fabrication_attack_nodes == true)
		{
			fabrication_malicious_nodes[i] = attacking_state;
		}
		else if (present_fabrication_attack_nodes == false)
		{
			fabrication_malicious_nodes[i] = false;
		}
		//cout<<"Fabrication malicious state of node "<<i<<" is "<<fabrication_malicious_nodes[i]<<endl;
		
		if (present_MIM_attack_nodes == true)
		{
			MIM_malicious_nodes[i] = attacking_state;
		}
		else if (present_MIM_attack_nodes == false)
		{
			MIM_malicious_nodes[i] = false;
		}
		
		
		if (present_vanishing_attack_nodes == true)
		{
			vanishing_malicious_nodes[i] = attacking_state;
		}
		else if (present_vanishing_attack_nodes == false)
		{
			vanishing_malicious_nodes[i] = false;
		}

		// Store per-node attack state to blockchain
		if (routing_algorithm == 4)
		{
			StoreNodeAttackStateToBlockchain(
				i, attack_percentage,
				location_malicious_nodes[i],
				flooding_malicious_nodes[i],
				fabrication_malicious_nodes[i],
				MIM_malicious_nodes[i],
				vanishing_malicious_nodes[i],
				trajectory_poisoning_malicious_nodes[i]
			);
		}
	}

	if (present_flooding_attack_controllers == true)
	{
		if(attack_percentage < 10)
		{
			flooding_malicious_controllers[0] = false;
			flooding_malicious_controllers[1] = false;
			flooding_malicious_controllers[2] = false;
			flooding_malicious_controllers[3] = false;
			
		}
		else if (attack_percentage < 35)
		{
			flooding_malicious_controllers[0] = true;
			flooding_malicious_controllers[1] = false;
			flooding_malicious_controllers[2] = false;
			flooding_malicious_controllers[3] = false;
		}
		else if (attack_percentage < 67)
		{
			flooding_malicious_controllers[0] = true;
			flooding_malicious_controllers[1] = true;
			flooding_malicious_controllers[2] = false;
			flooding_malicious_controllers[3] = false;
		}
		else if (attack_percentage < 101)
		{
			flooding_malicious_controllers[0] = true;
			flooding_malicious_controllers[1] = true;
			flooding_malicious_controllers[2] = true;
			flooding_malicious_controllers[3] = false;
		}
	}
	else if (present_flooding_attack_controllers == false)
	{
		flooding_malicious_controllers[0] = false;
		flooding_malicious_controllers[1] = false;
		flooding_malicious_controllers[2] = false;
		flooding_malicious_controllers[3] = false;
	}
	
	
	if (present_fabrication_attack_controllers == true)
	{
		if(attack_percentage<10)
		{
			fabrication_malicious_controllers[0] = false;
			fabrication_malicious_controllers[1] = false;
			fabrication_malicious_controllers[2] = false;
			fabrication_malicious_controllers[3] = false;
		}
		else if (attack_percentage<35)
		{
			fabrication_malicious_controllers[0] = true;
			fabrication_malicious_controllers[1] = false;
			fabrication_malicious_controllers[2] = false;
			fabrication_malicious_controllers[3] = false;
		}
		else if (attack_percentage<67)
		{
			fabrication_malicious_controllers[0] = true;
			fabrication_malicious_controllers[1] = true;
			fabrication_malicious_controllers[2] = false;
			fabrication_malicious_controllers[3] = false;
		}
		else if (attack_percentage<101)
		{
			fabrication_malicious_controllers[0] = true;
			fabrication_malicious_controllers[1] = true;
			fabrication_malicious_controllers[2] = true;
			fabrication_malicious_controllers[3] = false;
		}
		
		
	}
	else if (present_fabrication_attack_controllers == false)
	{
		fabrication_malicious_controllers[0] = false;
		fabrication_malicious_controllers[1] = false;
		fabrication_malicious_controllers[2] = false;
		fabrication_malicious_controllers[3] = false;
	}
	
	
	if (present_MIM_attack_controllers == true)
	{
		if(attack_percentage<10)
		{
			MIM_malicious_controllers[0] = false;
			MIM_malicious_controllers[1] = false;
			MIM_malicious_controllers[2] = false;
			MIM_malicious_controllers[3] = false;
		}
		else if (attack_percentage<35)
		{
			MIM_malicious_controllers[0] = true;
			MIM_malicious_controllers[1] = false;
			MIM_malicious_controllers[2] = false;
			MIM_malicious_controllers[3] = false;
		}
		else if (attack_percentage<67)
		{
			MIM_malicious_controllers[0] = true;
			MIM_malicious_controllers[1] = true;
			MIM_malicious_controllers[2] = false;
			MIM_malicious_controllers[3] = false;
		}
		
		else if (attack_percentage<101)
		{
			MIM_malicious_controllers[0] = true;
			MIM_malicious_controllers[1] = true;
			MIM_malicious_controllers[2] = true;
			MIM_malicious_controllers[3] = false;
		}		
		
		
	}
	else if (present_MIM_attack_controllers == false)
	{
		MIM_malicious_controllers[0] = false;
		MIM_malicious_controllers[1] = false;
		MIM_malicious_controllers[2] = false;
		MIM_malicious_controllers[3] = false;
	}
	
	
	if (present_vanishing_attack_controllers == true)
	{
		if(attack_percentage<10)
		{
			vanishing_malicious_controllers[0] = false;
			vanishing_malicious_controllers[1] = false;
			vanishing_malicious_controllers[2] = false;
			vanishing_malicious_controllers[3] = false;
		}
		else if(attack_percentage<35)
		{
			vanishing_malicious_controllers[0] = true;
			vanishing_malicious_controllers[1] = false;
			vanishing_malicious_controllers[2] = false;
			vanishing_malicious_controllers[3] = false;
		}
		else if(attack_percentage<67)
		{
			vanishing_malicious_controllers[0] = true;
			vanishing_malicious_controllers[1] = true;
			vanishing_malicious_controllers[2] = false;
			vanishing_malicious_controllers[3] = false;
		}
		else if(attack_percentage<101)
		{
			vanishing_malicious_controllers[0] = true;
			vanishing_malicious_controllers[1] = true;
			vanishing_malicious_controllers[2] = true;
			vanishing_malicious_controllers[3] = false;
		}
		
	}
	else if (present_vanishing_attack_controllers == false)
	{
		vanishing_malicious_controllers[0] = false;
		vanishing_malicious_controllers[1] = false;
		vanishing_malicious_controllers[2] = false;
		vanishing_malicious_controllers[3] = false;
	}
}
void initialize_server()
{
	// Updated: use our Python REST API (server.py) instead of old Node.js app.js
	const char* rest_api_dir = FAB_ROOT "/trajectory-rest-api";

	// Check if REST API is already running
	std::string check_api = execCmd("curl -s http://localhost:3000/health 2>/dev/null");
	if (check_api.find("ok") != std::string::npos)
	{
		std::cout << "[SERVER] REST API already running on port 3000." << std::endl;
	}
	else
	{
		// Start the Python REST API server
		std::string cmd = "bash -c 'cd " + std::string(rest_api_dir) +
		                  " && nohup python3 server.py >> /tmp/restapi.log 2>&1 &'";
		system(cmd.c_str());
		// Give it 2 seconds to start
		::sleep(2);
		std::cout << "[SERVER] Python REST API started." << std::endl;
	}
	std::cout << "Server started" << endl;
}
std::string escapeQuotes(const std::string& input) {
    std::string out;
    for (char c : input) {
        if (c == '"') out += '\\';
        out += c;
    }
    return out;
}
void CallBWTRCBFromNS3(uint32_t nid, std::string controller) {
    uint32_t size = get_size_of_data_at_nodes(data_at_nodes_inst + nid);
    // Guard: VLA of size 0 is undefined behaviour → use at least 1
    uint32_t safe_size = (size > 0) ? size : 1;
    uint32_t nodeid[safe_size];
    uint32_t dup_cnt[safe_size];
    uint32_t fab_cnt[safe_size];
    uint32_t rep_cnt[safe_size];
    uint32_t mat_LLDP[safe_size];
    Vector position[safe_size];
    //bool rep_loc_true[size];

    for (uint32_t i = 0; i < size; i++) {
        position[i] = Vector(0, 0, 0);
        nodeid[i] = large;
    }

    uint32_t k = 0;
    for (uint32_t i = 0; i < max; i++) {
        if (((data_at_nodes_inst + nid)->nodeid[i] != large) && (k < size)) {
            nodeid[k] = (data_at_nodes_inst + nid)->nodeid[i];
            position[k] = (data_at_nodes_inst + nid)->position[i];
            dup_cnt[k] = duplicate_count[nid][i];
            fab_cnt[k] = fabricated_count[nid][i];
            rep_cnt[k] = replay_count[nid][i];
            mat_LLDP[k] = matched_LLDP[nid][i];
            //rep_loc_true[k] = reported_location_correct[nid][i];
            k++;
        }
    }

    std::string nodeId = "Node" + std::to_string(nid);

    std::string mat_LLDP_str = "[";
    std::string rep_loc_str = "[";
    std::string dup_cnt_str = "[";
    std::string fab_cnt_str = "[";
    std::string rep_cnt_str = "[";
    std::string neighbors_str = "[";
    std::string controller_str = "[";

	uint32_t matLLDP_sum = 0;
    for (uint32_t i = 0; i < size; i++)
    {
        // matched LLDP
        mat_LLDP_str += std::to_string(mat_LLDP[i]);
        matLLDP_sum += mat_LLDP[i];

        // reported location: [bool, x, y]
        rep_loc_str += "[" + std::to_string(position[i].x) + "," +
                       std::to_string(position[i].y) + "," +
                       std::to_string(position[i].z) + "]";

        // counts
        dup_cnt_str += std::to_string(dup_cnt[i]);
        fab_cnt_str += std::to_string(fab_cnt[i]);
        rep_cnt_str += std::to_string(rep_cnt[i]);

        // neighbors (endorsers)
  
		neighbors_str += "\"Node" + std::to_string(nodeid[i]) + "\"";

        if (i < size - 1) {
            mat_LLDP_str += ",";
            rep_loc_str += ",";
            dup_cnt_str += ",";
            fab_cnt_str += ",";
            rep_cnt_str += ",";
            neighbors_str += ",";
        }
    }
	controller_str += "\"" + controller + "\"";  // wrap in quotes for JSON.parse
	controller_str += "]";
	mat_LLDP_str += ",";
	mat_LLDP_str += std::to_string(matLLDP_sum);
    mat_LLDP_str += "]";
    rep_loc_str += "]";
    dup_cnt_str += "]";
    fab_cnt_str += "]";
    rep_cnt_str += "]";
    neighbors_str += "]";

    // Compose full curl command
std::string curlCmd =
    "curl -X POST \"http://localhost:3000/invoke/BWTRCB?user=peer1@org1\" \\\n"
    "-H \"Content-Type: application/json\" \\\n"
    "-d '{\"args\": [\"" + nodeId + "\",\n" +
    "\"" + mat_LLDP_str + "\",\n" +   // <--- add quotes around JSON array
    "\"" + rep_loc_str + "\",\n" +
    "\"" + dup_cnt_str + "\",\n" +
    "\"" + fab_cnt_str + "\",\n" +
    "\"" + rep_cnt_str + "\",\n" +
    "\"" + escapeQuotes(neighbors_str) + "\",\n" +
    "\"" + escapeQuotes(neighbors_str) + "\",\n" +
    "\"" + escapeQuotes(controller_str) + "\"\n" +   // keep this properly escaped
    "]}'";

    // Execute the curl command
    std::cout << "Executing:\n" << curlCmd << std::endl;
    system(curlCmd.c_str());
}
std::string extractControllerFromResult(const std::string &resultStr) {
    // First unescape the double-escaped JSON from REST API response
    // e.g. {\\\"result\\\":\\\"Controller maintained...\\\"} → {\"result\":\"Controller maintained...\"}
    std::string unescaped = resultStr;
    std::string from = "\\\"";
    std::string to = "\"";
    size_t startPos = 0;
    while ((startPos = unescaped.find(from, startPos)) != std::string::npos) {
        unescaped.replace(startPos, from.length(), to);
        startPos += to.length();
    }
    // Also remove leading/trailing backslashes if present
    if (!unescaped.empty() && unescaped.front() == '\\') unescaped = unescaped.substr(1);

    // Match both "Controller changed for consortium" and "Controller maintained for consortium"
    std::string pattern1 = "Controller changed for consortium";
    std::string pattern2 = "Controller maintained for consortium";
    size_t pos = unescaped.find(pattern1);
    if (pos == std::string::npos) pos = unescaped.find(pattern2);
    if (pos == std::string::npos) {
        // Fallback: try on original resultStr
        pos = resultStr.find("as: ");
        if (pos == std::string::npos) return "";
        pos += 4; // length of "as: "
        size_t endPos2 = resultStr.find_first_of(" \",\n\\", pos);
        if (endPos2 == std::string::npos) endPos2 = resultStr.length();
        return resultStr.substr(pos, endPos2 - pos);
    }

    // The controller name comes after "as: "
    std::string asPattern = "as: ";
    pos = unescaped.find(asPattern, pos);
    if (pos == std::string::npos) return "";

    pos += asPattern.length();
    // Read until the end of string or first quote/space/comma (controller names like C0, C1, C2)
    size_t endPos = unescaped.find_first_of(" \",\n\\", pos);
    if (endPos == std::string::npos) endPos = unescaped.length();

    return unescaped.substr(pos, endPos - pos);
}
void BCTES(uint32_t nid, uint32_t pid, std::string controller, std::string consortium) {

    uint32_t size = get_size_of_data_at_nodes(data_at_nodes_inst + nid);
    // Guard: VLA of size 0 is undefined behaviour → use at least 1
    uint32_t safe_size = (size > 0) ? size : 1;
    uint32_t exp_nodeid[safe_size];
    uint32_t rec_nodeid[safe_size];
    uint32_t pout_cnt[safe_size];
    
    for (uint32_t i = 0; i < size; i++) 
    {
        exp_nodeid[i] = large;
        rec_nodeid[i] = large;
        pout_cnt[i] = 0;
    }

    uint32_t k = 0;
    for (uint32_t i = 0; i < max; i++) 
    {
        if (((data_at_nodes_inst + nid)->nodeid[i] != large) && (k < size)) 
        {
            exp_nodeid[k] = (data_at_nodes_inst + nid)->nodeid[i];
            rec_nodeid[k] = (data_at_nodes_inst + nid)->nodeid[i];
            cout<<"Expected node id"<<exp_nodeid[k]<<endl;
            k++;
        }
    }

    std::string nodeId = "Node" + std::to_string(nid);
    std::string exp_nodeid_str = "[";
    std::string rec_nodeid_str = "[";
    std::string pout_str = "[";
    std::string controller_str = "";
    std::string consortium_str = "";

    uint32_t rid_size = 0;
    for (uint32_t i = 0; i < size; i++)
    {
        if(E_mat[nid-2][exp_nodeid[i]-2][pid] == 0)
        {
			pout_cnt[i] = 2*RL_iterations;
			
		}
		else
		{
			pout_cnt[i] = 0;
		}
  
		exp_nodeid_str += "\"Node" + std::to_string(exp_nodeid[i]) + "\"";
		if(routing_packet_initial_timestampLLDP[0][0][nid-2][exp_nodeid[i]-2] < routing_packet_final_timestampLLDP[0][0][nid-2][exp_nodeid[i]-2])
		{
			rec_nodeid_str += "\"Node" + std::to_string(rec_nodeid[i]) + "\"";
			pout_str += "\"" + std::to_string(pout_cnt[i]) + "\"";
			rid_size++;
		}
		
        if (i < size - 1) 
        {
			//if(E_mat[nid-2][exp_nodeid[i]-2][pid] == 0)
			if(routing_packet_initial_timestampLLDP[0][0][nid-2][exp_nodeid[i]-2] < routing_packet_final_timestampLLDP[0][0][nid-2][exp_nodeid[i]-2])
			{
				if((i < size -1)&&(size > 2))
				{
					pout_str += ",";
				}
			}
			if(routing_packet_initial_timestampLLDP[0][0][nid-2][exp_nodeid[i]-2] < routing_packet_final_timestampLLDP[0][0][nid-2][exp_nodeid[i]-2])
			{
				if((i < size-1)&&(size > 2))
				{
					rec_nodeid_str += ",";
				}
			}
            exp_nodeid_str += ",";
        }
    }
    
    if(rid_size == 0)
    {
		rec_nodeid_str += "\"Node" + std::to_string(nid) + "\"";
		pout_str += "\"" + std::to_string(2*RL_iterations) + "\"";
	}
	controller_str +=  controller;  // wrap in quotes for JSON.parse
	//controller_str += "]";
	consortium_str +=  consortium;  // wrap in quotes for JSON.parse
	//consortium_str += "]";
    
    rec_nodeid_str += "]";
    exp_nodeid_str += "]";
    pout_str += "]";

    // Compose full curl command
std::string curlCmd =
    "curl -X POST \"http://localhost:3000/invoke/BCTES?user=peer1@org1\" \\\n"
    "-H \"Content-Type: application/json\" \\\n"
    "-d '{\"args\": [\"" + controller_str + "\",\n" +
    "\"" + consortium_str + "\",\n" +
    "\"" + nodeId + "\",\n" +
    "\"" + escapeQuotes(exp_nodeid_str) + "\",\n" +
    "\"" + escapeQuotes(rec_nodeid_str) + "\",\n" +
    "\"" + escapeQuotes(pout_str) + "\"\n" +   
    "]}'";

    // Execute the curl command
    std::cout << "Executing:\n" << curlCmd << std::endl;
    std::string response = execCmd(curlCmd);

    std::cout << "\nRaw Response:\n" << response << std::endl;

    // Step 1: extract the "result" JSON string
    
    std::string resultStr = extractValue(response, "result");
	std::cout << "\nResult string: " << resultStr << std::endl;
	std::string newController = extractControllerFromResult(resultStr);
	std::cout << "New Controller extracted: " << newController << std::endl;
	
	if(newController == "C0")
	{
		node_controller_ID[nid] = 0;
	}
	
	if(newController == "C1")
	{
		node_controller_ID[nid] = 1;
	}
	
	if(newController == "C2")
	{
		node_controller_ID[nid] = 2;
	}
	
	if(newController == "C3")
	{
		node_controller_ID[nid] = 3;
	}

    // Remove backslashes (unescape the inner JSON string)
    //resultJson.erase(std::remove(resultJson.begin(), resultJson.end(), '\\'), resultJson.end());

    ///std::cout << "\nInner JSON:\n" << resultJson << std::endl;
    
    


}
void RSU_routing_dataunicast_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> source_node, Ptr <Node> destination_node, Ptr <Packet> packet1)
{
	Ptr <Node> nu = DynamicCast <Node> (source_node);
	//uint32_t nid = uint32_t(nu->GetId());
	
	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
  	Ipv4InterfaceAddress iaddr;
  	if(N_Vehicles > 0)
  	{
		iaddr = ipv4->GetAddress(1,0);//2nd IPv4 interface,0th address index
	}
	else if (N_Vehicles == 0)
	{
		iaddr = ipv4->GetAddress(0,0);//1st IPv4 interface,0th address index
	}
	Ipv4Address dest_ip = iaddr.GetLocal();	
	ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);		
}
void AddglobalHMAC2(uint32_t casted_raw_source_nodeid, uint32_t casted_raw_destination_nodeid, uint32_t casted_raw_source_portid, Ptr<Packet> packet_i, uint32_t attempts)
{
	
	string HMAC_string(64, 'A');
	if(routing_algorithm == 4)
	{
		std::string filename_HMAC = NS3_ROOT "/analytics/data/security_global_HMAC_data.csv";
		HMAC_string = read_other_other_item_from_csv(filename_HMAC, std::to_string(casted_raw_destination_nodeid), std::to_string(casted_raw_source_nodeid), std::to_string(casted_raw_source_portid), 3);
	}
	cout<<"HMAC global string is "<<HMAC_string<<endl;
	uint8_t * HMAC2 = new uint8_t[64];
	HexStringToBytes(HMAC_string, HMAC2, 64);
	CustomLLDP_uplink_UnicastTag tagLLDP_uplink_unicast;
	if(packet_i->PeekPacketTag(tagLLDP_uplink_unicast))
	{
		cout<<"Sending real packet "<<endl;
		tagLLDP_uplink_unicast.SetHMAC2(HMAC2);
		packet_i->ReplacePacketTag(tagLLDP_uplink_unicast);
		Simulator::Schedule(Seconds(0.00025), &TrySendUplink, casted_raw_source_nodeid, casted_raw_destination_nodeid, casted_raw_source_portid, packet_i, 0);
	}
}
void RSU_dataunicast_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>) {} // routing stub

void set_lte_initial_timestamp()
{
	lte_initial_timestamp = Simulator::Now().GetSeconds();
}
void set_LLDP_initial_timestamp()
{
	LLDP_initial_timestamp = Simulator::Now().GetSeconds();
}
void set_ethernet_initial_timestamp()
{
	ethernet_initial_timestamp = Simulator::Now().GetSeconds();
}
void dsrc_data_broadcast(Ptr <NetDevice> nd, Ptr <Node> node, uint32_t node_index)
{
	uint32_t nid = node->GetId();
	//cout<<"Z value at "<<nid<<"is "<<Z_nodes[nid]<<endl;
	if (Z_nodes[nid] == 1)
	{
		packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
		cout<<"DSRC data Broadcasting from node "<<nid<<endl;
		Mac48Address dest = Mac48Address::GetBroadcast();
	  	uint16_t protocolwave = 0x88dc;//ethertype for WAVE is set here.
		Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (nd);
		Ptr <Node> ni = DynamicCast <Node> (node);
		CustomDataTag tag;
		CustomDataTag1 tag1;
		CustomDataTag2 tag2;
		CustomDataTag3 tag3;
		CustomDataTag4 tag4;
		CustomDataTag5 tag5;
		CustomDataTag6 tag6;
		CustomDataTag7 tag7;
		CustomDataTag8 tag8;
		CustomDataTag9 tag9;
		CustomDataTag10 tag10;
		CustomDataTag11 tag11;
		CustomDataTag12 tag12;
		CustomDataTag13 tag13;
		CustomDataTag14 tag14;
		CustomDataTag15 tag15;
		CustomDataTag16 tag16;
		CustomDataTag17 tag17;
		CustomDataTag18 tag18;
		CustomDataTag19 tag19;
		CustomDataTag20 tag20;
		CustomDataTag21 tag21;
		CustomDataTag22 tag22;
		CustomDataTag23 tag23;
		CustomDataTag24 tag24;
		CustomDataTag25 tag25;
		CustomDataTagmax tagmax;
		
		uint32_t nid = uint32_t(ni->GetId());
		uint32_t size = getNeighborsize((neighbordata_inst+nid));
		uint32_t safe_size = (size > 0) ? size : 1;
		uint32_t neighborid[safe_size];
		for (uint32_t i=0;i<size;i++)
		{
			neighborid[i] = large;
		}
		
		uint32_t j=0;
		for (uint32_t i=0;i<max;i++)
		{
			if ((((neighbordata_inst+nid)->neighborid[i]) != large) and (j<size))
			{
				neighborid[j] = (neighbordata_inst+nid)->neighborid[i];
		  		j++;
		  	}
		}
		
		Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node->GetObject<MobilityModel>());
		Vector posi = mdl->GetPosition();
		Vector current_velocity = mdl->GetVelocity();
		double delta_t = data_transmission_period;
		Vector acceleration = calculate_acceleration(previous_velocity_dsrc[node_index],current_velocity,delta_t);
		Time ti = Seconds(Simulator::Now().GetSeconds());
		Ptr <Packet> packet_i = Create<Packet> (0);
		switch (size)
		{	
			case 0:
				tag.SetNodeId(nid);
				tag.SetPosition(posi);
				tag.SetVelocity(current_velocity);
				tag.SetAcceleration(acceleration);
				tag.SetTimestamp(ti);
				packet_i->AddPacketTag(tag);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 1:
				tag1.SetNodeId(nid);
				tag1.SetNeighborids(neighborid);
				tag1.SetPosition(posi);
				tag1.SetVelocity(current_velocity);
				tag1.SetAcceleration(acceleration);
				tag1.SetTimestamp(ti);
				packet_i->AddPacketTag(tag1);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 2:
				tag2.SetNodeId(nid);
				tag2.SetNeighborids(neighborid);
				tag2.SetPosition(posi);
				tag2.SetVelocity(current_velocity);
				tag2.SetAcceleration(acceleration);
				tag2.SetTimestamp(ti);
				packet_i->AddPacketTag(tag2);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 3: 
				tag3.SetNodeId(nid);
				tag3.SetNeighborids(neighborid);
				tag3.SetPosition(posi);
				tag3.SetVelocity(current_velocity);
				tag3.SetAcceleration(acceleration);
				tag3.SetTimestamp(ti);
				packet_i->AddPacketTag(tag3);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 4:
				tag4.SetNodeId(nid);
				tag4.SetNeighborids(neighborid);
				tag4.SetPosition(posi);
				tag4.SetVelocity(current_velocity);
				tag4.SetAcceleration(acceleration);
				tag4.SetTimestamp(ti);
				packet_i->AddPacketTag(tag4);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 5:
				tag5.SetNodeId(nid);
				tag5.SetNeighborids(neighborid);
				tag5.SetPosition(posi);
				tag5.SetVelocity(current_velocity);
				tag5.SetAcceleration(acceleration);
				tag5.SetTimestamp(ti);
				packet_i->AddPacketTag(tag5);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 6:
				tag6.SetNodeId(nid);
				tag6.SetNeighborids(neighborid);
				tag6.SetPosition(posi);
				tag6.SetVelocity(current_velocity);
				tag6.SetAcceleration(acceleration);
				tag6.SetTimestamp(ti);
				packet_i->AddPacketTag(tag6);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 7:
				tag7.SetNodeId(nid);
				tag7.SetNeighborids(neighborid);
				tag7.SetPosition(posi);
				tag7.SetVelocity(current_velocity);
				tag7.SetAcceleration(acceleration);
				tag7.SetTimestamp(ti);
				packet_i->AddPacketTag(tag7);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 8:
				tag8.SetNodeId(nid);
				tag8.SetNeighborids(neighborid);
				tag8.SetPosition(posi);
				tag8.SetVelocity(current_velocity);
				tag8.SetAcceleration(acceleration);
				tag8.SetTimestamp(ti);
				packet_i->AddPacketTag(tag8);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 9:
				tag9.SetNodeId(nid);
				tag9.SetNeighborids(neighborid);
				tag9.SetPosition(posi);
				tag9.SetVelocity(current_velocity);
				tag9.SetAcceleration(acceleration);
				tag9.SetTimestamp(ti);
				packet_i->AddPacketTag(tag9);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 10:
				tag10.SetNodeId(nid);
				tag10.SetNeighborids(neighborid);
				tag10.SetPosition(posi);
				tag10.SetVelocity(current_velocity);
				tag10.SetAcceleration(acceleration);
				tag10.SetTimestamp(ti);
				packet_i->AddPacketTag(tag10);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 11:
				tag11.SetNodeId(nid);
				tag11.SetNeighborids(neighborid);
				tag11.SetPosition(posi);
				tag11.SetVelocity(current_velocity);
				tag11.SetAcceleration(acceleration);
				tag11.SetTimestamp(ti);
				packet_i->AddPacketTag(tag11);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 12:
				tag12.SetNodeId(nid);
				tag12.SetNeighborids(neighborid);
				tag12.SetPosition(posi);
				tag12.SetVelocity(current_velocity);
				tag12.SetAcceleration(acceleration);
				tag12.SetTimestamp(ti);
				packet_i->AddPacketTag(tag12);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 13:
				tag13.SetNodeId(nid);
				tag13.SetNeighborids(neighborid);
				tag13.SetPosition(posi);
				tag13.SetVelocity(current_velocity);
				tag13.SetAcceleration(acceleration);
				tag13.SetTimestamp(ti);
				packet_i->AddPacketTag(tag13);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 14:
				tag14.SetNodeId(nid);
				tag14.SetNeighborids(neighborid);
				tag14.SetPosition(posi);
				tag14.SetVelocity(current_velocity);
				tag14.SetAcceleration(acceleration);
				tag14.SetTimestamp(ti);
				packet_i->AddPacketTag(tag14);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 15:
				tag15.SetNodeId(nid);
				tag15.SetNeighborids(neighborid);
				tag15.SetPosition(posi);
				tag15.SetVelocity(current_velocity);
				tag15.SetAcceleration(acceleration);
				tag15.SetTimestamp(ti);
				packet_i->AddPacketTag(tag15);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 16:
				tag16.SetNodeId(nid);
				tag16.SetNeighborids(neighborid);
				tag16.SetPosition(posi);
				tag16.SetVelocity(current_velocity);
				tag16.SetAcceleration(acceleration);
				tag16.SetTimestamp(ti);
				packet_i->AddPacketTag(tag16);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 17:
				tag17.SetNodeId(nid);
				tag17.SetNeighborids(neighborid);
				tag17.SetPosition(posi);
				tag17.SetVelocity(current_velocity);
				tag17.SetAcceleration(acceleration);
				tag17.SetTimestamp(ti);
				packet_i->AddPacketTag(tag17);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 18:
				tag18.SetNodeId(nid);
				tag18.SetNeighborids(neighborid);
				tag18.SetPosition(posi);
				tag18.SetVelocity(current_velocity);
				tag18.SetAcceleration(acceleration);
				tag18.SetTimestamp(ti);
				packet_i->AddPacketTag(tag18);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 19:
				tag19.SetNodeId(nid);
				tag19.SetNeighborids(neighborid);
				tag19.SetPosition(posi);
				tag19.SetVelocity(current_velocity);
				tag19.SetAcceleration(acceleration);
				tag19.SetTimestamp(ti);
				packet_i->AddPacketTag(tag19);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 20:
				tag20.SetNodeId(nid);
				tag20.SetNeighborids(neighborid);
				tag20.SetPosition(posi);
				tag20.SetVelocity(current_velocity);
				tag20.SetAcceleration(acceleration);
				tag20.SetTimestamp(ti);
				packet_i->AddPacketTag(tag20);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 21:
				tag21.SetNodeId(nid);
				tag21.SetNeighborids(neighborid);
				tag21.SetPosition(posi);
				tag21.SetVelocity(current_velocity);
				tag21.SetAcceleration(acceleration);
				tag21.SetTimestamp(ti);
				packet_i->AddPacketTag(tag21);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 22:
				tag22.SetNodeId(nid);
				tag22.SetNeighborids(neighborid);
				tag22.SetPosition(posi);
				tag22.SetVelocity(current_velocity);
				tag22.SetAcceleration(acceleration);
				tag22.SetTimestamp(ti);
				packet_i->AddPacketTag(tag22);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 23:
				tag23.SetNodeId(nid);
				tag23.SetNeighborids(neighborid);
				tag23.SetPosition(posi);
				tag23.SetVelocity(current_velocity);
				tag23.SetAcceleration(acceleration);
				tag23.SetTimestamp(ti);
				packet_i->AddPacketTag(tag23);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 24:
				tag24.SetNodeId(nid);
				tag24.SetNeighborids(neighborid);
				tag24.SetPosition(posi);
				tag24.SetVelocity(current_velocity);
				tag24.SetAcceleration(acceleration);
				tag24.SetTimestamp(ti);
				packet_i->AddPacketTag(tag24);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			case 25:
				tag25.SetNodeId(nid);
				tag25.SetNeighborids(neighborid);
				tag25.SetPosition(posi);
				tag25.SetVelocity(current_velocity);
				tag25.SetAcceleration(acceleration);
				tag25.SetTimestamp(ti);
				packet_i->AddPacketTag(tag25);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
			default:
				tagmax.SetNodeId(nid);
				uint32_t neighboridmax[max];
				for(uint32_t i=0;i<max;i++)
				{
					if(i<size)
					{
						neighboridmax[i] = neighborid[i];
					}
					else
					{
						neighboridmax[i] = large;
					}
				}
				tagmax.SetNeighborids(neighboridmax);
				tagmax.SetPosition(posi);
				tagmax.SetVelocity(current_velocity);
				tagmax.SetAcceleration(acceleration);
				tagmax.SetTimestamp(ti);
				packet_i->AddPacketTag(tagmax);
				dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
				break;
		}
		cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
		previous_velocity_dsrc[node_index] = current_velocity;
	}
}
void update_mobility()
{
  for(uint32_t i=0;i<Vehicle_Nodes.GetN();i++)
  {
	  	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (Vehicle_Nodes.Get(i)->GetObject<MobilityModel>());
	  	srand(Now().GetSeconds()*i);
	  	int sign1 = (rand()%2)==0?-1:1;
	  	//double vx = 5.0 + (rand()%10);
	  	uint32_t vx_max = maxspeed*(1000.0/3600.0);
	  	double vx = (vx_max/8) + (rand()%(7*vx_max/8));
	  	Vector cur_pos = mdl->GetPosition();
	  	double px;
	  	if((cur_pos.x > (750+1000))|(cur_pos.x< (650)))
	  	{
			if(cur_pos.x > (750+1000))
			{
				px =  1750 - (rand()%20);
				vx = -vx;
			}
			if(cur_pos.x < (650))
			{
				px =  650 + (rand()%20);
				vx = vx;
			}
	  	}
	  	else
	  	{
	  		px = cur_pos.x;
	  		vx = vx;
	  	
	  	}
	  	srand(i*Now().GetSeconds()+0.2);
	  	int sign2 = (rand()%2)==0?-1:1;
	  	//double vy = 5.0 + (rand()%10);
	  	uint32_t vy_max = maxspeed*(1000.0/3600.0);
	  	double vy = (vy_max/8) + (rand()%(7*vy_max/8));
	  	double py;
	  	if((cur_pos.y > (1200+1000)) |(cur_pos.y<1000))
	  	{
			if(cur_pos.y > (1200+1000))
			{
				py = 2200 - (rand()%20);
				vy = - vy;
			}
			
			if(cur_pos.y < (1000))
			{
				py = 1000 + (rand()%20);
				vy = vy;
			}
	  	}
	  	else
	  	{
	  		py = cur_pos.y;
	  		vy = vy;
	  	}
	  	double updated_vx = sign1*vx;
	  	double updated_vy = sign2*vy;
	  	mdl->SetPosition(Vector(px, py, 0));
	  	mdl->SetVelocity(Vector(updated_vx, updated_vy, 0));
	  	cout<<"sign 1 is"<<sign1<<"vx is "<<vx<<"product is "<<updated_vx<<"sign 2 "<<sign2<<"vy is "<<vy<<"product is "<<updated_vy<<endl;
	  	//cout<<mdl->GetVelocity()<<endl;
	  	//cout<<"updating mobility file at "<<Now().GetSeconds()<<endl;
  }

}
void reset_confusion_matrix()
{
	Expected0Actual0 = 0;
	Expected0Actual1 = 0;
	Expected1Actual0 = 0;
	Expected1Actual1 = 0;
}
void clear_RQY()
{
    for (int i=0; i<total_size;i++)
    {
    	Y[i] = 0;
	R[i] = 0;
	Q[i] = 0;
    }
    Q_bar = 0;
}
void begin_sending_RSU_data_agent()
{
	list<uint32_t> agent_ids;
 	for (uint32_t i=(N_Vehicles+2);i<(total_size+2);i++)
 	{
 		if(X_nodes[i] == 1)
 		{
 			agent_ids.push_back(i);
 		}
 	}
 	int count = 0;
	for (auto it=agent_ids.begin(); it!=agent_ids.end(); ++it)
	{
		uint32_t u = *it;
		//cout<<"agent u is "<<u<<endl;
	  	Ptr <Node> nu = DynamicCast <Node> (RSU_Nodes.Get(u-N_Vehicles-2));	
	  	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(u-N_Vehicles-2));
		Simulator::Schedule(Seconds(0.000050*count),RSU_dataunicast_agent, udp_app, nu, management_Node.Get(0));
		count++;
	}
}
void print_time()
{
	cout<<"current time is "<<Simulator::Now().GetSeconds()<<endl;
}
double inv_factorial(long int n)
{
	if(n>1)
	{
		return (1.0/n)*(inv_factorial(n-1));
	}
	
	else
	{
		return 1.0;
	}
}
void assign_controllers()
{
	cout << "DEBUG: assign_controllers called. attack_number=" << attack_number << endl;
	for(uint32_t i=0;i<total_size;i++)
	{
		if(i < uint32_t(0.25*total_size))
		{
			node_controller_ID[i] =0;
			assigned_consortium_ID[i] = 0;
		}
		
		else if(i < uint32_t(0.50*total_size))
		{
			node_controller_ID[i] =1;
			assigned_consortium_ID[i] = 1;
		}
		else if(i < uint32_t(0.75*total_size))
		{
			node_controller_ID[i] =2;
			assigned_consortium_ID[i] = 2;
		}
		else
		{
			node_controller_ID[i] =3;
			assigned_consortium_ID[i] = 3;
		}
		// MRTPA: RSU maliciousness decided by attack_percentage for all nodes
		// RSU nodes are at dsrc_Nodes indices [N_Vehicles .. N_Vehicles+N_RSUs-1]
		if (i >= N_Vehicles && i < (N_Vehicles + N_RSUs)) {
			trajectory_poisoning_malicious_nodes[i] = GetBooleanWithProbability(attack_percentage, i);
			cout << "[MRTPA] RSU node " << i << " malicious="
			     << trajectory_poisoning_malicious_nodes[i]
			     << " (attack_percentage=" << attack_percentage << "%)" << endl;
		} else {
			trajectory_poisoning_malicious_nodes[i] = false;
		}
		for(uint32_t j=0;j<total_size;j++)
		{
			timestamp_stored[i][j][0] = Simulator::Now().GetSeconds();
			timestamp_stored[i][j][1] = Simulator::Now().GetSeconds();
		}

		// Store controller/consortium assignment to blockchain
		if (routing_algorithm == 4)
		{
			StoreControllerAssignmentToBlockchain(
				i,
				node_controller_ID[i],
				assigned_consortium_ID[i],
				trajectory_poisoning_malicious_nodes[i]
			);
		}
		cout<<"node "<<i<<"controller id "<<node_controller_ID[i]<<"consortium id"<<assigned_consortium_ID[i]<<endl;
	}

}
void assign_basic_keys()
{
	//Simulator::Schedule(Seconds(0),LDA_security, " is_controller=true create_security_manager_con=true netsize=1 node_id=0 generate_dig_rsa_key_pair=true generate_own_aes_key=true sign_data=true verify_signature=true initiate_session1=true initiate_session2=true create_hmac_global=true create_hmac_set1=true create_hmac_set2=true verify_key_expiry=true is_node=true pid=1 get_rsa_keys=true encrypt_rsa=true set_aes_key_for_pair=true encrypt_controller_data=true decrypt_controller_data=true generate_global_HMAC_secret_key=true get_digital_public_key=true get_session_HMAC_1=true get_session_HMAC_2=true create_global_HMAC_node=true decrypt_rsa=true get_aes_keys=true encrypt_aes_node_pair=true decrypt_aes_node_pair=true");
	//Simulator::Schedule(Seconds(0),LDA_security, " is_controller=true create_security_manager_con=true netsize=1 node_id=0 port_id=0 other_node_id=0 generate_dig_rsa_key_pair=true generate_dig_ecc_key_pair=true generate_own_aes_key=true encrypt_ECDH=true decrypt_ECDH=true sign_data=true verify_signature=true initiate_session1=true initiate_session2=true create_hmac_global=true encrypt_ECDH=true decrypt_ECDH=true create_hmac_set1=true create_hmac_set2=true verify_key_expiry=true is_node=true pid=1 get_rsa_keys=true encrypt_rsa=true set_aes_key_for_pair=true encrypt_controller_data=true decrypt_controller_data=true generate_global_HMAC_secret_key=true get_digital_public_key=true get_session_HMAC_1=true get_session_HMAC_2=true create_global_HMAC_node=true decrypt_rsa=true get_aes_keys=true encrypt_aes_node_pair=true decrypt_aes_node_pair=true""message=THis\\ is\\ a\\ gest\\ message");
	//Simulator::Schedule(Seconds(0),LDA_PQ_security, " is_controller=true create_security_manager_con=true netsize=1 sign_FALCON=true verify_FALCON=true generate_FALCON=true encrypt_ASCON=true decrypt_ASCON=true generate_ASCON_key=true node_id=0 port_id=0 other_node_id=0 generate_dig_rsa_key_pair=true generate_dig_ecc_key_pair=true generate_own_aes_key=true encrypt_ECDH=true decrypt_ECDH=true sign_data=true verify_signature=true initiate_session1=true initiate_session2=true create_hmac_global=true encrypt_ECDH=true decrypt_ECDH=true create_hmac_set1=true create_hmac_set2=true verify_key_expiry=true is_node=true pid=1 get_rsa_keys=true encrypt_rsa=true set_aes_key_for_pair=true encrypt_controller_data=true decrypt_controller_data=true generate_global_HMAC_secret_key=true get_digital_public_key=true get_session_HMAC_1=true get_session_HMAC_2=true create_global_HMAC_node=true decrypt_rsa=true get_aes_keys=true encrypt_aes_node_pair=true decrypt_aes_node_pair=true" "message=THis\\ is\\ a\\ gest\\ message");
	
	for(uint32_t node_id=0;node_id<total_size;node_id++)
	{
		std::ostringstream oss;
		oss << " is_controller=true create_security_manager_con=true netsize=1 "
			<< "node_id=" << node_id << " port_id=0 other_node_id=0 "
			<< "generate_dig_rsa_key_pair=true generate_dig_ecc_key_pair=true "
			<< "generate_own_aes_key=true encrypt_ECDH=false decrypt_ECDH=false "
			<< "sign_data=false verify_signature=false initiate_session1=true "
			<< "initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
			<< "decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
			<< "verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
			<< "encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
			<< "decrypt_controller_data=false generate_global_HMAC_secret_key=true "
			<< "get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
			<< "create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
			<< "encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
			<< " message=This\\ is\\ a\\ test\\ message";
	    std::string command_str = oss.str();
		Simulator::Schedule(Seconds(0.001*node_id), LDA_security, command_str);
		
		
		std::ostringstream oss2;
		oss2 << " is_controller=true create_security_manager_con=true netsize=1 "
		    << " sign_FALCON=false verify_FALCON=false generate_FALCON=true "
		    << " encrypt_ASCON=false decrypt_ASCON=false generate_ASCON_key=true "
		    << " node_id="<< node_id << " port_id=0 other_node_id=0 "
		    << " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false generate_own_aes_key=false "
		    << " encrypt_ECDH=false decrypt_ECDH=false "
		    << " sign_data=false verify_signature=false "
		    << " initiate_session1=false initiate_session2=false "
		    << " create_hmac_global=false "
		    << " encrypt_ECDH=false decrypt_ECDH=false "
		    << " create_hmac_set1=false create_hmac_set2=false "
		    << " verify_key_expiry=false is_node=false pid=1 "
		    << " get_rsa_keys=false encrypt_rsa=false set_aes_key_for_pair=false "
		    << " encrypt_controller_data=false decrypt_controller_data=false "
		    << " generate_global_HMAC_secret_key=false get_digital_public_key=false "
		    << " get_session_HMAC_1=false get_session_HMAC_2=false "
		    << " create_global_HMAC_node=false "
		    << " decrypt_rsa=false "
		    << " get_aes_keys=false "
		    << " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
		    << " message=THis\\ is\\ a\\ test\\ message";
	   
	   std::string command_str2 = oss2.str();
	   Simulator::Schedule(Seconds(0.001*node_id), LDA_PQ_security, command_str2);


	}
}

// ── Enqueue() ─────────────────────────────────────────────────────────────
void Enqueue (std::string context, Ptr <const Packet> pkt)
{
	cout<<"A packet enqued"<<endl;
}

// ── Dequeue() ─────────────────────────────────────────────────────────────
void Dequeue (std::string context, Ptr <const Packet> pkt)
{
	cout<<"A packet dequed"<<endl;
}

// ── MacTx() ─────────────────────────────────────────────────────────────
void MacTx (std::string context, Ptr <const Packet> pkt)
{
	//cout<<"This is MacTx"<<endl;
}

// ── CreateglobalHMAC2() ─────────────────────────────────────────────────────────────
void CreateglobalHMAC2(uint32_t casted_raw_source_nodeid, uint32_t casted_raw_destination_nodeid, uint32_t casted_raw_source_portid, Ptr<Packet> packet_i, uint32_t attempts)
{
		CustomLLDP_uplink_UnicastTag tagLLDP_uplink_unicast;
		if(packet_i->PeekPacketTag(tagLLDP_uplink_unicast))
		{
			if(routing_algorithm == 4)
			{
				cout<<"Creating global HMAC2"<<endl;
				uint8_t * HMAC1 = new uint8_t[64];
				HMAC1 = tagLLDP_uplink_unicast.GetHMAC1();
				std::string HMAC1_str = BytesToHexString(HMAC1, 32);
				cout<<"HMAC2 is "<<HMAC1_str<<endl;
				std::ostringstream oss4;
				   oss4 << " is_controller=true create_security_manager_con=true netsize=1 "
						<< " node_id=" << casted_raw_destination_nodeid << " port_id=" << casted_raw_source_portid  << " other_node_id=" <<casted_raw_source_nodeid << " "
						<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
						<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
						<< " sign_data=false verify_signature=false initiate_session1=false "
						<< " initiate_session2=false create_hmac_global=true encrypt_ECDH=false "
						<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
						<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
						<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
						<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
						<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
						<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
						<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
						<< " message=" <<  HMAC1_str << " ";
					
					std::string command_str4 = oss4.str();
					Simulator::Schedule(Seconds(0), LDA_security, command_str4);
			}
	
				Simulator::Schedule(Seconds(0.00025), &AddglobalHMAC2, casted_raw_source_nodeid, casted_raw_destination_nodeid, casted_raw_source_portid, packet_i, 0);
		}
}

// ── MacRx() ─────────────────────────────────────────────────────────────
void MacRx (std::string context, Ptr <const Packet> pkt)
{
	//context will include info about the source of this event. Use string manipulation if you want to extract info.
	//std::cout <<  context << std::endl;
	//cout<<context[10]<<endl;
	//Print the info.
	
	/*
	std::cout << "\t total packet Size=" << pkt->GetSerializedSize()
			  << " Freq="<<channelFreqMhz
			  << " Mode=" << txVector.GetMode()
			  << " Signal=" << signalNoise.signal
			  << " Noise=" << signalNoise.noise << std::endl;
	*/
	
	//int x = int (channelFreqMhz);
	//int y = int (staId);
	//std::cout << x << "+" << y << "=" << apb.Func(x, y) << std::endl;
	//We can also examine the WifiMacHeader
	
	uint32_t destination_node_id;
	//if (!((paper == 1) && (architecture == 1)))
	//{
		//cout<<"Rx";
		string casted_context = context;
		int n = casted_context.length();
		char char_array[n+1];
		strcpy(char_array, casted_context.c_str());
		string str = "/";
		int l = str.length();
		char test_char[l+1];
		strcpy(test_char,str.c_str());
		//cout<<"raw character array is "<<context[10]<<context[11]<<context[12];
		if((char_array[11] == test_char[0]) and (char_array[12] == test_char[0]))
		{
			stringstream ss;
			ss << char_array[10];
			ss >> destination_node_id;
			//cout<<"testing "<<destination_node_id;
		}
		else if(char_array[12] == test_char[0])
		{	
			stringstream ss;
			string mystr;
			mystr += mystr + char_array[10];
			mystr +=  char_array[11];
			ss << mystr;
			ss >> destination_node_id;
			//cout<<"testing "<<destination_node_id;
		}
		else
		{
			stringstream ss;
			string mystr;
			mystr += mystr + char_array[10];
			mystr +=  char_array[11];
			mystr +=  char_array[12];
			ss << mystr;
			ss >> destination_node_id;
			//cout<<"testing "<<destination_node_id;
		}
		
		if ((destination_node_id > (total_size+1)) or (destination_node_id < 2))
		{
			cout<<"invalid conversion. setting default value to 2"<<endl;
			destination_node_id = 2;
		}
		cout<<"Converted destination node id is "<<destination_node_id;		
		//dsrc_final_timestamp = Simulator::Now().GetSeconds();
		dsrc_total_received_packets = dsrc_total_received_packets + 1.0;
		if (paper == 1)
		{
			dsrc_total_packet_size = dsrc_total_packet_size + pkt->GetSerializedSize();
		}
		
		
		CustomLLDP_DP_UnicastTag tagDP_LLDP;
		if(pkt->PeekPacketTag(tagDP_LLDP))
		{
		dsrc_LLDP_final_timestamp = Simulator::Now().GetSeconds();
			cout<<endl;
		cout<<"DSRC unicast LLDP packet received"<<endl;
		uint8_t * stage = new uint8_t[2];
		uint8_t * HMAC_key;
		uint8_t * DS_public_key1;
		uint8_t * DS_public_key2 = new uint8_t[2560];
		uint8_t * DS_public_key3 = new uint8_t[2560];
		uint8_t * DS1 = new uint8_t[32];
		uint8_t * DS2;
		uint8_t * source_nodeid;
		uint8_t * source_portid;
		uint8_t * destination_nodeid;
		uint8_t * destination_portid;
		uint8_t * HMAC1;
		
		if(routing_algorithm == 4)
		{
			*(stage+0) = 1;
		}
		else
		{
			*(stage+0) = 2;
		}
		destination_portid = tagDP_LLDP.Getsrcportid();	
		HMAC_key = tagDP_LLDP.GetHMAC();
		DS_public_key1 = tagDP_LLDP.GetDS_public_key1();
		DS_public_key2 = tagDP_LLDP.GetDS_public_key2();
		//DS_public_key3 = tagDP_LLDP.GetDS_public_key3();
		//DS1 = tagDP_LLDP.GetDS1();
		DS2 = tagDP_LLDP.GetDS2();
		source_nodeid = tagDP_LLDP.Getsrcnodeid();
		source_portid = tagDP_LLDP.Getsrcportid();
		destination_nodeid = tagDP_LLDP.Getdesnodeid();
		HMAC1 = tagDP_LLDP.GetHMAC1();
		
	    uint32_t casted_raw_source_nodeid = static_cast<uint32_t>(*(source_nodeid+0));
		uint32_t casted_raw_source_portid = static_cast<uint32_t>(*(source_portid+0));
		uint32_t casted_raw_destination_nodeid = static_cast<uint32_t>(*(destination_nodeid+0));
		uint32_t casted_raw_destination_portid = static_cast<uint32_t>(*(destination_portid+0));
		
		
	    std::string HMAC_key_str = BytesToHexString(HMAC_key, 81);
	    std::string HMAC1_str = BytesToHexString(HMAC1, 32);
	    std::string digital_sig_str1 = BytesToHexString(DS_public_key1, 256);
	    std::string digital_sig_str2 = BytesToHexString(DS_public_key2, 1278);
		
		cout<<"HMAC key is "<<HMAC_key_str<<endl;
		cout<<"Digital signature 1 is"<<digital_sig_str1<<endl;
		cout<<"Digital signature 2 is"<<digital_sig_str2<<endl;
		cout<<"Digital signature 3 is"<<DS_public_key3<<endl;
		cout<<"source node id is "<<casted_raw_source_nodeid<<endl;
		cout<<"source port id is "<<casted_raw_source_portid<<endl;
		cout<<"destination node id is "<<casted_raw_destination_nodeid<<endl;
		cout<<"destination port id is "<<casted_raw_destination_portid<<endl;
		cout<<"HMAC1 is "<<HMAC1_str<<endl;
		cout<<"state is "<<static_cast<int>(*(stage+0))<<endl;
		cout<<"DS1 is "<<DS1<<endl;
		cout<<"DS2 is "<<DS2<<endl;
		/*
		for(uint32_t i=0;i<2*flows;i++)
		{
			for(uint32_t j=0;j<total_size;j++)	
			{
				(delta_at_nodes_inst+i)->delta_fi_inst[nodeid].delta_values[j] = delta_Set[i][j];
				//cout<< "i = "<<i<<"nid = "<<nid<<"j= "<<j<<"value="<<(delta_at_controller_inst+i)->delta_fi_inst[nid-2].delta_values[j]<<endl;
			}
		       (delta_at_nodes_inst+i)->source_f = sources[i];
		       (delta_at_nodes_inst+i)->destination_f = destinations[i];
		       (delta_at_nodes_inst+i)->flow_id = flow_ids[i];
		       (demanding_flow_struct_nodes_inst+i)->f_size = flow_sizes[i];
		       (load_at_nodes+i)->load_f[nodeid] = load_sum[i];
		}
		*/
		
		//cout<<"Received deltas and load values at node: "<<nodeid<<"at timestamp: "<<Now().GetMilliSeconds()<<endl;
		
	
		//cout<<"delta value of flow "<< (delta_at_nodes_inst+0)->flow_id<<"node id "<<nodeid<<", next hop 1 with flow size "<<(demanding_flow_struct_nodes_inst+0)->f_size<<" is "<<(delta_at_nodes_inst+0)->delta_fi_inst[nodeid].delta_values[1]<<"and Load sum is "<< (load_at_nodes+0)->load_f[nodeid]<<"source is "<<(delta_at_nodes_inst+0)->source_f<<"destination is "<<(delta_at_nodes_inst+0)->destination_f<<endl;
	 //cout<<"delta value of flow "<< (delta_at_nodes_inst+1)->flow_id<<"node id "<<nodeid<<", next hop 10 with flow size "<<(demanding_flow_struct_nodes_inst+1)->f_size<<" is "<<(delta_at_nodes_inst+1)->delta_fi_inst[nodeid].delta_values[10]<<"and Load sum is "<< (load_at_nodes+1)->load_f[nodeid]<<"source is "<<(delta_at_nodes_inst+1)->source_f<<"destination is "<<(delta_at_nodes_inst+1)->destination_f<<endl;
	    
	 	if(MIM_malicious_nodes[destination_node_id-2])
	 	{
			bool attacking_state = GetBooleanWithProbability(attack_percentage, destination_node_id);
	 		if(attacking_state)
	 		{
				CustomLLDP_uplink_UnicastTag tagLLDP_uplink_replay;
				//uint32_t nid = uint32_t(ni->GetId());
				//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
				Time ti = Seconds(Simulator::Now().GetSeconds());
				Ptr <Packet> packet_MIM = Create<Packet> (100);
				*(stage+0) = 2;
				tagLLDP_uplink_replay.SetStage(stage);
				tagLLDP_uplink_replay.SetHMAC_key(HMAC_key);
				tagLLDP_uplink_replay.SetDS_public_key1 (DS_public_key1);
				tagLLDP_uplink_replay.SetDS_public_key2 (DS_public_key2);
				tagLLDP_uplink_replay.SetDS_public_key3 (DS_public_key3);
				tagLLDP_uplink_replay.SetDS1 (DS1);
				tagLLDP_uplink_replay.SetDS2 (DS2);
				tagLLDP_uplink_replay.Setsrcnodeid (source_nodeid);
				tagLLDP_uplink_replay.Setsrcportid (source_portid);
				tagLLDP_uplink_replay.Setdesportid (source_portid);
				tagLLDP_uplink_replay.Setdesnodeid (&replay_buffer[destination_node_id]);
				tagLLDP_uplink_replay.SetHMAC1 (HMAC1);
				uint8_t * HMAC2_replay = HMAC_key;
				tagLLDP_uplink_replay.SetHMAC2 (HMAC2_replay);
				packet_MIM->AddPacketTag(tagLLDP_uplink_replay);
				//Simulator::Schedule(Seconds(0.000),send_Ethernet_LLDP_packetin_uplink_alone, 4, 0, *source_portid, packet_j);
				cout<<"Transmitting replay packet"<<endl;
				if(routing_algorithm != 4)
				{
					Simulator::Schedule(Seconds(0.000), TrySendUplink, *source_nodeid, destination_node_id-2, *source_portid, packet_MIM, 1);
				}
				else
				{
					Simulator::Schedule(Seconds(0.0075), TrySendUplink, *source_nodeid, destination_node_id-2, *source_portid, packet_MIM, 1);
				}
			}
	 	}
	 	
	 	if(fabrication_malicious_nodes[destination_node_id-2])
	 	{
	 	
	 		bool attacking_state = GetBooleanWithProbability(attack_percentage, destination_node_id);
	 		if(attacking_state)
	 		{
		 		CustomLLDP_uplink_UnicastTag tagLLDP_uplink_fabric;
				//uint32_t nid = uint32_t(ni->GetId());
				//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
				Time ti = Seconds(Simulator::Now().GetSeconds());
				Ptr <Packet> packet_FAB = Create<Packet> (100);
				tagLLDP_uplink_fabric.SetStage(stage);
				tagLLDP_uplink_fabric.SetHMAC_key(HMAC_key);
				tagLLDP_uplink_fabric.SetDS_public_key1 (DS_public_key1);
				tagLLDP_uplink_fabric.SetDS_public_key2 (DS_public_key2);
				tagLLDP_uplink_fabric.SetDS_public_key3 (DS_public_key3);
				tagLLDP_uplink_fabric.SetDS1 (DS1);
				tagLLDP_uplink_fabric.SetDS2 (DS2);
				srand(destination_node_id);
				
				uint8_t * local_source_nodeid = new uint8_t[32];
				uint8_t * local_source_portid = new uint8_t[32];
				bool success_alg2 = GetBooleanWithProbability(80, destination_node_id);
				if((routing_algorithm !=2)||(!success_alg2))//If not pure crypto
				{
					*local_source_nodeid = rand()%total_size;
					*local_source_portid = rand()%2;
				}
				else
				{
					//do nothing
				}
				
				if((routing_algorithm ==4))//If not pure crypto
				{
					*local_source_nodeid = rand()%total_size;
					*local_source_portid = rand()%2;
				}
				srand(destination_node_id+10);
				
				uint8_t * local_destination_nodeid = new uint8_t[32];
				uint8_t * local_destination_portid = new uint8_t[32];
				
				if((routing_algorithm !=2)||(!success_alg2))
				{
					*local_destination_nodeid = rand()%total_size;
					*local_destination_portid = rand()%2;
				}
				else
				{
					local_destination_portid = tagDP_LLDP.Getsrcportid();
					local_destination_nodeid = tagDP_LLDP.Getdesnodeid();
					
				}
				if((routing_algorithm ==4))
				{
					*local_destination_nodeid = rand()%total_size;
					*local_destination_portid = rand()%2;
				}
				cout<<*destination_portid<<endl;
				tagLLDP_uplink_fabric.Setsrcnodeid (local_source_nodeid);
				tagLLDP_uplink_fabric.Setsrcportid (local_source_portid);
				tagLLDP_uplink_fabric.Setdesportid (local_destination_portid);
				tagLLDP_uplink_fabric.Setdesnodeid (local_destination_nodeid);
				tagLLDP_uplink_fabric.SetHMAC1 (HMAC1);
				uint8_t * HMAC2_fabric = HMAC_key;
				tagLLDP_uplink_fabric.SetHMAC2 (HMAC2_fabric);
				packet_FAB->AddPacketTag(tagLLDP_uplink_fabric);
				cout<<"Transmitting fabricated packet"<<endl;
				//Simulator::Schedule(Seconds(0.000),send_Ethernet_LLDP_packetin_uplink_alone, 4, 0, *destination_portid, packet_j);
				if(routing_algorithm != 4)
				{
					Simulator::Schedule(Seconds(0.000), TrySendUplink, *local_source_nodeid, destination_node_id-2, *local_destination_portid, packet_FAB, 1);
				}
				else
				{
					Simulator::Schedule(Seconds(0.010), TrySendUplink, *local_source_nodeid, destination_node_id-2, *local_destination_portid, packet_FAB, 1);
				}
			}
	 	}
	 	
	 	
	 	if(vanishing_malicious_nodes[destination_node_id-2])
	 	{
			bool attacking_state = GetBooleanWithProbability(attack_percentage, destination_node_id);
	 		if(attacking_state)
	 		{
				CustomLLDP_uplink_UnicastTag tagLLDP_uplink_replay;
				//uint32_t nid = uint32_t(ni->GetId());
				//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
				Time ti = Seconds(Simulator::Now().GetSeconds());
				Ptr <Packet> packet_VAN = Create<Packet> (100);
				*(stage+0) = 2;
				tagLLDP_uplink_replay.SetStage(stage);
				tagLLDP_uplink_replay.SetHMAC_key(HMAC_key);
				tagLLDP_uplink_replay.SetDS_public_key1 (DS_public_key1);
				tagLLDP_uplink_replay.SetDS_public_key2 (DS_public_key2);
				tagLLDP_uplink_replay.SetDS_public_key3 (DS_public_key3);
				tagLLDP_uplink_replay.SetDS1 (DS1);
				tagLLDP_uplink_replay.SetDS2 (DS2);
				srand(Simulator::Now().GetSeconds()+destination_node_id);
				uint8_t des_port = uint8_t(rand()%2);
				tagLLDP_uplink_replay.Setsrcportid (&replay_buffer2_port[destination_node_id]);
				tagLLDP_uplink_replay.Setsrcnodeid (&replay_buffer2[destination_node_id]);
				tagLLDP_uplink_replay.Setdesnodeid (&replay_buffer[destination_node_id]);
				bool flip_state = GetBooleanWithProbability(80, destination_node_id);
				if (flip_state)
				{
					if(&replay_buffer2_port[destination_node_id] == 0)
					{
						des_port = 1;
						
					}
					else
					{
						des_port = 0;
					}
					tagLLDP_uplink_replay.Setdesportid (&des_port);
				}
				else
				{
					tagLLDP_uplink_replay.Setdesportid (&replay_buffer_port[destination_node_id]);
				}
				tagLLDP_uplink_replay.SetHMAC1 (HMAC1);
				uint8_t * HMAC2_replay = HMAC_key;
				tagLLDP_uplink_replay.SetHMAC2 (HMAC2_replay);
				packet_VAN->AddPacketTag(tagLLDP_uplink_replay);
				cout<<"Transmitting vanishing packet "<<endl;
				//Simulator::Schedule(Seconds(0.000),send_Ethernet_LLDP_packetin_uplink_alone, replay_buffer2[destination_node_id], destination_node_id, replay_buffer_port[destination_node_id], packet_j);
				if(routing_algorithm != 4)
				{
					Simulator::Schedule(Seconds(0.000), TrySendUplink, replay_buffer2[destination_node_id], destination_node_id-2, *destination_portid, packet_VAN, 1);
				}
				else
				{
					Simulator::Schedule(Seconds(0.0125), TrySendUplink, replay_buffer2[destination_node_id], destination_node_id-2, *destination_portid, packet_VAN, 1);
				}
			}
	 	}

	    
	    if(destination_node_id == casted_raw_destination_nodeid+2)
	    {
		
			CustomLLDP_uplink_UnicastTag tagLLDP_uplink;
			std::cout <<"Transmitting uplink packet with ID "<< "Pkt UID=" << pkt->GetUid()<<"at time "<<Simulator::Now().GetSeconds()<<endl;
			//uint32_t nid = uint32_t(ni->GetId());
			//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
			Time ti = Seconds(Simulator::Now().GetSeconds());
			Ptr <Packet> packet_i = Create<Packet> (100);
			tagLLDP_uplink.SetHMAC_key(HMAC_key);
			uint8_t * local_stage = new uint8_t[2];
			
			if(routing_algorithm == 4)
			{
				*(local_stage+0) = 1;
			}
			else
			{
				*(local_stage+0) = 2;
			}
			
			cout<<"checking state before assignment "<<static_cast<uint32_t>(*(stage+0))<<endl;
			tagLLDP_uplink.SetStage(local_stage);
			tagLLDP_uplink.SetDS_public_key1 (DS_public_key1);
			tagLLDP_uplink.SetDS_public_key2 (DS_public_key2);
			tagLLDP_uplink.SetDS_public_key3 (DS_public_key3);
			tagLLDP_uplink.SetDS1 (DS1);
			tagLLDP_uplink.SetDS2 (DS2);
			tagLLDP_uplink.Setsrcnodeid (source_nodeid);
			tagLLDP_uplink.Setsrcportid (source_portid);
			tagLLDP_uplink.Setdesportid (source_portid);
			tagLLDP_uplink.Setdesnodeid (destination_nodeid);
			tagLLDP_uplink.SetHMAC1 (HMAC1);
			//uint8_t * HMAC2 = HMAC_key;
			uint8_t * HMAC2 = new uint8_t[64];
			tagLLDP_uplink.SetHMAC2 (HMAC2);
			packet_i->AddPacketTag(tagLLDP_uplink);
			
			bool attacking_state2 = GetBooleanWithProbability(attack_percentage, casted_raw_destination_nodeid);
			cout<<"Vanishing attack state is "<<attacking_state2<<"not attacking state is "<<!attacking_state2<<"for destination "<<destination_node_id<<endl;
			cout<<"Not vanishing state is "<<!vanishing_malicious_nodes[casted_raw_destination_nodeid]<<endl;
			cout<<"Vanishing state is "<<vanishing_malicious_nodes[casted_raw_destination_nodeid]<<endl;
			bool cond2 = (!attacking_state2);
			cout<<"condition2 is"<<cond2<<endl;
			
			if((!vanishing_malicious_nodes[casted_raw_destination_nodeid])||(cond2))
			{
				/*
					if((Simulator::Now().GetSeconds()-uplink_last[casted_raw_destination_nodeid])>0.50)
					{
						Simulator::Schedule(Seconds(0.000), send_Ethernet_LLDP_packetin_uplink_alone, casted_raw_source_nodeid, casted_raw_destination_nodeid, casted_raw_source_portid, packet_i);
					}
					*/
				//Simulator::Schedule(Seconds(0.005), send_Ethernet_LLDP_packetin_uplink_alone, casted_raw_source_nodeid, casted_raw_destination_nodeid, casted_raw_source_portid, packet_i);
				//uplink_last[casted_raw_destination_nodeid] = Simulator::Now().GetSeconds();
				cout<<"Trasmitting actual packet"<<endl;
				Simulator::Schedule(Seconds(0.0000), &CreateglobalHMAC2, casted_raw_source_nodeid, casted_raw_destination_nodeid, casted_raw_source_portid, packet_i, 0);
			}
			
			//srand(Simulator::Now().GetSeconds());
			//uint32_t rand_i = rand()%2;
			
			
			
			//uint32_t ue0_index = 0;                   // Node index of UE0
			//uint32_t dest_index = 0;                  // Controller node index
			
			//uint32_t port_id   = 7777;                // Or whichever port you use for uplink
			//Ptr<Packet> testPkt = Create<Packet>(100); // 100-byte test packet

			//Simulator::Schedule(Seconds(0.000), &send_Ethernet_LLDP_packetin_uplink_alone,casted_raw_source_nodeid,casted_raw_destination_nodeid,port_id,testPkt);
			
			//Simulator::Schedule(Seconds(0.000), &TrySendUplink, casted_raw_source_nodeid, casted_raw_destination_nodeid, casted_raw_source_portid, testPkt, 0);

		}
		replay_buffer2[casted_raw_destination_nodeid] = replay_buffer[casted_raw_destination_nodeid];
		replay_buffer2_port[casted_raw_destination_nodeid] = replay_buffer_port[casted_raw_destination_nodeid];
		replay_buffer[casted_raw_destination_nodeid] = casted_raw_source_nodeid;		
		replay_buffer_port[casted_raw_destination_nodeid] = casted_raw_source_portid;
		
	
		
	}
	//}
	
		CustomDataUnicastTag_ModifiedRouting tagmodified_routing;
		if(pkt->PeekPacketTag(tagmodified_routing))
		{		
			//cout<<"transmiiting a a packet at "<<Now().GetMilliSeconds()<<endl;
			//uint32_t nid = source_node->GetId();
			
			
			uint32_t current_hop = destination_node_id -2;
			uint32_t fid = tagmodified_routing.GetflowId();
			uint32_t packet_ID = tagmodified_routing.GetpacketId();
			uint32_t channel = tagmodified_routing.GetchannelId();
			
			//cout<<"Received at hop "<<current_hop<<"packet id "<<packet_ID<<"flow ID"<<fid<<"at time "<<Now().GetSeconds()<<endl;
			
			//uint32_t previous_sender_ID = tagmodified_routing.Getprevious_senderId();
			Time previous_timestamp = tagmodified_routing.Getprevious_timestamp();
			Time originail_timestamp = tagmodified_routing.Getoriginal_timestamp();
			//cout<<previous_sender_ID<<endl;
			
			//uint32_t packets = txop_inst[fid].pending_packets[previous_sender_ID];
			//updateTxop(fid, previous_sender_ID, packets, false);
			
			uint32_t destination =  (delta_at_nodes_inst+fid)->destination_f;
			if(pd_all_inst[fid].pd_inst[current_hop].delivery[channel][packet_ID] == false)
			{
				pd_all_inst[fid].pd_inst[current_hop].delivery[channel][packet_ID] = true;
				
				if(destination == current_hop)
				{
					destination_counter[fid]++;
					routing_packet_final_timestamp[fid][packet_ID] = Now().GetSeconds();
					routing_packet_general_final_timestamp[fid][current_hop][packet_ID] = Now().GetSeconds();
					cout<<"Flow ID "<<fid<<"received "<<" Packet ID: "<<packet_ID<<"Totally received "<<destination_counter[fid]<<"packets at destination "<<destination<<" at "<<Now().GetSeconds()<<endl;
				}
				else
				{
					routing_packet_general_final_timestamp[fid][current_hop][packet_ID] = Now().GetSeconds();
					pd_all_inst[fid].pd_inst[current_hop].pending[channel][packet_ID] = true;
					//uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
					uint32_t p_size = (demanding_flow_struct_nodes_inst+fid)->p_size;
					struct custom_struct arguments;
					arguments.p_size = p_size;
					arguments.channel = channel;
					//double total_load = (load_at_nodes+fid)->load_f[current_hop];
					//uint32_t total_packets = ceil(total_load*f_size);
					
					//bool busy_current;
				  	uint32_t pending_packets = txop_inst[fid].pending_packets[channel][current_hop];
				  	//uint32_t pending_packets_copy = txop_inst[fid].pending_packets[current_hop];
					/*
					for(uint32_t f=0;f<2*flows;f++)
					{
						busy_current = txop_inst[f].busy[current_hop];
					}
					*/
					pending_packets++;
					arguments.CW = pd_all_inst[fid].pd_inst[current_hop].attempts[arguments.channel][packet_ID] + 2;
					updateTxop_self(fid, current_hop, pending_packets, false, arguments);
					//Modify tag
					//Ptr <Packet> packet_i = Create<Packet> (packet_size-28);
					//packet_i->AddPacketTag(tagmodified_routing);
					//cout<<"next hop is "<< next_hop_id <<endl;
									
					

				  	Ptr <NetDevice> current_nd = wifidevices.Get(current_hop);
					Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (current_nd);
					//Ptr <Node> ni = DynamicCast <Node> (source_node);				

					
					//double tg = compute_link_delay(current_hop, 1.0, 1, p_size, destination);
					//cout<<"Time gap is "<<tg<<endl;
					//double subflow_start_time = 0.0;
					uint32_t total_packet_counter = 0;
					
					
					auto index_top = all_sorted_delta_next_hop_flow_size.begin();
					advance(index_top,fid);
					//cout<<subflow_start_time<<total_packet_counter<<total_packets<<endl;

					auto index_middle = index_top->begin();
					advance(index_middle,current_hop);
					bool sent = false;
					//bool queued = false;
					while (sent == false)
					{
						if (routing_algorithm == 1)
						{
							list<uint32_t> indices;
							for(uint32_t j =0;j<total_size;j++)
							{
								auto index_innermost = index_middle->begin();
								//cout<<subflow_start_time<<total_packet_counter<<total_packets<<endl;
								advance(index_innermost,j);
								double sub_flow_load; 
								uint32_t nid;
								uint32_t sub_flow_packets;
								tie(sub_flow_load, nid, sub_flow_packets) = *index_innermost;
								//cout<<"sub flow load is "<<sub_flow_load<<" next hop "<<nid<<"packets "<<sub_flow_packets<<endl;		
								//uint32_t sub_flow_counter = 0;
								//cout<<sub_flow_counter<<endl;
								
								if(sub_flow_load !=0.0)
								{	
									indices.push_back(j);
								}
							}
							
							uint32_t rand_index = 0;
							if (indices.size() > 0)
							{
								rand_index = rand()%(indices.size());
							}
							else
							{
								sent =true;
							}
							//cout<<"size of indices is "<<indices.size()<<"random index is "<<rand_index<<endl;;
							auto index_list = indices.begin();
							advance(index_list, rand_index);
							uint32_t index = *index_list;
							//cout<<"index is "<<index<<endl;
							auto index_innermost = index_middle->begin();
							//cout<<subflow_start_time<<total_packet_counter<<total_packets<<endl;
							advance(index_innermost,index);
							double sub_flow_load; 
							uint32_t nid;
							uint32_t sub_flow_packets;
							tie(sub_flow_load, nid, sub_flow_packets) = *index_innermost;
							//cout<<"sub flow load is "<<sub_flow_load<<" next hop "<<nid<<"packets "<<sub_flow_packets<<endl;		
							uint32_t sub_flow_counter = 0;
							//cout<<sub_flow_counter<<endl;
							//cout<<"sub flow packets is "<<sub_flow_packets<<endl;
								
							if(sub_flow_load>0.0)
							{	
								
								uint32_t updated_packet_ID = packet_ID;
								//cout<<"updated packet ID is "<<updated_packet_ID<<endl;
								Simulator::Schedule (Seconds (0.0), check_delivery_and_retransmit, fid, updated_packet_ID, nid, current_hop, originail_timestamp, arguments);
								sub_flow_counter++;
								total_packet_counter++;
								if(get<2>(*index_innermost) > 0)
								{
									get<2>(*index_innermost) = get<2>(*index_innermost) - 1;	
								}					
								sent = true;
							}
						}
						else
						{
							for(uint32_t j =0;j<total_size;j++)
							{
								//cout<<"value of j is "<<j<<endl;
								auto index_innermost = index_middle->begin();
								//cout<<subflow_start_time<<total_packet_counter<<total_packets<<endl;
								advance(index_innermost,j);
								double sub_flow_load; 
								uint32_t nid;
								uint32_t sub_flow_packets;
								tie(sub_flow_load, nid, sub_flow_packets) = *index_innermost;
								//cout<<"sub flow load is "<<sub_flow_load<<" next hop "<<nid<<"packets "<<sub_flow_packets<<endl;		
								uint32_t sub_flow_counter = 0;
								//cout<<sub_flow_counter<<endl;
									
								if((sub_flow_packets>0) | (j==(total_size-1)))
								{	
									//cout<<"sub flow packet size is "<<sub_flow_packets<<endl;
									//Ptr <NetDevice> destination_nd = wifidevices.Get(nid);
									//Address addr = destination_nd->GetAddress();
									//Mac48Address dest_address = Mac48Address::ConvertFrom(addr);
									//cout <<endl<<"MAC address of next hop node "<<next_hop<<" is "<<dest_address<<endl;
					  				//uint16_t protocolwave = 0x88dc;
									
									/*
									bool busy_next;
									for(uint32_t f=0;f<2*flows;f++)
									{
										busy_next = txop_inst[f].busy[nid];
									}
									if(busy_next==true)
									{
										cout<<"Next Hop is busy. Queuing packet"<<endl;
										queued = true;
									}
									*/
									//else
									//{
										//for(uint32_t i=0;i<pending_packets;i++)
										//{
											/*
											Ptr <Packet> packet_i = Create<Packet> (p_size-28);
											CustomDataUnicastTag_ModifiedRouting tag;
											tag.SetflowId(fid);
											
											tag.SetpacketId(updated_packet_ID);
											tag.Setprevious_senderId(current_hop);
											tag.Setprevious_timestamp(MicroSeconds(Now().GetMicroSeconds()));
											tag.Setoriginal_timestamp(originail_timestamp);
											packet_i->AddPacketTag(tag);
											*/
											//uint32_t updated_packet_ID = packet_ID-pending_packets_copy+sub_flow_counter;
											uint32_t updated_packet_ID = packet_ID;
											//cout<<"updated packet ID is "<<updated_packet_ID<<endl;
											//Simulator::Schedule (Seconds (0.0), updateTxop, fid, current_hop, nid, pending_packets, true, arguements.channel);
											//cout<<"This is flow ID "<<fid<<"Re-transmission attempt 1 packet ID "<<updated_packet_ID<<" from "<<current_hop<<" to next hop "<<nid<<"at time "<<Now().GetSeconds()<<endl;
											//Simulator::Schedule (Seconds ((tg/1.0)*(sub_flow_counter)), &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);						
											//Simulator::Schedule (Seconds ((tg/1.0)*(sub_flow_counter)), check_delivery_and_retransmit, fid, updated_packet_ID, nid, current_hop, p_size, originail_timestamp);
											Simulator::Schedule (Seconds (0.0), check_delivery_and_retransmit, fid, updated_packet_ID, nid, current_hop, originail_timestamp, arguments);
											
											/*		
											if (retransmitted[fid][nid][updated_packet_ID] == true)
											{
												cout<<"incrementing counter due to retransmission"<<endl;
												sub_flow_counter = sub_flow_counter + s_flow_counter[fid][nid][updated_packet_ID];
											}
											*/
											//pending_packets--;
											sub_flow_counter++;
											total_packet_counter++;
											if(get<2>(*index_innermost) > 0)
											{
												get<2>(*index_innermost) = get<2>(*index_innermost) - 1;	
											}				
										//}
										//Simulator::Schedule (Seconds ((tg/0.99)*(sub_flow_counter)),updateTxop, fid, current_hop, nid, pending_packets, false, arguments.channel);
										sent = true;
									//}	
								}
								//subflow_start_time = (tg*total_packet_counter);
							}
						}
					}
					//uint32_t nid = uint32_t(ni->GetId());
					//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
					//Time ti = Seconds(Simulator::Now().GetSeconds());
					//Ptr <Packet> packet_i = Create<Packet> (packet_size-28);;

					//dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
					//dsrc_final_timestamp = Simulator::Now().GetSeconds();
					//dsrc_total_received_packets = dsrc_total_received_packets + 1.0;
					

				}
			}
			else
			{
				//cout<<"Duplicate packet "<<packet_ID<<" for flow id "<<fid<<" received at hop "<<current_hop<<endl;
			
			}
	}
	
	
	CustomDataUnicastTag_Routing tag_routing;
	
	

	if(pkt->PeekPacketTag(tag_routing))
	{
		/*
		cout<<"Data unicast tag received "<<endl;
		uint32_t node_index = tag_routing.GetsenderId();
		uint32_t destination = tag_routing.GetdestinationId() + 2;
		uint32_t * source = tag_routing.GetNodeId();
		uint32_t * port = tag_routing.GetPortId();
		
		size_t length = 5;

        // Convert back to string
        std::string recovered(reinterpret_cast<const char*>(port), length);
        
        
		if(routing_algorithm == 4)
		{
		   Simulator::Schedule(Seconds(0.0000), decrypt_routing_packet, node_index, *port, destination_node_id-2);	
		}
		Simulator::Schedule(Seconds(0.0005), proceed_routing_packet, node_index, *port, destination, destination_node_id, *source, tag_routing);
		*/
		
		/*
		if (architecture == 1)
		{
			cout<<"packet from "<<*source -2<<"with destination "<<destination -4<<"now at "<<destination_node_id -2<<endl;
		}
		
		if (!((paper == 1) && (architecture == 1)))
		{
			Y[*source - 2] = Y[*source - 2] - 1;
			packets_received_wl[*source - 2] = packets_received_wl[*source - 2] + 1;
			double delay = Now().GetMicroSeconds()-tag_routing.GetTimestamp()->GetMicroSeconds();
			one_hop_delay_training_wl[*source - 2] = one_hop_delay_training_wl[*source - 2] + delay;
			cout<<"1-hop delay wireless is "<<delay<<endl;
			
			if (destination_node_id != destination)
			{
				//uint32_t next_hop = routing_tables[destination_node_id -2].rows[destination-2].next_hop;
				uint32_t next_hop = find_next_hop(node_index,destination-2,destination_node_id -2);
				cout<<endl<<"next hop from routing table is "<< next_hop <<endl;
				if (next_hop == (*source -2))
				{
					cout<<"routing loop. stopping routing"<<endl;
				}
				else if (next_hop < total_size)
				{
					Ptr <Packet> packet_i = Create<Packet> (packet_additional_size);
					tag_routing.SetNodeId(&destination_node_id);
					Time ti = MicroSeconds(Simulator::Now().GetMicroSeconds());
					tag_routing.SetTimestamp(&ti);
					packet_i->AddPacketTag(tag_routing);
					
					if (((destination_node_id-2) > N_Vehicles) && (next_hop > N_Vehicles))
					{
						Ptr <Node> nu = DynamicCast <Node> (RSU_Nodes.Get(destination_node_id-2-N_Vehicles));	
				  		Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(destination_node_id-2-N_Vehicles));
				  		cout<<"Ethernet data Unicasting from node "<<destination_node_id - 2<<endl;
						Simulator::Schedule(Seconds(0),RSU_routing_dataunicast_alone, udp_app, nu, RSU_Nodes.Get(next_hop-N_Vehicles),packet_i);
					}
					
					else
					{
						Ptr <NetDevice> destination_nd = wifidevices.Get(next_hop);
						Address addr = destination_nd->GetAddress();
						Mac48Address dest_address = Mac48Address::ConvertFrom(addr);
						//cout <<endl<<"MAC address of next hop node "<<next_hop<<" is "<<dest_address<<endl;
					  	uint16_t protocolwave = 0x88dc;//
						Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (wifidevices.Get(destination_node_id -2));
						cout<<"DSRC data Unicasting from node "<<destination_node_id - 2<<endl;
						dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
						Simulator::Schedule (Seconds(0.000000) , &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);
					}
					
					
					Y[destination_node_id - 2] = Y[destination_node_id - 2] + 1;	
					//cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
					
				}
			}
			if (destination_node_id == destination)
			{
				cout<<"packet successfully delivered to destination node"<<destination_node_id - 2<<endl;
				dsrc_packet_final_timestamp[node_index+2] = Simulator::Now().GetSeconds();
				std::cout << "Received data unicasted packet from "<< tag_routing.GetsenderId()<<"to node "<<destination_node_id -2 <<"of size "<<tag_routing.GetSerializedSize()<<" at position "<< *tag_routing.Getposition()<<"with velocity "<<*tag_routing.Getvelocity()<<"with acceleration "<<*tag_routing.Getacceleration()<<"packet timestamp "<< tag_routing.GetTimestamp()->GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tag_routing.GetTimestamp()->GetMicroSeconds()<<"us"<<std::endl;
			}
		}
	*/
	}	
	
	//pkt->RemoveAtEnd(1000);
	//pkt->RemoveAllPacketTags();
}


// ── test_boolean() ─────────────────────────────────────────────────────────────
void test_boolean()
{
	for(uint32_t i=0;i<101;i++)
	{
		for(uint32_t j=0;j<20;j++)
		{
			bool attacking_state2 = GetBooleanWithProbability(i, j);
			cout<<"probability is "<<i<<"attack state is "<<attacking_state2<<"for source node "<<j<<endl;
		}
	}
	
	for(uint32_t j=0;j<total_size;j++)
	{
			
			cout<<"For "<<j<<"th node, location attack state is "<<location_malicious_nodes[j]<<endl;
			cout<<"For "<<j<<"th node, floodin attack state is "<<flooding_malicious_nodes[j]<<endl;
			cout<<"For "<<j<<"th node, fabrication attack state is "<<fabrication_malicious_nodes[j]<<endl;
			cout<<"For "<<j<<"th node, MIM attack state is "<<MIM_malicious_nodes[j]<<endl;
			cout<<"For "<<j<<"th node, vanishing attack state is "<<vanishing_malicious_nodes[j]<<endl;
			cout<<"Node "<<j<<"controller ID "<<node_controller_ID[j]<<endl;
	}
	
}

// ── reset_packet_timestamps() ─────────────────────────────────────────────────────────────
void  reset_packet_timestamps()
{
	for(uint32_t n=0; n<2;n++)
	{
		for(uint32_t k=0; k<2;k++)
		{
			for (uint32_t i=0; i<total_size ; i++)
			{
				for(uint32_t j=0; j<total_size;j++)
				{
					routing_packet_initial_timestampLLDP[n][k][i][j] = Simulator::Now().GetSeconds();
					for(uint32_t l=0;l<total_size;l++)
					{
						intercepted_packet_initial_timestampLLDP[n][k][i][j][l] = Simulator::Now().GetSeconds();
						intercepted_packet_final_timestampLLDP[n][k][i][j][l] = Simulator::Now().GetSeconds();
					}
					routing_packet_final_timestampLLDP[n][k][i][j] = Simulator::Now().GetSeconds();
				}
			}
		}
	}
}

// ── send_dsrc_data_unicast() ──────────────────────────────────────────────
void send_dsrc_data_unicast(Ptr <Node> source_node, uint32_t node_index, uint32_t destination, uint32_t port_id)
{
	    
	cout<<"Data unicast: transmiiting a packet at "<<Now().GetMilliSeconds()<<endl;
	uint32_t nid = source_node->GetId();
	//cout<<"original node id is "<<nid<<endl;
	//uint32_t next_hop = routing_tables[node_index].rows[destination].next_hop;
	
	double next_hop_exist = B_mat[nid-2][destination][port_id][port_id];
	cout<<"next hop exists :"<<next_hop_exist<<endl;
	//if (next_hop_exist)
	//{
		routing_packet_initial_timestampLLDP[port_id][port_id][nid-2][destination] = Simulator::Now().GetSeconds();
		//intercepted_packet_initial_timestampLLDP[port_id][nid-2][destination] = Simulator::Now().GetSeconds();
		Ptr <NetDevice> source_nd;
		Ptr <NetDevice> destination_nd;
		Address addr;
		Mac48Address dest_address;
		//cout <<endl<<"MAC address of next hop node "<<next_hop<<" is "<<dest_address<<endl;
	  	uint16_t protocolwave = 0x88dc;//
	  	Ptr <WifiNetDevice> wdi;
	  	
	  	uint32_t remainder = destination%2;
	  	if(port_id == 0)
	  	{
			if(remainder == 0)
			{
				destination_nd = wifidevices_180.Get(destination);
				addr = destination_nd->GetAddress();
				dest_address = Mac48Address::ConvertFrom(addr);
				source_nd = wifidevices_180.Get(node_index);
				wdi = DynamicCast <WifiNetDevice> (source_nd);
			}
			else
			{
				destination_nd = wifidevices_176.Get(destination);
				addr = destination_nd->GetAddress();
				dest_address = Mac48Address::ConvertFrom(addr);
				source_nd = wifidevices_176.Get(node_index);
				wdi = DynamicCast <WifiNetDevice> (source_nd);
			}
		    
		}
		else
		{
			if(remainder == 0)
			{
				destination_nd = wifidevices_182.Get(destination);
				addr = destination_nd->GetAddress();
				dest_address = Mac48Address::ConvertFrom(addr);
				source_nd = wifidevices_182.Get(node_index);
				wdi = DynamicCast <WifiNetDevice> (source_nd);
			}
			else
			{
				destination_nd = wifidevices_174.Get(destination);
				addr = destination_nd->GetAddress();
				dest_address = Mac48Address::ConvertFrom(addr);
				source_nd = wifidevices_174.Get(node_index);
				wdi = DynamicCast <WifiNetDevice> (source_nd);
			}

		
		}
		Ptr <Node> ni = DynamicCast <Node> (source_node);
		CustomDataUnicastTag_Routing tag;
		//uint32_t nid = uint32_t(ni->GetId());
		dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
		Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (source_node->GetObject<MobilityModel>());
		Vector posi = mdl->GetPosition();
		Vector current_velocity = mdl->GetVelocity();
		double delta_t = data_transmission_period;
		Vector acceleration = calculate_acceleration(previous_velocity_dsrc[node_index],current_velocity,delta_t);
		Time ti = Seconds(Simulator::Now().GetSeconds());
		Ptr <Packet> packet_i = Create<Packet> (0);
		tag.SetPortId(&port_id);
		tag.SetsenderId(nid-2);
		
		// MRTPA Attack Scenario 1: Vehicle sends CLEAN trajectory data.
		// Poisoning occurs at the RSU level in HandleReadOne() per Algorithm 1.
		// The vehicle (Phase 1) generates and transmits its real trajectory.
		cout << "[MRTPA Phase 1] Vehicle " << node_index << " sending trajectory to RSU at t="
		     << Simulator::Now().GetSeconds() << "s pos=(" << posi.x << "," << posi.y << ")" << endl;

		// ── Direct blockchain storage for V2RSU trajectory ──────────────
		// Store regardless of wifi link distance (DSRC range is logical in this model).
		// Algorithm 1, Line 19: Store ground truth Dlegit on blockchain.
		if (attack_number == 1 && node_index < N_Vehicles) {
			std::string vID  = "Vehicle" + std::to_string(node_index);
			std::string rID  = "RSU"     + std::to_string(destination - N_Vehicles);
			double cur_t = Simulator::Now().GetSeconds();
			// Store honest trajectory
			StoreTrajectoryToBlockchain(vID, rID, posi, current_velocity, acceleration, cur_t, false);
			total_trajectories_received++;
			// Algorithm 1, Line 21-24: If RSU is malicious, also store poisoned version
			if (destination < (uint32_t)(N_Vehicles + N_RSUs) &&
			    trajectory_poisoning_malicious_nodes[destination]) {
				Vector poisoned_pos = posi;
				Vector poisoned_vel = current_velocity;
				Vector poisoned_acc = acceleration;
				PoisonTrajectory(poisoned_pos, poisoned_vel, poisoned_acc, poisoning_intensity_theta);
				EnforceRealism(poisoned_pos, poisoned_vel, poisoned_acc);
				StoreTrajectoryToBlockchain(vID + "_poisoned", rID,
				    poisoned_pos, poisoned_vel, poisoned_acc, cur_t, true);
				total_trajectories_poisoned++;
			}
		}
		// ────────────────────────────────────────────────────────────────

		if(routing_algorithm == 4)
		{
			cout<<"Tryring to encyprt node id"<<endl;
			std::string filename_sign_AES = NS3_ROOT "/analytics/data/security_nodepair_AES_data.csv";
			string encrypted_nid = read_other_other_item_from_csv(filename_sign_AES, std::to_string(node_index), std::to_string(destination), std::to_string(port_id), 3);
			cout<<"Encrypted string is "<<encrypted_nid<<endl;
			const uint8_t* byteArray = reinterpret_cast<const uint8_t*>(encrypted_nid.data());
			cout<<byteArray<<endl;
		}
		
		tag.SetNodeId(&nid);
		tag.Setposition(&posi);
		tag.Setvelocity(&current_velocity);
		tag.Setacceleration(&acceleration);
		tag.SetTimestamp(&ti);
		tag.SetdestinationId(destination);
		uint32_t * port = tag.GetPortId();
		cout<<"This is source node. DSRC data Unicasting from node "<<nid - 2<<"from port "<<*port<<endl;
		
		packet_i->AddPacketTag(tag);
		dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
		Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);
		uint32_t * pt = tag.GetNodeId();
		//cout<<"node id from tag is "<<*pt<<endl;	
		Y[*pt - 2] = Y[*pt -2] + 1;
		//cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
		previous_velocity_dsrc[node_index] = current_velocity;
}

// ── centralized_dsrc_data_unicast() (real implementation) ────────────────────
void centralized_dsrc_data_unicast(Ptr <Node> source_node, uint32_t node_index, uint32_t destination, uint32_t port_id)
{
	uint32_t link_may_exist;
	if((attack_number == 1) || (attack_number == 6))
	{
		link_may_exist = abs(unit_step(400 - adjacencyMatrix[node_index][destination], 0));
	}
	else
	{
		link_may_exist = abs(unit_step(350 - adjacencyMatrix[node_index][destination], 0));
	}
	
	
	if(routing_algorithm == 4)
	{
		if(link_may_exist == 1)
		{
				Simulator::Schedule(Seconds(0), encrypt_dsrc_data_unicast, node_index, destination, port_id); 
				Simulator::Schedule(Seconds(0.0002), send_dsrc_data_unicast, source_node, node_index, destination, port_id);
		}
	}
	else
	{
		Simulator::Schedule(Seconds(0.0002), send_dsrc_data_unicast, source_node, node_index, destination, port_id);
	}
}
