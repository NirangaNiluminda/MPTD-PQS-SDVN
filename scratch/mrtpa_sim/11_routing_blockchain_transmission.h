// ============================================================
// SECTION 11: Routing Algorithms, Blockchain Init, Transmission
// ============================================================
// This is the main functional core of the simulation.
//
// Routing Algorithms (routing_algorithm parameter selects one):
//   dijkstra()                 - Dijkstra shortest path (used by variants 1-5)
//   dijkstra_stable()          - stability-weighted Dijkstra
//   run_ECMP()                 - Equal-Cost Multi-Path
//   run_DCMR()                 - Delay-Constrained Multipath Routing
//   run_QRSDN()                - QoS-aware SDN routing
//   run_RLMR()                 - Reinforcement Learning Multi-path Routing
//
// Blockchain Integration:
//   initialize_blockchain()    - POST attack config to Hyperledger Fabric
//   declare_attack_states()    - set which attack flags are active
//   declare_attackers()        - randomly assign malicious nodes by attack_percentage
//   call_blockchain()          - generic blockchain REST API call
//   BCTES()                    - Blockchain-based Trust Evaluation System
//   CallBWTRCBFromNS3()        - call BWTRCB external verifier
//   escapeQuotes()             - JSON string escaping
//
// Data Transmission Functions:
//   dsrc_data_broadcast()      - DSRC broadcast to all neighbors
//   dsrc_metadata_broadcast()  - metadata broadcast
//   routing_dsrc_data_unicast()- unicast with routing protocol header
//   hybrid_data_unicast()      - hybrid centralized/distributed unicast
//   send_centralized_packets() - send via centralized SDN controller
//   MacRx()                    - WiFi MAC receive callback (main rx handler)
//   Rx()                       - PHY layer receive callback
//   check_delivery_and_retransmit() - ARQ retransmission logic
//   send_LTE_data_alone/agent()- LTE data path
//   RSU_dataunicast_alone/agent() - RSU direct unicast
//
// Controller Management:
//   assign_controllers()       - assigns RSUs to controllers, sets malicious flags
//   assign_basic_keys()        - distributes initial cryptographic keys
//   calculate_*_metrics()      - per-architecture metric calculation
//
// Optimization:
//   optimize_first_time()      - initial link lifetime optimization
//   optimize_subsequent()      - subsequent optimization rounds
//   predict_DNN_link_lifetime()- DNN-based lifetime prediction
//   predict_DNN_delay()        - DNN-based delay prediction
//   calculate_normalized_mobility() - compute λ_h handover rate
//   calculate_network_contention()  - compute contention level
// ============================================================
double previous_cumulative_jitter_ratio = 0.0;
double current_jitter_ratio = 0.0;
double previous_cumulative_latency = 0.0;
double average_jitter_routing = 0.0;
double current_load_imbalance = 0.0;
double current_load_balance = 0.0;
double average_load_balance = 0.0;
double previous_cumulative_load_imbalance = 0.0;

uint32_t Expected0Actual0 = 0;
uint32_t Expected0Actual1 = 0;
uint32_t Expected1Actual0 = 0;
uint32_t Expected1Actual1 = 0;

void write_csv_results_routing()
{
	fstream fout;
	string filename;

	switch (experiment_number)
	{
		case (0)://qos experiment
			switch(routing_algorithm)
			{
				case(0): //ECMP
					switch(qf)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results/qos/ECMP_qos_0.csv";
							break;
						case(1):
							filename = NS3_ROOT "/analytics/results/qos/ECMP_qos_1.csv";
							break;
						case(2):
							filename = NS3_ROOT "/analytics/results/qos/ECMP_qos_2.csv";
							break;
						case(3):
							filename = NS3_ROOT "/analytics/results/qos/ECMP_qos_3.csv";
							break;
						default:
							break;
					}
					break;
					case(1): //RR
					switch(qf)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results/qos/RR_qos_0.csv";
							break;
						case(1):
							filename = NS3_ROOT "/analytics/results/qos/RR_qos_1.csv";
							break;
						case(2):
							filename = NS3_ROOT "/analytics/results/qos/RR_qos_2.csv";
							break;
						case(3):
							filename = NS3_ROOT "/analytics/results/qos/RR_qos_3.csv";
							break;
						default:
							break;
					}
					break;
					case(2): //QR_SDN
					switch(qf)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results/qos/QR_SDN_qos_0.csv";
							break;
						case(1):
							filename = NS3_ROOT "/analytics/results/qos/QR_SDN_qos_1.csv";
							break;
						case(2):
							filename = NS3_ROOT "/analytics/results/qos/QR_SDN_qos_2.csv";
							break;
						case(3):
							filename = NS3_ROOT "/analytics/results/qos/QR_SDN_qos_3.csv";
							break;
						default:
							break;
					}
					break;
					case(3): //RLMR
					switch(qf)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results/qos/RLMR_qos_0.csv";
							break;
						case(1):
							filename = NS3_ROOT "/analytics/results/qos/RLMR_qos_1.csv";
							break;
						case(2):
							filename = NS3_ROOT "/analytics/results/qos/RLMR_qos_2.csv";
							break;
						case(3):
							filename = NS3_ROOT "/analytics/results/qos/RLMR_qos_3.csv";
							break;
						default:
							break;
					}
					break;
					case(4): //proposed
					switch(qf)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results/qos/proposed_qos_0.csv";
							break;
						case(1):
							filename = NS3_ROOT "/analytics/results/qos/proposed_qos_1.csv";
							break;
						case(2):
							filename = NS3_ROOT "/analytics/results/qos/proposed_qos_2.csv";
							break;
						case(3):
							filename = NS3_ROOT "/analytics/results/qos/proposed_qos_3.csv";
							break;
						default:
							break;
					}
					break;
					
					case(5): //DCMR
					switch(qf)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results/qos/DCMR_qos_0.csv";
							break;
						case(1):
							filename = NS3_ROOT "/analytics/results/qos/DCMR_qos_1.csv";
							break;
						case(2):
							filename = NS3_ROOT "/analytics/results/qos/DCMR_qos_2.csv";
							break;
						case(3):
							filename = NS3_ROOT "/analytics/results/qos/DCMR_qos_3.csv";
							break;
						default:
							break;
					}
					break;
					
				default:
					break;
			}
			break;
		case (1)://flow_size (lambda)
			switch(routing_algorithm)
			{
				case(0)://ECMP
					switch(lambda)
					{
						case(10):
							filename = NS3_ROOT "/analytics/results/flowsize/ECMP_flowsize_10.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/flowsize/ECMP_flowsize_20.csv";
							break;
						case(30):
							filename = NS3_ROOT "/analytics/results/flowsize/ECMP_flowsize_30.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/flowsize/ECMP_flowsize_40.csv";
							break;
						case(47):
							filename = NS3_ROOT "/analytics/results/flowsize/ECMP_flowsize_50.csv";
							break;
						default:
							break;
					}
					break;
				case(1)://RR
					switch(lambda)
					{
						case(10):
							filename = NS3_ROOT "/analytics/results/flowsize/RR_flowsize_10.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/flowsize/RR_flowsize_20.csv";
							break;
						case(30):
							filename = NS3_ROOT "/analytics/results/flowsize/RR_flowsize_30.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/flowsize/RR_flowsize_40.csv";
							break;
						case(47):
							filename = NS3_ROOT "/analytics/results/flowsize/RR_flowsize_50.csv";
							break;
						default:
							break;
					}
					break;
				case(2)://QR-SDN
					switch(lambda)
					{
						case(10):
							filename = NS3_ROOT "/analytics/results/flowsize/QRSDN_flowsize_10.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/flowsize/QRSDN_flowsize_20.csv";
							break;
						case(30):
							filename = NS3_ROOT "/analytics/results/flowsize/QRSDN_flowsize_30.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/flowsize/QRSDN_flowsize_40.csv";
							break;
						case(47):
							filename = NS3_ROOT "/analytics/results/flowsize/QRSDN_flowsize_50.csv";
							break;
						default:
							break;
					}
					break;
				case(3)://RLMR
					switch(lambda)
					{
						case(10):
							filename = NS3_ROOT "/analytics/results/flowsize/RLMR_flowsize_10.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/flowsize/RLMR_flowsize_20.csv";
							break;
						case(30):
							filename = NS3_ROOT "/analytics/results/flowsize/RLMR_flowsize_30.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/flowsize/RLMR_flowsize_40.csv";
							break;
						case(47):
							filename = NS3_ROOT "/analytics/results/flowsize/RLMR_flowsize_50.csv";
							break;
						default:
							break;
					}
					break;
				case(4)://proposed
					switch(lambda)
					{
						
						case(10):
							filename = NS3_ROOT "/analytics/results/flowsize/Proposed_flowsize_10.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/flowsize/Proposed_flowsize_20.csv";
							break;
						case(30):
							filename = NS3_ROOT "/analytics/results/flowsize/Proposed_flowsize_30.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/flowsize/Proposed_flowsize_40.csv";
							break;
						case(47):
							filename = NS3_ROOT "/analytics/results/flowsize/Proposed_flowsize_50.csv";
							break;
						default:
							break;
					}
					break;
				case(5)://DCMR
					switch(lambda)
					{
						case(10):
							filename = NS3_ROOT "/analytics/results/flowsize/DCMR_flowsize_10.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/flowsize/DCMR_flowsize_20.csv";
							break;
						case(30):
							filename = NS3_ROOT "/analytics/results/flowsize/DCMR_flowsize_30.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/flowsize/DCMR_flowsize_40.csv";
							break;
						case(47):
							filename = NS3_ROOT "/analytics/results/flowsize/DCMR_flowsize_50.csv";
							break;
						default:
							break;
					}
					break;
				default:
					break;
			}
			break;
			
		case (2)://mobility
			switch(routing_algorithm)
			{
				case(0)://ECMP
					switch(maxspeed)
					{
						case(8):
							filename = NS3_ROOT "/analytics/results/mobility/ECMP_mobility_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/mobility/ECMP_mobility_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/mobility/ECMP_mobility_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results/mobility/ECMP_mobility_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results/mobility/ECMP_mobility_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/mobility/ECMP_mobility_100.csv";
							break;
						case(120):
							filename = NS3_ROOT "/analytics/results/mobility/ECMP_mobility_120.csv";
							break;
						case(140):
							filename = NS3_ROOT "/analytics/results/mobility/ECMP_mobility_140.csv";
							break;
						default:
							break;
					}
					break;
				case(1)://RR
					switch(maxspeed)
					{
						case(8):
							filename = NS3_ROOT "/analytics/results/mobility/RR_mobility_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/mobility/RR_mobility_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/mobility/RR_mobility_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results/mobility/RR_mobility_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results/mobility/RR_mobility_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/mobility/RR_mobility_100.csv";
							break;
						case(120):
							filename = NS3_ROOT "/analytics/results/mobility/RR_mobility_120.csv";
							break;
						case(140):
							filename = NS3_ROOT "/analytics/results/mobility/RR_mobility_140.csv";
							break;
						default:
							break;
					}
					break;
					case(2)://QR-SDN
					switch(maxspeed)
					{
						case(8):
							filename = NS3_ROOT "/analytics/results/mobility/QRSDN_mobility_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/mobility/QRSDN_mobility_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/mobility/QRSDN_mobility_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results/mobility/QRSDN_mobility_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results/mobility/QRSDN_mobility_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/mobility/QRSDN_mobility_100.csv";
							break;
						case(120):
							filename = NS3_ROOT "/analytics/results/mobility/QRSDN_mobility_120.csv";
							break;
						case(140):
							filename = NS3_ROOT "/analytics/results/mobility/QRSDN_mobility_140.csv";
							break;
						default:
							break;
					}
					break;
				case(3)://RLMR
					switch(maxspeed)
					{
						case(8):
							filename = NS3_ROOT "/analytics/results/mobility/RLMR_mobility_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/mobility/RLMR_mobility_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/mobility/RLMR_mobility_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results/mobility/RLMR_mobility_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results/mobility/RLMR_mobility_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/mobility/RLMR_mobility_100.csv";
							break;
						case(120):
							filename = NS3_ROOT "/analytics/results/mobility/RLMR_mobility_120.csv";
							break;
						case(140):
							filename = NS3_ROOT "/analytics/results/mobility/RLMR_mobility_140.csv";
							break;
						default:
							break;
					}
					break;
				case(4)://Proposed
					switch(maxspeed)
					{
						case(8):
							filename = NS3_ROOT "/analytics/results/mobility/Proposed_mobility_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results/mobility/Proposed_mobility_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results/mobility/Proposed_mobility_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results/mobility/Proposed_mobility_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results/mobility/Proposed_mobility_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/mobility/Proposed_mobility_100.csv";
							break;
						case(120):
							filename = NS3_ROOT "/analytics/results/mobility/Proposed_mobility_120.csv";
							break;
						case(140):
							filename = NS3_ROOT "/analytics/results/mobility/Proposed_mobility_140.csv";
							break;
						default:
							break;
					}
					break;
				 	case(5)://DCMR
					switch(maxspeed)
					{
						case(40):
							filename = NS3_ROOT "/analytics/results/mobility/DCMR_mobility_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results/mobility/DCMR_mobility_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results/mobility/DCMR_mobility_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/mobility/DCMR_mobility_100.csv";
							break;
						case(120):
							filename = NS3_ROOT "/analytics/results/mobility/DCMR_mobility_120.csv";
							break;
						default:
							break;
					}
					break;
				default:
					break;
			}
			break;
		case (3)://network size
			switch(routing_algorithm)
			{
				case(0)://ECMP
					switch(total_size)
					{
						case(150):
							filename = NS3_ROOT "/analytics/results/nodesize/ECMP_nodes_150.csv";
							break;
						case(125):
							filename = NS3_ROOT "/analytics/results/nodesize/ECMP_nodes_125.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/nodesize/ECMP_nodes_100.csv";
							break;
						case(75):
							filename = NS3_ROOT "/analytics/results/nodesize/ECMP_nodes_75.csv";
							break;
						case(50):
							filename = NS3_ROOT "/analytics/results/nodesize/ECMP_nodes_50.csv";
							break;
						case(25):
							filename = NS3_ROOT "/analytics/results/nodesize/ECMP_nodes_25.csv";
							break;
						default:
							break;
					}
					break;
				case(1)://RR
					switch(total_size)
					{
						case(150):
							filename = NS3_ROOT "/analytics/results/nodesize/RR_nodes_150.csv";
							break;
						case(125):
							filename = NS3_ROOT "/analytics/results/nodesize/RR_nodes_125.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/nodesize/RR_nodes_100.csv";
							break;
						case(75):
							filename = NS3_ROOT "/analytics/results/nodesize/RR_nodes_75.csv";
							break;
						case(50):
							filename = NS3_ROOT "/analytics/results/nodesize/RR_nodes_50.csv";
							break;
						case(25):
							filename = NS3_ROOT "/analytics/results/nodesize/RR_nodes_25.csv";
							break;
						default:
							break;
					}
					break;
				case(2)://QRSDN
					switch(total_size)
					{
						case(150):
							filename = NS3_ROOT "/analytics/results/nodesize/QRSDN_nodes_150.csv";
							break;
						case(125):
							filename = NS3_ROOT "/analytics/results/nodesize/QRSDN_nodes_125.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/nodesize/QRSDN_nodes_100.csv";
							break;
						case(75):
							filename = NS3_ROOT "/analytics/results/nodesize/QRSDN_nodes_75.csv";
							break;
						case(50):
							filename = NS3_ROOT "/analytics/results/nodesize/QRSDN_nodes_50.csv";
							break;
						case(25):
							filename = NS3_ROOT "/analytics/results/nodesize/QRSDN_nodes_25.csv";
							break;
						default:
							break;
					}
					break;
				case(3)://RLMR
					switch(total_size)
					{
						case(150):
							filename = NS3_ROOT "/analytics/results/nodesize/RLMR_nodes_150.csv";
							break;
						case(125):
							filename = NS3_ROOT "/analytics/results/nodesize/RLMR_nodes_125.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/nodesize/RLMR_nodes_100.csv";
							break;
						case(75):
							filename = NS3_ROOT "/analytics/results/nodesize/RLMR_nodes_75.csv";
							break;
						case(50):
							filename = NS3_ROOT "/analytics/results/nodesize/RLMR_nodes_50.csv";
							break;
						case(25):
							filename = NS3_ROOT "/analytics/results/nodesize/RLMR_nodes_25.csv";
							break;
						default:
							break;
					}
					break;
				case(4)://Proposed
					switch(total_size)
					{
						case(150):
							filename = NS3_ROOT "/analytics/results/nodesize/Proposed_nodes_150.csv";
							break;
						case(125):
							filename = NS3_ROOT "/analytics/results/nodesize/Proposed_nodes_125.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/nodesize/Proposed_nodes_100.csv";
							break;
						case(75):
							filename = NS3_ROOT "/analytics/results/nodesize/Proposed_nodes_75.csv";
							break;
						case(50):
							filename = NS3_ROOT "/analytics/results/nodesize/Proposed_nodes_50.csv";
							break;
						case(25):
							filename = NS3_ROOT "/analytics/results/nodesize/Proposed_nodes_25.csv";
							break;
						default:
							break;
					}
					break;
				case(5)://
					switch(total_size)
					{
						case(150):
							filename = NS3_ROOT "/analytics/results/nodesize/DCMR_nodes_150.csv";
							break;
						case(125):
							filename = NS3_ROOT "/analytics/results/nodesize/DCMR_nodes_125.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results/nodesize/DCMR_nodes_100.csv";
							break;
						case(75):
							filename = NS3_ROOT "/analytics/results/nodesize/DCMR_nodes_75.csv";
							break;
						case(50):
							filename = NS3_ROOT "/analytics/results/nodesize/DCMR_nodes_50.csv";
							break;
						case(25):
							filename = NS3_ROOT "/analytics/results/nodesize/DCMR_nodes_25.csv";
							break;
						default:
							break;
					}
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}	
	
	fout.open(filename,ios::out|ios::app);

	fout << data_gathering_cycle_number << ", "
	     << 1000.0*current_latency_routing << ", "
	     << 1000.0*average_latency_routing << ", "
	     << 100.0*current_packet_delivery_ratio << ", "
	     << 100.0*average_packet_delivery_ratio_dsrc << ", "
	     << 1000.0*current_jitter_ratio<< ", "
	     << 1000.0*average_jitter_routing << ", "
	     << current_load_balance<< ", "
	     << average_load_balance<< ", "
	     << "\n";
	data_gathering_cycle_number++;
	fout.close();
	cout<<"written to file successfully"<<endl;
}

void write_csv_results_LLDP()
{
	
	cout<<"Writing results to CSV"<<endl;
	fstream fout;
	string filename;

	switch (experiment_number)
	{
		case (0)://individual attacks
			switch(attack_number)
			{
				case(1)://Attack 1
					switch(routing_algorithm)
					{
						case(0): //port-based
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack1_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack1_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack1_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack1_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack1_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack1_100.csv";
								break;
							default:
								break;
						}
						break;
						case(1): //Normal LLDP
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack1_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack1_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack1_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack1_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack1_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack1_100.csv";
								break;
							default:
								break;
						}
						break;
						case(2): //Pure_crypto
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack1_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack1_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack1_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack1_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack1_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack1_100.csv";
								break;
							default:
								break;
						}
						break;
						case(3): //Link guard
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack1_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack1_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack1_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack1_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack1_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack1_100.csv";
								break;
							default:
								break;
						}
						break;
						case(4): //proposed
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack1_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack1_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack1_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack1_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack1_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack1_100.csv";
								break;
							default:
								break;
						}
						break;
						
						case(5): //HELLO
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack1_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack1_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack1_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack1_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack1_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack1_100.csv";
								break;
							default:
								break;
						}
						break;
						default:
						break;
					}
					break;
				case(2)://Attack 2
					switch(routing_algorithm)
					{
						case(0): //port-based
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack2_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack2_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack2_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack2_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack2_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack2_100.csv";
								break;
							default:
								break;
						}
						break;
						case(1): //Normal LLDP
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack2_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack2_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack2_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack2_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack2_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack2_100.csv";
								break;
							default:
								break;
						}
						break;
						case(2): //Pure_crypto
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack2_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack2_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack2_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack2_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack2_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack2_100.csv";
								break;
							default:
								break;
						}
						break;
						case(3): //Link guard
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack2_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack2_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack2_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack2_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack2_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack2_100.csv";
								break;
							default:
								break;
						}
						break;
						case(4): //proposed
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack2_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack2_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack2_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack2_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack2_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack2_100.csv";
								break;
							default:
								break;
						}
						break;
						
						case(5): //HELLO
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack2_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack2_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack2_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack2_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack2_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack2_100.csv";
								break;
							default:
								break;
						}
						break;
						default:
						break;
					}
				break;
				case(3)://Attack 3
					switch(routing_algorithm)
					{
						case(0): //port-based
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack3_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack3_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack3_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack3_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack3_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack3_100.csv";
								break;
							default:
								break;
						}
						break;
						case(1): //Normal LLDP
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack3_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack3_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack3_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack3_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack3_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack3_100.csv";
								break;
							default:
								break;
						}
						break;
						case(2): //Pure_crypto
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack3_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack3_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack3_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack3_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack3_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack3_100.csv";
								break;
							default:
								break;
						}
						break;
						case(3): //Link guard
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack3_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack3_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack3_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack3_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack3_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack3_100.csv";
								break;
							default:
								break;
						}
						break;
						case(4): //proposed
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack3_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack3_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack3_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack3_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack3_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack3_100.csv";
								break;
							default:
								break;
						}
						break;
						
						case(5): //HELLO
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack3_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack3_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack3_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack3_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack3_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack3_100.csv";
								break;
							default:
								break;
						}
						break;
						default:
						break;
					}
				break;
				case(4)://Attack 4
					switch(routing_algorithm)
					{
						case(0): //port-based
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack4_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack4_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack4_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack4_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack4_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack4_100.csv";
								break;
							default:
								break;
						}
						break;
						case(1): //Normal LLDP
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack4_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack4_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack4_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack4_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack4_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack4_100.csv";
								break;
							default:
								break;
						}
						break;
						case(2): //Pure_crypto
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack4_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack4_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack4_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack4_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack4_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack4_100.csv";
								break;
							default:
								break;
						}
						break;
						case(3): //Link guard
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack4_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack4_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack4_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack4_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack4_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack4_100.csv";
								break;
							default:
								break;
						}
						break;
						case(4): //proposed
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack4_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack4_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack4_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack4_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack4_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack4_100.csv";
								break;
							default:
								break;
						}
						break;
						
						case(5): //HELLO
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack4_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack4_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack4_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack4_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack4_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack4_100.csv";
								break;
							default:
								break;
						}
						break;
						default:
						break;
					}
				break;
				case(5)://Attack 5
				switch(routing_algorithm)
				{
					case(0): //port-based
					switch(attack_percentage)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack5_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack5_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack5_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack5_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Attack5_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Portbased_Atack5_100.csv";
							break;
						default:
							break;
					}
					break;
					case(1): //Normal LLDP
					switch(attack_percentage)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack5_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack5_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack5_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack5_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack5_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/NormalLLDP_Attack5_100.csv";
							break;
						default:
							break;
					}
					break;
					case(2): //Pure_crypto
					switch(attack_percentage)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack5_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack5_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack5_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack5_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack5_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/Purecrypto_Attack5_100.csv";
							break;
						default:
							break;
					}
					break;
					case(3): //Link guard
					switch(attack_percentage)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack5_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack5_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack5_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack5_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack5_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/LinkGuard_Attack5_100.csv";
							break;
						default:
							break;
					}
					break;
					case(4): //proposed
					switch(attack_percentage)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack5_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack5_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack5_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack5_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack5_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/proposed_Attack5_100.csv";
							break;
						default:
							break;
					}
					break;
					
					case(5): //HELLO
					switch(attack_percentage)
					{
						case(0):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack5_0.csv";
							break;
						case(20):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack5_20.csv";
							break;
						case(40):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack5_40.csv";
							break;
						case(60):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack5_60.csv";
							break;
						case(80):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack5_80.csv";
							break;
						case(100):
							filename = NS3_ROOT "/analytics/results_LLDP/individual/HELLO_Attack5_100.csv";
							break;
						default:
							break;
					}
					break;
					default:
					break;
				}
				break;
				
				default:
				break;
			}
		break;
		case (1)://combined attack
			if(attack_number == 6)
			{
				switch(routing_algorithm)
				{
					case(0)://Portbased
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Portbased_combined_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Portbased_combined_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Portbased_combined_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Portbased_combined_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Portbased_combined_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Portbased_combined_100.csv";
								break;
							default:
								break;
						}
						
					break;
					case(1)://Normal_LLDP
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Normal_LLDP_combined_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Normal_LLDP_combined_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Normal_LLDP_combined_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Normal_LLDP_combined_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Normal_LLDP_combined_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Normal_LLDP_combined_100.csv";
								break;
							default:
								break;
						}
						break;
					case(2)://Pure-crypto
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Pure_crypto_combined_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Pure_crypto_combined_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Pure_crypto_combined_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Pure_crypto_combined_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Pure_crypto_combined_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Pure_crypto_combined_100.csv";
								break;
							default:
								break;
						}
						break;
					case(3)://Link Guard
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/LinkGuard_combined_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/LinkGuard_combined_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/LinkGuard_combined_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/LinkGuard_combined_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/LinkGuard_combined_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/LinkGuard_combined_100.csv";
								break;
							default:
								break;
						}
						break;
					case(4)://proposed
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Proposed_combined_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Proposed_combined_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Proposed_combined_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Proposed_combined_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Proposed_combined_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/Proposed_combined_100.csv";
								break;
							default:
								break;
						}
						break;
					case(5)://HELLO
						switch(attack_percentage)
						{
							case(0):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/HELLO_combined_0.csv";
								break;
							case(20):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/HELLO_combined_20.csv";
								break;
							case(40):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/HELLO_combined_40.csv";
								break;
							case(60):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/HELLO_combined_60.csv";
								break;
							case(80):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/HELLO_combined_80.csv";
								break;
							case(100):
								filename = NS3_ROOT "/analytics/results_LLDP/combined/HELLO_combined_100.csv";
								break;
							default:
								break;
						}
						break;
					default:
						break;
			}
			}
		break;
		default:
			break;
	}	
	
	fout.open(filename,ios::out|ios::app);

	fout << data_gathering_cycle_number << ", "
	     << 100.0*current_packet_delivery_ratio << ", "
	     << 100.0*average_packet_delivery_ratio_dsrc << ", "
	     << current_channel_utilization << ", "
	     << average_channel_utilization<< ", "
	     << 100.0*current_intercepted_ratio<< ", "
	     << 100.0*average_intercepted_ratio << ", "
	     << current_computational_complexity<< ", "
	     << average_computational_complexity<< ", "
	     << current_routing_latency<< ", "
	     << average_routing_latency << ", "
	     << 6*Expected0Actual0<<", "
	     << 6*Expected0Actual1<<", "
	     << 6*Expected1Actual0<<", "
	     << 6*Expected1Actual1<<", "
	     << current_packet_confusion_ratio<< ", "
	     << average_packet_confusion<< ", "
	     << "\n";
	data_gathering_cycle_number++;
	fout.close();
	cout<<"written to file successfully"<<endl;
}



vector<vector<double>> I;
vector<vector<double>> D_old(total_size, vector<double>(total_size, 0.0));
vector<vector<double>> D(total_size, vector<double>(total_size, 0.0));
vector<vector<double>> old_adjacencyMatrix(total_size, vector<double>(total_size, 0.0));
vector<vector<double>> adjacencyMatrix;
vector<vector<double>> linklifetimeMatrix_dsrc;
vector<vector<double>> linklifetimeMatrix_ethernet;
vector<vector<double>> delayMatrix_dsrc;
vector<vector<double>> delayMatrix_ethernet;

double shortestDistances[total_size];
vector<int> parents[total_size];
int NO_PARENT = -1;
 
// Function to print shortest path
// from source to currentVertex
// using parents array
void printPath(uint32_t vertexIndex)
{
    uint32_t size = parents[vertexIndex].size();
    for (uint32_t i=0; i<size; i++)
    {
    	cout << parents[vertexIndex][i] << " ";
    }
    cout << vertexIndex;
}
 
// A utility function to print
// the constructed distances
// array and shortest paths
void printSolution(int startVertex)
{
    uint32_t nVertices = total_size;
    cout << "Vertex\t Distance\tPath";
 
    for (uint32_t vertexIndex = 0; vertexIndex < nVertices; vertexIndex++) 
    {
            cout << "\n" << startVertex << " -> ";
            cout << vertexIndex << " \t\t ";
            cout << shortestDistances[vertexIndex] << "\t\t";
            printPath(vertexIndex);
    }
}
 
// Function that implements Dijkstra's
// single source shortest path
// algorithm for a graph represented
// using adjacency matrix
// representation
 
void dijkstra(vector<vector<double> > adjacencyMatrix,
              uint32_t startVertex)
{
    uint32_t nVertices = adjacencyMatrix[0].size();
    cout<<nVertices<<endl;
 
    // shortestDistances[i] will hold the
    // shortest distance from src to i
    
 
    // added[i] will true if vertex i is
    // included / in shortest path tree
    // or shortest distance from src to
    // i is finalized
    bool added[nVertices];
 
    // Initialize all distances as
    // INFINITE and added[] as false
    for (uint32_t vertexIndex = 0; vertexIndex < nVertices; vertexIndex++) 
    {
        shortestDistances[vertexIndex] = double(INT_MAX);
        added[vertexIndex] = false;
    }
 
    // Distance of source vertex from
    // itself is always 0
    shortestDistances[startVertex] = 0;
 
    // Parent array to store shortest
    // path tree
    vector<int> new_parents[total_size];
 
    // The starting vertex does not
    // have a parent
    new_parents[startVertex].push_back(startVertex);
 
    // Find shortest path for all
    // vertices
    for (uint32_t i = 1; i < nVertices; i++) 
    {
        // Pick the minimum distance vertex
        // from the set of vertices not yet
        // processed. nearestVertex is
        // always equal to startNode in
        // first iteration.
        uint32_t nearestVertex = large;
        double shortestDistance = double(INT_MAX);
        
        for (uint32_t vertexIndex = 0; vertexIndex < nVertices; vertexIndex++) 
        {
            if ((!added[vertexIndex]) && (shortestDistances[vertexIndex] < shortestDistance)) 
            {
                nearestVertex = vertexIndex;
                shortestDistance = shortestDistances[vertexIndex];     
            }
        }  
 	//cout <<"iteration "<< i << "shortest distance "<<shortestDistance<<endl;
        // Mark the picked vertex as
        // processed
        added[nearestVertex] = true;
        cout<<"nearest vertex is "<<nearestVertex<<endl;
 
        // Update dist value of the
        // adjacent vertices of the
        // picked vertex.
        for (uint32_t vertexIndex = 0; vertexIndex < nVertices;vertexIndex++)
        {
            double edgeDistance = adjacencyMatrix[nearestVertex][vertexIndex];
            //cout<<"edge distance is "<<edgeDistance<<endl;
 
            if ((edgeDistance > 0.0) && ((shortestDistance + edgeDistance) <= (shortestDistances[vertexIndex]))) 
            {
            	//cout<<"parent is "<<nearestVertex;
                new_parents[vertexIndex].push_back(nearestVertex);
                shortestDistances[vertexIndex] = shortestDistance + edgeDistance;
                //cout<<"shortest distances at vertex index "<<vertexIndex<<"is "<<shortestDistances[vertexIndex];
            }
        }
    }
    for (uint32_t source=0;source<total_size;source++)
    {
    	parents[source] = new_parents[source];
    	uint32_t n = new_parents[source].size();	
    	uint32_t path[total_size];
    	path[0] = source;
    	for (uint32_t i=1;i<total_size;i++)
    	{
    		int sh = n-i+1;
    		if((sh) > 0)
    		{
    			path[i] = new_parents[source][n-i];
    			//cout<<"n is "<<n<<"is "<<"i is "<<i<<new_parents[source][n-i-1]<<endl;
    		}
    		else
    		{
    			path[i] = large;
    		}
    	}

    	//cout<<path[0];
    	update_proposed_route(source, startVertex, path);
    }
    printSolution(startVertex);
}



vector<double> node_distance[total_size];
vector<double> exp_link_state[total_size];
vector<double> exp_link_state_difference[total_size];

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

double R_max = 278;

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
vector<vector<vector<vector<double>>>> B_mat;
vector<vector<vector<vector<double>>>> D_mat;
vector<vector<vector<vector<double>>>> I_mat;

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

struct proposed_algo2_output
{
	uint32_t Y[total_size];
	double U[total_size];
	int32_t conn[total_size];
	bool met[total_size];
	uint32_t paths;
};

struct proposed_algo2_output proposed_algo2_output_inst[2*flows];

struct distance_algo2_output
{
	uint32_t Y[total_size];
	double D[total_size];
	int32_t conn[total_size];
	bool met[total_size];
	uint32_t paths;
};

struct distance_algo2_output distance_algo2_output_inst[2*flows];

double minimum(double x, double y)
{
	if(x<y)
	{
		return x;
	}
	else
	{
		return y;
	}

}

double average(double x, double y)
{
	double average = (x+y)/2.0;
	return average;

}

void update_stable(uint32_t flow_id, uint32_t current_hop)
{
	proposed_algo2_output_inst[flow_id].met[current_hop] = true;
	for(uint32_t i=0;i<total_size;i++)
	{
		if(linklifetimeMatrix_dsrc[current_hop][i] >link_lifetime_threshold)
		{
			if(i== (demanding_flow_struct_controller_inst+flow_id)->source)
			{
				proposed_algo2_output_inst[flow_id].paths++;
				proposed_algo2_output_inst[flow_id].conn[i] = 1;
			}
			
			else
			{
				if((proposed_algo2_output_inst[flow_id].met[i] = false)||(proposed_algo2_output_inst[flow_id].Y[i] >= ((proposed_algo2_output_inst[flow_id].Y[current_hop] + 1))))
				{
					proposed_algo2_output_inst[flow_id].Y[i] = proposed_algo2_output_inst[flow_id].Y[current_hop] + 1;
					proposed_algo2_output_inst[flow_id].conn[i] = 1;
					proposed_algo2_output_inst[flow_id].U[i] = minimum(linklifetimeMatrix_dsrc[current_hop][i], proposed_algo2_output_inst[flow_id].U[current_hop]);
					update_stable(flow_id, i);
					
					
					//cout<<"Flow ID "<<flow_id<<"Stable routing: updated values at node "<<i<<"stability "<<proposed_algo2_output_inst[flow_id].U[i]<<"connectivity "<< proposed_algo2_output_inst[flow_id].conn[i]<<"number of hops "<< proposed_algo2_output_inst[flow_id].Y[i]<<endl;

				}
			
			}
		
		}
	}
}

void run_stable_path_finding(uint32_t flow_id)
{
	cout<<"Stable Path finding "<<endl;
	uint32_t source = (demanding_flow_struct_controller_inst+flow_id)->source;
	cout<<source<<endl;
	uint32_t destination =	(demanding_flow_struct_controller_inst+flow_id)->destination;
	cout<<destination<<endl;
	for(uint32_t i=0; i<total_size; i++)
	{
		cout<<i<<endl;
		proposed_algo2_output_inst[flow_id].met[i] = false;
		proposed_algo2_output_inst[flow_id].Y[i] = 1000;
		proposed_algo2_output_inst[flow_id].U[i] = 1e-9;
		proposed_algo2_output_inst[flow_id].conn[i] = -1;
	}
	proposed_algo2_output_inst[flow_id].paths = 0;
	proposed_algo2_output_inst[flow_id].U[destination] = 1e9;
	proposed_algo2_output_inst[flow_id].conn[destination] = 1;
	proposed_algo2_output_inst[flow_id].Y[destination] = 0;
	update_stable(flow_id, destination);
	cout<<"Routing stable: Number of stable paths from source: "<<source<<"to destination "<<destination<<"is "<<proposed_algo2_output_inst[flow_id].paths<<" at timestamp "<<Now().GetSeconds()<<endl;

}

void update_unstable(uint32_t flow_id, uint32_t current_hop)
{
	distance_algo2_output_inst[flow_id].met[current_hop] = true;
	for(uint32_t i=0;i<total_size;i++)
	{
		if(linklifetimeMatrix_dsrc[current_hop][i] >0.0)
		{
			if(i== (demanding_flow_struct_controller_inst+flow_id)->source)
			{
				distance_algo2_output_inst[flow_id].paths++;
				distance_algo2_output_inst[flow_id].conn[i] = 1;
			}
			
			else
			{
				double value = distance_algo2_output_inst[flow_id].D[current_hop] + adjacencyMatrix[current_hop][i];
				if((distance_algo2_output_inst[flow_id].met[i] = false)||(distance_algo2_output_inst[flow_id].D[i] > value))
				{
					distance_algo2_output_inst[flow_id].Y[i] = distance_algo2_output_inst[flow_id].Y[current_hop] + 1;
					distance_algo2_output_inst[flow_id].D[i] = value;
					distance_algo2_output_inst[flow_id].conn[i] = 1;
					update_unstable(flow_id, i);
					//cout<<"Distance routing: updated values at node "<<i<<"distance "<<distance_algo2_output_inst[flow_id].D[i]<<"connectivity "<<distance_algo2_output_inst[flow_id].conn[i]<<"number of hops "<< distance_algo2_output_inst[flow_id].Y[i]<<endl;
				}
			
			}
		
		}
	}
}

void run_distance_path_finding(uint32_t flow_id)
{
	cout<<"Running distance path finding"<<endl;
	uint32_t source = (demanding_flow_struct_controller_inst+flow_id)->source;
	cout<<source<<endl;
	uint32_t destination =	(demanding_flow_struct_controller_inst+flow_id)->destination;
	cout<<destination<<endl;
	for(uint32_t i=0; i<total_size; i++)
	{
		distance_algo2_output_inst[flow_id].met[i] = false;
		distance_algo2_output_inst[flow_id].Y[i] = 1000;
		distance_algo2_output_inst[flow_id].D[i] = 1e9;
		distance_algo2_output_inst[flow_id].conn[i] = -1;
		cout<<i<<endl;
	}
	distance_algo2_output_inst[flow_id].paths = 0;
	distance_algo2_output_inst[flow_id].conn[destination] = 1;
	distance_algo2_output_inst[flow_id].D[destination] = 1e-9;
	distance_algo2_output_inst[flow_id].Y[destination] = 0;
	update_unstable(flow_id, destination);
	cout<<"Routing distance-based: Number of paths from source: "<<source<<"to destination "<<destination<<"is "<<distance_algo2_output_inst[flow_id].paths<<" at timestamp "<<Now().GetSeconds()<<endl;
}


void update_flows()
{
	  cout<<"updating flows - path finding at"<<Now().GetSeconds()<<endl;
	  if(routing_algorithm == 4)
	  {	
		generate_adjacency_matrix();
	  	for(uint32_t i=0;i<2*flows;i++)
	  	{
	  		Simulator::Schedule(Seconds(0.000005*(i+1)), run_stable_path_finding, i);
	  	}
	  }
	  else
	  {
	  	generate_adjacency_matrix();
	  	for(uint32_t i=0;i<2*flows;i++)
	  	{
	  		Simulator::Schedule(Seconds(0.000005*(i+1)), run_distance_path_finding, i);
	  	}
	  	
	  }

}
uint32_t scheduled_flows;

void filter_flows()
{
	  scheduled_flows = 0;
	  uint32_t flow_counter = 0;
	  if(routing_algorithm == 4)
	  {	
		for(uint32_t flow_id=0;flow_id<2*flows;flow_id++)
		{
			if (routing_test == true)
    			{
    				if(flow_id ==1)
    				{
    					(demanding_flow_struct_controller_inst+flow_id)->f_size = 0;
    				}
    				else
    				{
    					flow_counter++;
    					scheduled_flows++;
    				}
    			}
    			else
    			{
			  	if(proposed_algo2_output_inst[flow_id].paths == 0)
			  	{
			  		(demanding_flow_struct_controller_inst+flow_id)->f_size = 0;
			  		(demanding_flow_struct_nodes_inst+flow_id)->f_size = 0;
			  	}
			  	
			  	else
			  	{
			  		flow_counter++;
			  		scheduled_flows++;
			  	}
			}
		}
		cout<<"Number of connected flows "<<flow_counter<<"at timestamp "<<Now().GetSeconds()<<endl;
	  }
	  else
	  {

	  	for(uint32_t flow_id=0;flow_id<2*flows;flow_id++)
		{
		  	
		  	if (routing_test == true)
    			{
    				if(flow_id ==1)
    				{
    					(demanding_flow_struct_controller_inst+flow_id)->f_size = 0;
    				}
    				else
    				{
    					flow_counter++;
    					scheduled_flows++;
    				}
    			}
    			else
    			{
			  	if(distance_algo2_output_inst[flow_id].paths == 0)
			  	{
			  		(demanding_flow_struct_controller_inst+flow_id)->f_size = 0;
			  		(demanding_flow_struct_nodes_inst+flow_id)->f_size = 0;
			  	}
			  	
			  	else
			  	{
			  		flow_counter++;
			  		scheduled_flows++;
			  	}
		  	}
		}
		cout<<"Number of connected flows "<<flow_counter<<endl;
	  }
}


void dijkstra_stable(uint32_t startVertex)
{
    cout<<"started dijkstra stable solution"<<endl;
    uint32_t nVertices = adjacencyMatrix[0].size();
    cout<<nVertices<<endl;
    
    // shortestDistances[i] will hold the
    // shortest distance from src to i
    
 
    // added[i] will true if vertex i is
    // included / in shortest path tree
    // or shortest distance from src to
    // i is finalized
    uint32_t link_type = 0;//0-DSRC, 1-ethernet
    bool added[nVertices];
 
    // Initialize all distances as
    // INFINITE and added[] as false
    for (uint32_t vertexIndex = 0; vertexIndex < nVertices; vertexIndex++) 
    {
        shortestDistances[vertexIndex] = double(INT_MAX);
        added[vertexIndex] = false;
    }
 
    // Distance of source vertex from
    // itself is always 0
    shortestDistances[startVertex] = 0;
 
    // Parent array to store shortest
    // path tree
    vector<int> new_parents[total_size];
    vector<int> parent_link[total_size];
 
    // The starting vertex does not
    // have a parent
    new_parents[startVertex].push_back(startVertex);
    
    // Find shortest path for all
    // vertices

    for (uint32_t i = 1; i < nVertices; i++) 
    {
        // Pick the minimum distance vertex
        // from the set of vertices not yet
        // processed. nearestVertex is
        // always equal to startNode in
        // first iteration.
        uint32_t nearestVertex = large;
        double shortestDistance = double(INT_MAX);
        
        for (uint32_t vertexIndex = 0; vertexIndex < nVertices; vertexIndex++) 
        {
            if ((!added[vertexIndex]) && (shortestDistances[vertexIndex] < shortestDistance)) 
            {
                nearestVertex = vertexIndex;
                shortestDistance = shortestDistances[vertexIndex];     
            }
        }  
 	//cout <<"iteration "<< i << "shortest distance "<<shortestDistance<<endl;
        // Mark the picked vertex as
        // processed
        
	added[nearestVertex] = true;
	//cout<<"nearest vertex is "<<nearestVertex<<endl;
	
	// Update dist value of the
	// adjacent vertices of the
	// picked vertex.
	for (uint32_t vertexIndex = 0; vertexIndex < nVertices;vertexIndex++)
	{
		double edgeDistance;
		
		if (contention > contention_threshold)
		{
			//cout<<"distance mode is running"<<endl;
			edgeDistance = adjacencyMatrix[nearestVertex][vertexIndex];
			if ((linklifetimeMatrix_dsrc[nearestVertex][vertexIndex]) >= (linklifetimeMatrix_ethernet[nearestVertex][vertexIndex]))
			{
		    		link_type = 0;
		    	}
		    	
		    	else
			{
		    		link_type = 1;
		    	}
		    	
		    	if ((edgeDistance > 0.0)&&(shortestDistance + edgeDistance) <= (shortestDistances[vertexIndex]+30)) 
	    		{
		    		int n = new_parents[vertexIndex].size();
		    		uint32_t index;
		    		double edgeLife;
		    		if (n>0)
		    		{
		    			index = new_parents[vertexIndex][n-1];
		    			if (link_type == 0)
		    			{
		    		        	edgeLife = linklifetimeMatrix_dsrc[nearestVertex][index];
		    		        }
		    		        else if (link_type == 1)
		    		        {
		    		        	edgeLife = linklifetimeMatrix_ethernet[nearestVertex][index];
		    		        }
		    		        //cout<<"edge life is "<<edgeLife<<endl;
		    		        if (edgeLife > link_lifetime_threshold)
					{
						//cout<<"edge life is between "<<nearestVertex<<" and "<<index<<"is "<<edgeLife<<endl;
						new_parents[vertexIndex].push_back(nearestVertex);
						parent_link[vertexIndex].push_back(link_type);
						shortestDistances[vertexIndex] = shortestDistance + edgeDistance;
					}
		    		}
		    		else
		    		{
		    			new_parents[vertexIndex].push_back(nearestVertex);
		    			shortestDistances[vertexIndex] = shortestDistance + edgeDistance;
		    		}
				//cout<<"shortest distances at vertex index "<<vertexIndex<<"is "<<shortestDistances[vertexIndex];
	    		}
		}
		
		else
		{
			//cout<<"delay mode is running"<<endl;
			if ((linklifetimeMatrix_ethernet[nearestVertex][vertexIndex]) <= (linklifetimeMatrix_dsrc[nearestVertex][vertexIndex]))
			{
				edgeDistance = delayMatrix_dsrc[nearestVertex][vertexIndex];
		    		link_type = 0;
		    	}
		    	
		    	else
			{
				edgeDistance = delayMatrix_ethernet[nearestVertex][vertexIndex];
		    		link_type = 1;
		    	}
		    	
		    	if ((edgeDistance > 0.0)&&(shortestDistance + edgeDistance) <= (shortestDistances[vertexIndex])+30) 
	    		{
		    		int n = new_parents[vertexIndex].size();
		    		uint32_t index;
		    		double edgeLife;
		    		if (n>0)
		    		{
		    			index = new_parents[vertexIndex][n-1];
		    			if (link_type == 0)
		    			{
		    		        	edgeLife = linklifetimeMatrix_dsrc[nearestVertex][index];
		    		        }
		    		        else if (link_type == 1)
		    		        {
		    		        	edgeLife = linklifetimeMatrix_ethernet[nearestVertex][index];
		    		        }
		    		        //cout<<"edge life is "<<edgeLife<<endl;
		    		        if (edgeLife > link_lifetime_threshold)
					{
						//cout<<"edge life is between "<<nearestVertex<<" and "<<index<<"is "<<edgeLife<<endl;
						new_parents[vertexIndex].push_back(nearestVertex);
						parent_link[vertexIndex].push_back(link_type);
						shortestDistances[vertexIndex] = shortestDistance + edgeDistance;
					}
		    		}
		    		else
		    		{
		    			new_parents[vertexIndex].push_back(nearestVertex);
		    			shortestDistances[vertexIndex] = shortestDistance + edgeDistance;
		    		}
				//cout<<"shortest distances at vertex index "<<vertexIndex<<"is "<<shortestDistances[vertexIndex];
	    		}
		}
	    	
	    	//cout<<"edge distance is "<<edgeDistance<<endl;
 	  }   
    }
    for (uint32_t source=0;source<total_size;source++)
    {
    	parents[source] = new_parents[source];
    	uint32_t n = new_parents[source].size();
    	
    	//uint32_t j = 0;
    	//uint32_t next_hop[n];
    	//bool updated = false;
    	//uint32_t hop_count = 5;
    	//uint32_t reverse_next_hop[hop_count];
    	//bool routing_loop = false;
    	uint32_t path[total_size];
    	uint32_t alternative_path[total_size];
    	path[0] = source;
    	alternative_path[0] = source;
    	alternative_path[1] = startVertex;
    	for (uint32_t i=1;i<total_size;i++)
    	{
    		int sh = n-i+1;
    		if((sh) > 0)
    		{
    			path[i] = new_parents[source][n-i];
    			//cout<<"n is "<<n<<"is "<<"i is "<<i<<new_parents[source][n-i-1]<<endl;
    		}
    		else
    		{
    			path[i] = large;
    		}
    	}
    	for (uint32_t i=2;i<total_size;i++)
    	{
		alternative_path[i] = large;
    	}
    	//cout<<path[0];
    	//update_proposed_route(source, startVertex, path);
    	if ((source > (N_Vehicles-1)) && (startVertex > (N_Vehicles-1)))
    	{
    		if ((experiment_number == 7) && (link_lifetime_threshold > 6.00))
    		{
    			update_proposed_route(source, startVertex, path);
    		}
    		else
    		{
        		update_proposed_route(source, startVertex, alternative_path);
        	}
    	}
    	else
    	{
    		update_proposed_route(source, startVertex, path);
    	/*
	    	while((j < n) && (updated==false))
	    	{
		    	next_hop[j] = new_parents[source][n-j-1];
		    	reverse_next_hop[0] = routing_tables[next_hop[j]].rows[startVertex].next_hop;
		    	for (uint32_t i=1;i<hop_count;i++)
		    	{
		    		if(reverse_next_hop[i-1] != large)
		    		{
		    			reverse_next_hop[i] = routing_tables[reverse_next_hop[i-1]].rows[startVertex].next_hop;
		    		}
		    		else
		    		{
		    			reverse_next_hop[i] = large;
		    		}
		    	}
		    	
		    	
		    	for (uint32_t i=0; i<hop_count;i++)
		    	{
		    		if(reverse_next_hop[i] == source)
		    		{
		    			routing_loop = true;
		    		}
		    	}
		    	if (routing_loop == false)
		    	{
		    		update_route(source, startVertex, next_hop[j]);
		    		updated = true;
		    	}  	
		    	j++; 	
		}
	*/
	}
    }
    /*
    for (uint32_t source=0;source<total_size;source++)
    {
    	for (uint32_t k=0;k<total_size;k++)
    	{
    		cout<<"destination is "<<startVertex<<" "<<"source is "<<source<<" "<<k<<"th hop is "<<proposed_routing_tables[source].rows[startVertex].path[k]<<endl;
    	}
    }
    */
    printSolution(startVertex);  
}




void calculate_average_latency_routing()
{
	double total_latency = 0.0;
	uint32_t flow_counter = 0;
	uint32_t delivered_packet_counter = 0;
	for (uint32_t fid=0;fid<2*flows;fid++)
	{
		uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
		if (f_size > 0)
		{
			flow_counter++;
			for (uint32_t i=1; i<f_size+1;i++)
			{
				if (routing_packet_final_timestamp[fid][i] > routing_packet_initial_timestamp[fid][i])
				{
					packet_delay_routing[fid][i] = routing_packet_final_timestamp[fid][i] - routing_packet_initial_timestamp[fid][i];
					delivered_packet_counter++;
					//cout<<"Flow id "<<fid<<" packet "<<i<<"latency is "<<1000.0*packet_delay_routing[fid][i]<<" ms"<<endl;
				}
				
				//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
				total_latency = total_latency + packet_delay_routing[fid][i];
			}
		}
	}
	//total_latency = total_latency;
	if((flow_counter !=0)&(delivered_packet_counter != 0))
	{
		current_latency_routing = total_latency/(delivered_packet_counter);
	}
	else
	{
		current_latency_routing = 0.0;
	}
	//cout<<"Latency calculation: flow counter is "<<flow_counter<<" delivered packets is "<<delivered_packet_counter<<"current_latency is "<<current_latency_routing<<endl;
	double current_cumulative_latency = previous_cumulative_latency + current_latency_routing;
	average_latency_routing = (current_cumulative_latency)/(data_gathering_cycle_number);
	cout<<"average_latency "<<1000*average_latency_routing<<" ms"<<endl;	
	previous_cumulative_latency = current_cumulative_latency;
}


void calculate_average_packet_delivery_ratio_routing()
{
	uint32_t flow_counter = 0;
	uint32_t delivered_packet_counter = 0;
	uint32_t total_packets = 0;
	for (uint32_t fid=0;fid<2*flows;fid++)
	{
		uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
		if (f_size > 0)
		{
			flow_counter++;
			for (uint32_t i=1; i<f_size+1;i++)
			{
				if (routing_packet_final_timestamp[fid][i] > routing_packet_initial_timestamp[fid][i])
				{
					delivered_packet_counter++;
				}
				
				//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
				//total_latency = total_latency + packet_delay_routing[fid][i];
			}
		}
		total_packets = total_packets + f_size;
	}
	//cout<<"PDR calculation: flow counter is "<<flow_counter<<" delivered packets is "<<delivered_packet_counter<<endl;
	//total_latency = total_latency;
	if((flow_counter !=0)&(delivered_packet_counter != 0))
	{
		current_packet_delivery_ratio = delivered_packet_counter/(1.0*total_packets);
	}
	else
	{
		current_packet_delivery_ratio = 0.0;
	}
	
	double current_cumulative_ratio = previous_cumulative_ratio + current_packet_delivery_ratio;
	average_packet_delivery_ratio_dsrc = (current_cumulative_ratio)/(1.0*data_gathering_cycle_number);
	cout<<"average packet delivery ratio is "<<100.0*average_packet_delivery_ratio_dsrc<<endl;
	previous_cumulative_ratio = current_cumulative_ratio;

	
}

void calculate_average_packet_delivery_ratio_routingLLDP()
{
	uint32_t flow_counter = 0;
	uint32_t delivered_packet_counter = 0;
	uint32_t total_packets = 0;
	for (uint32_t fids=0;fids<2*flows;fids++)
	{
		for (uint32_t fidd=0;fidd<2*flows;fidd++)
		{
			//uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
			flow_counter++;
			for (uint32_t i=0; i<total_size;i++)
			{
				for (uint32_t j=0; j<total_size;j++)
				{
					if (B_mat[i][j][fids][fidd] == 1)
					{
						if (routing_packet_final_timestampLLDP[fids][fidd][i][j] > routing_packet_initial_timestampLLDP[fids][fidd][i][j])
						{
							delivered_packet_counter++;
						}
						total_packets = total_packets + 1;
					}
				}
				//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
				//total_latency = total_latency + packet_delay_routing[fid][i];
			}
		}
	}
	//cout<<"PDR calculation: flow counter is "<<flow_counter<<" delivered packets is "<<delivered_packet_counter<<endl;
	//total_latency = total_latency;
	if(delivered_packet_counter != 0)
	{
		current_packet_delivery_ratio = delivered_packet_counter/(1.0*total_packets);
	}
	else
	{
		current_packet_delivery_ratio = 0.0;
	}
	
	double current_cumulative_ratio = previous_cumulative_ratio + current_packet_delivery_ratio;
	average_packet_delivery_ratio_dsrc = (current_cumulative_ratio)/(1.0*data_gathering_cycle_number);
	cout<<"average packet delivery ratio is "<<100.0*average_packet_delivery_ratio_dsrc<<endl;
	previous_cumulative_ratio = current_cumulative_ratio;
	
	
}





void reset_expected_actual_count()
{
	Expected0Actual0 = 0;
	Expected0Actual1 = 0;
	Expected1Actual0 = 0;
	Expected1Actual1 = 0;
}

void calculate_average_packet_confusion_rate_routingLLDP()
{
	reset_expected_actual_count();
	uint32_t flow_counter = 0;
	uint32_t total_packets = 0;
	for (uint32_t fids=0;fids<2*flows;fids++)
	{
		for (uint32_t fidd=0;fidd<2*flows;fidd++)
		{
			//uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
			flow_counter++;
			for (uint32_t i=0; i<total_size;i++)
			{
				for (uint32_t j=0; j<total_size;j++)
				{
					if (routing_packet_final_timestampLLDP[fids][fidd][i][j] <= routing_packet_initial_timestampLLDP[fids][fidd][i][j])
					{
						if (B_mat[i][j][fids][fidd] == 1)
						{
							Expected1Actual0++;
						}
						else
						{
							Expected0Actual0++;
						}
					}
					else if (routing_packet_final_timestampLLDP[fids][fidd][i][j] > routing_packet_initial_timestampLLDP[fids][fidd][i][j])
					{
						if (B_mat[i][j][fids][fidd] == 1)
						{
							Expected1Actual1++;
						}
						else
						{
							Expected0Actual1++;
						}
					}
					
					total_packets = total_packets + 1;
				}
				//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
				//total_latency = total_latency + packet_delay_routing[fid][i];
			}
		}
	}
	double FN = Expected0Actual1;
	double TN = Expected0Actual0;
	double TP = Expected1Actual1;
	double FP = Expected1Actual0;
	cout<<FN<<"False negatives "<<TN<<"True negatives "<<TP<<"True positives "<<FP<<"False positives "<<endl;
	
	
	//uint32_t confusion_packet_counter = Expected1Actual0 + Expected0Actual1;
	//cout<<"PDR calculation: flow counter is "<<flow_counter<<" delivered packets is "<<delivered_packet_counter<<endl;
	//total_latency = total_latency;
	//if(confusion_packet_counter != 0)
	//{
		//current_packet_confusion_ratio = confusion_packet_counter/(1.0*total_packets);
	double epsilon = 0.000001;
    double numerator1 = (TP*TN);
    cout<<"numerator1 is "<<numerator1<<endl;
    double numerator2 = (FP*FN);
    cout<<"numerator2 is "<<numerator2<<endl;
    double numerator = numerator1 - numerator2;
    cout<<"numerator is "<<numerator<<endl;
    double denominator1 = (TP+FP+epsilon);
    cout<<"denominator1 is "<<denominator1<<endl;
    double denominator2 =  (TP+FN+epsilon);
    cout<<"denominator2 is "<<denominator2<<endl;
    double denominator3 = (TN+FP+epsilon);
    cout<<"denominator3 is "<<denominator3<<endl;
    double denominator4 =  (TN+FN+epsilon);
    cout<<"denominator4 is "<<denominator4<<endl;
    double denominator =  sqrt(((denominator1)*(denominator2)*(denominator3)*(denominator4)));
    cout<<"denominator is "<<denominator<<endl;
	current_packet_confusion_ratio = numerator/(denominator);
	//}
	//else
	//{
	//	current_packet_confusion_ratio = 0.0;
	//}
	
	double current_cumulative_confusion_ratio = previous_cumulative_confusion_ratio + current_packet_confusion_ratio;
	average_packet_confusion = (current_cumulative_confusion_ratio)/(1.0*data_gathering_cycle_number);
	cout<<"average MCC is "<<average_packet_confusion<<endl;
	cout<<"Expected 0 Actual 1 is "<<Expected0Actual1<<endl;
	cout<<"Expected 0 Actual 0 is "<<Expected0Actual0<<endl;
	cout<<"Expected 1 Actual 1 is "<<Expected1Actual1<<endl;
	cout<<"Expected 1 Actual 0 is "<<Expected1Actual0<<endl;
	previous_cumulative_confusion_ratio = current_cumulative_confusion_ratio;
	//reset_expected_actual_count();
}


void calculate_average_packet_capture_rate_routingLLDP()
{
	uint32_t flow_counter = 0;
	uint32_t intercepted_packet_counter = 0;
	uint32_t total_packets = 0;
	uint32_t total_links = 0;
	uint32_t total_discovered_links = 0;
	for (uint32_t fids=0;fids<2*flows;fids++)
	{	
		for (uint32_t fidd=0;fidd<2*flows;fidd++)
		{
			//uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
			flow_counter++;
			for (uint32_t i=0; i<total_size;i++)
			{
				for (uint32_t j=0; j<total_size;j++)
				{	
					if (B_mat[i][j][fids][fidd]==1)
					{
						total_discovered_links++;
						for (uint32_t k=0; k<total_size;k++)
						{
							if (intercepted_packet_final_timestampLLDP[fids][fidd][i][j][k] > intercepted_packet_initial_timestampLLDP[fids][fidd][i][j][k])
							{
								intercepted_packet_counter++;
							}
							total_packets = total_packets + 1;
						}
					}
					total_links++;
				}
				//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
				//total_latency = total_latency + packet_delay_routing[fid][i];
			}
			
		}
	}
	cout<<"Total discovered links is "<<total_discovered_links<<"total links is"<<total_links<<endl;
	//total_latency = total_latency;
	if(intercepted_packet_counter != 0)
	{
		//current_intercepted_ratio = (total_discovered_links/(1.0*total_links))*(intercepted_packet_counter/(1.0*total_packets));
		current_intercepted_ratio = (intercepted_packet_counter/(1.0*total_packets));
	}
	else
	{
		current_intercepted_ratio = 0.0;
	}
	
	double current_cumulative_intercepted_ratio = previous_cumulative_intercepted_ratio + current_intercepted_ratio;
	average_intercepted_ratio = (current_cumulative_intercepted_ratio)/(1.0*data_gathering_cycle_number);
	cout<<"average packet interception ratio is "<<100.0*average_intercepted_ratio<<endl;
	previous_cumulative_intercepted_ratio = current_cumulative_intercepted_ratio;
	
	
}
	
void calculate_average_jitter_routing()
{
	uint32_t flow_counter = 0;
	uint32_t delivered_jitter_counter = 0;
	double jitter_sum = 0.0;
	for (uint32_t fid=0;fid<2*flows;fid++)
	{
		uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
		if (f_size > 0)
		{
			flow_counter++;
			for (uint32_t i=1; i<f_size;i++)
			{
				if ((routing_packet_final_timestamp[fid][i] > routing_packet_initial_timestamp[fid][i]) & (routing_packet_final_timestamp[fid][i+1] > routing_packet_initial_timestamp[fid][i+1])&((routing_packet_final_timestamp[fid][i] > routing_packet_initial_timestamp[fid][i])))
				{
					packet_jitter_routing[fid][i] = abs(routing_packet_final_timestamp[fid][i+1] - routing_packet_final_timestamp[fid][i]);
					//cout<<"Flow id "<<fid<<"packet "<<i<<" and "<<i+1<<"jitter is "<<1000.0*packet_jitter_routing[fid][i]<<" ms"<<endl;
					delivered_jitter_counter++;
				}
				
				//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
				jitter_sum = jitter_sum + packet_jitter_routing[fid][i];
			}
		}
	}
	//cout<<"Jitter calculation: flow counter is "<<flow_counter<<" delivered jitter packets is "<<delivered_jitter_counter<<endl;
	//total_latency = total_latency;

	if((flow_counter !=0)&(delivered_jitter_counter != 0))
	{
		current_jitter_ratio = jitter_sum/(delivered_jitter_counter);
	}
	else
	{
		current_jitter_ratio = 0.0;
	}
	
	double current_cumulative_jitter_ratio = previous_cumulative_jitter_ratio + current_jitter_ratio;
	average_jitter_routing = (current_cumulative_jitter_ratio)/(data_gathering_cycle_number);
	cout<<"average jitter is "<<1000*average_jitter_routing<<endl;
	previous_cumulative_jitter_ratio = current_cumulative_jitter_ratio;

}

void calculate_average_load_balance_routing()
{
	uint32_t flow_counter = 0;
	double total_load_imbalance = 0.0;
	double phifbar[2*flows];
	for (uint32_t fid=0;fid<2*flows;fid++)
	{
		
		uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
		
		if (f_size > 0)
		{
			phifbar[fid] = 0.0;
			double latency_average = 0.0;
			for (uint32_t i=1; i<f_size+1;i++)
			{
				double packet_rec_counter = 0.0;
				double q_count = 0.0;
				double latency_sum = 0.0;
				for(uint32_t j=0;j<total_size;j++)
				{
					for(uint32_t l=0;l<total_size;l++)
					{
						if ((routing_packet_general_final_timestamp[fid][j][i] > routing_packet_general_initial_timestamp[fid][l][i])&((delta_at_controller_inst+fid)->delta_fi_inst[l].delta_values[j] > 0.0)&(sent_IDS[fid][l][i] == true))
						{
							double difference = routing_packet_general_final_timestamp[fid][j][i] - routing_packet_general_initial_timestamp[fid][l][i];
							packet_rec_counter++;
							latency_sum = latency_sum + difference;
							//cout<<"Flow id "<<fid<<" link "<<l<<"to "<<j<<"latency difference for packet "<<i<<"is "<<1000.0*difference<<" ms"<<endl;
						}
						if ((delta_at_controller_inst+fid)->delta_fi_inst[l].delta_values[j] > 0.0)
						{
							q_count++;
						}
					}
					//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;	
				}
				double local_average = 0.0;
				if(q_count >0)
				{
					//local_average = latency_sum/q_count;
					local_average = packet_rec_counter/q_count;
				}
				latency_average = latency_average + (local_average);
			}
			
			phifbar[fid] = latency_average;
			
			
			flow_counter++;
			//cout<<"phi bar for flow id "<<fid<<" is "<<phifbar[fid]<<endl;

			double q_count = 0;
			for(uint32_t j=0;j<total_size;j++)
			{
				for(uint32_t l=0;l<total_size;l++)
				{
					double local_count = 0.0;
					double local_sum = 0.0;
					for (uint32_t i=1; i<f_size+1;i++)
					{
						if ((routing_packet_general_final_timestamp[fid][j][i] > routing_packet_general_initial_timestamp[fid][l][i])&((delta_at_controller_inst+fid)->delta_fi_inst[l].delta_values[j] > 0.0)&(sent_IDS[fid][l][i] == true))
						{
							double diff = routing_packet_general_final_timestamp[fid][j][i] - routing_packet_general_initial_timestamp[fid][l][i];
							//double load_imbalance = (abs(diff - phifbar))/(phifbar);
							local_sum = local_sum + diff;
							local_count++;
							//cout<<"Flow id "<<fid<<" packet "<<i<<"latency is "<<1000.0*packet_delay_routing[fid][i]<<" ms"<<endl;
							
							//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
							//total_latency = total_latency + packet_delay_routing[fid][i];
						}
					}
					//double local_average = local_sum/(total_size*f_size);
					if (((delta_at_controller_inst+fid)->delta_fi_inst[l].delta_values[j] > 0.0))
					{
						double load_imbalance = 0.0;
						if(phifbar[fid]> 0.0)
						{
							//load_imbalance = (abs(local_sum - phifbar[fid]))/(phifbar[fid]);
							load_imbalance = (abs(local_count - phifbar[fid]))/(f_size/2.0);
						}
						//cout<<"load imbalance for link"<<l<<"to "<<j<<" is "<<load_imbalance<<endl;
						total_load_imbalance = total_load_imbalance + load_imbalance;
						q_count++;
					}
				}
					
			}
			if(q_count > 0)
			{
				total_load_imbalance = total_load_imbalance/q_count;
			}
			
		}
	}
	
	//total_latency = total_latency;
	
	if((flow_counter !=0))
	{
		current_load_imbalance = total_load_imbalance/(flow_counter);
	}
	
	current_load_balance = 100.0*(1.0-current_load_imbalance);
	
	//cout<<"Load balance calculation: flow counter is "<<flow_counter<<"current_load imbalance is "<<current_load_imbalance<<"current load balance is"<<current_load_balance<<endl;
	double current_cumulative_load_imbalance = previous_cumulative_load_imbalance + current_load_imbalance;
	
	
	average_load_balance = 100.0*(1.0 -((current_cumulative_load_imbalance)/(data_gathering_cycle_number)));
	cout<<"average load balance is "<<average_load_balance<<endl;	
	previous_cumulative_load_imbalance = current_cumulative_load_imbalance;
}

double dsrc_routing_packet_final_timestamp;

double bound_to_100(double x)
{
	if(x>100.0)
	{
		return 100.0;
	}
	else
	{
		return x;
	}
	
}


void calculate_average_channel_utilization_routingLLDP()
{
	cout<<"DSRC initial timestamp is "<< dsrc_initial_timestamp<<endl;
	cout<<"DSRC LLDP_initial timestamp is "<< dsrc_LLDP_initial_timestamp<<endl;
	cout<<"DSRC final timestamp is "<< dsrc_final_timestamp<<endl;
	if(routing_algorithm == 5)
	{
		if (dsrc_final_timestamp > dsrc_initial_timestamp)
		{
			dsrc_utilization_time = dsrc_final_timestamp - dsrc_initial_timestamp;
		}
		else
		{
			dsrc_utilization_time = 0.0;
		}
	}
	else
	{
		if (dsrc_LLDP_final_timestamp > dsrc_LLDP_initial_timestamp)
		{
			dsrc_utilization_time = dsrc_LLDP_final_timestamp - dsrc_LLDP_initial_timestamp;
		}
		else
		{
			dsrc_utilization_time = 0.0;
		}
	}
	double weight = 0.0;
	double weight_LLDP = LLDP_received_count/(total_size*total_size*2);
	switch(routing_algorithm)
	{
		case(0):
			weight = 0.3*weight_LLDP;
			break;
		case(1):
			weight = 0.3*weight_LLDP;
			break;
		case(2):
			weight = 0.35*weight_LLDP;
			break;
		case(3):
			weight = 0.70*weight_LLDP;
			break;
		case(4):
			weight = 0.50*weight_LLDP;
			break;
		case(5):
			weight = 0.0*weight_LLDP;
			break;
		default: 
			weight = 0.10*weight_LLDP;
			break;
	}
	if (lte_final_timestamp > lte_initial_timestamp)
	{
		lte_utilization_time = (lte_final_timestamp - lte_initial_timestamp)*weight + ((0.00005*N_Vehicles));
	}
	else
	{
		lte_utilization_time = 0.0;
	}
	//cout<<"lte final timestamp is :"<<lte_final_timestamp;
	if(routing_algorithm == 5)
	{
		if (ethernet_final_timestamp > ethernet_initial_timestamp)
		{
			ethernet_utilization_time = (ethernet_final_timestamp - ethernet_initial_timestamp)*weight + ((0.00005*N_RSUs));
		}
		else
		{
			ethernet_utilization_time = 0.0;
		}
	}
	else
	{
		if (ethernet_final_timestamp > ethernet_LLDP_initial_timestamp)
		{
			ethernet_utilization_time = (ethernet_final_timestamp - ethernet_LLDP_initial_timestamp)*weight + ((0.00005*N_RSUs));
		}
		else
		{
			ethernet_utilization_time = 0.0;
		}
	}
	cout<<"Weight is "<<weight<<endl;
	cout<<"Ethernet_final timestamp is "<< ethernet_final_timestamp<<endl;
	cout<<"Ethernet initial timestamp is "<< ethernet_LLDP_initial_timestamp<<endl;
	cout<<"Ethernet utilization time is "<<ethernet_utilization_time<<endl;
	current_dsrc_utilization = bound_to_100(100.0*(dsrc_utilization_time)/(data_transmission_period));
	current_ethernet_utilization = bound_to_100(100.0*(ethernet_utilization_time)/(data_transmission_period));
	current_lte_utilization = bound_to_100(100.0*(lte_utilization_time)/(data_transmission_period));
	current_channel_utilization = (current_dsrc_utilization+current_ethernet_utilization+current_lte_utilization)/3.0;
	
	double previous_cumulative_dsrc = (data_gathering_cycle_number - 1.0)*(average_dsrc_utilization);
	double previous_cumulative_ethernet = (data_gathering_cycle_number - 1.0)*(average_ethernet_utilization);
	double previous_cumulative_lte = (data_gathering_cycle_number - 1.0)*(average_lte_utilization);
	
	average_dsrc_utilization = (current_dsrc_utilization + previous_cumulative_dsrc)/(data_gathering_cycle_number);
	average_ethernet_utilization = (current_ethernet_utilization + previous_cumulative_ethernet)/(data_gathering_cycle_number);
	average_lte_utilization = (current_lte_utilization + previous_cumulative_lte)/(data_gathering_cycle_number);
	average_channel_utilization = (average_dsrc_utilization+average_ethernet_utilization+average_lte_utilization)/3.0;
	cout<<"DSRC uti: "<<average_dsrc_utilization<<"Ethernet uti "<<average_ethernet_utilization<<"LTE utilization "<<average_lte_utilization<<"Average channel utilization "<<average_channel_utilization<<endl;
}

double ns3_algorithm_complexity = 0.0;

void calculate_average_computation_complexity_routingLLDP()
{
	srand(Simulator::Now().GetSeconds());
	double rand_int = 0.50 + 0.01*(1+rand()%2);
	double total_complexity = 0.0;
	double hash_complexity = 120000.0*rand_int;
	double aes_encryption_complexity = 2000.0*rand_int;
	double aes_decryption_complexity = 2000.0*rand_int;
	double packet_out_cryptography_complexity = 2500.0*rand_int;
	double first_time_verification_cryptography_complexity = 3000.0*rand_int;
	double packet_in_cryptography_complexity = 2500.0*rand_int;
	cout<<"Algorithm runtime is "<<ns3_algorithm_complexity<<endl;
	
	double weight = 0.0;
	double weight_LLDP = (LLDP_received_count)/(2.0*total_size*total_size);
	switch(routing_algorithm)
	{
		case(0):
			total_complexity = ns3_algorithm_complexity;
			weight = total_complexity*weight_LLDP;
			break;
		case(1):
			total_complexity = ns3_algorithm_complexity;
			weight = total_complexity*weight_LLDP;
			break;
		case(2):
			total_complexity = 2*hash_complexity + ns3_algorithm_complexity;
			weight = total_complexity*weight_LLDP;
			break;
		case(3):
			total_complexity = ns3_algorithm_complexity+first_time_verification_cryptography_complexity;//To account for anomaly detection in this paper
			weight = total_complexity*weight_LLDP;
			break;
		case(4):
			total_complexity = 2*hash_complexity + aes_encryption_complexity +  aes_decryption_complexity + packet_out_cryptography_complexity +  first_time_verification_cryptography_complexity + packet_in_cryptography_complexity + ns3_algorithm_complexity;
			weight = total_complexity*weight_LLDP;
			break;
		case(5):
			total_complexity = ns3_algorithm_complexity;
			weight = total_complexity*1.0;
			break;
		default: 
			total_complexity = ns3_algorithm_complexity;
			weight = total_complexity*weight_LLDP;
			break;
	}
	current_computational_complexity = weight;
	double previous_cumulative_computational_complexity = (data_gathering_cycle_number - 1.0)*(average_computational_complexity);
	average_computational_complexity = (current_computational_complexity + previous_cumulative_computational_complexity)/(data_gathering_cycle_number);
	
	cout<<"Computational complexity: "<<average_computational_complexity<<endl;
}


void calculate_average_latency_routingLLDP()
{

	double total_latency = 0.0;
	double LLDP_latency;
	double HELLO_latency = HELLO_final_timestamp - HELLO_initial_timestamp;
	//cout<<"HELLO latency difference is "<<HELLO_latency<<endl;
	if(LLDP_final_timestamp > LLDP_initial_timestamp)
	{
		LLDP_latency = LLDP_final_timestamp-LLDP_initial_timestamp;
	}
	else
	{
		LLDP_latency = 0.0;
	}
	
	srand(Simulator::Now().GetSeconds());
	double rand_int = 0.50 + 0.01*(1+rand()%2);
	
	double blockchain_latency = 0.010*rand_int;
	//double weight_LLDP = LLDP_received_count/total_size;
	double weight_LLDP = 1.0;
	if(LLDP_received_count > 0)
	{
		weight_LLDP = 1.0*((LLDP_received_count)/(2.0*total_size*total_size*total_size));
	}
	double weight = 0.0;
	switch(routing_algorithm)
	{
		case(0):
			total_latency = LLDP_latency;
			weight = total_latency*weight_LLDP;
			break;
		case(1):
			total_latency = LLDP_latency;
			weight = total_latency*weight_LLDP;
			break;
		case(2):
			total_latency = LLDP_latency;
			weight = total_latency*weight_LLDP;
			break;
		case(3):
			total_latency = 2*LLDP_latency;
			weight = total_latency*weight_LLDP;
			break;
		case(4):
			total_latency = LLDP_latency+blockchain_latency;
			weight = total_latency*weight_LLDP;
			break;
		case(5):
			total_latency = HELLO_latency;
			weight = total_latency;
			cout<<"weight for HELLO is "<<weight<<endl;
			break;
		default: 
			total_latency = LLDP_latency;
			weight = total_latency*weight_LLDP;
			break;
	}
	current_routing_latency = weight;
	cout<<"current discovery latency "<<current_routing_latency<<endl;
	double previous_cumulative_routing_latency = (data_gathering_cycle_number - 1.0)*(average_routing_latency);
	average_routing_latency = (current_routing_latency + previous_cumulative_routing_latency)/(data_gathering_cycle_number);
	
	cout<<"Average latency: "<<average_routing_latency<<endl;
}


void calculate_performance_evaluation_metrics()
{

	Simulator::Schedule(Seconds(0.000000), calculate_average_latency_routing);
	Simulator::Schedule(Seconds(0.000020), calculate_average_packet_delivery_ratio_routing);
	Simulator::Schedule(Seconds(0.000040), calculate_average_jitter_routing);
	Simulator::Schedule(Seconds(0.000060), calculate_average_load_balance_routing);
	Simulator::Schedule(Seconds(0.000070), write_csv_results_routing);
}


void calculate_performance_evaluation_metricsLLDP()
{
	Simulator::Schedule(Seconds(0.000020), calculate_average_packet_delivery_ratio_routingLLDP);	
	Simulator::Schedule(Seconds(0.000040), calculate_average_channel_utilization_routingLLDP);
	Simulator::Schedule(Seconds(0.000060), calculate_average_packet_capture_rate_routingLLDP);
	Simulator::Schedule(Seconds(0.000070), calculate_average_computation_complexity_routingLLDP);
	Simulator::Schedule(Seconds(0.000080), calculate_average_latency_routingLLDP);
	Simulator::Schedule(Seconds(0.000090), calculate_average_packet_confusion_rate_routingLLDP);
	Simulator::Schedule(Seconds(0.000110), write_csv_results_LLDP);
}




void calculate_average_latency()
{
	double total_latency = 0.0;
	for (uint32_t i=2; i<total_size+2;i++)
	{
		if (packet_final_timestamp[i] > packet_initial_timestamp[i])
		{
			packet_delay[i] = packet_final_timestamp[i] - packet_initial_timestamp[i];
		}
		//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
		total_latency = total_latency + packet_delay[i];
	}
	current_latency = total_latency/(total_size);
	double previous_cumulative_latency = average_latency*(data_gathering_cycle_number - 1)*total_size;
	double current_cumulative_latency = previous_cumulative_latency + total_latency;
	average_latency = (current_cumulative_latency)/((data_gathering_cycle_number)*(total_size));
	cout<<"average_latency "<<1000*average_latency<<" ms"<<endl;
	
}

void calculate_packet_delivery_ratio()
{
	double delivered_packets = 0.0;
	for (uint32_t i=2; i<total_size+2;i++)
	{
		if (packet_final_timestamp[i] > packet_initial_timestamp[i])
		{
			delivered_packets = delivered_packets + 1;
		}
	}
	
	current_packet_delivery_ratio = delivered_packets/(total_size);
	if (architecture == 2)
	{
		double previous_cumulative_ratio = average_packet_delivery_ratio*(data_gathering_cycle_number - 2);
		double current_cumulative_ratio = previous_cumulative_ratio + current_packet_delivery_ratio;
		average_packet_delivery_ratio = (current_cumulative_ratio)/(data_gathering_cycle_number - 1);
	}
	if (architecture == 0)
	{
		double previous_cumulative_ratio = average_packet_delivery_ratio*(data_gathering_cycle_number - 1);
		double current_cumulative_ratio = previous_cumulative_ratio + current_packet_delivery_ratio;
		average_packet_delivery_ratio = (current_cumulative_ratio)/(data_gathering_cycle_number);
	}

	cout<<"packet delivery ratio is "<<100*average_packet_delivery_ratio<<endl;
	
}


void calculate_packet_delivery_ratio_dsrc()
{
	double delivered_packets = 0.0;
	for (uint32_t i=2; i<total_size+2;i++)
	{
		if (dsrc_packet_final_timestamp[i] > dsrc_packet_initial_timestamp[i])
		{
			delivered_packets = delivered_packets + 1;
		}
	}
	
	current_packet_delivery_ratio_dsrc = delivered_packets/(total_size);
	cout<<"current packet delivery ratio is "<<100*current_packet_delivery_ratio_dsrc<<endl;
	double previous_cumulative_ratio = average_packet_delivery_ratio_dsrc*(data_gathering_cycle_number - 1);
	double current_cumulative_ratio = previous_cumulative_ratio + current_packet_delivery_ratio_dsrc;
	average_packet_delivery_ratio_dsrc = (current_cumulative_ratio)/(data_gathering_cycle_number);
	cout<<"packet delivery ratio is "<<100*average_packet_delivery_ratio_dsrc<<endl;
	
}


void calculate_packet_delivery_ratio_dsrc_hybrid()
{
	double delivered_packets = 0.0;
	for (uint32_t i=2; i<total_size+2;i++)
	{
		if (dsrc_packet_final_timestamp[i] > dsrc_packet_initial_timestamp[i])
		{
			delivered_packets = delivered_packets + 1;
		}
	}
	
	current_packet_delivery_ratio_dsrc = delivered_packets/(total_size);
	cout<<"current packet delivery ratio is "<<100*current_packet_delivery_ratio_dsrc<<endl;
	double previous_cumulative_ratio = average_packet_delivery_ratio_dsrc*(data_gathering_cycle_number - 2);
	double current_cumulative_ratio = previous_cumulative_ratio + current_packet_delivery_ratio_dsrc;
	average_packet_delivery_ratio_dsrc = (current_cumulative_ratio)/(data_gathering_cycle_number -1);
	cout<<"packet delivery ratio is "<<100*average_packet_delivery_ratio_dsrc<<endl;
	
}

void calculate_average_latency_hybrid()
{
	double total_latency = 0.0;
	for (uint32_t i=2; i<total_size+2;i++)
	{
		if (dsrc_packet_final_timestamp[i] > dsrc_packet_initial_timestamp[i])
		{
			packet_delay_dsrc[i] = dsrc_packet_final_timestamp[i] - dsrc_packet_initial_timestamp[i];
		}
		else
		{
			packet_delay_dsrc[i] = 0.010;//maximum latency when packet not delivered
		}
		//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
		total_latency = total_latency + packet_delay_dsrc[i];
	}
	total_latency = total_latency;
	current_latency_dsrc = total_latency/(total_size);
	double previous_cumulative_latency = average_latency_dsrc*(data_gathering_cycle_number - 1)*total_size;
	double current_cumulative_latency = previous_cumulative_latency + total_latency;
	average_latency_dsrc = (current_cumulative_latency)/((data_gathering_cycle_number)*(total_size));
	cout<<"average_latency "<<1000*average_latency_dsrc<<" ms"<<endl;	
}


void calculate_average_latency_dsrc()
{
	double total_latency = 0.0;
	for (uint32_t i=2; i<total_size+2;i++)
	{
		if (dsrc_packet_final_timestamp[i] > dsrc_packet_initial_timestamp[i])
		{
			packet_delay_dsrc[i] = dsrc_packet_final_timestamp[i] - dsrc_packet_initial_timestamp[i];
		}
		//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
		total_latency = total_latency + packet_delay_dsrc[i];
	}
	total_latency = total_latency;
	current_latency_dsrc = total_latency/(total_size);
	double previous_cumulative_latency = average_latency_dsrc*(data_gathering_cycle_number - 1)*total_size;
	double current_cumulative_latency = previous_cumulative_latency + total_latency;
	average_latency_dsrc = (current_cumulative_latency)/((data_gathering_cycle_number)*(total_size));
	cout<<"average_latency "<<1000*average_latency_dsrc<<" ms"<<endl;	
}


void calculate_aodv_packet_delivery_ratio()
{
	double delivered_packets = 0.0;
	for (uint32_t i=2; i< (total_size+2); i++)
	{
		if (aodv_final_timestamp[i] > aodv_initial_timestamp[i])
		{
			delivered_packets = delivered_packets + 1;
		}
	}
	current_packet_delivery_ratio_dsrc = delivered_packets/(total_size);
	cout<<"current packet delivery ratio is "<<100*current_packet_delivery_ratio_dsrc<<endl;
	double previous_cumulative_ratio = average_packet_delivery_ratio_dsrc*(data_gathering_cycle_number - 1);
	double current_cumulative_ratio = previous_cumulative_ratio + current_packet_delivery_ratio_dsrc;
	average_packet_delivery_ratio_dsrc = (current_cumulative_ratio)/(data_gathering_cycle_number);
	cout<<"average packet delivery ratio is "<<100*average_packet_delivery_ratio_dsrc<<endl;	
}

void calculate_aodv_latency()
{
	double total_latency = 0.0;
	for (uint32_t i=2;i<(total_size+2);i++)
	{
		if (aodv_final_timestamp[i] > aodv_initial_timestamp[i])
		{
			packet_delay[i] = aodv_final_timestamp[i] - aodv_initial_timestamp[i];
		}
		else
		{
			packet_delay[i] = 0.010;//maximum latency when packet not delivered
		}
		total_latency = total_latency + packet_delay[i];	
	}
	//cout<<"packet "<<i<<"final timestamp "<<packet_final_timestamp[i]<<"initial timestamp: "<<packet_initial_timestamp[i]<<endl;
	current_latency_dsrc = total_latency/(total_size);
	double previous_cumulative_latency = average_latency_dsrc*(data_gathering_cycle_number - 1)*(total_size);
	double current_cumulative_latency = previous_cumulative_latency + total_latency;
	average_latency_dsrc = (current_cumulative_latency)/((data_gathering_cycle_number)*(total_size));
	cout<<"average_latency "<<1000*average_latency_dsrc<<" ms"<<"current latency is "<<current_latency_dsrc*1000<<" ms"<<endl;
}



void calculate_average_channel_utilization_with_solution()
{
	if (dsrc_final_timestamp > dsrc_initial_timestamp)
	{
		dsrc_utilization_time = dsrc_final_timestamp - dsrc_initial_timestamp;
	}
	else
	{
		dsrc_utilization_time = 0.0;
	}
	lte_utilization_time = (lte_final_timestamp - lte_initial_timestamp) + ((0.00005*N_Vehicles));
	cout<<"lte final timestamp is :"<<lte_final_timestamp;
	ethernet_utilization_time = (ethernet_final_timestamp - ethernet_initial_timestamp) + ((0.00005*N_RSUs));
	current_dsrc_utilization = 100.0*(dsrc_utilization_time)/(data_transmission_period);
	current_ethernet_utilization = 100.0*(ethernet_utilization_time)/(data_transmission_period);
	current_lte_utilization = 100.0*(lte_utilization_time)/(data_transmission_period);
	
	double previous_cumulative_dsrc = (data_gathering_cycle_number - 1.0)*(average_dsrc_utilization);
	double previous_cumulative_ethernet = (data_gathering_cycle_number - 1.0)*(average_ethernet_utilization);
	double previous_cumulative_lte = (data_gathering_cycle_number - 1.0)*(average_lte_utilization);
	
	average_dsrc_utilization = (current_dsrc_utilization + previous_cumulative_dsrc)/(data_gathering_cycle_number);
	average_ethernet_utilization = (current_ethernet_utilization + previous_cumulative_ethernet)/(data_gathering_cycle_number);
	average_lte_utilization = (current_lte_utilization + previous_cumulative_lte)/(data_gathering_cycle_number);
	cout<<"DSRC uti: "<<average_dsrc_utilization<<"Ethernet uti "<<average_ethernet_utilization<<"LTE utilization "<<average_lte_utilization<<endl;
}

void calculate_average_channel_utilization()
{
	if (dsrc_final_timestamp > dsrc_initial_timestamp)
	{
		dsrc_utilization_time = dsrc_final_timestamp - dsrc_initial_timestamp;
	}
	else
	{
		dsrc_utilization_time = 0.0;
	}
	lte_utilization_time = lte_final_timestamp - lte_initial_timestamp;
	cout<<"lte final timestamp is :"<<lte_final_timestamp;
	ethernet_utilization_time = ethernet_final_timestamp - ethernet_initial_timestamp;
	current_dsrc_utilization = 100.0*(dsrc_utilization_time)/(data_transmission_period);
	current_ethernet_utilization = 100.0*(ethernet_utilization_time)/(data_transmission_period);
	current_lte_utilization = 100.0*(lte_utilization_time)/(data_transmission_period);
	
	double previous_cumulative_dsrc = (data_gathering_cycle_number - 1.0)*(average_dsrc_utilization);
	double previous_cumulative_ethernet = (data_gathering_cycle_number - 1.0)*(average_ethernet_utilization);
	double previous_cumulative_lte = (data_gathering_cycle_number - 1.0)*(average_lte_utilization);
	
	average_dsrc_utilization = (current_dsrc_utilization + previous_cumulative_dsrc)/(data_gathering_cycle_number);
	average_ethernet_utilization = (current_ethernet_utilization + previous_cumulative_ethernet)/(data_gathering_cycle_number);
	average_lte_utilization = (current_lte_utilization + previous_cumulative_lte)/(data_gathering_cycle_number);
	cout<<"DSRC uti: "<<average_dsrc_utilization<<"Ethernet uti "<<average_ethernet_utilization<<"LTE utilization "<<average_lte_utilization<<endl;
}

void calculate_average_cost_with_solution()
{
	double ethernet_cost = 1.0;
	double dsrc_cost =2.0;
	double lte_cost = 40.0;
	//calculate total cost in kilo bytes
	double current_total_cost = ((ethernet_cost*ethernet_total_packet_size) + (dsrc_cost*dsrc_total_packet_size) + (lte_cost*lte_total_packet_size) + (lte_cost*2*N_Vehicles) + (ethernet_cost*2*N_RSUs))/1024.0;
	current_cost = current_total_cost/(total_size);
	cout<<"current average cost is "<<current_cost<<endl;
	double previous_cumulative_total_cost = (total_size)*(data_gathering_cycle_number - 1.0)*(average_cost);
	double current_cumulative_total_cost = previous_cumulative_total_cost + current_total_cost;
	average_cost = (current_cumulative_total_cost)/((data_gathering_cycle_number)*(total_size));
	cout<<"average cost per node is "<< average_cost<<endl;
	ethernet_total_packet_size = 0;
	dsrc_total_packet_size = 0;
	lte_total_packet_size = 0;
}

void calculate_average_cost_without_solution()
{
	double ethernet_cost = 1.0;
	double dsrc_cost =2.0;
	double lte_cost = 40.0;
	//calculate total cost in kilo bytes
	double current_total_cost = ((ethernet_cost*ethernet_total_packet_size) + (dsrc_cost*dsrc_total_packet_size) + (lte_cost*lte_total_packet_size))/1024.0;
	current_cost = current_total_cost/(total_size);
	cout<<"current average cost is "<<current_cost<<endl;
	double previous_cumulative_total_cost = (total_size)*(data_gathering_cycle_number - 1.0)*(average_cost);
	double current_cumulative_total_cost = previous_cumulative_total_cost + current_total_cost;
	average_cost = (current_cumulative_total_cost)/((data_gathering_cycle_number)*(total_size));
	cout<<"average cost per node is "<< average_cost<<endl;
	ethernet_total_packet_size = 0;
	dsrc_total_packet_size = 0;
	lte_total_packet_size = 0;
}


void calculate_average_cost_without_solution_dsrc()
{
	double dsrc_cost =2.0;
	//calculate total cost in kilo bytes
	double current_total_cost =  (dsrc_cost*dsrc_total_packet_size)*10/1024.0;
	current_cost = current_total_cost/(total_size);
	cout<<"current average cost is "<<current_cost<<endl;
	double previous_cumulative_total_cost = (total_size)*(data_gathering_cycle_number - 1.0)*(average_cost);
	double current_cumulative_total_cost = previous_cumulative_total_cost + current_total_cost;
	average_cost = (current_cumulative_total_cost)/((data_gathering_cycle_number)*(total_size));
	cout<<"average cost per node is "<< average_cost<<endl;
	ethernet_total_packet_size = 0;
	dsrc_total_packet_size = 0;
	lte_total_packet_size = 0;
	dsrc_total_received_packets = 0;
}




double times_optimized =0.0;
double times_checked = 0.0;

void calculate_percentage()
{
	optimization_percentage = 100.0*(times_optimized/times_checked);
}

void transmit_solution()
{
	read_csv();
	//After getting the solution, unicast the solution to the nodes.
	for (uint32_t u=0;u< total_size;u++)
	{
		if (u < (N_Vehicles))
		{
			Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(0));
			Simulator::Schedule(Seconds(0.002 + 0.000015*u),send_LTE_metadata_downlink_alone,udp_app,controller_Node.Get(0),Vehicle_Nodes.Get(u), u);
		}
		else
		{
			uint32_t index = u - N_Vehicles;
			//cout<<"index is "<<index;
			// Guard: skip if RSU_Nodes is empty (routing_test=true with N_RSUs=0)
			if (index >= RSU_Nodes.GetN()) { continue; }
			Ptr <Node> nu = DynamicCast <Node> (RSU_Nodes.Get(index));
	  		Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(0));
			Simulator::Schedule(Seconds(0.002 + 0.000015*u),RSU_metadata_downlink_unicast, udp_app, controller_Node.Get(0), nu);
		}
	}
}


void transmit_delta_values()
{
	//read_csv();
	//After getting the solution, unicast the solution to the nodes.
	for (uint32_t u=0;u< total_size;u++)
	{
		if (u < (N_Vehicles))
		{
			Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(0));
			Simulator::Schedule(Seconds(0.000 + (0.000015*u)),send_LTE_deltavalues_downlink_alone,udp_app,controller_Node.Get(0),Vehicle_Nodes.Get(u), u);
		}
		else
		{
			uint32_t index = u - N_Vehicles;
			//cout<<"index is "<<index;
			// Guard: skip if RSU_Nodes is empty (routing_test=true with N_RSUs=0)
			if (index >= RSU_Nodes.GetN()) { continue; }
			Ptr <Node> nu = DynamicCast <Node> (RSU_Nodes.Get(index));
	  		Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(0));
			Simulator::Schedule(Seconds(0.000 + (0.000015*u)),RSU_deltavalues_downlink_unicast, udp_app, controller_Node.Get(0), nu);
		}
	}
	cout<<"Transmitting delta values at"<<Now().GetSeconds()<<endl;
}



void transmit_LLDP_downlink(uint32_t u_src, uint32_t u_dst, uint32_t port_id)
{
	//read_csv();
		if (u_src < (N_Vehicles))
		{
			Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(0));
			if(routing_algorithm == 4)
			{
				Simulator::Schedule(Seconds(0.0001),compute_controller_packet_out_cryptography, u_src, u_dst, port_id);
			}
			Simulator::Schedule(Seconds(0.00025),send_LTE_LLDP_packetout_downlink_alone,udp_app,controller_Node.Get(0), u_src, u_dst, port_id);
			uint32_t controller_ID = node_controller_ID[u_src];
			if(flooding_malicious_controllers[controller_ID])
			{
				cout<<"Flooding LLDP packets by the controller"<<endl;
				srand(Simulator::Now().GetSeconds()+double(controller_ID));
				uint32_t flood_count = 2 + rand()%3;
				for(uint32_t i=0;i<flood_count;i++)
				{
					Simulator::Schedule(Seconds(0.00001*i),compute_controller_packet_out_cryptography, u_src, u_dst, port_id);
					Simulator::Schedule(Seconds(0.00025*i),send_LTE_LLDP_packetout_downlink_alone,udp_app,controller_Node.Get(0), u_src, u_dst, port_id);
				}
			}
		}
		else
		{
			uint32_t index = u_src - N_Vehicles;
			//cout<<"index is "<<index;
			Ptr <Node> nu = DynamicCast <Node> (RSU_Nodes.Get(index));	
	  		Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(0));
			Simulator::Schedule(Seconds(0.000 + (0.000015*u_src)),RSU_deltavalues_downlink_unicast, udp_app, controller_Node.Get(0), nu);
			
			uint32_t controller_ID = node_controller_ID[u_src];
			
			if(flooding_malicious_controllers[controller_ID])
			{
				srand(Simulator::Now().GetSeconds()+double(controller_ID));
				uint32_t flood_count = 3 + rand()%3;
				for(uint32_t i=0;i<flood_count;i++)
				{
					Simulator::Schedule(Seconds(0.000 + (0.000015*u_src*i)),RSU_deltavalues_downlink_unicast, udp_app, controller_Node.Get(0), nu);
				}
			}
		}
		cout<<"Transmitted LLDP for link "<<u_src<<"-"<<u_dst<<" at"<<Now().GetSeconds()<<endl;
}
	
	
void optimize_subsequent()
{
	//calculate entropy of the network and compare with threshold.
	std::string filename = NS3_ROOT "/analytics/data/optimization.py";
    	std::string command = "python3 ";
    	command += filename;
    	system(command.c_str());
}



void optimize_link_lifetime()
{
	//generate optimization solution for predicting link lifetimes
	std::string filename;
	switch(routing_algorithm)
	{
		case(0):
			filename = NS3_ROOT "/analytics/data/optimization_lifetime_ECMP.py";
			break;
		case(1):
			filename = NS3_ROOT "/analytics/data/optimization_lifetime_RR.py";
			break;
		case(2):
			filename = NS3_ROOT "/analytics/data/optimization_lifetime_QRSDN.py";
			break;
		case(3):
			filename = NS3_ROOT "/analytics/data/optimization_lifetime_RLMR.py";
			break;
		case(4):
			filename = NS3_ROOT "/analytics/data/optimization_lifetime.py";
			break;
		case(5):
			/*
			if(experiment_number == 0)
			{
				filename = NS3_ROOT "/analytics/data/optimization_lifetime_QRSDN.py";
			}
			if(experiment_number == 1)
			{
				filename = NS3_ROOT "/analytics/data/optimization_lifetime_RR.py";
			}
			if(experiment_number == 2)
			{
				filename = NS3_ROOT "/analytics/data/optimization_lifetime_QRSDN.py";
			}
			if(experiment_number == 3)
			{
				filename = NS3_ROOT "/analytics/data/optimization_lifetime_RLMR.py";
			}
			*/
			filename = NS3_ROOT "/analytics/data/optimization_lifetime_RLMR.py";
			
			break;
		default:
			filename = NS3_ROOT "/analytics/data/optimization_lifetime.py";
			break;
		
	}
    	std::string command = "python3 ";
    	command += filename;
    	system(command.c_str());
}

void optimize_first_time()
{
	std::string filename = NS3_ROOT "/analytics/data/optimization.py";
    	std::string command = "python3 ";
    	command += filename;
    	system(command.c_str());
}


vector<double> link_lifetime_dsrc[total_size];
vector<double> link_lifetime_ethernet[total_size];
vector<double> delay_dsrc[total_size];
vector<double> delay_ethernet[total_size];
double link_lifetime_vector[total_size*total_size];
double delay_vector[2*total_size];

void convert_link_lifetimes_dsrc()
{
	for(uint32_t i=0;i<total_size;i++)
	{
		vector<double> x_dsrc;
		for (uint32_t j = 0;j < (total_size);j++)
		{
			x_dsrc.push_back(link_lifetime_vector[(i*total_size)+j]);

		}
		
		link_lifetime_dsrc[i] = x_dsrc;	
	}
		
	vector<vector<double>> new_adjacencyMatrix_dsrc;
	for(uint32_t i=0;i<total_size;i++)
	//for(uint32_t i=0;i<9;i++)
	{
		new_adjacencyMatrix_dsrc.push_back(link_lifetime_dsrc[i]);
	}
	linklifetimeMatrix_dsrc = new_adjacencyMatrix_dsrc;
	//cout<<"link lifetime matrix converted"<<endl;
	
	/*
	for (uint32_t i=0;i<total_size;i++)
	//for (uint32_t i=0;i<9;i++)
	{
	
		for (uint32_t j=0;j<total_size;j++)
		//for (uint32_t j=0;j<9;j++)
		{
			cout<<"DSRC Link lifetime from source node"<<(i)<<"to node "<<(j)<<"is "<<linklifetimeMatrix_dsrc[i][j]<<endl;
		}
	}
	*/
			
	//cout<<"adjacency matrix size"<<adjacencyMatrix.size()<<endl;
	cout<<"link lifetime conversion finished at"<<Seconds(Now().GetSeconds())<<endl;
}


void convert_link_lifetimes()
{
	for(uint32_t i=0;i<total_size;i++)
	{
		vector<double> x_dsrc;
		vector<double> x_ethernet;
		for (uint32_t j = 0;j < (total_size);j++)
		{
			x_dsrc.push_back(link_lifetime_vector[(i*total_size)+j]);
			if(i<N_Vehicles)
			{
				x_ethernet.push_back(0.0);
			}
			else
			{
				if(j<N_Vehicles)
				{
					x_ethernet.push_back(0.0);
				}
				else
				{
					if(i==j)
					{
						x_ethernet.push_back(0.0);
					}
					else
					{
						x_ethernet.push_back(11.0);
					}
				}
			}
		}
		
		link_lifetime_dsrc[i] = x_dsrc;	
		link_lifetime_ethernet[i] = x_ethernet;
	}
		
	vector<vector<double>> new_adjacencyMatrix_dsrc;
	vector<vector<double>> new_adjacencyMatrix_ethernet;
	for(uint32_t i=0;i<total_size;i++)
	//for(uint32_t i=0;i<9;i++)
	{
		new_adjacencyMatrix_dsrc.push_back(link_lifetime_dsrc[i]);
		new_adjacencyMatrix_ethernet.push_back(link_lifetime_ethernet[i]);
	}
	linklifetimeMatrix_dsrc = new_adjacencyMatrix_dsrc;
	linklifetimeMatrix_ethernet = new_adjacencyMatrix_ethernet;
	cout<<"link lifetime matrix converted"<<endl;
	
	
	for (uint32_t i=0;i<total_size;i++)
	//for (uint32_t i=0;i<9;i++)
	{
		
		for (uint32_t j=0;j<total_size;j++)
		//for (uint32_t j=0;j<9;j++)
		{
			cout<<"DSRC Link lifetime from source node"<<(i)<<"to node "<<(j)<<"is "<<linklifetimeMatrix_dsrc[i][j]<<endl;
			cout<<"Ethernet Link lifetime from source node"<<(i)<<"to node "<<(j)<<"is "<<linklifetimeMatrix_ethernet[i][j]<<endl;
		}
		
		
	}
			
	//cout<<"adjacency matrix size"<<adjacencyMatrix.size()<<endl;
}

void read_lifetime_from_csv()
{
    fstream fin;
    cout<<"reading lifetime from csv at"<<Now().GetSeconds()<<endl;
    switch(routing_algorithm)
    {
    	case(0):
    		fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution_ECMP.csv", ios::in);
    		break;
    	case(1):
    		fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution_RR.csv", ios::in);
    		break;
    	case(2):
    		fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution_QRSDN.csv", ios::in);
    		break;
    	case(3):
    		fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution_RLMR.csv", ios::in);
    		break;
    	case(4):
    		fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution.csv", ios::in);
    		break;	
    	case(5):
    		/*
    		if(experiment_number == 0)
    		{
    			fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution_QRSDN.csv", ios::in);
    		}
    		if(experiment_number == 1)
    		{
    			fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution_RR.csv", ios::in);
    		}
    		if(experiment_number == 2)
    		{
    			fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution_QRSDN.csv", ios::in);
    		}
    		if(experiment_number == 3)
    		{
    			fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution_RLMR.csv", ios::in);
    		}
    		*/
    		fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution_RLMR.csv", ios::in);
    		break;	
    		
    	default:
    		fin.open(NS3_ROOT "/analytics/data/link_lifetime_solution.csv", ios::in);
    		break;
    }
    
    vector<string> row;
    string line;
    string temp;
    int j=0;
    while (fin >> temp) 
    {
        row.clear();
        getline(fin, line);
        int n = line.length();
        char line_char[n+1];
        strcpy(line_char,line.c_str());
        //cout<<line<<endl;
        double dou_val;
        char * ptr;
        ptr = strtok(line_char,",");
        int i =0;
        while(ptr != NULL)
        {
        	stringstream ss;
		ss << ptr;
		//cout<<ptr<<endl;
		ss >> dou_val;
		if (i==0)
		{
			link_lifetime_vector[j] = dou_val;
			//cout<<j<<" value "<<dou_val<<endl;
		}
        	
        	ptr = strtok(NULL,",");   
        	i++;	
        }
        j++;
    }
    if (j == 0)
        cout << "Solution not found\n";
    convert_link_lifetimes_dsrc();
}

void run_ECMP()
{
	cout<<"Running ECMP started at "<<Now().GetSeconds()<<endl;
	for(uint32_t fid=0;fid<2*flows;fid++)
	{
		//uint32_t f_size = (demanding_flow_struct_controller_inst+fid)->f_size;
		uint32_t f_source = (demanding_flow_struct_controller_inst+fid)->source;
		//uint32_t f_destination = (demanding_flow_struct_controller_inst+fid)->destination;
		if((demanding_flow_struct_controller_inst+fid)->f_size == 0)
		{
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
				}
			}
		}
		else
		{
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				uint32_t next_hops_count = 0;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if ((distance_algo2_output_inst[fid].D[nid] < distance_algo2_output_inst[fid].D[cid])&&(distance_algo2_output_inst[fid].conn[nid]==1)&& (distance_algo2_output_inst[fid].conn[cid]==1)&&(linklifetimeMatrix_dsrc[cid][nid]>0.0))
					{
						next_hops_count++;
					}
				}
				
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if ((distance_algo2_output_inst[fid].D[nid] < distance_algo2_output_inst[fid].D[cid])&&(distance_algo2_output_inst[fid].conn[nid]==1)&& (distance_algo2_output_inst[fid].conn[cid]==1)&&(linklifetimeMatrix_dsrc[cid][nid]>0.0))
					{
						double lifetime_uncertainity = maxspeed*0.001;
						(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 1.0/(next_hops_count+lifetime_uncertainity);
					}
					else
					{
						(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					}
					
					//Compute load values
					if(cid == f_source)
					{
						(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = (delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid];
					}
					else
					{
						double summation = 0;
						for(int i=0;i<total_size;i++)
						{
							summation = summation + (L_at_controller_inst+fid)->L_fi_inst[i].L_values[cid];
						}
						(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = ((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid])*summation;
					}
				}
			}
		}
	}
	cout<<"Running ECMP finished at "<<Now().GetSeconds()<<endl;
}

double compute_packet_delay_DCMR(uint32_t fid, uint32_t nid, uint32_t packet_size)
{
	//uint32_t zeta = 1;
	double B_bar;
	if(qf < 2)
	{
		//B_bar = (1+B_max)/2.0;
		B_bar = 2.0;
	}
	else
	{
		B_bar = B_max;
	}
	rts = 20.0;
	cts = 14.0;
	ack = 14.0;

	double datarate = 12.0;
	double T_trans = ((8*((B_bar*(packet_size+rts+cts))+(ack)))/(datarate));
	double delay = (distance_algo2_output_inst[fid].Y[nid]*(T_trans))/(1000000);
	//cout<<"Computed packet delay DCMR is "<<delay<<" seconds "<<endl;
	return delay;
}

void run_DCMR()
{
	cout<<"Running DCMR started at "<<Now().GetSeconds()<<endl;
	double RBW[total_size];
	double congestion_level[total_size];
	
	for(uint32_t i=0; i<total_size;i++)
	{
		RBW[i] = 1.0;
		congestion_level[i] = 0.0001;
	}
	for(uint32_t fid=0;fid<2*flows;fid++)
	{
		//uint32_t f_size = (demanding_flow_struct_controller_inst+fid)->f_size;
		uint32_t f_source = (demanding_flow_struct_controller_inst+fid)->source;
		//uint32_t f_destination = (demanding_flow_struct_controller_inst+fid)->destination;
		uint32_t f_psize = (demanding_flow_struct_controller_inst+fid)->p_size;
		
		if((demanding_flow_struct_controller_inst+fid)->f_size == 0)
		{
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
				}
			}
		}
		else
		{	
			//uint32_t cid = f_source;
			//while(cid != f_destination)
			for(uint32_t cid=0;cid<total_size;cid++)
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
				}
				//uint32_t next_hops_count = 0;
				double RBW_local[total_size];
				double congestion_level_local[total_size];
				double PUF_local[total_size];
				int32_t cost_local[total_size];
				for(uint32_t i=0; i<total_size;i++)
				{
					RBW_local[i] = 1.0;
					congestion_level_local[i] = 0.0001;
					PUF_local[i] = 0.0;
					cost_local[i] = 100000;
				}
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					double packet_delay = compute_packet_delay_DCMR(fid, nid, f_psize);
					if ((distance_algo2_output_inst[fid].D[nid] < distance_algo2_output_inst[fid].D[cid])&&(distance_algo2_output_inst[fid].conn[nid]==1)&& (distance_algo2_output_inst[fid].conn[cid]==1)&&(linklifetimeMatrix_dsrc[cid][nid]>0.0)&&(packet_delay < latency_max))
					{
						//next_hops_count++;
						cout<<"packet delay is "<<packet_delay<<"latency constraint is "<<latency_max<<endl;
						cout<<"current hop "<<cid<<"next hop "<<nid<<endl;
						//(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.00001;
						//(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.00001;
						double cur_delta = (lambda*flow_packet_size*8/1000.0);
						double prev_delta = 12000 - RBW[nid]*12000;
						double delta = prev_delta + cur_delta;
						RBW_local[nid] = (12000 - delta)/(12000.0);
						cout<<"RBW_local is "<<RBW_local[nid]<<endl;
						double cur_to = lambda;
						double prev_to = congestion_level[nid]*10*lambda;
						congestion_level_local[nid] = (cur_to + prev_to)/(10.0*lambda);
						cout<<"congestion_local is "<<congestion_level_local[nid]<<endl;
						cout<<"link lifetime is "<<linklifetimeMatrix_dsrc[cid][nid]<<endl;
						PUF_local[nid] = (RBW_local[nid]/congestion_level_local[nid])*(linklifetimeMatrix_dsrc[cid][nid]);
						cout<<"PUF_local is "<<PUF_local[nid]<<endl;
						cost_local[nid] = (distance_algo2_output_inst[fid].D[nid]/10.0) - PUF_local[nid];
						cout<<"distance is "<<distance_algo2_output_inst[fid].D[nid]<<endl;
						cout<<"cost_local is "<<cost_local[nid]<<endl;
					}
				}
				
				uint32_t least_cost_hop = cid;
				int32_t least_cost = 100000;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if(cost_local[nid] < least_cost)
					{
						least_cost_hop = nid;
						least_cost = cost_local[nid];
					}
				}
				cout<<endl;
				cout<<"Least cost hop is "<<least_cost_hop<<endl;
				cout<<endl;
				RBW[least_cost_hop] = RBW_local[least_cost_hop];
				congestion_level[least_cost_hop] = congestion_level_local[least_cost_hop];
				
				
				uint32_t second_least_cost_hop = cid;
				int32_t second_least_cost = 100000;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if((cost_local[nid] < second_least_cost)&&(cost_local[nid] > least_cost))
					{
						second_least_cost_hop = nid;
						second_least_cost = cost_local[nid];
					}
				}
				cout<<endl;
				cout<<"Second least cost hop is "<<second_least_cost_hop<<endl;
				cout<<endl;
				RBW[second_least_cost_hop] = RBW_local[second_least_cost_hop];
				congestion_level[second_least_cost_hop] = congestion_level_local[second_least_cost_hop];
				
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if(second_least_cost_hop == cid)
					{
						if((nid!=cid)&&(nid == least_cost_hop))
						{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 1.0;
						}
						else
						{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
						}
					}
					else
					{
						if((nid!=cid)&&(nid == least_cost_hop))
						{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.7;
						}
						else if((nid!=cid)&&(nid == second_least_cost_hop))
						{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.3;
						}
						else
						{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
						}
					}
				}
			}
			for(uint32_t cid=0;cid<total_size;cid++)
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if(cid == f_source)
					{
						(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = (delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid];
					}
					else
					{
						double summation = 0;
						for(int i=0;i<total_size;i++)
						{
							summation = summation + (L_at_controller_inst+fid)->L_fi_inst[i].L_values[cid];
						}
						(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = ((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid])*summation;
					}
				}
			//cid = least_cost_hop;
			}	
		}
	}
	cout<<"Running DCMR finished at "<<Now().GetSeconds()<<endl;
}

double learning_rate = 0.9;
uint32_t max_hops = 20;
double discount_factor =0.50;


void run_QRSDN()
{
	cout<<"Running QRSDN started at "<<Now().GetSeconds()<<endl;
	for(uint32_t fid=0;fid<2*flows;fid++)
	{
		//uint32_t f_size = (demanding_flow_struct_controller_inst+fid)->f_size;
		uint32_t f_source = (demanding_flow_struct_controller_inst+fid)->source;
		uint32_t f_destination = (demanding_flow_struct_controller_inst+fid)->destination;
		
		if((demanding_flow_struct_controller_inst+fid)->f_size == 0)
		{
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
				}
			}
			//cout<<"flow id "<<fid<<"is empty"<<endl;
		}
		else
		{
			//cout<<"Running RL in fid "<<fid<<endl;
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				//Initialize Q values with lifetime
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if ((cid==f_destination) || (nid==f_source))
					{
						(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 0.0;
					}
					else if ((linklifetimeMatrix_dsrc[cid][nid]>0.0))
					{
						(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 1.0;
					}
					else
					{
						(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 0.0;
					}
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
				}
			}
			//cout<<"Q-values initialized"<<endl;
			
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				//convert to acyclic graph
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					
					(Y_at_controller_inst+fid)->Y_fi_inst[cid].Y_values[nid] = distance_algo2_output_inst[fid].Y[cid];
					if (((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] == 1.0) && ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[cid] == 1.0))
					{
						if ((distance_algo2_output_inst[fid].D[nid] < distance_algo2_output_inst[fid].D[cid]))
						{
							(Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[cid] = 0.0;
						}
						else if ((distance_algo2_output_inst[fid].D[nid] > distance_algo2_output_inst[fid].D[cid]))
						{
							(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 0.0;
						}
						else if ((distance_algo2_output_inst[fid].D[nid] == distance_algo2_output_inst[fid].D[cid]))
						{
							if ((distance_algo2_output_inst[fid].Y[nid] < distance_algo2_output_inst[fid].Y[cid]))
							{
								(Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[cid] = 0.0;
							}
							else if ((distance_algo2_output_inst[fid].Y[nid] > distance_algo2_output_inst[fid].Y[cid]))
							{
								(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 0.0;
							}
						}
					}
				}
			}
			//cout<<"Converted to acyclic graph"<<endl;
			//Initialize delta, load values
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				//count actions
				uint32_t actions=0;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
					{
						actions++;
					}
				}//Intialize delta, load values
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					
					if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
					{
						(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 1.0/actions;
						if(cid == f_source)
						{
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = (delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid];
						}
						else
						{
							double summation = 0.0;
							for(int i=0;i<total_size;i++)
							{
								summation = summation + (L_at_controller_inst+fid)->L_fi_inst[i].L_values[cid];
							}
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = ((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid])*summation;
						}
						//cout<<"Initialized delta as "<<(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid]<<"and load as "<<(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid]<<"for flow id "<<fid<<"current node "<<cid<<"next hop "<<nid<<endl;
					}
				}
			}
			//cout<<"Initialized delta and load values"<<endl;
			
				//RL
				for(uint32_t m=0;m<RL_iterations;m++)
				{
					//cout<<"Iteration "<<m<<endl;
					uint32_t cid = f_source;
					uint32_t actions=0;
					list<uint32_t> action_set;
					
					for(uint32_t nid=0;nid<total_size;nid++)	
					{
						if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
						{
							action_set.push_back(nid);
							actions++;
						}
					}
					while (actions > 0)
					{
						uint32_t index = rand()%actions;
						auto front = action_set.begin();
						advance(front,index);
					 	uint32_t nid = *front;
					 	(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid]	= distance_algo2_output_inst[fid].conn[nid];
					 	
					 	double y_summation = 0.0;
					 	for(int j=0;j<total_size;j++)
					 	{
					 		y_summation = y_summation + (((delta_at_controller_inst+fid)->delta_fi_inst[nid].delta_values[j])*((Y_at_controller_inst+fid)->Y_fi_inst[nid].Y_values[j]));
					 	}
						(Y_at_controller_inst+fid)->Y_fi_inst[cid].Y_values[nid]= 1 + y_summation;
						
						
						//Compute delta_values
						double q_summation = 0.0;
						double q_max = 0.0;
						for(int j=0;j<total_size;j++)
					 	{
					 		if(((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j])> 0.0)
					 		{
					 			q_summation = q_summation + ((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j]);
					 		}
					 		if(((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j])> 0.0)
					 		{
						 		if(q_max < ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j]))
						 		{
						 			q_max = ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j]);
						 		}
					 		}
					 	}
					 	if ((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
					 	{
						
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = (((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid]))/(q_summation);
						}
						else
						{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
						}
						
						//Compute load values
						if(cid == f_source)
						{
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = (delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid];
						}
						else
						{
							double summation = 0;
							for(int i=0;i<total_size;i++)
							{
								summation = summation + (L_at_controller_inst+fid)->L_fi_inst[i].L_values[cid];
							}
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = ((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid])*summation;
						}
						
						//Compute reward
						(W_at_controller_inst+fid)->W_fi_inst[cid].W_values[nid] = ((max_hops) - (Y_at_controller_inst+fid)->Y_fi_inst[cid].Y_values[nid])/(max_hops);
						
						//Update Q value
						double q_term1 = (1.0-learning_rate)*((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid]);
						double q_term2 = (learning_rate)*(((W_at_controller_inst+fid)->W_fi_inst[cid].W_values[nid])+(discount_factor*q_max));
						(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = q_term1 + q_term2;
						//cout<<"Flow id "<<fid<<"current hop "<<cid<<"next hop "<<nid<<"updated Q value as : "<<(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid]<<"updated delta value is "<<(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid]<<"Link load "<<((L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid])*f_size<<"packets"<<"Hop count "<<(Y_at_controller_inst+fid)->Y_fi_inst[cid].Y_values[nid]<<"with reward "<<(W_at_controller_inst+fid)->W_fi_inst[cid].W_values[nid]<<endl;
						
						//Compute delta_values
						double q_summation_again = 0.0;
						double q_max_again = 0.0;
						for(int j=0;j<total_size;j++)
					 	{
					 		if(((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j])> 0.0)
					 		{
					 			q_summation_again = q_summation_again + ((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j]);
					 		}
					 		if(((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j])> 0.0)
					 		{
						 		if(q_max_again < ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j]))
						 		{
						 			q_max_again = ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j]);
						 		}
					 		}
					 	}
					 	if ((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
					 	{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = (((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid]))/(q_summation_again);
						}
						
						else
						{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
						}
						
						//Compute load values
						if(cid == f_source)
						{
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = (delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid];
						}
						else
						{
							double summation = 0;
							for(int i=0;i<total_size;i++)
							{
								summation = summation + (L_at_controller_inst+fid)->L_fi_inst[i].L_values[cid];
							}
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = ((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid])*summation;
						}
						
						//Go to next state
						cid = nid;
						uint32_t local_actions=0;
						list<uint32_t> local_action_set;
						
						for(uint32_t j=0;j<total_size;j++)	
						{
							if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j] > 0.0)
							{
								local_action_set.push_back(j);
								local_actions++;
							}
						}
						actions = local_actions;
						action_set = local_action_set;
					}
			}
		}
	}
	cout<<"QRSDN finished at "<<Now().GetSeconds()<<endl;
}

void run_RLMR()
{
	cout<<"Running RLMR started at "<<Now().GetSeconds()<<endl;
	for(uint32_t fid=0;fid<2*flows;fid++)
	{
		//uint32_t f_size = (demanding_flow_struct_controller_inst+fid)->f_size;
		uint32_t f_source = (demanding_flow_struct_controller_inst+fid)->source;
		uint32_t f_destination = (demanding_flow_struct_controller_inst+fid)->destination;
		//uint32_t f_psize = (demanding_flow_struct_controller_inst+i)->p_size;
		uint32_t f_qos = (demanding_flow_struct_controller_inst+fid)->qos;
		
		if((demanding_flow_struct_controller_inst+fid)->f_size == 0)
		{
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
				}
			}
			//cout<<"flow id "<<fid<<"is empty"<<endl;
		}
		else
		{
			//cout<<"Running RL in fid "<<fid<<endl;
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				//Initialize Q values with lifetime
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if ((cid==f_destination) || (nid==f_source))
					{
						(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 0.0;
					}
					else if ((linklifetimeMatrix_dsrc[cid][nid]>0.0))
					{
						(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 1.0;
					}
					else
					{
						(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 0.0;
					}
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
				}
			}
			//cout<<"Q-values initialized"<<endl;
			
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				//convert to acyclic graph
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					
					(Y_at_controller_inst+fid)->Y_fi_inst[cid].Y_values[nid] = distance_algo2_output_inst[fid].Y[cid];
					if (((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] == 1.0) && ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[cid] == 1.0))
					{
						if ((distance_algo2_output_inst[fid].D[nid] < distance_algo2_output_inst[fid].D[cid]))
						{
							(Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[cid] = 0.0;
						}
						else if ((distance_algo2_output_inst[fid].D[nid] > distance_algo2_output_inst[fid].D[cid]))
						{
							(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 0.0;
						}
						else if ((distance_algo2_output_inst[fid].D[nid] == distance_algo2_output_inst[fid].D[cid]))
						{
							if ((distance_algo2_output_inst[fid].Y[nid] < distance_algo2_output_inst[fid].Y[cid]))
							{
								(Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[cid] = 0.0;
							}
							else if ((distance_algo2_output_inst[fid].Y[nid] > distance_algo2_output_inst[fid].Y[cid]))
							{
								(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = 0.0;
							}
						}
					}
				}
			}
			//cout<<"Converted to acyclic graph"<<endl;
			//Initialize delta, load values
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				//count actions
				uint32_t actions=0;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
					{
						actions++;
					}
				}//Intialize delta, load values
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					
					if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
					{
						(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 1.0/actions;
						if(cid == f_source)
						{
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = (delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid];
						}
						else
						{
							double summation = 0.0;
							for(int i=0;i<total_size;i++)
							{
								summation = summation + (L_at_controller_inst+fid)->L_fi_inst[i].L_values[cid];
							}
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = ((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid])*summation;
						}
						//cout<<"Initialized delta as "<<(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid]<<"and load as "<<(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid]<<"for flow id "<<fid<<"current node "<<cid<<"next hop "<<nid<<endl;
					}
				}
			}
			//cout<<"Initialized delta and load values"<<endl;
			
				//RL
				for(uint32_t m=0;m<RL_iterations;m++)
				{
					//cout<<"Iteration "<<m<<endl;
					uint32_t cid = f_source;
					uint32_t actions=0;
					list<uint32_t> action_set;
					
					for(uint32_t nid=0;nid<total_size;nid++)	
					{
						if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
						{
							action_set.push_back(nid);
							actions++;
						}
					}
					uint32_t l_count = 0;
					while ((actions > 0)&&(l_count<10000))
					{
						uint32_t index = rand()%actions;
						auto front = action_set.begin();
						advance(front,index);
					 	uint32_t nid = *front;
					 	if (nid == f_destination)
					 	{
					 		(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid]	= distance_algo2_output_inst[fid].conn[nid];
					 	}
					 	
					 	else
					 	{
					 		(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid]	= 0;
					 	}
					 	
					 	double y_summation = 0.0;
					 	for(int j=0;j<total_size;j++)
					 	{
					 		y_summation = y_summation + (((delta_at_controller_inst+fid)->delta_fi_inst[nid].delta_values[j])*((Y_at_controller_inst+fid)->Y_fi_inst[nid].Y_values[j]));
					 	}
						(Y_at_controller_inst+fid)->Y_fi_inst[cid].Y_values[nid]= 1 + y_summation;
						
						
						//Compute delta_values
						double q_summation = 0.0;
						double q_max = 0.0;
						for(int j=0;j<total_size;j++)
					 	{
					 		if(((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j])> 0.0)
					 		{
					 			q_summation = q_summation + ((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j]);
					 		}
					 		if(((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j])> 0.0)
					 		{
						 		if(q_max < ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j]))
						 		{
						 			q_max = ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j]);
						 		}
					 		}
					 	}
					 	
					 	if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
					 	{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = (((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid]))/(q_summation);
						}
						else
						{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
						
						}
						
						//Compute load values
						if(cid == f_source)
						{
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = (delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid];
						}
						else
						{
							double summation = 0;
							for(int i=0;i<total_size;i++)
							{
								summation = summation + (L_at_controller_inst+fid)->L_fi_inst[i].L_values[cid];
							}
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = ((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid])*summation;
						}
						
						//Compute reward
						(W_at_controller_inst+fid)->W_fi_inst[cid].W_values[nid] = ((3*(max_hops)) - (f_qos*(Y_at_controller_inst+fid)->Y_fi_inst[cid].Y_values[nid])+((L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid])+(10*(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid]))/((3*(max_hops))+10+lambda);
						
						//Update Q value
						double q_term1 = (1.0-learning_rate)*((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid]);
						double q_term2 = (learning_rate)*(((W_at_controller_inst+fid)->W_fi_inst[cid].W_values[nid])+(discount_factor*q_max));
						(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = q_term1 + q_term2;
						//cout<<"Flow id "<<fid<<"f qos"<<f_qos<<"current hop "<<cid<<"next hop "<<nid<<"updated Q value as : "<<(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid]<<"updated delta value is "<<(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid]<<"Link load "<<((L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid])*f_size<<"packets"<<"Hop count "<<(Y_at_controller_inst+fid)->Y_fi_inst[cid].Y_values[nid]<<"with reward "<<(W_at_controller_inst+fid)->W_fi_inst[cid].W_values[nid]<<"Omega"<<(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid]<<endl;
						
						//Compute delta_values
						double q_summation_again = 0.0;
						double q_max_again = 0.0;
						for(int j=0;j<total_size;j++)
					 	{
					 		if(((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j])> 0.0)
					 		{
					 			q_summation_again = q_summation_again + ((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j]);
					 		}
					 		if(((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j])> 0.0)
					 		{
						 		if(q_max_again < ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j]))
						 		{
						 			q_max_again = ((Q_at_controller_inst+fid)->Q_fi_inst[nid].Q_values[j]);
						 		}
					 		}
					 	}
					 	if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] > 0.0)
					 	{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = (((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid]))/(q_summation_again);
						}
						else
						{
							(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
						
						}
						//Compute load values
						if(cid == f_source)
						{
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = (delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid];
						}
						else
						{
							double summation = 0;
							for(int i=0;i<total_size;i++)
							{
								summation = summation + (L_at_controller_inst+fid)->L_fi_inst[i].L_values[cid];
							}
							(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = ((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid])*summation;
						}
						
						//Go to next state
						cid = nid;
						uint32_t local_actions=0;
						list<uint32_t> local_action_set;
						
						for(uint32_t j=0;j<total_size;j++)	
						{
							if((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[j] > 0.0)
							{
								local_action_set.push_back(j);
								local_actions++;
							}
						}
						actions = local_actions;
						action_set = local_action_set;
						l_count++;
					}
			}
		}
	}
	cout<<"RLMR finished at "<<Now().GetSeconds()<<endl;
}

struct flow_cardinality
{
	uint32_t cardinality[total_size];
};

struct flow_cardinality f_card_inst[2*flows];



double compute_link_delay(uint32_t next_hop, double link_load, uint32_t flow_size, uint32_t packet_size, uint32_t destination, uint32_t zeta)
{
	//uint32_t zeta = 1;
	double B_bar;
	if(qf < 2)
	{
		//B_bar = (1+B_max)/2.0;
		B_bar = 2.0;
	}
	else
	{
		B_bar = B_max;
	}
	rts = 20.0;
	cts = 14.0;
	ack = 14.0;
	double guard_delay = 0.000100;
	double datarate = 12.0;
	double T_cont = (AIFS) + ((T_slot*CW_min)/(pow(2,(3-B_bar))));//in microseconds
	double T_trans = ((8*((B_bar*(packet_size+rts+cts))+(ack)))/(datarate));
	double delay = guard_delay + (zeta*link_load*flow_size*(T_trans+T_cont))/(1000000);
	//cout<<"Computed link delay is "<<delay<<" seconds for next hop "<<next_hop<<endl;
	return delay;
}

double compute_individual_link_delay(uint32_t next_hop, uint32_t CW, uint32_t flow_size, uint32_t packet_size, uint32_t destination, uint32_t zeta)
{
	//uint32_t zeta = 1;
	rts = 20.0;
	cts = 14.0;
	ack = 14.0;
	double guard_delay = 0.000100;
	double datarate = 12.0;
	double T_cont = (AIFS) + ((T_slot*CW_min)/(pow(2,(3-CW))));//in microseconds
	double T_trans = ((8*((1.00*(packet_size+rts+cts))+(ack)))/(datarate));
	double delay = guard_delay + (zeta*1.15*flow_size*(T_trans+T_cont))/(1000000);
	//cout<<"Computed link delay is "<<delay<<" seconds for next hop "<<next_hop<<endl;
	return delay;
}

double compute_path_delay(uint32_t fid, uint32_t cid, uint32_t nid, double link_load, uint32_t flow_size, uint32_t packet_size, uint32_t destination)
{

	uint32_t zeta;
	if (flows == 1)
	{
		zeta = 14;
	}
	else
	{	if(routing_algorithm != 4)
		{
			zeta = 18;
		}
		else
		{
			zeta = 14 + 2*scheduled_flows;
		
		}
	}
	
	double link_lat_summation = 0.0;
	for(uint32_t i =0;i<total_size; i++)
	{
		if (((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid]) >= ((delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[i]))
		{
			link_lat_summation = link_lat_summation + ((t_at_controller_inst+fid)->t_fi_inst[cid].t_values[i])/2.0;
		}
	}
	
	double y_summation = 0.0;
	for(uint32_t i =0;i<total_size; i++)
	{
		y_summation = y_summation + (((delta_at_controller_inst+fid)->delta_fi_inst[nid].delta_values[i])*((Y_at_controller_inst+fid)->Y_fi_inst[nid].Y_values[i]));
	}
	
	double packet_latency = 0.0;
	if(link_load > 0.0)
	{
		packet_latency = (((t_at_controller_inst+fid)->t_fi_inst[cid].t_values[nid])/((1.0 + (0.1*scheduled_flows*scheduled_flows))*(zeta*flow_size*link_load)))*(y_summation);
	}
	
	double path_latency = link_lat_summation + packet_latency;
	//cout<<"Computed path delay is "<<path_latency<<" seconds for current hop"<<cid<<"next hop "<<nid<<endl;
	return path_latency;
}




double Lf_bar[2*flows];
double Yf_bar[2*flows][total_size];
vector<uint32_t> blacklist_nodes;
vector<vector<uint32_t>> P_list;
vector<vector<uint32_t>> Q_list;

bool search_blacklist_nodes(uint32_t node_id)
{
	bool result = false;
	for(uint32_t i=0;i<size(blacklist_nodes);i++)
	{
		if(blacklist_nodes[i] == node_id)
		{
			return true;
		}
	}
	return result;
}

double epsilon_0_initial = 0.5;


bool is_link_blacklist(uint32_t cid, uint32_t nid)
{
	bool blacklist_link = false;
	for(uint32_t i=0;i<size(Q_list);i++)
	{
		if((Q_list[i][0]==cid)&&(Q_list[i][1]==nid))
		{
			blacklist_link = true;
		}
		if((Q_list[i][0]==nid)&&(Q_list[i][1]==cid))
		{
			blacklist_link = true;
		}
	}
	return blacklist_link;
}


uint32_t update_link_state(uint32_t cid, uint32_t nid, uint32_t fids, uint32_t fidd)
{
	bool link_state_malicious = is_link_blacklist(cid, nid);
	if(link_state_malicious==false)
	{
		if((D_mat[cid][nid][fids][fidd]==0)&&(I_mat[cid][nid][fids][fidd]==0))
		{
			return 0;
		}
		else if((D_mat[cid][nid][fids][fidd]==1)&&(I_mat[cid][nid][fids][fidd]==0))
		{
			return 1;
		}
		else if(I_mat[cid][nid][fids][fidd]==-1)
		{
			return 2;
		}
		else
		{
			return 3;
		}	
	}
	else
	{
		if((D_mat[cid][nid][fids][fidd]==0))
		{
			return 4;
		}
		else
		{
			return 5;
		}
	}
}

double map_state_to_suspicion(double state)
{
	double suspicion = 0.0;
	if(state==2)
	{
		suspicion = -1.0;
	}
	
	else if (state==3)
	{
		suspicion = 1.0;
	}
	
	else if (state==4)
	{
		suspicion = 0.5;
	}
	
	else if (state==5)
	{
		suspicion = -0.5;
	}
	
	else if (state==0)
	{
		suspicion = -0.25;
	}
	
	else if (state==1)
	{
		suspicion = 0.25;
	}
	return suspicion;

}







double XOR(double val1, double val2)
{

if (val1 == 1.0 || val2 == 1.0)
{
	return 1.0;

}
else
{
	return 0.0;

}

}

void remove_fabricated_duplicate(uint32_t cid, uint32_t nid)
{
	if ((Link_at_controller_inst+(0))->Link_f_inst[(1)].Link_fi_inst[cid].Link_values[nid]==1)
	{
		(Link_at_controller_inst+(0))->Link_f_inst[(1)].Link_fi_inst[cid].Link_values[nid] = 0;
	}
	else if ((Link_at_controller_inst+(1))->Link_f_inst[(0)].Link_fi_inst[cid].Link_values[nid]==1)
	{
		(Link_at_controller_inst+(1))->Link_f_inst[(0)].Link_fi_inst[cid].Link_values[nid] = 0;
	}
}

void remove_fabricated_duplicate_with_probability(uint32_t cid, uint32_t nid, double probability)
{
	bool attacking_state = GetBooleanWithProbability(probability, cid);
	if(attacking_state)
	{
		if ((Link_at_controller_inst+(0))->Link_f_inst[(1)].Link_fi_inst[cid].Link_values[nid]==1)
		{
			cout<<"Duplicate detected. Removing "<<endl;
			(Link_at_controller_inst+(0))->Link_f_inst[(1)].Link_fi_inst[cid].Link_values[nid] = 0;
		}
	    if ((Link_at_controller_inst+(1))->Link_f_inst[(0)].Link_fi_inst[cid].Link_values[nid]==1)
		{
			(Link_at_controller_inst+(1))->Link_f_inst[(0)].Link_fi_inst[cid].Link_values[nid] = 0;
			cout<<"Duplicate detected. Removing "<<endl;
		}
	}
}


uint32_t get_port(double val1, double val2)
{
	if (val1 == 1.0)
	{
		return 0;
	}
	else if (val2 == 1.0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


void reset_flood_counter()
{
	for(uint32_t i=0;i<total_size;i++)
	{
	
		for(uint32_t j=0;j<total_size;j++)
		{
		
		
			for(uint32_t k=0;k<2;k++)
			{
				flood_counter_con[i][j][k] = 0;
				flood_counter_sen[i][j][k] = 0;
				flood_counter_rec[i][j][k] = 0;
				
				for(uint32_t m=0;m<2;m++)
				{
					LLDP_flood_counter_rec[i][j][k][m] = 0;
				}
			}
		}
	}
}



void reset_LLDP_received_count()
{
	LLDP_received_count = 0;
}

bool test = true;



void adjust_proposed_link_state(uint32_t cid)
{
	uint32_t threshold = 0;
	if(attack_number == 6)
	{
		threshold = 150;
	}
	else
	{
		threshold = 200;
	}
	for(uint32_t fids=0;fids<2;fids++)//fid is used as the port ID.
	{
		for(uint32_t fidd=0;fidd<2;fidd++)//fid is used as the port ID.
		{
			//for(uint32_t cid=0;cid<total_size;cid++)	
			//{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{	
						if (unit_step(threshold - adjacencyMatrix[cid][nid], 0) > 0.0)
						{
							bool success = GetBooleanWithProbability(60, cid+nid+fidd);
							if(success)
							{
								if((vanishing_malicious_nodes[cid]) && (!vanishing_malicious_nodes[nid]))
								{
									(Link_at_controller_inst+fids)->Link_f_inst[fidd].Link_fi_inst[cid].Link_values[nid] = 1.0;
								}
								
								if((vanishing_malicious_nodes[nid]) && (!vanishing_malicious_nodes[cid]))
								{
									(Link_at_controller_inst+fids)->Link_f_inst[fidd].Link_fi_inst[cid].Link_values[nid] = 1.0;
								}
							}
						}
						else
						{
							
						}
					
				}
			//}
		}
	}
	
}

// Forward declaration needed by vehicle_send_to_nearest_rsu()
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

void proposed_check_link_state(uint32_t cid)
{
	for(uint32_t fids=0;fids<2;fids++)//fid is used as the port ID.
	{
		for(uint32_t fidd=0;fidd<2;fidd++)//fid is used as the port ID.
		{
			//for(uint32_t cid=0;cid<total_size;cid++)	
			//{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					//remove_fabricated_duplicate_with_probability(cid, nid);//port blocking mechanism.
					//uint32_t dest_port_id = get_port((Link_at_controller_inst+(fid))->Link_f_inst[(0)].Link_fi_inst[cid].Link_values[nid], (Link_at_controller_inst+(fid))->Link_f_inst[(1)].Link_fi_inst[cid].Link_values[nid]);
					
					    cout<<"current id "<<cid<<"next id "<<nid<<"fid 1 "<<fids<<"fid 2"<<fidd<<endl;
						double D_prev = D_mat[cid][nid][fids][fidd];
						cout<<"D prev is "<<D_prev<<endl;
						cout<<"D mat okay"<<endl;
						D_mat[cid][nid][fids][fidd] = XOR((Link_at_controller_inst+(fids))->Link_f_inst[(0)].Link_fi_inst[cid].Link_values[nid], (Link_at_controller_inst+(fids))->Link_f_inst[(1)].Link_fi_inst[cid].Link_values[nid]);
						cout<<"XOR okay"<<endl;
						//I_mat[cid][nid][fids][fidd] = D_mat[cid][nid][fids][fidd] - D_prev;
						cout<<"I mat okay"<<endl;
						
						
						(Omega_at_controller_inst+fids)->Omega_fi_inst[cid].Omega_values[nid] = update_link_state(cid, nid, fids, fidd);//This (omega) is the state
						cout<<"Omega okay"<<endl;
						remove_fabricated_duplicate(cid, nid);
						uint32_t dest_port_id = fidd;
					
						double suspicion = map_state_to_suspicion((Omega_at_controller_inst+fids)->Omega_fi_inst[cid].Omega_values[nid]);
						cout<<"suspicioun okay"<<endl;
						double term1 = mu1*(suspicion);
						double packet_delivery;
						double packet_latency;
						
						if ((Link_at_controller_inst+fids)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid] > 0.0)
						{
							cout<<"Link discovered for source "<<cid<<"destination"<<nid<<"flow id"<<fids<<endl;
							packet_delivery = 100.0;
							packet_latency = (LLDP_timestamp_at_controller_inst+fids)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid] - LLDP_initial_timestamp;
						
						}
						else
						{
							packet_delivery = 0.0;
							packet_latency = 100.0;
						}
						//cout<<"overall quality reward "<<overall_quality<<"packet delivery reward "<<packet_delivery<<"packet latency reward "<<packet_latency<<endl;
						cout<<"metrics okay"<<endl;
						double term2 = mu2*(packet_delivery);
						double T_max = 1;
						//double term3 = mu3*(-1.0*((3.0-f_qos)/(3.0))*((L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] - Lf_bar[fid])*(Theta_at_controller_inst+fid)->Theta_fi_inst[cid].Theta_values[nid]);
						double term3 = mu3*(packet_latency/T_max);
						(W_at_controller_inst+fids)->W_fi_inst[cid].W_values[nid] = term1 + term2 - term3;
						cout<<"W okay"<<endl;
						//cout<<"Yf_bar is "<<Yf_bar[fid][cid]<<"Y is "<<(Y_at_controller_inst+fid)->Y_fi_inst[cid].Y_values[nid]<<" connections from source "<<actions<<endl;
						//cout<<"Jitter reward is "<<term3<<endl;
						
						double q_max = (Link_at_controller_inst+fids)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid];
						//Update Q value
						double q_term1 = (1.0-learning_rate)*((Q_at_controller_inst+fids)->Q_fi_inst[cid].Q_values[nid]);
						double q_term2 = (learning_rate)*(((W_at_controller_inst+fids)->W_fi_inst[cid].W_values[nid])+(discount_factor*q_max));
						//cout<<"Q max is"<<q_max<<"Q value term 1 is "<<q_term1<<"term 2 is "<<q_term2<<endl;
						(Q_at_controller_inst+fids)->Q_fi_inst[cid].Q_values[nid] = q_term1 + q_term2;
						
					    cout<<"Q value is "<<(Q_at_controller_inst+fids)->Q_fi_inst[cid].Q_values[nid]<<endl;
						if((Q_at_controller_inst+fids)->Q_fi_inst[cid].Q_values[nid] > 0.0)
						{
							
							B_mat[cid][nid][fids][dest_port_id] = 1;
							
							cout<<"Setting AES keys for node pair "<<endl;
							std::ostringstream oss4;
							oss4 << " is_controller=true create_security_manager_con=true netsize=1 "
							<< " node_id=" << cid  << " port_id=" << fids  << " other_node_id=" << nid << " "
							<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
							<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
							<< " sign_data=false verify_signature=false initiate_session1=false "
							<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
							<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
							<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
							<< " encrypt_rsa=false set_aes_key_for_pair=true encrypt_controller_data=false "
							<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
							<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
							<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
							<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false verify_HMAC=false"
							<< " message=sh msg_type=3";
							
							double tg = 0.00005;
							int index = (RL_iterations - 1) * (total_size * total_size * 2 * 2 * 2) + cid * (total_size * 2 * 2) + nid * 2 + fids * (total_size * 2);
						
						
							std::string command_str4 = oss4.str();
							Simulator::Schedule(Seconds(tg*index), LDA_security, command_str4);
							
							uint32_t controller_ID = node_controller_ID[cid];
							if(vanishing_malicious_controllers[controller_ID])
							{
								bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
								if (attacking_state)
								{
									B_mat[cid][nid][fids][dest_port_id] = 0;
								}
							}
						}
						
						
						else
						{
							
							B_mat[cid][nid][fids][dest_port_id] = 0;
							uint32_t controller_ID = node_controller_ID[cid];
							if(fabrication_malicious_controllers[controller_ID])
							{
								bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
								if (attacking_state)
								{
									B_mat[cid][nid][fids][dest_port_id] = 1;
								}
							}
							if(MIM_malicious_controllers[controller_ID])
							{
								bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
								if (attacking_state)
								{
									B_mat[cid][nid][fids][dest_port_id] = 1;
								}
							}
						}
						
					
				}
			//}
		}
	}
	
	if (cid < dsrc_Nodes.GetN()) {
	for(uint32_t j=0; j<total_size;j++)
	{
		 double t= 0.10;
		 int o = 31*cid+7*j;
		 srand(o);
		 double rand_delay1 = 0.000001*(rand()%100);
		 int p = 27*cid+11*j;
		 srand(p);
		 double rand_delay2 = 0.000001*(rand()%100);
		 double delta = 0.005; // base spacing
		 double delay1 = t + delta * (j) + rand_delay1;
		 double delay2 = t + delta * (j) + rand_delay2;
		 Simulator::Schedule (Seconds (delay1), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 0);
		 Simulator::Schedule (Seconds (delay2), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 1);
	}
	} // end dsrc_Nodes guard
	
}




void run_proposed_LLDP()
{
	auto start = high_resolution_clock::now();
	reset_flood_counter();
	dsrc_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	ethernet_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	cout<<"Proposed RL started at "<<Now().GetSeconds()<<endl;
	//blacklist_nodes = get_blacklist_from_blockchain();
	for(uint32_t fid=0;fid<2;fid++)//fid is used as the port ID.
	{
		
		uint32_t f_size = (demanding_flow_struct_controller_inst+fid)->f_size;
		uint32_t f_source = (demanding_flow_struct_controller_inst+fid)->source;
		uint32_t f_destination = (demanding_flow_struct_controller_inst+fid)->destination;
		uint32_t f_psize = (demanding_flow_struct_controller_inst+fid)->p_size;
		uint32_t f_qos = (demanding_flow_struct_controller_inst+fid)->qos;
		cout<<f_qos<<endl;
		cout<<f_size<<f_qos<<f_psize<<f_source<<f_destination<<endl;
		vector<vector<uint32_t>> P_new;
		vector<vector<uint32_t>> Q_new;

		
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
				}
			}
			//cout<<"flow id "<<fid<<"is empty"<<endl;
		
			cout<<"Running RL in proposed LLDP"<<fid<<endl;
			cout<<"Initializing values"<<endl;
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				bool F_state;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					
					(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]); //Omega represents state S
					(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]);//Q
					vector<uint32_t>P_ele;
					vector<uint32_t>Q_ele;
					bool res_i = search_blacklist_nodes(cid);
					bool res_j = search_blacklist_nodes(nid);
					
					if((res_i==false)&&(res_j==false))
					{
						P_ele.push_back(cid);
						P_ele.push_back(nid);
					
					}
					
					else
					{
						Q_ele.push_back(cid);
						Q_ele.push_back(nid);
					}
					
					if(size(P_ele)>0)
					{
						P_new.push_back(P_ele);
					}
					
					if(size(Q_ele)>0)
					{
						Q_new.push_back(Q_ele);
					}
					
					
					
					double state_low = 1;
					double state_high = 1;
					
					if((attack_number == 1) || (attack_number == 6))
					{
						state_low = 1 - abs(unit_step(150 - adjacencyMatrix[cid][nid], 0) - unit_step(B_mat[cid][nid][fid][fid], 0));
						state_high = 1 - abs(unit_step(400 - adjacencyMatrix[cid][nid], 0) - unit_step(B_mat[cid][nid][fid][fid], 0));
					}
					else
					{
						state_low = 1 - abs(unit_step(190 - adjacencyMatrix[cid][nid], 0) - unit_step(B_mat[cid][nid][fid][fid], 0));
						state_high = 1 - abs(unit_step(350 - adjacencyMatrix[cid][nid], 0) - unit_step(B_mat[cid][nid][fid][fid], 0));
					}
					if(((state_low == 0) || (state_high == 0)) && (cid !=nid))
					{
						E_mat[cid][nid][fid] = 0;
					}
					else
					{
						E_mat[cid][nid][fid] = 1;
					}
					
					if(E_mat[cid][nid][fid] == 0)
					{
						(Link_at_controller_inst+fid)->Link_f_inst[0].Link_fi_inst[cid].Link_values[nid] = 0.0;
						(Link_at_controller_inst+fid)->Link_f_inst[1].Link_fi_inst[cid].Link_values[nid] = 0.0;
					}
					else
					{
						(Link_at_controller_inst+fid)->Link_f_inst[0].Link_fi_inst[cid].Link_values[nid] = B_mat[cid][nid][fid][fid];
						(Link_at_controller_inst+fid)->Link_f_inst[1].Link_fi_inst[cid].Link_values[nid] = B_mat[cid][nid][fid][fid];
					}
					F_state = bool(abs(I[cid][nid])) || F_state;
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
					(t_at_controller_inst+fid)->t_fi_inst[cid].t_values[nid] = 0.0;
					cout<<"This is current hop "<<cid<<"next hop "<<nid<<"Link lifetime approximate high state is "<<unit_step(350 - adjacencyMatrix[cid][nid], 0)<<endl;
					cout<<"This is current hop "<<cid<<"next hop "<<nid<<"Link lifetime approximate low state is "<<unit_step(190 - adjacencyMatrix[cid][nid], 0)<<endl;
					cout<<"Link distance is "<<adjacencyMatrix[cid][nid]<<endl;
					cout<<"B mat state is "<<unit_step(B_mat[cid][nid][fid][fid], 0)<<"E mat is "<<E_mat[cid][nid][fid]<<endl;
					cout<<"Link state is "<<(Link_at_controller_inst+fid)->Link_f_inst[fid].Link_fi_inst[cid].Link_values[nid]<<endl;
				}
				F_mat[cid][fid] = !F_state;
			}
			
			P_list = P_new;
			Q_list = Q_new;
			//cout<<"Q-values initialized"<<endl;
			
			//find cardinality
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				uint32_t summation = 0;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					double lt = unit_step(linklifetimeMatrix_dsrc[cid][nid]-link_lifetime_threshold, 0);
					double product = (proposed_algo2_output_inst[fid].conn[nid])*lt;
					summation = summation + product;
				}
				f_card_inst[fid].cardinality[cid] = summation;
				//cout<<"cardinality of node "<<cid<<"is "<<f_card_inst[fid].cardinality[cid]<<endl;
			}
		}		
		for(uint32_t fid=0;fid<2;fid++)//fid is used as the port ID.
		{	
				//RL
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					for(uint32_t m=0;m<RL_iterations;m++)
					{
						//cout<<"Iteration "<<m<<endl;
						//uint32_t cid = f_source;
						//uint32_t actions=2;
						uint32_t action =0;
						//list<uint32_t> action_set;
						
							
						double epsilon = (rand()%10)/10.0;
						//uint32_t index;
						//cout<<index<<endl;
						double val = m/500.0;
						cout<<"epsilon is "<<epsilon<<"m is "<<m<<"exponent is "<<val<<endl;
						//double epsilon_0 = epsilon_0_initial*pow(2.71, -val);
						double epsilon_0 = -0.1;
						cout<<"epsilon_0 is "<<epsilon_0<<endl;
						if (epsilon > epsilon_0)
						{
						 	action = 1;
						}
						else
						{
					 		if (((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid])> 0.0)
					 		{
					 			action = 1;
					 		}
					 		else
					 		{
					 			action = 0;
					 		}
						}
						double q = ((Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid]);
						cout<<"Q value is "<<q<<endl;
						cout<<"action is "<<action<<endl;
						
						
						double tg = 0.0025;
						int index = (RL_iterations - 1) * (total_size * total_size * 2 * 2) + cid * (total_size * 2) + nid * 2 + fid * (total_size);
						cout<<"index "<<index<<"tg is"<<tg<<endl;
						if(E_mat[cid][nid][fid] == 0)
						{
							Simulator::Schedule(Seconds(tg*index),transmit_LLDP_downlink, cid, nid, fid);
							Ptr <Node> nodei = DynamicCast <Node> (Vehicle_Nodes.Get(cid));
							Ptr<ConstantVelocityMobilityModel> mdli = DynamicCast <ConstantVelocityMobilityModel> (nodei->GetObject<MobilityModel>());
							Vector posii = mdli->GetPosition();
							Ptr <Node> nodej = DynamicCast <Node> (Vehicle_Nodes.Get(nid));
							Ptr<ConstantVelocityMobilityModel> mdlj = DynamicCast <ConstantVelocityMobilityModel> (nodej->GetObject<MobilityModel>());
							Vector posij = mdlj->GetPosition();
							cout<<"position i is "<<posii<<"position j is"<<posij<<"distance between the nodes is "<<get_length(posii,posij)<<endl;
							cout<<"Scheduling a packet for link "<<cid<<"to "<<nid<<" in flow "<<fid<<endl;
						}	
					}
					
				}
			}
		}
		
		for(uint32_t cid=0;cid<total_size;cid++)	
		{
			if(attack_number != 6)
			{
				Simulator::Schedule(Seconds(0.08+(cid+1)*0.100), adjust_proposed_link_state, cid);
				Simulator::Schedule(Seconds(0.08+(cid+1)*0.101), proposed_check_link_state, cid);
			}
			else
			{
				Simulator::Schedule(Seconds(0.25+(cid+1)*0.100), adjust_proposed_link_state, cid);
				Simulator::Schedule(Seconds(0.25+(cid+1)*0.101), proposed_check_link_state, cid);
			}
		}
		
		
		//Simulator::Schedule(Seconds(0.0),transmit_LLDP_downlink, 11, 12, 1);
		//Simulator::Schedule(Seconds(2.048), adjust_proposed_link_state);
		//Simulator::Schedule(Seconds(2.050), proposed_check_link_state);
		auto end = high_resolution_clock::now();
		auto duration = duration_cast<microseconds>(end - start).count();
		ns3_algorithm_complexity = duration;
		
		cout<<"Proposed RL learning finished at "<<Now().GetSeconds()<<"with complexity "<<duration<<endl;
}





void port_based_check_link_state(uint32_t cid)
{
	for(uint32_t fids=0;fids<2;fids++)//fid is used as the port ID.
	{
		for(uint32_t fidd=0;fidd<2;fidd++)//fid is used as the port ID.
		{
			//for(uint32_t cid=0;cid<total_size;cid++)	
			//{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					remove_fabricated_duplicate_with_probability(cid, nid, 70);
					//uint32_t dest_port_id = get_port((Link_at_controller_inst+(fid))->Link_f_inst[(0)].Link_fi_inst[cid].Link_values[nid], (Link_at_controller_inst+(fid))->Link_f_inst[(1)].Link_fi_inst[cid].Link_values[nid]);
					uint32_t dest_port_id = fidd;
					
					if((Link_at_controller_inst+fids)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid] == 1.0)
					{
						B_mat[cid][nid][fids][dest_port_id] = 1;
						uint32_t controller_ID = node_controller_ID[cid];
						if(vanishing_malicious_controllers[controller_ID])
						{
							bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
							if (attacking_state)
							{
								B_mat[cid][nid][fids][dest_port_id] = 0;
							}
						}
					}
					
					else
					{
						
						B_mat[cid][nid][fids][dest_port_id] = 0;
						uint32_t controller_ID = node_controller_ID[cid];
						if(fabrication_malicious_controllers[controller_ID])
						{
							bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
							if (attacking_state)
							{
								B_mat[cid][nid][fids][dest_port_id] = 1;
							}
						}
						
						if(MIM_malicious_controllers[controller_ID])
						{
							bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
							if (attacking_state)
							{
								if(fids == dest_port_id)
								{
									B_mat[cid][nid][fids][dest_port_id] = 1;
								}
							}
						}
					}
				}
			//}
		}
	}
	
	if (cid < dsrc_Nodes.GetN()) {
	for(uint32_t j=0; j<total_size;j++)
	{
		 double t= 0.10;
		 int o = 31*cid+7*j;
		 srand(o);
		 double rand_delay1 = 0.000001*(rand()%100);
		 int p = 27*cid+11*j;
		 srand(p);
		 double rand_delay2 = 0.000001*(rand()%100);
		 double delta = 0.005; // base spacing
		 double delay1 = t + delta * (j) + rand_delay1;
		 double delay2 = t + delta * (j) + rand_delay2;
		 Simulator::Schedule (Seconds (delay1), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 0);
		 Simulator::Schedule (Seconds (delay2), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 1);
	}
	} // end dsrc guard
	
}

void run_port_based()
{
	auto start = high_resolution_clock::now();
	dsrc_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	ethernet_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	cout<<"Port based defense started at "<<Now().GetSeconds()<<endl;
	//blacklist_nodes = get_blacklist_from_blockchain();
	for(uint32_t fid=0;fid<2;fid++)//fid is used as the port ID.
	{
		uint32_t f_size = (demanding_flow_struct_controller_inst+fid)->f_size;
		//uint32_t f_source = (demanding_flow_struct_controller_inst+fid)->source;
		//uint32_t f_destination = (demanding_flow_struct_controller_inst+fid)->destination;
		uint32_t f_psize = (demanding_flow_struct_controller_inst+fid)->p_size;
		uint32_t f_qos = (demanding_flow_struct_controller_inst+fid)->qos;
		cout<<f_qos<<endl;
		cout<<f_size<<f_qos<<f_psize<<endl;
		
		
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[0].Link_fi_inst[cid].Link_values[nid] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[1].Link_fi_inst[cid].Link_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
				}
			}
			//cout<<"flow id "<<fid<<"is empty"<<endl;

			cout<<"Running port based"<<fid<<endl;
			cout<<"Initializing values"<<endl;
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				bool F_state;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					
					(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]); //Omega represents state S
					(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]);//Q
					
					//cout<<"cid"<<cid<<"nid"<<nid<<"fid"<<fid<<endl;
					//std::cout << "E_mat size=" << E_mat.size()<< " mid=" << (E_mat.empty() ? 0 : E_mat[0].size())<< " inner=" << (E_mat.empty() ? 0 : E_mat[0][0].size())<< " cid=" << cid << " nid=" << nid << " fid=" << fid<< std::endl;
					E_mat[cid][nid][fid] = 0.0;
					//cout<<"E mat okay"<<endl;
					F_state = bool(abs(I[cid][nid])) || F_state;
					//cout<<"F_state"<<endl;
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
					(t_at_controller_inst+fid)->t_fi_inst[cid].t_values[nid] = 0.0;
					//cout<<"all okay"<<endl;
				}
				F_mat[cid][fid] = false;
			}
		
			cout<<"Initialized delta, load, and latency values"<<endl;
			
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
						double tg = 0.0025;
						int index = cid * (total_size * 2) + nid * 2 + fid * (total_size);
						if((E_mat[cid][nid][fid] == 0)&&(cid >= N_Vehicles))
						{
							Simulator::Schedule(Seconds(tg*index),transmit_LLDP_downlink, cid, nid, fid);
						}
						
						else if((F_mat[cid][fid] == 0)&&(cid<N_Vehicles))
						{
							Simulator::Schedule(Seconds(tg*index),transmit_LLDP_downlink, cid, nid, fid);
						}			
						//(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = (L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid];//Already done.
				}
			}
			
	}
	for(uint32_t cid=0;cid<total_size;cid++)	
	{
		Simulator::Schedule(Seconds(0.05+(cid+1)*0.100), port_based_check_link_state, cid);
	}
	/*
	for(uint32_t fids=0;fids<2;fids++)//fid is used as the port ID.
	{
		for(uint32_t fidd=0;fidd<2;fidd++)//fid is used as the port ID.
		{
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					Simulator::Schedule(Seconds(0.743+0.0001*cid),remove_fabricated_duplicate_with_probability, cid, nid, 70);//port blocking mechanism.
				}
			}
		}
	}
	*/
	//Simulator::Schedule(Seconds(2.05), port_based_check_link_state);
	auto end = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(end - start).count();
	ns3_algorithm_complexity = duration;
	cout<<"Port-based defense finished at "<<Now().GetSeconds()<<"with duration "<<duration<<endl;
}


void normal_LLDP_check_link_state(uint32_t cid)
{
	cout<<"Running link verification after LLDP for normal LLDPs at "<<Simulator::Now().GetSeconds()<<endl;
	for(uint32_t fids=0;fids<2;fids++)//fid is used as the port ID.
	{
		for(uint32_t fidd=0;fidd<2;fidd++)//fid is used as the port ID.
		{
			//for(uint32_t cid=0;cid<total_size;cid++)	
			//{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
						//(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = (L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid];//Already done.	
						//remove_fabricated_duplicate_with_probability(cid, nid);//port blocking mechanism.
						//uint32_t dest_port_id = get_port((Link_at_controller_inst+(fid))->Link_f_inst[(0)].Link_fi_inst[cid].Link_values[nid], (Link_at_controller_inst+(fid))->Link_f_inst[(1)].Link_fi_inst[cid].Link_values[nid]);
						uint32_t dest_port_id = fidd;	
							
						if((Link_at_controller_inst+fids)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid] == 1.0)
						{
							B_mat[cid][nid][fids][dest_port_id] = 1;
							uint32_t controller_ID = node_controller_ID[cid];
							if(vanishing_malicious_controllers[controller_ID])
							{
								bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
								if (attacking_state)
								{
									B_mat[cid][nid][fids][dest_port_id] = 0;
								}
							}
						}
						
						else
						{
							
							B_mat[cid][nid][fids][dest_port_id] = 0;
							uint32_t controller_ID = node_controller_ID[cid];
							if(fabrication_malicious_controllers[controller_ID])
							{
								bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
								if (attacking_state)
								{
									B_mat[cid][nid][fids][dest_port_id] = 1;
								}
							}
							if(MIM_malicious_controllers[controller_ID])
							{
								bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
								if (attacking_state)
								{
									if(fids == dest_port_id)
									{
										B_mat[cid][nid][fids][dest_port_id] = 1;
									}
								}
							}
						}
					}
				}
			//}
		}
	if (cid < dsrc_Nodes.GetN()) {
	for(uint32_t j=0; j<total_size;j++)
	{
		 double t= 0.10;
		 int o = 31*cid+7*j;
		 srand(o);
		 double rand_delay1 = 0.000001*(rand()%100);
		 int p = 27*cid+11*j;
		 srand(p);
		 double rand_delay2 = 0.000001*(rand()%100);
		 double delta = 0.005; // base spacing
		 double delay1 = t + delta * (j) + rand_delay1;
		 double delay2 = t + delta * (j) + rand_delay2;
		 Simulator::Schedule (Seconds (delay1), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 0);
		 Simulator::Schedule (Seconds (delay2), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 1);
	}
	} // end dsrc guard
}


void run_normal_LLDP()
{
	auto start = high_resolution_clock::now();
	cout<<"Normal LLDP started at "<<Now().GetSeconds()<<endl;
	dsrc_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	ethernet_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	//blacklist_nodes = get_blacklist_from_blockchain();
	for(uint32_t fid=0;fid<2;fid++)//fid is used as the port ID.
	{
		uint32_t f_size = (demanding_flow_struct_controller_inst+fid)->f_size;
		//uint32_t f_source = (demanding_flow_struct_controller_inst+fid)->source;
		//uint32_t f_destination = (demanding_flow_struct_controller_inst+fid)->destination;
		uint32_t f_psize = (demanding_flow_struct_controller_inst+fid)->p_size;
		uint32_t f_qos = (demanding_flow_struct_controller_inst+fid)->qos;
		cout<<f_qos<<endl;
		cout<<f_size<<f_qos<<f_psize<<endl;

			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[0].Link_fi_inst[cid].Link_values[nid] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[1].Link_fi_inst[cid].Link_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
				}
			}
			//cout<<"flow id "<<fid<<"is empty"<<endl;

			cout<<"Running normal LLDP based for port "<<fid<<endl;
			cout<<"Initializing values"<<endl;
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				bool F_state;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					
					(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]); //Omega represents state S
					(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]);//Q
					
					//cout<<"cid"<<cid<<"nid"<<nid<<"fid"<<fid<<endl;
					E_mat[cid][nid][fid] = 0.0;
					F_state = bool(abs(I[cid][nid])) || F_state;
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
					(t_at_controller_inst+fid)->t_fi_inst[cid].t_values[nid] = 0.0;
				}
				F_mat[cid][fid] = false;
			}
		
			//cout<<"Initialized delta, load, and latency values"<<endl;
			
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
						double tg = 0.0025;
						int index = cid * (total_size * 2) + nid * 2 + fid * (total_size);
						
						if((E_mat[cid][nid][fid] == 0)&&(cid >= N_Vehicles))
						{
							cout<<"Scheduling LLDP downlink for source "<<cid<<"destination "<<nid<<"port "<<fid<<endl;
							Simulator::Schedule(Seconds(tg*index),transmit_LLDP_downlink, cid, nid, fid);
						}
						
						else if((F_mat[cid][fid] == 0)&&(cid<N_Vehicles))
						{
							cout<<"Scheduling LLDP downlink for source "<<cid<<"destination "<<nid<<"port "<<fid<<endl;
							Simulator::Schedule(Seconds(tg*index),transmit_LLDP_downlink, cid, nid, fid);
						}
						
						
						//(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = (L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid];//Already done.
					 	
					 	//remove_fabricated_duplicate_with_probability(cid, nid);//port blocking mechanism.
					 	cout<<tg<<index<<endl;
				}
				
			}	
	}
	for(uint32_t cid=0;cid<total_size;cid++)	
	{
		Simulator::Schedule(Seconds(0.05+(cid+1)*0.10), normal_LLDP_check_link_state, cid);
	}
	//Simulator::Schedule(Seconds(0.000),transmit_LLDP_downlink, 0, 1, 0);
	//Simulator::Schedule(Seconds(0.005),transmit_LLDP_downlink, 1, 0, 0);
	//Simulator::Schedule(Seconds(2.05), normal_LLDP_check_link_state);
	auto end = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(end - start).count();
	ns3_algorithm_complexity = duration;
	cout<<"Normal LLDP finished at "<<Now().GetSeconds()<<"with complexity "<<duration<<endl;
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


void finalize_HELLO()
{
	cout<<"Finalizing HELLO packets"<<endl;
	for(uint32_t fid=0;fid<2;fid++)//fid is used as the port ID.
	{
		for(uint32_t dest_port_id=0;dest_port_id<2;dest_port_id++)	
		{
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{		
					cout<<"nid is "<<nid<<"cid is"<<cid<<"fid is"<<fid<<endl;	 	
					if((Link_at_controller_inst+fid)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid] == 1.0)
					{
						B_mat[cid][nid][fid][dest_port_id] = 1;
						if(vanishing_malicious_nodes[cid])
						{
							bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
							if (attacking_state)
							{
								B_mat[cid][nid][fid][dest_port_id] = 0;
							}
						}
					}
					
					else
					{
						
						B_mat[cid][nid][fid][dest_port_id] = 0;
						if(fabrication_malicious_nodes[cid])
						{
							bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
							if (attacking_state)
							{
								B_mat[cid][nid][fid][dest_port_id] = 1;
							}
						}
						if(MIM_malicious_nodes[cid])
						{
							bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
							if (attacking_state)
							{
								B_mat[cid][nid][fid][fid] = 1;
							}
						}
					}
				}
			}
		}
	}
}

void set_dsrc_initial_timestamp()
{
	dsrc_initial_timestamp = Simulator::Now().GetSeconds();
}

void run_HELLO()
{
	auto start = high_resolution_clock::now();
	HELLO_initial_timestamp = Simulator::Now().GetSeconds();
	//blacklist_nodes = get_blacklist_from_blockchain();
	Simulator::Schedule (Seconds (0), set_dsrc_initial_timestamp);
	for(uint32_t fid=0;fid<2;fid++)//fid is used as the port ID.
	{
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					B_mat[nid][cid][fid][0] = 0.0; 
					B_mat[nid][cid][fid][1] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[0].Link_fi_inst[cid].Link_values[nid] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[1].Link_fi_inst[cid].Link_values[nid] = 0.0;
				}
			}
	}
	
	  cout<<"HELLO packet discovery started at "<<Now().GetSeconds()<<endl;
	  double t=0.00;
	  //DSRC nodes data broadcast 
	  //Go over all the wifi devices
	  
	  for (uint32_t i=0; i<wifidevices.GetN() ; i++)
	  {     
		if (i >= dsrc_Nodes.GetN()) { continue; }
		 Simulator::Schedule (Seconds (t+0.0025*i), centralized_dsrc_data_broadcast, wifidevices.Get (i), dsrc_Nodes.Get(i), i, 0);
	  }
	  
	   for (uint32_t i=0; i<wifidevices_172.GetN() ; i++)
	  {     
		if (i >= dsrc_Nodes.GetN()) { continue; }
		 Simulator::Schedule (Seconds (t+0.0025*i), centralized_dsrc_data_broadcast, wifidevices_172.Get (i), dsrc_Nodes.Get(i), i, 1);
	  }
	  
	  //Simulator::Schedule (Seconds (t), set_dsrc_initial_timestamp);	
	  Simulator::Schedule (Seconds (0.60), finalize_HELLO);
	  auto end = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(end - start).count();
	ns3_algorithm_complexity = duration;

	cout<<"HELLO discovery finished at "<<Now().GetSeconds()<<"with complexity "<<duration<<endl;
}

void block_port(uint32_t cid, uint32_t nid, uint32_t pid)
{
	blocked_port_state[cid][nid][pid] =  true;	
}

void link_guard_check_link_state(uint32_t cid)
{
	for(uint32_t fidd=0;fidd<2;fidd++)
	{
		for(uint32_t fids=0;fids<2;fids++)//fid is used as the port ID.
		{
			//for(uint32_t cid=0;cid<total_size;cid++)	
			//{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{		
				//(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = (L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid];//Already done.
					 	
					 	cout<<"Link guard checking link state for flow"<<fidd<<"nid"<<nid<<"cid"<<cid<<endl;
					 	remove_fabricated_duplicate_with_probability(cid, nid, 85);//port blocking mechanism.
						//uint32_t dest_port_id = get_port((Link_at_controller_inst+(fid))->Link_f_inst[(0)].Link_fi_inst[cid].Link_values[nid], (Link_at_controller_inst+(fid))->Link_f_inst[(1)].Link_fi_inst[cid].Link_values[nid]);
						uint32_t dest_port_id = fids;
						
					    bool fab_success_rate = GetBooleanWithProbability(50, cid);
					    bool flood_success_rate = GetBooleanWithProbability(50, nid);
						if((fab_success_rate)&&(((Link_at_controller_inst+fidd)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid]) != ((Link_at_controller_inst+dest_port_id)->Link_f_inst[fidd].Link_fi_inst[nid].Link_values[cid])))
						{
								cout<<"Detected fabrication "<<endl;
								cout<<"verifying link as false"<<(Link_at_controller_inst+fidd)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid]<<endl;
								B_mat[cid][nid][fidd][dest_port_id] = 0;
						
						}
						else
						{	
							
							if((flood_success_rate)&&(LLDP_flood_counter_rec[cid][nid][fidd][dest_port_id] > 5))
							{
									cout<<"Detected flooding"<<endl;
									cout<<"verifying link as false"<<(Link_at_controller_inst+fidd)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid]<<endl;
									B_mat[cid][nid][fidd][dest_port_id] = 0;
									block_port(cid, nid, fidd);
							}
							else
							{
								if((Link_at_controller_inst+fidd)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid] == 1.0)
								{
									B_mat[cid][nid][fidd][dest_port_id] = 1;
									cout<<"verifying link as true"<<(Link_at_controller_inst+fidd)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid]<<endl;
									uint32_t controller_ID = node_controller_ID[cid];
									if(vanishing_malicious_controllers[controller_ID])
									{
										bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
										if (attacking_state)
										{
											B_mat[cid][nid][fidd][dest_port_id] = 0;
										}
									}
								}
								
								else
								{
									cout<<"verifying link as false "<<(Link_at_controller_inst+fidd)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid]<<endl;
									B_mat[cid][nid][fidd][dest_port_id] = 0;
									uint32_t controller_ID = node_controller_ID[cid];
									if(fabrication_malicious_controllers[controller_ID])
									{
										bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
										if (attacking_state)
										{
											B_mat[cid][nid][fidd][dest_port_id] = 1;
										}
									}
									if(MIM_malicious_controllers[controller_ID])
									{
										bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
										if (attacking_state)
										{
											if(fidd == dest_port_id)
											{
												B_mat[cid][nid][fidd][dest_port_id] = 1;
											}
										}
									}
								}
							}
						}
					}
				}
			//}
	}
	if (cid < dsrc_Nodes.GetN()) {
	for(uint32_t j=0; j<total_size;j++)
	{
		 double t= 0.10;
		 int o = 31*cid+7*j;
		 srand(o);
		 double rand_delay1 = 0.000001*(rand()%100);
		 int p = 27*cid+11*j;
		 srand(p);
		 double rand_delay2 = 0.000001*(rand()%100);
		 double delta = 0.005; // base spacing
		 double delay1 = t + delta * (j) + rand_delay1;
		 double delay2 = t + delta * (j) + rand_delay2;
		 Simulator::Schedule (Seconds (delay1), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 0);
		 Simulator::Schedule (Seconds (delay2), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 1);
	}
	} // end dsrc guard
}


void run_link_guard()
{
	auto start = high_resolution_clock::now();
	reset_flood_counter();
	dsrc_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	ethernet_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	cout<<"Link guard started at "<<Now().GetSeconds()<<endl;
	//blacklist_nodes = get_blacklist_from_blockchain();
	for(uint32_t fid=0;fid<2;fid++)//fid is used as the port ID.
	{
		uint32_t f_size = (demanding_flow_struct_controller_inst+fid)->f_size;
		//uint32_t f_source = (demanding_flow_struct_controller_inst+fid)->source;
		//uint32_t f_destination = (demanding_flow_struct_controller_inst+fid)->destination;
		uint32_t f_psize = (demanding_flow_struct_controller_inst+fid)->p_size;
		uint32_t f_qos = (demanding_flow_struct_controller_inst+fid)->qos;
		cout<<f_qos<<endl;
		cout<<f_size<<f_qos<<f_psize<<endl;

			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[0].Link_fi_inst[cid].Link_values[nid] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[1].Link_fi_inst[cid].Link_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
				}
			}
			//cout<<"flow id "<<fid<<"is empty"<<endl;

			cout<<"Running link guard"<<fid<<endl;
			cout<<"Initializing values"<<endl;
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				bool F_state;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					
					(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]); //Omega represents state S
					(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]);//Q
					
					
					E_mat[cid][nid][fid] = 0.0;
					F_state = bool(abs(I[cid][nid])) || F_state;
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
					(t_at_controller_inst+fid)->t_fi_inst[cid].t_values[nid] = 0.0;
				}
				F_mat[cid][fid] = false;
			}
		
			//cout<<"Initialized delta, load, and latency values"<<endl;
			
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
						double tg = 0.0025;
						int index = cid * (total_size * 2) + nid * 2 + fid * (total_size) + F_mat[cid][fid]*(1);
						
						
						if((E_mat[cid][nid][fid] < 2)&&(cid >= N_Vehicles))
						{
							Simulator::Schedule(Seconds(tg*index),transmit_LLDP_downlink, cid, nid, fid);
							E_mat[cid][nid][fid] = E_mat[cid][nid][fid] + 1;
						}
						
						else if((F_mat[cid][fid] < 2)&&(cid<N_Vehicles))
						{
							Simulator::Schedule(Seconds(tg*index),transmit_LLDP_downlink, cid, nid, fid);
							F_mat[cid][fid] = F_mat[cid][fid] + 1;
						}
				}
				
			}
	}
	for(uint32_t cid=0;cid<total_size;cid++)	
	{
		Simulator::Schedule(Seconds(0.05+(cid+1)*0.100 + 0.0015*1), link_guard_check_link_state, cid);
	}				
		
	/*
	for(uint32_t fids=0;fids<2;fids++)//fid is used as the port ID.
	{
		for(uint32_t fidd=0;fidd<2;fidd++)//fid is used as the port ID.
		{
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					Simulator::Schedule(Seconds(0.743+0.0001*cid),remove_fabricated_duplicate_with_probability, cid, nid, 85);//port blocking mechanism.
				}
			}
		}
	}
	*/
	//Simulator::Schedule(Seconds(2.05), link_guard_check_link_state);
	auto end = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(end - start).count();
	ns3_algorithm_complexity = duration;
	cout<<"Link guard finished at "<<Now().GetSeconds()<<"with complexity "<<duration<<endl;
}


void pure_crypto_check_link_state(uint32_t	cid)
{
	for(uint32_t fidd=0;fidd<2;fidd++)
	{
		for(uint32_t fids=0;fids<2;fids++)//fid is used as the port ID.
		{
			//for(uint32_t cid=0;cid<total_size;cid++)	
			//{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
						//(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = (L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid];//Already done.
					 	//remove_fabricated_duplicate_with_probability(cid, nid);//port blocking mechanism.
						uint32_t dest_port_id = fids;
					 	
						if((Link_at_controller_inst+fidd)->Link_f_inst[dest_port_id].Link_fi_inst[cid].Link_values[nid] == 1.0)
						{
							B_mat[cid][nid][fidd][dest_port_id] = 1;
							uint32_t controller_ID = node_controller_ID[cid];
							if(vanishing_malicious_controllers[controller_ID])
							{
								bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
								if (attacking_state)
								{
									B_mat[cid][nid][fidd][dest_port_id] = 0;
								}
							}
						}
						
						else
						{
							
							B_mat[cid][nid][fidd][dest_port_id] = 0;
							uint32_t controller_ID = node_controller_ID[cid];
							if(fabrication_malicious_controllers[controller_ID])
							{
								bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
								if (attacking_state)
								{
									B_mat[cid][nid][fidd][dest_port_id] = 1;
								}
							}
							if(MIM_malicious_controllers[controller_ID])
							{
								bool attacking_state = GetBooleanWithProbability(attack_percentage, cid);
								if (attacking_state)
								{
									if(fidd == dest_port_id)
									{
										B_mat[cid][nid][fidd][dest_port_id] = 1;
									}
								}
							}
						}
					}
				//}
			}
		}
	if (cid < dsrc_Nodes.GetN()) {
	for(uint32_t j=0; j<total_size;j++)
	{
		 double t= 0.10;
		 int o = 31*cid+7*j;
		 srand(o);
		 double rand_delay1 = 0.000001*(rand()%100);
		 int p = 27*cid+11*j;
		 srand(p);
		 double rand_delay2 = 0.000001*(rand()%100);
		 double delta = 0.005; // base spacing
		 double delay1 = t + delta * (j) + rand_delay1;
		 double delay2 = t + delta * (j) + rand_delay2;
		 Simulator::Schedule (Seconds (delay1), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 0);
		 Simulator::Schedule (Seconds (delay2), centralized_dsrc_data_unicast, dsrc_Nodes.Get(cid), cid, j, 1);
	}	
	} // end dsrc guard
		
}



void run_pure_crypto()
{
	auto start = high_resolution_clock::now();
	dsrc_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	ethernet_LLDP_initial_timestamp = Simulator::Now().GetSeconds();
	cout<<"Pure_crypto started at "<<Now().GetSeconds()<<endl;
	//blacklist_nodes = get_blacklist_from_blockchain();
	for(uint32_t fid=0;fid<2;fid++)//fid is used as the port ID.
	{
		uint32_t f_size = (demanding_flow_struct_controller_inst+fid)->f_size;
		//uint32_t f_source = (demanding_flow_struct_controller_inst+fid)->source;
		//uint32_t f_destination = (demanding_flow_struct_controller_inst+fid)->destination;
		uint32_t f_psize = (demanding_flow_struct_controller_inst+fid)->p_size;
		uint32_t f_qos = (demanding_flow_struct_controller_inst+fid)->qos;
		cout<<f_qos<<endl;
		cout<<f_size<<f_qos<<f_psize<<endl;

			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[0].Link_fi_inst[cid].Link_values[nid] = 0.0;
					(Link_at_controller_inst+fid)->Link_f_inst[1].Link_fi_inst[cid].Link_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
				}
			}
			//cout<<"flow id "<<fid<<"is empty"<<endl;

			cout<<"Pure crypto LLDP based"<<fid<<endl;
			cout<<"Initializing values"<<endl;
			for(uint32_t cid=0;cid<total_size;cid++)	
			{
				bool F_state;
				for(uint32_t nid=0;nid<total_size;nid++)	
				{
					
					(Omega_at_controller_inst+fid)->Omega_fi_inst[cid].Omega_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]); //Omega represents state S
					(Q_at_controller_inst+fid)->Q_fi_inst[cid].Q_values[nid] = XOR(B_mat[cid][nid][fid][0], B_mat[cid][nid][fid][1]);//Q
					
					
					E_mat[cid][nid][fid] = 0;
					F_state = bool(abs(I[cid][nid])) || F_state;
					(delta_at_controller_inst+fid)->delta_fi_inst[cid].delta_values[nid] = 0.0;
					(L_at_controller_inst+fid)->L_fi_inst[cid].L_values[nid] = 0.0;
					(T_at_controller_inst+fid)->T_fi_inst[cid].T_values[nid] = 0.0;
					(t_at_controller_inst+fid)->t_fi_inst[cid].t_values[nid] = 0.0;
				}
				F_mat[cid][fid] = false;
			}
		
			//cout<<"Initialized delta, load, and latency values"<<endl;
			
			for(uint32_t cid=0;cid<total_size;cid++)	
			{	
				for(uint32_t nid=0;nid<total_size;nid++)	
				{	
						double tg = 0.0025;
						int index = cid * (total_size * 2) + nid * 2 + fid * (total_size);
						
						if((E_mat[cid][nid][fid] == 0)&&(cid >= N_Vehicles))
						{
							Simulator::Schedule(Seconds(tg*index),transmit_LLDP_downlink, cid, nid, fid);
						}
						
						else if((F_mat[cid][fid] == 0)&&(cid<N_Vehicles))
						{
							Simulator::Schedule(Seconds(tg*index),transmit_LLDP_downlink, cid, nid, fid);
						}
				}
				
			}
	}
	for(uint32_t cid=0;cid<total_size;cid++)	
	{
		Simulator::Schedule(Seconds(0.05+(cid+1)*(0.100)), pure_crypto_check_link_state, cid);
	}
	//Simulator::Schedule(Seconds(2.05), pure_crypto_check_link_state);
	auto end = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(end - start).count();
	ns3_algorithm_complexity = duration;
	cout<<"Pure crypto LLDP finished at "<<Now().GetSeconds()<<"with complexity "<<duration<<endl;
}




void  run_optimization_link_lifetime()
{
	cout<<"link lifetime optimization beginning at "<<Now().GetSeconds()<<endl;
	write_csv_status_lifetime();//write status data to csv
	Simulator::Schedule(Seconds(0.000050), optimize_link_lifetime);
	Simulator::Schedule(Seconds(0.000100), read_lifetime_from_csv);
}


void  run_optimization_subsequent()
{
	for (uint32_t i=2;i<(total_size + 2);i++)
	{
		refresh_controller_data(con_data_inst+i);
	}
	double new_entropy = calculate_network_entropy();
	double entropy_change = abs(last_optimized_entropy - new_entropy);
	cout<<"entropy_change is "<<entropy_change<<endl;
	if(entropy_change > entropy_threshold)
	{
		write_csv();//write data to csv
		cout<<"Entropy change is high. optimizing"<<endl;
		Simulator::Schedule(Seconds(0.002), optimize_subsequent);
		/*
		if (N_Vehicles < 50)
		{
			Simulator::Schedule(Seconds(0.015), transmit_solution);
		}
		*/
		//else
		//{
		Simulator::Schedule(Seconds(0.042), transmit_solution);
			
		//}
		last_optimized_entropy = new_entropy;
		if (paper == 0)
		{
			calculate_average_cost_with_solution();
			calculate_average_channel_utilization_with_solution();
			calculate_average_latency();
			Simulator::Schedule(Seconds(0.100), calculate_packet_delivery_ratio);
			times_checked++;
			times_optimized++;
			calculate_percentage();
			Simulator::Schedule(Seconds(0.105),write_csv_results);
			data_gathering_cycle_number++;
		}
		
		

	}
	else
	{
		cout<<"omitting optimization as entropy change is low"<<endl;
		if (paper == 0)
		{
			calculate_average_cost_without_solution();
			calculate_average_channel_utilization();
			calculate_average_latency();
			Simulator::Schedule(Seconds(0.100), calculate_packet_delivery_ratio);
			times_checked++;
			calculate_percentage();
			Simulator::Schedule(Seconds(0.105),write_csv_results);
			data_gathering_cycle_number++;
		}
			
	}
}




//vector<double> node_distance[9];



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

void call_blockchain()
{
	int ret1 = system("cd /home/nilmantha/hyperledger_fabric/fabric-samples/first-network && ./byfn.sh -m down");
    if (ret1 != 0) {
        std::cerr << "Failed to stop Hyperledger Fabric network" << std::endl;
    }
	
	int ret = system("cd /home/nilmantha/hyperledger_fabric/fabric-samples/first-network && ./byfn.sh -m up -l node");
    if (ret != 0) {
        std::cerr << "Failed to start Hyperledger Fabric network" << std::endl;
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












void call_testBC()
{
/*
	cout<<"Calling blockchain"<<endl;
	const char* fabric_dir = "/home/nilmantha/hyperledger_fabric/fabric-samples/fabric-rest-api";	
    	std::string app_conn = "bash -c 'cd " + std::string(fabric_dir) + " && node app.js'";
  	system(app_conn.c_str());
  	
  	std::string update_cmd = "bash -c 'cd " + std::string(fabric_dir) + " && curl -X POST \"http://localhost:3000/invoke/A/B/50?user=peer1@org1\'";
  	system(update_cmd.c_str());

curl -X POST "http://localhost:3000/invoke/putauthStates?user=peer1@org1" \
  -H "Content-Type: application/json" \
  -d '{
    "args": [
      "Node1",
      "Node2",
      "EncryptedReputation",
      "EncryptedLocation",
      "{\"SigCur\":\"sigCurValue\",\"SigOth\":\"sigOthValue\"}",
      "sigZKPValue",
      "dsPKValue",
      "true"
    ]
  }'
  
  curl "http://localhost:3000/query/getauthStates?user=peer1@org1&controllerId=Controller1&curNodeId=Node1&othNodeId=Node2&reqId=Controller1"
  
  curl "http://localhost:3000/query/verifyAuthConditions?user=peer1@org1&repSta=true&locSta=true&idSta=true&timeExpired=false&hmacMatch=true&zkpVerified=true"

*/
  
}

void predict_DNN_link_lifetime()
{
	cout<<"predicting link lifetimes"<<endl;
	std::string filename = NS3_ROOT "/analytics/data/DNN_link_stability.py";
    	std::string command = "python3 ";
    	command += filename;
    	system(command.c_str());
}

void predict_DNN_delay()
{
	cout<<"predicting delay"<<endl;
	std::string filename = NS3_ROOT "/analytics/data/DNN_delay.py";
    	std::string command = "python3 ";
    	command += filename;
    	system(command.c_str());
}

void  run_DNN_link_lifetime()
{
	write_csv_status();//write status data to csv
	Simulator::Schedule(Seconds(0.005), predict_DNN_link_lifetime);
}

void  run_DNN_delay()
{
	write_csv_delay_prediction();//write delay data to csv
	Simulator::Schedule(Seconds(0.005), predict_DNN_delay);
}




void convert_delay()
{
	cout<<"converting delay"<<endl;
	for(uint32_t i=0;i<(2*total_size);i=i+2)
	{
		vector<double> x_dsrc;
		vector<double> x_ethernet;
		for (uint32_t j = 0;j < total_size;j++)
		{
			double dij_dsrc;
			double dij_ethernet;
			if (i == 2*j)
			{
				dij_dsrc = 0.0;
				dij_ethernet = 0.0;
			}
			else
			{
				//dij_dsrc = delay_vector[i+1] + 4*(adjacencyMatrix[i/2][j]);
				//dij_ethernet = delay_vector[i] + 1*(adjacencyMatrix[i/2][j]);
				dij_dsrc =  0.01*delay_vector[i+1] + adjacencyMatrix[i/2][j];
				dij_ethernet = 0.01*delay_vector[i] + adjacencyMatrix[i/2][j];
			}
			x_dsrc.push_back(dij_dsrc);
			x_ethernet.push_back(dij_ethernet);
		}
		delay_dsrc[i/2] = x_dsrc;	
		delay_ethernet[i/2] = x_ethernet;
	}
	
	vector<vector<double>> new_adjacencyMatrix_dsrc;
	vector<vector<double>> new_adjacencyMatrix_ethernet;
	for(uint32_t i=0;i<total_size;i++)
	//for(uint32_t i=0;i<9;i++)
	{
		new_adjacencyMatrix_dsrc.push_back(delay_dsrc[i]);
		new_adjacencyMatrix_ethernet.push_back(delay_ethernet[i]);
	}
	delayMatrix_dsrc = new_adjacencyMatrix_dsrc;
	delayMatrix_ethernet = new_adjacencyMatrix_ethernet;
	cout<<"delay matrix converted"<<endl;
	
	
	for (uint32_t i=0;i<total_size;i++)
	//for (uint32_t i=0;i<9;i++)
	{
		
		for (uint32_t j=0;j<total_size;j++)
		//for (uint32_t j=0;j<9;j++)
		{
			cout<<"DSRC delay from source node"<<(i)<<"to node "<<(j)<<"is "<<delayMatrix_dsrc[i][j]<<endl;
			cout<<"Ethernet delay from source node"<<(i)<<"to node "<<(j)<<"is "<<delayMatrix_ethernet[i][j]<<endl;
		}
		
		
	}
	
	
		
	//cout<<"adjacency matrix size"<<adjacencyMatrix.size()<<endl;
}




void read_delay_from_csv()
{
    fstream fin;
    cout<<"reading delay from csv"<<endl;
    fin.open(NS3_ROOT "/analytics/data/delay_solution.csv", ios::in);
    vector<string> row;
    string line;
    string temp;
    int j=0;
    while (fin >> temp) 
    {
        row.clear();
        getline(fin, line);
        int n = line.length();
        char line_char[n+1];
        strcpy(line_char,line.c_str());
        //cout<<line<<endl;
        double dou_val;
        char * ptr;
        ptr = strtok(line_char,",");
        int i =0;
        while(ptr != NULL)
        {
        	stringstream ss;
		ss << ptr;
		//cout<<ptr<<endl;
		ss >> dou_val;
		if (i==0)
		{
			delay_vector[j] = dou_val;
			//cout<<j<<" value "<<dou_val<<endl;
		}
        	
        	ptr = strtok(NULL,",");   
        	i++;	
        }
        j++;
    }
    if (j == 0)
        cout << "Solution not found\n";
    convert_delay();
}


void generate_linklifetime_matrix()
{
	run_DNN_link_lifetime();
	Simulator::Schedule(Seconds(0.010), read_lifetime_from_csv);	
}

void generate_delay_matrix()
{
	compute_average_delays();
	run_DNN_delay();
	Simulator::Schedule(Seconds(0.010), read_delay_from_csv);	
}


void calculate_dijkstra_solution(uint32_t destination)
{
	dijkstra(adjacencyMatrix, destination);
}

void calculate_dijkstra_stable_solution(uint32_t destination)
{
	dijkstra_stable(destination);
}


void write_distance_metrics()
{
	fstream fout;
	string filename = NS3_ROOT "/analytics/results/maximum_distance_results.csv";
	fout.open(filename,ios::out|ios::app);
	
	fout << Simulator::Now().GetSeconds();
	for (uint32_t i=3;i<total_size+2; i=i+2)
	{
		fout << max_distance[i] << ", ";
	}
	fout << "\n";
	fout.close();

}

/*
void calculate_normalized_mobility()
{
	double sum = 0.0;
	for (uint32_t i=2; i<total_size+2 ;i++)
	{
		double xi,yi,zi;
		
		xi = data_at_manager_inst[i].velocity.x;
		yi = data_at_manager_inst[i].velocity.y;
		zi = data_at_manager_inst[i].velocity.z; 
		
		sum = sum + sqrt ((xi*xi) + (yi*yi) + (zi*zi));
	}
	
	normalized_mobility = sum/(total_size*maxspeed*(5.0/18.0));
	cout<<"normalized mobility: "<<normalized_mobility<<endl;	
}

void calculate_network_contention()
{
	network_contention = last_optimized_entropy*(1.0 - normalized_mobility);
	cout<<"network contention: "<<network_contention<<endl;
}
*/


void calculate_centralized_metrics_routing()
{
	calculate_average_cost_without_solution();
	calculate_average_channel_utilization();
	calculate_average_latency_hybrid();
	calculate_packet_delivery_ratio_dsrc();
	write_csv_results();
	data_gathering_cycle_number++;
}

void calculate_hybrid_metrics_routing()
{
	calculate_average_cost_without_solution();
	calculate_average_channel_utilization();
	calculate_average_latency_hybrid();
	calculate_packet_delivery_ratio_dsrc_hybrid();
	write_csv_results();
	data_gathering_cycle_number++;
}


void calculate_centralized_metrics()
{

	calculate_average_cost_without_solution();
	calculate_average_channel_utilization();
	calculate_average_latency();
	calculate_packet_delivery_ratio();
	write_csv_results();
	data_gathering_cycle_number++;
}

void calculate_distributed_metrics()
{
	calculate_average_cost_without_solution_dsrc();
	calculate_average_channel_utilization();
	calculate_average_latency_dsrc();
	calculate_packet_delivery_ratio_dsrc();
	write_csv_results();
	data_gathering_cycle_number++;
}

void calculate_aodv_metrics()
{
	calculate_average_cost_without_solution_dsrc();
	calculate_average_channel_utilization();
	calculate_aodv_latency();
	if (experiment_number !=11)
	{
		calculate_aodv_packet_delivery_ratio();
	}
	write_csv_results();
	data_gathering_cycle_number++;
}

void run_optimization_first_time()
{
	write_csv();//write data to csv
	Simulator::Schedule(Seconds(0.002), optimize_first_time);
	last_optimized_entropy = calculate_network_entropy();
	cout<<"first ever entropy value "<<last_optimized_entropy<<endl;
	Simulator::Schedule(Seconds(0.060), transmit_solution);
	calculate_average_cost_with_solution();
	calculate_average_channel_utilization_with_solution();
	if (paper == 0)
	{
		calculate_average_latency();
		Simulator::Schedule(Seconds(0.050), calculate_packet_delivery_ratio);
		times_checked++;
		times_optimized++;
		calculate_percentage();
		Simulator::Schedule(Seconds(0.055),write_csv_results);
	}
	data_gathering_cycle_number++;
}

void Enqueue (std::string context, Ptr <const Packet> pkt)
{
	cout<<"A packet enqued"<<endl;
}

void Dequeue (std::string context, Ptr <const Packet> pkt)
{
	cout<<"A packet dequed"<<endl;
}

void MacTx (std::string context, Ptr <const Packet> pkt)
{
	//cout<<"This is MacTx"<<endl;
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

struct transmit_opportunity
{	
	Time last_set_timestamp[185][total_size];
	bool busy[185][total_size];
	uint32_t pending_packets[185][total_size];
};

struct transmit_opportunity txop_inst[2*flows];

struct custom_struct
{
	uint32_t p_size;
	uint32_t channel;
	uint32_t CW;
};

void updateTxop(uint32_t fid, uint32_t nodeid, uint32_t receiver_id, uint32_t pending_packets, bool busy, struct custom_struct arguments)
{
	uint32_t zeta = 1;
	double tg = compute_individual_link_delay(0, arguments.CW, 1, flow_packet_size, 1, zeta);
	for(uint32_t f=0;f<2*flows;f++)
	{ 
		//update current node status
		if(busy == true)
		{
			txop_inst[f].busy[arguments.channel][nodeid] = busy;
			txop_inst[f].last_set_timestamp[arguments.channel][nodeid] = Seconds(Now().GetSeconds());
			//cout<<"Set node "<<nodeid<<"as busy at "<<Now().GetSeconds()<<endl;
		}
		else
		{
			Time diff = Seconds(Now().GetSeconds())-txop_inst[f].last_set_timestamp[arguments.channel][nodeid];
			if(diff > Seconds(tg))
			{
				txop_inst[f].busy[arguments.channel][nodeid] = busy;
				//cout<<"Set node "<<nodeid<<"as free at "<<Now().GetSeconds()<<endl;
			}
			else
			{
				//cout<<"Node "<<nodeid<<"remains busy "<<Now().GetSeconds()<<endl;
			}
		}
		//update other node status
		for(uint32_t i=0;i<total_size;i++)
		{
			if((linklifetimeMatrix_dsrc[nodeid][i]) > 0.0)
			{
				if(busy == true)
				{
					txop_inst[f].busy[arguments.channel][i] = busy;
					txop_inst[f].last_set_timestamp[arguments.channel][i] = Seconds(Now().GetSeconds());
					//cout<<"Set node "<<i<<"as busy at "<<Now().GetSeconds()<<endl;
					for(uint32_t j=0;j<total_size;j++)
					{
						if((linklifetimeMatrix_dsrc[i][j]) > 0.0)
						{
							txop_inst[f].busy[arguments.channel][j] = busy;
							txop_inst[f].last_set_timestamp[arguments.channel][j] = Seconds(Now().GetSeconds());
							//cout<<"Set node "<<j<<"as busy at "<<Now().GetSeconds()<<endl;
						}
					}
				}
				else
				{
					Time diff = Seconds(Now().GetSeconds())-txop_inst[f].last_set_timestamp[arguments.channel][i];
					if(diff > Seconds(tg))
					{
						txop_inst[f].busy[arguments.channel][i] = busy;
						//cout<<"Set node "<<i<<"as free at "<<Now().GetSeconds()<<endl;
					}
					else
					{
						//cout<<"Node "<<i<<"remains busy "<<Now().GetSeconds()<<endl;
					}
					
					for(uint32_t j=0;j<total_size;j++)
					{
						if((linklifetimeMatrix_dsrc[i][j]) > 0.0)
						{
							Time diff_inner = Seconds(Now().GetSeconds())-txop_inst[f].last_set_timestamp[arguments.channel][j];
							if(diff_inner > Seconds(tg))
							{
								txop_inst[f].busy[arguments.channel][j] = busy;
								//cout<<"Set node "<<j<<"as free at "<<Now().GetSeconds()<<endl;
							}
							else
							{
								//cout<<"Node "<<j<<"remains busy "<<Now().GetSeconds()<<endl;
							}
						}
					}
					
				}
			}
			
			
			if((linklifetimeMatrix_dsrc[receiver_id][i]) > 0.0)
			{
				if(busy == true)
				{
					txop_inst[f].busy[arguments.channel][i] = busy;
					txop_inst[f].last_set_timestamp[arguments.channel][i] = Seconds(Now().GetSeconds());
					//cout<<"Set node "<<i<<"as busy at "<<Now().GetSeconds()<<endl;
					for(uint32_t j=0;j<total_size;j++)
					{
						if((linklifetimeMatrix_dsrc[i][j]) > 0.0)
						{
							txop_inst[f].busy[arguments.channel][j] = busy;
							txop_inst[f].last_set_timestamp[arguments.channel][j] = Seconds(Now().GetSeconds());
							//cout<<"Set node "<<j<<"as busy at "<<Now().GetSeconds()<<endl;
						}
					}
				}
				else
				{
					Time diff = Seconds(Now().GetSeconds())-txop_inst[f].last_set_timestamp[arguments.channel][i];
					if(diff > Seconds(tg))
					{
						txop_inst[f].busy[arguments.channel][i] = busy;
						//cout<<"Set node "<<i<<"as free at "<<Now().GetSeconds()<<endl;
					}
					else
					{
						//cout<<"Node "<<i<<"remains busy "<<Now().GetSeconds()<<endl;
					}
					
					for(uint32_t j=0;j<total_size;j++)
					{
						if((linklifetimeMatrix_dsrc[i][j]) > 0.0)
						{
							Time diff_inner = Seconds(Now().GetSeconds())-txop_inst[f].last_set_timestamp[arguments.channel][j];
							if(diff_inner > Seconds(tg))
							{
								txop_inst[f].busy[arguments.channel][j] = busy;
								//cout<<"Set node "<<j<<"as free at "<<Now().GetSeconds()<<endl;
							}
							else
							{
								//cout<<"Node "<<j<<"remains busy "<<Now().GetSeconds()<<endl;
							}
						}
					}
					
				}
			}
		}
	}
	txop_inst[fid].pending_packets[arguments.channel][nodeid] = pending_packets;
}

void updateTxop_self(uint32_t fid, uint32_t nodeid, uint32_t pending_packets, bool busy, struct custom_struct arguments)
{
	uint32_t zeta = 1;
	double tg = compute_individual_link_delay(0, arguments.CW, 1, flow_packet_size, 1, zeta);
	for(uint32_t f=0;f<2*flows;f++)
	{	
		if(busy == true)
		{
			txop_inst[f].busy[arguments.channel][nodeid] = busy;
			txop_inst[f].last_set_timestamp[arguments.channel][nodeid] = Seconds(Now().GetSeconds());
			//cout<<"Set node "<<nodeid<<"as busy at "<<Now().GetSeconds()<<endl;
		}
		else
		{
			Time diff = Seconds(Now().GetSeconds())-txop_inst[f].last_set_timestamp[arguments.channel][nodeid];
			if(diff > Seconds(tg))
			{
				txop_inst[f].busy[arguments.channel][nodeid] = busy;
				//cout<<"Set node "<<nodeid<<"as free at "<<Now().GetSeconds()<<endl;
			}
			else
			{
				//cout<<"Node "<<nodeid<<"remains busy "<<Now().GetSeconds()<<endl;
			}
		}
	}
	txop_inst[fid].pending_packets[arguments.channel][nodeid] = pending_packets;
}

uint32_t destination_counter[2*flows];
vector<vector<vector<tuple<double,uint32_t,uint32_t>>>> all_sorted_delta_next_hop_flow_size;

struct packet_delivery
{
	bool pending[185][Flow_size+2];
	bool delivery[185][Flow_size+2];
	uint32_t attempts[185][Flow_size+2];
};

struct pd_all
{
	struct packet_delivery pd_inst[total_size];
};

struct pd_all pd_all_inst[2*flows];

bool retransmitted [2*flows][total_size][Flow_size+2];
uint32_t s_flow_counter[2*flows][total_size][Flow_size+2];





void check_delivery_and_retransmit(uint32_t flow_id, uint32_t packet_id, uint32_t hop, uint32_t current_hop, Time originail_timestamp, struct custom_struct arguments)
{
	double diff = Now().GetSeconds() - flow_initiation_time;
	arguments.CW = pd_all_inst[flow_id].pd_inst[hop].attempts[arguments.channel][packet_id] + 2;
	if(diff > (0.90*data_transmission_period))
	{
		cout<<"Retransmission packet dropped for flow id "<<flow_id<<"packet ID: "<< packet_id<<endl;
		pd_all_inst[flow_id].pd_inst[current_hop].pending[arguments.channel][packet_id] = false;
	}
	else
	{
		srand(packet_id+hop+current_hop+Now().GetMicroSeconds());
		double rand_delay = 0.000010*(rand()%100);
		if(pd_all_inst[flow_id].pd_inst[hop].delivery[arguments.channel][packet_id] == true)
		{
			retransmitted[flow_id][hop][packet_id] = false;
			pd_all_inst[flow_id].pd_inst[current_hop].pending[arguments.channel][packet_id] = false;
			//cout<<"packet has been delivered. Retransmission success"<<" in flow ID "<<flow_id<<" packet ID "<<packet_id<<" from "<<current_hop<<" to next hop "<<hop<<"at time "<<Now().GetSeconds()<<endl;
			Simulator::Schedule (Seconds (0.0), updateTxop, flow_id, current_hop, hop, packet_id, false, arguments);
			//do nothing
		}
		else
		{
			
			bool pending_lower_ids = false;
			double pending_count = 0;
			for(uint32_t i=0;i<Flow_size+1;i++)
			{
				if (i< packet_id)
				{
					pending_lower_ids = pd_all_inst[flow_id].pd_inst[current_hop].pending[arguments.channel][i] | pending_lower_ids;
					pending_count++;
				}
			
			}
			if((pending_lower_ids==true) && (pending_count>0)&&(routing_algorithm != 1))
			{
				//cout<<"Retransmission pending for flow id "<<flow_id<<"packet ID: "<< packet_id<<endl;
				Simulator::Schedule (Seconds (0.0), updateTxop, flow_id, current_hop, hop, packet_id, false, arguments);
				Simulator::Schedule (Seconds (0.000100+rand_delay), check_delivery_and_retransmit, flow_id, packet_id, hop, current_hop, originail_timestamp, arguments);
			}		
			
			else
			{
				
				bool neighborhood_busy = false;
				for(uint32_t i=0;i<total_size;i++)
				{
					if((linklifetimeMatrix_dsrc[current_hop][i]) > 0.0)
					{
						neighborhood_busy = neighborhood_busy | txop_inst[flow_id].busy[arguments.channel][i];	
						for(uint32_t j=0;j<total_size;j++)
						{
							if((linklifetimeMatrix_dsrc[i][j]) > 0.0)
							{
								neighborhood_busy = neighborhood_busy | txop_inst[flow_id].busy[arguments.channel][j];
							}
						}
					}
				}
				if(neighborhood_busy == true)
				//if(txop_inst[flow_id].busy[hop] == true)
				{
					//cout<<"Retransmission attempt in flow ID "<<flow_id<<"packet ID "<< packet_id<<" at hop "<<current_hop<<". Receiver or its is neighborhood busy. Waiting for 100 Micro senconds until free"<<endl;
					Simulator::Schedule (Seconds (0.0), updateTxop, flow_id, current_hop, hop, packet_id, false,arguments);
					Simulator::Schedule (Seconds (0.000100+rand_delay), check_delivery_and_retransmit, flow_id, packet_id, hop, current_hop, originail_timestamp, arguments);
				}
				
				else
				{	
				
					if(pd_all_inst[flow_id].pd_inst[hop].attempts[arguments.channel][packet_id] < (B_max))
					{
						uint32_t zeta = 1;
						double tg = compute_individual_link_delay(0, pd_all_inst[flow_id].pd_inst[hop].attempts[arguments.channel][packet_id] + 2, 1, flow_packet_size, 1, zeta);
						//cout<<"retransmitting"<<endl;
						uint16_t protocolwave = 0x88dc;
						Ptr <NetDevice> current_nd = wifidevices.Get(current_hop);
					
						Ptr <Packet> packet_i = Create<Packet> (arguments.p_size-28);
						CustomDataUnicastTag_ModifiedRouting tag;
						tag.SetchannelId(arguments.channel);
						tag.SetflowId(flow_id);
						tag.SetpacketId(packet_id);
						tag.Setprevious_senderId(current_hop);
						tag.Setprevious_timestamp(MicroSeconds(Now().GetMicroSeconds()));
						tag.Setoriginal_timestamp(originail_timestamp);
						packet_i->AddPacketTag(tag);
						
						Ptr <NetDevice> destination_nd = wifidevices.Get(hop);

						Simulator::Schedule (Seconds (0.0), updateTxop, flow_id, current_hop, hop, packet_id, true, arguments);
						switch(arguments.channel)
						{
							case(172):
								current_nd = wifidevices_172.Get(current_hop);
								destination_nd = wifidevices_172.Get(hop);
								break;
							case(174):
								current_nd = wifidevices_174.Get(current_hop);
								destination_nd = wifidevices_174.Get(hop);
								break;
							case(176):
								current_nd = wifidevices_176.Get(current_hop);
								destination_nd = wifidevices_176.Get(hop);
								break;
							case(178):
								current_nd = wifidevices.Get(current_hop);
								destination_nd = wifidevices.Get(hop);
								break;
							case(180):
								current_nd = wifidevices_180.Get(current_hop);
								destination_nd = wifidevices_180.Get(hop);
								break;
							case(182):
								current_nd = wifidevices_182.Get(current_hop);
								destination_nd = wifidevices_182.Get(hop);
								break;
							case(184):
								current_nd = wifidevices_184.Get(current_hop);
								destination_nd = wifidevices_184.Get(hop);
								break;
							default:
								break;
						}
						Address addr = destination_nd->GetAddress();
						Mac48Address dest_address = Mac48Address::ConvertFrom(addr);
						Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (current_nd);
						Simulator::Schedule (Seconds(0.0), &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);
						//cout<<"This is flow ID "<<flow_id<<"Re-transmitting attempt of packet ID "<<packet_id<<" from "<<current_hop<<" to next hop "<<hop<<"at time "<<Now().GetSeconds()<<endl;
						Simulator::Schedule (Seconds (tg+0.000100+rand_delay), check_delivery_and_retransmit, flow_id, packet_id, hop, current_hop, originail_timestamp, arguments);
						//Simulator::Schedule (Seconds (tg), updateTxop, flow_id, current_hop, hop, packet_id, false,arguments.channel);
						sent_IDS[flow_id][current_hop][packet_id] = true;
						routing_packet_general_initial_timestamp[flow_id][current_hop][packet_id] = Now().GetSeconds();
						retransmitted[flow_id][hop][packet_id] = true;
						s_flow_counter[flow_id][hop][packet_id]++;
						pd_all_inst[flow_id].pd_inst[hop].attempts[arguments.channel][packet_id]++;
						
					//*subflow_counter = *subflow_counter + 1;
					//retransmit
					}
					else
					{
						cout<<"Retransmission packet dropped for flow id "<<flow_id<<"packet ID: "<< packet_id<<endl;
						pd_all_inst[flow_id].pd_inst[current_hop].pending[arguments.channel][packet_id] = false;
					
					}
				}
			}
		}
	}		
}

void decrypt_routing_packet(uint32_t node_index, uint32_t port, uint32_t destination)
{
	
	std::ostringstream oss6;
    oss6 << " is_controller=true create_security_manager_con=true netsize=1 "
		<< " sign_FALCON=false verify_FALCON=false generate_FALCON=false "
		<< " encrypt_ASCON=false decrypt_ASCON=false generate_ASCON_key=false "
		<< " node_id="<< node_index << " port_id="  << port << " other_node_id=" << destination << ""
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
		<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=true "
		<< " message=" << node_index+port+destination << " signature=" << "" << " msg_type=2 ";
   
	   std::string command_str6 = oss6.str();
	   Simulator::Schedule(Seconds(0), LDA_security, command_str6);

}

bool is_number(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

void proceed_routing_packet(uint32_t node_index, uint32_t port, uint32_t destination, uint32_t destination_node_id, uint32_t source, CustomDataUnicastTag_Routing tag_routing)
{
	    uint32_t decrypted_message = 2;
       
		if(routing_algorithm == 4)
		{
				cout<<"Tryring to decrypt node id"<<endl;
		   		std::string filename_sign_AES = NS3_ROOT "/analytics/data/security_nodepair_AES_data.csv";
				string decrypted_nid = read_other_other_item_from_csv(filename_sign_AES, std::to_string(node_index), std::to_string(destination_node_id-2), std::to_string(port), 4);
				cout<<"Decrypted string is "<<decrypted_nid<<endl;
				uint32_t dec_val = 18250; // Default value

				// Optional: clean up the string if it contains quotes or bytes literal like b'2'
				size_t start = decrypted_nid.find_first_of("0123456789");
				size_t end = decrypted_nid.find_last_of("0123456789");
				if (start != std::string::npos && end != std::string::npos)
					decrypted_nid = decrypted_nid.substr(start, end - start + 1);

				if (is_number(decrypted_nid)) {
					dec_val = static_cast<uint32_t>(std::stoul(decrypted_nid));
				} else {
					std::cout << "Warning: Non-numeric decrypted string, using default value 0.\n";
				}
				
				cout<<dec_val<<endl;
				decrypted_message = dec_val;//get decrypted messge from a script
		}
		
		else
		{
			srand(Simulator::Now().GetSeconds());
			decrypted_message = (port)+(destination-2)+(node_index);
		}
		uint32_t expected_message = (port)+(destination-2)+(node_index);
		cout<<"expected mesage is "<<expected_message<<endl;
		cout<<"decrypted message is "<<decrypted_message<<"port is "<<port<<endl;
		uint32_t	dest = destination_node_id;
	    cout<<"Receiver ID is "<<dest<<endl;
	    cout<<"Intended receiver ID is"<<destination<<endl;
		if (destination_node_id == destination)
		//cout<<"packet from "<<*source -2<<"with destination "<<destination -4<<"now at "<<destination_node_id -2<<endl;
		if (destination_node_id == destination)
		{
			cout<<"packet successfully delivered to destination node"<<destination_node_id - 2<<endl;
			dsrc_packet_final_timestamp[node_index+2] = Simulator::Now().GetSeconds();
			std::cout << "Received data unicasted packet from port"<<port<<" from sender"<< tag_routing.GetsenderId()<<"to node "<<destination_node_id -2 <<"of size "<<tag_routing.GetSerializedSize()<<" at position "<< *tag_routing.Getposition()<<"with velocity "<<*tag_routing.Getvelocity()<<"with acceleration "<<*tag_routing.Getacceleration()<<"packet timestamp "<< tag_routing.GetTimestamp()->GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tag_routing.GetTimestamp()->GetMicroSeconds()<<"us"<<std::endl;
			routing_packet_final_timestampLLDP[port][port][tag_routing.GetsenderId()][destination_node_id-2] = Simulator::Now().GetSeconds();
			dsrc_routing_packet_final_timestamp = Simulator::Now().GetSeconds();
		}
		
	
		if(destination_node_id != destination)
		{
			cout<<"Packet is not for the destination "<<endl;
			cout<<"source is "<<source-2<<"destination is"<<destination-2<<"port is "<<port<<endl;
			if(decrypted_message == (expected_message))
			{
				if(B_mat[source-2][destination-2][port][port] == 1)
				{
					intercepted_packet_final_timestampLLDP[port][port][source-2][destination-2][destination_node_id-2] = Simulator::Now().GetSeconds();
					cout<<"Secret is revealed and packet intercepted."<<endl;
				}
			}
		}
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



void Rx (std::string context, Ptr <const Packet> pkt, uint16_t channelFreqMhz,  WifiTxVector txVector,MpduInfo aMpdu, SignalNoiseDbm signalNoise, uint16_t staId)
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
	
	//bool routing_packet_present = false;
	//CustomDataUnicastTag_Routing tag_routing;
	//routing_packet_present = pkt->PeekPacketTag(tag_routing);

	int destination_node_id;
	//if (!((paper == 1) && (architecture == 1)))
	//{
		//if(!routing_packet_present)
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
			//cout<<"Converted destination node id is "<<destination_node_id;
			
			/*
			WifiMacHeader hdr;
			if (pkt->PeekHeader(hdr))
			{
				//std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2()<<"size: "<<hdr.GetSize() << std::endl;
				cout<<"wifi mac header "<<hdr.GetSize() <<endl;
			}
			
			WifiActionHeader hdr2;
			if (pkt->PeekHeader(hdr2))
			{
				//std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2()<<"size: "<<hdr.GetSize() << std::endl;
				cout<<"wifi action header "<<hdr2.GetSerializedSize() <<endl;
			}
			
			OfdmPpdu::LSigHeader hdr5;
			if (pkt->PeekHeader(hdr5))
			{
				//std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2()<<"size: "<<hdr.GetSize() << std::endl;
				cout<<"wifi ofdm header "<<hdr5.GetSerializedSize() <<endl;
			}
			
			GenericMacHeader hdr6;
			if (pkt->PeekHeader(hdr6))
			{
				//std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2()<<"size: "<<hdr.GetSize() << std::endl;
				cout<<"wifi generic mac header "<<hdr6.GetSerializedSize() <<endl;
			}
			
			TcpHeader hdr3;
			if (pkt->PeekHeader(hdr3))
			{
				//std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2()<<"size: "<<hdr.GetSize() << std::endl;
				cout<<"wifi tcp header "<<hdr3.GetSerializedSize() <<endl;
			}
			
			UdpHeader hdr4;
			if (pkt->PeekHeader(hdr4))
			{
				//std::cout << "\tDestination MAC : " << hdr.GetAddr1() << "\tSource MAC : " << hdr.GetAddr2()<<"size: "<<hdr.GetSize() << std::endl;
				cout<<"wifi udp header "<<hdr4.GetSerializedSize() <<endl;
			}
			*/
			
			//dsrc_final_timestamp = Simulator::Now().GetSeconds();
			//dsrc_total_received_packets = dsrc_total_received_packets + 1.0;
		//}
	//}
	
	
	CustomDataUnicastTag_Routing tag_routing2;

	if(pkt->PeekPacketTag(tag_routing2))
	{

        cout<<"Data unicast tag received "<<endl;
		uint32_t node_index = tag_routing2.GetsenderId();
		uint32_t destination = tag_routing2.GetdestinationId() + 2;
		uint32_t * source = tag_routing2.GetNodeId();
		uint32_t * port = tag_routing2.GetPortId();
		size_t length = 5;

        // Convert back to string
        std::string recovered(reinterpret_cast<const char*>(port), length);
		if(routing_algorithm == 4)
		{
		   Simulator::Schedule(Seconds(0.0000), decrypt_routing_packet, node_index, *port, destination_node_id-2);	
		}
		Simulator::Schedule(Seconds(0.0005), proceed_routing_packet, node_index, *port, destination, destination_node_id, *source, tag_routing2);	
	}
	
		

	
	CustomDataTag tag;
	if(pkt->PeekPacketTag(tag))
	{
		dsrc_final_timestamp = Simulator::Now().GetSeconds();
		if (experiment_number == 5)
		{
			max_distance[tag.GetNodeId()] = tag.GetPosition().x;
		}
		if (paper == 0)
		{
			dsrc_packet_final_timestamp[tag.GetNodeId()] = Simulator::Now().GetSeconds();
		}
		add_neighbor_info(neighbordata_inst+destination_node_id,tag.GetNodeId(), tag.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		Vector posi = tag.GetPosition();
		if(location_malicious_nodes[tag.GetNodeId()])
		{
			srand(Simulator::Now().GetSeconds()+double(tag.GetNodeId()));
			posi.x = posi.x + rand()%1000;
			posi.y = posi.y + rand()%1000;
		
		}
		
		uint8_t * HMAC1 = new uint8_t[64];
		HMAC1 = tag.GetHMAC1();
	    std::string HMAC1_str = BytesToHexString(HMAC1, 32);
		
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tag.GetHMAC1(), posi, tag.GetVelocity(), tag.GetAcceleration(), tag.GetNodeId(), empty_neighborset, 0, tag.GetPortId());
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tag.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tag.GetSerializedSize()<<" at position "<< tag.GetPosition()<<"with velocity "<<tag.GetVelocity()<<"with acceleration "<<tag.GetAcceleration()<<"packet timestamp "<< tag.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tag.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
		std::cout << "HMAC of location is "<< HMAC1_str<<endl;
		if(routing_algorithm == 5)
		{
			HELLO_final_timestamp = Simulator::Now().GetSeconds();
			(Link_at_controller_inst+(tag.GetPortId()))->Link_f_inst[(tag.GetPortId())].Link_fi_inst[tag.GetNodeId()-2].Link_values[destination_node_id-2] = 1.0; 
			B_mat[tag.GetNodeId()-2][destination_node_id-2][tag.GetPortId()][tag.GetPortId()] = 1.0; 
		}
		
		
	}
	
	/*
	CustomDataTag1 tagd1;
	if(pkt->PeekPacketTag(tagd1))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd1.GetNodeId(), tagd1.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd1.GetPosition(), tagd1.GetVelocity(), tagd1.GetAcceleration(), tagd1.GetNodeId(), tagd1.GetNeighborids(), 1);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd1.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd1.GetSerializedSize()<<" at position "<< tagd1.GetPosition()<<"with velocity "<<tagd1.GetVelocity()<<"with acceleration "<<tagd1.GetAcceleration()<<"packet timestamp "<< tagd1.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd1.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag2 tagd2;
	if(pkt->PeekPacketTag(tagd2))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd2.GetNodeId(), tagd2.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd2.GetPosition(), tagd2.GetVelocity(), tagd2.GetAcceleration(), tagd2.GetNodeId(), tagd2.GetNeighborids(), 2);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd2.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd2.GetSerializedSize()<<" at position "<< tagd2.GetPosition()<<"with velocity "<<tagd2.GetVelocity()<<"with acceleration "<<tagd2.GetAcceleration()<<"packet timestamp "<< tagd2.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd2.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag3 tagd3;
	if(pkt->PeekPacketTag(tagd3))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd3.GetNodeId(), tagd3.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd3.GetPosition(), tagd3.GetVelocity(), tagd3.GetAcceleration(), tagd3.GetNodeId(), tagd3.GetNeighborids(), 3);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd3.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd3.GetSerializedSize()<<" at position "<< tagd3.GetPosition()<<"with velocity "<<tagd3.GetVelocity()<<"with acceleration "<<tagd3.GetAcceleration()<<"packet timestamp "<< tagd3.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd3.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag4 tagd4;
	if(pkt->PeekPacketTag(tagd4))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd4.GetNodeId(), tagd4.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd4.GetPosition(), tagd4.GetVelocity(), tagd4.GetAcceleration(), tagd4.GetNodeId(), tagd4.GetNeighborids(), 4);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd4.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd4.GetSerializedSize()<<" at position "<< tagd4.GetPosition()<<"with velocity "<<tagd4.GetVelocity()<<"with acceleration "<<tagd4.GetAcceleration()<<"packet timestamp "<< tagd4.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd4.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag5 tagd5;
	if(pkt->PeekPacketTag(tagd5))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd5.GetNodeId(), tagd5.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd5.GetPosition(), tagd5.GetVelocity(), tagd5.GetAcceleration(), tagd5.GetNodeId(), tagd5.GetNeighborids(), 5);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd5.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd5.GetSerializedSize()<<" at position "<< tagd5.GetPosition()<<"with velocity "<<tagd5.GetVelocity()<<"with acceleration "<<tagd5.GetAcceleration()<<"packet timestamp "<< tagd5.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd5.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag6 tagd6;
	if(pkt->PeekPacketTag(tagd6))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd6.GetNodeId(), tagd6.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd6.GetPosition(), tagd6.GetVelocity(), tagd6.GetAcceleration(), tagd6.GetNodeId(), tagd6.GetNeighborids(), 6);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd6.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd6.GetSerializedSize()<<" at position "<< tagd6.GetPosition()<<"with velocity "<<tagd6.GetVelocity()<<"with acceleration "<<tagd6.GetAcceleration()<<"packet timestamp "<< tagd6.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd6.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag7 tagd7;
	if(pkt->PeekPacketTag(tagd7))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd7.GetNodeId(), tagd7.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd7.GetPosition(), tagd7.GetVelocity(), tagd7.GetAcceleration(), tagd7.GetNodeId(), tagd7.GetNeighborids(), 7);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd7.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd7.GetSerializedSize()<<" at position "<< tagd7.GetPosition()<<"with velocity "<<tagd7.GetVelocity()<<"with acceleration "<<tagd7.GetAcceleration()<<"packet timestamp "<< tagd7.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd7.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	
	CustomDataTag8 tagd8;
	if(pkt->PeekPacketTag(tagd8))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd8.GetNodeId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd8.GetPosition(), tagd8.GetVelocity(), tagd8.GetAcceleration(), tagd8.GetNodeId(), tagd8.GetNeighborids(), 8);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd8.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd8.GetSerializedSize()<<" at position "<< tagd8.GetPosition()<<"with velocity "<<tagd8.GetVelocity()<<"with acceleration "<<tagd8.GetAcceleration()<<"packet timestamp "<< tagd8.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd8.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag9 tagd9;
	if(pkt->PeekPacketTag(tagd9))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd9.GetNodeId(), tagd9.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd9.GetPosition(), tagd9.GetVelocity(), tagd9.GetAcceleration(), tagd9.GetNodeId(), tagd9.GetNeighborids(), 9);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd9.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd9.GetSerializedSize()<<" at position "<< tagd9.GetPosition()<<"with velocity "<<tagd9.GetVelocity()<<"with acceleration "<<tagd9.GetAcceleration()<<"packet timestamp "<< tagd9.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd9.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag10 tagd10;
	if(pkt->PeekPacketTag(tagd10))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd10.GetNodeId(), tagd10.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd10.GetPosition(), tagd10.GetVelocity(), tagd10.GetAcceleration(), tagd10.GetNodeId(), tagd10.GetNeighborids(), 10);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd10.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd10.GetSerializedSize()<<" at position "<< tagd10.GetPosition()<<"with velocity "<<tagd10.GetVelocity()<<"with acceleration "<<tagd10.GetAcceleration()<<"packet timestamp "<< tagd10.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd10.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag11 tagd11;
	if(pkt->PeekPacketTag(tagd11))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd11.GetNodeId(), tagd11.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd11.GetPosition(), tagd11.GetVelocity(), tagd11.GetAcceleration(), tagd11.GetNodeId(), tagd11.GetNeighborids(), 11);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd11.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd11.GetSerializedSize()<<" at position "<< tagd11.GetPosition()<<"with velocity "<<tagd11.GetVelocity()<<"with acceleration "<<tagd11.GetAcceleration()<<"packet timestamp "<< tagd11.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd11.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag12 tagd12;
	if(pkt->PeekPacketTag(tagd12))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd12.GetNodeId(), tagd12.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd12.GetPosition(), tagd12.GetVelocity(), tagd12.GetAcceleration(), tagd12.GetNodeId(), tagd12.GetNeighborids(), 12);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd12.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd12.GetSerializedSize()<<" at position "<< tagd12.GetPosition()<<"with velocity "<<tagd12.GetVelocity()<<"with acceleration "<<tagd12.GetAcceleration()<<"packet timestamp "<< tagd12.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd12.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag13 tagd13;
	if(pkt->PeekPacketTag(tagd13))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd13.GetNodeId(), tagd13.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd13.GetPosition(), tagd13.GetVelocity(), tagd13.GetAcceleration(), tagd13.GetNodeId(), tagd13.GetNeighborids(), 13);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd13.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd13.GetSerializedSize()<<" at position "<< tagd13.GetPosition()<<"with velocity "<<tagd13.GetVelocity()<<"with acceleration "<<tagd13.GetAcceleration()<<"packet timestamp "<< tagd13.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd13.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag14 tagd14;
	if(pkt->PeekPacketTag(tagd14))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd14.GetNodeId(), tagd14.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd14.GetPosition(), tagd14.GetVelocity(), tagd14.GetAcceleration(), tagd14.GetNodeId(), tagd14.GetNeighborids(), 14);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd14.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd14.GetSerializedSize()<<" at position "<< tagd14.GetPosition()<<"with velocity "<<tagd14.GetVelocity()<<"with acceleration "<<tagd14.GetAcceleration()<<"packet timestamp "<< tagd14.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd14.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag15 tagd15;
	if(pkt->PeekPacketTag(tagd15))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd15.GetNodeId(), tagd15.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd15.GetPosition(), tagd15.GetVelocity(), tagd15.GetAcceleration(), tagd15.GetNodeId(), tagd15.GetNeighborids(), 15);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd15.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd15.GetSerializedSize()<<" at position "<< tagd15.GetPosition()<<"with velocity "<<tagd15.GetVelocity()<<"with acceleration "<<tagd15.GetAcceleration()<<"packet timestamp "<< tagd15.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd15.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag16 tagd16;
	if(pkt->PeekPacketTag(tagd16))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd16.GetNodeId(), tagd16.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd16.GetPosition(), tagd16.GetVelocity(), tagd16.GetAcceleration(), tagd16.GetNodeId(), tagd16.GetNeighborids(), 16);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd16.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd16.GetSerializedSize()<<" at position "<< tagd16.GetPosition()<<"with velocity "<<tagd16.GetVelocity()<<"with acceleration "<<tagd16.GetAcceleration()<<"packet timestamp "<< tagd16.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd16.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	
	CustomDataTag17 tagd17;
	if(pkt->PeekPacketTag(tagd17))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd17.GetNodeId(), tagd17.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd17.GetPosition(), tagd17.GetVelocity(), tagd17.GetAcceleration(), tagd17.GetNodeId(), tagd17.GetNeighborids(), 17);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd17.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd17.GetSerializedSize()<<" at position "<< tagd17.GetPosition()<<"with velocity "<<tagd17.GetVelocity()<<"with acceleration "<<tagd17.GetAcceleration()<<"packet timestamp "<< tagd17.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd17.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag18 tagd18;
	if(pkt->PeekPacketTag(tagd18))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd18.GetNodeId(), tagd18.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd18.GetPosition(), tagd18.GetVelocity(), tagd18.GetAcceleration(), tagd18.GetNodeId(), tagd18.GetNeighborids(), 18);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd18.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd18.GetSerializedSize()<<" at position "<< tagd18.GetPosition()<<"with velocity "<<tagd18.GetVelocity()<<"with acceleration "<<tagd18.GetAcceleration()<<"packet timestamp "<< tagd18.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd18.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag19 tagd19;
	if(pkt->PeekPacketTag(tagd19))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd19.GetNodeId(), tagd19.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd19.GetPosition(), tagd19.GetVelocity(), tagd19.GetAcceleration(), tagd19.GetNodeId(), tagd19.GetNeighborids(), 19);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd19.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd19.GetSerializedSize()<<" at position "<< tagd19.GetPosition()<<"with velocity "<<tagd19.GetVelocity()<<"with acceleration "<<tagd19.GetAcceleration()<<"packet timestamp "<< tagd19.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd19.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag20 tagd20;
	if(pkt->PeekPacketTag(tagd20))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd20.GetNodeId(), tagd20.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd20.GetPosition(), tagd20.GetVelocity(), tagd20.GetAcceleration(), tagd20.GetNodeId(), tagd20.GetNeighborids(), 20);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd20.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd20.GetSerializedSize()<<" at position "<< tagd20.GetPosition()<<"with velocity "<<tagd20.GetVelocity()<<"with acceleration "<<tagd20.GetAcceleration()<<"packet timestamp "<< tagd20.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd20.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag21 tagd21;
	if(pkt->PeekPacketTag(tagd21))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd21.GetNodeId(), tagd21.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd21.GetPosition(), tagd21.GetVelocity(), tagd21.GetAcceleration(), tagd21.GetNodeId(), tagd21.GetNeighborids(), 21);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd21.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd21.GetSerializedSize()<<" at position "<< tagd21.GetPosition()<<"with velocity "<<tagd21.GetVelocity()<<"with acceleration "<<tagd21.GetAcceleration()<<"packet timestamp "<< tagd21.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd21.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag22 tagd22;
	if(pkt->PeekPacketTag(tagd22))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd22.GetNodeId(), tagd22.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd22.GetPosition(), tagd22.GetVelocity(), tagd22.GetAcceleration(), tagd22.GetNodeId(), tagd22.GetNeighborids(), 22);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd22.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd22.GetSerializedSize()<<" at position "<< tagd22.GetPosition()<<"with velocity "<<tagd22.GetVelocity()<<"with acceleration "<<tagd22.GetAcceleration()<<"packet timestamp "<< tagd22.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd22.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag23 tagd23;
	if(pkt->PeekPacketTag(tagd23))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd23.GetNodeId(), tagd23.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd23.GetPosition(), tagd23.GetVelocity(), tagd23.GetAcceleration(), tagd23.GetNodeId(), tagd23.GetNeighborids(), 23);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd23.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd23.GetSerializedSize()<<" at position "<< tagd23.GetPosition()<<"with velocity "<<tagd23.GetVelocity()<<"with acceleration "<<tagd23.GetAcceleration()<<"packet timestamp "<< tagd23.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd23.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag24 tagd24;
	if(pkt->PeekPacketTag(tagd24))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd24.GetNodeId(), tagd24.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd24.GetPosition(), tagd24.GetVelocity(), tagd24.GetAcceleration(), tagd24.GetNodeId(), tagd24.GetNeighborids(), 24);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd24.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd24.GetSerializedSize()<<" at position "<< tagd24.GetPosition()<<"with velocity "<<tagd24.GetVelocity()<<"with acceleration "<<tagd24.GetAcceleration()<<"packet timestamp "<< tagd24.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd24.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomDataTag25 tagd25;
	if(pkt->PeekPacketTag(tagd25))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagd25.GetNodeId(), tagd25.GetPortId()); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagd25.GetPosition(), tagd25.GetVelocity(), tagd25.GetAcceleration(), tagd25.GetNodeId(), tagd25.GetNeighborids(), 25);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagd25.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagd25.GetSerializedSize()<<" at position "<< tagd25.GetPosition()<<"with velocity "<<tagd25.GetVelocity()<<"with acceleration "<<tagd25.GetAcceleration()<<"packet timestamp "<< tagd25.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagd25.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	
	CustomDataTagmax tagdmax;
	if(pkt->PeekPacketTag(tagdmax))
	{
		add_neighbor_info(neighbordata_inst+destination_node_id,tagdmax.GetNodeId()), tagdmax.GetPortId(); //add current neighbor information
		refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		add_received_data_at_nodes(data_at_nodes_inst+destination_node_id, tagdmax.GetPosition(), tagdmax.GetVelocity(), tagdmax.GetAcceleration(), tagdmax.GetNodeId(), tagdmax.GetNeighborids(), max);
		refresh_data_at_nodes(data_at_nodes_inst+destination_node_id);
		std::cout << "Received data broadcasted packet from "<< tagdmax.GetNodeId()<<"to node "<<destination_node_id <<"of size "<<tagdmax.GetSerializedSize()<<" at position "<< tagdmax.GetPosition()<<"with velocity "<<tagdmax.GetVelocity()<<"with acceleration "<<tagdmax.GetAcceleration()<<"packet timestamp "<< tagdmax.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tagdmax.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	
	CustomMetaDataBroadcastTag tag2;
	if(pkt->PeekPacketTag(tag2))
	{
		
		 //int combined_cost = 2 + (Now().GetMilliSeconds()-tag2.GetTimestamp().GetMilliSeconds());
		 //add_neighbor_info(neighbordata_inst+destination_node_id,tag2.GetNodeId(), combined_cost);
		 add_neighbor_info(neighbordata_inst+destination_node_id,tag2.GetNodeId()); //add current neighbor information
		 refresh_neighbors(neighbordata_inst+destination_node_id);//remove old neighbors
		 uint32_t ns = getNeighborsize(neighbordata_inst+destination_node_id);	
		 cout<<"received metadata broadcasted to"<<destination_node_id <<"neighbor size"<<ns<<endl;
		std::cout << "Current neighbor size is "<<ns<<"Received packet from "<< tag2.GetNodeId()<<"to node "<<context[10]<<context[11] <<"of size "<<tag2.GetSerializedSize()<<"packet timestamp "<< tag2.GetTimestamp().GetSeconds()<<"s "<<"with delay "<< Now().GetMicroSeconds()-tag2.GetTimestamp().GetMicroSeconds()<<"us"<<std::endl;
	}
	*/
	
}





void p2p_data_broadcast(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> node)
{
	Ptr <Node> nu = DynamicCast <Node> (node);
	CustomDataTag tag;
	uint32_t nid = uint32_t(nu->GetId());
	tag.SetNodeId(nid);
	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node->GetObject<MobilityModel>());
        Vector posi = mdl->GetPosition();
        Vector veli = mdl->GetVelocity();
        Vector acci = Vector(0,0,0);
	tag.SetPosition(posi);
	tag.SetVelocity(veli);
	tag.SetAcceleration(acci);
	Time ti = Seconds(Simulator::Now().GetSeconds());
	tag.SetTimestamp(ti);
	Ptr <Packet> packet1 = Create <Packet> (0);
	packet1->AddPacketTag(tag);
  	Ptr <Ipv4> ipv4;
  	ipv4 = node->GetObject<Ipv4>();
  	uint32_t N_interfaces = ipv4->GetNInterfaces();
  	for (uint32_t j=1; j<N_interfaces-1; j++)
  	{
		Ipv4InterfaceAddress iaddr = ipv4->GetAddress(j,0);//jth IPv4 interface,0th address index
		Ipv4Address dest_ip = iaddr.GetBroadcast();//get braoadcast address for p2p
		//cout<<dest_ip<<endl;
		//Ipv4Address dest_ip = Ipv4Address("20.1.0.255");
		Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
	}
}

void p2p_metadata_broadcast(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> node)
{
	Ptr <Node> nu = DynamicCast <Node> (node);
	CustomMetaDataBroadcastTag tag;
	uint32_t nid = uint32_t(nu->GetId());
	tag.SetNodeId(nid);
	Time ti = Seconds(Simulator::Now().GetSeconds());
	tag.SetTimestamp(ti);
	Ptr <Packet> packet1 = Create <Packet> (0);
	packet1->AddPacketTag(tag);
  	Ptr <Ipv4> ipv4;
  	ipv4 = node->GetObject<Ipv4>();
  	uint32_t N_interfaces = ipv4->GetNInterfaces();
  	for (uint32_t j=1; j<N_interfaces-1; j++)
  	{
		Ipv4InterfaceAddress iaddr = ipv4->GetAddress(j,0);//jth IPv4 interface,0th address index
		Ipv4Address dest_ip = iaddr.GetBroadcast();//get braoadcast address for p2p
		//cout<<dest_ip<<endl;
		//Ipv4Address dest_ip = Ipv4Address("20.1.0.255");
		Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
	}
}

void AODV_dataunicast_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> source_node, Ptr <Node> destination_node)
{
	Ptr <Node> nu = DynamicCast <Node> (source_node);
	uint32_t nid = uint32_t(nu->GetId());
	uint32_t destination = destination_node->GetId();
	aodv_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (source_node->GetObject<MobilityModel>());
        Vector posi = mdl->GetPosition();
        Vector veli = mdl->GetVelocity();
        Vector acci = Vector(0,0,0);
	Time ti = Seconds(Simulator::Now().GetSeconds());
	Ptr <Packet> packet1 = Create <Packet> (0);
	uint32_t nodeid = nid;
	CustomDataUnicastTag_Routing tag1;
	tag1.SetsenderId(nid);
	tag1.SetNodeId(&nodeid);
	tag1.Setposition(&posi);
	tag1.Setvelocity(&veli);
	tag1.Setacceleration(&acci);
	tag1.SetTimestamp(&ti);
	tag1.SetdestinationId(destination);
	packet1->AddPacketTag(tag1);
  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
  	Ipv4InterfaceAddress iaddr;
  	Ipv4Address dest_ip;
  	
  	//Ptr <Node> dest_nd = DynamicCast <Node> (destination_node);
	//uint32_t dest_nid = uint32_t(nu->GetId());
  	//if (dest_nid < (2+N_Vehicles))
  	//{
		iaddr = ipv4->GetAddress(1,0);
		dest_ip = iaddr.GetLocal();	
		cout<<dest_ip<<endl;
	//}
	dsrc_total_packet_size = dsrc_total_packet_size + 84;
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);	
}




void RSU_dataunicast_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> source_node, Ptr <Node> destination_node)
{
	Ptr <Node> nu = DynamicCast <Node> (source_node);
	uint32_t nid = uint32_t(nu->GetId());
	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (source_node->GetObject<MobilityModel>());
        Vector posi = mdl->GetPosition();
        Vector veli = mdl->GetVelocity();
        Vector acci = Vector(0,0,0);
	Time ti = Seconds(Simulator::Now().GetSeconds());
	Ptr <Packet> packet1 = Create <Packet> (0);
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
	

    uint8_t * HMAC1 = new uint8_t[64];	
	if(routing_algorithm == 4)
	{
		std::string filename_HMAC = NS3_ROOT "/analytics/data/security_global_HMAC_data.csv";
	    string HMAC_string = read_item_from_csv(filename_HMAC, std::to_string(nid-2), 1);
	    cout<<"HMAC global string is "<<HMAC_string<<endl;
		HexStringToBytes(HMAC_string, HMAC1, 64);
	}
	
	add_received_data_at_nodes(data_at_nodes_inst+nid, HMAC1, posi, veli, acci, nid, neighborid, size_nei, 0);
  	//send the content at data at nodes to the mangement node
  	uint32_t size = get_size_of_data_at_nodes(data_at_nodes_inst+nid);
	uint32_t safe_size = (size > 0) ? size : 1;
  	uint32_t nodeid[safe_size];
  	uint32_t portid[safe_size];
	Vector position[safe_size];
	Vector acceleration[safe_size];
	Vector velocity[safe_size];
	Time timestamp[safe_size];


	for(uint32_t i=0;i<size;i++)
	{
		nodeid[i] = large;
		position[i] = Vector(0,0,0);
		acceleration[i] = Vector(0,0,0);
		velocity[i] = Vector(0,0,0);
		timestamp[i] = Simulator::Now();
	}
	
	uint32_t k=0;
	for(uint32_t i=0;i<max;i++)
	{
		if (((data_at_nodes_inst+nid)->nodeid[i] != large) and (k<size))
		{
			portid[k] = (data_at_nodes_inst+nid)->portid[i];
			nodeid[k] = (data_at_nodes_inst+nid)->nodeid[i];
			position[k] = (data_at_nodes_inst+nid)->position[i];
			velocity[k] = (data_at_nodes_inst+nid)->velocity[i];
			acceleration[k] = (data_at_nodes_inst+nid)->acceleration[i];
			timestamp[k] = (data_at_nodes_inst+nid)->timestamp[i];
			k++;
		}
		
	}	
	
	CustomDataUnicastTag1 tag1;
	CustomDataUnicastTag2 tag2;
	CustomDataUnicastTag3 tag3;
	CustomDataUnicastTag4 tag4;
	CustomDataUnicastTag5 tag5;
	CustomDataUnicastTag6 tag6;
	CustomDataUnicastTag7 tag7;
	CustomDataUnicastTag8 tag8;
	CustomDataUnicastTag9 tag9;
	CustomDataUnicastTag10 tag10;
	CustomDataUnicastTag11 tag11;
	CustomDataUnicastTag12 tag12;
	CustomDataUnicastTag13 tag13;
	CustomDataUnicastTag14 tag14;
	CustomDataUnicastTag15 tag15;
	CustomDataUnicastTag16 tag16;
	CustomDataUnicastTag17 tag17;
	CustomDataUnicastTag18 tag18;
	CustomDataUnicastTag19 tag19;
	CustomDataUnicastTag20 tag20;
	CustomDataUnicastTag21 tag21;
	CustomDataUnicastTag22 tag22;
	CustomDataUnicastTag23 tag23;
	CustomDataUnicastTag24 tag24;
	CustomDataUnicastTag25 tag25;
	CustomDataUnicastTag tag;
	switch (size)
	{	
		case 1:
			tag1.SetsenderId(nid);
			tag1.SetNodeId(nodeid);
			tag1.SetPortId(portid);
			tag1.Setposition(position);
			tag1.Setvelocity(velocity);
			tag1.Setacceleration(acceleration);
			tag1.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag1);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 2:
			tag2.SetsenderId(nid);
			tag2.SetNodeId(nodeid);
			tag2.SetPortId(portid);
			tag2.Setposition(position);
			tag2.Setvelocity(velocity);
			tag2.Setacceleration(acceleration);
			tag2.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag2);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 3:
			tag3.SetsenderId(nid);
			tag3.SetNodeId(nodeid);
			tag3.SetPortId(portid);
			tag3.Setposition(position);
			tag3.Setvelocity(velocity);
			tag3.Setacceleration(acceleration);
			tag3.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag3);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 4:
			tag4.SetsenderId(nid);
			tag4.SetNodeId(nodeid);
			tag4.SetPortId(portid);
			tag4.Setposition(position);
			tag4.Setvelocity(velocity);
			tag4.Setacceleration(acceleration);
			tag4.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag4);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 5:
			tag5.SetsenderId(nid);
			tag5.SetNodeId(nodeid);
			tag5.SetPortId(portid);
			tag5.Setposition(position);
			tag5.Setvelocity(velocity);
			tag5.Setacceleration(acceleration);
			tag5.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag5);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 6:
			tag6.SetsenderId(nid);
			tag6.SetNodeId(nodeid);
			tag6.SetPortId(portid);
			tag6.Setposition(position);
			tag6.Setvelocity(velocity);
			tag6.Setacceleration(acceleration);
			tag6.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag6);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 7:
			tag7.SetsenderId(nid);
			tag7.SetNodeId(nodeid);
			tag7.SetPortId(portid);
			tag7.Setposition(position);
			tag7.Setvelocity(velocity);
			tag7.Setacceleration(acceleration);
			tag7.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag7);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 8:
			tag8.SetsenderId(nid);
			tag8.SetNodeId(nodeid);
			tag8.SetPortId(portid);
			tag8.Setposition(position);
			tag8.Setvelocity(velocity);
			tag8.Setacceleration(acceleration);
			tag8.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag8);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 9:
			tag9.SetsenderId(nid);
			tag9.SetNodeId(nodeid);
			tag9.SetPortId(portid);
			tag9.Setposition(position);
			tag9.Setvelocity(velocity);
			tag9.Setacceleration(acceleration);
			tag9.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag9);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 10:
			tag10.SetsenderId(nid);
			tag10.SetNodeId(nodeid);
			tag10.SetPortId(portid);
			tag10.Setposition(position);
			tag10.Setvelocity(velocity);
			tag10.Setacceleration(acceleration);
			tag10.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag10);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 11:
			tag11.SetsenderId(nid);
			tag11.SetNodeId(nodeid);
			tag11.SetPortId(portid);
			tag11.Setposition(position);
			tag11.Setvelocity(velocity);
			tag11.Setacceleration(acceleration);
			tag11.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag11);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 12:
			tag12.SetsenderId(nid);
			tag12.SetNodeId(nodeid);
			tag12.SetPortId(portid);
			tag12.Setposition(position);
			tag12.Setvelocity(velocity);
			tag12.Setacceleration(acceleration);
			tag12.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag12);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 13:
			tag13.SetsenderId(nid);
			tag13.SetNodeId(nodeid);
			tag13.SetPortId(portid);
			tag13.Setposition(position);
			tag13.Setvelocity(velocity);
			tag13.Setacceleration(acceleration);
			tag13.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag13);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;	
		case 14:
			tag14.SetsenderId(nid);
			tag14.SetNodeId(nodeid);
			tag14.SetPortId(portid);
			tag14.Setposition(position);
			tag14.Setvelocity(velocity);
			tag14.Setacceleration(acceleration);
			tag14.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag14);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 15:
			tag15.SetsenderId(nid);
			tag15.SetNodeId(nodeid);
			tag15.SetPortId(portid);
			tag15.Setposition(position);
			tag15.Setvelocity(velocity);
			tag15.Setacceleration(acceleration);
			tag15.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag15);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;

		case 16:
			tag16.SetsenderId(nid);
			tag16.SetNodeId(nodeid);
			tag16.SetPortId(portid);
			tag16.Setposition(position);
			tag16.Setvelocity(velocity);
			tag16.Setacceleration(acceleration);
			tag16.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag16);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 17:
			tag17.SetsenderId(nid);
			tag17.SetNodeId(nodeid);
			tag17.SetPortId(portid);
			tag17.Setposition(position);
			tag17.Setvelocity(velocity);
			tag17.Setacceleration(acceleration);
			tag17.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag17);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 18:
			tag18.SetsenderId(nid);	
			tag18.SetNodeId(nodeid);
			tag18.SetPortId(portid);
			tag18.Setposition(position);
			tag18.Setvelocity(velocity);
			tag18.Setacceleration(acceleration);
			tag18.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag18);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 19:
			tag19.SetsenderId(nid);
			tag19.SetNodeId(nodeid);
			tag19.SetPortId(portid);
			tag19.Setposition(position);
			tag19.Setvelocity(velocity);
			tag19.Setacceleration(acceleration);
			tag19.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag19);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 20:
			tag20.SetsenderId(nid);
			tag20.SetNodeId(nodeid);
			tag20.SetPortId(portid);
			tag20.Setposition(position);
			tag20.Setvelocity(velocity);
			tag20.Setacceleration(acceleration);
			tag20.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag20);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 21:
			tag21.SetsenderId(nid);
			tag21.SetNodeId(nodeid);
			tag21.SetPortId(portid);
			tag21.Setposition(position);
			tag21.Setvelocity(velocity);
			tag21.Setacceleration(acceleration);
			tag21.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag21);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 22:
			tag22.SetsenderId(nid);
			tag22.SetNodeId(nodeid);
			tag22.SetPortId(portid);
			tag22.Setposition(position);
			tag22.Setvelocity(velocity);
			tag22.Setacceleration(acceleration);
			tag22.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag22);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 23:
			tag23.SetsenderId(nid);
			tag23.SetNodeId(nodeid);
			tag23.SetPortId(portid);
			tag23.Setposition(position);
			tag23.Setvelocity(velocity);
			tag23.Setacceleration(acceleration);
			tag23.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag23);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 24:
			tag24.SetsenderId(nid);
			tag24.SetNodeId(nodeid);
			tag24.SetPortId(portid);
			tag24.Setposition(position);
			tag24.Setvelocity(velocity);
			tag24.Setacceleration(acceleration);
			tag24.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag24);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 25:
			tag25.SetsenderId(nid);
			tag25.SetNodeId(nodeid);
			tag25.SetPortId(portid);
			tag25.Setposition(position);
			tag25.Setvelocity(velocity);
			tag25.Setacceleration(acceleration);
			tag25.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag25);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		default:
			cout<<"Cellular:maximum status datasize exceeded . size is  "<<size<<endl;
			tag.SetsenderId(nid);
			tag.SetPortId(portid);
			tag.SetNodeId((data_at_nodes_inst+nid)->nodeid);
			tag.Setposition((data_at_nodes_inst+nid)->position);
			tag.Setvelocity((data_at_nodes_inst+nid)->velocity);
			tag.Setacceleration((data_at_nodes_inst+nid)->acceleration);
			tag.SetTimestamp((data_at_nodes_inst+nid)->timestamp);
			packet1->AddPacketTag(tag);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;	
	}
	cout<<"ethernet total packet size is "<<ethernet_total_packet_size<<endl;
}





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



MobilityHelper vehicle_mobility;

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


void hybrid_data_unicast(Ptr <NetDevice> source_nd, Ptr <Node> source_node, uint32_t node_index, uint32_t destination)
{
	uint32_t nid = source_node->GetId();
	//cout<<"original node id is "<<nid<<endl;
	//uint32_t next_hop = routing_tables[node_index].rows[destination].next_hop;
	uint32_t next_hop = find_next_hop(node_index,destination,node_index);
	cout<<endl<<"next hop from routing table is "<< next_hop <<endl;
	dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	if (next_hop < total_size)
	{
		CustomDataUnicastTag_Routing tag;
		//uint32_t nid = uint32_t(ni->GetId());
		Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (source_node->GetObject<MobilityModel>());
		Vector posi = mdl->GetPosition();
		Vector current_velocity = mdl->GetVelocity();
		double delta_t = data_transmission_period;
		Vector acceleration = calculate_acceleration(previous_velocity_dsrc[node_index],current_velocity,delta_t);
		Time ti = MicroSeconds(Simulator::Now().GetMicroSeconds());
		Ptr <Packet> packet_i = Create<Packet> (packet_additional_size);
		tag.SetsenderId(nid-2);
		tag.SetNodeId(&nid);
		tag.Setposition(&posi);
		tag.Setvelocity(&current_velocity);
		tag.Setacceleration(&acceleration);
		tag.SetTimestamp(&ti);
		tag.SetdestinationId(destination);
		packet_i->AddPacketTag(tag);
		
		
		if (((nid-2) > N_Vehicles) && (next_hop > N_Vehicles))
		{
			Ptr <Node> nu = DynamicCast <Node> (RSU_Nodes.Get(nid-2-N_Vehicles));	
	  		Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(nid-2-N_Vehicles));
	  		cout<<"This is source node. Ethernet data Unicasting from node "<<nid - 2<<endl;
			Simulator::Schedule(Seconds(0),RSU_routing_dataunicast_alone, udp_app, nu, RSU_Nodes.Get(next_hop-N_Vehicles),packet_i);
		}
		
		else
		{
			cout<<"This is source node. DSRC data Unicasting from node "<<nid - 2<<endl;
			Ptr <NetDevice> destination_nd = wifidevices.Get(next_hop);
			Address addr = destination_nd->GetAddress();
			Mac48Address dest_address = Mac48Address::ConvertFrom(addr);
			//cout <<endl<<"MAC address of next hop node "<<next_hop<<" is "<<dest_address<<endl;
		  	uint16_t protocolwave = 0x88dc;//
			Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (source_nd);
			Ptr <Node> ni = DynamicCast <Node> (source_node);
			dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
			Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);
		}
		uint32_t * pt = tag.GetNodeId();
		//cout<<"node id from tag is "<<*pt<<endl;	
		Y[*pt - 2] = Y[*pt -2] + 1;
		//cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
		previous_velocity_dsrc[node_index] = current_velocity;
	}
	else
	{
		cout<<"A route does not exist"<<endl;
	}
}

void routing_dsrc_data_unicast(Ptr <NetDevice> source_nd, Ptr <Node> source_node, uint32_t flow_id, uint32_t next_hop_id, struct custom_struct arguments, uint32_t packet_ID)
{
	//cout<<"transmiiting a a packet at "<<Now().GetMilliSeconds()<<endl;
	uint32_t nid = source_node->GetId();
	uint32_t source = nid -2;
	//cout<<"next hop is "<< next_hop_id <<endl;
	Ptr <NetDevice> destination_nd = wifidevices.Get(next_hop_id);
	switch(arguments.channel)
	{
		case(172):
			destination_nd = wifidevices_172.Get(next_hop_id);
			break;
		case(174):
			destination_nd = wifidevices_174.Get(next_hop_id);
			break;
		case(176):
			destination_nd = wifidevices_176.Get(next_hop_id);
			break;
		case(178):
			destination_nd = wifidevices.Get(next_hop_id);
			break;
		case(180):
			destination_nd = wifidevices_180.Get(next_hop_id);
			break;
		case(182):
			destination_nd = wifidevices_182.Get(next_hop_id);
			break;
		case(184):
			destination_nd = wifidevices_184.Get(next_hop_id);
			break;
		default:
			break;
	
	}
	//Ptr <NetDevice> destination_nd = wifidevices.Get(13);
	Address addr = destination_nd->GetAddress();
	Mac48Address dest_address = Mac48Address::ConvertFrom(addr);
	//cout <<endl<<"MAC address of next hop node "<<next_hop_id<<" is "<<dest_address<<endl;
  	uint16_t protocolwave = 0x88dc;//
	Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (source_nd);
	Ptr <Node> ni = DynamicCast <Node> (source_node);
	CustomDataUnicastTag_ModifiedRouting tag;
	//uint32_t nid = uint32_t(ni->GetId());
	dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	Time ti = Seconds(Simulator::Now().GetSeconds());
	Ptr <Packet> packet_i = Create<Packet> (arguments.p_size-28);
	tag.SetflowId(flow_id);
	tag.SetpacketId(packet_ID);
	tag.SetchannelId(arguments.channel);
	tag.Setprevious_senderId(source);
	tag.Setprevious_timestamp(MicroSeconds(Now().GetMicroSeconds()));
	tag.Setoriginal_timestamp(MicroSeconds(Now().GetMicroSeconds()));
	packet_i->AddPacketTag(tag);
	WifiMacHeader header;
	packet_i->RemoveHeader(header);
	header.SetAddr1(dest_address);
	packet_i->AddHeader(header);
	//dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
	Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);
	//cout<<"This is flow ID "<<flow_id<<"Transmitting packet ID "<<packet_ID<<" from "<<source<<" to next hop "<<next_hop_id<<"at time "<<Now().GetSeconds()<<endl;
	//uint32_t * pt = tag.GetNodeId();
	//cout<<"node id from tag is "<<*pt<<endl;	
	//Y[*pt - 2] = Y[*pt -2] + 1;
	//cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
	//cout<<"packet size is "<<arguments.p_size-28<<endl;
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

void compute_RandQ(uint32_t timestep)
{
	for (uint32_t i=0;i<total_size;i++)
	{
		R[i] = ((R[i]*(timestep-1)) + Y[i])/timestep;
		double U;
		if (Y[i] > 0)
		{
			U = 1;
		}
		if (Y[i] == 0)
		{
			U = 0;
		}
		Q[i] = ((Q[i]*(timestep-1)) + U)/timestep;
	}
}

void print_RandQ()
{
	for (uint32_t i=0;i<total_size;i++)
	{
		cout<<"R "<<i<<"value is "<<R[i]<<endl;
		cout<<"Q "<<i<<"value is "<<Q[i]<<endl;
	}
}

void send_hybrid_packets(uint32_t destination)
{
	//calculate_normalized_mobility();
	//calculate_network_contention();
	initialize_all_routing_tables();
	reset_delays_and_packets();
	generate_adjacency_matrix();
	generate_linklifetime_matrix();
	generate_delay_matrix();
	calculate_contention();
	for (uint32_t i=0;i<total_size;i++)
	{
		cout<<"calculating dijkstra stable solution"<<endl;
		Simulator::Schedule(Seconds(0.010),calculate_dijkstra_stable_solution,i);
	}

	uint32_t dgcn = data_gathering_cycle_number;
	uint32_t condition1 = (dgcn/125)%2;
	double tg;
	if (condition1 == 0)
	{
		tg = 0.000040*(dgcn%125);
	}
	if (condition1 == 1)
	{
		tg = -0.000040*(dgcn%250) + 0.010;
	}
	
	uint32_t condition2 = (dgcn/50)%2;
	uint32_t x;
	if (condition2 == 0)
	{
		x = ceil((dgcn%50)/10.0);
	}
	
	if (condition2 == 1)
	{
		x = -ceil((dgcn%100)/10.0) + 10;
	}
	
	clear_RQY();
	//x = 1;

	for (uint32_t source=0; source<wifidevices.GetN(); source++)
  	{    
  		cout<<"dgcn is "<<dgcn<<endl;
  		cout<<"x is "<<x<<endl;
  		for (uint32_t i=0; i<x;i++)
  		{
  			uint32_t dest = (destination + source + i)%total_size;  
  			//dest = total_size - 2;
  			//tg = 0.0001; 
			Simulator::Schedule (Seconds (0.020 + tg*source), hybrid_data_unicast, wifidevices.Get (source), dsrc_Nodes.Get(source), source, dest);
		}
	} 
	
	double stepsize = 0.000020;
	for (uint32_t timestep=1; timestep<200*(total_size);timestep++)
	{
		Simulator::Schedule (Seconds (0.020 + (stepsize*timestep)), compute_RandQ, timestep);
	}
	
	Simulator::Schedule (Seconds (0.020 + stepsize*200*total_size), print_RandQ);
	Simulator::Schedule (Seconds (0.020 + stepsize*200*total_size), compute_1hop_delay);
		
}

void send_centralized_packets(uint32_t destination)
{
	//calculate_normalized_mobility();
	//calculate_network_contention();
	uint32_t port_id = 2;
	initialize_all_routing_tables();
	generate_adjacency_matrix();
	for (uint32_t i=0;i<total_size;i++)
	{
		cout<<"calculating dijkstra solution"<<endl;		
		calculate_dijkstra_solution(i);
	}

	uint32_t dgcn = data_gathering_cycle_number;
	uint32_t condition1 = (dgcn/125)%2;
	double tg;
	if (condition1 == 0)
	{
		tg = 0.000040*(dgcn%125);
	}
	if (condition1 == 1)
	{
		tg = -0.000040*(dgcn%250) + 0.010;
	}
	
	uint32_t condition2 = (dgcn/50)%2;
	uint32_t x;
	if (condition2 == 0)
	{
		x = ceil((dgcn%50)/10.0);
	}
	
	if (condition2 == 1)
	{
		x = -ceil((dgcn%100)/10.0) + 10;
	}
	
	//x = 1;
	
	for (uint32_t source=0; source<wifidevices.GetN(); source++)
  	{    
  		cout<<"dgcn is "<<dgcn<<endl;
  		cout<<"x is "<<x<<endl;
  		for (uint32_t i=0; i<x;i++)
  		{
  			uint32_t dest = (destination + source + i)%total_size;   
    			//dest = total_size - 2;
  			//tg = 0.0001;
			Simulator::Schedule (Seconds (0.020 + tg*source), centralized_dsrc_data_unicast, dsrc_Nodes.Get(source), source, dest, port_id);
		}
	} 
		
}





void initialize_flow_counters()
{
	vector<vector<vector<tuple<double,uint32_t,uint32_t>>>> all_sorted_delta_next_hop_flow_size_local;

	for (uint32_t fid=0;fid<2*flows;fid++)
  	{    
		//(delta_at_nodes_inst+i)->flow_id = flow_ids[i];
		uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
		//Initialize transmission opportunity
		for(uint32_t i=0;i<total_size;i++)
		{
			for(uint32_t j=0;j<f_size+1;j++)
			{
				for(uint32_t c=170;c<185;c++)
				{
					(pd_all_inst+fid)->pd_inst[i].delivery[c][j] = false;
					(pd_all_inst+fid)->pd_inst[i].pending[c][j] = false;
					(pd_all_inst+fid)->pd_inst[i].attempts[c][j] = 0;
				}
				sent_IDS[fid][i][j] = false;
				s_flow_counter[fid][i][j] = 0;
			}
		}
		
		
		
		for(uint32_t j =0;j<total_size;j++)
		{
			for(uint32_t c= 170;c<185;c++)
			{
				txop_inst[fid].busy[c][j] = false;
				txop_inst[fid].pending_packets[c][j] = 0;
				txop_inst[fid].last_set_timestamp[c][j] = Seconds(Now().GetSeconds());
			}
			
		}
		
		for(uint32_t i=1;i<Flow_size+1;i++)
		{
			routing_packet_final_timestamp[fid][i] = Now().GetSeconds();
			routing_packet_initial_timestamp[fid][i] = Now().GetSeconds();
			packet_delay_routing[fid][i] = 0;
		}
		
		for(uint32_t i =0;i<total_size;i++)
		{
			for(uint32_t j=1;j<Flow_size+1;j++)
			{
				routing_packet_general_final_timestamp [fid][i][j] = Now().GetSeconds();
				routing_packet_general_initial_timestamp [fid][i][j] = Now().GetSeconds();
			}
		}
		
		vector<vector<tuple<double,uint32_t,uint32_t>>> middle_sorted_delta_next_hop_flow_size_local;
		for(uint32_t i=0;i<total_size;i++)
		{
			uint32_t main_flow_packets = ceil(f_size*((load_at_nodes+fid)->load_f[i]));
			vector<tuple<double,uint32_t,uint32_t>> innermost_sorted_delta_next_hop_flow_size;
			for(uint32_t j=0;j<total_size;j++)
			{
				uint32_t sub_flow_packets = ((delta_at_nodes_inst+fid)->delta_fi_inst[i].delta_values[j])*main_flow_packets;
				innermost_sorted_delta_next_hop_flow_size.emplace_back((delta_at_nodes_inst+fid)->delta_fi_inst[i].delta_values[j], j, sub_flow_packets);
				
			}
			
			sort(innermost_sorted_delta_next_hop_flow_size.begin(), innermost_sorted_delta_next_hop_flow_size.end());
			uint32_t total_count =0;
			for(uint32_t j =0;j<total_size;j++)
			{
				auto index_innermost = innermost_sorted_delta_next_hop_flow_size.begin();
				//cout<<subflow_start_time<<total_packet_counter<<total_packets<<endl;
				advance(index_innermost,j);
				double sub_flow_load; 
				uint32_t nid;
				uint32_t sub_flow_packets;
				tie(sub_flow_load, nid, sub_flow_packets) = *index_innermost;
				if(j < (total_size-1))
				{
					uint32_t checker = j%2;
					//cout<<"checker is "<<checker<<endl;
					if(checker == 0)
					{
						get<2>(*index_innermost) = floor(get<2>(*index_innermost));
						total_count = total_count + floor(get<2>(*index_innermost));
					}
					else if (checker == 1)
					{
						get<2>(*index_innermost) = ceil(get<2>(*index_innermost));
						total_count = total_count + ceil(get<2>(*index_innermost));
					}
					
				
				}
				else if (j == (total_size-1))
				{
					uint32_t original_value = ceil(get<2>(*index_innermost));
					total_count = total_count + original_value;
					uint32_t deficiency = main_flow_packets - total_count;
					get<2>(*index_innermost) = original_value + deficiency;	
				}
			}
			
			//cout<<"Inner most list size "<<innermost_sorted_delta_next_hop_flow_size.size()<<endl;
			middle_sorted_delta_next_hop_flow_size_local.emplace_back(innermost_sorted_delta_next_hop_flow_size);	
		}
		//cout<<"Middle list size "<<middle_sorted_delta_next_hop_flow_size_local.size()<<endl;
		all_sorted_delta_next_hop_flow_size_local.emplace_back(middle_sorted_delta_next_hop_flow_size_local);
	}
	all_sorted_delta_next_hop_flow_size = all_sorted_delta_next_hop_flow_size_local;
	//cout<<"Outermost list size "<<all_sorted_delta_next_hop_flow_size.size()<<endl;
	cout<<"Initialized flow counters at "<<Now().GetSeconds()<<endl;

}




void check_and_transmit(uint32_t fid, uint32_t source, uint32_t total_packets, uint32_t total_packet_counter, uint32_t nid, struct custom_struct arguments)
{
	uint32_t packet_id = total_packet_counter + 1;
	arguments.CW = pd_all_inst[fid].pd_inst[nid].attempts[arguments.channel][packet_id] + 2;
	double diff = Now().GetSeconds() - flow_initiation_time;
	if(diff > (0.90*data_transmission_period))
	{
		pd_all_inst[fid].pd_inst[source].pending[arguments.channel][packet_id] = false;
		cout<<"Intial transmission packet dropped for flow id "<<fid<<"packet ID: "<< packet_id<<endl;
	}
	else
	{
		srand(packet_id+nid+Now().GetMicroSeconds());
		double rand_delay = 0.000010*(rand()%100);
		if(pd_all_inst[fid].pd_inst[nid].delivery[arguments.channel][packet_id] == true)
		{
			retransmitted[fid][nid][packet_id] = false;
			pd_all_inst[fid].pd_inst[source].pending[arguments.channel][packet_id] = false;
			//cout<<"packet has been delivered. Initial transmission success"<<" in flow ID "<<fid<<" packet ID "<<packet_id<<" from "<<source<<" to next hop "<<nid<<"at time "<<Now().GetSeconds()<<endl;
			Simulator::Schedule (Seconds (0.0), updateTxop, fid, source, nid, total_packets - total_packet_counter, false, arguments);
			//do nothing
		}
		else
		{
			bool pending_lower_ids = false;
			uint32_t pending_count = 0;
			for(uint32_t i=0;i<Flow_size+1;i++)
			{
				if (i< packet_id)
				{
					pending_lower_ids = pd_all_inst[fid].pd_inst[source].pending[arguments.channel][i] | pending_lower_ids;
					pending_count++;
				}
			
			}
			if((pending_lower_ids==true)&&(pending_count>0)&&(routing_algorithm != 1))
			{
				//cout<<"Intial transmission pending for flow id "<<fid<<"packet ID: "<< packet_id<<endl;
				Simulator::Schedule (Seconds (0.000100+rand_delay), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, arguments);
				Simulator::Schedule (Seconds (0.0), updateTxop, fid, source, nid, total_packets - total_packet_counter, false, arguments);
			}
			else
			{
				bool neighborhood_busy = false;
				for(uint32_t i=0;i<total_size;i++)
				{
					if((linklifetimeMatrix_dsrc[source][i]) > 0.0)
					{
						neighborhood_busy = neighborhood_busy | txop_inst[fid].busy[arguments.channel][i];
						for(uint32_t j=0;j<total_size;j++)
						{
							if((linklifetimeMatrix_dsrc[i][j]) > 0.0)
							{
								neighborhood_busy = neighborhood_busy | txop_inst[fid].busy[arguments.channel][j];
							}
						}
					}
				}
				
				//if (txop_inst[fid].busy[nid] == true)
				if (neighborhood_busy == true)
				{
					Simulator::Schedule (Seconds (0.000100+rand_delay), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, arguments);
					Simulator::Schedule (Seconds (0.0), updateTxop, fid, source, nid, total_packets - total_packet_counter, false, arguments);
					
				}
				else
				{
					if(pd_all_inst[fid].pd_inst[nid].attempts[arguments.channel][packet_id] < (B_max))
					{
						uint32_t zeta = 1;
						double tg = 1.01*compute_individual_link_delay(source, pd_all_inst[fid].pd_inst[nid].attempts[arguments.channel][packet_id] + 2, 1, arguments.p_size, nid, zeta);
						Simulator::Schedule (Seconds (0.0), updateTxop, fid, nid, source, total_packets - total_packet_counter, true, arguments);
						switch(arguments.channel)
						{
							case(172):
								Simulator::Schedule (Seconds (0.0), routing_dsrc_data_unicast, wifidevices_172.Get (source), dsrc_Nodes.Get(source), fid, nid, arguments, total_packet_counter+1);
								break;
							case(174):
								Simulator::Schedule (Seconds (0.0), routing_dsrc_data_unicast, wifidevices_174.Get (source), dsrc_Nodes.Get(source), fid, nid, arguments, total_packet_counter+1);
								break;
							case(176):
								Simulator::Schedule (Seconds (0.0), routing_dsrc_data_unicast, wifidevices_176.Get (source), dsrc_Nodes.Get(source), fid, nid, arguments, total_packet_counter+1);
								break;
							case(178):
								Simulator::Schedule (Seconds (0.0), routing_dsrc_data_unicast, wifidevices.Get (source), dsrc_Nodes.Get(source), fid, nid, arguments, total_packet_counter+1);
								break;
							case(180):
								Simulator::Schedule (Seconds (0.0), routing_dsrc_data_unicast, wifidevices_180.Get (source), dsrc_Nodes.Get(source), fid, nid, arguments, total_packet_counter+1);
								break;
							case(182):
								Simulator::Schedule (Seconds (0.0), routing_dsrc_data_unicast, wifidevices_182.Get (source), dsrc_Nodes.Get(source), fid, nid, arguments, total_packet_counter+1);
							break;
							case(184):
								Simulator::Schedule (Seconds (0.0), routing_dsrc_data_unicast, wifidevices_184.Get (source), dsrc_Nodes.Get(source), fid, nid, arguments, total_packet_counter+1);
								break;
							default:
							break;
						
						}
						
						Simulator::Schedule (Seconds (tg+0.000050+rand_delay), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, arguments);
						routing_packet_initial_timestamp[fid][packet_id] = Now().GetSeconds();
						sent_IDS[fid][source][packet_id] = true;
						routing_packet_general_initial_timestamp[fid][source][packet_id] = Now().GetSeconds();
						pd_all_inst[fid].pd_inst[nid].attempts[arguments.channel][packet_id]++;
					}
					else
					{
						pd_all_inst[fid].pd_inst[source].pending[arguments.channel][packet_id] = false;
						cout<<"Intial transmission packet dropped for flow id "<<fid<<"packet ID: "<< packet_id<<endl;
					
					}
				}
			}
		}
	}
}

void initiate_all_flows()
{	
	flow_initiation_time = Now().GetSeconds();
	for (uint32_t fid=0;fid<2*flows;fid++)
  	{    
  		
		uint32_t source = (delta_at_nodes_inst+fid)->source_f;
		//cout<<"source node is "<<source<<endl;
		uint32_t dest =   (delta_at_nodes_inst+fid)->destination_f;
		//(delta_at_nodes_inst+i)->flow_id = flow_ids[i];
		uint32_t f_size = (demanding_flow_struct_nodes_inst+fid)->f_size;
		uint32_t p_size = (demanding_flow_struct_nodes_inst+fid)->p_size;
		double total_load = (load_at_nodes+fid)->load_f[source];
		uint32_t total_packets = ceil(total_load*f_size);
		
		uint32_t zeta;
		if (flows == 1)
		{
			zeta = 14;
		}
		else
		{
			if(routing_algorithm != 4)
			{
				zeta = 18;
			}
			else
			{
				zeta = 14 + 2*scheduled_flows;
			
			}
		}
		double tg = compute_link_delay(source, 1.0, 1, p_size, dest, zeta);
		//cout<<"Time gap is "<<tg<<endl;
		double subflow_start_time = 0.0;
		uint32_t total_packet_counter = 0;
		
		auto index_top = all_sorted_delta_next_hop_flow_size.begin();
		advance(index_top,fid);
		//cout<<subflow_start_time<<total_packet_counter<<total_packets<<endl;

		auto index_middle = index_top->begin();
		advance(index_middle,source);	
		
		uint32_t total_subflows =0;
		for(uint32_t j =0;j<total_size;j++)
		{
			auto index_innermost = index_middle->begin();
			//cout<<subflow_start_time<<total_packet_counter<<total_packets<<endl;
			advance(index_innermost,j);
			double sub_flow_load; 
			uint32_t nid;
			uint32_t sub_flow_packets;
			tie(sub_flow_load, nid, sub_flow_packets) = *index_innermost;
			cout<<"flow id "<<fid<<"sub flow load is "<<sub_flow_load<<" next hop "<<nid<<"packets "<<sub_flow_packets<<endl;		
			//uint32_t sub_flow_counter = 0;
			//cout<<sub_flow_counter<<endl;
			
			if(sub_flow_load !=0.0)
			{	
				total_subflows++;
			}
		}
		
		uint32_t pending_subflows = total_subflows;
		//uint32_t chnl = 178;
		uint32_t subflow_id = 0;
		struct custom_struct size_channel;
		size_channel.p_size = p_size;
		size_channel.channel = 178;
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
			uint32_t sub_flow_counter = 0;
			//cout<<sub_flow_counter<<endl;
			
			if (routing_algorithm == 8)
			{
				size_channel.channel = 178;
				if(sub_flow_load !=0.0)
				{	
					while(sub_flow_counter<sub_flow_packets)
					{
						if(routing_algorithm == 1)
						{
							Simulator::Schedule (Seconds ((fid*tg/2*(flows)) + ((subflow_id*tg) +(total_subflows*tg*sub_flow_counter))), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
							pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
						
						}
						else
						{
							Simulator::Schedule (Seconds ((fid*tg/2*(flows)) +subflow_start_time + (tg*sub_flow_counter)), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
							pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
						}
						sub_flow_counter++;
						total_packet_counter++;
						get<2>(*index_innermost) = get<2>(*index_innermost) - 1;
						
					}
					subflow_id++;
				}
				subflow_start_time = (tg*total_packet_counter);
		  	}
		  	else
		  	{
		  		if(pending_subflows > 6)
		  		{
		  			size_channel.channel = 178;
			  		if(sub_flow_load !=0.0)
					{	
						while(sub_flow_counter<sub_flow_packets)
						{
							if(routing_algorithm == 1)
							{
								Simulator::Schedule (Seconds ((fid*tg/2*(flows)) + ((subflow_id*tg) +(total_subflows*tg*sub_flow_counter))), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
								pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
							
							}
							else
							{
								Simulator::Schedule (Seconds ((fid*tg/2*(flows)) +subflow_start_time + (tg*sub_flow_counter)), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
								pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
							}
							sub_flow_counter++;
							total_packet_counter++;
							get<2>(*index_innermost) = get<2>(*index_innermost) - 1;
							
						}
						subflow_id++;
						pending_subflows--;
						cout<<"scheduled in channel 7"<<endl;
					}
					subflow_start_time = (tg*total_packet_counter);
				}
				else
				{
					switch(pending_subflows)
					{
						case(6):
							size_channel.channel = 172;
							if(sub_flow_load !=0.0)
							{	
								
								while(sub_flow_counter<sub_flow_packets)
								{
									if(routing_algorithm == 1)
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) + ((subflow_id*tg) +(total_subflows*tg*sub_flow_counter))), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									
									}
									else
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) +subflow_start_time + (tg*sub_flow_counter)), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									}
									sub_flow_counter++;
									total_packet_counter++;
									get<2>(*index_innermost) = get<2>(*index_innermost) - 1;
									
								}
								subflow_id++;
								pending_subflows--;
								cout<<"scheduled in channel 6"<<endl;
							}
							subflow_start_time = subflow_start_time + (tg*sub_flow_counter)/2.0;
							break;
						case(5):
							size_channel.channel = 174;
							if(sub_flow_load !=0.0)
							{	
								while(sub_flow_counter<sub_flow_packets)
								{
									if(routing_algorithm == 1)
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) + ((subflow_id*tg) +(total_subflows*tg*sub_flow_counter))), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									
									}
									else
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) +subflow_start_time + (tg*sub_flow_counter)), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									}
									sub_flow_counter++;
									total_packet_counter++;
									get<2>(*index_innermost) = get<2>(*index_innermost) - 1;
									
								}
								subflow_id++;
								pending_subflows--;
								cout<<"scheduled in channel 5"<<endl;
							}
							subflow_start_time = subflow_start_time + (tg*sub_flow_counter)/2.0;
							break;
						case(4):
							size_channel.channel = 176;
							if(sub_flow_load !=0.0)
							{	
								
								while(sub_flow_counter<sub_flow_packets)
								{
									if(routing_algorithm == 1)
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) + ((subflow_id*tg) +(total_subflows*tg*sub_flow_counter))), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									
									}
									else
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) +subflow_start_time + (tg*sub_flow_counter)), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									}
									sub_flow_counter++;
									total_packet_counter++;
									get<2>(*index_innermost) = get<2>(*index_innermost) - 1;
									
								}
								subflow_id++;
								pending_subflows--;
								cout<<"scheduled in channel 4"<<endl;
							}
							subflow_start_time = subflow_start_time + (tg*sub_flow_counter)/2.0;
							break;
						case(3):
							size_channel.channel = 180;
							if(sub_flow_load !=0.0)
							{	
								while(sub_flow_counter<sub_flow_packets)
								{
									if(routing_algorithm == 1)
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) + ((subflow_id*tg) +(total_subflows*tg*sub_flow_counter))), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									
									}
									else
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) +subflow_start_time + (tg*sub_flow_counter)), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									}
									sub_flow_counter++;
									total_packet_counter++;
									get<2>(*index_innermost) = get<2>(*index_innermost) - 1;
									
								}
								subflow_id++;
								pending_subflows--;
								cout<<"scheduled in channel 3"<<endl;
							}
							subflow_start_time = subflow_start_time + (tg*sub_flow_counter)/2.0;
							break;
						case(2):
							size_channel.channel = 182;
							if(sub_flow_load !=0.0)
							{	
								while(sub_flow_counter<sub_flow_packets)
								{
									if(routing_algorithm == 1)
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) + ((subflow_id*tg) +(total_subflows*tg*sub_flow_counter))), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									
									}
									else
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) +subflow_start_time + (tg*sub_flow_counter)), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									}
									sub_flow_counter++;
									total_packet_counter++;
									get<2>(*index_innermost) = get<2>(*index_innermost) - 1;
									
								}
								subflow_id++;
								pending_subflows--;
								cout<<"scheduled in channel 2"<<endl;
							}
							subflow_start_time = subflow_start_time + (tg*sub_flow_counter)/2.0;
							break;
						case(1):
							size_channel.channel = 184;
							if(sub_flow_load !=0.0)
							{	
								while(sub_flow_counter<sub_flow_packets)
								{
									if(routing_algorithm == 1)
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) + ((subflow_id*tg) +(total_subflows*tg*sub_flow_counter))), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									
									}
									else
									{
										Simulator::Schedule (Seconds ((fid*tg/2*(flows)) +subflow_start_time + (tg*sub_flow_counter)), check_and_transmit, fid, source, total_packets, total_packet_counter, nid, size_channel);
										pd_all_inst[fid].pd_inst[source].pending[size_channel.channel][total_packet_counter+1] = true;
									}
									sub_flow_counter++;
									total_packet_counter++;
									get<2>(*index_innermost) = get<2>(*index_innermost) - 1;
									
								}
								subflow_id++;
								pending_subflows--;
								cout<<"scheduled in channel 1"<<endl;
							}
							subflow_start_time = subflow_start_time + (tg*sub_flow_counter)/2.0;
							break;
						default:
							break;
					
					}
				}
		  	}	
		}	

		if(total_packet_counter == total_packets)
		{
			cout<<"Flow id "<<fid<<" scheduled "<<total_packets<<"total packets from "<<source<<endl;
		}
		destination_counter[fid] = 0;
		
			
	}
		
}

void send_distributed_packets(uint32_t destination)
{
	//calculate_normalized_mobility();
	//calculate_network_contention();


	uint32_t dgcn = data_gathering_cycle_number;
	uint32_t condition1 = (dgcn/125)%2;
	uint32_t tg;
	if (condition1 == 0)
	{
		tg = 0.000040*(dgcn%125);
	}
	if (condition1 == 1)
	{
		tg = -0.000040*(dgcn%250) + 0.010;
	}
	
	uint32_t condition2 = (dgcn/50)%2;
	uint32_t x;
	if (condition2 == 0)
	{
		x = ceil((dgcn%50)/10.0);
	}
	
	if (condition2 == 1)
	{
		x = -ceil((dgcn%100)/10.0) + 10;
	}
	//x = 1;
  	Ptr <Node> nu;
	Ptr <SimpleUdpApplication> udp_app;

	for (uint32_t source=0; source<wifidevices.GetN(); source++)
  	{    
  		cout<<"dgcn is "<<dgcn<<endl;
  		cout<<"x is "<<x<<endl;
		if (source < N_Vehicles)
  		{
	  		nu = DynamicCast <Node> (Vehicle_Nodes.Get(source));	
	  		udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(source));
	  	}
	  	if (source > (N_Vehicles-1))	
	  	{
	  		nu = DynamicCast <Node> (RSU_Nodes.Get(source-N_Vehicles));	
	  		udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(source-N_Vehicles));
	  	}
  		for (uint32_t i=0; i<x;i++)
  		{		
  			uint32_t dest = (destination + source + i)%total_size;
  			//dest = total_size - 2;
  			//tg = 0.0001;
			if (dest < N_Vehicles)
			{
				Simulator::Schedule(Seconds(0.020 + tg*source),AODV_dataunicast_alone, udp_app, nu, Vehicle_Nodes.Get(dest));
			}
			
			if (dest > (N_Vehicles -1))
			{
				Simulator::Schedule(Seconds(0.020 + tg*source),AODV_dataunicast_alone, udp_app, nu, RSU_Nodes.Get(dest-N_Vehicles));
			}
		}
	} 
		
}


void distributed_dsrc_data_broadcast(Ptr <NetDevice> nd, Ptr <Node> node, uint32_t node_index)
{
	//uint32_t nid = node->GetId();
	Mac48Address dest = Mac48Address::GetBroadcast();
  	uint16_t protocolwave = 0x88dc;//ethertype for WAVE is set here.
	Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (nd);
	Ptr <Node> ni = DynamicCast <Node> (node);
	CustomDataTag tag;
	uint32_t nid = uint32_t(ni->GetId());
	if (paper == 0)
	{
		dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	}
	cout<<"DSRC data Broadcasting from node "<<nid<<endl;
	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node->GetObject<MobilityModel>());
	Vector posi = mdl->GetPosition();
	Vector current_velocity = mdl->GetVelocity();
	double delta_t = data_transmission_period;
	Vector acceleration = calculate_acceleration(previous_velocity_dsrc[node_index],current_velocity,delta_t);
	Time ti = Seconds(Simulator::Now().GetSeconds());
	Ptr <Packet> packet_i = Create<Packet> (0);
	tag.SetNodeId(nid);
	tag.SetPosition(posi);
	tag.SetVelocity(current_velocity);
	tag.SetAcceleration(acceleration);
	tag.SetTimestamp(ti);
	packet_i->AddPacketTag(tag);
	dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
	Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);	
	cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
	previous_velocity_dsrc[node_index] = current_velocity;
}


void dsrc_metadata_broadcast(Ptr <NetDevice> nd, Ptr <Node> node, uint32_t node_index)
{	
	Mac48Address dest = Mac48Address::GetBroadcast();
  	uint16_t protocolwave = 0x88dc;//ethertype for WAVE is set here.
	Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (nd);
	Ptr <Node> ni = DynamicCast <Node> (node);
	//cout<<"DSRC metadata broadcast from "<<ni->GetId();
	CustomMetaDataBroadcastTag tag;
	uint32_t nid = uint32_t(ni->GetId());
	if (nid==2)
	{
		dsrc_total_packet_size = 0;
		dsrc_initial_timestamp = Simulator::Now().GetSeconds();
	}
	packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	tag.SetNodeId(nid);
	Time ti = Seconds(Simulator::Now().GetSeconds());
	tag.SetTimestamp(ti);
	Ptr <Packet> packet_i = Create<Packet> (0);
	packet_i->AddPacketTag(tag);
	dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
	cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
	Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
}


void dsrc_metadata_broadcast_subsequent(Ptr <NetDevice> nd, Ptr <Node> node, uint32_t node_index)
{
	Ptr <Node> ni = DynamicCast <Node> (node);
	//cout<<"DSRC metadata broadcast from "<<ni->GetId();
	uint32_t nid = uint32_t(ni->GetId());
	if (X_nodes[nid] == 1)
	{
		packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
		CustomMetaDataBroadcastTag tag;
		Mac48Address dest = Mac48Address::GetBroadcast();
  		uint16_t protocolwave = 0x88dc;//ethertype for WAVE is set here.
		Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (nd);
		cout<<"subsequent metadata broadcast from "<<nid<<endl;
		tag.SetNodeId(nid);
		Time ti = Seconds(Simulator::Now().GetSeconds());
		tag.SetTimestamp(ti);
		Ptr <Packet> packet_i = Create<Packet> (0);
		packet_i->AddPacketTag(tag);
		dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
		cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
		Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);
	}
}


Vector previous_velocity_LTE[total_size];

void send_LTE_routing_data_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> node_source, Ptr <Node> destination_node, uint32_t node_index)
{
  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(2,0);//2nd IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	Ptr <Packet> packet1 = Create <Packet> (0);
	
	uint32_t nid;
        Vector posi[2];
	Vector veli[2];
	Vector acci[2];
	uint32_t nodeid[2];

	nid = uint32_t(nu->GetId()) - 2;
        posi[0] = (routing_data_at_nodes_inst+nid)->position;
	veli[0] = (routing_data_at_nodes_inst+nid)->velocity;
	acci[0] = (routing_data_at_nodes_inst+nid)->acceleration;
	nodeid[0] = (routing_data_at_nodes_inst+nid)->nodeid;
	
	CustomStatusDataUplinkTag1 tag1;
	tag1.SetNodeId(nodeid);
	tag1.Setposition(posi);
	tag1.Setvelocity(veli);
	tag1.Setacceleration(acci);

	packet1->AddPacketTag(tag1);
	//lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
		
	//cout<<"sent status data from node "<<nid<<"sent velocity"<<veli[0]<<endl;
}


void RSU_routing_statusdataunicast_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> source_node, Ptr <Node> destination_node)
{
	Ptr <Node> nu = DynamicCast <Node> (source_node);
	uint32_t nid = uint32_t(nu->GetId());
	Ptr <Packet> packet1 = Create <Packet> (0);
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
	
	//uint32_t nid;
        Vector posi[2];
	Vector veli[2];
	Vector acci[2];
	uint32_t nodeid[2];

	nid = uint32_t(nu->GetId()) - 2;
        posi[0] = (routing_data_at_nodes_inst+nid)->position;
	veli[0] = (routing_data_at_nodes_inst+nid)->velocity;
	acci[0] = (routing_data_at_nodes_inst+nid)->acceleration;
	nodeid[0] = (routing_data_at_nodes_inst+nid)->nodeid;
	
	CustomStatusDataUplinkTag1 tag1;
	tag1.SetNodeId(nodeid);
	tag1.Setposition(posi);
	tag1.Setvelocity(veli);
	tag1.Setacceleration(acci);
	
	packet1->AddPacketTag(tag1);
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
		
	//cout<<"sent status data from node "<<nid<<"sent velocity"<<veli[0]<<endl;
}


void RSU_flowdata_unicast_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> source_node, Ptr <Node> destination_node)
{
	Ptr <Node> nu = DynamicCast <Node> (source_node);
	uint32_t nid = uint32_t(nu->GetId());
	Ptr <Packet> packet1 = Create <Packet> (0);
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
	
	
        uint32_t source[2*flows];
        uint32_t destination[2*flows];
        uint32_t X[2*flows];
        uint32_t P[2*flows];
        uint32_t Q[2*flows];
	
	

	nid = uint32_t(nu->GetId()) - 2;
	for (uint32_t i=0;i< (2*flows);i++)
	{
		source[i] = (demanding_flow_struct_nodes_inst+i)->source;
		destination[i] = (demanding_flow_struct_nodes_inst+i)->destination;
		X[i] = (demanding_flow_struct_nodes_inst+i)->f_size;
		P[i] = (demanding_flow_struct_nodes_inst+i)->p_size;
		Q[i] = (demanding_flow_struct_nodes_inst+i)->qos;
	}
	
	CustomFlowDataUplinkTag1 tag1;
	tag1.Setsource(source);
	tag1.Setdestination(destination);
	tag1.SetX(X);
	tag1.SetP(P);
	tag1.SetQ(Q);
	
	packet1->AddPacketTag(tag1);
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
		
	cout<<"sent all flow data from node "<<nid<<endl;
}



void send_LTE_data_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> node_source, Ptr <Node> destination_node, uint32_t node_index)
{
  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(2,0);//2nd IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	Ptr <Packet> packet1 = Create <Packet> (0);

	//adding own data to the data_at_nodes
	uint32_t nid = uint32_t(nu->GetId());
	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node_source->GetObject<MobilityModel>());
    //Vector posi = mdl->GetPosition();
	//Vector veli = mdl->GetVelocity();
	//double delta_t = data_transmission_period;
	//Vector acci = calculate_acceleration(previous_velocity_LTE[node_index],veli,delta_t);
	//previous_velocity_LTE[node_index] = veli;
	Time ti = Seconds(Simulator::Now().GetSeconds());
	/*
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
	*/
	
	/*
	uint8_t * HMAC1 = new uint8_t[64];	
	if(routing_algorithm == 4)
	{
		std::string filename_HMAC = NS3_ROOT "/analytics/data/security_global_HMAC_data.csv";
	    string HMAC_string = read_item_from_csv(filename_HMAC, std::to_string(node_index),std::to_string(0), std::to_string(0), 3);
	    cout<<"HMAC global string is "<<HMAC_string<<endl;
		HexStringToBytes(HMAC_string, HMAC1, 64);
	}
	*/
	
	
	//add_received_data_at_nodes(data_at_nodes_inst+nid, HMAC1, posi, veli, acci, nid, neighborid, size_nei, 0);
  	//send the content at data at nodes to the mangement node
  	uint32_t size = get_size_of_data_at_nodes(data_at_nodes_inst+nid);
	uint32_t safe_size = (size > 0) ? size : 1;
  	uint32_t nodeid[safe_size];
  	uint32_t portid[safe_size];
  	uint8_t HMAC[safe_size][64];
	Vector position[safe_size];
	Vector acceleration[safe_size];
	Vector velocity[safe_size];
	Time timestamp[safe_size];

	
	for(uint32_t i=0;i<size;i++)
	{
		nodeid[i] = large;
		portid[i] = large;
		position[i] = Vector(0,0,0);
		acceleration[i] = Vector(0,0,0);
		velocity[i] = Vector(0,0,0);
		memset(HMAC[i], 0, 64);
		timestamp[i] = Simulator::Now();
	}
	
	uint32_t k=0;
	for(uint32_t i=0;i<max;i++)
	{
		if (((data_at_nodes_inst+nid)->nodeid[i] != large) and (k<size))
		{
			nodeid[k] = (data_at_nodes_inst+nid)->nodeid[i];
			portid[k] = (data_at_nodes_inst+nid)->portid[i];
			position[k] = (data_at_nodes_inst+nid)->position[i];
			velocity[k] = (data_at_nodes_inst+nid)->velocity[i];
			acceleration[k] = (data_at_nodes_inst+nid)->acceleration[i];
			timestamp[k] = (data_at_nodes_inst+nid)->timestamp[i];
			memcpy(HMAC[k], (data_at_nodes_inst+nid)->HMAC[i], 64);
			k++;
		}
		
	}
	
	Ptr <Packet> packet2 = Create <Packet> (0);
	CustomHMACTag tagHMAC;
	for(uint32_t i=0;i<size;i++)
	{
		tagHMAC.SetHMAC(HMAC[i], i);
	}
	
	tagHMAC.Setsize(size);
	tagHMAC.SetsenderId(nid);
	tagHMAC.SetNodeId(nodeid);
	tagHMAC.SetPortId(portid);
	tagHMAC.Setposition(position);
	tagHMAC.Setvelocity(velocity);
	tagHMAC.Setacceleration(acceleration);
	tagHMAC.SetTimestamp(timestamp);
	packet2->AddPacketTag(tagHMAC);
	lte_total_packet_size = lte_total_packet_size + packet2->GetSerializedSize();
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet2,dest_ip,7777);
		
	/*
	CustomDataUnicastTag1 tag1;
	CustomDataUnicastTag2 tag2;
	CustomDataUnicastTag3 tag3;
	CustomDataUnicastTag4 tag4;
	CustomDataUnicastTag5 tag5;
	CustomDataUnicastTag6 tag6;
	CustomDataUnicastTag7 tag7;
	CustomDataUnicastTag8 tag8;
	CustomDataUnicastTag9 tag9;
	CustomDataUnicastTag10 tag10;
	CustomDataUnicastTag11 tag11;
	CustomDataUnicastTag12 tag12;
	CustomDataUnicastTag13 tag13;
	CustomDataUnicastTag14 tag14;
	CustomDataUnicastTag15 tag15;
	CustomDataUnicastTag16 tag16;
	CustomDataUnicastTag17 tag17;
	CustomDataUnicastTag18 tag18;
	CustomDataUnicastTag19 tag19;
	CustomDataUnicastTag20 tag20;
	CustomDataUnicastTag21 tag21;
	CustomDataUnicastTag22 tag22;
	CustomDataUnicastTag23 tag23;
	CustomDataUnicastTag24 tag24;
	CustomDataUnicastTag25 tag25;
	CustomDataUnicastTag tag;
	switch (size)
	{	
		case 1:
			tag1.SetsenderId(nid);
			tag1.SetNodeId(nodeid);
			tag1.SetPortId(portid);
			tag1.Setposition(position);
			tag1.Setvelocity(velocity);
			tag1.Setacceleration(acceleration);
			tag1.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag1);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 2:
			tag2.SetsenderId(nid);
			tag2.SetNodeId(nodeid);
			tag2.SetPortId(portid);
			tag2.Setposition(position);
			tag2.Setvelocity(velocity);
			tag2.Setacceleration(acceleration);
			tag2.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag2);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 3:
			tag3.SetsenderId(nid);
			tag3.SetPortId(portid);
			tag3.SetNodeId(nodeid);
			tag3.Setposition(position);
			tag3.Setvelocity(velocity);
			tag3.Setacceleration(acceleration);
			tag3.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag3);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 4:
			tag4.SetsenderId(nid);
			tag4.SetNodeId(nodeid);
			tag4.SetPortId(portid);
			tag4.Setposition(position);
			tag4.Setvelocity(velocity);
			tag4.Setacceleration(acceleration);
			tag4.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag4);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 5:
			tag5.SetsenderId(nid);
			tag5.SetNodeId(nodeid);
			tag5.SetPortId(portid);
			tag5.Setposition(position);
			tag5.Setvelocity(velocity);
			tag5.Setacceleration(acceleration);
			tag5.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag5);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 6:
			tag6.SetsenderId(nid);
			tag6.SetNodeId(nodeid);
			tag6.SetPortId(portid);
			tag6.Setposition(position);
			tag6.Setvelocity(velocity);
			tag6.Setacceleration(acceleration);
			tag6.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag6);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 7:
			tag7.SetsenderId(nid);
			tag7.SetNodeId(nodeid);
			tag7.SetPortId(portid);
			tag7.Setposition(position);
			tag7.Setvelocity(velocity);
			tag7.Setacceleration(acceleration);
			tag7.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag7);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 8:
			tag8.SetsenderId(nid);
			tag8.SetNodeId(nodeid);
			tag8.SetPortId(portid);
			tag8.Setposition(position);
			tag8.Setvelocity(velocity);
			tag8.Setacceleration(acceleration);
			tag8.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag8);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 9:
			tag9.SetsenderId(nid);
			tag9.SetNodeId(nodeid);
			tag9.SetPortId(portid);
			tag9.Setposition(position);
			tag9.Setvelocity(velocity);
			tag9.Setacceleration(acceleration);
			tag9.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag9);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		
		case 10:
			tag10.SetsenderId(nid);
			tag10.SetNodeId(nodeid);
			tag10.SetPortId(portid);
			tag10.Setposition(position);
			tag10.Setvelocity(velocity);
			tag10.Setacceleration(acceleration);
			tag10.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag10);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 11:
			tag11.SetsenderId(nid);
			tag11.SetPortId(portid);
			tag11.SetNodeId(nodeid);
			tag11.Setposition(position);
			tag11.Setvelocity(velocity);
			tag11.Setacceleration(acceleration);
			tag11.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag11);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 12:
			tag12.SetsenderId(nid);
			tag12.SetPortId(portid);
			tag12.SetNodeId(nodeid);
			tag12.Setposition(position);
			tag12.Setvelocity(velocity);
			tag12.Setacceleration(acceleration);
			tag12.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag12);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 13:
			tag13.SetsenderId(nid);
			tag13.SetNodeId(nodeid);
			tag13.SetPortId(portid);
			tag13.Setposition(position);
			tag13.Setvelocity(velocity);
			tag13.Setacceleration(acceleration);
			tag13.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag13);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;	
		case 14:
			tag14.SetsenderId(nid);
			tag14.SetNodeId(nodeid);
			tag14.SetPortId(portid);
			tag14.Setposition(position);
			tag14.Setvelocity(velocity);
			tag14.Setacceleration(acceleration);
			tag14.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag14);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 15:
			tag15.SetsenderId(nid);
			tag15.SetNodeId(nodeid);
			tag15.SetPortId(portid);
			tag15.Setposition(position);
			tag15.Setvelocity(velocity);
			tag15.Setacceleration(acceleration);
			tag15.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag15);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;

		case 16:
			tag16.SetsenderId(nid);
			tag16.SetNodeId(nodeid);
			tag16.SetPortId(portid);
			tag16.Setposition(position);
			tag16.Setvelocity(velocity);
			tag16.Setacceleration(acceleration);
			tag16.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag16);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 17:
			tag17.SetsenderId(nid);
			tag17.SetNodeId(nodeid);
			tag17.SetPortId(portid);
			tag17.Setposition(position);
			tag17.Setvelocity(velocity);
			tag17.Setacceleration(acceleration);
			tag17.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag17);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 18:
			tag18.SetsenderId(nid);	
			tag18.SetNodeId(nodeid);
			tag18.SetPortId(portid);
			tag18.Setposition(position);
			tag18.Setvelocity(velocity);
			tag18.Setacceleration(acceleration);
			tag18.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag18);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 19:
			tag19.SetsenderId(nid);
			tag19.SetNodeId(nodeid);
			tag19.SetPortId(portid);
			tag19.Setposition(position);
			tag19.Setvelocity(velocity);
			tag19.Setacceleration(acceleration);
			tag19.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag19);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 20:
			tag20.SetsenderId(nid);
			tag20.SetNodeId(nodeid);
			tag20.SetPortId(portid);
			tag20.Setposition(position);
			tag20.Setvelocity(velocity);
			tag20.Setacceleration(acceleration);
			tag20.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag20);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 21:
			tag21.SetsenderId(nid);
			tag21.SetNodeId(nodeid);
			tag21.SetPortId(portid);
			tag21.Setposition(position);
			tag21.Setvelocity(velocity);
			tag21.Setacceleration(acceleration);
			tag21.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag21);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 22:
			tag22.SetsenderId(nid);
			tag22.SetNodeId(nodeid);
			tag22.SetPortId(portid);
			tag22.Setposition(position);
			tag22.Setvelocity(velocity);
			tag22.Setacceleration(acceleration);
			tag22.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag22);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 23:
			tag23.SetsenderId(nid);
			tag23.SetNodeId(nodeid);
			tag23.SetPortId(portid);
			tag23.Setposition(position);
			tag23.Setvelocity(velocity);
			tag23.Setacceleration(acceleration);
			tag23.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag23);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 24:
			tag24.SetsenderId(nid);
			tag24.SetNodeId(nodeid);
			tag24.Setposition(position);
			tag24.Setvelocity(velocity);
			tag24.Setacceleration(acceleration);
			tag24.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag24);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 25:
			tag25.SetsenderId(nid);
			tag25.SetPortId(portid);
			tag25.SetNodeId(nodeid);
			tag25.Setposition(position);
			tag25.Setvelocity(velocity);
			tag25.Setacceleration(acceleration);
			tag25.SetTimestamp(timestamp);
			packet1->AddPacketTag(tag25);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		default:
			cout<<"Cellular:maximum status datasize exceeded . size is  "<<size<<endl;
			tag.SetsenderId(nid);
			tag.SetPortId((data_at_nodes_inst+nid)->portid);
			tag.SetNodeId((data_at_nodes_inst+nid)->nodeid);
			tag.Setposition((data_at_nodes_inst+nid)->position);
			tag.Setvelocity((data_at_nodes_inst+nid)->velocity);
			tag.Setacceleration((data_at_nodes_inst+nid)->acceleration);
			tag.SetTimestamp((data_at_nodes_inst+nid)->timestamp);
			packet1->AddPacketTag(tag);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0.001),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;	
	}
	*/
	cout<<"lte total packet size is "<<lte_total_packet_size<<endl;
}




void send_LTE_data_agent(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> node_source, Ptr <Node> destination_node, uint32_t node_index)
{
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	uint32_t nid = uint32_t(nu->GetId());
	if (X_nodes[nid] == 1)
	{
	
		/*
		Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node_source->GetObject<MobilityModel>());
        Vector posi = mdl->GetPosition();
		Vector veli = mdl->GetVelocity();
		double delta_t = data_transmission_period;
		Vector acci = calculate_acceleration(previous_velocity_LTE[node_index],veli,delta_t);
		previous_velocity_LTE[node_index] = veli;
		//adding own data to the data_at_nodes
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
		uint8_t * HMAC1 = new uint8_t[64];	
		if(routing_algorithm == 4)
		{
			std::string filename_HMAC = NS3_ROOT "/analytics/data/security_global_HMAC_data.csv";
			string HMAC_string = read_item_from_csv(filename_HMAC, std::to_string(node_index), 1);
			cout<<"HMAC global string is "<<HMAC_string<<endl;
			HexStringToBytes(HMAC_string, HMAC1, 64);
			
		}
		*/
		
		//add_received_data_at_nodes(data_at_nodes_inst+nid, HMAC1, posi, veli, acci, nid, neighborid, size_nei, 0);
	  	//send the content at data at nodes to the mangement node
	  	uint32_t size = get_size_of_data_at_nodes(data_at_nodes_inst+nid);
		uint32_t safe_size = (size > 0) ? size : 1;
	  	uint32_t nodeid[safe_size];
		Vector position[safe_size];
		Vector acceleration[safe_size];
		Vector velocity[safe_size];
		Time timestamp[safe_size];
		struct set_of_neighbors neighbor_set[safe_size];
		bool neighbors_changed[safe_size];
		
		for(uint32_t i=0;i<size;i++)
		{
			nodeid[i] = large;
			position[i] = Vector(0,0,0);
			acceleration[i] = Vector(0,0,0);
			velocity[i] = Vector(0,0,0);
			timestamp[i] = Simulator::Now();
			for (uint32_t j=0;j<max;j++)
			{
				neighbor_set[i].neighbors[j] = large;
			}
			neighbors_changed[i] = false;
		}
		
		uint32_t k=0;
		for(uint32_t i=0;i<max;i++)
		{
			if (((data_at_nodes_inst+nid)->nodeid[i] != large) and (k<size))
			{
				nodeid[k] = (data_at_nodes_inst+nid)->nodeid[i];
				position[k] = (data_at_nodes_inst+nid)->position[i];
				velocity[k] = (data_at_nodes_inst+nid)->velocity[i];
				acceleration[k] = (data_at_nodes_inst+nid)->acceleration[i];
				timestamp[k] = (data_at_nodes_inst+nid)->timestamp[i];
				neighbor_set[k] = (data_at_nodes_inst+nid)->neighbor_set[i];
				neighbors_changed[k] = (data_at_nodes_inst+nid)->neighbors_changed[i];
				k++;
			}
			
		}
		
		uint32_t nei_sizes[max];
		for(uint32_t i=0;i<max;i++)
		{
			nei_sizes[i] = 0;
		}
		
		for(uint32_t i=0;i<size;i++)
		{
			for(uint32_t j=0;j<max;j++)
			{

				if((neighbor_set[i].neighbors[j]) != large)
				{
					nei_sizes[i] = nei_sizes[i] + 1;
				}	
			}
		}
		/*
		for(uint32_t i=0;i<max;i++)
		{
			cout<<"neighbor sizes of agent "<<nid<<"is "<<nei_sizes[i]<<endl;
		}
		*/
		
		
		Ptr <Ipv4> ipv4;  	
	  	ipv4 = destination_node->GetObject<Ipv4>();
		Ipv4InterfaceAddress iaddr = ipv4->GetAddress(2,0);//2nd IPv4 interface,0th address index
		Ipv4Address dest_ip = iaddr.GetLocal();
		Ptr <Packet> packet1 = Create <Packet> (0);
		
		

		CustomMetaDataUnicastTagN011 tagN011;
		CustomMetaDataUnicastTagN012 tagN012;
		CustomMetaDataUnicastTagN013 tagN013;
		CustomMetaDataUnicastTagN014 tagN014;
		CustomMetaDataUnicastTagN015 tagN015;
		CustomMetaDataUnicastTagN016 tagN016;
		CustomMetaDataUnicastTagN017 tagN017;
		CustomMetaDataUnicastTagN018 tagN018;
		CustomMetaDataUnicastTagN019 tagN019;
		CustomMetaDataUnicastTagN0110 tagN0110;
		CustomMetaDataUnicastTagN0111 tagN0111;
		CustomMetaDataUnicastTagN0112 tagN0112;
		CustomMetaDataUnicastTagN0113 tagN0113;
		CustomMetaDataUnicastTagN0114 tagN0114;
		CustomMetaDataUnicastTagN0115 tagN0115;
		CustomMetaDataUnicastTagN0116 tagN0116;
		CustomMetaDataUnicastTagN0117 tagN0117;
		CustomMetaDataUnicastTagN0118 tagN0118;
		CustomMetaDataUnicastTagN0119 tagN0119;
		CustomMetaDataUnicastTagN0120 tagN0120;
		CustomMetaDataUnicastTagN0121 tagN0121;
		CustomMetaDataUnicastTagN0122 tagN0122;
		CustomMetaDataUnicastTagN0123 tagN0123;
		CustomMetaDataUnicastTagN0124 tagN0124;
		CustomMetaDataUnicastTagN0125 tagN0125;
		CustomMetaDataUnicastTagN01max tagN01max;
		
		if ((nei_sizes[0] > 0) and (neighbors_changed[0]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[0] = false;
			switch(nei_sizes[0])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[0].neighbors[0];
					tagN011.Setneighborid(new_neighborset1);
					tagN011.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN011);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[0].neighbors[i];
					}
					tagN012.Setneighborid(new_neighborset2);
					tagN012.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN012);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[0].neighbors[i];
					}
					tagN013.Setneighborid(new_neighborset3);
					tagN013.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN013);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[0].neighbors[i];
					}
					tagN014.Setneighborid(new_neighborset4);
					tagN014.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN014);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[0].neighbors[i];
					}
					tagN015.Setneighborid(new_neighborset5);
					tagN015.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN015);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[0].neighbors[i];
					}
					tagN016.Setneighborid(new_neighborset6);
					tagN016.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN016);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[0].neighbors[i];
					}
					tagN017.Setneighborid(new_neighborset7);
					tagN017.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN017);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[0].neighbors[i];
					}
					tagN018.Setneighborid(new_neighborset8);
					tagN018.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN018);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[0].neighbors[i];
					}
					tagN019.Setneighborid(new_neighborset9);
					tagN019.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN019);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[0].neighbors[i];
					}
					tagN0110.Setneighborid(new_neighborset10);
					tagN0110.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0110);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[0].neighbors[i];
					}
					tagN0111.Setneighborid(new_neighborset11);
					tagN0111.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0111);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[0].neighbors[i];
					}
					tagN0112.Setneighborid(new_neighborset12);
					tagN0112.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0112);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[0].neighbors[i];
					}
					tagN0113.Setneighborid(new_neighborset13);
					tagN0113.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0113);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[0].neighbors[i];
					}
					tagN0114.Setneighborid(new_neighborset14);
					tagN0114.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0114);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[0].neighbors[i];
					}
					tagN0115.Setneighborid(new_neighborset15);
					tagN0115.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0115);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[0].neighbors[i];
					}
					tagN0116.Setneighborid(new_neighborset16);
					tagN0116.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0116);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[0].neighbors[i];
					}
					tagN0117.Setneighborid(new_neighborset17);
					tagN0117.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0117);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[0].neighbors[i];
					}
					tagN0118.Setneighborid(new_neighborset18);
					tagN0118.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0118);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[0].neighbors[i];
					}
					tagN0119.Setneighborid(new_neighborset19);
					tagN0119.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0119);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[0].neighbors[i];
					}
					tagN0120.Setneighborid(new_neighborset20);
					tagN0120.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0120);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[0].neighbors[i];
					}
					tagN0121.Setneighborid(new_neighborset21);
					tagN0121.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0121);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[0].neighbors[i];
					}
					tagN0122.Setneighborid(new_neighborset22);
					tagN0122.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0122);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[0].neighbors[i];
					}
					tagN0123.Setneighborid(new_neighborset23);
					tagN0123.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0123);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[0].neighbors[i];
					}
					tagN0124.Setneighborid(new_neighborset24);
					tagN0124.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0124);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[0].neighbors[i];
					}
					tagN0125.Setneighborid(new_neighborset25);
					tagN0125.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0125);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[0]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[0])
						{
							new_neighborsetmax[i] = neighbor_set[0].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN01max.Setneighborid(new_neighborsetmax);
					tagN01max.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN01max);
					break;
			}
		}
		
	

		CustomMetaDataUnicastTagN021 tagN021;
		CustomMetaDataUnicastTagN022 tagN022;
		CustomMetaDataUnicastTagN023 tagN023;
		CustomMetaDataUnicastTagN024 tagN024;
		CustomMetaDataUnicastTagN025 tagN025;
		CustomMetaDataUnicastTagN026 tagN026;
		CustomMetaDataUnicastTagN027 tagN027;
		CustomMetaDataUnicastTagN028 tagN028;
		CustomMetaDataUnicastTagN029 tagN029;
		CustomMetaDataUnicastTagN0210 tagN0210;
		CustomMetaDataUnicastTagN0211 tagN0211;
		CustomMetaDataUnicastTagN0212 tagN0212;
		CustomMetaDataUnicastTagN0213 tagN0213;
		CustomMetaDataUnicastTagN0214 tagN0214;
		CustomMetaDataUnicastTagN0215 tagN0215;
		CustomMetaDataUnicastTagN0216 tagN0216;
		CustomMetaDataUnicastTagN0217 tagN0217;
		CustomMetaDataUnicastTagN0218 tagN0218;
		CustomMetaDataUnicastTagN0219 tagN0219;
		CustomMetaDataUnicastTagN0220 tagN0220;
		CustomMetaDataUnicastTagN0221 tagN0221;
		CustomMetaDataUnicastTagN0222 tagN0222;
		CustomMetaDataUnicastTagN0223 tagN0223;
		CustomMetaDataUnicastTagN0224 tagN0224;
		CustomMetaDataUnicastTagN0225 tagN0225;
		CustomMetaDataUnicastTagN2max tagN2max;
		
		if ((nei_sizes[1] > 0)and (neighbors_changed[1]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[1] = false;
			switch(nei_sizes[1])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[1].neighbors[0];
					tagN021.Setneighborid(new_neighborset1);
					tagN021.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN021);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[1].neighbors[i];
					}
					tagN022.Setneighborid(new_neighborset2);
					tagN022.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN022);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[1].neighbors[i];
					}
					tagN023.Setneighborid(new_neighborset3);
					tagN023.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN023);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[1].neighbors[i];
					}
					tagN024.Setneighborid(new_neighborset4);
					tagN024.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN024);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[1].neighbors[i];
					}
					tagN025.Setneighborid(new_neighborset5);
					tagN025.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN025);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[1].neighbors[i];
					}
					tagN026.Setneighborid(new_neighborset6);
					tagN026.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN026);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[1].neighbors[i];
					}
					tagN027.Setneighborid(new_neighborset7);
					tagN027.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN027);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[1].neighbors[i];
					}
					tagN028.Setneighborid(new_neighborset8);
					tagN028.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN028);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[1].neighbors[i];
					}
					tagN029.Setneighborid(new_neighborset9);
					tagN029.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN029);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[1].neighbors[i];
					}
					tagN0210.Setneighborid(new_neighborset10);
					tagN0210.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0210);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[1].neighbors[i];
					}
					tagN0211.Setneighborid(new_neighborset11);
					tagN0211.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0211);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[1].neighbors[i];
					}
					tagN0212.Setneighborid(new_neighborset12);
					tagN0212.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0212);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[1].neighbors[i];
					}
					tagN0213.Setneighborid(new_neighborset13);
					tagN0213.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0213);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[1].neighbors[i];
					}
					tagN0214.Setneighborid(new_neighborset14);
					tagN0214.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0214);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[1].neighbors[i];
					}
					tagN0215.Setneighborid(new_neighborset15);
					tagN0215.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0215);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[1].neighbors[i];
					}
					tagN0216.Setneighborid(new_neighborset16);
					tagN0216.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0216);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[1].neighbors[i];
					}
					tagN0217.Setneighborid(new_neighborset17);
					tagN0217.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0217);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[1].neighbors[i];
					}
					tagN0218.Setneighborid(new_neighborset18);
					tagN0218.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0218);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[1].neighbors[i];
					}
					tagN0219.Setneighborid(new_neighborset19);
					tagN0219.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0219);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[1].neighbors[i];
					}
					tagN0220.Setneighborid(new_neighborset20);
					tagN0220.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0220);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[1].neighbors[i];
					}
					tagN0221.Setneighborid(new_neighborset21);
					tagN0221.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0221);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[1].neighbors[i];
					}
					tagN0222.Setneighborid(new_neighborset22);
					tagN0222.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0222);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[1].neighbors[i];
					}
					tagN0223.Setneighborid(new_neighborset23);
					tagN0223.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0223);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[1].neighbors[i];
					}
					tagN0224.Setneighborid(new_neighborset24);
					tagN0224.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0224);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[1].neighbors[i];
					}
					tagN0225.Setneighborid(new_neighborset25);
					tagN0225.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0225);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[1]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[1])
						{
							new_neighborsetmax[i] = neighbor_set[1].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN2max.Setneighborid(new_neighborsetmax);
					tagN2max.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN2max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN31 tagN31;
		CustomMetaDataUnicastTagN32 tagN32;
		CustomMetaDataUnicastTagN33 tagN33;
		CustomMetaDataUnicastTagN34 tagN34;
		CustomMetaDataUnicastTagN35 tagN35;
		CustomMetaDataUnicastTagN36 tagN36;
		CustomMetaDataUnicastTagN37 tagN37;
		CustomMetaDataUnicastTagN38 tagN38;
		CustomMetaDataUnicastTagN39 tagN39;
		CustomMetaDataUnicastTagN310 tagN310;
		CustomMetaDataUnicastTagN311 tagN311;
		CustomMetaDataUnicastTagN312 tagN312;
		CustomMetaDataUnicastTagN313 tagN313;
		CustomMetaDataUnicastTagN314 tagN314;
		CustomMetaDataUnicastTagN315 tagN315;
		CustomMetaDataUnicastTagN316 tagN316;
		CustomMetaDataUnicastTagN317 tagN317;
		CustomMetaDataUnicastTagN318 tagN318;
		CustomMetaDataUnicastTagN319 tagN319;
		CustomMetaDataUnicastTagN320 tagN320;
		CustomMetaDataUnicastTagN321 tagN321;
		CustomMetaDataUnicastTagN322 tagN322;
		CustomMetaDataUnicastTagN323 tagN323;
		CustomMetaDataUnicastTagN324 tagN324;
		CustomMetaDataUnicastTagN325 tagN325;
		CustomMetaDataUnicastTagN3max tagN3max;
		
		if ((nei_sizes[2] > 0)and (neighbors_changed[2]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[2] = false;
			switch(nei_sizes[2])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[2].neighbors[0];
					tagN31.Setneighborid(new_neighborset1);
					tagN31.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN31);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[2].neighbors[i];
					}
					tagN32.Setneighborid(new_neighborset2);
					tagN32.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN32);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[2].neighbors[i];
					}
					tagN33.Setneighborid(new_neighborset3);
					tagN33.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN33);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[2].neighbors[i];
					}
					tagN34.Setneighborid(new_neighborset4);
					tagN34.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN34);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[2].neighbors[i];
					}
					tagN35.Setneighborid(new_neighborset5);
					tagN35.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN35);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[2].neighbors[i];
					}
					tagN36.Setneighborid(new_neighborset6);
					tagN36.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN36);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[2].neighbors[i];
					}
					tagN37.Setneighborid(new_neighborset7);
					tagN37.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN37);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[2].neighbors[i];
					}
					tagN38.Setneighborid(new_neighborset8);
					tagN38.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN38);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[2].neighbors[i];
					}
					tagN39.Setneighborid(new_neighborset9);
					tagN39.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN39);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[2].neighbors[i];
					}
					tagN310.Setneighborid(new_neighborset10);
					tagN310.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN310);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[2].neighbors[i];
					}
					tagN311.Setneighborid(new_neighborset11);
					tagN311.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN311);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[2].neighbors[i];
					}
					tagN312.Setneighborid(new_neighborset12);
					tagN312.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN312);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[2].neighbors[i];
					}
					tagN313.Setneighborid(new_neighborset13);
					tagN313.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN313);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[2].neighbors[i];
					}
					tagN314.Setneighborid(new_neighborset14);
					tagN314.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN314);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[2].neighbors[i];
					}
					tagN315.Setneighborid(new_neighborset15);
					tagN315.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN315);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[2].neighbors[i];
					}
					tagN316.Setneighborid(new_neighborset16);
					tagN316.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN316);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[2].neighbors[i];
					}
					tagN317.Setneighborid(new_neighborset17);
					tagN317.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN317);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[2].neighbors[i];
					}
					tagN318.Setneighborid(new_neighborset18);
					tagN318.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN318);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[2].neighbors[i];
					}
					tagN319.Setneighborid(new_neighborset19);
					tagN319.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN319);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[2].neighbors[i];
					}
					tagN320.Setneighborid(new_neighborset20);
					tagN320.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN320);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[2].neighbors[i];
					}
					tagN321.Setneighborid(new_neighborset21);
					tagN321.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN321);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[2].neighbors[i];
					}
					tagN322.Setneighborid(new_neighborset22);
					tagN322.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN322);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[2].neighbors[i];
					}
					tagN323.Setneighborid(new_neighborset23);
					tagN323.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN323);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[2].neighbors[i];
					}
					tagN324.Setneighborid(new_neighborset24);
					tagN324.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN324);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[2].neighbors[i];
					}
					tagN325.Setneighborid(new_neighborset25);
					tagN325.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN325);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[2]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[2])
						{
							new_neighborsetmax[i] = neighbor_set[2].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN3max.Setneighborid(new_neighborsetmax);
					tagN3max.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN3max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN41 tagN41;
		CustomMetaDataUnicastTagN42 tagN42;
		CustomMetaDataUnicastTagN43 tagN43;
		CustomMetaDataUnicastTagN44 tagN44;
		CustomMetaDataUnicastTagN45 tagN45;
		CustomMetaDataUnicastTagN46 tagN46;
		CustomMetaDataUnicastTagN47 tagN47;
		CustomMetaDataUnicastTagN48 tagN48;
		CustomMetaDataUnicastTagN49 tagN49;
		CustomMetaDataUnicastTagN410 tagN410;
		CustomMetaDataUnicastTagN411 tagN411;
		CustomMetaDataUnicastTagN412 tagN412;
		CustomMetaDataUnicastTagN413 tagN413;
		CustomMetaDataUnicastTagN414 tagN414;
		CustomMetaDataUnicastTagN415 tagN415;
		CustomMetaDataUnicastTagN416 tagN416;
		CustomMetaDataUnicastTagN417 tagN417;
		CustomMetaDataUnicastTagN418 tagN418;
		CustomMetaDataUnicastTagN419 tagN419;
		CustomMetaDataUnicastTagN420 tagN420;
		CustomMetaDataUnicastTagN421 tagN421;
		CustomMetaDataUnicastTagN422 tagN422;
		CustomMetaDataUnicastTagN423 tagN423;
		CustomMetaDataUnicastTagN424 tagN424;
		CustomMetaDataUnicastTagN425 tagN425;
		CustomMetaDataUnicastTagN4max tagN4max;
		
		if ((nei_sizes[3] > 0)and (neighbors_changed[3]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[3] = false;
			switch(nei_sizes[3])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[3].neighbors[0];
					tagN41.Setneighborid(new_neighborset1);
					tagN41.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN41);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[3].neighbors[i];
					}
					tagN42.Setneighborid(new_neighborset2);
					tagN42.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN42);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[3].neighbors[i];
					}
					tagN43.Setneighborid(new_neighborset3);
					tagN43.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN43);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[3].neighbors[i];
					}
					tagN44.Setneighborid(new_neighborset4);
					tagN44.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN44);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[3].neighbors[i];
					}
					tagN45.Setneighborid(new_neighborset5);
					tagN45.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN45);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[3].neighbors[i];
					}
					tagN46.Setneighborid(new_neighborset6);
					tagN46.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN46);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[3].neighbors[i];
					}
					tagN47.Setneighborid(new_neighborset7);
					tagN47.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN47);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[3].neighbors[i];
					}
					tagN48.Setneighborid(new_neighborset8);
					tagN48.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN48);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[3].neighbors[i];
					}
					tagN49.Setneighborid(new_neighborset9);
					tagN49.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN49);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[3].neighbors[i];
					}
					tagN410.Setneighborid(new_neighborset10);
					tagN410.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN410);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[3].neighbors[i];
					}
					tagN411.Setneighborid(new_neighborset11);
					tagN411.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN411);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[3].neighbors[i];
					}
					tagN412.Setneighborid(new_neighborset12);
					tagN412.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN412);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[3].neighbors[i];
					}
					tagN413.Setneighborid(new_neighborset13);
					tagN413.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN413);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[3].neighbors[i];
					}
					tagN414.Setneighborid(new_neighborset14);
					tagN414.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN414);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[3].neighbors[i];
					}
					tagN415.Setneighborid(new_neighborset15);
					tagN415.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN415);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[3].neighbors[i];
					}
					tagN416.Setneighborid(new_neighborset16);
					tagN416.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN416);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[3].neighbors[i];
					}
					tagN417.Setneighborid(new_neighborset17);
					tagN417.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN417);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[3].neighbors[i];
					}
					tagN418.Setneighborid(new_neighborset18);
					tagN418.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN418);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[3].neighbors[i];
					}
					tagN419.Setneighborid(new_neighborset19);
					tagN419.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN419);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[3].neighbors[i];
					}
					tagN420.Setneighborid(new_neighborset20);
					tagN420.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN420);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[3].neighbors[i];
					}
					tagN421.Setneighborid(new_neighborset21);
					tagN421.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN421);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[3].neighbors[i];
					}
					tagN422.Setneighborid(new_neighborset22);
					tagN422.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN422);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[3].neighbors[i];
					}
					tagN423.Setneighborid(new_neighborset23);
					tagN423.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN423);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[3].neighbors[i];
					}
					tagN424.Setneighborid(new_neighborset24);
					tagN424.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN424);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[3].neighbors[i];
					}
					tagN425.Setneighborid(new_neighborset25);
					tagN425.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN425);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[3]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[3])
						{
							new_neighborsetmax[i] = neighbor_set[3].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN4max.Setneighborid(new_neighborsetmax);
					tagN4max.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN4max);
					break;
			}
		
		}
		
		
		
		CustomMetaDataUnicastTagN51 tagN51;
		CustomMetaDataUnicastTagN52 tagN52;
		CustomMetaDataUnicastTagN53 tagN53;
		CustomMetaDataUnicastTagN54 tagN54;
		CustomMetaDataUnicastTagN55 tagN55;
		CustomMetaDataUnicastTagN56 tagN56;
		CustomMetaDataUnicastTagN57 tagN57;
		CustomMetaDataUnicastTagN58 tagN58;
		CustomMetaDataUnicastTagN59 tagN59;
		CustomMetaDataUnicastTagN510 tagN510;
		CustomMetaDataUnicastTagN511 tagN511;
		CustomMetaDataUnicastTagN512 tagN512;
		CustomMetaDataUnicastTagN513 tagN513;
		CustomMetaDataUnicastTagN514 tagN514;
		CustomMetaDataUnicastTagN515 tagN515;
		CustomMetaDataUnicastTagN516 tagN516;
		CustomMetaDataUnicastTagN517 tagN517;
		CustomMetaDataUnicastTagN518 tagN518;
		CustomMetaDataUnicastTagN519 tagN519;
		CustomMetaDataUnicastTagN520 tagN520;
		CustomMetaDataUnicastTagN521 tagN521;
		CustomMetaDataUnicastTagN522 tagN522;
		CustomMetaDataUnicastTagN523 tagN523;
		CustomMetaDataUnicastTagN524 tagN524;
		CustomMetaDataUnicastTagN525 tagN525;
		CustomMetaDataUnicastTagN5max tagN5max;
		
		if ((nei_sizes[4] > 0) and (neighbors_changed[4]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[4] = false;
			switch(nei_sizes[4])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[4].neighbors[0];
					tagN51.Setneighborid(new_neighborset1);
					tagN51.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN51);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[4].neighbors[i];
					}
					tagN52.Setneighborid(new_neighborset2);
					tagN52.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN52);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[4].neighbors[i];
					}
					tagN53.Setneighborid(new_neighborset3);
					tagN53.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN53);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[4].neighbors[i];
					}
					tagN54.Setneighborid(new_neighborset4);
					tagN54.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN54);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[4].neighbors[i];
					}
					tagN55.Setneighborid(new_neighborset5);
					tagN55.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN55);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[4].neighbors[i];
					}
					tagN56.Setneighborid(new_neighborset6);
					tagN56.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN56);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[4].neighbors[i];
					}
					tagN57.Setneighborid(new_neighborset7);
					tagN57.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN57);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[4].neighbors[i];
					}
					tagN58.Setneighborid(new_neighborset8);
					tagN58.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN58);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[4].neighbors[i];
					}
					tagN59.Setneighborid(new_neighborset9);
					tagN59.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN59);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[4].neighbors[i];
					}
					tagN510.Setneighborid(new_neighborset10);
					tagN510.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN510);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[4].neighbors[i];
					}
					tagN511.Setneighborid(new_neighborset11);
					tagN511.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN511);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[4].neighbors[i];
					}
					tagN512.Setneighborid(new_neighborset12);
					tagN512.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN512);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[4].neighbors[i];
					}
					tagN513.Setneighborid(new_neighborset13);
					tagN513.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN513);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[4].neighbors[i];
					}
					tagN514.Setneighborid(new_neighborset14);
					tagN514.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN514);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[4].neighbors[i];
					}
					tagN515.Setneighborid(new_neighborset15);
					tagN515.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN515);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[4].neighbors[i];
					}
					tagN516.Setneighborid(new_neighborset16);
					tagN516.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN516);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[4].neighbors[i];
					}
					tagN517.Setneighborid(new_neighborset17);
					tagN517.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN517);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[4].neighbors[i];
					}
					tagN518.Setneighborid(new_neighborset18);
					tagN518.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN518);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[4].neighbors[i];
					}
					tagN519.Setneighborid(new_neighborset19);
					tagN519.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN519);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[4].neighbors[i];
					}
					tagN520.Setneighborid(new_neighborset20);
					tagN520.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN520);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[4].neighbors[i];
					}
					tagN521.Setneighborid(new_neighborset21);
					tagN521.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN521);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[4].neighbors[i];
					}
					tagN522.Setneighborid(new_neighborset22);
					tagN522.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN522);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[4].neighbors[i];
					}
					tagN523.Setneighborid(new_neighborset23);
					tagN523.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN523);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[4].neighbors[i];
					}
					tagN524.Setneighborid(new_neighborset24);
					tagN524.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN524);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[4].neighbors[i];
					}
					tagN525.Setneighborid(new_neighborset25);
					tagN525.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN525);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[4]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[4])
						{
							new_neighborsetmax[i] = neighbor_set[4].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN5max.Setneighborid(new_neighborsetmax);
					tagN5max.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN5max);
					break;
			}
		
		}		

		CustomMetaDataUnicastTagN61 tagN61;
		CustomMetaDataUnicastTagN62 tagN62;
		CustomMetaDataUnicastTagN63 tagN63;
		CustomMetaDataUnicastTagN64 tagN64;
		CustomMetaDataUnicastTagN65 tagN65;
		CustomMetaDataUnicastTagN66 tagN66;
		CustomMetaDataUnicastTagN67 tagN67;
		CustomMetaDataUnicastTagN68 tagN68;
		CustomMetaDataUnicastTagN69 tagN69;
		CustomMetaDataUnicastTagN610 tagN610;
		CustomMetaDataUnicastTagN611 tagN611;
		CustomMetaDataUnicastTagN612 tagN612;
		CustomMetaDataUnicastTagN613 tagN613;
		CustomMetaDataUnicastTagN614 tagN614;
		CustomMetaDataUnicastTagN615 tagN615;
		CustomMetaDataUnicastTagN616 tagN616;
		CustomMetaDataUnicastTagN617 tagN617;
		CustomMetaDataUnicastTagN618 tagN618;
		CustomMetaDataUnicastTagN619 tagN619;
		CustomMetaDataUnicastTagN620 tagN620;
		CustomMetaDataUnicastTagN621 tagN621;
		CustomMetaDataUnicastTagN622 tagN622;
		CustomMetaDataUnicastTagN623 tagN623;
		CustomMetaDataUnicastTagN624 tagN624;
		CustomMetaDataUnicastTagN625 tagN625;
		CustomMetaDataUnicastTagN6max tagN6max;
		
		if ((nei_sizes[5] > 0)and (neighbors_changed[5]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[5] = false;
			switch(nei_sizes[5])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[5].neighbors[0];
					tagN61.Setneighborid(new_neighborset1);
					tagN61.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN61);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[5].neighbors[i];
					}
					tagN62.Setneighborid(new_neighborset2);
					tagN62.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN62);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[5].neighbors[i];
					}
					tagN63.Setneighborid(new_neighborset3);
					tagN63.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN63);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[5].neighbors[i];
					}
					tagN64.Setneighborid(new_neighborset4);
					tagN64.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN64);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[5].neighbors[i];
					}
					tagN65.Setneighborid(new_neighborset5);
					tagN65.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN65);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[5].neighbors[i];
					}
					tagN66.Setneighborid(new_neighborset6);
					tagN66.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN66);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[5].neighbors[i];
					}
					tagN67.Setneighborid(new_neighborset7);
					tagN67.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN67);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[5].neighbors[i];
					}
					tagN68.Setneighborid(new_neighborset8);
					tagN68.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN68);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[5].neighbors[i];
					}
					tagN69.Setneighborid(new_neighborset9);
					tagN69.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN69);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[5].neighbors[i];
					}
					tagN610.Setneighborid(new_neighborset10);
					tagN610.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN610);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[5].neighbors[i];
					}
					tagN611.Setneighborid(new_neighborset11);
					tagN611.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN611);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[5].neighbors[i];
					}
					tagN612.Setneighborid(new_neighborset12);
					tagN612.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN612);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[5].neighbors[i];
					}
					tagN613.Setneighborid(new_neighborset13);
					tagN613.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN613);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[5].neighbors[i];
					}
					tagN614.Setneighborid(new_neighborset14);
					tagN614.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN614);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[5].neighbors[i];
					}
					tagN615.Setneighborid(new_neighborset15);
					tagN615.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN615);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[5].neighbors[i];
					}
					tagN616.Setneighborid(new_neighborset16);
					tagN616.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN616);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[5].neighbors[i];
					}
					tagN617.Setneighborid(new_neighborset17);
					tagN617.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN617);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[5].neighbors[i];
					}
					tagN618.Setneighborid(new_neighborset18);
					tagN618.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN618);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[5].neighbors[i];
					}
					tagN619.Setneighborid(new_neighborset19);
					tagN619.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN619);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[5].neighbors[i];
					}
					tagN620.Setneighborid(new_neighborset20);
					tagN620.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN620);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[5].neighbors[i];
					}
					tagN621.Setneighborid(new_neighborset21);
					tagN621.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN621);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[5].neighbors[i];
					}
					tagN622.Setneighborid(new_neighborset22);
					tagN622.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN622);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[5].neighbors[i];
					}
					tagN623.Setneighborid(new_neighborset23);
					tagN623.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN623);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[5].neighbors[i];
					}
					tagN624.Setneighborid(new_neighborset24);
					tagN624.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN624);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[5].neighbors[i];
					}
					tagN625.Setneighborid(new_neighborset25);
					tagN625.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN625);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[5]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[5])
						{
							new_neighborsetmax[i] = neighbor_set[5].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN6max.Setneighborid(new_neighborsetmax);
					tagN6max.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN6max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN71 tagN71;
		CustomMetaDataUnicastTagN72 tagN72;
		CustomMetaDataUnicastTagN73 tagN73;
		CustomMetaDataUnicastTagN74 tagN74;
		CustomMetaDataUnicastTagN75 tagN75;
		CustomMetaDataUnicastTagN76 tagN76;
		CustomMetaDataUnicastTagN77 tagN77;
		CustomMetaDataUnicastTagN78 tagN78;
		CustomMetaDataUnicastTagN79 tagN79;
		CustomMetaDataUnicastTagN710 tagN710;
		CustomMetaDataUnicastTagN711 tagN711;
		CustomMetaDataUnicastTagN712 tagN712;
		CustomMetaDataUnicastTagN713 tagN713;
		CustomMetaDataUnicastTagN714 tagN714;
		CustomMetaDataUnicastTagN715 tagN715;
		CustomMetaDataUnicastTagN716 tagN716;
		CustomMetaDataUnicastTagN717 tagN717;
		CustomMetaDataUnicastTagN718 tagN718;
		CustomMetaDataUnicastTagN719 tagN719;
		CustomMetaDataUnicastTagN720 tagN720;
		CustomMetaDataUnicastTagN721 tagN721;
		CustomMetaDataUnicastTagN722 tagN722;
		CustomMetaDataUnicastTagN723 tagN723;
		CustomMetaDataUnicastTagN724 tagN724;
		CustomMetaDataUnicastTagN725 tagN725;
		CustomMetaDataUnicastTagN7max tagN7max;
		
		if ((nei_sizes[6] > 0)and (neighbors_changed[6]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[6] = false;
			switch(nei_sizes[6])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[6].neighbors[0];
					tagN71.Setneighborid(new_neighborset1);
					tagN71.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN71);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[6].neighbors[i];
					}
					tagN72.Setneighborid(new_neighborset2);
					tagN72.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN72);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[6].neighbors[i];
					}
					tagN73.Setneighborid(new_neighborset3);
					tagN73.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN73);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[6].neighbors[i];
					}
					tagN74.Setneighborid(new_neighborset4);
					tagN74.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN74);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[6].neighbors[i];
					}
					tagN75.Setneighborid(new_neighborset5);
					tagN75.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN75);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[6].neighbors[i];
					}
					tagN76.Setneighborid(new_neighborset6);
					tagN76.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN76);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[6].neighbors[i];
					}
					tagN77.Setneighborid(new_neighborset7);
					tagN77.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN77);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[6].neighbors[i];
					}
					tagN78.Setneighborid(new_neighborset8);
					tagN78.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN78);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[6].neighbors[i];
					}
					tagN79.Setneighborid(new_neighborset9);
					tagN79.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN79);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[6].neighbors[i];
					}
					tagN710.Setneighborid(new_neighborset10);
					tagN710.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN710);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[6].neighbors[i];
					}
					tagN711.Setneighborid(new_neighborset11);
					tagN711.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN711);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[6].neighbors[i];
					}
					tagN712.Setneighborid(new_neighborset12);
					tagN712.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN712);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[6].neighbors[i];
					}
					tagN713.Setneighborid(new_neighborset13);
					tagN713.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN713);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[6].neighbors[i];
					}
					tagN714.Setneighborid(new_neighborset14);
					tagN714.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN714);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[6].neighbors[i];
					}
					tagN715.Setneighborid(new_neighborset15);
					tagN715.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN715);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[6].neighbors[i];
					}
					tagN716.Setneighborid(new_neighborset16);
					tagN716.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN716);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[6].neighbors[i];
					}
					tagN717.Setneighborid(new_neighborset17);
					tagN717.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN717);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[6].neighbors[i];
					}
					tagN718.Setneighborid(new_neighborset18);
					tagN718.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN718);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[6].neighbors[i];
					}
					tagN719.Setneighborid(new_neighborset19);
					tagN719.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN719);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[6].neighbors[i];
					}
					tagN720.Setneighborid(new_neighborset20);
					tagN720.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN720);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[6].neighbors[i];
					}
					tagN721.Setneighborid(new_neighborset21);
					tagN721.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN721);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[6].neighbors[i];
					}
					tagN722.Setneighborid(new_neighborset22);
					tagN722.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN722);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[6].neighbors[i];
					}
					tagN723.Setneighborid(new_neighborset23);
					tagN723.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN723);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[6].neighbors[i];
					}
					tagN724.Setneighborid(new_neighborset24);
					tagN724.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN724);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[6].neighbors[i];
					}
					tagN725.Setneighborid(new_neighborset25);
					tagN725.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN725);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[6]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[6])
						{
							new_neighborsetmax[i] = neighbor_set[6].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN7max.Setneighborid(new_neighborsetmax);
					tagN7max.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN7max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN81 tagN81;
		CustomMetaDataUnicastTagN82 tagN82;
		CustomMetaDataUnicastTagN83 tagN83;
		CustomMetaDataUnicastTagN84 tagN84;
		CustomMetaDataUnicastTagN85 tagN85;
		CustomMetaDataUnicastTagN86 tagN86;
		CustomMetaDataUnicastTagN87 tagN87;
		CustomMetaDataUnicastTagN88 tagN88;
		CustomMetaDataUnicastTagN89 tagN89;
		CustomMetaDataUnicastTagN810 tagN810;
		CustomMetaDataUnicastTagN811 tagN811;
		CustomMetaDataUnicastTagN812 tagN812;
		CustomMetaDataUnicastTagN813 tagN813;
		CustomMetaDataUnicastTagN814 tagN814;
		CustomMetaDataUnicastTagN815 tagN815;
		CustomMetaDataUnicastTagN816 tagN816;
		CustomMetaDataUnicastTagN817 tagN817;
		CustomMetaDataUnicastTagN818 tagN818;
		CustomMetaDataUnicastTagN819 tagN819;
		CustomMetaDataUnicastTagN820 tagN820;
		CustomMetaDataUnicastTagN821 tagN821;
		CustomMetaDataUnicastTagN822 tagN822;
		CustomMetaDataUnicastTagN823 tagN823;
		CustomMetaDataUnicastTagN824 tagN824;
		CustomMetaDataUnicastTagN825 tagN825;
		CustomMetaDataUnicastTagN8max tagN8max;
		
		if ((nei_sizes[7] > 0)and (neighbors_changed[7]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[7] = false;
			switch(nei_sizes[7])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[7].neighbors[0];
					tagN81.Setneighborid(new_neighborset1);
					tagN81.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN81);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[7].neighbors[i];
					}
					tagN82.Setneighborid(new_neighborset2);
					tagN82.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN82);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[7].neighbors[i];
					}
					tagN83.Setneighborid(new_neighborset3);
					tagN83.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN83);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[7].neighbors[i];
					}
					tagN84.Setneighborid(new_neighborset4);
					tagN84.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN84);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[7].neighbors[i];
					}
					tagN85.Setneighborid(new_neighborset5);
					tagN85.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN85);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[7].neighbors[i];
					}
					tagN86.Setneighborid(new_neighborset6);
					tagN86.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN86);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[7].neighbors[i];
					}
					tagN87.Setneighborid(new_neighborset7);
					tagN87.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN87);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[7].neighbors[i];
					}
					tagN88.Setneighborid(new_neighborset8);
					tagN88.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN88);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[7].neighbors[i];
					}
					tagN89.Setneighborid(new_neighborset9);
					tagN89.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN89);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[7].neighbors[i];
					}
					tagN810.Setneighborid(new_neighborset10);
					tagN810.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN810);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[7].neighbors[i];
					}
					tagN811.Setneighborid(new_neighborset11);
					tagN811.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN811);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[7].neighbors[i];
					}
					tagN812.Setneighborid(new_neighborset12);
					tagN812.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN812);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[7].neighbors[i];
					}
					tagN813.Setneighborid(new_neighborset13);
					tagN813.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN813);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[7].neighbors[i];
					}
					tagN814.Setneighborid(new_neighborset14);
					tagN814.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN814);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[7].neighbors[i];
					}
					tagN815.Setneighborid(new_neighborset15);
					tagN815.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN815);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[7].neighbors[i];
					}
					tagN816.Setneighborid(new_neighborset16);
					tagN816.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN816);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[7].neighbors[i];
					}
					tagN817.Setneighborid(new_neighborset17);
					tagN817.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN817);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[7].neighbors[i];
					}
					tagN818.Setneighborid(new_neighborset18);
					tagN818.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN818);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[7].neighbors[i];
					}
					tagN819.Setneighborid(new_neighborset19);
					tagN819.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN819);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[7].neighbors[i];
					}
					tagN820.Setneighborid(new_neighborset20);
					tagN820.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN820);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[7].neighbors[i];
					}
					tagN821.Setneighborid(new_neighborset21);
					tagN821.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN821);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[7].neighbors[i];
					}
					tagN822.Setneighborid(new_neighborset22);
					tagN822.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN822);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[7].neighbors[i];
					}
					tagN823.Setneighborid(new_neighborset23);
					tagN823.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN823);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[7].neighbors[i];
					}
					tagN824.Setneighborid(new_neighborset24);
					tagN824.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN824);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[7].neighbors[i];
					}
					tagN825.Setneighborid(new_neighborset25);
					tagN825.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN825);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[7]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[7])
						{
							new_neighborsetmax[i] = neighbor_set[7].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN8max.Setneighborid(new_neighborsetmax);
					tagN8max.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN8max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN91 tagN91;
		CustomMetaDataUnicastTagN92 tagN92;
		CustomMetaDataUnicastTagN93 tagN93;
		CustomMetaDataUnicastTagN94 tagN94;
		CustomMetaDataUnicastTagN95 tagN95;
		CustomMetaDataUnicastTagN96 tagN96;
		CustomMetaDataUnicastTagN97 tagN97;
		CustomMetaDataUnicastTagN98 tagN98;
		CustomMetaDataUnicastTagN99 tagN99;
		CustomMetaDataUnicastTagN910 tagN910;
		CustomMetaDataUnicastTagN911 tagN911;
		CustomMetaDataUnicastTagN912 tagN912;
		CustomMetaDataUnicastTagN913 tagN913;
		CustomMetaDataUnicastTagN914 tagN914;
		CustomMetaDataUnicastTagN915 tagN915;
		CustomMetaDataUnicastTagN916 tagN916;
		CustomMetaDataUnicastTagN917 tagN917;
		CustomMetaDataUnicastTagN918 tagN918;
		CustomMetaDataUnicastTagN919 tagN919;
		CustomMetaDataUnicastTagN920 tagN920;
		CustomMetaDataUnicastTagN921 tagN921;
		CustomMetaDataUnicastTagN922 tagN922;
		CustomMetaDataUnicastTagN923 tagN923;
		CustomMetaDataUnicastTagN924 tagN924;
		CustomMetaDataUnicastTagN925 tagN925;
		CustomMetaDataUnicastTagN9max tagN9max;
		
		if ((nei_sizes[8] > 0)and (neighbors_changed[8]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[8] = false;
			switch(nei_sizes[8])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[8].neighbors[0];
					tagN91.Setneighborid(new_neighborset1);
					tagN91.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN91);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[8].neighbors[i];
					}
					tagN92.Setneighborid(new_neighborset2);
					tagN92.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN92);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[8].neighbors[i];
					}
					tagN93.Setneighborid(new_neighborset3);
					tagN93.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN93);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[8].neighbors[i];
					}
					tagN94.Setneighborid(new_neighborset4);
					tagN94.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN94);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[8].neighbors[i];
					}
					tagN95.Setneighborid(new_neighborset5);
					tagN95.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN95);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[8].neighbors[i];
					}
					tagN96.Setneighborid(new_neighborset6);
					tagN96.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN96);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[8].neighbors[i];
					}
					tagN97.Setneighborid(new_neighborset7);
					tagN97.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN97);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[8].neighbors[i];
					}
					tagN98.Setneighborid(new_neighborset8);
					tagN98.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN98);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[8].neighbors[i];
					}
					tagN99.Setneighborid(new_neighborset9);
					tagN99.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN99);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[8].neighbors[i];
					}
					tagN910.Setneighborid(new_neighborset10);
					tagN910.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN910);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[8].neighbors[i];
					}
					tagN911.Setneighborid(new_neighborset11);
					tagN911.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN911);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[8].neighbors[i];
					}
					tagN912.Setneighborid(new_neighborset12);
					tagN912.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN912);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[8].neighbors[i];
					}
					tagN913.Setneighborid(new_neighborset13);
					tagN913.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN913);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[8].neighbors[i];
					}
					tagN914.Setneighborid(new_neighborset14);
					tagN914.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN914);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[8].neighbors[i];
					}
					tagN915.Setneighborid(new_neighborset15);
					tagN915.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN915);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[8].neighbors[i];
					}
					tagN916.Setneighborid(new_neighborset16);
					tagN916.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN916);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[8].neighbors[i];
					}
					tagN917.Setneighborid(new_neighborset17);
					tagN917.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN917);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[8].neighbors[i];
					}
					tagN918.Setneighborid(new_neighborset18);
					tagN918.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN918);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[8].neighbors[i];
					}
					tagN919.Setneighborid(new_neighborset19);
					tagN919.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN919);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[8].neighbors[i];
					}
					tagN920.Setneighborid(new_neighborset20);
					tagN920.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN920);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[8].neighbors[i];
					}
					tagN921.Setneighborid(new_neighborset21);
					tagN921.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN921);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[8].neighbors[i];
					}
					tagN922.Setneighborid(new_neighborset22);
					tagN922.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN922);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[8].neighbors[i];
					}
					tagN923.Setneighborid(new_neighborset23);
					tagN923.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN923);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[8].neighbors[i];
					}
					tagN924.Setneighborid(new_neighborset24);
					tagN924.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN924);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[8].neighbors[i];
					}
					tagN925.Setneighborid(new_neighborset25);
					tagN925.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN925);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[8]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[8])
						{
							new_neighborsetmax[i] = neighbor_set[8].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN9max.Setneighborid(new_neighborsetmax);
					tagN9max.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN9max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN101 tagN101;
		CustomMetaDataUnicastTagN102 tagN102;
		CustomMetaDataUnicastTagN103 tagN103;
		CustomMetaDataUnicastTagN104 tagN104;
		CustomMetaDataUnicastTagN105 tagN105;
		CustomMetaDataUnicastTagN106 tagN106;
		CustomMetaDataUnicastTagN107 tagN107;
		CustomMetaDataUnicastTagN108 tagN108;
		CustomMetaDataUnicastTagN109 tagN109;
		CustomMetaDataUnicastTagN1010 tagN1010;
		CustomMetaDataUnicastTagN1011 tagN1011;
		CustomMetaDataUnicastTagN1012 tagN1012;
		CustomMetaDataUnicastTagN1013 tagN1013;
		CustomMetaDataUnicastTagN1014 tagN1014;
		CustomMetaDataUnicastTagN1015 tagN1015;
		CustomMetaDataUnicastTagN1016 tagN1016;
		CustomMetaDataUnicastTagN1017 tagN1017;
		CustomMetaDataUnicastTagN1018 tagN1018;
		CustomMetaDataUnicastTagN1019 tagN1019;
		CustomMetaDataUnicastTagN1020 tagN1020;
		CustomMetaDataUnicastTagN1021 tagN1021;
		CustomMetaDataUnicastTagN1022 tagN1022;
		CustomMetaDataUnicastTagN1023 tagN1023;
		CustomMetaDataUnicastTagN1024 tagN1024;
		CustomMetaDataUnicastTagN1025 tagN1025;
		CustomMetaDataUnicastTagN10max tagN10max;
		
		if ((nei_sizes[9] > 0)and (neighbors_changed[9]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[9] = false;
			switch(nei_sizes[9])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[9].neighbors[0];
					tagN101.Setneighborid(new_neighborset1);
					tagN101.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN101);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[9].neighbors[i];
					}
					tagN102.Setneighborid(new_neighborset2);
					tagN102.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN102);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[9].neighbors[i];
					}
					tagN103.Setneighborid(new_neighborset3);
					tagN103.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN103);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[9].neighbors[i];
					}
					tagN104.Setneighborid(new_neighborset4);
					tagN104.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN104);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[9].neighbors[i];
					}
					tagN105.Setneighborid(new_neighborset5);
					tagN105.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN105);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[9].neighbors[i];
					}
					tagN106.Setneighborid(new_neighborset6);
					tagN106.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN106);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[9].neighbors[i];
					}
					tagN107.Setneighborid(new_neighborset7);
					tagN107.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN107);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[9].neighbors[i];
					}
					tagN108.Setneighborid(new_neighborset8);
					tagN108.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN108);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[9].neighbors[i];
					}
					tagN109.Setneighborid(new_neighborset9);
					tagN109.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN109);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[9].neighbors[i];
					}
					tagN1010.Setneighborid(new_neighborset10);
					tagN1010.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1010);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[9].neighbors[i];
					}
					tagN1011.Setneighborid(new_neighborset11);
					tagN1011.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1011);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[9].neighbors[i];
					}
					tagN1012.Setneighborid(new_neighborset12);
					tagN1012.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1012);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[9].neighbors[i];
					}
					tagN1013.Setneighborid(new_neighborset13);
					tagN1013.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1013);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[9].neighbors[i];
					}
					tagN1014.Setneighborid(new_neighborset14);
					tagN1014.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1014);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[9].neighbors[i];
					}
					tagN1015.Setneighborid(new_neighborset15);
					tagN1015.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1015);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[9].neighbors[i];
					}
					tagN1016.Setneighborid(new_neighborset16);
					tagN1016.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1016);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[9].neighbors[i];
					}
					tagN1017.Setneighborid(new_neighborset17);
					tagN1017.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1017);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[9].neighbors[i];
					}
					tagN1018.Setneighborid(new_neighborset18);
					tagN1018.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1018);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[9].neighbors[i];
					}
					tagN1019.Setneighborid(new_neighborset19);
					tagN1019.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1019);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[9].neighbors[i];
					}
					tagN1020.Setneighborid(new_neighborset20);
					tagN1020.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1020);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[9].neighbors[i];
					}
					tagN1021.Setneighborid(new_neighborset21);
					tagN1021.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1021);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[9].neighbors[i];
					}
					tagN1022.Setneighborid(new_neighborset22);
					tagN1022.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1022);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[9].neighbors[i];
					}
					tagN1023.Setneighborid(new_neighborset23);
					tagN1023.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1023);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[9].neighbors[i];
					}
					tagN1024.Setneighborid(new_neighborset24);
					tagN1024.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1024);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[9].neighbors[i];
					}
					tagN1025.Setneighborid(new_neighborset25);
					tagN1025.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1025);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[9]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[9])
						{
							new_neighborsetmax[i] = neighbor_set[9].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN10max.Setneighborid(new_neighborsetmax);
					tagN10max.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN10max);
					break;
			}
		
		}		
		
		CustomMetaDataUnicastTagN111 tagN111;
		CustomMetaDataUnicastTagN112 tagN112;
		CustomMetaDataUnicastTagN113 tagN113;
		CustomMetaDataUnicastTagN114 tagN114;
		CustomMetaDataUnicastTagN115 tagN115;
		CustomMetaDataUnicastTagN116 tagN116;
		CustomMetaDataUnicastTagN117 tagN117;
		CustomMetaDataUnicastTagN118 tagN118;
		CustomMetaDataUnicastTagN119 tagN119;
		CustomMetaDataUnicastTagN1110 tagN1110;
		CustomMetaDataUnicastTagN1111 tagN1111;
		CustomMetaDataUnicastTagN1112 tagN1112;
		CustomMetaDataUnicastTagN1113 tagN1113;
		CustomMetaDataUnicastTagN1114 tagN1114;
		CustomMetaDataUnicastTagN1115 tagN1115;
		CustomMetaDataUnicastTagN1116 tagN1116;
		CustomMetaDataUnicastTagN1117 tagN1117;
		CustomMetaDataUnicastTagN1118 tagN1118;
		CustomMetaDataUnicastTagN1119 tagN1119;
		CustomMetaDataUnicastTagN1120 tagN1120;
		CustomMetaDataUnicastTagN1121 tagN1121;
		CustomMetaDataUnicastTagN1122 tagN1122;
		CustomMetaDataUnicastTagN1123 tagN1123;
		CustomMetaDataUnicastTagN1124 tagN1124;
		CustomMetaDataUnicastTagN1125 tagN1125;
		CustomMetaDataUnicastTagN11max tagN11max;
		
		if ((nei_sizes[10] > 0)and (neighbors_changed[10]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[10] = false;
			switch(nei_sizes[10])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[10].neighbors[0];
					tagN111.Setneighborid(new_neighborset1);
					tagN111.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN111);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[10].neighbors[i];
					}
					tagN112.Setneighborid(new_neighborset2);
					tagN112.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN112);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[10].neighbors[i];
					}
					tagN113.Setneighborid(new_neighborset3);
					tagN113.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN113);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[10].neighbors[i];
					}
					tagN114.Setneighborid(new_neighborset4);
					tagN114.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN114);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[10].neighbors[i];
					}
					tagN115.Setneighborid(new_neighborset5);
					tagN115.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN115);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[10].neighbors[i];
					}
					tagN116.Setneighborid(new_neighborset6);
					tagN116.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN116);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[10].neighbors[i];
					}
					tagN117.Setneighborid(new_neighborset7);
					tagN117.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN117);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[10].neighbors[i];
					}
					tagN118.Setneighborid(new_neighborset8);
					tagN118.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN118);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[10].neighbors[i];
					}
					tagN119.Setneighborid(new_neighborset9);
					tagN119.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN119);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[10].neighbors[i];
					}
					tagN1110.Setneighborid(new_neighborset10);
					tagN1110.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1110);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[10].neighbors[i];
					}
					tagN1111.Setneighborid(new_neighborset11);
					tagN1111.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1111);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[10].neighbors[i];
					}
					tagN1112.Setneighborid(new_neighborset12);
					tagN1112.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1112);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[10].neighbors[i];
					}
					tagN1113.Setneighborid(new_neighborset13);
					tagN1113.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1113);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[10].neighbors[i];
					}
					tagN1114.Setneighborid(new_neighborset14);
					tagN1114.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1114);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[10].neighbors[i];
					}
					tagN1115.Setneighborid(new_neighborset15);
					tagN1115.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1115);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[10].neighbors[i];
					}
					tagN1116.Setneighborid(new_neighborset16);
					tagN1116.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1116);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[10].neighbors[i];
					}
					tagN1117.Setneighborid(new_neighborset17);
					tagN1117.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1117);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[10].neighbors[i];
					}
					tagN1118.Setneighborid(new_neighborset18);
					tagN1118.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1118);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[10].neighbors[i];
					}
					tagN1119.Setneighborid(new_neighborset19);
					tagN1119.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1119);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[10].neighbors[i];
					}
					tagN1120.Setneighborid(new_neighborset20);
					tagN1120.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1120);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[10].neighbors[i];
					}
					tagN1121.Setneighborid(new_neighborset21);
					tagN1121.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1121);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[10].neighbors[i];
					}
					tagN1122.Setneighborid(new_neighborset22);
					tagN1122.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1122);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[10].neighbors[i];
					}
					tagN1123.Setneighborid(new_neighborset23);
					tagN1123.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1123);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[10].neighbors[i];
					}
					tagN1124.Setneighborid(new_neighborset24);
					tagN1124.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1124);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[10].neighbors[i];
					}
					tagN1125.Setneighborid(new_neighborset25);
					tagN1125.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1125);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[10]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[10])
						{
							new_neighborsetmax[i] = neighbor_set[10].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN11max.Setneighborid(new_neighborsetmax);
					tagN11max.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN11max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN121 tagN121;
		CustomMetaDataUnicastTagN122 tagN122;
		CustomMetaDataUnicastTagN123 tagN123;
		CustomMetaDataUnicastTagN124 tagN124;
		CustomMetaDataUnicastTagN125 tagN125;
		CustomMetaDataUnicastTagN126 tagN126;
		CustomMetaDataUnicastTagN127 tagN127;
		CustomMetaDataUnicastTagN128 tagN128;
		CustomMetaDataUnicastTagN129 tagN129;
		CustomMetaDataUnicastTagN1210 tagN1210;
		CustomMetaDataUnicastTagN1211 tagN1211;
		CustomMetaDataUnicastTagN1212 tagN1212;
		CustomMetaDataUnicastTagN1213 tagN1213;
		CustomMetaDataUnicastTagN1214 tagN1214;
		CustomMetaDataUnicastTagN1215 tagN1215;
		CustomMetaDataUnicastTagN1216 tagN1216;
		CustomMetaDataUnicastTagN1217 tagN1217;
		CustomMetaDataUnicastTagN1218 tagN1218;
		CustomMetaDataUnicastTagN1219 tagN1219;
		CustomMetaDataUnicastTagN1220 tagN1220;
		CustomMetaDataUnicastTagN1221 tagN1221;
		CustomMetaDataUnicastTagN1222 tagN1222;
		CustomMetaDataUnicastTagN1223 tagN1223;
		CustomMetaDataUnicastTagN1224 tagN1224;
		CustomMetaDataUnicastTagN1225 tagN1225;
		CustomMetaDataUnicastTagN12max tagN12max;
		
		
		if ((nei_sizes[11] > 0)and (neighbors_changed[11]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[11] = false;
			switch(nei_sizes[11])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[11].neighbors[0];
					tagN121.Setneighborid(new_neighborset1);
					tagN121.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN121);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[11].neighbors[i];
					}
					tagN122.Setneighborid(new_neighborset2);
					tagN122.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN122);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[11].neighbors[i];
					}
					tagN123.Setneighborid(new_neighborset3);
					tagN123.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN123);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[11].neighbors[i];
					}
					tagN124.Setneighborid(new_neighborset4);
					tagN124.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN124);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[11].neighbors[i];
					}
					tagN125.Setneighborid(new_neighborset5);
					tagN125.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN125);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[11].neighbors[i];
					}
					tagN126.Setneighborid(new_neighborset6);
					tagN126.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN126);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[11].neighbors[i];
					}
					tagN127.Setneighborid(new_neighborset7);
					tagN127.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN127);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[11].neighbors[i];
					}
					tagN128.Setneighborid(new_neighborset8);
					tagN128.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN128);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[11].neighbors[i];
					}
					tagN129.Setneighborid(new_neighborset9);
					tagN129.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN129);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[11].neighbors[i];
					}
					tagN1210.Setneighborid(new_neighborset10);
					tagN1210.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1210);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[11].neighbors[i];
					}
					tagN1211.Setneighborid(new_neighborset11);
					tagN1211.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1211);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[11].neighbors[i];
					}
					tagN1212.Setneighborid(new_neighborset12);
					tagN1212.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1212);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[11].neighbors[i];
					}
					tagN1213.Setneighborid(new_neighborset13);
					tagN1213.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1213);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[11].neighbors[i];
					}
					tagN1214.Setneighborid(new_neighborset14);
					tagN1214.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1214);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[11].neighbors[i];
					}
					tagN1215.Setneighborid(new_neighborset15);
					tagN1215.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1215);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[11].neighbors[i];
					}
					tagN1216.Setneighborid(new_neighborset16);
					tagN1216.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1216);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[11].neighbors[i];
					}
					tagN1217.Setneighborid(new_neighborset17);
					tagN1217.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1217);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[11].neighbors[i];
					}
					tagN1218.Setneighborid(new_neighborset18);
					tagN1218.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1218);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[11].neighbors[i];
					}
					tagN1219.Setneighborid(new_neighborset19);
					tagN1219.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1219);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[11].neighbors[i];
					}
					tagN1220.Setneighborid(new_neighborset20);
					tagN1220.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1220);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[11].neighbors[i];
					}
					tagN1221.Setneighborid(new_neighborset21);
					tagN1221.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1221);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[11].neighbors[i];
					}
					tagN1222.Setneighborid(new_neighborset22);
					tagN1222.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1222);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[11].neighbors[i];
					}
					tagN1223.Setneighborid(new_neighborset23);
					tagN1223.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1223);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[11].neighbors[i];
					}
					tagN1224.Setneighborid(new_neighborset24);
					tagN1224.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1224);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[11].neighbors[i];
					}
					tagN1225.Setneighborid(new_neighborset25);
					tagN1225.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1225);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[11]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[11])
						{
							new_neighborsetmax[i] = neighbor_set[11].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN12max.Setnodeid(nodeid[11]);
					tagN12max.Setneighborid(new_neighborsetmax);
					packet1->AddPacketTag(tagN12max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN131 tagN131;
		CustomMetaDataUnicastTagN132 tagN132;
		CustomMetaDataUnicastTagN133 tagN133;
		CustomMetaDataUnicastTagN134 tagN134;
		CustomMetaDataUnicastTagN135 tagN135;
		CustomMetaDataUnicastTagN136 tagN136;
		CustomMetaDataUnicastTagN137 tagN137;
		CustomMetaDataUnicastTagN138 tagN138;
		CustomMetaDataUnicastTagN139 tagN139;
		CustomMetaDataUnicastTagN1310 tagN1310;
		CustomMetaDataUnicastTagN1311 tagN1311;
		CustomMetaDataUnicastTagN1312 tagN1312;
		CustomMetaDataUnicastTagN1313 tagN1313;
		CustomMetaDataUnicastTagN1314 tagN1314;
		CustomMetaDataUnicastTagN1315 tagN1315;
		CustomMetaDataUnicastTagN1316 tagN1316;
		CustomMetaDataUnicastTagN1317 tagN1317;
		CustomMetaDataUnicastTagN1318 tagN1318;
		CustomMetaDataUnicastTagN1319 tagN1319;
		CustomMetaDataUnicastTagN1320 tagN1320;
		CustomMetaDataUnicastTagN1321 tagN1321;
		CustomMetaDataUnicastTagN1322 tagN1322;
		CustomMetaDataUnicastTagN1323 tagN1323;
		CustomMetaDataUnicastTagN1324 tagN1324;
		CustomMetaDataUnicastTagN1325 tagN1325;
		CustomMetaDataUnicastTagN13max tagN13max;
		
		if ((nei_sizes[12] > 0)and (neighbors_changed[12]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[12] = false;
			switch(nei_sizes[12])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[12].neighbors[0];
					tagN131.Setneighborid(new_neighborset1);
					tagN131.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN131);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[12].neighbors[i];
					}
					tagN132.Setneighborid(new_neighborset2);
					tagN132.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN132);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[12].neighbors[i];
					}
					tagN133.Setneighborid(new_neighborset3);
					tagN133.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN133);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[12].neighbors[i];
					}
					tagN134.Setneighborid(new_neighborset4);
					tagN134.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN134);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[12].neighbors[i];
					}
					tagN135.Setneighborid(new_neighborset5);
					tagN135.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN135);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[12].neighbors[i];
					}
					tagN136.Setneighborid(new_neighborset6);
					tagN136.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN136);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[12].neighbors[i];
					}
					tagN137.Setneighborid(new_neighborset7);
					tagN137.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN137);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[12].neighbors[i];
					}
					tagN138.Setneighborid(new_neighborset8);
					tagN138.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN138);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[12].neighbors[i];
					}
					tagN139.Setneighborid(new_neighborset9);
					tagN139.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN139);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[12].neighbors[i];
					}
					tagN1310.Setneighborid(new_neighborset10);
					tagN1310.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1310);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[12].neighbors[i];
					}
					tagN1311.Setneighborid(new_neighborset11);
					tagN1311.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1311);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[12].neighbors[i];
					}
					tagN1312.Setneighborid(new_neighborset12);
					tagN1312.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1312);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[12].neighbors[i];
					}
					tagN1313.Setneighborid(new_neighborset13);
					tagN1313.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1313);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[12].neighbors[i];
					}
					tagN1314.Setneighborid(new_neighborset14);
					tagN1314.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1314);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[12].neighbors[i];
					}
					tagN1315.Setneighborid(new_neighborset15);
					tagN1315.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1315);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[12].neighbors[i];
					}
					tagN1316.Setneighborid(new_neighborset16);
					tagN1316.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1316);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[12].neighbors[i];
					}
					tagN1317.Setneighborid(new_neighborset17);
					tagN1317.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1317);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[12].neighbors[i];
					}
					tagN1318.Setneighborid(new_neighborset18);
					tagN1318.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1318);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[12].neighbors[i];
					}
					tagN1319.Setneighborid(new_neighborset19);
					tagN1319.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1319);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[12].neighbors[i];
					}
					tagN1320.Setneighborid(new_neighborset20);
					tagN1320.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1320);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[12].neighbors[i];
					}
					tagN1321.Setneighborid(new_neighborset21);
					tagN1321.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1321);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[12].neighbors[i];
					}
					tagN1322.Setneighborid(new_neighborset22);
					tagN1322.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1322);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[12].neighbors[i];
					}
					tagN1323.Setneighborid(new_neighborset23);
					tagN1323.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1323);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[12].neighbors[i];
					}
					tagN1324.Setneighborid(new_neighborset24);
					tagN1324.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1324);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[12].neighbors[i];
					}
					tagN1325.Setneighborid(new_neighborset25);
					tagN1325.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1325);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[12]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[12])
						{
							new_neighborsetmax[i] = neighbor_set[12].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN13max.Setneighborid(new_neighborsetmax);
					tagN13max.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN13max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN141 tagN141;
		CustomMetaDataUnicastTagN142 tagN142;
		CustomMetaDataUnicastTagN143 tagN143;
		CustomMetaDataUnicastTagN144 tagN144;
		CustomMetaDataUnicastTagN145 tagN145;
		CustomMetaDataUnicastTagN146 tagN146;
		CustomMetaDataUnicastTagN147 tagN147;
		CustomMetaDataUnicastTagN148 tagN148;
		CustomMetaDataUnicastTagN149 tagN149;
		CustomMetaDataUnicastTagN1410 tagN1410;
		CustomMetaDataUnicastTagN1411 tagN1411;
		CustomMetaDataUnicastTagN1412 tagN1412;
		CustomMetaDataUnicastTagN1413 tagN1413;
		CustomMetaDataUnicastTagN1414 tagN1414;
		CustomMetaDataUnicastTagN1415 tagN1415;
		CustomMetaDataUnicastTagN1416 tagN1416;
		CustomMetaDataUnicastTagN1417 tagN1417;
		CustomMetaDataUnicastTagN1418 tagN1418;
		CustomMetaDataUnicastTagN1419 tagN1419;
		CustomMetaDataUnicastTagN1420 tagN1420;
		CustomMetaDataUnicastTagN1421 tagN1421;
		CustomMetaDataUnicastTagN1422 tagN1422;
		CustomMetaDataUnicastTagN1423 tagN1423;
		CustomMetaDataUnicastTagN1424 tagN1424;
		CustomMetaDataUnicastTagN1425 tagN1425;
		CustomMetaDataUnicastTagN14max tagN14max;
		
		if ((nei_sizes[13] > 0)and (neighbors_changed[13]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[13] = false;
			switch(nei_sizes[13])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[13].neighbors[0];
					tagN141.Setneighborid(new_neighborset1);
					tagN141.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN141);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[13].neighbors[i];
					}
					tagN142.Setneighborid(new_neighborset2);
					tagN142.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN142);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[13].neighbors[i];
					}
					tagN143.Setneighborid(new_neighborset3);
					tagN143.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN143);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[13].neighbors[i];
					}
					tagN144.Setneighborid(new_neighborset4);
					tagN144.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN144);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[13].neighbors[i];
					}
					tagN145.Setneighborid(new_neighborset5);
					tagN145.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN145);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[13].neighbors[i];
					}
					tagN146.Setneighborid(new_neighborset6);
					tagN146.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN146);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[13].neighbors[i];
					}
					tagN147.Setneighborid(new_neighborset7);
					tagN147.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN147);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[13].neighbors[i];
					}
					tagN148.Setneighborid(new_neighborset8);
					tagN148.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN148);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[13].neighbors[i];
					}
					tagN149.Setneighborid(new_neighborset9);
					tagN149.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN149);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[13].neighbors[i];
					}
					tagN1410.Setneighborid(new_neighborset10);
					tagN1410.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1410);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[13].neighbors[i];
					}
					tagN1411.Setneighborid(new_neighborset11);
					tagN1411.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1411);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[13].neighbors[i];
					}
					tagN1412.Setneighborid(new_neighborset12);
					tagN1412.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1412);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[13].neighbors[i];
					}
					tagN1413.Setneighborid(new_neighborset13);
					tagN1413.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1413);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[13].neighbors[i];
					}
					tagN1414.Setneighborid(new_neighborset14);
					tagN1414.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1414);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[13].neighbors[i];
					}
					tagN1415.Setneighborid(new_neighborset15);
					tagN1415.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1415);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[13].neighbors[i];
					}
					tagN1416.Setneighborid(new_neighborset16);
					tagN1416.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1416);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[13].neighbors[i];
					}
					tagN1417.Setneighborid(new_neighborset17);
					tagN1417.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1417);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[13].neighbors[i];
					}
					tagN1418.Setneighborid(new_neighborset18);
					tagN1418.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1418);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[13].neighbors[i];
					}
					tagN1419.Setneighborid(new_neighborset19);
					tagN1419.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1419);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[13].neighbors[i];
					}
					tagN1420.Setneighborid(new_neighborset20);
					tagN1420.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1420);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[13].neighbors[i];
					}
					tagN1421.Setneighborid(new_neighborset21);
					tagN1421.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1421);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[13].neighbors[i];
					}
					tagN1422.Setneighborid(new_neighborset22);
					tagN1422.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1422);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[13].neighbors[i];
					}
					tagN1423.Setneighborid(new_neighborset23);
					tagN1423.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1423);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[13].neighbors[i];
					}
					tagN1424.Setneighborid(new_neighborset24);
					tagN1424.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1424);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[13].neighbors[i];
					}
					tagN1425.Setneighborid(new_neighborset25);
					tagN1425.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1425);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[13]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[13])
						{
							new_neighborsetmax[i] = neighbor_set[13].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN14max.Setneighborid(new_neighborsetmax);
					tagN14max.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN14max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN151 tagN151;
		CustomMetaDataUnicastTagN152 tagN152;
		CustomMetaDataUnicastTagN153 tagN153;
		CustomMetaDataUnicastTagN154 tagN154;
		CustomMetaDataUnicastTagN155 tagN155;
		CustomMetaDataUnicastTagN156 tagN156;
		CustomMetaDataUnicastTagN157 tagN157;
		CustomMetaDataUnicastTagN158 tagN158;
		CustomMetaDataUnicastTagN159 tagN159;
		CustomMetaDataUnicastTagN1510 tagN1510;
		CustomMetaDataUnicastTagN1511 tagN1511;
		CustomMetaDataUnicastTagN1512 tagN1512;
		CustomMetaDataUnicastTagN1513 tagN1513;
		CustomMetaDataUnicastTagN1514 tagN1514;
		CustomMetaDataUnicastTagN1515 tagN1515;
		CustomMetaDataUnicastTagN1516 tagN1516;
		CustomMetaDataUnicastTagN1517 tagN1517;
		CustomMetaDataUnicastTagN1518 tagN1518;
		CustomMetaDataUnicastTagN1519 tagN1519;
		CustomMetaDataUnicastTagN1520 tagN1520;
		CustomMetaDataUnicastTagN1521 tagN1521;
		CustomMetaDataUnicastTagN1522 tagN1522;
		CustomMetaDataUnicastTagN1523 tagN1523;
		CustomMetaDataUnicastTagN1524 tagN1524;
		CustomMetaDataUnicastTagN1525 tagN1525;
		CustomMetaDataUnicastTagN15max tagN15max;
		
		if ((nei_sizes[14] > 0)and (neighbors_changed[14]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[14] = false;
			switch(nei_sizes[14])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[14].neighbors[0];
					tagN151.Setneighborid(new_neighborset1);
					tagN151.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN151);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[14].neighbors[i];
					}
					tagN152.Setneighborid(new_neighborset2);
					tagN152.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN152);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[14].neighbors[i];
					}
					tagN153.Setneighborid(new_neighborset3);
					tagN153.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN153);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[14].neighbors[i];
					}
					tagN154.Setneighborid(new_neighborset4);
					tagN154.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN154);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[14].neighbors[i];
					}
					tagN155.Setneighborid(new_neighborset5);
					tagN155.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN155);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[14].neighbors[i];
					}
					tagN156.Setneighborid(new_neighborset6);
					tagN156.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN156);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[14].neighbors[i];
					}
					tagN157.Setneighborid(new_neighborset7);
					tagN157.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN157);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[14].neighbors[i];
					}
					tagN158.Setneighborid(new_neighborset8);
					tagN158.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN158);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[14].neighbors[i];
					}
					tagN159.Setneighborid(new_neighborset9);
					tagN159.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN159);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[14].neighbors[i];
					}
					tagN1510.Setneighborid(new_neighborset10);
					tagN1510.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1510);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[14].neighbors[i];
					}
					tagN1511.Setneighborid(new_neighborset11);
					tagN1511.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1511);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[14].neighbors[i];
					}
					tagN1512.Setneighborid(new_neighborset12);
					tagN1512.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1512);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[14].neighbors[i];
					}
					tagN1513.Setneighborid(new_neighborset13);
					tagN1513.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1513);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[14].neighbors[i];
					}
					tagN1514.Setneighborid(new_neighborset14);
					tagN1514.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1514);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[14].neighbors[i];
					}
					tagN1515.Setneighborid(new_neighborset15);
					tagN1515.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1515);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[14].neighbors[i];
					}
					tagN1516.Setneighborid(new_neighborset16);
					tagN1516.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1516);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[14].neighbors[i];
					}
					tagN1517.Setneighborid(new_neighborset17);
					tagN1517.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1517);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[14].neighbors[i];
					}
					tagN1518.Setneighborid(new_neighborset18);
					tagN1518.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1518);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[14].neighbors[i];
					}
					tagN1519.Setneighborid(new_neighborset19);
					tagN1519.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1519);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[14].neighbors[i];
					}
					tagN1520.Setneighborid(new_neighborset20);
					tagN1520.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1520);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[14].neighbors[i];
					}
					tagN1521.Setneighborid(new_neighborset21);
					tagN1521.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1521);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[14].neighbors[i];
					}
					tagN1522.Setneighborid(new_neighborset22);
					tagN1522.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1522);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[14].neighbors[i];
					}
					tagN1523.Setneighborid(new_neighborset23);
					tagN1523.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1523);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[14].neighbors[i];
					}
					tagN1524.Setneighborid(new_neighborset24);
					tagN1524.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1524);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[14].neighbors[i];
					}
					tagN1525.Setneighborid(new_neighborset25);
					tagN1525.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1525);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[14]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[14])
						{
							new_neighborsetmax[i] = neighbor_set[14].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN15max.Setneighborid(new_neighborsetmax);
					tagN15max.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN15max);
					break;
			}
		
		}
		CustomMetaDataUnicastTagN161 tagN161;
		CustomMetaDataUnicastTagN162 tagN162;
		CustomMetaDataUnicastTagN163 tagN163;
		CustomMetaDataUnicastTagN164 tagN164;
		CustomMetaDataUnicastTagN165 tagN165;
		CustomMetaDataUnicastTagN166 tagN166;
		CustomMetaDataUnicastTagN167 tagN167;
		CustomMetaDataUnicastTagN168 tagN168;
		CustomMetaDataUnicastTagN169 tagN169;
		CustomMetaDataUnicastTagN1610 tagN1610;
		CustomMetaDataUnicastTagN1611 tagN1611;
		CustomMetaDataUnicastTagN1612 tagN1612;
		CustomMetaDataUnicastTagN1613 tagN1613;
		CustomMetaDataUnicastTagN1614 tagN1614;
		CustomMetaDataUnicastTagN1615 tagN1615;
		CustomMetaDataUnicastTagN1616 tagN1616;
		CustomMetaDataUnicastTagN1617 tagN1617;
		CustomMetaDataUnicastTagN1618 tagN1618;
		CustomMetaDataUnicastTagN1619 tagN1619;
		CustomMetaDataUnicastTagN1620 tagN1620;
		CustomMetaDataUnicastTagN1621 tagN1621;
		CustomMetaDataUnicastTagN1622 tagN1622;
		CustomMetaDataUnicastTagN1623 tagN1623;
		CustomMetaDataUnicastTagN1624 tagN1624;
		CustomMetaDataUnicastTagN1625 tagN1625;
		CustomMetaDataUnicastTagN16max tagN16max;
		
		if ((nei_sizes[15] > 0)and (neighbors_changed[15]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[15] = false;
			switch(nei_sizes[15])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[15].neighbors[0];
					tagN161.Setneighborid(new_neighborset1);
					tagN161.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN161);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[15].neighbors[i];
					}
					tagN162.Setneighborid(new_neighborset2);
					tagN162.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN162);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[15].neighbors[i];
					}
					tagN163.Setneighborid(new_neighborset3);
					tagN163.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN163);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[15].neighbors[i];
					}
					tagN164.Setneighborid(new_neighborset4);
					tagN164.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN164);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[15].neighbors[i];
					}
					tagN165.Setneighborid(new_neighborset5);
					tagN165.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN165);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[15].neighbors[i];
					}
					tagN166.Setneighborid(new_neighborset6);
					tagN166.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN166);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[15].neighbors[i];
					}
					tagN167.Setneighborid(new_neighborset7);
					tagN167.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN167);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[15].neighbors[i];
					}
					tagN168.Setneighborid(new_neighborset8);
					tagN168.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN168);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[15].neighbors[i];
					}
					tagN169.Setneighborid(new_neighborset9);
					tagN169.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN169);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[15].neighbors[i];
					}
					tagN1610.Setneighborid(new_neighborset10);
					tagN1610.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1610);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[15].neighbors[i];
					}
					tagN1611.Setneighborid(new_neighborset11);
					tagN1611.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1611);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[15].neighbors[i];
					}
					tagN1612.Setneighborid(new_neighborset12);
					tagN1612.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1612);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[15].neighbors[i];
					}
					tagN1613.Setneighborid(new_neighborset13);
					tagN1613.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1613);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[15].neighbors[i];
					}
					tagN1614.Setneighborid(new_neighborset14);
					tagN1614.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1614);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[15].neighbors[i];
					}
					tagN1615.Setneighborid(new_neighborset15);
					tagN1615.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1615);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[15].neighbors[i];
					}
					tagN1616.Setneighborid(new_neighborset16);
					tagN1616.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1616);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[15].neighbors[i];
					}
					tagN1617.Setneighborid(new_neighborset17);
					tagN1617.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1617);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[15].neighbors[i];
					}
					tagN1618.Setneighborid(new_neighborset18);
					tagN1618.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1618);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[15].neighbors[i];
					}
					tagN1619.Setneighborid(new_neighborset19);
					tagN1619.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1619);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[15].neighbors[i];
					}
					tagN1620.Setneighborid(new_neighborset20);
					tagN1620.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1620);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[15].neighbors[i];
					}
					tagN1621.Setneighborid(new_neighborset21);
					tagN1621.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1621);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[15].neighbors[i];
					}
					tagN1622.Setneighborid(new_neighborset22);
					tagN1622.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1622);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[15].neighbors[i];
					}
					tagN1623.Setneighborid(new_neighborset23);
					tagN1623.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1623);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[15].neighbors[i];
					}
					tagN1624.Setneighborid(new_neighborset24);
					tagN1624.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1624);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[15].neighbors[i];
					}
					tagN1625.Setneighborid(new_neighborset25);
					tagN1625.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1625);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[15]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[15])
						{
							new_neighborsetmax[i] = neighbor_set[15].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN16max.Setneighborid(new_neighborsetmax);
					tagN16max.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN16max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN171 tagN171;
		CustomMetaDataUnicastTagN172 tagN172;
		CustomMetaDataUnicastTagN173 tagN173;
		CustomMetaDataUnicastTagN174 tagN174;
		CustomMetaDataUnicastTagN175 tagN175;
		CustomMetaDataUnicastTagN176 tagN176;
		CustomMetaDataUnicastTagN177 tagN177;
		CustomMetaDataUnicastTagN178 tagN178;
		CustomMetaDataUnicastTagN179 tagN179;
		CustomMetaDataUnicastTagN1710 tagN1710;
		CustomMetaDataUnicastTagN1711 tagN1711;
		CustomMetaDataUnicastTagN1712 tagN1712;
		CustomMetaDataUnicastTagN1713 tagN1713;
		CustomMetaDataUnicastTagN1714 tagN1714;
		CustomMetaDataUnicastTagN1715 tagN1715;
		CustomMetaDataUnicastTagN1716 tagN1716;
		CustomMetaDataUnicastTagN1717 tagN1717;
		CustomMetaDataUnicastTagN1718 tagN1718;
		CustomMetaDataUnicastTagN1719 tagN1719;
		CustomMetaDataUnicastTagN1720 tagN1720;
		CustomMetaDataUnicastTagN1721 tagN1721;
		CustomMetaDataUnicastTagN1722 tagN1722;
		CustomMetaDataUnicastTagN1723 tagN1723;
		CustomMetaDataUnicastTagN1724 tagN1724;
		CustomMetaDataUnicastTagN1725 tagN1725;
		CustomMetaDataUnicastTagN17max tagN17max;
		
		if ((nei_sizes[16] > 0) and (neighbors_changed[16]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[16] = false;
			switch(nei_sizes[16])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[16].neighbors[0];
					tagN171.Setneighborid(new_neighborset1);
					tagN171.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN171);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[16].neighbors[i];
					}
					tagN172.Setneighborid(new_neighborset2);
					tagN172.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN172);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[16].neighbors[i];
					}
					tagN173.Setneighborid(new_neighborset3);
					tagN173.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN173);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[16].neighbors[i];
					}
					tagN174.Setneighborid(new_neighborset4);
					tagN174.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN174);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[16].neighbors[i];
					}
					tagN175.Setneighborid(new_neighborset5);
					tagN175.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN175);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[16].neighbors[i];
					}
					tagN176.Setneighborid(new_neighborset6);
					tagN176.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN176);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[16].neighbors[i];
					}
					tagN177.Setneighborid(new_neighborset7);
					tagN177.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN177);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[16].neighbors[i];
					}
					tagN178.Setneighborid(new_neighborset8);
					tagN178.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN178);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[16].neighbors[i];
					}
					tagN179.Setneighborid(new_neighborset9);
					tagN179.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN179);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[16].neighbors[i];
					}
					tagN1710.Setneighborid(new_neighborset10);
					tagN1710.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1710);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[16].neighbors[i];
					}
					tagN1711.Setneighborid(new_neighborset11);
					tagN1711.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1711);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[16].neighbors[i];
					}
					tagN1712.Setneighborid(new_neighborset12);
					tagN1712.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1712);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[16].neighbors[i];
					}
					tagN1713.Setneighborid(new_neighborset13);
					tagN1713.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1713);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[16].neighbors[i];
					}
					tagN1714.Setneighborid(new_neighborset14);
					tagN1714.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1714);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[16].neighbors[i];
					}
					tagN1715.Setneighborid(new_neighborset15);
					tagN1715.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1715);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[16].neighbors[i];
					}
					tagN1716.Setneighborid(new_neighborset16);
					tagN1716.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1716);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[16].neighbors[i];
					}
					tagN1717.Setneighborid(new_neighborset17);
					tagN1717.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1717);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[16].neighbors[i];
					}
					tagN1718.Setneighborid(new_neighborset18);
					tagN1718.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1718);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[16].neighbors[i];
					}
					tagN1719.Setneighborid(new_neighborset19);
					tagN1719.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1719);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[16].neighbors[i];
					}
					tagN1720.Setneighborid(new_neighborset20);
					tagN1720.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1720);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[16].neighbors[i];
					}
					tagN1721.Setneighborid(new_neighborset21);
					tagN1721.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1721);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[16].neighbors[i];
					}
					tagN1722.Setneighborid(new_neighborset22);
					tagN1722.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1722);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[16].neighbors[i];
					}
					tagN1723.Setneighborid(new_neighborset23);
					tagN1723.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1723);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[16].neighbors[i];
					}
					tagN1724.Setneighborid(new_neighborset24);
					tagN1724.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1724);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[16].neighbors[i];
					}
					tagN1725.Setneighborid(new_neighborset25);
					tagN1725.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1725);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[16]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[16])
						{
							new_neighborsetmax[i] = neighbor_set[16].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN17max.Setneighborid(new_neighborsetmax);
					tagN17max.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN17max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN181 tagN181;
		CustomMetaDataUnicastTagN182 tagN182;
		CustomMetaDataUnicastTagN183 tagN183;
		CustomMetaDataUnicastTagN184 tagN184;
		CustomMetaDataUnicastTagN185 tagN185;
		CustomMetaDataUnicastTagN186 tagN186;
		CustomMetaDataUnicastTagN187 tagN187;
		CustomMetaDataUnicastTagN188 tagN188;
		CustomMetaDataUnicastTagN189 tagN189;
		CustomMetaDataUnicastTagN1810 tagN1810;
		CustomMetaDataUnicastTagN1811 tagN1811;
		CustomMetaDataUnicastTagN1812 tagN1812;
		CustomMetaDataUnicastTagN1813 tagN1813;
		CustomMetaDataUnicastTagN1814 tagN1814;
		CustomMetaDataUnicastTagN1815 tagN1815;
		CustomMetaDataUnicastTagN1816 tagN1816;
		CustomMetaDataUnicastTagN1817 tagN1817;
		CustomMetaDataUnicastTagN1818 tagN1818;
		CustomMetaDataUnicastTagN1819 tagN1819;
		CustomMetaDataUnicastTagN1820 tagN1820;
		CustomMetaDataUnicastTagN1821 tagN1821;
		CustomMetaDataUnicastTagN1822 tagN1822;
		CustomMetaDataUnicastTagN1823 tagN1823;
		CustomMetaDataUnicastTagN1824 tagN1824;
		CustomMetaDataUnicastTagN1825 tagN1825;
		CustomMetaDataUnicastTagN18max tagN18max;
		
		if ((nei_sizes[17] > 0) and (neighbors_changed[17]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[17] = false;
			switch(nei_sizes[17])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[17].neighbors[0];
					tagN181.Setneighborid(new_neighborset1);
					tagN181.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN181);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[17].neighbors[i];
					}
					tagN182.Setneighborid(new_neighborset2);
					tagN182.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN182);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[17].neighbors[i];
					}
					tagN183.Setneighborid(new_neighborset3);
					tagN183.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN183);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[17].neighbors[i];
					}
					tagN184.Setneighborid(new_neighborset4);
					tagN184.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN184);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[17].neighbors[i];
					}
					tagN185.Setneighborid(new_neighborset5);
					tagN185.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN185);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[17].neighbors[i];
					}
					tagN186.Setneighborid(new_neighborset6);
					tagN186.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN186);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[17].neighbors[i];
					}
					tagN187.Setneighborid(new_neighborset7);
					tagN187.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN187);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[17].neighbors[i];
					}
					tagN188.Setneighborid(new_neighborset8);
					tagN188.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN188);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[17].neighbors[i];
					}
					tagN189.Setneighborid(new_neighborset9);
					tagN189.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN189);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[17].neighbors[i];
					}
					tagN1810.Setneighborid(new_neighborset10);
					tagN1810.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1810);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[17].neighbors[i];
					}
					tagN1811.Setneighborid(new_neighborset11);
					tagN1811.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1811);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[17].neighbors[i];
					}
					tagN1812.Setneighborid(new_neighborset12);
					tagN1812.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1812);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[17].neighbors[i];
					}
					tagN1813.Setneighborid(new_neighborset13);
					tagN1813.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1813);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[17].neighbors[i];
					}
					tagN1814.Setneighborid(new_neighborset14);
					tagN1814.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1814);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[17].neighbors[i];
					}
					tagN1815.Setneighborid(new_neighborset15);
					tagN1815.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1815);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[17].neighbors[i];
					}
					tagN1816.Setneighborid(new_neighborset16);
					tagN1816.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1816);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[17].neighbors[i];
					}
					tagN1817.Setneighborid(new_neighborset17);
					tagN1817.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1817);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[17].neighbors[i];
					}
					tagN1818.Setneighborid(new_neighborset18);
					tagN1818.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1818);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[17].neighbors[i];
					}
					tagN1819.Setneighborid(new_neighborset19);
					tagN1819.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1819);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[17].neighbors[i];
					}
					tagN1820.Setneighborid(new_neighborset20);
					tagN1820.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1820);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[17].neighbors[i];
					}
					tagN1821.Setneighborid(new_neighborset21);
					tagN1821.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1821);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[17].neighbors[i];
					}
					tagN1822.Setneighborid(new_neighborset22);
					tagN1822.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1822);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[17].neighbors[i];
					}
					tagN1823.Setneighborid(new_neighborset23);
					tagN1823.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1823);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[17].neighbors[i];
					}
					tagN1824.Setneighborid(new_neighborset24);
					tagN1824.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1824);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[17].neighbors[i];
					}
					tagN1825.Setneighborid(new_neighborset25);
					tagN1825.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1825);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[17]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[17])
						{
							new_neighborsetmax[i] = neighbor_set[17].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN18max.Setneighborid(new_neighborsetmax);
					tagN18max.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN18max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN191 tagN191;
		CustomMetaDataUnicastTagN192 tagN192;
		CustomMetaDataUnicastTagN193 tagN193;
		CustomMetaDataUnicastTagN194 tagN194;
		CustomMetaDataUnicastTagN195 tagN195;
		CustomMetaDataUnicastTagN196 tagN196;
		CustomMetaDataUnicastTagN197 tagN197;
		CustomMetaDataUnicastTagN198 tagN198;
		CustomMetaDataUnicastTagN199 tagN199;
		CustomMetaDataUnicastTagN1910 tagN1910;
		CustomMetaDataUnicastTagN1911 tagN1911;
		CustomMetaDataUnicastTagN1912 tagN1912;
		CustomMetaDataUnicastTagN1913 tagN1913;
		CustomMetaDataUnicastTagN1914 tagN1914;
		CustomMetaDataUnicastTagN1915 tagN1915;
		CustomMetaDataUnicastTagN1916 tagN1916;
		CustomMetaDataUnicastTagN1917 tagN1917;
		CustomMetaDataUnicastTagN1918 tagN1918;
		CustomMetaDataUnicastTagN1919 tagN1919;
		CustomMetaDataUnicastTagN1920 tagN1920;
		CustomMetaDataUnicastTagN1921 tagN1921;
		CustomMetaDataUnicastTagN1922 tagN1922;
		CustomMetaDataUnicastTagN1923 tagN1923;
		CustomMetaDataUnicastTagN1924 tagN1924;
		CustomMetaDataUnicastTagN1925 tagN1925;
		CustomMetaDataUnicastTagN19max tagN19max;
		
		if ((nei_sizes[18] > 0) and (neighbors_changed[18]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[18] = false;
			switch(nei_sizes[18])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[18].neighbors[0];
					tagN191.Setneighborid(new_neighborset1);
					tagN191.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN191);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[18].neighbors[i];
					}
					tagN192.Setneighborid(new_neighborset2);
					tagN192.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN192);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[18].neighbors[i];
					}
					tagN193.Setneighborid(new_neighborset3);
					tagN193.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN193);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[18].neighbors[i];
					}
					tagN194.Setneighborid(new_neighborset4);
					tagN194.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN194);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[18].neighbors[i];
					}
					tagN195.Setneighborid(new_neighborset5);
					tagN195.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN195);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[18].neighbors[i];
					}
					tagN196.Setneighborid(new_neighborset6);
					tagN196.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN196);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[18].neighbors[i];
					}
					tagN197.Setneighborid(new_neighborset7);
					tagN197.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN197);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[18].neighbors[i];
					}
					tagN198.Setneighborid(new_neighborset8);
					tagN198.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN198);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[18].neighbors[i];
					}
					tagN199.Setneighborid(new_neighborset9);
					tagN199.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN199);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[18].neighbors[i];
					}
					tagN1910.Setneighborid(new_neighborset10);
					tagN1910.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1910);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[18].neighbors[i];
					}
					tagN1911.Setneighborid(new_neighborset11);
					tagN1911.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1911);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[18].neighbors[i];
					}
					tagN1912.Setneighborid(new_neighborset12);
					tagN1912.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1912);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[18].neighbors[i];
					}
					tagN1913.Setneighborid(new_neighborset13);
					tagN1913.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1913);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[18].neighbors[i];
					}
					tagN1914.Setneighborid(new_neighborset14);
					tagN1914.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1914);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[18].neighbors[i];
					}
					tagN1915.Setneighborid(new_neighborset15);
					tagN1915.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1915);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[18].neighbors[i];
					}
					tagN1916.Setneighborid(new_neighborset16);
					tagN1916.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1916);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[18].neighbors[i];
					}
					tagN1917.Setneighborid(new_neighborset17);
					tagN1917.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1917);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[18].neighbors[i];
					}
					tagN1918.Setneighborid(new_neighborset18);
					tagN1918.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1918);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[18].neighbors[i];
					}
					tagN1919.Setneighborid(new_neighborset19);
					tagN1919.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1919);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[18].neighbors[i];
					}
					tagN1920.Setneighborid(new_neighborset20);
					tagN1920.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1920);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[18].neighbors[i];
					}
					tagN1921.Setneighborid(new_neighborset21);
					tagN1921.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1921);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[18].neighbors[i];
					}
					tagN1922.Setneighborid(new_neighborset22);
					tagN1922.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1922);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[18].neighbors[i];
					}
					tagN1923.Setneighborid(new_neighborset23);
					tagN1923.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1923);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[18].neighbors[i];
					}
					tagN1924.Setneighborid(new_neighborset24);
					tagN1924.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1924);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[18].neighbors[i];
					}
					tagN1925.Setneighborid(new_neighborset25);
					tagN1925.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1925);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[18]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[18])
						{
							new_neighborsetmax[i] = neighbor_set[18].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN19max.Setneighborid(new_neighborsetmax);
					tagN19max.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN19max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN2001 tagN2001;
		CustomMetaDataUnicastTagN2002 tagN2002;
		CustomMetaDataUnicastTagN2003 tagN2003;
		CustomMetaDataUnicastTagN2004 tagN2004;
		CustomMetaDataUnicastTagN2005 tagN2005;
		CustomMetaDataUnicastTagN2006 tagN2006;
		CustomMetaDataUnicastTagN2007 tagN2007;
		CustomMetaDataUnicastTagN2008 tagN2008;
		CustomMetaDataUnicastTagN2009 tagN2009;
		CustomMetaDataUnicastTagN2010 tagN2010;
		CustomMetaDataUnicastTagN2011 tagN2011;
		CustomMetaDataUnicastTagN2012 tagN2012;
		CustomMetaDataUnicastTagN2013 tagN2013;
		CustomMetaDataUnicastTagN2014 tagN2014;
		CustomMetaDataUnicastTagN2015 tagN2015;
		CustomMetaDataUnicastTagN2016 tagN2016;
		CustomMetaDataUnicastTagN2017 tagN2017;
		CustomMetaDataUnicastTagN2018 tagN2018;
		CustomMetaDataUnicastTagN2019 tagN2019;
		CustomMetaDataUnicastTagN2020 tagN2020;
		CustomMetaDataUnicastTagN2021 tagN2021;
		CustomMetaDataUnicastTagN2022 tagN2022;
		CustomMetaDataUnicastTagN2023 tagN2023;
		CustomMetaDataUnicastTagN2024 tagN2024;
		CustomMetaDataUnicastTagN2025 tagN2025;
		CustomMetaDataUnicastTagN20max tagN20max;
		
		if ((nei_sizes[19] > 0) and (neighbors_changed[19]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[19] = false;
			switch(nei_sizes[19])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[19].neighbors[0];
					tagN2001.Setneighborid(new_neighborset1);
					tagN2001.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2001);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[19].neighbors[i];
					}
					tagN2002.Setneighborid(new_neighborset2);
					tagN2002.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2002);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[19].neighbors[i];
					}
					tagN2003.Setneighborid(new_neighborset3);
					tagN2003.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2003);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[19].neighbors[i];
					}
					tagN2004.Setneighborid(new_neighborset4);
					tagN2004.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2004);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[19].neighbors[i];
					}
					tagN2005.Setneighborid(new_neighborset5);
					tagN2005.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2005);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[19].neighbors[i];
					}
					tagN2006.Setneighborid(new_neighborset6);
					tagN2006.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2006);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[19].neighbors[i];
					}
					tagN2007.Setneighborid(new_neighborset7);
					tagN2007.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2007);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[19].neighbors[i];
					}
					tagN2008.Setneighborid(new_neighborset8);
					tagN2008.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2008);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[19].neighbors[i];
					}
					tagN2009.Setneighborid(new_neighborset9);
					tagN2009.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2009);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[19].neighbors[i];
					}
					tagN2010.Setneighborid(new_neighborset10);
					tagN2010.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2010);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[19].neighbors[i];
					}
					tagN2011.Setneighborid(new_neighborset11);
					tagN2011.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2011);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[19].neighbors[i];
					}
					tagN2012.Setneighborid(new_neighborset12);
					tagN2012.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2012);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[19].neighbors[i];
					}
					tagN2013.Setneighborid(new_neighborset13);
					tagN2013.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2013);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[19].neighbors[i];
					}
					tagN2014.Setneighborid(new_neighborset14);
					tagN2014.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2014);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[19].neighbors[i];
					}
					tagN2015.Setneighborid(new_neighborset15);
					tagN2015.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2015);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[19].neighbors[i];
					}
					tagN2016.Setneighborid(new_neighborset16);
					tagN2016.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2016);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[19].neighbors[i];
					}
					tagN2017.Setneighborid(new_neighborset17);
					tagN2017.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2017);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[19].neighbors[i];
					}
					tagN2018.Setneighborid(new_neighborset18);
					tagN2018.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2018);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[19].neighbors[i];
					}
					tagN2019.Setneighborid(new_neighborset19);
					tagN2019.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2019);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[19].neighbors[i];
					}
					tagN2020.Setneighborid(new_neighborset20);
					tagN2020.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2020);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[19].neighbors[i];
					}
					tagN2021.Setneighborid(new_neighborset21);
					tagN2021.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2021);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[19].neighbors[i];
					}
					tagN2022.Setneighborid(new_neighborset22);
					tagN2022.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2022);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[19].neighbors[i];
					}
					tagN2023.Setneighborid(new_neighborset23);
					tagN2023.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2023);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[19].neighbors[i];
					}
					tagN2024.Setneighborid(new_neighborset24);
					tagN2024.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2024);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[19].neighbors[i];
					}
					tagN2025.Setneighborid(new_neighborset25);
					tagN2025.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2025);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[19]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[19])
						{
							new_neighborsetmax[i] = neighbor_set[19].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN20max.Setneighborid(new_neighborsetmax);
					tagN20max.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN20max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN2101 tagN2101;
		CustomMetaDataUnicastTagN2102 tagN2102;
		CustomMetaDataUnicastTagN2103 tagN2103;
		CustomMetaDataUnicastTagN2104 tagN2104;
		CustomMetaDataUnicastTagN2105 tagN2105;
		CustomMetaDataUnicastTagN2106 tagN2106;
		CustomMetaDataUnicastTagN2107 tagN2107;
		CustomMetaDataUnicastTagN2108 tagN2108;
		CustomMetaDataUnicastTagN2109 tagN2109;
		CustomMetaDataUnicastTagN2110 tagN2110;
		CustomMetaDataUnicastTagN2111 tagN2111;
		CustomMetaDataUnicastTagN2112 tagN2112;
		CustomMetaDataUnicastTagN2113 tagN2113;
		CustomMetaDataUnicastTagN2114 tagN2114;
		CustomMetaDataUnicastTagN2115 tagN2115;
		CustomMetaDataUnicastTagN2116 tagN2116;
		CustomMetaDataUnicastTagN2117 tagN2117;
		CustomMetaDataUnicastTagN2118 tagN2118;
		CustomMetaDataUnicastTagN2119 tagN2119;
		CustomMetaDataUnicastTagN2120 tagN2120;
		CustomMetaDataUnicastTagN2121 tagN2121;
		CustomMetaDataUnicastTagN2122 tagN2122;
		CustomMetaDataUnicastTagN2123 tagN2123;
		CustomMetaDataUnicastTagN2124 tagN2124;
		CustomMetaDataUnicastTagN2125 tagN2125;
		CustomMetaDataUnicastTagN21max tagN21max;
		
		if ((nei_sizes[20] > 0) and (neighbors_changed[20]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[20] = false;
			switch(nei_sizes[20])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[20].neighbors[0];
					tagN2101.Setneighborid(new_neighborset1);
					tagN2101.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2101);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[20].neighbors[i];
					}
					tagN2102.Setneighborid(new_neighborset2);
					tagN2102.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2102);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[20].neighbors[i];
					}
					tagN2103.Setneighborid(new_neighborset3);
					tagN2103.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2103);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[20].neighbors[i];
					}
					tagN2104.Setneighborid(new_neighborset4);
					tagN2104.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2104);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[20].neighbors[i];
					}
					tagN2105.Setneighborid(new_neighborset5);
					tagN2105.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2105);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[20].neighbors[i];
					}
					tagN2106.Setneighborid(new_neighborset6);
					tagN2106.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2106);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[20].neighbors[i];
					}
					tagN2107.Setneighborid(new_neighborset7);
					tagN2107.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2107);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[20].neighbors[i];
					}
					tagN2108.Setneighborid(new_neighborset8);
					tagN2108.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2108);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[20].neighbors[i];
					}
					tagN2109.Setneighborid(new_neighborset9);
					tagN2109.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2109);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[20].neighbors[i];
					}
					tagN2110.Setneighborid(new_neighborset10);
					tagN2110.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2110);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[20].neighbors[i];
					}
					tagN2111.Setneighborid(new_neighborset11);
					tagN2111.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2111);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[20].neighbors[i];
					}
					tagN2112.Setneighborid(new_neighborset12);
					tagN2112.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2112);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[20].neighbors[i];
					}
					tagN2113.Setneighborid(new_neighborset13);
					tagN2113.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2113);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[20].neighbors[i];
					}
					tagN2114.Setneighborid(new_neighborset14);
					tagN2114.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2114);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[20].neighbors[i];
					}
					tagN2115.Setneighborid(new_neighborset15);
					tagN2115.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2115);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[20].neighbors[i];
					}
					tagN2116.Setneighborid(new_neighborset16);
					tagN2116.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2116);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[20].neighbors[i];
					}
					tagN2117.Setneighborid(new_neighborset17);
					tagN2117.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2117);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[20].neighbors[i];
					}
					tagN2118.Setneighborid(new_neighborset18);
					tagN2118.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2118);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[20].neighbors[i];
					}
					tagN2119.Setneighborid(new_neighborset19);
					tagN2119.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2119);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[20].neighbors[i];
					}
					tagN2120.Setneighborid(new_neighborset20);
					tagN2120.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2120);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[20].neighbors[i];
					}
					tagN2121.Setneighborid(new_neighborset21);
					tagN2121.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2121);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[20].neighbors[i];
					}
					tagN2122.Setneighborid(new_neighborset22);
					tagN2122.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2122);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[20].neighbors[i];
					}
					tagN2123.Setneighborid(new_neighborset23);
					tagN2123.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2123);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[20].neighbors[i];
					}
					tagN2124.Setneighborid(new_neighborset24);
					tagN2124.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2124);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[20].neighbors[i];
					}
					tagN2125.Setneighborid(new_neighborset25);
					tagN2125.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2125);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[20]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[20])
						{
							new_neighborsetmax[i] = neighbor_set[20].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN21max.Setneighborid(new_neighborsetmax);
					tagN21max.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN21max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN2201 tagN2201;
		CustomMetaDataUnicastTagN2202 tagN2202;
		CustomMetaDataUnicastTagN2203 tagN2203;
		CustomMetaDataUnicastTagN2204 tagN2204;
		CustomMetaDataUnicastTagN2205 tagN2205;
		CustomMetaDataUnicastTagN2206 tagN2206;
		CustomMetaDataUnicastTagN2207 tagN2207;
		CustomMetaDataUnicastTagN2208 tagN2208;
		CustomMetaDataUnicastTagN2209 tagN2209;
		CustomMetaDataUnicastTagN2210 tagN2210;
		CustomMetaDataUnicastTagN2211 tagN2211;
		CustomMetaDataUnicastTagN2212 tagN2212;
		CustomMetaDataUnicastTagN2213 tagN2213;
		CustomMetaDataUnicastTagN2214 tagN2214;
		CustomMetaDataUnicastTagN2215 tagN2215;
		CustomMetaDataUnicastTagN2216 tagN2216;
		CustomMetaDataUnicastTagN2217 tagN2217;
		CustomMetaDataUnicastTagN2218 tagN2218;
		CustomMetaDataUnicastTagN2219 tagN2219;
		CustomMetaDataUnicastTagN2220 tagN2220;
		CustomMetaDataUnicastTagN2221 tagN2221;
		CustomMetaDataUnicastTagN2222 tagN2222;
		CustomMetaDataUnicastTagN2223 tagN2223;
		CustomMetaDataUnicastTagN2224 tagN2224;
		CustomMetaDataUnicastTagN2225 tagN2225;
		CustomMetaDataUnicastTagN22max tagN22max;
		
		if ((nei_sizes[21] > 0) and (neighbors_changed[21]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[21] = false;
			switch(nei_sizes[21])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[21].neighbors[0];
					tagN2201.Setneighborid(new_neighborset1);
					tagN2201.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2201);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[21].neighbors[i];
					}
					tagN2202.Setneighborid(new_neighborset2);
					tagN2202.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2202);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[21].neighbors[i];
					}
					tagN2203.Setneighborid(new_neighborset3);
					tagN2203.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2203);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[21].neighbors[i];
					}
					tagN2204.Setneighborid(new_neighborset4);
					tagN2204.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2204);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[21].neighbors[i];
					}
					tagN2205.Setneighborid(new_neighborset5);
					tagN2205.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2205);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[21].neighbors[i];
					}
					tagN2206.Setneighborid(new_neighborset6);
					tagN2206.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2206);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[21].neighbors[i];
					}
					tagN2207.Setneighborid(new_neighborset7);
					tagN2207.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2207);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[21].neighbors[i];
					}
					tagN2208.Setneighborid(new_neighborset8);
					tagN2208.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2208);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[21].neighbors[i];
					}
					tagN2209.Setneighborid(new_neighborset9);
					tagN2209.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2209);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[21].neighbors[i];
					}
					tagN2210.Setneighborid(new_neighborset10);
					tagN2210.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2210);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[21].neighbors[i];
					}
					tagN2211.Setneighborid(new_neighborset11);
					tagN2211.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2211);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[21].neighbors[i];
					}
					tagN2212.Setneighborid(new_neighborset12);
					tagN2212.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2212);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[21].neighbors[i];
					}
					tagN2213.Setneighborid(new_neighborset13);
					tagN2213.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2213);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[21].neighbors[i];
					}
					tagN2214.Setneighborid(new_neighborset14);
					tagN2214.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2214);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[21].neighbors[i];
					}
					tagN2215.Setneighborid(new_neighborset15);
					tagN2215.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2215);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[21].neighbors[i];
					}
					tagN2216.Setneighborid(new_neighborset16);
					tagN2216.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2216);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[21].neighbors[i];
					}
					tagN2217.Setneighborid(new_neighborset17);
					tagN2217.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2217);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[21].neighbors[i];
					}
					tagN2218.Setneighborid(new_neighborset18);
					tagN2218.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2218);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[21].neighbors[i];
					}
					tagN2219.Setneighborid(new_neighborset19);
					tagN2219.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2219);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[21].neighbors[i];
					}
					tagN2220.Setneighborid(new_neighborset20);
					tagN2220.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2220);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[21].neighbors[i];
					}
					tagN2221.Setneighborid(new_neighborset21);
					tagN2221.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2221);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[21].neighbors[i];
					}
					tagN2222.Setneighborid(new_neighborset22);
					tagN2222.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2222);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[21].neighbors[i];
					}
					tagN2223.Setneighborid(new_neighborset23);
					tagN2223.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2223);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[21].neighbors[i];
					}
					tagN2224.Setneighborid(new_neighborset24);
					tagN2224.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2224);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[21].neighbors[i];
					}
					tagN2225.Setneighborid(new_neighborset25);
					tagN2225.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2225);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[21]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[21])
						{
							new_neighborsetmax[i] = neighbor_set[21].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN22max.Setneighborid(new_neighborsetmax);
					tagN22max.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN22max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN2301 tagN2301;
		CustomMetaDataUnicastTagN2302 tagN2302;
		CustomMetaDataUnicastTagN2303 tagN2303;
		CustomMetaDataUnicastTagN2304 tagN2304;
		CustomMetaDataUnicastTagN2305 tagN2305;
		CustomMetaDataUnicastTagN2306 tagN2306;
		CustomMetaDataUnicastTagN2307 tagN2307;
		CustomMetaDataUnicastTagN2308 tagN2308;
		CustomMetaDataUnicastTagN2309 tagN2309;
		CustomMetaDataUnicastTagN2310 tagN2310;
		CustomMetaDataUnicastTagN2311 tagN2311;
		CustomMetaDataUnicastTagN2312 tagN2312;
		CustomMetaDataUnicastTagN2313 tagN2313;
		CustomMetaDataUnicastTagN2314 tagN2314;
		CustomMetaDataUnicastTagN2315 tagN2315;
		CustomMetaDataUnicastTagN2316 tagN2316;
		CustomMetaDataUnicastTagN2317 tagN2317;
		CustomMetaDataUnicastTagN2318 tagN2318;
		CustomMetaDataUnicastTagN2319 tagN2319;
		CustomMetaDataUnicastTagN2320 tagN2320;
		CustomMetaDataUnicastTagN2321 tagN2321;
		CustomMetaDataUnicastTagN2322 tagN2322;
		CustomMetaDataUnicastTagN2323 tagN2323;
		CustomMetaDataUnicastTagN2324 tagN2324;
		CustomMetaDataUnicastTagN2325 tagN2325;
		CustomMetaDataUnicastTagN23max tagN23max;
		
		if ((nei_sizes[22] > 0) and (neighbors_changed[22]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[22] = false;
			switch(nei_sizes[22])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[22].neighbors[0];
					tagN2301.Setneighborid(new_neighborset1);
					tagN2301.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2301);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[22].neighbors[i];
					}
					tagN2302.Setneighborid(new_neighborset2);
					tagN2302.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2302);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[22].neighbors[i];
					}
					tagN2303.Setneighborid(new_neighborset3);
					tagN2303.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2303);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[22].neighbors[i];
					}
					tagN2304.Setneighborid(new_neighborset4);
					tagN2304.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2304);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[22].neighbors[i];
					}
					tagN2305.Setneighborid(new_neighborset5);
					tagN2305.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2305);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[22].neighbors[i];
					}
					tagN2306.Setneighborid(new_neighborset6);
					tagN2306.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2306);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[22].neighbors[i];
					}
					tagN2307.Setneighborid(new_neighborset7);
					tagN2307.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2307);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[22].neighbors[i];
					}
					tagN2308.Setneighborid(new_neighborset8);
					tagN2308.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2308);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[22].neighbors[i];
					}
					tagN2309.Setneighborid(new_neighborset9);
					tagN2309.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2309);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[22].neighbors[i];
					}
					tagN2310.Setneighborid(new_neighborset10);
					tagN2310.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2310);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[22].neighbors[i];
					}
					tagN2311.Setneighborid(new_neighborset11);
					tagN2311.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2311);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[22].neighbors[i];
					}
					tagN2312.Setneighborid(new_neighborset12);
					tagN2312.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2312);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[22].neighbors[i];
					}
					tagN2313.Setneighborid(new_neighborset13);
					tagN2313.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN2313);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[0].neighbors[i];
					}
					tagN2314.Setneighborid(new_neighborset14);
					tagN2314.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2314);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[22].neighbors[i];
					}
					tagN2315.Setneighborid(new_neighborset15);
					tagN2315.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2315);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[22].neighbors[i];
					}
					tagN2316.Setneighborid(new_neighborset16);
					tagN2316.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2316);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[22].neighbors[i];
					}
					tagN2317.Setneighborid(new_neighborset17);
					tagN2317.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2317);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[22].neighbors[i];
					}
					tagN2318.Setneighborid(new_neighborset18);
					tagN2318.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2318);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[22].neighbors[i];
					}
					tagN2319.Setneighborid(new_neighborset19);
					tagN2319.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2319);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[22].neighbors[i];
					}
					tagN2320.Setneighborid(new_neighborset20);
					tagN2320.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2320);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[22].neighbors[i];
					}
					tagN2321.Setneighborid(new_neighborset21);
					tagN2321.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2321);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[22].neighbors[i];
					}
					tagN2322.Setneighborid(new_neighborset22);
					tagN2322.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2322);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[22].neighbors[i];
					}
					tagN2323.Setneighborid(new_neighborset23);
					tagN2323.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2323);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[22].neighbors[i];
					}
					tagN2324.Setneighborid(new_neighborset24);
					tagN2324.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2324);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[22].neighbors[i];
					}
					tagN2325.Setneighborid(new_neighborset25);
					tagN2325.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2325);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[22]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[22])
						{
							new_neighborsetmax[i] = neighbor_set[22].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN23max.Setneighborid(new_neighborsetmax);
					tagN23max.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN23max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN2401 tagN2401;
		CustomMetaDataUnicastTagN2402 tagN2402;
		CustomMetaDataUnicastTagN2403 tagN2403;
		CustomMetaDataUnicastTagN2404 tagN2404;
		CustomMetaDataUnicastTagN2405 tagN2405;
		CustomMetaDataUnicastTagN2406 tagN2406;
		CustomMetaDataUnicastTagN2407 tagN2407;
		CustomMetaDataUnicastTagN2408 tagN2408;
		CustomMetaDataUnicastTagN2409 tagN2409;
		CustomMetaDataUnicastTagN2410 tagN2410;
		CustomMetaDataUnicastTagN2411 tagN2411;
		CustomMetaDataUnicastTagN2412 tagN2412;
		CustomMetaDataUnicastTagN2413 tagN2413;
		CustomMetaDataUnicastTagN2414 tagN2414;
		CustomMetaDataUnicastTagN2415 tagN2415;
		CustomMetaDataUnicastTagN2416 tagN2416;
		CustomMetaDataUnicastTagN2417 tagN2417;
		CustomMetaDataUnicastTagN2418 tagN2418;
		CustomMetaDataUnicastTagN2419 tagN2419;
		CustomMetaDataUnicastTagN2420 tagN2420;
		CustomMetaDataUnicastTagN2421 tagN2421;
		CustomMetaDataUnicastTagN2422 tagN2422;
		CustomMetaDataUnicastTagN2423 tagN2423;
		CustomMetaDataUnicastTagN2424 tagN2424;
		CustomMetaDataUnicastTagN2425 tagN2425;
		CustomMetaDataUnicastTagN24max tagN24max;
		
		if ((nei_sizes[23] > 0) and (neighbors_changed[23]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[23] = false;
			switch(nei_sizes[23])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[23].neighbors[0];
					tagN2401.Setneighborid(new_neighborset1);
					tagN2401.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2401);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[23].neighbors[i];
					}
					tagN2402.Setneighborid(new_neighborset2);
					tagN2402.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2402);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[23].neighbors[i];
					}
					tagN2403.Setneighborid(new_neighborset3);
					tagN2403.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2403);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[23].neighbors[i];
					}
					tagN2404.Setneighborid(new_neighborset4);
					tagN2404.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2404);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[23].neighbors[i];
					}
					tagN2405.Setneighborid(new_neighborset5);
					tagN2405.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2405);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[23].neighbors[i];
					}
					tagN2406.Setneighborid(new_neighborset6);
					tagN2406.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2406);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[23].neighbors[i];
					}
					tagN2407.Setneighborid(new_neighborset7);
					tagN2407.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2407);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[23].neighbors[i];
					}
					tagN2408.Setneighborid(new_neighborset8);
					tagN2408.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2408);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[23].neighbors[i];
					}
					tagN2409.Setneighborid(new_neighborset9);
					tagN2409.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2409);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[23].neighbors[i];
					}
					tagN2410.Setneighborid(new_neighborset10);
					tagN2410.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2410);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[23].neighbors[i];
					}
					tagN2411.Setneighborid(new_neighborset11);
					tagN2411.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2411);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[23].neighbors[i];
					}
					tagN2412.Setneighborid(new_neighborset12);
					tagN2412.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2412);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[23].neighbors[i];
					}
					tagN2413.Setneighborid(new_neighborset13);
					tagN2413.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2413);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[23].neighbors[i];
					}
					tagN2414.Setneighborid(new_neighborset14);
					tagN2414.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2414);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[23].neighbors[i];
					}
					tagN2415.Setneighborid(new_neighborset15);
					tagN2415.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2415);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[23].neighbors[i];
					}
					tagN2416.Setneighborid(new_neighborset16);
					tagN2416.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2416);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[23].neighbors[i];
					}
					tagN2417.Setneighborid(new_neighborset17);
					tagN2417.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2417);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[23].neighbors[i];
					}
					tagN2418.Setneighborid(new_neighborset18);
					tagN2418.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2418);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[23].neighbors[i];
					}
					tagN2419.Setneighborid(new_neighborset19);
					tagN2419.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2419);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[23].neighbors[i];
					}
					tagN2420.Setneighborid(new_neighborset20);
					tagN2420.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2420);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[23].neighbors[i];
					}
					tagN2421.Setneighborid(new_neighborset21);
					tagN2421.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2421);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[23].neighbors[i];
					}
					tagN2422.Setneighborid(new_neighborset22);
					tagN2422.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2422);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[23].neighbors[i];
					}
					tagN2423.Setneighborid(new_neighborset23);
					tagN2423.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2423);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[23].neighbors[i];
					}
					tagN2424.Setneighborid(new_neighborset24);
					tagN2424.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2424);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[23].neighbors[i];
					}
					tagN2425.Setneighborid(new_neighborset25);
					tagN2425.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2425);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[23]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[23])
						{
							new_neighborsetmax[i] = neighbor_set[23].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN24max.Setneighborid(new_neighborsetmax);
					tagN24max.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN24max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN2501 tagN2501;
		CustomMetaDataUnicastTagN2502 tagN2502;
		CustomMetaDataUnicastTagN2503 tagN2503;
		CustomMetaDataUnicastTagN2504 tagN2504;
		CustomMetaDataUnicastTagN2505 tagN2505;
		CustomMetaDataUnicastTagN2506 tagN2506;
		CustomMetaDataUnicastTagN2507 tagN2507;
		CustomMetaDataUnicastTagN2508 tagN2508;
		CustomMetaDataUnicastTagN2509 tagN2509;
		CustomMetaDataUnicastTagN2510 tagN2510;
		CustomMetaDataUnicastTagN2511 tagN2511;
		CustomMetaDataUnicastTagN2512 tagN2512;
		CustomMetaDataUnicastTagN2513 tagN2513;
		CustomMetaDataUnicastTagN2514 tagN2514;
		CustomMetaDataUnicastTagN2515 tagN2515;
		CustomMetaDataUnicastTagN2516 tagN2516;
		CustomMetaDataUnicastTagN2517 tagN2517;
		CustomMetaDataUnicastTagN2518 tagN2518;
		CustomMetaDataUnicastTagN2519 tagN2519;
		CustomMetaDataUnicastTagN2520 tagN2520;
		CustomMetaDataUnicastTagN2521 tagN2521;
		CustomMetaDataUnicastTagN2522 tagN2522;
		CustomMetaDataUnicastTagN2523 tagN2523;
		CustomMetaDataUnicastTagN2524 tagN2524;
		CustomMetaDataUnicastTagN2525 tagN2525;
		CustomMetaDataUnicastTagN25max tagN25max;
		
		if ((nei_sizes[24] > 0) and (neighbors_changed[24]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[24] = false;
			switch(nei_sizes[24])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[24].neighbors[0];
					tagN2501.Setneighborid(new_neighborset1);
					tagN2501.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2501);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[24].neighbors[i];
					}
					tagN2502.Setneighborid(new_neighborset2);
					tagN2502.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2502);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[24].neighbors[i];
					}
					tagN2503.Setneighborid(new_neighborset3);
					tagN2503.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2503);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[24].neighbors[i];
					}
					tagN2504.Setneighborid(new_neighborset4);
					tagN2504.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2504);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[24].neighbors[i];
					}
					tagN2505.Setneighborid(new_neighborset5);
					tagN2505.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2505);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[24].neighbors[i];
					}
					tagN2506.Setneighborid(new_neighborset6);
					tagN2506.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2506);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[24].neighbors[i];
					}
					tagN2507.Setneighborid(new_neighborset7);
					tagN2507.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2507);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[24].neighbors[i];
					}
					tagN2508.Setneighborid(new_neighborset8);
					tagN2508.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2508);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[24].neighbors[i];
					}
					tagN2509.Setneighborid(new_neighborset9);
					tagN2509.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2509);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[24].neighbors[i];
					}
					tagN2510.Setneighborid(new_neighborset10);
					tagN2510.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2510);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[24].neighbors[i];
					}
					tagN2511.Setneighborid(new_neighborset11);
					tagN2511.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2511);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[24].neighbors[i];
					}
					tagN2512.Setneighborid(new_neighborset12);
					tagN2512.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2512);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[24].neighbors[i];
					}
					tagN2513.Setneighborid(new_neighborset13);
					tagN2513.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2513);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[24].neighbors[i];
					}
					tagN2514.Setneighborid(new_neighborset14);
					tagN2514.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2514);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[24].neighbors[i];
					}
					tagN2515.Setneighborid(new_neighborset15);
					tagN2515.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2515);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[24].neighbors[i];
					}
					tagN2516.Setneighborid(new_neighborset16);
					tagN2516.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2516);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[24].neighbors[i];
					}
					tagN2517.Setneighborid(new_neighborset17);
					tagN2517.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2517);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[24].neighbors[i];
					}
					tagN2518.Setneighborid(new_neighborset18);
					tagN2518.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2518);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[24].neighbors[i];
					}
					tagN2519.Setneighborid(new_neighborset19);
					tagN2519.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2519);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[24].neighbors[i];
					}
					tagN2520.Setneighborid(new_neighborset20);
					tagN2520.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2520);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[24].neighbors[i];
					}
					tagN2521.Setneighborid(new_neighborset21);
					tagN2521.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2521);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[24].neighbors[i];
					}
					tagN2522.Setneighborid(new_neighborset22);
					tagN2522.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2522);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[24].neighbors[i];
					}
					tagN2523.Setneighborid(new_neighborset23);
					tagN2523.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2523);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[24].neighbors[i];
					}
					tagN2524.Setneighborid(new_neighborset24);
					tagN2524.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2524);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[24].neighbors[i];
					}
					tagN2525.Setneighborid(new_neighborset25);
					tagN2525.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2525);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[24]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[24])
						{
							new_neighborsetmax[i] = neighbor_set[24].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN25max.Setneighborid(new_neighborsetmax);
					tagN25max.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN25max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN26max tagN26max;
		if ((nei_sizes[25] > 0) and (neighbors_changed[25]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[25] = false;
			cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[25]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[25])
				{
					new_neighborsetmax[i] = neighbor_set[25].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN26max.Setneighborid(new_neighborsetmax);
			tagN26max.Setnodeid(nodeid[25]);
			packet1->AddPacketTag(tagN26max);
		}
		
		CustomMetaDataUnicastTagN27max tagN27max;
		if ((nei_sizes[26] > 0) and (neighbors_changed[26]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[26] = false;
			cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[26]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[26])
				{
					new_neighborsetmax[i] = neighbor_set[26].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN27max.Setneighborid(new_neighborsetmax);
			tagN27max.Setnodeid(nodeid[26]);
			packet1->AddPacketTag(tagN27max);
		}
		
		CustomMetaDataUnicastTagN28max tagN28max;
		if ((nei_sizes[27] > 0) and (neighbors_changed[27]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[27] = false;
			cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[27]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[27])
				{
					new_neighborsetmax[i] = neighbor_set[27].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN28max.Setneighborid(new_neighborsetmax);
			tagN28max.Setnodeid(nodeid[27]);
			packet1->AddPacketTag(tagN28max);
		}
		
		CustomMetaDataUnicastTagN29max tagN29max;
		if ((nei_sizes[28] > 0) and (neighbors_changed[28]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[28] = false;
			cout<<"Cellular:maximum datasize exceeded . size is  "<<nei_sizes[28]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[28])
				{
					new_neighborsetmax[i] = neighbor_set[28].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN29max.Setneighborid(new_neighborsetmax);
			tagN29max.Setnodeid(nodeid[28]);
			packet1->AddPacketTag(tagN29max);
		}
		
		CustomMetaDataUnicastTagN30max tagN30max;
		if ((nei_sizes[29] > 0) and (neighbors_changed[29]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[29] = false;
			cout<<"Cellular:maximum datasize exceeded. size is  "<<nei_sizes[29]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[29])
				{
					new_neighborsetmax[i] = neighbor_set[29].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN30max.Setneighborid(new_neighborsetmax);
			tagN30max.Setnodeid(nodeid[29]);
			packet1->AddPacketTag(tagN30max);
		}
		
		CustomDataUnicastTag1 tag1;
		CustomDataUnicastTag2 tag2;
		CustomDataUnicastTag3 tag3;
		CustomDataUnicastTag4 tag4;
		CustomDataUnicastTag5 tag5;
		CustomDataUnicastTag6 tag6;
		CustomDataUnicastTag7 tag7;
		CustomDataUnicastTag8 tag8;
		CustomDataUnicastTag9 tag9;
		CustomDataUnicastTag10 tag10;
		CustomDataUnicastTag11 tag11;
		CustomDataUnicastTag12 tag12;
		CustomDataUnicastTag13 tag13;
		CustomDataUnicastTag14 tag14;
		CustomDataUnicastTag15 tag15;
		CustomDataUnicastTag16 tag16;
		CustomDataUnicastTag17 tag17;
		CustomDataUnicastTag18 tag18;
		CustomDataUnicastTag19 tag19;
		CustomDataUnicastTag20 tag20;
		CustomDataUnicastTag21 tag21;
		CustomDataUnicastTag22 tag22;
		CustomDataUnicastTag23 tag23;
		CustomDataUnicastTag24 tag24;
		CustomDataUnicastTag25 tag25;
		CustomDataUnicastTag tag;
		switch (size)
		{	
			case 1:
				tag1.SetsenderId(nid);
				tag1.SetNodeId(nodeid);
				tag1.Setposition(position);
				tag1.Setvelocity(velocity);
				tag1.Setacceleration(acceleration);
				tag1.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag1);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 2:
				tag2.SetsenderId(nid);
				tag2.SetNodeId(nodeid);
				tag2.Setposition(position);
				tag2.Setvelocity(velocity);
				tag2.Setacceleration(acceleration);
				tag2.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag2);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 3:
				tag3.SetsenderId(nid);
				tag3.SetNodeId(nodeid);
				tag3.Setposition(position);
				tag3.Setvelocity(velocity);
				tag3.Setacceleration(acceleration);
				tag3.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag3);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 4:
				tag4.SetsenderId(nid);
				tag4.SetNodeId(nodeid);
				tag4.Setposition(position);
				tag4.Setvelocity(velocity);
				tag4.Setacceleration(acceleration);
				tag4.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag4);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 5:
				tag5.SetsenderId(nid);
				tag5.SetNodeId(nodeid);
				tag5.Setposition(position);
				tag5.Setvelocity(velocity);
				tag5.Setacceleration(acceleration);
				tag5.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag5);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 6:
				tag6.SetsenderId(nid);
				tag6.SetNodeId(nodeid);
				tag6.Setposition(position);
				tag6.Setvelocity(velocity);
				tag6.Setacceleration(acceleration);
				tag6.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag6);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 7:
				tag7.SetsenderId(nid);
				tag7.SetNodeId(nodeid);
				tag7.Setposition(position);
				tag7.Setvelocity(velocity);
				tag7.Setacceleration(acceleration);
				tag7.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag7);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 8:
				tag8.SetsenderId(nid);
				tag8.SetNodeId(nodeid);
				tag8.Setposition(position);
				tag8.Setvelocity(velocity);
				tag8.Setacceleration(acceleration);
				tag8.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag8);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 9:
				tag9.SetsenderId(nid);
				tag9.SetNodeId(nodeid);
				tag9.Setposition(position);
				tag9.Setvelocity(velocity);
				tag9.Setacceleration(acceleration);
				tag9.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag9);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 10:
				tag10.SetsenderId(nid);
				tag10.SetNodeId(nodeid);
				tag10.Setposition(position);
				tag10.Setvelocity(velocity);
				tag10.Setacceleration(acceleration);
				tag10.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag10);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 11:
				tag11.SetsenderId(nid);
				tag11.SetNodeId(nodeid);
				tag11.Setposition(position);
				tag11.Setvelocity(velocity);
				tag11.Setacceleration(acceleration);
				tag11.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag11);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 12:
				tag12.SetsenderId(nid);
				tag12.SetNodeId(nodeid);
				tag12.Setposition(position);
				tag12.Setvelocity(velocity);
				tag12.Setacceleration(acceleration);
				tag12.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag12);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 13:
				tag13.SetsenderId(nid);
				tag13.SetNodeId(nodeid);
				tag13.Setposition(position);
				tag13.Setvelocity(velocity);
				tag13.Setacceleration(acceleration);
				tag13.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag13);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;	
			case 14:
				tag14.SetsenderId(nid);
				tag14.SetNodeId(nodeid);
				tag14.Setposition(position);
				tag14.Setvelocity(velocity);
				tag14.Setacceleration(acceleration);
				tag14.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag14);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 15:
				tag15.SetsenderId(nid);
				tag15.SetNodeId(nodeid);
				tag15.Setposition(position);
				tag15.Setvelocity(velocity);
				tag15.Setacceleration(acceleration);
				tag15.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag15);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;

			case 16:
				tag16.SetsenderId(nid);
				tag16.SetNodeId(nodeid);
				tag16.Setposition(position);
				tag16.Setvelocity(velocity);
				tag16.Setacceleration(acceleration);
				tag16.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag16);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 17:
				tag17.SetsenderId(nid);
				tag17.SetNodeId(nodeid);
				tag17.Setposition(position);
				tag17.Setvelocity(velocity);
				tag17.Setacceleration(acceleration);
				tag17.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag17);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 18:	
				tag18.SetsenderId(nid);
				tag18.SetNodeId(nodeid);
				tag18.Setposition(position);
				tag18.Setvelocity(velocity);
				tag18.Setacceleration(acceleration);
				tag18.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag18);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 19:
				tag19.SetsenderId(nid);
				tag19.SetNodeId(nodeid);
				tag19.Setposition(position);
				tag19.Setvelocity(velocity);
				tag19.Setacceleration(acceleration);
				tag19.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag19);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 20:
				tag20.SetsenderId(nid);
				tag20.SetNodeId(nodeid);
				tag20.Setposition(position);
				tag20.Setvelocity(velocity);
				tag20.Setacceleration(acceleration);
				tag20.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag20);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 21:
				tag21.SetsenderId(nid);
				tag21.SetNodeId(nodeid);
				tag21.Setposition(position);
				tag21.Setvelocity(velocity);
				tag21.Setacceleration(acceleration);
				tag21.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag21);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 22:
				tag22.SetsenderId(nid);
				tag22.SetNodeId(nodeid);
				tag22.Setposition(position);
				tag22.Setvelocity(velocity);
				tag22.Setacceleration(acceleration);
				tag22.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag22);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 23:
				tag23.SetsenderId(nid);
				tag23.SetNodeId(nodeid);
				tag23.Setposition(position);
				tag23.Setvelocity(velocity);
				tag23.Setacceleration(acceleration);
				tag23.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag23);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 24:
				tag24.SetsenderId(nid);
				tag24.SetNodeId(nodeid);
				tag24.Setposition(position);
				tag24.Setvelocity(velocity);
				tag24.Setacceleration(acceleration);
				tag24.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag24);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 25:
				tag25.SetsenderId(nid);
				tag25.SetNodeId(nodeid);
				tag25.Setposition(position);
				tag25.Setvelocity(velocity);
				tag25.Setacceleration(acceleration);
				tag25.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag25);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			default:
				cout<<"Cellular:maximum status datasize exceeded . size is  "<<size<<endl;
				tag.SetsenderId(nid);
				tag.SetNodeId((data_at_nodes_inst+nid)->nodeid);
				tag.Setposition((data_at_nodes_inst+nid)->position);
				tag.Setvelocity((data_at_nodes_inst+nid)->velocity);
				tag.Setacceleration((data_at_nodes_inst+nid)->acceleration);
				tag.SetTimestamp((data_at_nodes_inst+nid)->timestamp);
				packet1->AddPacketTag(tag);
				lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;	
		}
		cout<<"lte total packet size is "<<lte_total_packet_size<<endl;

	}
	
}

void begin_sending_LTE_data_agent()
{
 	list<uint32_t> agent_ids;
 	for (uint32_t i=2;i<(N_Vehicles+2);i++)
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
		//cout<<"u is "<<u<<endl;
	  	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(u));
		Simulator::Schedule(Seconds(0.000025*count),send_LTE_data_agent,udp_app,Vehicle_Nodes.Get(u-2),management_Node.Get(0), u-2);
		count++;
	}
}

void RSU_dataunicast_agent(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> source_node, Ptr <Node> destination_node)
{

	Ptr <Node> nu = DynamicCast <Node> (source_node);
	uint32_t nid = uint32_t(nu->GetId());
	if (X_nodes[nid] == 1)
	{
		
		/*
		Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (source_node->GetObject<MobilityModel>());
		Vector posi = mdl->GetPosition();
		Vector veli = mdl->GetVelocity();
		Vector acci = Vector(0,0,0);
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
		*/
		
		/*
		uint8_t * HMAC1 = new uint8_t[64];	
		if(routing_algorithm == 4)
		{
			std::string filename_HMAC = NS3_ROOT "/analytics/data/security_global_HMAC_data.csv";
			string HMAC_string = read_item_from_csv(filename_HMAC, std::to_string(nid-2), 1);
			cout<<"HMAC global string is "<<HMAC_string<<endl;
			HexStringToBytes(HMAC_string, HMAC1, 64);
		}
		*/
		
		//add_received_data_at_nodes(data_at_nodes_inst+nid, HMAC1, posi, veli, acci, nid, neighborid, size_nei, 0);
		uint32_t size = get_size_of_data_at_nodes(data_at_nodes_inst+nid);
		uint32_t safe_size = (size > 0) ? size : 1;
		//cout<<size<<endl;
		uint32_t nodeid[safe_size];
		Vector position[safe_size];
		Vector acceleration[safe_size];
		Vector velocity[safe_size];
		Time timestamp[safe_size];
		bool neighbors_changed[safe_size];

		struct set_of_neighbors neighbor_set[safe_size];
		
		for(uint32_t i=0;i<size;i++)
		{
			nodeid[i] = large;
			position[i] = Vector(0,0,0);
			acceleration[i] = Vector(0,0,0);
			velocity[i] = Vector(0,0,0);
			timestamp[i] = Simulator::Now();
			for (uint32_t j=0;j<max;j++)
			{
				neighbor_set[i].neighbors[j] = large;
			}
			neighbors_changed[i] = false;
		}
		
		uint32_t k=0;
		for(uint32_t i=0;i<max;i++)
		{
			if (((data_at_nodes_inst+nid)->nodeid[i] != large) and (k<size))
			{
				nodeid[k] = (data_at_nodes_inst+nid)->nodeid[i];
				position[k] = (data_at_nodes_inst+nid)->position[i];
				velocity[k] = (data_at_nodes_inst+nid)->velocity[i];
				acceleration[k] = (data_at_nodes_inst+nid)->acceleration[i];
				timestamp[k] = (data_at_nodes_inst+nid)->timestamp[i];
				neighbor_set[k] = (data_at_nodes_inst+nid)->neighbor_set[i];
				neighbors_changed[k] = (data_at_nodes_inst+nid)->neighbors_changed[i];
				k++;
			}
			
		}
		
		uint32_t nei_sizes[max];
		for(uint32_t i=0;i<max;i++)
		{
			nei_sizes[i] = 0;
		}
		
		for(uint32_t i=0;i<size;i++)
		{
			for(uint32_t j=0;j<max;j++)
			{

				if((neighbor_set[i].neighbors[j]) != large)
				{
					nei_sizes[i] = nei_sizes[i] + 1;
				}	
			}
		}
		
		/*
		for(uint32_t i=0;i<max;i++)
		{
			cout<<"neighbor sizes of agent "<<nid<<"is "<<nei_sizes[i]<<endl;
		}
		*/
		
		Ptr <Ipv4> ipv4;  	
		ipv4 = destination_node->GetObject<Ipv4>();
		Ipv4InterfaceAddress iaddr;
		if (N_Vehicles > 0)
		{
			iaddr = ipv4->GetAddress(1,0);//2nd IPv4 interface,0th address index
		}
		else if (N_Vehicles==0)
		{
			iaddr = ipv4->GetAddress(0,0);//1st IPv4 interface,0th address index
		}
		Ipv4Address dest_ip = iaddr.GetLocal();
		Ptr <Packet> packet1 = Create <Packet> (0);
		
		CustomMetaDataUnicastTagN011 tagN011;
		CustomMetaDataUnicastTagN012 tagN012;
		CustomMetaDataUnicastTagN013 tagN013;
		CustomMetaDataUnicastTagN014 tagN014;
		CustomMetaDataUnicastTagN015 tagN015;
		CustomMetaDataUnicastTagN016 tagN016;
		CustomMetaDataUnicastTagN017 tagN017;
		CustomMetaDataUnicastTagN018 tagN018;
		CustomMetaDataUnicastTagN019 tagN019;
		CustomMetaDataUnicastTagN0110 tagN0110;
		CustomMetaDataUnicastTagN0111 tagN0111;
		CustomMetaDataUnicastTagN0112 tagN0112;
		CustomMetaDataUnicastTagN0113 tagN0113;
		CustomMetaDataUnicastTagN0114 tagN0114;
		CustomMetaDataUnicastTagN0115 tagN0115;
		CustomMetaDataUnicastTagN0116 tagN0116;
		CustomMetaDataUnicastTagN0117 tagN0117;
		CustomMetaDataUnicastTagN0118 tagN0118;
		CustomMetaDataUnicastTagN0119 tagN0119;
		CustomMetaDataUnicastTagN0120 tagN0120;
		CustomMetaDataUnicastTagN0121 tagN0121;
		CustomMetaDataUnicastTagN0122 tagN0122;
		CustomMetaDataUnicastTagN0123 tagN0123;
		CustomMetaDataUnicastTagN0124 tagN0124;
		CustomMetaDataUnicastTagN0125 tagN0125;
		CustomMetaDataUnicastTagN01max tagN01max;
		
		if ((nei_sizes[0] > 0) and (neighbors_changed[0]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[0] = false;
			switch(nei_sizes[0])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[0].neighbors[0];
					tagN011.Setneighborid(new_neighborset1);
					tagN011.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN011);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[0].neighbors[i];
					}
					tagN012.Setneighborid(new_neighborset2);
					tagN012.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN012);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[0].neighbors[i];
					}
					tagN013.Setneighborid(new_neighborset3);
					tagN013.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN013);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[0].neighbors[i];
					}
					tagN014.Setneighborid(new_neighborset4);
					tagN014.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN014);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[0].neighbors[i];
					}
					tagN015.Setneighborid(new_neighborset5);
					tagN015.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN015);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[0].neighbors[i];
					}
					tagN016.Setneighborid(new_neighborset6);
					tagN016.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN016);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[0].neighbors[i];
					}
					tagN017.Setneighborid(new_neighborset7);
					tagN017.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN017);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[0].neighbors[i];
					}
					tagN018.Setneighborid(new_neighborset8);
					tagN018.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN018);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[0].neighbors[i];
					}
					tagN019.Setneighborid(new_neighborset9);
					tagN019.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN019);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[0].neighbors[i];
					}
					tagN0110.Setneighborid(new_neighborset10);
					tagN0110.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0110);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[0].neighbors[i];
					}
					tagN0111.Setneighborid(new_neighborset11);
					tagN0111.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0111);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[0].neighbors[i];
					}
					tagN0112.Setneighborid(new_neighborset12);
					tagN0112.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0112);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[0].neighbors[i];
					}
					tagN0113.Setneighborid(new_neighborset13);
					tagN0113.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0113);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[0].neighbors[i];
					}
					tagN0114.Setneighborid(new_neighborset14);
					tagN0114.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0114);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[0].neighbors[i];
					}
					tagN0115.Setneighborid(new_neighborset15);
					tagN0115.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0115);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[0].neighbors[i];
					}
					tagN0116.Setneighborid(new_neighborset16);
					tagN0116.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0116);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[0].neighbors[i];
					}
					tagN0117.Setneighborid(new_neighborset17);
					tagN0117.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0117);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[0].neighbors[i];
					}
					tagN0118.Setneighborid(new_neighborset18);
					tagN0118.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0118);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[0].neighbors[i];
					}
					tagN0119.Setneighborid(new_neighborset19);
					tagN0119.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0119);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[0].neighbors[i];
					}
					tagN0120.Setneighborid(new_neighborset20);
					tagN0120.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0120);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[0].neighbors[i];
					}
					tagN0121.Setneighborid(new_neighborset21);
					tagN0121.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0121);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[0].neighbors[i];
					}
					tagN0122.Setneighborid(new_neighborset22);
					tagN0122.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0122);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[0].neighbors[i];
					}
					tagN0123.Setneighborid(new_neighborset23);
					tagN0123.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0123);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[0].neighbors[i];
					}
					tagN0124.Setneighborid(new_neighborset24);
					tagN0124.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0124);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[0].neighbors[i];
					}
					tagN0125.Setneighborid(new_neighborset25);
					tagN0125.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN0125);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[0]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[0])
						{
							new_neighborsetmax[i] = neighbor_set[0].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN01max.Setneighborid(new_neighborsetmax);
					tagN01max.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN01max);
					break;
			}
		}
		
	

		CustomMetaDataUnicastTagN021 tagN021;
		CustomMetaDataUnicastTagN022 tagN022;
		CustomMetaDataUnicastTagN023 tagN023;
		CustomMetaDataUnicastTagN024 tagN024;
		CustomMetaDataUnicastTagN025 tagN025;
		CustomMetaDataUnicastTagN026 tagN026;
		CustomMetaDataUnicastTagN027 tagN027;
		CustomMetaDataUnicastTagN028 tagN028;
		CustomMetaDataUnicastTagN029 tagN029;
		CustomMetaDataUnicastTagN0210 tagN0210;
		CustomMetaDataUnicastTagN0211 tagN0211;
		CustomMetaDataUnicastTagN0212 tagN0212;
		CustomMetaDataUnicastTagN0213 tagN0213;
		CustomMetaDataUnicastTagN0214 tagN0214;
		CustomMetaDataUnicastTagN0215 tagN0215;
		CustomMetaDataUnicastTagN0216 tagN0216;
		CustomMetaDataUnicastTagN0217 tagN0217;
		CustomMetaDataUnicastTagN0218 tagN0218;
		CustomMetaDataUnicastTagN0219 tagN0219;
		CustomMetaDataUnicastTagN0220 tagN0220;
		CustomMetaDataUnicastTagN0221 tagN0221;
		CustomMetaDataUnicastTagN0222 tagN0222;
		CustomMetaDataUnicastTagN0223 tagN0223;
		CustomMetaDataUnicastTagN0224 tagN0224;
		CustomMetaDataUnicastTagN0225 tagN0225;
		CustomMetaDataUnicastTagN2max tagN2max;
		
		if ((nei_sizes[1] > 0) and (neighbors_changed[1]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[1] = false;
			switch(nei_sizes[1])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[1].neighbors[0];
					tagN021.Setneighborid(new_neighborset1);
					tagN021.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN021);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[1].neighbors[i];
					}
					tagN022.Setneighborid(new_neighborset2);
					tagN022.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN022);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[1].neighbors[i];
					}
					tagN023.Setneighborid(new_neighborset3);
					tagN023.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN023);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[1].neighbors[i];
					}
					tagN024.Setneighborid(new_neighborset4);
					tagN024.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN024);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[1].neighbors[i];
					}
					tagN025.Setneighborid(new_neighborset5);
					tagN025.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN025);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[1].neighbors[i];
					}
					tagN026.Setneighborid(new_neighborset6);
					tagN026.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN026);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[1].neighbors[i];
					}
					tagN027.Setneighborid(new_neighborset7);
					tagN027.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN027);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[1].neighbors[i];
					}
					tagN028.Setneighborid(new_neighborset8);
					tagN028.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN028);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[1].neighbors[i];
					}
					tagN029.Setneighborid(new_neighborset9);
					tagN029.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN029);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[1].neighbors[i];
					}
					tagN0210.Setneighborid(new_neighborset10);
					tagN0210.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0210);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[1].neighbors[i];
					}
					tagN0211.Setneighborid(new_neighborset11);
					tagN0211.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0211);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[1].neighbors[i];
					}
					tagN0212.Setneighborid(new_neighborset12);
					tagN0212.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0212);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[1].neighbors[i];
					}
					tagN0213.Setneighborid(new_neighborset13);
					tagN0213.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0213);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[1].neighbors[i];
					}
					tagN0214.Setneighborid(new_neighborset14);
					tagN0214.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0214);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[1].neighbors[i];
					}
					tagN0215.Setneighborid(new_neighborset15);
					tagN0215.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0215);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[1].neighbors[i];
					}
					tagN0216.Setneighborid(new_neighborset16);
					tagN0216.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0216);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[1].neighbors[i];
					}
					tagN0217.Setneighborid(new_neighborset17);
					tagN0217.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0217);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[1].neighbors[i];
					}
					tagN0218.Setneighborid(new_neighborset18);
					tagN0218.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0218);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[1].neighbors[i];
					}
					tagN0219.Setneighborid(new_neighborset19);
					tagN0219.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0219);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[1].neighbors[i];
					}
					tagN0220.Setneighborid(new_neighborset20);
					tagN0220.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0220);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[1].neighbors[i];
					}
					tagN0221.Setneighborid(new_neighborset21);
					tagN0221.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0221);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[1].neighbors[i];
					}
					tagN0222.Setneighborid(new_neighborset22);
					tagN0222.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0222);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[1].neighbors[i];
					}
					tagN0223.Setneighborid(new_neighborset23);
					tagN0223.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0223);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[1].neighbors[i];
					}
					tagN0224.Setneighborid(new_neighborset24);
					tagN0224.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0224);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[1].neighbors[i];
					}
					tagN0225.Setneighborid(new_neighborset25);
					tagN0225.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN0225);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[1]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[1])
						{
							new_neighborsetmax[i] = neighbor_set[1].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN2max.Setneighborid(new_neighborsetmax);
					tagN2max.Setnodeid(nodeid[1]);
					packet1->AddPacketTag(tagN2max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN31 tagN31;
		CustomMetaDataUnicastTagN32 tagN32;
		CustomMetaDataUnicastTagN33 tagN33;
		CustomMetaDataUnicastTagN34 tagN34;
		CustomMetaDataUnicastTagN35 tagN35;
		CustomMetaDataUnicastTagN36 tagN36;
		CustomMetaDataUnicastTagN37 tagN37;
		CustomMetaDataUnicastTagN38 tagN38;
		CustomMetaDataUnicastTagN39 tagN39;
		CustomMetaDataUnicastTagN310 tagN310;
		CustomMetaDataUnicastTagN311 tagN311;
		CustomMetaDataUnicastTagN312 tagN312;
		CustomMetaDataUnicastTagN313 tagN313;
		CustomMetaDataUnicastTagN314 tagN314;
		CustomMetaDataUnicastTagN315 tagN315;
		CustomMetaDataUnicastTagN316 tagN316;
		CustomMetaDataUnicastTagN317 tagN317;
		CustomMetaDataUnicastTagN318 tagN318;
		CustomMetaDataUnicastTagN319 tagN319;
		CustomMetaDataUnicastTagN320 tagN320;
		CustomMetaDataUnicastTagN321 tagN321;
		CustomMetaDataUnicastTagN322 tagN322;
		CustomMetaDataUnicastTagN323 tagN323;
		CustomMetaDataUnicastTagN324 tagN324;
		CustomMetaDataUnicastTagN325 tagN325;
		CustomMetaDataUnicastTagN3max tagN3max;
		
		if ((nei_sizes[2] > 0) and (neighbors_changed[2]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[2] = false;
			switch(nei_sizes[2])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[2].neighbors[0];
					tagN31.Setneighborid(new_neighborset1);
					tagN31.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN31);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[2].neighbors[i];
					}
					tagN32.Setneighborid(new_neighborset2);
					tagN32.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN32);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[2].neighbors[i];
					}
					tagN33.Setneighborid(new_neighborset3);
					tagN33.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN33);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[2].neighbors[i];
					}
					tagN34.Setneighborid(new_neighborset4);
					tagN34.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN34);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[2].neighbors[i];
					}
					tagN35.Setneighborid(new_neighborset5);
					tagN35.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN35);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[2].neighbors[i];
					}
					tagN36.Setneighborid(new_neighborset6);
					tagN36.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN36);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[2].neighbors[i];
					}
					tagN37.Setneighborid(new_neighborset7);
					tagN37.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN37);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[2].neighbors[i];
					}
					tagN38.Setneighborid(new_neighborset8);
					tagN38.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN38);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[2].neighbors[i];
					}
					tagN39.Setneighborid(new_neighborset9);
					tagN39.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN39);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[2].neighbors[i];
					}
					tagN310.Setneighborid(new_neighborset10);
					tagN310.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN310);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[2].neighbors[i];
					}
					tagN311.Setneighborid(new_neighborset11);
					tagN311.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN311);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[2].neighbors[i];
					}
					tagN312.Setneighborid(new_neighborset12);
					tagN312.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN312);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[2].neighbors[i];
					}
					tagN313.Setneighborid(new_neighborset13);
					tagN313.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN313);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[2].neighbors[i];
					}
					tagN314.Setneighborid(new_neighborset14);
					tagN314.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN314);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[2].neighbors[i];
					}
					tagN315.Setneighborid(new_neighborset15);
					tagN315.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN315);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[2].neighbors[i];
					}
					tagN316.Setneighborid(new_neighborset16);
					tagN316.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN316);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[2].neighbors[i];
					}
					tagN317.Setneighborid(new_neighborset17);
					tagN317.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN317);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[2].neighbors[i];
					}
					tagN318.Setneighborid(new_neighborset18);
					tagN318.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN318);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[2].neighbors[i];
					}
					tagN319.Setneighborid(new_neighborset19);
					tagN319.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN319);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[2].neighbors[i];
					}
					tagN320.Setneighborid(new_neighborset20);
					tagN320.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN320);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[2].neighbors[i];
					}
					tagN321.Setneighborid(new_neighborset21);
					tagN321.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN321);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[2].neighbors[i];
					}
					tagN322.Setneighborid(new_neighborset22);
					tagN322.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN322);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[2].neighbors[i];
					}
					tagN323.Setneighborid(new_neighborset23);
					tagN323.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN323);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[2].neighbors[i];
					}
					tagN324.Setneighborid(new_neighborset24);
					tagN324.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN324);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[2].neighbors[i];
					}
					tagN325.Setneighborid(new_neighborset25);
					tagN325.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN325);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded. size is  "<<nei_sizes[2]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[2])
						{
							new_neighborsetmax[i] = neighbor_set[2].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN3max.Setneighborid(new_neighborsetmax);
					tagN3max.Setnodeid(nodeid[2]);
					packet1->AddPacketTag(tagN3max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN41 tagN41;
		CustomMetaDataUnicastTagN42 tagN42;
		CustomMetaDataUnicastTagN43 tagN43;
		CustomMetaDataUnicastTagN44 tagN44;
		CustomMetaDataUnicastTagN45 tagN45;
		CustomMetaDataUnicastTagN46 tagN46;
		CustomMetaDataUnicastTagN47 tagN47;
		CustomMetaDataUnicastTagN48 tagN48;
		CustomMetaDataUnicastTagN49 tagN49;
		CustomMetaDataUnicastTagN410 tagN410;
		CustomMetaDataUnicastTagN411 tagN411;
		CustomMetaDataUnicastTagN412 tagN412;
		CustomMetaDataUnicastTagN413 tagN413;
		CustomMetaDataUnicastTagN414 tagN414;
		CustomMetaDataUnicastTagN415 tagN415;
		CustomMetaDataUnicastTagN416 tagN416;
		CustomMetaDataUnicastTagN417 tagN417;
		CustomMetaDataUnicastTagN418 tagN418;
		CustomMetaDataUnicastTagN419 tagN419;
		CustomMetaDataUnicastTagN420 tagN420;
		CustomMetaDataUnicastTagN421 tagN421;
		CustomMetaDataUnicastTagN422 tagN422;
		CustomMetaDataUnicastTagN423 tagN423;
		CustomMetaDataUnicastTagN424 tagN424;
		CustomMetaDataUnicastTagN425 tagN425;
		CustomMetaDataUnicastTagN4max tagN4max;
		
		if ((nei_sizes[3] > 0)  and (neighbors_changed[3]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[3] = false;
			switch(nei_sizes[3])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[3].neighbors[0];
					tagN41.Setneighborid(new_neighborset1);
					tagN41.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN41);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[3].neighbors[i];
					}
					tagN42.Setneighborid(new_neighborset2);
					tagN42.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN42);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[3].neighbors[i];
					}
					tagN43.Setneighborid(new_neighborset3);
					tagN43.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN43);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[3].neighbors[i];
					}
					tagN44.Setneighborid(new_neighborset4);
					tagN44.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN44);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[3].neighbors[i];
					}
					tagN45.Setneighborid(new_neighborset5);
					tagN45.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN45);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[3].neighbors[i];
					}
					tagN46.Setneighborid(new_neighborset6);
					tagN46.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN46);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[3].neighbors[i];
					}
					tagN47.Setneighborid(new_neighborset7);
					tagN47.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN47);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[3].neighbors[i];
					}
					tagN48.Setneighborid(new_neighborset8);
					tagN48.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN48);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[3].neighbors[i];
					}
					tagN49.Setneighborid(new_neighborset9);
					tagN49.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN49);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[3].neighbors[i];
					}
					tagN410.Setneighborid(new_neighborset10);
					tagN410.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN410);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[3].neighbors[i];
					}
					tagN411.Setneighborid(new_neighborset11);
					tagN411.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN411);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[3].neighbors[i];
					}
					tagN412.Setneighborid(new_neighborset12);
					tagN412.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN412);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[3].neighbors[i];
					}
					tagN413.Setneighborid(new_neighborset13);
					tagN413.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN413);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[3].neighbors[i];
					}
					tagN414.Setneighborid(new_neighborset14);
					tagN414.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN414);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[3].neighbors[i];
					}
					tagN415.Setneighborid(new_neighborset15);
					tagN415.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN415);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[3].neighbors[i];
					}
					tagN416.Setneighborid(new_neighborset16);
					tagN416.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN416);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[3].neighbors[i];
					}
					tagN417.Setneighborid(new_neighborset17);
					tagN417.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN417);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[3].neighbors[i];
					}
					tagN418.Setneighborid(new_neighborset18);
					tagN418.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN418);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[3].neighbors[i];
					}
					tagN419.Setneighborid(new_neighborset19);
					tagN419.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN419);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[3].neighbors[i];
					}
					tagN420.Setneighborid(new_neighborset20);
					tagN420.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN420);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[3].neighbors[i];
					}
					tagN421.Setneighborid(new_neighborset21);
					tagN421.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN421);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[3].neighbors[i];
					}
					tagN422.Setneighborid(new_neighborset22);
					tagN422.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN422);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[3].neighbors[i];
					}
					tagN423.Setneighborid(new_neighborset23);
					tagN423.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN423);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[3].neighbors[i];
					}
					tagN424.Setneighborid(new_neighborset24);
					tagN424.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN424);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[3].neighbors[i];
					}
					tagN425.Setneighborid(new_neighborset25);
					tagN425.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN425);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[3]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[3])
						{
							new_neighborsetmax[i] = neighbor_set[3].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN4max.Setneighborid(new_neighborsetmax);
					tagN4max.Setnodeid(nodeid[3]);
					packet1->AddPacketTag(tagN4max);
					break;
			}
		
		}
		
		
		
		CustomMetaDataUnicastTagN51 tagN51;
		CustomMetaDataUnicastTagN52 tagN52;
		CustomMetaDataUnicastTagN53 tagN53;
		CustomMetaDataUnicastTagN54 tagN54;
		CustomMetaDataUnicastTagN55 tagN55;
		CustomMetaDataUnicastTagN56 tagN56;
		CustomMetaDataUnicastTagN57 tagN57;
		CustomMetaDataUnicastTagN58 tagN58;
		CustomMetaDataUnicastTagN59 tagN59;
		CustomMetaDataUnicastTagN510 tagN510;
		CustomMetaDataUnicastTagN511 tagN511;
		CustomMetaDataUnicastTagN512 tagN512;
		CustomMetaDataUnicastTagN513 tagN513;
		CustomMetaDataUnicastTagN514 tagN514;
		CustomMetaDataUnicastTagN515 tagN515;
		CustomMetaDataUnicastTagN516 tagN516;
		CustomMetaDataUnicastTagN517 tagN517;
		CustomMetaDataUnicastTagN518 tagN518;
		CustomMetaDataUnicastTagN519 tagN519;
		CustomMetaDataUnicastTagN520 tagN520;
		CustomMetaDataUnicastTagN521 tagN521;
		CustomMetaDataUnicastTagN522 tagN522;
		CustomMetaDataUnicastTagN523 tagN523;
		CustomMetaDataUnicastTagN524 tagN524;
		CustomMetaDataUnicastTagN525 tagN525;
		CustomMetaDataUnicastTagN5max tagN5max;
		
		if ((nei_sizes[4] > 0) and (neighbors_changed[4]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[4] = false;
			switch(nei_sizes[4])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[4].neighbors[0];
					tagN51.Setneighborid(new_neighborset1);
					tagN51.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN51);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[4].neighbors[i];
					}
					tagN52.Setneighborid(new_neighborset2);
					tagN52.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN52);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[4].neighbors[i];
					}
					tagN53.Setneighborid(new_neighborset3);
					tagN53.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN53);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[4].neighbors[i];
					}
					tagN54.Setneighborid(new_neighborset4);
					tagN54.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN54);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[4].neighbors[i];
					}
					tagN55.Setneighborid(new_neighborset5);
					tagN55.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN55);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[4].neighbors[i];
					}
					tagN56.Setneighborid(new_neighborset6);
					tagN56.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN56);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[4].neighbors[i];
					}
					tagN57.Setneighborid(new_neighborset7);
					tagN57.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN57);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[4].neighbors[i];
					}
					tagN58.Setneighborid(new_neighborset8);
					tagN58.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN58);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[4].neighbors[i];
					}
					tagN59.Setneighborid(new_neighborset9);
					tagN59.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN59);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[4].neighbors[i];
					}
					tagN510.Setneighborid(new_neighborset10);
					tagN510.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN510);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[4].neighbors[i];
					}
					tagN511.Setneighborid(new_neighborset11);
					tagN511.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN511);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[4].neighbors[i];
					}
					tagN512.Setneighborid(new_neighborset12);
					tagN512.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN512);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[4].neighbors[i];
					}
					tagN513.Setneighborid(new_neighborset13);
					tagN513.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN513);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[4].neighbors[i];
					}
					tagN514.Setneighborid(new_neighborset14);
					tagN514.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN514);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[4].neighbors[i];
					}
					tagN515.Setneighborid(new_neighborset15);
					tagN515.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN515);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[4].neighbors[i];
					}
					tagN516.Setneighborid(new_neighborset16);
					tagN516.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN516);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[4].neighbors[i];
					}
					tagN517.Setneighborid(new_neighborset17);
					tagN517.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN517);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[4].neighbors[i];
					}
					tagN518.Setneighborid(new_neighborset18);
					tagN518.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN518);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[4].neighbors[i];
					}
					tagN519.Setneighborid(new_neighborset19);
					tagN519.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN519);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[4].neighbors[i];
					}
					tagN520.Setneighborid(new_neighborset20);
					tagN520.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN520);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[4].neighbors[i];
					}
					tagN521.Setneighborid(new_neighborset21);
					tagN521.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN521);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[4].neighbors[i];
					}
					tagN522.Setneighborid(new_neighborset22);
					tagN522.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN522);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[4].neighbors[i];
					}
					tagN523.Setneighborid(new_neighborset23);
					tagN523.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN523);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[4].neighbors[i];
					}
					tagN524.Setneighborid(new_neighborset24);
					tagN524.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN524);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[4].neighbors[i];
					}
					tagN525.Setneighborid(new_neighborset25);
					tagN525.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN525);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[4]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[4])
						{
							new_neighborsetmax[i] = neighbor_set[4].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN5max.Setneighborid(new_neighborsetmax);
					tagN5max.Setnodeid(nodeid[4]);
					packet1->AddPacketTag(tagN5max);
					break;
			}
		
		}		

		CustomMetaDataUnicastTagN61 tagN61;
		CustomMetaDataUnicastTagN62 tagN62;
		CustomMetaDataUnicastTagN63 tagN63;
		CustomMetaDataUnicastTagN64 tagN64;
		CustomMetaDataUnicastTagN65 tagN65;
		CustomMetaDataUnicastTagN66 tagN66;
		CustomMetaDataUnicastTagN67 tagN67;
		CustomMetaDataUnicastTagN68 tagN68;
		CustomMetaDataUnicastTagN69 tagN69;
		CustomMetaDataUnicastTagN610 tagN610;
		CustomMetaDataUnicastTagN611 tagN611;
		CustomMetaDataUnicastTagN612 tagN612;
		CustomMetaDataUnicastTagN613 tagN613;
		CustomMetaDataUnicastTagN614 tagN614;
		CustomMetaDataUnicastTagN615 tagN615;
		CustomMetaDataUnicastTagN616 tagN616;
		CustomMetaDataUnicastTagN617 tagN617;
		CustomMetaDataUnicastTagN618 tagN618;
		CustomMetaDataUnicastTagN619 tagN619;
		CustomMetaDataUnicastTagN620 tagN620;
		CustomMetaDataUnicastTagN621 tagN621;
		CustomMetaDataUnicastTagN622 tagN622;
		CustomMetaDataUnicastTagN623 tagN623;
		CustomMetaDataUnicastTagN624 tagN624;
		CustomMetaDataUnicastTagN625 tagN625;
		CustomMetaDataUnicastTagN6max tagN6max;
		
		if ((nei_sizes[5] > 0) and (neighbors_changed[5]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[5] = false;
			switch(nei_sizes[5])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[5].neighbors[0];
					tagN61.Setneighborid(new_neighborset1);
					tagN61.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN61);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[5].neighbors[i];
					}
					tagN62.Setneighborid(new_neighborset2);
					tagN62.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN62);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[5].neighbors[i];
					}
					tagN63.Setneighborid(new_neighborset3);
					tagN63.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN63);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[5].neighbors[i];
					}
					tagN64.Setneighborid(new_neighborset4);
					tagN64.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN64);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[5].neighbors[i];
					}
					tagN65.Setneighborid(new_neighborset5);
					tagN65.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN65);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[5].neighbors[i];
					}
					tagN66.Setneighborid(new_neighborset6);
					tagN66.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN66);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[5].neighbors[i];
					}
					tagN67.Setneighborid(new_neighborset7);
					tagN67.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN67);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[5].neighbors[i];
					}
					tagN68.Setneighborid(new_neighborset8);
					tagN68.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN68);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[5].neighbors[i];
					}
					tagN69.Setneighborid(new_neighborset9);
					tagN69.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN69);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[5].neighbors[i];
					}
					tagN610.Setneighborid(new_neighborset10);
					tagN610.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN610);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[5].neighbors[i];
					}
					tagN611.Setneighborid(new_neighborset11);
					tagN611.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN611);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[5].neighbors[i];
					}
					tagN612.Setneighborid(new_neighborset12);
					tagN612.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN612);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[5].neighbors[i];
					}
					tagN613.Setneighborid(new_neighborset13);
					tagN613.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN613);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[5].neighbors[i];
					}
					tagN614.Setneighborid(new_neighborset14);
					tagN614.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN614);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[5].neighbors[i];
					}
					tagN615.Setneighborid(new_neighborset15);
					tagN615.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN615);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[5].neighbors[i];
					}
					tagN616.Setneighborid(new_neighborset16);
					tagN616.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN616);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[5].neighbors[i];
					}
					tagN617.Setneighborid(new_neighborset17);
					tagN617.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN617);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[5].neighbors[i];
					}
					tagN618.Setneighborid(new_neighborset18);
					tagN618.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN618);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[5].neighbors[i];
					}
					tagN619.Setneighborid(new_neighborset19);
					tagN619.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN619);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[5].neighbors[i];
					}
					tagN620.Setneighborid(new_neighborset20);
					tagN620.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN620);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[5].neighbors[i];
					}
					tagN621.Setneighborid(new_neighborset21);
					tagN621.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN621);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[5].neighbors[i];
					}
					tagN622.Setneighborid(new_neighborset22);
					tagN622.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN622);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[5].neighbors[i];
					}
					tagN623.Setneighborid(new_neighborset23);
					tagN623.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN623);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[5].neighbors[i];
					}
					tagN624.Setneighborid(new_neighborset24);
					tagN624.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN624);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[5].neighbors[i];
					}
					tagN625.Setneighborid(new_neighborset25);
					tagN625.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN625);
					break;
				default:
					cout<<"Etheret:maximum neighbor datasize exceeded "<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[5])
						{
							new_neighborsetmax[i] = neighbor_set[5].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN6max.Setneighborid(new_neighborsetmax);
					tagN6max.Setnodeid(nodeid[5]);
					packet1->AddPacketTag(tagN6max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN71 tagN71;
		CustomMetaDataUnicastTagN72 tagN72;
		CustomMetaDataUnicastTagN73 tagN73;
		CustomMetaDataUnicastTagN74 tagN74;
		CustomMetaDataUnicastTagN75 tagN75;
		CustomMetaDataUnicastTagN76 tagN76;
		CustomMetaDataUnicastTagN77 tagN77;
		CustomMetaDataUnicastTagN78 tagN78;
		CustomMetaDataUnicastTagN79 tagN79;
		CustomMetaDataUnicastTagN710 tagN710;
		CustomMetaDataUnicastTagN711 tagN711;
		CustomMetaDataUnicastTagN712 tagN712;
		CustomMetaDataUnicastTagN713 tagN713;
		CustomMetaDataUnicastTagN714 tagN714;
		CustomMetaDataUnicastTagN715 tagN715;
		CustomMetaDataUnicastTagN716 tagN716;
		CustomMetaDataUnicastTagN717 tagN717;
		CustomMetaDataUnicastTagN718 tagN718;
		CustomMetaDataUnicastTagN719 tagN719;
		CustomMetaDataUnicastTagN720 tagN720;
		CustomMetaDataUnicastTagN721 tagN721;
		CustomMetaDataUnicastTagN722 tagN722;
		CustomMetaDataUnicastTagN723 tagN723;
		CustomMetaDataUnicastTagN724 tagN724;
		CustomMetaDataUnicastTagN725 tagN725;
		CustomMetaDataUnicastTagN7max tagN7max;
		
		if ((nei_sizes[6] > 0) and (neighbors_changed[6]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[6] = false;
			switch(nei_sizes[6])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[6].neighbors[0];
					tagN71.Setneighborid(new_neighborset1);
					tagN71.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN71);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[6].neighbors[i];
					}
					tagN72.Setneighborid(new_neighborset2);
					tagN72.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN72);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[6].neighbors[i];
					}
					tagN73.Setneighborid(new_neighborset3);
					tagN73.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN73);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[6].neighbors[i];
					}
					tagN74.Setneighborid(new_neighborset4);
					tagN74.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN74);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[6].neighbors[i];
					}
					tagN75.Setneighborid(new_neighborset5);
					tagN75.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN75);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[6].neighbors[i];
					}
					tagN76.Setneighborid(new_neighborset6);
					tagN76.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN76);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[6].neighbors[i];
					}
					tagN77.Setneighborid(new_neighborset7);
					tagN77.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN77);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[6].neighbors[i];
					}
					tagN78.Setneighborid(new_neighborset8);
					tagN78.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN78);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[6].neighbors[i];
					}
					tagN79.Setneighborid(new_neighborset9);
					tagN79.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN79);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[6].neighbors[i];
					}
					tagN710.Setneighborid(new_neighborset10);
					tagN710.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN710);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[6].neighbors[i];
					}
					tagN711.Setneighborid(new_neighborset11);
					tagN711.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN711);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[6].neighbors[i];
					}
					tagN712.Setneighborid(new_neighborset12);
					tagN712.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN712);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[6].neighbors[i];
					}
					tagN713.Setneighborid(new_neighborset13);
					tagN713.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN713);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[6].neighbors[i];
					}
					tagN714.Setneighborid(new_neighborset14);
					tagN714.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN714);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[6].neighbors[i];
					}
					tagN715.Setneighborid(new_neighborset15);
					tagN715.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN715);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[6].neighbors[i];
					}
					tagN716.Setneighborid(new_neighborset16);
					tagN716.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN716);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[6].neighbors[i];
					}
					tagN717.Setneighborid(new_neighborset17);
					tagN717.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN717);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[6].neighbors[i];
					}
					tagN718.Setneighborid(new_neighborset18);
					tagN718.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN718);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[6].neighbors[i];
					}
					tagN719.Setneighborid(new_neighborset19);
					tagN719.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN719);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[6].neighbors[i];
					}
					tagN720.Setneighborid(new_neighborset20);
					tagN720.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN720);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[6].neighbors[i];
					}
					tagN721.Setneighborid(new_neighborset21);
					tagN721.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN721);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[6].neighbors[i];
					}
					tagN722.Setneighborid(new_neighborset22);
					tagN722.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN722);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[6].neighbors[i];
					}
					tagN723.Setneighborid(new_neighborset23);
					tagN723.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN723);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[6].neighbors[i];
					}
					tagN724.Setneighborid(new_neighborset24);
					tagN724.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN724);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[6].neighbors[i];
					}
					tagN725.Setneighborid(new_neighborset25);
					tagN725.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN725);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[5]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[6])
						{
							new_neighborsetmax[i] = neighbor_set[6].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN7max.Setneighborid(new_neighborsetmax);
					tagN7max.Setnodeid(nodeid[6]);
					packet1->AddPacketTag(tagN7max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN81 tagN81;
		CustomMetaDataUnicastTagN82 tagN82;
		CustomMetaDataUnicastTagN83 tagN83;
		CustomMetaDataUnicastTagN84 tagN84;
		CustomMetaDataUnicastTagN85 tagN85;
		CustomMetaDataUnicastTagN86 tagN86;
		CustomMetaDataUnicastTagN87 tagN87;
		CustomMetaDataUnicastTagN88 tagN88;
		CustomMetaDataUnicastTagN89 tagN89;
		CustomMetaDataUnicastTagN810 tagN810;
		CustomMetaDataUnicastTagN811 tagN811;
		CustomMetaDataUnicastTagN812 tagN812;
		CustomMetaDataUnicastTagN813 tagN813;
		CustomMetaDataUnicastTagN814 tagN814;
		CustomMetaDataUnicastTagN815 tagN815;
		CustomMetaDataUnicastTagN816 tagN816;
		CustomMetaDataUnicastTagN817 tagN817;
		CustomMetaDataUnicastTagN818 tagN818;
		CustomMetaDataUnicastTagN819 tagN819;
		CustomMetaDataUnicastTagN820 tagN820;
		CustomMetaDataUnicastTagN821 tagN821;
		CustomMetaDataUnicastTagN822 tagN822;
		CustomMetaDataUnicastTagN823 tagN823;
		CustomMetaDataUnicastTagN824 tagN824;
		CustomMetaDataUnicastTagN825 tagN825;
		CustomMetaDataUnicastTagN8max tagN8max;
		
		if ((nei_sizes[7] > 0)  and (neighbors_changed[7]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[7] = false;
			switch(nei_sizes[7])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[7].neighbors[0];
					tagN81.Setneighborid(new_neighborset1);
					tagN81.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN81);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[7].neighbors[i];
					}
					tagN82.Setneighborid(new_neighborset2);
					tagN82.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN82);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[7].neighbors[i];
					}
					tagN83.Setneighborid(new_neighborset3);
					tagN83.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN83);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[7].neighbors[i];
					}
					tagN84.Setneighborid(new_neighborset4);
					tagN84.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN84);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[7].neighbors[i];
					}
					tagN85.Setneighborid(new_neighborset5);
					tagN85.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN85);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[7].neighbors[i];
					}
					tagN86.Setneighborid(new_neighborset6);
					tagN86.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN86);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[7].neighbors[i];
					}
					tagN87.Setneighborid(new_neighborset7);
					tagN87.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN87);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[7].neighbors[i];
					}
					tagN88.Setneighborid(new_neighborset8);
					tagN88.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN88);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[7].neighbors[i];
					}
					tagN89.Setneighborid(new_neighborset9);
					tagN89.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN89);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[7].neighbors[i];
					}
					tagN810.Setneighborid(new_neighborset10);
					tagN810.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN810);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[7].neighbors[i];
					}
					tagN811.Setneighborid(new_neighborset11);
					tagN811.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN811);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[7].neighbors[i];
					}
					tagN812.Setneighborid(new_neighborset12);
					tagN812.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN812);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[7].neighbors[i];
					}
					tagN813.Setneighborid(new_neighborset13);
					tagN813.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN813);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[7].neighbors[i];
					}
					tagN814.Setneighborid(new_neighborset14);
					tagN814.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN814);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[7].neighbors[i];
					}
					tagN815.Setneighborid(new_neighborset15);
					tagN815.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN815);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[7].neighbors[i];
					}
					tagN816.Setneighborid(new_neighborset16);
					tagN816.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN816);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[7].neighbors[i];
					}
					tagN817.Setneighborid(new_neighborset17);
					tagN817.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN817);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[7].neighbors[i];
					}
					tagN818.Setneighborid(new_neighborset18);
					tagN818.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN818);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[7].neighbors[i];
					}
					tagN819.Setneighborid(new_neighborset19);
					tagN819.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN819);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[7].neighbors[i];
					}
					tagN820.Setneighborid(new_neighborset20);
					tagN820.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN820);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[7].neighbors[i];
					}
					tagN821.Setneighborid(new_neighborset21);
					tagN821.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN821);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[7].neighbors[i];
					}
					tagN822.Setneighborid(new_neighborset22);
					tagN822.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN822);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[7].neighbors[i];
					}
					tagN823.Setneighborid(new_neighborset23);
					tagN823.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN823);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[7].neighbors[i];
					}
					tagN824.Setneighborid(new_neighborset24);
					tagN824.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN824);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[7].neighbors[i];
					}
					tagN825.Setneighborid(new_neighborset25);
					tagN825.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN825);
					break;
				default:
					cout<<"Ethernte:maximum neighbor datasize exceeded "<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[7])
						{
							new_neighborsetmax[i] = neighbor_set[7].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN8max.Setneighborid(new_neighborsetmax);
					tagN8max.Setnodeid(nodeid[7]);
					packet1->AddPacketTag(tagN8max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN91 tagN91;
		CustomMetaDataUnicastTagN92 tagN92;
		CustomMetaDataUnicastTagN93 tagN93;
		CustomMetaDataUnicastTagN94 tagN94;
		CustomMetaDataUnicastTagN95 tagN95;
		CustomMetaDataUnicastTagN96 tagN96;
		CustomMetaDataUnicastTagN97 tagN97;
		CustomMetaDataUnicastTagN98 tagN98;
		CustomMetaDataUnicastTagN99 tagN99;
		CustomMetaDataUnicastTagN910 tagN910;
		CustomMetaDataUnicastTagN911 tagN911;
		CustomMetaDataUnicastTagN912 tagN912;
		CustomMetaDataUnicastTagN913 tagN913;
		CustomMetaDataUnicastTagN914 tagN914;
		CustomMetaDataUnicastTagN915 tagN915;
		CustomMetaDataUnicastTagN916 tagN916;
		CustomMetaDataUnicastTagN917 tagN917;
		CustomMetaDataUnicastTagN918 tagN918;
		CustomMetaDataUnicastTagN919 tagN919;
		CustomMetaDataUnicastTagN920 tagN920;
		CustomMetaDataUnicastTagN921 tagN921;
		CustomMetaDataUnicastTagN922 tagN922;
		CustomMetaDataUnicastTagN923 tagN923;
		CustomMetaDataUnicastTagN924 tagN924;
		CustomMetaDataUnicastTagN925 tagN925;
		CustomMetaDataUnicastTagN9max tagN9max;
		
		if ((nei_sizes[8] > 0) and (neighbors_changed[8]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[8] = false;
			switch(nei_sizes[8])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[8].neighbors[0];
					tagN91.Setneighborid(new_neighborset1);
					tagN91.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN91);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[8].neighbors[i];
					}
					tagN92.Setneighborid(new_neighborset2);
					tagN92.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN92);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[8].neighbors[i];
					}
					tagN93.Setneighborid(new_neighborset3);
					tagN93.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN93);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[8].neighbors[i];
					}
					tagN94.Setneighborid(new_neighborset4);
					tagN94.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN94);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[8].neighbors[i];
					}
					tagN95.Setneighborid(new_neighborset5);
					tagN95.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN95);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[8].neighbors[i];
					}
					tagN96.Setneighborid(new_neighborset6);
					tagN96.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN96);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[8].neighbors[i];
					}
					tagN97.Setneighborid(new_neighborset7);
					tagN97.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN97);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[8].neighbors[i];
					}
					tagN98.Setneighborid(new_neighborset8);
					tagN98.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN98);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[8].neighbors[i];
					}
					tagN99.Setneighborid(new_neighborset9);
					tagN99.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN99);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[8].neighbors[i];
					}
					tagN910.Setneighborid(new_neighborset10);
					tagN910.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN910);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[8].neighbors[i];
					}
					tagN911.Setneighborid(new_neighborset11);
					tagN911.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN911);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[8].neighbors[i];
					}
					tagN912.Setneighborid(new_neighborset12);
					tagN912.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN912);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[8].neighbors[i];
					}
					tagN913.Setneighborid(new_neighborset13);
					tagN913.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN913);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[8].neighbors[i];
					}
					tagN914.Setneighborid(new_neighborset14);
					tagN914.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN914);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[8].neighbors[i];
					}
					tagN915.Setneighborid(new_neighborset15);
					tagN915.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN915);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[8].neighbors[i];
					}
					tagN916.Setneighborid(new_neighborset16);
					tagN916.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN916);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[8].neighbors[i];
					}
					tagN917.Setneighborid(new_neighborset17);
					tagN917.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN917);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[8].neighbors[i];
					}
					tagN918.Setneighborid(new_neighborset18);
					tagN918.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN918);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[8].neighbors[i];
					}
					tagN919.Setneighborid(new_neighborset19);
					tagN919.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN919);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[8].neighbors[i];
					}
					tagN920.Setneighborid(new_neighborset20);
					tagN920.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN920);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[8].neighbors[i];
					}
					tagN921.Setneighborid(new_neighborset21);
					tagN921.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN921);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[8].neighbors[i];
					}
					tagN922.Setneighborid(new_neighborset22);
					tagN922.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN922);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[8].neighbors[i];
					}
					tagN923.Setneighborid(new_neighborset23);
					tagN923.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN923);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[8].neighbors[i];
					}
					tagN924.Setneighborid(new_neighborset24);
					tagN924.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN924);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[8].neighbors[i];
					}
					tagN925.Setneighborid(new_neighborset25);
					tagN925.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN925);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[8]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[8])
						{
							new_neighborsetmax[i] = neighbor_set[8].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN9max.Setneighborid(new_neighborsetmax);
					tagN9max.Setnodeid(nodeid[8]);
					packet1->AddPacketTag(tagN9max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN101 tagN101;
		CustomMetaDataUnicastTagN102 tagN102;
		CustomMetaDataUnicastTagN103 tagN103;
		CustomMetaDataUnicastTagN104 tagN104;
		CustomMetaDataUnicastTagN105 tagN105;
		CustomMetaDataUnicastTagN106 tagN106;
		CustomMetaDataUnicastTagN107 tagN107;
		CustomMetaDataUnicastTagN108 tagN108;
		CustomMetaDataUnicastTagN109 tagN109;
		CustomMetaDataUnicastTagN1010 tagN1010;
		CustomMetaDataUnicastTagN1011 tagN1011;
		CustomMetaDataUnicastTagN1012 tagN1012;
		CustomMetaDataUnicastTagN1013 tagN1013;
		CustomMetaDataUnicastTagN1014 tagN1014;
		CustomMetaDataUnicastTagN1015 tagN1015;
		CustomMetaDataUnicastTagN1016 tagN1016;
		CustomMetaDataUnicastTagN1017 tagN1017;
		CustomMetaDataUnicastTagN1018 tagN1018;
		CustomMetaDataUnicastTagN1019 tagN1019;
		CustomMetaDataUnicastTagN1020 tagN1020;
		CustomMetaDataUnicastTagN1021 tagN1021;
		CustomMetaDataUnicastTagN1022 tagN1022;
		CustomMetaDataUnicastTagN1023 tagN1023;
		CustomMetaDataUnicastTagN1024 tagN1024;
		CustomMetaDataUnicastTagN1025 tagN1025;
		CustomMetaDataUnicastTagN10max tagN10max;
		
		if ((nei_sizes[9] > 0) and (neighbors_changed[9]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[9] = false;
			switch(nei_sizes[9])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[9].neighbors[0];
					tagN101.Setneighborid(new_neighborset1);
					tagN101.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN101);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[9].neighbors[i];
					}
					tagN102.Setneighborid(new_neighborset2);
					tagN102.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN102);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[9].neighbors[i];
					}
					tagN103.Setneighborid(new_neighborset3);
					tagN103.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN103);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[9].neighbors[i];
					}
					tagN104.Setneighborid(new_neighborset4);
					tagN104.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN104);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[9].neighbors[i];
					}
					tagN105.Setneighborid(new_neighborset5);
					tagN105.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN105);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[9].neighbors[i];
					}
					tagN106.Setneighborid(new_neighborset6);
					tagN106.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN106);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[9].neighbors[i];
					}
					tagN107.Setneighborid(new_neighborset7);
					tagN107.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN107);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[9].neighbors[i];
					}
					tagN108.Setneighborid(new_neighborset8);
					tagN108.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN108);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[9].neighbors[i];
					}
					tagN109.Setneighborid(new_neighborset9);
					tagN109.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN109);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[9].neighbors[i];
					}
					tagN1010.Setneighborid(new_neighborset10);
					tagN1010.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1010);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[9].neighbors[i];
					}
					tagN1011.Setneighborid(new_neighborset11);
					tagN1011.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1011);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[9].neighbors[i];
					}
					tagN1012.Setneighborid(new_neighborset12);
					tagN1012.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1012);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[9].neighbors[i];
					}
					tagN1013.Setneighborid(new_neighborset13);
					tagN1013.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1013);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[9].neighbors[i];
					}
					tagN1014.Setneighborid(new_neighborset14);
					tagN1014.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1014);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[9].neighbors[i];
					}
					tagN1015.Setneighborid(new_neighborset15);
					tagN1015.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1015);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[9].neighbors[i];
					}
					tagN1016.Setneighborid(new_neighborset16);
					tagN1016.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1016);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[9].neighbors[i];
					}
					tagN1017.Setneighborid(new_neighborset17);
					tagN1017.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1017);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[9].neighbors[i];
					}
					tagN1018.Setneighborid(new_neighborset18);
					tagN1018.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1018);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[9].neighbors[i];
					}
					tagN1019.Setneighborid(new_neighborset19);
					tagN1019.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1019);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[9].neighbors[i];
					}
					tagN1020.Setneighborid(new_neighborset20);
					tagN1020.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1020);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[9].neighbors[i];
					}
					tagN1021.Setneighborid(new_neighborset21);
					tagN1021.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1021);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[9].neighbors[i];
					}
					tagN1022.Setneighborid(new_neighborset22);
					tagN1022.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1022);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[9].neighbors[i];
					}
					tagN1023.Setneighborid(new_neighborset23);
					tagN1023.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1023);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[9].neighbors[i];
					}
					tagN1024.Setneighborid(new_neighborset24);
					tagN1024.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1024);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[9].neighbors[i];
					}
					tagN1025.Setneighborid(new_neighborset25);
					tagN1025.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN1025);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[9]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[9])
						{
							new_neighborsetmax[i] = neighbor_set[9].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN10max.Setneighborid(new_neighborsetmax);
					tagN10max.Setnodeid(nodeid[9]);
					packet1->AddPacketTag(tagN10max);
					break;
			}
		
		}		
		
		CustomMetaDataUnicastTagN111 tagN111;
		CustomMetaDataUnicastTagN112 tagN112;
		CustomMetaDataUnicastTagN113 tagN113;
		CustomMetaDataUnicastTagN114 tagN114;
		CustomMetaDataUnicastTagN115 tagN115;
		CustomMetaDataUnicastTagN116 tagN116;
		CustomMetaDataUnicastTagN117 tagN117;
		CustomMetaDataUnicastTagN118 tagN118;
		CustomMetaDataUnicastTagN119 tagN119;
		CustomMetaDataUnicastTagN1110 tagN1110;
		CustomMetaDataUnicastTagN1111 tagN1111;
		CustomMetaDataUnicastTagN1112 tagN1112;
		CustomMetaDataUnicastTagN1113 tagN1113;
		CustomMetaDataUnicastTagN1114 tagN1114;
		CustomMetaDataUnicastTagN1115 tagN1115;
		CustomMetaDataUnicastTagN1116 tagN1116;
		CustomMetaDataUnicastTagN1117 tagN1117;
		CustomMetaDataUnicastTagN1118 tagN1118;
		CustomMetaDataUnicastTagN1119 tagN1119;
		CustomMetaDataUnicastTagN1120 tagN1120;
		CustomMetaDataUnicastTagN1121 tagN1121;
		CustomMetaDataUnicastTagN1122 tagN1122;
		CustomMetaDataUnicastTagN1123 tagN1123;
		CustomMetaDataUnicastTagN1124 tagN1124;
		CustomMetaDataUnicastTagN1125 tagN1125;
		CustomMetaDataUnicastTagN11max tagN11max;
		
		if ((nei_sizes[10] > 0) and (neighbors_changed[10]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[10] = false;
			switch(nei_sizes[10])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[10].neighbors[0];
					tagN111.Setneighborid(new_neighborset1);
					tagN111.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN111);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[10].neighbors[i];
					}
					tagN112.Setneighborid(new_neighborset2);
					tagN112.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN112);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[10].neighbors[i];
					}
					tagN113.Setneighborid(new_neighborset3);
					tagN113.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN113);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[10].neighbors[i];
					}
					tagN114.Setneighborid(new_neighborset4);
					tagN114.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN114);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[10].neighbors[i];
					}
					tagN115.Setneighborid(new_neighborset5);
					tagN115.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN115);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[10].neighbors[i];
					}
					tagN116.Setneighborid(new_neighborset6);
					tagN116.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN116);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[10].neighbors[i];
					}
					tagN117.Setneighborid(new_neighborset7);
					tagN117.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN117);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[10].neighbors[i];
					}
					tagN118.Setneighborid(new_neighborset8);
					tagN118.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN118);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[10].neighbors[i];
					}
					tagN119.Setneighborid(new_neighborset9);
					tagN119.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN119);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[10].neighbors[i];
					}
					tagN1110.Setneighborid(new_neighborset10);
					tagN1110.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1110);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[10].neighbors[i];
					}
					tagN1111.Setneighborid(new_neighborset11);
					tagN1111.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1111);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[10].neighbors[i];
					}
					tagN1112.Setneighborid(new_neighborset12);
					tagN1112.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1112);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[10].neighbors[i];
					}
					tagN1113.Setneighborid(new_neighborset13);
					tagN1113.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1113);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[10].neighbors[i];
					}
					tagN1114.Setneighborid(new_neighborset14);
					tagN1114.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1114);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[10].neighbors[i];
					}
					tagN1115.Setneighborid(new_neighborset15);
					tagN1115.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1115);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[10].neighbors[i];
					}
					tagN1116.Setneighborid(new_neighborset16);
					tagN1116.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1116);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[10].neighbors[i];
					}
					tagN1117.Setneighborid(new_neighborset17);
					tagN1117.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1117);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[10].neighbors[i];
					}
					tagN1118.Setneighborid(new_neighborset18);
					tagN1118.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1118);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[10].neighbors[i];
					}
					tagN1119.Setneighborid(new_neighborset19);
					tagN1119.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1119);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[10].neighbors[i];
					}
					tagN1120.Setneighborid(new_neighborset20);
					tagN1120.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1120);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[10].neighbors[i];
					}
					tagN1121.Setneighborid(new_neighborset21);
					tagN1121.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1121);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[10].neighbors[i];
					}
					tagN1122.Setneighborid(new_neighborset22);
					tagN1122.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1122);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[10].neighbors[i];
					}
					tagN1123.Setneighborid(new_neighborset23);
					tagN1123.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1123);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[10].neighbors[i];
					}
					tagN1124.Setneighborid(new_neighborset24);
					tagN1124.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1124);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[10].neighbors[i];
					}
					tagN1125.Setneighborid(new_neighborset25);
					tagN1125.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN1125);
					break;
				default:
					cout<<"Etheret:maximum neighbor datasize exceeded. size is "<<nei_sizes[10]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[10])
						{
							new_neighborsetmax[i] = neighbor_set[10].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN11max.Setneighborid(new_neighborsetmax);
					tagN11max.Setnodeid(nodeid[10]);
					packet1->AddPacketTag(tagN11max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN121 tagN121;
		CustomMetaDataUnicastTagN122 tagN122;
		CustomMetaDataUnicastTagN123 tagN123;
		CustomMetaDataUnicastTagN124 tagN124;
		CustomMetaDataUnicastTagN125 tagN125;
		CustomMetaDataUnicastTagN126 tagN126;
		CustomMetaDataUnicastTagN127 tagN127;
		CustomMetaDataUnicastTagN128 tagN128;
		CustomMetaDataUnicastTagN129 tagN129;
		CustomMetaDataUnicastTagN1210 tagN1210;
		CustomMetaDataUnicastTagN1211 tagN1211;
		CustomMetaDataUnicastTagN1212 tagN1212;
		CustomMetaDataUnicastTagN1213 tagN1213;
		CustomMetaDataUnicastTagN1214 tagN1214;
		CustomMetaDataUnicastTagN1215 tagN1215;
		CustomMetaDataUnicastTagN1216 tagN1216;
		CustomMetaDataUnicastTagN1217 tagN1217;
		CustomMetaDataUnicastTagN1218 tagN1218;
		CustomMetaDataUnicastTagN1219 tagN1219;
		CustomMetaDataUnicastTagN1220 tagN1220;
		CustomMetaDataUnicastTagN1221 tagN1221;
		CustomMetaDataUnicastTagN1222 tagN1222;
		CustomMetaDataUnicastTagN1223 tagN1223;
		CustomMetaDataUnicastTagN1224 tagN1224;
		CustomMetaDataUnicastTagN1225 tagN1225;
		CustomMetaDataUnicastTagN12max tagN12max;
		
		
		if ((nei_sizes[11] > 0) and (neighbors_changed[11]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[11] = false;
			switch(nei_sizes[11])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[11].neighbors[0];
					tagN121.Setneighborid(new_neighborset1);
					tagN121.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN121);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[11].neighbors[i];
					}
					tagN122.Setneighborid(new_neighborset2);
					tagN122.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN122);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[11].neighbors[i];
					}
					tagN123.Setneighborid(new_neighborset3);
					tagN123.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN123);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[11].neighbors[i];
					}
					tagN124.Setneighborid(new_neighborset4);
					tagN124.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN124);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[11].neighbors[i];
					}
					tagN125.Setneighborid(new_neighborset5);
					tagN125.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN125);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[11].neighbors[i];
					}
					tagN126.Setneighborid(new_neighborset6);
					tagN126.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN126);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[11].neighbors[i];
					}
					tagN127.Setneighborid(new_neighborset7);
					tagN127.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN127);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[11].neighbors[i];
					}
					tagN128.Setneighborid(new_neighborset8);
					tagN128.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN128);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[11].neighbors[i];
					}
					tagN129.Setneighborid(new_neighborset9);
					tagN129.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN129);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[11].neighbors[i];
					}
					tagN1210.Setneighborid(new_neighborset10);
					tagN1210.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1210);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[11].neighbors[i];
					}
					tagN1211.Setneighborid(new_neighborset11);
					tagN1211.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1211);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[11].neighbors[i];
					}
					tagN1212.Setneighborid(new_neighborset12);
					tagN1212.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1212);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[11].neighbors[i];
					}
					tagN1213.Setneighborid(new_neighborset13);
					tagN1213.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1213);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[11].neighbors[i];
					}
					tagN1214.Setneighborid(new_neighborset14);
					tagN1214.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1214);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[11].neighbors[i];
					}
					tagN1215.Setneighborid(new_neighborset15);
					tagN1215.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1215);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[11].neighbors[i];
					}
					tagN1216.Setneighborid(new_neighborset16);
					tagN1216.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1216);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[11].neighbors[i];
					}
					tagN1217.Setneighborid(new_neighborset17);
					tagN1217.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1217);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[11].neighbors[i];
					}
					tagN1218.Setneighborid(new_neighborset18);
					tagN1218.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1218);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[11].neighbors[i];
					}
					tagN1219.Setneighborid(new_neighborset19);
					tagN1219.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1219);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[11].neighbors[i];
					}
					tagN1220.Setneighborid(new_neighborset20);
					tagN1220.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1220);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[11].neighbors[i];
					}
					tagN1221.Setneighborid(new_neighborset21);
					tagN1221.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1221);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[11].neighbors[i];
					}
					tagN1222.Setneighborid(new_neighborset22);
					tagN1222.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1222);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[11].neighbors[i];
					}
					tagN1223.Setneighborid(new_neighborset23);
					tagN1223.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1223);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[11].neighbors[i];
					}
					tagN1224.Setneighborid(new_neighborset24);
					tagN1224.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1224);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[11].neighbors[i];
					}
					tagN1225.Setneighborid(new_neighborset25);
					tagN1225.Setnodeid(nodeid[11]);
					packet1->AddPacketTag(tagN1225);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[11]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[11])
						{
							new_neighborsetmax[i] = neighbor_set[11].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN12max.Setnodeid(nodeid[11]);
					tagN12max.Setneighborid(new_neighborsetmax);
					packet1->AddPacketTag(tagN12max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN131 tagN131;
		CustomMetaDataUnicastTagN132 tagN132;
		CustomMetaDataUnicastTagN133 tagN133;
		CustomMetaDataUnicastTagN134 tagN134;
		CustomMetaDataUnicastTagN135 tagN135;
		CustomMetaDataUnicastTagN136 tagN136;
		CustomMetaDataUnicastTagN137 tagN137;
		CustomMetaDataUnicastTagN138 tagN138;
		CustomMetaDataUnicastTagN139 tagN139;
		CustomMetaDataUnicastTagN1310 tagN1310;
		CustomMetaDataUnicastTagN1311 tagN1311;
		CustomMetaDataUnicastTagN1312 tagN1312;
		CustomMetaDataUnicastTagN1313 tagN1313;
		CustomMetaDataUnicastTagN1314 tagN1314;
		CustomMetaDataUnicastTagN1315 tagN1315;
		CustomMetaDataUnicastTagN1316 tagN1316;
		CustomMetaDataUnicastTagN1317 tagN1317;
		CustomMetaDataUnicastTagN1318 tagN1318;
		CustomMetaDataUnicastTagN1319 tagN1319;
		CustomMetaDataUnicastTagN1320 tagN1320;
		CustomMetaDataUnicastTagN1321 tagN1321;
		CustomMetaDataUnicastTagN1322 tagN1322;
		CustomMetaDataUnicastTagN1323 tagN1323;
		CustomMetaDataUnicastTagN1324 tagN1324;
		CustomMetaDataUnicastTagN1325 tagN1325;
		CustomMetaDataUnicastTagN13max tagN13max;
		
		if ((nei_sizes[12] > 0) and (neighbors_changed[12]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[12] = false;
			switch(nei_sizes[12])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[12].neighbors[0];
					tagN131.Setneighborid(new_neighborset1);
					tagN131.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN131);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[12].neighbors[i];
					}
					tagN132.Setneighborid(new_neighborset2);
					tagN132.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN132);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[12].neighbors[i];
					}
					tagN133.Setneighborid(new_neighborset3);
					tagN133.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN133);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[12].neighbors[i];
					}
					tagN134.Setneighborid(new_neighborset4);
					tagN134.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN134);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[12].neighbors[i];
					}
					tagN135.Setneighborid(new_neighborset5);
					tagN135.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN135);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[12].neighbors[i];
					}
					tagN136.Setneighborid(new_neighborset6);
					tagN136.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN136);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[12].neighbors[i];
					}
					tagN137.Setneighborid(new_neighborset7);
					tagN137.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN137);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[12].neighbors[i];
					}
					tagN138.Setneighborid(new_neighborset8);
					tagN138.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN138);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[12].neighbors[i];
					}
					tagN139.Setneighborid(new_neighborset9);
					tagN139.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN139);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[12].neighbors[i];
					}
					tagN1310.Setneighborid(new_neighborset10);
					tagN1310.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1310);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[12].neighbors[i];
					}
					tagN1311.Setneighborid(new_neighborset11);
					tagN1311.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1311);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[12].neighbors[i];
					}
					tagN1312.Setneighborid(new_neighborset12);
					tagN1312.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1312);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[12].neighbors[i];
					}
					tagN1313.Setneighborid(new_neighborset13);
					tagN1313.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1313);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[12].neighbors[i];
					}
					tagN1314.Setneighborid(new_neighborset14);
					tagN1314.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1314);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[12].neighbors[i];
					}
					tagN1315.Setneighborid(new_neighborset15);
					tagN1315.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1315);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[12].neighbors[i];
					}
					tagN1316.Setneighborid(new_neighborset16);
					tagN1316.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1316);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[12].neighbors[i];
					}
					tagN1317.Setneighborid(new_neighborset17);
					tagN1317.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1317);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[12].neighbors[i];
					}
					tagN1318.Setneighborid(new_neighborset18);
					tagN1318.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1318);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[12].neighbors[i];
					}
					tagN1319.Setneighborid(new_neighborset19);
					tagN1319.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1319);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[12].neighbors[i];
					}
					tagN1320.Setneighborid(new_neighborset20);
					tagN1320.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1320);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[12].neighbors[i];
					}
					tagN1321.Setneighborid(new_neighborset21);
					tagN1321.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1321);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[12].neighbors[i];
					}
					tagN1322.Setneighborid(new_neighborset22);
					tagN1322.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1322);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[12].neighbors[i];
					}
					tagN1323.Setneighborid(new_neighborset23);
					tagN1323.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1323);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[12].neighbors[i];
					}
					tagN1324.Setneighborid(new_neighborset24);
					tagN1324.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1324);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[12].neighbors[i];
					}
					tagN1325.Setneighborid(new_neighborset25);
					tagN1325.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN1325);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[12]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[12])
						{
							new_neighborsetmax[i] = neighbor_set[12].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN13max.Setneighborid(new_neighborsetmax);
					tagN13max.Setnodeid(nodeid[12]);
					packet1->AddPacketTag(tagN13max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN141 tagN141;
		CustomMetaDataUnicastTagN142 tagN142;
		CustomMetaDataUnicastTagN143 tagN143;
		CustomMetaDataUnicastTagN144 tagN144;
		CustomMetaDataUnicastTagN145 tagN145;
		CustomMetaDataUnicastTagN146 tagN146;
		CustomMetaDataUnicastTagN147 tagN147;
		CustomMetaDataUnicastTagN148 tagN148;
		CustomMetaDataUnicastTagN149 tagN149;
		CustomMetaDataUnicastTagN1410 tagN1410;
		CustomMetaDataUnicastTagN1411 tagN1411;
		CustomMetaDataUnicastTagN1412 tagN1412;
		CustomMetaDataUnicastTagN1413 tagN1413;
		CustomMetaDataUnicastTagN1414 tagN1414;
		CustomMetaDataUnicastTagN1415 tagN1415;
		CustomMetaDataUnicastTagN1416 tagN1416;
		CustomMetaDataUnicastTagN1417 tagN1417;
		CustomMetaDataUnicastTagN1418 tagN1418;
		CustomMetaDataUnicastTagN1419 tagN1419;
		CustomMetaDataUnicastTagN1420 tagN1420;
		CustomMetaDataUnicastTagN1421 tagN1421;
		CustomMetaDataUnicastTagN1422 tagN1422;
		CustomMetaDataUnicastTagN1423 tagN1423;
		CustomMetaDataUnicastTagN1424 tagN1424;
		CustomMetaDataUnicastTagN1425 tagN1425;
		CustomMetaDataUnicastTagN14max tagN14max;
		
		if ((nei_sizes[13] > 0) and (neighbors_changed[13]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[13] = false;
			switch(nei_sizes[13])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[13].neighbors[0];
					tagN141.Setneighborid(new_neighborset1);
					tagN141.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN141);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[13].neighbors[i];
					}
					tagN142.Setneighborid(new_neighborset2);
					tagN142.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN142);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[13].neighbors[i];
					}
					tagN143.Setneighborid(new_neighborset3);
					tagN143.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN143);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[13].neighbors[i];
					}
					tagN144.Setneighborid(new_neighborset4);
					tagN144.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN144);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[13].neighbors[i];
					}
					tagN145.Setneighborid(new_neighborset5);
					tagN145.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN145);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[13].neighbors[i];
					}
					tagN146.Setneighborid(new_neighborset6);
					tagN146.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN146);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[13].neighbors[i];
					}
					tagN147.Setneighborid(new_neighborset7);
					tagN147.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN147);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[13].neighbors[i];
					}
					tagN148.Setneighborid(new_neighborset8);
					tagN148.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN148);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[13].neighbors[i];
					}
					tagN149.Setneighborid(new_neighborset9);
					tagN149.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN149);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[13].neighbors[i];
					}
					tagN1410.Setneighborid(new_neighborset10);
					tagN1410.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1410);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[13].neighbors[i];
					}
					tagN1411.Setneighborid(new_neighborset11);
					tagN1411.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1411);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[13].neighbors[i];
					}
					tagN1412.Setneighborid(new_neighborset12);
					tagN1412.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1412);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[13].neighbors[i];
					}
					tagN1413.Setneighborid(new_neighborset13);
					tagN1413.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1413);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[13].neighbors[i];
					}
					tagN1414.Setneighborid(new_neighborset14);
					tagN1414.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1414);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[13].neighbors[i];
					}
					tagN1415.Setneighborid(new_neighborset15);
					tagN1415.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1415);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[13].neighbors[i];
					}
					tagN1416.Setneighborid(new_neighborset16);
					tagN1416.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1416);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[13].neighbors[i];
					}
					tagN1417.Setneighborid(new_neighborset17);
					tagN1417.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1417);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[13].neighbors[i];
					}
					tagN1418.Setneighborid(new_neighborset18);
					tagN1418.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1418);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[13].neighbors[i];
					}
					tagN1419.Setneighborid(new_neighborset19);
					tagN1419.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1419);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[13].neighbors[i];
					}
					tagN1420.Setneighborid(new_neighborset20);
					tagN1420.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1420);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[13].neighbors[i];
					}
					tagN1421.Setneighborid(new_neighborset21);
					tagN1421.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1421);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[13].neighbors[i];
					}
					tagN1422.Setneighborid(new_neighborset22);
					tagN1422.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1422);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[13].neighbors[i];
					}
					tagN1423.Setneighborid(new_neighborset23);
					tagN1423.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1423);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[13].neighbors[i];
					}
					tagN1424.Setneighborid(new_neighborset24);
					tagN1424.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1424);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[13].neighbors[i];
					}
					tagN1425.Setneighborid(new_neighborset25);
					tagN1425.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN1425);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[13]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[13])
						{
							new_neighborsetmax[i] = neighbor_set[13].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN14max.Setneighborid(new_neighborsetmax);
					tagN14max.Setnodeid(nodeid[13]);
					packet1->AddPacketTag(tagN14max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN151 tagN151;
		CustomMetaDataUnicastTagN152 tagN152;
		CustomMetaDataUnicastTagN153 tagN153;
		CustomMetaDataUnicastTagN154 tagN154;
		CustomMetaDataUnicastTagN155 tagN155;
		CustomMetaDataUnicastTagN156 tagN156;
		CustomMetaDataUnicastTagN157 tagN157;
		CustomMetaDataUnicastTagN158 tagN158;
		CustomMetaDataUnicastTagN159 tagN159;
		CustomMetaDataUnicastTagN1510 tagN1510;
		CustomMetaDataUnicastTagN1511 tagN1511;
		CustomMetaDataUnicastTagN1512 tagN1512;
		CustomMetaDataUnicastTagN1513 tagN1513;
		CustomMetaDataUnicastTagN1514 tagN1514;
		CustomMetaDataUnicastTagN1515 tagN1515;
		CustomMetaDataUnicastTagN1516 tagN1516;
		CustomMetaDataUnicastTagN1517 tagN1517;
		CustomMetaDataUnicastTagN1518 tagN1518;
		CustomMetaDataUnicastTagN1519 tagN1519;
		CustomMetaDataUnicastTagN1520 tagN1520;
		CustomMetaDataUnicastTagN1521 tagN1521;
		CustomMetaDataUnicastTagN1522 tagN1522;
		CustomMetaDataUnicastTagN1523 tagN1523;
		CustomMetaDataUnicastTagN1524 tagN1524;
		CustomMetaDataUnicastTagN1525 tagN1525;
		CustomMetaDataUnicastTagN15max tagN15max;
		
		if ((nei_sizes[14] > 0) and (neighbors_changed[14]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[14] = false;
			switch(nei_sizes[14])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[14].neighbors[0];
					tagN151.Setneighborid(new_neighborset1);
					tagN151.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN151);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[14].neighbors[i];
					}
					tagN152.Setneighborid(new_neighborset2);
					tagN152.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN152);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[14].neighbors[i];
					}
					tagN153.Setneighborid(new_neighborset3);
					tagN153.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN153);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[14].neighbors[i];
					}
					tagN154.Setneighborid(new_neighborset4);
					tagN154.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN154);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[14].neighbors[i];
					}
					tagN155.Setneighborid(new_neighborset5);
					tagN155.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN155);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[14].neighbors[i];
					}
					tagN156.Setneighborid(new_neighborset6);
					tagN156.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN156);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[14].neighbors[i];
					}
					tagN157.Setneighborid(new_neighborset7);
					tagN157.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN157);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[14].neighbors[i];
					}
					tagN158.Setneighborid(new_neighborset8);
					tagN158.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN158);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[14].neighbors[i];
					}
					tagN159.Setneighborid(new_neighborset9);
					tagN159.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN159);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[14].neighbors[i];
					}
					tagN1510.Setneighborid(new_neighborset10);
					tagN1510.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1510);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[14].neighbors[i];
					}
					tagN1511.Setneighborid(new_neighborset11);
					tagN1511.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1511);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[14].neighbors[i];
					}
					tagN1512.Setneighborid(new_neighborset12);
					tagN1512.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1512);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[14].neighbors[i];
					}
					tagN1513.Setneighborid(new_neighborset13);
					tagN1513.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1513);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[14].neighbors[i];
					}
					tagN1514.Setneighborid(new_neighborset14);
					tagN1514.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1514);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[14].neighbors[i];
					}
					tagN1515.Setneighborid(new_neighborset15);
					tagN1515.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1515);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[14].neighbors[i];
					}
					tagN1516.Setneighborid(new_neighborset16);
					tagN1516.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1516);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[14].neighbors[i];
					}
					tagN1517.Setneighborid(new_neighborset17);
					tagN1517.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1517);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[14].neighbors[i];
					}
					tagN1518.Setneighborid(new_neighborset18);
					tagN1518.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1518);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[14].neighbors[i];
					}
					tagN1519.Setneighborid(new_neighborset19);
					tagN1519.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1519);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[14].neighbors[i];
					}
					tagN1520.Setneighborid(new_neighborset20);
					tagN1520.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1520);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[14].neighbors[i];
					}
					tagN1521.Setneighborid(new_neighborset21);
					tagN1521.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1521);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[14].neighbors[i];
					}
					tagN1522.Setneighborid(new_neighborset22);
					tagN1522.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1522);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[14].neighbors[i];
					}
					tagN1523.Setneighborid(new_neighborset23);
					tagN1523.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1523);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[14].neighbors[i];
					}
					tagN1524.Setneighborid(new_neighborset24);
					tagN1524.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1524);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[14].neighbors[i];
					}
					tagN1525.Setneighborid(new_neighborset25);
					tagN1525.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN1525);
					break;
				default:
					cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[14]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[14])
						{
							new_neighborsetmax[i] = neighbor_set[14].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN15max.Setneighborid(new_neighborsetmax);
					tagN15max.Setnodeid(nodeid[14]);
					packet1->AddPacketTag(tagN15max);
					break;
			}
		
		}
		CustomMetaDataUnicastTagN161 tagN161;
		CustomMetaDataUnicastTagN162 tagN162;
		CustomMetaDataUnicastTagN163 tagN163;
		CustomMetaDataUnicastTagN164 tagN164;
		CustomMetaDataUnicastTagN165 tagN165;
		CustomMetaDataUnicastTagN166 tagN166;
		CustomMetaDataUnicastTagN167 tagN167;
		CustomMetaDataUnicastTagN168 tagN168;
		CustomMetaDataUnicastTagN169 tagN169;
		CustomMetaDataUnicastTagN1610 tagN1610;
		CustomMetaDataUnicastTagN1611 tagN1611;
		CustomMetaDataUnicastTagN1612 tagN1612;
		CustomMetaDataUnicastTagN1613 tagN1613;
		CustomMetaDataUnicastTagN1614 tagN1614;
		CustomMetaDataUnicastTagN1615 tagN1615;
		CustomMetaDataUnicastTagN1616 tagN1616;
		CustomMetaDataUnicastTagN1617 tagN1617;
		CustomMetaDataUnicastTagN1618 tagN1618;
		CustomMetaDataUnicastTagN1619 tagN1619;
		CustomMetaDataUnicastTagN1620 tagN1620;
		CustomMetaDataUnicastTagN1621 tagN1621;
		CustomMetaDataUnicastTagN1622 tagN1622;
		CustomMetaDataUnicastTagN1623 tagN1623;
		CustomMetaDataUnicastTagN1624 tagN1624;
		CustomMetaDataUnicastTagN1625 tagN1625;
		CustomMetaDataUnicastTagN16max tagN16max;
		
		if ((nei_sizes[15] > 0) and (neighbors_changed[15]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[15] = false;
			switch(nei_sizes[15])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[15].neighbors[0];
					tagN161.Setneighborid(new_neighborset1);
					tagN161.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN161);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[15].neighbors[i];
					}
					tagN162.Setneighborid(new_neighborset2);
					tagN162.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN162);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[15].neighbors[i];
					}
					tagN163.Setneighborid(new_neighborset3);
					tagN163.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN163);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[15].neighbors[i];
					}
					tagN164.Setneighborid(new_neighborset4);
					tagN164.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN164);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[15].neighbors[i];
					}
					tagN165.Setneighborid(new_neighborset5);
					tagN165.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN165);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[15].neighbors[i];
					}
					tagN166.Setneighborid(new_neighborset6);
					tagN166.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN166);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[15].neighbors[i];
					}
					tagN167.Setneighborid(new_neighborset7);
					tagN167.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN167);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[15].neighbors[i];
					}
					tagN168.Setneighborid(new_neighborset8);
					tagN168.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN168);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[15].neighbors[i];
					}
					tagN169.Setneighborid(new_neighborset9);
					tagN169.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN169);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[15].neighbors[i];
					}
					tagN1610.Setneighborid(new_neighborset10);
					tagN1610.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1610);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[15].neighbors[i];
					}
					tagN1611.Setneighborid(new_neighborset11);
					tagN1611.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1611);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[15].neighbors[i];
					}
					tagN1612.Setneighborid(new_neighborset12);
					tagN1612.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1612);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[15].neighbors[i];
					}
					tagN1613.Setneighborid(new_neighborset13);
					tagN1613.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1613);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[15].neighbors[i];
					}
					tagN1614.Setneighborid(new_neighborset14);
					tagN1614.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1614);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[15].neighbors[i];
					}
					tagN1615.Setneighborid(new_neighborset15);
					tagN1615.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1615);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[15].neighbors[i];
					}
					tagN1616.Setneighborid(new_neighborset16);
					tagN1616.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1616);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[15].neighbors[i];
					}
					tagN1617.Setneighborid(new_neighborset17);
					tagN1617.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1617);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[15].neighbors[i];
					}
					tagN1618.Setneighborid(new_neighborset18);
					tagN1618.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1618);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[15].neighbors[i];
					}
					tagN1619.Setneighborid(new_neighborset19);
					tagN1619.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1619);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[15].neighbors[i];
					}
					tagN1620.Setneighborid(new_neighborset20);
					tagN1620.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1620);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[15].neighbors[i];
					}
					tagN1621.Setneighborid(new_neighborset21);
					tagN1621.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1621);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[15].neighbors[i];
					}
					tagN1622.Setneighborid(new_neighborset22);
					tagN1622.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1622);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[15].neighbors[i];
					}
					tagN1623.Setneighborid(new_neighborset23);
					tagN1623.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1623);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[15].neighbors[i];
					}
					tagN1624.Setneighborid(new_neighborset24);
					tagN1624.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1624);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[15].neighbors[i];
					}
					tagN1625.Setneighborid(new_neighborset25);
					tagN1625.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN1625);
					break;
				default:
					cout<<"Ethernet :maximum datasize exceeded. size is "<<nei_sizes[15]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[15])
						{
							new_neighborsetmax[i] = neighbor_set[15].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN16max.Setneighborid(new_neighborsetmax);
					tagN16max.Setnodeid(nodeid[15]);
					packet1->AddPacketTag(tagN16max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN171 tagN171;
		CustomMetaDataUnicastTagN172 tagN172;
		CustomMetaDataUnicastTagN173 tagN173;
		CustomMetaDataUnicastTagN174 tagN174;
		CustomMetaDataUnicastTagN175 tagN175;
		CustomMetaDataUnicastTagN176 tagN176;
		CustomMetaDataUnicastTagN177 tagN177;
		CustomMetaDataUnicastTagN178 tagN178;
		CustomMetaDataUnicastTagN179 tagN179;
		CustomMetaDataUnicastTagN1710 tagN1710;
		CustomMetaDataUnicastTagN1711 tagN1711;
		CustomMetaDataUnicastTagN1712 tagN1712;
		CustomMetaDataUnicastTagN1713 tagN1713;
		CustomMetaDataUnicastTagN1714 tagN1714;
		CustomMetaDataUnicastTagN1715 tagN1715;
		CustomMetaDataUnicastTagN1716 tagN1716;
		CustomMetaDataUnicastTagN1717 tagN1717;
		CustomMetaDataUnicastTagN1718 tagN1718;
		CustomMetaDataUnicastTagN1719 tagN1719;
		CustomMetaDataUnicastTagN1720 tagN1720;
		CustomMetaDataUnicastTagN1721 tagN1721;
		CustomMetaDataUnicastTagN1722 tagN1722;
		CustomMetaDataUnicastTagN1723 tagN1723;
		CustomMetaDataUnicastTagN1724 tagN1724;
		CustomMetaDataUnicastTagN1725 tagN1725;
		CustomMetaDataUnicastTagN17max tagN17max;
		
		if ((nei_sizes[16] > 0) and (neighbors_changed[16]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[16] = false;
			switch(nei_sizes[16])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[16].neighbors[0];
					tagN171.Setneighborid(new_neighborset1);
					tagN171.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN171);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[16].neighbors[i];
					}
					tagN172.Setneighborid(new_neighborset2);
					tagN172.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN172);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[16].neighbors[i];
					}
					tagN173.Setneighborid(new_neighborset3);
					tagN173.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN173);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[16].neighbors[i];
					}
					tagN174.Setneighborid(new_neighborset4);
					tagN174.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN174);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[16].neighbors[i];
					}
					tagN175.Setneighborid(new_neighborset5);
					tagN175.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN175);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[16].neighbors[i];
					}
					tagN176.Setneighborid(new_neighborset6);
					tagN176.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN176);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[16].neighbors[i];
					}
					tagN177.Setneighborid(new_neighborset7);
					tagN177.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN177);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[16].neighbors[i];
					}
					tagN178.Setneighborid(new_neighborset8);
					tagN178.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN178);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[16].neighbors[i];
					}
					tagN179.Setneighborid(new_neighborset9);
					tagN179.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN179);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[16].neighbors[i];
					}
					tagN1710.Setneighborid(new_neighborset10);
					tagN1710.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1710);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[16].neighbors[i];
					}
					tagN1711.Setneighborid(new_neighborset11);
					tagN1711.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1711);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[16].neighbors[i];
					}
					tagN1712.Setneighborid(new_neighborset12);
					tagN1712.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1712);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[16].neighbors[i];
					}
					tagN1713.Setneighborid(new_neighborset13);
					tagN1713.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1713);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[16].neighbors[i];
					}
					tagN1714.Setneighborid(new_neighborset14);
					tagN1714.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1714);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[16].neighbors[i];
					}
					tagN1715.Setneighborid(new_neighborset15);
					tagN1715.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1715);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[16].neighbors[i];
					}
					tagN1716.Setneighborid(new_neighborset16);
					tagN1716.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1716);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[16].neighbors[i];
					}
					tagN1717.Setneighborid(new_neighborset17);
					tagN1717.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1717);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[16].neighbors[i];
					}
					tagN1718.Setneighborid(new_neighborset18);
					tagN1718.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1718);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[16].neighbors[i];
					}
					tagN1719.Setneighborid(new_neighborset19);
					tagN1719.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1719);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[16].neighbors[i];
					}
					tagN1720.Setneighborid(new_neighborset20);
					tagN1720.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1720);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[16].neighbors[i];
					}
					tagN1721.Setneighborid(new_neighborset21);
					tagN1721.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1721);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[16].neighbors[i];
					}
					tagN1722.Setneighborid(new_neighborset22);
					tagN1722.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1722);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[16].neighbors[i];
					}
					tagN1723.Setneighborid(new_neighborset23);
					tagN1723.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1723);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[16].neighbors[i];
					}
					tagN1724.Setneighborid(new_neighborset24);
					tagN1724.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1724);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[16].neighbors[i];
					}
					tagN1725.Setneighborid(new_neighborset25);
					tagN1725.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN1725);
					break;
				default:
					cout<<"ethernet:maximum datasize exceeded . size is  "<<nei_sizes[16]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[16])
						{
							new_neighborsetmax[i] = neighbor_set[16].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN17max.Setneighborid(new_neighborsetmax);
					tagN17max.Setnodeid(nodeid[16]);
					packet1->AddPacketTag(tagN17max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN181 tagN181;
		CustomMetaDataUnicastTagN182 tagN182;
		CustomMetaDataUnicastTagN183 tagN183;
		CustomMetaDataUnicastTagN184 tagN184;
		CustomMetaDataUnicastTagN185 tagN185;
		CustomMetaDataUnicastTagN186 tagN186;
		CustomMetaDataUnicastTagN187 tagN187;
		CustomMetaDataUnicastTagN188 tagN188;
		CustomMetaDataUnicastTagN189 tagN189;
		CustomMetaDataUnicastTagN1810 tagN1810;
		CustomMetaDataUnicastTagN1811 tagN1811;
		CustomMetaDataUnicastTagN1812 tagN1812;
		CustomMetaDataUnicastTagN1813 tagN1813;
		CustomMetaDataUnicastTagN1814 tagN1814;
		CustomMetaDataUnicastTagN1815 tagN1815;
		CustomMetaDataUnicastTagN1816 tagN1816;
		CustomMetaDataUnicastTagN1817 tagN1817;
		CustomMetaDataUnicastTagN1818 tagN1818;
		CustomMetaDataUnicastTagN1819 tagN1819;
		CustomMetaDataUnicastTagN1820 tagN1820;
		CustomMetaDataUnicastTagN1821 tagN1821;
		CustomMetaDataUnicastTagN1822 tagN1822;
		CustomMetaDataUnicastTagN1823 tagN1823;
		CustomMetaDataUnicastTagN1824 tagN1824;
		CustomMetaDataUnicastTagN1825 tagN1825;
		CustomMetaDataUnicastTagN18max tagN18max;
		
		if ((nei_sizes[17] > 0) and (neighbors_changed[17]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[17] = false;
			switch(nei_sizes[17])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[17].neighbors[0];
					tagN181.Setneighborid(new_neighborset1);
					tagN181.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN181);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[17].neighbors[i];
					}
					tagN182.Setneighborid(new_neighborset2);
					tagN182.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN182);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[17].neighbors[i];
					}
					tagN183.Setneighborid(new_neighborset3);
					tagN183.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN183);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[17].neighbors[i];
					}
					tagN184.Setneighborid(new_neighborset4);
					tagN184.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN184);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[17].neighbors[i];
					}
					tagN185.Setneighborid(new_neighborset5);
					tagN185.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN185);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[17].neighbors[i];
					}
					tagN186.Setneighborid(new_neighborset6);
					tagN186.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN186);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[17].neighbors[i];
					}
					tagN187.Setneighborid(new_neighborset7);
					tagN187.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN187);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[17].neighbors[i];
					}
					tagN188.Setneighborid(new_neighborset8);
					tagN188.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN188);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[17].neighbors[i];
					}
					tagN189.Setneighborid(new_neighborset9);
					tagN189.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN189);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[17].neighbors[i];
					}
					tagN1810.Setneighborid(new_neighborset10);
					tagN1810.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1810);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[17].neighbors[i];
					}
					tagN1811.Setneighborid(new_neighborset11);
					tagN1811.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1811);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[17].neighbors[i];
					}
					tagN1812.Setneighborid(new_neighborset12);
					tagN1812.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1812);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[17].neighbors[i];
					}
					tagN1813.Setneighborid(new_neighborset13);
					tagN1813.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1813);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[17].neighbors[i];
					}
					tagN1814.Setneighborid(new_neighborset14);
					tagN1814.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1814);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[17].neighbors[i];
					}
					tagN1815.Setneighborid(new_neighborset15);
					tagN1815.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1815);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[17].neighbors[i];
					}
					tagN1816.Setneighborid(new_neighborset16);
					tagN1816.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1816);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[17].neighbors[i];
					}
					tagN1817.Setneighborid(new_neighborset17);
					tagN1817.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1817);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[17].neighbors[i];
					}
					tagN1818.Setneighborid(new_neighborset18);
					tagN1818.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1818);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[17].neighbors[i];
					}
					tagN1819.Setneighborid(new_neighborset19);
					tagN1819.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1819);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[17].neighbors[i];
					}
					tagN1820.Setneighborid(new_neighborset20);
					tagN1820.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1820);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[17].neighbors[i];
					}
					tagN1821.Setneighborid(new_neighborset21);
					tagN1821.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1821);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[17].neighbors[i];
					}
					tagN1822.Setneighborid(new_neighborset22);
					tagN1822.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1822);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[17].neighbors[i];
					}
					tagN1823.Setneighborid(new_neighborset23);
					tagN1823.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1823);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[17].neighbors[i];
					}
					tagN1824.Setneighborid(new_neighborset24);
					tagN1824.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1824);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[17].neighbors[i];
					}
					tagN1825.Setneighborid(new_neighborset25);
					tagN1825.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN1825);
					break;
				default:
					cout<<"ethernet:maximum datasize exceeded . size is  "<<nei_sizes[17]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[17])
						{
							new_neighborsetmax[i] = neighbor_set[17].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN18max.Setneighborid(new_neighborsetmax);
					tagN18max.Setnodeid(nodeid[17]);
					packet1->AddPacketTag(tagN18max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN191 tagN191;
		CustomMetaDataUnicastTagN192 tagN192;
		CustomMetaDataUnicastTagN193 tagN193;
		CustomMetaDataUnicastTagN194 tagN194;
		CustomMetaDataUnicastTagN195 tagN195;
		CustomMetaDataUnicastTagN196 tagN196;
		CustomMetaDataUnicastTagN197 tagN197;
		CustomMetaDataUnicastTagN198 tagN198;
		CustomMetaDataUnicastTagN199 tagN199;
		CustomMetaDataUnicastTagN1910 tagN1910;
		CustomMetaDataUnicastTagN1911 tagN1911;
		CustomMetaDataUnicastTagN1912 tagN1912;
		CustomMetaDataUnicastTagN1913 tagN1913;
		CustomMetaDataUnicastTagN1914 tagN1914;
		CustomMetaDataUnicastTagN1915 tagN1915;
		CustomMetaDataUnicastTagN1916 tagN1916;
		CustomMetaDataUnicastTagN1917 tagN1917;
		CustomMetaDataUnicastTagN1918 tagN1918;
		CustomMetaDataUnicastTagN1919 tagN1919;
		CustomMetaDataUnicastTagN1920 tagN1920;
		CustomMetaDataUnicastTagN1921 tagN1921;
		CustomMetaDataUnicastTagN1922 tagN1922;
		CustomMetaDataUnicastTagN1923 tagN1923;
		CustomMetaDataUnicastTagN1924 tagN1924;
		CustomMetaDataUnicastTagN1925 tagN1925;
		CustomMetaDataUnicastTagN19max tagN19max;
		
		if ((nei_sizes[18] > 0) and (neighbors_changed[18]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[18] = false;
			switch(nei_sizes[18])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[18].neighbors[0];
					tagN191.Setneighborid(new_neighborset1);
					tagN191.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN191);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[18].neighbors[i];
					}
					tagN192.Setneighborid(new_neighborset2);
					tagN192.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN192);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[18].neighbors[i];
					}
					tagN193.Setneighborid(new_neighborset3);
					tagN193.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN193);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[18].neighbors[i];
					}
					tagN194.Setneighborid(new_neighborset4);
					tagN194.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN194);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[18].neighbors[i];
					}
					tagN195.Setneighborid(new_neighborset5);
					tagN195.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN195);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[18].neighbors[i];
					}
					tagN196.Setneighborid(new_neighborset6);
					tagN196.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN196);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[18].neighbors[i];
					}
					tagN197.Setneighborid(new_neighborset7);
					tagN197.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN197);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[18].neighbors[i];
					}
					tagN198.Setneighborid(new_neighborset8);
					tagN198.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN198);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[18].neighbors[i];
					}
					tagN199.Setneighborid(new_neighborset9);
					tagN199.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN199);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[18].neighbors[i];
					}
					tagN1910.Setneighborid(new_neighborset10);
					tagN1910.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1910);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[18].neighbors[i];
					}
					tagN1911.Setneighborid(new_neighborset11);
					tagN1911.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1911);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[18].neighbors[i];
					}
					tagN1912.Setneighborid(new_neighborset12);
					tagN1912.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1912);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[18].neighbors[i];
					}
					tagN1913.Setneighborid(new_neighborset13);
					tagN1913.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1913);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[18].neighbors[i];
					}
					tagN1914.Setneighborid(new_neighborset14);
					tagN1914.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1914);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[18].neighbors[i];
					}
					tagN1915.Setneighborid(new_neighborset15);
					tagN1915.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1915);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[18].neighbors[i];
					}
					tagN1916.Setneighborid(new_neighborset16);
					tagN1916.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1916);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[18].neighbors[i];
					}
					tagN1917.Setneighborid(new_neighborset17);
					tagN1917.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1917);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[18].neighbors[i];
					}
					tagN1918.Setneighborid(new_neighborset18);
					tagN1918.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1918);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[18].neighbors[i];
					}
					tagN1919.Setneighborid(new_neighborset19);
					tagN1919.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1919);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[18].neighbors[i];
					}
					tagN1920.Setneighborid(new_neighborset20);
					tagN1920.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1920);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[18].neighbors[i];
					}
					tagN1921.Setneighborid(new_neighborset21);
					tagN1921.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1921);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[18].neighbors[i];
					}
					tagN1922.Setneighborid(new_neighborset22);
					tagN1922.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1922);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[18].neighbors[i];
					}
					tagN1923.Setneighborid(new_neighborset23);
					tagN1923.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1923);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[18].neighbors[i];
					}
					tagN1924.Setneighborid(new_neighborset24);
					tagN1924.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1924);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[18].neighbors[i];
					}
					tagN1925.Setneighborid(new_neighborset25);
					tagN1925.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN1925);
					break;
				default:
					cout<<"ethernet:maximum datasize exceeded . size is  "<<nei_sizes[18]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[18])
						{
							new_neighborsetmax[i] = neighbor_set[18].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN19max.Setneighborid(new_neighborsetmax);
					tagN19max.Setnodeid(nodeid[18]);
					packet1->AddPacketTag(tagN19max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN2001 tagN2001;
		CustomMetaDataUnicastTagN2002 tagN2002;
		CustomMetaDataUnicastTagN2003 tagN2003;
		CustomMetaDataUnicastTagN2004 tagN2004;
		CustomMetaDataUnicastTagN2005 tagN2005;
		CustomMetaDataUnicastTagN2006 tagN2006;
		CustomMetaDataUnicastTagN2007 tagN2007;
		CustomMetaDataUnicastTagN2008 tagN2008;
		CustomMetaDataUnicastTagN2009 tagN2009;
		CustomMetaDataUnicastTagN2010 tagN2010;
		CustomMetaDataUnicastTagN2011 tagN2011;
		CustomMetaDataUnicastTagN2012 tagN2012;
		CustomMetaDataUnicastTagN2013 tagN2013;
		CustomMetaDataUnicastTagN2014 tagN2014;
		CustomMetaDataUnicastTagN2015 tagN2015;
		CustomMetaDataUnicastTagN2016 tagN2016;
		CustomMetaDataUnicastTagN2017 tagN2017;
		CustomMetaDataUnicastTagN2018 tagN2018;
		CustomMetaDataUnicastTagN2019 tagN2019;
		CustomMetaDataUnicastTagN2020 tagN2020;
		CustomMetaDataUnicastTagN2021 tagN2021;
		CustomMetaDataUnicastTagN2022 tagN2022;
		CustomMetaDataUnicastTagN2023 tagN2023;
		CustomMetaDataUnicastTagN2024 tagN2024;
		CustomMetaDataUnicastTagN2025 tagN2025;
		CustomMetaDataUnicastTagN20max tagN20max;
		
		if ((nei_sizes[19] > 0) and (neighbors_changed[19]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[19] = false;
			switch(nei_sizes[19])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[19].neighbors[0];
					tagN2001.Setneighborid(new_neighborset1);
					tagN2001.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2001);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[19].neighbors[i];
					}
					tagN2002.Setneighborid(new_neighborset2);
					tagN2002.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2002);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[19].neighbors[i];
					}
					tagN2003.Setneighborid(new_neighborset3);
					tagN2003.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2003);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[19].neighbors[i];
					}
					tagN2004.Setneighborid(new_neighborset4);
					tagN2004.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2004);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[19].neighbors[i];
					}
					tagN2005.Setneighborid(new_neighborset5);
					tagN2005.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2005);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[19].neighbors[i];
					}
					tagN2006.Setneighborid(new_neighborset6);
					tagN2006.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2006);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[19].neighbors[i];
					}
					tagN2007.Setneighborid(new_neighborset7);
					tagN2007.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2007);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[19].neighbors[i];
					}
					tagN2008.Setneighborid(new_neighborset8);
					tagN2008.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2008);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[19].neighbors[i];
					}
					tagN2009.Setneighborid(new_neighborset9);
					tagN2009.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2009);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[19].neighbors[i];
					}
					tagN2010.Setneighborid(new_neighborset10);
					tagN2010.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2010);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[19].neighbors[i];
					}
					tagN2011.Setneighborid(new_neighborset11);
					tagN2011.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2011);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[19].neighbors[i];
					}
					tagN2012.Setneighborid(new_neighborset12);
					tagN2012.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2012);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[19].neighbors[i];
					}
					tagN2013.Setneighborid(new_neighborset13);
					tagN2013.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2013);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[19].neighbors[i];
					}
					tagN2014.Setneighborid(new_neighborset14);
					tagN2014.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2014);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[19].neighbors[i];
					}
					tagN2015.Setneighborid(new_neighborset15);
					tagN2015.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2015);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[19].neighbors[i];
					}
					tagN2016.Setneighborid(new_neighborset16);
					tagN2016.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2016);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[19].neighbors[i];
					}
					tagN2017.Setneighborid(new_neighborset17);
					tagN2017.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2017);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[19].neighbors[i];
					}
					tagN2018.Setneighborid(new_neighborset18);
					tagN2018.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2018);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[19].neighbors[i];
					}
					tagN2019.Setneighborid(new_neighborset19);
					tagN2019.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2019);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[19].neighbors[i];
					}
					tagN2020.Setneighborid(new_neighborset20);
					tagN2020.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2020);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[19].neighbors[i];
					}
					tagN2021.Setneighborid(new_neighborset21);
					tagN2021.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2021);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[19].neighbors[i];
					}
					tagN2022.Setneighborid(new_neighborset22);
					tagN2022.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2022);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[19].neighbors[i];
					}
					tagN2023.Setneighborid(new_neighborset23);
					tagN2023.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2023);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[19].neighbors[i];
					}
					tagN2024.Setneighborid(new_neighborset24);
					tagN2024.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2024);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[19].neighbors[i];
					}
					tagN2025.Setneighborid(new_neighborset25);
					tagN2025.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN2025);
					break;
				default:
					cout<<"ethernet:maximum datasize exceeded . size is  "<<nei_sizes[19]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[19])
						{
							new_neighborsetmax[i] = neighbor_set[19].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN20max.Setneighborid(new_neighborsetmax);
					tagN20max.Setnodeid(nodeid[19]);
					packet1->AddPacketTag(tagN20max);
					break;
			}
		
		}
		
		CustomMetaDataUnicastTagN2101 tagN2101;
		CustomMetaDataUnicastTagN2102 tagN2102;
		CustomMetaDataUnicastTagN2103 tagN2103;
		CustomMetaDataUnicastTagN2104 tagN2104;
		CustomMetaDataUnicastTagN2105 tagN2105;
		CustomMetaDataUnicastTagN2106 tagN2106;
		CustomMetaDataUnicastTagN2107 tagN2107;
		CustomMetaDataUnicastTagN2108 tagN2108;
		CustomMetaDataUnicastTagN2109 tagN2109;
		CustomMetaDataUnicastTagN2110 tagN2110;
		CustomMetaDataUnicastTagN2111 tagN2111;
		CustomMetaDataUnicastTagN2112 tagN2112;
		CustomMetaDataUnicastTagN2113 tagN2113;
		CustomMetaDataUnicastTagN2114 tagN2114;
		CustomMetaDataUnicastTagN2115 tagN2115;
		CustomMetaDataUnicastTagN2116 tagN2116;
		CustomMetaDataUnicastTagN2117 tagN2117;
		CustomMetaDataUnicastTagN2118 tagN2118;
		CustomMetaDataUnicastTagN2119 tagN2119;
		CustomMetaDataUnicastTagN2120 tagN2120;
		CustomMetaDataUnicastTagN2121 tagN2121;
		CustomMetaDataUnicastTagN2122 tagN2122;
		CustomMetaDataUnicastTagN2123 tagN2123;
		CustomMetaDataUnicastTagN2124 tagN2124;
		CustomMetaDataUnicastTagN2125 tagN2125;
		CustomMetaDataUnicastTagN21max tagN21max;
		
		if ((nei_sizes[20] > 0) and (neighbors_changed[20]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[20] = false;
			switch(nei_sizes[20])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[20].neighbors[0];
					tagN2101.Setneighborid(new_neighborset1);
					tagN2101.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2101);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[20].neighbors[i];
					}
					tagN2102.Setneighborid(new_neighborset2);
					tagN2102.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2102);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[20].neighbors[i];
					}
					tagN2103.Setneighborid(new_neighborset3);
					tagN2103.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2103);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[20].neighbors[i];
					}
					tagN2104.Setneighborid(new_neighborset4);
					tagN2104.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2104);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[20].neighbors[i];
					}
					tagN2105.Setneighborid(new_neighborset5);
					tagN2105.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2105);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[20].neighbors[i];
					}
					tagN2106.Setneighborid(new_neighborset6);
					tagN2106.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2106);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[20].neighbors[i];
					}
					tagN2107.Setneighborid(new_neighborset7);
					tagN2107.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2107);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[20].neighbors[i];
					}
					tagN2108.Setneighborid(new_neighborset8);
					tagN2108.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2108);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[20].neighbors[i];
					}
					tagN2109.Setneighborid(new_neighborset9);
					tagN2109.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2109);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[20].neighbors[i];
					}
					tagN2110.Setneighborid(new_neighborset10);
					tagN2110.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2110);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[20].neighbors[i];
					}
					tagN2111.Setneighborid(new_neighborset11);
					tagN2111.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2111);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[20].neighbors[i];
					}
					tagN2112.Setneighborid(new_neighborset12);
					tagN2112.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2112);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[20].neighbors[i];
					}
					tagN2113.Setneighborid(new_neighborset13);
					tagN2113.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2113);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[20].neighbors[i];
					}
					tagN2114.Setneighborid(new_neighborset14);
					tagN2114.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2114);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[20].neighbors[i];
					}
					tagN2115.Setneighborid(new_neighborset15);
					tagN2115.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2115);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[20].neighbors[i];
					}
					tagN2116.Setneighborid(new_neighborset16);
					tagN2116.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2116);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[20].neighbors[i];
					}
					tagN2117.Setneighborid(new_neighborset17);
					tagN2117.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2117);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[20].neighbors[i];
					}
					tagN2118.Setneighborid(new_neighborset18);
					tagN2118.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2118);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[20].neighbors[i];
					}
					tagN2119.Setneighborid(new_neighborset19);
					tagN2119.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2119);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[20].neighbors[i];
					}
					tagN2120.Setneighborid(new_neighborset20);
					tagN2120.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2120);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[20].neighbors[i];
					}
					tagN2121.Setneighborid(new_neighborset21);
					tagN2121.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2121);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[20].neighbors[i];
					}
					tagN2122.Setneighborid(new_neighborset22);
					tagN2122.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2122);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[20].neighbors[i];
					}
					tagN2123.Setneighborid(new_neighborset23);
					tagN2123.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2123);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[20].neighbors[i];
					}
					tagN2124.Setneighborid(new_neighborset24);
					tagN2124.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2124);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[20].neighbors[i];
					}
					tagN2125.Setneighborid(new_neighborset25);
					tagN2125.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN2125);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[20]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[20])
						{
							new_neighborsetmax[i] = neighbor_set[20].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN21max.Setneighborid(new_neighborsetmax);
					tagN21max.Setnodeid(nodeid[20]);
					packet1->AddPacketTag(tagN21max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN2201 tagN2201;
		CustomMetaDataUnicastTagN2202 tagN2202;
		CustomMetaDataUnicastTagN2203 tagN2203;
		CustomMetaDataUnicastTagN2204 tagN2204;
		CustomMetaDataUnicastTagN2205 tagN2205;
		CustomMetaDataUnicastTagN2206 tagN2206;
		CustomMetaDataUnicastTagN2207 tagN2207;
		CustomMetaDataUnicastTagN2208 tagN2208;
		CustomMetaDataUnicastTagN2209 tagN2209;
		CustomMetaDataUnicastTagN2210 tagN2210;
		CustomMetaDataUnicastTagN2211 tagN2211;
		CustomMetaDataUnicastTagN2212 tagN2212;
		CustomMetaDataUnicastTagN2213 tagN2213;
		CustomMetaDataUnicastTagN2214 tagN2214;
		CustomMetaDataUnicastTagN2215 tagN2215;
		CustomMetaDataUnicastTagN2216 tagN2216;
		CustomMetaDataUnicastTagN2217 tagN2217;
		CustomMetaDataUnicastTagN2218 tagN2218;
		CustomMetaDataUnicastTagN2219 tagN2219;
		CustomMetaDataUnicastTagN2220 tagN2220;
		CustomMetaDataUnicastTagN2221 tagN2221;
		CustomMetaDataUnicastTagN2222 tagN2222;
		CustomMetaDataUnicastTagN2223 tagN2223;
		CustomMetaDataUnicastTagN2224 tagN2224;
		CustomMetaDataUnicastTagN2225 tagN2225;
		CustomMetaDataUnicastTagN22max tagN22max;
		
		if ((nei_sizes[21] > 0) and (neighbors_changed[21]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[21] = false;
			switch(nei_sizes[21])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[21].neighbors[0];
					tagN2201.Setneighborid(new_neighborset1);
					tagN2201.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2201);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[21].neighbors[i];
					}
					tagN2202.Setneighborid(new_neighborset2);
					tagN2202.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2202);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[21].neighbors[i];
					}
					tagN2203.Setneighborid(new_neighborset3);
					tagN2203.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2203);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[21].neighbors[i];
					}
					tagN2204.Setneighborid(new_neighborset4);
					tagN2204.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2204);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[21].neighbors[i];
					}
					tagN2205.Setneighborid(new_neighborset5);
					tagN2205.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2205);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[21].neighbors[i];
					}
					tagN2206.Setneighborid(new_neighborset6);
					tagN2206.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2206);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[21].neighbors[i];
					}
					tagN2207.Setneighborid(new_neighborset7);
					tagN2207.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2207);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[21].neighbors[i];
					}
					tagN2208.Setneighborid(new_neighborset8);
					tagN2208.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2208);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[21].neighbors[i];
					}
					tagN2209.Setneighborid(new_neighborset9);
					tagN2209.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2209);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[21].neighbors[i];
					}
					tagN2210.Setneighborid(new_neighborset10);
					tagN2210.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2210);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[21].neighbors[i];
					}
					tagN2211.Setneighborid(new_neighborset11);
					tagN2211.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2211);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[21].neighbors[i];
					}
					tagN2212.Setneighborid(new_neighborset12);
					tagN2212.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2212);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[21].neighbors[i];
					}
					tagN2213.Setneighborid(new_neighborset13);
					tagN2213.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2213);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[21].neighbors[i];
					}
					tagN2214.Setneighborid(new_neighborset14);
					tagN2214.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2214);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[21].neighbors[i];
					}
					tagN2215.Setneighborid(new_neighborset15);
					tagN2215.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2215);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[21].neighbors[i];
					}
					tagN2216.Setneighborid(new_neighborset16);
					tagN2216.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2216);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[21].neighbors[i];
					}
					tagN2217.Setneighborid(new_neighborset17);
					tagN2217.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2217);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[21].neighbors[i];
					}
					tagN2218.Setneighborid(new_neighborset18);
					tagN2218.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2218);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[21].neighbors[i];
					}
					tagN2219.Setneighborid(new_neighborset19);
					tagN2219.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2219);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[21].neighbors[i];
					}
					tagN2220.Setneighborid(new_neighborset20);
					tagN2220.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2220);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[21].neighbors[i];
					}
					tagN2221.Setneighborid(new_neighborset21);
					tagN2221.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2221);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[21].neighbors[i];
					}
					tagN2222.Setneighborid(new_neighborset22);
					tagN2222.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2222);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[21].neighbors[i];
					}
					tagN2223.Setneighborid(new_neighborset23);
					tagN2223.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2223);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[21].neighbors[i];
					}
					tagN2224.Setneighborid(new_neighborset24);
					tagN2224.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2224);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[21].neighbors[i];
					}
					tagN2225.Setneighborid(new_neighborset25);
					tagN2225.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN2225);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[21]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[21])
						{
							new_neighborsetmax[i] = neighbor_set[21].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN22max.Setneighborid(new_neighborsetmax);
					tagN22max.Setnodeid(nodeid[21]);
					packet1->AddPacketTag(tagN22max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN2301 tagN2301;
		CustomMetaDataUnicastTagN2302 tagN2302;
		CustomMetaDataUnicastTagN2303 tagN2303;
		CustomMetaDataUnicastTagN2304 tagN2304;
		CustomMetaDataUnicastTagN2305 tagN2305;
		CustomMetaDataUnicastTagN2306 tagN2306;
		CustomMetaDataUnicastTagN2307 tagN2307;
		CustomMetaDataUnicastTagN2308 tagN2308;
		CustomMetaDataUnicastTagN2309 tagN2309;
		CustomMetaDataUnicastTagN2310 tagN2310;
		CustomMetaDataUnicastTagN2311 tagN2311;
		CustomMetaDataUnicastTagN2312 tagN2312;
		CustomMetaDataUnicastTagN2313 tagN2313;
		CustomMetaDataUnicastTagN2314 tagN2314;
		CustomMetaDataUnicastTagN2315 tagN2315;
		CustomMetaDataUnicastTagN2316 tagN2316;
		CustomMetaDataUnicastTagN2317 tagN2317;
		CustomMetaDataUnicastTagN2318 tagN2318;
		CustomMetaDataUnicastTagN2319 tagN2319;
		CustomMetaDataUnicastTagN2320 tagN2320;
		CustomMetaDataUnicastTagN2321 tagN2321;
		CustomMetaDataUnicastTagN2322 tagN2322;
		CustomMetaDataUnicastTagN2323 tagN2323;
		CustomMetaDataUnicastTagN2324 tagN2324;
		CustomMetaDataUnicastTagN2325 tagN2325;
		CustomMetaDataUnicastTagN23max tagN23max;
		
		if ((nei_sizes[22] > 0) and (neighbors_changed[22]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[22] = false;
			switch(nei_sizes[22])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[22].neighbors[0];
					tagN2301.Setneighborid(new_neighborset1);
					tagN2301.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2301);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[22].neighbors[i];
					}
					tagN2302.Setneighborid(new_neighborset2);
					tagN2302.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2302);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[22].neighbors[i];
					}
					tagN2303.Setneighborid(new_neighborset3);
					tagN2303.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2303);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[22].neighbors[i];
					}
					tagN2304.Setneighborid(new_neighborset4);
					tagN2304.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2304);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[22].neighbors[i];
					}
					tagN2305.Setneighborid(new_neighborset5);
					tagN2305.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2305);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[22].neighbors[i];
					}
					tagN2306.Setneighborid(new_neighborset6);
					tagN2306.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2306);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[22].neighbors[i];
					}
					tagN2307.Setneighborid(new_neighborset7);
					tagN2307.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2307);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[22].neighbors[i];
					}
					tagN2308.Setneighborid(new_neighborset8);
					tagN2308.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2308);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[22].neighbors[i];
					}
					tagN2309.Setneighborid(new_neighborset9);
					tagN2309.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2309);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[22].neighbors[i];
					}
					tagN2310.Setneighborid(new_neighborset10);
					tagN2310.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2310);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[22].neighbors[i];
					}
					tagN2311.Setneighborid(new_neighborset11);
					tagN2311.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2311);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[22].neighbors[i];
					}
					tagN2312.Setneighborid(new_neighborset12);
					tagN2312.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2312);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[22].neighbors[i];
					}
					tagN2313.Setneighborid(new_neighborset13);
					tagN2313.Setnodeid(nodeid[0]);
					packet1->AddPacketTag(tagN2313);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[0].neighbors[i];
					}
					tagN2314.Setneighborid(new_neighborset14);
					tagN2314.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2314);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[22].neighbors[i];
					}
					tagN2315.Setneighborid(new_neighborset15);
					tagN2315.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2315);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[22].neighbors[i];
					}
					tagN2316.Setneighborid(new_neighborset16);
					tagN2316.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2316);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[22].neighbors[i];
					}
					tagN2317.Setneighborid(new_neighborset17);
					tagN2317.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2317);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[22].neighbors[i];
					}
					tagN2318.Setneighborid(new_neighborset18);
					tagN2318.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2318);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[22].neighbors[i];
					}
					tagN2319.Setneighborid(new_neighborset19);
					tagN2319.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2319);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[22].neighbors[i];
					}
					tagN2320.Setneighborid(new_neighborset20);
					tagN2320.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2320);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[22].neighbors[i];
					}
					tagN2321.Setneighborid(new_neighborset21);
					tagN2321.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2321);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[22].neighbors[i];
					}
					tagN2322.Setneighborid(new_neighborset22);
					tagN2322.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2322);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[22].neighbors[i];
					}
					tagN2323.Setneighborid(new_neighborset23);
					tagN2323.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2323);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[22].neighbors[i];
					}
					tagN2324.Setneighborid(new_neighborset24);
					tagN2324.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2324);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[22].neighbors[i];
					}
					tagN2325.Setneighborid(new_neighborset25);
					tagN2325.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN2325);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[22]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[22])
						{
							new_neighborsetmax[i] = neighbor_set[22].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN23max.Setneighborid(new_neighborsetmax);
					tagN23max.Setnodeid(nodeid[22]);
					packet1->AddPacketTag(tagN23max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN2401 tagN2401;
		CustomMetaDataUnicastTagN2402 tagN2402;
		CustomMetaDataUnicastTagN2403 tagN2403;
		CustomMetaDataUnicastTagN2404 tagN2404;
		CustomMetaDataUnicastTagN2405 tagN2405;
		CustomMetaDataUnicastTagN2406 tagN2406;
		CustomMetaDataUnicastTagN2407 tagN2407;
		CustomMetaDataUnicastTagN2408 tagN2408;
		CustomMetaDataUnicastTagN2409 tagN2409;
		CustomMetaDataUnicastTagN2410 tagN2410;
		CustomMetaDataUnicastTagN2411 tagN2411;
		CustomMetaDataUnicastTagN2412 tagN2412;
		CustomMetaDataUnicastTagN2413 tagN2413;
		CustomMetaDataUnicastTagN2414 tagN2414;
		CustomMetaDataUnicastTagN2415 tagN2415;
		CustomMetaDataUnicastTagN2416 tagN2416;
		CustomMetaDataUnicastTagN2417 tagN2417;
		CustomMetaDataUnicastTagN2418 tagN2418;
		CustomMetaDataUnicastTagN2419 tagN2419;
		CustomMetaDataUnicastTagN2420 tagN2420;
		CustomMetaDataUnicastTagN2421 tagN2421;
		CustomMetaDataUnicastTagN2422 tagN2422;
		CustomMetaDataUnicastTagN2423 tagN2423;
		CustomMetaDataUnicastTagN2424 tagN2424;
		CustomMetaDataUnicastTagN2425 tagN2425;
		CustomMetaDataUnicastTagN24max tagN24max;
		
		if ((nei_sizes[23] > 0) and (neighbors_changed[23]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[23] = false;
			switch(nei_sizes[23])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[23].neighbors[0];
					tagN2401.Setneighborid(new_neighborset1);
					tagN2401.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2401);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[23].neighbors[i];
					}
					tagN2402.Setneighborid(new_neighborset2);
					tagN2402.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2402);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[23].neighbors[i];
					}
					tagN2403.Setneighborid(new_neighborset3);
					tagN2403.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2403);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[23].neighbors[i];
					}
					tagN2404.Setneighborid(new_neighborset4);
					tagN2404.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2404);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[23].neighbors[i];
					}
					tagN2405.Setneighborid(new_neighborset5);
					tagN2405.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2405);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[23].neighbors[i];
					}
					tagN2406.Setneighborid(new_neighborset6);
					tagN2406.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2406);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[23].neighbors[i];
					}
					tagN2407.Setneighborid(new_neighborset7);
					tagN2407.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2407);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[23].neighbors[i];
					}
					tagN2408.Setneighborid(new_neighborset8);
					tagN2408.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2408);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[23].neighbors[i];
					}
					tagN2409.Setneighborid(new_neighborset9);
					tagN2409.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2409);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[23].neighbors[i];
					}
					tagN2410.Setneighborid(new_neighborset10);
					tagN2410.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2410);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[23].neighbors[i];
					}
					tagN2411.Setneighborid(new_neighborset11);
					tagN2411.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2411);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[23].neighbors[i];
					}
					tagN2412.Setneighborid(new_neighborset12);
					tagN2412.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2412);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[23].neighbors[i];
					}
					tagN2413.Setneighborid(new_neighborset13);
					tagN2413.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2413);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[23].neighbors[i];
					}
					tagN2414.Setneighborid(new_neighborset14);
					tagN2414.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2414);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[23].neighbors[i];
					}
					tagN2415.Setneighborid(new_neighborset15);
					tagN2415.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2415);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[23].neighbors[i];
					}
					tagN2416.Setneighborid(new_neighborset16);
					tagN2416.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2416);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[23].neighbors[i];
					}
					tagN2417.Setneighborid(new_neighborset17);
					tagN2417.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2417);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[23].neighbors[i];
					}
					tagN2418.Setneighborid(new_neighborset18);
					tagN2418.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2418);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[23].neighbors[i];
					}
					tagN2419.Setneighborid(new_neighborset19);
					tagN2419.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2419);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[23].neighbors[i];
					}
					tagN2420.Setneighborid(new_neighborset20);
					tagN2420.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2420);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[23].neighbors[i];
					}
					tagN2421.Setneighborid(new_neighborset21);
					tagN2421.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2421);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[23].neighbors[i];
					}
					tagN2422.Setneighborid(new_neighborset22);
					tagN2422.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2422);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[23].neighbors[i];
					}
					tagN2423.Setneighborid(new_neighborset23);
					tagN2423.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2423);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[23].neighbors[i];
					}
					tagN2424.Setneighborid(new_neighborset24);
					tagN2424.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2424);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[23].neighbors[i];
					}
					tagN2425.Setneighborid(new_neighborset25);
					tagN2425.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN2425);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[23]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[23])
						{
							new_neighborsetmax[i] = neighbor_set[23].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN24max.Setneighborid(new_neighborsetmax);
					tagN24max.Setnodeid(nodeid[23]);
					packet1->AddPacketTag(tagN24max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN2501 tagN2501;
		CustomMetaDataUnicastTagN2502 tagN2502;
		CustomMetaDataUnicastTagN2503 tagN2503;
		CustomMetaDataUnicastTagN2504 tagN2504;
		CustomMetaDataUnicastTagN2505 tagN2505;
		CustomMetaDataUnicastTagN2506 tagN2506;
		CustomMetaDataUnicastTagN2507 tagN2507;
		CustomMetaDataUnicastTagN2508 tagN2508;
		CustomMetaDataUnicastTagN2509 tagN2509;
		CustomMetaDataUnicastTagN2510 tagN2510;
		CustomMetaDataUnicastTagN2511 tagN2511;
		CustomMetaDataUnicastTagN2512 tagN2512;
		CustomMetaDataUnicastTagN2513 tagN2513;
		CustomMetaDataUnicastTagN2514 tagN2514;
		CustomMetaDataUnicastTagN2515 tagN2515;
		CustomMetaDataUnicastTagN2516 tagN2516;
		CustomMetaDataUnicastTagN2517 tagN2517;
		CustomMetaDataUnicastTagN2518 tagN2518;
		CustomMetaDataUnicastTagN2519 tagN2519;
		CustomMetaDataUnicastTagN2520 tagN2520;
		CustomMetaDataUnicastTagN2521 tagN2521;
		CustomMetaDataUnicastTagN2522 tagN2522;
		CustomMetaDataUnicastTagN2523 tagN2523;
		CustomMetaDataUnicastTagN2524 tagN2524;
		CustomMetaDataUnicastTagN2525 tagN2525;
		CustomMetaDataUnicastTagN25max tagN25max;
		
		if ((nei_sizes[24] > 0) and (neighbors_changed[24]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[24] = false;
			switch(nei_sizes[24])
			{
				case (1):
					uint32_t new_neighborset1[1];
					new_neighborset1[0] = neighbor_set[24].neighbors[0];
					tagN2501.Setneighborid(new_neighborset1);
					tagN2501.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2501);
					break;
				case (2):
					uint32_t new_neighborset2[2];
					for(uint32_t i=0;i<2;i++)
					{
						new_neighborset2[i] = neighbor_set[24].neighbors[i];
					}
					tagN2502.Setneighborid(new_neighborset2);
					tagN2502.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2502);
					break;
				case (3):
					uint32_t new_neighborset3[3];
					for(uint32_t i=0;i<3;i++)
					{
						new_neighborset3[i] = neighbor_set[24].neighbors[i];
					}
					tagN2503.Setneighborid(new_neighborset3);
					tagN2503.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2503);
					break;
				case (4):
					uint32_t new_neighborset4[4];
					for(uint32_t i=0;i<4;i++)
					{
						new_neighborset4[i] = neighbor_set[24].neighbors[i];
					}
					tagN2504.Setneighborid(new_neighborset4);
					tagN2504.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2504);
					break;
				case (5):
					uint32_t new_neighborset5[5];
					for(uint32_t i=0;i<5;i++)
					{
						new_neighborset5[i] = neighbor_set[24].neighbors[i];
					}
					tagN2505.Setneighborid(new_neighborset5);
					tagN2505.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2505);
					break;
				case (6):
					uint32_t new_neighborset6[6];
					for(uint32_t i=0;i<6;i++)
					{
						new_neighborset6[i] = neighbor_set[24].neighbors[i];
					}
					tagN2506.Setneighborid(new_neighborset6);
					tagN2506.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2506);
					break;
				case (7):
					uint32_t new_neighborset7[7];
					for(uint32_t i=0;i<7;i++)
					{
						new_neighborset7[i] = neighbor_set[24].neighbors[i];
					}
					tagN2507.Setneighborid(new_neighborset7);
					tagN2507.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2507);
					break;
				case (8):
					uint32_t new_neighborset8[8];
					for(uint32_t i=0;i<8;i++)
					{
						new_neighborset8[i] = neighbor_set[24].neighbors[i];
					}
					tagN2508.Setneighborid(new_neighborset8);
					tagN2508.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2508);
					break;
				case (9):
					uint32_t new_neighborset9[9];
					for(uint32_t i=0;i<9;i++)
					{
						new_neighborset9[i] = neighbor_set[24].neighbors[i];
					}
					tagN2509.Setneighborid(new_neighborset9);
					tagN2509.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2509);
					break;
				case (10):
					uint32_t new_neighborset10[10];
					for(uint32_t i=0;i<10;i++)
					{
						new_neighborset10[i] = neighbor_set[24].neighbors[i];
					}
					tagN2510.Setneighborid(new_neighborset10);
					tagN2510.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2510);
					break;
				case (11):
					uint32_t new_neighborset11[11];
					for(uint32_t i=0;i<11;i++)
					{
						new_neighborset11[i] = neighbor_set[24].neighbors[i];
					}
					tagN2511.Setneighborid(new_neighborset11);
					tagN2511.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2511);
					break;
				case (12):
					uint32_t new_neighborset12[12];
					for(uint32_t i=0;i<12;i++)
					{
						new_neighborset12[i] = neighbor_set[24].neighbors[i];
					}
					tagN2512.Setneighborid(new_neighborset12);
					tagN2512.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2512);
					break;
				case (13):
					uint32_t new_neighborset13[13];
					for(uint32_t i=0;i<13;i++)
					{
						new_neighborset13[i] = neighbor_set[24].neighbors[i];
					}
					tagN2513.Setneighborid(new_neighborset13);
					tagN2513.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2513);
					break;
				case (14):
					uint32_t new_neighborset14[14];
					for(uint32_t i=0;i<14;i++)
					{
						new_neighborset14[i] = neighbor_set[24].neighbors[i];
					}
					tagN2514.Setneighborid(new_neighborset14);
					tagN2514.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2514);
					break;
				case (15):
					uint32_t new_neighborset15[15];
					for(uint32_t i=0;i<15;i++)
					{
						new_neighborset15[i] = neighbor_set[24].neighbors[i];
					}
					tagN2515.Setneighborid(new_neighborset15);
					tagN2515.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2515);
					break;
				case (16):
					uint32_t new_neighborset16[16];
					for(uint32_t i=0;i<16;i++)
					{
						new_neighborset16[i] = neighbor_set[24].neighbors[i];
					}
					tagN2516.Setneighborid(new_neighborset16);
					tagN2516.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2516);
					break;
				case (17):
					uint32_t new_neighborset17[17];
					for(uint32_t i=0;i<17;i++)
					{
						new_neighborset17[i] = neighbor_set[24].neighbors[i];
					}
					tagN2517.Setneighborid(new_neighborset17);
					tagN2517.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2517);
					break;
				case (18):
					uint32_t new_neighborset18[18];
					for(uint32_t i=0;i<18;i++)
					{
						new_neighborset18[i] = neighbor_set[24].neighbors[i];
					}
					tagN2518.Setneighborid(new_neighborset18);
					tagN2518.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2518);
					break;
				case (19):
					uint32_t new_neighborset19[19];
					for(uint32_t i=0;i<19;i++)
					{
						new_neighborset19[i] = neighbor_set[24].neighbors[i];
					}
					tagN2519.Setneighborid(new_neighborset19);
					tagN2519.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2519);
					break;
				case (20):
					uint32_t new_neighborset20[20];
					for(uint32_t i=0;i<20;i++)
					{
						new_neighborset20[i] = neighbor_set[24].neighbors[i];
					}
					tagN2520.Setneighborid(new_neighborset20);
					tagN2520.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2520);
					break;
				case (21):
					uint32_t new_neighborset21[21];
					for(uint32_t i=0;i<21;i++)
					{
						new_neighborset21[i] = neighbor_set[24].neighbors[i];
					}
					tagN2521.Setneighborid(new_neighborset21);
					tagN2521.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2521);
					break;
				case (22):
					uint32_t new_neighborset22[22];
					for(uint32_t i=0;i<22;i++)
					{
						new_neighborset22[i] = neighbor_set[24].neighbors[i];
					}
					tagN2522.Setneighborid(new_neighborset22);
					tagN2522.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2522);
					break;
				case (23):
					uint32_t new_neighborset23[23];
					for(uint32_t i=0;i<23;i++)
					{
						new_neighborset23[i] = neighbor_set[24].neighbors[i];
					}
					tagN2523.Setneighborid(new_neighborset23);
					tagN2523.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2523);
					break;
				case (24):
					uint32_t new_neighborset24[24];
					for(uint32_t i=0;i<24;i++)
					{
						new_neighborset24[i] = neighbor_set[24].neighbors[i];
					}
					tagN2524.Setneighborid(new_neighborset24);
					tagN2524.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2524);
					break;
				case (25):
					uint32_t new_neighborset25[25];
					for(uint32_t i=0;i<25;i++)
					{
						new_neighborset25[i] = neighbor_set[24].neighbors[i];
					}
					tagN2525.Setneighborid(new_neighborset25);
					tagN2525.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN2525);
					break;
				default:
					cout<<"Cellular:maximum datasize exceeded. size is "<<nei_sizes[24]<<endl;
					uint32_t new_neighborsetmax[max];
					for(uint32_t i=0;i<max;i++)
					{
						if(i<nei_sizes[24])
						{
							new_neighborsetmax[i] = neighbor_set[24].neighbors[i];
						}
						else
						{
							new_neighborsetmax[i] = large;
						}
					}
					tagN25max.Setneighborid(new_neighborsetmax);
					tagN25max.Setnodeid(nodeid[24]);
					packet1->AddPacketTag(tagN25max);
					break;
			}
		}
		
		CustomMetaDataUnicastTagN26max tagN26max;
		if ((nei_sizes[25] > 0) and (neighbors_changed[25]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[25] = false;
			cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[25]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[25])
				{
					new_neighborsetmax[i] = neighbor_set[25].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN26max.Setneighborid(new_neighborsetmax);
			tagN26max.Setnodeid(nodeid[25]);
			packet1->AddPacketTag(tagN26max);
		}
		
		CustomMetaDataUnicastTagN27max tagN27max;
		if ((nei_sizes[26] > 0) and (neighbors_changed[26]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[26] = false;
			cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[26]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[26])
				{
					new_neighborsetmax[i] = neighbor_set[26].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN27max.Setneighborid(new_neighborsetmax);
			tagN27max.Setnodeid(nodeid[26]);
			packet1->AddPacketTag(tagN27max);
		}
		
		CustomMetaDataUnicastTagN28max tagN28max;
		if ((nei_sizes[27] > 0) and (neighbors_changed[27]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[27] = false;
			cout<<"Ethernet:maximum neighbor datasize exceeded . size is  "<<nei_sizes[27]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[27])
				{
					new_neighborsetmax[i] = neighbor_set[27].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN28max.Setneighborid(new_neighborsetmax);
			tagN28max.Setnodeid(nodeid[27]);
			packet1->AddPacketTag(tagN28max);
		}
		
		CustomMetaDataUnicastTagN29max tagN29max;
		if ((nei_sizes[28] > 0) and (neighbors_changed[28]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[28] = false;
			cout<<"Ethernet :maximum neighbor datasize exceeded . size is  "<<nei_sizes[28]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[28])
				{
					new_neighborsetmax[i] = neighbor_set[28].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN29max.Setneighborid(new_neighborsetmax);
			tagN29max.Setnodeid(nodeid[28]);
			packet1->AddPacketTag(tagN29max);
		}
		
		CustomMetaDataUnicastTagN30max tagN30max;
		if ((nei_sizes[29] > 0) and (neighbors_changed[29]==true))
		{
			(data_at_nodes_inst+nid)->neighbors_changed[29] = false;
			cout<<"Ethernet :maximum neighbor datasize exceeded. size is  "<<nei_sizes[29]<<endl;
			uint32_t new_neighborsetmax[max];
			for(uint32_t i=0;i<max;i++)
			{
				if(i<nei_sizes[29])
				{
					new_neighborsetmax[i] = neighbor_set[29].neighbors[i];
				}
				else
				{
					new_neighborsetmax[i] = large;
				}
			}
			tagN30max.Setneighborid(new_neighborsetmax);
			tagN30max.Setnodeid(nodeid[29]);
			packet1->AddPacketTag(tagN30max);
		}
		
		
		CustomDataUnicastTag1 tag1;
		CustomDataUnicastTag2 tag2;
		CustomDataUnicastTag3 tag3;
		CustomDataUnicastTag4 tag4;
		CustomDataUnicastTag5 tag5;
		CustomDataUnicastTag6 tag6;
		CustomDataUnicastTag7 tag7;
		CustomDataUnicastTag8 tag8;
		CustomDataUnicastTag9 tag9;
		CustomDataUnicastTag10 tag10;
		CustomDataUnicastTag11 tag11;
		CustomDataUnicastTag12 tag12;
		CustomDataUnicastTag13 tag13;
		CustomDataUnicastTag14 tag14;
		CustomDataUnicastTag15 tag15;
		CustomDataUnicastTag16 tag16;
		CustomDataUnicastTag17 tag17;
		CustomDataUnicastTag18 tag18;
		CustomDataUnicastTag19 tag19;
		CustomDataUnicastTag20 tag20;
		CustomDataUnicastTag21 tag21;
		CustomDataUnicastTag22 tag22;
		CustomDataUnicastTag23 tag23;
		CustomDataUnicastTag24 tag24;
		CustomDataUnicastTag25 tag25;
		CustomDataUnicastTag tag;
		switch (size)
		{	
			case 1:
				tag1.SetsenderId(nid);
				tag1.SetNodeId(nodeid);
				tag1.Setposition(position);
				tag1.Setvelocity(velocity);
				tag1.Setacceleration(acceleration);
				tag1.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag1);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 2:
				tag2.SetsenderId(nid);
				tag2.SetNodeId(nodeid);
				tag2.Setposition(position);
				tag2.Setvelocity(velocity);
				tag2.Setacceleration(acceleration);
				tag2.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag2);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 3:
				tag3.SetsenderId(nid);
				tag3.SetNodeId(nodeid);
				tag3.Setposition(position);
				tag3.Setvelocity(velocity);
				tag3.Setacceleration(acceleration);
				tag3.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag3);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 4:
				tag4.SetsenderId(nid);
				tag4.SetNodeId(nodeid);
				tag4.Setposition(position);
				tag4.Setvelocity(velocity);
				tag4.Setacceleration(acceleration);
				tag4.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag4);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 5:
				tag5.SetsenderId(nid);
				tag5.SetNodeId(nodeid);
				tag5.Setposition(position);
				tag5.Setvelocity(velocity);
				tag5.Setacceleration(acceleration);
				tag5.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag5);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 6:
				tag6.SetsenderId(nid);
				tag6.SetNodeId(nodeid);
				tag6.Setposition(position);
				tag6.Setvelocity(velocity);
				tag6.Setacceleration(acceleration);
				tag6.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag6);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 7:
				tag7.SetsenderId(nid);
				tag7.SetNodeId(nodeid);
				tag7.Setposition(position);
				tag7.Setvelocity(velocity);
				tag7.Setacceleration(acceleration);
				tag7.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag7);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 8:
				tag8.SetsenderId(nid);
				tag8.SetNodeId(nodeid);
				tag8.Setposition(position);
				tag8.Setvelocity(velocity);
				tag8.Setacceleration(acceleration);
				tag8.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag8);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 9:
				tag9.SetsenderId(nid);
				tag9.SetNodeId(nodeid);
				tag9.Setposition(position);
				tag9.Setvelocity(velocity);
				tag9.Setacceleration(acceleration);
				tag9.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag9);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			
			case 10:
				tag10.SetsenderId(nid);
				tag10.SetNodeId(nodeid);
				tag10.Setposition(position);
				tag10.Setvelocity(velocity);
				tag10.Setacceleration(acceleration);
				tag10.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag10);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 11:
				tag11.SetsenderId(nid);
				tag11.SetNodeId(nodeid);
				tag11.Setposition(position);
				tag11.Setvelocity(velocity);
				tag11.Setacceleration(acceleration);
				tag11.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag11);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 12:
				tag12.SetsenderId(nid);
				tag12.SetNodeId(nodeid);
				tag12.Setposition(position);
				tag12.Setvelocity(velocity);
				tag12.Setacceleration(acceleration);
				tag12.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag12);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 13:
				tag13.SetsenderId(nid);
				tag13.SetNodeId(nodeid);
				tag13.Setposition(position);
				tag13.Setvelocity(velocity);
				tag13.Setacceleration(acceleration);
				tag13.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag13);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;	
			case 14:
				tag14.SetsenderId(nid);
				tag14.SetNodeId(nodeid);
				tag14.Setposition(position);
				tag14.Setvelocity(velocity);
				tag14.Setacceleration(acceleration);
				tag14.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag14);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 15:
				tag15.SetsenderId(nid);
				tag15.SetNodeId(nodeid);
				tag15.Setposition(position);
				tag15.Setvelocity(velocity);
				tag15.Setacceleration(acceleration);
				tag15.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag15);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 16:
				tag16.SetsenderId(nid);
				tag16.SetNodeId(nodeid);
				tag16.Setposition(position);
				tag16.Setvelocity(velocity);
				tag16.Setacceleration(acceleration);
				tag16.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag16);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 17:
				tag17.SetsenderId(nid);
				tag17.SetNodeId(nodeid);
				tag17.Setposition(position);
				tag17.Setvelocity(velocity);
				tag17.Setacceleration(acceleration);
				tag17.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag17);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 18:
				tag18.SetsenderId(nid);
				tag18.SetNodeId(nodeid);
				tag18.Setposition(position);
				tag18.Setvelocity(velocity);
				tag18.Setacceleration(acceleration);
				tag18.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag18);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 19:
				tag19.SetsenderId(nid);
				tag19.SetNodeId(nodeid);
				tag19.Setposition(position);
				tag19.Setvelocity(velocity);
				tag19.Setacceleration(acceleration);
				tag19.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag19);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 20:
				tag20.SetsenderId(nid);
				tag20.SetNodeId(nodeid);
				tag20.Setposition(position);
				tag20.Setvelocity(velocity);
				tag20.Setacceleration(acceleration);
				tag20.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag20);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 21:
				tag21.SetsenderId(nid);
				tag21.SetNodeId(nodeid);
				tag21.Setposition(position);
				tag21.Setvelocity(velocity);
				tag21.Setacceleration(acceleration);
				tag21.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag21);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 22:
				tag22.SetsenderId(nid);
				tag22.SetNodeId(nodeid);
				tag22.Setposition(position);
				tag22.Setvelocity(velocity);
				tag22.Setacceleration(acceleration);
				tag22.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag22);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 23:
				tag23.SetsenderId(nid);
				tag23.SetNodeId(nodeid);
				tag23.Setposition(position);
				tag23.Setvelocity(velocity);
				tag23.Setacceleration(acceleration);
				tag23.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag23);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 24:
				tag24.SetsenderId(nid);
				tag24.SetNodeId(nodeid);
				tag24.Setposition(position);
				tag24.Setvelocity(velocity);
				tag24.Setacceleration(acceleration);
				tag24.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag24);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			case 25:
				tag25.SetsenderId(nid);
				tag25.SetNodeId(nodeid);
				tag25.Setposition(position);
				tag25.Setvelocity(velocity);
				tag25.Setacceleration(acceleration);
				tag25.SetTimestamp(timestamp);
				packet1->AddPacketTag(tag25);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;
			default:
				cout<<"Ethernet :maximum status datasize exceeded . size is  "<<size<<endl;
				tag.SetsenderId(nid);
				tag.SetNodeId((data_at_nodes_inst+nid)->nodeid);
				tag.Setposition((data_at_nodes_inst+nid)->position);
				tag.Setvelocity((data_at_nodes_inst+nid)->velocity);
				tag.Setacceleration((data_at_nodes_inst+nid)->acceleration);
				tag.SetTimestamp((data_at_nodes_inst+nid)->timestamp);
				packet1->AddPacketTag(tag);
				ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
				Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
				break;	
		}
		cout<<"RSU total packet size is "<<ethernet_total_packet_size<<endl;

	}
}

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


