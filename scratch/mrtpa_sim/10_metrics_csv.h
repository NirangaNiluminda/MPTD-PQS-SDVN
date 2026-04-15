// ============================================================
// SECTION 10: Performance Metrics and CSV Output Functions
// ============================================================
// These functions compute and save all performance metrics
// reported in the paper's evaluation section.
//
// CSV Write Functions:
//   write_csv()                - write optimization convergence data
//   write_csv_status_lifetime()- write link lifetime statistics
//   write_csv_status()         - write current network status
//   read_csv()                 - read previously saved metrics
//   write_csv_results()        - MAIN RESULTS: PDR, latency, jitter, security
//   write_csv_results_routing()- routing algorithm comparison results
//   write_csv_results_LLDP()   - LLDP-specific results
//   write_csv_delay_training() - training data for DNN delay prediction
//
// Global result variables (used in write_csv_results):
//   current_cost, average_latency, average_packet_delivery_ratio
//   current_packet_confusion_ratio, current_intercepted_ratio
//   average_latency_routing, normalized_mobility, network_contention
//
// Routing timing arrays:
//   routing_packet_initial_timestamp[flow][packet]
//   routing_packet_final_timestamp[flow][packet]
//   intercepted_packet_*timestamp arrays
// ============================================================
void write_csv()
{
	fstream fout;
	fout.open(NS3_ROOT "/analytics/data/optimization_data.csv",ios::out|ios::trunc);
	for (uint32_t i=2; i<total_size+2 ;i++)
	{
		fout << total_size << ", "
		     <<	con_data_inst[i].B << ", "
		     << con_data_inst[i].neighborsize << ", ";
		     //<< con_data_inst[i].frequency << ", "
		     //<< con_data_inst[i].datasize << ", ";
		     for(uint32_t j=0;j<max;j++)
		     {
		     	fout<< con_data_inst[i].neighborid[j] << ", ";
		     }
		     /*
		     for(uint32_t j=0;j<max;j++)
		     {
		     	fout<< con_data_inst[i].combined_cost[j] << ", ";
		     }
		     */
		     fout<< "\n";
	}
	fout.close();
}

void write_csv_status_lifetime()
{
	fstream fout;
	switch(routing_algorithm)
	{
		case(0):
			fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data_ECMP.csv",ios::out|ios::trunc);
			break;
		case(1):
			fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data_RR.csv",ios::out|ios::trunc);
			break;
		case(2):
			fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data_QRSDN.csv",ios::out|ios::trunc);
			break;
		case(3):
			fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data_RLMR.csv",ios::out|ios::trunc);
			break;
		case(4):
			fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data.csv",ios::out|ios::trunc);
			break;
		case(5):
			/*
			if(experiment_number == 0)
			{
				fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data_QRSDN.csv",ios::out|ios::trunc);
			}
			if(experiment_number == 1)
			{
				fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data_RR.csv",ios::out|ios::trunc);
			}
			if(experiment_number == 2)
			{
				fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data_QRSDN.csv",ios::out|ios::trunc);
			}
			if(experiment_number == 3)
			{
				fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data_RLMR.csv",ios::out|ios::trunc);
			}
			*/
			fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data_RLMR.csv",ios::out|ios::trunc);
			break;
			
		default:
			fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data.csv",ios::out|ios::trunc);
			break;
	}
	for (uint32_t i=0; i<total_size ;i++)
	{
		//cout<<"writing status "<<i<<endl;
		fout << total_size << ", "
		     << (routing_data_at_controller_inst+i)->nodeid << ", "
		     << (routing_data_at_controller_inst+i)->position.x << ", "
		     << (routing_data_at_controller_inst+i)->position.y << ", "
		     << (routing_data_at_controller_inst+i)->velocity.x<< ", "
		     << (routing_data_at_controller_inst+i)->velocity.y << ", "
		     << (routing_data_at_controller_inst+i)->acceleration.x << ", "
		     << (routing_data_at_controller_inst+i)->acceleration.y << ", "
		     << mobility_scenario << ", "
		     << N_Vehicles << ", "
		     << N_RSUs << ", "
		     << "\n";
	}
	fout.close();
	cout<<"finished writing link lifetime status at"<<Now().GetSeconds()<<endl;
}

void write_csv_status()
{
	fstream fout;
	fout.open(NS3_ROOT "/analytics/data/optimization_link_lifetime_data.csv",ios::out|ios::trunc);
	for (uint32_t i=2; i<total_size+2 ;i++)
	{
		Ptr <Node> node;
		if ((i-2) < N_Vehicles)
		{	
			node = DynamicCast <Node> (Vehicle_Nodes.Get(i-2));
		}
		else
		{
			node = DynamicCast <Node> (RSU_Nodes.Get(i-N_Vehicles-2));
		}
		
		Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node->GetObject<MobilityModel>());
        	Vector position = mdl->GetPosition();
        	Vector velocity = mdl->GetVelocity();
		//cout<<"writing status "<<i<<endl;
		fout << total_size << ", "
		     << position.x << ", "
		     <<	position.y << ", "
		     << velocity.x<< ", "
		     << velocity.y << ", "
		     << data_at_manager_inst[i].acceleration.x << ", "
		     << data_at_manager_inst[i].acceleration.y << ", "
		     << mobility_scenario << ", "
		     << N_Vehicles << ", "
		     << N_RSUs << ", "
		     << "\n";
	}
	fout.close();
	cout<<"finished writing status"<<endl;
}


void read_csv()
{
    fstream fin;
    fin.open(NS3_ROOT "/analytics/data/optimization_results.csv", ios::in);
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
        int int_val;
        char * ptr;
        ptr = strtok(line_char,",");
        int i =0;
        while(ptr != NULL)
        {
        	stringstream ss;
		ss << ptr;
		ss >> int_val;
		if (i==0)
		{
			X_gurobi[j+2] = int_val;
			//cout<<"x"<<j<<" value "<<int_val<<endl;
		}
		if (i==1)
		{
			Z_gurobi[j+2] = int_val;
			//cout<<"z"<<j<<"value "<<int_val<<endl;
		}
        	
        	ptr = strtok(NULL,",");   
        	i++;	
        }
        j++;
    }
    if (j == 0)
        cout << "Solution not found\n";
}

double current_cost = 0.0;
double current_lte_utilization = 0.0;
double current_ethernet_utilization = 0.0;
double current_dsrc_utilization=0.0;
double current_computational_complexity=0.0;
double current_routing_latency=0.0;
double current_latency=0.0;
double current_latency_dsrc = 0.0;
double optimization_percentage = 0.0;
double average_packet_delivery_ratio = 0.0;
double current_packet_delivery_ratio = 0.0;
double current_packet_confusion_ratio = 0.0;
double current_intercepted_ratio = 0.0;
double average_packet_delivery_ratio_dsrc = 0.0;
double average_packet_confusion = 0.0;
double average_intercepted_ratio = 0.0;
double current_packet_delivery_ratio_dsrc = 0.0;
double normalized_mobility = 0.0;
double network_contention = 0.0;

void write_csv_results()
{
	fstream fout;
	string filename;
	if (architecture == 0)
	{
		switch (experiment_number)
		{
			case (0)://entropy experiment
				filename = NS3_ROOT "/analytics/results/centralized_entropy.csv";
	
				break;
			case (1)://optimization frequency
				if (data_transmission_frequency == 0.02)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_0.02.csv";
				}
				if (data_transmission_frequency ==0.05)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_0.05.csv";
				}
				if (data_transmission_frequency ==0.10)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_0.10.csv";
				}
				if (data_transmission_frequency ==0.25)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_0.25.csv";
				}
				if (data_transmission_frequency ==0.50)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_0.50.csv";
				}

				if (data_transmission_frequency == 1.00)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_1.00.csv";
				}

				if (data_transmission_frequency ==2.00)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_2.csv";
				}

				if (data_transmission_frequency ==4.00)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_4.csv";
				}

				if (data_transmission_frequency ==6.00)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_6.csv";
				}

				if (data_transmission_frequency ==8.00)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_8.csv";
				}

				if (data_transmission_frequency ==10.00)
				{
					filename = NS3_ROOT "/analytics/results/centralized_frequency_10.csv";
				}

				break;
			case (2): //number of nodes
				switch(total_size)
				{
					case (4):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_4.csv";
						break;
					case (8):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_8.csv";
						break;
					case (16):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_16.csv";
						break;
					case (32):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_32.csv";
						break;
					case (64):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_64.csv";
						break;
					case (96):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_96.csv";
						break;
					case (128):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_128.csv";
						break;
					case (160):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_160.csv";
						break;						
					case (192):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_192.csv";
						break;
					case (224):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_224.csv";
						break;
					case (256):
						filename = NS3_ROOT "/analytics/results/centralized_nodes_256.csv";
						break;
				}
				break;
			case (3)://mobility scenario
				if (mobility_scenario == 0) //urban mobility
				  {
				  	switch(maxspeed)
				  	{
				  		case (0):
				  			filename = NS3_ROOT "/analytics/results/centralized_mobility_urban_0.csv";
					  		break;
				  		case (10):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_urban_10.csv";
					  		break;
					  	case (20):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_urban_20.csv";
					  		break;
					  	case (30):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_urban_30.csv";
					  		break;
					  	case (40):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_urban_40.csv";
					  		break;
					  	case (50):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_urban_50.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_urban_60.csv";
					  		break;
					  	default:
					  		break;
					 }
				   }
				   
				   if (mobility_scenario == 1) //non-urban mobility
				   {
				   	switch(maxspeed)
				   	{
				   		case (0):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_0.csv";
				   	  		break;
				   		case (10):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_10.csv";
				   	  		break;
				   	  	case (20):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_20.csv";
					  		break;
					  	case (30):
					   		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_30.csv";
					   		break;
					   	case (40):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_40.csv";
					  		break;
					  	case (50):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_50.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_60.csv";
					  		break;
				   	  	case (70):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_70.csv";
				   	  		break;
				   	  	case (80):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_80.csv";
				   	  		break;
				   	  	case (90):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_90.csv";
				   	  		break;
				   	  	case (100):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_rural_100.csv";
				   	  		break;
				   	  	default:
				   	  		break;
					 }
				   }
				   
				   if (mobility_scenario == 2)//highway
				   {
				   	  switch(maxspeed)
				   	  {
				   	  	case (0):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_0.csv";
				   	  		break;
				   	  	case (10):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_10.csv";
				   	  		break;
				   	  	case (30):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_30.csv";
				   	  		break;
				   	  	case (50):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_50.csv";
				   	  		break;
				   	  	case (70):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_70.csv";
				   	  		break;
				   	  	case (90):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_90.csv";
				   	  		break;
				   	  	case (110):
				   	  		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_110.csv";
				   	  		break;
					 	case (130):
					 		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_130.csv";
					 		break;
					 	case (150):
					 		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_150.csv";
					 		break;
					 	case (170):
					 		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_170.csv";
					 		break;
					 	case (190):
					 		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_190.csv";
					 		break;
					 	case (210):
					 		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_210.csv";
					 		break;
					 	case (230):
					 		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_230.csv";
					 		break;
					 	case (250):
					 		filename = NS3_ROOT "/analytics/results/centralized_mobility_autobahn_250.csv";
					 		break;
					 	default:
					 		break;
					  }
				   }
				break;
			case (4): //RSU ratios
				uint32_t ratio;
				if (N_RSUs != 0)
				{
					ratio = N_Vehicles/N_RSUs;
				}
				else
				{
					ratio = 200;
				}
				switch (ratio)
				{
					case(200)://200 veh, 0 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_inf.csv";
						break;
					case(199)://199 veh, 1 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_199.csv";
						break;
					case(99)://198 veh, 2 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_99.csv";
						break;
					case(49)://196 veh, 4 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_49.csv";
						break;
					case(24)://192 veh, 8 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_24.csv";
						break;
					case(9)://180 veh, 20 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_9.csv";
						break;
					case(4)://160 veh, 40 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_4.csv";
						break;
					case(3):// 150 veh, 50 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_3.csv";
						break;
					case(2): //134 veh, 66 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_2.csv";
						break;
					case(1): //100 veh, 100 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_1.csv";
						break;
					case(0): //0 veh, 200 RSU
						filename = NS3_ROOT "/analytics/results/centralized_heterogeneity_0.csv";
						break;
				}
				break;
			case (7)://threshold experiment
				filename = NS3_ROOT "/analytics/results_routing/centralized_threshold.csv";
				break;	
			case (8)://threshold experiment
				filename = NS3_ROOT "/analytics/results_routing/centralized_threshold.csv";
				break;
			case (9)://routing frequency
				if (routing_frequency == 0.02)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_0.02.csv";
				}
				if (routing_frequency ==0.05)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_0.05.csv";
				}
				if (routing_frequency ==0.10)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_0.10.csv";
				}
				if (routing_frequency ==0.25)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_0.25.csv";
				}
				if (routing_frequency ==0.50)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_0.50.csv";
				}
				if (routing_frequency == 1.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_1.00.csv";
				}
				if (routing_frequency ==2.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_2.csv";
				}

				if (routing_frequency ==3.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_3.csv";
				}
		
				if (routing_frequency == 4.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_4.csv";
				}

				if (routing_frequency ==5.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/centralized_routing_frequency_5.csv";
				}
				break;
			case (10): //number of nodes for routing
				switch(total_size)
				{
					case (4):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_4.csv";
						break;
					case (8):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_8.csv";
						break;
					case (16):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_16.csv";
						break;
					case (32):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_32.csv";
						break;
					case (64):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_64.csv";
						break;
					case (96):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_96.csv";
						break;
					case (128):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_128.csv";
						break;
					case (160):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_160.csv";
						break;						
					case (192):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_192.csv";
						break;
					case (224):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_224.csv";
						break;
					case (256):
						filename = NS3_ROOT "/analytics/results_routing/centralized_routing_nodes_256.csv";
						break;
				}
				break;
			case (11)://mobility scenario routing
				if (mobility_scenario == 0) //urban mobility
				  {
				  	switch(maxspeed)
				  	{
				  		case (0):
				  			filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_urban_0.csv";
					  		break;
				  		case (10):
					  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_urban_10.csv";
					  		break;
					  	case (20):
					  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_urban_20.csv";
					  		break;
					  	case (30):
					  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_urban_30.csv";
					  		break;
					  	case (40):
					  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_urban_40.csv";
					  		break;
					  	case (50):
					  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_urban_50.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_urban_60.csv";
					  		break;
					  	default:
					  		break;
					 }
				   }
				   
				   if (mobility_scenario == 1) //non-urban mobility
				   {
				   	switch(maxspeed)
				   	{
				   		case (0):
				   	  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_rural_0.csv";
				  	  		break;
				   	  	case (20):
					  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_rural_20.csv";
					  		break;
					   	case (40):
					  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_rural_40.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_rural_60.csv";
					  		break;
				   	  	case (80):
				   	  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_rural_80.csv";
				   	  		break;
				   	  	case (100):
				   	  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_rural_100.csv";
				   	  		break;
				   	  	default:
				   	  		break;
					 }
				   }
				   
				   if (mobility_scenario == 2)//highway
				   {
				   	  switch(maxspeed)
				   	  {
				   	  	case (0):
				   	  		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_autobahn_0.csv";
				   	  		break;
				   	  	case (30):
				   	  		filename = NS3_ROOT "/analytics/results_routing/centralized__routing_mobility_autobahn_30.csv";
				   	  		break;
				   	  	case (50):
				   	  		filename = NS3_ROOT "/analytics/results_routing/centralized__routing_mobility_autobahn_50.csv";
				   	  		break;
				   	  	case (90):
				   	  		filename = NS3_ROOT "/analytics/results_routing/centralized__routing_mobility_autobahn_90.csv";
				   	  		break;
					 	case (130):
					 		filename = NS3_ROOT "/analytics/results_routing/centralized__routing_mobility_autobahn_130.csv";
					 		break;
					 	case (170):
					 		filename = NS3_ROOT "/analytics/results_routing/centralized__routing_mobility_autobahn_170.csv";
					 		break;
					 	case (210):
					 		filename = NS3_ROOT "/analytics/results_routing/centralized__routing_mobility_autobahn_210.csv";
					 		break;
					 	case (250):
					 		filename = NS3_ROOT "/analytics/results_routing/centralized_routing_mobility_autobahn_250.csv";
					 		break;
					 	default:
					 		break;
					  }
				   }
				break;
		}
	}
	
	if (architecture == 1)
	{
		switch (experiment_number)
		{
			case (0)://entropy experiment
				filename = NS3_ROOT "/analytics/results/distributed_entropy.csv";
	
				break;
			case (1)://optimization frequency
				if (data_transmission_frequency == 0.02)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_0.02.csv";
				}
				if (data_transmission_frequency ==0.05)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_0.05.csv";
				}
				if (data_transmission_frequency ==0.10)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_0.10.csv";
				}
				if (data_transmission_frequency ==0.25)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_0.25.csv";
				}
				if (data_transmission_frequency ==0.50)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_0.50.csv";
				}

				if (data_transmission_frequency == 1.00)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_1.00.csv";
				}

				if (data_transmission_frequency ==2.00)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_2.csv";
				}

				if (data_transmission_frequency ==4.00)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_4.csv";
				}

				if (data_transmission_frequency ==6.00)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_6.csv";
				}

				if (data_transmission_frequency ==8.00)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_8.csv";
				}

				if (data_transmission_frequency ==10.00)
				{
					filename = NS3_ROOT "/analytics/results/distributed_frequency_10.csv";
				}

				break;
			case (2): //number of nodes
				switch(total_size)
				{
					case (4):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_4.csv";
						break;
					case (8):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_8.csv";
						break;
					case (16):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_16.csv";
						break;
					case (32):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_32.csv";
						break;
					case (64):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_64.csv";
						break;
					case (96):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_96.csv";
						break;
					case (128):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_128.csv";
						break;
					case (160):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_160.csv";
						break;						
					case (192):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_192.csv";
						break;
					case (224):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_224.csv";
						break;
					case (256):
						filename = NS3_ROOT "/analytics/results/distributed_nodes_256.csv";
						break;
				}
				break;
			case (3)://mobility scenario
				if (mobility_scenario == 0) //urban mobility
				  {
				  	switch(maxspeed)
				  	{
				  		case (0):
				  			filename = NS3_ROOT "/analytics/results/distributed_mobility_urban_0.csv";
					  		break;
				  		case (10):
					  		filename = NS3_ROOT "/analytics/results/distributed_mobility_urban_10.csv";
					  		break;
					  	case (20):
					  		filename = NS3_ROOT "/analytics/results/distributed_mobility_urban_20.csv";
					  		break;
					  	case (30):
					  		filename = NS3_ROOT "/analytics/results/distributed_mobility_urban_30.csv";
					  		break;
					  	case (40):
					  		filename = NS3_ROOT "/analytics/results/distributed_mobility_urban_40.csv";
					  		break;
					  	case (50):
					  		filename = NS3_ROOT "/analytics/results/distributed_mobility_urban_50.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results/distributed_mobility_urban_60.csv";
					  		break;
					  	default:
					  		break;
					 }
				   }
				   
				   if (mobility_scenario == 1) //non-urban mobility
				   {
				   	switch(maxspeed)
				   	{
				   		case (0):
				   	  		filename = NS3_ROOT "/analytics/results/distributed_mobility_rural_0.csv";
				   	  		break;
				   	  	case (20):
					  		filename = NS3_ROOT "/analytics/results/distributed_mobility_rural_20.csv";
					  		break;
					   	case (40):
					  		filename = NS3_ROOT "/analytics/results/distributed_mobility_rural_40.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results/distributed_mobility_rural_60.csv";
					  		break;
				   	  	case (80):
				   	  		filename = NS3_ROOT "/analytics/results/distributed_mobility_rural_80.csv";
				   	  		break;
				   	  	case (100):
				   	  		filename = NS3_ROOT "/analytics/results/distributed_mobility_rural_100.csv";
				   	  		break;
				   	  	default:
				   	  		break;
					 }
				   }
				   
				   if (mobility_scenario == 2)//highway
				   {
				   	  switch(maxspeed)
				   	  {
				   	  	case (0):
				   	  		filename = NS3_ROOT "/analytics/results/distributed_mobility_autobahn_0.csv";
				   	  		break;
				   	  	case (30):
				   	  		filename = NS3_ROOT "/analytics/results/distributed_mobility_autobahn_30.csv";
				   	  		break;
				   	  	case (50):
				   	  		filename = NS3_ROOT "/analytics/results/distributed_mobility_autobahn_50.csv";
				   	  		break;
				   	  	case (90):
				   	  		filename = NS3_ROOT "/analytics/results/distributed_mobility_autobahn_90.csv";
					 	case (130):
					 		filename = NS3_ROOT "/analytics/results/distributed_mobility_autobahn_130.csv";
					 		break;
					 	case (170):
					 		filename = NS3_ROOT "/analytics/results/distributed_mobility_autobahn_170.csv";
					 		break;
					 	case (210):
					 		filename = NS3_ROOT "/analytics/results/distributed_mobility_autobahn_210.csv";
					 		break;
					 	case (250):
					 		filename = NS3_ROOT "/analytics/results/distributed_mobility_autobahn_250.csv";
					 		break;
					 	default:
					 		break;
					  }
				   }
				break;
			case (4): //RSU ratios
				uint32_t ratio;
				if (N_RSUs != 0)
				{
					ratio = N_Vehicles/N_RSUs;
				}
				else
				{
					ratio = 200;
				}
				switch (ratio)
				{
					case(200)://200 veh, 0 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_inf.csv";
						break;
					case(199)://199 veh, 1 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_199.csv";
						break;
					case(99)://198 veh, 2 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_99.csv";
						break;
					case(49)://196 veh, 4 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_49.csv";
						break;
					case(24)://192 veh, 8 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_24.csv";
						break;
					case(9)://180 veh, 20 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_9.csv";
						break;
					case(4)://160 veh, 40 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_4.csv";
						break;
					case(3):// 150 veh, 50 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_3.csv";
						break;
					case(2): //134 veh, 66 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_2.csv";
						break;
					case(1): //100 veh, 100 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_1.csv";
						break;
					case(0): //0 veh, 200 RSU
						filename = NS3_ROOT "/analytics/results/distributed_heterogeneity_0.csv";
						break;
				}
				break;
			case (7)://link lifetime threshold experiment
				filename = NS3_ROOT "/analytics/results_routing/distributed_threshold.csv";
				break;	
			case (8)://contention threshold experiment
				filename = NS3_ROOT "/analytics/results_routing/distributed_threshold.csv";
				break;
			case (9)://routing frequency
				if (routing_frequency == 0.02)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_0.02.csv";
				}
				if (routing_frequency ==0.05)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_0.05.csv";
				}
				if (routing_frequency ==0.10)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_0.10.csv";
				}
				if (routing_frequency ==0.25)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_0.25.csv";
				}
				if (routing_frequency ==0.50)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_0.50.csv";
				}
				if (routing_frequency == 1.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_1.00.csv";
				}
				if (routing_frequency ==2.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_2.csv";
				}

				if (routing_frequency ==3.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_3.csv";
				}
		
				if (routing_frequency == 4.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_4.csv";
				}

				if (routing_frequency ==5.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/distributed_routing_frequency_5.csv";
				}

				break;
			case (10): //number of nodes for routing
				switch(total_size)
				{
					case (4):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_4.csv";
						break;
					case (8):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_8.csv";
						break;
					case (16):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_16.csv";
						break;
					case (32):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_32.csv";
						break;
					case (64):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_64.csv";
						break;
					case (96):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_96.csv";
						break;
					case (128):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_128.csv";
						break;
					case (160):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_160.csv";
						break;						
					case (192):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_192.csv";
						break;
					case (224):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_224.csv";
						break;
					case (256):
						filename = NS3_ROOT "/analytics/results_routing/distributed_routing_nodes_256.csv";
						break;
				}
				break;
			case (11)://mobility scenario - routing
				if (mobility_scenario == 0) //urban mobility
				  {
				  	switch(maxspeed)
				  	{
				  		case (0):
				  			filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_urban_0.csv";
					  		break;
				  		case (10):
					  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_urban_10.csv";
					  		break;
					  	case (20):
					  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_urban_20.csv";
					  		break;
					  	case (30):
					  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_urban_30.csv";
					  		break;
					  	case (40):
					  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_urban_40.csv";
					  		break;
					  	case (50):
					  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_urban_50.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_urban_60.csv";
					  		break;
					  	default:
					  		break;
					 }
				   }
				   
				   if (mobility_scenario == 1) //non-urban mobility
				   {
				   	switch(maxspeed)
				   	{
				   		case (0):
				   	  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_rural_0.csv";
				   	  		break;
				   	  	case (20):
					  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_rural_20.csv";
					  		break;
					   	case (40):
					  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_rural_40.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_rural_60.csv";
					  		break;
				   	  	case (80):
				   	  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_rural_80.csv";
				   	  		break;
				   	  	case (100):
				   	  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_rural_100.csv";
				   	  		break;
				   	  	default:
				   	  		break;
					 }
				   }
				   
				   if (mobility_scenario == 2)//highway
				   {
				   	  switch(maxspeed)
				   	  {
				   	  	case (0):
				   	  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_autobahn_0.csv";
				   	  		break;
				   	  	case (30):
				   	  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_autobahn_30.csv";
				   	  		break;
				   	  	case (50):
				   	  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_autobahn_50.csv";
				   	  		break;
				   	  	case (90):
				   	  		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_autobahn_90.csv";
				   	  		break;
					 	case (130):
					 		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_autobahn_130.csv";
					 		break;
					 	case (170):
					 		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_autobahn_170.csv";
					 		break;
					 	case (210):
					 		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_autobahn_210.csv";
					 		break;
					 	case (250):
					 		filename = NS3_ROOT "/analytics/results_routing/distributed_routing_mobility_autobahn_250.csv";
					 		break;
					 	default:
					 		break;
					  }
				   }
				break;
		}
	}
	
	if (architecture == 2)
	{
		switch (experiment_number)
		{
			case (0)://entropy experiment
				if (entropy_threshold == 0.000)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.000.csv";
				}
				if(entropy_threshold == 0.001)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.001.csv";
				}
				if(entropy_threshold == 0.002)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.002.csv";
				}
				if(entropy_threshold == 0.005)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.005.csv";
				}
				if(entropy_threshold == 0.010)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.010.csv";
				}
				if(entropy_threshold == 0.020)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.020.csv";
				}
				if(entropy_threshold == 0.050)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.050.csv";
				}
				if(entropy_threshold == 0.100)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.100.csv";
				}
				if(entropy_threshold == 0.200)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.200.csv";
				}
				if(entropy_threshold == 0.500)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_entropy_0.500.csv";
				}
				break;
			case (1)://optimization frequency
				if (optimization_frequency == 0.02)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_0.02.csv";
				}
				if (optimization_frequency ==0.05)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_0.05.csv";
				}
				if (optimization_frequency ==0.10)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_0.10.csv";
				}
				if (optimization_frequency ==0.25)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_0.25.csv";
				}
				if (optimization_frequency ==0.50)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_0.50.csv";
				}
				if (optimization_frequency == 1.0)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_1.00.csv";
				}
				if (optimization_frequency ==2.0)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_2.csv";
				}

				if (optimization_frequency ==4.0)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_4.csv";
				}
		
				if (optimization_frequency == 6.0)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_6.csv";
				}

				if (optimization_frequency ==8.0)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_8.csv";
				}

				if (optimization_frequency ==10.0)
				{
					filename = NS3_ROOT "/analytics/results/hybrid_frequency_10.csv";
				}

				break;
			case (2): //number of nodes
				switch(total_size)
				{
					case (4):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_4.csv";
						break;
					case (8):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_8.csv";
						break;
					case (16):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_16.csv";
						break;
					case (32):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_32.csv";
						break;
					case (64):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_64.csv";
						break;
					case (96):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_96.csv";
						break;
					case (128):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_128.csv";
						break;
					case (160):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_160.csv";
						break;
					case (192):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_192.csv";
						break;						
					case (224):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_224.csv";
						break;
					case (256):
						filename = NS3_ROOT "/analytics/results/hybrid_nodes_256.csv";
						break;
				}
				break;
			case (3)://mobility scenario
				if (mobility_scenario == 0) //urban mobility
				  {
				  	switch(maxspeed)
				  	{
				  		case (0):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_urban_0.csv";
					  		break;
				  		case (10):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_urban_10.csv";
					  		break;
					  	case (20):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_urban_20.csv";
					  		break;
					  	case (30):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_urban_30.csv";
					  		break;
					  	case (40):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_urban_40.csv";
					  		break;
					  	case (50):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_urban_50.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_urban_60.csv";
					  		break;
					  	default:
					  		break;
					 }
				   }
				   
				   if (mobility_scenario == 1) //non-urban mobility
				   {
				   	switch(maxspeed)
				   	{
				   		case (0):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_0.csv";
				   	  		break;
				   		case (10):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_10.csv";
				   	  		break;
				   	  	case (20):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_20.csv";
					  		break;
					  	case (30):
					   		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_30.csv";
					   		break;
					   	case (40):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_40.csv";
					  		break;
					  	case (50):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_50.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_60.csv";
					  		break;
				   	  	case (70):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_70.csv";
				   	  		break;
				   	  	case (80):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_80.csv";
				   	  		break;
				   	  	case (90):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_90.csv";
				   	  		break;
				   	  	case (100):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_rural_100.csv";
				   	  		break;
				   	  	default:
				   	  		break;
					 }
				   }
				   
				   if (mobility_scenario == 2)//highway
				   {
				   	  switch(maxspeed)
				   	  {
				   	  	case (0):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_0.csv";
				   	  		break;
				   	  	case (10):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_10.csv";
				   	  		break;
				   	  	case (30):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_30.csv";
				   	  		break;
				   	  	case (50):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_50.csv";
				   	  		break;
				   	  	case (70):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_70.csv";
				   	  		break;
				   	  	case (90):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_90.csv";
				   	  		break;
				   	  	case (110):
				   	  		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_110.csv";
				   	  		break;
					 	case (130):
					 		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_130.csv";
					 		break;
					 	case (150):
					 		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_150.csv";
					 		break;
					 	case (170):
					 		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_170.csv";
					 		break;
					 	case (190):
					 		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_190.csv";
					 		break;
					 	case (210):
					 		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_210.csv";
					 		break;
					 	case (230):
					 		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_230.csv";
					 		break;
					 	case (250):
					 		filename = NS3_ROOT "/analytics/results/hybrid_mobility_autobahn_250.csv";
					 		break;
					 	default:
					 		break;
					  }
				   }
				break;
			case (4): //RSU ratios
				uint32_t ratio;
				if (N_RSUs != 0)
				{
					ratio = N_Vehicles/N_RSUs;
				}
				else
				{
					ratio = 200;
				}
				switch (ratio)
				{
					case(200)://200 veh, 0 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_inf.csv";
						break;
					case(199)://199 veh, 1 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_199.csv";
						break;
					case(99)://198 veh, 2 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_99.csv";
						break;
					case(49)://196 veh, 4 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_49.csv";
						break;
					case(24)://192 veh, 8 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_24.csv";
						break;
					case(9)://180 veh, 20 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_9.csv";
						break;
					case(4)://160 veh, 40 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_4.csv";
						break;
					case(3):// 150 veh, 50 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_3.csv";
						break;
					case(2): //134 veh, 66 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_2.csv";
						break;
					case(1): //100 veh, 100 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_1.csv";
						break;
					case(0): //0 veh, 200 RSU
						filename = NS3_ROOT "/analytics/results/hybrid_heterogeneity_0.csv";
						break;
				}
				break;
			case (7)://link lifetime experiment
				if (link_lifetime_threshold == 0.000)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_0.000.csv";
				}
				if(link_lifetime_threshold == 0.100)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_0.100.csv";
				}
				if(link_lifetime_threshold == 0.200)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_0.200.csv";
				}
				if(link_lifetime_threshold == 0.500)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_0.500.csv";
				}
				if(link_lifetime_threshold == 1.00)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_1.00.csv";
				}
				if(link_lifetime_threshold == 2.00)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_2.000.csv";
				}
				if(link_lifetime_threshold == 4.00)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_4.000.csv";
				}
				if(link_lifetime_threshold == 6.000)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_6.000.csv";
				}
				if(link_lifetime_threshold == 8.000)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_8.000.csv";
				}
				if(link_lifetime_threshold == 12.000)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_link_lifetime_10.000.csv";
				}
				break;	
			case (8)://contention experiment
				if (contention_threshold == 0.000)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.000.csv";
				}
				if(contention_threshold == 0.001)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.001.csv";
				}
				if(contention_threshold == 0.002)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.002.csv";
				}
				if(contention_threshold == 0.005)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.005.csv";
				}
				if(contention_threshold == 0.010)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.010.csv";
				}
				if(contention_threshold == 0.020)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.020.csv";
				}
				if(contention_threshold == 0.050)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.050.csv";
				}
				if(contention_threshold == 0.100)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.100.csv";
				}
				if(contention_threshold == 0.200)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.200.csv";
				}
				if(contention_threshold == 0.500)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_contention_0.500.csv";
				}
				break;	
			case (9)://routing frequency
				if (routing_frequency == 0.02)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_0.02.csv";
				}
				if (routing_frequency ==0.05)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_0.05.csv";
				}
				if (routing_frequency ==0.10)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_0.10.csv";
				}
				if (routing_frequency ==0.25)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_0.25.csv";
				}
				if (routing_frequency ==0.50)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_0.50.csv";
				}
				if (routing_frequency == 1.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_1.00.csv";
				}
				if (routing_frequency ==2.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_2.csv";
				}

				if (routing_frequency ==3.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_3.csv";
				}
		
				if (routing_frequency == 4.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_4.csv";
				}

				if (routing_frequency ==5.0)
				{
					filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_frequency_5.csv";
				}

				break;
			case (10): //number of nodes-routing
				switch(total_size)
				{
					case (4):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_4.csv";
						break;
					case (8):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_8.csv";
						break;
					case (16):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_16.csv";
						break;
					case (32):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_32.csv";
						break;
					case (64):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_64.csv";
						break;
					case (96):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_96.csv";
						break;
					case (128):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_128.csv";
						break;
					case (160):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_160.csv";
						break;
					case (192):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_192.csv";
						break;						
					case (224):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_224.csv";
						break;
					case (256):
						filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_nodes_256.csv";
						break;
				}
				break;
			case (11)://mobility scenario
				if (mobility_scenario == 0) //urban mobility
				  {
				  	switch(maxspeed)
				  	{
				  		case (0):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_urban_0.csv";
					  		break;
				  		case (10):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_urban_10.csv";
					  		break;
					  	case (20):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_urban_20.csv";
					  		break;
					  	case (30):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_urban_30.csv";
					  		break;
					  	case (40):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_urban_40.csv";
					  		break;
					  	case (50):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_urban_50.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_urban_60.csv";
					  		break;
					  	default:
					  		break;
					 }
				   }
				   
				   if (mobility_scenario == 1) //non-urban mobility
				   {
				   	switch(maxspeed)
				   	{
				   		case (0):
				   	  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_rural_0.csv";
				   	  		break;
				   	  	case (20):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_rural_20.csv";
					  		break;
					   	case (40):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_rural_40.csv";
					  		break;
					  	case (60):
					  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_rural_60.csv";
					  		break;
				   	  	case (80):
				   	  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_rural_80.csv";
				   	  		break;
				   	  	case (100):
				   	  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_rural_100.csv";
				   	  		break;
				   	  	default:
				   	  		break;
					 }
				   }
				   
				   if (mobility_scenario == 2)//highway
				   {
				   	  switch(maxspeed)
				   	  {
				   	  	case (0):
				   	  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_autobahn_0.csv";
				   	  		break;
				   	  	case (30):
				   	  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_autobahn_30.csv";
				   	  		break;
				   	  	case (50):
				   	  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_autobahn_50.csv";
				   	  		break;
				   	  	case (90):
				   	  		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_autobahn_90.csv";
				   	  		break;
					 	case (130):
					 		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_autobahn_130.csv";
					 		break;
					 	case (170):
					 		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_autobahn_170.csv";
					 		break;
					 	case (210):
					 		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_autobahn_210.csv";
					 		break;
					 	case (250):
					 		filename = NS3_ROOT "/analytics/results_routing/hybrid_routing_mobility_autobahn_250.csv";
					 		break;
					 	default:
					 		break;
					  }
				   }
				break;
		}

	}
	
	fout.open(filename,ios::out|ios::app);
	if (architecture == 0)
	{
		fout << data_gathering_cycle_number << ", ";
	}
	if (architecture == 2)
	{
		fout << (data_gathering_cycle_number - 1) << ", ";
	}
	if (paper == 0)
	{
	fout << current_cost << ", "
	     << average_cost << ", "
	     << current_lte_utilization << ", "
	     << average_lte_utilization << ", "
	     << current_ethernet_utilization << ", "
	     << average_ethernet_utilization << ", "
	     << current_dsrc_utilization << ", "
	     << average_dsrc_utilization << ", "
	     << 1000*current_latency << ", "
	     << 1000*average_latency << ", "
	     << optimization_percentage << ", "
	     << 100*current_packet_delivery_ratio << ", "
	     << 100*average_packet_delivery_ratio << ", "
	     << "\n";
	}
	
	if (paper == 1)
	{
	fout << current_cost << ", "
	     << average_cost << ", "
	     << current_lte_utilization << ", "
	     << average_lte_utilization << ", "
	     << current_ethernet_utilization << ", "
	     << average_ethernet_utilization << ", "
	     << current_dsrc_utilization << ", "
	     << average_dsrc_utilization << ", "
	     << 1000*current_latency_dsrc << ", "
	     << 1000*average_latency_dsrc << ", "
	     << 100*current_packet_delivery_ratio_dsrc << ", "
	     << 100*average_packet_delivery_ratio_dsrc << ", "
	     << "\n";
	}
	fout.close();
}

double utilization_time = 0.0;

double packet_delay_routing [2*flows][Flow_size+1];
double packet_jitter_routing [2*flows][Flow_size+1];
double routing_packet_initial_timestamp [2*flows][Flow_size+1];
double routing_packet_final_timestamp [2*flows][Flow_size+1];
double routing_packet_general_final_timestamp [2*flows][total_size][Flow_size+1];
double routing_packet_general_initial_timestamp [2*flows][total_size][Flow_size+1];


double routing_packet_initial_timestampLLDP [2*flows][2*flows][total_size][total_size];
double routing_packet_final_timestampLLDP [2*flows][2*flows][total_size][total_size];
double intercepted_packet_initial_timestampLLDP [2*flows][2*flows][total_size][total_size][total_size];
double intercepted_packet_final_timestampLLDP [2*flows][2*flows][total_size][total_size][total_size];

double average_latency_routing = 0.0;
double current_latency_routing = 0.0;
double previous_cumulative_ratio = 0.0;
double previous_cumulative_confusion_ratio = 0.0;
double previous_cumulative_intercepted_ratio = 0.0;
