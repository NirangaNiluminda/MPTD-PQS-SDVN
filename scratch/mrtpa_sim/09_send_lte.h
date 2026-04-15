// ============================================================
// SECTION 9: LTE Metadata Send Functions and Related Globals
// ============================================================
// Contents:
//   bool routing_time             - flag: is routing active now?
//   average_cost, average_*_utilization - running average metrics
//   clear_solution()              - clear routing solution state
//   send_LTE_metadata_uplink_alone()    - vehicle → controller via LTE
//   send_LTE_metadata_downlink_alone()  - controller → vehicle via LTE
//   send_LTE_deltavalues_downlink_alone() - send optimization delta values
//   send_LTE_LLDP_packetout_downlink()  - LLDP packet-out via LTE downlink
//   compute_controller_packet_out_cryptography() - encrypt control packet
//   RSU_deltavalues_downlink_unicast()  - RSU delta values unicast
//   RSU_metadata_uplink_unicast()       - RSU metadata uplink
//   RSU_metadata_downlink_unicast()     - RSU metadata downlink
//   sent_IDS[][][] flag array           - track IDS packet send state
// ============================================================
//int memblock_key = 2333; //< memory block key, need to keep the same in the python script
//APB apb(memblock_key);


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
	for (int i=0;i<(total_size+2);i++)
	{
		Z_gurobi[i] = 1;
		X_gurobi[i] = 1;
		Z_nodes[i] = 1;
		X_nodes[i] = 1;
	}
}



void send_LTE_metadata_uplink_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> node_source, Ptr <Node> destination_node, uint32_t node_index)
{

  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(2,0);//2nd IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	uint32_t nid = uint32_t(nu->GetId());
	if (nid == 2)
	{
		lte_total_packet_size = 0;
		lte_initial_timestamp = Simulator::Now().GetSeconds(); 	
	}
	uint32_t size = getNeighborsize((neighbordata_inst+nid));
	uint32_t safe_size = (size > 0) ? size : 1;
	//cout<<"sending vehicle data of neighborsize "<<size<<endl;
	uint32_t neighborid[safe_size];
	//uint32_t combined_cost[safe_size];
	for (uint32_t i=0;i<size;i++)
	{
		neighborid[i] = large;
	  	//combined_cost[i] = large;
	}
	CustomMetaDataUnicastTag0 tag0;
	CustomMetaDataUnicastTag1 tag1;
	CustomMetaDataUnicastTag2 tag2;
	CustomMetaDataUnicastTag3 tag3;
	CustomMetaDataUnicastTag4 tag4;
	CustomMetaDataUnicastTag5 tag5;
	CustomMetaDataUnicastTag6 tag6;
	CustomMetaDataUnicastTag7 tag7;
	CustomMetaDataUnicastTag8 tag8;
	CustomMetaDataUnicastTag9 tag9;
	CustomMetaDataUnicastTag10 tag10;
	CustomMetaDataUnicastTag11 tag11;
	CustomMetaDataUnicastTag12 tag12;
	CustomMetaDataUnicastTag13 tag13;
	CustomMetaDataUnicastTag14 tag14;
	CustomMetaDataUnicastTag15 tag15;
	CustomMetaDataUnicastTag16 tag16;
	CustomMetaDataUnicastTag17 tag17;
	CustomMetaDataUnicastTag18 tag18;
	CustomMetaDataUnicastTag19 tag19;
	CustomMetaDataUnicastTag20 tag20;
	CustomMetaDataUnicastTag21 tag21;
	CustomMetaDataUnicastTag22 tag22;
	CustomMetaDataUnicastTag23 tag23;
	CustomMetaDataUnicastTag24 tag24;
	CustomMetaDataUnicastTag25 tag25;
	CustomMetaDataUnicastTag tag;
	
	Time ti = Seconds(Simulator::Now().GetSeconds());
	Ptr <Packet> packet1 = Create <Packet> (0);
	uint32_t j = 0;
	for (uint32_t i=0;i<max;i++)
	{
		if ((((neighbordata_inst+nid)->neighborid[i]) != large) and (j<size))
		{
			neighborid[j] = (neighbordata_inst+nid)->neighborid[i];
	  		//combined_cost[i] = (neighbordata_inst+nid)->combined_cost[i];
	  		j++;
	  	}
	}
	switch (size)
	{
		case 0:
			tag0.SetNodeId(nid);
			//tag0.Setfrequency (data_transmission_frequency);
			//tag0.Setdatasize (84);
			tag0.SetTimestamp(ti);
			packet1->AddPacketTag(tag0);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 1:
			tag1.SetNodeId(nid);
			//tag1.Setfrequency (data_transmission_frequency);
			tag1.Setneighborid (neighborid);
			//tag1.Setcombinedcost (combined_cost);
			//tag1.Setdatasize (84);
			tag1.SetTimestamp(ti);
			packet1->AddPacketTag(tag1);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 2:
			tag2.SetNodeId(nid);
			//tag2.Setfrequency (data_transmission_frequency);
			tag2.Setneighborid (neighborid);
			//tag2.Setcombinedcost (combined_cost);
			//tag2.Setdatasize (84);
			tag2.SetTimestamp(ti);
			packet1->AddPacketTag(tag2);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 3:
			tag3.SetNodeId(nid);
			//tag3.Setfrequency (data_transmission_frequency);
			tag3.Setneighborid (neighborid);
			//tag3.Setcombinedcost (combined_cost);
			//tag3.Setdatasize (84);
			tag3.SetTimestamp(ti);
			packet1->AddPacketTag(tag3);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 4:
			tag4.SetNodeId(nid);
			//tag4.Setfrequency (data_transmission_frequency);
			tag4.Setneighborid (neighborid);
			//tag4.Setcombinedcost (combined_cost);
			//tag4.Setdatasize (84);
			tag4.SetTimestamp(ti);
			packet1->AddPacketTag(tag4);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 5:
			tag5.SetNodeId(nid);
			//tag5.Setfrequency (data_transmission_frequency);
			tag5.Setneighborid (neighborid);
			//tag5.Setcombinedcost (combined_cost);
			//tag5.Setdatasize (84);
			tag5.SetTimestamp(ti);
			packet1->AddPacketTag(tag5);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 6:
			tag6.SetNodeId(nid);
			//tag6.Setfrequency (data_transmission_frequency);
			tag6.Setneighborid (neighborid);
			//tag6.Setcombinedcost (combined_cost);
			//tag6.Setdatasize (84);
			tag6.SetTimestamp(ti);
			packet1->AddPacketTag(tag6);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 7:
			tag7.SetNodeId(nid);
			//tag7.Setfrequency (data_transmission_frequency);
			tag7.Setneighborid (neighborid);
			//tag7.Setcombinedcost (combined_cost);
			//tag7.Setdatasize (84);
			tag7.SetTimestamp(ti);
			packet1->AddPacketTag(tag7);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 8:
			tag8.SetNodeId(nid);
			//tag8.Setfrequency (data_transmission_frequency);
			tag8.Setneighborid (neighborid);
			//tag8.Setcombinedcost (combined_cost);
			//tag8.Setdatasize (84);
			tag8.SetTimestamp(ti);
			packet1->AddPacketTag(tag8);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 9:
			tag9.SetNodeId(nid);
			//tag9.Setfrequency (data_transmission_frequency);
			tag9.Setneighborid (neighborid);
			//tag9.Setcombinedcost (combined_cost);
			//tag9.Setdatasize (84);
			tag9.SetTimestamp(ti);
			packet1->AddPacketTag(tag9);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 10:
			tag10.SetNodeId(nid);
			//tag10.Setfrequency (data_transmission_frequency);
			tag10.Setneighborid (neighborid);
			//tag10.Setcombinedcost (combined_cost);
			//tag10.Setdatasize (84);
			tag10.SetTimestamp(ti);
			packet1->AddPacketTag(tag10);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 11:
			tag11.SetNodeId(nid);
			//tag11.Setfrequency (data_transmission_frequency);
			tag11.Setneighborid (neighborid);
			//tag11.Setcombinedcost (combined_cost);
			//tag11.Setdatasize (84);
			tag11.SetTimestamp(ti);
			packet1->AddPacketTag(tag11);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 12:
			tag12.SetNodeId(nid);
			//tag12.Setfrequency (data_transmission_frequency);
			tag12.Setneighborid (neighborid);
			//tag12.Setcombinedcost (combined_cost);
			//tag12.Setdatasize (84);
			tag12.SetTimestamp(ti);
			packet1->AddPacketTag(tag12);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 13:
			tag13.SetNodeId(nid);
			//tag13.Setfrequency (data_transmission_frequency);
			tag13.Setneighborid (neighborid);
			//tag13.Setcombinedcost (combined_cost);
			//tag13.Setdatasize (84);
			tag13.SetTimestamp(ti);
			packet1->AddPacketTag(tag13);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 14:
			tag14.SetNodeId(nid);
			//tag14.Setfrequency (data_transmission_frequency);
			tag14.Setneighborid (neighborid);
			//tag14.Setcombinedcost (combined_cost);
			//tag14.Setdatasize (84);
			tag14.SetTimestamp(ti);
			packet1->AddPacketTag(tag14);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 15:
			tag15.SetNodeId(nid);
			//tag15.Setfrequency (data_transmission_frequency);
			tag15.Setneighborid (neighborid);
			//tag15.Setcombinedcost (combined_cost);
			//tag15.Setdatasize (84);
			tag15.SetTimestamp(ti);
			packet1->AddPacketTag(tag15);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 16:
			tag16.SetNodeId(nid);
			//tag16.Setfrequency (data_transmission_frequency);
			tag16.Setneighborid (neighborid);
			//tag16.Setcombinedcost (combined_cost);
			//tag16.Setdatasize (84);
			tag16.SetTimestamp(ti);
			packet1->AddPacketTag(tag16);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 17:
			tag17.SetNodeId(nid);
			//tag17.Setfrequency (data_transmission_frequency);
			tag17.Setneighborid (neighborid);
			//tag17.Setcombinedcost (combined_cost);
			//tag17.Setdatasize (84);
			tag17.SetTimestamp(ti);
			packet1->AddPacketTag(tag17);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 18:
			tag18.SetNodeId(nid);
			//tag18.Setfrequency (data_transmission_frequency);
			tag18.Setneighborid (neighborid);
			//tag18.Setcombinedcost (combined_cost);
			//tag18.Setdatasize (84);
			tag18.SetTimestamp(ti);
			packet1->AddPacketTag(tag18);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 19:
			tag19.SetNodeId(nid);
			//tag19.Setfrequency (data_transmission_frequency);
			tag19.Setneighborid (neighborid);
			//tag19.Setcombinedcost (combined_cost);
			//tag19.Setdatasize (84);
			tag19.SetTimestamp(ti);
			packet1->AddPacketTag(tag19);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 20:
			tag20.SetNodeId(nid);
			//tag20.Setfrequency (data_transmission_frequency);
			tag20.Setneighborid (neighborid);
			//tag20.Setcombinedcost (combined_cost);
			//tag20.Setdatasize (84);
			tag20.SetTimestamp(ti);
			packet1->AddPacketTag(tag20);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 21:
			tag21.SetNodeId(nid);
			//tag21.Setfrequency (data_transmission_frequency);
			tag21.Setneighborid (neighborid);
			//tag21.Setcombinedcost (combined_cost);
			//tag21.Setdatasize (84);
			tag21.SetTimestamp(ti);
			packet1->AddPacketTag(tag21);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 22:
			tag22.SetNodeId(nid);
			//tag22.Setfrequency (data_transmission_frequency);
			tag22.Setneighborid (neighborid);
			//tag22.Setcombinedcost (combined_cost);
			//tag22.Setdatasize (84);
			tag22.SetTimestamp(ti);
			packet1->AddPacketTag(tag22);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 23:
			tag23.SetNodeId(nid);
			//tag23.Setfrequency (data_transmission_frequency);
			tag23.Setneighborid (neighborid);
			//tag23.Setcombinedcost (combined_cost);
			//tag23.Setdatasize (84);
			tag23.SetTimestamp(ti);
			packet1->AddPacketTag(tag23);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 24:
			tag24.SetNodeId(nid);
			//tag24.Setfrequency (data_transmission_frequency);
			tag24.Setneighborid (neighborid);
			//tag24.Setcombinedcost (combined_cost);
			//tag24.Setdatasize (84);
			tag24.SetTimestamp(ti);
			packet1->AddPacketTag(tag24);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 25:
			tag25.SetNodeId(nid);
			//tag25.Setfrequency (data_transmission_frequency);
			tag25.Setneighborid (neighborid);
			//tag25.Setcombinedcost (combined_cost);
			//tag25.Setdatasize (84);
			tag25.SetTimestamp(ti);
			packet1->AddPacketTag(tag25);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		default:
			cout<<"Cellular:maximum status datasize exceeded. size is "<<size<<endl;
			tag.SetNodeId(nid);
			//tag.Setfrequency (data_transmission_frequency);
			tag.Setneighborid ((neighbordata_inst+nid)->neighborid);
			//tag.Setcombinedcost ((neighbordata_inst+nid)->combined_cost);
			//tag.Setdatasize (84);
			tag.SetTimestamp(ti);
			packet1->AddPacketTag(tag);
			lte_total_packet_size = lte_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
	}
	cout<<"lte total packet size is "<<lte_total_packet_size<<endl;
}

void send_LTE_metadata_downlink_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> node_source, Ptr <Node> destination_node, uint32_t node_index)
{
  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	//cout<<dest_ip<<endl;
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	CustomMetaDataDownlinkUnicastTag tag;
	uint32_t nid = uint32_t(destination_node->GetId());
	tag.SetNodeId(nid);
	tag.SetZ (Z_gurobi[nid]);
	tag.SetX (X_gurobi[nid]);
	//tag.SetZ (1);
	//tag.SetX (0);
	Ptr <Packet> packet1 = Create <Packet> (0);
	packet1->AddPacketTag(tag);
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
}



void send_LTE_deltavalues_downlink_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> node_source, Ptr <Node> destination_node, uint32_t node_index)
{
  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	//cout<<dest_ip<<endl;
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	CustomDeltavaluesDownlinkUnicastTag tag;
	uint32_t nid = uint32_t(destination_node->GetId());
	//cout<<"node id is "<<nid<<"dest ip "<<dest_ip<<"custom value is"<<(delta_at_controller_inst+3)->delta_fi_inst[4].delta_values[5]<<endl;
	
	double delta_Set[2*flows][total_size];
	uint32_t sources[2*flows];
	uint32_t destinations[2*flows];
	uint32_t flow_ids[2*flows];
	uint32_t flow_sizes[2*flows];
	uint32_t nodeid = nid-2;
	double load[2*flows];
	
	for(uint32_t i=0;i<2*flows;i++)
	{
		load[i] = 0.0;
		for(uint32_t j=0;j<total_size;j++)	
		{
			load[i] = load[i] + (L_at_controller_inst+i)->L_fi_inst[nid-2].L_values[j];
			delta_Set[i][j] = (delta_at_controller_inst+i)->delta_fi_inst[nid-2].delta_values[j];
			//cout<< "i = "<<i<<"nid = "<<nid<<"j= "<<j<<"value="<<(delta_at_controller_inst+i)->delta_fi_inst[nid-2].delta_values[j]<<endl;
		}
		sources[i] = (demanding_flow_struct_controller_inst+i)->source;
		destinations[i] = (demanding_flow_struct_controller_inst+i)->destination;
		flow_ids[i] = i;
		flow_sizes[i] = (demanding_flow_struct_controller_inst+i)->f_size;
	}
	/*

	*/
	
	//cout<<delta_Set[3][2]<<dest_ip<<endl;
	//TEST - comment at implementation
	/*
	if ((nid-2) == 2)
	{
		delta_Set[3][5] = 0.75;
		sources[3] = 7;
		destinations[3] = 15;
		flow_ids[3] = 3;
	}
	*/
	//
	
	tag.Setdeltas(delta_Set);
	tag.Setsources (sources);
	tag.Setdestinations (destinations);
	tag.Setflow_ids (flow_ids);
	tag.Setflow_sizes(flow_sizes);
	tag.Setnodeid(nodeid);
	tag.Setload(load);
	//tag.SetX (0);
	Ptr <Packet> packet1 = Create <Packet> (0);
	packet1->AddPacketTag(tag);
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
}







void compute_controller_packet_out_cryptography(uint32_t node_index, uint32_t destination_index, uint32_t port_id)
{
	if(routing_algorithm == 4)
	{
	
	std::ostringstream oss1;
	    //Encrypt the node index using ASCON
		oss1 << " is_controller=true create_security_manager_con=true netsize=1 "
		    << " sign_FALCON=false verify_FALCON=false generate_FALCON=false "
		    << " encrypt_ASCON=true decrypt_ASCON=false generate_ASCON_key=false "
		    << " node_id="<< node_index << " port_id="  << port_id << " other_node_id=" << destination_index << ""
		    << " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false generate_own_aes_key=false"
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
		    << " message=" << node_index << " msg_type=1";
	   
	    std::string command_str1 = oss1.str();
	    Simulator::Schedule(Seconds(0), LDA_PQ_security, command_str1);
	  
	    //Encrypt port id using ASCON
	  	std::ostringstream oss2;
		oss2 << " is_controller=true create_security_manager_con=true netsize=1 "
		    << " sign_FALCON=false verify_FALCON=false generate_FALCON=false "
		    << " encrypt_ASCON=true decrypt_ASCON=false generate_ASCON_key=false "
		    << " node_id="<< node_index << " port_id="  << port_id << " other_node_id=" << destination_index << ""
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
		    << " message=" << port_id << " msg_type=2";
	   
	   std::string command_str2 = oss2.str();
	   Simulator::Schedule(Seconds(0), LDA_PQ_security, command_str2);   
	   
	   std::string filename = NS3_ROOT "/analytics/data/security_data.csv";
	   string HMAC_key = read_item_from_csv(filename, std::to_string(node_index), 10);
	   
	   
	   //Encrypt HMAC1 key
	   std::ostringstream oss3;
	   oss3 << " is_controller=true create_security_manager_con=true netsize=1 "
		    << " sign_FALCON=false verify_FALCON=false generate_FALCON=false "
		    << " encrypt_ASCON=true decrypt_ASCON=false generate_ASCON_key=false "
		    << " node_id="<< node_index << " port_id="  << port_id << " other_node_id=" << destination_index << ""
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
		    << " message=" << HMAC_key << " msg_type=3";
	   
	   std::string command_str3 = oss3.str();
	   Simulator::Schedule(Seconds(0), LDA_PQ_security, command_str3);
	   
	   
	   //Sign node id and port id using RSA-digital signature.
	   std::ostringstream oss4;
	   oss4 << " is_controller=true create_security_manager_con=true netsize=1 "
			<< " node_id=" << node_index << " port_id=" << port_id << " other_node_id=" << destination_index << " "
			<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
			<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
			<< " sign_data=true verify_signature=false initiate_session1=false "
			<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
			<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
			<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
			<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
			<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
			<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
			<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
			<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
			<< " message=" << node_index+port_id+destination_index << " ";
	    
	    std::string command_str4 = oss4.str();
		Simulator::Schedule(Seconds(0), LDA_security, command_str4);
	}
	
}




void send_LTE_LLDP_packetout_downlink_alone(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> node_source, uint32_t node_index, uint32_t destination_index, uint32_t port_id)
{
	cout<<endl;
	cout<<"Sending packet out to source "<<node_index<<"destination "<<destination_index<<"port "<<port_id<<endl;
	Ptr <Node> destination_node = Vehicle_Nodes.Get(node_index);
  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	cout<<dest_ip<<endl;
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	CustomLLDPDownlinkUnicastTag tag;
	uint32_t nid = uint32_t(destination_node->GetId());
	//cout<<"node id is "<<nid<<"dest ip "<<dest_ip<<"custom value is"<<(delta_at_controller_inst+3)->delta_fi_inst[4].delta_values[5]<<endl;
    std::string node_enc(36, 'A');
    std::string port_enc(36, 'A');
    std::string HMAC_key_enc(162, 'B');
    std::string digital_sig(512, 'C');

	
    /*
	std::ostringstream oss;
		oss << " is_controller=true create_security_manager_con=true netsize=1 "
			<< "node_id=" << node_index << " port_id=" << port_id << "other_node_id=" << destination_index << " "
			<< "generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
			<< "generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
			<< "sign_data=true verify_signature=false initiate_session1=true "
			<< "initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
			<< "decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
			<< "verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
			<< "encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
			<< "decrypt_controller_data=false generate_global_HMAC_secret_key=true "
			<< "get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
			<< "create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
			<< "encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
			<< "message=This\\ is\\ a\\ test\\ message";
	    std::string command_str = oss.str();
		Simulator::Schedule(Seconds(0), LDA_security, command_str);
	*/	
	
	if(routing_algorithm == 4)
	{
		cout<<"Reading digital signature LTE LLDP packet out"<<endl;
		std::string sig_file = NS3_ROOT "/analytics/data/security_con_dig_sig_data.csv";
		digital_sig = read_other_other_item_from_csv(sig_file, std::to_string(node_index), std::to_string(port_id), std::to_string(destination_index),  3);
		
		cout<<"Reading ASCON data 1 LTE LLDP packet out"<<endl;
		std::string filename_nodeencr = NS3_ROOT "/analytics/data/security_ASCON_data1.csv";
		node_enc = read_other_item_from_csv(filename_nodeencr, std::to_string(node_index), std::to_string(port_id), 2);
		   
		cout<<"Reading ASCON data 2 LTE LLDP packet out"<<endl;
		std::string filename_portenc = NS3_ROOT "/analytics/data/security_ASCON_data2.csv";
		port_enc = read_other_item_from_csv(filename_portenc, std::to_string(node_index), std::to_string(port_id), 2);
		   
		cout<<"Reading ASCON data 3 LTE LLDP packet out"<<endl;
		std::string filename_HMACkey_enc = NS3_ROOT "/analytics/data/security_ASCON_data3.csv";
		HMAC_key_enc = read_other_item_from_csv(filename_HMACkey_enc, std::to_string(node_index), std::to_string(port_id), 2);
	}
	cout<<"encrypted node_id size is "<<node_enc.size()<<"encrypted port id size is "<< port_enc.size()<<"HMAC key encrypted size is "<<HMAC_key_enc.size()<<"signature size is "<<digital_sig.size()<<endl;

	
	uint8_t * stage = new uint8_t[1];
	uint8_t * HMAC_key = new uint8_t[161];//161
	uint8_t * DS_public_key1 = new uint8_t[512];//512
	uint8_t * DS_public_key2 = new uint8_t[2560];
	uint8_t * DS_public_key3 =new uint8_t[2560];
	uint8_t * DS1 = new uint8_t[200];
	uint8_t * DS2 = new uint8_t[200];
	uint8_t * source_nodeid = new uint8_t[36];//35
	uint8_t * source_portid = new uint8_t[36];//35
	uint8_t * raw_source_nodeid = new uint8_t[1]; 
	uint8_t * raw_source_portid = new uint8_t[1];
	uint8_t * destination_nodeid = new uint8_t[32];
	uint8_t * HMAC1 = new uint8_t[64];
	uint8_t * HMAC2 = new uint8_t[64];
	
	
	*(stage+0) = 1;
	*(raw_source_nodeid+0) = static_cast<uint8_t>(node_index);
	*(raw_source_portid+0) = static_cast<uint8_t>(port_id);
	memset(destination_nodeid, 0, 32);
	*(destination_nodeid+0) = static_cast<uint8_t>(destination_index);
	
	cout<<"Sending packet out to raw source node id"<<static_cast<uint32_t>(*(raw_source_nodeid+0))<<"destination "<<static_cast<uint32_t>(*(destination_nodeid+0))<<"raw port id"<<static_cast<uint32_t>(*(raw_source_portid+0))<<"Stage is "<<static_cast<uint32_t>(*(stage+0))<<endl;
	
	//memcpy(source_nodeid, node_enc.data(), 35);
	
	HexStringToBytes(node_enc, source_nodeid, 36);
	HexStringToBytes(HMAC_key_enc, HMAC_key, 162);
	HexStringToBytes(port_enc, source_portid, 36);
	HexStringToBytes(digital_sig, DS_public_key1, 512);
	
	/*
	cout<<"prining byte converted encrypted data"<<endl;
	for(uint32_t i=0;i<36;i++)
	{
		cout<<*(source_nodeid+i)<<endl;
	}
	
	std::string str1 = BytesToHexString(source_nodeid, 18);
	cout<<"prining reformed hexadecimal encrypted data"<<endl;
	cout<<(str1)<<endl;
	*/
	
	//memcpy(source_portid, port_enc.data(), 35);
	//memcpy(HMAC_key, HMAC_key_enc.data(), 161);
	//memcpy(DS1, digital_sig.data(), 200);
	memset(DS2, 0, 200);
	memset(DS1, 0, 200);
	memset(DS_public_key2, 0, 2560);
	memset(DS_public_key3, 0, 2560);
	
	
	cout<<"source index is "<<nid-2<<endl;
	cout<<"destination index is "<<destination_index<<endl;
	/*
	for(uint32_t i=0;i<2*flows;i++)
	{
		load[i] = 0.0;
		for(uint32_t j=0;j<total_size;j++)	
		{
			load[i] = load[i] + (L_at_controller_inst+i)->L_fi_inst[nid-2].L_values[j];
			delta_Set[i][j] = (delta_at_controller_inst+i)->delta_fi_inst[nid-2].delta_values[j];
			//cout<< "i = "<<i<<"nid = "<<nid<<"j= "<<j<<"value="<<(delta_at_controller_inst+i)->delta_fi_inst[nid-2].delta_values[j]<<endl;
		}
		sources[i] = (demanding_flow_struct_controller_inst+i)->source;
		destinations[i] = (demanding_flow_struct_controller_inst+i)->destination;
		flow_ids[i] = i;
		flow_sizes[i] = (demanding_flow_struct_controller_inst+i)->f_size;
	}
	*/

	
	//cout<<delta_Set[3][2]<<dest_ip<<endl;
	//TEST - comment at implementation
	/*
	if ((nid-2) == 2)
	{
		delta_Set[3][5] = 0.75;
		sources[3] = 7;
		destinations[3] = 15;
		flow_ids[3] = 3;
	}
	*/
	//
	tag.SetStage(stage);
	cout<<1<<endl;
	tag.SetHMAC_key(HMAC_key);
	cout<<2<<endl;
	tag.SetHMAC1(HMAC1);
	cout<<3<<endl;
	tag.SetHMAC2(HMAC2);
	cout<<4<<endl;
	tag.SetDS_public_key1 (DS_public_key1);
	cout<<5<<endl;
	tag.SetDS_public_key2 (DS_public_key2);
	cout<<6<<endl;
	tag.SetDS_public_key3 (DS_public_key3);
	cout<<7<<endl;
	tag.SetDS1 (DS1);
	cout<<8<<endl;
	tag.SetDS2 (DS2);
	cout<<9<<endl;
	tag.Setsrcnodeid (source_nodeid);
	cout<<10<<endl;
	tag.Setsrcportid (source_portid);
	cout<<11<<endl;
	tag.Setrawsrcnodeid (raw_source_nodeid);
	cout<<12<<endl;
	tag.Setrawsrcportid (raw_source_portid);
	cout<<13<<endl;
	tag.Setdesnodeid (destination_nodeid);
	cout<<14<<endl;
	
	uint8_t * test = tag.Getdesnodeid();
	cout<<"Checking destination node id"<<static_cast<uint32_t>(*(test+0))<<endl;
	uint8_t * test2 = tag.Getrawsrcnodeid();
	cout<<"Checking source node id"<<static_cast<uint32_t>(*(test2+0))<<endl;
	uint8_t * test3 = tag.Getrawsrcportid();
	cout<<"Checking port id"<<static_cast<uint32_t>(*(test3+0))<<endl;
	
	//tag.SetX (0);
	Ptr <Packet> packet1 = Create <Packet> (0);
	packet1->AddPacketTag(tag);
	std::cout << "Pkt UID=" << packet1->GetUid()<<endl;
	/*
	if((Simulator::Now().GetSeconds()-downlink_last)>0.50)
	{
		cout<<"Retransmitting packet Sending packet out to source "<<node_index<<"destination "<<destination_index<<"port "<<port_id<<endl;
		Simulator::Schedule(Seconds(0.000),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
	}
	*/
	//Simulator::Schedule(Seconds(0.005),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
	Simulator::Schedule(Seconds(0.005),&TrySendDownlink, destination_index, node_index, port_id, packet1, 0);
	//cout<<"Sent packet at "<<Simulator::Now().GetSeconds()<<endl;
	downlink_last = Simulator::Now().GetSeconds();

}




void RSU_deltavalues_downlink_unicast(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> source_node, Ptr <Node> destination_node)
{
	Ptr <Node> nu = DynamicCast <Node> (source_node);
	uint32_t nid = uint32_t(destination_node->GetId());
	
	CustomDeltavaluesDownlinkUnicastTag tag;
	//cout<<"node id is "<<nid<<"dest ip "<<dest_ip<<"custom value is"<<(delta_at_controller_inst+3)->delta_fi_inst[4].delta_values[5]<<endl;
	
	double delta_Set[2*flows][total_size];
	uint32_t sources[2*flows];
	uint32_t destinations[2*flows];
	uint32_t flow_ids[2*flows];
	uint32_t flow_sizes[2*flows];
	uint32_t nodeid = nid-2;
	double load[2*flows];
	
	for(uint32_t i=0;i<2*flows;i++)
	{
		load[i] = 0.0;
		for(uint32_t j=0;j<total_size;j++)	
		{
			load[i] = load[i] + (L_at_controller_inst+i)->L_fi_inst[nid-2].L_values[j];
			delta_Set[i][j] = (delta_at_controller_inst+i)->delta_fi_inst[nid-2].delta_values[j];
			//cout<< "i = "<<i<<"nid = "<<nid<<"j= "<<j<<"value="<<(delta_at_controller_inst+i)->delta_fi_inst[nid-2].delta_values[j]<<endl;
		}
		sources[i] = (demanding_flow_struct_controller_inst+i)->source;
		destinations[i] = (demanding_flow_struct_controller_inst+i)->destination;
		flow_ids[i] = i;
		flow_sizes[i] = (demanding_flow_struct_controller_inst+i)->f_size;
	}
	
	//cout<<delta_Set[3][2]<<dest_ip<<endl;
	
	tag.Setdeltas(delta_Set);
	tag.Setsources (sources);
	tag.Setdestinations (destinations);
	tag.Setflow_ids (flow_ids);
	tag.Setflow_sizes(flow_sizes);
	tag.Setnodeid(nodeid);
	tag.Setload(load);

	Ptr <Packet> packet1 = Create <Packet> (0);
	packet1->AddPacketTag(tag);
  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
  	Ipv4InterfaceAddress iaddr;
	iaddr = ipv4->GetAddress(1,0);//2nd IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	//cout<<"destination ip address "<<dest_ip;
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
}

void RSU_metadata_uplink_unicast(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> source_node, Ptr <Node> destination_node)
{

	Ptr <Node> nu = DynamicCast <Node> (source_node);
	uint32_t nid = uint32_t(nu->GetId());
	if (nid == (N_Vehicles+2))
	{
		ethernet_total_packet_size = 0;
		ethernet_initial_timestamp = Simulator::Now().GetSeconds();
	}
	uint32_t size = getNeighborsize((neighbordata_inst+nid));
	uint32_t safe_size = (size > 0) ? size : 1;
	uint32_t neighborid[safe_size];
	//uint32_t combined_cost[safe_size];
	for (uint32_t i=0;i<size;i++)
	{
		neighborid[i] = large;
	  	//combined_cost[i] = large;
	}
	//cout<<neighborid[0]<<combined_cost[0]<<endl;
	//cout<<"RSU: "<<size<<"node id"<<nid<<endl;
	CustomMetaDataUnicastTag0 tag0;
	CustomMetaDataUnicastTag1 tag1;
	CustomMetaDataUnicastTag2 tag2;
	CustomMetaDataUnicastTag3 tag3;
	CustomMetaDataUnicastTag4 tag4;
	CustomMetaDataUnicastTag5 tag5;
	CustomMetaDataUnicastTag6 tag6;
	CustomMetaDataUnicastTag7 tag7;
	CustomMetaDataUnicastTag8 tag8;
	CustomMetaDataUnicastTag9 tag9;
	CustomMetaDataUnicastTag10 tag10;
	CustomMetaDataUnicastTag11 tag11;
	CustomMetaDataUnicastTag12 tag12;
	CustomMetaDataUnicastTag13 tag13;
	CustomMetaDataUnicastTag14 tag14;
	CustomMetaDataUnicastTag15 tag15;
	CustomMetaDataUnicastTag16 tag16;
	CustomMetaDataUnicastTag17 tag17;
	CustomMetaDataUnicastTag18 tag18;
	CustomMetaDataUnicastTag19 tag19;
	CustomMetaDataUnicastTag20 tag20;
	CustomMetaDataUnicastTag21 tag21;
	CustomMetaDataUnicastTag22 tag22;
	CustomMetaDataUnicastTag23 tag23;
	CustomMetaDataUnicastTag24 tag24;
	CustomMetaDataUnicastTag25 tag25;
	CustomMetaDataUnicastTag tag;
	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr;
	if (N_Vehicles > 0)
	{
		iaddr = ipv4->GetAddress(1,0);//2nd IPv4 interface,0th address index
	}
	else if (N_Vehicles == 0)
	{
		iaddr = ipv4->GetAddress(0,0);//1st IPv4 interface,0th address index
	}
	Ipv4Address dest_ip = iaddr.GetLocal();
	Time ti = Seconds(Simulator::Now().GetSeconds());
	Ptr <Packet> packet1 = Create <Packet> (0);
	uint32_t j=0;
	for (uint32_t i=0;i<max;i++)
	{
		if ((((neighbordata_inst+nid)->neighborid[i]) != large) and (j<size))
		{
			neighborid[j] = (neighbordata_inst+nid)->neighborid[i];
	  		//combined_cost[i] = (neighbordata_inst+nid)->combined_cost[i];
	  		j++;
	  	}
	}
	switch (size)
	{
		case 0:
			cout<<"case 0";
			tag0.SetNodeId(nid);
			//tag0.Setfrequency (data_transmission_frequency);
			//tag0.Setdatasize (84);
			tag0.SetTimestamp(ti);
			packet1->AddPacketTag(tag0);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 1:
			cout<<"case 1";
			tag1.SetNodeId(nid);
			//tag1.Setfrequency (data_transmission_frequency);
			tag1.Setneighborid (neighborid);
			//tag1.Setcombinedcost (combined_cost);
			//tag1.Setdatasize (84);
			tag1.SetTimestamp(ti);
			packet1->AddPacketTag(tag1);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 2:
			cout<<"case 2";
			tag2.SetNodeId(nid);
			//tag2.Setfrequency (data_transmission_frequency);
			tag2.Setneighborid (neighborid);
			//tag2.Setcombinedcost (combined_cost);
			//tag2.Setdatasize (84);
			tag2.SetTimestamp(ti);
			packet1->AddPacketTag(tag2);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 3:
			cout<<"case 3";
			tag3.SetNodeId(nid);
			//tag3.Setfrequency (data_transmission_frequency);
			tag3.Setneighborid (neighborid);
			//tag3.Setcombinedcost (combined_cost);
			//tag3.Setdatasize (84);
			tag3.SetTimestamp(ti);
			packet1->AddPacketTag(tag3);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 4:
			tag4.SetNodeId(nid);
			//tag4.Setfrequency (data_transmission_frequency);
			tag4.Setneighborid (neighborid);
			//tag4.Setcombinedcost (combined_cost);
			//tag4.Setdatasize (84);
			tag4.SetTimestamp(ti);
			packet1->AddPacketTag(tag4);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 5:
			tag5.SetNodeId(nid);
			//tag5.Setfrequency (data_transmission_frequency);
			tag5.Setneighborid (neighborid);
			//tag5.Setcombinedcost (combined_cost);
			//tag5.Setdatasize (84);
			tag5.SetTimestamp(ti);
			packet1->AddPacketTag(tag5);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 6:
			tag6.SetNodeId(nid);
			//tag6.Setfrequency (data_transmission_frequency);
			tag6.Setneighborid (neighborid);
			//tag6.Setcombinedcost (combined_cost);
			//tag6.Setdatasize (84);
			tag6.SetTimestamp(ti);
			packet1->AddPacketTag(tag6);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 7:
			tag7.SetNodeId(nid);
			//tag7.Setfrequency (data_transmission_frequency);
			tag7.Setneighborid (neighborid);
			//tag7.Setcombinedcost (combined_cost);
			//tag7.Setdatasize (84);
			tag7.SetTimestamp(ti);
			packet1->AddPacketTag(tag7);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 8:
			tag8.SetNodeId(nid);
			//tag8.Setfrequency (data_transmission_frequency);
			tag8.Setneighborid (neighborid);
			//tag8.Setcombinedcost (combined_cost);
			//tag8.Setdatasize (84);
			tag8.SetTimestamp(ti);
			packet1->AddPacketTag(tag8);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 9:
			tag9.SetNodeId(nid);
			//tag9.Setfrequency (data_transmission_frequency);
			tag9.Setneighborid (neighborid);
			//tag9.Setcombinedcost (combined_cost);
			//tag9.Setdatasize (84);
			tag9.SetTimestamp(ti);
			packet1->AddPacketTag(tag9);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 10:
			tag10.SetNodeId(nid);
			//tag10.Setfrequency (data_transmission_frequency);
			tag10.Setneighborid (neighborid);
			//tag10.Setcombinedcost (combined_cost);
			//tag10.Setdatasize (84);
			tag10.SetTimestamp(ti);
			packet1->AddPacketTag(tag10);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 11:
			tag11.SetNodeId(nid);
			//tag11.Setfrequency (data_transmission_frequency);
			tag11.Setneighborid (neighborid);
			//tag11.Setcombinedcost (combined_cost);
			//tag11.Setdatasize (84);
			tag11.SetTimestamp(ti);
			packet1->AddPacketTag(tag11);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 12:
			tag12.SetNodeId(nid);
			//tag12.Setfrequency (data_transmission_frequency);
			tag12.Setneighborid (neighborid);
			//tag12.Setcombinedcost (combined_cost);
			//tag12.Setdatasize (84);
			tag12.SetTimestamp(ti);
			packet1->AddPacketTag(tag12);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 13:
			tag13.SetNodeId(nid);
			//tag13.Setfrequency (data_transmission_frequency);
			tag13.Setneighborid (neighborid);
			//tag13.Setcombinedcost (combined_cost);
			//tag13.Setdatasize (84);
			tag13.SetTimestamp(ti);
			packet1->AddPacketTag(tag13);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 14:
			tag14.SetNodeId(nid);
			//tag14.Setfrequency (data_transmission_frequency);
			tag14.Setneighborid (neighborid);
			//tag14.Setcombinedcost (combined_cost);
			//tag14.Setdatasize (84);
			tag14.SetTimestamp(ti);
			packet1->AddPacketTag(tag14);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 15:
			tag15.SetNodeId(nid);
			//tag15.Setfrequency (data_transmission_frequency);
			tag15.Setneighborid (neighborid);
			//tag15.Setcombinedcost (combined_cost);
			//tag15.Setdatasize (84);
			tag15.SetTimestamp(ti);
			packet1->AddPacketTag(tag15);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 16:
			tag16.SetNodeId(nid);
			//tag16.Setfrequency (data_transmission_frequency);
			tag16.Setneighborid (neighborid);
			//tag16.Setcombinedcost (combined_cost);
			//tag16.Setdatasize (84);
			tag16.SetTimestamp(ti);
			packet1->AddPacketTag(tag16);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 17:
			tag17.SetNodeId(nid);
			//tag17.Setfrequency (data_transmission_frequency);
			tag17.Setneighborid (neighborid);
			//tag17.Setcombinedcost (combined_cost);
			//tag17.Setdatasize (84);
			tag17.SetTimestamp(ti);
			packet1->AddPacketTag(tag17);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 18:
			tag18.SetNodeId(nid);
			//tag18.Setfrequency (data_transmission_frequency);
			tag18.Setneighborid (neighborid);
			//tag18.Setcombinedcost (combined_cost);
			//tag18.Setdatasize (84);
			tag18.SetTimestamp(ti);
			packet1->AddPacketTag(tag18);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 19:
			tag19.SetNodeId(nid);
			//tag19.Setfrequency (data_transmission_frequency);
			tag19.Setneighborid (neighborid);
			//tag19.Setcombinedcost (combined_cost);
			//tag19.Setdatasize (84);
			tag19.SetTimestamp(ti);
			packet1->AddPacketTag(tag19);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 20:
			tag20.SetNodeId(nid);
			//tag20.Setfrequency (data_transmission_frequency);
			tag20.Setneighborid (neighborid);
			//tag20.Setcombinedcost (combined_cost);
			//tag20.Setdatasize (84);
			tag20.SetTimestamp(ti);
			packet1->AddPacketTag(tag20);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 21:
			tag21.SetNodeId(nid);
			//tag21.Setfrequency (data_transmission_frequency);
			tag21.Setneighborid (neighborid);
			//tag21.Setcombinedcost (combined_cost);
			//tag21.Setdatasize (84);
			tag21.SetTimestamp(ti);
			packet1->AddPacketTag(tag21);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 22:
			tag22.SetNodeId(nid);
			//tag22.Setfrequency (data_transmission_frequency);
			tag22.Setneighborid (neighborid);
			//tag22.Setcombinedcost (combined_cost);
			//tag22.Setdatasize (84);
			tag22.SetTimestamp(ti);
			packet1->AddPacketTag(tag22);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 23:
			tag23.SetNodeId(nid);
			//tag23.Setfrequency (data_transmission_frequency);
			tag23.Setneighborid (neighborid);
			//tag23.Setcombinedcost (combined_cost);
			//tag23.Setdatasize (84);
			tag23.SetTimestamp(ti);
			packet1->AddPacketTag(tag23);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 24:
			tag24.SetNodeId(nid);
			//tag24.Setfrequency (data_transmission_frequency);
			tag24.Setneighborid (neighborid);
			//tag24.Setcombinedcost (combined_cost);
			//tag24.Setdatasize (84);
			tag24.SetTimestamp(ti);
			packet1->AddPacketTag(tag24);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		case 25:
			tag25.SetNodeId(nid);
			//tag25.Setfrequency (data_transmission_frequency);
			tag25.Setneighborid (neighborid);
			//tag25.Setcombinedcost (combined_cost);
			//tag25.Setdatasize (84);
			tag25.SetTimestamp(ti);
			packet1->AddPacketTag(tag25);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
		default:
			cout<<"RSU: maximum data size exceeded. size is"<<size<<endl;
			tag.SetNodeId(nid);
			//tag.Setfrequency (data_transmission_frequency);
			tag.Setneighborid ((neighbordata_inst+nid)->neighborid);
			//tag.Setcombinedcost ((neighbordata_inst+nid)->combined_cost);
			//tag.Setdatasize (84);
			tag.SetTimestamp(ti);
			packet1->AddPacketTag(tag);
			ethernet_total_packet_size = ethernet_total_packet_size + packet1->GetSerializedSize();
			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
			break;
	}
	cout<<"RSU total packet size is "<<ethernet_total_packet_size<<endl;
}
bool sent_IDS[2*flows][total_size][Flow_size+2];

void RSU_metadata_downlink_unicast(Ptr <SimpleUdpApplication> udp_app, Ptr <Node> source_node, Ptr <Node> destination_node)
{
	Ptr <Node> nu = DynamicCast <Node> (source_node);
	CustomMetaDataDownlinkUnicastTag tag;
	uint32_t nid = uint32_t(destination_node->GetId());
	tag.SetNodeId(nid);
	tag.SetZ (Z_gurobi[nid]);
	tag.SetX (X_gurobi[nid]);
	//tag.SetZ (0);
	//tag.SetX (1);
	Ptr <Packet> packet1 = Create <Packet> (0);
	packet1->AddPacketTag(tag);
  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
  	Ipv4InterfaceAddress iaddr;
	iaddr = ipv4->GetAddress(1,0);//2nd IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	//cout<<"destination ip address "<<dest_ip;
	Simulator::Schedule(Seconds(0),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip,7777);
}

