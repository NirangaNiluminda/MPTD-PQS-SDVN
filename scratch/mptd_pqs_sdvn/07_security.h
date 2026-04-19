// ============================================================
// SECTION 7: Security Protocols (HMAC, Digital Signatures, Crypto)
// ============================================================
// Contents:
//   LDA_security()                   - Lightweight Detection Algorithm
//   LDA_PQ_security()                - Post-quantum crypto variant (FALCON/ASCON)
//   location_HMAC_verify()           - verify location using HMAC
//   verify_location()                - MRTPA Phase 2: verify trajectory vs stored
//   create_HMAC1_and_digital_signature() - generate HMAC1 + RSA/ECC signature
//   check_signature()                - verify digital signature
//   verify_uplink_packet_first_time()  - first-time uplink verification
//   verify_uplink_packet_second_time() - second-time uplink verification
//   encrypt_HMAC2()                  - encrypt secondary HMAC
//   read_uplink_data_first/second()  - parse uplink packet data
//   send_LTE_LLDP_packetin_uplink()  - send LLDP packet uplink via LTE
//   send_Ethernet_LLDP_packetin()    - send LLDP via Ethernet backhaul
//   LLDP_dsrc_data_unicast()         - LLDP over DSRC (data plane)
//   Checkcounterandflood()           - flooding attack detection/mitigation
// ============================================================
bool routing_test = true;

NetDeviceContainer wifidevices;
NetDeviceContainer wifidevices_172;
NetDeviceContainer wifidevices_174;
NetDeviceContainer wifidevices_176;
NetDeviceContainer wifidevices_180;
NetDeviceContainer wifidevices_182;
NetDeviceContainer wifidevices_184;


NodeContainer dsrc_Nodes;

double data_gathering_cycle_number = 1.0;
double M;
uint32_t Y[total_size];
double R[total_size];
double Q[total_size];
double N_WL[total_size];
double N_WI[total_size];
double Q_nei[total_size];
double Q_bar;
double D_wl_bar[total_size];
double D_wi_bar[total_size];
double one_hop_delay_training_wl[total_size];
double packets_received_wl[total_size];
double one_hop_delay_training_wi[total_size];
double packets_received_wi[total_size];
double d_cont_wl_bar;
double d_cont_wl_max;
double d_cont_wi_bar;
double d_cont_wi_max;
double contention;
double base_packet_size = 204;
double packet_additional_size = 0;
double packet_size;
double rts;
double cts;
double ack;
double DR_WL = 12.0;
double DR_WI = 1000.0;
double SIFS = 12;
double E = 6;
double T_c;
double T_slot = 20.0;
double rho_wl;
double rho_wi;
double CW_min = 15.0;

// ── RL delay-training functions (stubbed — not used in MPTD-PQS) ─────────────
void reset_delays_and_packets() {}
void write_csv_delay_training(uint32_t, uint32_t) {}
void write_csv_delay_prediction() {}
void compute_1hop_delay() {}
double calculate_wireless_entropy() { return 0.0; }
double calculate_wired_entropy() { return 0.0; }
void compute_Qbar() {}
void compute_Qnei() {}
void compute_wireless_average_delay(uint32_t) {}
void compute_wired_average_delay(uint32_t) {}
void compute_average_delays() {}
void calculate_contention() {}


bool uplink_state[total_size];
bool downlink_state[total_size];

class SimpleUdpApplication : public Application 
  {
    public:
      SimpleUdpApplication ();
      virtual ~SimpleUdpApplication ();

      static TypeId GetTypeId ();
      virtual TypeId GetInstanceTypeId () const;

      /** \brief handles incoming packets on port 7777
       */
      void HandleReadOne (Ptr<Socket> socket);

      /** \brief handles incoming packets on port 9999
       */
      void HandleReadTwo (Ptr<Socket> socket);

      /** \brief Send an outgoing packet. This creates a new socket every time (not the best solution)
      */
      void SendPacket (Ptr<Packet> packet, Ipv4Address destination, uint16_t port);
      void test();
      void UplinkConnect(Ipv4Address destination, uint16_t port);
      void DownlinkConnect(Ipv4Address destination, uint16_t port);
      void UplinkSendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t node_id);
      void DownlinkSendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t node_id);
  

    private:
      
      
      void SetupReceiveSocket (Ptr<Socket> socket, uint16_t port);
      virtual void StartApplication ();


      Ptr<Socket> m_recv_socket1; /**< A socket to receive on a specific port */
      Ptr<Socket> m_recv_socket2; /**< A socket to receive on a specific port */
      uint16_t m_port1; 
      uint16_t m_port2;

      Ptr<Socket> m_send_socket; /**< A socket to listen on a specific port */
      Ptr<Socket> m_uplink_send_socket;
      Ptr<Socket> m_downlink_send_socket;
  };
  



// (guard closed in 04_state_globals.h)

#define PURPLE_CODE "\033[95m"
#define CYAN_CODE "\033[96m"
#define TEAL_CODE "\033[36m"
#define BLUE_CODE "\033[94m"
#define GREEN_CODE "\033[32m"
#define YELLOW_CODE "\033[33m"
#define LIGHT_YELLOW_CODE "\033[93m"
#define RED_CODE "\033[91m"
#define BOLD_CODE "\033[1m"
#define END_CODE "\033[0m"




class SimpleUdpApplication;
 NS_OBJECT_ENSURE_REGISTERED(SimpleUdpApplication);

/*
namespace ns3 {
    class SimpleUdpApplication;
    void SendPacket(ns3::Ptr<ns3::Packet> packet, ns3::Ipv4Address dest, uint16_t port);
}
*/

 //NS_LOG_COMPONENT_DEFINE("SimpleUdpApplication");


  TypeId
  SimpleUdpApplication::GetTypeId()
  {
    static TypeId tid = TypeId("ns3::SimpleUdpApplication")
                            .AddConstructor<SimpleUdpApplication>()
                            .SetParent<Application>();
    return tid;
  }

  TypeId
  SimpleUdpApplication::GetInstanceTypeId() const
  {
    return SimpleUdpApplication::GetTypeId();
  }

  SimpleUdpApplication::SimpleUdpApplication()
  {
    m_port1 = 7777;
    m_port2 = 9999;
  }
  SimpleUdpApplication::~SimpleUdpApplication()
  {
  }
  void SimpleUdpApplication::SetupReceiveSocket(Ptr<Socket> socket, uint16_t port)
  {
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), port);
    if (socket->Bind(local) == -1)
    {
      NS_FATAL_ERROR("Failed to bind socket");
    }
  }
  void SimpleUdpApplication::StartApplication()
  {
    //Receive sockets
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    m_recv_socket1 = Socket::CreateSocket(GetNode(), tid);
    m_recv_socket2 = Socket::CreateSocket(GetNode(), tid);

    SetupReceiveSocket(m_recv_socket1, m_port1);
    SetupReceiveSocket(m_recv_socket2, m_port2);

    m_recv_socket1->SetRecvCallback(MakeCallback(&SimpleUdpApplication::HandleReadOne, this));
    m_recv_socket2->SetRecvCallback(MakeCallback(&SimpleUdpApplication::HandleReadTwo, this));

    //Send Socket
    m_send_socket = Socket::CreateSocket(GetNode(), tid);
    m_uplink_send_socket = Socket::CreateSocket(GetNode(), tid);
    m_downlink_send_socket = Socket::CreateSocket(GetNode(), tid);
    
    uint16_t uplink_local_port1 = 10000; // unique per UE
	InetSocketAddress local1 = InetSocketAddress(Ipv4Address::GetAny(), uplink_local_port1);
	m_uplink_send_socket->Bind(local1);
	
	uint16_t downlink_local_port3 = 30000; // unique per UE
	InetSocketAddress local3 = InetSocketAddress(Ipv4Address::GetAny(), downlink_local_port3);
	m_downlink_send_socket->Bind(local3);
	
	
	uint16_t uplink_local_port2 = 20000; // unique per UE
	InetSocketAddress local2 = InetSocketAddress(Ipv4Address::GetAny(), uplink_local_port2);
	m_send_socket->Bind(local2);
    
    m_recv_socket1->SetAllowBroadcast(true);
    m_recv_socket2->SetAllowBroadcast(true);
    m_send_socket->SetAllowBroadcast(true);
    m_uplink_send_socket->SetAllowBroadcast(true);
    m_downlink_send_socket->SetAllowBroadcast(true);
  }
  
    void SimpleUdpApplication::test()
  {
 	cout<<"Test function"<<endl;
  }

  void SimpleUdpApplication::HandleReadTwo(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);
    Ptr<Packet> packet;
    Address from;
    Address localAddress;
    while ((packet = socket->RecvFrom(from)))
    {
      NS_LOG_INFO(PURPLE_CODE << "HandleReadTwo : Received a Packet of size: " << packet->GetSize() << " at time " << Now().GetSeconds() << END_CODE);
      NS_LOG_INFO("Content: " << packet->ToString());
    }
  }

  void SimpleUdpApplication::SendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t port)
  {
    //cout<<m_send_socket<<endl;
    NS_LOG_FUNCTION (this << packet << destination << port);
    m_send_socket->Connect(InetSocketAddress(Ipv4Address::ConvertFrom(destination), port));
    int x = m_send_socket->Send(packet);
    if (x == -1)
    {
    	cout<<"An Error occured in sending"<<endl;
    }
  }
  
   void SimpleUdpApplication::UplinkConnect(Ipv4Address destination, uint16_t port)
  {
    //cout<<m_send_socket<<endl;
    //NS_LOG_FUNCTION (this << packet << destination << port);
    int x = m_uplink_send_socket->Connect(InetSocketAddress(Ipv4Address::ConvertFrom(destination), port));
    if (x == -1)
    {
    	cout<<"An Error in connencting uplink"<<endl;
    }
}
  
   void SimpleUdpApplication::UplinkSendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t node_id)
  {
    //cout<<m_send_socket<<endl;
    //NS_LOG_FUNCTION (this << packet << destination << port);
    //m_uplink_send_socket->Connect(InetSocketAddress(Ipv4Address::ConvertFrom(destination), port));
    int x = m_uplink_send_socket->Send(packet);
    if (x == -1)
    {
       cout<<"An Error occured in sending packet uplink"<<endl;
       uplink_state[node_id] = false;
    }
    else
    {
		cout<<"Uplink packet transmitted"<<endl;
		uplink_state[node_id] = true;
	}

  }
  
   void SimpleUdpApplication::DownlinkConnect(Ipv4Address destination, uint16_t port)
  {
    //cout<<m_send_socket<<endl;
    //NS_LOG_FUNCTION (this << packet << destination << port);
    int x = m_downlink_send_socket->Connect(InetSocketAddress(Ipv4Address::ConvertFrom(destination), port));
    if (x == -1)
    {
    	cout<<"An Error in connencting downlink"<<endl;
    }
}
  
  void SimpleUdpApplication::DownlinkSendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t node_id)
  {
    //cout<<m_send_socket<<endl;
    //NS_LOG_FUNCTION (this << packet << destination << port);
    //m_uplink_send_socket->Connect(InetSocketAddress(Ipv4Address::ConvertFrom(destination), port));
    int x = m_downlink_send_socket->Send(packet);
    if (x == -1)
    {
       cout<<"An Error occured in sending packet downlink"<<endl;
       downlink_state[node_id] = false;
    }
    else
    {
		cout<<"Downlink packet transmitted"<<endl;
		downlink_state[node_id] = true;
	}

  }


double temp_link_set[total_size][total_size][2][2];
uint32_t flood_counter_con[total_size][total_size][2];
uint32_t flood_counter_sen[total_size][total_size][2];
uint32_t flood_counter_rec[total_size][total_size][2];
uint32_t LLDP_flood_counter_rec[total_size][total_size][2][2];
uint32_t RL_iterations = uint32_t(1);

bool check_signature()
{
 	return true;

}

void send_LTE_LLDP_packetin_uplink_alone(uint32_t node_index, uint32_t destination_index, uint32_t port_id, Ptr <Packet> packet1)
{
	Ptr <Node> node_source = Vehicle_Nodes.Get(destination_index);
	Ptr <Node> destination_node = controller_Node.Get(0);
	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(destination_index+2));

  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(2,0);//1st IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	cout<<dest_ip<<endl;
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	//uint32_t nid = uint32_t(destination_node->GetId());
	//cout<<"node id is "<<nid<<"dest ip "<<dest_ip<<"custom value is"<<(delta_at_controller_inst+3)->delta_fi_inst[4].delta_values[5]<<endl;
	bool s1 = (( flood_counter_rec[node_index][destination_index][port_id] < 4.0)&&(routing_algorithm==3));
	bool s2 = (( flood_counter_rec[node_index][destination_index][port_id] < 2*RL_iterations)&&(routing_algorithm==4));
	bool s3 = ((routing_algorithm != 3)&&(routing_algorithm != 4));
	cout<<"s1 is"<<s1<<"s2 is "<<s2<<"s3 is "<<s3<<endl;
	if(s1||s2||s3)
	{
		cout<<"Packet in sent attempt at time "<<Simulator::Now().GetSeconds()<<"from node "<<destination_index<<endl;
		Simulator::Schedule(Seconds(0),&SimpleUdpApplication::UplinkSendPacket,udp_app,packet1,dest_ip,destination_index);
		ueBusy[destination_index] = true;
	}
	if(routing_algorithm==3)
	{
		flood_counter_rec[node_index][destination_index][port_id] = flood_counter_rec[node_index][destination_index][port_id] + 1;
	}
	if (routing_algorithm == 4)
	{
	  	bool signature_check = check_signature();
	  	if (signature_check == true)
	  	{
	  		
	  	}
	
	}

}

void Trysend_Ethernet_LLDP_packetout_downlink_alone(uint32_t node_index, uint32_t destination_index, uint32_t port_id, Ptr <Packet> packet1)
{
	Ptr <Node> destination_node = RSU_Nodes.Get(destination_index);
	Ptr <Node> node_source = management_Node.Get(0);
	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(destination_index));

  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	cout<<dest_ip<<endl;
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	//uint32_t nid = uint32_t(destination_node->GetId());
	//cout<<"node id is "<<nid<<"dest ip "<<dest_ip<<"custom value is"<<(delta_at_controller_inst+3)->delta_fi_inst[4].delta_values[5]<<endl;
	/*
	bool s1 = (( flood_counter_rec[node_index][destination_index][port_id] < 10.0)&&(routing_algorithm==3));
	bool s2 = (( flood_counter_rec[node_index][destination_index][port_id] < 2*RL_iterations)&&(routing_algorithm==4));
	bool s3 = ((routing_algorithm != 3)&&(routing_algorithm != 4));
	cout<<"s1 is"<<s1<<"s2 is "<<s2<<"s3 is "<<s3<<endl;
	if(s1||s2||s3)
	{
	*/
		cout<<"Ethernet Packet out sent attempt at time "<<Simulator::Now().GetSeconds()<<"to node "<<destination_index<<endl;
		Simulator::Schedule(Seconds(0),&SimpleUdpApplication::DownlinkSendPacket,udp_app,packet1,dest_ip,destination_index);
		ueDLBusy[destination_index] = true;
	//}
	/*
	if(routing_algorithm==3)
	{
		flood_counter_rec[node_index][destination_index][port_id] = flood_counter_rec[node_index][destination_index][port_id] + 1;
	}
	if (routing_algorithm == 4)
	{
	  	bool signature_check = check_signature();
	  	if (signature_check == true)
	  	{
	  		flood_counter_rec[node_index][destination_index][port_id] = flood_counter_rec[node_index][destination_index][port_id] + 1;
	  	}
	
	}
	*/

}


void Trysend_LTE_LLDP_packetout_downlink_secondtime_alone(uint32_t node_index, uint32_t destination_index, uint32_t port_id, Ptr <Packet> packet1)
{
	Ptr <Node> destination_node = Vehicle_Nodes.Get(destination_index);
	Ptr <Node> node_source = controller_Node.Get(0);
	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(destination_index+2));

  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	cout<<dest_ip<<endl;
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	//uint32_t nid = uint32_t(destination_node->GetId());
	//cout<<"node id is "<<nid<<"dest ip "<<dest_ip<<"custom value is"<<(delta_at_controller_inst+3)->delta_fi_inst[4].delta_values[5]<<endl;
	/*
	bool s1 = (( flood_counter_rec[node_index][destination_index][port_id] < 10.0)&&(routing_algorithm==3));
	bool s2 = (( flood_counter_rec[node_index][destination_index][port_id] < 2*RL_iterations)&&(routing_algorithm==4));
	bool s3 = ((routing_algorithm != 3)&&(routing_algorithm != 4));
	cout<<"s1 is"<<s1<<"s2 is "<<s2<<"s3 is "<<s3<<endl;
	if(s1||s2||s3)
	{
	*/
		cout<<"LTE Second time Packet out sent attempt at time "<<Simulator::Now().GetSeconds()<<"to node "<<destination_index<<endl;
		Simulator::Schedule(Seconds(0),&SimpleUdpApplication::DownlinkSendPacket,udp_app,packet1,dest_ip,destination_index);
		ueDLBusy[destination_index] = true;
	//}
	/*
	if(routing_algorithm==3)
	{
		flood_counter_rec[node_index][destination_index][port_id] = flood_counter_rec[node_index][destination_index][port_id] + 1;
	}
	if (routing_algorithm == 4)
	{
	  	bool signature_check = check_signature();
	  	if (signature_check == true)
	  	{
	  		flood_counter_rec[node_index][destination_index][port_id] = flood_counter_rec[node_index][destination_index][port_id] + 1;
	  	}
	
	}
	*/

}

void Trysend_LTE_LLDP_packetout_downlink_alone(uint32_t node_index, uint32_t destination_index, uint32_t port_id, Ptr <Packet> packet1)
{
	Ptr <Node> destination_node = Vehicle_Nodes.Get(destination_index);
	Ptr <Node> node_source = controller_Node.Get(0);
	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(destination_index+2));

  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	cout<<dest_ip<<endl;
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	//uint32_t nid = uint32_t(destination_node->GetId());
	//cout<<"node id is "<<nid<<"dest ip "<<dest_ip<<"custom value is"<<(delta_at_controller_inst+3)->delta_fi_inst[4].delta_values[5]<<endl;
	/*
	bool s1 = (( flood_counter_rec[node_index][destination_index][port_id] < 10.0)&&(routing_algorithm==3));
	bool s2 = (( flood_counter_rec[node_index][destination_index][port_id] < 2*RL_iterations)&&(routing_algorithm==4));
	bool s3 = ((routing_algorithm != 3)&&(routing_algorithm != 4));
	cout<<"s1 is"<<s1<<"s2 is "<<s2<<"s3 is "<<s3<<endl;
	if(s1||s2||s3)
	{
	*/
		cout<<"LTE Packet out sent attempt at time "<<Simulator::Now().GetSeconds()<<"to node "<<destination_index<<endl;
		Simulator::Schedule(Seconds(0),&SimpleUdpApplication::DownlinkSendPacket,udp_app,packet1,dest_ip,destination_index);
		ueDLBusy[destination_index] = true;
	//}
	/*
	if(routing_algorithm==3)
	{
		flood_counter_rec[node_index][destination_index][port_id] = flood_counter_rec[node_index][destination_index][port_id] + 1;
	}
	if (routing_algorithm == 4)
	{
	  	bool signature_check = check_signature();
	  	if (signature_check == true)
	  	{
	  		flood_counter_rec[node_index][destination_index][port_id] = flood_counter_rec[node_index][destination_index][port_id] + 1;
	  	}
	
	}
	*/

}


void send_Ethernet_LLDP_packetin_uplink_alone(uint32_t node_index, uint32_t destination_index, uint32_t port_id, Ptr <Packet> packet1)
{
	Ptr <Node> node_source = RSU_Nodes.Get(destination_index);
	Ptr <Node> destination_node = management_Node.Get(0);
	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(destination_index));

  	Ptr <Ipv4> ipv4;  	
  	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	cout<<dest_ip<<endl;
	Ptr <Node> nu = DynamicCast <Node> (node_source);
	//uint32_t nid = uint32_t(destination_node->GetId());
	//cout<<"node id is "<<nid<<"dest ip "<<dest_ip<<"custom value is"<<(delta_at_controller_inst+3)->delta_fi_inst[4].delta_values[5]<<endl;
	bool s1 = (( flood_counter_rec[node_index][destination_index][port_id] < 6.0)&&(routing_algorithm==3));
	bool s2 = (( flood_counter_rec[node_index][destination_index][port_id] < 2*RL_iterations)&&(routing_algorithm==4));
	bool s3 = ((routing_algorithm != 3)&&(routing_algorithm != 4));
	cout<<"s1 is"<<s1<<"s2 is "<<s2<<"s3 is "<<s3<<endl;
	if(s1||s2||s3)
	{
		cout<<"Packet in sent attempt at time "<<Simulator::Now().GetSeconds()<<"from node "<<destination_index<<endl;
		Simulator::Schedule(Seconds(0),&SimpleUdpApplication::UplinkSendPacket,udp_app,packet1,dest_ip,destination_index);
		ueBusy[destination_index] = true;
	}
	if(routing_algorithm==3)
	{
		flood_counter_rec[node_index][destination_index][port_id] = flood_counter_rec[node_index][destination_index][port_id] + 1;
	}
	if (routing_algorithm == 4)
	{
	  	bool signature_check = check_signature();
	  	if (signature_check == true)
	  	{
	  		//flood_counter_rec[node_index][destination_index][port_id] = flood_counter_rec[node_index][destination_index][port_id] + 1;
	  	}
	
	}

}


void connect_to_uplink_RSU()
{
	    cout<<"number of apps "<<RSU_apps.GetN()<<endl;
		for(uint32_t node_index=0; node_index<total_size;node_index++)
		{
			// Guard: skip if RSU_Nodes is empty (e.g. routing_test=true with N_RSUs=0)
			if (node_index >= RSU_Nodes.GetN()) { continue; }
			Ptr <Node> node_source = RSU_Nodes.Get(node_index);
			Ptr <Node> destination_node = management_Node.Get(0);
			Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(node_index));

			Ptr <Ipv4> ipv4;  	
			ipv4 = destination_node->GetObject<Ipv4>();
			Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
			Ipv4Address dest_ip = iaddr.GetLocal();
			cout<<dest_ip<<endl;
			Ptr <Node> nu = DynamicCast <Node> (node_source);

			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::UplinkConnect,udp_app,dest_ip,7777);
			cout<<"CSMA Connected uplink for node "<<node_index<<" at "<<Simulator::Now().GetSeconds()<<endl;
		}

}

void connect_to_downlink_RSU()
{
	    cout<<"number of apps "<<RSU_apps.GetN()<<endl;
		for(uint32_t node_index=0; node_index<total_size;node_index++)
		{
			// Guard: skip if RSU_Nodes is empty (e.g. routing_test=true with N_RSUs=0)
			if (node_index >= RSU_Nodes.GetN()) { continue; }
			Ptr <Node> destination_node = RSU_Nodes.Get(node_index);
			Ptr <Node> node_source = management_Node.Get(0);
			Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(node_index));

			Ptr <Ipv4> ipv4;  	
			ipv4 = destination_node->GetObject<Ipv4>();
			Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
			Ipv4Address dest_ip = iaddr.GetLocal();
			cout<<dest_ip<<endl;
			Ptr <Node> nu = DynamicCast <Node> (node_source);

			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::DownlinkConnect,udp_app,dest_ip,7777);
			cout<<"CSMA Connected downlink for node "<<node_index<<" at "<<Simulator::Now().GetSeconds()<<endl;
		}

}


void connect_to_uplink()
{
	    cout<<"number of apps "<<apps.GetN()<<endl;
		for(uint32_t node_index=0; node_index<total_size;node_index++)
		{
			// Guard: skip if Vehicle_Nodes doesn't have this index (e.g. routing_test=true with N_Vehicles=3)
			if (node_index >= Vehicle_Nodes.GetN()) { cout<<"[UPLINK] Skipping node "<<node_index<<" (not in Vehicle_Nodes)"<<endl; continue; }
			Ptr <Node> node_source = Vehicle_Nodes.Get(node_index);
			Ptr <Node> destination_node = controller_Node.Get(0);
			Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(node_index+2));

			Ptr <Ipv4> ipv4;  	
			ipv4 = destination_node->GetObject<Ipv4>();
			Ipv4InterfaceAddress iaddr = ipv4->GetAddress(2,0);//1st IPv4 interface,0th address index
			Ipv4Address dest_ip = iaddr.GetLocal();
			cout<<dest_ip<<endl;
			Ptr <Node> nu = DynamicCast <Node> (node_source);

			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::UplinkConnect,udp_app,dest_ip,7777);
			cout<<"Connected uplink for node "<<node_index<<" at "<<Simulator::Now().GetSeconds()<<endl;
		}

}

void connect_to_downlink()
{
	    cout<<"number of apps "<<apps.GetN()<<endl;
		for(uint32_t node_index=0; node_index<total_size;node_index++)
		{
			// Guard: skip if Vehicle_Nodes doesn't have this index (e.g. routing_test=true)
			if (node_index >= Vehicle_Nodes.GetN()) { cout<<"[DOWNLINK] Skipping node "<<node_index<<" (not in Vehicle_Nodes)"<<endl; continue; }
			Ptr <Node> destination_node = Vehicle_Nodes.Get(node_index);
			Ptr <Node> node_source = controller_Node.Get(0);
			Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (apps.Get(node_index+2));

			Ptr <Ipv4> ipv4;  	
			ipv4 = destination_node->GetObject<Ipv4>();
			Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
			Ipv4Address dest_ip = iaddr.GetLocal();
			cout<<dest_ip<<endl;
			Ptr <Node> nu = DynamicCast <Node> (node_source);

			Simulator::Schedule(Seconds(0),&SimpleUdpApplication::DownlinkConnect,udp_app,dest_ip,7777);
			cout<<"Connected downlink for node "<<node_index<<" at "<<Simulator::Now().GetSeconds()<<endl;
		}

}

bool reported_location_HMAC_correct[total_size][total_size];
bool reported_location_intra_correct[total_size];
bool reported_location_inter_correct[total_size];
bool reported_location_behavioral_correct[total_size];
bool reported_location_correct[total_size];

string read_other_other_item_from_csv(std::string filename, std::string node_id, std::string other_node_id, std::string port_id, uint32_t col_index)
{
    fstream fin;
    cout<<"reading item from csv at"<<Now().GetSeconds()<<"for node id"<<node_id<<"and port id"<<port_id<<endl;
    fin.open(filename, ios::in);
    	
    if (!fin.is_open()) {
        throw runtime_error("Could not open file " + filename);
    }

    string line;

    while (getline(fin, line)) {
        stringstream ss(line);
        string item;
        vector<string> row_items;
        
        // Parse the entire line into a vector of column values
        while (getline(ss, item, ',')) {
            row_items.push_back(item);
        }

        // Ensure we have at least two columns to compare node_id and port_id
        if (row_items.size() >= 3) {
            if (row_items[0] == node_id && row_items[1] == other_node_id && row_items[2] == port_id) {
                if (col_index < row_items.size()) {
                    cout << "Found the item as " << row_items[col_index] << endl;
                    return row_items[col_index];
                } else {
                    cerr << "Warning: Column index out of range for node " << node_id << endl;
                    return "";
                }
            }
        }
    }

    cerr << "Warning: No matching row found for node_id " << node_id
         << ", other_node_id " << other_node_id << ", and port_id " << port_id << endl;

    return "";
}

string read_other_item_from_csv(std::string filename, std::string node_id, std::string port_id, uint32_t col_index)
{
    fstream fin;
    cout<<"reading item from csv at"<<Now().GetSeconds()<<"for node id"<<node_id<<"and port id"<<port_id<<endl;
    fin.open(filename, ios::in);
    	
    if (!fin.is_open()) {
        throw runtime_error("Could not open file " + filename);
    }

    string line;

    while (getline(fin, line)) {
        stringstream ss(line);
        string item;
        vector<string> row_items;
        
        // Parse the entire line into a vector of column values
        while (getline(ss, item, ',')) {
            row_items.push_back(item);
        }

        // Ensure we have at least two columns to compare node_id and port_id
        if (row_items.size() >= 2) {
            if (row_items[0] == node_id && row_items[1] == port_id) {
                if (col_index < row_items.size()) {
                    cout << "Found the item as " << row_items[col_index] << endl;
                    return row_items[col_index];
                } else {
                    cerr << "Warning: Column index out of range for node " << node_id << endl;
                    return "";
                }
            }
        }
    }

    cerr << "Warning: No matching row found for node_id " << node_id
         << ", and port_id " << port_id << endl;

    return "";
}

std::string BytesToHexString(const uint8_t* byteArray, size_t length) {
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteArray[i]);
    }
    return oss.str();
}

void LDA_security(std::string argument)
{
	//calculate entropy of the network and compare with threshold.
	std::string filename = NS3_ROOT "/analytics/data/LDA_security.py";
    	std::string command = "python3 ";
    	command += filename;
    	command += argument;
    	system(command.c_str());
}

void location_HMAC_verify(uint32_t i, uint32_t j)
{

	  uint32_t node_j = (data_at_manager_inst+i)->source_node[j];
	  uint32_t node_i = (data_at_manager_inst+i)->source_node[i];
	  Vector locationj = (data_at_manager_inst+i)->aggposition[j];
	  cout<<"location x is "<<static_cast<int>(locationj.x)<<"location y is "<<static_cast<int>(locationj.y)<<"for node source"<<node_j<<endl;
	  uint8_t * HMACj = (data_at_manager_inst+i)->HMAC[j];
	  std::string HMAC1_str = BytesToHexString(HMACj, 32);
	  cout<<"HMAC string is "<<HMAC1_str<<endl;


	 std::ostringstream oss3;
	 oss3 << " is_controller=true create_security_manager_con=true netsize=1 "
		<< " node_id=" << node_j << " port_id=" << 0  << " other_node_id=" << node_i << " "
		<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
		<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
		<< " sign_data=false verify_signature=false initiate_session1=false "
		<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
		<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
		<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
		<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
		<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
		<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
		<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
		<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false verify_HMAC=true"
		<< " message=" << static_cast<int>(locationj.x)+static_cast<int>(locationj.y) << " hashval=" << HMAC1_str << " msg_type=1";
	
	std::string command_str3 = oss3.str();
	Simulator::Schedule(Seconds(0), LDA_security, command_str3);
}
void location_HMAC_continue(uint32_t i, uint32_t j)
{
		
	    uint32_t node_j = (data_at_manager_inst+i)->source_node[j];
	    uint32_t node_i = (data_at_manager_inst+i)->source_node[i];
	    cout<<"node i is "<<node_i<<"node j is "<<node_j<<endl;
		std::string filename_HMAC1 = NS3_ROOT "/analytics/data/security_global_HMAC_verification_data.csv";
		cout<<"Location HMAC continue"<<endl;
		string HMAC1_verification_string = read_other_other_item_from_csv(filename_HMAC1, std::to_string(j), std::to_string(i), std::to_string(0), 3);
		cout<<"Location HMAC_verification string is "<<HMAC1_verification_string.substr(0,4)<<endl;
		
		if(HMAC1_verification_string.substr(0,4) == "True")
		{
			reported_location_HMAC_correct[node_i][node_j] = true;	
		}
}

double get_length(Vector posi_1, Vector posi_2)
{
	double valx = (posi_1.x - posi_2.x)*(posi_1.x - posi_2.x);
	double valy = (posi_1.y - posi_2.y)*(posi_1.y - posi_2.y);
	double result = sqrt(valx + valy);
	return result;	
}

bool is_majority(uint32_t x, uint32_t y)
{
	double half = 1.0*(y/2.0);
	if((1.0*x) > half)
	{
		return true;
	}
	else
	{
		return false;
	}
	
}

Vector location_approximate[total_size];
Vector last_true_location[total_size];
Vector partially_correct_reported_location[total_size];
double	last_true_location_timestamp[total_size];
bool using_location_approximate[total_size];

Vector calculate_location_approximate(uint32_t i, uint32_t size, const std::vector<Vector>& vecList, double time_elapsed)
{
	 if (vecList.empty()) {
        return last_true_location[i];  // return last true location if empty
    }

    double sumX = 0.0, sumY = 0.0, sumZ = 0.0;

    for (const auto& v : vecList) {
        sumX += v.x;
        sumY += v.y;
        sumZ += v.z;
    }

    double n = size;
    double distance = get_length(Vector(sumX / n, sumY / n, sumZ / n), last_true_location[i]);
    if(distance < 120.0*time_elapsed)
    {
		return Vector(sumX / n, sumY / n, sumZ / n);
	}
	else
	{
		return last_true_location[i];
	}
}

void interlocation_continue(uint32_t j)
{	
	uint32_t correct_count = 0;
	uint32_t total_count = 0;
	for(uint32_t i=0; i<total_size;i++)
	{
		
		if((reported_location_HMAC_correct[i][j] == true)&&(reported_location_HMAC_correct[i][i] == true))
		{
			double distance = get_length((data_at_manager_inst+i)->aggposition[j], (data_at_manager_inst+i)->aggposition[i]);
			if(distance < 300)
			{
				correct_count++;
			}
			total_count++;
		}
	}
	cout<<"This is interlocation verification for node "<<j<<"total count is "<<total_count<<"correct count is "<<correct_count<<endl;
    reported_location_inter_correct[j] = is_majority(correct_count, total_count);	
}

void set_last_true_location_and_timestamp(uint32_t i, Vector location)
{
	last_true_location[i] = location;
	last_true_location_timestamp[i]= Simulator::Now().GetSeconds();
	using_location_approximate[i] = false;
}


void setting_last_true_location_and_timestamp(uint32_t i)
{
	 Ptr <Node> node_copy = DynamicCast <Node> (Vehicle_Nodes.Get(i));
	 Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node_copy->GetObject<MobilityModel>());
	 Vector posi = mdl->GetPosition();
	 last_true_location[i] = posi;
	 last_true_location_timestamp[i]= Simulator::Now().GetSeconds();
	 using_location_approximate[i] = false;
}

						


void intralocation_continue(uint32_t i)
{
	uint32_t correct_count = 0;
	uint32_t total_count = 0;
	cout<<"This is intralocation verification for node "<<i<<endl;
	if(reported_location_inter_correct[i] == true)
	{
		cout<<"inter reported location for "<<i<<" is correct"<<endl;
		for(uint32_t j=0; j<total_size;j++)
		{
			
			if((reported_location_HMAC_correct[i][j] == true)&&(reported_location_HMAC_correct[i][i] == true))
			{
				double distance = get_length((data_at_manager_inst+i)->aggposition[j], (data_at_manager_inst+i)->aggposition[i]);
				if(distance < 300)
				{
					correct_count++;
					partially_correct_reported_location[i] = (data_at_manager_inst+i)->aggposition[i];
					cout<<"This i is intralocation checkeing for "<<i<<" to "<<j<<"partially correct location is "<<partially_correct_reported_location[i]<<endl;
				}
				total_count++;
			}
		}
		cout<<"This is intralocation verification for node "<<i<<"total count is "<<total_count<<"correct count is "<<correct_count<<endl;
		reported_location_intra_correct[i] = is_majority(correct_count, total_count);	
	}
}




void behavioral_continue(uint32_t i)
{
	if(reported_location_intra_correct[i] == true)
	{
		cout<<"Intra reported location is also for "<<i<<" is correct"<<endl;
	    double time_elapsed =  Simulator::Now().GetSeconds() - last_true_location_timestamp[i];
	    cout<<"Time elapsed for "<<i<<" is "<<time_elapsed<<endl;
	    double max_difference = time_elapsed*120;
	    cout<<"Max difference for "<<i<<" is "<<max_difference<<endl;
	    cout<<"Partially correct reported location is "<<i<<" is "<<partially_correct_reported_location[i]<<endl;
	    cout<<"Last true location for "<<i<<" is "<<last_true_location[i]<<endl;
		double distance = get_length(partially_correct_reported_location[i], last_true_location[i]);
		cout<<"Distance difference for "<<i<<" is "<<distance<<endl;
		if(distance < max_difference)
		{
			cout<<"Location for "<<i<<" is correct and verified and location is "<<partially_correct_reported_location[i]<<endl;
			set_last_true_location_and_timestamp(i, partially_correct_reported_location[i]);
			using_location_approximate[i] = false;
		}			
		else
		{
			
			uint32_t total_count = 0;
			std::vector<Vector> vectorList;
			for(uint32_t j=0; j<total_size;j++)
			{
				if((reported_location_HMAC_correct[i][j] == true))
				{
					vectorList.push_back((data_at_manager_inst+i)->aggposition[j]);
					total_count++;
				}
			}
			location_approximate[i] = calculate_location_approximate(i, total_count, vectorList, time_elapsed);
			cout<<"Location is incorrect. Approximating location for "<<i<<"as "<<location_approximate[i]<<endl;
			using_location_approximate[i] = true;
		}
	}
	else
	{
		
	}
}

void verify_location()
{
	for(uint32_t i=0; i<total_size;i++)
	{
		for(uint32_t j=0; j<total_size;j++)
		{
	  		if(routing_algorithm == 4)
	  		{
				uint32_t source_node_id = (data_at_manager_inst+i)->source_node[j];
				if((source_node_id >=0) && (source_node_id<total_size))
				{
					Simulator::Schedule(Seconds(0.0+0.00001*(i+(j*total_size))), location_HMAC_verify, i, j);
					Simulator::Schedule(Seconds(0.00050+0.00001*(i+(j*total_size))), location_HMAC_continue, i, j);
					Simulator::Schedule(Seconds(0.00150+0.00001*(total_size+(total_size*total_size))), interlocation_continue, j);
				}
			}
		}
		Simulator::Schedule(Seconds(0.0020+0.00001*(total_size+(total_size*total_size))), intralocation_continue, i);
		Simulator::Schedule(Seconds(0.00250+0.00001*(total_size+(total_size*total_size))), behavioral_continue, i);
	}
}

uint8_t replay_buffer[total_size];
uint8_t replay_buffer_port[total_size];
uint8_t replay_buffer2[total_size];
uint8_t replay_buffer2_port[total_size];


void Checkstate_and_retransmit(uint32_t srcNodeId, uint32_t dstNodeId, uint32_t srcPortId, Ptr<Packet> pkt)
{
	if (uplink_state[dstNodeId] == false)
	{
		cout<<"Packet in sent attempt failed at time "<<Simulator::Now().GetSeconds()<<"from node "<<dstNodeId<<"so retransmitting "<<endl;
		Simulator::Schedule(Seconds(0.0000), send_Ethernet_LLDP_packetin_uplink_alone, srcNodeId, dstNodeId, srcPortId, pkt);
		Simulator::Schedule(Seconds(0.0010), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
	}
}

void TrySendUplink(uint32_t srcNodeId, uint32_t dstNodeId, uint32_t srcPortId, Ptr<Packet> pkt, uint32_t attempts)
{
	 
	srand(Simulator::Now().GetSeconds());
	double rand_time = 0.00001*(rand()%100);
	cout<<"This is try send uplink first time for destination node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
    /*
    if (vanishing_malicious_nodes[dstNodeId])
        return; // node vanished, stop trying
    */
    if (ueBusy[dstNodeId])
    {
        // Still busy → check again after 5 ms
        if((Simulator::Now().GetSeconds() - uplink_last[dstNodeId] > 0.0025+rand_time) && (Simulator::Now().GetSeconds() - last_downlink[dstNodeId] > 0.0025+rand_time))
        {
			ueBusy[dstNodeId] = false; 
		}
        Simulator::Schedule(Seconds(0.0025+rand_time), &TrySendUplink, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
        cout<<"Node "<<dstNodeId<<" is still busy for uplink"<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
        return; 
    }
    else
    {
		if((Simulator::Now().GetSeconds()-downlink_last)>(0.0005+rand_time))
		{
			if((Simulator::Now().GetSeconds() - uplink_last[dstNodeId]) > (0.050+rand_time))
			{
			// Free → apply your 0.5 s guard
				if ((attempts < 2)&&((Link_duplicates_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0))
				{
					cout<<"Initializing uplink and transmitting for destination node id"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					Simulator::Schedule(Seconds(0.0+rand_time), send_Ethernet_LLDP_packetin_uplink_alone, srcNodeId, dstNodeId, srcPortId, pkt);
					//Simulator::Schedule(Seconds(0.0+rand_time), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
					attempts++;
					Simulator::Schedule(Seconds(0.005+rand_time), &TrySendUplink, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
					uplink_last[dstNodeId] = Simulator::Now().GetSeconds();  
				}
				else
				{
					cout<<"Cancelling first time uplink retransmissions as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					return;
				}
					
			}
			else
			{
				if((Link_duplicates_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0)
				{
					if(attempts<2)
					{
						
						cout<<"Trying to send packet in uplink attempt "<<attempts<<"from destination node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
						Simulator::Schedule(Seconds(0.0+rand_time), send_Ethernet_LLDP_packetin_uplink_alone, srcNodeId, dstNodeId, srcPortId, pkt);
						//Simulator::Schedule(Seconds(0.0+rand_time), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
						attempts++;
						Simulator::Schedule(Seconds(0.005+rand_time), &TrySendUplink, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
						uplink_last[dstNodeId] = Simulator::Now().GetSeconds();  
						
					}
				}
				else
				{
					cout<<"Cancelling first time uplink retransmissions as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					return;
				}
			}
			  
		}
		else
		{
			if ((Link_duplicates_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0)
			{
				Simulator::Schedule(Seconds(0.0005+rand_time), &TrySendUplink, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
				cout<<"Downlink is busy. Delaying uplink for destination Node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
			}
			else
			{
				cout<<"Cancelling first time uplink retransmissions as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
				return;
			}
				
		} 
    }
}


void TrySendUplinkSecondTime(uint32_t srcNodeId, uint32_t dstNodeId, uint32_t srcPortId, Ptr<Packet> pkt, uint32_t attempts)
{
	 
	srand(Simulator::Now().GetSeconds());
	double rand_time = 0.00001*(rand()%100);
	cout<<"This is try send uplink second time for destination node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
    /*
    if (vanishing_malicious_nodes[dstNodeId])
        return; // node vanished, stop trying
    */
    if (ueBusy[dstNodeId])
    {
        // Still busy → check again after 5 ms
        if((Simulator::Now().GetSeconds() - uplink_last[dstNodeId] > 0.0025+rand_time) && (Simulator::Now().GetSeconds() - last_downlink[dstNodeId] > 0.0025+rand_time))
        {
			ueBusy[dstNodeId] = false; 
		}
        Simulator::Schedule(Seconds(0.0025+rand_time), &TrySendUplinkSecondTime, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
        cout<<"Node "<<dstNodeId<<" is still busy for uplink second time"<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
        return; 
    }
    else
    {
		if((Simulator::Now().GetSeconds()-downlink_last)>(0.0005+rand_time))
		{
			// Free → apply your 0.5 s guard
			if ((Simulator::Now().GetSeconds() - uplink_last[dstNodeId]) > (0.050+rand_time))
			{
				if((attempts<2)&&((Link_duplicates_SecondTime_uplink_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0))
				{
					cout<<"Initializing uplink and transmitting for destination node id"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					Simulator::Schedule(Seconds(0.0+rand_time), send_Ethernet_LLDP_packetin_uplink_alone, srcNodeId, dstNodeId, srcPortId, pkt);
					//Simulator::Schedule(Seconds(0.0+rand_time), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
					attempts++;
					Simulator::Schedule(Seconds(0.005+rand_time), &TrySendUplinkSecondTime, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
					uplink_last[dstNodeId] = Simulator::Now().GetSeconds();  
				}
				else
				{
					cout<<"Cancelling second time uplink retransmissions as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					return;
				}
			}
			else
			{
				if((Link_duplicates_SecondTime_uplink_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0)
				{
					if(attempts<2)
					{
						
						cout<<"Trying to send packet in uplink attempt "<<attempts<<"from destination node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
						Simulator::Schedule(Seconds(0.0+rand_time), send_Ethernet_LLDP_packetin_uplink_alone, srcNodeId, dstNodeId, srcPortId, pkt);
						//Simulator::Schedule(Seconds(0.0+rand_time), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
						attempts++;
						Simulator::Schedule(Seconds(0.005+rand_time), &TrySendUplinkSecondTime, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
						uplink_last[dstNodeId] = Simulator::Now().GetSeconds();  
						
					}
				}
				else
				{
					cout<<"Cancelling second time uplink retransmissions as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					return;
				}
			}
		}	  
		else
		{
			if((Link_duplicates_SecondTime_uplink_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0)
			{
				Simulator::Schedule(Seconds(0.0005+rand_time), &TrySendUplinkSecondTime, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
				cout<<"Downlink is busy. Delaying uplink for destination Node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
			}
			else
			{
					cout<<"Cancelling second time uplink retransmissions as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					return;
			}
				
		} 
    }
}


void Checkstate_and_retransmit_downlink(uint32_t srcNodeId, uint32_t dstNodeId, uint32_t srcPortId, Ptr<Packet> pkt)
{
	if (downlink_state[dstNodeId] == false)
	{
		cout<<"Packet in sent attempt failed at time "<<Simulator::Now().GetSeconds()<<"from node "<<dstNodeId<<"so retransmitting "<<endl;
		Simulator::Schedule(Seconds(0.0000), send_Ethernet_LLDP_packetin_uplink_alone, srcNodeId, dstNodeId, srcPortId, pkt);
		Simulator::Schedule(Seconds(0.0010), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
	}
}

void TrySendDownlink(uint32_t srcNodeId, uint32_t dstNodeId, uint32_t srcPortId, Ptr<Packet> pkt, uint32_t attempts)
{
	 
	srand(Simulator::Now().GetSeconds());
	double rand_time = 0.00001*(rand()%100);
	cout<<"This is try send downlink first time for destination node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
    /*
    if (vanishing_malicious_nodes[dstNodeId])
        return; // node vanished, stop trying
    */
    if (ueDLBusy[dstNodeId])
    {
        // Still busy → check again after 5 ms
        if((Simulator::Now().GetSeconds() - downlink_last > 0.0025+rand_time) && (Simulator::Now().GetSeconds() - uplink_last[dstNodeId] > 0.0025+rand_time))
        {
			ueDLBusy[dstNodeId] = false; 
		}
        Simulator::Schedule(Seconds(0.0025+rand_time), &TrySendDownlink, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
        cout<<"Node "<<dstNodeId<<" is still busy "<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
        return; 
    }
    else
    {
		if((Simulator::Now().GetSeconds()-uplink_last[dstNodeId])>(0.0005+rand_time))
		{
			if((Simulator::Now().GetSeconds() - last_downlink[dstNodeId]) > (0.050+rand_time))
			{
				// Free → apply your 0.5 s guard
				if ((attempts < 2)&&((Link_duplicates_downlink_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0))
				{
					cout<<"Initializing uplink and transmitting for destination node id"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					Simulator::Schedule(Seconds(0.0+rand_time), Trysend_LTE_LLDP_packetout_downlink_alone, srcNodeId, dstNodeId, srcPortId, pkt);
					attempts++;
					//Simulator::Schedule(Seconds(0.0+rand_time), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
					Simulator::Schedule(Seconds(0.005+rand_time), &TrySendDownlink, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
					last_downlink[dstNodeId] = Simulator::Now().GetSeconds();  
				}
				else
				{
					cout<<"Cancelling retransmissions downlink first time as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					return;
				}
				
			}
			else
			{
				if((Link_duplicates_downlink_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0)
				{
					if(attempts<2)
					{
						
						cout<<"Trying to send packet in donwlink attempt "<<attempts<<"from destination node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
						Simulator::Schedule(Seconds(0.0+rand_time), Trysend_LTE_LLDP_packetout_downlink_alone, srcNodeId, dstNodeId, srcPortId, pkt);
						//Simulator::Schedule(Seconds(0.0+rand_time), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
						attempts++;
						Simulator::Schedule(Seconds(0.005+rand_time), &TrySendDownlink, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
						last_downlink[dstNodeId] = Simulator::Now().GetSeconds();  
						
					}
				}
				else
				{
					cout<<"Cancelling retransmissions downlink first time as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					return;
				}
			}
			  
		}
		else
		{
			if ((Link_duplicates_downlink_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0)
			{
				Simulator::Schedule(Seconds(0.0005+rand_time), &TrySendDownlink, srcNodeId, dstNodeId, srcPortId, pkt, attempts);
				cout<<"Uplink is busy. Delaying uplink for destination Node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
			}
			else
			{
				cout<<"Cancelling retransmissions downlink first time as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
				return;
			}
			
		} 
    }
}




void TrySendDownlinkSecondTime(uint32_t srcNodeId, uint32_t dstNodeId, uint32_t srcPortId, Ptr<Packet> pkt, uint32_t attempts, double t)
{
	 
	srand(Simulator::Now().GetSeconds());
	double rand_time = 0.00001*(rand()%100);
	cout<<"This is try send downlink second time for destination node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<"which was initiated at"<<t<<endl;
    /*
    if (vanishing_malicious_nodes[dstNodeId])
        return; // node vanished, stop trying
    */
    if (ueDLBusy[dstNodeId])
    {
        // Still busy → check again after 5 ms
        if((Simulator::Now().GetSeconds() - downlink_last > 0.0025+rand_time) && (Simulator::Now().GetSeconds() - uplink_last[dstNodeId] > 0.0025+rand_time))
        {
			ueDLBusy[dstNodeId] = false; 
		}
        Simulator::Schedule(Seconds(0.0025+rand_time), &TrySendDownlinkSecondTime, srcNodeId, dstNodeId, srcPortId, pkt, attempts, t);
        cout<<"Node "<<dstNodeId<<" is still busy for downlink second time"<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
        return; 
    }
    else
    {
		if((Simulator::Now().GetSeconds()-uplink_last[dstNodeId])>(0.0005+rand_time))
		{
			if((Simulator::Now().GetSeconds() - last_downlink[dstNodeId]) > (0.050+rand_time))
			{
				// Free → apply your 0.5 s guard
				if ((attempts<2)&&((Link_duplicates_SecondTime_downlink_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0))
				{
					cout<<"Initializing downlink and transmitting for destination node id"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					Simulator::Schedule(Seconds(0.0+rand_time), Trysend_LTE_LLDP_packetout_downlink_secondtime_alone, srcNodeId, dstNodeId, srcPortId, pkt);
					attempts++;
					//Simulator::Schedule(Seconds(0.0+rand_time), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
					Simulator::Schedule(Seconds(0.075+rand_time), &TrySendDownlinkSecondTime, srcNodeId, dstNodeId, srcPortId, pkt, attempts, t);
					last_downlink[dstNodeId] = Simulator::Now().GetSeconds();  
				}
				else
				{
					cout<<"Cancelling retransmissions downlink second time as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					return;
				}
					
			}
			else
			{
				if((Link_duplicates_SecondTime_downlink_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0)
				{
					if(attempts<2)
					{
						
						cout<<"Trying to send packet in donwlink attempt "<<attempts<<"from destination node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
						Simulator::Schedule(Seconds(0.0+rand_time), Trysend_LTE_LLDP_packetout_downlink_secondtime_alone, srcNodeId, dstNodeId, srcPortId, pkt);
						//Simulator::Schedule(Seconds(0.0+rand_time), Checkstate_and_retransmit, srcNodeId, dstNodeId, srcPortId, pkt);
						attempts++;
						Simulator::Schedule(Seconds(0.075+rand_time), &TrySendDownlinkSecondTime, srcNodeId, dstNodeId, srcPortId, pkt, attempts, t);
						last_downlink[dstNodeId] = Simulator::Now().GetSeconds();  
						
					}
				}
				else
				{
					cout<<"Cancelling retransmissions downlink second time as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
					return;
				}
			}
			  
		}
		else
		{
			if ((Link_duplicates_SecondTime_downlink_at_controller_inst+srcPortId)->Link_f_inst[srcPortId].Link_fi_inst[srcNodeId].Link_values[dstNodeId] == 0.0)
			{
				Simulator::Schedule(Seconds(0.005+rand_time), &TrySendDownlinkSecondTime, srcNodeId, dstNodeId, srcPortId, pkt, attempts, t);
				cout<<"Uplink is busy. Delaying uplink for destination Node "<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
			}
			else
			{
				cout<<"Cancelling retransmissions downlink second time as packet transmitted for destination"<<dstNodeId<<" source node "<<srcNodeId<<"port "<<srcPortId<<" at timestamp "<<Simulator::Now().GetSeconds()<<endl;
				return;
			}
			
		} 
    }
}

void Checkcounterandflood(uint32_t current_hop_id, uint32_t next_hop_id, uint32_t port_id, Ptr <Packet> packet_i, bool sender)
{
	//cout<<"transmiiting a a packet at "<<Now().GetMilliSeconds()<<endl;
	Ptr <Node> source_node = dsrc_Nodes.Get(current_hop_id);
	uint32_t nid = source_node->GetId();
	uint32_t source = nid -2;
	cout<<source<<endl;
	cout<<"next hop is "<< next_hop_id <<endl;
	Ptr <NetDevice> source_nd;
	Ptr <NetDevice> destination_nd;
	if(port_id == 0)
	{
		source_nd = wifidevices.Get(current_hop_id);
		destination_nd = wifidevices.Get(next_hop_id);
	}
	else
	{
		source_nd = wifidevices_172.Get(current_hop_id);
		destination_nd = wifidevices_172.Get(next_hop_id);
	}
	//Ptr <NetDevice> destination_nd = wifidevices.Get(13);
	Address addr = destination_nd->GetAddress();
	Mac48Address dest_address = Mac48Address::ConvertFrom(addr);
	cout <<endl<<"MAC address of next hop node "<<next_hop_id<<" is "<<dest_address<<endl;
  	uint16_t protocolwave = 0x88dc;//
	Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (source_nd);
	Ptr <Node> ni = DynamicCast <Node> (source_node);
	//uint32_t nid = uint32_t(ni->GetId());
	//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	Time ti = Seconds(Simulator::Now().GetSeconds());
	WifiMacHeader header;
	packet_i->RemoveHeader(header);
	header.SetAddr1(dest_address);
	packet_i->AddHeader(header);
	//dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
	srand(Simulator::Now().GetSeconds()+current_hop_id);
	uint32_t k = rand()%2;
	cout<<"k is "<<k<<endl;
	bool s2 = ((flood_counter_sen[current_hop_id][next_hop_id][port_id] < RL_iterations))&&(sender == true);
	if(s2)
	{
		Simulator::Schedule (Seconds(0.000) , &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);
	}
	
	bool s3 = ((flood_counter_rec[current_hop_id][next_hop_id][port_id] < RL_iterations))&&(sender == false);
	if(s3)
	{
		Simulator::Schedule (Seconds(0.000) , &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);
	}
}


void LLDP_dsrc_data_unicast(uint32_t current_hop_id, uint32_t next_hop_id, uint32_t port_id, Ptr <Packet> packet_i)
{
	//cout<<"transmiiting a a packet at "<<Now().GetMilliSeconds()<<endl;
	Ptr <Node> source_node = dsrc_Nodes.Get(current_hop_id);
	uint32_t nid = source_node->GetId();
	uint32_t source = nid -2;
	cout<<source<<endl;
	cout<<"next hop is "<< next_hop_id <<endl;
	Ptr <NetDevice> source_nd;
	Ptr <NetDevice> destination_nd;
	if(port_id == 0)
	{
		source_nd = wifidevices.Get(current_hop_id);
		destination_nd = wifidevices.Get(next_hop_id);
	}
	else
	{
		source_nd = wifidevices_172.Get(current_hop_id);
		destination_nd = wifidevices_172.Get(next_hop_id);
	}
	//Ptr <NetDevice> destination_nd = wifidevices.Get(13);
	Address addr = destination_nd->GetAddress();
	Mac48Address dest_address = Mac48Address::ConvertFrom(addr);
	cout <<endl<<"MAC address of next hop node "<<next_hop_id<<" is "<<dest_address<<endl;
  	uint16_t protocolwave = 0x88dc;//
	Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (source_nd);
	Ptr <Node> ni = DynamicCast <Node> (source_node);
	//uint32_t nid = uint32_t(ni->GetId());
	//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	Time ti = Seconds(Simulator::Now().GetSeconds());
	WifiMacHeader header;
	packet_i->RemoveHeader(header);
	header.SetAddr1(dest_address);
	packet_i->AddHeader(header);
	//dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
	srand(Simulator::Now().GetSeconds()+current_hop_id);
	uint32_t k = rand()%2;
	bool attacking_state2 = GetBooleanWithProbability(attack_percentage, current_hop_id);
	cout<<"Vanishing attack state is "<<attacking_state2<<"not attacking state is "<<!attacking_state2<<endl;
	cout<<"k is "<<k<<endl;
	
	bool s1 = (( flood_counter_sen[current_hop_id][next_hop_id][port_id] < 1.0)&&(routing_algorithm==3));
	bool s2 = (( flood_counter_sen[current_hop_id][next_hop_id][port_id] < RL_iterations)&&(routing_algorithm==4));
	bool s3 = ((routing_algorithm != 3)&&(routing_algorithm != 4));
	if((!vanishing_malicious_nodes[current_hop_id])||(!attacking_state2))
	{
			if(s1 || s2 || s3)
			{
				Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);
			}
	}
	
	Ptr<Packet> packet_original = packet_i->Copy();
	
	if(vanishing_malicious_nodes[current_hop_id])
	{
		if(attacking_state2)
		{
			CustomLLDP_DP_UnicastTag tag;
			packet_i->PeekPacketTag(tag);
			srand(Simulator::Now().GetSeconds()+double(current_hop_id));
			uint8_t nid = rand()%total_size;
			uint8_t pid = rand()%2;
			srand(Simulator::Now().GetSeconds()+double(next_hop_id));
			uint8_t des_nid = rand()%total_size;
			tag.Setsrcnodeid(&nid);
			tag.Setsrcportid(&pid);
			tag.Setdesnodeid(&des_nid);
			packet_i->RemovePacketTag(tag);
			// Add modified tag back
			packet_i->AddPacketTag(tag);
			if(s1 || s2 || s3)
			{
				Simulator::Schedule (Seconds(0.011) , &WifiNetDevice::Send, wdi, packet_i, dest_address, protocolwave);
			}
		}
	}
	
	Ptr<Packet> packet_copy[7];
	if((flooding_malicious_nodes[current_hop_id]) && (!blocked_port_state[current_hop_id][next_hop_id][port_id]))
	{
		srand(Simulator::Now().GetSeconds()+double(current_hop_id));
		uint32_t flood_count = 5 + rand()%3;
		if(attack_number == 6)
		{
			flood_count = 2;
		}
		uint32_t rand_value = rand()%1000;
		for(uint32_t i=0;i<flood_count;i++)
		{
			packet_copy[i] = packet_original->Copy();
			if(s1 || s2 || s3)
			{
				cout<<endl;
				cout<<"Flooding packets by the node "<<current_hop_id<<" flood packet id "<<i<<endl;
				if(routing_algorithm != 4)
				{
					CustomLLDP_DP_UnicastTag tag;
					packet_copy[i]->PeekPacketTag(tag);
					cout<<"source node id"<<uint32_t(*tag.Getsrcnodeid())<<endl;
					cout<<"port id"<<uint32_t(*tag.Getsrcportid())<<endl;
					cout<<"destination node id"<<uint32_t(*tag.Getdesnodeid())<<endl;
					Simulator::Schedule (Seconds(0.010*i+0.00001*rand_value) , &WifiNetDevice::Send, wdi, packet_copy[i], dest_address, protocolwave);
				}
				else
				{
					Simulator::Schedule (Seconds(0.010*i+0.00001*rand_value) , Checkcounterandflood, current_hop_id, next_hop_id, port_id, packet_copy[i], true);
				}
			}
		}
	}
	
	
	
	if(fabrication_malicious_nodes[current_hop_id])
	{
		uint8_t stage[1];
		uint8_t * HMAC_key;
		uint8_t * DS_public_key1;
		uint8_t * DS_public_key2;
		uint8_t * DS_public_key3;
		uint8_t * DS1;
		uint8_t * DS2;
		uint8_t * source_portid;
		uint8_t destination_nodeid;
		uint8_t destination_portid;
		uint8_t * HMAC1;
		stage[0] = 2;
		
		CustomLLDP_DP_UnicastTag tag_LLDP_DP;
		if(packet_original->PeekPacketTag(tag_LLDP_DP))
		{	
			
			HMAC_key = tag_LLDP_DP.GetHMAC();
			DS_public_key1 = tag_LLDP_DP.GetDS_public_key1();
			DS_public_key2 = tag_LLDP_DP.GetDS_public_key2();
			DS_public_key3 = tag_LLDP_DP.GetDS_public_key3();
			DS1 = tag_LLDP_DP.GetDS1();
			DS2 = tag_LLDP_DP.GetDS2();
			source_portid = tag_LLDP_DP.Getsrcportid();
			//source_nodeid = tagDP_LLDP.Getsrcnodeid();
			srand(Simulator::Now().GetSeconds()+double(current_hop_id));
			bool success_alg2 = GetBooleanWithProbability(80, current_hop_id);
			if((routing_algorithm != 2)||(!success_alg2))
			{
				destination_nodeid = uint8_t(rand()%total_size);
				uint32_t i = 0;
				uint32_t counter = 0;
				while ((destination_nodeid == uint8_t(next_hop_id)) || (destination_nodeid == uint8_t(current_hop_id)))
				{
					if(counter<20)
					{
						cout<<"Ineffective fabrication"<<endl;
						srand(Simulator::Now().GetSeconds()+double(i));
						destination_nodeid = uint8_t(rand() % total_size);
					}
					else
					{
							break;
					}
					counter++;
				}
			}
			else
			{
				destination_nodeid = uint8_t(rand() % total_size);
			}
			cout<<"Fabricating a packet between "<<current_hop_id<<" and "<<uint32_t(destination_nodeid)<<endl;
			
			tag_LLDP_DP.Setdesnodeid(&destination_nodeid);
			HMAC1 = tag_LLDP_DP.GetHMAC();
			
			CustomLLDP_uplink_UnicastTag tagLLDP_uplink;

			//uint32_t nid = uint32_t(ni->GetId());
			//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
			Time ti = Seconds(Simulator::Now().GetSeconds());
			Ptr <Packet> packet_new = Create<Packet> (100);
			tagLLDP_uplink.SetStage(stage);
			tagLLDP_uplink.SetHMAC_key(HMAC_key);
			tagLLDP_uplink.SetDS_public_key1 (DS_public_key1);
			tagLLDP_uplink.SetDS_public_key2 (DS_public_key2);
			tagLLDP_uplink.SetDS_public_key3 (DS_public_key3);
			tagLLDP_uplink.SetDS1 (DS1);
			tagLLDP_uplink.SetDS2 (DS2);
			uint8_t current = uint8_t(current_hop_id);
			tagLLDP_uplink.Setsrcnodeid (&current);
			tagLLDP_uplink.Setsrcportid (source_portid);
			if((routing_algorithm !=2)||(!success_alg2))
			{
				destination_portid = uint8_t(rand()%2);
			}
			else
			{
				destination_portid = uint8_t(*source_portid);
			}
			tagLLDP_uplink.Setdesportid (&destination_portid);
			tagLLDP_uplink.Setdesnodeid (&destination_nodeid);
			tagLLDP_uplink.SetHMAC1 (HMAC1);
			uint8_t * HMAC2 = HMAC_key;
			tagLLDP_uplink.SetHMAC2 (HMAC2);
			packet_new->AddPacketTag(tagLLDP_uplink);
			if(s1 || s2 || s3)
			{
				//Simulator::Schedule(Seconds(0.000), send_Ethernet_LLDP_packetin_uplink_alone, 4, 0, destination_portid, packet_i);
				if((routing_algorithm != 2)||(!success_alg2))
				{
					Simulator::Schedule(Seconds(0.010), TrySendUplink, current_hop_id, current_hop_id, port_id, packet_new, 1);
				}
			}
		}
	}
	
	if(routing_algorithm==3)
	{
		flood_counter_sen[current_hop_id][next_hop_id][port_id] = flood_counter_sen[current_hop_id][next_hop_id][port_id] + 1;
	}
	if (routing_algorithm == 4)
	{
	  	bool signature_check = check_signature();
	  	if (signature_check == true)
	  	{
	  		//flood_counter_sen[current_hop_id][next_hop_id][port_id] = flood_counter_sen[current_hop_id][next_hop_id][port_id] + 1;
	  	}
	
	}
	//cout<<"This is flow ID "<<flow_id<<"Transmitting packet ID "<<packet_ID<<" from "<<source<<" to next hop "<<next_hop_id<<"at time "<<Now().GetSeconds()<<endl;
	//uint32_t * pt = tag.GetNodeId();
	//cout<<"node id from tag is "<<*pt<<endl;	
	//Y[*pt - 2] = Y[*pt -2] + 1;
	//cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
	//cout<<"packet size is "<<arguments.p_size-28<<endl;
}


























bool Z_gurobi[total_size+2];
bool X_gurobi[total_size+2];

bool Z_nodes[total_size+2];
bool X_nodes[total_size+2];

uint32_t LLDP_received_count = 0;

string read_item_from_csv(std::string filename, std::string node_id, int col_index)
{
    fstream fin;
    cout<<"reading item from csv at"<<Now().GetSeconds()<<"for node id "<<node_id<<endl;
    fin.open(filename, ios::in);
    	
    if (!fin.is_open()) {
        throw runtime_error("Could not open file " + filename);
    }

    string line;

    while (getline(fin, line)) {
        stringstream ss(line);
        string item;
        int current_col = 0;
        string first_col_val;

        // Get the first column (column 0)
        if (getline(ss, first_col_val, ',')) {
            if (first_col_val == node_id) {
                // If column 0 matches node_id, parse the rest to find col_index
                if (col_index == 0) return first_col_val;

                while (getline(ss, item, ',')) {
                    current_col++;
                    if (current_col == col_index) {
                        cout << "Found the item as " << item << endl;
                        return item;
                    }
                }
                cerr << "Warning: Column index out of range for node " << node_id << endl;
                    return "";
            }
        }
    }

    cerr << "Warning: No matching row found for node_id " << node_id<< endl;

    return "";
}









void LDA_PQ_security(std::string argument)
{
	//calculate entropy of the network and compare with threshold.
	std::string filename = NS3_ROOT "/analytics/data/LDA_PQ_security.py";
    	std::string command = "python3 ";
    	command += filename;
    	command += argument;
    	system(command.c_str());
}

uint32_t duplicate_count[total_size][total_size];
uint32_t fabricated_count[total_size][total_size];
uint32_t replay_count[total_size][total_size];
uint32_t matched_LLDP[total_size][total_size];



void reset_LLDP_counters()
{
	for(uint32_t i=0;i<total_size;i++)
	{
		reported_location_intra_correct[i] = false;
		reported_location_inter_correct[i] = false;
		reported_location_behavioral_correct[i] = false;
		reported_location_correct[i] = false;
		for(uint32_t j=0;j<total_size;j++)
		{
			duplicate_count[i][j] = 0;
			fabricated_count[i][j] = 0;
			replay_count[i][j] = 0;
			matched_LLDP[i][j] = 0;	
			reported_location_HMAC_correct[i][j] = false;
		}
	}
}


void HexStringToBytes(const std::string& hex, uint8_t* byteArray, size_t maxLength) {
    size_t length = hex.length();

    // If the length is odd, append '0' to the hex string
    std::string updatedHex = hex;
    if (length % 2 != 0) {
        updatedHex += "0";  // Adding '0' at the end to make it even-length
        std::cout << "Hex string was odd, added '0': " << updatedHex << std::endl;
    }

    size_t byteCount = updatedHex.length() / 2;

    // Ensure the byte array can hold the required number of bytes
    if (byteCount > maxLength) {
        throw std::overflow_error("Hex string too large for destination array");
    }

    // Convert hex string to byte array
    for (size_t i = 0; i < byteCount; ++i) {
        std::string byteStr = updatedHex.substr(2 * i, 2);
        byteArray[i] = static_cast<uint8_t>(strtol(byteStr.c_str(), nullptr, 16));
    }
    cout<<"Converted hex string"<<endl;
}

// Convert uint8_t array to hex string



struct downlink_packet_decrypt
{
	uint32_t node_index; 
	uint32_t port_id; 
	uint32_t destination_index; 
	uint8_t stage;
	std::string encrypted_nodeID;
	std::string encrypted_portID;
	std::string encrypted_HMAC;
	std::string signature;

};



void send_dataplane_packet(struct downlink_rest_data dlrd)
{
	string FALCON1_string(2560, 'A');
	string HMAC_string(64, 'A');
	
	if(routing_algorithm == 4)
	{
	       
	       cout<<"Reading HMAC 1 at nodes"<<endl;
			std::string filename_HMAC = NS3_ROOT "/analytics/data/security_node1_HMAC_data.csv";
			HMAC_string = read_other_other_item_from_csv(filename_HMAC, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_raw_source_portid), std::to_string(dlrd.casted_destination_nodeid), 3);
			cout<<"HMAC 1 string is "<<HMAC_string<<endl;
			cout<<endl;
		   
		   cout<<"Reading Digital signature at nodes "<<endl;
		   std::string filename_sign_FALCON1 = NS3_ROOT "/analytics/data/security_node1_dig_sig_data.csv";
		   FALCON1_string = read_other_other_item_from_csv(filename_sign_FALCON1, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 3);
		   cout<<"Digital signature node1 string is "<<FALCON1_string<<endl;
	}
	
	uint8_t * HMAC1 = new uint8_t[64];
	HexStringToBytes(HMAC_string, HMAC1, 64);
	HexStringToBytes(FALCON1_string, dlrd.DS_public_key2, 2560);



	CustomLLDP_DP_UnicastTag tagLLDP_DSRC;
	//uint32_t nid = uint32_t(ni->GetId());
	//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	Time ti = Seconds(Simulator::Now().GetSeconds());
	Ptr <Packet> packet_i = Create<Packet> (100);
	tagLLDP_DSRC.SetHMAC(dlrd.HMAC);
	tagLLDP_DSRC.SetDS_public_key1 (dlrd.DS_public_key1);
	tagLLDP_DSRC.SetDS_public_key2 (dlrd.DS_public_key2);
	tagLLDP_DSRC.SetDS_public_key3 (dlrd.DS_public_key3);
	tagLLDP_DSRC.SetDS1 (dlrd.DS1);
	tagLLDP_DSRC.SetDS2 (dlrd.DS2);
	tagLLDP_DSRC.Setsrcnodeid (dlrd.raw_source_nodeid);
	tagLLDP_DSRC.Setsrcportid (dlrd.raw_source_portid);
	tagLLDP_DSRC.Setdesnodeid (dlrd.destination_nodeid);
	tagLLDP_DSRC.SetHMAC1 (HMAC1);
	packet_i->AddPacketTag(tagLLDP_DSRC);
	Simulator::Schedule (Seconds (0.0), LLDP_dsrc_data_unicast, dlrd.casted_raw_source_nodeid, dlrd.casted_destination_nodeid, dlrd.casted_raw_source_portid, packet_i);

	
}

void create_HMAC1_and_digital_signature(struct downlink_rest_data dlrd)
{
	
	cout<<"Creating HMAC1 at nodes"<<endl;
			  std::ostringstream oss4;
			   oss4 << " is_controller=true create_security_manager_con=true netsize=1 "
					<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
					<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
					<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
					<< " sign_data=false verify_signature=false initiate_session1=false "
					<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
					<< " decrypt_ECDH=false create_hmac_set1=true create_hmac_set2=false "
					<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
					<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
					<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
					<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
					<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
					<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
					<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid  << " ";
				
				std::string command_str4 = oss4.str();
				Simulator::Schedule(Seconds(0.00001), LDA_security, command_str4);
				
				cout<<"Creting digital signature 2 at nodes"<<endl;
			   std::ostringstream oss3;
			   oss3 << " is_controller=true create_security_manager_con=true netsize=1 "
					<< " sign_FALCON=true verify_FALCON=false generate_FALCON=false "
					<< " encrypt_ASCON=false decrypt_ASCON=false generate_ASCON_key=false "
					<< " node_id="<< dlrd.casted_raw_source_nodeid << " port_id="  << dlrd.casted_raw_source_portid << " other_node_id=" << dlrd.casted_destination_nodeid  << ""
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
					<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid << " msg_type=1";
			   
			   std::string command_str3 = oss3.str();
			   Simulator::Schedule(Seconds(0.00002), LDA_PQ_security, command_str3);
	
}

void set_packet_content_at_node2(struct downlink_rest_data dlrd)
{
			(Link_duplicates_SecondTime_downlink_at_controller_inst+dlrd.casted_raw_source_portid)->Link_f_inst[dlrd.casted_raw_source_portid].Link_fi_inst[dlrd.casted_raw_source_nodeid].Link_values[dlrd.casted_destination_nodeid] = 1.0;
		    
		    cout<<"packet delivery state for stage two for source"<<dlrd.casted_raw_source_nodeid<<" destination "<<dlrd.casted_destination_nodeid<<"port "<<dlrd.casted_raw_source_portid<<"was set as "<<(Link_duplicates_SecondTime_downlink_at_controller_inst+dlrd.casted_raw_source_portid)->Link_f_inst[dlrd.casted_raw_source_portid].Link_fi_inst[dlrd.casted_raw_source_nodeid].Link_values[dlrd.casted_destination_nodeid]<<endl;
		    
		    cout<<"This is stage 2"<<endl;
		    //HMAC2
			cout<<"Creating HMAC2 at the node"<<endl;
			std::ostringstream oss4;
		   oss4 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=false initiate_session1=false "
				<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
				<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=true "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
				<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid  << " ";
			
			std::string command_str4 = oss4.str();
			Simulator::Schedule(Seconds(0.00001), LDA_security, command_str4);
			
			
			
			//Encrypt using DH
			cout<<"Encrypt using AES at the node"<<endl;
			std::ostringstream oss5;
		   oss5 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=false initiate_session1=false "
				<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=true "
				<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
				<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid  << " ";
			
			std::string command_str5 = oss5.str();
			Simulator::Schedule(Seconds(0.00002), LDA_security, command_str5);
			
			
			
		   //Digital signature node 3
		   cout<<"Creating Digital signature 3 at the node"<<endl;
		   std::ostringstream oss3;
		   oss3 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " sign_FALCON=true verify_FALCON=false generate_FALCON=false "
				<< " encrypt_ASCON=false decrypt_ASCON=false generate_ASCON_key=false "
				<< " node_id="<< dlrd.casted_raw_source_nodeid << " port_id="  << dlrd.casted_raw_source_portid << " other_node_id=" << dlrd.casted_destination_nodeid  << ""
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
				<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid << " msg_type=2";
		    std::string command_str3 = oss3.str();
			Simulator::Schedule(Seconds(0.00003), LDA_PQ_security, command_str3);
}

void read_packet_content_at_node2(struct downlink_rest_data dlrd)
{
       //Create HMAC 2
	   string HMAC2_string;
	   string encrypted_string;
	   string FALCON2_string;
		
	   cout<<"Reading HMAC2 at second node"<<endl;
	   std::string filename_HMAC2 = NS3_ROOT "/analytics/data/security_node2_HMAC_data.csv";
	   HMAC2_string = read_other_other_item_from_csv(filename_HMAC2, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 3);
	   cout<<"HMAC 2 string is "<<HMAC2_string<<endl;
		
	   cout<<"Reading encrypted string at second node"<<endl;
	   std::string filename_DH = NS3_ROOT "/analytics/data/security_ECDH_data.csv";
	   encrypted_string = read_other_other_item_from_csv(filename_DH, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 3);
	   cout<<"ECDH_encrypted string is "<<encrypted_string<<endl;
	   
	   cout<<"Reading digital signature at second node"<<endl;
	   std::string filename_sign_FALCON2 = NS3_ROOT "/analytics/data/security_node2_dig_sig_data.csv";
	   FALCON2_string = read_other_other_item_from_csv(filename_sign_FALCON2, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 3);
	   cout<<"Digital signature node2 string is "<<FALCON2_string<<endl;
	   
	   uint8_t * HMAC2 = new uint8_t[64];
	   HexStringToBytes(HMAC2_string, HMAC2, 64);
	   HexStringToBytes(FALCON2_string, dlrd.DS_public_key3, 2560);
	   HexStringToBytes(encrypted_string, dlrd.DS1, 32);
	   cout<<"strings converted "<<endl;
	   
	   CustomLLDP_uplink_UnicastTag tagLLDP_uplink;
		//uint32_t nid = uint32_t(ni->GetId());
		//dsrc_packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
		Time ti = Seconds(Simulator::Now().GetSeconds());
		Ptr <Packet> packet_i = Create<Packet> (100);
		tagLLDP_uplink.SetHMAC_key(dlrd.HMAC_key);
		tagLLDP_uplink.SetStage(dlrd.stage);
		tagLLDP_uplink.SetDS_public_key1 (dlrd.DS_public_key1);
		tagLLDP_uplink.SetDS_public_key2 (dlrd.DS_public_key2);
		tagLLDP_uplink.SetDS_public_key3 (dlrd.DS_public_key3);
		tagLLDP_uplink.SetDS1 (dlrd.DS1);
		tagLLDP_uplink.SetDS2 (dlrd.DS2);
		tagLLDP_uplink.Setsrcnodeid (dlrd.source_nodeid);
		tagLLDP_uplink.Setsrcportid (dlrd.source_portid);
		tagLLDP_uplink.Setdesportid (dlrd.source_portid);
		tagLLDP_uplink.Setdesnodeid (dlrd.destination_nodeid);
		tagLLDP_uplink.SetHMAC1 (dlrd.HMAC1);
		//uint8_t * HMAC2 = HMAC_key;
		tagLLDP_uplink.SetHMAC2 (HMAC2);
		packet_i->AddPacketTag(tagLLDP_uplink);
		//if(!vanishing_malicious_nodes[*dlrd.destination_nodeid])
		//{
		srand(Simulator::Now().GetSeconds());
		double randval = 0.00001*(rand()%100);
		Simulator::Schedule(Seconds(randval), &TrySendUplinkSecondTime, dlrd.casted_raw_source_nodeid, dlrd.casted_destination_nodeid, dlrd.casted_raw_source_portid, packet_i, 0);
		//}
}


void proceed_downlink_rest(struct downlink_rest_data dlrd)
{
	    
	    auto dlrd_copy = new downlink_rest_data(dlrd); // copy construct on heap
	    string dec_node_id;
	    string dec_port_id;
	    std::string cnid;
	    std::string cpid;
	    string verification;
	    if(routing_algorithm == 4)
	    {
			std::string filename_source = NS3_ROOT "/analytics/data/security_ASCON_data1.csv";
			cout<<"Reading ASCON 1 data"<<endl;
			dec_node_id = read_other_item_from_csv(filename_source, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_raw_source_portid), 0);
			
			cout<<"Reading ASCON 2 data"<<endl;
			std::string filename_port = NS3_ROOT "/analytics/data/security_ASCON_data2.csv";
			dec_port_id = read_other_item_from_csv(filename_port, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_raw_source_portid), 1);
			
			std::string filename_HMACkey;
			string dec_key;
			if(*dlrd.stage == 1)
			{
				cout<<"Reading ASCON 3 data"<<endl;
				filename_HMACkey = NS3_ROOT "/analytics/data/security_ASCON_data3.csv";
				dec_key = read_other_item_from_csv(filename_HMACkey, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_raw_source_portid), 3);
			}
			
			if(*dlrd.stage == 2)
			{
				cout<<"Reading HMAC key"<<endl;
				filename_HMACkey = NS3_ROOT "/analytics/data/security_ASCON_data4.csv";
				dec_key = read_other_other_item_from_csv(filename_HMACkey, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 4);
			}
			
			cout<<"Reading digital signature"<<endl;
			std::string filename = NS3_ROOT "/analytics/data/security_con_dig_sig_data.csv";
			verification = read_other_other_item_from_csv(
    filename,
    std::to_string(dlrd.casted_raw_source_nodeid),      // node_id
    std::to_string(dlrd.casted_destination_nodeid),     // other_node_id
    std::to_string(dlrd.casted_raw_source_portid),      // port_id
    4
);

			dec_node_id = read_other_other_item_from_csv(
    filename,
    std::to_string(dlrd.casted_raw_source_nodeid),      // node_id
    std::to_string(dlrd.casted_destination_nodeid),     // other_node_id
    std::to_string(dlrd.casted_raw_source_portid),      // port_id
    0
);

dec_port_id = read_other_other_item_from_csv(
    filename,
    std::to_string(dlrd.casted_raw_source_nodeid),      // node_id
    std::to_string(dlrd.casted_destination_nodeid),     // other_node_id
    std::to_string(dlrd.casted_raw_source_portid),      // port_id
    1
);

			
			cout<<"decoded node id is "<<dec_node_id<<endl;
			if (dec_node_id.size() >= 3 && dec_node_id[0] == 'b' && dec_node_id[1] == '\'' && dec_node_id.back() == '\'') 
			{
				dec_node_id = dec_node_id.substr(2, dec_node_id.size() - 3); // Get the middle part
			}
			cout<<"decoded node id is "<<dec_node_id<<endl;
			cout<<"decoded port id is "<<dec_port_id<<endl;
			if (dec_port_id.size() >= 3 && dec_port_id[0] == 'b' && dec_port_id[1] == '\'' && dec_port_id.back() == '\'') 
			{
				dec_port_id = dec_port_id.substr(2, dec_port_id.size() - 3); // Get the middle part
			}
			cout<<"decoded port id is "<<dec_port_id<<endl;
			cout<<"Signature verification is "<<verification<<endl;
			
			cnid = std::to_string(dlrd.casted_raw_source_nodeid);
			cpid = std::to_string(dlrd.casted_raw_source_portid);
			cout<<"casted node id is "<<cnid<<endl;
			cout<<"casted port id is "<<cpid<<endl;
		}
		bool send = false;
		if(routing_algorithm == 4)
		{
			bool cond1 = false;
			bool cond2 = false;
			bool cond3 = (verification.find("True") != std::string::npos);
			
			// Safe parsing: check for empty strings and handle exceptions
			try {
				if (!dec_node_id.empty() && !cnid.empty()) {
					cond1 = std::stoi(dec_node_id) == std::stoi(cnid);
				}
			} catch (const std::invalid_argument& e) {
				cout << "Warning: Invalid node id format. dec_node_id='" << dec_node_id << "', cnid='" << cnid << "'" << endl;
			} catch (const std::out_of_range& e) {
				cout << "Warning: Node id out of range. dec_node_id='" << dec_node_id << "', cnid='" << cnid << "'" << endl;
			}
			
			try {
				if (!dec_port_id.empty() && !cpid.empty()) {
					cond2 = std::stoi(dec_port_id) == std::stoi(cpid);
				}
			} catch (const std::invalid_argument& e) {
				cout << "Warning: Invalid port id format. dec_port_id='" << dec_port_id << "', cpid='" << cpid << "'" << endl;
			} catch (const std::out_of_range& e) {
				cout << "Warning: Port id out of range. dec_port_id='" << dec_port_id << "', cpid='" << cpid << "'" << endl;
			}
			
			cout<<"cond1 is "<<cond1<<endl;
			cout<<"cond2 is "<<cond2<<endl;
			cout<<"cond3 is "<<cond3<<endl;
			if((cond1)&&(cond2)&&(cond3))
			{
				send = true;
			}
			
		}
		else
		{
			send = true;
		}
		cout<<"send state is "<<send<<endl;
		if((*dlrd.stage == 1)&&(send==true))//Send a packet in data plane
		{
		
			if(routing_algorithm == 4)
			{ 
			    Simulator::Schedule(Seconds(0.00025), create_HMAC1_and_digital_signature, *dlrd_copy);	
			}   
			
			Simulator::Schedule(Seconds(0.00050), send_dataplane_packet, *dlrd_copy);
	                			
		}
	
		else if(*dlrd.stage == 2)//Send packet in
		{
			if(routing_algorithm == 4)
			{
				Simulator::Schedule(Seconds(0.00025), set_packet_content_at_node2, *dlrd_copy);
			    Simulator::Schedule(Seconds(0.00050), read_packet_content_at_node2, *dlrd_copy);   
			}
		}
	
}


void verify_uplink_packet_first_time(struct downlink_rest_data dlrd)
{
	
		std::string HMAC_key_str = BytesToHexString(dlrd.HMAC_key, 81);
		cout<<"HMAC key is "<<HMAC_key_str<<endl;
	    std::string HMAC1_str = BytesToHexString(dlrd.HMAC1, 32);
	    cout<<"HMAC1 is "<<HMAC1_str<<endl;
	    std::string HMAC2_str = BytesToHexString(dlrd.HMAC2, 32);
	    cout<<"HMAC2 is "<<HMAC2_str<<endl;
	    std::string digital_sig_str1 = BytesToHexString(dlrd.DS_public_key1, 256);
	    cout<<"Digital signature 1 is"<<digital_sig_str1<<endl;
	    std::string digital_sig_str2 = BytesToHexString(dlrd.DS_public_key2, 1280);
	    cout<<"Digital signature 2 is"<<digital_sig_str2<<endl;
	    std::string digital_sig_str3 = BytesToHexString(dlrd.DS_public_key3, 1280);
	    cout<<"Digital signature 3 is"<<digital_sig_str3<<endl;
	    std::string DS1_str = BytesToHexString(dlrd.DS1, 16);
		
		cout<<"source node id is "<<dlrd.casted_raw_source_nodeid<<endl;
		cout<<"source port id is "<<dlrd.casted_raw_source_portid<<endl;
		cout<<"destination node id is "<<dlrd.casted_destination_nodeid<<endl;
		cout<<"destination port id is "<<dlrd.casted_raw_destination_portid<<endl;
		
	
		cout<<"state is "<<*dlrd.stage<<endl;
		cout<<"DS1 is "<<DS1_str<<endl;
		cout<<"DS2 is "<<dlrd.DS2<<endl;
		
		
		   //Signature 1 verification
		   cout<<"Signature 1 verification at the controller first time"<<endl;
		   std::ostringstream oss1;
		   oss1 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=true initiate_session1=false "
				<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
				<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
				<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid  << " signature=" << digital_sig_str1<< " ";
			
			std::string command_str1 = oss1.str();
			Simulator::Schedule(Seconds(0.00001), LDA_security, command_str1);

		   //HMAC1 verification
		   cout<<"HMAC1 verification at the controller first time"<<endl;
		   std::ostringstream oss3;
		   oss3 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=false initiate_session1=false "
				<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
				<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false verify_HMAC=true"
				<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid << " hashval=" << HMAC1_str << " msg_type=2";
			
			std::string command_str3 = oss3.str();
			Simulator::Schedule(Seconds(0.00002), LDA_security, command_str3);	
	
			
			//HMAC 2 verification
			cout<<"HMAC2 verification at the controller first time"<<endl;
			 std::ostringstream oss4;
			 oss4 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_destination_nodeid << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" <<dlrd.casted_raw_source_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=false initiate_session1=false "
				<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
				<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false verify_HMAC=true"
				<< " message=" << HMAC1_str << " hashval=" << HMAC2_str << " msg_type=1";
	
			std::string command_str4 = oss4.str();
			Simulator::Schedule(Seconds(0.00003), LDA_security, command_str4);
}




void send_uplink_data_first_time(struct downlink_rest_data dlrd)
{
	cout<<"Reading HMAC2 key encrypted at controller"<<endl;
	std::string filename_HMAC2key_enc = NS3_ROOT "/analytics/data/security_ASCON_data4.csv";
	string HMAC2_key_enc = read_other_other_item_from_csv(filename_HMAC2key_enc, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 3);
	cout<<"HMAC key encrypted size is "<<HMAC2_key_enc.size()<<endl;
	
	
	uint8_t * HMAC_key = new uint8_t[161];//161
	HexStringToBytes(HMAC2_key_enc, HMAC_key, 162);

	
	cout<<"HMAC2_key encrypted is "<<HMAC2_key_enc<<endl;			
	cout<<"Sending packet back to the node "<<endl;
	cout<<"source "<<dlrd.casted_raw_source_nodeid<<"destination "<<dlrd.casted_destination_nodeid<<"port "<< dlrd.casted_raw_source_portid<<endl;
	Ptr <Node> destination_node = Vehicle_Nodes.Get(dlrd.casted_destination_nodeid);
	Ptr <Ipv4> ipv4;  	
	ipv4 = destination_node->GetObject<Ipv4>();
	Ipv4InterfaceAddress iaddr = ipv4->GetAddress(1,0);//1st IPv4 interface,0th address index
	Ipv4Address dest_ip = iaddr.GetLocal();
	cout<<"IPV4 address is "<<dest_ip<<endl;
	CustomLLDPDownlinkUnicastTag tag;
	dlrd.stage[0] = 2;
	uint8_t srcnd = uint8_t(dlrd.casted_raw_source_nodeid);
	uint8_t srcport = uint8_t(dlrd.casted_raw_source_portid);
	uint8_t dest = uint8_t(dlrd.casted_destination_nodeid);
	
	
	Simulator::Schedule(Seconds(0.000), Store_timestamp, srcnd, dest, srcport);
	tag.Setrawsrcnodeid(&srcnd);
    tag.Setrawsrcportid(&srcport);
	tag.SetStage(dlrd.stage);
	//tag.SetHMAC(dlrd.HMAC_key);
	tag.SetHMAC_key(HMAC_key);
	tag.SetHMAC1(dlrd.HMAC1);
	tag.SetHMAC2 (dlrd.HMAC2);
	tag.SetDS_public_key1 (dlrd.DS_public_key1);
	tag.SetDS_public_key2 (dlrd.DS_public_key2);
	tag.SetDS_public_key3 (dlrd.DS_public_key3);
	tag.SetDS1 (dlrd.DS1);
	tag.SetDS2 (dlrd.DS2);
	tag.Setsrcnodeid (dlrd.source_nodeid);
	tag.Setsrcportid (dlrd.source_portid);
	tag.Setdesnodeid (&dest);
	cout<<"Packet tags set"<<endl;
	//tag.SetX (0);
	Ptr <Packet> packet1 = Create <Packet> (100);
	packet1->AddPacketTag(tag);
	srand(Simulator::Now().GetSeconds());
	double rand_time = 0.00001*(rand()%100);
	Ptr <SimpleUdpApplication> udp_app = DynamicCast <SimpleUdpApplication> (RSU_apps.Get(0));
	cout<<"UDP app selected"<<endl;
	if ((udp_app == 0)||(packet1==0)) 
	{
		std::cout << "udp_app is null! Cannot schedule SendPacket." << std::endl;
	}
	else
	{
		cout<<"packet going to transmit"<<endl;
		cout<<"Destination ip is "<<dest_ip<<endl;
		//Ptr <Packet> packet2 = Create <Packet> (100);
		//Simulator::Schedule(Seconds(rand_time+0.005),&SimpleUdpApplication::SendPacket,udp_app,packet1,dest_ip, 7777);
		Simulator::Schedule(Seconds(rand_time),&TrySendDownlinkSecondTime, dlrd.casted_raw_source_nodeid, dlrd.casted_destination_nodeid, dlrd.casted_raw_source_portid, packet1, 0, Simulator::Now().GetSeconds());
		//Simulator::Schedule(Seconds(0.005),&TrySendDownlink, destination_index, node_index, port_id, packet1, 0);
		cout<<"Packet transmitted"<<endl;
	}
	
}

void encrypt_HMAC2(struct downlink_rest_data dlrd)
{
	   //Encrypt HMAC2 key
	   
	   cout<<"Reading HMAC2 key at controller"<<endl;
	   std::string filename_HMAC2 = NS3_ROOT "/analytics/data/security_HMAC2_data.csv";
	   string HMAC2_key = read_other_other_item_from_csv(filename_HMAC2, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 3); 
	   
	   std::ostringstream oss3;
	   oss3 << " is_controller=true create_security_manager_con=true netsize=1 "
		    << " sign_FALCON=false verify_FALCON=false generate_FALCON=false "
		    << " encrypt_ASCON=true decrypt_ASCON=false generate_ASCON_key=false "
		    << " node_id="<< dlrd.casted_raw_source_nodeid << " port_id="  << dlrd.casted_raw_source_portid<< " other_node_id=" << dlrd.casted_destination_nodeid << ""
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
		    << " message=" << HMAC2_key << " msg_type=4";
	   
	   std::string command_str3 = oss3.str();
	   Simulator::Schedule(Seconds(0), LDA_PQ_security, command_str3);
	
}

void read_uplink_data_first_time(struct downlink_rest_data dlrd)
{
	       
	       auto dlrd_copy = new downlink_rest_data(dlrd); // copy construct on heap

	        string DS1_verification_string;
			string HMAC1_verification_string;
		    std::string HMAC2_str = BytesToHexString(dlrd.HMAC1, 32);

			
			cout<<"Reading Dig signature 1 verification"<<endl;
			std::string filename_DS1 = NS3_ROOT "/analytics/data/security_con_dig_sig_data.csv";
			DS1_verification_string = read_other_other_item_from_csv(filename_DS1, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_raw_source_portid), std::to_string(dlrd.casted_destination_nodeid), 4);
			cout<<"DS1 verification string is "<<DS1_verification_string<<endl;
			
			cout<<"Reading HMAC1 verification"<<endl;
			std::string filename_HMAC1 = NS3_ROOT "/analytics/data/security_node1_HMAC_data.csv";
			HMAC1_verification_string = read_other_other_item_from_csv(filename_HMAC1, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_raw_source_portid),std::to_string(dlrd.casted_destination_nodeid), 4);
			cout<<"HMAC1_verification string is "<<HMAC1_verification_string<<endl;
			
			cout<<"Reading HMAC2 verification"<<endl;
			std::string filename_HMAC2 = NS3_ROOT "/analytics/data/security_global_HMAC_verification_data.csv";

			string HMAC2_verification_string = read_other_other_item_from_csv(filename_HMAC2, std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_raw_source_portid), 3);
			cout<<"Location HMAC_verification string is "<<HMAC2_verification_string.substr(0,4)<<endl;
			
			cout<<"This is stage 1 at the controller authenticating"<<endl;
			//Authenticate node
			cout<<"DS1 verification string is "<<DS1_verification_string.substr(0, 4)<<"HMAC1 verification string is "<<HMAC1_verification_string.substr(0, 4)<<"HMAC2 verification string is "<<HMAC2_verification_string.substr(0, 4)<<endl;
			if ((DS1_verification_string.substr(0, 4) == "True") && (HMAC1_verification_string.substr(0, 4)=="True") && (HMAC2_verification_string.substr(0,4) == "True"))
			{
				duplicate_count[dlrd.casted_raw_source_nodeid][dlrd.casted_destination_nodeid]++;
				//Get HMAC 2 key
				cout<<"Creating HMAC 2 key at the controller "<<endl;
				std::ostringstream oss4;
				oss4 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=false initiate_session1=false "
				<< " initiate_session2=true create_hmac_global=false encrypt_ECDH=false "
				<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false verify_HMAC=false"
				<< " message=" << HMAC2_str << " msg_type=3";
			
			    flood_counter_rec[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] = flood_counter_rec[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] + 1;
				std::string command_str4 = oss4.str();
				Simulator::Schedule(Seconds(0.000000), LDA_security, command_str4);	
				Simulator::Schedule(Seconds(0.000250), encrypt_HMAC2, *dlrd_copy);				
				Simulator::Schedule(Seconds(0.000500), send_uplink_data_first_time, *dlrd_copy);
				(Link_duplicates_at_controller_inst+dlrd.casted_raw_source_portid)->Link_f_inst[dlrd.casted_raw_source_portid].Link_fi_inst[dlrd.casted_raw_source_nodeid].Link_values[dlrd.casted_destination_nodeid] = 1.0;
			}
}




void verify_uplink_packet_second_time(struct downlink_rest_data dlrd)
{
		std::string HMAC_key_str = BytesToHexString(dlrd.HMAC_key, 81);
		cout<<"HMAC key is "<<HMAC_key_str<<endl;
	    std::string HMAC1_str = BytesToHexString(dlrd.HMAC1, 32);
	    cout<<"HMAC1 is "<<HMAC1_str<<endl;
	    std::string HMAC2_str = BytesToHexString(dlrd.HMAC2, 32);
	    cout<<"HMAC2 is "<<HMAC2_str<<endl;
	    std::string digital_sig_str1 = BytesToHexString(dlrd.DS_public_key1, 256);
	    cout<<"Digital signature 1 is"<<digital_sig_str1<<endl;
	    std::string digital_sig_str2 = BytesToHexString(dlrd.DS_public_key2, 1280);
	    cout<<"Digital signature 2 is"<<digital_sig_str2<<endl;
	    std::string digital_sig_str3 = BytesToHexString(dlrd.DS_public_key3, 1280);
	    cout<<"Digital signature 3 is"<<digital_sig_str3<<endl;
	    std::string DS1_str = BytesToHexString(dlrd.DS1, 16);
		
		cout<<"source node id is "<<dlrd.casted_raw_source_nodeid<<endl;
		cout<<"source port id is "<<dlrd.casted_raw_source_portid<<endl;
		cout<<"destination node id is "<<dlrd.casted_destination_nodeid<<endl;
		cout<<"destination port id is "<<dlrd.casted_raw_destination_portid<<endl;
		
		
		cout<<"state is "<<dlrd.stage<<endl;
		cout<<"DS1 is "<<DS1_str<<endl;
		cout<<"DS2 is "<<dlrd.DS2<<endl;
		
		cout<<"Getting timestamp from blockchain"<<endl;
        Simulator::Schedule(Seconds(0.000), Get_timestamp, dlrd.casted_raw_source_nodeid, dlrd.casted_destination_nodeid, dlrd.casted_raw_source_portid, "C1");

	//Signature 1 verification
		   cout<<"Verifying signature 1 at controller "<<endl;
		   std::ostringstream oss1;
		   oss1 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=true initiate_session1=false "
				<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
				<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
				<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid  << " signature=" << digital_sig_str1<< " ";
			
			std::string command_str1 = oss1.str();
			Simulator::Schedule(Seconds(0.00001), LDA_security, command_str1);
			
			
			
		   //Encrypted message verification
		   cout<<"Decrypting message at the controller "<<endl;
		   std::ostringstream oss2;
		   oss2 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=false initiate_session1=false "
				<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
				<< " decrypt_ECDH=true create_hmac_set1=false create_hmac_set2=false "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false "
				<< " message=" << DS1_str << " ";
			
			std::string command_str2 = oss2.str();
			Simulator::Schedule(Seconds(0.00002), LDA_security, command_str2);
			

			
		   //HMAC1 verification
		   cout<<"HMAC1 verification at the controller "<<endl;
		   std::ostringstream oss3;
		   oss3 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=false initiate_session1=false "
				<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
				<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false verify_HMAC=true"
				<< " message=" << dlrd.casted_raw_source_nodeid+dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid << " hashval=" << HMAC1_str << " msg_type=2";
			
			std::string command_str3 = oss3.str();
			Simulator::Schedule(Seconds(0.00003), LDA_security, command_str3);
			

			
			//HMAC2 verification
			cout<<"HMAC2 verification at the controller "<<endl;
			std::ostringstream oss4;
			oss4 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " node_id=" << dlrd.casted_raw_source_nodeid  << " port_id=" << dlrd.casted_raw_source_portid  << " other_node_id=" << dlrd.casted_destination_nodeid << " "
				<< " generate_dig_rsa_key_pair=false generate_dig_ecc_key_pair=false "
				<< " generate_own_aes_key=false encrypt_ECDH=false decrypt_ECDH=false "
				<< " sign_data=false verify_signature=false initiate_session1=false "
				<< " initiate_session2=false create_hmac_global=false encrypt_ECDH=false "
				<< " decrypt_ECDH=false create_hmac_set1=false create_hmac_set2=false "
				<< " verify_key_expiry=false is_node=false pid=1 get_rsa_keys=false "
				<< " encrypt_rsa=false set_aes_key_for_pair=false encrypt_controller_data=false "
				<< " decrypt_controller_data=false generate_global_HMAC_secret_key=false "
				<< " get_digital_public_key=false get_session_HMAC_1=false get_session_HMAC_2=false "
				<< " create_global_HMAC_node=false decrypt_rsa=false get_aes_keys=false "
				<< " encrypt_aes_node_pair=false decrypt_aes_node_pair=false verify_HMAC=true"
				<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid << " hashval=" << HMAC2_str<< " msg_type=3";
			
			std::string command_str4 = oss4.str();
			Simulator::Schedule(Seconds(0.00004), LDA_security, command_str4);
			

			
		   //Signature 2 verification
		   cout<<"Signature 2 verification at the controller "<<endl;
		   std::ostringstream oss5;
		   oss5 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " sign_FALCON=false verify_FALCON=true generate_FALCON=false "
				<< " encrypt_ASCON=false decrypt_ASCON=false generate_ASCON_key=false "
				<< " node_id="<< dlrd.casted_raw_source_nodeid << " port_id="  << dlrd.casted_raw_source_portid << " other_node_id=" << dlrd.casted_destination_nodeid  << ""
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
				<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid << " signature=" << digital_sig_str2 << " msg_type=1 ";
		   
		   std::string command_str5 = oss5.str();
		   Simulator::Schedule(Seconds(0.00005), LDA_PQ_security, command_str5);
		   
		   
		   //Signature 3 verification 
		   cout<<"Signature 3 verification at the controller "<<endl;
		   std::ostringstream oss6;
		   oss6 << " is_controller=true create_security_manager_con=true netsize=1 "
				<< " sign_FALCON=false verify_FALCON=true generate_FALCON=false "
				<< " encrypt_ASCON=false decrypt_ASCON=false generate_ASCON_key=false "
				<< " node_id="<< dlrd.casted_raw_source_nodeid << " port_id="  << dlrd.casted_raw_source_portid << " other_node_id=" << dlrd.casted_destination_nodeid  << ""
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
				<< " message=" << dlrd.casted_raw_source_nodeid +dlrd.casted_raw_source_portid+dlrd.casted_destination_nodeid << " signature=" << digital_sig_str3 << " msg_type=2 ";
		   
		   std::string command_str6 = oss6.str();
		   Simulator::Schedule(Seconds(0.00006), LDA_PQ_security, command_str6);
		   

	
}
#include <algorithm>
#include <cctype>

std::string trim(const std::string& s) {
    auto start = s.begin();
    while (start != s.end() && std::isspace((unsigned char)*start)) {
        start++;
    }

    auto end = s.end();
    do {
        end--;
    } while (std::distance(start, end) > 0 && std::isspace((unsigned char)*end));

    return std::string(start, end + 1);
}


void read_uplink_data_second_time(struct downlink_rest_data dlrd)
{
	
	    string DS1_verification_string;
		string decrypted_string_ori;
		string HMAC1_verification_string;
		string HMAC2_verification_string;
		string FALCON1_verification_string;
		string FALCON2_verification_string;
		std::string decrypted_string;
		
		if(routing_algorithm == 4)
		{
		cout<<"Reading Dig sign 1 verification for source"<<dlrd.casted_raw_source_nodeid<<"port "<<dlrd.casted_raw_source_portid<<"destination "<<dlrd.casted_destination_nodeid<<endl;
	    std::string filename_DS1 = NS3_ROOT "/analytics/data/security_con_dig_sig_data.csv";
		DS1_verification_string = read_other_other_item_from_csv(filename_DS1, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_raw_source_portid), std::to_string(dlrd.casted_destination_nodeid), 4);
		cout<<"DS1 verification string is "<<DS1_verification_string.substr(0, 4)<<endl;
		
		cout<<"Reading ECDH data"<<endl;
		std::string filename_DH = NS3_ROOT "/analytics/data/security_ECDH_data.csv";
		decrypted_string_ori = read_other_other_item_from_csv(filename_DH, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 4);
		
		decrypted_string = trim(decrypted_string_ori);
		cout<<"ECDH_decrypted string is "<<decrypted_string<<endl;
		cout<<"size of decrypted string is "<<decrypted_string.size()<<endl;
		cout<<"size of converted string is "<<std::to_string(dlrd.casted_raw_source_nodeid+dlrd.casted_destination_nodeid+dlrd.casted_raw_source_portid).size()<<endl;
		bool similarity = (decrypted_string==std::to_string(dlrd.casted_raw_source_nodeid+dlrd.casted_destination_nodeid+dlrd.casted_raw_source_portid));
		cout<<"Converted casted string is "<<std::to_string(dlrd.casted_raw_source_nodeid+dlrd.casted_destination_nodeid+dlrd.casted_raw_source_portid)<<"are they same "<<similarity<<endl;
		
		cout<<"Reading HMAC 1 verification string"<<endl;
		std::string filename_HMAC1 = NS3_ROOT "/analytics/data/security_node1_HMAC_data.csv";
		HMAC1_verification_string = read_other_other_item_from_csv(filename_HMAC1, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_raw_source_portid), std::to_string(dlrd.casted_destination_nodeid), 4);
		cout<<"HMAC1_verification string is "<<HMAC1_verification_string.substr(0, 4)<<endl;
		
		cout<<"Reading HMAC 2 verification string"<<endl;
		std::string filename_HMAC2 = NS3_ROOT "/analytics/data/security_node2_HMAC_data.csv";
		HMAC2_verification_string = read_other_other_item_from_csv(filename_HMAC2, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 4);
		cout<<"HMAC2_verification string is "<<HMAC2_verification_string.substr(0, 4)<<endl;
	   
	   cout<<"Reading FALCON 1 verification string"<<endl;
	   std::string filename_verify_FALCON1 = NS3_ROOT "/analytics/data/security_node1_dig_sig_data.csv";
	   FALCON1_verification_string = read_other_other_item_from_csv(filename_verify_FALCON1, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 4);
	   cout<<"Digital signature 2 verification string is "<<FALCON1_verification_string.substr(0, 4)<<endl;
	   
	   cout<<"Reading FALCON 2 verification string"<<endl;
	   std::string filename_verify_FALCON2 = NS3_ROOT "/analytics/data/security_node2_dig_sig_data.csv";
	   FALCON2_verification_string = read_other_other_item_from_csv(filename_verify_FALCON2, std::to_string(dlrd.casted_raw_source_nodeid), std::to_string(dlrd.casted_destination_nodeid), std::to_string(dlrd.casted_raw_source_portid), 4);
	   cout<<"Digital signature 3 verification string is "<<FALCON2_verification_string.substr(0, 4)<<endl;
   }
	   
	   double time_difference = Simulator::Now().GetSeconds() - timestamp_stored[dlrd.casted_raw_source_nodeid][dlrd.casted_destination_nodeid][dlrd.casted_raw_source_portid];
	   cout<<"Stored timestamp is "<<timestamp_stored[dlrd.casted_raw_source_nodeid][dlrd.casted_destination_nodeid][dlrd.casted_raw_source_portid]<<endl;
	   cout<<"Time difference is "<<time_difference<<endl;
	   	if(*dlrd.stage == 2)
		{
				if((routing_algorithm ==4))//proposed
				{
					if((DS1_verification_string.substr(0, 4) != "True")||(FALCON1_verification_string.substr(0, 4) != "True")||(FALCON2_verification_string.substr(0, 4) != "True"))
					{
						cout<<"Increasing fabricated count"<<endl;
						fabricated_count[dlrd.casted_raw_source_nodeid][dlrd.casted_destination_nodeid]++;
					}
					
					if(HMAC2_verification_string.substr(0, 4) != "True")
					{
						cout<<"Increasing replay count"<<endl;
						replay_count[dlrd.casted_raw_source_nodeid][dlrd.casted_destination_nodeid]++;
					}
					
					
					if((time_difference < 0.20)&&(DS1_verification_string.substr(0, 4) == "True")&&(decrypted_string == std::to_string(dlrd.casted_raw_source_nodeid+dlrd.casted_destination_nodeid+dlrd.casted_raw_source_portid))&&(HMAC2_verification_string.substr(0, 4) == "True")&&(HMAC1_verification_string.substr(0, 4)=="True")&&(FALCON1_verification_string.substr(0, 4) == "True")&&(FALCON2_verification_string.substr(0, 4) == "True"))
					{
						cout<<"Matched LLDP found"<<endl;
						matched_LLDP[dlrd.casted_raw_source_nodeid][dlrd.casted_destination_nodeid]++;
					
						//Do all verifications here;
						bool signature_check = check_signature();
						if (signature_check == true)
						{    
							cout<<"Increasing flood counter"<<endl;
							flood_counter_con[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] = flood_counter_con[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] + 1.0;
						}
						bool s2 = ( flood_counter_con[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] < 2*RL_iterations);
						if(s2)
						{
							flood_counter_sen[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] = flood_counter_sen[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] + 1;
							flood_counter_rec[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] = flood_counter_rec[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] + 1;
							(Link_at_controller_inst+(*dlrd.source_portid))->Link_f_inst[(*dlrd.destination_portid)].Link_fi_inst[*dlrd.source_nodeid].Link_values[*dlrd.destination_nodeid] = 1.0;
							(LLDP_timestamp_at_controller_inst+(*dlrd.source_portid))->Link_f_inst[*dlrd.destination_portid].Link_fi_inst[*dlrd.source_nodeid].Link_values[*dlrd.destination_nodeid] = Simulator::Now().GetSeconds();
							(Link_duplicates_SecondTime_uplink_at_controller_inst+dlrd.casted_raw_source_portid)->Link_f_inst[dlrd.casted_raw_source_portid].Link_fi_inst[dlrd.casted_raw_source_nodeid].Link_values[dlrd.casted_destination_nodeid] = 1.0;
		                     cout<<"Setting link state as exsiting "<<endl;
						}
						
					}
				}
		
			//need to set L after verification and authentication for proposed.
			if((routing_algorithm ==0)||(routing_algorithm ==1))//port-based and normal
			{
				(Link_at_controller_inst+(*dlrd.source_portid))->Link_f_inst[(*dlrd.destination_portid)].Link_fi_inst[*dlrd.source_nodeid].Link_values[*dlrd.destination_nodeid] = 1.0;
			}
			else if((routing_algorithm ==2))//hash-based
			{
				//verify hash;
				(Link_at_controller_inst+(*dlrd.source_portid))->Link_f_inst[(*dlrd.destination_portid)].Link_fi_inst[*dlrd.source_nodeid].Link_values[*dlrd.destination_nodeid] = 1.0;
			}
			
			else if((routing_algorithm ==3))//Link guard
			{
				//Do all verifications here;
				temp_link_set[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid][*dlrd.destination_portid] = 1.0;
				//double val1 = temp_link_set[*source_nodeid][*destination_nodeid][*source_portid][*destination_portid];
				//double val2 = temp_link_set[*destination_nodeid][*source_nodeid][*destination_portid][*source_portid];
				//bool s1 = (flood_counter_con[*source_nodeid][*destination_nodeid][*source_portid] < 50.0);
				//if(s1)
				//{
					//if ((val1 == val2) && (val2==1.0))
					//{
						(Link_at_controller_inst+(*dlrd.source_portid))->Link_f_inst[(*dlrd.destination_portid)].Link_fi_inst[*dlrd.source_nodeid].Link_values[*dlrd.destination_nodeid] = 1.0;
					//}
				//}
				LLDP_flood_counter_rec[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid][*dlrd.destination_portid]++;
				flood_counter_con[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] = flood_counter_con[*dlrd.source_nodeid][*dlrd.destination_nodeid][*dlrd.source_portid] + 1.0;
			}
			
		}
}

void decrypt_downlink_packet(struct downlink_packet_decrypt dlpd)
{
    // Legacy LLDP decrypt stub — body moved to 08_lldp_handlers.h in old codebase.
    // Replaced with 08_beacon_handlers.h in Stage 4. No-op stub.
    (void)dlpd;
}

// ============================================================
// STAGE 7: Post-Quantum Cryptography — TRS + Simulated CKKS FHE
// Paper §3.3.2 (TRS, Eq. 3.58-3.60) and §3.3.3 (FHE, Eq. 3.61-3.65)
//
// Implementations (TRSSignature, FHECiphertext, generate_trs_aggregate,
// verify_trs, fhe_encrypt_scalar, fhe_aggregate, fhe_decrypt_scalar)
// are defined in 06_mrtpa_attack.h (included before this file) so that
// StoreTrajectoryToBlockchain() can use them at the point of call.
//
// When OpenFHE is installed, replace FHECiphertext with Ciphertext<DCRTPoly>
// and add to 01_includes.h:
//   #include <openfhe.h>
//   using namespace lbcrypto;
// ============================================================
