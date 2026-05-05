// ============================================================
// 07_socket_layer.h — UDP Socket Layer (MPTD-PQS)
// Renamed from 07_security.h (Stage 10B cleanup)
// ============================================================
// Contents:
//   SimpleUdpApplication class — beacon socket I/O (§3.4.4)
//   Colour macros for NS-3 log output
//   Trace callbacks (print_time, Rx, MacRx, MacTx, Enqueue)
//   Legacy LDA stubs — dead code, kept to satisfy 12_main.h scheduler calls
//
// Removed vs 07_security.h:
//   wifidevices_172/174/176/180/182/184 (unused secondary containers)
//   Z_gurobi[], X_gurobi[], Z_nodes[], X_nodes[] (Gurobi arrays — clear_solution() emptied)
// ============================================================

bool routing_test = true;

// ── DSRC device containers (installed in 12_main.h) ──────────────────────────
NetDeviceContainer wifidevices;
// Legacy DSRC channel device containers (used by 12_main.h channel setup)
NetDeviceContainer wifidevices_172;
NetDeviceContainer wifidevices_174;
NetDeviceContainer wifidevices_176;
NetDeviceContainer wifidevices_180;
NetDeviceContainer wifidevices_182;
NetDeviceContainer wifidevices_184;

NodeContainer dsrc_Nodes;

// ── SimpleUdpApplication — beacon socket I/O (§3.4.4) ────────────────────────
class SimpleUdpApplication : public Application
{
public:
    SimpleUdpApplication();
    virtual ~SimpleUdpApplication();

    static TypeId GetTypeId();
    virtual TypeId GetInstanceTypeId() const;

    void HandleReadOne(Ptr<Socket> socket);       // management node receive (legacy LDA path)
    void HandleReadTwo(Ptr<Socket> socket);      // vehicle downlink receive [DL-VEH-RX]
    void handle_readone(Ptr<Socket> socket);     // RSU DSRC receive handler (professor's term)
    void handle_downlink_at_rsu(Ptr<Socket> socket); // RSU receives management downlink → forwards to vehicles
                                                 // = fires when vehicle beacon arrives at RSU:6666

    void SendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t port);
    void test();
    void UplinkConnect(Ipv4Address destination, uint16_t port);
    void DownlinkConnect(Ipv4Address destination, uint16_t port);
    void UplinkSendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t node_id);
    void DownlinkSendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t node_id);

private:
    void SetupReceiveSocket(Ptr<Socket> socket, uint16_t port);
    virtual void StartApplication();

    Ptr<Socket> m_recv_socket1;
    Ptr<Socket> m_recv_socket2;
    Ptr<Socket> m_recv_socket3;   // RSU: DSRC beacon receive (port 6666) — Option B
    Ptr<Socket> m_recv_socket_dl; // RSU: management downlink receive (port 8888)
    uint16_t m_port1;
    uint16_t m_port2;

    Ptr<Socket> m_send_socket;
    Ptr<Socket> m_uplink_send_socket;
    Ptr<Socket> m_downlink_send_socket;
    Ptr<Socket> m_relay_socket;   // RSU: forwards poisoned/clean beacon to management_node
};

// ── Color macros for NS-3 log output ─────────────────────────────────────────
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

// ── SimpleUdpApplication implementations ─────────────────────────────────────

TypeId SimpleUdpApplication::GetTypeId()
{
    static TypeId tid = TypeId("ns3::SimpleUdpApplication")
                            .AddConstructor<SimpleUdpApplication>()
                            .SetParent<Application>();
    return tid;
}

TypeId SimpleUdpApplication::GetInstanceTypeId() const
{
    return SimpleUdpApplication::GetTypeId();
}

SimpleUdpApplication::SimpleUdpApplication()
{
    m_port1 = 7777;
    m_port2 = 9999;
}

SimpleUdpApplication::~SimpleUdpApplication() {}

void SimpleUdpApplication::SetupReceiveSocket(Ptr<Socket> socket, uint16_t port)
{
    InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), port);
    if (socket->Bind(local) == -1) {
        NS_FATAL_ERROR("Failed to bind socket");
    }
}

void SimpleUdpApplication::StartApplication()
{
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    uint32_t nid = GetNode()->GetId();

    // Detect whether this application instance runs on an RSU node (Option B).
    // g_first_rsu_node_id and g_num_active_rsus are set in 12_main.h after node creation.
    bool is_rsu = g_option_b_active &&
                  (g_num_active_rsus > 0) &&
                  (nid >= g_first_rsu_node_id) &&
                  (nid <  g_first_rsu_node_id + g_num_active_rsus);

    if (is_rsu) {
        // ── RSU node: listen on port 6666 for vehicle DSRC beacons ───────────────
        m_recv_socket3 = Socket::CreateSocket(GetNode(), tid);
        SetupReceiveSocket(m_recv_socket3, 6666);
        m_recv_socket3->SetRecvCallback(
            MakeCallback(&SimpleUdpApplication::handle_readone, this)); // professor's term
        m_recv_socket3->SetAllowBroadcast(true);

        // ── RSU relay socket: forward beacons to management_node via CSMA ────────
        m_relay_socket = Socket::CreateSocket(GetNode(), tid);
        m_relay_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 51000));
        m_relay_socket->SetAllowBroadcast(false);

        // Keep send socket for any legacy calls (also used by downlink forward to vehicles)
        m_send_socket = Socket::CreateSocket(GetNode(), tid);
        m_send_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 20000));
        m_send_socket->SetAllowBroadcast(true);

        // ── RSU downlink socket: receive control response from management (port 8888) ─────
        // centralized_dsrc_data_broadcast / centralized_dsrc_data_unicast arrive here
        // before being re-broadcast to vehicles on DSRC port 9999.
        m_recv_socket_dl = Socket::CreateSocket(GetNode(), tid);
        SetupReceiveSocket(m_recv_socket_dl, 8888);
        m_recv_socket_dl->SetRecvCallback(
            MakeCallback(&SimpleUdpApplication::handle_downlink_at_rsu, this));

        cout << "[OPT-B] RSU node " << nid
             << " (idx=" << (nid - g_first_rsu_node_id) << ")"
             << " listening on DSRC port 6666, downlink port 8888" << endl;
    } else {
        // ── Management/vehicle node: standard socket setup ────────────────────────
        m_recv_socket1 = Socket::CreateSocket(GetNode(), tid);
        m_recv_socket2 = Socket::CreateSocket(GetNode(), tid);

        SetupReceiveSocket(m_recv_socket1, m_port1);
        SetupReceiveSocket(m_recv_socket2, m_port2);

        m_recv_socket1->SetRecvCallback(MakeCallback(&SimpleUdpApplication::HandleReadOne, this));
        m_recv_socket2->SetRecvCallback(MakeCallback(&SimpleUdpApplication::HandleReadTwo, this));

        m_send_socket          = Socket::CreateSocket(GetNode(), tid);
        m_uplink_send_socket   = Socket::CreateSocket(GetNode(), tid);
        m_downlink_send_socket = Socket::CreateSocket(GetNode(), tid);

        m_uplink_send_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 10000));
        m_downlink_send_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 30000));
        m_send_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 20000));

        m_recv_socket1->SetAllowBroadcast(true);
        m_recv_socket2->SetAllowBroadcast(true);
        m_send_socket->SetAllowBroadcast(true);
        m_uplink_send_socket->SetAllowBroadcast(true);
        m_downlink_send_socket->SetAllowBroadcast(true);

        // ── Management node (nid=1): store downlink socket globally ──────────────────
        // HandleBeaconReceived() is a free function without `this`, so it uses
        // g_mgmt_downlink_socket to send centralized_dsrc_data_broadcast/unicast.
        // nid==1 is always management_node (controller_Node is nid=0, created first).
        if (GetNode()->GetId() == 1) {
            g_mgmt_downlink_socket = m_downlink_send_socket;
            cout << "[DL-INIT] management node " << nid
                 << " downlink socket registered (port 30000)" << endl;
        }
    }
}

void SimpleUdpApplication::test()
{
    cout << "Test function" << endl;
}

// HandleReadTwo — vehicle receives downlink control packet from RSU
// Professor's terms: receives centralized_dsrc_data_broadcast / centralized_dsrc_data_unicast
// Flow: management → [DL-MGT-TX] → RSU:8888 → [DL-RSU-FWD] → vehicle:9999 → here → [DL-VEH-RX]
void SimpleUdpApplication::HandleReadTwo(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from))) {
        uint32_t my_nid = GetNode()->GetId();

        // Guard: skip management/controller/RSU nodes — only vehicles log downlink receipt
        // (RSU broadcasts on 3.255.255.255 which may also reach management on CSMA)
        bool is_vehicle = (my_nid >= 2) &&
                          !(g_option_b_active && my_nid >= g_first_rsu_node_id);
        if (!is_vehicle) continue;

        DownlinkControlTag dl_tag;
        if (packet->RemovePacketTag(dl_tag)) {
            // ── Downlink control packet: alert from management/controller ─────────────
            const char* alert_str = (dl_tag.GetAlertType() == 0) ? "CLEAN_ROUTING" :
                                    (dl_tag.GetAlertType() == 1) ? "ATTACK_DETECTED" :
                                                                   "WRONG_ROUTING";
            // vid displayed as V(nid-2) so it matches vehicle index used in logs
            uint32_t vid = my_nid - 2;
            cout << "[DL-VEH-RX] V" << vid
                 << " (nid=" << my_nid << ")"
                 << " from RSU" << dl_tag.GetRsuId()
                 << " alert=" << alert_str
                 << " spd_adv=" << dl_tag.GetSpeedAdvice() << " m/s"
                 << " t=" << Simulator::Now().GetSeconds() << endl;
        } else {
            NS_LOG_INFO(PURPLE_CODE << "HandleReadTwo: V" << (my_nid - 2)
                        << " received packet size=" << packet->GetSize()
                        << " t=" << Now().GetSeconds() << END_CODE);
        }
    }
}

void SimpleUdpApplication::SendPacket(Ptr<Packet> packet, Ipv4Address destination, uint16_t port)
{
    NS_LOG_FUNCTION(this << packet << destination << port);
    m_send_socket->Connect(InetSocketAddress(Ipv4Address::ConvertFrom(destination), port));
    int x = m_send_socket->Send(packet);
    if (x == -1) { cout << "An Error occured in sending" << endl; }
}

void SimpleUdpApplication::UplinkConnect(Ipv4Address destination, uint16_t port)
{
    int x = m_uplink_send_socket->Connect(
                InetSocketAddress(Ipv4Address::ConvertFrom(destination), port));
    if (x == -1) { cout << "An Error in connecting uplink" << endl; }
}

void SimpleUdpApplication::UplinkSendPacket(Ptr<Packet> packet, Ipv4Address destination,
                                             uint16_t node_id)
{
    int x = m_uplink_send_socket->Send(packet);
    if (x == -1) {
        cout << "An Error occured in sending packet uplink (node " << node_id << ")" << endl;
    } else {
        cout << "Uplink packet transmitted" << endl;
    }
}

void SimpleUdpApplication::DownlinkConnect(Ipv4Address destination, uint16_t port)
{
    int x = m_downlink_send_socket->Connect(
                InetSocketAddress(Ipv4Address::ConvertFrom(destination), port));
    if (x == -1) { cout << "An Error in connecting downlink" << endl; }
}

void SimpleUdpApplication::DownlinkSendPacket(Ptr<Packet> packet, Ipv4Address destination,
                                               uint16_t node_id)
{
    int x = m_downlink_send_socket->Send(packet);
    if (x == -1) {
        cout << "An Error occured in sending packet downlink (node " << node_id << ")" << endl;
    } else {
        cout << "Downlink packet transmitted" << endl;
    }
}
// HandleReadOne is implemented in 08_detection_engine.h (out-of-class definition)

// ── WiFi MAC timing parameters (used by 12_main.h WiFi MAC config) ───────────
uint32_t CW_min  = 15;
double   SIFS    = 12;    // Short Inter-Frame Space (µs), 802.11p
double   T_slot  = 20.0; // Slot time (µs), 802.11p

// ── Legacy LDA routing stubs — dead code when routing_test=true ──────────────
// Kept here to satisfy 12_main.h scheduler calls without modification.
void clear_RQY()                                                                               {}
void reset_LLDP_counters()                                                                     {}
void connect_to_uplink()                                                                       {}
void connect_to_uplink_RSU()                                                                   {}
void connect_to_downlink()                                                                     {}
void connect_to_downlink_RSU()                                                                 {}
void send_LTE_LLDP_packetin_uplink_alone(uint32_t, uint32_t, uint32_t, Ptr<Packet>)           {}
void send_Ethernet_LLDP_packetin_uplink_alone(uint32_t, uint32_t, uint32_t, Ptr<Packet>)      {}
void Trysend_Ethernet_LLDP_packetout_downlink_alone(uint32_t, uint32_t, uint32_t, Ptr<Packet>){}
void Trysend_LTE_LLDP_packetout_downlink_alone(uint32_t, uint32_t, uint32_t, Ptr<Packet>)    {}
void update_mobility()                                                                         {}
void set_last_true_location_and_timestamp(uint32_t, Vector)                                   {}
void setting_last_true_location_and_timestamp(uint32_t)                                       {}
void set_dsrc_initial_timestamp()                                                              {}
void verify_location()                                                                         {}
void send_LTE_data_alone(Ptr<SimpleUdpApplication>, Ptr<Node>, Ptr<Node>, uint32_t)           {}
void set_lte_initial_timestamp()                                                               {}
void set_ethernet_initial_timestamp()                                                          {}
void set_LLDP_initial_timestamp()                                                              {}
void run_optimization_link_lifetime()                                                          {}
void update_flows()                                                                            {}
void filter_flows()                                                                            {}
void LDA_security(const char*)                                                                 {}
void reset_LLDP_received_count()                                                               {}
void run_port_based()                                                                          {}
void run_normal_LLDP()                                                                         {}
void run_pure_crypto()                                                                         {}
void run_link_guard()                                                                          {}
void run_proposed_LLDP()                                                                       {}
void run_HELLO()                                                                               {}
void transmit_delta_values()                                                                   {}
void calculate_performance_evaluation_metricsLLDP()                                            {}
void reset_packet_timestamps()                                                                 {}
void reset_confusion_matrix()                                                                  {}

// ── Trace callbacks (wired via Config::ConnectFailSafe in 12_main.h) ──────────
void print_time()
{
    cout << "[SIM] t=" << Simulator::Now().GetSeconds() << "s" << endl;
}
void Rx(std::string, Ptr<const Packet>, uint16_t, WifiTxVector, MpduInfo, SignalNoiseDbm, uint16_t) {}
void MacRx(std::string, Ptr<const Packet>)             {}
void MacTx(std::string, Ptr<const Packet>)             {}
void Enqueue(std::string, Ptr<const WifiMacQueueItem>) {}
