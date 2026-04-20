// ============================================================
// 07_security.h — MPTD-PQS Security Layer (Stage 10B cleanup)
// ============================================================
// Retained: SimpleUdpApplication class + socket I/O + essential globals
// Removed:  2600+ lines of LLDP discovery, HMAC verify, routing retry,
//           flooding guards, location verification (LDA routing code)
// ============================================================

bool routing_test = true;

// ── DSRC device containers (installed in 12_main.h) ──────────────────────────
NetDeviceContainer wifidevices;
NetDeviceContainer wifidevices_172;
NetDeviceContainer wifidevices_174;
NetDeviceContainer wifidevices_176;
NetDeviceContainer wifidevices_180;
NetDeviceContainer wifidevices_182;
NetDeviceContainer wifidevices_184;

NodeContainer dsrc_Nodes;

// ── LTE uplink/downlink state tracking ───────────────────────────────────────
bool uplink_state[total_size];
bool downlink_state[total_size];

// ── SimpleUdpApplication — beacon socket I/O (§3.4.4) ────────────────────────
class SimpleUdpApplication : public Application
{
public:
    SimpleUdpApplication();
    virtual ~SimpleUdpApplication();

    static TypeId GetTypeId();
    virtual TypeId GetInstanceTypeId() const;

    void HandleReadOne(Ptr<Socket> socket);   // implemented in 08_beacon_handlers.h
    void HandleReadTwo(Ptr<Socket> socket);

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
    uint16_t m_port1;
    uint16_t m_port2;

    Ptr<Socket> m_send_socket;
    Ptr<Socket> m_uplink_send_socket;
    Ptr<Socket> m_downlink_send_socket;
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
}

void SimpleUdpApplication::test()
{
    cout << "Test function" << endl;
}

void SimpleUdpApplication::HandleReadTwo(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from))) {
        NS_LOG_INFO(PURPLE_CODE << "HandleReadTwo: Received a Packet of size: "
                    << packet->GetSize() << " at time " << Now().GetSeconds() << END_CODE);
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
        cout << "An Error occured in sending packet uplink" << endl;
        uplink_state[node_id] = false;
    } else {
        cout << "Uplink packet transmitted" << endl;
        uplink_state[node_id] = true;
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
        cout << "An Error occured in sending packet downlink" << endl;
        downlink_state[node_id] = false;
    } else {
        cout << "Downlink packet transmitted" << endl;
        downlink_state[node_id] = true;
    }
}
// HandleReadOne is implemented in 08_beacon_handlers.h (out-of-class definition)

// ── LDA/WiFi MAC globals (legacy — required by 12_main.h switch + 09_send_lte.h) ─────────────
uint32_t CW_min  = 15;      // Minimum contention window (overwritten in 12_main.h switch)
uint32_t SIFS    = 12;      // Short Inter-Frame Space (μs)
double   T_slot  = 20.0;    // Slot time (μs)

// ── Gurobi optimization arrays (legacy — used by clear_solution() in 09_send_lte.h) ──────────
double Z_gurobi[total_size+2];
double X_gurobi[total_size+2];
double Z_nodes  [total_size+2];
double X_nodes  [total_size+2];

// ── LDA routing stubs — all dead code when routing_test=true ──────────────────────────────────
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

// ── Trace callbacks (wired via Config::ConnectFailSafe in 12_main.h) ──────────────────────────
void print_time()
{
    cout << "[SIM] t=" << Simulator::Now().GetSeconds() << "s" << endl;
}
void Rx(std::string, Ptr<const Packet>, uint16_t, WifiTxVector, MpduInfo, SignalNoiseDbm, uint16_t) {}
void MacRx(std::string, Ptr<const Packet>)             {}
void MacTx(std::string, Ptr<const Packet>)             {}
void Enqueue(std::string, Ptr<const WifiMacQueueItem>) {}
