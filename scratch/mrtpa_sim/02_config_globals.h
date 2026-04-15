// ============================================================
// SECTION 2: Simulation Configuration & Global Variables
// ============================================================
// Contents:
//   - Simulation parameters: N_Vehicles, N_RSUs, simTime
//   - Routing algorithm selection: routing_algorithm (0-5)
//   - Attack parameters: attack_number (1-6), attack_percentage
//   - MRTPA parameters: poisoning_intensity_theta, max_position_deviation
//   - Malicious node flags: trajectory_poisoning_malicious_nodes[]
//   - LTE callbacks: UeTxStartCallback, UeTxEndCallback
//   - Matrix structs: Link, Link_fi, Link_f, E_mat, F_mat
//   - generate_F_and_E() initialization function
// ============================================================

// ── Portable Path Configuration ────────────────────────────────────────────
// CHANGE THESE TWO LINES when moving to a different machine.
// Usage in code: NS3_ROOT "/analytics/data/file.csv"
//                FAB_ROOT "/test-network/..."
// (Adjacent string literal concatenation — no .c_str() needed)
#define NS3_ROOT "/home/niranga/ns-allinone-3.35/ns-3.35"
#define FAB_ROOT "/home/niranga/fabric-samples"
// ───────────────────────────────────────────────────────────────────────────

using namespace std::chrono;


#define max 40

#define max1 1
#define max2 2
#define max3 3
#define max4 4
#define max5 5
#define max6 6
#define max7 7
#define max8 8
#define max9 9
#define max10 10
#define max11 11
#define max12 12
#define max13 13
#define max14 14
#define max15 15
#define max16 16
#define max17 17
#define max18 18
#define max19 19
#define max20 20
#define max21 21
#define max22 22
#define max23 23
#define max24 24
#define max25 25

int lambda = 30;

const int Flow_size = 55;
const int controllers = 4;
uint32_t flow_size = 55;

const int total_size = 16;
uint32_t N_RSUs = 0;
uint32_t N_Vehicles = 16;

const int flows = 1;

int routing_algorithm = 4; //0-port based, 1-normal LLDP, 2-crypto-based, 3-Link guard, 4-proposed LLDP, 5-HELLO packets
int experiment_number = 0; //0 - individual attack, 1 - combined attack
int attack_number = 5; //1 - Attack 1, etc. 2-Attack 2, 3-Attack 3, 4-Attack 4, 5-Attack 5, 6-Combined attack

bool controller_malicious_assumption = true;
int attack_percentage = 40;

double simTime = 13.7;

uint16_t N_eNodeBs = 1+ N_Vehicles/40;
int var = N_Vehicles+N_RSUs;
uint32_t large=50000;

uint32_t node_controller_ID[total_size];

double optimization_frequency = 0.33;
double optimization_period = 1.0/optimization_frequency;
double data_transmission_frequency = 0.33;
double data_transmission_period = 1.0/data_transmission_frequency;
double entropy_threshold = 0.005;
double routing_frequency = data_transmission_frequency;
double contention_threshold = 0.0;
double link_lifetime_threshold = 0.400;
int mobility_scenario = 0;// 0 - urban, 1 - non-urban, 2 - highway
int architecture = 0; // 0 - centralized, 1 - distributed, 2 - hybrid
int maxspeed = 60;	

int paper = 1; //0-optimization, 1 -architecture

uint32_t flow_packet_size = 100;
uint32_t qf = 1;
uint32_t AIFSN = 0;
double B_max = 0.0;
double latency_max = 0.0;
double loss_max = 0.0;
uint32_t CW_max = 0;
double AIFS = 0.0;

double mu1 = 0.010;
double mu2 = 10.00;
double mu3 = 10.0;

bool present_location_attack_nodes = false;
bool present_flooding_attack_nodes = true;
bool present_fabrication_attack_nodes = false;
bool present_MIM_attack_nodes = false;
bool present_vanishing_attack_nodes = false;

//bool present_location_attack_controllers = true;
bool present_flooding_attack_controllers = false;
bool present_fabrication_attack_controllers = false;
bool present_MIM_attack_controllers = false;
bool present_vanishing_attack_controllers = false;

bool location_malicious_nodes[total_size];
bool flooding_malicious_nodes[total_size];
bool fabrication_malicious_nodes[total_size];
bool MIM_malicious_nodes[total_size];
bool vanishing_malicious_nodes[total_size];

bool flooding_malicious_controllers[controllers];
bool fabrication_malicious_controllers[controllers];
bool MIM_malicious_controllers[controllers];
bool vanishing_malicious_controllers[controllers];

bool trajectory_poisoning_malicious_nodes[total_size];

// ============================================================
// MRTPA (Malicious RSU Trajectory Poisoning Attack) - Algorithm 1
// ============================================================
double poisoning_intensity_theta = 0.5;     // θ ∈ [0,1] controlling deviation magnitude
double max_position_deviation = 50.0;       // Max position deviation in meters
double max_velocity_deviation = 15.0;       // Max velocity deviation in m/s
double max_acceleration_deviation = 5.0;    // Max acceleration deviation in m/s²
double max_realistic_speed = 33.33;         // ~120 km/h max realistic vehicle speed
double max_realistic_acceleration = 4.0;    // Max realistic acceleration m/s²
double min_position_x = 0.0;               // Simulation area bounds
double max_position_x = 2000.0;
double min_position_y = 0.0;
double max_position_y = 2000.0;

// Counters for MRTPA logging
uint32_t total_trajectories_received = 0;
uint32_t total_trajectories_poisoned = 0;
uint32_t total_trajectories_stored_blockchain = 0;

bool training = false; //true if training data set for machine learnng is generated
bool training_delay = false;

double HELLO_final_timestamp;
double HELLO_initial_timestamp;

double uplink_last[total_size];


double downlink_last = 0.0;

using namespace std;
using namespace ns3;
double current_channel_utilization;
double average_channel_utilization;



uint32_t assigned_consortium_ID[total_size];





struct downlink_rest_data
{
	uint32_t casted_raw_source_nodeid; 
	uint32_t casted_raw_source_portid; 
	uint32_t casted_destination_nodeid; 
	uint32_t casted_raw_destination_portid;
	uint8_t * stage = new uint8_t[2];
	uint8_t * HMAC_key = new uint8_t[163];
	uint8_t * HMAC = new uint8_t[65];
	uint8_t * DS_public_key1 = new uint8_t[513];
	uint8_t * DS_public_key2 = new uint8_t[2561];
	uint8_t * DS_public_key3 = new uint8_t[2561];
	uint8_t * DS1 = new uint8_t[201];
	uint8_t * DS2 = new uint8_t[201]; 
	uint8_t * source_nodeid = new uint8_t[36];
	uint8_t * source_portid = new uint8_t[36];
	uint8_t * raw_source_nodeid = new uint8_t[2];
	uint8_t * raw_source_portid = new uint8_t[2];
	uint8_t * destination_nodeid = new uint8_t[33];
	uint8_t * destination_portid = new uint8_t[33];
	uint8_t * HMAC1 = new uint8_t[65];
	uint8_t * HMAC2 = new uint8_t[65];
	
};


bool GetBooleanWithProbability(double probabilityPercent, int nodeID) {
    // Create a uniform random variable between 0.0 and 100.0
    //ns3::Ptr<ns3::UniformRandomVariable> uv = ns3::CreateObject<ns3::UniformRandomVariable>();
    //double randomValue = uv->GetValue(0.0, 100.0);
    srand(Simulator::Now().GetSeconds() + 1.0*(rand()%50) + 5.0*nodeID);
    double randomValue = 1.0*(rand()%100);    
    return randomValue < probabilityPercent;
}

bool blocked_port_state[total_size][total_size][2];

double last_downlink[total_size];

std::vector<bool> ueBusy; // global or in a struct
std::vector<bool> ueDLBusy; // global or in a struct


void UeTxStartCallback(uint32_t ueId, Ptr<const Packet> p)
{
    ueBusy[ueId] = true; // UE started transmitting
    ueDLBusy[ueId] = true; 
    std::cout << Simulator::Now().GetSeconds() 
              << " : UE uplink transmission in progress" << ueId << " TX started\n";
}

void UeTxEndCallback(uint32_t ueId, Ptr<const Packet> p)
{
    ueBusy[ueId] = false; // UE finished transmitting
    ueDLBusy[ueId] = false; 
    std::cout << Simulator::Now().GetSeconds() 
              << " : UE " << ueId << " TX ended\n";
}

vector<vector<vector<double>>> E_mat;
vector<vector<bool>> F_mat;

struct Link_fi
{
	double Link_values[total_size];
};

struct Link_f
{
 	struct Link_fi Link_fi_inst[total_size];
};

struct Link
{
 	struct Link_f Link_f_inst[2*flows];
};

struct Link Link_at_controller_inst[2*flows];
struct Link Link_duplicates_at_controller_inst[2*flows];
struct Link Link_duplicates_downlink_at_controller_inst[2*flows];
struct Link Link_duplicates_SecondTime_downlink_at_controller_inst[2*flows];
struct Link Link_duplicates_SecondTime_uplink_at_controller_inst[2*flows];
struct Link LLDP_timestamp_at_controller_inst[2*flows];


uint32_t flooding_counter[total_size][total_size][2];





void generate_F_and_E()
{
   E_mat.assign(total_size,
        std::vector<std::vector<double>>(total_size,
            std::vector<double>(2, 0.0)));

    F_mat.assign(total_size,
        std::vector<bool>(2, false));
        
        cout<<"E and F initialized"<<endl;
        cout<<"Sample E value "<<E_mat[0][0][0]<<endl;
        cout<<"Dimension sizes "<<E_mat.size()<<"middle"<<E_mat[0].size()<<"innermost"<< E_mat[0][0].size();
        E_mat[0][0][0] = 0.0;
    
    for(uint32_t i=0;i<total_size; i++)
    {
		for(uint32_t j=0; j<total_size; j++)
		{
			for(uint32_t k=0; k<2; k++)
			{
				blocked_port_state[i][j][k] =  false;
				flooding_counter[i][j][k] = 0;
				(Link_duplicates_at_controller_inst+k)->Link_f_inst[k].Link_fi_inst[i].Link_values[j] = 0.0;
				(Link_duplicates_downlink_at_controller_inst+k)->Link_f_inst[k].Link_fi_inst[i].Link_values[j] = 0.0;
				(Link_duplicates_SecondTime_downlink_at_controller_inst+k)->Link_f_inst[k].Link_fi_inst[i].Link_values[j] = 0.0;
				(Link_duplicates_SecondTime_uplink_at_controller_inst+k)->Link_f_inst[k].Link_fi_inst[i].Link_values[j] = 0.0;
				(LLDP_timestamp_at_controller_inst+k)->Link_f_inst[k].Link_fi_inst[i].Link_values[j] = 0.0;
			}
		}
	}

}


NS_LOG_COMPONENT_DEFINE ("vanet");

