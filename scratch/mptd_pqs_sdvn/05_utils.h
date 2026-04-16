// ============================================================
// SECTION 5: Utility and Initialization Functions
// MPTD-PQS: Dual-Mode Detection for MP and TP Attacks in SDVN
// ============================================================
// Contents:
//   execCmd(cmd)                   - execute shell command, return stdout
//   extractValue(json, key)        - extract value from JSON string
//   calculate_acceleration()       - compute acceleration from velocities
//   Structs: data_at_nodes, data_at_manager, routing_data_at_nodes, etc.
//   (Structs kept until 08/11 headers are rewritten in Stages 4 & 6)
// ============================================================
// Removed: clear_delta_at_controller(), clear_delta_at_nodes()
//   — used delta_f struct which was legacy LDA flow optimization (Stage 3)

// ── Legacy stub for 07_security.h functions (remove when 07 is cleaned) ───
// downlink_rest_data was in old LDA codebase; kept as minimal stub so that
// function signatures in 07_security.h compile without modification.
// All DS/HMAC fields are uint8_t* as in the original LDA codebase.
struct downlink_rest_data {
    uint8_t  _stg = 0, _rsnid = 0, _rspid = 0;
    uint32_t _snid = 0, _spid = 0, _dnid = 0, _dpid = 0;
    uint8_t  _hmac[81]    = {};
    uint8_t  _hmac_key[81]= {};
    uint8_t  _hmac1[32]   = {};
    uint8_t  _hmac2[32]   = {};
    uint8_t  _dpk1[256]   = {};
    uint8_t  _dpk2[1280]  = {};
    uint8_t  _dpk3[1280]  = {};
    uint8_t  _ds1[16]     = {};
    uint8_t  _ds2[16]     = {};
    uint8_t  _ds[64]      = {};
    uint8_t  _dpk[64]     = {};
    uint8_t*  stage              = &_stg;
    uint8_t*  raw_source_nodeid  = &_rsnid;
    uint8_t*  raw_source_portid  = &_rspid;
    uint32_t* source_nodeid      = &_snid;
    uint32_t* source_portid      = &_spid;
    uint32_t* destination_nodeid = &_dnid;
    uint32_t* destination_portid = &_dpid;
    uint8_t*  HMAC           = _hmac;
    uint8_t*  HMAC_key       = _hmac_key;
    uint8_t*  HMAC1          = _hmac1;
    uint8_t*  HMAC2          = _hmac2;
    uint8_t*  DS_public_key1 = _dpk1;
    uint8_t*  DS_public_key2 = _dpk2;
    uint8_t*  DS_public_key3 = _dpk3;
    uint8_t*  DS1            = _ds1;
    uint8_t*  DS2            = _ds2;
    uint8_t*  DS             = _ds;
    uint8_t*  DS_public_key  = _dpk;
    uint32_t  casted_raw_source_nodeid      = 0;
    uint32_t  casted_raw_source_portid      = 0;
    uint32_t  casted_destination_nodeid     = 0;
    uint32_t  casted_raw_destination_portid = 0;
};

struct demanding_flow_struct_nodes
{
	uint32_t source;
	uint32_t destination;
	uint32_t f_size;
	uint32_t p_size;
	uint32_t qos;
};

struct demanding_flow_struct_controller
{
	uint32_t source;
	uint32_t destination;
	uint32_t f_size;
	uint32_t p_size;
	uint32_t qos;
};

struct controller_data
{
	uint32_t B;
	uint32_t neighborsize;
	//double frequency;
	//uint32_t datasize;
	uint32_t neighborid[max];
	double lastupdated;
	//uint32_t combined_cost[max];
};


struct routing_data_at_nodes
{
	Vector acceleration;
	Vector velocity;
	Vector position;
	uint32_t nodeid;
};

struct routing_data_at_controller
{
	Vector acceleration;
	Vector velocity;
	Vector position;
	uint32_t nodeid;
};


struct neighbor_data
{
	uint32_t neighborid[max];
	uint32_t neighborportid[max];
	//uint32_t combined_cost[max];
	Time timestamp[max];
};

struct set_of_neighbors
{
	uint32_t neighbors[max];
};

struct data_at_nodes
{
	Time timestamp[max];
	Vector acceleration[max];
	Vector velocity[max];
	Vector position[max];
	uint32_t nodeid[max];
	uint32_t portid[max];
	uint8_t HMAC[max][64];
	struct set_of_neighbors neighbor_set[max];
	bool neighbors_changed[max];
};

struct data_at_manager
{
	Time timestamp;
	Vector acceleration;
	Vector velocity;
	Vector position;
	uint32_t nodeid;
	uint32_t portid;
	uint8_t HMAC[total_size][64];
	Vector aggposition [total_size];
	uint32_t source_node[total_size];
};

struct demanding_flow_struct_nodes demanding_flow_struct_nodes_inst[2*flows];
struct demanding_flow_struct_controller demanding_flow_struct_controller_inst[2*flows];

struct routing_data_at_nodes routing_data_at_nodes_inst[total_size];
struct routing_data_at_controller routing_data_at_controller_inst[total_size];


struct data_at_nodes data_at_nodes_inst[total_size+2];
struct data_at_manager data_at_manager_inst[total_size+2];

void print_management_data()
{
	for(uint32_t i=0;i<total_size+2;i++)
	{
		cout<<"i ="<<i<<"node id "<<(data_at_manager_inst+i)->nodeid<<"acceleration "<<(data_at_manager_inst+i)->acceleration<<"velocity "<<(data_at_manager_inst+i)->velocity<<"position "<<(data_at_manager_inst+i)->position<<"timestamp "<<(data_at_manager_inst+i)->timestamp<<endl;
	}
}

void clear_routing_data_at_nodes(struct routing_data_at_nodes * nd1)
{
	nd1->acceleration = Vector(0,0,0);
	nd1->velocity = Vector(0,0,0);
	nd1->position = Vector(0,0,0);
	nd1->nodeid = large;
}

void clear_data_at_nodes(struct data_at_nodes * nd1)
{
	for(uint32_t i=0; i<max;i++)
	{
		nd1->timestamp[i] = Simulator::Now();
		nd1->acceleration[i] = Vector(0,0,0);
		nd1->velocity[i] = Vector(0,0,0);
		nd1->position[i] = Vector(0,0,0);
		nd1->nodeid[i] = large;
		nd1->portid[i] = large;
		memset(nd1->HMAC[i], 0, 64);
		for(uint32_t j=0;j<max;j++)
		{
			nd1->neighbor_set[i].neighbors[j] = large;
		}
		nd1->neighbors_changed[i] = false;
	}
}

Vector previous_velocity_dsrc[total_size];

Vector calculate_acceleration (Vector initial_vel, Vector final_vel, double time)
{
	double ax = (final_vel.x - initial_vel.x)/time;
	double ay = (final_vel.y - initial_vel.y)/time;
	double az = (final_vel.z - initial_vel.z)/time;
	Vector acceleration;
	acceleration.x = ax;
	acceleration.y = ay;
	acceleration.z = az;
	return acceleration;
}



#include <cstdlib>
#include <string>

void initialize_all_scores()
{
	
	
}

std::string execCmd(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);

    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

#include <iostream>
#include <string>
#include <algorithm>

std::string extractValue(const std::string& json, const std::string& key) {
    std::string pattern = "\"" + key + "\":";
    size_t start = json.find(pattern);
    if (start == std::string::npos) return "";

    start += pattern.length();

    // Skip whitespace and possible quote
    while (start < json.size() && (json[start] == ' ' || json[start] == '\"')) start++;

    std::string value;
    bool escape = false;

    if (json[start] == '{') {
        // Handle nested JSON object
        int braceCount = 0;
        for (size_t i = start; i < json.size(); ++i) {
            char c = json[i];
            if (c == '{') braceCount++;
            if (c == '}') braceCount--;
            value.push_back(c);
            if (braceCount == 0) break;
        }
    } else {
        // Handle normal quoted string
        for (size_t i = start; i < json.size(); ++i) {
            char c = json[i];
            if (c == '\\' && !escape) {
                escape = true;
                continue;
            }
            if (c == '\"' && !escape) {
                break; // end of string
            }
            value.push_back(c);
            escape = false;
        }
    }

    return value;
}


