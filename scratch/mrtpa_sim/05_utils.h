// ============================================================
// SECTION 5: Utility and Initialization Functions
// ============================================================
// Contents:
//   clear_delta_at_controller()    - zero out delta matrices
//   clear_delta_at_nodes()         - zero out node-level deltas
//   print_management_data()        - debug print management state
//   clear_routing_data_at_nodes()  - reset per-node routing tables
//   clear_data_at_nodes()          - clear received data buffers
//   initialize_all_scores()        - reset all performance score arrays
//   execCmd(cmd)                   - execute shell command, return stdout
//   extractValue(json, key)        - extract value from JSON string
// ============================================================
void clear_delta_at_controller(struct delta_f * nd1)
{
	for(uint32_t i=0; i<2*flows;i++)
	{
		(nd1+i)->source_f = 0;
		(nd1+i)->destination_f = 0;
		(nd1+i)->flow_id = 0;
		for(uint32_t j=0;j<total_size;j++)
		{
			for(uint32_t k=0;k<total_size;k++)
			{
				(nd1+i)->delta_fi_inst[j].delta_values[k] = 0.0;
			}
		}
	}
	cout<<"Solution at controller cleared"<<endl;
}

void clear_delta_at_nodes(struct delta_f * nd1)
{
	for(uint32_t i=0; i<2*flows;i++)
	{
		(nd1+i)->source_f = 0;
		(nd1+i)->destination_f = 0;
		(nd1+i)->flow_id = 0;
		for(uint32_t j=0;j<total_size;j++)
		{
			for(uint32_t k=0;k<total_size;k++)
			{
				(nd1+i)->delta_fi_inst[j].delta_values[k] = 0.0;
			}
		}
	}
	cout<<"Solution at nodes cleared at "<<Now().GetSeconds()<<endl;
}

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


