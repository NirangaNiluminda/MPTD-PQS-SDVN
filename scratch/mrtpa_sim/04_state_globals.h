// ============================================================
// SECTION 4: Runtime State Variables and Flow Structs
// ============================================================
// Contents:
//   - Timing/utilization variables: dsrc_utilization_time, packet_delay[]
//   - Packet timestamp arrays: dsrc_packet_initial_timestamp[], etc.
//   - Flow structs: Q_f, L_f, W_f, t_f, U_f, Y_f, delta_f, load_f
//   - Flow state instances: Q_at_controller_inst, delta_at_nodes_inst, etc.
//
// These hold per-packet timing and per-flow optimization state
// collected during the simulation run.
// ============================================================

#ifndef NS3_UDP_ARQ_APPLICATION_H
#define NS3_UDP_ARQ_APPLICATION_H


double dsrc_utilization_time = 0.0;
double lte_utilization_time = 0.0;
double ethernet_utilization_time = 0.0;
double packet_delay[total_size+2];
double packet_delay_dsrc[total_size+2];

double dsrc_packet_initial_timestamp[total_size+2];
double packet_initial_timestamp[total_size+2];
double dsrc_initial_timestamp;
double dsrc_LLDP_initial_timestamp;
double dsrc_LLDP_final_timestamp;
double lte_initial_timestamp;
double LLDP_initial_timestamp;
double ethernet_initial_timestamp;
double ethernet_LLDP_initial_timestamp;
double aodv_initial_timestamp[total_size+2];

double dsrc_packet_final_timestamp[total_size+2];
double packet_final_timestamp[total_size+2];
double dsrc_final_timestamp;
double dsrc_total_received_packets = 0.0;
double lte_final_timestamp;
double LLDP_final_timestamp;
double ethernet_final_timestamp;
double aodv_final_timestamp[total_size+2];

double max_distance[total_size+2];

struct Q_fi
{
	double Q_values[total_size];
};

struct Q_f
{
 	struct Q_fi Q_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct Q_f Q_at_controller_inst[2*flows];


struct L_fi
{
	double L_values[total_size];
};

struct L_f
{
 	struct L_fi L_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct L_f L_at_controller_inst[2*flows];


struct W_fi
{
	double W_values[total_size];
};

struct W_f
{
 	struct W_fi W_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct W_f W_at_controller_inst[2*flows];



struct Omega_fi
{
	double Omega_values[total_size];
};

struct Omega_f
{
 	struct Omega_fi Omega_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct Omega_f Omega_at_controller_inst[2*flows];



struct Theta_fi
{
	double Theta_values[total_size];
};

struct Theta_f
{
 	struct Theta_fi Theta_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct Theta_f Theta_at_controller_inst[2*flows];


struct T_fi
{
	double T_values[total_size];
};

struct T_f
{
 	struct T_fi T_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct T_f T_at_controller_inst[2*flows];


struct t_fi
{
	double t_values[total_size];
};

struct t_f
{
 	struct t_fi t_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct t_f t_at_controller_inst[2*flows];

struct U_fi
{
	double U_values[total_size];
};

struct U_f
{
 	struct U_fi U_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct U_f U_at_controller_inst[2*flows];


struct Y_fi
{
	double Y_values[total_size];
};

struct Y_f
{
 	struct Y_fi Y_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct Y_f Y_at_controller_inst[2*flows];

struct delta_fi
{
	double delta_values[total_size];
};

struct delta_f
{
 	struct delta_fi delta_fi_inst[total_size];
 	uint32_t source_f;
 	uint32_t destination_f;
 	uint32_t flow_id;
};

struct delta_f delta_at_controller_inst[2*flows];
struct delta_f delta_at_nodes_inst[2*flows];


struct load_f
{
	double load_f[total_size];
};

struct load_f load_at_nodes[2*flows];

#endif // NS3_UDP_ARQ_APPLICATION_H
