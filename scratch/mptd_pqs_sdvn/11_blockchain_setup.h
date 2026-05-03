// ============================================================
// 11_blockchain_setup.h — MPTD-PQS Blockchain & Controller Setup
// Renamed + cleaned from 11_blockchain_transmission.h (Stage 10B cleanup)
// ============================================================
// Retained:
//   initialize_blockchain()  — start Hyperledger Fabric test-network (§3.3.4)
//   initialize_server()      — start Python REST API on port 3000
//   assign_controllers()     — assign controller/consortium IDs + RSU malicious flags
//   escapeQuotes()           — helper for JSON REST calls
//   assign_basic_keys()      — key distribution stub (routing_algorithm==4 only)
//   test_boolean()           — debug: print attack state of all nodes
//
// Removed vs 11_blockchain_transmission.h:
//   generate_adjacency_matrix(), generate_B_matrix()      — LDA routing stubs
//   centralized_dsrc_data_broadcast/unicast()             — LDA routing stubs
//   vehicle_send_to_nearest_rsu()                         — LDA routing stub
//   send_dsrc_data_unicast()                              — LDA routing stub
//   initialize_bmatrix(), CallBWTRCBFromNS3(), BCTES()    — Blockchain LDA stubs
//   Forward declarations for removed stubs
//   timestamp_stored loop in assign_controllers()         — LDA HMAC legacy
// ============================================================

// ── initialize_blockchain() — start Hyperledger Fabric (§3.3.4) ──────────────
void initialize_blockchain()
{
    cout << "Initializing blockchain (Hyperledger Fabric test-network with CCAAS)" << endl;
    const char* fabric_dir   = FAB_ROOT "/test-network";
    const char* rest_api_dir = FAB_ROOT "/trajectory-rest-api";

    std::string check_cmd = "docker ps --filter name=peer0.org1 --format '{{.Names}}' 2>/dev/null";
    std::string result    = execCmd(check_cmd);

    if (result.find("peer0.org1") != std::string::npos) {
        cout << "[BLOCKCHAIN] Fabric test-network already running." << endl;
    } else {
        cout << "[BLOCKCHAIN] Starting Fabric test-network..." << endl;
        std::string cmd_down = "bash -c 'cd " + std::string(fabric_dir) + " && ./network.sh down'";
        system(cmd_down.c_str());
        std::string cmd_up = "bash -c 'cd " + std::string(fabric_dir) +
                             " && ./network.sh up createChannel -c mychannel -ca'";
        system(cmd_up.c_str());
        std::string cmd_cc = "bash -c 'cd " + std::string(fabric_dir) +
                             " && ./network.sh deployCCAAS -ccn trajectory -ccp ../trajectory-chaincode'";
        system(cmd_cc.c_str());
    }

    std::string api_result = execCmd("curl -s http://localhost:3000/health 2>/dev/null");
    if (api_result.find("ok") != std::string::npos) {
        cout << "[BLOCKCHAIN] REST API already running on port 3000." << endl;
    } else {
        cout << "[BLOCKCHAIN] Starting REST API server..." << endl;
        std::string cmd_api = "bash -c 'cd " + std::string(rest_api_dir) + " && python3 server.py &'";
        system(cmd_api.c_str());
        sleep(2);
    }
    cout << "[BLOCKCHAIN] Initialization complete." << endl;
}

// ── escapeQuotes() — helper for JSON REST calls ───────────────────────────────
std::string escapeQuotes(const std::string& input)
{
    std::string out;
    for (char c : input) {
        if (c == '"') out += '\\';
        out += c;
    }
    return out;
}

// ── initialize_server() — start Python REST API on port 3000 ─────────────────
void initialize_server()
{
    const char* rest_api_dir = FAB_ROOT "/trajectory-rest-api";
    std::string check_api = execCmd("curl -s http://localhost:3000/health 2>/dev/null");
    if (check_api.find("ok") != std::string::npos) {
        std::cout << "[SERVER] REST API already running on port 3000." << std::endl;
    } else {
        std::string cmd = "bash -c 'cd " + std::string(rest_api_dir) +
                          " && nohup python3 server.py >> /tmp/restapi.log 2>&1 &'";
        system(cmd.c_str());
        ::sleep(2);
        std::cout << "[SERVER] Python REST API started." << std::endl;
    }
    std::cout << "Server started" << endl;
}

// ── assign_controllers() — assign node→controller + RSU malicious flags ──────
void assign_controllers()
{
    cout << "DEBUG: assign_controllers called. attack_number=" << attack_number << endl;
    for (uint32_t i = 0; i < total_size; i++) {
        if      (i < uint32_t(0.25 * total_size)) { node_controller_ID[i] = 0; assigned_consortium_ID[i] = 0; }
        else if (i < uint32_t(0.50 * total_size)) { node_controller_ID[i] = 1; assigned_consortium_ID[i] = 1; }
        else if (i < uint32_t(0.75 * total_size)) { node_controller_ID[i] = 2; assigned_consortium_ID[i] = 2; }
        else                                       { node_controller_ID[i] = 3; assigned_consortium_ID[i] = 3; }

        // RSU nodes: malicious status from attack_percentage
        if (i >= N_Vehicles && i < (N_Vehicles + N_RSUs)) {
            trajectory_poisoning_malicious_nodes[i] = GetBooleanWithProbability(attack_percentage, i);
            cout << "[MRTPA] RSU node " << i << " malicious="
                 << trajectory_poisoning_malicious_nodes[i]
                 << " (attack_percentage=" << attack_percentage << "%)" << endl;
        } else {
            trajectory_poisoning_malicious_nodes[i] = false;
        }

        if (routing_algorithm == 4) {
            StoreControllerAssignmentToBlockchain(
                i, node_controller_ID[i], assigned_consortium_ID[i],
                trajectory_poisoning_malicious_nodes[i]);
        }
        cout << "node " << i << " controller id " << node_controller_ID[i]
             << " consortium id " << assigned_consortium_ID[i] << endl;
    }
}

// ── Legacy routing stubs — still called by 12_main.h scheduler ───────────────
// These were in 11_blockchain_transmission.h. Kept as empty stubs since
// 12_main.h is UNCHANGED. All are dead code when routing_test=true.
void centralized_dsrc_data_broadcast(Ptr<NetDevice>, Ptr<Node>, uint32_t, uint32_t) {}
void centralized_dsrc_data_unicast(Ptr<Node>, uint32_t, uint32_t, uint32_t)         {}
void vehicle_send_to_nearest_rsu(uint32_t, double)                                  {}
void send_dsrc_data_unicast(Ptr<Node>, uint32_t, uint32_t, uint32_t)                {}
void generate_adjacency_matrix()                                                     {}
void generate_B_matrix()                                                             {}
void initialize_bmatrix()                                                            {}
void CallBWTRCBFromNS3(uint32_t, std::string)                                        {}
void BCTES(uint32_t, uint32_t, std::string, std::string)                             {}

// ── assign_basic_keys() — LDA RSA/ECC key distribution stub ──────────────────
// Only active when routing_algorithm==4. All crypto functions removed in Stage 10B.
void assign_basic_keys()
{
    cout << "[assign_basic_keys] stub — LDA crypto removed in Stage 10B" << endl;
}

// ── test_boolean() — debug: print per-node attack state ──────────────────────
void test_boolean()
{
    for (uint32_t i = 0; i < 101; i++) {
        for (uint32_t j = 0; j < 20; j++) {
            bool s = GetBooleanWithProbability(i, j);
            cout << "probability is " << i << " attack state is " << s
                 << " for source node " << j << endl;
        }
    }
    for (uint32_t j = 0; j < total_size; j++) {
        cout << "For " << j << "th node, tp_vehicle attack state is "         << tp_vehicle_nodes[j]        << endl;
        cout << "For " << j << "th node, heading_spoof attack state is "     << heading_spoof_nodes[j]     << endl;
        cout << "For " << j << "th node, rsu_fabrication attack state is "   << rsu_fabrication_nodes[j]   << endl;
        cout << "For " << j << "th node, sybil_mitm attack state is "        << sybil_mitm_nodes[j]        << endl;
        cout << "For " << j << "th node, beacon_suppression attack state is " << beacon_suppression_nodes[j] << endl;
        cout << "Node " << j << " controller ID " << node_controller_ID[j] << endl;
    }
}
