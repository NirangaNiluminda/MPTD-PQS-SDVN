// ============================================================
// 11_blockchain_transmission.h — MPTD-PQS Blockchain & Attack Setup
//                                (Stage 10B cleanup)
// ============================================================
// Retained:
//   initialize_blockchain()   — start Hyperledger Fabric test-network (§3.3.4)
//   initialize_server()       — start Python REST API on port 3000
//   declare_attack_states()   — set per-attack-number flags + StoreAttackConfigToBlockchain
//   declare_attackers()       — assign malicious node status from attack_percentage
//   assign_controllers()      — assign controller/consortium IDs + trajectory_poisoning_malicious_nodes
//   assign_basic_keys()       — key distribution stub (only under routing_algorithm==4)
//   test_boolean()            — debug: print attack state of all nodes
//
// Removed: ~2700 lines of LDA routing (dijkstra, ECMP, DCMR, QRSDN, RLMR,
//          LLDP, B-matrix, adjacency matrix, centralized DSRC TX/RX, HMAC,
//          CallBWTRCBFromNS3, BCTES, and all routing stubs)
// ============================================================

// ── Forward declarations for stubs below (used by 12_main.h scheduler) ───────
void centralized_dsrc_data_unicast(Ptr<Node>, uint32_t, uint32_t, uint32_t);
void centralized_dsrc_data_broadcast(Ptr<NetDevice>, Ptr<Node>, uint32_t, uint32_t);

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

// ── declare_attack_states() — map attack_number → LDA flags + blockchain log ──
void declare_attack_states()
{
    if (attack_number == 6) {
        present_location_attack_nodes      = true;
        present_flooding_attack_nodes      = true;
        present_fabrication_attack_nodes   = true;
        present_MIM_attack_nodes           = true;
        present_vanishing_attack_nodes     = true;
        if (controller_malicious_assumption) {
            present_flooding_attack_controllers    = true;
            present_fabrication_attack_controllers = true;
            present_MIM_attack_controllers         = true;
            present_vanishing_attack_controllers   = true;
        }
    } else if (attack_number == 1) {
        // TP-S1: Compromised RSU trajectory poisoning (§3.4.1, Figure 3.1)
        // Attacker = RSU (trajectory_poisoning_malicious_nodes set in assign_controllers)
        // NO malicious vehicles — all vehicles are honest in this scenario
        present_location_attack_nodes    = false;
        present_flooding_attack_nodes    = false;
        present_fabrication_attack_nodes = false;
        present_MIM_attack_nodes         = false;
        present_vanishing_attack_nodes   = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
    } else if (attack_number == 2) {
        // TP-S2: Malicious vehicle trajectory poisoning (§3.4.1, Figure 3.2)
        // Attacker = vehicle; sends fake but realistic trajectory data
        present_location_attack_nodes    = true;
        present_flooding_attack_nodes    = false;
        present_fabrication_attack_nodes = false;
        present_MIM_attack_nodes         = false;
        present_vanishing_attack_nodes   = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
    } else if (attack_number == 3) {
        // MP-S1: Sybil via compromised RSU — ghost vehicle ID injection (§3.4.2, Figure 3.4)
        // Attacker = RSU; generates additional fake vehicle identities
        // NO malicious vehicles — all vehicles are honest
        present_location_attack_nodes      = false;
        present_flooding_attack_nodes      = false;
        present_fabrication_attack_nodes   = false;
        present_MIM_attack_nodes           = false;
        present_vanishing_attack_nodes     = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
    } else if (attack_number == 4) {
        // MP-S2: Sybil via malicious vehicle impersonation (§3.4.2, Figure 3.5)
        // Attacker = vehicle; sends extra beacons with stolen vehicle IDs
        present_location_attack_nodes    = false;
        present_flooding_attack_nodes    = false;
        present_fabrication_attack_nodes = false;
        present_MIM_attack_nodes         = true;   // reuse MIM flag for identity theft
        present_vanishing_attack_nodes   = false;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        present_vanishing_attack_controllers   = false;
    } else if (attack_number == 5) {
        present_location_attack_nodes    = false;
        present_flooding_attack_nodes    = false;
        present_fabrication_attack_nodes = false;
        present_MIM_attack_nodes         = false;
        present_vanishing_attack_nodes   = true;
        present_flooding_attack_controllers    = false;
        present_fabrication_attack_controllers = false;
        present_MIM_attack_controllers         = false;
        if (controller_malicious_assumption) present_vanishing_attack_controllers = true;
    } else if (attack_number == 7) {
        // MP-S4: Coordinated multi-source — all attack types simultaneously (§3.2.4)
        present_location_attack_nodes      = true;
        present_flooding_attack_nodes      = true;
        present_fabrication_attack_nodes   = true;
        present_MIM_attack_nodes           = true;
        present_vanishing_attack_nodes     = true;
        if (controller_malicious_assumption) {
            present_flooding_attack_controllers    = true;
            present_fabrication_attack_controllers = true;
            present_MIM_attack_controllers         = true;
            present_vanishing_attack_controllers   = true;
        }
    }

    if (routing_algorithm == 4) {
        StoreAttackConfigToBlockchain(
            attack_number,
            present_location_attack_nodes,
            present_flooding_attack_nodes,
            present_fabrication_attack_nodes,
            present_MIM_attack_nodes,
            present_vanishing_attack_nodes,
            present_flooding_attack_controllers,
            present_fabrication_attack_controllers,
            present_MIM_attack_controllers,
            present_vanishing_attack_controllers,
            controller_malicious_assumption);
    }
}

// ── declare_attackers() — assign per-node malicious status ───────────────────
void declare_attackers()
{
    for (uint32_t i = 0; i < total_size; i++) {
        bool attacking_state = GetBooleanWithProbability(attack_percentage, i);

        location_malicious_nodes[i]    = present_location_attack_nodes    ? attacking_state : false;
        flooding_malicious_nodes[i]    = present_flooding_attack_nodes    ? attacking_state : false;
        fabrication_malicious_nodes[i] = present_fabrication_attack_nodes ? attacking_state : false;
        MIM_malicious_nodes[i]         = present_MIM_attack_nodes         ? attacking_state : false;
        vanishing_malicious_nodes[i]   = present_vanishing_attack_nodes   ? attacking_state : false;

        if (routing_algorithm == 4) {
            StoreNodeAttackStateToBlockchain(
                i, attack_percentage,
                location_malicious_nodes[i],
                flooding_malicious_nodes[i],
                fabrication_malicious_nodes[i],
                MIM_malicious_nodes[i],
                vanishing_malicious_nodes[i],
                trajectory_poisoning_malicious_nodes[i]);
        }
    }

    // Controller malicious assignment (by attack_percentage threshold)
    auto set_ctrl = [&](bool* arr, bool flag) {
        bool v0 = false, v1 = false, v2 = false;
        if (flag) {
            if      (attack_percentage >= 10)  v0 = true;
            if      (attack_percentage >= 35)  v1 = true;
            if      (attack_percentage >= 67)  v2 = true;
        }
        arr[0] = v0; arr[1] = v1; arr[2] = v2; arr[3] = false;
    };
    set_ctrl(flooding_malicious_controllers,    present_flooding_attack_controllers);
    set_ctrl(fabrication_malicious_controllers, present_fabrication_attack_controllers);
    set_ctrl(MIM_malicious_controllers,         present_MIM_attack_controllers);
    set_ctrl(vanishing_malicious_controllers,   present_vanishing_attack_controllers);
}

// ── declare_compromised_rsus() — set which RSUs are compromised ───────────────
// Called for attack_number 1 (TP-S1) and 3 (MP-S1) where the RSU is attacker.
// Uses attack_percentage to determine how many of the 4 RSUs are compromised:
//   10–33%  → 1 RSU (RSU 0)
//   34–66%  → 2 RSUs (RSU 0, 1)
//   67–100% → 3 RSUs (RSU 0, 1, 2)
void declare_compromised_rsus()
{
    compromised_rsu[0] = compromised_rsu[1] = compromised_rsu[2] = compromised_rsu[3] = false;

    if (attack_number != 1 && attack_number != 3) return; // only RSU-level attacks

    if (attack_percentage >= 10)  compromised_rsu[0] = true;
    if (attack_percentage >= 34)  compromised_rsu[1] = true;
    if (attack_percentage >= 67)  compromised_rsu[2] = true;

    for (int r = 0; r < 4; r++) {
        if (compromised_rsu[r])
            cout << "[RSU-COMPROMISE] RSU " << r << " is COMPROMISED"
                 << " (attack=" << attack_number
                 << " pct=" << attack_percentage << "%)" << endl;
    }
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

        for (uint32_t j = 0; j < total_size; j++) {
            timestamp_stored[i][j][0] = Simulator::Now().GetSeconds();
            timestamp_stored[i][j][1] = Simulator::Now().GetSeconds();
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

// ── assign_basic_keys() — LDA RSA/ECC key distribution (routing_algorithm==4 only) ──
void assign_basic_keys()
{
    // All Simulator::Schedule calls for LDA_security/LDA_PQ_security are
    // commented out — those functions no longer exist in MPTD-PQS mode.
    // This stub satisfies the call in 12_main.h under routing_algorithm==4.
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
        cout << "For " << j << "th node, location attack state is "      << location_malicious_nodes[j]    << endl;
        cout << "For " << j << "th node, flooding attack state is "      << flooding_malicious_nodes[j]    << endl;
        cout << "For " << j << "th node, fabrication attack state is "   << fabrication_malicious_nodes[j] << endl;
        cout << "For " << j << "th node, MIM attack state is "           << MIM_malicious_nodes[j]         << endl;
        cout << "For " << j << "th node, vanishing attack state is "     << vanishing_malicious_nodes[j]   << endl;
        cout << "Node " << j << " controller ID " << node_controller_ID[j] << endl;
    }
}

// ── Routing stubs (satisfy 12_main.h scheduler calls in routing_test paths) ──
void generate_adjacency_matrix() {}
void generate_B_matrix()         {}

void centralized_dsrc_data_broadcast(Ptr<NetDevice>, Ptr<Node>, uint32_t, uint32_t) {}
void centralized_dsrc_data_unicast(Ptr<Node>, uint32_t, uint32_t, uint32_t) {}
void vehicle_send_to_nearest_rsu(uint32_t, double) {}

// ── send_dsrc_data_unicast stub — satisfies forward decl in 08_beacon_handlers.h
void send_dsrc_data_unicast(Ptr<Node>, uint32_t, uint32_t, uint32_t) {}

// ── Blockchain routing stubs (called from 12_main.h under routing_algorithm==4) ──────────────
void initialize_bmatrix()                              {}
void CallBWTRCBFromNS3(uint32_t, std::string)          {}
void BCTES(uint32_t, uint32_t, std::string, std::string) {}
