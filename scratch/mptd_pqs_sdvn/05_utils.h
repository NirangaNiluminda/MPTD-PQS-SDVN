// ============================================================
// SECTION 5: Utility and Initialization Functions
// MPTD-PQS: Dual-Mode Detection for MP and TP Attacks in SDVN
// ============================================================
// Contents:
//   execCmd(cmd)            — execute shell command, return stdout
//                             Used by: blockchain REST calls, IPFS API calls
//   extractValue(json, key) — extract value from JSON string
//                             Used by: blockchain response parsing,
//                             FUTURE: IPFS CID extraction from add response
//   data_at_nodes struct    — per-node beacon receive buffer (cleared in 12_main.h)
//   routing_data_at_nodes   — per-node routing state (cleared in 12_main.h)
//   clear_data_at_nodes()   — called by 12_main.h during init
//   clear_routing_data_at_nodes() — called by 12_main.h during init
// ============================================================

#include <cstdlib>
#include <string>
#include <iostream>
#include <algorithm>

// ── Shell command executor ────────────────────────────────────────────────────
// Used by blockchain REST calls in 06c_blockchain_api.h and 11_blockchain_setup.h.
// Will also be used for IPFS API calls (e.g., curl http://localhost:5001/api/v0/add).
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

// ── JSON value extractor ──────────────────────────────────────────────────────
// Parses a flat or nested JSON string and returns the value for a given key.
// KEEP: needed for parsing IPFS API responses (e.g., extracting CID hash
// from {"Name":"file","Hash":"QmXxx","Size":"123"}) and blockchain responses.
std::string extractValue(const std::string& json, const std::string& key) {
    std::string pattern = "\"" + key + "\":";
    size_t start = json.find(pattern);
    if (start == std::string::npos) return "";

    start += pattern.length();

    // Skip whitespace and possible opening quote
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
        // Handle normal quoted string value
        for (size_t i = start; i < json.size(); ++i) {
            char c = json[i];
            if (c == '\\' && !escape) { escape = true; continue; }
            if (c == '\"' && !escape) break;
            value.push_back(c);
            escape = false;
        }
    }
    return value;
}

// ── Neighbor set struct (nested inside data_at_nodes) ─────────────────────────
struct set_of_neighbors {
    uint32_t neighbors[MPTD_MAX_NEIGHBORS];
};

// ── Per-node beacon receive buffer (cleared in 12_main.h init loop) ──────────
struct data_at_nodes {
    Time     timestamp[MPTD_MAX_NEIGHBORS];
    Vector   acceleration[MPTD_MAX_NEIGHBORS];
    Vector   velocity[MPTD_MAX_NEIGHBORS];
    Vector   position[MPTD_MAX_NEIGHBORS];
    uint32_t nodeid[MPTD_MAX_NEIGHBORS];
    uint32_t portid[MPTD_MAX_NEIGHBORS];
    uint8_t  HMAC[MPTD_MAX_NEIGHBORS][64];
    struct set_of_neighbors neighbor_set[MPTD_MAX_NEIGHBORS];
    bool     neighbors_changed[MPTD_MAX_NEIGHBORS];
};

struct data_at_nodes data_at_nodes_inst[total_size+2];

void clear_data_at_nodes(struct data_at_nodes *nd1)
{
    for (uint32_t i = 0; i < MPTD_MAX_NEIGHBORS; i++) {
        nd1->timestamp[i]    = Simulator::Now();
        nd1->acceleration[i] = Vector(0, 0, 0);
        nd1->velocity[i]     = Vector(0, 0, 0);
        nd1->position[i]     = Vector(0, 0, 0);
        nd1->nodeid[i]       = large;
        nd1->portid[i]       = large;
        memset(nd1->HMAC[i], 0, 64);
        for (uint32_t j = 0; j < MPTD_MAX_NEIGHBORS; j++)
            nd1->neighbor_set[i].neighbors[j] = large;
        nd1->neighbors_changed[i] = false;
    }
}

// ── Per-node routing state (cleared in 12_main.h init loop) ──────────────────
struct routing_data_at_nodes {
    Vector   acceleration;
    Vector   velocity;
    Vector   position;
    uint32_t nodeid;
};

struct routing_data_at_nodes routing_data_at_nodes_inst[total_size];

void clear_routing_data_at_nodes(struct routing_data_at_nodes *nd1)
{
    nd1->acceleration = Vector(0, 0, 0);
    nd1->velocity     = Vector(0, 0, 0);
    nd1->position     = Vector(0, 0, 0);
    nd1->nodeid       = large;
}
