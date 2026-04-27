// ============================================================
// SECTION 6: MRTPA - Malicious RSU Trajectory Poisoning Attack
// ============================================================
// Implements Algorithm 1 from the paper:
// 'Mobility Pattern and Trajectory Poisoning Attacks in VANET'
//
// Blockchain Storage Functions (REST API to localhost:3000):
//   StoreAttackConfigToBlockchain()      - store attack setup to ledger
//   StoreNodeAttackStateToBlockchain()   - store per-node attacker role
//   StoreControllerAssignmentToBlockchain() - store controller assignment
//   StoreTrajectoryToBlockchain()        - store real + poisoned trajectory
//   StoreControlDecisionToBlockchain()   - store SDN control packet decision
//   FlagMaliciousOnBlockchain()          - flag node as malicious
//
// Core MRTPA Algorithm Functions:
//   PoisonTrajectory(position, velocity, acceleration, theta)
//     - Applies deviation: fake_pos = real_pos + theta * deviation
//     - theta = poisoning_intensity_theta (0.5 default)
//   EnforceRealism(position, velocity, acceleration)
//     - Bounds fake trajectory within realistic vehicle limits
//     - max_realistic_speed = 33.33 m/s (~120 km/h)
//     - max_realistic_acceleration = 4.0 m/s^2
//
// Attack Flow:
//   Phase 1: Vehicle sends real trajectory to RSU
//   Phase 2: RSU checks if malicious -> calls PoisonTrajectory
//            -> calls StoreTrajectoryToBlockchain (IsPoisoned=true)
//   The panel demo should show: compare IsPoisoned=true vs false records
// ============================================================
// ============================================================
// Attack State Blockchain Storage Functions
// Called by declare_attack_states(), declare_attackers(), assign_controllers()
// ============================================================

// StoreAttackConfigToBlockchain: stores global attack flags (declare_attack_states output)
void StoreAttackConfigToBlockchain(
    uint32_t attackNum,
    bool locNodes, bool floodNodes, bool fabNodes, bool mimNodes, bool vanNodes,
    bool floodCtrl, bool fabCtrl, bool mimCtrl, bool vanCtrl,
    bool ctrlMalAssumption)
{
    std::string body =
        "{\"attackNumber\":\"" + std::to_string(attackNum) + "\","
        "\"locNodes\":\""    + (locNodes   ? "true" : "false") + "\","
        "\"floodNodes\":\""  + (floodNodes ? "true" : "false") + "\","
        "\"fabNodes\":\""    + (fabNodes   ? "true" : "false") + "\","
        "\"mimNodes\":\""    + (mimNodes   ? "true" : "false") + "\","
        "\"vanNodes\":\""    + (vanNodes   ? "true" : "false") + "\","
        "\"floodCtrl\":\""   + (floodCtrl  ? "true" : "false") + "\","
        "\"fabCtrl\":\""     + (fabCtrl    ? "true" : "false") + "\","
        "\"mimCtrl\":\""     + (mimCtrl    ? "true" : "false") + "\","
        "\"vanCtrl\":\""     + (vanCtrl    ? "true" : "false") + "\","
        "\"ctrlMaliciousAssumption\":\"" + (ctrlMalAssumption ? "true" : "false") + "\"}";

    std::string curlCmd =
        "curl -s -X POST http://localhost:3000/api/attackconfig "
        "-H \"Content-Type: application/json\" "
        "-d '" + body + "'";
    std::cout << "[ATTACK_CFG] Storing attack config for attack_number=" << attackNum << " to blockchain" << std::endl;
    std::string resp = execCmd(curlCmd);
    std::cout << "[ATTACK_CFG] Response: " << resp << std::endl;
}

// StoreNodeAttackStateToBlockchain: stores per-node attacker role (declare_attackers output)
void StoreNodeAttackStateToBlockchain(
    uint32_t nodeIdx, int atkPct,
    bool isLocMal, bool isFloodMal, bool isFabMal,
    bool isMIMMal, bool isVanMal, bool isTrajMal)
{
    std::string body =
        "{\"nodeIndex\":\""        + std::to_string(nodeIdx) + "\","
        "\"attackPercentage\":\""  + std::to_string(atkPct)  + "\","
        "\"isLocMal\":\""          + (isLocMal   ? "true" : "false") + "\","
        "\"isFloodMal\":\""        + (isFloodMal ? "true" : "false") + "\","
        "\"isFabMal\":\""          + (isFabMal   ? "true" : "false") + "\","
        "\"isMIMMal\":\""          + (isMIMMal   ? "true" : "false") + "\","
        "\"isVanMal\":\""          + (isVanMal   ? "true" : "false") + "\","
        "\"isTrajMal\":\""         + (isTrajMal  ? "true" : "false") + "\"}";

    std::string curlCmd =
        "curl -s -X POST http://localhost:3000/api/nodeattackstate "
        "-H \"Content-Type: application/json\" "
        "-d '" + body + "'";
    std::string resp = execCmd(curlCmd);
    std::cout << "[NODE_ATK] Node " << nodeIdx
              << " locMal=" << isLocMal << " trajMal=" << isTrajMal
              << " → " << resp << std::endl;
}

// StoreControllerAssignmentToBlockchain: stores node-controller mapping (assign_controllers output)
void StoreControllerAssignmentToBlockchain(
    uint32_t nodeIdx, uint32_t ctrlID, uint32_t consID, bool isTrajPoisoner)
{
    std::string body =
        "{\"nodeIndex\":\""      + std::to_string(nodeIdx)  + "\","
        "\"controllerID\":\""   + std::to_string(ctrlID)   + "\","
        "\"consortiumID\":\""   + std::to_string(consID)   + "\","
        "\"isTrajPoisoner\":\"" + (isTrajPoisoner ? "true" : "false") + "\"}";

    std::string curlCmd =
        "curl -s -X POST http://localhost:3000/api/assignment "
        "-H \"Content-Type: application/json\" "
        "-d '" + body + "'";
    std::string resp = execCmd(curlCmd);
    std::cout << "[ASSIGN] Node " << nodeIdx
              << " → controller=" << ctrlID << " consortium=" << consID
              << " trajPoisoner=" << isTrajPoisoner
              << " → " << resp << std::endl;
}

// ============================================================
// MRTPA Functions: PoisonTrajectory, EnforceRealism, Blockchain Storage
// ============================================================

// PoisonTrajectory: Apply poisoning with intensity θ (Algorithm 1, Line 22)
// Generic: modifies position + velocity + acceleration simultaneously.
// Called directly only as fallback; prefer PoisonTrajectoryByType() below.
void PoisonTrajectory(Vector &position, Vector &velocity, Vector &acceleration, double theta)
{
    double t = Simulator::Now().GetSeconds();
    position.x    += theta * max_position_deviation     * sin(t * 0.7);
    position.y    += theta * max_position_deviation     * cos(t * 0.5);
    velocity.x    += theta * max_velocity_deviation     * sin(t * 1.3);
    velocity.y    += theta * max_velocity_deviation     * cos(t * 0.9);
    acceleration.x += theta * max_acceleration_deviation * cos(t * 1.7);
    acceleration.y += theta * max_acceleration_deviation * sin(t * 1.1);
}

// ============================================================
// PoisonTrajectoryByType — per-attack differentiated injection
// Paper §3.4.1–3.4.2 — each attack manipulates a DIFFERENT field
// so that distinct detection signatures fire per attack type.
//
//  attack 1 TP-S1 Location Spoofing  → position drift only
//                                       fires: TP-S1 (kinematic), TP-S4/S5 (drift)
//  attack 2 TP-S2 Flooding            → velocity/heading exaggeration
//                                       fires: TP-S2 (heading rate)
//  attack 3 TP-S3 Fabrication         → extreme acceleration injection
//                                       fires: TP-S3 (|a|>a_max)
//  attack 4 MP-S1 Sybil RSU           → position drift (density inflation handled by RSU)
//                                       fires: MP-S1 (identity density)
//  attack 5 MP-S2 Vanishing           → suppressed at send level (no poison here)
//                                       effect: FN — vehicle sends nothing
//  attack 6 MP-S4 Combined            → position + heading + acceleration together
//                                       fires: TP-S1, TP-S2, TP-S3, TP-S4/S5
//  attack 7 Coordinated Multi-Source  → phase-locked position drift across attackers
//                                       fires: TP-S1 + MP-S2 (sync timing)
// ============================================================
void PoisonTrajectoryByType(Vector &position, Vector &velocity, Vector &acceleration,
                             double theta, int atk_num)
{
    double t = Simulator::Now().GetSeconds();

    switch (atk_num)
    {
        case 1:
            // TP-S1: Location Spoofing — position drift only (Eq. 3.10)
            // Triggers: TP-S1 (kinematic), TP-S4 (dead-reckoning), TP-S5 (drift)
            position.x += theta * max_position_deviation * sin(t * 0.7);
            position.y += theta * max_position_deviation * cos(t * 0.5);
            break;

        case 2:
            // TP-S2: Flooding — abrupt heading + speed exaggeration (Eq. 3.11)
            // Triggers: TP-S2 (|Δθ| > ω_max·T_b), also TP-S4 via large velocity jump
            velocity.x += theta * max_velocity_deviation * 2.0 * sin(t * 3.1);
            velocity.y += theta * max_velocity_deviation * 2.0 * cos(t * 2.7);
            // Position also drifts in velocity direction (vehicle claims to be ahead)
            {
                double spd = std::sqrt(velocity.x * velocity.x + velocity.y * velocity.y);
                if (spd > 1e-6) {
                    position.x += theta * max_position_deviation * (velocity.x / spd);
                    position.y += theta * max_position_deviation * (velocity.y / spd);
                }
            }
            // Large Δv + Δpos → TP-S2 fires
            break;

        case 3:
            // TP-S3: Fabrication — extreme acceleration injection (Eq. 3.12)
            // Triggers: TP-S3 (|a_i| > a_max = 4 m/s²) — inject 2.5× the limit
            acceleration.x = theta * a_max * 2.5 * cos(t * 1.7);
            acceleration.y = theta * a_max * 2.5 * sin(t * 1.1);
            // Also slightly offset position so dead-reckoning diverges
            position.x += theta * max_position_deviation * 0.3 * sin(t * 0.4);
            break;

        case 4:
            // MP-S1: Sybil via RSU — position drift to inflate RSU density count
            // The RSU identity density check (Eq. 3.16) fires when too many
            // IDs appear in the coverage area. Position drift moves attacker
            // beacons across RSU boundaries, appearing as multiple identities.
            position.x += theta * max_position_deviation * 1.5 * sin(t * 0.3);
            position.y += theta * max_position_deviation * 1.5 * cos(t * 0.4);
            break;

        case 5:
            // MP-S2: Vanishing — NO trajectory modification here.
            // Beacon suppression is handled at the send level in 09_send_lte.h:
            // vanishing attackers skip sending every alternate beacon (50% drop).
            // Effect on metrics: FN increase (poisoned beacons not sent → not detected)
            break;

        case 6:
            // MP-S4: Combined / All-type attack (Eq. 3.19)
            // Simultaneously triggers TP-S1, TP-S2, TP-S3, TP-S4/S5
            position.x    += theta * max_position_deviation     * sin(t * 0.7);
            position.y    += theta * max_position_deviation     * cos(t * 0.5);
            velocity.x    += theta * max_velocity_deviation     * 1.5 * sin(t * 2.9);
            velocity.y    += theta * max_velocity_deviation     * 1.5 * cos(t * 2.3);
            acceleration.x = theta * a_max * 2.0               * cos(t * 1.7);
            acceleration.y = theta * a_max * 2.0               * sin(t * 1.1);
            break;

        case 7:
            // Coordinated Multi-Source — phase-locked drift across all attackers
            // All attacker vehicles use the SAME sinusoidal phase → identical
            // fake positions → triggers MP-S2 (sync timing) + TP-S1 (drift)
            // Phase offset = π/2 to distinguish from attack 1
            position.x += theta * max_position_deviation * sin(t * 0.7 + 1.5708);
            position.y += theta * max_position_deviation * cos(t * 0.5 + 1.5708);
            velocity.x += theta * max_velocity_deviation * 0.5 * sin(t * 0.7 + 1.5708);
            velocity.y += theta * max_velocity_deviation * 0.5 * cos(t * 0.5 + 1.5708);
            break;

        default:
            // Fallback: generic full-field poisoning
            PoisonTrajectory(position, velocity, acceleration, theta);
            break;
    }
}

// EnforceRealism: Clamp poisoned values to physically plausible ranges (Algorithm 1, Line 23)
// Ensures poisoned data doesn't trigger simple anomaly detectors
void EnforceRealism(Vector &position, Vector &velocity, Vector &acceleration)
{
    // Clamp position to simulation area bounds (avoid std::max/std::min due to #define max)
    position.x = (position.x < min_position_x) ? min_position_x : ((position.x > max_position_x) ? max_position_x : position.x);
    position.y = (position.y < min_position_y) ? min_position_y : ((position.y > max_position_y) ? max_position_y : position.y);

    // Clamp velocity magnitude to realistic vehicle speed
    double speed = sqrt(velocity.x * velocity.x + velocity.y * velocity.y + velocity.z * velocity.z);
    if (speed > max_realistic_speed)
    {
        double scale = max_realistic_speed / speed;
        velocity.x *= scale;
        velocity.y *= scale;
        velocity.z *= scale;
    }

    // Clamp acceleration magnitude
    double accel_mag = sqrt(acceleration.x * acceleration.x + acceleration.y * acceleration.y + acceleration.z * acceleration.z);
    if (accel_mag > max_realistic_acceleration)
    {
        double scale = max_realistic_acceleration / accel_mag;
        acceleration.x *= scale;
        acceleration.y *= scale;
        acceleration.z *= scale;
    }
}

// ============================================================
// STAGE 7: Post-Quantum Cryptography — TRS + Simulated CKKS FHE
// Placed here (before StoreTrajectoryToBlockchain) so types are available
// at the point of use. Definitions are logically part of §3.3.2-3.3.3.
// Paper §3.3.2 (TRS, Eq. 3.58-3.60) and §3.3.3 (FHE, Eq. 3.61-3.65)
// ============================================================

// ── Threshold Ring Signatures (TRS) ─────────────────────────────────────────
struct TRSSignature {
    std::string           aggregate_hash;
    std::vector<uint32_t> signers;
    bool                  verified;
    double                timestamp;
};

static uint32_t trs_fnv1a(const std::string &s)
{
    uint32_t h = 2166136261u;
    for (char c : s) { h ^= (uint8_t)c; h *= 16777619u; }
    return h;
}

TRSSignature generate_trs_aggregate(uint32_t rsu_id,
    double agg_pos_x, double agg_pos_y,
    double agg_speed, double /*agg_heading*/,
    double timestamp, uint32_t n_rsus = 4)
{
    TRSSignature sig;
    sig.aggregate_hash = "RSU"  + std::to_string(rsu_id)
                       + "_spd" + std::to_string((int)(agg_speed * 100))
                       + "_t"   + std::to_string((int)(timestamp  * 10));
    sig.timestamp = timestamp;
    (void)agg_pos_x; (void)agg_pos_y;

    int threshold = (int)(n_rsus / 2) + 1;
    uint32_t seed = trs_fnv1a(sig.aggregate_hash);
    std::vector<uint32_t> ring;
    ring.reserve(n_rsus);
    for (uint32_t r = 0; r < n_rsus; r++) ring.push_back(r);
    for (int i = (int)ring.size() - 1; i > 0; i--) {
        seed = seed * 1664525u + 1013904223u;
        int j = (int)(seed % (uint32_t)(i + 1));
        std::swap(ring[i], ring[j]);
    }
    for (int i = 0; i < threshold && i < (int)ring.size(); i++)
        sig.signers.push_back(ring[i]);

    sig.verified = false;
    return sig;
}

bool verify_trs(TRSSignature &sig, uint32_t n_rsus = 4)
{
    int threshold = (int)(n_rsus / 2) + 1;
    sig.verified  = ((int)sig.signers.size() >= threshold);
    return sig.verified;
}

// ── Simulated CKKS FHE ───────────────────────────────────────────────────────
struct FHECiphertext {
    double noisy_value;
    bool   valid;
};

static const double FHE_CKKS_NOISE_STD = 1e-6;

FHECiphertext fhe_encrypt_scalar(double value)
{
    static uint32_t fhe_seed = 987654321u;
    fhe_seed = fhe_seed * 1664525u + 1013904223u;
    double u1 = (double)((fhe_seed >> 8) & 0xFFFF) / 65536.0 + 1e-9;
    fhe_seed = fhe_seed * 1664525u + 1013904223u;
    double u2 = (double)((fhe_seed >> 8) & 0xFFFF) / 65536.0 + 1e-9;
    double noise = FHE_CKKS_NOISE_STD
                 * std::sqrt(-2.0 * std::log(u1))
                 * std::cos(2.0 * M_PI * u2);
    return FHECiphertext{value + noise, true};
}

FHECiphertext fhe_aggregate(const std::vector<FHECiphertext> &cts)
{
    if (cts.empty()) return FHECiphertext{0.0, false};
    double sum = 0.0;
    for (const auto &ct : cts) sum += ct.noisy_value;
    return FHECiphertext{sum / (double)cts.size(), true};
}

double fhe_decrypt_scalar(const FHECiphertext &ct)
{
    return ct.valid ? ct.noisy_value : 0.0;
}

// ── End Stage 7 PQ Crypto ────────────────────────────────────────────────────

// Store trajectory to blockchain via REST API (both legitimate and poisoned)
void StoreTrajectoryToBlockchain(std::string vehicleID, std::string rsuID,
    Vector position, Vector velocity, Vector acceleration,
    double timestamp, bool isPoisoned)
{
    std::string curlCmd =
        "curl -s -X POST http://localhost:3000/api/trajectory "
        "-H \"Content-Type: application/json\" "
        "-d '{\"vehicleID\":\"" + vehicleID + "\","
        "\"rsuID\":\"" + rsuID + "\","
        "\"posX\":\"" + std::to_string(position.x) + "\","
        "\"posY\":\"" + std::to_string(position.y) + "\","
        "\"posZ\":\"" + std::to_string(position.z) + "\","
        "\"velX\":\"" + std::to_string(velocity.x) + "\","
        "\"velY\":\"" + std::to_string(velocity.y) + "\","
        "\"velZ\":\"" + std::to_string(velocity.z) + "\","
        "\"accX\":\"" + std::to_string(acceleration.x) + "\","
        "\"accY\":\"" + std::to_string(acceleration.y) + "\","
        "\"accZ\":\"" + std::to_string(acceleration.z) + "\","
        "\"timestamp\":\"" + std::to_string(timestamp) + "\","
        "\"isPoisoned\":\"" + std::string(isPoisoned ? "true" : "false") + "\"}' "
        "> /dev/null 2>&1 &";

    cout << "[BLOCKCHAIN] Storing trajectory: Vehicle=" << vehicleID
         << " RSU=" << rsuID
         << " Poisoned=" << (isPoisoned ? "YES" : "NO")
         << " t=" << timestamp << "s" << endl;

    system(curlCmd.c_str());
    total_trajectories_stored_blockchain++;

    // ── Stage 7: PQ signing + encrypted speed aggregate ──────────────────────
    if (use_pq_crypto) {
        // TRS: RSU signs the trajectory aggregate hash (Paper §3.3.2, Eq. 3.58-3.60)
        uint32_t rsu_idx = 0;
        if (rsuID.size() > 3) {
            try { rsu_idx = (uint32_t)std::stoi(rsuID.substr(3)); } catch (...) {}
        }
        double spd = std::sqrt(velocity.x * velocity.x + velocity.y * velocity.y);
        TRSSignature sig = generate_trs_aggregate(
            rsu_idx, position.x, position.y, spd, 0.0, timestamp);
        verify_trs(sig);
        std::cout << "[TRS] Vehicle=" << vehicleID
                  << " RSU=" << rsuID
                  << " signers=" << sig.signers.size()
                  << " verified=" << (sig.verified ? "YES" : "NO")
                  << " hash=" << sig.aggregate_hash << "\n";

        // FHE: encrypt speed scalar (Paper §3.3.3, Eq. 3.61)
        FHECiphertext ct = fhe_encrypt_scalar(spd);
        std::cout << "[FHE] Vehicle=" << vehicleID
                  << " speed_enc=" << ct.noisy_value
                  << " (plaintext≈" << spd << ")\n";
    }
}

// Store control decision to blockchain
void StoreControlDecisionToBlockchain(std::string controllerID, std::string decision,
    double timestamp, std::string basedOnData)
{
    std::string curlCmd =
        "curl -s -X POST http://localhost:3000/api/control "
        "-H \"Content-Type: application/json\" "
        "-d '{\"controllerID\":\"" + controllerID + "\","
        "\"decision\":\"" + decision + "\","
        "\"timestamp\":\"" + std::to_string(timestamp) + "\","
        "\"basedOnData\":\"" + basedOnData + "\"}' "
        "> /dev/null 2>&1 &";

    system(curlCmd.c_str());
}

// Flag a malicious entity on the blockchain
void FlagMaliciousOnBlockchain(std::string entityID, std::string reason)
{
    std::string curlCmd =
        "curl -s -X POST http://localhost:3000/api/flag "
        "-H \"Content-Type: application/json\" "
        "-d '{\"entityID\":\"" + entityID + "\","
        "\"reason\":\"" + reason + "\"}' "
        "> /dev/null 2>&1 &";

    system(curlCmd.c_str());
}

// ============================================================
// Stage 6: SC-Trust + SC-Revoke Blockchain Calls
// Called by 08_beacon_handlers.h after each detection round
// ============================================================

// CallSCTrust: update per-vehicle trust score on Fabric ledger
// τ_i(t) = 0.3·τ_i(t-1) + 0.7·(1-Φ)  computed inside chaincode SCTrustUpdate
void CallSCTrust(uint32_t vehicleID, double phiScore, uint32_t sigMask,
                 bool isAnomaly, double timestamp)
{
    std::string body =
        "{\"vehicleID\":\""  + std::to_string(vehicleID)          + "\","
        "\"phiScore\":\""    + std::to_string(phiScore)            + "\","
        "\"sigMask\":\""     + std::to_string(sigMask)             + "\","
        "\"isAnomaly\":\""   + (isAnomaly ? "true" : "false")      + "\","
        "\"timestamp\":\""   + std::to_string(timestamp)           + "\"}";

    std::string cmd =
        "curl -s -X POST http://localhost:3000/api/sctrust"
        " -H 'Content-Type: application/json'"
        " -d '" + body + "' > /dev/null 2>&1 &";
    system(cmd.c_str());

    if (isAnomaly)
        std::cout << "[SC-TRUST] Vehicle " << vehicleID
                  << "  Φ=" << phiScore << "  isAnomaly=1" << std::endl;
}

// CallSCRevoke: write an immutable revocation record for a vehicle
// Triggered by 08_beacon_handlers.h when consecutive_anomaly reaches threshold
void CallSCRevoke(uint32_t vehicleID, const std::string &reason,
                  uint32_t rsuID, double timestamp)
{
    std::string body =
        "{\"vehicleID\":\""  + std::to_string(vehicleID)  + "\","
        "\"reason\":\""      + reason                      + "\","
        "\"rsuID\":\""       + std::to_string(rsuID)       + "\","
        "\"timestamp\":\""   + std::to_string(timestamp)   + "\"}";

    std::string cmd =
        "curl -s -X POST http://localhost:3000/api/screvoke"
        " -H 'Content-Type: application/json'"
        " -d '" + body + "' > /dev/null 2>&1 &";
    system(cmd.c_str());

    std::cout << "[SC-REVOKE] Vehicle " << vehicleID
              << " REVOKED by RSU " << rsuID
              << " reason=" << reason
              << " t=" << timestamp << "s" << std::endl;
}

// ============================================================
// End of MRTPA Functions
// ============================================================


void Store_timestamp(uint32_t cid, uint32_t nid, uint32_t pid) {
   
    double timestamp = Simulator::Now().GetSeconds();
    
    //bool rep_loc_true[size];

    std::string node_cur = "Node" + std::to_string(cid);
    std::string node_nex = "Node" + std::to_string(nid)+"Port" + std::to_string(pid);
    std::string timestamp_str = std::to_string(timestamp);

    // Compose full curl command
std::string sigJson = "{\"SigCur\":\"" + timestamp_str + "\",\"SigOth\":\"" + timestamp_str + "\"}";
std::string escapedSigJson;

// Escape quotes for JSON string
for (char c : sigJson) {
    if (c == '\"') escapedSigJson += "\\\"";
    else escapedSigJson += c;
}

std::string curlCmd =
    "curl -X POST \"http://localhost:3000/invoke/putauthStates?user=peer1@org1\" "
    "-H \"Content-Type: application/json\" "
    "-d '{\"args\": [\"" + node_cur + "\","
    "\"" + node_nex + "\","
    "\"EncryptedReputationValue\","
    "\"EncryptedLocationValue\","
    "\"" + escapedSigJson + "\","
    "\"ZKPSignatureValue\","
    "\"DSValue\","
    "\"true\"]}'";



    // Execute the curl command
    std::cout << "Executing:\n" << curlCmd << std::endl;
    system(curlCmd.c_str());
}


double timestamp_stored[total_size][total_size][2];


void Get_timestamp(uint32_t cid, uint32_t nid, uint32_t pid, std::string controllerid) {
    std::string node_cur = "Node" + std::to_string(cid);
    std::string node_nex = "Node" + std::to_string(nid) + "Port" + std::to_string(pid);

    std::string curlCmd =
        "curl -X POST \"http://localhost:3000/invoke/getauthStates?user=peer1@org1\" "
        "-H \"Content-Type: application/json\" "
        "-d '{"
        "\"args\": [\"" + controllerid + "\", "
        "\"" + node_cur + "\", "
        "\"" + node_nex + "\", "
        "\"" + controllerid + "\"]"
        "}'";

    std::cout << "Executing:\n" << curlCmd << std::endl;
    std::string response = execCmd(curlCmd);

    std::cout << "\nRaw Response:\n" << response << std::endl;

    // Step 1: extract the "result" JSON string
    std::string resultJson = extractValue(response, "result");

    // Remove backslashes (unescape the inner JSON string)
    resultJson.erase(std::remove(resultJson.begin(), resultJson.end(), '\\'), resultJson.end());

    std::cout << "\nInner JSON:\n" << resultJson << std::endl;

    // Step 2: extract actual values from inner JSON
    std::string encReput = extractValue(resultJson, "EncReput");
    std::string encLocat = extractValue(resultJson, "EncLocat");
    std::string sigNodeIDs = extractValue(resultJson, "SigNodeIDs");
    std::string sigZKP = extractValue(resultJson, "SigZKP");
    std::string dsPK = extractValue(resultJson, "DS_PK");

    std::cout << "\nExtracted Values:" << std::endl;
    std::cout << "EncReput: " << encReput << std::endl;
    std::cout << "EncLocat: " << encLocat << std::endl;
    std::cout << "SigNodeIDs: " << sigNodeIDs << std::endl;
    std::cout << "SigZKP: " << sigZKP << std::endl;
    std::cout << "DS_PK: " << dsPK << std::endl;

    // Optional: parse nested SigNodeIDs JSON
    std::string sigCur = extractValue(sigNodeIDs, "SigCur");
    std::string sigOth = extractValue(sigNodeIDs, "SigOth");
    if (!sigCur.empty() && !sigOth.empty()) {
        std::cout << "Nested SigCur: " << sigCur << std::endl;
        std::cout << "Nested SigOth: " << sigOth << std::endl;
    }
    
    try {
    float sigCurFloat = std::stof(sigCur);
    timestamp_stored[cid][nid][pid] = sigCurFloat; // store as float
	} 
	catch (const std::invalid_argument& e) 
	{
		std::cerr << "Invalid float conversion for SigCur: " << sigCur << std::endl;
	} catch (const std::out_of_range& e) 
	{
		std::cerr << "Float out of range for SigCur: " << sigCur << std::endl;
	}
}





void update_previous_velocity(Ptr <NetDevice> nd, Ptr <Node> node)
{
	
	Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (nd);
	Ptr <Node> ni = DynamicCast <Node> (node);
	//CustomDataTag tag;
	uint32_t nid = uint32_t(ni->GetId()) - 2;
	//packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	//cout<<"updating data from node "<<nid<<endl;
	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node->GetObject<MobilityModel>());
	Vector current_velocity = mdl->GetVelocity();
	previous_velocity_dsrc[nid] = current_velocity;
	//cout<<"updating velocity of node "<<nid<<"as "<<previous_velocity_dsrc[nid]<<"at time "<<Now().GetSeconds()<<endl;
}

// add_routing_data_at_nodes() removed in Stage 10 — LDA legacy, no references after Stage 2 cleanup


void add_demanding_flow_struct_nodes(struct demanding_flow_struct_nodes * nd1, uint32_t source, uint32_t destination, uint32_t x, uint32_t z, uint32_t q)
{	

	nd1->source = source;
	nd1->destination = destination;
	nd1->f_size = x;
	nd1->p_size = z;
	nd1->qos = q;
	//cout<<"updating flow with source as: "<<nd1->source<<"destination: "<<nd1->destination<<endl;
}	


void refresh_data_at_nodes(struct data_at_nodes * nd1)//If data is old, remove them
{
	for(uint32_t i=0; i<max;i++)
	{
		double elapsed_time = Simulator::Now().GetSeconds() - nd1->timestamp[i].GetSeconds();
		if(elapsed_time > (2.0*data_transmission_period))
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
				if((nd1->neighbor_set[i].neighbors[j]) != large)//If existing neighbor data is deleted, set neighbor changed to true.
				{
					nd1->neighbors_changed[i] = true;
				}
				nd1->neighbor_set[i].neighbors[j] = large;
			}
		}
	}
}

uint32_t empty_neighborset[max];

void initialize_empty()
{
	for (uint32_t i =0; i < max; i++)
	{
		empty_neighborset[i] = large;
	}
}


uint32_t get_size_of_data_at_nodes(struct data_at_nodes * nd1)
{
	uint32_t size = 0;
	for(uint32_t i=0; i<max;i++)
	{
		if((nd1->nodeid[i] != large) and (nd1->nodeid[i] < (total_size+2)) and (nd1->nodeid[i]>1))
		{
			size++;
		}
	}
	return size;
}

void add_received_data_at_nodes(struct data_at_nodes * nd1, uint8_t * HMAC, Vector pos, Vector vel, Vector acc, uint32_t nid, uint32_t * neighbor_set,uint32_t size, uint32_t pid)
{
	bool found = false;
	bool set = false;
	for(uint32_t i=0; i<max;i++)
	{
		//if node id is found, update it
		if ((found == false) and (nd1->nodeid[i]==nid))
		{
			nd1->timestamp[i] = Simulator::Now();
			nd1->acceleration[i] = acc;
			nd1->velocity[i] = vel;
			nd1->position[i] = pos;
			nd1->nodeid[i] = nid;
			nd1->portid[i] = pid;
			memcpy(nd1->HMAC[i], HMAC, 64);
			for(uint32_t j=0;j<max;j++)
			{
				if(j< size)
				{
					if((nd1->neighbor_set[i].neighbors[j]) != neighbor_set[j])//check whether any neighbor changed
					{
						nd1->neighbors_changed[i] = true;
					}
					nd1->neighbor_set[i].neighbors[j] = neighbor_set[j];
				}
				else
				{
					nd1->neighbor_set[i].neighbors[j] = large;
				}
			}
			found = true;
		}
	}
	
	for(uint32_t i=0; i<max;i++)
	{
		//if node id is not found, add at the first empty location
		if ((found==false) and (set == false) and (nd1->nodeid[i]==large))
		{
			nd1->timestamp[i] = Simulator::Now();
			nd1->acceleration[i] = acc;
			nd1->velocity[i] = vel;
			nd1->position[i] = pos;
			nd1->nodeid[i] = nid;
			nd1->portid[i] = pid;
			memcpy(nd1->HMAC[i], HMAC, 64);
			nd1->neighbors_changed[i] = true;
			for(uint32_t j=0;j<max;j++)
			{
				if(j< size)
				{
					nd1->neighbor_set[i].neighbors[j] = neighbor_set[j];
				}
				else
				{
					nd1->neighbor_set[i].neighbors[j] = large;
				}
			}
			set = true;
		}
	}	
}

void clear_data_at_manager(struct data_at_manager * nd1)
{
	nd1->timestamp = Simulator::Now();
	nd1->acceleration = Vector(0,0,0);
	nd1->velocity = Vector(0,0,0);
	nd1->position = Vector(0,0,0);
	nd1->nodeid = large;
	for(uint32_t i=0;i<total_size;i++)
	{
		memset(nd1->HMAC[i], 0, 64);
		nd1->aggposition[i] = Vector(0,0,0);
		nd1->source_node[i] = large;
	}
}

void clear_controllerdata(struct controller_data * nd1)
{
	nd1->B = large;
	nd1->neighborsize = large;
	//nd1->frequency = large;
	//nd1->datasize = large;
	for(uint32_t i=0; i<max;i++)
	{
		nd1->neighborid[i] = large;
		//nd1->combined_cost[i] = large;
	}
	nd1->lastupdated = Simulator::Now().GetSeconds();
}

struct neighbor_data neighbordata_inst[total_size+2];
struct controller_data con_data_inst[total_size+2];

double sum_of_nodeids = 0;
void nodeid_sum()
{
	sum_of_nodeids = 0;
	for (uint32_t i=2;i<total_size+2;i++)
	{
		sum_of_nodeids = sum_of_nodeids + i;
	}
}

double last_optimized_entropy = 0.0;

double calculate_network_entropy()
{
	double summation_veh = 0.0;
	double summation_rsu = 0.0;
	for (uint32_t i=0;i<total_size; i++)
	{
		if( con_data_inst[i+2].neighborsize != 0)
		{
			int vehicle_neighbors = 0;
			int rsu_neighbors = 0;
			for (uint32_t j=0;j<max;j++)
			{
				if((con_data_inst[i+2].neighborid[j]) != large)
				{
					if ((con_data_inst[i+2].neighborid[j]) < (N_Vehicles+2))
					{
						vehicle_neighbors++;
					}
					else if ((con_data_inst[i+2].neighborid[j]) < (total_size+2))
					{
						rsu_neighbors++;
					}
					
				}
			}
			if (vehicle_neighbors != 0)
			{
				summation_veh = summation_veh + log(vehicle_neighbors);
			}
			if (rsu_neighbors != 0)
			{
				summation_rsu = summation_rsu + log(rsu_neighbors);
			}
		}
	}
	double rsu_deno = 0.0;
	double entropy_rsu = 0.0;
	double veh_deno = 0.0;
	double entropy_veh = 0.0;
	if (N_RSUs >1)
	{
		rsu_deno = (N_RSUs*log(N_RSUs-1)) + (N_Vehicles*log(N_RSUs));
		entropy_rsu = (summation_rsu)/(rsu_deno);
	}
	if (N_Vehicles > 1)
	{
		veh_deno = (N_RSUs*log(N_Vehicles)) + (N_Vehicles*log(N_Vehicles-1));
		entropy_veh = (summation_veh)/(veh_deno);
	}
	double final_entropy = 0.5*(entropy_veh + entropy_rsu);
	return final_entropy;
		
}

void clear_neighbordata(struct neighbor_data * nd1)
{
	for(uint32_t i=0; i<max;i++)
	{
		nd1->neighborid[i] = large;
		//nd1->combined_cost[i] = large;
		nd1->timestamp[i] = Simulator::Now();
	}
}

void add_neighbor_info(struct neighbor_data * nd1, uint32_t node_id, uint32_t pid)
{
	bool setter = false;
	bool found = false;
	for(uint32_t i=0; i<max;i++)
	{
		if((nd1->neighborid[i] == node_id) and (found==false))//If node is already a neighbor, update timestamp and cost
		{
			nd1->timestamp[i] = Simulator::Now();
			nd1->neighborid[i] = node_id;
			nd1->neighborportid[i] = pid;
			//nd1->combined_cost[i] = combined_cost;
			found = true;
			//cout<<"found neighbor at index"<<i<<endl;
		}
	}
	
	for(uint32_t j=0; j<max;j++)
	{
		if((setter == false) and (found==false) and (nd1->neighborid[j] == large))// If node is not found, add it at the first empty location
		{
			nd1->timestamp[j] = Simulator::Now();
			nd1->neighborid[j] = node_id;
			nd1->neighborportid[j] = pid;
			//nd1->combined_cost[j] = combined_cost;
			setter = true;
			//cout<<"neighbor not found setting at index"<<j<<endl;
		}
	}

}

void refresh_neighbors(struct neighbor_data * nd1)
{
	uint32_t now = Simulator::Now().GetMilliSeconds();
	for(uint32_t i=0; i<max;i++)
	{
		uint32_t last_timestamp = nd1->timestamp[i].GetMilliSeconds();
		uint32_t difference = now - last_timestamp;
		double update_frequency = data_transmission_frequency;
		uint32_t period = 1.5*uint32_t(1000/update_frequency);
		//cout<<"difference"<<difference<<"period"<<period<<endl;
		if (difference > period)//If difference is greater than update period, we remove the node.
		{	
			//cout<<"removing old neighbor at index "<<i<<endl;
			nd1->neighborid[i] = large;
			//nd1->combined_cost[i] = large;
		}
	}
}

uint32_t getNeighborsize(struct neighbor_data * nd1)
{
	uint32_t  neighborsize = 0;
	for(uint32_t i=0; i<max;i++)
	{
		if((nd1->neighborid[i] != large) and (nd1->neighborid[i] > 1) and (nd1->neighborid[i] < (total_size+2)))
		{
			neighborsize++;	
		}
	}
	return neighborsize;
}

uint32_t getcontrollerNeighborsize(struct controller_data * nd1)
{
	uint32_t  neighborsize = 0;
	for(uint32_t i=0; i<max;i++)
	{
		if(nd1->neighborid[i] != large)
		{
			neighborsize++;	
		}
	}
	return neighborsize;
}

void refresh_controller_data(struct controller_data * nd1)//To clear neighbors when updates are not received
{
	double time_difference = Simulator::Now().GetSeconds() - (nd1->lastupdated);
	if((time_difference) > (1.5*data_transmission_period))
	{
		nd1->neighborsize = 0;
		for(uint32_t i=0; i<max;i++)
		{
			nd1->neighborid[i] = large;
		}
		nd1->lastupdated = Simulator::Now().GetSeconds();
	}
}


struct proposed_routing_table_row
{
	uint32_t source_node;
	uint32_t destination_node;
	uint32_t path[total_size];
};

struct routing_table_row
{
	uint32_t source_node;
	uint32_t destination_node;
	uint32_t next_hop;
};

struct routing_table
{
	struct routing_table_row rows[total_size];
};

struct proposed_routing_table
{
	struct proposed_routing_table_row rows[total_size];
};

struct proposed_routing_table proposed_routing_tables[total_size];
struct routing_table routing_tables[total_size];

void initialize_all_routing_tables()
{
	for (uint32_t i=0;i<total_size;i++)
	{
		for(uint32_t j=0;j<total_size;j++)
		{
			routing_tables[i].rows[j].source_node = large;
			proposed_routing_tables[i].rows[j].source_node = large;
			routing_tables[i].rows[j].destination_node = large;
			proposed_routing_tables[i].rows[j].destination_node = large;
			routing_tables[i].rows[j].next_hop = large;
			for(uint32_t k=0;k<total_size;k++)
			{
				proposed_routing_tables[i].rows[j].path[k] = large;
			}
		}
	}
}

void update_route(uint32_t source, uint32_t destination, uint32_t next_hop)
{
	routing_tables[source].rows[destination].source_node = source;
	routing_tables[source].rows[destination].destination_node = destination;
	routing_tables[source].rows[destination].next_hop = next_hop;
}

void update_proposed_route(uint32_t source, uint32_t destination, uint32_t * path)
{
	proposed_routing_tables[source].rows[destination].source_node = source;
	proposed_routing_tables[source].rows[destination].destination_node = destination;
	for(uint32_t k=0;k<total_size;k++)
	{
		//cout<<path[0]<<endl;
		proposed_routing_tables[source].rows[destination].path[k] = *(path+k);
	}
}

uint32_t find_next_hop(uint32_t source, uint32_t destination, uint32_t current_hop)
{
	bool found = false;
	uint32_t k=0;
	uint32_t next_hop=0;
	while(found==false)
	{
		uint32_t this_hop = proposed_routing_tables[source].rows[destination].path[k];
		if (current_hop == this_hop)
		{
			next_hop = proposed_routing_tables[source].rows[destination].path[k+1];
			found = true;
		}
		k++;
	}
	return next_hop;
}

long dsrc_total_packet_size = 0;
long ethernet_total_packet_size = 0;
long lte_total_packet_size = 0;

ApplicationContainer apps;
ApplicationContainer RSU_apps;
NodeContainer controller_Node;
NodeContainer management_Node;
NodeContainer Vehicle_Nodes;
NodeContainer RSU_Nodes;
//NodeContainer Custom_Nodes;
