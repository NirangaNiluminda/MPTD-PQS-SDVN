// ============================================================
// 06c_blockchain_api.h — Blockchain REST API Functions
// MPTD-PQS SDVN (split from 06_mrtpa_attack.h, Stage 10B cleanup)
// ============================================================
// All Hyperledger Fabric REST API calls via localhost:3000.
// Depends on: 06b_pq_crypto.h (TRSSignature, FHECiphertext types)
//             05_utils.h (execCmd)
//             02_config_globals.h (use_pq_crypto, routing_algorithm)
//
// Contents:
//   StoreAttackConfigToBlockchain()      — called by declare_attack_states()
//   StoreNodeAttackStateToBlockchain()   — called by declare_attackers()
//   StoreControllerAssignmentToBlockchain() — called by assign_controllers()
//   StoreTrajectoryToBlockchain()        — called by 08_detection_engine.h
//   StoreControlDecisionToBlockchain()   — called by 08_detection_engine.h
//   FlagMaliciousOnBlockchain()          — called by 08_detection_engine.h
//   CallSCTrust()                        — SC-Trust ledger update
//   CallSCRevoke()                       — SC-Revoke immutable record
// ============================================================

// R7g.3: Single guard macro for every REST helper. When skip_blockchain is set
// (training-sweep mode), the curl call is bypassed — the sim still produces a
// full beacon CSV; only the ledger writes are skipped.
#define MPTD_BLOCKCHAIN_GUARD() do { if (skip_blockchain) return; } while (0)

// ── StoreAttackConfigToBlockchain — store global attack flags to ledger ───────
// Called by declare_attack_states() to record the active attack type.
void StoreAttackConfigToBlockchain(
    uint32_t attackNum,
    bool tpVehicle, bool headingSpoof, bool rsuFab, bool sybilMitm, bool beaconSup,
    bool ctrlMalAssumption)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::string body =
        "{\"attackNumber\":\""    + std::to_string(attackNum) + "\","
        "\"tpVehicle\":\""        + (tpVehicle      ? "true" : "false") + "\","
        "\"headingSpoof\":\""     + (headingSpoof   ? "true" : "false") + "\","
        "\"rsuFabrication\":\""   + (rsuFab         ? "true" : "false") + "\","
        "\"sybilMitm\":\""        + (sybilMitm      ? "true" : "false") + "\","
        "\"beaconSuppression\":\"" + (beaconSup     ? "true" : "false") + "\","
        "\"ctrlMaliciousAssumption\":\"" + (ctrlMalAssumption ? "true" : "false") + "\"}";

    std::string curlCmd =
        "curl -s -X POST http://localhost:3000/api/attackconfig "
        "-H \"Content-Type: application/json\" "
        "-d '" + body + "'";
    std::cout << "[ATTACK_CFG] Storing attack config for attack_number=" << attackNum << " to blockchain" << std::endl;
    std::string resp = execCmd(curlCmd);
    std::cout << "[ATTACK_CFG] Response: " << resp << std::endl;
}

// ── StoreNodeAttackStateToBlockchain — store per-node attacker role ───────────
// Called by declare_attackers() for each node in the simulation.
void StoreNodeAttackStateToBlockchain(
    uint32_t nodeIdx, int atkPct,
    bool isLocMal, bool isFloodMal, bool isFabMal,
    bool isMIMMal, bool isVanMal, bool isTrajMal)
{
    MPTD_BLOCKCHAIN_GUARD();
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

// ── StoreControllerAssignmentToBlockchain — store node→controller mapping ────
// Called by assign_controllers() in 11_blockchain_setup.h.
void StoreControllerAssignmentToBlockchain(
    uint32_t nodeIdx, uint32_t ctrlID, uint32_t consID, bool isTrajPoisoner)
{
    MPTD_BLOCKCHAIN_GUARD();
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

// ── StoreTrajectoryToBlockchain — record real + poisoned trajectory ───────────
// Paper §3.3.4: Each beacon reception is stored on Fabric ledger.
// When use_pq_crypto=true: runs real TRS signing (§3.5.4 Eq. 3.46–3.49) +
// FHE encryption (§3.5.4 Eq. 3.61). Per Invariant 5, TRS verification gates
// the submission — a failed σ_TRS verify bails out before the curl POST and
// the trajectory_stored counter is NOT incremented.
//
// R8.4 (2026-05-29): Replaced the legacy generate_trs_aggregate string-hash
// stub with the real evidence_sign_and_verify pipeline (paper Algorithm 6).
// PARR is now empirically observable via g_trs_verified_count /
// g_trs_rejected_count instead of formula-approximated in evaluate_all.py.
void StoreTrajectoryToBlockchain(std::string vehicleID, std::string rsuID,
    Vector position, Vector velocity, Vector acceleration,
    double timestamp, bool isPoisoned)
{
    // R8.4: TRS verification runs whenever use_pq_crypto, REGARDLESS of
    // skip_blockchain. Sweep mode (skip_blockchain=true) still needs the
    // crypto cost on the PBPO clock and σ_TRS verify/reject counts on the
    // PARR clock — only the Fabric REST call is the part we skip. The
    // explicit skip_blockchain check is moved below, after the TRS gate.

    // ── PQ TRS gate (Invariant 5: TRS-then-FHE-then-submit) ──────────────────
    if (use_pq_crypto) {
        // Build m_j evidence (paper Eq. 3.46). Per-beacon mode: vehicle_set = {vid}.
        uint32_t rsu_idx = 0;
        if (rsuID.size() > 3) {
            try { rsu_idx = (uint32_t)std::stoi(rsuID.substr(3)); } catch (...) {}
        }
        uint32_t vid = 0;
        try { vid = (uint32_t)std::stoi(vehicleID); } catch (...) {}

        EvidenceMessage m_j;
        m_j.rsu_id      = rsu_idx;
        m_j.timestamp   = timestamp;
        m_j.agg_pos_x   = position.x;
        m_j.agg_pos_y   = position.y;
        m_j.agg_vel_x   = velocity.x;
        m_j.agg_vel_y   = velocity.y;
        m_j.agg_accel_x = acceleration.x;
        m_j.agg_accel_y = acceleration.y;
        m_j.vehicle_set.push_back(vid);

        // Real TRS chain: partial_sign × t → aggregate → verify_threshold
        // (paper Eq. 3.47–3.49). evidence_sign_and_verify lives in
        // 06b1_trs_backend.h.
        std::vector<uint8_t>  sigma_trs;
        std::vector<uint32_t> signers;
        bool verified = evidence_sign_and_verify(m_j, sigma_trs, signers);
        if (verified) g_trs_verified_count++;
        else          g_trs_rejected_count++;

        std::cout << "[TRS] Vehicle=" << vehicleID
                  << " RSU=" << rsuID
                  << " signers=" << signers.size()
                  << " sigma_bytes=" << sigma_trs.size()
                  << " verified=" << (verified ? "YES" : "NO") << "\n";

        if (!verified) {
            // Invariant 5: σ_TRS verification gates submission. Reject early.
            std::cout << "[TRS-REJECT] vehicle=" << vehicleID
                      << " t=" << timestamp
                      << " — σ_TRS verify failed; skipping chain submit\n";
            return;
        }

        // FHE: encrypt speed scalar AFTER TRS verify (paper Eq. 3.61).
        double spd = std::sqrt(velocity.x * velocity.x + velocity.y * velocity.y);
        FHECiphertext ct = fhe_encrypt_scalar(spd);
        std::cout << "[FHE] Vehicle=" << vehicleID
                  << " speed_enc=" << ct.noisy_value
                  << " (plaintext≈" << spd << ")\n";
    }

    // ── Submit to Fabric ledger (gated on TRS verify above) ──────────────────
    // Sweep mode (--skip_blockchain=true) stops here: PARR/PBPO already booked
    // above, no need to pay the curl roundtrip when there's no Fabric anyway.
    if (skip_blockchain) return;

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
}

// ── StoreControlDecisionToBlockchain — record SDN control packet decision ────
void StoreControlDecisionToBlockchain(std::string controllerID, std::string decision,
    double timestamp, std::string basedOnData)
{
    MPTD_BLOCKCHAIN_GUARD();
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

// ── FlagMaliciousOnBlockchain — write immutable malicious flag for an entity ─
void FlagMaliciousOnBlockchain(std::string entityID, std::string reason)
{
    MPTD_BLOCKCHAIN_GUARD();
    std::string curlCmd =
        "curl -s -X POST http://localhost:3000/api/flag "
        "-H \"Content-Type: application/json\" "
        "-d '{\"entityID\":\"" + entityID + "\","
        "\"reason\":\"" + reason + "\"}' "
        "> /dev/null 2>&1 &";

    system(curlCmd.c_str());
}

// ── CallSCTrust — update per-vehicle trust score on Fabric ledger ─────────────
// τ_i(t) = 0.3·τ_i(t-1) + 0.7·(1-Φ) computed inside chaincode SCTrustUpdate
// Called by 08_detection_engine.h after each detection round.
void CallSCTrust(uint32_t vehicleID, double phiScore, uint32_t sigMask,
                 bool isAnomaly, double timestamp)
{
    MPTD_BLOCKCHAIN_GUARD();
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

// ── CallSCRevoke — write immutable revocation record for a vehicle ────────────
// Triggered by 08_detection_engine.h when consecutive_anomaly reaches threshold.
void CallSCRevoke(uint32_t vehicleID, const std::string &reason,
                  uint32_t rsuID, double timestamp)
{
    MPTD_BLOCKCHAIN_GUARD();
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
