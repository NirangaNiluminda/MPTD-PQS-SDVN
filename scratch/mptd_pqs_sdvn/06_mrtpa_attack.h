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
// Adds controlled noise to position, velocity, and acceleration
void PoisonTrajectory(Vector &position, Vector &velocity, Vector &acceleration, double theta)
{
    // Seed with time-varying component for different poisoning each call
    double time_factor = Simulator::Now().GetSeconds();

    // Position poisoning: gradual drift proportional to θ and time
    double pos_noise_x = theta * max_position_deviation * sin(time_factor * 0.7);
    double pos_noise_y = theta * max_position_deviation * cos(time_factor * 0.5);
    position.x += pos_noise_x;
    position.y += pos_noise_y;

    // Velocity poisoning: scale deviation by θ
    double vel_noise_x = theta * max_velocity_deviation * sin(time_factor * 1.3);
    double vel_noise_y = theta * max_velocity_deviation * cos(time_factor * 0.9);
    velocity.x += vel_noise_x;
    velocity.y += vel_noise_y;

    // Acceleration poisoning: subtle changes
    double acc_noise_x = theta * max_acceleration_deviation * cos(time_factor * 1.7);
    double acc_noise_y = theta * max_acceleration_deviation * sin(time_factor * 1.1);
    acceleration.x += acc_noise_x;
    acceleration.y += acc_noise_y;
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

void add_routing_data_at_nodes(struct routing_data_at_nodes * nd1, Ptr <NetDevice> nd, Ptr <Node> node)
{	
	//routing_time = false;
	//uint32_t nid = node->GetId();
	//Mac48Address dest = Mac48Address::GetBroadcast();
  	//uint16_t protocolwave = 0x88dc;//ethertype for WAVE is set here.
	Ptr <WifiNetDevice> wdi = DynamicCast <WifiNetDevice> (nd);
	Ptr <Node> ni = DynamicCast <Node> (node);
	//CustomDataTag tag;
	uint32_t nid = uint32_t(ni->GetId()) - 2;
	//packet_initial_timestamp[nid] = Simulator::Now().GetSeconds();
	//cout<<"updating data from node "<<nid<<endl;
	Ptr<ConstantVelocityMobilityModel> mdl = DynamicCast <ConstantVelocityMobilityModel> (node->GetObject<MobilityModel>());
	Vector posi = mdl->GetPosition();
	Vector current_velocity = mdl->GetVelocity();
	double delta_t = 0.000200;
	
	Vector acceleration;
	acceleration = calculate_acceleration(previous_velocity_dsrc[nid],current_velocity,delta_t);
	//cout<<"calculating acceleration for nid "<<nid<<"with previous velocity "<<previous_velocity_dsrc[nid]<<"current velocity "<<current_velocity<<" is "<<acceleration<<endl;
	
	//Ptr <Packet> packet_i = Create<Packet> (0);
	//tag.SetNodeId(nid);
	/*
	tag.SetPosition(posi);
	tag.SetVelocity(current_velocity);
	tag.SetAcceleration(acceleration);
	tag.SetTimestamp(ti);
	packet_i->AddPacketTag(tag);
	dsrc_total_packet_size = dsrc_total_packet_size + packet_i->GetSerializedSize();
	//Simulator::Schedule (Seconds(0) , &WifiNetDevice::Send, wdi, packet_i, dest, protocolwave);	
	cout<<"dsrc total size is "<<dsrc_total_packet_size<<endl;
	*/
	//previous_velocity_dsrc[nid] = current_velocity;
	
	nd1->acceleration = acceleration;
	nd1->velocity = current_velocity;
	nd1->position = posi;
	nd1->nodeid = nid;
	//cout<<"updating data from node "<<nid<< "updated as acceleration"<<nd1->acceleration<<"velocity: "<<nd1->velocity<< "position"<<nd1->position<<endl;
}


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
