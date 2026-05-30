package chaincode

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

// ─────────────────────────────────────────────────────────────────────────────
// Data structures
// ─────────────────────────────────────────────────────────────────────────────

// TrajectoryReport – vehicle mobility report (MRTPA Attack Scenario 1)
type TrajectoryReport struct {
	ID         string  `json:"ID"`
	VehicleID  string  `json:"VehicleID"`
	RSUID      string  `json:"RSUID"`
	PositionX  float64 `json:"PositionX"`
	PositionY  float64 `json:"PositionY"`
	PositionZ  float64 `json:"PositionZ"`
	VelocityX  float64 `json:"VelocityX"`
	VelocityY  float64 `json:"VelocityY"`
	VelocityZ  float64 `json:"VelocityZ"`
	AccelX     float64 `json:"AccelX"`
	AccelY     float64 `json:"AccelY"`
	AccelZ     float64 `json:"AccelZ"`
	Timestamp  string  `json:"Timestamp"`
	IsPoisoned bool    `json:"IsPoisoned"`
	StoredAt   string  `json:"StoredAt"`
}

// TrajectoryRef – on-chain record with IPFS hash + detection scores.
// Full trajectory data (posX/Y/Z, velX/Y/Z, accX/Y/Z) lives off-chain in IPFS.
// Detection fields (GATScore, AutoencoderScore, TrustScore, ControllerDecision)
// are initially empty ("") and updated later by the detection pipeline.
type TrajectoryRef struct {
	ID                 string `json:"ID"`
	VehicleID          string `json:"VehicleID"`
	RSUID              string `json:"RSUID"`
	IPFSHash           string `json:"IPFSHash"`           // CID of full data in IPFS
	IsPoisoned         bool   `json:"IsPoisoned"`         // flag set by RSU (simulation)
	Timestamp          string `json:"Timestamp"`
	StoredAt           string `json:"StoredAt"`
	// ── Detection results (filled later by GAT / Autoencoder pipeline) ──
	GATScore           string `json:"GATScore"`           // Graph Attention Network anomaly score
	AutoencoderScore   string `json:"AutoencoderScore"`   // Temporal Autoencoder reconstruction error
	TrustScore         string `json:"TrustScore"`         // Combined/total trust value
	ControllerDecision string `json:"ControllerDecision"` // e.g. "ACCEPT", "REJECT", "QUARANTINE"
}

// ControlDecision – SDVN controller routing decision
type ControlDecision struct {
	ID           string `json:"ID"`
	ControllerID string `json:"ControllerID"`
	Decision     string `json:"Decision"`
	Timestamp    string `json:"Timestamp"`
	BasedOnData  string `json:"BasedOnData"`
}

// MaliciousFlag – flagged malicious entity
type MaliciousFlag struct {
	ID        string `json:"ID"`
	EntityID  string `json:"EntityID"`
	Reason    string `json:"Reason"`
	FlaggedAt string `json:"FlaggedAt"`
}

// AuthState – node authentication/reputation state (putauthStates / getauthStates)
// Matches the original lda_attack.cc Store_timestamp() call format
type AuthState struct {
	ID                     string `json:"ID"`
	CurNodeID              string `json:"CurNodeID"`
	OthNodeID              string `json:"OthNodeID"`
	EncryptedReputation    string `json:"EncryptedReputation"`
	EncryptedLocation      string `json:"EncryptedLocation"`
	Signature              string `json:"Signature"`
	ZKPSignature           string `json:"ZKPSignature"`
	DigitalSignature       string `json:"DigitalSignature"`
	IsValid                string `json:"IsValid"`
	UpdatedAt              string `json:"UpdatedAt"`
}

// TrustRecord – per-node LLDP trust/routing data (BWTRCB function)
type TrustRecord struct {
	ID           string `json:"ID"`
	NodeID       string `json:"NodeID"`
	MatLLDP      string `json:"MatLLDP"`
	RepLocStr    string `json:"RepLocStr"`
	DupCntStr    string `json:"DupCntStr"`
	FabCntStr    string `json:"FabCntStr"`
	RepCntStr    string `json:"RepCntStr"`
	Neighbors    string `json:"Neighbors"`
	Controller   string `json:"Controller"`
	UpdatedAt    string `json:"UpdatedAt"`
}

// ConsortiumElection – Byzantine Controller Trust Election (BCTES function)
type ConsortiumElection struct {
	ID           string `json:"ID"`
	Controller   string `json:"Controller"`
	Consortium   string `json:"Consortium"`
	NodeID       string `json:"NodeID"`
	ExpNodeIDs   string `json:"ExpNodeIDs"`
	RecNodeIDs   string `json:"RecNodeIDs"`
	PoutCnt      string `json:"PoutCnt"`
	UpdatedAt    string `json:"UpdatedAt"`
}

// AttackConfig – global attack-type flags set by declare_attack_states()
// Stores which attack types are active for the current simulation run
type AttackConfig struct {
	ID                             string `json:"ID"`
	AttackNumber                   string `json:"AttackNumber"`
	LocationAttackNodes            string `json:"LocationAttackNodes"`
	FloodingAttackNodes            string `json:"FloodingAttackNodes"`
	FabricationAttackNodes         string `json:"FabricationAttackNodes"`
	MIMAttackNodes                 string `json:"MIMAttackNodes"`
	VanishingAttackNodes           string `json:"VanishingAttackNodes"`
	FloodingAttackControllers      string `json:"FloodingAttackControllers"`
	FabricationAttackControllers   string `json:"FabricationAttackControllers"`
	MIMAttackControllers           string `json:"MIMAttackControllers"`
	VanishingAttackControllers     string `json:"VanishingAttackControllers"`
	ControllerMaliciousAssumption  string `json:"ControllerMaliciousAssumption"`
	StoredAt                       string `json:"StoredAt"`
}

// NodeAttackState – per-node attacker assignment set by declare_attackers()
// Records whether each node is malicious for each attack type
type NodeAttackState struct {
	ID                      string `json:"ID"`
	NodeIndex               string `json:"NodeIndex"`
	AttackPercentage        string `json:"AttackPercentage"`
	IsLocationMalicious     string `json:"IsLocationMalicious"`
	IsFloodingMalicious     string `json:"IsFloodingMalicious"`
	IsFabricationMalicious  string `json:"IsFabricationMalicious"`
	IsMIMMalicious          string `json:"IsMIMMalicious"`
	IsVanishingMalicious    string `json:"IsVanishingMalicious"`
	IsTrajectoryMalicious   string `json:"IsTrajectoryMalicious"`
	StoredAt                string `json:"StoredAt"`
}

// ControllerAssignment – per-node controller/consortium mapping set by assign_controllers()
// Records the initial assignment of each node to a controller and consortium
type ControllerAssignment struct {
	ID                    string `json:"ID"`
	NodeIndex             string `json:"NodeIndex"`
	ControllerID          string `json:"ControllerID"`
	ConsortiumID          string `json:"ConsortiumID"`
	IsTrajectoryPoisoner  string `json:"IsTrajectoryPoisoner"`
	StoredAt              string `json:"StoredAt"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Trajectory functions (MRTPA Attack Scenario 1)
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) StoreTrajectory(ctx contractapi.TransactionContextInterface,
	vehicleID, rsuID,
	posX, posY, posZ,
	velX, velY, velZ,
	accX, accY, accZ,
	timestamp, isPoisonedStr string) error {

	pX, _ := strconv.ParseFloat(posX, 64)
	pY, _ := strconv.ParseFloat(posY, 64)
	pZ, _ := strconv.ParseFloat(posZ, 64)
	vX, _ := strconv.ParseFloat(velX, 64)
	vY, _ := strconv.ParseFloat(velY, 64)
	vZ, _ := strconv.ParseFloat(velZ, 64)
	aX, _ := strconv.ParseFloat(accX, 64)
	aY, _ := strconv.ParseFloat(accY, 64)
	aZ, _ := strconv.ParseFloat(accZ, 64)
	isPoisoned := isPoisonedStr == "true" || isPoisonedStr == "True" || isPoisonedStr == "1"

	id := fmt.Sprintf("TRAJ_%s_%s_%s", vehicleID, rsuID, timestamp)
	report := TrajectoryReport{
		ID: id, VehicleID: vehicleID, RSUID: rsuID,
		PositionX: pX, PositionY: pY, PositionZ: pZ,
		VelocityX: vX, VelocityY: vY, VelocityZ: vZ,
		AccelX: aX, AccelY: aY, AccelZ: aZ,
		Timestamp: timestamp, IsPoisoned: isPoisoned,
		StoredAt: time.Now().Format(time.RFC3339),
	}
	reportJSON, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, reportJSON)
}

func (s *SmartContract) QueryTrajectory(ctx contractapi.TransactionContextInterface, id string) (*TrajectoryReport, error) {
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %v", err)
	}
	if data == nil {
		return nil, fmt.Errorf("trajectory %s not found", id)
	}
	var report TrajectoryReport
	err = json.Unmarshal(data, &report)
	return &report, err
}

func (s *SmartContract) GetAllTrajectories(ctx contractapi.TransactionContextInterface) ([]*TrajectoryReport, error) {
	iter, err := ctx.GetStub().GetStateByRange("TRAJ_", "TRAJ_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*TrajectoryReport
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var r TrajectoryReport
		if err := json.Unmarshal(qr.Value, &r); err != nil {
			return nil, err
		}
		results = append(results, &r)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// TrajectoryRef functions (IPFS off-chain storage — MRTPA Attack Scenario 1)
// ─────────────────────────────────────────────────────────────────────────────

// StoreTrajectoryRef – stores IPFS hash + key fields on-chain.
// Full trajectory data is already stored in IPFS; only the CID comes here.
// Detection fields (GATScore etc.) are left empty — filled by UpdateTrajectoryRef later.
func (s *SmartContract) StoreTrajectoryRef(ctx contractapi.TransactionContextInterface,
	vehicleID, rsuID, ipfsHash, isPoisonedStr, timestamp string) error {

	isPoisoned := isPoisonedStr == "true" || isPoisonedStr == "True" || isPoisonedStr == "1"
	id := fmt.Sprintf("TRAJREF_%s_%s_%s", vehicleID, rsuID, timestamp)
	ref := TrajectoryRef{
		ID:                 id,
		VehicleID:          vehicleID,
		RSUID:              rsuID,
		IPFSHash:           ipfsHash,
		IsPoisoned:         isPoisoned,
		Timestamp:          timestamp,
		StoredAt:           time.Now().Format(time.RFC3339),
		GATScore:           "",
		AutoencoderScore:   "",
		TrustScore:         "",
		ControllerDecision: "",
	}
	refJSON, err := json.Marshal(ref)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, refJSON)
}

// UpdateTrajectoryRef – updates detection scores on an existing TrajectoryRef.
// Called after GAT / Autoencoder analysis is complete.
func (s *SmartContract) UpdateTrajectoryRef(ctx contractapi.TransactionContextInterface,
	id, gatScore, autoencoderScore, trustScore, controllerDecision string) error {

	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read TrajectoryRef %s: %v", id, err)
	}
	if data == nil {
		return fmt.Errorf("TrajectoryRef %s not found", id)
	}
	var ref TrajectoryRef
	if err := json.Unmarshal(data, &ref); err != nil {
		return err
	}
	ref.GATScore           = gatScore
	ref.AutoencoderScore   = autoencoderScore
	ref.TrustScore         = trustScore
	ref.ControllerDecision = controllerDecision
	refJSON, err := json.Marshal(ref)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, refJSON)
}

// GetAllTrajectoryRefs – returns all IPFS-backed trajectory references
func (s *SmartContract) GetAllTrajectoryRefs(ctx contractapi.TransactionContextInterface) ([]*TrajectoryRef, error) {
	iter, err := ctx.GetStub().GetStateByRange("TRAJREF_", "TRAJREF_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*TrajectoryRef
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var r TrajectoryRef
		if err := json.Unmarshal(qr.Value, &r); err != nil {
			return nil, err
		}
		results = append(results, &r)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Control & flag functions
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) StoreControlDecision(ctx contractapi.TransactionContextInterface,
	controllerID, decision, timestamp, basedOnData string) error {

	id := fmt.Sprintf("CTRL_%s_%s", controllerID, timestamp)
	cd := ControlDecision{ID: id, ControllerID: controllerID,
		Decision: decision, Timestamp: timestamp, BasedOnData: basedOnData}
	cdJSON, err := json.Marshal(cd)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, cdJSON)
}

func (s *SmartContract) FlagMalicious(ctx contractapi.TransactionContextInterface,
	entityID, reason string) error {

	id := fmt.Sprintf("FLAG_%s_%s", entityID, time.Now().Format("20060102150405"))
	flag := MaliciousFlag{ID: id, EntityID: entityID, Reason: reason,
		FlaggedAt: time.Now().Format(time.RFC3339)}
	flagJSON, err := json.Marshal(flag)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, flagJSON)
}

// ─────────────────────────────────────────────────────────────────────────────
// putauthStates / getauthStates  (original lda_attack.cc Store_timestamp calls)
// Args: curNodeID, othNodeID, encReputation, encLocation, signature, zkp, ds, isValid
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) PutAuthStates(ctx contractapi.TransactionContextInterface,
	curNodeID, othNodeID, encReputation, encLocation,
	signature, zkpSignature, digitalSig, isValid string) error {

	id := fmt.Sprintf("AUTH_%s_%s", curNodeID, othNodeID)
	auth := AuthState{
		ID:                  id,
		CurNodeID:           curNodeID,
		OthNodeID:           othNodeID,
		EncryptedReputation: encReputation,
		EncryptedLocation:   encLocation,
		Signature:           signature,
		ZKPSignature:        zkpSignature,
		DigitalSignature:    digitalSig,
		IsValid:             isValid,
		UpdatedAt:           time.Now().Format(time.RFC3339),
	}
	authJSON, err := json.Marshal(auth)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, authJSON)
}

func (s *SmartContract) GetAuthStates(ctx contractapi.TransactionContextInterface,
	controllerID, curNodeID, othNodeID, reqID string) (*AuthState, error) {

	id := fmt.Sprintf("AUTH_%s_%s", curNodeID, othNodeID)
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read auth state: %v", err)
	}
	if data == nil {
		// Return empty auth state if not found (don't error - NS3 handles missing)
		return &AuthState{ID: id, CurNodeID: curNodeID, OthNodeID: othNodeID,
			IsValid: "false", UpdatedAt: "never"}, nil
	}
	var auth AuthState
	err = json.Unmarshal(data, &auth)
	return &auth, err
}

func (s *SmartContract) GetAllAuthStates(ctx contractapi.TransactionContextInterface) ([]*AuthState, error) {
	iter, err := ctx.GetStub().GetStateByRange("AUTH_", "AUTH_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*AuthState
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var a AuthState
		if err := json.Unmarshal(qr.Value, &a); err != nil {
			return nil, err
		}
		results = append(results, &a)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// BWTRCB – Bandwidth-Trust-Routing-Consortium-Blockchain
// Stores per-node LLDP trust matrix data
// Args: nodeID, matLLDP, repLoc, dupCnt, fabCnt, repCnt, neighbors, neighborsAlt, controller
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) BWTRCB(ctx contractapi.TransactionContextInterface,
	nodeID, matLLDP, repLoc, dupCnt, fabCnt, repCnt,
	neighbors, neighborsAlt, controller string) error {

	id := fmt.Sprintf("TRUST_%s", nodeID)
	rec := TrustRecord{
		ID:         id,
		NodeID:     nodeID,
		MatLLDP:    matLLDP,
		RepLocStr:  repLoc,
		DupCntStr:  dupCnt,
		FabCntStr:  fabCnt,
		RepCntStr:  repCnt,
		Neighbors:  neighbors,
		Controller: controller,
		UpdatedAt:  time.Now().Format(time.RFC3339),
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	// Return a simple acknowledgement that NS3 can parse
	ctx.GetStub().SetEvent("BWTRCB", []byte(fmt.Sprintf(`{"node":"%s","status":"ok"}`, nodeID)))
	return ctx.GetStub().PutState(id, recJSON)
}

func (s *SmartContract) GetTrustRecord(ctx contractapi.TransactionContextInterface, nodeID string) (*TrustRecord, error) {
	id := fmt.Sprintf("TRUST_%s", nodeID)
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read trust record: %v", err)
	}
	if data == nil {
		return &TrustRecord{ID: id, NodeID: nodeID, UpdatedAt: "never"}, nil
	}
	var rec TrustRecord
	err = json.Unmarshal(data, &rec)
	return &rec, err
}

func (s *SmartContract) GetAllTrustRecords(ctx contractapi.TransactionContextInterface) ([]*TrustRecord, error) {
	iter, err := ctx.GetStub().GetStateByRange("TRUST_", "TRUST_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*TrustRecord
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var r TrustRecord
		if err := json.Unmarshal(qr.Value, &r); err != nil {
			return nil, err
		}
		results = append(results, &r)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// BCTES – Byzantine Controller Trust Election System
// Args: controller, consortium, nodeID, expNodeIDs, recNodeIDs, poutCnt
// Returns a result string that NS3 parses for controller changes
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) BCTES(ctx contractapi.TransactionContextInterface,
	controller, consortium, nodeID,
	expNodeIDs, recNodeIDs, poutCnt string) (string, error) {

	id := fmt.Sprintf("ELECT_%s_%s_%s", consortium, controller, nodeID)
	election := ConsortiumElection{
		ID:         id,
		Controller: controller,
		Consortium: consortium,
		NodeID:     nodeID,
		ExpNodeIDs: expNodeIDs,
		RecNodeIDs: recNodeIDs,
		PoutCnt:    poutCnt,
		UpdatedAt:  time.Now().Format(time.RFC3339),
	}
	electionJSON, err := json.Marshal(election)
	if err != nil {
		return "", err
	}
	if err := ctx.GetStub().PutState(id, electionJSON); err != nil {
		return "", err
	}

	// Return response in the format NS3 BCTES function expects:
	// "Controller changed for consortium X as: CY" or just acknowledge
	result := fmt.Sprintf(`{"result":"Controller maintained for consortium %s as: %s","node":"%s","status":"ok"}`,
		consortium, controller, nodeID)
	return result, nil
}

func (s *SmartContract) GetAllElections(ctx contractapi.TransactionContextInterface) ([]*ConsortiumElection, error) {
	iter, err := ctx.GetStub().GetStateByRange("ELECT_", "ELECT_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*ConsortiumElection
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var e ConsortiumElection
		if err := json.Unmarshal(qr.Value, &e); err != nil {
			return nil, err
		}
		results = append(results, &e)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// StoreAttackConfig – stores global attack flags from declare_attack_states()
// Args: attackNumber, locNodes, floodNodes, fabNodes, mimNodes, vanNodes,
//       floodCtrl, fabCtrl, mimCtrl, vanCtrl, ctrlMalAssumption
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) StoreAttackConfig(ctx contractapi.TransactionContextInterface,
	attackNumber,
	locNodes, floodNodes, fabNodes, mimNodes, vanNodes,
	floodCtrl, fabCtrl, mimCtrl, vanCtrl,
	ctrlMalAssumption string) error {

	id := fmt.Sprintf("ATKCFG_%s", attackNumber)
	cfg := AttackConfig{
		ID:                            id,
		AttackNumber:                  attackNumber,
		LocationAttackNodes:           locNodes,
		FloodingAttackNodes:           floodNodes,
		FabricationAttackNodes:        fabNodes,
		MIMAttackNodes:                mimNodes,
		VanishingAttackNodes:          vanNodes,
		FloodingAttackControllers:     floodCtrl,
		FabricationAttackControllers:  fabCtrl,
		MIMAttackControllers:          mimCtrl,
		VanishingAttackControllers:    vanCtrl,
		ControllerMaliciousAssumption: ctrlMalAssumption,
		StoredAt:                      time.Now().Format(time.RFC3339),
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, cfgJSON)
}

func (s *SmartContract) GetAttackConfig(ctx contractapi.TransactionContextInterface, attackNumber string) (*AttackConfig, error) {
	id := fmt.Sprintf("ATKCFG_%s", attackNumber)
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read attack config: %v", err)
	}
	if data == nil {
		return &AttackConfig{ID: id, AttackNumber: attackNumber, StoredAt: "never"}, nil
	}
	var cfg AttackConfig
	err = json.Unmarshal(data, &cfg)
	return &cfg, err
}

func (s *SmartContract) GetAllAttackConfigs(ctx contractapi.TransactionContextInterface) ([]*AttackConfig, error) {
	iter, err := ctx.GetStub().GetStateByRange("ATKCFG_", "ATKCFG_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*AttackConfig
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var c AttackConfig
		if err := json.Unmarshal(qr.Value, &c); err != nil {
			return nil, err
		}
		results = append(results, &c)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// StoreNodeAttackState – stores per-node attacker role from declare_attackers()
// Args: nodeIndex, attackPercentage, isLocMal, isFloodMal, isFabMal, isMIMMal,
//       isVanMal, isTrajMal
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) StoreNodeAttackState(ctx contractapi.TransactionContextInterface,
	nodeIndex, attackPercentage,
	isLocMal, isFloodMal, isFabMal, isMIMMal, isVanMal, isTrajMal string) error {

	id := fmt.Sprintf("NODEATTK_%s", nodeIndex)
	state := NodeAttackState{
		ID:                     id,
		NodeIndex:              nodeIndex,
		AttackPercentage:       attackPercentage,
		IsLocationMalicious:    isLocMal,
		IsFloodingMalicious:    isFloodMal,
		IsFabricationMalicious: isFabMal,
		IsMIMMalicious:         isMIMMal,
		IsVanishingMalicious:   isVanMal,
		IsTrajectoryMalicious:  isTrajMal,
		StoredAt:               time.Now().Format(time.RFC3339),
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, stateJSON)
}

func (s *SmartContract) GetNodeAttackState(ctx contractapi.TransactionContextInterface, nodeIndex string) (*NodeAttackState, error) {
	id := fmt.Sprintf("NODEATTK_%s", nodeIndex)
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read node attack state: %v", err)
	}
	if data == nil {
		return &NodeAttackState{ID: id, NodeIndex: nodeIndex, StoredAt: "never"}, nil
	}
	var state NodeAttackState
	err = json.Unmarshal(data, &state)
	return &state, err
}

func (s *SmartContract) GetAllNodeAttackStates(ctx contractapi.TransactionContextInterface) ([]*NodeAttackState, error) {
	iter, err := ctx.GetStub().GetStateByRange("NODEATTK_", "NODEATTK_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*NodeAttackState
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var s NodeAttackState
		if err := json.Unmarshal(qr.Value, &s); err != nil {
			return nil, err
		}
		results = append(results, &s)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// StoreControllerAssignment – stores node-to-controller mapping from assign_controllers()
// Args: nodeIndex, controllerID, consortiumID, isTrajPoisoner
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) StoreControllerAssignment(ctx contractapi.TransactionContextInterface,
	nodeIndex, controllerID, consortiumID, isTrajPoisoner string) error {

	id := fmt.Sprintf("ASSIGN_%s", nodeIndex)
	assignment := ControllerAssignment{
		ID:                   id,
		NodeIndex:            nodeIndex,
		ControllerID:         controllerID,
		ConsortiumID:         consortiumID,
		IsTrajectoryPoisoner: isTrajPoisoner,
		StoredAt:             time.Now().Format(time.RFC3339),
	}
	assignJSON, err := json.Marshal(assignment)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, assignJSON)
}

func (s *SmartContract) GetControllerAssignment(ctx contractapi.TransactionContextInterface, nodeIndex string) (*ControllerAssignment, error) {
	id := fmt.Sprintf("ASSIGN_%s", nodeIndex)
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read controller assignment: %v", err)
	}
	if data == nil {
		return &ControllerAssignment{ID: id, NodeIndex: nodeIndex, StoredAt: "never"}, nil
	}
	var a ControllerAssignment
	err = json.Unmarshal(data, &a)
	return &a, err
}

func (s *SmartContract) GetAllControllerAssignments(ctx contractapi.TransactionContextInterface) ([]*ControllerAssignment, error) {
	iter, err := ctx.GetStub().GetStateByRange("ASSIGN_", "ASSIGN_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*ControllerAssignment
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var a ControllerAssignment
		if err := json.Unmarshal(qr.Value, &a); err != nil {
			return nil, err
		}
		results = append(results, &a)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// SC-Trust: MPTD-PQS per-vehicle trust score (Stage 6)
// Key prefix: SCTRUST_<vehicleID>
// Trust update rule: τ_i(t) = α·τ_i(t-1) + (1-α)·(1-Φ),  α=0.3
// ─────────────────────────────────────────────────────────────────────────────

// SCTrustScore – per-vehicle trust score maintained by MPTD-PQS detection.
//
// Paper §3.5.5 / Eq 3.55:
//   τ_i(t) = α·τ_i(t-1) + (1-α)·(1 - (1/|R|)·Σ_{r_j∈R} ψ_j^{(i)}(t))
// The new MeanPsi / NumRSUsLastEpoch / ConsecutiveLowEpochs / LastEpochTimestamp
// fields are populated by SCTrustFinalizeEpoch (Eq 3.55-aligned path).
// The legacy PhiScore / SigMask / IsAnomaly fields are kept for backward
// compatibility with the deprecated single-RSU SCTrustUpdate entry point.
type SCTrustScore struct {
	ID         string  `json:"ID"`
	VehicleID  string  `json:"VehicleID"`
	TrustScore float64 `json:"TrustScore"` // τ_i ∈ [0,1]; higher = more trusted
	// ── Paper Eq 3.55 fields (set by SCTrustFinalizeEpoch) ──
	MeanPsi              float64 `json:"MeanPsi"`              // (1/|R|)·Σ ψ_j^{(i)}(t) from last epoch
	NumRSUsLastEpoch     int     `json:"NumRSUsLastEpoch"`     // |R| of last finalized epoch
	ConsecutiveLowEpochs int     `json:"ConsecutiveLowEpochs"` // running counter for T_rev gate
	LastEpochTimestamp   string  `json:"LastEpochTimestamp"`   // epoch label of last finalize
	// ── Legacy single-RSU update fields (deprecated) ──
	PhiScore    float64 `json:"PhiScore"`    // last Φ_i(t) fused anomaly score (legacy)
	SigMask     string  `json:"SigMask"`     // bitmask of triggered detection rules (legacy)
	IsAnomaly   bool    `json:"IsAnomaly"`   // last detection decision (legacy)
	UpdateCount int     `json:"UpdateCount"` // total number of updates received (both paths)
	UpdatedAt   string  `json:"UpdatedAt"`
}

// SCTrustUpdate – LEGACY single-RSU trust update path (deprecated).
//
// This entry point does NOT implement Eq 3.55 correctly because it accepts a
// single fused Φ_i directly from the caller instead of computing the mean
// across the witnessing RSU set R.  It is preserved only so existing
// Stage-6 integrations keep working while the production path is migrated.
//
// New code MUST use the Eq 3.56 evidence-submission pipeline:
//   SCTrustSubmitEvidence(...)   per RSU in the witnessing set
//   SCTrustFinalizeEpoch(...)    once the epoch closes
// Args: vehicleID, phiScore, sigMask, isAnomaly ("true"/"false"), timestamp
func (s *SmartContract) SCTrustUpdate(ctx contractapi.TransactionContextInterface,
	vehicleID, phiScore, sigMask, isAnomalyStr, timestamp string) error {

	const alpha = 0.3 // smoothing factor (paper §3.5, legacy value)

	phi, _ := strconv.ParseFloat(phiScore, 64)
	isAnomaly := isAnomalyStr == "true" || isAnomalyStr == "1"

	id := fmt.Sprintf("SCTRUST_%s", vehicleID)
	var rec SCTrustScore

	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("SCTrustUpdate read failed: %v", err)
	}
	if data == nil {
		rec = SCTrustScore{ID: id, VehicleID: vehicleID, TrustScore: 1.0}
	} else {
		if err := json.Unmarshal(data, &rec); err != nil {
			return err
		}
	}

	// τ_i(t) = α·τ_i(t-1) + (1-α)·(1-Φ)
	rec.TrustScore  = alpha*rec.TrustScore + (1-alpha)*(1-phi)
	rec.PhiScore    = phi
	rec.SigMask     = sigMask
	rec.IsAnomaly   = isAnomaly
	rec.UpdateCount++
	rec.UpdatedAt   = timestamp

	recJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, recJSON)
}

// GetTrustScore – read the current MPTD-PQS trust score for a vehicle.
func (s *SmartContract) GetTrustScore(ctx contractapi.TransactionContextInterface,
	vehicleID string) (*SCTrustScore, error) {

	id := fmt.Sprintf("SCTRUST_%s", vehicleID)
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("GetTrustScore read failed: %v", err)
	}
	if data == nil {
		return &SCTrustScore{ID: id, VehicleID: vehicleID,
			TrustScore: 1.0, UpdatedAt: "never"}, nil
	}
	var rec SCTrustScore
	err = json.Unmarshal(data, &rec)
	return &rec, err
}

func (s *SmartContract) GetAllTrustScores(ctx contractapi.TransactionContextInterface) ([]*SCTrustScore, error) {
	iter, err := ctx.GetStub().GetStateByRange("SCTRUST_", "SCTRUST_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*SCTrustScore
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var r SCTrustScore
		if err := json.Unmarshal(qr.Value, &r); err != nil {
			return nil, err
		}
		results = append(results, &r)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// SC-Revoke: immutable revocation record (Stage 6)
// Key prefix: SCREVOKE_<vehicleID>_<timestamp>
// A vehicle is considered revoked if ANY SCREVOKE_ record exists for it.
// ─────────────────────────────────────────────────────────────────────────────

// RevokeRecord – immutable record written when a vehicle is revoked
type RevokeRecord struct {
	ID        string `json:"ID"`
	VehicleID string `json:"VehicleID"`
	Reason    string `json:"Reason"`    // e.g. "3_consecutive_anomalies"
	RSUID     string `json:"RSUID"`     // RSU that triggered revocation
	Timestamp string `json:"Timestamp"`
	RevokedAt string `json:"RevokedAt"`
}

// SCRevoke – LEGACY single-RSU revocation path (deprecated).
//
// This entry point lets ONE RSU write a revocation record unilaterally and is
// therefore NOT compatible with paper Eq 3.58 (which requires ≥ 2f+1 distinct
// RSU votes for revocation under BFT consensus).  It is preserved only so
// existing Stage-6 integrations keep working.
//
// New code MUST use SCRevokeVote(...), which (a) records the per-RSU vote
// idempotently, (b) counts distinct voters across all stored votes, and (c)
// commits the immutable SCREVOKE_ record + emits "SCRevoke" event only once
// the 2f+1 threshold is reached.
// Args: vehicleID, reason, rsuID, timestamp
func (s *SmartContract) SCRevoke(ctx contractapi.TransactionContextInterface,
	vehicleID, reason, rsuID, timestamp string) error {

	id := fmt.Sprintf("SCREVOKE_%s_%s", vehicleID, timestamp)
	rec := RevokeRecord{
		ID:        id,
		VehicleID: vehicleID,
		Reason:    reason,
		RSUID:     rsuID,
		Timestamp: timestamp,
		RevokedAt: time.Now().Format(time.RFC3339),
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	ctx.GetStub().SetEvent("SCRevoke",
		[]byte(fmt.Sprintf(`{"vehicleID":"%s","reason":"%s"}`, vehicleID, reason)))
	return ctx.GetStub().PutState(id, recJSON)
}

// IsRevoked – returns "true" or "false" string (chaincode args are strings).
func (s *SmartContract) IsRevoked(ctx contractapi.TransactionContextInterface,
	vehicleID string) (string, error) {

	prefix := fmt.Sprintf("SCREVOKE_%s_", vehicleID)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return "false", err
	}
	defer iter.Close()
	if iter.HasNext() {
		return "true", nil
	}
	return "false", nil
}

func (s *SmartContract) GetAllRevokeRecords(ctx contractapi.TransactionContextInterface) ([]*RevokeRecord, error) {
	iter, err := ctx.GetStub().GetStateByRange("SCREVOKE_", "SCREVOKE_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var results []*RevokeRecord
	for iter.HasNext() {
		qr, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var r RevokeRecord
		if err := json.Unmarshal(qr.Value, &r); err != nil {
			return nil, err
		}
		results = append(results, &r)
	}
	return results, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyAuthConditions – query endpoint for authentication verification
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) VerifyAuthConditions(ctx contractapi.TransactionContextInterface,
	repSta, locSta, idSta, timeExpired, hmacMatch, zkpVerified string) (string, error) {

	// Simple verification logic: all conditions must be true, none expired
	allValid := (repSta == "true" && locSta == "true" && idSta == "true" &&
		timeExpired == "false" && hmacMatch == "true" && zkpVerified == "true")

	result := fmt.Sprintf(`{"verified":%t,"repSta":"%s","locSta":"%s","idSta":"%s","timeExpired":"%s","hmacMatch":"%s","zkpVerified":"%s"}`,
		allValid, repSta, locSta, idSta, timeExpired, hmacMatch, zkpVerified)
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// MPTD-PQS paper §3.5.5 — Distributed Trust / Revocation / Controller Audit
//
// This block implements the canonical paper-aligned versions of:
//   • SC-Trust   per Eq 3.55  (mean RSU anomaly EMA + T_rev consecutive-epoch gate)
//   • SC-Revoke  per Eq 3.58  (BFT 2f+1 distinct-RSU vote threshold)
//   • CP-DETECT  per Eq 3.59  (f+1 RSU-vs-controller conflict gate)
//
// Evidence tuples follow Eq 3.56 / 3.57:
//   E_j(t) = (ID_i, ψ_j^{(i)}(t), t, h(b_i(t)), σ_j^sub)        — RSU evidence
//   E_c(t) = (ID_i, Φ_i(t),       t, h(X_i(t)), σ_c^sub)        — Controller evidence
//
// Only the hash h(b_i(t)) is stored on-chain; raw beacon payload lives in IPFS
// (paper invariant: blockchain holds only references + scores, never raw
// kinematics).
//
// Legacy SCTrustUpdate / SCRevoke from the Stage-6 prototype are kept above
// for backward compatibility but DO NOT satisfy Eq 3.55 / Eq 3.58. New
// ingestion paths must use this block.
// ─────────────────────────────────────────────────────────────────────────────

// NetworkConfig — system-wide BFT parameters.  Bootstrap via SCInitNetworkConfig.
type NetworkConfig struct {
	ID           string  `json:"ID"`           // always "NETCFG"
	NumRSUs      int     `json:"NumRSUs"`      // |R_total| (channel-wide RSU count)
	Alpha        float64 `json:"Alpha"`        // EMA factor in Eq 3.55
	TauThreshold float64 `json:"TauThreshold"` // τ_th — trust floor for T_rev gate
	TRev         int     `json:"TRev"`         // T_rev consecutive-epoch gate
	PsiAnomalyTh float64 `json:"PsiAnomalyTh"` // ψ_th — anomaly cutoff (used by CP-DETECT)
	UpdatedAt    string  `json:"UpdatedAt"`
}

// EpochSubmission — Eq 3.56 E_j(t) tuple from RSU r_j on vehicle i at epoch t.
// Key: SUBM_<vehicleID>_<epoch>_<rsuID>  → at most one submission per (i,t,j).
type EpochSubmission struct {
	ID          string  `json:"ID"`
	VehicleID   string  `json:"VehicleID"`
	RSUID       string  `json:"RSUID"`
	Epoch       string  `json:"Epoch"`
	Psi         float64 `json:"Psi"`        // ψ_j^{(i)}(t) anomaly score
	BeaconHash  string  `json:"BeaconHash"` // h(b_i(t)) — IPFS CID or content hash
	Signature   string  `json:"Signature"`  // σ_j^sub
	SubmittedAt string  `json:"SubmittedAt"`
}

// ControllerSubmission — Eq 3.57 E_c(t) tuple from controller on vehicle i.
// Key: CSUBM_<vehicleID>_<epoch>
type ControllerSubmission struct {
	ID           string  `json:"ID"`
	ControllerID string  `json:"ControllerID"`
	VehicleID    string  `json:"VehicleID"`
	Epoch        string  `json:"Epoch"`
	Phi          float64 `json:"Phi"`        // Φ_i(t) controller's fused score
	BeaconHash   string  `json:"BeaconHash"` // h(X_i(t))
	Signature    string  `json:"Signature"`  // σ_c^sub
	SubmittedAt  string  `json:"SubmittedAt"`
}

// RevokeVote — per-RSU vote for revoking a vehicle (BFT 2f+1, Eq 3.58).
// Key: VOTE_<vehicleID>_<rsuID>  (one vote per RSU; idempotent on resend).
type RevokeVote struct {
	ID        string `json:"ID"`
	VehicleID string `json:"VehicleID"`
	RSUID     string `json:"RSUID"`
	Reason    string `json:"Reason"`
	Signature string `json:"Signature"`
	VotedAt   string `json:"VotedAt"`
}

// ControllerFlag — CP-DETECT result (Eq 3.59) when ≥ f+1 RSUs disagree.
// Key: CFLAG_<controllerID>_<vehicleID>_<epoch>
type ControllerFlag struct {
	ID            string `json:"ID"`
	ControllerID  string `json:"ControllerID"`
	VehicleID     string `json:"VehicleID"`
	Epoch         string `json:"Epoch"`
	ConflictCount int    `json:"ConflictCount"`
	NumRSUs       int    `json:"NumRSUs"`
	ThresholdFP1  int    `json:"ThresholdFP1"` // f+1 used at evaluation time
	FlaggedAt     string `json:"FlaggedAt"`
}

// fByzantine returns Byzantine-tolerance f given the total RSU count.
// Hyperledger requires n ≥ 3f+1, so f = floor((n-1)/3).  Returns 0 if n < 4.
func fByzantine(numRSUs int) int {
	if numRSUs < 4 {
		return 0
	}
	return (numRSUs - 1) / 3
}

// ── NetworkConfig ────────────────────────────────────────────────────────────

// SCInitNetworkConfig — bootstrap or update channel-wide BFT parameters.
// Args: numRSUs, alpha, tauTh, T_rev, psiAnomalyTh   (all strings)
func (s *SmartContract) SCInitNetworkConfig(ctx contractapi.TransactionContextInterface,
	numRSUsStr, alphaStr, tauThStr, tRevStr, psiThStr string) error {

	numRSUs, err := strconv.Atoi(numRSUsStr)
	if err != nil {
		return fmt.Errorf("numRSUs parse: %v", err)
	}
	if numRSUs < 4 {
		return fmt.Errorf("numRSUs=%d too small; BFT needs N ≥ 4 (so f ≥ 1)", numRSUs)
	}
	alpha, err := strconv.ParseFloat(alphaStr, 64)
	if err != nil {
		return fmt.Errorf("alpha parse: %v", err)
	}
	tauTh, err := strconv.ParseFloat(tauThStr, 64)
	if err != nil {
		return fmt.Errorf("tauTh parse: %v", err)
	}
	tRev, err := strconv.Atoi(tRevStr)
	if err != nil {
		return fmt.Errorf("tRev parse: %v", err)
	}
	psiTh, err := strconv.ParseFloat(psiThStr, 64)
	if err != nil {
		return fmt.Errorf("psiTh parse: %v", err)
	}

	cfg := NetworkConfig{
		ID:           "NETCFG",
		NumRSUs:      numRSUs,
		Alpha:        alpha,
		TauThreshold: tauTh,
		TRev:         tRev,
		PsiAnomalyTh: psiTh,
		UpdatedAt:    time.Now().Format(time.RFC3339),
	}
	j, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState("NETCFG", j)
}

// GetNetworkConfig — read NETCFG; if absent, return sensible paper-§4.1.3 defaults.
func (s *SmartContract) GetNetworkConfig(ctx contractapi.TransactionContextInterface) (*NetworkConfig, error) {
	data, err := ctx.GetStub().GetState("NETCFG")
	if err != nil {
		return nil, err
	}
	if data == nil {
		return &NetworkConfig{
			ID:           "NETCFG",
			NumRSUs:      4,   // minimum N for BFT (f=1)
			Alpha:        0.3, // EMA smoothing (paper §3.5)
			TauThreshold: 0.5, // τ_th
			TRev:         3,   // T_rev consecutive-epoch gate
			PsiAnomalyTh: 0.5, // ψ_th
			UpdatedAt:    "default",
		}, nil
	}
	var c NetworkConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ── Eq 3.56 / 3.57: evidence submission ──────────────────────────────────────

// SCTrustSubmitEvidence — RSU r_j writes E_j(t) tuple for vehicle i in epoch t.
// Args: vehicleID, rsuID, epoch, psi, beaconHash, signature
// Idempotent: re-submitting overwrites the previous entry for the same (i,t,j).
func (s *SmartContract) SCTrustSubmitEvidence(ctx contractapi.TransactionContextInterface,
	vehicleID, rsuID, epoch, psiStr, beaconHash, signature string) error {

	psi, err := strconv.ParseFloat(psiStr, 64)
	if err != nil {
		return fmt.Errorf("psi parse: %v", err)
	}
	id := fmt.Sprintf("SUBM_%s_%s_%s", vehicleID, epoch, rsuID)
	rec := EpochSubmission{
		ID:          id,
		VehicleID:   vehicleID,
		RSUID:       rsuID,
		Epoch:       epoch,
		Psi:         psi,
		BeaconHash:  beaconHash,
		Signature:   signature,
		SubmittedAt: time.Now().Format(time.RFC3339),
	}
	j, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, j)
}

// SCControllerSubmitEvidence — Controller writes E_c(t) tuple for vehicle i.
// Args: vehicleID, controllerID, epoch, phi, beaconHash, signature
// Idempotent on (vehicleID, epoch).
func (s *SmartContract) SCControllerSubmitEvidence(ctx contractapi.TransactionContextInterface,
	vehicleID, controllerID, epoch, phiStr, beaconHash, signature string) error {

	phi, err := strconv.ParseFloat(phiStr, 64)
	if err != nil {
		return fmt.Errorf("phi parse: %v", err)
	}
	id := fmt.Sprintf("CSUBM_%s_%s", vehicleID, epoch)
	rec := ControllerSubmission{
		ID:           id,
		ControllerID: controllerID,
		VehicleID:    vehicleID,
		Epoch:        epoch,
		Phi:          phi,
		BeaconHash:   beaconHash,
		Signature:    signature,
		SubmittedAt:  time.Now().Format(time.RFC3339),
	}
	j, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, j)
}

// ── Eq 3.55: SC-Trust finalize per-epoch ─────────────────────────────────────

// SCTrustFinalizeEpoch — once an epoch closes, compute mean RSU anomaly and
// update τ_i(t) per Eq 3.55.  Also updates the T_rev consecutive-low counter
// and emits "TrustLow" event when ConsecutiveLowEpochs ≥ T_rev so RSUs can
// begin voting on revocation.
//
// Args: vehicleID, epoch
// Returns the updated SCTrustScore record.
func (s *SmartContract) SCTrustFinalizeEpoch(ctx contractapi.TransactionContextInterface,
	vehicleID, epoch string) (*SCTrustScore, error) {

	cfg, err := s.GetNetworkConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("NetworkConfig: %v", err)
	}

	// 1. Aggregate all RSU submissions for this (vehicleID, epoch).
	prefix := fmt.Sprintf("SUBM_%s_%s_", vehicleID, epoch)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	seenRSU := make(map[string]bool)
	sumPsi := 0.0
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var sub EpochSubmission
		if e := json.Unmarshal(qr.Value, &sub); e != nil {
			return nil, e
		}
		if seenRSU[sub.RSUID] {
			continue // dedupe in case of replays / re-submissions
		}
		seenRSU[sub.RSUID] = true
		sumPsi += sub.Psi
	}
	numWitnesses := len(seenRSU)
	if numWitnesses == 0 {
		return nil, fmt.Errorf("SCTrustFinalizeEpoch: no submissions for %s @ %s",
			vehicleID, epoch)
	}
	meanPsi := sumPsi / float64(numWitnesses)

	// 2. Read prior trust score (initialise to 1.0 if absent).
	id := fmt.Sprintf("SCTRUST_%s", vehicleID)
	var rec SCTrustScore
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		rec = SCTrustScore{ID: id, VehicleID: vehicleID, TrustScore: 1.0}
	} else {
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, err
		}
	}

	// 3. Eq 3.55: τ_i(t) = α·τ_i(t-1) + (1-α)·(1 - meanPsi)
	rec.TrustScore = cfg.Alpha*rec.TrustScore + (1-cfg.Alpha)*(1-meanPsi)
	rec.MeanPsi = meanPsi
	rec.NumRSUsLastEpoch = numWitnesses
	rec.LastEpochTimestamp = epoch
	rec.UpdateCount++
	rec.UpdatedAt = time.Now().Format(time.RFC3339)

	// 4. T_rev consecutive-low-epoch gate.
	if rec.TrustScore < cfg.TauThreshold {
		rec.ConsecutiveLowEpochs++
	} else {
		rec.ConsecutiveLowEpochs = 0
	}

	// 5. Emit TrustLow event if T_rev reached so RSUs can begin voting on SCRevoke.
	if rec.ConsecutiveLowEpochs >= cfg.TRev {
		ctx.GetStub().SetEvent("TrustLow", []byte(fmt.Sprintf(
			`{"vehicleID":"%s","epoch":"%s","trust":%f,"consec":%d,"trev":%d}`,
			vehicleID, epoch, rec.TrustScore, rec.ConsecutiveLowEpochs, cfg.TRev)))
	}

	j, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(id, j); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ── Eq 3.59: CP-DETECT controller-conflict ───────────────────────────────────

// CPDetectCheck — count RSU disagreements with the controller for (vehicleID, epoch).
// Disagreement is defined as binary classification mismatch:
//   conflict_j  =  (Φ_i > ψ_th)  XOR  (ψ_j^{(i)} > ψ_th)
// If the total conflict count ≥ f+1, writes ControllerFlag and emits
// "CPDetectFlag" event.  Returns nil if no flag was raised.
func (s *SmartContract) CPDetectCheck(ctx contractapi.TransactionContextInterface,
	vehicleID, epoch string) (*ControllerFlag, error) {

	cfg, err := s.GetNetworkConfig(ctx)
	if err != nil {
		return nil, err
	}

	csubData, err := ctx.GetStub().GetState(fmt.Sprintf("CSUBM_%s_%s", vehicleID, epoch))
	if err != nil {
		return nil, err
	}
	if csubData == nil {
		return nil, nil // no controller submission → nothing to check
	}
	var cs ControllerSubmission
	if err := json.Unmarshal(csubData, &cs); err != nil {
		return nil, err
	}
	cAnom := cs.Phi > cfg.PsiAnomalyTh

	prefix := fmt.Sprintf("SUBM_%s_%s_", vehicleID, epoch)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	seenRSU := make(map[string]bool)
	conflict := 0
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var sub EpochSubmission
		if e := json.Unmarshal(qr.Value, &sub); e != nil {
			return nil, e
		}
		if seenRSU[sub.RSUID] {
			continue
		}
		seenRSU[sub.RSUID] = true
		rAnom := sub.Psi > cfg.PsiAnomalyTh
		if cAnom != rAnom {
			conflict++
		}
	}

	f := fByzantine(cfg.NumRSUs)
	fP1 := f + 1
	if conflict < fP1 || len(seenRSU) == 0 {
		return nil, nil // not enough RSUs disagree
	}

	flag := ControllerFlag{
		ID:            fmt.Sprintf("CFLAG_%s_%s_%s", cs.ControllerID, vehicleID, epoch),
		ControllerID:  cs.ControllerID,
		VehicleID:     vehicleID,
		Epoch:         epoch,
		ConflictCount: conflict,
		NumRSUs:       len(seenRSU),
		ThresholdFP1:  fP1,
		FlaggedAt:     time.Now().Format(time.RFC3339),
	}
	j, err := json.Marshal(flag)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(flag.ID, j); err != nil {
		return nil, err
	}
	ctx.GetStub().SetEvent("CPDetectFlag", []byte(fmt.Sprintf(
		`{"controllerID":"%s","vehicleID":"%s","epoch":"%s","conflict":%d,"threshold":%d}`,
		cs.ControllerID, vehicleID, epoch, conflict, fP1)))
	return &flag, nil
}

// IsControllerFlagged — returns "true" / "false" based on whether ANY
// CFLAG_ record exists for the controller.
func (s *SmartContract) IsControllerFlagged(ctx contractapi.TransactionContextInterface,
	controllerID string) (string, error) {
	prefix := fmt.Sprintf("CFLAG_%s_", controllerID)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return "false", err
	}
	defer iter.Close()
	if iter.HasNext() {
		return "true", nil
	}
	return "false", nil
}

func (s *SmartContract) GetAllControllerFlags(ctx contractapi.TransactionContextInterface) ([]*ControllerFlag, error) {
	iter, err := ctx.GetStub().GetStateByRange("CFLAG_", "CFLAG_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var out []*ControllerFlag
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var f ControllerFlag
		if e := json.Unmarshal(qr.Value, &f); e != nil {
			return nil, e
		}
		out = append(out, &f)
	}
	return out, nil
}

// ── Eq 3.58: SC-Revoke BFT 2f+1 vote ─────────────────────────────────────────

// SCRevokeVote — RSU r_j casts a revocation vote for vehicle i.  After storing
// the vote, count distinct RSU votes; if ≥ 2f+1, write the immutable
// SCREVOKE_<vehicleID>_<timestamp> record and emit "SCRevoke" event.
//
// Args: vehicleID, rsuID, reason, signature, timestamp
// Returns: {"voted":true,"votes":N,"threshold":2f+1,"revoked":bool}
func (s *SmartContract) SCRevokeVote(ctx contractapi.TransactionContextInterface,
	vehicleID, rsuID, reason, signature, timestamp string) (string, error) {

	cfg, err := s.GetNetworkConfig(ctx)
	if err != nil {
		return "", err
	}

	// 1. Store the vote (idempotent per RSU).
	voteID := fmt.Sprintf("VOTE_%s_%s", vehicleID, rsuID)
	vote := RevokeVote{
		ID:        voteID,
		VehicleID: vehicleID,
		RSUID:     rsuID,
		Reason:    reason,
		Signature: signature,
		VotedAt:   time.Now().Format(time.RFC3339),
	}
	vJSON, err := json.Marshal(vote)
	if err != nil {
		return "", err
	}
	if err := ctx.GetStub().PutState(voteID, vJSON); err != nil {
		return "", err
	}

	// 2. Count distinct votes.
	//
	// IMPORTANT: in Fabric, PutState writes within a transaction are NOT visible
	// to GetStateByRange in the same transaction — the iterator only sees the
	// already-committed state. We therefore seed `seen` with the rsuID we just
	// wrote so the threshold check fires on the same TX that pushes the count
	// over 2f+1 (otherwise it would lag one TX behind and SCRevoke would never
	// commit until a 4th, redundant vote arrived).
	prefix := fmt.Sprintf("VOTE_%s_", vehicleID)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return "", err
	}
	defer iter.Close()
	seen := make(map[string]bool)
	seen[rsuID] = true // count the vote we just PutState'd in this TX
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return "", e
		}
		var v RevokeVote
		if e := json.Unmarshal(qr.Value, &v); e != nil {
			return "", e
		}
		seen[v.RSUID] = true
	}
	count := len(seen)
	f := fByzantine(cfg.NumRSUs)
	threshold := 2*f + 1

	// 3. Commit revocation iff threshold reached AND no prior SCREVOKE_ exists.
	revoked := false
	if count >= threshold {
		chkPrefix := fmt.Sprintf("SCREVOKE_%s_", vehicleID)
		chk, e2 := ctx.GetStub().GetStateByRange(chkPrefix, chkPrefix+"~")
		if e2 != nil {
			return "", e2
		}
		already := chk.HasNext()
		chk.Close()
		if !already {
			id := fmt.Sprintf("SCREVOKE_%s_%s", vehicleID, timestamp)
			rev := RevokeRecord{
				ID:        id,
				VehicleID: vehicleID,
				Reason:    reason,
				RSUID:     rsuID,
				Timestamp: timestamp,
				RevokedAt: time.Now().Format(time.RFC3339),
			}
			rJSON, err := json.Marshal(rev)
			if err != nil {
				return "", err
			}
			if err := ctx.GetStub().PutState(id, rJSON); err != nil {
				return "", err
			}
			ctx.GetStub().SetEvent("SCRevoke", []byte(fmt.Sprintf(
				`{"vehicleID":"%s","reason":"%s","votes":%d,"threshold":%d}`,
				vehicleID, reason, count, threshold)))
		}
		revoked = true
	}
	return fmt.Sprintf(`{"voted":true,"votes":%d,"threshold":%d,"revoked":%t}`,
		count, threshold, revoked), nil
}

// SCRevokeStatus — diagnostics: current vote count + threshold + revoked flag.
func (s *SmartContract) SCRevokeStatus(ctx contractapi.TransactionContextInterface,
	vehicleID string) (string, error) {

	cfg, err := s.GetNetworkConfig(ctx)
	if err != nil {
		return "", err
	}

	prefix := fmt.Sprintf("VOTE_%s_", vehicleID)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return "", err
	}
	defer iter.Close()
	seen := make(map[string]bool)
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return "", e
		}
		var v RevokeVote
		if e := json.Unmarshal(qr.Value, &v); e != nil {
			return "", e
		}
		seen[v.RSUID] = true
	}
	isRev, _ := s.IsRevoked(ctx, vehicleID)
	f := fByzantine(cfg.NumRSUs)
	threshold := 2*f + 1
	return fmt.Sprintf(`{"votes":%d,"threshold":%d,"revoked":%s}`,
		len(seen), threshold, isRev), nil
}

// GetEpochSubmissions — list all RSU submissions for one (vehicleID, epoch).
func (s *SmartContract) GetEpochSubmissions(ctx contractapi.TransactionContextInterface,
	vehicleID, epoch string) ([]*EpochSubmission, error) {

	prefix := fmt.Sprintf("SUBM_%s_%s_", vehicleID, epoch)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var out []*EpochSubmission
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var sub EpochSubmission
		if e := json.Unmarshal(qr.Value, &sub); e != nil {
			return nil, e
		}
		out = append(out, &sub)
	}
	return out, nil
}

// GetControllerSubmission — fetch the controller's E_c(t) for (vehicleID, epoch).
func (s *SmartContract) GetControllerSubmission(ctx contractapi.TransactionContextInterface,
	vehicleID, epoch string) (*ControllerSubmission, error) {

	id := fmt.Sprintf("CSUBM_%s_%s", vehicleID, epoch)
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("no controller submission for %s @ %s", vehicleID, epoch)
	}
	var cs ControllerSubmission
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, err
	}
	return &cs, nil
}

// GetRevokeVotes — list all stored votes for a vehicle.
func (s *SmartContract) GetRevokeVotes(ctx contractapi.TransactionContextInterface,
	vehicleID string) ([]*RevokeVote, error) {

	prefix := fmt.Sprintf("VOTE_%s_", vehicleID)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var out []*RevokeVote
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var v RevokeVote
		if e := json.Unmarshal(qr.Value, &v); e != nil {
			return nil, e
		}
		out = append(out, &v)
	}
	return out, nil
}
