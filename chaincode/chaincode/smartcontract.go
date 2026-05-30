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

// SCTrustScore – per-vehicle trust score maintained by MPTD-PQS detection
type SCTrustScore struct {
	ID          string  `json:"ID"`
	VehicleID   string  `json:"VehicleID"`
	TrustScore  float64 `json:"TrustScore"`   // τ_i ∈ [0,1]; higher = more trusted
	PhiScore    float64 `json:"PhiScore"`     // last Φ_i(t) fused anomaly score
	SigMask     string  `json:"SigMask"`      // bitmask of triggered detection rules
	IsAnomaly   bool    `json:"IsAnomaly"`    // last detection decision
	UpdateCount int     `json:"UpdateCount"`  // number of updates received
	UpdatedAt   string  `json:"UpdatedAt"`
}

// SCTrustUpdate – update the running trust score for a vehicle.
// Args: vehicleID, phiScore, sigMask, isAnomaly ("true"/"false"), timestamp
func (s *SmartContract) SCTrustUpdate(ctx contractapi.TransactionContextInterface,
	vehicleID, phiScore, sigMask, isAnomalyStr, timestamp string) error {

	const alpha = 0.3 // smoothing factor (paper §3.5)

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

// SCRevoke – write an immutable revocation record for a vehicle.
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
