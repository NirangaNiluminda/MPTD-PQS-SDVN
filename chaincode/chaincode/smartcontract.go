// MPTD-PQS chaincode — paper §3.5.5 distributed trust layer.
//
// Implements the four smart contracts from the framework's "Blockchain Trust
// Layer" section (paper §3.5.5):
//   • SC-Register (Algorithm 7)        — on-chain identity onboarding with
//                                        ≥ 2f+1 RSU endorsement quorum.
//   • SC-Trust    (Eq 3.55 / 3.56 / 3.57)
//                                       — epoch-aggregated EMA trust score
//                                         with T_rev consecutive-low gate.
//   • CP-DETECT   (Algorithm 8, Eq 3.59)
//                                       — controller / RSU disagreement
//                                         flag at f+1 threshold.
//   • SC-Revoke   (Eq 3.58)             — BFT 2f+1 distinct-RSU revocation
//                                         vote → immutable revocation
//                                         record + SCRevoke event.
//
// Architectural invariants honoured:
//   1. RSU → blockchain submissions are direct (no controller relay; the
//      controller appears as a non-authoritative peer per invariant 2).
//   2. SC-Trust evidence and SC-Revoke votes are accepted ONLY from
//      identities that hold a valid on-chain registration record (status
//      = ACTIVE). This is the SC-Register gate established in Algorithm 7
//      and referenced in §3.5.5 ("SC-Trust processes anomaly evidence
//      exclusively for identities with a valid on-chain registration").
//   3. Lazy SCTRUST_<id> materialisation is gone — τ_init is committed at
//      registration time, so finalize-epoch reads a record that always
//      exists for registered vehicles.
//
// Crypto choices (decided in TASK ② design-gap resolution):
//   • Endorsement signature = EC-ECDSA on the NIST P-256 curve, ASN.1-DER
//     encoded. Reuses each RSU's existing Fabric MSP identity key.
//   • τ_init = 1.0 (benign vehicles start fully trusted; SC-Trust's EMA
//     only drags scores down on detected anomalies).
//   • Endorsement digest = SHA-256(vehicleID ‖ pkHex ‖ hKuHex). String
//     concatenation matches the NS-3 endorsement-collection path.
//
// Bootstrap: paper §3.5.5 does not specify how the first 2f+1 RSUs come
// online with no peers to endorse them. SCBootstrapRSU is the explicit
// genesis-time path used by the simulation driver — it is intentionally
// admin-flavoured (callers must hold an Org1MSP identity) and is exercised
// only at sim start for the initial RSU set. Every subsequent registration
// — RSU additions, vehicle onboarding — flows through SCRegister with
// strict endorsement enforcement.
package chaincode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

type SmartContract struct {
	contractapi.Contract
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const (
	RoleVehicle    = "VEHICLE"
	RoleRSU        = "RSU"
	RoleController = "CONTROLLER"

	StatusActive  = "ACTIVE"
	StatusRevoked = "REVOKED"

	// τ_init at registration time. Paper §3.5.5 mentions τ_init without a
	// numeric default; we set it to the fully-clean ceiling so SC-Trust's
	// EMA (Eq 3.55) only ever drags benign vehicles down on real anomalies.
	TauInit = 1.0
)

// ─────────────────────────────────────────────────────────────────────────────
// Data structures
// ─────────────────────────────────────────────────────────────────────────────

// RegistrationRecord — Algorithm 7 SC-Register output. Stored under key
// REG_<ID>. Status flips to "REVOKED" when SC-Revoke commits.
type RegistrationRecord struct {
	ID           string  `json:"ID"`
	Role         string  `json:"Role"`         // VEHICLE | RSU | CONTROLLER
	PkHex        string  `json:"PkHex"`        // uncompressed P-256, 0x04‖X‖Y, 130 hex chars
	HKuHex       string  `json:"HKuHex"`       // h(K_u_i), 64 hex chars (SHA-256)
	TauInit      float64 `json:"TauInit"`      // τ_init at registration
	Status       string  `json:"Status"`       // ACTIVE | REVOKED
	TReg         string  `json:"TReg"`         // caller-supplied registration timestamp
	RegisteredAt string  `json:"RegisteredAt"` // server-side commit time (RFC3339)
}

// NetworkConfig — channel-wide BFT parameters. Bootstrap via SCInitNetworkConfig.
type NetworkConfig struct {
	ID           string  `json:"ID"`           // always "NETCFG"
	NumRSUs      int     `json:"NumRSUs"`      // |R_total|
	Alpha        float64 `json:"Alpha"`        // EMA factor in Eq 3.55
	TauThreshold float64 `json:"TauThreshold"` // τ_th — trust floor for T_rev gate
	TRev         int     `json:"TRev"`         // T_rev consecutive-epoch gate
	PsiAnomalyTh float64 `json:"PsiAnomalyTh"` // ψ_th — anomaly cutoff
	UpdatedAt    string  `json:"UpdatedAt"`
}

// SCTrustScore — per-vehicle EMA trust score (Eq 3.55). Created at registration
// with TrustScore = TauInit; updated by SCTrustFinalizeEpoch.
type SCTrustScore struct {
	ID                   string  `json:"ID"`
	VehicleID            string  `json:"VehicleID"`
	TrustScore           float64 `json:"TrustScore"`           // τ_i ∈ [0,1]; higher = more trusted
	MeanPsi              float64 `json:"MeanPsi"`              // (1/|R|)·Σ ψ_j^{(i)}(t) from last finalised epoch
	NumRSUsLastEpoch     int     `json:"NumRSUsLastEpoch"`     // |R| of last finalised epoch
	ConsecutiveLowEpochs int     `json:"ConsecutiveLowEpochs"` // running counter for T_rev gate
	LastEpochTimestamp   string  `json:"LastEpochTimestamp"`
	UpdateCount          int     `json:"UpdateCount"`
	UpdatedAt            string  `json:"UpdatedAt"`
}

// EpochSubmission — Eq 3.56 RSU evidence tuple. Key: SUBM_<vehicleID>_<epoch>_<rsuID>.
type EpochSubmission struct {
	ID          string  `json:"ID"`
	VehicleID   string  `json:"VehicleID"`
	RSUID       string  `json:"RSUID"`
	Epoch       string  `json:"Epoch"`
	Psi         float64 `json:"Psi"`        // ψ_j^{(i)}(t)
	BeaconHash  string  `json:"BeaconHash"` // h(b_i(t))
	Signature   string  `json:"Signature"`  // σ_j^sub
	SubmittedAt string  `json:"SubmittedAt"`
}

// ControllerSubmission — Eq 3.57 controller evidence tuple. Key: CSUBM_<vehicleID>_<epoch>.
type ControllerSubmission struct {
	ID           string  `json:"ID"`
	ControllerID string  `json:"ControllerID"`
	VehicleID    string  `json:"VehicleID"`
	Epoch        string  `json:"Epoch"`
	Phi          float64 `json:"Phi"`        // Φ_i(t)
	BeaconHash   string  `json:"BeaconHash"` // h(X_i(t))
	Signature    string  `json:"Signature"`  // σ_c^sub
	SubmittedAt  string  `json:"SubmittedAt"`
}

// RevokeVote — per-RSU vote (BFT 2f+1, Eq 3.58). Key: VOTE_<vehicleID>_<rsuID>.
type RevokeVote struct {
	ID        string `json:"ID"`
	VehicleID string `json:"VehicleID"`
	RSUID     string `json:"RSUID"`
	Reason    string `json:"Reason"`
	Signature string `json:"Signature"`
	VotedAt   string `json:"VotedAt"`
}

// RevokeRecord — immutable revocation entry (Eq 3.58). Key: SCREVOKE_<vehicleID>_<timestamp>.
type RevokeRecord struct {
	ID        string `json:"ID"`
	VehicleID string `json:"VehicleID"`
	Reason    string `json:"Reason"`
	RSUID     string `json:"RSUID"` // RSU that pushed the count over threshold
	Timestamp string `json:"Timestamp"`
	RevokedAt string `json:"RevokedAt"`
}

// ControllerFlag — CP-DETECT output (Eq 3.59). Key: CFLAG_<controllerID>_<vehicleID>_<epoch>.
type ControllerFlag struct {
	ID                 string `json:"ID"`
	ControllerID       string `json:"ControllerID"`
	VehicleID          string `json:"VehicleID"`
	Epoch              string `json:"Epoch"`
	ConflictCount      int    `json:"ConflictCount"`
	NumRSUs            int    `json:"NumRSUs"`
	ImplicitCleanVotes int    `json:"ImplicitCleanVotes"`
	ThresholdFP1       int    `json:"ThresholdFP1"`
	FlaggedAt          string `json:"FlaggedAt"`
}

// Endorser — one element of the endorsersJSON array passed to SCRegister.
type Endorser struct {
	RSUID  string `json:"rsuID"`
	SigHex string `json:"sigHex"` // ASN.1-DER ECDSA-P256 signature, hex-encoded
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle
// ─────────────────────────────────────────────────────────────────────────────

func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// fByzantine returns f given the total RSU count under the Fabric n ≥ 3f+1
// rule. Returns 0 when n < 4 so 2f+1 = 1 (degenerate single-RSU test setups).
func fByzantine(numRSUs int) int {
	if numRSUs < 4 {
		return 0
	}
	return (numRSUs - 1) / 3
}

// getRegistration returns the on-chain registration record for `id`, or nil
// if no record exists. Distinct error vs. nil is reserved for I/O failures.
func (s *SmartContract) getRegistration(ctx contractapi.TransactionContextInterface,
	id string) (*RegistrationRecord, error) {

	data, err := ctx.GetStub().GetState("REG_" + id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var rec RegistrationRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// requireActive asserts that `id` is registered with the given role and
// status = ACTIVE. Returns a chaincode-side rejection error when the gate
// fails so callers (SCTrust*, SCRevokeVote) bounce on unregistered IDs.
func (s *SmartContract) requireActive(ctx contractapi.TransactionContextInterface,
	id, expectedRole string) error {

	rec, err := s.getRegistration(ctx, id)
	if err != nil {
		return fmt.Errorf("registration lookup for %s: %v", id, err)
	}
	if rec == nil {
		return fmt.Errorf("rejected: %s is not registered", id)
	}
	if rec.Status != StatusActive {
		return fmt.Errorf("rejected: %s status=%s (expected ACTIVE)", id, rec.Status)
	}
	if expectedRole != "" && rec.Role != expectedRole {
		return fmt.Errorf("rejected: %s role=%s (expected %s)",
			id, rec.Role, expectedRole)
	}
	return nil
}

// parseP256PubKey decodes an uncompressed P-256 public key from hex.
// Expected format: 130 hex chars (1 byte 0x04 prefix + 32 bytes X + 32 bytes Y).
func parseP256PubKey(pkHex string) (*ecdsa.PublicKey, error) {
	raw, err := hex.DecodeString(pkHex)
	if err != nil {
		return nil, fmt.Errorf("pk hex decode: %v", err)
	}
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("pk must be 65-byte uncompressed P-256 (got %d bytes)", len(raw))
	}
	curve := elliptic.P256()
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("pk point not on P-256")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// verifyECDSAP256 verifies an ASN.1-DER ECDSA signature over `digest` using
// the public key in `pkHex`. Returns true on success, false on any failure
// (decode, parse, signature mismatch). Mirrors crypto/ecdsa.VerifyASN1.
func verifyECDSAP256(pkHex, sigHex string, digest []byte) bool {
	pub, err := parseP256PubKey(pkHex)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ecdsa.VerifyASN1(pub, digest, sig)
}

// endorsementDigest returns SHA-256(vehicleID ‖ pkHex ‖ hKuHex). The string
// concatenation is the canonical form NS-3 endorsement collectors hash, and
// must stay byte-identical on both sides.
func endorsementDigest(vehicleID, pkHex, hKuHex string) []byte {
	h := sha256.New()
	h.Write([]byte(vehicleID))
	h.Write([]byte(pkHex))
	h.Write([]byte(hKuHex))
	out := h.Sum(nil)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm 7 — SC-Register
// ─────────────────────────────────────────────────────────────────────────────

// SCRegister — paper Algorithm 7 verbatim.
// Args:
//   vehicleID   — paper ID_i; chaincode key suffix.
//   role        — "VEHICLE" | "RSU" | "CONTROLLER".
//   pkHex       — uncompressed P-256 pubkey (130 hex chars, "04…").
//   hKuHex      — SHA-256(K_u_i) hex (64 chars).
//   tReg        — caller-supplied registration timestamp.
//   endorsersJSON — JSON array [{"rsuID":"…","sigHex":"…"}, …].
//
// Returns nil on commit, or a "rejected: …" error on duplicate / insufficient
// endorsements / signature failure. Emits "Registered" event on commit so
// RSUs / vehicles can be tracked in real time by the gateway event drainer.
func (s *SmartContract) SCRegister(ctx contractapi.TransactionContextInterface,
	vehicleID, role, pkHex, hKuHex, tReg, endorsersJSON string) error {

	// 1. Validate role / encoding.
	switch role {
	case RoleVehicle, RoleRSU, RoleController:
	default:
		return fmt.Errorf("rejected: invalid role %q", role)
	}
	if _, err := parseP256PubKey(pkHex); err != nil {
		return fmt.Errorf("rejected: invalid pk: %v", err)
	}
	if len(hKuHex) != 64 {
		return fmt.Errorf("rejected: hKuHex must be 64 hex chars (got %d)", len(hKuHex))
	}
	if _, err := hex.DecodeString(hKuHex); err != nil {
		return fmt.Errorf("rejected: hKuHex not hex: %v", err)
	}

	// 2. Algorithm 7 line 2-4: duplicate-identity check.
	existing, err := s.getRegistration(ctx, vehicleID)
	if err != nil {
		return fmt.Errorf("registration lookup: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("rejected: duplicate identity %s", vehicleID)
	}

	// 3. Parse endorsements.
	var endorsers []Endorser
	if err := json.Unmarshal([]byte(endorsersJSON), &endorsers); err != nil {
		return fmt.Errorf("rejected: endorsersJSON parse: %v", err)
	}

	// 4. Algorithm 7 line 5: count distinct endorsing RSU peers whose
	//    on-chain pk verifies sigHex against the digest. Each endorser
	//    must be a registered ACTIVE RSU; we look up the pk on-chain so
	//    callers cannot inject arbitrary keys.
	digest := endorsementDigest(vehicleID, pkHex, hKuHex)
	seen := make(map[string]bool)
	validCount := 0
	for _, e := range endorsers {
		if e.RSUID == "" || e.SigHex == "" {
			continue
		}
		if seen[e.RSUID] {
			continue
		}
		regE, err := s.getRegistration(ctx, e.RSUID)
		if err != nil || regE == nil {
			continue
		}
		if regE.Role != RoleRSU || regE.Status != StatusActive {
			continue
		}
		if !verifyECDSAP256(regE.PkHex, e.SigHex, digest) {
			continue
		}
		seen[e.RSUID] = true
		validCount++
	}

	// 5. Algorithm 7 line 6-8: 2f+1 BFT threshold (Eq 3.58 same constant).
	cfg, err := s.GetNetworkConfig(ctx)
	if err != nil {
		return fmt.Errorf("NetworkConfig: %v", err)
	}
	threshold := 2*fByzantine(cfg.NumRSUs) + 1
	if validCount < threshold {
		return fmt.Errorf("rejected: insufficient endorsements (got %d valid, need %d)",
			validCount, threshold)
	}

	// 6. Algorithm 7 line 9-11: commit registration + initial trust state.
	rec := RegistrationRecord{
		ID:           vehicleID,
		Role:         role,
		PkHex:        pkHex,
		HKuHex:       hKuHex,
		TauInit:      TauInit,
		Status:       StatusActive,
		TReg:         tReg,
		RegisteredAt: time.Now().Format(time.RFC3339),
	}
	rJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("REG_"+vehicleID, rJSON); err != nil {
		return err
	}

	// Eagerly seed SCTRUST_<id> with τ_init so SCTrustFinalizeEpoch never
	// has to lazy-init a row for an unregistered vehicle.
	if role == RoleVehicle {
		if err := s.initTrustScore(ctx, vehicleID); err != nil {
			return err
		}
	}

	ctx.GetStub().SetEvent("Registered",
		[]byte(fmt.Sprintf(`{"ID":"%s","role":"%s","tReg":"%s"}`,
			vehicleID, role, tReg)))
	return nil
}

// SCBootstrapRSU — genesis-time path used to seed the initial RSU set when
// no peers yet exist to provide 2f+1 endorsements. Unconditionally commits
// a registration record with Role=RSU, Status=ACTIVE.
//
// SECURITY: in a multi-org production deployment this MUST be gated by a
// Fabric MSP admin role check (cid.GetMSPID + an "admin" OU attribute). The
// current test-network is single-org (Org1MSP), so all callers share the
// same MSP identity — the access control reduces to "the sim driver invokes
// this once at genesis, no runtime caller invokes it". Adding an OU-based
// admin check is a Phase 4 task once Fabric-CA per-node enrollment lands.
//
// Args: rsuID, pkHex, hKuHex, tReg
func (s *SmartContract) SCBootstrapRSU(ctx contractapi.TransactionContextInterface,
	rsuID, pkHex, hKuHex, tReg string) error {

	if _, err := parseP256PubKey(pkHex); err != nil {
		return fmt.Errorf("rejected: invalid pk: %v", err)
	}
	if len(hKuHex) != 64 {
		return fmt.Errorf("rejected: hKuHex must be 64 hex chars")
	}

	existing, err := s.getRegistration(ctx, rsuID)
	if err != nil {
		return fmt.Errorf("registration lookup: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("rejected: duplicate identity %s", rsuID)
	}

	rec := RegistrationRecord{
		ID:           rsuID,
		Role:         RoleRSU,
		PkHex:        pkHex,
		HKuHex:       hKuHex,
		TauInit:      TauInit,
		Status:       StatusActive,
		TReg:         tReg,
		RegisteredAt: time.Now().Format(time.RFC3339),
	}
	rJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("REG_"+rsuID, rJSON); err != nil {
		return err
	}

	ctx.GetStub().SetEvent("Registered",
		[]byte(fmt.Sprintf(`{"ID":"%s","role":"%s","tReg":"%s","bootstrap":true}`,
			rsuID, RoleRSU, tReg)))
	return nil
}

// GetRegistration — read a single registration record.
func (s *SmartContract) GetRegistration(ctx contractapi.TransactionContextInterface,
	id string) (*RegistrationRecord, error) {

	rec, err := s.getRegistration(ctx, id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return rec, nil
}

// IsRegistered — string-typed wrapper for clients that need a yes/no answer
// without the full record payload.
func (s *SmartContract) IsRegistered(ctx contractapi.TransactionContextInterface,
	id string) (string, error) {

	rec, err := s.getRegistration(ctx, id)
	if err != nil {
		return "false", err
	}
	if rec == nil || rec.Status != StatusActive {
		return "false", nil
	}
	return "true", nil
}

// GetAllRegistrations — list every committed registration record. Useful
// for diagnostics + sim-side verification of bootstrap completion.
func (s *SmartContract) GetAllRegistrations(ctx contractapi.TransactionContextInterface) ([]*RegistrationRecord, error) {
	iter, err := ctx.GetStub().GetStateByRange("REG_", "REG_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var out []*RegistrationRecord
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var r RegistrationRecord
		if e := json.Unmarshal(qr.Value, &r); e != nil {
			return nil, e
		}
		out = append(out, &r)
	}
	return out, nil
}

// initTrustScore seeds SCTRUST_<vehicleID> with TrustScore = TauInit. Called
// from SCRegister at registration time so SCTrustFinalizeEpoch can assume
// the row already exists.
func (s *SmartContract) initTrustScore(ctx contractapi.TransactionContextInterface,
	vehicleID string) error {

	id := "SCTRUST_" + vehicleID
	existing, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	if existing != nil {
		return nil // idempotent on duplicate-SCRegister bootstrap retries
	}
	rec := SCTrustScore{
		ID:         id,
		VehicleID:  vehicleID,
		TrustScore: TauInit,
		UpdatedAt:  time.Now().Format(time.RFC3339),
	}
	j, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, j)
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkConfig
// ─────────────────────────────────────────────────────────────────────────────

// SCInitNetworkConfig — bootstrap or update channel-wide BFT parameters.
// Args: numRSUs, alpha, tauTh, T_rev, psiAnomalyTh (all strings).
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

// GetNetworkConfig — read NETCFG; if absent, return paper §4.1.3 defaults.
func (s *SmartContract) GetNetworkConfig(ctx contractapi.TransactionContextInterface) (*NetworkConfig, error) {
	data, err := ctx.GetStub().GetState("NETCFG")
	if err != nil {
		return nil, err
	}
	if data == nil {
		return &NetworkConfig{
			ID:           "NETCFG",
			NumRSUs:      4,
			Alpha:        0.3,
			TauThreshold: 0.5,
			TRev:         3,
			PsiAnomalyTh: 0.5,
			UpdatedAt:    "default",
		}, nil
	}
	var c NetworkConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Eq 3.56 / 3.57 — evidence submission (REGISTRATION-GATED)
// ─────────────────────────────────────────────────────────────────────────────

// SCTrustSubmitEvidence — RSU r_j writes E_j(t) for vehicle i at epoch t.
// Idempotent on (i,t,j) — re-submitting overwrites the previous entry.
//
// REGISTRATION GATE: both vehicleID and rsuID must hold ACTIVE registrations.
func (s *SmartContract) SCTrustSubmitEvidence(ctx contractapi.TransactionContextInterface,
	vehicleID, rsuID, epoch, psiStr, beaconHash, signature string) error {

	if err := s.requireActive(ctx, vehicleID, RoleVehicle); err != nil {
		return err
	}
	if err := s.requireActive(ctx, rsuID, RoleRSU); err != nil {
		return err
	}

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

// SCControllerSubmitEvidence — Controller writes E_c(t) for vehicle i.
// Idempotent on (vehicleID, epoch).
//
// REGISTRATION GATE: both vehicleID and controllerID must hold ACTIVE
// registrations.
func (s *SmartContract) SCControllerSubmitEvidence(ctx contractapi.TransactionContextInterface,
	vehicleID, controllerID, epoch, phiStr, beaconHash, signature string) error {

	if err := s.requireActive(ctx, vehicleID, RoleVehicle); err != nil {
		return err
	}
	if err := s.requireActive(ctx, controllerID, RoleController); err != nil {
		return err
	}

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

// ─────────────────────────────────────────────────────────────────────────────
// Eq 3.55 — SC-Trust finalize per-epoch
// ─────────────────────────────────────────────────────────────────────────────

// SCTrustFinalizeEpoch — aggregate the RSU submissions for one (vehicle,
// epoch) and update τ_i per Eq 3.55. Increments the ConsecutiveLowEpochs
// counter when τ_i < τ_th, emits "TrustLow" once ConsecutiveLowEpochs ≥
// T_rev so RSUs begin voting on SC-Revoke.
//
// Lazy materialisation is gone — SCTRUST_<vehicleID> is created at
// SCRegister time, so a missing row means the vehicle is unregistered and
// finalize should not have been called.
//
// Args: vehicleID, epoch
// Returns the updated SCTrustScore record.
func (s *SmartContract) SCTrustFinalizeEpoch(ctx contractapi.TransactionContextInterface,
	vehicleID, epoch string) (*SCTrustScore, error) {

	if err := s.requireActive(ctx, vehicleID, RoleVehicle); err != nil {
		return nil, err
	}

	cfg, err := s.GetNetworkConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("NetworkConfig: %v", err)
	}

	// Aggregate distinct-RSU submissions for (vehicleID, epoch).
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
			continue
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

	// Read current SCTRUST_ record (must exist — created at SC-Register).
	id := "SCTRUST_" + vehicleID
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("SCTrustFinalizeEpoch: SCTRUST_%s missing (registration lost?)",
			vehicleID)
	}
	var rec SCTrustScore
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}

	// Eq 3.55: τ_i(t) = α·τ_i(t-1) + (1-α)·(1 - meanPsi).
	rec.TrustScore = cfg.Alpha*rec.TrustScore + (1-cfg.Alpha)*(1-meanPsi)
	rec.MeanPsi = meanPsi
	rec.NumRSUsLastEpoch = numWitnesses
	rec.LastEpochTimestamp = epoch
	rec.UpdateCount++
	rec.UpdatedAt = time.Now().Format(time.RFC3339)

	// T_rev consecutive-low-epoch gate.
	if rec.TrustScore < cfg.TauThreshold {
		rec.ConsecutiveLowEpochs++
	} else {
		rec.ConsecutiveLowEpochs = 0
	}

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

// GetTrustScore — read τ_i for one vehicle.
func (s *SmartContract) GetTrustScore(ctx contractapi.TransactionContextInterface,
	vehicleID string) (*SCTrustScore, error) {

	id := "SCTRUST_" + vehicleID
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("no trust score for %s (vehicle unregistered?)", vehicleID)
	}
	var rec SCTrustScore
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// GetAllTrustScores — list every vehicle's current trust score.
func (s *SmartContract) GetAllTrustScores(ctx contractapi.TransactionContextInterface) ([]*SCTrustScore, error) {
	iter, err := ctx.GetStub().GetStateByRange("SCTRUST_", "SCTRUST_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var out []*SCTrustScore
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var r SCTrustScore
		if e := json.Unmarshal(qr.Value, &r); e != nil {
			return nil, e
		}
		out = append(out, &r)
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Algorithm 8 / Eq 3.59 — CP-DETECT
// ─────────────────────────────────────────────────────────────────────────────

// CPDetectCheck — counts RSU disagreements with the controller for one
// (vehicleID, epoch). Disagreement is the binary classifier mismatch:
//
//	conflict_j  =  (Φ_i > ψ_th) XOR (ψ_j^{(i)} > ψ_th)
//
// Plus implicit clean votes: RSUs that did NOT submit a SUBM are reporting
// ψ_j ≤ ψ_th (the NS-3 RSU gating contract — only writes SUBM on anomaly).
// When the controller flags the vehicle as anomalous (cAnom=true) those
// implicit clean votes count as conflicts; when the controller agrees the
// vehicle is clean, missing SUBMs are agreement, not conflict.
//
// Returns the ControllerFlag on flag-fire, or nil if conflict < f+1.
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
		return nil, nil
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

	implicitCleanVotes := cfg.NumRSUs - len(seenRSU)
	if implicitCleanVotes < 0 {
		implicitCleanVotes = 0
	}
	if cAnom && implicitCleanVotes > 0 {
		conflict += implicitCleanVotes
	}

	f := fByzantine(cfg.NumRSUs)
	fP1 := f + 1
	if conflict < fP1 {
		return nil, nil
	}

	flag := ControllerFlag{
		ID:                 fmt.Sprintf("CFLAG_%s_%s_%s", cs.ControllerID, vehicleID, epoch),
		ControllerID:       cs.ControllerID,
		VehicleID:          vehicleID,
		Epoch:              epoch,
		ConflictCount:      conflict,
		NumRSUs:            len(seenRSU),
		ImplicitCleanVotes: implicitCleanVotes,
		ThresholdFP1:       fP1,
		FlaggedAt:          time.Now().Format(time.RFC3339),
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

// IsControllerFlagged — yes/no string for clients.
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

// ─────────────────────────────────────────────────────────────────────────────
// Eq 3.58 — SC-Revoke BFT 2f+1 vote (REGISTRATION-GATED)
// ─────────────────────────────────────────────────────────────────────────────

// SCRevokeVote — RSU r_j casts a revocation vote for vehicle i. Stores the
// vote idempotently, then counts distinct RSU votes; on ≥ 2f+1 commits the
// SCREVOKE_ record, flips the vehicle's registration Status to REVOKED,
// and emits "SCRevoke".
//
// REGISTRATION GATE: both vehicleID and rsuID must hold ACTIVE registrations.
//
// Returns: {"voted":true,"votes":N,"threshold":2f+1,"revoked":bool}
func (s *SmartContract) SCRevokeVote(ctx contractapi.TransactionContextInterface,
	vehicleID, rsuID, reason, signature, timestamp string) (string, error) {

	if err := s.requireActive(ctx, vehicleID, RoleVehicle); err != nil {
		return "", err
	}
	if err := s.requireActive(ctx, rsuID, RoleRSU); err != nil {
		return "", err
	}

	cfg, err := s.GetNetworkConfig(ctx)
	if err != nil {
		return "", err
	}

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

	// Count distinct votes. PutState inside a TX is not visible to
	// GetStateByRange inside the same TX, so seed `seen` with the rsuID
	// we just wrote — otherwise the threshold check lags by one TX.
	prefix := fmt.Sprintf("VOTE_%s_", vehicleID)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return "", err
	}
	defer iter.Close()
	seen := make(map[string]bool)
	seen[rsuID] = true
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
			// Flip registration status to REVOKED so subsequent
			// evidence / vote submissions for this vehicle bounce
			// at the requireActive gate.
			regData, err := ctx.GetStub().GetState("REG_" + vehicleID)
			if err == nil && regData != nil {
				var reg RegistrationRecord
				if err := json.Unmarshal(regData, &reg); err == nil {
					reg.Status = StatusRevoked
					rj, _ := json.Marshal(reg)
					_ = ctx.GetStub().PutState("REG_"+vehicleID, rj)
				}
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

// SCRevokeStatus — diagnostics: vote count + threshold + revoked flag.
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

// IsRevoked — string-typed wrapper checking for ANY SCREVOKE_<id>_ entry.
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
	var out []*RevokeRecord
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var r RevokeRecord
		if e := json.Unmarshal(qr.Value, &r); e != nil {
			return nil, e
		}
		out = append(out, &r)
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostic read APIs
// ─────────────────────────────────────────────────────────────────────────────

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
