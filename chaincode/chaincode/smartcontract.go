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
	// StatusExcluded — a controller flagged by CP-DETECT (f+1 RSU conflict,
	// Eq 3.64–3.67 / invariant 2). Distinct from REVOKED: exclusion removes a
	// controller from the trusted set C_trusted so a successor takes over,
	// whereas REVOKED is the terminal vehicle state from a 2f+1 SC-Revoke vote.
	// An EXCLUDED controller's submissions bounce at requireActive, taking it
	// out of consensus exactly as invariant 2 requires.
	StatusExcluded = "EXCLUDED"

	// τ_init at registration time. Paper §3.5.5 mentions τ_init without a
	// numeric default; we set it to the fully-clean ceiling so SC-Trust's
	// EMA (Eq 3.55) only ever drags benign vehicles down on real anomalies.
	TauInit = 1.0

	// RSU trust-lifecycle states (paper §3.5.1 + §3.5.5 RSU SC-Trust path,
	// Eq eq:rsu_trust / eq:rsu_misbehave). Distinct from RegistrationRecord.Status:
	//   • TRUSTED — RSU is an endorser; its evidence carries quorum weight in
	//     the 2f+1 SC-Revoke / SC-Register / CP-DETECT counts.
	//   • CLIENT  — demoted/quarantined (τ_{r_j} < τ_min). It may still SUBMIT
	//     evidence so its score can recover, but those submissions carry ZERO
	//     quorum weight and it may not endorse. Recovery (τ ≥ τ_min) promotes
	//     it back to TRUSTED. Sustained low trust over T_rev windows escalates
	//     to a terminal RegistrationRecord.Status = REVOKED via SC-Revoke.
	// A TRUSTED RSU with τ_min ≤ τ < τ_warn is flagged PROBATIONARY: it keeps
	// endorser/quorum status but is under watch (RSUTrustScore.Probationary).
	RSUStateTrusted = "TRUSTED"
	RSUStateClient  = "CLIENT"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data structures
// ─────────────────────────────────────────────────────────────────────────────

// RegistrationRecord — Algorithm 7 SC-Register output. Stored under key
// REG_<ID>. Status flips to "REVOKED" when SC-Revoke commits.
type RegistrationRecord struct {
	ID           string  `json:"ID"`
	Role         string  `json:"Role"`               // VEHICLE | RSU | CONTROLLER
	PkHex        string  `json:"PkHex"`              // uncompressed P-256, 0x04‖X‖Y, 130 hex chars
	HKuHex       string  `json:"HKuHex"`             // h(K_u_i), 64 hex chars (SHA-256)
	TauInit      float64 `json:"TauInit"`            // τ_init at registration
	Status       string  `json:"Status"`             // ACTIVE | REVOKED | EXCLUDED
	RSUState     string  `json:"RSUState,omitempty"` // RSU only: TRUSTED | CLIENT (endorser vs quarantined)
	TReg         string  `json:"TReg"`               // caller-supplied registration timestamp
	RegisteredAt string  `json:"RegisteredAt"`       // server-side commit time (RFC3339)
}

// NetworkConfig — channel-wide BFT parameters. Bootstrap via SCInitNetworkConfig.
// defaultTWindowSec — T_w, the sliding-window length (sim seconds) over which
// distinct RSU revocation witnesses accumulate toward the 2f+1 quorum (Eq 3.65).
// Tunable default: change here (or backfill via a future SCInitNetworkConfig arg)
// once empirical tuning settles. Kept as a config field so it is per-channel state.
const defaultTWindowSec = 30.0

type NetworkConfig struct {
	ID           string  `json:"ID"`           // always "NETCFG"
	NumRSUs      int     `json:"NumRSUs"`      // |R_total|
	Alpha        float64 `json:"Alpha"`        // EMA factor in Eq 3.55
	TauWarn      float64 `json:"TauWarn"`      // τ_warn — probation entry (paper §3.5.1)
	TauMin       float64 `json:"TauMin"`       // τ_min — demotion + T_rev revocation gate
	TRev         int     `json:"TRev"`         // T_rev consecutive-epoch gate
	PsiAnomalyTh float64 `json:"PsiAnomalyTh"` // ψ_th — anomaly cutoff
	TWindowSec   float64 `json:"TWindowSec"`   // T_w — revocation-vote sliding window (Eq 3.65)
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
	ConsecutiveLowEpochs int     `json:"ConsecutiveLowEpochs"` // running counter for T_rev gate (τ < τ_min)
	Probationary         bool    `json:"Probationary,omitempty"` // τ_min ≤ τ_i < τ_warn — reduced routing priority (paper §3.5.1)
	LastEpochTimestamp   string  `json:"LastEpochTimestamp"`
	UpdateCount          int     `json:"UpdateCount"`
	UpdatedAt            string  `json:"UpdatedAt"`
}

// RSUTrustScore — per-RSU EMA trust score (paper Eq eq:rsu_trust, reusing the
// vehicle EMA form of Eq 3.55 driven by the misbehaviour signal m_j of
// Eq eq:rsu_misbehave). Created at RSU registration with TrustScore = TauInit;
// updated by SCRSUFinalizeEpoch. Key: RSUTRUST_<rsuID>.
type RSUTrustScore struct {
	ID                   string  `json:"ID"`
	RSUID                string  `json:"RSUID"`
	TrustScore           float64 `json:"TrustScore"`           // τ_{r_j} ∈ [0,1]; higher = more trusted
	State                string  `json:"State"`                // TRUSTED | CLIENT (mirrors REG_.RSUState)
	MeanMisbehave        float64 `json:"MeanMisbehave"`        // m_j(t) from last finalised epoch (Eq eq:rsu_misbehave)
	NumReportsLastEpoch  int     `json:"NumReportsLastEpoch"`  // |V_j(t)| of last finalised epoch
	ConsecutiveLowEpochs int     `json:"ConsecutiveLowEpochs"` // running counter for the T_rev revocation gate (τ < τ_min)
	LastEpochTimestamp   string  `json:"LastEpochTimestamp"`
	UpdateCount          int     `json:"UpdateCount"`
	Probationary         bool    `json:"Probationary,omitempty"` // τ_min ≤ τ_{r_j} < τ_warn — still TRUSTED/endorsing but under watch (paper §3.5.1)
	FloorHeld            bool    `json:"FloorHeld,omitempty"`    // τ < τ_min but held TRUSTED by the BFT 3f+1 floor guard
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

// RevokeVote — per-RSU vote (BFT 2f+1, Eq 3.65). Key: VOTE_<vehicleID>_<rsuID>.
// One slot per (vehicle,RSU): a re-vote overwrites, so each RSU is counted at most
// once toward the quorum (paper §3.5.5: "each RSU is counted at most once").
type RevokeVote struct {
	ID        string `json:"ID"`
	VehicleID string `json:"VehicleID"`
	RSUID     string `json:"RSUID"`
	Reason    string `json:"Reason"`
	Signature string `json:"Signature"`
	// Timestamp — SIM-time (seconds) at which the RSU cast the vote. This is the
	// field the sliding-window quorum (Eq 3.65, [t-T_w, t]) filters on. VotedAt
	// below is wall-clock and is for audit only — it cannot do sim-window math.
	Timestamp string `json:"Timestamp"`
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

// ControllerReassignment — C_trusted reassignment record written when CP-DETECT
// excludes a controller (Eq 3.64–3.67 / invariant 2). Key:
// CTRLREASSIGN_<excludedController>_<epoch>.
type ControllerReassignment struct {
	ID                  string `json:"ID"`
	ExcludedController  string `json:"ExcludedController"`
	SuccessorController string `json:"SuccessorController"` // "" if no ACTIVE successor remains
	Reason              string `json:"Reason"`
	Epoch               string `json:"Epoch"`
	ConflictCount       int    `json:"ConflictCount"`
	ThresholdFP1        int    `json:"ThresholdFP1"`
	At                  string `json:"At"`
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

// concatDigest returns SHA-256 over the ordered string concatenation of
// `parts`. This is the one canonical hashing rule shared by every signed
// payload in the contract — the NS-3 signer MUST hash the exact same string
// arguments, in the same order, with no separators, or verification fails.
func concatDigest(parts ...string) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return h.Sum(nil)
}

// endorsementDigest returns SHA-256(vehicleID ‖ pkHex ‖ hKuHex). The string
// concatenation is the canonical form NS-3 endorsement collectors hash, and
// must stay byte-identical on both sides.
func endorsementDigest(vehicleID, pkHex, hKuHex string) []byte {
	return concatDigest(vehicleID, pkHex, hKuHex)
}

// evidenceDigest — canonical digest the RSU signs for its σ_j^sub (Eq 3.61).
// Binds the vehicle, the submitting RSU, the epoch, the anomaly score string
// (verbatim, as transmitted), and the beacon hash h(b_i(t)). When the full-
// mode TRS aggregate path is used, beaconHash carries the FHE ciphertext
// digest h(Enc(A_ring)) so the signature binds the ciphertext per Eq 3.49.
func evidenceDigest(vehicleID, rsuID, epoch, psiStr, beaconHash string) []byte {
	return concatDigest(vehicleID, rsuID, epoch, psiStr, beaconHash)
}

// controllerEvidenceDigest — canonical digest the controller signs for its
// σ_c^sub (Eq 3.62). Binds vehicle, controller, epoch, the controller anomaly
// score Φ string (verbatim), and the beacon hash h(X_i(t)).
func controllerEvidenceDigest(vehicleID, controllerID, epoch, phiStr, beaconHash string) []byte {
	return concatDigest(vehicleID, controllerID, epoch, phiStr, beaconHash)
}

// revokeVoteDigest — canonical digest the RSU signs for its revocation vote
// (Eq 3.63). Binds the target vehicle, the voting RSU, the reason, and the
// caller-supplied timestamp so a vote cannot be replayed for another vehicle.
func revokeVoteDigest(vehicleID, rsuID, reason, timestamp string) []byte {
	return concatDigest(vehicleID, rsuID, reason, timestamp)
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
		// Only TRUSTED-state RSUs may endorse — a demoted (CLIENT) RSU's
		// signature carries zero quorum weight (paper §3.5.1 RSU lifecycle).
		if regE.RSUState != "" && regE.RSUState != RSUStateTrusted {
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
	// An RSU joins the endorser set fully trusted (paper §3.5.1 reuses τ_init).
	if role == RoleRSU {
		rec.RSUState = RSUStateTrusted
	}
	rJSON, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState("REG_"+vehicleID, rJSON); err != nil {
		return err
	}

	// Eagerly seed the per-identity trust row with τ_init so the finalize
	// paths never lazy-init a row for an unregistered identity. Vehicles get
	// SCTRUST_<id> (Eq 3.55); RSUs get RSUTRUST_<id> (Eq eq:rsu_trust).
	switch role {
	case RoleVehicle:
		if err := s.initTrustScore(ctx, vehicleID); err != nil {
			return err
		}
	case RoleRSU:
		if err := s.initRSUTrustScore(ctx, vehicleID); err != nil {
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
		RSUState:     RSUStateTrusted,
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

	// Seed RSUTRUST_<id> with τ_init so SCRSUFinalizeEpoch reads a row that
	// always exists for a bootstrapped RSU.
	if err := s.initRSUTrustScore(ctx, rsuID); err != nil {
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

// initRSUTrustScore seeds RSUTRUST_<rsuID> with TrustScore = TauInit and
// State = TRUSTED. Called at RSU registration (SCRegister / SCBootstrapRSU) so
// SCRSUFinalizeEpoch can assume the row already exists. Idempotent.
func (s *SmartContract) initRSUTrustScore(ctx contractapi.TransactionContextInterface,
	rsuID string) error {

	id := "RSUTRUST_" + rsuID
	existing, err := ctx.GetStub().GetState(id)
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	rec := RSUTrustScore{
		ID:         id,
		RSUID:      rsuID,
		TrustScore: TauInit,
		State:      RSUStateTrusted,
		UpdatedAt:  time.Now().Format(time.RFC3339),
	}
	j, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, j)
}

// isTrustedRSU reports whether rsuID is an ACTIVE RSU currently in the TRUSTED
// (endorser) state. This is the on-chain enforcement of "client-state RSU
// submissions carry zero quorum weight" (paper §3.5.1 + Sir's design): every
// quorum-critical count (SC-Register endorsements, SC-Revoke 2f+1 votes,
// CP-DETECT conflicts, the misbehaviour quorum q_i) consults this gate, while
// non-quorum evidence submission stays open so a demoted RSU can recover.
//
// An empty RSUState is treated as TRUSTED so RSUs that predate the field within
// a single deploy are not silently demoted.
func (s *SmartContract) isTrustedRSU(ctx contractapi.TransactionContextInterface,
	rsuID string) bool {

	reg, err := s.getRegistration(ctx, rsuID)
	if err != nil || reg == nil {
		return false
	}
	if reg.Role != RoleRSU || reg.Status != StatusActive {
		return false
	}
	return reg.RSUState == "" || reg.RSUState == RSUStateTrusted
}

// countTrustedRSUs returns |R_trusted(t)|: the number of ACTIVE RSUs currently in
// the trusted endorser set (RSUState empty or TRUSTED). Used by the BFT floor
// guard (paper §3.5.1: |R_trusted(t)| ≥ 3f+1 at all times). Writes made earlier
// in the same transaction are visible here, so a finalize loop that demotes RSUs
// one at a time sees the shrinking count.
func (s *SmartContract) countTrustedRSUs(ctx contractapi.TransactionContextInterface) (int, error) {
	iter, err := ctx.GetStub().GetStateByRange("REG_", "REG_~")
	if err != nil {
		return 0, err
	}
	defer iter.Close()
	n := 0
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return 0, e
		}
		var reg RegistrationRecord
		if e := json.Unmarshal(qr.Value, &reg); e != nil {
			continue // non-registration value under REG_ range — skip
		}
		if reg.Role != RoleRSU || reg.Status != StatusActive {
			continue
		}
		if reg.RSUState == "" || reg.RSUState == RSUStateTrusted {
			n++
		}
	}
	return n, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// NetworkConfig
// ─────────────────────────────────────────────────────────────────────────────

// SCInitNetworkConfig — bootstrap or update channel-wide BFT parameters.
// Args: numRSUs, alpha, tauWarn, tauMin, T_rev, psiAnomalyTh (all strings).
func (s *SmartContract) SCInitNetworkConfig(ctx contractapi.TransactionContextInterface,
	numRSUsStr, alphaStr, tauWarnStr, tauMinStr, tRevStr, psiThStr string) error {

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
	tauWarn, err := strconv.ParseFloat(tauWarnStr, 64)
	if err != nil {
		return fmt.Errorf("tauWarn parse: %v", err)
	}
	tauMin, err := strconv.ParseFloat(tauMinStr, 64)
	if err != nil {
		return fmt.Errorf("tauMin parse: %v", err)
	}
	if tauMin > tauWarn {
		return fmt.Errorf("τ_min=%g must be ≤ τ_warn=%g (paper §3.5.1)", tauMin, tauWarn)
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
		TauWarn:      tauWarn,
		TauMin:       tauMin,
		TRev:         tRev,
		PsiAnomalyTh: psiTh,
		TWindowSec:   defaultTWindowSec, // T_w (Eq 3.65); no init arg yet — tune via const
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
			TauWarn:      0.5,
			TauMin:       0.3,
			TRev:         3,
			PsiAnomalyTh: 0.5,
			TWindowSec:   defaultTWindowSec,
			UpdatedAt:    "default",
		}, nil
	}
	var c NetworkConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	// Backfill T_w for NETCFG records written before the field existed (or by a
	// 6-arg SCInitNetworkConfig that predates it) so the window filter never
	// degenerates to a zero-length window that drops every prior witness.
	if c.TWindowSec <= 0 {
		c.TWindowSec = defaultTWindowSec
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

	// Eq 3.61 — verify σ_j^sub against the submitting RSU's on-chain P-256
	// key over the canonical evidence digest. Strict reject mirrors the
	// SCRegister endorsement gate: an unverifiable signature is dropped, so
	// only genuinely-keyed RSU evidence ever reaches SC-Trust aggregation.
	regRSU, err := s.getRegistration(ctx, rsuID)
	if err != nil {
		return fmt.Errorf("rsu registration lookup: %v", err)
	}
	if regRSU == nil {
		return fmt.Errorf("rejected: rsu %s not registered", rsuID)
	}
	if !verifyECDSAP256(regRSU.PkHex, signature,
		evidenceDigest(vehicleID, rsuID, epoch, psiStr, beaconHash)) {
		return fmt.Errorf("rejected: invalid evidence signature for rsu %s", rsuID)
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

	// Eq 3.62 — verify σ_c^sub against the controller's on-chain P-256 key.
	// The controller writes evidence as a non-authoritative client (invariant
	// 2): its submission is recorded and fed to CP-DETECT, but an unsigned or
	// forged controller submission is rejected here before it can skew the
	// f+1 conflict count.
	regCtrl, err := s.getRegistration(ctx, controllerID)
	if err != nil {
		return fmt.Errorf("controller registration lookup: %v", err)
	}
	if regCtrl == nil {
		return fmt.Errorf("rejected: controller %s not registered", controllerID)
	}
	if !verifyECDSAP256(regCtrl.PkHex, signature,
		controllerEvidenceDigest(vehicleID, controllerID, epoch, phiStr, beaconHash)) {
		return fmt.Errorf("rejected: invalid controller signature for %s", controllerID)
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
// Eq 3.59 — SC-Trust finalize per-epoch
// ─────────────────────────────────────────────────────────────────────────────

// SCTrustFinalizeEpoch — aggregate the RSU submissions for one (vehicle,
// epoch) and update τ_i per Eq 3.59. Increments the ConsecutiveLowEpochs
// counter when τ_i < τ_min and, once ConsecutiveLowEpochs ≥ T_rev, issues a
// DIRECT slow-path revocation (paper §3.5.5 p.72 "RevocationRequest to
// SC-Revoke"): commits the SCREVOKE_ record, flips REG_ status to REVOKED, and
// emits "SCRevoke". This mirrors the vehicle fast path (SCRevokeVote) and the
// RSU trust-decay path (SCRSUFinalizeEpoch) — the old observed-only "TrustLow"
// re-vote signal was a dead end for low-and-slow attackers and is removed.
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
		// Zero quorum weight for demoted (CLIENT) RSUs: their evidence is
		// recorded but excluded from the trust-driving aggregate so a
		// quarantined RSU cannot influence vehicle revocation (§3.5.1).
		if !s.isTrustedRSU(ctx, sub.RSUID) {
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

	// Eq 3.59: τ_i(t) = α·τ_i(t-1) + (1-α)·(1 - meanPsi).
	rec.TrustScore = cfg.Alpha*rec.TrustScore + (1-cfg.Alpha)*(1-meanPsi)
	rec.MeanPsi = meanPsi
	rec.NumRSUsLastEpoch = numWitnesses
	rec.LastEpochTimestamp = epoch
	rec.UpdateCount++
	rec.UpdatedAt = time.Now().Format(time.RFC3339)

	// Three-state lifecycle (paper §3.5.1). Probation at τ_warn (reduced routing
	// priority, still active); the T_rev revocation gate counts epochs below the
	// stricter τ_min.
	rec.Probationary = rec.TrustScore < cfg.TauWarn && rec.TrustScore >= cfg.TauMin
	if rec.TrustScore < cfg.TauMin {
		rec.ConsecutiveLowEpochs++
	} else {
		rec.ConsecutiveLowEpochs = 0
	}

	// Slow-path revocation (paper §3.5.5, p.72): "if τ_i(t) remains below τ_min
	// for T_rev consecutive epochs, SC-Trust emits a RevocationRequest event to
	// SC-Revoke." This is a DIRECT revocation request — NOT a re-vote: a
	// low-and-slow attacker whose per-beacon ψ stays just under ψ_th never
	// produces the flags Path-1 voting (Eq 3.65/3.67) needs, so routing back to
	// voting would be a dead end. We therefore commit the same revocation state
	// the fast path produces (SCREVOKE_ record + REG_ status flip + "SCRevoke"
	// event for the CRL-Update/LKH-rekey fan-out), keeping vehicle and RSU
	// trust-decay paths symmetric (cf. SCRSUFinalizeEpoch).
	if rec.ConsecutiveLowEpochs >= cfg.TRev {
		// Idempotency: only the first finalize that trips the gate commits the
		// revocation (mirrors the fast path's pre-write existence check).
		chkPrefix := fmt.Sprintf("SCREVOKE_%s_", vehicleID)
		chk, e2 := ctx.GetStub().GetStateByRange(chkPrefix, chkPrefix+"~")
		if e2 != nil {
			return nil, e2
		}
		already := chk.HasNext()
		chk.Close()
		if !already {
			revID := fmt.Sprintf("SCREVOKE_%s_%s", vehicleID, epoch)
			rev := RevokeRecord{
				ID:        revID,
				VehicleID: vehicleID,
				Reason:    "trust_decay",
				RSUID:     "SC-TRUST", // contract-driven slow path, no single voting RSU
				Timestamp: epoch,
				RevokedAt: time.Now().Format(time.RFC3339),
			}
			if rj, e := json.Marshal(rev); e == nil {
				if err := ctx.GetStub().PutState(revID, rj); err != nil {
					return nil, err
				}
			}
			// Flip registration status to REVOKED so subsequent evidence / vote
			// submissions for this vehicle bounce at requireActive.
			if regData, e := ctx.GetStub().GetState("REG_" + vehicleID); e == nil && regData != nil {
				var reg RegistrationRecord
				if e := json.Unmarshal(regData, &reg); e == nil {
					reg.Status = StatusRevoked
					if rj, e := json.Marshal(reg); e == nil {
						_ = ctx.GetStub().PutState("REG_"+vehicleID, rj)
					}
				}
			}
			// "SCRevoke" (not the old observed-only "TrustLow") so the NS-3 event
			// drainer drives the CRL-Update/LKH rekey, identical to the fast path.
			ctx.GetStub().SetEvent("SCRevoke", []byte(fmt.Sprintf(
				`{"vehicleID":"%s","reason":"trust_decay","epoch":"%s","trust":%f,"consec":%d,"trev":%d}`,
				vehicleID, epoch, rec.TrustScore, rec.ConsecutiveLowEpochs, cfg.TRev)))
		}
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
// activeControllerExcluding returns the ID of the lowest-numbered controller
// whose registration is ACTIVE, skipping `exclude`. This is the deterministic
// head of the trusted set C_trusted (Eq 3.1). Returns "" when none remain.
func (s *SmartContract) activeControllerExcluding(ctx contractapi.TransactionContextInterface,
	exclude string) (string, error) {

	iter, err := ctx.GetStub().GetStateByRange("REG_", "REG_~")
	if err != nil {
		return "", err
	}
	defer iter.Close()
	best := ""
	bestIdx := int(^uint(0) >> 1) // max int
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return "", e
		}
		var r RegistrationRecord
		if e := json.Unmarshal(qr.Value, &r); e != nil {
			return "", e
		}
		if r.Role != RoleController || r.Status != StatusActive || r.ID == exclude {
			continue
		}
		// Numeric ordering of the CTRL_<idx> suffix; fall back to string
		// compare when the suffix is non-numeric.
		idx := bestIdx
		if n := len("CTRL_"); len(r.ID) > n {
			if v, e := strconv.Atoi(r.ID[n:]); e == nil {
				idx = v
			}
		}
		if idx < bestIdx || (idx == bestIdx && (best == "" || r.ID < best)) {
			best = r.ID
			bestIdx = idx
		}
	}
	return best, nil
}

// excludeAndReassignController flips a CP-DETECT-flagged controller to EXCLUDED
// and records the C_trusted reassignment to its successor (Eq 3.64–3.67 /
// invariant 2). Idempotent: a controller already EXCLUDED yields no new record.
// Returns the reassignment (nil if the controller was already excluded).
func (s *SmartContract) excludeAndReassignController(ctx contractapi.TransactionContextInterface,
	controllerID, epoch, reason string, conflict, thresholdFP1 string) (*ControllerReassignment, error) {

	reg, err := s.getRegistration(ctx, controllerID)
	if err != nil {
		return nil, err
	}
	if reg == nil || reg.Role != RoleController {
		return nil, nil // nothing to exclude
	}
	if reg.Status != StatusActive {
		return nil, nil // already excluded/revoked — idempotent
	}

	reg.Status = StatusExcluded
	rj, err := json.Marshal(reg)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState("REG_"+controllerID, rj); err != nil {
		return nil, err
	}

	successor, err := s.activeControllerExcluding(ctx, controllerID)
	if err != nil {
		return nil, err
	}

	cInt, _ := strconv.Atoi(conflict)
	tInt, _ := strconv.Atoi(thresholdFP1)
	ra := ControllerReassignment{
		ID:                  fmt.Sprintf("CTRLREASSIGN_%s_%s", controllerID, epoch),
		ExcludedController:  controllerID,
		SuccessorController: successor,
		Reason:              reason,
		Epoch:               epoch,
		ConflictCount:       cInt,
		ThresholdFP1:        tInt,
		At:                  time.Now().Format(time.RFC3339),
	}
	raj, err := json.Marshal(ra)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(ra.ID, raj); err != nil {
		return nil, err
	}
	return &ra, nil
}

// GetActiveController returns the current head of C_trusted — the lowest-
// numbered ACTIVE controller. Node-side evidence submitters query this to learn
// which controller identity to submit under after a reassignment.
func (s *SmartContract) GetActiveController(ctx contractapi.TransactionContextInterface) (string, error) {
	id, err := s.activeControllerExcluding(ctx, "")
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", fmt.Errorf("no active controller in C_trusted")
	}
	return id, nil
}

// GetTrustedControllers lists every registered controller and its status — the
// full C_trusted set plus any EXCLUDED members, for diagnostics / evidence.
func (s *SmartContract) GetTrustedControllers(ctx contractapi.TransactionContextInterface) ([]*RegistrationRecord, error) {
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
		if r.Role == RoleController {
			out = append(out, &r)
		}
	}
	return out, nil
}

// GetControllerReassignments lists all C_trusted reassignment records.
func (s *SmartContract) GetControllerReassignments(ctx contractapi.TransactionContextInterface) ([]*ControllerReassignment, error) {
	iter, err := ctx.GetStub().GetStateByRange("CTRLREASSIGN_", "CTRLREASSIGN_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var out []*ControllerReassignment
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var r ControllerReassignment
		if e := json.Unmarshal(qr.Value, &r); e != nil {
			return nil, e
		}
		out = append(out, &r)
	}
	return out, nil
}

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
		// Only TRUSTED RSUs vote in the f+1 controller-conflict quorum
		// (§3.5.1 RSU lifecycle — CLIENT submissions carry zero weight).
		if !s.isTrustedRSU(ctx, sub.RSUID) {
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

	// Invariant 2 / Eq 3.64–3.67: the f+1 flag is the operational trigger to
	// exclude the controller from C_trusted and activate the successor. RSU
	// consensus (the conflict count) drives this, never the controller itself
	// (invariant 6). A Fabric TX emits only one event, so we emit a single
	// "ControllerReassign" carrying the flag context when a (new) exclusion
	// happens, else the plain "CPDetectFlag".
	ra, err := s.excludeAndReassignController(ctx, cs.ControllerID, epoch,
		"cp_detect_conflict", strconv.Itoa(conflict), strconv.Itoa(fP1))
	if err != nil {
		return nil, err
	}
	if ra != nil {
		ctx.GetStub().SetEvent("ControllerReassign", []byte(fmt.Sprintf(
			`{"excluded":"%s","successor":"%s","vehicleID":"%s","epoch":"%s","conflict":%d,"threshold":%d}`,
			ra.ExcludedController, ra.SuccessorController, vehicleID, epoch, conflict, fP1)))
	} else {
		ctx.GetStub().SetEvent("CPDetectFlag", []byte(fmt.Sprintf(
			`{"controllerID":"%s","vehicleID":"%s","epoch":"%s","conflict":%d,"threshold":%d}`,
			cs.ControllerID, vehicleID, epoch, conflict, fP1)))
	}
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

	// Eq 3.63 — verify the revocation vote signature against the voting RSU's
	// on-chain P-256 key. Without this gate a single forged identity could
	// stuff the 2f+1 tally; binding (vehicleID‖rsuID‖reason‖timestamp) also
	// stops a valid vote being replayed against a different vehicle.
	regRSU, err := s.getRegistration(ctx, rsuID)
	if err != nil {
		return "", fmt.Errorf("rsu registration lookup: %v", err)
	}
	if regRSU == nil {
		return "", fmt.Errorf("rejected: rsu %s not registered", rsuID)
	}
	if !verifyECDSAP256(regRSU.PkHex, signature,
		revokeVoteDigest(vehicleID, rsuID, reason, timestamp)) {
		return "", fmt.Errorf("rejected: invalid revoke vote signature for rsu %s", rsuID)
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
		Timestamp: timestamp, // sim-time; the window quorum (Eq 3.65) filters on this
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
	// ── Sliding-window quorum (Eq 3.65): |{r_j ∈ R_trusted : ∃ t′∈[t-T_w, t],
	// ψ_j(t′)>ψ_th}| ≥ 2f+1. Only votes whose SIM-time falls within the last
	// T_w seconds count toward the quorum, so 2f+1 independent witnesses must
	// accumulate *within the window* rather than over the whole run. "now" is
	// the sim-time of the vote being cast in this TX.
	windowNow, nowErr := strconv.ParseFloat(timestamp, 64)
	windowLow := windowNow - cfg.TWindowSec
	inWindow := func(v RevokeVote) bool {
		if nowErr != nil {
			return true // can't parse "now" → don't drop votes (degrade safe)
		}
		vt, e := strconv.ParseFloat(v.Timestamp, 64)
		if e != nil {
			return true // legacy vote without sim-time → include (conservative)
		}
		return vt >= windowLow && vt <= windowNow
	}
	// Only TRUSTED RSU votes carry quorum weight toward 2f+1 (§3.5.1 RSU
	// lifecycle). The vote of a demoted (CLIENT) voter is still stored above
	// for audit, but excluded from the tally — so seed the voter only if it
	// is currently trusted (compensating for read-after-write within the TX).
	// The just-cast vote's timestamp == windowNow, so it is in-window by definition.
	if s.isTrustedRSU(ctx, rsuID) {
		seen[rsuID] = true
	}
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return "", e
		}
		var v RevokeVote
		if e := json.Unmarshal(qr.Value, &v); e != nil {
			return "", e
		}
		if !s.isTrustedRSU(ctx, v.RSUID) {
			continue
		}
		if !inWindow(v) {
			continue // witness outside [t-T_w, t] — expired, no quorum weight
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
// NOTE: this reports the RAW lifetime distinct-vote count (un-windowed), since it
// takes no sim-time reference. The authoritative revocation decision in
// SCRevokeVote applies the T_w sliding window (Eq 3.65); this count may therefore
// exceed the in-window quorum and is for audit/inspection only.
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
// Eq eq:rsu_trust / eq:rsu_misbehave — RSU SC-Trust finalize per-epoch
// ─────────────────────────────────────────────────────────────────────────────

// SCRSUFinalizeEpoch evaluates every RSU's behaviour for one epoch against the
// collective decision of the trusted endorser set and updates each RSU trust
// score τ_{r_j} (paper §3.5.1 + §3.5.5 RSU SC-Trust path).
//
// For the epoch, the contract reconstructs, from on-chain evidence:
//   • q_i ∈ {0,1} — the 2f+1 quorum outcome per vehicle, computed ONLY over
//     distinct TRUSTED RSUs (anti-collusion: a coalition of demoted RSUs can
//     never form the quorum that scores their peers, Eq eq:rsu_misbehave).
//   • m_j(t) — RSU r_j's misbehaviour signal: the mean disagreement between its
//     own per-vehicle flag and q_i over the vehicles it reported on (V_j(t)).
//
// NS-3 RSUs emit a SUBM only on anomaly, so a reported vehicle always carries
// flag_j = 1; m_j therefore captures OVER-REPORTING (flagging vehicles the
// trusted quorum cleared). Under-reporting (a missed detection the quorum
// caught) is not observable from anomaly-only submissions — closing that
// direction needs a per-vehicle clean-verdict hook on the NS-3 side and is left
// as a documented follow-up.
//
// Each RSU's τ_{r_j} then decays by the vehicle EMA form (Eq 3.55) driven by
// m_j, and the three-state lifecycle is applied: demote to CLIENT below τ_th,
// promote back to TRUSTED on recovery, and escalate to a terminal SC-Revoke
// after T_rev consecutive low-trust epochs.
//
// Args: epoch. Returns the updated RSUTrustScore records.
func (s *SmartContract) SCRSUFinalizeEpoch(ctx contractapi.TransactionContextInterface,
	epoch string) ([]*RSUTrustScore, error) {

	cfg, err := s.GetNetworkConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("NetworkConfig: %v", err)
	}
	quorum := 2*fByzantine(cfg.NumRSUs) + 1

	// Single pass over all submissions, filtered to this epoch. Keys are
	// SUBM_<veh>_<epoch>_<rsu> (vehicle-first), so the epoch is not a
	// contiguous range — we scan and filter, which is fine at sim scale.
	iter, err := ctx.GetStub().GetStateByRange("SUBM_", "SUBM_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	// trustedFlaggers[veh] = set of distinct TRUSTED RSUs flagging veh.
	trustedFlaggers := make(map[string]map[string]bool)
	// rsuReports[rsu][veh] = true — vehicles rsu reported on (V_j(t)).
	rsuReports := make(map[string]map[string]bool)

	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var sub EpochSubmission
		if e := json.Unmarshal(qr.Value, &sub); e != nil {
			return nil, e
		}
		if sub.Epoch != epoch {
			continue
		}
		flagged := sub.Psi > cfg.PsiAnomalyTh

		if rsuReports[sub.RSUID] == nil {
			rsuReports[sub.RSUID] = make(map[string]bool)
		}
		rsuReports[sub.RSUID][sub.VehicleID] = true

		if flagged && s.isTrustedRSU(ctx, sub.RSUID) {
			if trustedFlaggers[sub.VehicleID] == nil {
				trustedFlaggers[sub.VehicleID] = make(map[string]bool)
			}
			trustedFlaggers[sub.VehicleID][sub.RSUID] = true
		}
	}

	// q_i per vehicle: 1 iff ≥ 2f+1 distinct trusted RSUs flagged it.
	q := make(map[string]int)
	for veh, flaggers := range trustedFlaggers {
		if len(flaggers) >= quorum {
			q[veh] = 1
		}
	}

	var out []*RSUTrustScore
	for rsuID, vehSet := range rsuReports {
		// m_j(t): mean disagreement over the vehicles r_j reported on.
		dis := 0
		for veh := range vehSet {
			// flag_j = 1 for every reported vehicle (anomaly-only SUBM).
			if 1 != q[veh] {
				dis++
			}
		}
		mj := float64(dis) / float64(len(vehSet))

		rec, err := s.updateRSUTrust(ctx, rsuID, mj, len(vehSet), epoch, cfg)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			out = append(out, rec)
		}
	}
	return out, nil
}

// updateRSUTrust applies the EMA update and the three-state lifecycle for one
// RSU given its per-epoch misbehaviour signal m_j. Mirrors the vehicle path and
// the paper's two-threshold scheme (§3.5.1): while τ ≥ τ_warn the RSU is a
// healthy TRUSTED endorser; τ_min ≤ τ < τ_warn flags it PROBATIONARY (still
// TRUSTED/endorsing, under watch); τ < τ_min demotes it to CLIENT (no quorum
// weight, may not endorse, may still submit to recover); τ < τ_min sustained
// for T_rev windows escalates to terminal SC-Revoke. Returns the updated
// record, or nil if the RSU is already revoked / has no trust row.
func (s *SmartContract) updateRSUTrust(ctx contractapi.TransactionContextInterface,
	rsuID string, mj float64, numReports int, epoch string, cfg *NetworkConfig) (*RSUTrustScore, error) {

	reg, err := s.getRegistration(ctx, rsuID)
	if err != nil {
		return nil, err
	}
	if reg == nil || reg.Role != RoleRSU || reg.Status != StatusActive {
		return nil, nil // unregistered or already revoked/excluded — skip
	}

	id := "RSUTRUST_" + rsuID
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var rec RSUTrustScore
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}

	// Eq eq:rsu_trust: τ_{r_j}(t) = α·τ_{r_j}(t-1) + (1-α)·(1 - m_j).
	rec.TrustScore = cfg.Alpha*rec.TrustScore + (1-cfg.Alpha)*(1-mj)
	rec.MeanMisbehave = mj
	rec.NumReportsLastEpoch = numReports
	rec.LastEpochTimestamp = epoch
	rec.UpdateCount++
	rec.UpdatedAt = time.Now().Format(time.RFC3339)

	// T_rev consecutive-low-epoch gate, keyed on the stricter τ_min floor.
	if rec.TrustScore < cfg.TauMin {
		rec.ConsecutiveLowEpochs++
	} else {
		rec.ConsecutiveLowEpochs = 0
	}

	// BFT floor guard (paper §3.5.1): |R_trusted(t)| ≥ 3f+1 must hold at all
	// times. A transition OUT of the trusted set (demotion or revocation of a
	// currently-trusted RSU) is blocked when it would drop the trusted count
	// below the floor; the RSU is instead retained as a probationary TRUSTED
	// member — keeping its quorum weight — until a replacement registers and
	// lifts the count back above the floor, at which point the pending
	// transition resumes (ConsecutiveLowEpochs is preserved, not reset).
	// Client-state RSUs are already outside R_trusted, so their revocation is
	// never floor-blocked.
	floor := 3*fByzantine(cfg.NumRSUs) + 1
	currentlyTrusted := reg.RSUState == "" || reg.RSUState == RSUStateTrusted
	wantsOut := rec.TrustScore < cfg.TauMin // demotion or revocation territory
	floorWouldBreak := false
	if wantsOut && currentlyTrusted {
		nTrusted, e := s.countTrustedRSUs(ctx)
		if e != nil {
			return nil, e
		}
		if nTrusted-1 < floor {
			floorWouldBreak = true
		}
	}

	// State machine (paper §3.5.1 two-threshold scheme). Order: floor guard >
	// terminal revoke (τ < τ_min for T_rev) > demote (τ < τ_min) > probation
	// (τ_min ≤ τ < τ_warn, stays TRUSTED) > healthy. The floor guard takes
	// precedence so |R_trusted| never drops below 3f+1.
	switch {
	case floorWouldBreak:
		rec.State = RSUStateTrusted
		reg.RSUState = RSUStateTrusted
		rec.Probationary = false
		if !rec.FloorHeld {
			rec.FloorHeld = true
			ctx.GetStub().SetEvent("RSUProbationHold", []byte(fmt.Sprintf(
				`{"rsuID":"%s","trust":%f,"consec":%d,"floor":%d,"epoch":"%s"}`,
				rsuID, rec.TrustScore, rec.ConsecutiveLowEpochs, floor, epoch)))
		}
	case rec.ConsecutiveLowEpochs >= cfg.TRev:
		rec.Probationary = false
		rec.FloorHeld = false
		rec.State = RSUStateClient
		reg.RSUState = RSUStateClient
		reg.Status = StatusRevoked
		ts := time.Now().Format(time.RFC3339Nano)
		revID := fmt.Sprintf("SCREVOKE_%s_%s", rsuID, ts)
		rev := RevokeRecord{
			ID:        revID,
			VehicleID: rsuID, // target identity (an RSU here)
			Reason:    "rsu_trust_decay",
			RSUID:     rsuID,
			Timestamp: ts,
			RevokedAt: ts,
		}
		if rj, e := json.Marshal(rev); e == nil {
			_ = ctx.GetStub().PutState(revID, rj)
		}
		ctx.GetStub().SetEvent("RSURevoke", []byte(fmt.Sprintf(
			`{"rsuID":"%s","trust":%f,"consec":%d,"trev":%d}`,
			rsuID, rec.TrustScore, rec.ConsecutiveLowEpochs, cfg.TRev)))
	case rec.TrustScore < cfg.TauMin:
		rec.Probationary = false
		rec.FloorHeld = false
		if rec.State != RSUStateClient {
			rec.State = RSUStateClient
			reg.RSUState = RSUStateClient
			ctx.GetStub().SetEvent("RSUDemoted", []byte(fmt.Sprintf(
				`{"rsuID":"%s","trust":%f,"mj":%f,"epoch":"%s"}`,
				rsuID, rec.TrustScore, mj, epoch)))
		}
	case rec.TrustScore < cfg.TauWarn:
		// Probationary trusted: still endorses, flagged. A CLIENT that has
		// recovered to ≥ τ_min is promoted back to TRUSTED here.
		rec.FloorHeld = false
		rec.State = RSUStateTrusted
		if reg.RSUState == RSUStateClient {
			reg.RSUState = RSUStateTrusted
			ctx.GetStub().SetEvent("RSUPromoted", []byte(fmt.Sprintf(
				`{"rsuID":"%s","trust":%f,"epoch":"%s"}`,
				rsuID, rec.TrustScore, epoch)))
		} else {
			reg.RSUState = RSUStateTrusted
		}
		if !rec.Probationary {
			rec.Probationary = true
			ctx.GetStub().SetEvent("RSUProbation", []byte(fmt.Sprintf(
				`{"rsuID":"%s","trust":%f,"mj":%f,"epoch":"%s"}`,
				rsuID, rec.TrustScore, mj, epoch)))
		}
	default:
		rec.Probationary = false
		rec.FloorHeld = false
		if rec.State == RSUStateClient {
			rec.State = RSUStateTrusted
			reg.RSUState = RSUStateTrusted
			ctx.GetStub().SetEvent("RSUPromoted", []byte(fmt.Sprintf(
				`{"rsuID":"%s","trust":%f,"epoch":"%s"}`,
				rsuID, rec.TrustScore, epoch)))
		} else {
			rec.State = RSUStateTrusted
		}
	}

	if rj, err := json.Marshal(reg); err == nil {
		if err := ctx.GetStub().PutState("REG_"+rsuID, rj); err != nil {
			return nil, err
		}
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

// GetRSUTrustScore — read τ_{r_j} for one RSU.
func (s *SmartContract) GetRSUTrustScore(ctx contractapi.TransactionContextInterface,
	rsuID string) (*RSUTrustScore, error) {

	id := "RSUTRUST_" + rsuID
	data, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("no RSU trust score for %s (RSU unregistered?)", rsuID)
	}
	var rec RSUTrustScore
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// GetAllRSUTrustScores — list every RSU's current trust score + state.
func (s *SmartContract) GetAllRSUTrustScores(ctx contractapi.TransactionContextInterface) ([]*RSUTrustScore, error) {
	iter, err := ctx.GetStub().GetStateByRange("RSUTRUST_", "RSUTRUST_~")
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var out []*RSUTrustScore
	for iter.HasNext() {
		qr, e := iter.Next()
		if e != nil {
			return nil, e
		}
		var r RSUTrustScore
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
