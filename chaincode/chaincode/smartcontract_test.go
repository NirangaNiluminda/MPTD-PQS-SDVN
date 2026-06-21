// Formal functional verification of the MPTD-PQS chaincode (paper §3.5.5).
//
// These are UNIT tests: every smart-contract function is exercised in
// isolation against an in-memory fake ledger with hand-crafted ("dummy")
// inputs — NO NS-3 simulation, NO live Fabric network, NO Docker. Each test
// asserts both the happy path (valid input → correct on-chain write) and the
// rejection paths (malformed / unauthorised input → correct refusal), which
// the integration run cannot reach because every simulated node is valid.
//
// Run:  go test ./chaincode/ -v -cover
//
// Counterfeiter mocks (mocks/) fake shim.ChaincodeStubInterface; the
// fakeLedger below wires GetState/PutState/DelState/GetStateByRange to a
// map[string][]byte so state persists across calls within a test.
package chaincode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/queryresult"
	"github.com/hyperledger/fabric-samples/trajectory-chaincode/chaincode/mocks"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test harness: in-memory fake ledger behind the counterfeiter stub
// ─────────────────────────────────────────────────────────────────────────────

type fakeLedger struct{ m map[string][]byte }

func newCtx() (*mocks.TransactionContext, *fakeLedger) {
	fl := &fakeLedger{m: map[string][]byte{}}
	stub := &mocks.ChaincodeStub{}

	stub.GetStateStub = func(k string) ([]byte, error) { return fl.m[k], nil }
	stub.PutStateStub = func(k string, v []byte) error { fl.m[k] = v; return nil }
	stub.DelStateStub = func(k string) error { delete(fl.m, k); return nil }
	stub.SetEventStub = func(string, []byte) error { return nil }
	stub.GetStateByRangeStub = func(start, end string) (shim.StateQueryIteratorInterface, error) {
		var keys []string
		for k := range fl.m {
			if k >= start && k < end {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var kvs []*queryresult.KV
		for _, k := range keys {
			kvs = append(kvs, &queryresult.KV{Key: k, Value: fl.m[k]})
		}
		return newIter(kvs), nil
	}

	ctx := &mocks.TransactionContext{}
	ctx.GetStubReturns(stub)
	return ctx, fl
}

func newIter(kvs []*queryresult.KV) *mocks.StateQueryIterator {
	it := &mocks.StateQueryIterator{}
	i := 0
	it.HasNextStub = func() bool { return i < len(kvs) }
	it.NextStub = func() (*queryresult.KV, error) { kv := kvs[i]; i++; return kv, nil }
	it.CloseStub = func() error { return nil }
	return it
}

// ── assertions (stdlib only — no testify) ────────────────────────────────────

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func errHas(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("expected error containing %q, got %q", sub, err.Error())
	}
}

func approx(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("approx: got %v want %v", got, want)
	}
}

// ── dummy-data builders ──────────────────────────────────────────────────────

const dummyHKu = "abababababababababababababababababababababababababababababababab" // 62...
// dummyHKu must be exactly 64 hex chars:
var hku64 = strings.Repeat("ab", 32)

// genID returns a fresh P-256 keypair and its uncompressed 0x04‖X‖Y hex.
func genID(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ok(t, err)
	raw := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	return priv, hex.EncodeToString(raw)
}

func signHex(t *testing.T, priv *ecdsa.PrivateKey, digest []byte) string {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	ok(t, err)
	return hex.EncodeToString(sig)
}

func seedReg(fl *fakeLedger, id, role, pkHex string) {
	rec := RegistrationRecord{ID: id, Role: role, PkHex: pkHex, HKuHex: hku64,
		TauInit: TauInit, Status: StatusActive, RegisteredAt: "seed"}
	b, _ := json.Marshal(rec)
	fl.m["REG_"+id] = b
}

// seedRegKeyed registers an ACTIVE node with a FRESH P-256 keypair and returns
// the private key, so the test can produce signatures the chaincode actually
// verifies (Eq 3.61–3.63 evidence/vote gates). seedReg alone reuses a shared pk
// whose private key is discarded — fine for read-path tests, useless for the
// signature-gated write paths.
func seedRegKeyed(t *testing.T, fl *fakeLedger, id, role string) *ecdsa.PrivateKey {
	t.Helper()
	priv, pk := genID(t)
	seedReg(fl, id, role, pk)
	return priv
}

// castVote signs the canonical revokeVoteDigest with the voting RSU's key and
// submits the vote, mirroring how the NS-3 CallSCRevokeVote wrapper folds
// signing into the call so signed-bytes == transmitted-bytes.
func castVote(t *testing.T, sc SmartContract, ctx *mocks.TransactionContext,
	priv *ecdsa.PrivateKey, veh, rsu, reason, ts string) (string, error) {
	t.Helper()
	sig := signHex(t, priv, revokeVoteDigest(veh, rsu, reason, ts))
	return sc.SCRevokeVote(ctx, veh, rsu, reason, sig, ts)
}

func seedNetCfg(fl *fakeLedger, n int, alpha, tauWarn, tauMin float64, tRev int, psiTh float64) {
	cfg := NetworkConfig{ID: "NETCFG", NumRSUs: n, Alpha: alpha, TauWarn: tauWarn, TauMin: tauMin,
		TRev: tRev, PsiAnomalyTh: psiTh, UpdatedAt: "seed"}
	b, _ := json.Marshal(cfg)
	fl.m["NETCFG"] = b
}

func seedTrust(fl *fakeLedger, veh string, score float64) {
	rec := SCTrustScore{ID: "SCTRUST_" + veh, VehicleID: veh, TrustScore: score}
	b, _ := json.Marshal(rec)
	fl.m["SCTRUST_"+veh] = b
}

func seedSubm(fl *fakeLedger, veh, epoch, rsu string, psi float64) {
	id := fmt.Sprintf("SUBM_%s_%s_%s", veh, epoch, rsu)
	rec := EpochSubmission{ID: id, VehicleID: veh, RSUID: rsu, Epoch: epoch, Psi: psi}
	b, _ := json.Marshal(rec)
	fl.m[id] = b
}

func seedRSUTrust(fl *fakeLedger, rsu string, score float64) {
	rec := RSUTrustScore{ID: "RSUTRUST_" + rsu, RSUID: rsu, TrustScore: score,
		State: RSUStateTrusted}
	b, _ := json.Marshal(rec)
	fl.m["RSUTRUST_"+rsu] = b
}

func seedCSub(fl *fakeLedger, veh, ctrl, epoch string, phi float64) {
	id := fmt.Sprintf("CSUBM_%s_%s", veh, epoch)
	rec := ControllerSubmission{ID: id, ControllerID: ctrl, VehicleID: veh, Epoch: epoch, Phi: phi}
	b, _ := json.Marshal(rec)
	fl.m[id] = b
}

// ═════════════════════════════════════════════════════════════════════════════
// Pure helper functions (no ledger needed)
// ═════════════════════════════════════════════════════════════════════════════

func TestFByzantine(t *testing.T) {
	cases := map[int]int{0: 0, 1: 0, 3: 0, 4: 1, 6: 1, 7: 2, 10: 3, 13: 4}
	for n, want := range cases {
		if got := fByzantine(n); got != want {
			t.Errorf("fByzantine(%d)=%d want %d", n, got, want)
		}
	}
}

func TestParseP256PubKey(t *testing.T) {
	_, pk := genID(t)
	if _, err := parseP256PubKey(pk); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := parseP256PubKey("zzzz"); err == nil {
		t.Error("bad hex accepted")
	}
	if _, err := parseP256PubKey("04abcd"); err == nil {
		t.Error("wrong-length key accepted")
	}
	// valid length, valid 0x04 prefix, but point not on curve.
	bad := "04" + strings.Repeat("11", 64)
	if _, err := parseP256PubKey(bad); err == nil {
		t.Error("off-curve point accepted")
	}
}

func TestVerifyECDSAP256(t *testing.T) {
	priv, pk := genID(t)
	digest := endorsementDigest("VEH_1", pk, hku64)
	sig := signHex(t, priv, digest)

	if !verifyECDSAP256(pk, sig, digest) {
		t.Error("valid signature rejected")
	}
	// tampered digest
	if verifyECDSAP256(pk, sig, endorsementDigest("VEH_2", pk, hku64)) {
		t.Error("signature verified against wrong digest")
	}
	// bad sig hex
	if verifyECDSAP256(pk, "zz", digest) {
		t.Error("bad sig hex verified")
	}
	// wrong key
	_, otherPk := genID(t)
	if verifyECDSAP256(otherPk, sig, digest) {
		t.Error("signature verified under wrong public key")
	}
}

func TestEndorsementDigest(t *testing.T) {
	d1 := endorsementDigest("VEH_1", "pk", "hku")
	if len(d1) != 32 {
		t.Fatalf("digest len=%d want 32", len(d1))
	}
	// order/content sensitivity
	if string(d1) == string(endorsementDigest("VEH_2", "pk", "hku")) {
		t.Error("digest not sensitive to vehicleID")
	}
	if string(d1) == string(endorsementDigest("VEH_1", "pk2", "hku")) {
		t.Error("digest not sensitive to pkHex")
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Algorithm 7 — SC-Register
// ═════════════════════════════════════════════════════════════════════════════

// buildEndorsers seeds `count` ACTIVE RSUs and returns a valid endorsersJSON
// signing endorsementDigest(vehID, vehPk, hku64).
func buildEndorsers(t *testing.T, fl *fakeLedger, vehID, vehPk string, count int) string {
	digest := endorsementDigest(vehID, vehPk, hku64)
	var es []Endorser
	for i := 0; i < count; i++ {
		rsuID := fmt.Sprintf("RSU_%d", i)
		priv, pk := genID(t)
		seedReg(fl, rsuID, RoleRSU, pk)
		es = append(es, Endorser{RSUID: rsuID, SigHex: signHex(t, priv, digest)})
	}
	b, _ := json.Marshal(es)
	return string(b)
}

func TestSCRegister_Happy(t *testing.T) {
	ctx, fl := newCtx()
	seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5) // f=1 → threshold 2f+1 = 3
	sc := SmartContract{}
	_, vehPk := genID(t)
	endorsers := buildEndorsers(t, fl, "VEH_1", vehPk, 3)

	err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, hku64, "t0", endorsers)
	ok(t, err)

	if fl.m["REG_VEH_1"] == nil {
		t.Fatal("registration record not written")
	}
	var rec RegistrationRecord
	json.Unmarshal(fl.m["REG_VEH_1"], &rec)
	if rec.Role != RoleVehicle || rec.Status != StatusActive {
		t.Errorf("bad record: %+v", rec)
	}
	if fl.m["SCTRUST_VEH_1"] == nil {
		t.Error("trust score not seeded for vehicle")
	}
}

func TestSCRegister_Rejections(t *testing.T) {
	_, vehPk := genID(t)

	t.Run("invalid role", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		sc := SmartContract{}
		err := sc.SCRegister(ctx, "VEH_1", "ALIEN", vehPk, hku64, "t", "[]")
		errHas(t, err, "invalid role")
	})

	t.Run("invalid pubkey", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, "04dead", hku64, "t", "[]")
		errHas(t, err, "invalid pk")
	})

	t.Run("hKuHex wrong length", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, "abcd", "t", "[]")
		errHas(t, err, "64 hex chars")
	})

	t.Run("hKuHex not hex", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		badHku := strings.Repeat("zz", 32) // 64 chars but not hex
		err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, badHku, "t", "[]")
		errHas(t, err, "not hex")
	})

	t.Run("duplicate identity", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, vehPk)
		sc := SmartContract{}
		err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, hku64, "t", "[]")
		errHas(t, err, "duplicate identity")
	})

	t.Run("malformed endorsersJSON", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, hku64, "t", "{not-an-array}")
		errHas(t, err, "endorsersJSON parse")
	})

	t.Run("insufficient endorsements", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5) // need 3
		sc := SmartContract{}
		endorsers := buildEndorsers(t, fl, "VEH_1", vehPk, 2) // only 2
		err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, hku64, "t", endorsers)
		errHas(t, err, "insufficient endorsements")
	})

	t.Run("endorser not an RSU is ignored", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		sc := SmartContract{}
		// 2 valid RSUs + 1 endorser registered as VEHICLE (must be skipped) → 2<3
		digest := endorsementDigest("VEH_1", vehPk, hku64)
		var es []Endorser
		for i := 0; i < 2; i++ {
			id := fmt.Sprintf("RSU_%d", i)
			priv, pk := genID(t)
			seedReg(fl, id, RoleRSU, pk)
			es = append(es, Endorser{RSUID: id, SigHex: signHex(t, priv, digest)})
		}
		privV, pkV := genID(t)
		seedReg(fl, "VEH_X", RoleVehicle, pkV) // wrong role
		es = append(es, Endorser{RSUID: "VEH_X", SigHex: signHex(t, privV, digest)})
		b, _ := json.Marshal(es)
		err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, hku64, "t", string(b))
		errHas(t, err, "insufficient endorsements")
	})

	t.Run("bad endorser signature is ignored", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		sc := SmartContract{}
		digest := endorsementDigest("VEH_1", vehPk, hku64)
		var es []Endorser
		for i := 0; i < 2; i++ {
			id := fmt.Sprintf("RSU_%d", i)
			priv, pk := genID(t)
			seedReg(fl, id, RoleRSU, pk)
			es = append(es, Endorser{RSUID: id, SigHex: signHex(t, priv, digest)})
		}
		// third RSU exists but signs the WRONG digest → verify fails → skipped
		badPriv, badPk := genID(t)
		seedReg(fl, "RSU_2", RoleRSU, badPk)
		wrong := signHex(t, badPriv, endorsementDigest("OTHER", vehPk, hku64))
		es = append(es, Endorser{RSUID: "RSU_2", SigHex: wrong})
		b, _ := json.Marshal(es)
		err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, hku64, "t", string(b))
		errHas(t, err, "insufficient endorsements")
	})

	t.Run("duplicate endorser RSU counted once", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		sc := SmartContract{}
		digest := endorsementDigest("VEH_1", vehPk, hku64)
		priv, pk := genID(t)
		seedReg(fl, "RSU_0", RoleRSU, pk)
		sig := signHex(t, priv, digest)
		// same RSU_0 three times → distinct count = 1 < 3
		es := []Endorser{
			{RSUID: "RSU_0", SigHex: sig},
			{RSUID: "RSU_0", SigHex: sig},
			{RSUID: "RSU_0", SigHex: sig},
		}
		b, _ := json.Marshal(es)
		err := sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, hku64, "t", string(b))
		errHas(t, err, "insufficient endorsements")
	})
}

// ═════════════════════════════════════════════════════════════════════════════
// SCBootstrapRSU
// ═════════════════════════════════════════════════════════════════════════════

func TestSCBootstrapRSU(t *testing.T) {
	_, pk := genID(t)

	t.Run("happy", func(t *testing.T) {
		ctx, fl := newCtx()
		sc := SmartContract{}
		ok(t, sc.SCBootstrapRSU(ctx, "RSU_0", pk, hku64, "t0"))
		var rec RegistrationRecord
		json.Unmarshal(fl.m["REG_RSU_0"], &rec)
		if rec.Role != RoleRSU || rec.Status != StatusActive {
			t.Errorf("bad bootstrap record: %+v", rec)
		}
	})

	t.Run("bad pubkey", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		errHas(t, sc.SCBootstrapRSU(ctx, "RSU_0", "04dead", hku64, "t"), "invalid pk")
	})

	t.Run("hKuHex wrong length", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		errHas(t, sc.SCBootstrapRSU(ctx, "RSU_0", pk, "abcd", "t"), "64 hex chars")
	})

	t.Run("duplicate", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "RSU_0", RoleRSU, pk)
		sc := SmartContract{}
		errHas(t, sc.SCBootstrapRSU(ctx, "RSU_0", pk, hku64, "t"), "duplicate identity")
	})
}

// ═════════════════════════════════════════════════════════════════════════════
// Registration read APIs
// ═════════════════════════════════════════════════════════════════════════════

func TestRegistrationReads(t *testing.T) {
	_, pk := genID(t)

	t.Run("GetRegistration found / not found", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		sc := SmartContract{}
		rec, err := sc.GetRegistration(ctx, "VEH_1")
		ok(t, err)
		if rec.ID != "VEH_1" {
			t.Error("wrong record")
		}
		_, err = sc.GetRegistration(ctx, "MISSING")
		errHas(t, err, "not found")
	})

	t.Run("IsRegistered", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		sc := SmartContract{}
		if v, _ := sc.IsRegistered(ctx, "VEH_1"); v != "true" {
			t.Error("active vehicle not reported registered")
		}
		if v, _ := sc.IsRegistered(ctx, "MISSING"); v != "false" {
			t.Error("missing vehicle reported registered")
		}
		// revoked → false
		var rec RegistrationRecord
		json.Unmarshal(fl.m["REG_VEH_1"], &rec)
		rec.Status = StatusRevoked
		b, _ := json.Marshal(rec)
		fl.m["REG_VEH_1"] = b
		if v, _ := sc.IsRegistered(ctx, "VEH_1"); v != "false" {
			t.Error("revoked vehicle reported registered")
		}
	})

	t.Run("GetAllRegistrations", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		seedReg(fl, "RSU_0", RoleRSU, pk)
		seedReg(fl, "CTRL_0", RoleController, pk)
		sc := SmartContract{}
		all, err := sc.GetAllRegistrations(ctx)
		ok(t, err)
		if len(all) != 3 {
			t.Errorf("got %d registrations want 3", len(all))
		}
	})
}

// ═════════════════════════════════════════════════════════════════════════════
// NetworkConfig
// ═════════════════════════════════════════════════════════════════════════════

func TestNetworkConfig(t *testing.T) {
	t.Run("init happy + read back", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		ok(t, sc.SCInitNetworkConfig(ctx, "7", "0.4", "0.6", "0.4", "2", "0.55"))
		cfg, err := sc.GetNetworkConfig(ctx)
		ok(t, err)
		if cfg.NumRSUs != 7 || cfg.TRev != 2 {
			t.Errorf("config not persisted: %+v", cfg)
		}
		approx(t, cfg.Alpha, 0.4)
		approx(t, cfg.TauWarn, 0.6)
		approx(t, cfg.TauMin, 0.4)
		approx(t, cfg.PsiAnomalyTh, 0.55)
	})

	t.Run("numRSUs too small", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		errHas(t, sc.SCInitNetworkConfig(ctx, "3", "0.3", "0.5", "0.3", "3", "0.5"), "too small")
	})

	t.Run("tau_min above tau_warn rejected", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		errHas(t, sc.SCInitNetworkConfig(ctx, "4", "0.3", "0.4", "0.6", "3", "0.5"), "must be ≤")
	})

	t.Run("parse errors", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		errHas(t, sc.SCInitNetworkConfig(ctx, "x", "0.3", "0.5", "0.3", "3", "0.5"), "numRSUs parse")
		errHas(t, sc.SCInitNetworkConfig(ctx, "4", "x", "0.5", "0.3", "3", "0.5"), "alpha parse")
		errHas(t, sc.SCInitNetworkConfig(ctx, "4", "0.3", "x", "0.3", "3", "0.5"), "tauWarn parse")
		errHas(t, sc.SCInitNetworkConfig(ctx, "4", "0.3", "0.5", "x", "3", "0.5"), "tauMin parse")
		errHas(t, sc.SCInitNetworkConfig(ctx, "4", "0.3", "0.5", "0.3", "x", "0.5"), "tRev parse")
		errHas(t, sc.SCInitNetworkConfig(ctx, "4", "0.3", "0.5", "0.3", "3", "x"), "psiTh parse")
	})

	t.Run("defaults when absent", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		cfg, err := sc.GetNetworkConfig(ctx)
		ok(t, err)
		if cfg.NumRSUs != 4 || cfg.UpdatedAt != "default" {
			t.Errorf("unexpected defaults: %+v", cfg)
		}
	})
}

// ═════════════════════════════════════════════════════════════════════════════
// Eq 3.56 / 3.57 — evidence submission (registration-gated)
// ═════════════════════════════════════════════════════════════════════════════

func TestSCTrustSubmitEvidence(t *testing.T) {
	_, pk := genID(t)

	t.Run("happy", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		rsuPriv := seedRegKeyed(t, fl, "RSU_0", RoleRSU)
		sc := SmartContract{}
		sig := signHex(t, rsuPriv, evidenceDigest("VEH_1", "RSU_0", "E1", "0.7", "h"))
		ok(t, sc.SCTrustSubmitEvidence(ctx, "VEH_1", "RSU_0", "E1", "0.7", "h", sig))
		if fl.m["SUBM_VEH_1_E1_RSU_0"] == nil {
			t.Fatal("evidence not written")
		}
		var rec EpochSubmission
		json.Unmarshal(fl.m["SUBM_VEH_1_E1_RSU_0"], &rec)
		approx(t, rec.Psi, 0.7)
	})

	t.Run("invalid evidence signature rejected", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		rsuPriv := seedRegKeyed(t, fl, "RSU_0", RoleRSU)
		sc := SmartContract{}
		// valid sig but over a DIFFERENT psi than transmitted → digest mismatch
		sig := signHex(t, rsuPriv, evidenceDigest("VEH_1", "RSU_0", "E1", "0.1", "h"))
		errHas(t, sc.SCTrustSubmitEvidence(ctx, "VEH_1", "RSU_0", "E1", "0.7", "h", sig),
			"invalid evidence signature")
		if fl.m["SUBM_VEH_1_E1_RSU_0"] != nil {
			t.Error("evidence must not be written when signature fails")
		}
	})

	t.Run("evidence signed by foreign key rejected", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		seedRegKeyed(t, fl, "RSU_0", RoleRSU)
		sc := SmartContract{}
		// a well-formed sig from some OTHER key — not RSU_0's registered key
		foreign, _ := genID(t)
		sig := signHex(t, foreign, evidenceDigest("VEH_1", "RSU_0", "E1", "0.7", "h"))
		errHas(t, sc.SCTrustSubmitEvidence(ctx, "VEH_1", "RSU_0", "E1", "0.7", "h", sig),
			"invalid evidence signature")
	})

	t.Run("vehicle not registered", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "RSU_0", RoleRSU, pk)
		sc := SmartContract{}
		errHas(t, sc.SCTrustSubmitEvidence(ctx, "VEH_1", "RSU_0", "E1", "0.7", "h", "s"),
			"VEH_1 is not registered")
	})

	t.Run("rsu not registered", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		sc := SmartContract{}
		errHas(t, sc.SCTrustSubmitEvidence(ctx, "VEH_1", "RSU_0", "E1", "0.7", "h", "s"),
			"RSU_0 is not registered")
	})

	t.Run("wrong role for vehicle slot", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleRSU, pk) // registered, but as RSU
		seedReg(fl, "RSU_0", RoleRSU, pk)
		sc := SmartContract{}
		errHas(t, sc.SCTrustSubmitEvidence(ctx, "VEH_1", "RSU_0", "E1", "0.7", "h", "s"),
			"expected VEHICLE")
	})

	t.Run("bad psi", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		rsuPriv := seedRegKeyed(t, fl, "RSU_0", RoleRSU)
		sc := SmartContract{}
		// sign the (malformed) psi string verbatim so we pass the sig gate and
		// reach the float parse, which is what this case asserts.
		sig := signHex(t, rsuPriv, evidenceDigest("VEH_1", "RSU_0", "E1", "NaNx", "h"))
		errHas(t, sc.SCTrustSubmitEvidence(ctx, "VEH_1", "RSU_0", "E1", "NaNx", "h", sig),
			"psi parse")
	})
}

func TestSCControllerSubmitEvidence(t *testing.T) {
	_, pk := genID(t)

	t.Run("happy", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		ctrlPriv := seedRegKeyed(t, fl, "CTRL_0", RoleController)
		sc := SmartContract{}
		sig := signHex(t, ctrlPriv, controllerEvidenceDigest("VEH_1", "CTRL_0", "E1", "0.8", "h"))
		ok(t, sc.SCControllerSubmitEvidence(ctx, "VEH_1", "CTRL_0", "E1", "0.8", "h", sig))
		if fl.m["CSUBM_VEH_1_E1"] == nil {
			t.Fatal("controller evidence not written")
		}
	})

	t.Run("controller not registered", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		sc := SmartContract{}
		errHas(t, sc.SCControllerSubmitEvidence(ctx, "VEH_1", "CTRL_0", "E1", "0.8", "h", "s"),
			"CTRL_0 is not registered")
	})

	t.Run("invalid controller signature rejected", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		seedRegKeyed(t, fl, "CTRL_0", RoleController)
		sc := SmartContract{}
		foreign, _ := genID(t)
		sig := signHex(t, foreign, controllerEvidenceDigest("VEH_1", "CTRL_0", "E1", "0.8", "h"))
		errHas(t, sc.SCControllerSubmitEvidence(ctx, "VEH_1", "CTRL_0", "E1", "0.8", "h", sig),
			"invalid controller signature")
	})

	t.Run("bad phi", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		ctrlPriv := seedRegKeyed(t, fl, "CTRL_0", RoleController)
		sc := SmartContract{}
		sig := signHex(t, ctrlPriv, controllerEvidenceDigest("VEH_1", "CTRL_0", "E1", "xx", "h"))
		errHas(t, sc.SCControllerSubmitEvidence(ctx, "VEH_1", "CTRL_0", "E1", "xx", "h", sig),
			"phi parse")
	})
}

// ═════════════════════════════════════════════════════════════════════════════
// Eq 3.55 — SC-Trust finalize per epoch
// ═════════════════════════════════════════════════════════════════════════════

func TestSCTrustFinalizeEpoch(t *testing.T) {
	_, pk := genID(t)

	t.Run("EMA over 3 RSU witnesses", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		seedTrust(fl, "VEH_1", 1.0)
		// Witness RSUs must be registered+trusted: SCTrustFinalizeEpoch
		// excludes non-trusted RSU submissions from the aggregate (§3.5.1).
		seedReg(fl, "RSU_0", RoleRSU, pk)
		seedReg(fl, "RSU_1", RoleRSU, pk)
		seedReg(fl, "RSU_2", RoleRSU, pk)
		seedSubm(fl, "VEH_1", "E1", "RSU_0", 0.6)
		seedSubm(fl, "VEH_1", "E1", "RSU_1", 0.4)
		seedSubm(fl, "VEH_1", "E1", "RSU_2", 0.5) // mean = 0.5
		sc := SmartContract{}
		rec, err := sc.SCTrustFinalizeEpoch(ctx, "VEH_1", "E1")
		ok(t, err)
		approx(t, rec.MeanPsi, 0.5)
		// τ = 0.3*1.0 + 0.7*(1-0.5) = 0.65
		approx(t, rec.TrustScore, 0.65)
		if rec.NumRSUsLastEpoch != 3 {
			t.Errorf("witnesses=%d want 3", rec.NumRSUsLastEpoch)
		}
	})

	t.Run("no submissions errors", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		seedTrust(fl, "VEH_1", 1.0)
		sc := SmartContract{}
		_, err := sc.SCTrustFinalizeEpoch(ctx, "VEH_1", "E1")
		errHas(t, err, "no submissions")
	})

	t.Run("unregistered vehicle rejected", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		sc := SmartContract{}
		_, err := sc.SCTrustFinalizeEpoch(ctx, "VEH_1", "E1")
		errHas(t, err, "not registered")
	})

	t.Run("T_rev consecutive-low gate increments", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.0, 0.5, 0.3, 2, 0.5) // alpha=0 → τ = 1-meanPsi
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		seedTrust(fl, "VEH_1", 1.0)
		seedReg(fl, "RSU_0", RoleRSU, pk) // trusted witness (§3.5.1)
		sc := SmartContract{}

		seedSubm(fl, "VEH_1", "E1", "RSU_0", 0.8) // τ=0.2 <0.5
		r1, err := sc.SCTrustFinalizeEpoch(ctx, "VEH_1", "E1")
		ok(t, err)
		if r1.ConsecutiveLowEpochs != 1 {
			t.Errorf("consec=%d want 1", r1.ConsecutiveLowEpochs)
		}
		seedSubm(fl, "VEH_1", "E2", "RSU_0", 0.8) // τ=0.2 again
		r2, err := sc.SCTrustFinalizeEpoch(ctx, "VEH_1", "E2")
		ok(t, err)
		if r2.ConsecutiveLowEpochs != 2 {
			t.Errorf("consec=%d want 2 (>= T_rev)", r2.ConsecutiveLowEpochs)
		}
	})

	t.Run("trust recovery resets consec counter", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.0, 0.5, 0.3, 2, 0.5)
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		seedTrust(fl, "VEH_1", 0.2)
		seedReg(fl, "RSU_0", RoleRSU, pk) // trusted witness (§3.5.1)
		fl.m["SCTRUST_VEH_1"] = func() []byte {
			r := SCTrustScore{ID: "SCTRUST_VEH_1", VehicleID: "VEH_1", TrustScore: 0.2, ConsecutiveLowEpochs: 1}
			b, _ := json.Marshal(r)
			return b
		}()
		seedSubm(fl, "VEH_1", "E9", "RSU_0", 0.1) // τ=0.9 ≥0.5 → reset
		sc := SmartContract{}
		rec, err := sc.SCTrustFinalizeEpoch(ctx, "VEH_1", "E9")
		ok(t, err)
		if rec.ConsecutiveLowEpochs != 0 {
			t.Errorf("consec=%d want 0 after recovery", rec.ConsecutiveLowEpochs)
		}
	})
}

func TestTrustReads(t *testing.T) {
	_, pk := genID(t)
	t.Run("GetTrustScore found / missing", func(t *testing.T) {
		ctx, fl := newCtx()
		seedTrust(fl, "VEH_1", 0.9)
		sc := SmartContract{}
		rec, err := sc.GetTrustScore(ctx, "VEH_1")
		ok(t, err)
		approx(t, rec.TrustScore, 0.9)
		_, err = sc.GetTrustScore(ctx, "VEH_X")
		errHas(t, err, "no trust score")
	})
	t.Run("GetAllTrustScores", func(t *testing.T) {
		ctx, fl := newCtx()
		seedTrust(fl, "VEH_1", 1.0)
		seedTrust(fl, "VEH_2", 0.5)
		_ = pk
		sc := SmartContract{}
		all, err := sc.GetAllTrustScores(ctx)
		ok(t, err)
		if len(all) != 2 {
			t.Errorf("got %d want 2", len(all))
		}
	})
}

// ═════════════════════════════════════════════════════════════════════════════
// Algorithm 8 / Eq 3.59 — CP-DETECT
// ═════════════════════════════════════════════════════════════════════════════

func TestCPDetectCheck(t *testing.T) {
	t.Run("no controller submission → nil", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		sc := SmartContract{}
		flag, err := sc.CPDetectCheck(ctx, "VEH_1", "E1")
		ok(t, err)
		if flag != nil {
			t.Error("expected nil flag when no controller submission")
		}
	})

	t.Run("controller-anom vs implicit-clean RSUs fires flag", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)        // f=1 → f+1 = 2
		seedCSub(fl, "VEH_1", "CTRL_0", "E1", 0.8) // Φ>ψ_th → cAnom=true
		// no RSU SUBMs → 4 implicit clean votes → conflict=4 ≥ 2
		sc := SmartContract{}
		flag, err := sc.CPDetectCheck(ctx, "VEH_1", "E1")
		ok(t, err)
		if flag == nil {
			t.Fatal("expected flag to fire")
		}
		if flag.ConflictCount < flag.ThresholdFP1 {
			t.Errorf("conflict %d < threshold %d", flag.ConflictCount, flag.ThresholdFP1)
		}
		if fl.m[flag.ID] == nil {
			t.Error("flag not persisted on-chain")
		}
	})

	t.Run("controller-clean minor disagreement → no flag", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)        // f+1 = 2
		seedCSub(fl, "VEH_1", "CTRL_0", "E1", 0.2) // cAnom=false
		seedSubm(fl, "VEH_1", "E1", "RSU_0", 0.8)  // 1 RSU disagrees
		sc := SmartContract{}
		flag, err := sc.CPDetectCheck(ctx, "VEH_1", "E1")
		ok(t, err)
		if flag != nil {
			t.Error("single disagreement should not reach f+1 threshold")
		}
	})
}

func TestControllerFlagReads(t *testing.T) {
	ctx, fl := newCtx()
	seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
	seedCSub(fl, "VEH_1", "CTRL_0", "E1", 0.9)
	sc := SmartContract{}
	_, err := sc.CPDetectCheck(ctx, "VEH_1", "E1") // fires a flag
	ok(t, err)

	if v, _ := sc.IsControllerFlagged(ctx, "CTRL_0"); v != "true" {
		t.Error("controller should be flagged")
	}
	if v, _ := sc.IsControllerFlagged(ctx, "CTRL_9"); v != "false" {
		t.Error("unknown controller should not be flagged")
	}
	all, err := sc.GetAllControllerFlags(ctx)
	ok(t, err)
	if len(all) != 1 {
		t.Errorf("got %d flags want 1", len(all))
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Multi-controller C_trusted set — CP-DETECT exclusion + reassignment
// (invariant 2 / Eq 3.64–3.67). The 5 logical controllers CTRL_0..CTRL_4 form
// the trusted set; the lowest-numbered ACTIVE member is the head. A CP-DETECT
// f+1 conflict EXCLUDES the offending controller and hands C_trusted to the
// next ACTIVE member — driven by RSU consensus, never the controller itself.
// ═════════════════════════════════════════════════════════════════════════════

func seedControllers(fl *fakeLedger, n int) {
	_, pk := genIDStatic()
	for i := 0; i < n; i++ {
		seedReg(fl, fmt.Sprintf("CTRL_%d", i), RoleController, pk)
	}
}

// genIDStatic mirrors genID but without *testing.T, for non-asserting seeds.
func genIDStatic() (*ecdsa.PrivateKey, string) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	return priv, hex.EncodeToString(raw)
}

func TestActiveControllerSelection(t *testing.T) {
	t.Run("head is lowest-numbered ACTIVE controller", func(t *testing.T) {
		ctx, fl := newCtx()
		seedControllers(fl, 5)
		sc := SmartContract{}
		id, err := sc.GetActiveController(ctx)
		ok(t, err)
		if id != "CTRL_0" {
			t.Errorf("active controller=%s want CTRL_0", id)
		}
	})

	t.Run("excluded head skipped for successor", func(t *testing.T) {
		ctx, fl := newCtx()
		seedControllers(fl, 5)
		// Manually flip CTRL_0 to EXCLUDED.
		var reg RegistrationRecord
		json.Unmarshal(fl.m["REG_CTRL_0"], &reg)
		reg.Status = StatusExcluded
		b, _ := json.Marshal(reg)
		fl.m["REG_CTRL_0"] = b
		sc := SmartContract{}
		id, err := sc.GetActiveController(ctx)
		ok(t, err)
		if id != "CTRL_1" {
			t.Errorf("successor=%s want CTRL_1", id)
		}
	})

	t.Run("no active controller errors", func(t *testing.T) {
		ctx, _ := newCtx()
		sc := SmartContract{}
		_, err := sc.GetActiveController(ctx)
		errHas(t, err, "no active controller")
	})

	t.Run("GetTrustedControllers lists all", func(t *testing.T) {
		ctx, fl := newCtx()
		seedControllers(fl, 5)
		sc := SmartContract{}
		all, err := sc.GetTrustedControllers(ctx)
		ok(t, err)
		if len(all) != 5 {
			t.Errorf("trusted controllers=%d want 5", len(all))
		}
	})
}

func TestCPDetectExcludesAndReassigns(t *testing.T) {
	ctx, fl := newCtx()
	seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5) // f=1 → f+1 = 2
	seedControllers(fl, 5)              // CTRL_0..CTRL_4 ACTIVE
	_, vpk := genIDStatic()
	seedReg(fl, "VEH_1", RoleVehicle, vpk) // so evidence reaches the controller gate
	// CTRL_0 (current head) flags an anomaly the RSUs implicitly clean-vote
	// against → conflict ≥ f+1 → exclude CTRL_0, hand off to CTRL_1.
	seedCSub(fl, "VEH_1", "CTRL_0", "E1", 0.9)
	sc := SmartContract{}

	flag, err := sc.CPDetectCheck(ctx, "VEH_1", "E1")
	ok(t, err)
	if flag == nil {
		t.Fatal("expected CP-DETECT flag to fire")
	}

	// CTRL_0 must now be EXCLUDED and bounce at requireActive.
	var reg RegistrationRecord
	json.Unmarshal(fl.m["REG_CTRL_0"], &reg)
	if reg.Status != StatusExcluded {
		t.Errorf("CTRL_0 status=%s want EXCLUDED", reg.Status)
	}

	// C_trusted head must roll over to CTRL_1.
	head, err := sc.GetActiveController(ctx)
	ok(t, err)
	if head != "CTRL_1" {
		t.Errorf("new head=%s want CTRL_1", head)
	}

	// A reassignment record must be written, naming excluded + successor.
	ras, err := sc.GetControllerReassignments(ctx)
	ok(t, err)
	if len(ras) != 1 {
		t.Fatalf("reassignments=%d want 1", len(ras))
	}
	if ras[0].ExcludedController != "CTRL_0" || ras[0].SuccessorController != "CTRL_1" {
		t.Errorf("reassignment excluded=%s successor=%s want CTRL_0→CTRL_1",
			ras[0].ExcludedController, ras[0].SuccessorController)
	}
	if ras[0].ConflictCount < ras[0].ThresholdFP1 {
		t.Errorf("conflict %d < threshold %d", ras[0].ConflictCount, ras[0].ThresholdFP1)
	}

	// An EXCLUDED controller's evidence must bounce at requireActive.
	err2 := sc.SCControllerSubmitEvidence(ctx, "VEH_1", "CTRL_0", "E2", "0.9", "h", "s")
	errHas(t, err2, "status=EXCLUDED")

	// Idempotence: re-running CP-DETECT for a new epoch under the now-EXCLUDED
	// CTRL_0 writes no second reassignment record.
	seedCSub(fl, "VEH_2", "CTRL_0", "E2", 0.9)
	_, err = sc.CPDetectCheck(ctx, "VEH_2", "E2")
	ok(t, err)
	ras2, err := sc.GetControllerReassignments(ctx)
	ok(t, err)
	if len(ras2) != 1 {
		t.Errorf("reassignments after idempotent re-run=%d want 1", len(ras2))
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Eq 3.58 — SC-Revoke BFT 2f+1 vote
// ═════════════════════════════════════════════════════════════════════════════

func TestSCRevokeVote(t *testing.T) {
	_, pk := genID(t)

	setup := func() (*mocks.TransactionContext, *fakeLedger, SmartContract, map[string]*ecdsa.PrivateKey) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5) // f=1 → 2f+1 = 3
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		privs := map[string]*ecdsa.PrivateKey{}
		for i := 0; i < 4; i++ {
			id := fmt.Sprintf("RSU_%d", i)
			privs[id] = seedRegKeyed(t, fl, id, RoleRSU)
		}
		return ctx, fl, SmartContract{}, privs
	}

	t.Run("below threshold does not revoke", func(t *testing.T) {
		ctx, fl, sc, privs := setup()
		res, err := castVote(t, sc, ctx, privs["RSU_0"], "VEH_1", "RSU_0", "tp", "ts1")
		ok(t, err)
		if !strings.Contains(res, `"revoked":false`) {
			t.Errorf("unexpected result: %s", res)
		}
		if v, _ := sc.IsRevoked(ctx, "VEH_1"); v != "false" {
			t.Error("revoked too early")
		}
		_ = fl
	})

	t.Run("invalid vote signature rejected", func(t *testing.T) {
		ctx, _, sc, privs := setup()
		// RSU_1's key signing a vote claimed to come from RSU_0 → digest binds
		// RSU_0, so verification against RSU_0's registered key fails.
		sig := signHex(t, privs["RSU_1"], revokeVoteDigest("VEH_1", "RSU_0", "tp", "ts"))
		_, err := sc.SCRevokeVote(ctx, "VEH_1", "RSU_0", "tp", sig, "ts")
		errHas(t, err, "invalid revoke vote signature")
	})

	t.Run("2f+1 distinct votes revoke + flip status", func(t *testing.T) {
		ctx, fl, sc, privs := setup()
		ok2 := func(_ string, e error) { ok(t, e) }
		ok2(castVote(t, sc, ctx, privs["RSU_0"], "VEH_1", "RSU_0", "tp", "ts"))
		ok2(castVote(t, sc, ctx, privs["RSU_1"], "VEH_1", "RSU_1", "tp", "ts"))
		res, err := castVote(t, sc, ctx, privs["RSU_2"], "VEH_1", "RSU_2", "tp", "ts")
		ok(t, err)
		if !strings.Contains(res, `"revoked":true`) {
			t.Fatalf("expected revoked true, got %s", res)
		}
		if v, _ := sc.IsRevoked(ctx, "VEH_1"); v != "true" {
			t.Error("IsRevoked should be true")
		}
		var reg RegistrationRecord
		json.Unmarshal(fl.m["REG_VEH_1"], &reg)
		if reg.Status != StatusRevoked {
			t.Errorf("status=%s want REVOKED", reg.Status)
		}
	})

	t.Run("vote after revoke bounces on gate", func(t *testing.T) {
		ctx, _, sc, privs := setup()
		castVote(t, sc, ctx, privs["RSU_0"], "VEH_1", "RSU_0", "tp", "ts")
		castVote(t, sc, ctx, privs["RSU_1"], "VEH_1", "RSU_1", "tp", "ts")
		castVote(t, sc, ctx, privs["RSU_2"], "VEH_1", "RSU_2", "tp", "ts") // revokes
		_, err := castVote(t, sc, ctx, privs["RSU_3"], "VEH_1", "RSU_3", "tp", "ts")
		errHas(t, err, "status=REVOKED")
	})

	t.Run("unregistered vehicle / rsu rejected", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		sc := SmartContract{}
		_, err := sc.SCRevokeVote(ctx, "VEH_1", "RSU_0", "tp", "s", "ts")
		errHas(t, err, "VEH_1 is not registered")
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		_, err = sc.SCRevokeVote(ctx, "VEH_1", "RSU_0", "tp", "s", "ts")
		errHas(t, err, "RSU_0 is not registered")
	})
}

// TestSCRevokeWindow exercises the sliding-window quorum (Eq 3.65): only votes
// whose SIM-time falls within the last T_w seconds (default 30 s, backfilled by
// GetNetworkConfig) count toward 2f+1. A witness older than T_w expires and must
// not contribute, even though it stays on the ledger for audit.
func TestSCRevokeWindow(t *testing.T) {
	_, pk := genID(t)

	setup := func() (*mocks.TransactionContext, SmartContract, map[string]*ecdsa.PrivateKey) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5) // f=1 → 2f+1 = 3; T_w backfills to 30
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		privs := map[string]*ecdsa.PrivateKey{}
		for i := 0; i < 4; i++ {
			id := fmt.Sprintf("RSU_%d", i)
			privs[id] = seedRegKeyed(t, fl, id, RoleRSU)
		}
		return ctx, SmartContract{}, privs
	}

	t.Run("three witnesses within T_w revoke", func(t *testing.T) {
		ctx, sc, privs := setup()
		ok2 := func(_ string, e error) { ok(t, e) }
		ok2(castVote(t, sc, ctx, privs["RSU_0"], "VEH_1", "RSU_0", "tp", "0.0"))
		ok2(castVote(t, sc, ctx, privs["RSU_1"], "VEH_1", "RSU_1", "tp", "10.0"))
		res, err := castVote(t, sc, ctx, privs["RSU_2"], "VEH_1", "RSU_2", "tp", "20.0")
		ok(t, err)
		if !strings.Contains(res, `"revoked":true`) {
			t.Fatalf("3 in-window witnesses should revoke; got %s", res)
		}
	})

	t.Run("expired witness does not count toward quorum", func(t *testing.T) {
		ctx, sc, privs := setup()
		// RSU_0 witnesses at t=0, then a long gap. By the time RSU_1/RSU_2 vote
		// near t=100-110, RSU_0's vote (t=0) is far outside [now-30, now] and is
		// dropped — so only 2 in-window witnesses remain and revocation must NOT
		// fire (proves the window, vs. the old "count all votes forever" bug).
		castVote(t, sc, ctx, privs["RSU_0"], "VEH_1", "RSU_0", "tp", "0.0")
		castVote(t, sc, ctx, privs["RSU_1"], "VEH_1", "RSU_1", "tp", "100.0")
		res, err := castVote(t, sc, ctx, privs["RSU_2"], "VEH_1", "RSU_2", "tp", "110.0")
		ok(t, err)
		if !strings.Contains(res, `"revoked":false`) {
			t.Fatalf("expired RSU_0 must not pad the quorum; got %s", res)
		}
		if v, _ := sc.IsRevoked(ctx, "VEH_1"); v != "false" {
			t.Error("vehicle revoked despite only 2 in-window witnesses")
		}
		// A 3rd fresh witness inside the window now completes the quorum.
		res, err = castVote(t, sc, ctx, privs["RSU_3"], "VEH_1", "RSU_3", "tp", "115.0")
		ok(t, err)
		if !strings.Contains(res, `"revoked":true`) {
			t.Fatalf("3 in-window witnesses (RSU_1/2/3) should revoke; got %s", res)
		}
	})
}

func TestRevokeReads(t *testing.T) {
	_, pk := genID(t)
	ctx, fl := newCtx()
	seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
	seedReg(fl, "VEH_1", RoleVehicle, pk)
	privs := map[string]*ecdsa.PrivateKey{}
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("RSU_%d", i)
		privs[id] = seedRegKeyed(t, fl, id, RoleRSU)
	}
	sc := SmartContract{}

	t.Run("SCRevokeStatus pre-revoke", func(t *testing.T) {
		castVote(t, sc, ctx, privs["RSU_0"], "VEH_1", "RSU_0", "tp", "ts")
		st, err := sc.SCRevokeStatus(ctx, "VEH_1")
		ok(t, err)
		if !strings.Contains(st, `"votes":1`) || !strings.Contains(st, `"threshold":3`) {
			t.Errorf("status=%s", st)
		}
	})

	t.Run("GetRevokeVotes + GetAllRevokeRecords", func(t *testing.T) {
		castVote(t, sc, ctx, privs["RSU_1"], "VEH_1", "RSU_1", "tp", "ts")
		castVote(t, sc, ctx, privs["RSU_2"], "VEH_1", "RSU_2", "tp", "ts") // now revoked
		votes, err := sc.GetRevokeVotes(ctx, "VEH_1")
		ok(t, err)
		if len(votes) != 3 {
			t.Errorf("votes=%d want 3", len(votes))
		}
		recs, err := sc.GetAllRevokeRecords(ctx)
		ok(t, err)
		if len(recs) != 1 {
			t.Errorf("revoke records=%d want 1", len(recs))
		}
	})
}

// ═════════════════════════════════════════════════════════════════════════════
// §3.5.1 — RSU dynamic trust lifecycle: demotion (TRUSTED→CLIENT), terminal
// SC-Revoke after T_rev consecutive-low epochs, and the BFT floor guard hold.
// ═════════════════════════════════════════════════════════════════════════════

func TestSCRSUFinalizeEpoch(t *testing.T) {
	_, pk := genID(t)

	// findRSU returns the RSUTrustScore for rsu from a finalize result slice.
	findRSU := func(out []*RSUTrustScore, rsu string) *RSUTrustScore {
		for _, r := range out {
			if r.RSUID == rsu {
				return r
			}
		}
		return nil
	}

	t.Run("demotion TRUSTED→CLIENT below tau_th", func(t *testing.T) {
		ctx, fl := newCtx()
		// f=(4-1)/3=1 → floor=4. Register 5 trusted RSUs so demoting one
		// keeps |R_trusted|-1 = 4 ≥ floor (no floor-guard interference).
		seedNetCfg(fl, 4, 0.0, 0.5, 0.3, 3, 0.5) // alpha=0 → τ = 1-m_j
		for i := 0; i < 5; i++ {
			seedReg(fl, fmt.Sprintf("RSU_%d", i), RoleRSU, pk)
		}
		seedRSUTrust(fl, "RSU_0", 1.0)
		// RSU_0 is the lone flagger of VEH_99 → quorum verdict q=0 disagrees
		// with its flag → m_0=1 → τ=0 < 0.5 → demote.
		seedSubm(fl, "VEH_99", "E1", "RSU_0", 0.9)
		sc := SmartContract{}
		out, err := sc.SCRSUFinalizeEpoch(ctx, "E1")
		ok(t, err)
		r0 := findRSU(out, "RSU_0")
		if r0 == nil || r0.State != RSUStateClient {
			t.Fatalf("RSU_0 state=%v want CLIENT", r0)
		}
		approx(t, r0.TrustScore, 0.0)
		reg, err := sc.GetRegistration(ctx, "RSU_0")
		ok(t, err)
		if reg.RSUState != RSUStateClient {
			t.Errorf("REG RSUState=%s want CLIENT", reg.RSUState)
		}
		if reg.Status != StatusActive {
			t.Errorf("demoted RSU should stay ACTIVE, got %s", reg.Status)
		}
	})

	t.Run("probation band tau_min<=tau<tau_warn stays TRUSTED+flagged", func(t *testing.T) {
		ctx, fl := newCtx()
		// alpha=1 → τ frozen at the seeded value (m_j weight is (1-α)=0), so we
		// can land RSU_0 squarely in the probation band [0.3, 0.5).
		seedNetCfg(fl, 4, 1.0, 0.5, 0.3, 3, 0.5)
		for i := 0; i < 5; i++ {
			seedReg(fl, fmt.Sprintf("RSU_%d", i), RoleRSU, pk)
		}
		seedRSUTrust(fl, "RSU_0", 0.4)
		seedSubm(fl, "VEH_99", "E1", "RSU_0", 0.9)
		sc := SmartContract{}
		out, err := sc.SCRSUFinalizeEpoch(ctx, "E1")
		ok(t, err)
		r0 := findRSU(out, "RSU_0")
		if r0 == nil || r0.State != RSUStateTrusted || !r0.Probationary || r0.FloorHeld {
			t.Fatalf("RSU_0=%v want TRUSTED+Probationary (not floor-held)", r0)
		}
		reg, err := sc.GetRegistration(ctx, "RSU_0")
		ok(t, err)
		if reg.RSUState != RSUStateTrusted || reg.Status != StatusActive {
			t.Errorf("probationary RSU must stay TRUSTED+ACTIVE, got state=%s status=%s",
				reg.RSUState, reg.Status)
		}
	})

	t.Run("T_rev consecutive-low → SC-Revoke + status REVOKED", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.0, 0.5, 0.3, 2, 0.5) // T_rev=2
		for i := 0; i < 5; i++ {
			seedReg(fl, fmt.Sprintf("RSU_%d", i), RoleRSU, pk)
		}
		seedRSUTrust(fl, "RSU_0", 1.0)
		sc := SmartContract{}

		seedSubm(fl, "VEH_99", "E1", "RSU_0", 0.9) // m=1 → τ=0, consec=1 → demote
		_, err := sc.SCRSUFinalizeEpoch(ctx, "E1")
		ok(t, err)
		seedSubm(fl, "VEH_99", "E2", "RSU_0", 0.9) // consec=2 ≥ T_rev → revoke
		out, err := sc.SCRSUFinalizeEpoch(ctx, "E2")
		ok(t, err)
		r0 := findRSU(out, "RSU_0")
		if r0 == nil || r0.ConsecutiveLowEpochs < 2 {
			t.Fatalf("RSU_0=%v want consec≥2", r0)
		}
		reg, err := sc.GetRegistration(ctx, "RSU_0")
		ok(t, err)
		if reg.Status != StatusRevoked {
			t.Errorf("REG Status=%s want REVOKED", reg.Status)
		}
		isRev, err := sc.IsRevoked(ctx, "RSU_0")
		ok(t, err)
		if isRev != "true" {
			t.Errorf("IsRevoked(RSU_0)=%s want true", isRev)
		}
		recs, err := sc.GetAllRevokeRecords(ctx)
		ok(t, err)
		found := false
		for _, r := range recs {
			if r.RSUID == "RSU_0" && r.Reason == "rsu_trust_decay" {
				found = true
			}
		}
		if !found {
			t.Errorf("no rsu_trust_decay revoke record for RSU_0 (%d recs)", len(recs))
		}
	})

	t.Run("BFT floor guard holds demotion as probationary", func(t *testing.T) {
		ctx, fl := newCtx()
		// Register EXACTLY floor (4) trusted RSUs: demoting one would drop
		// |R_trusted| to 3 < floor=4, so the guard holds RSU_0 TRUSTED.
		seedNetCfg(fl, 4, 0.0, 0.5, 0.3, 3, 0.5)
		for i := 0; i < 4; i++ {
			seedReg(fl, fmt.Sprintf("RSU_%d", i), RoleRSU, pk)
		}
		seedRSUTrust(fl, "RSU_0", 1.0)
		seedSubm(fl, "VEH_99", "E1", "RSU_0", 0.9) // wants out, but floor blocks
		sc := SmartContract{}
		out, err := sc.SCRSUFinalizeEpoch(ctx, "E1")
		ok(t, err)
		r0 := findRSU(out, "RSU_0")
		if r0 == nil || r0.State != RSUStateTrusted || !r0.FloorHeld {
			t.Fatalf("RSU_0=%v want TRUSTED+floor-held", r0)
		}
		reg, err := sc.GetRegistration(ctx, "RSU_0")
		ok(t, err)
		if reg.RSUState == RSUStateClient || reg.Status != StatusActive {
			t.Errorf("floor-held RSU must stay TRUSTED+ACTIVE, got state=%s status=%s",
				reg.RSUState, reg.Status)
		}
	})
}

// ═════════════════════════════════════════════════════════════════════════════
// Diagnostic read APIs + lifecycle
// ═════════════════════════════════════════════════════════════════════════════

func TestDiagnosticReads(t *testing.T) {
	ctx, fl := newCtx()
	seedSubm(fl, "VEH_1", "E1", "RSU_0", 0.6)
	seedSubm(fl, "VEH_1", "E1", "RSU_1", 0.7)
	seedCSub(fl, "VEH_1", "CTRL_0", "E1", 0.8)
	sc := SmartContract{}

	t.Run("GetEpochSubmissions", func(t *testing.T) {
		subs, err := sc.GetEpochSubmissions(ctx, "VEH_1", "E1")
		ok(t, err)
		if len(subs) != 2 {
			t.Errorf("subs=%d want 2", len(subs))
		}
	})

	t.Run("GetControllerSubmission found / missing", func(t *testing.T) {
		cs, err := sc.GetControllerSubmission(ctx, "VEH_1", "E1")
		ok(t, err)
		approx(t, cs.Phi, 0.8)
		_, err = sc.GetControllerSubmission(ctx, "VEH_1", "E9")
		errHas(t, err, "no controller submission")
	})
}

func TestInitLedger(t *testing.T) {
	ctx, _ := newCtx()
	sc := SmartContract{}
	ok(t, sc.InitLedger(ctx))
}

// ─────────────────────────────────────────────────────────────────────────────
// Infrastructure-failure paths: ledger I/O errors and corrupt on-chain state.
// Unreachable from the integration run (a real ledger does not fail mid-call,
// and committed state is never malformed JSON), so they are only verifiable
// here via fault injection. Each asserts the function surfaces the fault
// instead of silently returning a wrong result.
// ─────────────────────────────────────────────────────────────────────────────

func stubOf(ctx *mocks.TransactionContext) *mocks.ChaincodeStub {
	return ctx.GetStub().(*mocks.ChaincodeStub)
}

func TestGetStateErrorsPropagate(t *testing.T) {
	sc := SmartContract{}
	mk := func() *mocks.TransactionContext {
		ctx, _ := newCtx()
		stubOf(ctx).GetStateStub = func(string) ([]byte, error) {
			return nil, fmt.Errorf("ledger down")
		}
		return ctx
	}

	t.Run("GetRegistration", func(t *testing.T) {
		_, err := sc.GetRegistration(mk(), "VEH_1")
		errHas(t, err, "ledger down")
	})
	t.Run("IsRegistered", func(t *testing.T) {
		_, err := sc.IsRegistered(mk(), "VEH_1")
		errHas(t, err, "ledger down")
	})
	t.Run("GetNetworkConfig", func(t *testing.T) {
		_, err := sc.GetNetworkConfig(mk())
		errHas(t, err, "ledger down")
	})
	t.Run("GetTrustScore", func(t *testing.T) {
		_, err := sc.GetTrustScore(mk(), "VEH_1")
		errHas(t, err, "ledger down")
	})
	t.Run("GetControllerSubmission", func(t *testing.T) {
		_, err := sc.GetControllerSubmission(mk(), "VEH_1", "E1")
		errHas(t, err, "ledger down")
	})
	t.Run("requireActive gate (SCTrustSubmitEvidence)", func(t *testing.T) {
		err := sc.SCTrustSubmitEvidence(mk(), "VEH_1", "RSU_0", "E1", "0.7", "h", "s")
		errHas(t, err, "ledger down")
	})
	t.Run("SCRevokeStatus via GetNetworkConfig", func(t *testing.T) {
		_, err := sc.SCRevokeStatus(mk(), "VEH_1")
		errHas(t, err, "ledger down")
	})
}

func TestCorruptStateUnmarshal(t *testing.T) {
	sc := SmartContract{}
	bad := []byte("{ this is not valid json")

	t.Run("REG_ (GetRegistration)", func(t *testing.T) {
		ctx, fl := newCtx()
		fl.m["REG_VEH_1"] = bad
		if _, err := sc.GetRegistration(ctx, "VEH_1"); err == nil {
			t.Fatal("expected unmarshal error on corrupt registration")
		}
	})
	t.Run("NETCFG (GetNetworkConfig)", func(t *testing.T) {
		ctx, fl := newCtx()
		fl.m["NETCFG"] = bad
		if _, err := sc.GetNetworkConfig(ctx); err == nil {
			t.Fatal("expected unmarshal error on corrupt netcfg")
		}
	})
	t.Run("SCTRUST_ (GetTrustScore)", func(t *testing.T) {
		ctx, fl := newCtx()
		fl.m["SCTRUST_VEH_1"] = bad
		if _, err := sc.GetTrustScore(ctx, "VEH_1"); err == nil {
			t.Fatal("expected unmarshal error on corrupt trust score")
		}
	})
	t.Run("CSUBM_ (GetControllerSubmission)", func(t *testing.T) {
		ctx, fl := newCtx()
		fl.m["CSUBM_VEH_1_E1"] = bad
		if _, err := sc.GetControllerSubmission(ctx, "VEH_1", "E1"); err == nil {
			t.Fatal("expected unmarshal error on corrupt controller submission")
		}
	})
	t.Run("CSUBM_ (CPDetectCheck)", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		fl.m["CSUBM_VEH_1_E1"] = bad
		if _, err := sc.CPDetectCheck(ctx, "VEH_1", "E1"); err == nil {
			t.Fatal("expected unmarshal error on corrupt CSUBM in CP-DETECT")
		}
	})
}

func TestPutStateErrorsPropagate(t *testing.T) {
	sc := SmartContract{}
	_, pk := genID(t)
	failPut := func(ctx *mocks.TransactionContext) {
		stubOf(ctx).PutStateStub = func(string, []byte) error {
			return fmt.Errorf("commit refused")
		}
	}

	t.Run("SCInitNetworkConfig", func(t *testing.T) {
		ctx, _ := newCtx()
		failPut(ctx)
		errHas(t, sc.SCInitNetworkConfig(ctx, "4", "0.3", "0.5", "0.3", "3", "0.5"), "commit refused")
	})
	t.Run("SCBootstrapRSU", func(t *testing.T) {
		ctx, _ := newCtx()
		failPut(ctx)
		errHas(t, sc.SCBootstrapRSU(ctx, "RSU_0", pk, hku64, "t0"), "commit refused")
	})
	t.Run("SCRegister", func(t *testing.T) {
		ctx, fl := newCtx()
		seedNetCfg(fl, 4, 0.3, 0.5, 0.3, 3, 0.5)
		_, vehPk := genID(t)
		endorsers := buildEndorsers(t, fl, "VEH_1", vehPk, 3)
		failPut(ctx)
		errHas(t, sc.SCRegister(ctx, "VEH_1", RoleVehicle, vehPk, hku64, "t0", endorsers), "commit refused")
	})
	t.Run("SCTrustSubmitEvidence", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		rsuPriv := seedRegKeyed(t, fl, "RSU_0", RoleRSU)
		sig := signHex(t, rsuPriv, evidenceDigest("VEH_1", "RSU_0", "E1", "0.7", "h"))
		failPut(ctx) // sig must pass so PutState is reached
		errHas(t, sc.SCTrustSubmitEvidence(ctx, "VEH_1", "RSU_0", "E1", "0.7", "h", sig), "commit refused")
	})
	t.Run("SCControllerSubmitEvidence", func(t *testing.T) {
		ctx, fl := newCtx()
		seedReg(fl, "VEH_1", RoleVehicle, pk)
		ctrlPriv := seedRegKeyed(t, fl, "CTRL_0", RoleController)
		sig := signHex(t, ctrlPriv, controllerEvidenceDigest("VEH_1", "CTRL_0", "E1", "0.8", "h"))
		failPut(ctx)
		errHas(t, sc.SCControllerSubmitEvidence(ctx, "VEH_1", "CTRL_0", "E1", "0.8", "h", sig), "commit refused")
	})
}

func TestRangeQueryErrorsPropagate(t *testing.T) {
	sc := SmartContract{}
	failRange := func(ctx *mocks.TransactionContext) {
		stubOf(ctx).GetStateByRangeStub = func(string, string) (shim.StateQueryIteratorInterface, error) {
			return nil, fmt.Errorf("range failed")
		}
	}

	t.Run("GetAllRegistrations", func(t *testing.T) {
		ctx, _ := newCtx()
		failRange(ctx)
		_, err := sc.GetAllRegistrations(ctx)
		errHas(t, err, "range failed")
	})
	t.Run("GetAllTrustScores", func(t *testing.T) {
		ctx, _ := newCtx()
		failRange(ctx)
		_, err := sc.GetAllTrustScores(ctx)
		errHas(t, err, "range failed")
	})
	t.Run("GetAllRevokeRecords", func(t *testing.T) {
		ctx, _ := newCtx()
		failRange(ctx)
		_, err := sc.GetAllRevokeRecords(ctx)
		errHas(t, err, "range failed")
	})
	t.Run("GetAllControllerFlags", func(t *testing.T) {
		ctx, _ := newCtx()
		failRange(ctx)
		_, err := sc.GetAllControllerFlags(ctx)
		errHas(t, err, "range failed")
	})
	t.Run("GetEpochSubmissions", func(t *testing.T) {
		ctx, _ := newCtx()
		failRange(ctx)
		_, err := sc.GetEpochSubmissions(ctx, "VEH_1", "E1")
		errHas(t, err, "range failed")
	})
	t.Run("GetRevokeVotes", func(t *testing.T) {
		ctx, _ := newCtx()
		failRange(ctx)
		_, err := sc.GetRevokeVotes(ctx, "VEH_1")
		errHas(t, err, "range failed")
	})
	t.Run("IsRevoked", func(t *testing.T) {
		ctx, _ := newCtx()
		failRange(ctx)
		_, err := sc.IsRevoked(ctx, "VEH_1")
		errHas(t, err, "range failed")
	})
}

func TestIteratorNextErrorPropagates(t *testing.T) {
	sc := SmartContract{}
	ctx, _ := newCtx()
	stubOf(ctx).GetStateByRangeStub = func(string, string) (shim.StateQueryIteratorInterface, error) {
		it := &mocks.StateQueryIterator{}
		it.HasNextReturns(true)
		it.NextReturns(nil, fmt.Errorf("iterator broke"))
		it.CloseReturns(nil)
		return it, nil
	}
	_, err := sc.GetAllRegistrations(ctx)
	errHas(t, err, "iterator broke")
}
