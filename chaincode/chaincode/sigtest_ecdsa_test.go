//go:build ledger_ecdsa

// sigtest_ecdsa_test.go — scheme-aware test signing helpers for the ABLATION
// EC-ECDSA P-256 verifier (-tags ledger_ecdsa). Produces P-256 keypairs and
// ASN.1-DER signatures so the chaincode's verifyLedgerSig accepts them.

package chaincode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// ledgerTestKey is the opaque keypair the tests sign with under the active
// scheme. For the ECDSA ablation it is a *ecdsa.PrivateKey.
type ledgerTestKey = *ecdsa.PrivateKey

// genID returns a fresh P-256 keypair and its uncompressed 0x04‖X‖Y hex.
func genID(t *testing.T) (ledgerTestKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ok(t, err)
	raw := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	return priv, hex.EncodeToString(raw)
}

// signHex signs `digest` with the key's P-256 secret key (ASN.1-DER) as hex.
func signHex(t *testing.T, priv ledgerTestKey, digest []byte) string {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	ok(t, err)
	return hex.EncodeToString(sig)
}

// genIDStatic mirrors genID but without *testing.T, for non-asserting seeds.
func genIDStatic() (ledgerTestKey, string) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	return priv, hex.EncodeToString(raw)
}
