//go:build !ledger_ecdsa

// sigtest_mldsa_test.go — scheme-aware test signing helpers for the DEFAULT
// ML-DSA-87 verifier. Produces ML-DSA-87 keypairs and signatures (FIPS 204
// pure, empty context) so the chaincode's verifyLedgerSig accepts them — a
// circl↔circl round-trip mirroring the NS-3 liboqs signer ↔ chaincode path.

package chaincode

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// ledgerTestKey is the opaque keypair the tests sign with under the active
// scheme. For ML-DSA-87 it wraps the circl public/private key pair.
type ledgerTestKey struct {
	pub  *mldsa87.PublicKey
	priv *mldsa87.PrivateKey
}

// genID returns a fresh ML-DSA-87 keypair and its public key as hex (the value
// registered on chain as PkHex).
func genID(t *testing.T) (ledgerTestKey, string) {
	t.Helper()
	pub, priv, err := mldsa87.GenerateKey(rand.Reader)
	ok(t, err)
	return ledgerTestKey{pub: pub, priv: priv}, hex.EncodeToString(pub.Bytes())
}

// signHex signs `digest` with the key's ML-DSA-87 secret key (empty context,
// matching the liboqs signer) and returns the signature as hex.
func signHex(t *testing.T, k ledgerTestKey, digest []byte) string {
	t.Helper()
	sig := make([]byte, mldsa87.SignatureSize)
	err := mldsa87.SignTo(k.priv, digest, nil /*ctx*/, false /*randomized*/, sig)
	ok(t, err)
	return hex.EncodeToString(sig)
}

// genIDStatic mirrors genID but without *testing.T, for non-asserting seeds.
func genIDStatic() (ledgerTestKey, string) {
	pub, priv, _ := mldsa87.GenerateKey(rand.Reader)
	return ledgerTestKey{pub: pub, priv: priv}, hex.EncodeToString(pub.Bytes())
}
