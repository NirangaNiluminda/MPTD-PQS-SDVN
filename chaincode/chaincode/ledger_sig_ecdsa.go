//go:build ledger_ecdsa

// ledger_sig_ecdsa.go — ABLATION application-payload signature verifier.
//
// Classical EC-ECDSA P-256 (ASN.1-DER) verification of the on-chain signatures
// the contract checks. This is the pre-PQ baseline retained for the RQ5
// overhead comparison; the default verifier is ML-DSA-87 (ledger_sig_mldsa.go).
//
// Build this variant with: -tags ledger_ecdsa. It MUST be paired with the NS-3
// signer built -DMPTD_LEDGER_SIG_ECDSA — a scheme mismatch makes every
// signature fail verification.

package chaincode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
)

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

// validateLedgerPubKey checks that pkHex is a well-formed P-256 public key.
func validateLedgerPubKey(pkHex string) error {
	_, err := parseP256PubKey(pkHex)
	return err
}

// verifyLedgerSig verifies an ASN.1-DER ECDSA signature over `digest` using
// the public key in `pkHex`. Returns true on success, false on any failure
// (decode, parse, signature mismatch). Mirrors crypto/ecdsa.VerifyASN1.
func verifyLedgerSig(pkHex, sigHex string, digest []byte) bool {
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
