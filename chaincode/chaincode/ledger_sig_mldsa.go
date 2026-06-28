//go:build !ledger_ecdsa

// ledger_sig_mldsa.go — DEFAULT application-payload signature verifier.
//
// Verifies the on-chain signatures the contract checks (SC-Register
// endorsements, σ_j^sub RSU evidence Eq 3.61, σ_c^sub controller evidence
// Eq 3.62, revoke votes Eq 3.63) using ML-DSA-87 (CRYSTALS-Dilithium5,
// FIPS 204, NIST Level 5) via Cloudflare circl.
//
// This is the post-quantum half of the NS-3 ↔ Fabric application payload. The
// NS-3 signer (scratch/.../11_blockchain_setup.h) signs the SAME 32-byte
// canonical digest with liboqs OQS_SIG ML-DSA-87, which uses the FIPS 204 pure
// variant with an EMPTY context string — so Verify here is called with a nil
// context to match. A mismatch (e.g. signer built -DMPTD_LEDGER_SIG_ECDSA while
// this verifier is active) makes every signature fail.
//
// SCOPE: this upgrades only the application payload we control. Fabric's own
// MSP transaction signing, peer/client TLS and Raft ordering remain classical
// ECDSA (BCCSP). Accurate claim: "post-quantum (Level 5) on the application
// payload; classical at the Fabric platform layer."
//
// Build the ECDSA-P256 ablation instead with: -tags ledger_ecdsa (must match
// the NS-3 signer's -DMPTD_LEDGER_SIG_ECDSA).

package chaincode

import (
	"encoding/hex"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// validateLedgerPubKey checks that pkHex decodes to a well-formed ML-DSA-87
// public key (PublicKeySize bytes that unpack successfully). Used at
// registration to reject malformed PkHex before it is stored on chain.
func validateLedgerPubKey(pkHex string) error {
	raw, err := hex.DecodeString(pkHex)
	if err != nil {
		return fmt.Errorf("pk hex decode: %v", err)
	}
	if len(raw) != mldsa87.PublicKeySize {
		return fmt.Errorf("pk must be %d-byte ML-DSA-87 public key (got %d bytes)",
			mldsa87.PublicKeySize, len(raw))
	}
	var pub mldsa87.PublicKey
	if err := pub.UnmarshalBinary(raw); err != nil {
		return fmt.Errorf("pk unpack: %v", err)
	}
	return nil
}

// verifyLedgerSig verifies an ML-DSA-87 signature over `digest` using the
// public key in `pkHex`. Returns true on success, false on any failure
// (decode, unpack, wrong size, signature mismatch). The context is nil to
// match the liboqs signer's empty FIPS 204 context.
func verifyLedgerSig(pkHex, sigHex string, digest []byte) bool {
	rawPK, err := hex.DecodeString(pkHex)
	if err != nil || len(rawPK) != mldsa87.PublicKeySize {
		return false
	}
	var pub mldsa87.PublicKey
	if err := pub.UnmarshalBinary(rawPK); err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != mldsa87.SignatureSize {
		return false
	}
	return mldsa87.Verify(&pub, digest, nil, sig)
}
