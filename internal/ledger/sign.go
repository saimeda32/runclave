package ledger

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// ReceiptPayloadType binds a signature to "this is a runclave receipt" so a
// signature over one kind of blob can never be replayed as another (DSSE's whole
// point).
const ReceiptPayloadType = "application/vnd.runclave.receipt+json"

// pae is the DSSE Pre-Authentication Encoding: DSSEv1 SP len(type) SP type SP
// len(payload) SP payload, with lengths in ASCII decimal. Signing the PAE (not the
// raw payload) is what makes the payload-type binding tamper-proof.
func pae(payloadType string, payload []byte) []byte {
	return []byte("DSSEv1 " +
		strconv.Itoa(len(payloadType)) + " " + payloadType + " " +
		strconv.Itoa(len(payload)) + " " + string(payload))
}

// Envelope is a DSSE-style signed receipt: the receipt JSON as the payload, one
// Ed25519 signature over its PAE, and the public key that made it. It is
// self-describing on purpose, so `runclave verify` needs no key server or network:
// verification proves the receipt is intact and was signed by the holder of that
// key. Whether to TRUST that key (its fingerprint) is a separate, human decision.
type Envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     []byte `json:"payload"`   // the receipt JSON (base64-encoded in the file)
	KeyID       string `json:"keyid"`     // sha256 fingerprint of PublicKey
	PublicKey   []byte `json:"publicKey"` // the Ed25519 public key (base64 in the file)
	Sig         []byte `json:"sig"`       // Ed25519 signature over pae(payloadType, payload)
}

// KeyFingerprint is a short, stable id for a public key (what a user compares to
// confirm "this is my machine's key").
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:])[:32]
}

// SignReceipt marshals the receipt and signs its PAE with priv, returning a
// self-describing envelope.
func SignReceipt(r Receipt, priv ed25519.PrivateKey) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("ledger: bad private key size")
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return Envelope{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return Envelope{
		PayloadType: ReceiptPayloadType,
		Payload:     payload,
		KeyID:       KeyFingerprint(pub),
		PublicKey:   pub,
		Sig:         ed25519.Sign(priv, pae(ReceiptPayloadType, payload)),
	}, nil
}

// VerifyEnvelope checks the signature against the embedded public key and returns
// the receipt. Fail-closed: a tampered payload/type, a bad or wrong-sized key or
// signature, or a keyid that doesn't match the public key all return an error and
// never a receipt. It proves integrity + who signed; deciding whether to trust that
// signer is the caller's job.
func VerifyEnvelope(e Envelope) (Receipt, error) {
	if len(e.PublicKey) != ed25519.PublicKeySize {
		return Receipt{}, fmt.Errorf("ledger: bad public key size")
	}
	if len(e.Sig) != ed25519.SignatureSize {
		return Receipt{}, fmt.Errorf("ledger: bad signature size")
	}
	if e.PayloadType != ReceiptPayloadType {
		return Receipt{}, fmt.Errorf("ledger: unexpected payload type %q", e.PayloadType)
	}
	if e.KeyID != KeyFingerprint(e.PublicKey) {
		return Receipt{}, fmt.Errorf("ledger: keyid does not match the public key")
	}
	if !ed25519.Verify(e.PublicKey, pae(e.PayloadType, e.Payload), e.Sig) {
		return Receipt{}, fmt.Errorf("ledger: signature check failed (receipt tampered or wrong key)")
	}
	var r Receipt
	if err := json.Unmarshal(e.Payload, &r); err != nil {
		return Receipt{}, fmt.Errorf("ledger: envelope payload is not a receipt: %w", err)
	}
	return r, nil
}
