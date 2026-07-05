package ledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// A signed receipt round-trips: verify returns the same receipt and the signer id.
func TestSignVerifyRoundTrip(t *testing.T) {
	_, priv := testKey(t)
	r := Receipt{Agent: "claude-code", Disposition: "persisted", Image: "runclave/claude-code:latest", EgressAllowed: 3, EgressDenied: 1}
	env, err := SignReceipt(r, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyEnvelope(env)
	if err != nil {
		t.Fatalf("valid envelope must verify: %v", err)
	}
	if got.Agent != r.Agent || got.Disposition != r.Disposition || got.EgressDenied != 1 {
		t.Fatalf("verified receipt mismatch: %+v", got)
	}
	if env.KeyID != KeyFingerprint(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("keyid must be the signer's fingerprint")
	}
}

// ANY tamper with the payload must fail verification (the whole point).
func TestTamperedPayloadRejected(t *testing.T) {
	_, priv := testKey(t)
	env, _ := SignReceipt(Receipt{Agent: "a", Disposition: "persisted"}, priv)
	// Flip a byte in the receipt JSON payload.
	env.Payload[len(env.Payload)/2] ^= 0xff
	if _, err := VerifyEnvelope(env); err == nil {
		t.Fatal("a tampered payload must not verify")
	}
}

// Swapping in an attacker's key: if they replace only the public key, the keyid no
// longer matches; if they replace key + keyid, the original signature no longer
// verifies under the new key. Either way, fail-closed.
func TestKeySubstitutionRejected(t *testing.T) {
	_, priv := testKey(t)
	env, _ := SignReceipt(Receipt{Agent: "a", Disposition: "persisted"}, priv)

	attackerPub, _ := testKey(t)
	// Replace public key only -> keyid mismatch.
	e1 := env
	e1.PublicKey = attackerPub
	if _, err := VerifyEnvelope(e1); err == nil {
		t.Fatal("public-key swap (keyid mismatch) must fail")
	}
	// Replace key AND keyid, keep the original signature -> signature fails.
	e2 := env
	e2.PublicKey = attackerPub
	e2.KeyID = KeyFingerprint(attackerPub)
	if _, err := VerifyEnvelope(e2); err == nil {
		t.Fatal("key+keyid swap must still fail (sig was over the original key)")
	}
}

// The payload type is bound into the signature, so a forged type is rejected.
func TestPayloadTypeBound(t *testing.T) {
	_, priv := testKey(t)
	env, _ := SignReceipt(Receipt{Agent: "a", Disposition: "persisted"}, priv)
	env.PayloadType = "application/vnd.attacker+json"
	if _, err := VerifyEnvelope(env); err == nil {
		t.Fatal("a changed payload type must fail")
	}
}

// Malformed keys/signatures fail closed rather than panicking or passing.
func TestMalformedInputsFailClosed(t *testing.T) {
	_, priv := testKey(t)
	env, _ := SignReceipt(Receipt{Agent: "a", Disposition: "persisted"}, priv)
	bad := env
	bad.Sig = []byte("too short")
	if _, err := VerifyEnvelope(bad); err == nil {
		t.Fatal("short signature must fail")
	}
	bad2 := env
	bad2.PublicKey = []byte{1, 2, 3}
	if _, err := VerifyEnvelope(bad2); err == nil {
		t.Fatal("short public key must fail")
	}
}
