package fleet

import (
	"crypto/ed25519"
	"testing"

	"github.com/saimeda/runclave/internal/ledger"
)

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	// Deterministic key from a fixed seed (no Date/rand needed).
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

// F-D3: a signed bundle verifies; a tampered bundle fails.
func TestBundleSignVerifyAndTamper(t *testing.T) {
	pub, priv := keypair(t)
	b := Bundle{Version: "1", PolicyHashes: []string{"aaa", "bbb"}, Payload: []byte("packs")}
	sb := Sign(b, priv)
	if err := Verify(sb, pub); err != nil {
		t.Fatalf("clean bundle failed to verify: %v", err)
	}
	// Tamper the payload without re-signing -> must fail.
	sb.Bundle.Payload = []byte("evil")
	if err := Verify(sb, pub); err == nil {
		t.Fatal("tampered bundle verified OK (F1 broken)")
	}
	// Tamper the blessed set -> must fail.
	sb2 := Sign(b, priv)
	sb2.Bundle.PolicyHashes = append(sb2.Bundle.PolicyHashes, "ccc")
	if err := Verify(sb2, pub); err == nil {
		t.Fatal("tampered policy-hash set verified OK")
	}
}

// F-D4: verify-before-load is fail-closed - wrong signer / empty key cannot load.
func TestLoadVerifiedFailClosed(t *testing.T) {
	_, priv := keypair(t)
	b := Bundle{Version: "1", PolicyHashes: []string{"aaa"}, Payload: []byte("x")}
	sb := Sign(b, priv)

	// Wrong signer key.
	wrongPub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if _, err := LoadVerified(sb, wrongPub); err == nil {
		t.Fatal("bundle loaded under the wrong signer key (F-D4 broken)")
	}
	// Empty/absent trusted key must refuse (fail-closed), not accept.
	if _, err := LoadVerified(sb, nil); err == nil {
		t.Fatal("bundle loaded with no trusted key (must fail-closed)")
	}
}

// F-D5: collector accepts a blessed+signed receipt, rejects unknown-hash and bad-sig.
func TestCollectorAcceptReject(t *testing.T) {
	pub, priv := keypair(t)
	blessed := "policyhash_blessed_000000"
	c := NewCollector([]string{blessed}, pub)

	good := SignReceipt(ledger.Receipt{Agent: "claude-code", PolicyHash: blessed, Backend: "apple-container"}, priv)
	if err := c.Collect(good); err != nil {
		t.Fatalf("blessed+signed receipt was rejected: %v", err)
	}
	// Unknown policy hash -> reject.
	unknown := SignReceipt(ledger.Receipt{Agent: "x", PolicyHash: "not_blessed", Backend: "docker"}, priv)
	if err := c.Collect(unknown); err == nil {
		t.Fatal("receipt with unblessed policy hash was accepted (F2 broken)")
	}
	// Bad signature (signed by an untrusted key) -> reject.
	badSig := SignReceipt(ledger.Receipt{Agent: "y", PolicyHash: blessed, Backend: "docker"}, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err := c.Collect(badSig); err == nil {
		t.Fatal("receipt signed by an untrusted key was accepted")
	}

	if c.Verify().Accepted != 1 {
		t.Fatalf("expected 1 accepted, got %d", c.Verify().Accepted)
	}
}

// F-D6: fleet report flags a session on a non-strong backend.
func TestFleetReportFlagsWeakBackend(t *testing.T) {
	pub, priv := keypair(t)
	blessed := "h1"
	c := NewCollector([]string{blessed}, pub)
	_ = c.Collect(SignReceipt(ledger.Receipt{Agent: "a", PolicyHash: blessed, Backend: "apple-container"}, priv))
	_ = c.Collect(SignReceipt(ledger.Receipt{Agent: "b", PolicyHash: blessed, Backend: "docker"}, priv))
	rep := c.Verify()
	if rep.Accepted != 2 {
		t.Fatalf("accepted=%d want 2", rep.Accepted)
	}
	if len(rep.WeakBackend) != 1 {
		t.Fatalf("expected 1 weak-backend flag (docker), got %v", rep.WeakBackend)
	}
}

// Domain separation (critic fix): a bundle signature must NOT validate as a
// receipt signature or vice-versa, even if fields are crafted to align.
func TestCrossTypeSignatureRejected(t *testing.T) {
	pub, priv := keypair(t)
	// Sign a bundle whose Version is "receipt" - the old pae() (no domain tag)
	// could let this cross-parse. With domain separation it must not.
	b := Bundle{Version: "receipt", PolicyHashes: []string{"x"}, Payload: []byte("y")}
	sb := Sign(b, priv)
	// The bundle signature must not verify as a receipt signature.
	forged := SignedReceipt{Receipt: ledger.Receipt{Agent: "x", PolicyHash: "x"}, Signature: sb.Signature}
	c := NewCollector([]string{"x"}, pub)
	if err := c.Collect(forged); err == nil {
		t.Fatal("a bundle signature cross-validated as a receipt (domain separation broken)")
	}
}

// F-D5 fail-closed: empty blessed set accepts nothing.
func TestEmptyBlessedSetAcceptsNothing(t *testing.T) {
	pub, priv := keypair(t)
	c := NewCollector(nil, pub)
	if err := c.Collect(SignReceipt(ledger.Receipt{Agent: "a", PolicyHash: "anything", Backend: "apple-container"}, priv)); err == nil {
		t.Fatal("empty blessed set accepted a receipt (must fail-closed)")
	}
}
