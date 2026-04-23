package ledger

import (
	"encoding/json"
	"testing"
)

// D10: a clean chain verifies, and tampering with any entry breaks it.
func TestHashChainDetectsTampering(t *testing.T) {
	l := New()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(l.Append("command", map[string]string{"cmd": "npm install"}))
	must(l.Append("egress", map[string]any{"host": "registry.npmjs.org", "allowed": true}))
	must(l.Append("file-write", map[string]string{"path": "package-lock.json"}))

	if err := l.Verify(); err != nil {
		t.Fatalf("clean chain failed to verify: %v", err)
	}

	// Tamper with a past payload without recomputing hashes - the exact thing a
	// receipt-forger would try. Verification must catch it.
	l.entries[1].Payload = json.RawMessage(`{"host":"evil.com","allowed":true}`)
	if err := l.Verify(); err == nil {
		t.Fatal("tampered payload verified OK; hash chain is not tamper-evident (A1 broken)")
	}
}

// A broken PrevHash link is caught too.
func TestBrokenLinkDetected(t *testing.T) {
	l := New()
	_ = l.Append("meta", map[string]string{"a": "1"})
	_ = l.Append("meta", map[string]string{"b": "2"})
	l.entries[1].PrevHash = "deadbeef"
	if err := l.Verify(); err == nil {
		t.Fatal("broken prev-hash link verified OK")
	}
}

// D11: a receipt captures the effective boundary + disposition.
func TestReceiptShape(t *testing.T) {
	r := Receipt{
		Agent:         "claude-code",
		PolicyHash:    PolicyHash([]byte("policy-bytes")),
		Backend:       "apple-container",
		AllowedEgress: []string{"api.anthropic.com"},
		EgressAllowed: 5,
		EgressDenied:  1,
		Disposition:   "destroyed",
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || r.PolicyHash == "" {
		t.Fatal("receipt did not marshal / missing policy hash")
	}
}
