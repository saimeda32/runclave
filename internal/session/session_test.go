package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saimeda/runclave/internal/backend"
	"github.com/saimeda/runclave/internal/policy"
)

// fakeDriver lets us test the session without a real container backend.
type fakeDriver struct{}

func (fakeDriver) Name() string                    { return "fake" }
func (fakeDriver) Strength() backend.Strength      { return backend.StrengthContainer }
func (fakeDriver) Available() bool                 { return true }
func (fakeDriver) CreateArgs(n, i string) []string { return []string{"fake", "run", n, i} }

func testPack() *policy.Pack {
	p := &policy.Pack{Agent: "test", Scope: "local", Type: "cli-headless"}
	p.Run.Command = "test"
	p.Egress.Model = []string{"api.anthropic.com"}
	return p
}

// D11 (real, not vacuous): a session that records egress decisions produces a
// receipt whose counts are WIRED from the proxy, plus a verifiable ledger.
func TestSessionProducesReceiptWithWiredCounts(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0)
	sess, err := Start(testPack(), fakeDriver{}, Options{
		RawPolicy:   []byte("agent: test"),
		ListenProxy: false, // no real port needed to test the receipt path
		Clock:       func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}

	// Drive real decisions through the same code path ServeHTTP uses.
	if !sess.Proxy.Decide("api.anthropic.com:443") {
		t.Fatal("allowlisted host was denied")
	}
	if sess.Proxy.Decide("evil.com:443") {
		t.Fatal("non-allowlisted host was allowed")
	}
	if sess.Proxy.Decide("exfil.example.com:443") {
		t.Fatal("non-allowlisted host was allowed")
	}

	dir := t.TempDir()
	receiptPath := filepath.Join(dir, "receipt.json")
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	r, err := sess.Finish("destroyed", receiptPath, ledgerPath, 3)
	if err != nil {
		t.Fatal(err)
	}

	// The receipt's egress counts must reflect the actual decisions (1 allow, 2 deny),
	// not test-supplied literals - this is what makes the test non-vacuous.
	if r.EgressAllowed != 1 {
		t.Fatalf("receipt egress_allowed=%d want 1", r.EgressAllowed)
	}
	if r.EgressDenied != 2 {
		t.Fatalf("receipt egress_denied=%d want 2", r.EgressDenied)
	}
	if r.Disposition != "destroyed" || r.FilesChanged != 3 {
		t.Fatalf("receipt disposition/files wrong: %+v", r)
	}
	if r.PolicyHash == "" || r.LedgerHead == "" {
		t.Fatal("receipt missing policy hash or ledger head")
	}

	// The receipt file must actually be written and parse back.
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("receipt not valid JSON: %v", err)
	}

	// The ledger must record every egress decision + meta and verify intact.
	if err := sess.Ledger.Verify(); err != nil {
		t.Fatalf("ledger verify failed: %v", err)
	}
	// meta-start + 3 egress + meta-finish = 5 entries.
	if sess.Ledger.Len() != 5 {
		t.Fatalf("ledger has %d entries, want 5", sess.Ledger.Len())
	}
}
