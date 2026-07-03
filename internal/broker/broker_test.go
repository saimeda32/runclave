package broker

import (
	"strings"
	"testing"
)

// stubMinter records the repo it was asked to mint for.
type stubMinter struct{ lastRepo string }

func (m *stubMinter) Mint(repo string) (string, string, int64, error) {
	m.lastRepo = repo
	return "x-access-token", "ghs_stub_token_for_" + repo, 1_700_003_600, nil
}

// The load-bearing property (S8): the broker mints for the SESSION's repo and
// ignores the box-claimed host/path. A box asking for a DIFFERENT repo still only
// gets the session repo's creds, and the minter is called with the session repo.
func TestAuthzIgnoresBoxClaimedRepo(t *testing.T) {
	m := &stubMinter{}
	s := &Session{ID: "s1", Repo: "github.com/owner/blessed", Minter: m}

	// Box lies: claims it wants creds for an attacker repo.
	req := Request{Op: "get", Attrs: map[string]string{
		"protocol": "https", "host": "github.com", "path": "attacker/evil.git",
	}}
	resp, err := s.Handle(req)
	if err != nil {
		t.Fatal(err)
	}
	// Minter must have been called for the SESSION repo, not the box-claimed one.
	if m.lastRepo != "github.com/owner/blessed" {
		t.Fatalf("minter called for %q; must be the session repo (authz bypass!)", m.lastRepo)
	}
	// Response token must be for the session repo.
	if !strings.Contains(resp, "blessed") || strings.Contains(resp, "evil") {
		t.Fatalf("response leaked creds for the wrong repo: %s", resp)
	}
	// The mismatch must be recorded as an anomaly.
	if len(s.Anomalies) != 1 {
		t.Fatalf("expected 1 anomaly for the repo mismatch, got %v", s.Anomalies)
	}
	// Response must carry username, password, and expiry (native rotation).
	for _, want := range []string{"username=x-access-token", "password=ghs_stub", "password_expiry_utc="} {
		if !strings.Contains(resp, want) {
			t.Fatalf("response missing %q: %s", want, resp)
		}
	}
}

// store/erase are no-ops (ephemeral creds).
func TestStoreEraseNoOp(t *testing.T) {
	s := &Session{ID: "s", Repo: "github.com/o/r", Minter: &stubMinter{}}
	for _, op := range []string{"store", "erase"} {
		out, err := s.Handle(Request{Op: op, Attrs: map[string]string{"host": "github.com"}})
		if err != nil || out != "" {
			t.Fatalf("%s should be a silent no-op, got out=%q err=%v", op, out, err)
		}
	}
}

// Fail-closed: an unscoped session (no repo / no minter) refuses to mint.
func TestUnscopedSessionFailsClosed(t *testing.T) {
	if _, err := (&Session{ID: "s", Minter: &stubMinter{}}).Handle(Request{Op: "get"}); err == nil {
		t.Fatal("session with no repo must fail-closed on get")
	}
	if _, err := (&Session{ID: "s", Repo: "github.com/o/r"}).Handle(Request{Op: "get"}); err == nil {
		t.Fatal("session with no minter must fail-closed on get")
	}
}

// Critic fixes: minter output with control chars is refused (response-injection
// defense); a non-expiring token is refused; anomaly logged even without host.
type evilMinter struct {
	user, token string
	exp         int64
}

func (m evilMinter) Mint(repo string) (string, string, int64, error) {
	return m.user, m.token, m.exp, nil
}

func TestMinterOutputSanitized(t *testing.T) {
	// A token containing a newline that would inject password_expiry_utc=0.
	s := &Session{ID: "s", Repo: "github.com/o/r", Minter: evilMinter{"x", "tok\npassword_expiry_utc=0", 1_700_000_000}}
	if _, err := s.Handle(Request{Op: "get", Attrs: map[string]string{"host": "github.com"}}); err == nil {
		t.Fatal("minter output with a newline must be refused (response injection)")
	}
	// A non-expiring token must be refused.
	s2 := &Session{ID: "s", Repo: "github.com/o/r", Minter: evilMinter{"x", "tok", 0}}
	if _, err := s2.Handle(Request{Op: "get", Attrs: map[string]string{"host": "github.com"}}); err == nil {
		t.Fatal("non-expiring token must be refused")
	}
}

func TestAnomalyLoggedWhenHostOmitted(t *testing.T) {
	s := &Session{ID: "s", Repo: "github.com/o/r", Minter: &stubMinter{}}
	// Box omits host entirely to try to evade the anomaly trail.
	_, err := s.Handle(Request{Op: "get", Attrs: map[string]string{"protocol": "https"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Anomalies) != 1 {
		t.Fatalf("host-omission must still be recorded as an anomaly, got %v", s.Anomalies)
	}
}

// A key containing a control char is rejected (not just values).
func TestParseRejectsControlCharInKey(t *testing.T) {
	if _, err := ParseRequest("get", strings.NewReader("ho\x00st=github.com\n\n")); err == nil {
		t.Fatal("control char in a KEY must be rejected")
	}
}

// Request parsing rejects control-char smuggling (S7 / Clone2Leak class).
func TestParseRejectsControlChars(t *testing.T) {
	_, err := ParseRequest("get", strings.NewReader("protocol=https\nhost=github.com\rmalicious=1\n\n"))
	if err == nil {
		t.Fatal("CR in a credential attribute must be rejected")
	}
	// A clean request parses.
	req, err := ParseRequest("get", strings.NewReader("protocol=https\nhost=github.com\npath=o/r.git\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	if req.Attrs["host"] != "github.com" || req.Attrs["path"] != "o/r.git" {
		t.Fatalf("parsed attrs wrong: %v", req.Attrs)
	}
}
