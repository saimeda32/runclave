package broker

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// End to end over a real unix socket: the in-box Query relays a git `get`, the
// daemon mints for the SESSION repo, and the caller gets username+password back.
func TestServeQueryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "broker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	m := &stubMinter{}
	sess := &Session{ID: "s1", Repo: "github.com/owner/name", Minter: m}
	go Serve(l, sess)

	// git sends attribute lines then a blank line; the box shim forwards them.
	in := strings.NewReader("protocol=https\nhost=github.com\npath=owner/name.git\n\n")
	var out strings.Builder
	if err := Query(sock, "get", in, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "username=x-access-token") || !strings.Contains(got, "password=ghs_stub_token_for_") {
		t.Fatalf("expected minted credential in response, got %q", got)
	}
	if !strings.Contains(got, "password_expiry_utc=") {
		t.Fatalf("response must carry an expiry so git rotates, got %q", got)
	}
	// Authz must have used the SESSION repo, not anything the client claimed.
	if m.lastRepo != "github.com/owner/name" {
		t.Fatalf("minted for %q, want the session repo", m.lastRepo)
	}
}

// A box that claims a DIFFERENT repo still gets creds only for the session repo,
// and the mismatch is recorded. The daemon never trusts box-supplied identity.
func TestServeIgnoresBoxClaimedRepo(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "b.sock")
	l, _ := net.Listen("unix", sock)
	defer l.Close()
	m := &stubMinter{}
	sess := &Session{ID: "s", Repo: "github.com/owner/real", Minter: m}
	go Serve(l, sess)

	in := strings.NewReader("protocol=https\nhost=github.com\npath=attacker/evil.git\n\n")
	var out strings.Builder
	if err := Query(sock, "get", in, &out); err != nil {
		t.Fatal(err)
	}
	if m.lastRepo != "github.com/owner/real" {
		t.Fatalf("authz leaked to box-claimed repo: minted for %q", m.lastRepo)
	}
	if len(sess.Anomalies) == 0 {
		t.Fatal("a repo mismatch must be recorded as an anomaly")
	}
}

// A mismatch must be surfaced LIVE via LogAnomaly (the daemon logs it), not just
// buried in the Anomalies slice.
func TestAnomalyIsLoggedLive(t *testing.T) {
	var logged []string
	s := &Session{ID: "s", Repo: "github.com/owner/real", Minter: &stubMinter{},
		LogAnomaly: func(m string) { logged = append(logged, m) }}
	_, err := s.Handle(Request{Op: "get", Attrs: map[string]string{
		"protocol": "https", "host": "github.com", "path": "attacker/evil.git"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "attacker/evil") {
		t.Fatalf("mismatch must be logged live, got %v", logged)
	}
}
