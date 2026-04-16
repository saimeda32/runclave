package egress

import "testing"

// D7 default-deny + D6 fail-closed: an empty allowlist blocks everything.
func TestEmptyAllowlistBlocksAll(t *testing.T) {
	p := New(nil, nil)
	for _, host := range []string{"api.anthropic.com", "example.com", "localhost"} {
		if p.Allowed(host) {
			t.Fatalf("empty allowlist allowed %q; must be default-deny (C6)", host)
		}
	}
}

// D8: an exact host on the allowlist is permitted; others are not.
func TestExactAllow(t *testing.T) {
	p := New([]string{"api.anthropic.com"}, nil)
	if !p.Allowed("api.anthropic.com") {
		t.Fatal("allowlisted host was denied")
	}
	if !p.Allowed("api.anthropic.com:443") {
		t.Fatal("allowlisted host:port was denied")
	}
	if p.Allowed("evil.com") {
		t.Fatal("non-allowlisted host was allowed")
	}
}

// Explicit "*" = allow-all (user's intentional choice), surfaced via AllowsEverything
// so it can be warned/recorded - but a malformed/smuggled host is STILL rejected.
func TestExplicitAllowAll(t *testing.T) {
	p := New([]string{"*"}, nil)
	if !p.AllowsEverything() {
		t.Fatal("a bare '*' entry must put the proxy in allow-all mode")
	}
	for _, host := range []string{"anything.example", "evil.com", "1.2.3.4:443"} {
		if !p.Allowed(host) {
			t.Fatalf("allow-all must permit %q", host)
		}
	}
	if p.Allowed("good.com\x00.evil.com") {
		t.Fatal("allow-all must still reject a control-char-smuggled host (E8)")
	}
	if New([]string{"api.anthropic.com"}, nil).AllowsEverything() {
		t.Fatal("a normal allowlist must not be allow-all")
	}
}

// Wildcard suffix entries match subdomains but not the bare parent tricks.
func TestWildcardSuffix(t *testing.T) {
	p := New([]string{"*.githubcopilot.com"}, nil)
	if !p.Allowed("api.githubcopilot.com") {
		t.Fatal("subdomain of wildcard was denied")
	}
	if p.Allowed("githubcopilotXcom") {
		t.Fatal("lookalike host matched wildcard")
	}
	if p.Allowed("evil-githubcopilot.com") {
		t.Fatal("suffix confusion: evil-githubcopilot.com must not match *.githubcopilot.com")
	}
}

// D9 (E8): hostnames with null bytes / control chars are rejected before the
// allowlist match, defeating the SOCKS5 null-byte smuggling class.
func TestNullByteHostnameRejected(t *testing.T) {
	p := New([]string{"good.com"}, nil)
	cases := []string{
		"good.com\x00.evil.com", // classic null-byte smuggle
		"good.com\r\n.evil.com", // CR-LF injection
		"good.com\t",            // tab
		"good.com .evil.com",    // space
	}
	for _, h := range cases {
		if p.Allowed(h) {
			t.Fatalf("hostname %q with control/space chars was allowed (E8 broken)", h)
		}
	}
}

// Decision counters feed the run receipt (A3).
func TestCounters(t *testing.T) {
	p := New([]string{"ok.com"}, nil)
	p.Decide("ok.com")
	p.Decide("no.com")
	p.Decide("no.com")
	if got := p.Counters.Allowed.Load(); got != 1 {
		t.Fatalf("allowed=%d want 1", got)
	}
	if got := p.Counters.Denied.Load(); got != 2 {
		t.Fatalf("denied=%d want 2", got)
	}
}
