// Package broker is the host-side secret broker skeleton.
// It answers git credential-helper requests coming from INSIDE a box over a
// per-session unix socket, minting short-lived creds scoped to ONLY the repo the
// session was created for. The raw long-lived secret (GitHub App key) never
// enters the box.
//
// The load-bearing security property (S8): authorization is HOST-SIDE. The
// broker mints for the session's recorded repo and IGNORES the host/path the box
// supplies in the request - a compromised box cannot ask for creds to a
// different repo, because box-supplied identity is never consulted for authz.
package broker

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// TokenMinter mints a short-lived credential for a repo. Production = a GitHub
// App installation token (1h, repo+permission scoped); the App private key stays
// with the minter, never in the box. Stubbed in tests.
type TokenMinter interface {
	// Mint returns (username, token, expiryUnix) for exactly the given repo.
	Mint(repo string) (username, token string, expiryUnix int64, err error)
}

// Session binds one per-session socket to one repo scope + a minter.
type Session struct {
	ID     string
	Repo   string // the ONLY repo this session may obtain creds for, e.g. "github.com/owner/name"
	Minter TokenMinter
	// Anomalies records box-claimed host/path that didn't match Repo (logged, not trusted).
	Anomalies []string
}

// Request is a parsed git credential-helper request. Op is get|store|erase.
type Request struct {
	Op    string
	Attrs map[string]string
}

// ParseRequest reads the key=value\n lines git sends on stdin (terminated by a
// blank line or EOF) for the given op.
func ParseRequest(op string, r io.Reader) (Request, error) {
	req := Request{Op: op, Attrs: map[string]string{}}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return req, fmt.Errorf("broker: malformed credential line %q", line)
		}
		// Reject control chars in BOTH key and value (CR/LF/NUL smuggling -
		// Clone2Leak class, S7). Critic: value-only was narrower than the claim.
		if strings.ContainsAny(k, "\x00\r\n") || strings.ContainsAny(v, "\x00\r\n") {
			return req, fmt.Errorf("broker: control char in credential attribute %q", k)
		}
		req.Attrs[k] = v
	}
	return req, sc.Err()
}

// Handle processes a request and returns the response bytes git expects on
// stdout. For "get" it mints creds for the SESSION's repo (never the box-claimed
// one). For "store"/"erase" it is a no-op (tokens are ephemeral, criterion S8).
func (s *Session) Handle(req Request) (string, error) {
	switch req.Op {
	case "store", "erase":
		return "", nil // ephemeral creds: nothing to persist or revoke box-side
	case "get":
		if s.Repo == "" || s.Minter == nil {
			return "", fmt.Errorf("broker: session not scoped (no repo/minter); refusing (fail-closed)")
		}
		// Record - but do NOT trust - box-claimed identity. Authz uses s.Repo only.
		// Log ANY mismatch including a missing host (a box could otherwise evade the
		// anomaly trail by omitting host; treat empty-claimed as a mismatch to note).
		claimed := boxClaimedRepo(req.Attrs)
		if claimed != s.Repo {
			shown := claimed
			if shown == "" {
				shown = "(no host supplied)"
			}
			s.Anomalies = append(s.Anomalies,
				fmt.Sprintf("box asked for %q; minting for session repo %q", shown, s.Repo))
		}
		user, token, exp, err := s.Minter.Mint(s.Repo)
		if err != nil {
			return "", fmt.Errorf("broker: mint failed: %w", err)
		}
		// The broker REQUIRES short-lived creds: a non-expiring token would be
		// cached indefinitely inside the box, defeating rotation. Fail-closed.
		if exp <= 0 {
			return "", fmt.Errorf("broker: minter returned a non-expiring token; refusing")
		}
		// Defense-in-depth: never write minter output that could inject extra
		// response lines (a \n in user/token could smuggle a second key git parses).
		if strings.ContainsAny(user, "\x00\r\n") || strings.ContainsAny(token, "\x00\r\n") {
			return "", fmt.Errorf("broker: minter returned a credential with control chars; refusing")
		}
		var b strings.Builder
		fmt.Fprintf(&b, "username=%s\n", user)
		fmt.Fprintf(&b, "password=%s\n", token)
		// Git ignores an expired password on fill and re-asks -> native rotation.
		fmt.Fprintf(&b, "password_expiry_utc=%s\n", strconv.FormatInt(exp, 10))
		b.WriteString("\n")
		return b.String(), nil
	default:
		return "", fmt.Errorf("broker: unknown op %q", req.Op)
	}
}

// boxClaimedRepo reconstructs "host/path" from the box-supplied attributes (for
// anomaly logging only - never for authorization).
func boxClaimedRepo(attrs map[string]string) string {
	host := attrs["host"]
	if host == "" {
		return ""
	}
	p := strings.TrimSuffix(strings.TrimPrefix(attrs["path"], "/"), ".git")
	if p == "" {
		return host
	}
	return host + "/" + p
}
