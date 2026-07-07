// Package egress is the default-deny network boundary for a sandbox. When a box
// is wired to route through it, the box's only network route is this host-side
// HTTP CONNECT proxy, and the box cannot reconfigure it (enforcement lives
// outside the agent's process - the boundary must not be a flag the agent can flip).
//
// What it actually enforces today (be precise - no overclaiming):
//   - Authorization on the CONNECT target host against a domain allowlist (E1/E3).
//   - Hostname SYNTAX validation before the allowlist match: reject null bytes,
//     control chars, CR/LF, spaces (E8, the SOCKS5 null-byte smuggling class).
//   - A blind bidirectional tunnel: it never terminates TLS or inspects bodies
//     (E5; SSL inspection breaks Cursor/Copilot/Windsurf/JetBrains), so HTTP/2
//     bidi streaming passes untouched (E6).
//
// What it does NOT yet do (documented residual,): it does
// NOT parse the TLS ClientHello, so it cannot verify SNI matches the CONNECT
// target. Domain-fronting (allowlisted CONNECT host + different inner SNI) is a
// known P1 gap, not a defended case. Do not claim SNI-level filtering here.
package egress

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

// Decision counters for the run receipt (A3).
type Counters struct {
	Allowed atomic.Int64
	Denied  atomic.Int64
}

// Proxy enforces a domain allowlist. Zero value is not usable; use New.
type Proxy struct {
	allow    map[string]struct{}
	suffixes []string // for "*.example.com" style entries, stored as ".example.com"
	allowAll bool     // set by a bare "*" entry - explicit, intentional allow-all
	Counters Counters
	// onDecision is optional; receives (host, allowed) for ledger logging.
	onDecision func(host string, allowed bool)
	// ca + inject enable credential injection: for a host in inject, the proxy
	// TLS-terminates (MITM) with a ca-minted cert and forces the credential header,
	// so the real secret lives only here in the gateway, never in the box. nil = the
	// default blind-tunnel behaviour (no MITM).
	ca     *CA
	inject map[string]InjectRule // keyed by hostname (no port)
	// injectTransport is the round-tripper to the REAL upstream for injected hosts;
	// nil means http.DefaultTransport (validates the upstream cert against system
	// roots). Overridable for tests.
	injectTransport http.RoundTripper
	// injectSem caps concurrent MITM connections (each does an RSA handshake), so a
	// hostile box can't amplify load with many inject CONNECTs.
	injectSem chan struct{}
}

// maxInjectConns bounds concurrent credential-injection MITM connections.
const maxInjectConns = 256

// SetInjector turns on credential injection for the given hosts. Each injected host
// MUST also be in the egress allowlist (injection is MITM, not a bypass). The box
// must trust ca.CertPEM() for the handshake to succeed.
func (p *Proxy) SetInjector(ca *CA, rules map[string]InjectRule) error {
	for host, r := range rules {
		if err := r.valid(); err != nil {
			return err
		}
		if !p.Allowed(host + ":443") {
			return fmt.Errorf("egress: inject host %q is not in the allowlist", host)
		}
	}
	p.ca, p.inject = ca, rules
	p.injectSem = make(chan struct{}, maxInjectConns)
	return nil
}

// AllowsEverything reports whether this proxy is in explicit allow-all mode, so
// callers can warn loudly and record it in the receipt (never silent).
func (p *Proxy) AllowsEverything() bool { return p.allowAll }

// New builds a proxy from an allowlist.
//   - EMPTY allowlist -> deny everything (fail-closed default, C6 - the opposite of
//     CVE-2025-66479). Not being explicit gets you nothing, not everything.
//   - A bare "*" entry -> EXPLICIT allow-all. The user asked for unrestricted egress,
//     so they get it - flexibility is fine. It is never SILENT: AllowsEverything()
//     lets callers warn loudly and record it in the receipt, so a box is never
//     mistaken for sandboxed when the user chose otherwise.
//   - "*.foo.com" -> subdomain suffix match (any depth, incl. broad ones like "*.com"
//     if the user really wants - it's their trusted pack, not repo-controlled per P5).
func New(allow []string, onDecision func(host string, allowed bool)) *Proxy {
	p := &Proxy{allow: make(map[string]struct{}), onDecision: onDecision}
	for _, d := range allow {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			continue
		}
		if d == "*" {
			p.allowAll = true // explicit, intentional
			continue
		}
		if strings.HasPrefix(d, "*.") {
			suf := d[1:] // "*.foo.com" -> ".foo.com"
			if suf == "." {
				continue // degenerate "*." - use "*" for allow-all instead
			}
			p.suffixes = append(p.suffixes, suf)
			continue
		}
		p.allow[d] = struct{}{}
	}
	return p
}

// validHostname rejects hostnames that could smuggle past the allowlist check.
// Null bytes and control chars are the SOCKS5/CR-LF injection class (E8): the
// allowlist sees "good.com\x00.evil.com" but the OS resolver truncates at the
// null and dials evil. We reject rather than try to normalize.
func validHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c < 0x20 || c == 0x7f { // control chars incl. NUL, CR, LF
			return false
		}
	}
	return !strings.ContainsAny(host, " \t")
}

// Allowed reports whether egress to host is permitted. Exposed for testing and
// for reuse by non-proxy paths (e.g. a DNS guard).
func (p *Proxy) Allowed(host string) bool {
	// Strip any port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !validHostname(host) {
		return false // fail-closed on anything we can't cleanly parse (E8) - even in
		// allow-all mode, a malformed/smuggled host is still rejected.
	}
	if p.allowAll {
		return true // explicit allow-all (recorded in the receipt, never silent)
	}
	h := strings.ToLower(host)
	if _, ok := p.allow[h]; ok {
		return true
	}
	for _, suf := range p.suffixes {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

// Decide authorizes egress to host, updates counters, and fires the decision
// hook (E4 logging). Exported so the same code path is used by ServeHTTP and by
// callers/tests that drive decisions deterministically.
func (p *Proxy) Decide(host string) bool {
	ok := p.Allowed(host)
	if ok {
		p.Counters.Allowed.Add(1)
	} else {
		p.Counters.Denied.Add(1)
	}
	if p.onDecision != nil {
		p.onDecision(host, ok)
	}
	return ok
}

// ServeHTTP implements the CONNECT proxy. Only CONNECT is supported - the box's
// clients are configured to tunnel everything through here.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT supported", http.StatusMethodNotAllowed)
		return
	}
	host := r.Host // "host:port" for CONNECT
	if !p.Decide(host) {
		// Deny is a hard close with a clear status; the receipt/ledger records it.
		http.Error(w, "egress denied by policy", http.StatusForbidden)
		return
	}
	// Credential injection: for an injected host, MITM this TLS connection instead of
	// blind-tunnelling, so we can force the real credential header (the box never has
	// the secret). Only allowlisted + explicitly-injected hosts take this path.
	if hn, _, e := net.SplitHostPort(host); e == nil && p.ca != nil {
		// Match the normalized key the injector stored (lowercase, bare host), so a
		// differently-cased CONNECT authority can't silently skip injection.
		if rule, ok := p.inject[strings.ToLower(hn)]; ok {
			// Cap concurrent MITM connections; shed load rather than block/amplify.
			select {
			case p.injectSem <- struct{}{}:
			default:
				http.Error(w, "too many injected connections", http.StatusServiceUnavailable)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				<-p.injectSem
				http.Error(w, "hijack unsupported", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			srcConn, _, err := hj.Hijack()
			if err != nil {
				<-p.injectSem
				return
			}
			go p.mitmInject(srcConn, host, hn, rule)
			return
		}
	}
	dstConn, err := net.Dial("tcp", host)
	if err != nil {
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		dstConn.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	srcConn, _, err := hj.Hijack()
	if err != nil {
		dstConn.Close()
		return
	}
	// Blind pipe - no inspection (E5). HTTP/2 bidi streams pass through (E6).
	go func() { _, _ = io.Copy(dstConn, srcConn); dstConn.Close() }()
	go func() { _, _ = io.Copy(srcConn, dstConn); srcConn.Close() }()
}

// Summary returns a one-line human/receipt string of decisions so far.
func (p *Proxy) Summary() string {
	return fmt.Sprintf("egress: %d allowed, %d denied",
		p.Counters.Allowed.Load(), p.Counters.Denied.Load())
}
