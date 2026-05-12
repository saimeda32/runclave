// Package session orchestrates one runclave run: it ties policy, backend
// selection, the egress boundary, and the ledger/receipt into a single lifecycle.
// This is the production wiring that makes egress and ledger real rather than
// standalone libraries - a run actually stands up the proxy, records decisions
// to the ledger, and emits a receipt (A3).
package session

import (
	"net"
	"net/http"
	"time"

	"github.com/saimeda/runclave/internal/backend"
	"github.com/saimeda/runclave/internal/egress"
	"github.com/saimeda/runclave/internal/ledger"
	"github.com/saimeda/runclave/internal/policy"
)

// Session is a live run. Create with Start; end with Finish.
type Session struct {
	Pack    *policy.Pack
	Driver  backend.Driver
	Proxy   *egress.Proxy
	Ledger  *ledger.Ledger
	rawPol  []byte
	srv     *http.Server
	ln      net.Listener
	started time.Time
	clock   func() time.Time
}

// Options configure a session.
type Options struct {
	RawPolicy   []byte // raw pack bytes, for the receipt's policy hash
	ListenProxy bool   // if true, bind the egress proxy on a local port
	Clock       func() time.Time
}

// Start wires everything for a run. The egress proxy is built from the pack's
// allowlist (default-deny) and its decisions are logged to the ledger (E4).
func Start(pack *policy.Pack, drv backend.Driver, opts Options) (*Session, error) {
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	s := &Session{
		Pack:    pack,
		Driver:  drv,
		Ledger:  ledger.New(),
		rawPol:  opts.RawPolicy,
		started: clock(),
		clock:   clock,
	}
	// Every egress decision is appended to the ledger as it happens.
	s.Proxy = egress.New(pack.AllowedDomains(), func(host string, allowed bool) {
		_ = s.Ledger.Append("egress", map[string]any{"host": host, "allowed": allowed})
	})

	// Session-open meta record: what boundary is in force.
	_ = s.Ledger.Append("meta", map[string]any{
		"event":       "session-start",
		"agent":       pack.Agent,
		"backend":     drv.Name(),
		"strength":    drv.Strength().String(),
		"policy_hash": ledger.PolicyHash(opts.RawPolicy),
		"allowlist":   pack.AllowedDomains(),
	})

	if opts.ListenProxy {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		s.ln = ln
		s.srv = &http.Server{Handler: s.Proxy}
		go func() { _ = s.srv.Serve(ln) }()
	}
	return s, nil
}

// ProxyAddr returns the address a box should route egress through (empty if the
// proxy wasn't started).
func (s *Session) ProxyAddr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Finish tears the session down and produces the run receipt (A3). disposition
// is "destroyed" or "persisted". It returns the receipt and the paths written.
func (s *Session) Finish(disposition, receiptPath, ledgerPath string, filesChanged int) (ledger.Receipt, error) {
	_ = s.Ledger.Append("meta", map[string]any{"event": "session-finish", "disposition": disposition})
	if s.srv != nil {
		_ = s.srv.Close()
	}
	r := ledger.Receipt{
		Agent:         s.Pack.Agent,
		PolicyHash:    ledger.PolicyHash(s.rawPol),
		Backend:       s.Driver.Name(),
		AllowedEgress: s.Pack.AllowedDomains(),
		EgressAllowed: s.Proxy.Counters.Allowed.Load(),
		EgressDenied:  s.Proxy.Counters.Denied.Load(),
		FilesChanged:  filesChanged,
		Disposition:   disposition,
		LedgerEntries: s.Ledger.Len(),
		LedgerHead:    s.Ledger.Head(),
		StartedAt:     s.started,
		FinishedAt:    s.clock(),
	}
	if ledgerPath != "" {
		if err := s.Ledger.WriteJSONL(ledgerPath); err != nil {
			return r, err
		}
	}
	if receiptPath != "" {
		if err := ledger.WriteReceipt(receiptPath, r); err != nil {
			return r, err
		}
	}
	return r, nil
}
