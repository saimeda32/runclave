// Package fleet is the OPT-IN, ADDITIVE fleet layer (see
// runclave-design/). It gives a security team three things across a
// mixed fleet: (F1) signed policy distribution, (F2) attestation aggregation,
// (F3) fleet verification. It never executes anything, never phones home unless
// an endpoint is explicitly configured, and never carries run content - only
// receipts (effective boundary + side effects). The standalone binary is
// complete without any of this (N5 intent preserved).
//
// Signing uses Ed25519 (stdlib, zero new deps) with a PAE (pre-authentication
// encoding) so exact bytes are signed - no canonicalization bugs. Production
// swaps the raw-key path for cosign keyless (Fulcio/Rekor) over the SAME Ed25519
// primitive and the SAME trust root as receipts (A4) and releases (T2).
package fleet

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/saimeda/runclave/internal/ledger"
)

// pae is the pre-authentication encoding: version tag + a DOMAIN tag (the
// message type) + field ARITY + len+value per field. Domain-separating by type
// (like DSSE's payloadType) binds a signature to "this is a bundle" vs "this is
// a receipt", so one signature can never cross-validate across types - closing
// closing a cross-type confusion. A tampered field changes the signed
// bytes; no canonical-JSON ambiguity.
func pae(domain string, parts ...[]byte) []byte {
	out := []byte("runclave-fleet/v1 " + domain + " " + strconv.Itoa(len(parts)))
	for _, p := range parts {
		out = append(out, ' ')
		out = append(out, []byte(strconv.Itoa(len(p)))...)
		out = append(out, ' ')
		out = append(out, p...)
	}
	return out
}

// ---- F1: signed policy distribution ----

// Bundle is a policy bundle: the blessed set of policy-pack hashes + an opaque
// payload (the packs themselves). PolicyHashes is what the collector checks
// receipts against.
type Bundle struct {
	Version      string   `json:"version"`
	PolicyHashes []string `json:"policy_hashes"`
	Payload      []byte   `json:"payload"`
}

// SignedBundle wraps a Bundle with an Ed25519 signature over its PAE.
type SignedBundle struct {
	Bundle    Bundle `json:"bundle"`
	Signature []byte `json:"signature"`
}

func (b Bundle) signBytes() []byte {
	hashes, _ := json.Marshal(b.PolicyHashes)
	return pae("bundle", []byte(b.Version), hashes, b.Payload)
}

// Sign produces a SignedBundle. The private key stays with the security team
// (in production, an ephemeral Fulcio-issued key); it never reaches an endpoint.
func Sign(b Bundle, priv ed25519.PrivateKey) SignedBundle {
	return SignedBundle{Bundle: b, Signature: ed25519.Sign(priv, b.signBytes())}
}

// Verify checks the signature against a TRUSTED public key. Fail-closed: any
// mismatch (tampered payload, wrong signer, empty sig) returns an error. This is
// the gate in "verify before load" (P3/F-D4).
func Verify(sb SignedBundle, trusted ed25519.PublicKey) error {
	if len(trusted) != ed25519.PublicKeySize {
		return fmt.Errorf("fleet: no/invalid trusted key; refusing (fail-closed)")
	}
	if len(sb.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("fleet: missing/invalid signature; refusing")
	}
	if !ed25519.Verify(trusted, sb.Bundle.signBytes(), sb.Signature) {
		return fmt.Errorf("fleet: signature does not verify against trusted key (tampered or wrong signer)")
	}
	return nil
}

// LoadVerified verifies then returns the bundle. It NEVER returns a bundle that
// failed verification - an unsigned/wrong-signer bundle cannot be loaded.
func LoadVerified(sb SignedBundle, trusted ed25519.PublicKey) (*Bundle, error) {
	if err := Verify(sb, trusted); err != nil {
		return nil, err
	}
	b := sb.Bundle
	return &b, nil
}

// ---- F2: attestation aggregation ----

// SignedReceipt is a run receipt plus an Ed25519 signature over its PAE (the
// A4 DSSE-signed receipt, simplified to the same primitive for the slice).
type SignedReceipt struct {
	Receipt   ledger.Receipt `json:"receipt"`
	Signature []byte         `json:"signature"`
}

func receiptSignBytes(r ledger.Receipt) []byte {
	raw, _ := json.Marshal(r)
	return pae("receipt", raw)
}

// SignReceipt signs a receipt (host-side key, per SECRET-BROKER key location).
func SignReceipt(r ledger.Receipt, priv ed25519.PrivateKey) SignedReceipt {
	return SignedReceipt{Receipt: r, Signature: ed25519.Sign(priv, receiptSignBytes(r))}
}

// strongBackends are backends that give a real (VM/microVM) boundary. Weak or
// unknown backends are flagged by the fleet report.
var strongBackends = map[string]bool{
	"apple-container": true, // per-container VM
	// docker/colima are shared-kernel "container" strength -> flagged as not-strong
	// on their own; on Colima the real boundary is the Lima VM (context-dependent).
}

// Collector is an append-only SINK: it ingests receipts, verifies each
// signature, and checks the policy hash is in the blessed set. It stores and
// verifies; it NEVER executes anything.
type Collector struct {
	blessed  map[string]bool
	trusted  ed25519.PublicKey
	accepted []ledger.Receipt
	rejected []RejectedReceipt
}

// RejectedReceipt records why a receipt was refused (for the report/audit).
type RejectedReceipt struct {
	Agent  string `json:"agent"`
	Reason string `json:"reason"`
}

// NewCollector builds a collector over a blessed policy-hash set and the trusted
// signer key. An empty blessed set means NOTHING is accepted (fail-closed).
func NewCollector(blessedHashes []string, trusted ed25519.PublicKey) *Collector {
	m := make(map[string]bool, len(blessedHashes))
	for _, h := range blessedHashes {
		if h != "" {
			m[h] = true
		}
	}
	return &Collector{blessed: m, trusted: trusted}
}

// Collect ingests one signed receipt. It rejects (does not store as accepted) a
// receipt with a bad signature or a policy hash not in the blessed set.
func (c *Collector) Collect(sr SignedReceipt) error {
	r := sr.Receipt
	if len(c.trusted) != ed25519.PublicKeySize ||
		len(sr.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(c.trusted, receiptSignBytes(r), sr.Signature) {
		c.rejected = append(c.rejected, RejectedReceipt{r.Agent, "signature does not verify"})
		return fmt.Errorf("fleet: receipt signature does not verify")
	}
	if !c.blessed[r.PolicyHash] {
		c.rejected = append(c.rejected, RejectedReceipt{r.Agent, "policy hash not in blessed set: " + shortHash(r.PolicyHash)})
		return fmt.Errorf("fleet: receipt policy hash %s not blessed", shortHash(r.PolicyHash))
	}
	c.accepted = append(c.accepted, r)
	return nil
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ---- F3: fleet verification report ----

// Report is the fleet-verify output: evidence, not trust.
//
// Caveat (own it, don't overclaim): WeakBackend reflects the backend string the
// receipt ASSERTS. The string is inside the signed bytes, so post-signing
// tampering is caught - but a compromised/misconfigured host that signs a
// receipt claiming "apple-container" while actually on docker is NOT detected. A
// malicious signer is out of scope; this report is evidence of what hosts
// attested, not proof of the isolation they actually ran.
type Report struct {
	Accepted       int               `json:"accepted"`
	Rejected       int               `json:"rejected"`
	WeakBackend    []string          `json:"weak_backend"`    // agents on a non-strong backend
	RejectedDetail []RejectedReceipt `json:"rejected_detail"` // why each was refused
}

// Verify produces the report over everything collected so far.
func (c *Collector) Verify() Report {
	rep := Report{
		Accepted:       len(c.accepted),
		Rejected:       len(c.rejected),
		RejectedDetail: c.rejected,
	}
	for _, r := range c.accepted {
		if !strongBackends[r.Backend] {
			rep.WeakBackend = append(rep.WeakBackend, fmt.Sprintf("%s(%s)", r.Agent, r.Backend))
		}
	}
	return rep
}

// BundleHash is a helper: the sha256 of a policy pack's raw bytes, matching the
// receipt's PolicyHash (ledger.PolicyHash) so blessed sets and receipts align.
func BundleHash(packRaw []byte) string {
	sum := sha256.Sum256(packRaw)
	return hex.EncodeToString(sum[:])
}
