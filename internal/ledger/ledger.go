// Package ledger is the hash-chained, append-only session record (A1) and the
// run receipt (A3). Local-only, no telemetry, ever (A2). The ledger explains
// *what happened*; the receipt summarizes the *effective boundary + side effects*
// separately from any chat transcript.
//
// Integrity model - be precise about what the hash chain does and does not give:
//   - It DETECTS accidental corruption and naive single-entry edits: changing a
//     payload without recomputing downstream hashes breaks Verify().
//   - The primary tamper *resistance* comes from WHERE the ledger lives: it is
//     written host-side, outside the box. The in-box agent - the actual threat -
//     has no write path to it (same "no path to the real disk" property as W6).
//   - It is NOT cryptographically tamper-EVIDENT against a host-side attacker who
//     can rewrite the file: genesis and the hash are public, so such an attacker
//     can recompute the whole chain (and can truncate the tail; a prefix of a
//     valid chain still verifies). Non-repudiation via signing with an escrowed
//     key is future work, not a P1 claim. Do not call this "tamper-proof."
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// genesis is the chain seed; the first entry's PrevHash is this constant.
const genesis = "runclave-genesis"

// Entry is one appended record. Hash = sha256(PrevHash + canonical(payload)).
type Entry struct {
	Seq      int             `json:"seq"`
	Kind     string          `json:"kind"` // "command" | "egress" | "file-write" | "meta"
	Payload  json.RawMessage `json:"payload"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

// Ledger is an in-memory chain that can be flushed to JSONL. For P1 we keep it
// in memory and write on close; a production version appends incrementally.
type Ledger struct {
	entries []Entry
	last    string
	// clock is injected so tests are deterministic (no Date.now in the chain).
	clock func() time.Time
}

func New() *Ledger {
	return &Ledger{last: genesis, clock: time.Now}
}

// hashEntry computes the chain hash for a payload given the previous hash.
func hashEntry(prev string, seq int, kind string, payload []byte) string {
	h := sha256.New()
	// Domain-separate the fields so reordering can't collide.
	fmt.Fprintf(h, "%s\n%d\n%s\n", prev, seq, kind)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// Append adds a record and extends the chain.
func (l *Ledger) Append(kind string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	seq := len(l.entries)
	hash := hashEntry(l.last, seq, kind, raw)
	l.entries = append(l.entries, Entry{
		Seq:      seq,
		Kind:     kind,
		Payload:  raw,
		PrevHash: l.last,
		Hash:     hash,
	})
	l.last = hash
	return nil
}

// Verify recomputes the whole chain and reports the first break. This catches
// accidental corruption and naive edits (editing any past entry changes its hash
// and breaks every subsequent PrevHash link). It does NOT catch a full-chain
// recompute or tail truncation - see the package-level integrity note. Callers
// that need rollback detection should compare Len()/Head() against an
// independently retained value (e.g. the receipt's LedgerEntries/LedgerHead).
func (l *Ledger) Verify() error {
	prev := genesis
	for i, e := range l.entries {
		if e.Seq != i {
			return fmt.Errorf("entry %d: seq mismatch (%d)", i, e.Seq)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("entry %d: broken link (prev=%s want=%s)", i, e.PrevHash, prev)
		}
		want := hashEntry(prev, e.Seq, e.Kind, e.Payload)
		if e.Hash != want {
			return fmt.Errorf("entry %d: hash mismatch (tampered payload?)", i)
		}
		prev = e.Hash
	}
	return nil
}

// WriteJSONL flushes the chain to a file, one entry per line.
func (l *Ledger) WriteJSONL(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range l.entries {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

// Len returns the number of entries (for receipts/tests).
func (l *Ledger) Len() int { return len(l.entries) }

// Receipt is the post-run artifact (A3): the effective boundary + side effects,
// distinct from the transcript. Machine-readable so runs are comparable/replayable.
type Receipt struct {
	Agent         string    `json:"agent"`
	PolicyHash    string    `json:"policy_hash"`
	Backend       string    `json:"backend"`
	GrantedWrite  []string  `json:"granted_write_scopes"`
	AllowedEgress []string  `json:"allowed_egress"`
	EgressAllowed int64     `json:"egress_allowed"`
	EgressDenied  int64     `json:"egress_denied"`
	FilesChanged  int       `json:"files_changed"`
	Disposition   string    `json:"disposition"` // planned | persisted | destroyed | failed
	LedgerEntries int       `json:"ledger_entries"`
	LedgerHead    string    `json:"ledger_head"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
}

// PolicyHash is a helper to hash the raw policy bytes for the receipt.
func PolicyHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Head returns the current chain head hash (goes into the receipt).
func (l *Ledger) Head() string { return l.last }

// WriteReceipt marshals a receipt to a file.
func WriteReceipt(path string, r Receipt) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
