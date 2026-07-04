package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// D5: the shipped claude-code pack loads and validates.
func TestClaudeCodePackLoads(t *testing.T) {
	// Resolve repo-root/policies from this test's location.
	path := filepath.Join("..", "..", "policies", "claude-code.yaml")
	p, err := Load(path)
	if err != nil {
		t.Fatalf("claude-code pack failed to load: %v", err)
	}
	if p.Agent != "claude-code" {
		t.Fatalf("agent=%q", p.Agent)
	}
	if len(p.AllowedDomains()) == 0 {
		t.Fatal("claude-code pack has empty egress allowlist")
	}
	found := false
	for _, d := range p.AllowedDomains() {
		if d == "api.anthropic.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected api.anthropic.com in allowlist")
	}
}

// D6 fail-closed: an empty egress allowlist must ERROR, never mean allow-all.
func TestEmptyAllowlistRejected(t *testing.T) {
	dir := t.TempDir()
	pack := `agent: test
scope: local
type: cli-headless
run:
  command: test
egress:
  model: []
  infra: []
`
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(pack), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("empty allowlist pack loaded OK; must fail closed (C6)")
	}
}

// D6: unknown YAML fields are rejected so a typo can't silently disable a control.
func TestUnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	pack := `agent: test
scope: local
type: cli-headless
run:
  command: test
egress:
  model: [api.example.com]
egres_typo:
  model: [wide-open.com]
`
	path := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(path, []byte(pack), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("pack with unknown field loaded OK; typo'd controls could be silently ignored")
	}
}

// track-only packs skip local-execution validation (they never run locally).
func TestTrackOnlySkipsValidation(t *testing.T) {
	dir := t.TempDir()
	pack := `agent: devin
scope: track-only
`
	path := filepath.Join(dir, "devin.yaml")
	if err := os.WriteFile(path, []byte(pack), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("track-only pack should validate: %v", err)
	}
}

// A caller-supplied agent name must never traverse out of the policies dir. Both
// Find and RawBytes reject a name with path separators or `..`, on-disk or embedded.
func TestAgentNameTraversalRejected(t *testing.T) {
	bad := []string{"../../etc/passwd", "..", "a/b", "a\\b", "with space", ""}
	for _, name := range bad {
		if _, err := Find("/tmp", name); err == nil {
			t.Fatalf("Find must reject agent name %q", name)
		}
		if _, err := RawBytes("/tmp", name); err == nil {
			t.Fatalf("RawBytes must reject agent name %q", name)
		}
	}
	// The real packs still resolve.
	for _, name := range []string{"claude-code", "gemini-cli"} {
		if _, err := Find("", name); err != nil {
			t.Fatalf("Find(%q) must still work: %v", name, err)
		}
	}
}
