// Package policy loads agent policy packs - the "agents are data, not code"
// adapter model (see runclave-design/). Core code never names a
// specific agent; it reads one of these packs. Adding an agent = a new YAML file.
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Pack is the full declarative description of one agent. The six top-level
// dimensions (Type, Egress, Auth, Paths, MCP, NativeSandbox) are exactly the
// axes the 14-agent matrix showed agents differ on.
type Pack struct {
	Agent string `yaml:"agent"`
	Scope string `yaml:"scope"` // "local" | "track-only"
	Type  string `yaml:"type"`  // "cli-headless" | "ide-thin-client"

	Run struct {
		Command       string            `yaml:"command"`
		HeadlessFlags []string          `yaml:"headlessFlags"`
		ContainerEnv  map[string]string `yaml:"containerEnv"`
		// Image is the box image for this agent. It should build FROM the runclave
		// base and add the agent CLI. Empty falls back to the agent-agnostic base
		// (which has git but not the agent, so the exec will fail).
		Image string `yaml:"image"`
		// Shell is the interactive shell `runclave . --shell` runs in this image.
		// Empty defaults to "sh" (present on alpine/debian/node images); set "bash"
		// when the image ships it.
		Shell string `yaml:"shell"`
		// PromptPositional says the task prompt is a trailing POSITIONAL argument (e.g.
		// `codex exec <flags> <prompt>`), not the value of a flag like `-p`. When true, a
		// `--` end-of-options separator is inserted before the prompt so a task that
		// starts with a dash is not mistaken for one of the agent's own flags.
		PromptPositional bool `yaml:"promptPositional"`
	} `yaml:"run"`

	Egress struct {
		Model         []string `yaml:"model"`          // allow: inference + auth
		Infra         []string `yaml:"infra"`          // allow: registries, updates
		TelemetryDeny []string `yaml:"telemetry_deny"` // deny by default
	} `yaml:"egress"`

	Auth struct {
		Method     string `yaml:"method"` // file-copy|env-token|machine-locked|keyring-fallback
		EnvVar     string `yaml:"envVar"`
		TokenPath  string `yaml:"tokenPath"`
		DeviceFlow bool   `yaml:"deviceFlow"`
		// LoginPaths are the host paths (under the user's home, ~ allowed) that hold
		// THIS agent's existing login, so `runclave . --login` can mount them
		// read-only and the agent reuses your machine's login instead of you exporting
		// a token. Opt-in only: sharing a login file punches a declared hole in the
		// filesystem isolation and hands the box a long-lived, unscoped credential.
		LoginPaths []string `yaml:"loginPaths"`
	} `yaml:"auth"`

	Paths struct {
		RelocateEnv        string   `yaml:"relocateEnv"`
		CredentialHotspots []string `yaml:"credentialHotspots"`
	} `yaml:"paths"`

	MCP struct {
		ConfigPath    string `yaml:"configPath"`
		ConsentPolicy string `yaml:"consentPolicy"` // "outside-repo"
	} `yaml:"mcp"`

	NativeSandbox struct {
		Mode        string `yaml:"mode"` // disable|passthrough|approval-only|own-runtime
		DisableFlag string `yaml:"disableFlag"`
	} `yaml:"nativeSandbox"`
}

// AllowedDomains returns the union of model + infra egress domains - the
// allowlist the egress proxy enforces. Telemetry is intentionally excluded
// (denied by default, criterion E7). Blank/whitespace-only entries are dropped
// so a pack of ["", "  "] cannot masquerade as a non-empty allowlist.
func (p *Pack) AllowedDomains() []string {
	out := make([]string, 0, len(p.Egress.Model)+len(p.Egress.Infra))
	for _, d := range append(append([]string{}, p.Egress.Model...), p.Egress.Infra...) {
		if strings.TrimSpace(d) != "" {
			out = append(out, d)
		}
	}
	return out
}

// Validate enforces invariants a pack must satisfy before we trust it to gate a
// sandbox. Fail-closed: a malformed pack must error, never silently widen access.
func (p *Pack) Validate() error {
	if p.Agent == "" {
		return fmt.Errorf("policy: missing 'agent'")
	}
	switch p.Scope {
	case "local", "track-only":
	case "":
		p.Scope = "local"
	default:
		return fmt.Errorf("policy %q: invalid scope %q", p.Agent, p.Scope)
	}
	if p.Scope == "track-only" {
		return nil // no local execution; nothing more to validate
	}
	switch p.Type {
	case "cli-headless", "ide-thin-client":
	default:
		return fmt.Errorf("policy %q: invalid type %q", p.Agent, p.Type)
	}
	if p.Type == "cli-headless" && p.Run.Command == "" {
		return fmt.Errorf("policy %q: cli-headless requires run.command", p.Agent)
	}
	// Egress allowlist must be non-empty for a local agent. An empty allowlist
	// that silently meant "allow all" is exactly CVE-2025-66479; we treat empty
	// as a config error, not as open access (criterion C6, fail-closed).
	if len(p.AllowedDomains()) == 0 {
		return fmt.Errorf("policy %q: empty egress allowlist; refusing (fail-closed)", p.Agent)
	}
	return nil
}

// parse decodes+validates raw pack bytes. Shared by Load (file) and loadEmbedded.
func parse(data []byte) (*Pack, error) {
	var p Pack
	// KnownFields: reject unknown keys so a typo'd field can't silently disable
	// a control the author thought they set.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Load reads and validates a single pack file.
func Load(path string) (*Pack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}

// Find resolves an agent pack. Precedence: a `--policies <dir>` override on disk
// (for local/experimental packs), else the pack embedded in the binary (so
// `runclave .` works in any repo). Empty dir = embedded only.
// validAgentName rejects a pack name that isn't a plain slug, so a caller-supplied
// name (e.g. `--agent`, `run <agent>`) can never traverse out of the policies dir
// with `/` or `..`. Embedded lookup via embed.FS already rejects `..`; this closes
// the on-disk (`--policies`) path too.
func validAgentName(agent string) bool {
	if agent == "" || len(agent) > 64 {
		return false
	}
	for _, r := range agent {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func Find(dir, agent string) (*Pack, error) {
	if !validAgentName(agent) {
		return nil, fmt.Errorf("policy: invalid agent name %q (letters, digits, - and _ only)", agent)
	}
	if dir != "" {
		if path := filepath.Join(dir, agent+".yaml"); fileExists(path) {
			return Load(path)
		}
	}
	if p, ok, err := loadEmbedded(agent); ok {
		return p, err
	}
	return nil, fmt.Errorf("no policy pack for agent %q (dir %q, embedded: %v)", agent, dir, EmbeddedAgents())
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
