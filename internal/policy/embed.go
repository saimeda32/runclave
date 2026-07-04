package policy

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// packsFS embeds the canonical policy packs into the binary so `runclave .` works
// in ANY repo, not just runclave's own checkout. A `--policies <dir>` override
// still takes precedence for local/experimental packs.
//
//go:embed packs/*.yaml
var packsFS embed.FS

// EmbeddedAgents lists the agent packs shipped in the binary.
func EmbeddedAgents() []string {
	entries, err := fs.ReadDir(packsFS, "packs")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if len(name) > 5 && name[len(name)-5:] == ".yaml" {
			out = append(out, name[:len(name)-5])
		}
	}
	return out
}

// RawBytes returns the raw pack bytes with the same precedence as Find (explicit
// dir override, else embedded). Used to hash the active policy into the receipt.
func RawBytes(dir, agent string) ([]byte, error) {
	if !validAgentName(agent) {
		return nil, fmt.Errorf("policy: invalid agent name %q", agent)
	}
	if dir != "" {
		if path := filepath.Join(dir, agent+".yaml"); fileExists(path) {
			return os.ReadFile(path)
		}
	}
	return packsFS.ReadFile("packs/" + agent + ".yaml")
}

// loadEmbedded loads a pack from the embedded FS, or returns (nil,false) if absent.
func loadEmbedded(agent string) (*Pack, bool, error) {
	if !validAgentName(agent) {
		return nil, false, nil
	}
	data, err := packsFS.ReadFile("packs/" + agent + ".yaml")
	if err != nil {
		return nil, false, nil // not embedded
	}
	p, err := parse(data)
	return p, true, err
}
