// Package ide synthesizes the thin-client attach invocation so `runclave .` can
// launch the user's IDE already attached to a box we created - zero clicks (see
// runclave-design/). The mechanism: build a
// vscode-remote://attached-container+<hex>/<path> URI (hex = the container JSON)
// and hand it to `code`/`cursor --folder-uri`. VS Code and Cursor use DIFFERENT
// container JSON schemas - that difference is the whole reason this is per-IDE data.
package ide

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// Kind is a supported IDE.
type Kind string

const (
	VSCode Kind = "vscode"
	Cursor Kind = "cursor"
)

// attachAuthority builds the `attached-container+<hex>` authority for an IDE.
// VS Code keys on containerName ("/<name>"); Cursor keys on containerId with a
// settingType tag. Wrong schema per IDE = silent attach failure, so this is exact.
func attachAuthority(kind Kind, containerName, containerID string) (string, error) {
	var payload any
	switch kind {
	case VSCode:
		if containerName == "" {
			return "", fmt.Errorf("ide: vscode attach needs a container name")
		}
		payload = map[string]string{"containerName": "/" + strings.TrimPrefix(containerName, "/")}
	case Cursor:
		if containerID == "" {
			return "", fmt.Errorf("ide: cursor attach needs a container id")
		}
		payload = map[string]string{"settingType": "container", "containerId": containerID}
	default:
		return "", fmt.Errorf("ide: unsupported IDE %q", kind)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return "attached-container+" + hex.EncodeToString(raw), nil
}

// AttachURI builds the full vscode-remote:// URI opening workspacePath inside the
// box. workspacePath must be an absolute path INSIDE the container.
func AttachURI(kind Kind, containerName, containerID, workspacePath string) (string, error) {
	auth, err := attachAuthority(kind, containerName, containerID)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(workspacePath, "/") {
		return "", fmt.Errorf("ide: workspace path must be absolute (in-box), got %q", workspacePath)
	}
	// Reject traversal (critic F9): path.Clean must not escape or change the path;
	// a canonical absolute in-box path shouldn't contain "..".
	if strings.Contains(workspacePath, "..") || path.Clean(workspacePath) != workspacePath {
		return "", fmt.Errorf("ide: workspace path must be canonical absolute (no ..), got %q", workspacePath)
	}
	// Percent-encode each path segment (critic F8) so reserved chars (# ? space)
	// can't turn into a URI fragment/query or an invalid URI. Slashes stay as
	// separators; splitting on "/" preserves the leading slash via the empty
	// first element.
	segs := strings.Split(workspacePath, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "vscode-remote://" + auth + strings.Join(segs, "/"), nil
}

// AttachArgv is the command that opens the IDE already attached - zero clicks.
// binary is the IDE CLI on PATH (`code` or `cursor`).
func AttachArgv(kind Kind, binary, containerName, containerID, workspacePath string) ([]string, error) {
	uri, err := AttachURI(kind, containerName, containerID, workspacePath)
	if err != nil {
		return nil, err
	}
	return []string{binary, "--folder-uri", uri}, nil
}

// DecodeAuthority reverses attachAuthority for tests/inspection: returns the JSON
// object encoded in an `attached-container+<hex>` authority.
func DecodeAuthority(authority string) (map[string]string, error) {
	h := strings.TrimPrefix(authority, "attached-container+")
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
