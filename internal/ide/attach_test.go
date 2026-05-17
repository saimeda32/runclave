package ide

import (
	"strings"
	"testing"
)

// VS Code uses containerName ("/<name>"); the URI must round-trip to that JSON.
func TestVSCodeAttachURI(t *testing.T) {
	uri, err := AttachURI(VSCode, "runclave-proj", "", "/workspaces/proj")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "vscode-remote://attached-container+") {
		t.Fatalf("bad URI scheme: %s", uri)
	}
	if !strings.HasSuffix(uri, "/workspaces/proj") {
		t.Fatalf("workspace path missing: %s", uri)
	}
	auth := strings.TrimSuffix(strings.TrimPrefix(uri, "vscode-remote://"), "/workspaces/proj")
	m, err := DecodeAuthority(auth)
	if err != nil {
		t.Fatal(err)
	}
	if m["containerName"] != "/runclave-proj" {
		t.Fatalf("vscode containerName=%q want /runclave-proj", m["containerName"])
	}
}

// Cursor uses a DIFFERENT schema (settingType+containerId) - wrong schema =
// silent attach failure, so this must be exact and distinct from VS Code.
func TestCursorAttachURIDistinctSchema(t *testing.T) {
	uri, err := AttachURI(Cursor, "", "abc123", "/workspaces/proj")
	if err != nil {
		t.Fatal(err)
	}
	auth := strings.TrimSuffix(strings.TrimPrefix(uri, "vscode-remote://"), "/workspaces/proj")
	m, err := DecodeAuthority(auth)
	if err != nil {
		t.Fatal(err)
	}
	if m["settingType"] != "container" || m["containerId"] != "abc123" {
		t.Fatalf("cursor schema wrong: %v", m)
	}
	if _, ok := m["containerName"]; ok {
		t.Fatal("cursor payload must NOT use vscode's containerName key")
	}
}

// Fail-closed on bad inputs: missing ref, non-absolute path, unknown IDE.
func TestAttachFailClosed(t *testing.T) {
	if _, err := AttachURI(VSCode, "", "", "/w"); err == nil {
		t.Fatal("vscode attach with no container name should error")
	}
	if _, err := AttachURI(Cursor, "", "", "/w"); err == nil {
		t.Fatal("cursor attach with no container id should error")
	}
	if _, err := AttachURI(VSCode, "box", "", "relative/path"); err == nil {
		t.Fatal("non-absolute in-box workspace path should error")
	}
	if _, err := AttachURI(Kind("emacs"), "box", "id", "/w"); err == nil {
		t.Fatal("unsupported IDE should error")
	}
}

// Critic F8/F9: reserved chars in the path are percent-encoded (no fragment/query
// injection) and traversal ("..") is rejected.
func TestPathEncodingAndTraversal(t *testing.T) {
	// A path with a space and a '#' must be percent-encoded, not left raw.
	uri, err := AttachURI(VSCode, "box", "", "/work spaces/a#b")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(uri, "#") || strings.Contains(uri, " ") {
		t.Fatalf("reserved chars not encoded: %s", uri)
	}
	if !strings.Contains(uri, "%20") || !strings.Contains(uri, "%23") {
		t.Fatalf("expected %%20 and %%23 in encoded path: %s", uri)
	}
	// Traversal must be rejected.
	for _, bad := range []string{"/a/../b", "/..", "/foo/.."} {
		if _, err := AttachURI(VSCode, "box", "", bad); err == nil {
			t.Fatalf("traversal path %q should be rejected", bad)
		}
	}
}

// The launch argv is the zero-click open: `<binary> --folder-uri <uri>`.
func TestAttachArgv(t *testing.T) {
	argv, err := AttachArgv(VSCode, "code", "box", "", "/workspaces/proj")
	if err != nil {
		t.Fatal(err)
	}
	if len(argv) != 3 || argv[0] != "code" || argv[1] != "--folder-uri" {
		t.Fatalf("unexpected argv: %v", argv)
	}
}
