package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saimeda/runclave/internal/box"
	"github.com/saimeda/runclave/internal/policy"
)

// packWith returns a claude-code-shaped pack whose login paths are the given ones.
func packWith(loginPaths ...string) *policy.Pack {
	p := &policy.Pack{Agent: "claude-code"}
	p.Auth.LoginPaths = loginPaths
	return p
}

// homeFixture makes a temp dir, canonicalizes it (macOS /var -> /private/var), and
// points $HOME at it so buildLoginMounts resolves the same root the test uses.
func homeFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if r, err := filepath.EvalSymlinks(home); err == nil {
		home = r
	}
	t.Setenv("HOME", home)
	return home
}

// --login off, or a pack with no login paths, produces no mounts and no root.
func TestBuildLoginMountsOptOut(t *testing.T) {
	var out bytes.Buffer
	if m, root, err := buildLoginMounts(packWith("~/.claude"), false, &out); err != nil || m != nil || root != "" {
		t.Fatalf("--login off must yield nothing, got m=%v root=%q err=%v", m, root, err)
	}
	if m, root, err := buildLoginMounts(packWith(), true, &out); err != nil || m != nil || root != "" {
		t.Fatalf("no login paths must yield nothing, got m=%v root=%q err=%v", m, root, err)
	}
}

// A real login file under home is mounted read-only to the box home, and the home
// root is returned so the box layer can re-confine it.
func TestBuildLoginMountsHappyPath(t *testing.T) {
	home := homeFixture(t)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	mounts, root, err := buildLoginMounts(packWith("~/.claude.json"), true, &out)
	if err != nil {
		t.Fatal(err)
	}
	if root != home {
		t.Fatalf("root %q, want %q", root, home)
	}
	if len(mounts) != 1 {
		t.Fatalf("want 1 mount, got %v", mounts)
	}
	if mounts[0].BoxPath != box.BoxHome+"/.claude.json" {
		t.Fatalf("box path %q, want %s/.claude.json", mounts[0].BoxPath, box.BoxHome)
	}
	if mounts[0].HostPath != filepath.Join(home, ".claude.json") {
		t.Fatalf("host path %q, want the file under home", mounts[0].HostPath)
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Fatal("sharing a login must print a warning")
	}
}

// The important one: a login dotfile that is a SYMLINK pointing outside home must
// be refused, because docker binds the symlink's target. Lstat alone would miss it.
func TestBuildLoginMountsRejectsSymlinkEscape(t *testing.T) {
	home := homeFixture(t)
	outside := t.TempDir() // a sibling temp dir, NOT under home
	if r, err := filepath.EvalSymlinks(outside); err == nil {
		outside = r
	}
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// ~/.claude -> /outside/secret
	if err := os.Symlink(secret, filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, _, err := buildLoginMounts(packWith("~/.claude"), true, &out); err == nil {
		t.Fatal("a login symlink resolving outside home must be refused")
	}
}

// A pack path that is literally outside home is refused too.
func TestBuildLoginMountsRejectsOutsideHome(t *testing.T) {
	homeFixture(t)
	var out bytes.Buffer
	if _, _, err := buildLoginMounts(packWith("/etc/shadow"), true, &out); err == nil {
		t.Fatal("a login path outside home must be refused")
	}
}

// A missing login file is skipped with a note, not an error (you're just not
// logged in on this machine).
func TestBuildLoginMountsSkipsMissing(t *testing.T) {
	homeFixture(t)
	var out bytes.Buffer
	mounts, _, err := buildLoginMounts(packWith("~/.claude"), true, &out)
	if err != nil {
		t.Fatalf("a missing login path must not error, got %v", err)
	}
	if len(mounts) != 0 {
		t.Fatalf("a missing login path must produce no mount, got %v", mounts)
	}
	if !strings.Contains(out.String(), "not found") {
		t.Fatal("a missing login path should be noted")
	}
}
