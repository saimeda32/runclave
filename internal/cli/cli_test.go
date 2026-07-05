package cli

import (
	"bytes"
	"os"
	"os/exec"
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

// deriveRepo normalizes both git@ and https origins to host/owner/name, and
// returns "" (skip brokering) when there is no github origin.
func TestDeriveRepo(t *testing.T) {
	cases := map[string]string{
		"git@github.com:owner/name.git":          "github.com/owner/name",
		"https://github.com/owner/name.git":      "github.com/owner/name",
		"https://github.com/owner/name":          "github.com/owner/name",
		"ssh://git@github.com/owner/name.git":    "github.com/owner/name",
		"ssh://git@github.com:22/owner/name.git": "github.com/owner/name", // port dropped, not folded into scope
		"git@gitlab.com:owner/name.git":          "",                      // not github
		"git@github.com.evil.com:owner/name.git": "",                      // look-alike host rejected
	}
	for url, want := range cases {
		dir := t.TempDir()
		mustGit(t, dir, "init", "-q")
		mustGit(t, dir, "remote", "add", "origin", url)
		if got := deriveRepo(dir); got != want {
			t.Fatalf("deriveRepo(%q) = %q, want %q", url, got, want)
		}
	}
	// No origin at all -> "".
	noRemote := t.TempDir()
	mustGit(t, noRemote, "init", "-q")
	if got := deriveRepo(noRemote); got != "" {
		t.Fatalf("deriveRepo with no origin = %q, want empty", got)
	}
}

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v (%s)", args, err, out)
	}
}

// sessionBrokerSocket creates a runclave-owned, owner-only session dir under the
// user's runtime dir and returns a socket path the box guard will accept.
func TestSessionBrokerSocket(t *testing.T) {
	rt := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", rt)
	sock, cleanup, err := sessionBrokerSocket("runclave-proj")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(sock, ".sock") || !strings.Contains(sock, "/runclave/") {
		t.Fatalf("socket %q must be a .sock inside a runclave dir", sock)
	}
	fi, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatalf("session dir must exist: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("session dir must be 0700, got %o", fi.Mode().Perm())
	}
	cleanup()
	if _, err := os.Stat(filepath.Dir(sock)); !os.IsNotExist(err) {
		t.Fatal("cleanup must remove the session dir")
	}
}

// The receipt records the box image actually booted, so an --image override (which
// the policy hash does not reflect) is still on the audit trail.
func TestReceiptRecordsEffectiveImage(t *testing.T) {
	pol := &policy.Pack{Agent: "x"}
	pol.Run.Image = "runclave/all:latest"
	pol.Egress.Model = []string{"example.com"}
	var out bytes.Buffer
	writeRunReceipt(&out, "testimgbox", pol, []byte("agent: x"), "docker", "persisted", 1, 0)
	dir, derr := receiptDir()
	if derr != nil {
		t.Fatal(derr)
	}
	path := filepath.Join(dir, "runclave-testimgbox-receipt.json")
	defer os.Remove(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"image"`) || !strings.Contains(string(data), "runclave/all:latest") {
		t.Fatalf("receipt must record the effective image, got: %s", data)
	}
}

// The receipt's egress numbers come from counting the gateway's own decision log.
func TestCountEgressLines(t *testing.T) {
	log := "runclave proxy: default-deny CONNECT proxy on 0.0.0.0:8888 (2 domains allowed)\n" +
		"egress ALLOW api.anthropic.com:443\n" +
		"egress DENY evil.example.com:443\n" +
		"egress ALLOW claude.ai:443\n" +
		"some unrelated line\n"
	allow, deny := countEgressLines(log)
	if allow != 2 || deny != 1 {
		t.Fatalf("got allow=%d deny=%d, want 2 and 1", allow, deny)
	}
	if a, d := countEgressLines(""); a != 0 || d != 0 {
		t.Fatalf("empty log must be 0,0, got %d,%d", a, d)
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
