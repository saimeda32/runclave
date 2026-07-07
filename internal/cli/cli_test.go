package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saimeda/runclave/internal/box"
	"github.com/saimeda/runclave/internal/egress"
	"github.com/saimeda/runclave/internal/ide"
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

// `runclave open` opens the cloned-repo path in the box: BoxHome/<repo>, where
// <repo> is the box name minus the runclave- prefix.
func TestDefaultWorkspacePath(t *testing.T) {
	if got := defaultWorkspacePath("runclave-myproj"); got != box.BoxHome+"/myproj" {
		t.Fatalf("workspace path %q, want %s/myproj", got, box.BoxHome)
	}
	// And that path builds a valid, decodable VS Code attach URI for the box.
	uri, err := ide.AttachURI(ide.VSCode, "runclave-myproj", "deadbeef", defaultWorkspacePath("runclave-myproj"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "vscode-remote://attached-container+") || !strings.HasSuffix(uri, box.BoxHome+"/myproj") {
		t.Fatalf("unexpected attach URI: %s", uri)
	}
	auth := strings.TrimSuffix(strings.TrimPrefix(uri, "vscode-remote://"), box.BoxHome+"/myproj")
	m, err := ide.DecodeAuthority(auth)
	if err != nil {
		t.Fatal(err)
	}
	if m["containerName"] != "/runclave-myproj" {
		t.Fatalf("authority must encode the container name, got %v", m)
	}
}

// The in-guest lockdown ruleset must default-drop egress and allow ONLY loopback,
// established, DNS, and TCP to the proxy endpoint (the Apple backend's egress control).
func TestBuildLockdownRuleset(t *testing.T) {
	rs := buildLockdownRuleset("192.168.64.2", "8888", "192.168.64.1")
	for _, want := range []string{
		"policy drop;",
		`oifname "lo" accept`,
		"ct state established,related accept",
		"ip daddr 192.168.64.1 udp dport 53 accept",   // pinned DNS
		"ip daddr 192.168.64.2 tcp dport 8888 accept", // the proxy, and only the proxy
	} {
		if !strings.Contains(rs, want) {
			t.Fatalf("lockdown ruleset missing %q:\n%s", want, rs)
		}
	}
	// Without a pinned DNS it should allow port 53 generally (not a specific ip).
	if open := buildLockdownRuleset("10.0.0.2", "8888", ""); !strings.Contains(open, "udp dport 53 accept") || strings.Contains(open, "ip daddr  udp") {
		t.Fatalf("unpinned DNS ruleset wrong:\n%s", open)
	}
}

// runclave ls lists workload boxes only: runclave- prefixed, excluding the -gw
// gateway sidecars and any non-runclave container docker's substring filter caught.
func TestParseLsBoxes(t *testing.T) {
	out := "runclave-proj\trunclave/claude-code:latest\t2 minutes ago\n" +
		"runclave-proj-gw\trunclave/gateway:latest\t2 minutes ago\n" +
		"runclave-api\trunclave/codex:latest\tabout an hour ago\n" +
		"runclave-my-gw\trunclave/gemini-cli:latest\t5 minutes ago\n" + // repo named "my-gw": a real box, must NOT be hidden
		"myrunclave-thing\tsomeimage\t3 days ago\n"
	boxes := parseLsBoxes(out)
	if len(boxes) != 3 {
		t.Fatalf("want 3 boxes (gateway excluded by image, non-runclave excluded), got %d: %+v", len(boxes), boxes)
	}
	names := map[string]bool{}
	for _, b := range boxes {
		names[b.Name] = true
		if strings.Contains(b.Image, "runclave/gateway") {
			t.Fatalf("gateway sidecar must be excluded: %+v", b)
		}
	}
	if !names["runclave-proj"] || !names["runclave-api"] || !names["runclave-my-gw"] {
		t.Fatalf("missing expected boxes (incl. the -gw-named repo): %v", names)
	}
	if names["runclave-proj-gw"] || names["myrunclave-thing"] {
		t.Fatalf("gateway or non-runclave leaked in: %v", names)
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

// Injection wiring: enableInjection reads the real secret from the environment
// (never argv), refuses the unsafe shapes, and writes a CA CERT (not the key) for
// the box to trust. Traffic-level injection is covered in internal/egress.
func TestProxyInjectionWiring(t *testing.T) {
	dir := t.TempDir()
	caOut := filepath.Join(dir, "ca.pem")
	var out, errb bytes.Buffer

	// Missing --inject-value-env / --inject-ca-out is a usage error.
	if code := enableInjection(egress.New([]string{"api.anthropic.com"}, nil),
		"api.anthropic.com", "Authorization", "", caOut, &out, &errb); code != 2 {
		t.Fatalf("missing value-env should be usage error 2, got %d", code)
	}

	// An empty env var must NOT inject a blank credential.
	t.Setenv("RUNCLAVE_TEST_TOKEN", "")
	if code := enableInjection(egress.New([]string{"api.anthropic.com"}, nil),
		"api.anthropic.com", "Authorization", "RUNCLAVE_TEST_TOKEN", caOut, &out, &errb); code != 1 {
		t.Fatalf("empty token env should fail with 1, got %d", code)
	}

	// A host that isn't allowlisted must be refused (injection is not a bypass).
	t.Setenv("RUNCLAVE_TEST_TOKEN", "REAL-SECRET")
	if code := enableInjection(egress.New([]string{"api.anthropic.com"}, nil),
		"evil.example.com", "Authorization", "RUNCLAVE_TEST_TOKEN", caOut, &out, &errb); code != 1 {
		t.Fatalf("non-allowlisted inject host should be refused with 1, got %d", code)
	}

	// Happy path: returns 0, writes a real CA cert, and never leaks the token.
	out.Reset()
	errb.Reset()
	code := enableInjection(egress.New([]string{"api.anthropic.com"}, nil),
		"api.anthropic.com", "Authorization", "RUNCLAVE_TEST_TOKEN", caOut, &out, &errb)
	if code != 0 {
		t.Fatalf("happy path should return 0, got %d (%s)", code, errb.String())
	}
	pemBytes, err := os.ReadFile(caOut)
	if err != nil {
		t.Fatalf("CA cert file not written: %v", err)
	}
	blk, _ := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("expected a CERTIFICATE PEM, got %v", blk)
	}
	if strings.Contains(string(pemBytes), "PRIVATE KEY") {
		t.Fatalf("the CA private key must never be written to disk")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || !crt.IsCA {
		t.Fatalf("written cert must be a parseable CA cert: %v", err)
	}
	if strings.Contains(string(pemBytes), "REAL-SECRET") {
		t.Fatalf("the token must never appear in the written CA cert file")
	}
	if strings.Contains(out.String()+errb.String(), "REAL-SECRET") {
		t.Fatalf("the token must never appear in output: %q / %q", out.String(), errb.String())
	}

	// A host with a port or wildcard is a bad flag, not a silent non-injection.
	for _, bad := range []string{"api.anthropic.com:443", "*.anthropic.com"} {
		if code := enableInjection(egress.New([]string{"api.anthropic.com"}, nil),
			bad, "Authorization", "RUNCLAVE_TEST_TOKEN", filepath.Join(dir, "x.pem"), &out, &errb); code != 2 {
			t.Fatalf("--inject-host %q should be a usage error 2, got %d", bad, code)
		}
	}

	// Case mismatch must NOT silently disable injection: the rule key is normalized to
	// lowercase so it matches the box's CONNECT authority. Proven by the injector
	// accepting a mixed-case flag against a lowercase allowlist and writing the cert.
	caOut2 := filepath.Join(dir, "ca2.pem")
	if code := enableInjection(egress.New([]string{"api.anthropic.com"}, nil),
		"API.Anthropic.Com", "Authorization", "RUNCLAVE_TEST_TOKEN", caOut2, &out, &errb); code != 0 {
		t.Fatalf("mixed-case inject host should normalize and succeed, got %d (%s)", code, errb.String())
	}
	if _, err := os.Stat(caOut2); err != nil {
		t.Fatalf("normalized-host run should have written its cert: %v", err)
	}

	// The CA write must refuse a pre-planted symlink (root-follow / box-supplied CA).
	linkPath := filepath.Join(dir, "link.pem")
	if err := os.Symlink(filepath.Join(dir, "target.pem"), linkPath); err != nil {
		t.Fatalf("symlink setup: %v", err)
	}
	if code := enableInjection(egress.New([]string{"api.anthropic.com"}, nil),
		"api.anthropic.com", "Authorization", "RUNCLAVE_TEST_TOKEN", linkPath, &out, &errb); code != 1 {
		t.Fatalf("writing the CA cert onto a symlink must fail closed with 1, got %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "target.pem")); err == nil {
		t.Fatalf("symlink target must NOT have been created/written through")
	}
}
