package backend

import (
	"strings"
	"testing"
)

type fake struct {
	name string
	str  Strength
}

func (f fake) Name() string                    { return f.name }
func (f fake) Strength() Strength              { return f.str }
func (f fake) Available() bool                 { return true }
func (f fake) CreateArgs(n, i string) []string { return []string{f.name, n, i} }

// D12/C2: detection picks the STRONGEST available backend by default.
func TestSelectPicksStrongest(t *testing.T) {
	avail := []Driver{
		fake{"docker", StrengthContainer},
		fake{"apple-container", StrengthMicroVM},
	}
	sortStrongestFirst(avail)
	d, err := selectFrom(avail, "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name() != "apple-container" {
		t.Fatalf("default picked %q, want apple-container (strongest)", d.Name())
	}
}

// C2: --backend override selects the named backend even if weaker.
func TestSelectOverride(t *testing.T) {
	avail := []Driver{
		fake{"apple-container", StrengthMicroVM},
		fake{"docker", StrengthContainer},
	}
	d, err := selectFrom(avail, "docker")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name() != "docker" {
		t.Fatalf("override picked %q, want docker", d.Name())
	}
}

// C3: requesting an unavailable backend fails loudly, never silently degrades.
func TestSelectUnavailableErrors(t *testing.T) {
	avail := []Driver{fake{"docker", StrengthContainer}}
	if _, err := selectFrom(avail, "apple-container"); err == nil {
		t.Fatal("requesting an unavailable backend should error, not fall back silently")
	}
}

// No backend available at all is an error, not a nil driver.
func TestSelectNoneErrors(t *testing.T) {
	if _, err := selectFrom(nil, ""); err == nil {
		t.Fatal("no backend available should error")
	}
}

// The real macOS driver argv must never grant host-disk access (checked here as
// a sanity cross-check; the authoritative guard lives in workspace).
func TestRealDriverArgvHasNoVolumeFlag(t *testing.T) {
	for _, d := range []Driver{appleContainer{}, dockerCLI{}} {
		argv := d.CreateArgs("box", "img")
		for _, a := range argv {
			if a == "-v" || a == "--volume" || a == "--mount" || a == "--privileged" {
				t.Fatalf("%s CreateArgs contains host-access flag %q: %v", d.Name(), a, argv)
			}
		}
	}
}

// P2 chokepoint (E11): the Docker workload must drop NET_ADMIN/NET_RAW, forbid
// privilege escalation, run non-root, and default to no-egress (fail-closed).
func TestDockerChokepointHardening(t *testing.T) {
	argv := strings.Join(dockerCLI{}.CreateArgs("box", "img"), " ")
	for _, want := range []string{
		"--cap-drop ALL", // strongest least-privilege (critic F2); workload needs no caps
		"--security-opt no-new-privileges",
		"--user 10001:10001",
		"--network none", // fail-closed: no egress until lifecycle attaches sandbox-net
	} {
		if !strings.Contains(argv, want) {
			t.Fatalf("docker chokepoint missing %q in: %s", want, argv)
		}
	}
	if strings.Contains(argv, "docker.sock") || strings.Contains(argv, "--network host") {
		t.Fatalf("docker args expose host network/socket: %s", argv)
	}
	// The host-escape guard must still pass on the hardened args.
	// (imported check lives in workspace; here just assert no --privileged crept in)
	if strings.Contains(argv, "--privileged") {
		t.Fatalf("hardened args must not contain --privileged: %s", argv)
	}
}
