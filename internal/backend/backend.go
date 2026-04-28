// Package backend is the per-OS isolation driver. runclave writes ZERO isolation
// code of its own (criterion C1/N1) - each driver composes an OS-native,
// vendor-audited backend. On macOS we support BOTH Apple `container` (per-VM
// hardware boundary, macOS 26+) and Docker/Colima (broad compat), auto-picking
// the strongest available (C2).
package backend

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Strength orders backends so detection can pick the strongest available.
type Strength int

const (
	StrengthNone      Strength = iota
	StrengthContainer          // shared-kernel container (Docker/Colima/Podman)
	StrengthMicroVM            // per-container lightweight VM (Apple container, gVisor/Kata)
)

func (s Strength) String() string {
	switch s {
	case StrengthMicroVM:
		return "microVM"
	case StrengthContainer:
		return "container"
	default:
		return "none"
	}
}

// Driver is the interface every backend implements. P1 wires detection and the
// plan; the actual create/exec calls shell out to the underlying tool.
type Driver interface {
	Name() string
	Strength() Strength
	Available() bool
	// CreateArgs returns the argv the driver would run to create an isolated box
	// with the given image and name. Returned (not executed) so it is unit-testable
	// and so we can assert no host path is bind-mounted (W6).
	CreateArgs(name, image string) []string
}

// --- Apple container (macOS 26+, per-container VM) ---

type appleContainer struct{}

func (appleContainer) Name() string       { return "apple-container" }
func (appleContainer) Strength() Strength { return StrengthMicroVM }
func (appleContainer) Available() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	return exec.Command("container", "--version").Run() == nil
}
func (appleContainer) CreateArgs(name, image string) []string {
	// Per-container VM: the hardware/VM boundary IS the isolation, so shared-kernel
	// cap-drop hardening matters far less than for Docker. Egress control lives in
	// the guest (in-guest nftables per  - Apple `container` has
	// no native mandatory-proxy primitive). No -v/--mount of any host path (W1/W6).
	return []string{"container", "run", "-d", "--name", name, image, "sleep", "infinity"}
}

// --- Docker / Colima (shared-kernel container) ---

type dockerCLI struct{}

func (dockerCLI) Name() string       { return "docker" }
func (dockerCLI) Strength() Strength { return StrengthContainer }
func (dockerCLI) Available() bool {
	// `docker info` (not just `docker --version`) confirms a working daemon,
	// which is what Colima also provides.
	return exec.Command("docker", "info").Run() == nil
}
func (dockerCLI) CreateArgs(name, image string) []string {
	// Workload hardening + FAIL-CLOSED default ( E11, W6).
	// IMPORTANT: this is NOT itself the egress chokepoint - it is a
	// fail-closed default. The actual chokepoint is established at lifecycle time
	// (P2-4), which MUST attach the box only to an INTERNAL sandbox-net whose sole
	// route is the egress proxy/gateway; it must never `docker network connect` the
	// box to a NAT'd/open network. These args ensure that until that happens the box
	// has no egress, and that the workload itself can't re-route or escalate:
	//   --cap-drop ALL : empty bounding set (workload needs no caps as non-root)
	//   --security-opt no-new-privileges : no setuid escalation
	//   --user (non-root, numeric so it needs no /etc/passwd entry)
	//   --network none : no interfaces at all until the constrained attach
	//   NO -v host bind mount, NO docker.sock (W6) - never added here.
	return []string{
		"docker", "run", "-d", "--name", name,
		"--network", "none",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", "10001:10001",
		image, "sleep", "infinity",
	}
}

// candidates is the ordered set of drivers we know about, per OS.
func candidates() []Driver {
	switch runtime.GOOS {
	case "darwin":
		return []Driver{appleContainer{}, dockerCLI{}}
	default:
		// Linux/Windows drivers land in P3; Docker still works where present.
		return []Driver{dockerCLI{}}
	}
}

// Detect returns all available drivers, strongest first.
func Detect() []Driver {
	var avail []Driver
	for _, d := range candidates() {
		if d.Available() {
			avail = append(avail, d)
		}
	}
	sortStrongestFirst(avail)
	return avail
}

// Select picks the strongest available backend, or the one named by `want` if
// set (the `--backend` override, C2). Errors if nothing is available or the
// requested backend isn't present - fail loudly, never silently degrade (C3).
func Select(want string) (Driver, error) {
	return selectFrom(Detect(), want)
}

// selectFrom is the pure selection logic over a given available set, split out
// so it is unit-testable without depending on what's installed on the machine.
func selectFrom(avail []Driver, want string) (Driver, error) {
	if len(avail) == 0 {
		return nil, fmt.Errorf("no isolation backend available (install Apple `container` on macOS 26+, or Docker/Colima)")
	}
	if want != "" {
		for _, d := range avail {
			if d.Name() == want {
				return d, nil
			}
		}
		return nil, fmt.Errorf("requested backend %q not available; have: %s", want, names(avail))
	}
	return avail[0], nil
}

// sortStrongestFirst orders drivers strongest-first (exported logic for Detect
// and tests). Stable insertion sort; n is tiny.
func sortStrongestFirst(avail []Driver) {
	for i := 1; i < len(avail); i++ {
		for j := i; j > 0 && avail[j].Strength() > avail[j-1].Strength(); j-- {
			avail[j], avail[j-1] = avail[j-1], avail[j]
		}
	}
}

func names(ds []Driver) string {
	out := ""
	for i, d := range ds {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s(%s)", d.Name(), d.Strength())
	}
	return out
}

// NamesOf is the exported form for CLI/receipt reporting.
func NamesOf(ds []Driver) string { return names(ds) }
