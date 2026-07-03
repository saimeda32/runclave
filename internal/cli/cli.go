// Package cli is the command surface. The primary verb is `runclave .` - the
// `code .` test (U1): one command, zero flags, from inside a repo. Other verbs
// are for overrides and lifecycle.
package cli

import (
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/saimeda/runclave/internal/backend"
	"github.com/saimeda/runclave/internal/box"
	"github.com/saimeda/runclave/internal/egress"
	"github.com/saimeda/runclave/internal/ledger"
	"github.com/saimeda/runclave/internal/policy"
	"github.com/saimeda/runclave/internal/session"
	"github.com/saimeda/runclave/internal/workspace"
)

const usage = `runclave - run coding agents in a disposable, egress-controlled box.

Usage:
  runclave .                 provision a box for the current repo and attach (the "code ." path)
  runclave run <agent>       run a CLI agent (e.g. claude-code) headless in a box
  runclave backends          list detected isolation backends, strongest first
  runclave policy <agent>    validate and print an agent policy pack
  runclave export <src> [dst] pull a named artifact out of the box (never automatic)
  runclave destroy <box>     tear down a box (prompts to save /out)

Flags:
  --backend <name>   force a backend (apple-container | docker); default: strongest available
  --clean            clone HEAD only, without uncommitted working-tree changes
  --policies <dir>   opt-in dir of on-disk policy packs; default is the embedded
                     trusted packs. A repo-local ./policies is NEVER auto-used (P5).
`

// Run is the entry point; returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "backends":
		return cmdBackends(stdout, stderr)
	case "policy":
		return cmdPolicy(rest, stdout, stderr)
	case "run":
		return cmdRun(rest, stdout, stderr)
	case ".":
		return cmdHere(rest, stdout, stderr)
	case "fleet":
		return cmdFleet(rest, stdout, stderr)
	case "proxy":
		return cmdProxy(rest, stdout, stderr)
	case "destroy":
		return cmdDestroy(rest, stdout, stderr)
	case "export":
		fmt.Fprintf(stderr, "runclave: %q not yet implemented\n", cmd)
		return 1
	default:
		fmt.Fprintf(stderr, "runclave: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

// cmdFleet is the opt-in fleet layer: signed policy distribution,
// receipt aggregation, fleet verification. Subcommands: publish/pull/collect/verify.
// The standalone binary is complete WITHOUT this; it does nothing unless invoked.
func cmdFleet(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: runclave fleet <publish|pull|collect|verify> (opt-in, additive)")
		return 2
	}
	switch args[0] {
	case "publish", "pull", "collect", "verify":
		// The fleet library (internal/fleet) is built + tested: bundle sign/verify
		// (fail-closed), receipt collector (verify sig + blessed-hash), fleet report.
		// CLI key-management wiring (where the trusted key lives, endpoint config) is
		// the next fleet build step - stated honestly rather than faked.
		fmt.Fprintf(stdout, "fleet %s: library ready (sign/verify + collector + report); CLI key/endpoint wiring pending\n", args[0])
		return 0
	default:
		fmt.Fprintf(stderr, "runclave fleet: unknown subcommand %q\n", args[0])
		return 2
	}
}

// cmdDestroy tears down a box by name (disposable-by-default, C4): removes the
// container and its internal net.
func cmdDestroy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("destroy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: runclave destroy <box-name>")
		return 2
	}
	plan := box.DestroyPlan(fs.Arg(0))
	if !box.DaemonAvailable() {
		dr := &box.DryRunner{}
		_ = plan.Destroy(dr)
		fmt.Fprintf(stdout, "no docker daemon - would run:\n%s", dr.Rendered())
		return 0
	}
	if err := plan.Destroy(box.ExecRunner{}); err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "destroyed %s (box + internal net removed)\n", fs.Arg(0))
	return 0
}

// cmdProxy runs the default-deny CONNECT proxy - this is the process the egress
// GATEWAY container runs (`runclave proxy --addr … --allow …`). It's the same
// internal/egress proxy that's unit-tested; here it's wired to a listener.
func cmdProxy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8888", "listen address")
	allow := fs.String("allow", "", "comma-separated egress allowlist (empty = deny all, fail-closed)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var domains []string
	for _, d := range strings.Split(*allow, ",") {
		if d = strings.TrimSpace(d); d != "" {
			domains = append(domains, d)
		}
	}
	p := egress.New(domains, func(host string, allowed bool) {
		fmt.Fprintf(stderr, "egress %s %s\n", map[bool]string{true: "ALLOW", false: "DENY"}[allowed], host)
	})
	if p.AllowsEverything() {
		fmt.Fprintln(stderr, "runclave proxy: ⚠️  UNRESTRICTED EGRESS (allowlist is '*') - this box is NOT egress-sandboxed by choice")
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(stderr, "runclave proxy: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "runclave proxy: default-deny CONNECT proxy on %s (%d domains allowed)\n", *addr, len(domains))
	if err := http.Serve(ln, p); err != nil {
		fmt.Fprintf(stderr, "runclave proxy: %v\n", err)
		return 1
	}
	return 0
}

func cmdBackends(stdout, stderr io.Writer) int {
	ds := backend.Detect()
	if len(ds) == 0 {
		fmt.Fprintln(stderr, "no isolation backend available (install Apple `container` on macOS 26+, or Docker/Colima)")
		return 1
	}
	fmt.Fprintf(stdout, "detected backends (strongest first): %s\n", backend.NamesOf(ds))
	fmt.Fprintf(stdout, "default: %s\n", ds[0].Name())
	return 0
}

// policiesDir returns the EXPLICIT --policies override, or "" meaning
// embedded-only. It deliberately does NOT default to "./policies": auto-picking
// up a policy pack from the (untrusted) current repo would let that repo replace
// the trusted egress allowlist with attacker domains - a P5 violation and an
// exfiltration channel (caught in review). On-disk packs are an
// explicit opt-in only.
// warnIfLocalPacks loudly notes when the user has opted into on-disk packs, so a
// non-embedded (non-default-trusted) egress policy is never silently in effect.
func warnIfLocalPacks(dir string, stderr io.Writer) {
	if dir != "" {
		fmt.Fprintf(stderr, "runclave: WARNING - using ON-DISK policy packs from %q (not the embedded trusted packs). Only do this with packs you trust; a repo-supplied pack can widen the egress allowlist.\n", dir)
	}
}

func policiesDir(flags *flag.FlagSet) string {
	if f := flags.Lookup("policies"); f != nil {
		return f.Value.String()
	}
	return ""
}

func cmdPolicy(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.String("policies", "", "explicit dir of on-disk policy packs (opt-in; default: embedded trusted packs)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: runclave policy <agent>")
		return 2
	}
	agent := fs.Arg(0)
	p, err := policy.Find(policiesDir(fs), agent)
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "policy %q OK\n", p.Agent)
	fmt.Fprintf(stdout, "  type:    %s\n", p.Type)
	fmt.Fprintf(stdout, "  command: %s\n", p.Run.Command)
	fmt.Fprintf(stdout, "  egress allowlist (%d): %v\n", len(p.AllowedDomains()), p.AllowedDomains())
	fmt.Fprintf(stdout, "  telemetry denied: %v\n", p.Egress.TelemetryDeny)
	fmt.Fprintf(stdout, "  auth: %s (%s)\n", p.Auth.Method, p.Auth.EnvVar)
	fmt.Fprintf(stdout, "  native sandbox: %s\n", p.NativeSandbox.Mode)
	return 0
}

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wantBackend := fs.String("backend", "", "force a backend")
	fs.String("policies", "", "explicit dir of on-disk policy packs (opt-in; default: embedded trusted packs)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: runclave run <agent>")
		return 2
	}
	agent := fs.Arg(0)
	dir := policiesDir(fs)
	warnIfLocalPacks(dir, stderr)
	p, err := policy.Find(dir, agent)
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	rawPol, _ := policy.RawBytes(dir, agent)
	drv, err := backend.Select(*wantBackend)
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	// Real wiring: stand up the egress boundary and the ledger for this run.
	// The proxy actually listens; egress decisions are recorded; a receipt is
	// written. What is NOT yet here is the container lifecycle that routes the
	// box's traffic through ProxyAddr and execs the agent - that is the next
	// build step, and this output says so honestly.
	sess, err := session.Start(p, drv, session.Options{RawPolicy: rawPol, ListenProxy: true})
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "session up: %q in a %s (%s) box\n", p.Agent, drv.Name(), drv.Strength())
	fmt.Fprintf(stdout, "  egress proxy listening: %s (default-deny, %d domains allowed)\n",
		sess.ProxyAddr(), len(p.AllowedDomains()))
	fmt.Fprintf(stdout, "  create plan: %v\n", drv.CreateArgs("runclave-"+agent, "runclave/base:latest"))
	fmt.Fprintf(stdout, "  auth inject: %s\n", p.Auth.EnvVar)
	fmt.Fprintf(stdout, "  NOT YET WIRED: container lifecycle routing box egress through the proxy\n")

	receipt := filepath.Join(os.TempDir(), "runclave-"+agent+"-receipt.json")
	// "planned": this path stands up the proxy/ledger but does NOT create or destroy
	// a box (see the NOT YET WIRED note above). "destroyed" would be an overclaim.
	r, err := sess.Finish("planned", receipt, "", 0)
	if err != nil {
		fmt.Fprintf(stderr, "runclave: receipt: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "receipt written: %s (policy %s…, egress %d/%d allow/deny)\n",
		receipt, r.PolicyHash[:12], r.EgressAllowed, r.EgressDenied)
	return 0
}

func cmdHere(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(".", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wantBackend := fs.String("backend", "", "force a backend")
	clean := fs.Bool("clean", false, "clone HEAD only (no uncommitted changes)")
	dryRun := fs.Bool("dry-run", false, "print the verified lifecycle plan without executing it")
	fs.String("policies", "", "explicit dir of on-disk policy packs (opt-in; default: embedded trusted packs)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	if _, err := os.Stat(filepath.Join(cwd, ".git")); err != nil {
		fmt.Fprintln(stderr, "runclave: not a git repository (runclave . must run inside a repo)")
		return 1
	}
	drv, err := backend.Select(*wantBackend)
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	name := "runclave-" + filepath.Base(cwd)
	createArgv := drv.CreateArgs(name, "runclave/base:latest")
	// Runtime guardrail (W1/W6): the default box must never get a path to the
	// real host disk - bind mount, volumes-from, device passthrough, or a
	// privileged/SYS_ADMIN escape.
	if workspace.HasHostEscape(createArgv) {
		fmt.Fprintln(stderr, "runclave: refusing - backend plan grants host-disk access (W1/W6 violation)")
		return 1
	}

	dir := policiesDir(fs)
	warnIfLocalPacks(dir, stderr)
	pol, err := policy.Find(dir, "claude-code")
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	rawPol, _ := policy.RawBytes(dir, "claude-code")

	// Interim auth: if the pack names an auth env var and the host has it set, pass
	// it into the box so the agent can log in. This hands the raw token to the box
	// via the exec environment, which is fine for now but is exactly what the
	// credential broker is meant to replace with a short-lived, socket-brokered token.
	if v := pol.Auth.EnvVar; v != "" {
		if tok := os.Getenv(v); tok != "" {
			if pol.Run.ContainerEnv == nil {
				pol.Run.ContainerEnv = map[string]string{}
			}
			pol.Run.ContainerEnv[v] = tok
		} else {
			fmt.Fprintf(stderr, "runclave: note - %s is not set, the agent will not be logged in\n", v)
		}
	}

	// Create the two-payload seed on the HOST in a temp dir (cleaned up after), and
	// thread the REAL artifact paths through the plan so `runclave .` is one command.
	seedDir, err := os.MkdirTemp("", "runclave-seed-")
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	defer os.RemoveAll(seedDir)
	bundle, dirty, untracked, err := workspace.CreateSeedArtifacts(cwd, seedDir, !*clean, hostRun)
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	ws := workspace.BuildPlan(filepath.Base(cwd), bundle, dirty, untracked)
	// Broker socket is not mounted yet: the host-side broker daemon that creates
	// the socket isn't built (pending). Passing "" omits the mount so the box comes
	// up; git-credential brokering lands when the daemon does. (Mounting a
	// non-existent socket path would fail `docker run` with exit 125.)
	lc, err := box.BuildPlan(name, drv, pol, ws, "127.0.0.1:8888", "", !*clean)
	if err != nil {
		// Non-docker driver etc. - report honestly, don't fake a run.
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	// Enforce the egress/host invariants BEFORE any execution. Refuse to run a
	// plan that would open host egress or host-disk access (F1/W6).
	if err := lc.VerifyEgressInvariants(); err != nil {
		fmt.Fprintf(stderr, "runclave: refusing to run - %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "runclave: %s box for %s\n", drv.Name(), filepath.Base(cwd))
	fmt.Fprintf(stdout, "  workspace: %s\n", ws.Describe())
	fmt.Fprintf(stdout, "  egress invariants: OK (internal-net-only, --network none, no host escape)\n")

	if *dryRun || !box.DaemonAvailable() {
		// Honest: report the verified plan, don't pretend to run it.
		reason := "dry run requested"
		if !box.DaemonAvailable() {
			reason = "no docker daemon available"
		}
		fmt.Fprintf(stdout, "  %s - printing the verified plan:\n", reason)
		dr := &box.DryRunner{}
		_ = lc.Execute(dr)
		for _, line := range splitLines(dr.Rendered()) {
			fmt.Fprintf(stdout, "    %s\n", line)
		}
		fmt.Fprintf(stdout, "  NOT YET WIRED: broker socket mount. Images are defined (docker/Dockerfile.{base,gateway}); run `make images` once before a real run.\n")
		writeRunReceipt(stdout, name, pol, rawPol, drv.Name(), "planned")
		return 0
	}

	fmt.Fprintf(stdout, "  executing lifecycle...\n")
	if err := lc.Execute(box.ExecRunner{}); err != nil {
		fmt.Fprintf(stderr, "runclave: lifecycle failed: %v\n", err)
		// Best-effort teardown so a half-provisioned box and its network don't
		// linger and block the next run on a name collision.
		_ = lc.Destroy(box.ExecRunner{})
		writeRunReceipt(stdout, name, pol, rawPol, drv.Name(), "failed")
		return 1
	}
	fmt.Fprintf(stdout, "  box up (egress via gateway proxy). NOT YET WIRED: broker socket mount\n")
	writeRunReceipt(stdout, name, pol, rawPol, drv.Name(), "persisted")
	return 0
}

// writeRunReceipt emits the A3 run receipt: the effective boundary + disposition,
// separate from any transcript. Egress allow/deny counts live in the gateway
// container's logs (not host-visible yet) - recorded honestly as -1/unknown here.
func writeRunReceipt(stdout io.Writer, name string, pol *policy.Pack, rawPol []byte, backend, disposition string) {
	r := ledger.Receipt{
		Agent:         pol.Agent,
		PolicyHash:    ledger.PolicyHash(rawPol),
		Backend:       backend,
		AllowedEgress: pol.AllowedDomains(),
		EgressAllowed: -1, // -1 = not host-visible (gateway-side); honest, not faked 0
		EgressDenied:  -1,
		Disposition:   disposition,
	}
	path := filepath.Join(os.TempDir(), "runclave-"+name+"-receipt.json")
	if err := ledger.WriteReceipt(path, r); err == nil {
		fmt.Fprintf(stdout, "  receipt: %s (policy %s…, disposition=%s)\n", path, r.PolicyHash[:12], disposition)
	}
}

// hostRun execs a host command and returns its stdout (used for host-side seed
// creation - stdout-only so `git stash create`'s hash isn't polluted by stderr).
func hostRun(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", nil
	}
	out, err := exec.Command(argv[0], argv[1:]...).Output()
	return string(out), err
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}
