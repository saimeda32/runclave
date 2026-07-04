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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/saimeda/runclave/internal/backend"
	"github.com/saimeda/runclave/internal/box"
	"github.com/saimeda/runclave/internal/broker"
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
  runclave brokerd           host-side credential daemon: lends short-lived, repo-scoped git tokens to a box
  runclave credential <op>   in-box git credential helper (talks to the broker; not run by hand)

Flags:
  --backend <name>   force a backend (apple-container | docker); default: strongest available
  --clean            clone HEAD only, without uncommitted working-tree changes
  --shell            drop into an interactive shell in the box instead of running
                     the agent (same isolation and egress boundary)
  --login            mount this agent's existing host login (read-only) so it starts
                     logged in; shares a long-lived credential, off by default
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
	case "credential":
		return cmdCredential(rest, stdout, stderr)
	case "brokerd":
		return cmdBrokerd(rest, stdout, stderr)
	case "export":
		fmt.Fprintf(stderr, "runclave: %q not yet implemented\n", cmd)
		return 1
	default:
		fmt.Fprintf(stderr, "runclave: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

// cmdCredential is the IN-BOX git credential helper. git invokes it as
// `runclave credential <get|store|erase>` (configured via credential.helper).
// It forwards the request to the host broker over $RUNCLAVE_BROKER_SOCK and
// relays the short-lived answer. The box holds no long-lived secret: without the
// socket it prints nothing and git falls back, which is the fail-closed default.
func cmdCredential(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: runclave credential <get|store|erase>")
		return 2
	}
	op := args[0]
	sock := os.Getenv("RUNCLAVE_BROKER_SOCK")
	if sock == "" {
		// No broker wired: emit nothing. git treats an empty answer as "no
		// credential" and moves on, rather than us inventing one.
		return 0
	}
	if err := broker.Query(sock, op, os.Stdin, stdout); err != nil {
		// A broker error must NOT surface a credential; stay silent so git falls
		// back instead of proceeding with a half-answer.
		fmt.Fprintf(stderr, "runclave credential: %v\n", err)
		return 0
	}
	return 0
}

// cmdBrokerd is the HOST-SIDE credential daemon. It listens on a per-session unix
// socket and answers git credential requests from inside the box with a
// short-lived, repo-scoped GitHub App token. The App private key is read here on
// the host, once, and never leaves; the box only ever sees the minted token.
//
// The socket path it binds is the same path handed to the box (mounted read-only
// at a runclave-owned location), so authz stays host-side and per-session.
func cmdBrokerd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("brokerd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "", "unix socket path to listen on (per session)")
	repo := fs.String("repo", "", "the ONLY repo this session may obtain creds for, e.g. github.com/owner/name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *socket == "" || *repo == "" {
		fmt.Fprintln(stderr, "usage: runclave brokerd --socket <path> --repo <host/owner/name>")
		return 2
	}
	// Guard the path we are about to delete + bind. Require a .sock name, and if a
	// file is already there, refuse unless it is itself a socket. This stops a
	// mistyped --socket (e.g. a private key path) from being removed - the earlier
	// "runclave-owned, only removes our own socket" claim was not actually enforced.
	if !strings.HasSuffix(*socket, ".sock") {
		fmt.Fprintln(stderr, "runclave brokerd: --socket must be a path ending in .sock")
		return 2
	}
	minter, err := githubAppMinterFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "runclave brokerd: %v\n", err)
		return 1
	}
	// Keep the socket's directory owner-only too, so the socket can't be reached
	// (or a stale one swapped) by another local user via the parent dir.
	if err := os.MkdirAll(filepath.Dir(*socket), 0o700); err != nil {
		fmt.Fprintf(stderr, "runclave brokerd: socket dir: %v\n", err)
		return 1
	}
	// Clear a stale socket from a crashed prior run so Listen can bind. Only remove
	// it if what is there is actually a socket - never clobber a regular file.
	if fi, statErr := os.Lstat(*socket); statErr == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			fmt.Fprintf(stderr, "runclave brokerd: refusing - %s exists and is not a socket\n", *socket)
			return 1
		}
		_ = os.Remove(*socket)
	}
	// Create the socket 0600 ATOMICALLY: set a restrictive umask across Listen so
	// there is no window where another local user can connect before a chmod. A
	// post-hoc chmod leaves the socket world-reachable between bind and chmod.
	oldMask := syscall.Umask(0o177)
	l, err := net.Listen("unix", *socket)
	syscall.Umask(oldMask)
	if err != nil {
		fmt.Fprintf(stderr, "runclave brokerd: listen: %v\n", err)
		return 1
	}
	defer l.Close()
	// Belt-and-suspenders: pin perms explicitly too (umask only clears bits).
	_ = os.Chmod(*socket, 0o600)
	sess := &broker.Session{ID: filepath.Base(*socket), Repo: *repo, Minter: minter}
	// Surface repo mismatches live (a compromised box asking for a different repo)
	// instead of letting them pile up unread in the session.
	sess.LogAnomaly = func(m string) { fmt.Fprintf(stderr, "runclave brokerd: anomaly: %s\n", m) }
	fmt.Fprintf(stdout, "runclave brokerd: serving %s for %s\n", *socket, *repo)
	if err := broker.Serve(l, sess); err != nil {
		fmt.Fprintf(stderr, "runclave brokerd: %v\n", err)
		return 1
	}
	return 0
}

// stdinIsTerminal reports whether stdin is a real terminal, so `docker exec` gets
// -t only when a pseudo-terminal makes sense (piped/redirected stdin would make
// `-t` fail). Uses the char-device heuristic to avoid an external terminal dep.
func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// githubAppConfigured reports whether all three GitHub App settings are present,
// which is the signal to auto-start the broker for `runclave .`.
func githubAppConfigured() bool {
	return os.Getenv("RUNCLAVE_GH_APP_ID") != "" &&
		os.Getenv("RUNCLAVE_GH_INSTALLATION_ID") != "" &&
		os.Getenv("RUNCLAVE_GH_PRIVATE_KEY") != ""
}

// deriveRepo turns the repo's origin remote into the "github.com/owner/name" scope
// the broker mints for. Returns "" (not an error) when there is no usable github
// origin, so the caller simply skips brokering. Only github.com is supported today.
// Parsing is exact: the host must be exactly github.com (any port or userinfo is
// dropped, and a look-alike like github.com.evil.com is rejected), and the path
// must be exactly owner/name - so a crafted origin can never mint for a scope the
// user did not intend; the worst case is "" (skip).
func deriveRepo(cwd string) string {
	out, err := exec.Command("git", "-C", cwd, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	raw := strings.TrimSuffix(strings.TrimSpace(string(out)), ".git")
	var host, path string
	switch {
	case strings.Contains(raw, "://"):
		u, perr := url.Parse(raw)
		if perr != nil {
			return ""
		}
		host = u.Hostname() // drops any :port and user@
		path = u.Path
	case strings.Contains(raw, ":"):
		// scp-like: [user@]github.com:owner/name
		hostpart, p, _ := strings.Cut(raw, ":")
		if at := strings.LastIndex(hostpart, "@"); at >= 0 {
			hostpart = hostpart[at+1:]
		}
		host, path = hostpart, p
	default:
		return ""
	}
	if host != "github.com" {
		return ""
	}
	path = strings.Trim(path, "/")
	if path == "" || strings.Count(path, "/") != 1 {
		return "" // must be exactly owner/name
	}
	return "github.com/" + path
}

// sessionBrokerSocket returns a per-session socket path inside a runclave-owned,
// owner-only directory under the user's runtime or cache dir. This resolves where
// the socket LIVES across operating systems (no root or /run needed). Caveat kept
// honest: on the macOS Docker VM, bind-mounting a HOST unix socket into the box
// crosses the VM's file-sharing layer and is not verified here; it works on native
// Linux docker. So this settles the path, not a proven macOS end-to-end mount.
// Returns the socket path and a cleanup that removes the session dir.
func sessionBrokerSocket(name string) (string, func(), error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		c, err := os.UserCacheDir()
		if err != nil {
			return "", nil, fmt.Errorf("cannot find a runtime/cache dir for the broker socket: %w", err)
		}
		base = c
	}
	dir := filepath.Join(base, "runclave", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", nil, err
	}
	sock := filepath.Join(dir, "broker.sock")
	return sock, func() { _ = os.RemoveAll(dir) }, nil
}

// startBrokerd launches `runclave brokerd` as a child on the given socket, waits
// briefly for the socket to appear, and returns a stop func. If the daemon exits
// early (e.g. a misconfigured App), it returns an error so the caller runs without
// brokered git rather than mounting a dead socket.
func startBrokerd(sock, repo string, stderr io.Writer) (func(), error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "brokerd", "--socket", sock, "--repo", repo)
	// Hand the child ONLY what brokerd needs: the App config plus PATH. Passing the
	// whole environment would needlessly give the daemon the agent's own token etc.
	// The private key is a file PATH here; brokerd reads it on the host, never argv.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"RUNCLAVE_GH_APP_ID=" + os.Getenv("RUNCLAVE_GH_APP_ID"),
		"RUNCLAVE_GH_INSTALLATION_ID=" + os.Getenv("RUNCLAVE_GH_INSTALLATION_ID"),
		"RUNCLAVE_GH_PRIVATE_KEY=" + os.Getenv("RUNCLAVE_GH_PRIVATE_KEY"),
	}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// One goroutine owns Wait (reaps the child); stop() only signals it to exit.
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	stop := func() { _ = cmd.Process.Kill() }
	// Wait for the socket to appear, but bail immediately if the daemon exits first
	// (a bad key path/format makes brokerd fail closed before it ever listens).
	for i := 0; i < 40; i++ {
		if _, statErr := os.Stat(sock); statErr == nil {
			return stop, nil
		}
		select {
		case <-exited:
			return nil, fmt.Errorf("broker daemon exited before it was ready (check the GitHub App config)")
		case <-time.After(50 * time.Millisecond):
		}
	}
	stop()
	return nil, fmt.Errorf("broker daemon did not come up in time")
}

// githubAppMinterFromEnv builds the production minter from the operator's
// configuration. Fail-closed: any missing piece is an error, never a silent
// fallback to a long-lived secret.
func githubAppMinterFromEnv() (*broker.GitHubAppMinter, error) {
	appID := os.Getenv("RUNCLAVE_GH_APP_ID")
	instID := os.Getenv("RUNCLAVE_GH_INSTALLATION_ID")
	keyPath := os.Getenv("RUNCLAVE_GH_PRIVATE_KEY")
	if appID == "" || instID == "" || keyPath == "" {
		return nil, fmt.Errorf("GitHub App not configured (set RUNCLAVE_GH_APP_ID, RUNCLAVE_GH_INSTALLATION_ID, RUNCLAVE_GH_PRIVATE_KEY)")
	}
	pem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	key, err := broker.ParseRSAKey(pem)
	if err != nil {
		return nil, err
	}
	return &broker.GitHubAppMinter{AppID: appID, InstallationID: instID, Key: key}, nil
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
		fmt.Fprintf(stderr, "runclave: WARNING - using ON-DISK policy packs from %q (not the embedded trusted packs). Only do this with packs you trust: a repo-supplied pack can widen the egress allowlist AND name an arbitrary box image, which the host pulls over its own network (outside the sandbox) and runs as the box.\n", dir)
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
	login := fs.Bool("login", false, "mount this agent's existing host login (read-only) so it starts logged in; shares a long-lived credential with the box")
	shell := fs.Bool("shell", false, "drop into an interactive shell in the box instead of running the agent (same isolation and egress boundary)")
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

	// Interim auth: if the pack names an auth env var, the exec step passes it to the
	// box BY NAME (`docker exec -e NAME`), so docker reads the value from runclave's
	// own environment at exec time. The token value is never placed on an argv or in
	// a rendered plan, so it does not leak to host `ps` or a --dry-run print. It does
	// still enter the box's process env for the agent to use; giving the box only a
	// short-lived, socket-brokered token instead is what the credential broker adds.
	if v := pol.Auth.EnvVar; v != "" && os.Getenv(v) == "" {
		fmt.Fprintf(stderr, "runclave: note - %s is not set, the agent will not be logged in\n", v)
	}

	// Create the two-payload seed on the HOST in a temp dir (cleaned up after), and
	// thread the REAL artifact paths through the plan so `runclave .` is one command.
	seedDir, err := os.MkdirTemp("", "runclave-seed-")
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	// Host-side cleanups run on normal return AND on Ctrl-C. Go does not run defers
	// on a signal, so without this an interrupted run would leave the seed dir and
	// the broker socket dir behind. (The detached box is intentionally persistent;
	// tear a lingering one down with `runclave destroy`.)
	var cleanupOnce sync.Once
	var cleanups []func()
	runCleanups := func() {
		cleanupOnce.Do(func() {
			for i := len(cleanups) - 1; i >= 0; i-- {
				cleanups[i]()
			}
		})
	}
	defer runCleanups()
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		runCleanups()
		os.Exit(130)
	}()
	cleanups = append(cleanups, func() { _ = os.RemoveAll(seedDir) })
	bundle, dirty, untracked, err := workspace.CreateSeedArtifacts(cwd, seedDir, !*clean, hostRun)
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	ws := workspace.BuildPlan(filepath.Base(cwd), bundle, dirty, untracked)
	// Opt-in login sharing: only when --login is passed do we mount this agent's
	// existing host login (read-only) so it starts already authenticated.
	loginMounts, loginHostRoot, err := buildLoginMounts(pol, *login, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	var loginShared []string // for the receipt audit trail
	for _, m := range loginMounts {
		loginShared = append(loginShared, m.HostPath)
	}
	// Git brokering: if a GitHub App is configured and the repo has a github origin,
	// auto-start `runclave brokerd` on a per-session, user-owned socket and mount it,
	// so the box's git gets short-lived tokens and no long-lived secret enters it. If
	// the App isn't configured, or there's no origin, we simply run without it. On a
	// --dry-run we show the mount but don't spawn a daemon.
	brokerSock := ""
	if githubAppConfigured() {
		repo := deriveRepo(cwd)
		if repo == "" {
			fmt.Fprintf(stderr, "runclave: broker: no github.com origin remote, running without brokered git\n")
		} else if sock, cleanup, serr := sessionBrokerSocket(name); serr != nil {
			fmt.Fprintf(stderr, "runclave: broker: %v; running without brokered git\n", serr)
		} else if *dryRun {
			brokerSock = sock // show the mount in the plan; don't spawn a daemon
			cleanups = append(cleanups, cleanup)
		} else if stop, berr := startBrokerd(sock, repo, stderr); berr != nil {
			fmt.Fprintf(stderr, "runclave: broker: %v; running without brokered git\n", berr)
			cleanup()
		} else {
			brokerSock = sock
			// It's up and listening; tokens are minted per request (a wrong App or
			// missing repo access would surface only then, and git falls back).
			fmt.Fprintf(stderr, "runclave: broker: up for %s (short-lived tokens, minted on demand)\n", repo)
			cleanups = append(cleanups, func() { stop(); cleanup() })
		}
	}
	lc, err := box.BuildPlan(name, drv, pol, ws, "127.0.0.1:8888", brokerSock, !*clean, loginMounts, loginHostRoot)
	if err != nil {
		// Non-docker driver etc. - report honestly, don't fake a run.
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	// --shell: same box, same egress boundary, same seed - just an interactive shell
	// in place of the headless agent exec. The shell is the pack's (default sh, which
	// every base image has); -t is allocated only when stdin is a real terminal.
	if *shell {
		sh := pol.Run.Shell
		if sh == "" {
			sh = "sh"
		}
		lc.SetInteractiveShell(sh, stdinIsTerminal())
		if pol.Auth.EnvVar != "" && os.Getenv(pol.Auth.EnvVar) != "" {
			fmt.Fprintf(stderr, "runclave: note - the shell has the agent's auth token in its environment (%s); anyone at this prompt can read it\n", pol.Auth.EnvVar)
		}
	}
	// Enforce the egress/host invariants BEFORE any execution. Refuse to run a
	// plan that would open host egress or host-disk access (F1/W6).
	if err := lc.VerifyEgressInvariants(); err != nil {
		fmt.Fprintf(stderr, "runclave: refusing to run - %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "runclave: %s box for %s\n", drv.Name(), filepath.Base(cwd))
	fmt.Fprintf(stdout, "  workspace: %s\n", ws.Describe())
	fmt.Fprintf(stdout, "  egress invariants: OK (box on the internal net only, egress via gateway, no host escape)\n")

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
		if brokerSock == "" {
			fmt.Fprintf(stdout, "  git broker: off (set RUNCLAVE_GH_APP_ID/INSTALLATION_ID/PRIVATE_KEY and add a github origin to enable). Images: run `make images` once before a real run.\n")
		} else {
			fmt.Fprintf(stdout, "  git broker: would serve short-lived tokens on %s (daemon not started for a dry run)\n", brokerSock)
		}
		writeRunReceipt(stdout, name, pol, rawPol, drv.Name(), "planned", loginShared...)
		return 0
	}

	if *shell {
		fmt.Fprintf(stdout, "  box up. dropping you into a shell (type 'exit' to leave; the box persists)...\n")
	} else {
		fmt.Fprintf(stdout, "  executing lifecycle...\n")
	}
	if err := lc.Execute(box.ExecRunner{}); err != nil {
		fmt.Fprintf(stderr, "runclave: lifecycle failed: %v\n", err)
		// Best-effort teardown so a half-provisioned box and its network don't
		// linger and block the next run on a name collision.
		_ = lc.Destroy(box.ExecRunner{})
		writeRunReceipt(stdout, name, pol, rawPol, drv.Name(), "failed", loginShared...)
		return 1
	}
	if *shell {
		fmt.Fprintf(stdout, "  shell session ended (box persists; `runclave destroy %s` to remove)\n", name)
	} else {
		fmt.Fprintf(stdout, "  box up (egress via gateway proxy)\n")
	}
	if brokerSock != "" {
		// Honest lifetime: the broker served the agent's git DURING this run and
		// stops now, on return. The box is detached and persists; if you re-enter it
		// later, git is not brokered until you run through runclave again.
		fmt.Fprintf(stdout, "  git broker: served this run; stops now (box persists without it)\n")
	}
	writeRunReceipt(stdout, name, pol, rawPol, drv.Name(), "persisted", loginShared...)
	return 0
}

// buildLoginMounts turns the pack's declared login paths into read-only box
// mounts, but ONLY when the user passed --login. It is deliberately strict: each
// path must resolve (following symlinks) to somewhere under the user's own home,
// so a pack cannot ask to mount /etc, /, or another user's files, and a dotfile
// that is a symlink pointing outside home cannot smuggle a host path in (docker
// binds the symlink's TARGET, so we confine on the resolved target). A missing
// path is skipped with a note rather than failing the run. It returns the home
// root so the box layer can independently re-confine every mount, and warns loudly
// that a long-lived, unscoped credential is being shared.
func buildLoginMounts(pol *policy.Pack, want bool, stderr io.Writer) ([]box.LoginMount, string, error) {
	if !want {
		return nil, "", nil
	}
	if len(pol.Auth.LoginPaths) == 0 {
		fmt.Fprintf(stderr, "runclave: --login given but the %s pack declares no login paths; nothing to share\n", pol.Agent)
		return nil, "", nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil, "", fmt.Errorf("--login: cannot resolve your home directory")
	}
	// Canonicalize home too, so the "resolved target under home" check below compares
	// like with like even when home itself sits behind a symlink (e.g. /var -> /private/var).
	if r, e := filepath.EvalSymlinks(home); e == nil {
		home = r
	}
	home = filepath.Clean(home)
	underHome := func(p string) bool {
		return p == home || strings.HasPrefix(p, home+string(os.PathSeparator))
	}
	var mounts []box.LoginMount
	var shared []string
	for _, raw := range pol.Auth.LoginPaths {
		host := raw
		if host == "~" {
			host = home
		} else if strings.HasPrefix(host, "~/") {
			host = filepath.Join(home, host[2:])
		}
		host = filepath.Clean(host)
		if !filepath.IsAbs(host) {
			return nil, "", fmt.Errorf("--login: pack login path %q did not resolve to an absolute path", raw)
		}
		// The declared (link) path must itself be under home...
		if !underHome(host) {
			return nil, "", fmt.Errorf("--login: pack login path %q is outside your home (%s); refusing", raw, home)
		}
		if _, statErr := os.Lstat(host); statErr != nil {
			fmt.Fprintf(stderr, "runclave: --login: %s not found on this machine, skipping (are you logged in?)\n", host)
			continue
		}
		// ...and so must the RESOLVED target, because docker follows a symlinked
		// bind source host-side. Without this, ~/.claude -> /etc would mount /etc.
		real, evErr := filepath.EvalSymlinks(host)
		if evErr != nil {
			fmt.Fprintf(stderr, "runclave: --login: cannot resolve %s, skipping (%v)\n", host, evErr)
			continue
		}
		real = filepath.Clean(real)
		if !underHome(real) {
			return nil, "", fmt.Errorf("--login: pack login path %q resolves to %q, outside your home (%s); refusing", raw, real, home)
		}
		// Mount the RESOLVED source (what docker binds anyway) but keep the box
		// destination at the path the agent expects (derived from the declared name).
		boxPath := box.BoxHome + strings.TrimPrefix(host, home)
		if boxPath == box.BoxHome { // the declared path was home itself: would over-share
			return nil, "", fmt.Errorf("--login: pack login path %q is your whole home; refusing", raw)
		}
		mounts = append(mounts, box.LoginMount{HostPath: real, BoxPath: boxPath})
		shared = append(shared, real)
	}
	if len(mounts) > 0 {
		fmt.Fprintf(stderr, "runclave: WARNING - --login shares your real %s login (read-only) with the box: %s\n"+
			"  This is a long-lived, unscoped credential, not a short-lived brokered token. If the box is\n"+
			"  compromised the credential can be used until you rotate it. Prefer a scoped token when you can.\n",
			pol.Agent, strings.Join(shared, ", "))
	}
	return mounts, home, nil
}

// writeRunReceipt emits the A3 run receipt: the effective boundary + disposition,
// separate from any transcript. Egress allow/deny counts live in the gateway
// container's logs (not host-visible yet) - recorded honestly as -1/unknown here.
func writeRunReceipt(stdout io.Writer, name string, pol *policy.Pack, rawPol []byte, backend, disposition string, loginShared ...string) {
	r := ledger.Receipt{
		Agent:         pol.Agent,
		PolicyHash:    ledger.PolicyHash(rawPol),
		Backend:       backend,
		AllowedEgress: pol.AllowedDomains(),
		EgressAllowed: -1, // -1 = not host-visible (gateway-side); honest, not faked 0
		EgressDenied:  -1,
		LoginShared:   loginShared,
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
