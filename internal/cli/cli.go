// Package cli is the command surface. The primary verb is `runclave .` - the
// `code .` test (U1): one command, zero flags, from inside a repo. Other verbs
// are for overrides and lifecycle.
package cli

import (
	"crypto/ed25519"
	"crypto/rand"
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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/saimeda/runclave/internal/backend"
	"github.com/saimeda/runclave/internal/box"
	"github.com/saimeda/runclave/internal/broker"
	"github.com/saimeda/runclave/internal/egress"
	"github.com/saimeda/runclave/internal/ide"
	"github.com/saimeda/runclave/internal/ledger"
	"github.com/saimeda/runclave/internal/policy"
	"github.com/saimeda/runclave/internal/workspace"
)

const usage = `runclave - run coding agents in a disposable, egress-controlled box.

Usage:
  runclave . [flags] [task]  provision a box for the current repo and run the agent, optionally on a
                             task prompt (e.g. runclave . --agent codex "fix the flaky test").
                             Flags must come before the task.
  runclave run <agent> [task] run an agent on this repo (alias for the . command with --agent)
  runclave backends          list detected isolation backends, strongest first
  runclave policy <agent>    validate and print an agent policy pack
  runclave export <box> <path> [dst]  copy a file out of a box (explicit; never automatic)
  runclave destroy <box>     tear down a box (box, gateway, and its network)
  runclave ls                list running runclave boxes
  runclave snapshot <box>    commit a box to a reusable image (fork/rollback via --image)
  runclave pause <box>       freeze an idle box's processes (undo with runclave resume)
  runclave doctor            check docker + images are ready (and not stale)
  runclave open <box>        attach your editor (VS Code/Cursor) to a running box (the "code ." experience)
  runclave verify <receipt>  check a signed run receipt (.dsse.json) offline; fail-closed on tamper
  runclave version           print the build version
  runclave brokerd           host-side credential daemon: lends short-lived, repo-scoped git tokens to a box
  runclave credential <op>   in-box git credential helper (talks to the broker; not run by hand)

Flags:
  --agent <name>     which agent policy pack to run (default claude-code; e.g. gemini-cli)
  --image <ref>      override the box image (e.g. runclave/all, the combined image with
                     every agent CLI); default is the agent's own minimal image
  --backend <name>   force a backend (docker; apple-container planned); default: docker
  --clean            clone HEAD only, without uncommitted working-tree changes
  --shell            drop into an interactive shell in the box instead of running
                     the agent (same isolation and egress boundary)
  --rm               tear the box and its network down when the run (or shell) exits,
                     leaving nothing behind; the signed receipt is the only artifact
  --login            mount this agent's existing host login (read-only) so it starts
                     logged in; shares a long-lived credential, off by default
  --policies <dir>   opt-in dir of on-disk policy packs; default is the embedded
                     trusted packs. A repo-local ./policies is NEVER auto-used (P5).
`

// Version is the build version, stamped via -ldflags "-X ...cli.Version=...".
// Defaults to "dev" for a plain `go build`.
var Version = "dev"

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
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "runclave %s\n", Version)
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
	case "verify":
		return cmdVerify(rest, stdout, stderr)
	case "probe":
		return cmdProbe(rest, stdout, stderr)
	case "lockdown":
		return cmdLockdown(rest, stdout, stderr)
	case "open":
		return cmdOpen(rest, stdout, stderr)
	case "ls":
		return cmdLs(rest, stdout, stderr)
	case "snapshot":
		return cmdSnapshot(rest, stdout, stderr)
	case "pause":
		return cmdPauseResume(rest, stdout, stderr, true)
	case "resume":
		return cmdPauseResume(rest, stdout, stderr, false)
	case "doctor":
		return cmdDoctor(rest, stdout, stderr)
	case "export":
		return cmdExport(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "runclave: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

// defaultWorkspacePath returns the in-box repo path for a box named runclave-<repo>.
// The seed clones the repo to BoxHome/<repo>, so that is where the editor should open.
func defaultWorkspacePath(boxName string) string {
	return box.BoxHome + "/" + strings.TrimPrefix(boxName, "runclave-")
}

// pickIDE resolves the requested IDE (or autodetects) to (kind, binary-on-PATH).
// binary is "" when no CLI is found, so the caller can fall back to printing the URI.
func pickIDE(want string) (ide.Kind, string) {
	find := func(bin string) string {
		if p, err := exec.LookPath(bin); err == nil {
			return p
		}
		return ""
	}
	switch want {
	case "cursor":
		return ide.Cursor, find("cursor")
	case "vscode", "code", "":
		if b := find("code"); b != "" {
			return ide.VSCode, b
		}
		if want == "" { // autodetect: fall back to cursor if code is absent
			if b := find("cursor"); b != "" {
				return ide.Cursor, b
			}
		}
		return ide.VSCode, ""
	default:
		return ide.VSCode, ""
	}
}

// cmdOpen attaches the user's editor (VS Code or Cursor) to a RUNNING box - the
// `code .` experience against the sandbox. It builds the vscode-remote:// attach URI
// and hands it to the IDE CLI. This is a CONTROL channel only: the box's isolation
// and egress boundary were established at creation and are unchanged; the editor
// server runs INSIDE the box, and attaching adds no host mount or network path.
func cmdOpen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ideFlag := fs.String("ide", "", "which IDE: vscode|cursor (default: autodetect code/cursor on PATH)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: runclave open [--ide vscode|cursor] <box> [in-box-path]")
		return 2
	}
	// Validate --ide instead of silently falling back to vscode on a typo.
	switch *ideFlag {
	case "", "vscode", "code", "cursor":
	default:
		fmt.Fprintf(stderr, "runclave open: unknown --ide %q (use vscode or cursor)\n", *ideFlag)
		return 2
	}
	boxName := fs.Arg(0)
	// The box must be running; grab its id (Cursor keys attach on the id) and the
	// networks it's on, so we can confirm this is a RUNCLAVE box before claiming it's
	// isolated. Attaching to some arbitrary container and printing "isolated box,
	// egress unchanged" would be a false guarantee.
	out, err := exec.Command("docker", "inspect", "-f",
		"{{.Id}}|{{.State.Running}}|{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}", boxName).Output()
	if err != nil {
		fmt.Fprintf(stderr, "runclave open: no such box %q (bring one up with `runclave .`)\n", boxName)
		return 1
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 3)
	if len(parts) != 3 || parts[1] != "true" {
		fmt.Fprintf(stderr, "runclave open: box %q is not running\n", boxName)
		return 1
	}
	id := parts[0]
	onRunclaveNet := false
	for _, n := range strings.Fields(parts[2]) {
		if strings.HasPrefix(n, "runclave-net-") {
			onRunclaveNet = true
		}
	}
	if !onRunclaveNet {
		fmt.Fprintf(stderr, "runclave open: %q is not a runclave box (not on a runclave-net-* network); refusing to attach and claim isolation it may not have\n", boxName)
		return 1
	}
	wp := defaultWorkspacePath(boxName)
	if fs.NArg() >= 2 {
		wp = fs.Arg(1)
	}
	kind, binary := pickIDE(*ideFlag)
	if binary == "" {
		uri, uerr := ide.AttachURI(kind, boxName, id, wp)
		if uerr != nil {
			fmt.Fprintf(stderr, "runclave open: %v\n", uerr)
			return 1
		}
		fmt.Fprintf(stdout, "No code/cursor CLI found on PATH. Open this in your editor (Dev Containers / Remote):\n  %s\n", uri)
		return 0
	}
	argv, err := ide.AttachArgv(kind, binary, boxName, id, wp)
	if err != nil {
		fmt.Fprintf(stderr, "runclave open: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "runclave: attaching %s to the isolated box %s at %s\n", filepath.Base(binary), boxName, wp)
	fmt.Fprintf(stdout, "  control channel only: the box's isolation and egress boundary are unchanged; the editor server runs inside the box\n")
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		uri, _ := ide.AttachURI(kind, boxName, id, wp)
		fmt.Fprintf(stderr, "runclave open: launching %s failed: %v\n  open this URI manually: %s\n", binary, err, uri)
		return 1
	}
	return 0
}

// runclaveBoxExists reports whether a container by this name exists and is a
// runclave box (name prefix). Returns the running-state too.
func runclaveBoxExists(name string) (running, ok bool) {
	if !strings.HasPrefix(name, "runclave-") {
		return false, false
	}
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(out)) == "true", true
}

// cmdSnapshot commits a box's filesystem to a reusable image, so you can fork or
// roll back to it later with `runclave . --image <tag>`. The CubeSandbox
// snapshot/clone idea, done with docker commit (coarser than CoW, but real).
func cmdSnapshot(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: runclave snapshot <box> [image-tag]")
		return 2
	}
	boxName := args[0]
	if _, ok := runclaveBoxExists(boxName); !ok {
		fmt.Fprintf(stderr, "runclave snapshot: no runclave box %q\n", boxName)
		return 1
	}
	tag := "runclave/snap-" + strings.TrimPrefix(boxName, "runclave-") + ":latest"
	if len(args) >= 2 {
		tag = args[1]
	}
	// A committed image can carry secrets the agent wrote to disk - the user's own
	// artifact, but worth flagging so a snapshot isn't shared unthinkingly.
	out, err := exec.Command("docker", "commit", boxName, tag).CombinedOutput()
	if err != nil {
		fmt.Fprintf(stderr, "runclave snapshot: %v\n%s", err, strings.TrimSpace(string(out)))
		return 1
	}
	fmt.Fprintf(stdout, "snapshot: %s -> %s\n", boxName, tag)
	fmt.Fprintf(stdout, "  fork/rollback from it:  runclave . --image %s\n", tag)
	fmt.Fprintf(stdout, "  note: the image may contain anything the agent wrote to disk; don't share it blindly\n")
	return 0
}

// cmdPauseResume freezes or unfreezes a box's processes (docker pause/unpause), so
// an idle box costs nothing while keeping its state - the AutoPause idea, manual.
func cmdPauseResume(args []string, stdout, stderr io.Writer, pause bool) int {
	verb, dockerVerb := "resume", "unpause"
	if pause {
		verb, dockerVerb = "pause", "pause"
	}
	if len(args) < 1 {
		fmt.Fprintf(stderr, "usage: runclave %s <box>\n", verb)
		return 2
	}
	boxName := args[0]
	if _, ok := runclaveBoxExists(boxName); !ok {
		fmt.Fprintf(stderr, "runclave %s: no runclave box %q\n", verb, boxName)
		return 1
	}
	out, err := exec.Command("docker", dockerVerb, boxName).CombinedOutput()
	if err != nil {
		fmt.Fprintf(stderr, "runclave %s: %v\n%s", verb, err, strings.TrimSpace(string(out)))
		return 1
	}
	fmt.Fprintf(stdout, "%sd %s\n", verb, boxName)
	return 0
}

// imagePresent reports whether a local docker image exists.
func imagePresent(img string) bool {
	return exec.Command("docker", "image", "inspect", img).Run() == nil
}

// imageRunclaveVersion runs `runclave version` inside an image and returns the
// version string, or "" if it can't be read. Used to spot a STALE image whose baked
// binary predates a feature the lifecycle now depends on (e.g. the readiness probe).
func imageRunclaveVersion(img string) string {
	out, err := exec.Command("docker", "run", "--rm", "--network", "none", img, "runclave", "version").Output()
	if err != nil {
		return ""
	}
	f := strings.Fields(strings.TrimSpace(string(out)))
	if len(f) == 2 && f[0] == "runclave" {
		return f[1]
	}
	return ""
}

// cmdDoctor checks the local setup: docker, the images runclave needs, and whether
// any agent image is stale (its baked runclave differs from this CLI). It exists to
// turn the confusing "provision then fail" cases into a clear, up-front diagnosis.
func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	allOK := true
	say := func(ok bool, msg string) {
		mark := "x"
		if ok {
			mark = "ok"
		} else {
			allOK = false
		}
		fmt.Fprintf(stdout, "  [%s] %s\n", mark, msg)
	}
	fmt.Fprintf(stdout, "runclave doctor (cli %s):\n", Version)

	if !box.DaemonAvailable() {
		say(false, "docker daemon reachable")
		fmt.Fprintln(stdout, "\nstart Docker (or Colima) and re-run - nothing else can be checked without it.")
		return 1
	}
	say(true, "docker daemon reachable")

	anyMissing := false
	for _, img := range []string{"runclave/base:latest", "runclave/gateway:latest"} {
		present := imagePresent(img)
		say(present, "image "+img)
		anyMissing = anyMissing || !present
	}
	for _, agent := range policy.EmbeddedAgents() {
		p, err := policy.Find("", agent)
		if err != nil || p.Run.Image == "" {
			continue
		}
		present := imagePresent(p.Run.Image)
		say(present, "agent "+agent+" -> "+p.Run.Image)
		if !present {
			anyMissing = true
			continue
		}
		if iv := imageRunclaveVersion(p.Run.Image); iv != "" && iv != Version {
			fmt.Fprintf(stdout, "      note: %s ships runclave %s but this cli is %s; rebuild with `make images` (a stale binary may lack `probe`)\n", p.Run.Image, iv, Version)
		}
	}
	if anyMissing {
		fmt.Fprintln(stdout, "\nsome images are missing - build them with `make images`.")
	}
	if allOK {
		fmt.Fprintln(stdout, "\nall good - `runclave .` is ready.")
		return 0
	}
	return 1
}

// lsBox is one running runclave box for `runclave ls`.
type lsBox struct{ Name, Image, Age string }

// parseLsBoxes turns `docker ps` tab-separated output (name\timage\tage per line)
// into the workload boxes: names under the runclave- prefix, EXCLUDING the -gw
// gateway sidecars, so the list shows the boxes a user acts on.
func parseLsBoxes(dockerOut string) []lsBox {
	var boxes []lsBox
	for _, line := range strings.Split(strings.TrimRight(dockerOut, "\n"), "\n") {
		if line == "" {
			continue
		}
		f := strings.SplitN(line, "\t", 3)
		if len(f) < 3 {
			continue
		}
		name, image := f[0], f[1]
		// Exclude the gateway sidecars by IMAGE (authoritative), not by a -gw name
		// suffix - so a repo dir that happens to end in "-gw" isn't hidden.
		if !strings.HasPrefix(name, "runclave-") || strings.Contains(image, "runclave/gateway") {
			continue
		}
		boxes = append(boxes, lsBox{Name: name, Image: image, Age: f[2]})
	}
	return boxes
}

// cmdLs lists running runclave boxes (not the gateway sidecars), with hints.
func cmdLs(args []string, stdout, stderr io.Writer) int {
	out, err := exec.Command("docker", "ps", "--filter", "name=runclave-",
		"--format", "{{.Names}}\t{{.Image}}\t{{.RunningFor}}").Output()
	if err != nil {
		fmt.Fprintf(stderr, "runclave ls: %v (is docker running?)\n", err)
		return 1
	}
	boxes := parseLsBoxes(string(out))
	if len(boxes) == 0 {
		fmt.Fprintln(stdout, "no runclave boxes running (start one with `runclave .`)")
		return 0
	}
	fmt.Fprintf(stdout, "%-30s %-28s %s\n", "BOX", "IMAGE (agent)", "AGE")
	for _, b := range boxes {
		fmt.Fprintf(stdout, "%-30s %-28s %s\n", b.Name, b.Image, b.Age)
	}
	fmt.Fprintln(stdout, "\nattach:  runclave open <box>     remove:  runclave destroy <box>")
	return 0
}

// buildLockdownRuleset returns the nftables ruleset that drops all egress except
// loopback, established/related, DNS, and TCP to the one proxy endpoint. Split out
// as a pure function so it is unit-testable without touching the guest firewall.
func buildLockdownRuleset(proxyIP, proxyPort, dnsIP string) string {
	dns := "udp dport 53 accept\n    tcp dport 53 accept"
	if dnsIP != "" {
		dns = "ip daddr " + dnsIP + " udp dport 53 accept\n    ip daddr " + dnsIP + " tcp dport 53 accept"
	}
	return "table inet runclave {\n" +
		"  chain output {\n" +
		"    type filter hook output priority 0; policy drop;\n" +
		"    oifname \"lo\" accept\n" +
		"    ct state established,related accept\n" +
		"    " + dns + "\n" +
		"    ip daddr " + proxyIP + " tcp dport " + proxyPort + " accept\n" +
		"  }\n" +
		"}\n"
}

// cmdLockdown applies an in-guest egress firewall: the Apple-container backend has
// no `--internal` no-route network like Docker, so enforcement must live inside the
// guest VM (see runclave-design/EGRESS-ENFORCEMENT.md). It needs root (CAP_NET_ADMIN),
// so a box image runs it from the ENTRYPOINT before dropping to the agent user.
// UNVERIFIED: this path is built but not yet tested on a live macOS 26 `container`.
func cmdLockdown(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lockdown", flag.ContinueOnError)
	fs.SetOutput(stderr)
	proxy := fs.String("proxy", "", "host:port - the ONLY egress TCP endpoint allowed")
	dns := fs.String("dns", "", "optional DNS resolver IP to pin (default: allow any port 53)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *proxy == "" {
		fmt.Fprintln(stderr, "usage: runclave lockdown --proxy <host:port> [--dns <ip>]")
		return 2
	}
	host, port, err := net.SplitHostPort(*proxy)
	if err != nil {
		fmt.Fprintf(stderr, "runclave lockdown: bad --proxy %q: %v\n", *proxy, err)
		return 2
	}
	ip := host
	if net.ParseIP(host) == nil {
		ips, lerr := net.LookupIP(host)
		if lerr != nil || len(ips) == 0 {
			fmt.Fprintf(stderr, "runclave lockdown: cannot resolve proxy host %q: %v\n", host, lerr)
			return 1
		}
		ip = ips[0].String()
	}
	ruleset := buildLockdownRuleset(ip, port, *dns)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(stderr, "runclave lockdown: applying nftables failed (needs root + nft in the image): %v\n", err)
		return 1
	}
	return 0
}

// cmdProbe waits until a TCP address accepts connections (or times out). It runs
// IN the box before the agent, so the agent's first request doesn't race the
// gateway proxy still binding its port. Portable: the runclave binary is in every
// box image, so no shell/nc dependency.
func cmdProbe(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeout := fs.Duration("timeout", 15*time.Second, "max time to wait for the address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: runclave probe [--timeout d] <host:port>")
		return 2
	}
	addr := fs.Arg(0)
	end := time.Now().Add(*timeout)
	for time.Now().Before(end) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = c.Close()
			return 0
		}
		time.Sleep(150 * time.Millisecond)
	}
	fmt.Fprintf(stderr, "runclave probe: %s did not accept connections within %s\n", addr, *timeout)
	return 1
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

// receiptKeyPath returns the owner-only key file path, creating (and tightening) the
// runclave config dir. Kept separate so a read-only caller can locate the key
// without generating one.
func receiptKeyPath() (string, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfg, "runclave")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o700) // tighten a pre-existing loose dir
	return filepath.Join(dir, "receipt_ed25519.key"), nil
}

// loadReceiptKey loads the signing key if it exists, WITHOUT generating one. Used by
// read-only paths (verify) so they never mint a machine identity as a side effect.
func loadReceiptKey() (ed25519.PrivateKey, bool, error) {
	path, err := receiptKeyPath()
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(data) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("receipt key %s is corrupt (wrong size)", path)
	}
	return ed25519.PrivateKey(data), true, nil
}

// receiptSigningKey loads this machine's Ed25519 receipt-signing key, generating and
// persisting one (owner-only) on first use. Generation is race-safe: the key is
// written to a temp file with its full contents, then hard-linked into place, so the
// FIRST writer wins atomically and a loser re-reads the winner's key (no split
// identity, no 0-length window). The private key stays on the host; only the public
// key travels, inside each signed receipt.
func receiptSigningKey() (ed25519.PrivateKey, error) {
	if priv, ok, err := loadReceiptKey(); err != nil {
		return nil, err
	} else if ok {
		return priv, nil
	}
	path, err := receiptKeyPath()
	if err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".key-*.tmp")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(priv); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	// Atomic first-writer-wins: Link fails if the path already exists.
	if err := os.Link(tmp.Name(), path); err != nil {
		if priv2, ok, lerr := loadReceiptKey(); lerr == nil && ok {
			return priv2, nil // someone else won the race; use their key
		}
		return nil, err
	}
	return priv, nil
}

// cmdVerify checks a signed receipt envelope offline: the signature must verify
// against the public key embedded in it (fail-closed on any tamper), and the signer
// fingerprint is shown so the user can confirm it is a key they trust. It notes when
// the signer is THIS machine's key.
func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	expect := fs.String("key", "", "require the signer to be this key fingerprint (e.g. ed25519:...); fail otherwise")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "usage: runclave verify [--key <fingerprint>] <receipt.dsse.json>")
		return 2
	}
	env, err := ledger.ReadEnvelope(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "runclave verify: %v\n", err)
		return 1
	}
	r, err := ledger.VerifyEnvelope(env)
	if err != nil {
		fmt.Fprintf(stderr, "runclave verify: INVALID - %v\n", err)
		return 1
	}
	// The signature is cryptographically valid, but that only proves integrity and
	// WHO signed - not that the signer is one you trust. Establish trust: a pinned
	// --key that must match (fail-closed), else whether it is this machine's own key.
	mine := false
	if priv, ok, _ := loadReceiptKey(); ok {
		mine = env.KeyID == ledger.KeyFingerprint(priv.Public().(ed25519.PublicKey))
	}
	if *expect != "" && env.KeyID != *expect {
		fmt.Fprintf(stderr, "runclave verify: signature is valid but signed by %s, NOT the required %s\n", env.KeyID, *expect)
		return 1
	}
	fmt.Fprintf(stdout, "OK: signature valid\n")
	switch {
	case *expect != "":
		fmt.Fprintf(stdout, "  signer:      %s (matches the required key)\n", env.KeyID)
	case mine:
		fmt.Fprintf(stdout, "  signer:      %s (this machine's key)\n", env.KeyID)
	default:
		fmt.Fprintf(stdout, "  signer:      %s\n", env.KeyID)
		fmt.Fprintf(stdout, "  WARNING: this is an UNKNOWN signer. A valid signature is not proof of authenticity -\n")
		fmt.Fprintf(stdout, "           anyone can sign a receipt with their own key. Pass --key <fingerprint> to\n")
		fmt.Fprintf(stdout, "           require a specific signer and fail otherwise.\n")
	}
	fmt.Fprintf(stdout, "  agent:       %s\n", r.Agent)
	fmt.Fprintf(stdout, "  image:       %s\n", r.Image)
	fmt.Fprintf(stdout, "  disposition: %s\n", r.Disposition)
	fmt.Fprintf(stdout, "  egress:      %d allowed, %d denied\n", r.EgressAllowed, r.EgressDenied)
	return 0
}

// gatewayEgressCounts reads the gateway container's log and counts the ALLOW/DENY
// decisions the proxy made, so the receipt carries real egress numbers instead of
// "unknown". Returns -1,-1 if the log can't be read (then the receipt stays honest
// about not knowing). The proxy logs one "egress ALLOW <host>" / "egress DENY
// <host>" line per decision.
func gatewayEgressCounts(gwName string) (int64, int64) {
	if gwName == "" {
		return -1, -1
	}
	out, err := exec.Command("docker", "logs", gwName).CombinedOutput()
	if err != nil {
		return -1, -1
	}
	return countEgressLines(string(out))
}

// countEgressLines tallies the proxy's ALLOW/DENY decision lines from its log.
func countEgressLines(log string) (int64, int64) {
	var allow, deny int64
	for _, line := range strings.Split(log, "\n") {
		switch {
		case strings.Contains(line, "egress ALLOW"):
			allow++
		case strings.Contains(line, "egress DENY"):
			deny++
		}
	}
	return allow, deny
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
	fmt.Fprintf(stdout, "destroyed %s (box, gateway, and internal net removed)\n", fs.Arg(0))
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
	injectHost := fs.String("inject-host", "", "comma-separated hosts to inject a credential for (each MUST also be in --allow); the gateway MITMs these with an ephemeral CA so the real secret never enters the box")
	injectHeader := fs.String("inject-header", "Authorization", "the header to force onto injected requests")
	injectValueEnv := fs.String("inject-value-env", "", "name of the env var holding the REAL credential value; read from the environment (never argv, so it stays out of `ps`)")
	injectCAOut := fs.String("inject-ca-out", "", "path to write the CA certificate the box must trust (cert only; the CA key never leaves this process)")
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
	if *injectHost != "" {
		if code := enableInjection(p, *injectHost, *injectHeader, *injectValueEnv, *injectCAOut, stdout, stderr); code != 0 {
			return code
		}
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

// enableInjection turns on credential injection on p from the proxy's flags. The
// gateway generates its OWN ephemeral CA here (the key never leaves this process),
// writes only the cert to injectCAOut for the box to trust, and reads the real
// secret from the environment (not argv) so it stays out of `ps`. Each injected
// host must already be in the allowlist - SetInjector refuses otherwise, so
// injection can never be a bypass. Returns a non-zero CLI code on any failure.
func enableInjection(p *egress.Proxy, hostsCSV, header, valueEnv, caOut string, stdout, stderr io.Writer) int {
	if valueEnv == "" || caOut == "" {
		fmt.Fprintln(stderr, "runclave proxy: --inject-host requires --inject-value-env and --inject-ca-out")
		return 2
	}
	token := os.Getenv(valueEnv)
	if token == "" {
		fmt.Fprintf(stderr, "runclave proxy: env %q is empty; refusing to inject a blank credential\n", valueEnv)
		return 1
	}
	rules := map[string]egress.InjectRule{}
	for _, h := range strings.Split(hostsCSV, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		// Normalize to exactly what the box's TLS client puts in the CONNECT authority
		// (lowercase, bare host). A mismatch here would pass the allowlist check yet
		// silently miss the inject-map lookup at request time - injection "ON" in the
		// log but the credential never forced. Reject ports/wildcards/whitespace with a
		// clear message instead of letting them fail obscurely downstream.
		if strings.ContainsAny(h, ":*") || strings.ContainsAny(h, " \t") {
			fmt.Fprintf(stderr, "runclave proxy: --inject-host %q must be a bare hostname (no port, no wildcard)\n", h)
			return 2
		}
		rules[strings.ToLower(h)] = egress.InjectRule{Header: header, Value: token}
	}
	if len(rules) == 0 {
		fmt.Fprintln(stderr, "runclave proxy: --inject-host listed no hosts")
		return 2
	}
	ca, err := egress.GenerateCA()
	if err != nil {
		fmt.Fprintf(stderr, "runclave proxy: generate CA: %v\n", err)
		return 1
	}
	if err := p.SetInjector(ca, rules); err != nil {
		// e.g. an inject host that isn't allowlisted - fail loudly, don't silently skip.
		fmt.Fprintf(stderr, "runclave proxy: %v\n", err)
		return 1
	}
	// Write the CERT only (never the key) so the box can trust the MITM leaf. 0644 is
	// right for a public cert. O_EXCL|O_NOFOLLOW: the gateway runs as root and writes
	// into a mount the (untrusted) box can touch - refuse to follow a symlink the box
	// planted (root-truncate-an-arbitrary-path) or to reuse a file the box pre-created
	// with its OWN CA. Fail closed if the target already exists.
	f, err := os.OpenFile(caOut, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		fmt.Fprintf(stderr, "runclave proxy: create CA cert %q: %v\n", caOut, err)
		return 1
	}
	if _, err := f.Write(ca.CertPEM()); err != nil {
		f.Close()
		fmt.Fprintf(stderr, "runclave proxy: write CA cert to %q: %v\n", caOut, err)
		return 1
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(stderr, "runclave proxy: write CA cert to %q: %v\n", caOut, err)
		return 1
	}
	// Do NOT log the token or the env var's value - only that injection is on and for
	// which hosts, so the receipt/log is safe to keep.
	hosts := make([]string, 0, len(rules))
	for h := range rules {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	fmt.Fprintf(stdout, "runclave proxy: credential injection ON for %s (header %q; secret stays in the gateway; CA cert -> %s)\n",
		strings.Join(hosts, ","), header, caOut)
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
	// nativeSandbox/paths/mcp are DESCRIPTIVE (see policy.Pack): the actual controls
	// are the box (fresh home, no host FS) + the egress allowlist. Label it so the
	// output doesn't read as "runclave enforces this".
	fmt.Fprintf(stdout, "  agent's own sandbox: %s (via run flags; descriptive)\n", p.NativeSandbox.Mode)
	fmt.Fprintf(stdout, "  enforcement: box isolation (fresh home, no host FS) + the egress allowlist above\n")
	return 0
}

func cmdRun(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		// No agent, or a flag first (e.g. `run --help`): don't treat it as an agent
		// name. Forward flags straight through so help/errors are sensible.
		if len(args) >= 1 && (args[0] == "-h" || args[0] == "--help") {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprintln(stderr, "usage: runclave run <agent> [flags] [task]")
		return 2
	}
	// `runclave run <agent> ...` is a convenience alias for `runclave . --agent
	// <agent> ...` - the full isolated lifecycle lives in cmdHere; run just preselects
	// the agent so `runclave run codex "fix the bug"` reads naturally.
	return cmdHere(append([]string{"--agent", args[0]}, args[1:]...), stdout, stderr)
}

// cmdExport pulls an artifact OUT of a box - never automatic, always explicit.
// `runclave export <box> <path-in-box> [host-dest]` is a thin, safe wrapper over
// docker cp; host-dest defaults to the current directory.
func cmdExport(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, "usage: runclave export <box> <path-in-box> [host-dest]")
		return 2
	}
	boxName, src := args[0], args[1]
	dst := "."
	if len(args) >= 3 {
		dst = args[2]
	}
	out, err := exec.Command("docker", "cp", boxName+":"+src, dst).CombinedOutput()
	if err != nil {
		fmt.Fprintf(stderr, "runclave export: %v\n%s", err, strings.TrimSpace(string(out)))
		return 1
	}
	fmt.Fprintf(stdout, "exported %s:%s -> %s\n", boxName, src, dst)
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
	rm := fs.Bool("rm", false, "tear the box and its network down when the run (or shell) exits, leaving nothing behind (ephemeral)")
	agent := fs.String("agent", "claude-code", "which agent policy pack to run (e.g. claude-code, gemini-cli, codex, copilot)")
	image := fs.String("image", "", "override the box image (e.g. runclave/all:latest, the combined image with every agent CLI); default is the agent's own minimal image")
	fs.String("policies", "", "explicit dir of on-disk policy packs (opt-in; default: embedded trusted packs)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Any positional args form the task prompt handed to the agent, so
	// `runclave . "fix the flaky test"` (or unquoted words) actually gives it work.
	prompt := strings.TrimSpace(strings.Join(fs.Args(), " "))
	// Go's flag parsing stops at the first non-flag arg, so a runclave flag placed
	// AFTER the task silently becomes part of the task (e.g. `runclave . "x" --dry-run`
	// does a real run). Warn loudly if a task token looks like a known runclave flag.
	knownFlags := map[string]bool{"--dry-run": true, "--clean": true, "--shell": true, "--login": true, "--agent": true, "--image": true, "--backend": true, "--policies": true}
	for _, tok := range fs.Args() {
		if knownFlags[tok] {
			fmt.Fprintf(stderr, "runclave: WARNING - %q is part of the TASK, not a flag. runclave flags must come before the task (runclave . [flags] [task]).\n", tok)
		}
	}
	if *shell && prompt != "" {
		fmt.Fprintf(stderr, "runclave: note - --shell ignores the task prompt; you get an interactive shell in the repo instead\n")
	}
	// `runclave .` with no task and no --shell: the headless agents want a prompt
	// (they run `<agent> -p`), so a taskless run would just fail. The right zero-arg
	// behavior is the `code .` one - drop the user into an interactive shell in the
	// isolated box. Pass a task to run the agent instead.
	if prompt == "" && !*shell {
		fmt.Fprintf(stderr, "runclave: no task given - opening an interactive shell in the box (pass a task to run the agent, e.g. runclave . \"fix the flaky test\")\n")
		*shell = true
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
	pol, err := policy.Find(dir, *agent)
	if err != nil {
		fmt.Fprintf(stderr, "runclave: %v\n", err)
		return 1
	}
	rawPol, _ := policy.RawBytes(dir, *agent)

	// Surface an allow-all (`*`) pack to the operator at run time - not just in the
	// gateway's own logs - so an unrestricted box is never a quiet surprise.
	for _, d := range pol.AllowedDomains() {
		if d == "*" {
			fmt.Fprintf(stderr, "runclave: WARNING - the %s pack allows ALL egress (\"*\"); this box is NOT egress-sandboxed\n", pol.Agent)
			break
		}
	}

	// --image override: run this agent in a different box image (e.g. the combined
	// runclave/all image that carries every agent CLI). The egress allowlist and all
	// invariants are unchanged - only which image the box boots from. The agent's own
	// command still comes from the pack, so the image just has to contain that CLI.
	if *image != "" {
		pol.Run.Image = *image
		fmt.Fprintf(stderr, "runclave: box image overridden to %s. The egress allowlist and isolation are unchanged, but the host pulls this image over its own network (outside the sandbox) and runs it as the box, so only use an image you trust.\n", *image)
	}

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
	var lc box.Plan
	if drv.Name() == "apple-container" {
		// The Apple backend is a separate, UNVERIFIED lifecycle (in-guest firewall
		// instead of a --internal net). Say so loudly - it has not been tested on a
		// live macOS 26 `container`.
		fmt.Fprintf(stderr, "runclave: WARNING - the apple-container backend is UNVERIFIED (built, not yet tested on a live container CLI); use --backend docker for the tested path\n")
		lc, err = box.BuildApplePlan(name, pol, ws, brokerSock, loginMounts, prompt)
	} else {
		lc, err = box.BuildPlan(name, drv, pol, ws, "127.0.0.1:8888", brokerSock, !*clean, loginMounts, loginHostRoot, prompt)
	}
	if err != nil {
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
	// Box teardown, guarded so it runs at most once whether from the normal --rm path
	// or from the Ctrl-C signal handler. Registering it in cleanups (only for --rm)
	// means an interrupt tears the box/gateway/net down too, honouring --rm's "nothing
	// left behind" even on interrupt - not just the host-side seed/broker dirs.
	var boxTornDown sync.Once
	teardownBox := func() error {
		var derr error
		boxTornDown.Do(func() { derr = lc.Destroy(box.ExecRunner{}) })
		return derr
	}
	if *rm {
		cleanups = append(cleanups, func() { _ = teardownBox() })
	}
	// Enforce the boundary invariants BEFORE any execution (each backend has its own).
	guardErr := lc.VerifyEgressInvariants()
	invariantsMsg := "OK (box on the internal net only, egress via gateway, no host escape)"
	if drv.Name() == "apple-container" {
		guardErr = lc.VerifyAppleInvariants()
		invariantsMsg = "OK (in-guest egress lockdown to the gateway, no host escape)"
	}
	if guardErr != nil {
		fmt.Fprintf(stderr, "runclave: refusing to run - %v\n", guardErr)
		return 1
	}

	fmt.Fprintf(stdout, "runclave: %s box for %s\n", drv.Name(), filepath.Base(cwd))
	fmt.Fprintf(stdout, "  workspace: %s\n", ws.Describe())
	fmt.Fprintf(stdout, "  egress invariants: %s\n", invariantsMsg)

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
		if *rm {
			fmt.Fprintf(stdout, "  --rm: on a real run the box, gateway and net are torn down when it exits\n")
		}
		writeRunReceipt(stdout, name, pol, rawPol, drv.Name(), "planned", -1, -1, loginShared...)
		return 0
	}

	if *shell {
		persistNote := "the box persists"
		if *rm {
			persistNote = "the box is torn down on exit (--rm)"
		}
		fmt.Fprintf(stdout, "  box up. dropping you into a shell (type 'exit' to leave; %s)...\n", persistNote)
	} else {
		fmt.Fprintf(stdout, "  executing lifecycle...\n")
	}
	if err := lc.Execute(box.ExecRunner{}); err != nil {
		fmt.Fprintf(stderr, "runclave: lifecycle failed: %v\n", err)
		// Read egress counts (the gateway log may explain the failure) BEFORE teardown.
		fAllow, fDeny := gatewayEgressCounts(lc.GatewayName)
		// Best-effort teardown so a half-provisioned box and its network don't
		// linger and block the next run on a name collision. This tears the box down
		// even without --rm (a broken box is not useful to keep); say so.
		_ = teardownBox()
		fmt.Fprintf(stdout, "  box torn down after the failure\n")
		writeRunReceipt(stdout, name, pol, rawPol, drv.Name(), "failed", fAllow, fDeny, loginShared...)
		return 1
	}
	if brokerSock != "" {
		// Honest lifetime: the broker served the agent's git DURING this run and
		// stops now, on return. The box is detached; if it persists and you re-enter
		// it later, git is not brokered until you run through runclave again.
		fmt.Fprintf(stdout, "  git broker: served this run; stops now\n")
	}
	// Read the real egress counts from the gateway's own log BEFORE any teardown (the
	// gateway must still exist), so the receipt reports what actually happened.
	egAllow, egDeny := gatewayEgressCounts(lc.GatewayName)
	if egAllow >= 0 {
		fmt.Fprintf(stdout, "  egress: %d allowed, %d denied (from the gateway log)\n", egAllow, egDeny)
	}
	// --rm: ephemeral run. Tear the box, gateway and net down so nothing is left
	// behind. The disposition is recorded as "destroyed", and the receipt (signed) is
	// the only artifact that outlives the box.
	disposition := "persisted"
	if *rm {
		if derr := teardownBox(); derr != nil {
			// Honest: teardown didn't fully complete, so the (signed) receipt must not
			// claim "destroyed" or "nothing left behind".
			fmt.Fprintf(stderr, "runclave: teardown: %v\n", derr)
			disposition = "destroy-failed"
			fmt.Fprintf(stdout, "  run complete; teardown FAILED - some resources may remain (try `runclave destroy %s`)\n", name)
		} else {
			disposition = "destroyed"
			if *shell {
				fmt.Fprintf(stdout, "  shell session ended; box torn down (--rm), nothing left behind\n")
			} else {
				fmt.Fprintf(stdout, "  run complete; box torn down (--rm), nothing left behind\n")
			}
		}
	} else if *shell {
		fmt.Fprintf(stdout, "  shell session ended (box persists; `runclave destroy %s` to remove)\n", name)
	} else {
		fmt.Fprintf(stdout, "  box up (egress via gateway proxy; `runclave destroy %s` to remove)\n", name)
	}
	writeRunReceipt(stdout, name, pol, rawPol, drv.Name(), disposition, egAllow, egDeny, loginShared...)
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
func writeRunReceipt(stdout io.Writer, name string, pol *policy.Pack, rawPol []byte, backend, disposition string, egressAllow, egressDeny int64, loginShared ...string) {
	// Record the box image actually booted. This matters when --image overrode the
	// pack's image: the policy hash is of the pack bytes and would not reflect it, so
	// the effective image is captured here for the audit trail.
	effImage := pol.Run.Image
	if effImage == "" {
		effImage = "runclave/base:latest"
	}
	r := ledger.Receipt{
		Agent:         pol.Agent,
		PolicyHash:    ledger.PolicyHash(rawPol),
		Backend:       backend,
		Image:         effImage,
		AllowedEgress: pol.AllowedDomains(),
		EgressAllowed: egressAllow, // -1 when not read (planned/failed); real counts from the gateway log on a persisted run
		EgressDenied:  egressDeny,
		LoginShared:   loginShared,
		Disposition:   disposition,
	}
	// Receipts go in an owner-only runclave dir, NOT shared /tmp. On Linux os.TempDir
	// is the world-writable /tmp, where a local user could pre-plant a symlink at the
	// predictable receipt path and have the write follow it (destructive clobber). An
	// 0700 dir only the owner can write closes that. The readable .json is convenience;
	// the SIGNED .dsse.json envelope is the artifact `runclave verify` actually checks.
	dir, derr := receiptDir()
	if derr != nil {
		fmt.Fprintf(stdout, "  (receipt not written: %v)\n", derr)
		return
	}
	path := filepath.Join(dir, "runclave-"+name+"-receipt.json")
	if err := ledger.WriteReceipt(path, r); err == nil {
		fmt.Fprintf(stdout, "  receipt: %s (policy %s…, disposition=%s)\n", path, r.PolicyHash[:12], disposition)
	}
	// Sign the receipt so it is tamper-evident and offline-verifiable (`runclave
	// verify`). A signing-key problem is non-fatal: the unsigned receipt still stands.
	if priv, err := receiptSigningKey(); err == nil {
		if env, serr := ledger.SignReceipt(r, priv); serr == nil {
			sigPath := filepath.Join(dir, "runclave-"+name+"-receipt.dsse.json")
			if werr := ledger.WriteEnvelope(sigPath, env); werr == nil {
				fmt.Fprintf(stdout, "  signed:  %s (%s; verify with `runclave verify %s`)\n", sigPath, env.KeyID, sigPath)
			}
		}
	} else {
		fmt.Fprintf(stdout, "  (receipt not signed: %v)\n", err)
	}
}

// receiptDir is an owner-only directory for receipts, under the user's cache dir.
func receiptDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "runclave", "receipts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(dir, 0o700)
	return dir, nil
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
