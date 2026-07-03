// Package box orchestrates one sandbox lifecycle as an ordered plan of steps
// over a Runner interface, so the SEQUENCE and its security properties are
// unit-testable without a live daemon; the real daemon path is integration-guarded.
//
// Scope: this plan is docker-family only (docker, colima). Apple `container` uses
// a different CLI and its egress chokepoint is in-guest nftables, not
// `docker network --internal`, so that backend has a separate lifecycle that is
// not built yet. BuildPlan returns an error for non-docker drivers.
//
// The plan creates an internal network with no route to the internet, provisions a
// hardened gateway that runs the allowlist proxy and a hardened box, both directly
// on that network, copies the seed artifacts in, reconstructs the working tree, and
// execs the agent with HTTP(S)_PROXY pointed at the gateway.
package box

import (
	"fmt"
	"strings"

	"github.com/saimeda/runclave/internal/backend"
	"github.com/saimeda/runclave/internal/policy"
	"github.com/saimeda/runclave/internal/workspace"
)

// Runner executes a command. Real impl shells out; tests use a fake that records.
type Runner interface {
	Run(argv []string) (string, error)
}

// Step is one lifecycle action.
type Step struct {
	Desc  string
	Argv  []string
	InBox bool              // true -> run inside the box via `docker exec`
	Env   map[string]string // in-box env injected as `docker exec -e K=V`
}

// Plan is the full ordered lifecycle.
type Plan struct {
	Name        string
	Net         string   // the internal sandbox-net (the ONLY net the WORKLOAD box may join)
	GatewayName string   // the egress-proxy gateway container (may also join OutboundNet)
	OutboundNet string   // the net with real internet egress - ONLY the gateway may join it
	BrokerSock  string   // host path of the per-session broker socket (mounted read-only)
	Allowlist   []string // the exact egress allowlist the gateway proxy must enforce
	Steps       []Step
}

// brokerDst is the fixed in-box path the broker socket is mounted at. The in-box
// git credential-helper shim talks to the host broker over this socket.
const brokerDst = "/run/runclave/broker.sock"

// brokerSockPrefix is the runclave-owned directory the broker socket MUST live
// under. The exception is granted only for sockets here - a mount of any other
// host path (/, /etc, …) is never eligible, so the boundary is enforced, not
// merely assumed from the caller's constant.
const brokerSockPrefix = "/run/runclave/"

// validBrokerSock enforces that the exception's source is a genuine, safe socket
// path, not any host path a future flag or config might supply. Without this the
// mount shape is validated tightly but the source is trusted, so src=/ would be
// stripped and hidden from the host-escape check. This is the missing floor.
func validBrokerSock(sock string) bool {
	if sock == "" {
		return false
	}
	if !strings.HasSuffix(sock, ".sock") { // must be a socket, not a dir
		return false
	}
	if strings.ContainsAny(sock, ",") || strings.Contains(sock, "..") { // no option/traversal smuggling
		return false
	}
	return strings.HasPrefix(sock, brokerSockPrefix) // runclave-owned location only
}

// allowedBrokerMountSpec is the ONE --mount the box provision step may carry. A
// unix socket is an IPC endpoint, not a filesystem tree - so binding exactly this
// one socket read-only is NOT the host-disk access W6 forbids.
func allowedBrokerMountSpec(sock string) string {
	return "type=bind,src=" + sock + ",dst=" + brokerDst + ",ro"
}

// removeBrokerMount strips ONLY the exact allowed broker-socket --mount from argv,
// so the remainder can be checked by HasHostEscape. It refuses to strip unless
// `sock` passes validBrokerSock - so a hostile source (src=/) is NOT hidden from
// HasHostEscape and gets rejected. Any OTHER mount (dir bind, different socket,
// -v) is left in place and caught.
func removeBrokerMount(a []string, sock string) []string {
	if !validBrokerSock(sock) {
		return a // invalid/absent -> strip nothing -> HasHostEscape sees any mount
	}
	spec := allowedBrokerMountSpec(sock)
	out := make([]string, 0, len(a))
	for i := 0; i < len(a); i++ {
		if a[i] == "--mount" && i+1 < len(a) && a[i+1] == spec {
			i++ // skip the spec value too
			continue
		}
		if a[i] == "--mount="+spec {
			continue
		}
		out = append(out, a[i])
	}
	return out
}

func sandboxNet(name string) string { return "runclave-net-" + name }

// setNetwork replaces the --network value in a `docker run` argv with net (or
// inserts `--network net` right after `run` if absent). Handles the space and
// =value forms of both --network and --net. Used to put the box directly on the
// internal sandbox-net instead of the driver's default `--network none`.
func setNetwork(a []string, net string) []string {
	for i := 0; i < len(a); i++ {
		switch {
		case (a[i] == "--network" || a[i] == "--net") && i+1 < len(a):
			a[i], a[i+1] = "--network", net
			return a
		case strings.HasPrefix(a[i], "--network=") || strings.HasPrefix(a[i], "--net="):
			a[i] = "--network=" + net
			return a
		}
	}
	if len(a) >= 2 && a[0] == "docker" && a[1] == "run" {
		return append(a[:2], append([]string{"--network", net}, a[2:]...)...)
	}
	return a
}

// DestroyPlan returns a minimal plan (name + derived net) suitable for teardown
// of an existing box by name - so `runclave destroy <name>` can remove it without
// reconstructing the full provisioning plan.
func DestroyPlan(name string) Plan {
	return Plan{Name: name, Net: sandboxNet(name)}
}

// BuildPlan assembles the Docker-family lifecycle. Errors for non-docker drivers.
func BuildPlan(name string, drv backend.Driver, pack *policy.Pack, ws workspace.Plan, proxyAddr, brokerSock string, includeDirty bool) (Plan, error) {
	if name == "" || drv == nil || pack == nil {
		return Plan{}, fmt.Errorf("box: name, driver and pack are required")
	}
	if drv.Name() != "docker" {
		return Plan{}, fmt.Errorf("box: lifecycle plan is docker-family only; %q uses a separate path (see package doc)", drv.Name())
	}
	// Fail-closed: a broker socket, if given, must be a genuine .sock under the
	// runclave-owned prefix - never an arbitrary host path.
	if brokerSock != "" && !validBrokerSock(brokerSock) {
		return Plan{}, fmt.Errorf("box: broker socket %q is not a valid runclave socket path (must be a .sock under %s)", brokerSock, brokerSockPrefix)
	}
	net := sandboxNet(name)
	gwName := name + "-gw"
	outNet := "bridge" // Docker's default NAT'd net - the gateway's route to the internet.
	// The egress-proxy GATEWAY runs the allowlist CONNECT proxy (`runclave proxy`)
	// and straddles two nets: the internal sandbox-net (to receive the box's
	// traffic) and outNet (to reach the internet). The box has NO route except
	// through this gateway -> the box's only egress is the allowlist proxy.
	// NOTE (honest): the gateway image `runclave/gateway` (the runclave binary in a
	// minimal image) is not built here - that Dockerfile is a remaining stub.
	gwAllow := strings.Join(pack.AllowedDomains(), ",")
	// Provisioning pattern (reworked after a real run: Docker refuses to
	// `network connect` a container created with `--network none`). The --internal
	// net is created FIRST; box and gateway are provisioned DIRECTLY on it via
	// `--network <net>`. The box gets no other net (internal has no internet route).
	// The gateway then also joins the outbound net (allowed - a container already on
	// a user net CAN join another). So the box's only egress is the gateway proxy.
	steps := []Step{
		{Desc: "create internal sandbox-net (no NAT/route to internet)", Argv: []string{"docker", "network", "create", "--internal", net}},
		// Gateway: hardened, provisioned ON the internal net, then also joined to outbound.
		{Desc: "provision egress gateway (hardened, on internal net)", Argv: []string{
			"docker", "run", "-d", "--name", gwName, "--network", net,
			"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
			"runclave/gateway:latest", "runclave", "proxy", "--addr", "0.0.0.0:8888", "--allow", gwAllow,
		}},
		{Desc: "attach gateway to outbound net (its route to the internet)", Argv: []string{"docker", "network", "connect", outNet, gwName}},
	}
	// Box (workload): hardened, provisioned DIRECTLY on the internal net ONLY (no
	// separate connect). If a broker socket is configured, mount ONLY that socket
	// (read-only) so the in-box git credential helper can reach the host broker.
	// The box runs the pack's image (which builds FROM the base and adds the agent
	// CLI). Packs without an image fall back to the agent-agnostic base.
	boxImage := pack.Run.Image
	if boxImage == "" {
		boxImage = "runclave/base:latest"
	}
	boxArgv := setNetwork(drv.CreateArgs(name, boxImage), net)
	if brokerSock != "" && len(boxArgv) >= 2 && boxArgv[0] == "docker" && boxArgv[1] == "run" {
		boxArgv = append(boxArgv[:2], append([]string{"--mount", allowedBrokerMountSpec(brokerSock)}, boxArgv[2:]...)...)
	}
	steps = append(steps,
		Step{Desc: "provision box (hardened, on internal net ONLY, broker socket ro)", Argv: boxArgv},
	)
	// The box routes egress at the gateway's name on the internal net.
	proxyAddr = gwName + ":8888"
	// Seed TRANSFER: copy the two-payload artifacts into the box's /seed (one-shot
	// docker cp - no bind mount, no standing path back; W7). The base image
	// pre-creates /seed owned by the box user, so no in-box mkdir is needed.
	if ws.HostBundlePath != "" {
		steps = append(steps, Step{Desc: "copy history bundle into box", Argv: []string{"docker", "cp", ws.HostBundlePath, name + ":/seed/repo.bundle"}})
	}
	// Copy the dirty/untracked payloads only if the host actually produced them
	// (empty repo state -> no dirty bundle / no untracked tar). Uses the REAL host
	// paths threaded through the workspace plan, not hardcoded placeholders.
	if ws.HostDirtyBundle != "" {
		steps = append(steps, Step{Desc: "copy dirty bundle into box", Argv: []string{"docker", "cp", ws.HostDirtyBundle, name + ":/seed/dirty.bundle"}})
	}
	if ws.HostUntrackedTar != "" {
		steps = append(steps, Step{Desc: "copy untracked tar into box", Argv: []string{"docker", "cp", ws.HostUntrackedTar, name + ":/seed/untracked.tar"}})
	}
	_ = includeDirty // dirty inclusion is now driven by which host artifacts exist
	// Seed APPLY: in-box reconstruction (from workspace.BuildPlan).
	for _, w := range ws.Steps {
		steps = append(steps, Step{Desc: "seed: " + w.Desc, Argv: w.Argv, InBox: true})
	}
	// Exec the agent, egress pointed at the proxy via env (the convenience layer;
	// the ACTUAL chokepoint is the internal-net gateway). This is REAL now, not a
	// Desc string: HTTP(S)_PROXY are injected into the exec env.
	execArgv := append([]string{pack.Run.Command}, pack.Run.HeadlessFlags...)
	env := map[string]string{}
	if proxyAddr != "" {
		env["HTTP_PROXY"] = "http://" + proxyAddr
		env["HTTPS_PROXY"] = "http://" + proxyAddr
	}
	if brokerSock != "" {
		env["RUNCLAVE_BROKER_SOCK"] = brokerDst // in-box git cred helper talks here
	}
	for k, v := range pack.Run.ContainerEnv {
		env[k] = v
	}
	brokerNote := "no broker"
	if brokerSock != "" {
		brokerNote = "broker socket " + brokerDst
	}
	steps = append(steps, Step{
		Desc:  fmt.Sprintf("exec agent (egress->%s; %s)", proxyAddr, brokerNote),
		Argv:  execArgv,
		InBox: true,
		Env:   env,
	})
	return Plan{Name: name, Net: net, GatewayName: gwName, OutboundNet: outNet, BrokerSock: brokerSock, Allowlist: pack.AllowedDomains(), Steps: steps}, nil
}

// VerifyEgressInvariants checks the plan's OWN structure for the F1/W6 invariants.
// Honest scope: this guards OUR generated plan against regressions - it is NOT an
// adversarial boundary (a hand-crafted hostile plan can evade a denylist; the real
// boundary is the backend/VM, per N8). It enforces, positionally:
//   - every container-creating step's --network equals the internal sandbox-net
//     (p.Net) - provisioned DIRECTLY on it (the box can't `network connect` out of
//     `--network none`, per the real-run finding);
//   - the `network create` for p.Net includes `--internal` (no NAT/route out);
//   - the WORKLOAD box has ZERO `network connect`s; the GATEWAY has EXACTLY ONE, to
//     the outbound net (its egress purpose);
//   - NET_ADMIN is dropped and never re-added on both containers (the anti-L3-bypass
//     dependency); the gateway runs `runclave proxy` with EXACTLY the trusted --allow;
//   - no step grants host-disk access (workspace.HasHostEscape) beyond the one exact
//     broker socket, or uses --network host / docker.sock.
func (p Plan) VerifyEgressInvariants() error {
	sawInternalCreate := false
	boxConnects := 0        // the box is provisioned ON the net; it must have NO connects
	gwOutboundConnects := 0 // the gateway must have EXACTLY ONE connect, to the outbound net
	for _, s := range p.Steps {
		// The box provision step is the ONLY step permitted a mount, and ONLY the
		// exact broker socket (removed before the check). Every other mount/-v, and
		// every mount on every other step, is still caught by HasHostEscape.
		checkArgv := s.Argv
		if isContainerCreate(s.Argv) && flagValueEq(s.Argv, "--name") == p.Name {
			checkArgv = removeBrokerMount(s.Argv, p.BrokerSock)
		}
		if workspace.HasHostEscape(checkArgv) {
			return fmt.Errorf("box: step %q grants host-disk access (W6)", s.Desc)
		}
		a := s.Argv
		joined := strings.Join(a, " ")
		if strings.Contains(joined, "--network host") || strings.Contains(joined, "docker.sock") {
			return fmt.Errorf("box: step %q exposes host network/socket", s.Desc)
		}
		// Any container-CREATING step must be provisioned DIRECTLY on the internal
		// sandbox-net (reworked after a real run: `--network none` can't later be
		// `network connect`ed). Every --network/--net flag present must equal p.Net;
		// absent is rejected (Docker would default to the NAT'd bridge = open egress).
		if isContainerCreate(a) {
			if bad, ok := allNetworksEqual(a, p.Net); !ok {
				return fmt.Errorf("box: container-creating step must be --network %s, got %q", p.Net, bad)
			}
			// The anti-L3-bypass property (a dual-homed gateway can't route/NAT for the
			// box) rests on NEITHER container having CAP_NET_ADMIN - without it neither
			// can add a route or install MASQUERADE.
			if !dropsNetAdmin(a) {
				return fmt.Errorf("box: container-creating step must drop NET_ADMIN (--cap-drop ALL or NET_ADMIN); the egress model depends on it")
			}
		}
		// `docker network create <...> <net>`: for our sandbox-net, require --internal.
		if isDockerSub(a, "network", "create") {
			netName := a[len(a)-1]
			if netName == p.Net {
				sawInternalCreate = true
				if !contains(a, "--internal") {
					return fmt.Errorf("box: sandbox-net must be created --internal (F1)")
				}
			}
		}
		// `docker network connect <net> <container>`: net=arg[3], container=arg[4].
		// The WORKLOAD box is provisioned directly on the internal net -> it must have
		// NO connect at all. The GATEWAY (also provisioned on the internal net) may
		// have EXACTLY ONE connect, to the outbound net (that's its egress purpose).
		if isDockerSub(a, "network", "connect") {
			if len(a) < 5 {
				return fmt.Errorf("box: malformed network connect: %v", a)
			}
			net, container := a[3], a[4]
			switch container {
			case p.Name:
				boxConnects++ // any box connect is a violation (checked after loop)
				_ = net
			case p.GatewayName:
				if net != p.OutboundNet {
					return fmt.Errorf("box: gateway connect must target the outbound net, got %q", net)
				}
				gwOutboundConnects++
			default:
				return fmt.Errorf("box: unknown container %q attached to a net", container)
			}
		}
	}
	if !sawInternalCreate {
		return fmt.Errorf("box: plan never creates the --internal sandbox-net")
	}
	if boxConnects != 0 {
		return fmt.Errorf("box: the workload box must be provisioned ON the internal net, not `network connect`ed (%d connects found)", boxConnects)
	}
	if p.GatewayName != "" && gwOutboundConnects != 1 {
		return fmt.Errorf("box: the gateway must have exactly ONE outbound connect, found %d", gwOutboundConnects)
	}
	// The gateway must actually run `runclave proxy` (its command is the egress
	// enforcement). A swapped command (e.g. a permissive forwarder) would defeat the
	// allowlist; if it ran nothing the box would be fail-closed, but a wrong proxy is
	// the risk the guard should catch (defence in depth).
	if p.GatewayName != "" {
		gwRunsProxy := false
		for _, s := range p.Steps {
			a := s.Argv
			if isContainerCreate(a) && flagValueEq(a, "--name") == p.GatewayName {
				gwRunsProxy = argvContainsSeq(a, "runclave", "proxy")
				// Note: the gateway's --allow must be EXACTLY the
				// trusted allowlist - not a broader set an attacker-crafted plan could
				// swap in. A non-empty exact match is required.
				want := strings.Join(p.Allowlist, ",")
				got := flagValueEq(a, "--allow")
				if want == "" || got != want {
					return fmt.Errorf("box: gateway --allow (%q) must equal the trusted allowlist (%q)", got, want)
				}
			}
		}
		if !gwRunsProxy {
			return fmt.Errorf("box: gateway container must run `runclave proxy` (egress enforcement)")
		}
	}
	return nil
}

// flagValueEq returns the value of a flag (space or =form), or "".
func flagValueEq(a []string, flag string) string {
	if v, ok := flagValue(a, flag); ok {
		return v
	}
	return ""
}

// argvContainsSeq reports whether x,y appear adjacent in argv (e.g. "runclave proxy").
func argvContainsSeq(a []string, x, y string) bool {
	for i := 0; i+1 < len(a); i++ {
		if a[i] == x && a[i+1] == y {
			return true
		}
	}
	return false
}

func isDockerSub(a []string, sub, verb string) bool {
	return len(a) >= 3 && a[0] == "docker" && a[1] == sub && a[2] == verb
}
func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}

// dropsNetAdmin reports whether a container-creating argv EFFECTIVELY removes
// CAP_NET_ADMIN. It must be dropped (via --cap-drop ALL or NET_ADMIN) AND NOT
// re-added (via --cap-add ALL or NET_ADMIN). An earlier version of this check
// ignored --cap-add, so `--cap-drop ALL --cap-add NET_ADMIN` falsely passed -
// which would let the gateway install MASQUERADE and route the box out (the exact
// L3 bypass the egress model rests on preventing).
func dropsNetAdmin(a []string) bool {
	dropped := false
	for i := 0; i < len(a); i++ {
		var dropV, addV string
		switch {
		case a[i] == "--cap-drop" && i+1 < len(a):
			dropV = a[i+1]
		case strings.HasPrefix(a[i], "--cap-drop="):
			dropV = strings.TrimPrefix(a[i], "--cap-drop=")
		case a[i] == "--cap-add" && i+1 < len(a):
			addV = a[i+1]
		case strings.HasPrefix(a[i], "--cap-add="):
			addV = strings.TrimPrefix(a[i], "--cap-add=")
		default:
			continue
		}
		if u := strings.ToUpper(dropV); u == "ALL" || strings.Contains(u, "NET_ADMIN") {
			dropped = true
		}
		if u := strings.ToUpper(addV); u == "ALL" || strings.Contains(u, "NET_ADMIN") {
			return false // re-added -> NOT effectively dropped, no matter what was dropped
		}
	}
	return dropped
}

// isContainerCreate reports whether argv creates a container, covering
// `docker run`, `docker create`, and the `docker container run|create` management
// form (verb at a[2]).
func isContainerCreate(a []string) bool {
	if len(a) < 2 || a[0] != "docker" {
		return false
	}
	if a[1] == "run" || a[1] == "create" {
		return true
	}
	return len(a) >= 3 && a[1] == "container" && (a[2] == "run" || a[2] == "create")
}

// allNetworksEqual scans EVERY --network/--net occurrence and returns ok=true only
// if at least one is present AND all equal `want`. Absent -> ok=false (Docker's
// NAT'd-bridge default). A conflicting flag -> ok=false with the offending value.
func allNetworksEqual(a []string, want string) (bad string, ok bool) {
	seen := false
	for i := 0; i < len(a); i++ {
		var v string
		switch {
		case a[i] == "--network" || a[i] == "--net":
			if i+1 < len(a) {
				v = a[i+1]
			}
		case strings.HasPrefix(a[i], "--network="):
			v = strings.TrimPrefix(a[i], "--network=")
		case strings.HasPrefix(a[i], "--net="):
			v = strings.TrimPrefix(a[i], "--net=")
		default:
			continue
		}
		seen = true
		if v != want {
			return v, false
		}
	}
	if !seen {
		return "", false
	}
	return "", true
}

// allNetworksNone is retained for reference/tests; the live guard uses allNetworksEqual.
func allNetworksNone(a []string) (bad string, ok bool) {
	seen := false
	for i := 0; i < len(a); i++ {
		var v string
		switch {
		case a[i] == "--network" || a[i] == "--net":
			if i+1 < len(a) {
				v = a[i+1]
			}
		case strings.HasPrefix(a[i], "--network="):
			v = strings.TrimPrefix(a[i], "--network=")
		case strings.HasPrefix(a[i], "--net="):
			v = strings.TrimPrefix(a[i], "--net=")
		default:
			continue
		}
		seen = true
		if v != "none" {
			return v, false
		}
	}
	if !seen {
		return "", false
	}
	return "", true
}

// flagValue returns the value of `flag` in argv, handling BOTH `--flag value`
// (space form) and `--flag=value` (equals form). Second return is whether the
// flag was present at all. Handling both forms avoids the guard both
// false-passing (--network=bridge read as absent) and false-failing (--network=none).
func flagValue(a []string, flag string) (string, bool) {
	for i := 0; i < len(a); i++ {
		if a[i] == flag {
			if i+1 < len(a) {
				return a[i+1], true
			}
			return "", true
		}
		if v, ok := strings.CutPrefix(a[i], flag+"="); ok {
			return v, true
		}
	}
	return "", false
}

// DestroySteps tears the box down: force-remove the container and its internal
// net. Disposable-by-default (C4): destroy leaves zero residue. `-f` so it works
// whether or not the box is still running.
func (p Plan) DestroySteps() []Step {
	return []Step{
		{Desc: "remove box", Argv: []string{"docker", "rm", "-f", p.Name}},
		{Desc: "remove internal net", Argv: []string{"docker", "network", "rm", p.Net}},
	}
}

// Destroy executes the teardown. Best-effort: it attempts every step and returns
// the first error, so a partially-provisioned box is still cleaned as far as possible.
func (p Plan) Destroy(r Runner) error {
	var firstErr error
	for _, s := range p.DestroySteps() {
		if _, err := r.Run(s.Argv); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("box: teardown step %q: %w", s.Desc, err)
		}
	}
	return firstErr
}

// Execute runs the plan via the Runner. In-box steps are wrapped as
// `docker exec [-e K=V ...] <name> <argv>`; host steps run directly.
func (p Plan) Execute(r Runner) error {
	for _, s := range p.Steps {
		argv := s.Argv
		if s.InBox {
			wrap := []string{"docker", "exec"}
			for k, v := range s.Env {
				wrap = append(wrap, "-e", k+"="+v)
			}
			wrap = append(wrap, p.Name)
			argv = append(wrap, s.Argv...)
		}
		if _, err := r.Run(argv); err != nil {
			return fmt.Errorf("box: step %q failed: %w", s.Desc, err)
		}
	}
	return nil
}
