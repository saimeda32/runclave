package box

import (
	"strings"
	"testing"

	"github.com/saimeda/runclave/internal/backend"
	"github.com/saimeda/runclave/internal/policy"
	"github.com/saimeda/runclave/internal/workspace"
)

// dockerDriver mimics the real docker driver name so BuildPlan accepts it.
type dockerDriver struct{}

func (dockerDriver) Name() string               { return "docker" }
func (dockerDriver) Strength() backend.Strength { return backend.StrengthContainer }
func (dockerDriver) Available() bool            { return true }
func (dockerDriver) CreateArgs(n, i string) []string {
	return []string{"docker", "run", "-d", "--name", n, "--network", "none", "--cap-drop", "ALL", i}
}

// nonDocker triggers the docker-family scope error.
type nonDocker struct{ dockerDriver }

func (nonDocker) Name() string { return "apple-container" }

type fakeRunner struct{ calls [][]string }

func (r *fakeRunner) Run(argv []string) (string, error) {
	r.calls = append(r.calls, argv)
	return "", nil
}

func testPack() *policy.Pack {
	p := &policy.Pack{Agent: "claude-code", Scope: "local", Type: "cli-headless"}
	p.Run.Command = "claude"
	p.Run.HeadlessFlags = []string{"-p"}
	p.Egress.Model = []string{"api.anthropic.com", "claude.ai"}
	return p
}

func buildOK(t *testing.T) Plan {
	t.Helper()
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "/host/dirty.bundle", "/host/untracked.tar")
	p, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "/run/runclave/broker.sock", true, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The generated plan must satisfy its own egress invariants.
func TestPlanPassesEgressInvariants(t *testing.T) {
	if err := buildOK(t).VerifyEgressInvariants(); err != nil {
		t.Fatalf("generated plan failed its own invariants: %v", err)
	}
}

// Non-docker driver is rejected (honest scope, not a silent wrong-CLI plan).
func TestNonDockerRejected(t *testing.T) {
	ws := workspace.BuildPlan("p", "/h/b", "", "")
	if _, err := BuildPlan("b", nonDocker{}, testPack(), ws, "", "", false, nil, "", ""); err == nil {
		t.Fatal("non-docker driver must be rejected by the docker-family plan")
	}
}

// Critic F1-A: a sandbox-net created WITHOUT --internal must be caught.
func TestGuardRequiresInternalNet(t *testing.T) {
	p := Plan{Name: "b", Net: "runclave-net-b", Steps: []Step{
		{Argv: []string{"docker", "network", "create", "runclave-net-b"}}, // missing --internal
		{Argv: []string{"docker", "network", "connect", "runclave-net-b", "b"}},
	}}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("net created without --internal must be flagged (F1-A)")
	}
}

// Critic F1-B: a provision step with an open network (not --network none) is caught.
func TestGuardRejectsOpenProvisionNet(t *testing.T) {
	p := Plan{Name: "b", Net: "runclave-net-b", Steps: []Step{
		{Argv: []string{"docker", "run", "-d", "--name", "b", "--network", "bridge", "img"}},
		{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
	}}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("provision with --network bridge must be flagged (F1-B)")
	}
}

// Critic F1-C/D: attaching the box to a NON-internal net (positional) is caught,
// even when the sandbox-net string appears elsewhere (container position).
func TestGuardPositionalConnect(t *testing.T) {
	p := Plan{Name: "b", Net: "runclave-net-b", Steps: []Step{
		{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
		// Attach container (named like the net) to the OPEN bridge - net is arg[3].
		{Argv: []string{"docker", "network", "connect", "bridge", "runclave-net-b"}},
	}}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("connecting to a non-internal net must be flagged even with name in container pos (F1-C/D)")
	}
}

// The network check must cover `docker create` and the
// `--net` alias and the `=value` form, not just `docker run --network`.
func TestGuardCoversCreateAndNetAlias(t *testing.T) {
	cases := [][]string{
		{"docker", "create", "--name", "b", "--network", "bridge", "img"},    // create verb
		{"docker", "run", "-d", "--net", "host", "img"},                      // --net alias
		{"docker", "run", "-d", "--network=bridge", "img"},                   // =value form
		{"docker", "create", "--name", "b", "img"},                           // absent -> defaults to bridge
		{"docker", "container", "run", "-d", "--net", "host", "img"},         // docker container run/create form
		{"docker", "container", "create", "--name", "b", "img"},              // mgmt form, absent net
		{"docker", "run", "-d", "--network", "none", "--net", "host", "img"}, // conflicting double flag
	}
	for _, provision := range cases {
		p := Plan{Name: "b", Net: "runclave-net-b", Steps: []Step{
			{Argv: provision},
			{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
		}}
		if err := p.VerifyEgressInvariants(); err == nil {
			t.Fatalf("open/absent network on %v must be flagged", provision)
		}
	}
	// The legitimate case: provisioned ON the sandbox-net (=form) with NET_ADMIN
	// dropped, no gateway (GatewayName empty -> gateway checks skipped).
	ok := Plan{Name: "b", Net: "runclave-net-b", Steps: []Step{
		{Argv: []string{"docker", "run", "-d", "--network=runclave-net-b", "--cap-drop", "ALL", "img"}},
		{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
	}}
	if err := ok.VerifyEgressInvariants(); err != nil {
		t.Fatalf("provision on the sandbox-net with cap-drop must be accepted, got %v", err)
	}
	// --network none is now REJECTED (Docker can't connect out of it - the real-run bug).
	noneCase := Plan{Name: "b", Net: "runclave-net-b", Steps: []Step{
		{Argv: []string{"docker", "run", "-d", "--network", "none", "--cap-drop", "ALL", "img"}},
		{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
	}}
	if err := noneCase.VerifyEgressInvariants(); err == nil {
		t.Fatal("--network none must now be rejected (box must be ON the sandbox-net)")
	}
}

// Seed transfer + proxy env are REAL: docker cp steps exist and the exec step's
// HTTP_PROXY points at the GATEWAY (not localhost) - the box's only egress route.
func TestSeedTransferAndProxyEnvAreReal(t *testing.T) {
	p := buildOK(t)
	var sawCp, sawProxyEnv bool
	for _, s := range p.Steps {
		if strings.HasPrefix(strings.Join(s.Argv, " "), "docker cp /host/repo.bundle") {
			sawCp = true
		}
		if s.InBox && s.Env["HTTP_PROXY"] == "http://runclave-proj-gw:8888" {
			sawProxyEnv = true
		}
	}
	if !sawCp {
		t.Fatal("seed transfer (docker cp of the bundle) must be a real step")
	}
	if !sawProxyEnv {
		t.Fatalf("exec HTTP_PROXY must point at the gateway; steps: %+v", p.Steps)
	}
}

// The gateway is the sole egress point: it runs `runclave proxy`, joins internal
// + outbound, and the box joins internal ONLY. VerifyEgressInvariants must accept
// this shape, and must REJECT the box joining the outbound net.
func TestGatewayIsSoleEgressPoint(t *testing.T) {
	p := buildOK(t)
	if err := p.VerifyEgressInvariants(); err != nil {
		t.Fatalf("gateway plan must pass invariants: %v", err)
	}
	var gwRunsProxy, gwOnOutbound, boxOnlyInternal bool
	boxOnlyInternal = true
	for _, s := range p.Steps {
		a := s.Argv
		j := strings.Join(a, " ")
		if strings.Contains(j, p.GatewayName) && strings.Contains(j, "runclave proxy") {
			gwRunsProxy = true
		}
		// Positional (not substring): docker network connect <net> <container>.
		if len(a) == 5 && a[1] == "network" && a[2] == "connect" {
			net, container := a[3], a[4]
			if container == p.GatewayName && net == p.OutboundNet {
				gwOnOutbound = true
			}
			if container == p.Name && net == p.OutboundNet {
				boxOnlyInternal = false
			}
		}
	}
	if !gwRunsProxy {
		t.Fatal("gateway must run `runclave proxy`")
	}
	if !gwOnOutbound {
		t.Fatal("gateway must be attached to the outbound net (its route to the internet)")
	}
	if !boxOnlyInternal {
		t.Fatal("the box must NEVER be attached to the outbound net")
	}
}

// The guard must reject a container-creating step that does NOT
// drop NET_ADMIN - the anti-L3-bypass property depends on it.
func TestGuardRequiresNetAdminDropped(t *testing.T) {
	p := Plan{Name: "b", Net: "runclave-net-b", GatewayName: "b-gw", OutboundNet: "bridge", Steps: []Step{
		{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
		// box provisioned WITHOUT --cap-drop -> could add a route via a NAT gateway
		{Argv: []string{"docker", "run", "-d", "--name", "b", "--network", "runclave-net-b", "img"}},
	}}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("a container without NET_ADMIN dropped must be flagged (L3-bypass dependency)")
	}
}

// The guard must reject a gateway that doesn't run `runclave proxy`.
func TestGuardRequiresGatewayRunsProxy(t *testing.T) {
	p := Plan{Name: "b", Net: "runclave-net-b", GatewayName: "b-gw", OutboundNet: "bridge", Steps: []Step{
		{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
		// gateway runs a permissive forwarder instead of the allowlist proxy
		{Argv: []string{"docker", "run", "-d", "--name", "b-gw", "--network", "runclave-net-b", "--cap-drop", "ALL", "img", "socat", "TCP-LISTEN:8888,fork", "TCP:evil:80"}},
		{Argv: []string{"docker", "run", "-d", "--name", "b", "--network", "runclave-net-b", "--cap-drop", "ALL", "img"}},
		{Argv: []string{"docker", "network", "connect", "runclave-net-b", "b"}},
	}}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("a gateway not running `runclave proxy` must be flagged")
	}
}

// The guard must REJECT the workload box being attached to the outbound net.
func TestGuardRejectsBoxOnOutbound(t *testing.T) {
	p := Plan{Name: "b", Net: "runclave-net-b", GatewayName: "b-gw", OutboundNet: "bridge", Steps: []Step{
		{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
		{Argv: []string{"docker", "network", "connect", "bridge", "b"}}, // box on outbound - forbidden
	}}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("the workload box on the outbound net must be flagged")
	}
}

// Destroy removes the box and its internal net (disposable-by-default, C4), and
// is best-effort (attempts all steps even if one fails).
func TestDestroyRemovesBoxAndNet(t *testing.T) {
	p := buildOK(t)
	r := &fakeRunner{}
	if err := p.Destroy(r); err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, c := range r.calls {
		joined += strings.Join(c, " ") + "|"
	}
	if !strings.Contains(joined, "docker rm -f runclave-proj") {
		t.Fatalf("destroy must force-remove the box: %s", joined)
	}
	if !strings.Contains(joined, "docker network rm runclave-net-runclave-proj") {
		t.Fatalf("destroy must remove the internal net: %s", joined)
	}
}

// Broker socket mount: the box provision may carry EXACTLY the broker socket
// (a unix socket is IPC, not host-disk access), but nothing else.
func TestBrokerSocketMountNarrowlyAllowed(t *testing.T) {
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "", "")
	// With a broker socket configured, the plan must still pass its invariants.
	p, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "/run/runclave/broker.sock", false, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.VerifyEgressInvariants(); err != nil {
		t.Fatalf("plan with the broker socket mount must pass: %v", err)
	}
	// The box provision step must actually carry the broker --mount.
	var sawMount bool
	for _, s := range p.Steps {
		if strings.Contains(strings.Join(s.Argv, " "), "src=/run/runclave/broker.sock") {
			sawMount = true
		}
	}
	if !sawMount {
		t.Fatal("box provision must mount the broker socket when configured")
	}
}

// A DIR bind (or any non-broker mount) on the box must STILL be rejected - the
// allowance is only the exact broker socket, not a filesystem escape.
func TestNonBrokerMountStillRejected(t *testing.T) {
	// Box provision with a DIR bind mount + the broker socket set.
	p := Plan{Name: "b", Net: "runclave-net-b", GatewayName: "b-gw", OutboundNet: "bridge",
		BrokerSock: "/run/runclave/broker.sock", Steps: []Step{
			{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
			{Argv: []string{"docker", "run", "-d", "--name", "b-gw", "--network", "runclave-net-b", "--cap-drop", "ALL", "img", "runclave", "proxy"}},
			{Argv: []string{"docker", "run", "-d", "--name", "b", "--network", "runclave-net-b", "--cap-drop", "ALL",
				"--mount", "type=bind,src=/etc,dst=/host-etc", "img"}}, // DIR bind - escape
			{Argv: []string{"docker", "network", "connect", "runclave-net-b", "b"}},
		}}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("a non-broker (dir) bind mount on the box must still be rejected")
	}
	// A SECOND mount alongside the allowed broker mount must also be rejected.
	p2 := Plan{Name: "b", Net: "runclave-net-b", GatewayName: "b-gw", OutboundNet: "bridge",
		BrokerSock: "/run/runclave/broker.sock", Steps: []Step{
			{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
			{Argv: []string{"docker", "run", "-d", "--name", "b-gw", "--network", "runclave-net-b", "--cap-drop", "ALL", "img", "runclave", "proxy"}},
			{Argv: []string{"docker", "run", "-d", "--name", "b", "--network", "runclave-net-b", "--cap-drop", "ALL",
				"--mount", "type=bind,src=/run/runclave/broker.sock,dst=/run/runclave/broker.sock,ro",
				"--mount", "type=bind,src=/etc,dst=/x", "img"}}, // broker OK, but a second dir bind
			{Argv: []string{"docker", "network", "connect", "runclave-net-b", "b"}},
		}}
	if err := p2.VerifyEgressInvariants(); err == nil {
		t.Fatal("a second (dir) mount alongside the broker socket must be rejected")
	}
}

// A hostile broker source (src=/ or /etc) must NOT
// be granted the exception - validBrokerSock is the floor. removeBrokerMount must
// refuse to strip it, so HasHostEscape catches the full-host-FS mount.
func TestHostileBrokerSourceRejected(t *testing.T) {
	// A plan whose "broker" mount actually binds / (whole host FS) - must be caught.
	p := Plan{Name: "b", Net: "runclave-net-b", GatewayName: "b-gw", OutboundNet: "bridge",
		BrokerSock: "/", Steps: []Step{
			{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
			{Argv: []string{"docker", "run", "-d", "--name", "b-gw", "--network", "runclave-net-b", "--cap-drop", "ALL", "img", "runclave", "proxy"}},
			{Argv: []string{"docker", "run", "-d", "--name", "b", "--network", "runclave-net-b", "--cap-drop", "ALL",
				"--mount", "type=bind,src=/,dst=/run/runclave/broker.sock,ro", "img"}},
			{Argv: []string{"docker", "network", "connect", "runclave-net-b", "b"}},
		}}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("a broker mount binding the whole host FS (src=/) must be rejected")
	}

	// validBrokerSock floor: only a .sock under the runclave prefix passes.
	for _, bad := range []string{"", "/etc", "/etc/x.sock", "/run/runclave/../etc/x.sock", "/run/runclave/x.sock,ro=bad", "/run/runclave/adir"} {
		if validBrokerSock(bad) {
			t.Fatalf("validBrokerSock(%q) must be false", bad)
		}
	}
	if !validBrokerSock("/run/runclave/broker.sock") {
		t.Fatal("the canonical broker socket must be valid")
	}

	// BuildPlan must refuse an invalid broker path outright (fail-closed).
	ws := workspace.BuildPlan("p", "/h/b", "", "")
	if _, err := BuildPlan("b", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "/etc", false, nil, "", ""); err == nil {
		t.Fatal("BuildPlan must reject a non-socket broker path")
	}
}

// `--cap-drop ALL --cap-add NET_ADMIN` re-grants NET_ADMIN and must
// be rejected - the anti-L3-bypass property depends on NET_ADMIN staying dropped.
func TestGuardRejectsCapAddNetAdmin(t *testing.T) {
	if dropsNetAdmin([]string{"--cap-drop", "ALL", "--cap-add", "NET_ADMIN"}) {
		t.Fatal("--cap-add NET_ADMIN after --cap-drop ALL must count as NOT dropped")
	}
	if dropsNetAdmin([]string{"--cap-drop", "ALL", "--cap-add=ALL"}) {
		t.Fatal("--cap-add=ALL must count as NOT dropped")
	}
	if !dropsNetAdmin([]string{"--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE"}) {
		t.Fatal("a harmless cap-add must not flip the drop")
	}
}

// the gateway's --allow must equal the trusted allowlist; a broader
// allowlist swapped into the gateway command is rejected.
func TestGuardRejectsGatewayAllowlistMismatch(t *testing.T) {
	p := Plan{Name: "b", Net: "runclave-net-b", GatewayName: "b-gw", OutboundNet: "bridge",
		Allowlist: []string{"api.anthropic.com"}, Steps: []Step{
			{Argv: []string{"docker", "network", "create", "--internal", "runclave-net-b"}},
			// gateway runs proxy but with a BROADER allowlist than the pack
			{Argv: []string{"docker", "run", "-d", "--name", "b-gw", "--network", "runclave-net-b", "--cap-drop", "ALL", "img", "runclave", "proxy", "--allow", "api.anthropic.com,evil.com"}},
			{Argv: []string{"docker", "network", "connect", "bridge", "b-gw"}},
			{Argv: []string{"docker", "run", "-d", "--name", "b", "--network", "runclave-net-b", "--cap-drop", "ALL", "img"}},
		}}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("a gateway --allow broader than the trusted allowlist must be rejected")
	}
}

// Execute wraps in-box steps as `docker exec [-e ...] <name>` and runs all in order.
func TestExecuteWrapsAndSequences(t *testing.T) {
	p := buildOK(t)
	r := &fakeRunner{}
	if err := p.Execute(r); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != len(p.Steps) {
		t.Fatalf("ran %d, want %d", len(r.calls), len(p.Steps))
	}
	for i, s := range p.Steps {
		if s.InBox && !strings.HasPrefix(strings.Join(r.calls[i], " "), "docker exec ") {
			t.Fatalf("in-box step not wrapped: %v", r.calls[i])
		}
	}
}

// An opt-in login mount is a DECLARED hole: the plan must (a) carry exactly the
// requested read-only bind, (b) still pass its own host-escape guard because that
// one bind is sanctioned, and (c) reject anything not under the box home or with a
// traversal/absolute-outside path.
func TestLoginMountAllowedButNarrow(t *testing.T) {
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "", "")
	good := []LoginMount{{HostPath: "/Users/me/.claude", BoxPath: BoxHome + "/.claude"}}
	p, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "", true, good, "/Users/me", "")
	if err != nil {
		t.Fatalf("a valid login mount must be accepted: %v", err)
	}
	// The read-only bind is actually present on the box-create step.
	joined := ""
	for _, s := range p.Steps {
		joined += strings.Join(s.Argv, " ") + "\n"
	}
	if !strings.Contains(joined, "type=bind,src=/Users/me/.claude,dst="+BoxHome+"/.claude,ro") {
		t.Fatalf("login mount must appear as a read-only bind, got:\n%s", joined)
	}
	// And the plan still passes its own guard - the sanctioned mount is stripped
	// before the escape check, nothing else is.
	if err := p.VerifyEgressInvariants(); err != nil {
		t.Fatalf("plan with a sanctioned login mount must pass invariants: %v", err)
	}
}

// A pack that tries to mount outside the box home, the host root, or via traversal
// is rejected at plan build - the hole cannot be widened past the declared shape.
func TestLoginMountRejectsEscape(t *testing.T) {
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "", "")
	bad := [][]LoginMount{
		{{HostPath: "/", BoxPath: BoxHome + "/x"}},                          // host root: whole-FS mount
		{{HostPath: "/etc/shadow", BoxPath: "/etc/shadow"}},                 // box path outside the box home
		{{HostPath: "/etc", BoxPath: BoxHome + "/.claude"}},                 // source outside the home root
		{{HostPath: "/Users/other/.claude", BoxPath: BoxHome + "/.claude"}}, // another user's home
		{{HostPath: "/Users/me/.claude", BoxPath: BoxHome + "/../etc"}},     // traversal in box path
		{{HostPath: "/Users/me/,x", BoxPath: BoxHome + "/.claude"}},         // option smuggling via comma
	}
	for _, m := range bad {
		if _, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "", true, m, "/Users/me", ""); err == nil {
			t.Fatalf("login mount %v must be rejected", m)
		}
	}
	// And with NO host root configured, a login mount is refused outright.
	if _, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "",
		true, []LoginMount{{HostPath: "/Users/me/.claude", BoxPath: BoxHome + "/.claude"}}, "", ""); err == nil {
		t.Fatal("login mounts with no host root must be refused")
	}
}

// An attacker-crafted plan that hand-inserts an UNsanctioned mount (not matching
// any declared LoginMount) must still be caught by the guard - stripping is only
// for the exact declared specs.
func TestGuardCatchesUnsanctionedMount(t *testing.T) {
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "", "")
	p, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "",
		true, []LoginMount{{HostPath: "/Users/me/.claude", BoxPath: BoxHome + "/.claude"}}, "/Users/me", "")
	if err != nil {
		t.Fatal(err)
	}
	// Splice a DIFFERENT host mount into the box-create step, as a compromised
	// planner might. It is not in p.LoginMounts, so it is not stripped -> caught.
	for i, s := range p.Steps {
		if isContainerCreate(s.Argv) && flagValueEq(s.Argv, "--name") == p.Name {
			evil := append([]string{s.Argv[0], s.Argv[1], "--mount", "type=bind,src=/etc,dst=" + BoxHome + "/etc,ro"}, s.Argv[2:]...)
			p.Steps[i].Argv = evil
		}
	}
	if err := p.VerifyEgressInvariants(); err == nil {
		t.Fatal("an unsanctioned host mount must be caught by the guard")
	}
}

// A task prompt is appended to the agent exec as its final argument, and the agent
// runs IN the cloned repo dir (docker exec -w), not the box home.
func TestPromptAndWorkdir(t *testing.T) {
	ws := workspace.BuildPlan("myproj", "/host/repo.bundle", "", "")
	p, err := BuildPlan("runclave-myproj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "", true, nil, "", "fix the flaky test")
	if err != nil {
		t.Fatal(err)
	}
	var exec Step
	for _, s := range p.Steps {
		if s.IsAgentExec {
			exec = s
		}
	}
	// The prompt is the LAST argv element (claude -p "<prompt>").
	if exec.Argv[len(exec.Argv)-1] != "fix the flaky test" {
		t.Fatalf("prompt must be the final exec arg, got %v", exec.Argv)
	}
	if exec.WorkDir != BoxHome+"/myproj" {
		t.Fatalf("agent must run in the cloned repo dir, got WorkDir %q", exec.WorkDir)
	}
	// It renders with -w pointing at the repo.
	r := &fakeRunner{}
	if err := p.Execute(r); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls[len(r.calls)-1], " ")
	if !strings.Contains(joined, "-w "+BoxHome+"/myproj ") || !strings.HasSuffix(joined, "fix the flaky test") {
		t.Fatalf("exec must render with -w <repo> and the prompt, got %q", joined)
	}
	// No prompt -> no trailing prompt arg (the exec is just command+flags).
	p2, _ := BuildPlan("runclave-myproj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "", true, nil, "", "")
	for _, s := range p2.Steps {
		if s.IsAgentExec && s.Argv[len(s.Argv)-1] != "-p" {
			t.Fatalf("no prompt must leave exec as command+flags, got %v", s.Argv)
		}
	}
}

// A task prompt that happens to contain "docker.sock" or start with a dash must NOT
// trip the host-escape/network guard - those checks are for host-side steps, and the
// prompt rides on an in-box docker-exec step.
func TestPromptDoesNotTripHostEscapeGuard(t *testing.T) {
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "", "")
	for _, task := range []string{"fix the docker.sock permission bug", "-v is the verbose flag to remove", "make --network host work"} {
		p, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "", true, nil, "", task)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.VerifyEgressInvariants(); err != nil {
			t.Fatalf("a task prompt %q must not fail the guard: %v", task, err)
		}
	}
}

// A positional-prompt pack (codex) gets a `--` separator before the task, so a task
// starting with a dash is not parsed as an agent flag.
func TestPositionalPromptSeparator(t *testing.T) {
	pack := testPack()
	pack.Run.PromptPositional = true
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "", "")
	p, err := BuildPlan("runclave-proj", dockerDriver{}, pack, ws, "127.0.0.1:8888", "", true, nil, "", "--help me")
	if err != nil {
		t.Fatal(err)
	}
	var exec Step
	for _, s := range p.Steps {
		if s.IsAgentExec {
			exec = s
		}
	}
	// ... command flags -- "--help me"
	if exec.Argv[len(exec.Argv)-2] != "--" || exec.Argv[len(exec.Argv)-1] != "--help me" {
		t.Fatalf("positional prompt must be preceded by `--`, got %v", exec.Argv)
	}
	// A non-positional pack must NOT insert `--`.
	p2, _ := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "", true, nil, "", "do X")
	for _, s := range p2.Steps {
		if s.IsAgentExec {
			for _, tok := range s.Argv {
				if tok == "--" {
					t.Fatalf("non-positional pack must not insert `--`, got %v", s.Argv)
				}
			}
		}
	}
}

// --shell rewrites only the FINAL step into an interactive in-box shell, keeping
// the box/gateway/seed and the egress env intact, and it still passes the guard.
func TestInteractiveShellPlan(t *testing.T) {
	p := buildOK(t)
	nSteps := len(p.Steps)
	// Find the agent-exec step up front, so we can prove --shell rewrote THAT one.
	var execEnv map[string]string
	execIdx := -1
	for i, s := range p.Steps {
		if s.IsAgentExec {
			execIdx, execEnv = i, s.Env
		}
	}
	if execIdx < 0 {
		t.Fatal("plan must have an agent-exec step")
	}
	if !p.SetInteractiveShell("bash", true) {
		t.Fatal("SetInteractiveShell must report it rewrote the exec step")
	}
	if len(p.Steps) != nSteps {
		t.Fatalf("--shell must not add or drop steps, got %d want %d", len(p.Steps), nSteps)
	}
	// The rewritten step is the SAME step that was the agent exec (found by flag).
	rw := p.Steps[execIdx]
	if !rw.Interactive || !rw.TTY || len(rw.Argv) != 1 || rw.Argv[0] != "bash" {
		t.Fatalf("agent-exec step must become an interactive bash, got %+v", rw)
	}
	// The shell keeps the same egress env (so it's inside the same boundary + proxy).
	if rw.Env["HTTP_PROXY"] != execEnv["HTTP_PROXY"] || rw.Env["HTTP_PROXY"] == "" {
		t.Fatalf("shell must keep the agent's proxy env, got %v", rw.Env)
	}
	if err := p.VerifyEgressInvariants(); err != nil {
		t.Fatalf("interactive-shell plan must pass invariants: %v", err)
	}
	// With a TTY it renders as an attached `docker exec -it <box> bash`.
	r := &fakeRunner{}
	if err := p.Execute(r); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.calls[execIdx], " ")
	// Runs in the cloned repo (-w) with a TTY (-it) and is a bash shell.
	if !strings.Contains(joined, "docker exec -w /home/runclave/proj -it ") || !strings.HasSuffix(joined, " bash") {
		t.Fatalf("shell step must render as `docker exec -w <repo> -it <box> bash`, got %q", joined)
	}
	// Without a TTY (piped stdin) it must use -i only, never -t.
	p2 := buildOK(t)
	p2.SetInteractiveShell("sh", false)
	r2 := &fakeRunner{}
	if err := p2.Execute(r2); err != nil {
		t.Fatal(err)
	}
	last := strings.Join(r2.calls[len(r2.calls)-1], " ")
	if !strings.Contains(last, " -i ") || strings.Contains(last, "-it") {
		t.Fatalf("no-TTY shell must render -i (no -t), got %q", last)
	}
}

// The broker socket may live in any runclave-OWNED directory (so a per-session
// socket under the user's runtime/cache dir works without root), but an arbitrary
// host path is never eligible for the mount exception.
func TestValidBrokerSock(t *testing.T) {
	good := []string{
		"/run/runclave/broker.sock",
		"/home/u/.cache/runclave/runclave-proj/broker.sock",
		"/tmp/runclave-abc/broker.sock",
		"/Users/me/Library/Caches/runclave/box/broker.sock",
	}
	for _, s := range good {
		if !validBrokerSock(s) {
			t.Fatalf("expected %q to be a valid broker socket", s)
		}
	}
	bad := []string{
		"",
		"relative/runclave/x.sock",       // not absolute
		"/etc/passwd",                    // not a .sock, no runclave dir
		"/home/u/.ssh/id_rsa.sock",       // .sock but no runclave-owned dir
		"/run/runclave/../etc/evil.sock", // traversal
		"/run/runclave/x.sock,dst=/,ro",  // option smuggling
		"/runclavehack/x.sock",           // dir name is not "runclave"/"runclave-*"
	}
	for _, s := range bad {
		if validBrokerSock(s) {
			t.Fatalf("expected %q to be REJECTED as a broker socket", s)
		}
	}
}

// When a broker socket is present, the plan points in-box git at the broker
// credential helper (so a push fetches a short-lived token) and turns on
// useHttpPath (so the broker can log any repo mismatch). Without a socket, no
// such step exists.
func TestBrokerWiresGitCredentialHelper(t *testing.T) {
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "", "")
	withSock, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "/run/runclave/broker.sock", true, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, s := range withSock.Steps {
		joined += strings.Join(s.Argv, " ") + "\n"
	}
	if !strings.Contains(joined, "credential.helper !runclave credential") {
		t.Fatalf("broker socket must wire the git credential helper, got:\n%s", joined)
	}
	if !strings.Contains(joined, "credential.useHttpPath true") {
		t.Fatalf("broker socket must enable useHttpPath, got:\n%s", joined)
	}
	// No socket -> no credential-helper wiring.
	noSock, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "", true, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range noSock.Steps {
		if strings.Contains(strings.Join(s.Argv, " "), "credential.helper") {
			t.Fatal("no broker socket must mean no credential-helper step")
		}
	}
}

// A secret auth token is passed to the box BY NAME only. Its value must never
// appear on an argv or in a rendered plan (host `ps` / --dry-run leak). The value
// is supplied by runclave's own environment at exec time, not by the plan.
func TestAuthTokenPassedByNameNotValue(t *testing.T) {
	pack := testPack()
	pack.Auth.EnvVar = "CLAUDE_CODE_OAUTH_TOKEN"
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "", "")
	p, err := BuildPlan("runclave-proj", dockerDriver{}, pack, ws, "127.0.0.1:8888", "", true, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// The exec step must declare the token as pass-by-name, and must NOT stash the
	// value in Env (which renders as -e K=V).
	var exec Step
	for _, s := range p.Steps {
		if strings.HasPrefix(s.Desc, "exec agent") {
			exec = s
		}
	}
	found := false
	for _, n := range exec.PassEnv {
		if n == "CLAUDE_CODE_OAUTH_TOKEN" {
			found = true
		}
	}
	if !found {
		t.Fatalf("auth token must be in PassEnv, got %v", exec.PassEnv)
	}
	if _, ok := exec.Env["CLAUDE_CODE_OAUTH_TOKEN"]; ok {
		t.Fatal("auth token must NOT be in Env (that renders its value as -e K=V)")
	}
	// Render the whole plan the way --dry-run does; the token NAME may appear but a
	// value assignment (NAME=...) must not.
	r := &fakeRunner{}
	if err := p.Execute(r); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.calls {
		for _, tok := range c {
			if strings.HasPrefix(tok, "CLAUDE_CODE_OAUTH_TOKEN=") {
				t.Fatalf("token value leaked onto argv: %q", tok)
			}
		}
	}
	// The name-only form must be present on the exec step.
	joined := ""
	for _, c := range r.calls {
		joined += strings.Join(c, " ") + "\n"
	}
	if !strings.Contains(joined, "-e CLAUDE_CODE_OAUTH_TOKEN ") && !strings.Contains(joined, "-e CLAUDE_CODE_OAUTH_TOKEN\n") {
		t.Fatalf("expected name-only -e CLAUDE_CODE_OAUTH_TOKEN in rendered plan, got:\n%s", joined)
	}
}
