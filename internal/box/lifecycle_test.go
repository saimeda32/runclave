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
	p, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "/run/runclave/broker.sock", true)
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
	if _, err := BuildPlan("b", nonDocker{}, testPack(), ws, "", "", false); err == nil {
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
	p, err := BuildPlan("runclave-proj", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "/run/runclave/broker.sock", false)
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
	if _, err := BuildPlan("b", dockerDriver{}, testPack(), ws, "127.0.0.1:8888", "/etc", false); err == nil {
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
