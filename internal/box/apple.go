package box

import (
	"fmt"
	"strings"

	"github.com/saimeda/runclave/internal/policy"
	"github.com/saimeda/runclave/internal/workspace"
)

// Apple `container` (macOS 26+) backend lifecycle.
//
// UNVERIFIED: this whole path is built but has NOT been tested against a live
// `container` CLI. It assumes `container` mirrors docker's run/exec/cp/network verbs
// (Apple's stated CLI-familiarity goal); the exact flags may need tuning on a real
// macOS 26 box. It is kept SEPARATE from the docker lifecycle so the tested Docker
// path is untouched.
//
// The key difference from Docker: Apple `container` has NO `--internal` no-route
// network primitive, so egress can't be enforced by network topology. Instead an
// in-guest firewall (`runclave lockdown`) drops all egress except the gateway proxy -
// the same allowlist boundary, enforced inside the VM. See runclave-design/
// EGRESS-ENFORCEMENT.md ("Apple container ... the current WEAK SPOT").
//
// Not yet supported on this backend (returns an error / is skipped): the git broker
// socket and --login mounts (they need host bind-mounts whose `container` support is
// unconfirmed). The box + egress + agent run works; those extras are docker-only for now.

// BuildApplePlan builds the Apple-container lifecycle plan. loginMounts/brokerSock
// are rejected (unsupported on this backend today) rather than silently ignored.
func BuildApplePlan(name string, pack *policy.Pack, ws workspace.Plan, brokerSock string, loginMounts []LoginMount, prompt string) (Plan, error) {
	if name == "" || pack == nil {
		return Plan{}, fmt.Errorf("box: name and pack are required")
	}
	if brokerSock != "" {
		return Plan{}, fmt.Errorf("box: the git broker is not supported on the apple-container backend yet")
	}
	if len(loginMounts) > 0 {
		return Plan{}, fmt.Errorf("box: --login is not supported on the apple-container backend yet")
	}
	if len(pack.AllowedDomains()) == 0 {
		return Plan{}, fmt.Errorf("box: empty egress allowlist; refusing (fail-closed)")
	}

	net := sandboxNet(name)
	gwName := name + "-gw"
	proxyAddr := gwName + ":8888"
	gwAllow := strings.Join(pack.AllowedDomains(), ",")
	boxImage := pack.Run.Image
	if boxImage == "" {
		boxImage = "runclave/base:latest"
	}

	steps := []Step{
		// A user network (Apple has no --internal): egress is instead cut in-guest.
		{Desc: "create container network", Argv: []string{"container", "network", "create", net}},
		// Gateway VM: runs the allowlist proxy, the box's only permitted egress.
		{Desc: "provision egress gateway VM", Argv: []string{
			"container", "run", "-d", "--name", gwName, "--network", net,
			"runclave/gateway:latest", "runclave", "proxy", "--addr", "0.0.0.0:8888", "--allow", gwAllow,
		}},
		// Box VM: the per-VM boundary IS the isolation (no cap-drop needed).
		{Desc: "provision box VM", Argv: []string{
			"container", "run", "-d", "--name", name, "--network", net, boxImage, "sleep", "infinity",
		}},
		// THE egress control: drop all egress except the gateway (in-guest, needs root).
		{Desc: "apply in-guest egress lockdown (the --internal analog)", InBox: true,
			Argv: []string{"runclave", "lockdown", "--proxy", proxyAddr}},
	}

	// Seed transfer (bundles are local files - no network needed, fine post-lockdown).
	if ws.HostBundlePath != "" {
		steps = append(steps, Step{Desc: "copy history bundle into box", Argv: []string{"container", "cp", ws.HostBundlePath, name + ":/seed/repo.bundle"}})
	}
	if ws.HostDirtyBundle != "" {
		steps = append(steps, Step{Desc: "copy dirty bundle into box", Argv: []string{"container", "cp", ws.HostDirtyBundle, name + ":/seed/dirty.bundle"}})
	}
	if ws.HostUntrackedTar != "" {
		steps = append(steps, Step{Desc: "copy untracked tar into box", Argv: []string{"container", "cp", ws.HostUntrackedTar, name + ":/seed/untracked.tar"}})
	}
	for _, w := range ws.Steps {
		steps = append(steps, Step{Desc: "seed: " + w.Desc, Argv: w.Argv, InBox: true})
	}

	// Wait for the gateway, then exec the agent (Execute wraps in-box steps with
	// `container exec` because the plan's Runtime is "container").
	steps = append(steps, Step{Desc: "wait for the gateway proxy to be ready", InBox: true,
		Argv: []string{"runclave", "probe", proxyAddr}, BestEffort: true})

	execArgv := append([]string{pack.Run.Command}, pack.Run.HeadlessFlags...)
	if prompt != "" {
		if pack.Run.PromptPositional {
			execArgv = append(execArgv, "--")
		}
		execArgv = append(execArgv, prompt)
	}
	workDir := ""
	if ws.RepoDir != "" {
		workDir = BoxHome + "/" + ws.RepoDir
	}
	env := map[string]string{"HTTP_PROXY": "http://" + proxyAddr, "HTTPS_PROXY": "http://" + proxyAddr}
	for k, v := range pack.Run.ContainerEnv {
		env[k] = v
	}
	var passEnv []string
	if pack.Auth.EnvVar != "" {
		passEnv = append(passEnv, pack.Auth.EnvVar)
	}
	steps = append(steps, Step{
		Desc: "exec agent (egress locked to the gateway)", Argv: execArgv, InBox: true,
		Env: env, PassEnv: passEnv, IsAgentExec: true, WorkDir: workDir,
	})

	return Plan{Name: name, Runtime: "container", Net: net, GatewayName: gwName,
		Allowlist: pack.AllowedDomains(), Steps: steps}, nil
}

// VerifyAppleInvariants checks the apple plan's own boundary properties, since the
// docker-specific VerifyEgressInvariants (which asserts --internal, cap-drop, etc.)
// does not apply to the VM-per-box, in-guest-firewall model.
func (p Plan) VerifyAppleInvariants() error {
	var sawLockdown, sawGatewayProxy, sawAgent bool
	for _, s := range p.Steps {
		// No host bind-mount / host-escape on any provisioning step.
		if workspace.HasHostEscape(s.Argv) && !s.InBox {
			return fmt.Errorf("box: step %q grants host access (W6)", s.Desc)
		}
		joined := strings.Join(s.Argv, " ")
		if s.InBox && strings.Contains(joined, "runclave lockdown") {
			sawLockdown = true
		}
		if strings.Contains(joined, "runclave proxy") && strings.Contains(joined, "--allow "+strings.Join(p.Allowlist, ",")) {
			sawGatewayProxy = true
		}
		if s.IsAgentExec {
			sawAgent = true
		}
	}
	if !sawLockdown {
		return fmt.Errorf("box: apple plan is missing the in-guest egress lockdown - egress would be unrestricted")
	}
	if !sawGatewayProxy {
		return fmt.Errorf("box: apple plan gateway must run `runclave proxy` with exactly the pack allowlist")
	}
	if !sawAgent {
		return fmt.Errorf("box: apple plan has no agent-exec step")
	}
	return nil
}
