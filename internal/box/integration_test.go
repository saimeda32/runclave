//go:build integration

// Real-path integration test: provisions a box the way `runclave .` actually does
// (net + gateway + box, via the lifecycle Plan against a live Docker daemon) and
// asserts the egress boundary is genuinely ENFORCED - a disallowed host gets 403,
// an allowed host gets a 200 tunnel, and the box has no direct internet. This is the
// class of check unit tests can't do; it would have caught the gateway ENTRYPOINT
// bug where the proxy bound loopback with an empty allowlist.
//
// Skipped unless run explicitly:  go test -tags integration ./internal/box/
// Requires `make images` first (runclave/base + runclave/gateway).
package box_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/saimeda/runclave/internal/backend"
	"github.com/saimeda/runclave/internal/box"
	"github.com/saimeda/runclave/internal/policy"
	"github.com/saimeda/runclave/internal/workspace"
)

func imagePresent(img string) bool {
	return exec.Command("docker", "image", "inspect", img).Run() == nil
}

// boxExec runs `docker exec <name> sh -c <script>` and returns combined output.
func boxExec(name, script string) (string, error) {
	out, err := exec.Command("docker", "exec", name, "sh", "-c", script).CombinedOutput()
	return string(out), err
}

func TestIntegrationEgressEnforced(t *testing.T) {
	if !box.DaemonAvailable() {
		t.Skip("docker daemon not available")
	}
	if !imagePresent("runclave/base:latest") || !imagePresent("runclave/gateway:latest") {
		t.Skip("images missing - run `make images` first")
	}
	drv, err := backend.Select("docker")
	if err != nil {
		t.Skipf("no docker driver: %v", err)
	}

	name := "runclave-integ-smoke"
	// Clean any leftover from a prior aborted run, and always tear down at the end.
	_ = box.DestroyPlan(name).Destroy(box.ExecRunner{})
	t.Cleanup(func() { _ = box.DestroyPlan(name).Destroy(box.ExecRunner{}) })

	// A minimal pack: allow example.com, NOT example.org. The "agent" is `true` so the
	// box comes up without needing a cloned repo; the readiness probe still runs.
	pack := &policy.Pack{Agent: "integ-smoke", Scope: "local", Type: "cli-headless"}
	pack.Run.Command = "true"
	pack.Run.Image = "runclave/base:latest"
	pack.Egress.Model = []string{"example.com"}

	ws := workspace.Plan{} // no seed, no repo dir - we only exercise the egress boundary
	plan, err := box.BuildPlan(name, drv, pack, ws, "127.0.0.1:8888", "", false, nil, "", "")
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if err := plan.VerifyEgressInvariants(); err != nil {
		t.Fatalf("plan failed its own invariants: %v", err)
	}
	// Execute the REAL provisioning. If the gateway proxy is misconfigured (e.g. binds
	// loopback), the in-box readiness probe step fails here - catching that bug.
	if err := plan.Execute(box.ExecRunner{}); err != nil {
		t.Fatalf("provisioning failed (this is the real-path check): %v", err)
	}

	gw := plan.GatewayName
	connect := func(host string) string {
		script := "printf 'CONNECT " + host + ":443 HTTP/1.1\\r\\nHost: " + host + ":443\\r\\n\\r\\n' | nc -w5 " + gw + " 8888 | head -1"
		out, _ := boxExec(name, script)
		return strings.TrimSpace(out)
	}

	// Allowed host: the proxy opens the tunnel (200).
	if got := connect("example.com"); !strings.Contains(got, "200") {
		t.Fatalf("allowed host example.com should get a 200 tunnel, got %q", got)
	}
	// Disallowed host: the proxy denies (403). This is the core enforcement claim.
	if got := connect("example.org"); !strings.Contains(got, "403") {
		t.Fatalf("disallowed host example.org must be denied (403), got %q", got)
	}
	// The box has no direct route to the internet: a direct TCP dial to a public IP
	// (bypassing the proxy) must fail, since the box is on the internal net.
	if out, err := boxExec(name, "nc -w4 1.1.1.1 443 </dev/null && echo REACHED || echo blocked"); err == nil {
		if strings.Contains(out, "REACHED") {
			t.Fatalf("box reached the internet directly (isolation broken): %q", strings.TrimSpace(out))
		}
	}
	// The gateway log recorded the decisions (feeds the receipt's egress counts).
	if log, _ := exec.Command("docker", "logs", gw).CombinedOutput(); !strings.Contains(string(log), "egress ALLOW") || !strings.Contains(string(log), "egress DENY") {
		t.Fatalf("gateway log should show both an ALLOW and a DENY, got:\n%s", log)
	}
}
