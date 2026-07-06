package box

import (
	"strings"
	"testing"

	"github.com/saimeda/runclave/internal/policy"
	"github.com/saimeda/runclave/internal/workspace"
)

// The Apple plan uses `container` verbs, applies the in-guest lockdown (its --internal
// analog), runs the agent, and passes its own invariants. UNVERIFIED against a live
// container CLI; this only asserts the plan STRUCTURE is what we intend.
func TestBuildApplePlanStructure(t *testing.T) {
	pack := &policy.Pack{Agent: "codex", Scope: "local", Type: "cli-headless"}
	pack.Run.Command = "codex"
	pack.Run.HeadlessFlags = []string{"exec"}
	pack.Run.PromptPositional = true
	pack.Egress.Model = []string{"api.openai.com"}
	ws := workspace.BuildPlan("proj", "/host/repo.bundle", "", "")

	p, err := BuildApplePlan("runclave-proj", pack, ws, "", nil, "fix it")
	if err != nil {
		t.Fatal(err)
	}
	if p.Runtime != "container" {
		t.Fatalf("apple plan must set Runtime=container, got %q", p.Runtime)
	}
	joined := ""
	for _, s := range p.Steps {
		joined += strings.Join(s.Argv, " ") + "|"
	}
	for _, want := range []string{
		"container network create runclave-net-runclave-proj",
		"container run -d --name runclave-proj-gw",
		"runclave proxy --addr 0.0.0.0:8888 --allow api.openai.com",
		"runclave lockdown --proxy runclave-proj-gw:8888",
		"container cp /host/repo.bundle runclave-proj:/seed/repo.bundle",
		"codex exec -- fix it",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("apple plan missing %q in:\n%s", want, joined)
		}
	}
	if err := p.VerifyAppleInvariants(); err != nil {
		t.Fatalf("apple plan must pass its own invariants: %v", err)
	}
	// Broker + --login are not supported on this backend yet: they must be refused.
	if _, err := BuildApplePlan("runclave-proj", pack, ws, "/run/x.sock", nil, ""); err == nil {
		t.Fatal("apple plan must reject a broker socket (unsupported)")
	}
	if _, err := BuildApplePlan("runclave-proj", pack, ws, "", []LoginMount{{HostPath: "/h", BoxPath: BoxHome + "/x"}}, ""); err == nil {
		t.Fatal("apple plan must reject --login mounts (unsupported)")
	}
}
