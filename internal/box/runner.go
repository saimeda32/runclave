package box

import (
	"os"
	"os/exec"
	"strings"
)

// ExecRunner is the real Runner: it shells out via os/exec. Used by the wired
// `runclave .` path only when a daemon is actually present.
type ExecRunner struct{}

// Run executes argv and returns combined output.
func (ExecRunner) Run(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", nil
	}
	// cmd.Env is left nil so the child inherits runclave's environment. That is what
	// lets `docker exec -e NAME` (Step.PassEnv) read a secret's value from here
	// without the value ever appearing on an argv.
	cmd := exec.Command(argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// RunInteractive runs argv attached to the caller's terminal, for an in-box shell
// (`docker exec -it … bash`). stdio is inherited so the user gets a real TTY; the
// inherited environment still supplies any `-e NAME` pass-through secret.
func (ExecRunner) RunInteractive(argv []string) error {
	if len(argv) == 0 {
		return nil
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// DaemonAvailable reports whether a docker daemon is reachable, so the caller can
// integration-guard the real Execute path (unit paths never touch a daemon).
func DaemonAvailable() bool {
	return exec.Command("docker", "info").Run() == nil
}

// DryRunner records commands without executing - for `--dry-run` and tests.
type DryRunner struct{ Calls [][]string }

func (d *DryRunner) Run(argv []string) (string, error) {
	d.Calls = append(d.Calls, argv)
	return "", nil
}

// Rendered returns the recorded commands as human-readable lines.
func (d *DryRunner) Rendered() string {
	var b strings.Builder
	for _, c := range d.Calls {
		b.WriteString(strings.Join(c, " "))
		b.WriteByte('\n')
	}
	return b.String()
}
