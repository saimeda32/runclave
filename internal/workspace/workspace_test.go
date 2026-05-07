package workspace

import (
	"strings"
	"testing"
)

// D13 (W1/W6): the workspace must be a full clone, never a bind mount. Assert
// the detection guard catches every host bind-mount form, and passes clean argv.
func TestHasHostBindMount(t *testing.T) {
	mounted := [][]string{
		{"docker", "run", "-v", "/Users/me/repo:/work", "img"},
		{"docker", "run", "-v/Users/me/repo:/work", "img"},
		{"docker", "run", "--volume", "/h:/c", "img"},
		{"docker", "run", "--volume=/h:/c", "img"},
		{"container", "run", "--mount", "type=bind,src=/h,dst=/c", "img"},
	}
	for _, argv := range mounted {
		if !HasHostBindMount(argv) {
			t.Fatalf("failed to detect host bind mount in %v (W6 guard broken)", argv)
		}
	}
	clean := [][]string{
		{"docker", "run", "-d", "--name", "box", "--network", "none", "img", "sleep", "infinity"},
		{"container", "run", "-d", "--name", "box", "img", "sleep", "infinity"},
	}
	for _, argv := range clean {
		if HasHostBindMount(argv) {
			t.Fatalf("false positive bind-mount detection in %v", argv)
		}
	}
}

// The broadened guard (W1/W6) must catch host-disk escapes that aren't -v mounts.
// Asserts against HasHostEscape - the SAME function the production guard in
// cli.go calls - so the test can't pass while production fails (the masking-test
// bug caught in review).
func TestHasHostEscapeBeyondBindMounts(t *testing.T) {
	escapes := [][]string{
		{"docker", "run", "--volumes-from", "other", "img"},
		{"docker", "run", "--volumes-from=other", "img"},
		{"docker", "run", "--device", "/dev/sda", "img"},
		{"docker", "run", "--device=/dev/sda", "img"},
		{"docker", "run", "--privileged", "img"},
		{"docker", "run", "--cap-add=SYS_ADMIN", "img"},
		{"docker", "run", "--cap-add", "SYS_ADMIN", "img"}, // space-separated form
		{"docker", "run", "--cap-add=sys_admin", "img"},    // lowercase
		{"docker", "run", "--cap-add=ALL", "img"},          // ALL includes SYS_ADMIN
		{"docker", "run", "--cap-add", "ALL", "img"},       // ALL, space form
	}
	for _, argv := range escapes {
		if !HasHostEscape(argv) {
			t.Fatalf("host-disk escape not detected by HasHostEscape: %v", argv)
		}
	}
	// A harmless cap-add must not trip the check (no false positive).
	if HasHostEscape([]string{"docker", "run", "--cap-add=NET_BIND_SERVICE", "img"}) {
		t.Fatal("false positive on a non-dangerous cap-add")
	}
}

// Default plan carries the full dirty state - tracked AND untracked (W1a).
// The old plan used `git diff HEAD`, which silently dropped untracked files;
// this asserts the untracked payload is present so that bug can't regress.
func TestBuildPlanDirty(t *testing.T) {
	dirty := BuildPlan("repo", "/seed/repo.bundle", "/seed/dirty.bundle", "/seed/untracked.tar")
	joined := ""
	for _, s := range dirty.Steps {
		joined += s.Desc + "|"
	}
	if !strings.Contains(joined, "untracked") {
		t.Fatalf("dirty plan must restore untracked files (the diff-HEAD bug); got %q", joined)
	}
	if !strings.Contains(joined, "staged+unstaged") {
		t.Fatalf("dirty plan must apply tracked staged+unstaged; got %q", joined)
	}
	clean := BuildPlan("repo", "/seed/repo.bundle", "", "")
	if len(clean.Steps) != 1 {
		t.Fatalf("clean plan should be HEAD-only, got %v", clean.Describe())
	}
}

// CreateSeedArtifacts: repo.bundle always; dirty.bundle only when stash create
// returns a hash; untracked.tar only when there are untracked files.
func TestCreateSeedArtifacts(t *testing.T) {
	run := func(argv []string) (string, error) {
		joined := strings.Join(argv, " ")
		switch {
		case strings.Contains(joined, "stash create"):
			return "abc123stashhash\n", nil
		case strings.Contains(joined, "ls-files --others"):
			return "u.txt\n", nil
		}
		return "", nil
	}
	if b, d, u, err := CreateSeedArtifacts("/repo", "/seed", true, run); err != nil || b == "" || d == "" || u == "" {
		t.Fatalf("all three payloads expected, got b=%q d=%q u=%q err=%v", b, d, u, err)
	}
	// Clean repo: empty stash + empty ls-files -> only the bundle.
	clean := func(argv []string) (string, error) { return "", nil }
	if b, d, u, err := CreateSeedArtifacts("/repo", "/seed", true, clean); err != nil || b == "" || d != "" || u != "" {
		t.Fatalf("clean repo: only bundle expected, got b=%q d=%q u=%q err=%v", b, d, u, err)
	}
	// --clean (includeDirty=false): bundle only, never touches stash/ls.
	if b, d, u, err := CreateSeedArtifacts("/repo", "/seed", false, run); err != nil || b == "" || d != "" || u != "" {
		t.Fatalf("--clean: only bundle expected, got b=%q d=%q u=%q err=%v", b, d, u, err)
	}
}

// The untracked capture must run WITHOUT a shell and pass each filename as its
// own argv element, so a repo path or filename with shell metacharacters cannot
// inject a host command (and paths with spaces still work).
func TestUntrackedCaptureIsShellFree(t *testing.T) {
	var argvs [][]string
	run := func(argv []string) (string, error) {
		argvs = append(argvs, argv)
		if strings.Contains(strings.Join(argv, " "), "ls-files --others") {
			// two untracked files, one with a space and a shell metachar in the name
			return "u.txt\x00weird; name.txt\x00", nil
		}
		return "", nil
	}
	if _, _, u, err := CreateSeedArtifacts("/repo dir", "/seed", true, run); err != nil || u == "" {
		t.Fatalf("expected an untracked tar, got u=%q err=%v", u, err)
	}
	for _, a := range argvs {
		if a[0] == "sh" || a[0] == "bash" {
			t.Fatalf("untracked capture must not use a shell, got %v", a)
		}
		if a[0] == "tar" {
			// the filenames must be discrete argv elements, not one concatenated string
			joined := strings.Join(a, " ")
			if !strings.Contains(joined, "u.txt") || !strings.Contains(joined, "weird; name.txt") {
				t.Fatalf("tar must receive each file as its own arg, got %v", a)
			}
		}
	}
}

// The full-clone step uses `git clone` of a bundle - full history, not shallow.
func TestFullCloneNotShallow(t *testing.T) {
	p := BuildPlan("repo", "/seed/repo.bundle", "", "")
	argv := strings.Join(p.Steps[0].Argv, " ")
	if !strings.Contains(argv, "git clone") {
		t.Fatalf("expected git clone, got %q", argv)
	}
	if strings.Contains(argv, "--depth") {
		t.Fatal("clone must not be shallow (W1 full working tree)")
	}
}
