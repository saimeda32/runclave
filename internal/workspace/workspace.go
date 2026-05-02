// Package workspace provisions the box's copy of the repo. The box gets a FULL,
// real git clone (history + refs) plus the host's uncommitted working-tree
// changes by default, so the engineer can switch branches / rebase / do anything
// inside the box (W1/W1a). It is NEVER a bind mount of the host tree (W1/W6):
// the agent has no path to the real disk. Work comes back out via git (W2) or
// explicit export (W5).
package workspace

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Plan is the set of steps to seed a box from a host repo. Returned as data so
// it is testable and auditable (we assert it contains no host bind-mount). The
// Host*Path fields are the REAL host artifacts the lifecycle `docker cp`s in; an
// empty path means that payload is absent (no dirty state / no untracked files).
type Plan struct {
	HostBundlePath   string // git bundle of full history (required)
	HostDirtyBundle  string // bundle of the stash-create commit (tracked dirty), optional
	HostUntrackedTar string // tar of untracked files, optional
	// Steps are the shell steps run INSIDE the box to reconstruct the repo.
	Steps []Step
}

// Step is one command executed inside the box during provisioning.
type Step struct {
	Desc string
	Argv []string
}

// BuildPlan constructs the provisioning plan. repoName is the destination dir
// inside the box; bundlePath is a git bundle of the host repo transferred in.
//
// Git has TWO disjoint payloads and no single command moves both (see
// runclave-design/): committed history (git bundle) and
// dirty state (staged+unstaged+untracked). The dirty side is itself split:
// `git stash create` captures tracked staged/unstaged as a commit object, but
// UNTRACKED files must be carried separately as a tar - `git diff HEAD` (the old
// approach) silently dropped them.
func BuildPlan(repoName, bundlePath, dirtyBundle, untrackedTar string) Plan {
	steps := []Step{
		{Desc: "clone full history from bundle", Argv: []string{"git", "clone", "/seed/repo.bundle", repoName}},
	}
	// Tracked dirty state (only if a stash bundle exists): fetch + stash apply so
	// the staged/unstaged split is preserved (W1a).
	if dirtyBundle != "" {
		steps = append(steps,
			Step{Desc: "fetch tracked dirty state (stash bundle)", Argv: []string{"git", "-C", repoName, "fetch", "/seed/dirty.bundle", "refs/runclave/seed-stash"}},
			Step{Desc: "apply tracked staged+unstaged changes", Argv: []string{"git", "-C", repoName, "stash", "apply", "FETCH_HEAD"}},
		)
	}
	// Untracked files (only if any): NOT in any git object; carried as a tar.
	if untrackedTar != "" {
		steps = append(steps,
			Step{Desc: "restore untracked files", Argv: []string{"tar", "xf", "/seed/untracked.tar", "-C", repoName}},
		)
	}
	return Plan{HostBundlePath: bundlePath, HostDirtyBundle: dirtyBundle, HostUntrackedTar: untrackedTar, Steps: steps}
}

// RunFunc executes a host command and returns its stdout. Injected so
// CreateSeedArtifacts is testable without a real git repo.
type RunFunc func(argv []string) (stdout string, err error)

// CreateSeedArtifacts produces the two-payload seed on the HOST in seedDir:
// repo.bundle (full history, always), dirty.bundle (tracked staged+unstaged, only
// if there IS dirty state), untracked.tar (only if there ARE untracked files). It
// returns the real paths for whichever exist ("" for absent payloads) - so the
// lifecycle only copies+applies what actually exists. Non-destructive: `git stash
// create` does not touch the user's working tree.
func CreateSeedArtifacts(repoDir, seedDir string, includeDirty bool, run RunFunc) (bundle, dirty, untracked string, err error) {
	bundle = filepath.Join(seedDir, "repo.bundle")
	if _, err = run(HostBundleArgv(repoDir, bundle)); err != nil {
		return "", "", "", fmt.Errorf("seed: history bundle: %w", err)
	}
	if !includeDirty {
		return bundle, "", "", nil
	}
	hash, err := run(HostStashCreateArgv(repoDir))
	if err != nil {
		return "", "", "", fmt.Errorf("seed: stash create: %w", err)
	}
	if h := strings.TrimSpace(hash); h != "" {
		dirty = filepath.Join(seedDir, "dirty.bundle")
		// `git bundle create <file> <bare-hash>` fails - a bundle needs a REF, not a
		// loose commit. Name the stash commit with a temp runclave ref, bundle that,
		// then delete the ref (cleaned up even if the bundle fails -> no stray ref).
		const ref = "refs/runclave/seed-stash"
		if _, err = run([]string{"git", "-C", repoDir, "update-ref", ref, h}); err != nil {
			return "", "", "", fmt.Errorf("seed: name stash: %w", err)
		}
		_, bErr := run([]string{"git", "-C", repoDir, "bundle", "create", dirty, ref})
		_, _ = run([]string{"git", "-C", repoDir, "update-ref", "-d", ref}) // always cleanup
		if bErr != nil {
			return "", "", "", fmt.Errorf("seed: dirty bundle: %w", bErr)
		}
	}
	// List untracked files NUL-separated, then tar them by explicit argv - NO shell.
	// The old `sh -c "cd " + repoDir + …` was a host command-injection hole (a repo
	// dir named `x;$(cmd)` ran on the host) and broke on paths with spaces. Passing
	// each filename as a separate exec argv is injection-proof and space-safe. tar
	// has no -h, so untracked symlinks are stored as links (host file contents never
	// enter the box).
	others, err := run([]string{"git", "-C", repoDir, "ls-files", "--others", "--exclude-standard", "-z"})
	if err != nil {
		return "", "", "", fmt.Errorf("seed: ls untracked: %w", err)
	}
	var files []string
	for _, f := range strings.Split(others, "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	if len(files) > 0 {
		untracked = filepath.Join(seedDir, "untracked.tar")
		args := append([]string{"tar", "-C", repoDir, "-cf", untracked, "--"}, files...)
		if _, err = run(args); err != nil {
			return "", "", "", fmt.Errorf("seed: untracked tar: %w", err)
		}
	}
	return bundle, dirty, untracked, nil
}

// HasHostEscape inspects a driver's create-argv for flags that would give the
// box a path to the real host disk - bind mounts, --volumes-from, --device,
// --privileged, --cap-add SYS_ADMIN/ALL, --pid=host (procfs reach into host FS).
//
// Scope (important, so this isn't mistaken for more than it is): it guards OUR
// OWN backend drivers' generated argv - a defense-in-depth check that runclave
// never accidentally introduces host access in code we author. It is NOT a
// security boundary against adversarial argv (that would be the command-denylist
// antipattern, N8); the real boundary is the backend/VM. It aims to be broad but
// is a best-effort denylist, not a proof of isolation.
func HasHostEscape(createArgv []string) bool {
	// dangerousCap reports whether a capability value grants host-mount ability.
	dangerousCap := func(v string) bool {
		v = strings.ToLower(v)
		return strings.Contains(v, "sys_admin") || v == "all" || strings.Contains(v, "all")
	}
	for i, a := range createArgv {
		la := strings.ToLower(a)
		// Flags whose VALUE is the following token (space-separated form). We must
		// look ahead, or `--cap-add SYS_ADMIN` slips past (the flag token itself
		// never contains the value).
		next := ""
		if i+1 < len(createArgv) {
			next = createArgv[i+1]
		}
		switch {
		// bind mounts (all forms)
		case la == "-v" || la == "--volume" || la == "--mount":
			return true
		case strings.HasPrefix(la, "-v") && len(la) > 2:
			return true
		case strings.HasPrefix(la, "--volume="):
			return true
		case strings.HasPrefix(la, "--mount") && strings.Contains(la, "bind"):
			return true
		// mounts inherited from another container
		case la == "--volumes-from" || strings.HasPrefix(la, "--volumes-from="):
			return true
		// raw host device passthrough
		case la == "--device" || strings.HasPrefix(la, "--device="):
			return true
		// runtime escape: privileged lets the box mount host FS itself
		case la == "--privileged" || la == "--privileged=true":
			return true
		// host PID namespace exposes /proc/<hostpid>/root - a path to host FS
		case la == "--pid=host" || (la == "--pid" && strings.ToLower(next) == "host"):
			return true
		// capability escape: SYS_ADMIN or ALL, in BOTH "--cap-add=X" and
		// "--cap-add X" forms.
		case la == "--cap-add" && dangerousCap(next):
			return true
		case strings.HasPrefix(la, "--cap-add=") && dangerousCap(strings.TrimPrefix(la, "--cap-add=")):
			return true
		}
	}
	return false
}

// HasHostBindMount is retained as an alias for callers that specifically mean
// "bind mount"; it now delegates to the full host-escape check so no caller can
// accidentally get the narrower (weaker) behavior. New code should use
// HasHostEscape directly.
func HasHostBindMount(createArgv []string) bool {
	return HasHostEscape(createArgv)
}

// HostBundleArgv builds the host-side command to bundle full history for transfer.
// `--all` includes every ref (branches, tags, remotes) - equivalent to a mirror.
func HostBundleArgv(repoDir, outBundle string) []string {
	return []string{"git", "-C", repoDir, "bundle", "create", outBundle, "--all"}
}

// HostStashCreateArgv captures tracked staged+unstaged state as a commit object
// WITHOUT disturbing the user's working tree (non-destructive seed). It prints a
// commit hash; the caller bundles that hash for transfer.
func HostStashCreateArgv(repoDir string) []string {
	return []string{"git", "-C", repoDir, "stash", "create"}
}

// Describe renders the plan for the receipt/ledger.
func (p Plan) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "full-clone (dirty=%v, untracked=%v):", p.HostDirtyBundle != "", p.HostUntrackedTar != "")
	for _, s := range p.Steps {
		fmt.Fprintf(&b, " [%s]", s.Desc)
	}
	return b.String()
}
