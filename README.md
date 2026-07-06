# runclave

Run a coding agent inside a throwaway box that can't touch your real files and can only reach the network you allow.

A lot of people want to use tools like Claude Code, Copilot, Cursor, Codex and friends, but are nervous about running them straight on their laptop. The worry is usually some mix of: a bad dependency the agent pulls in, a prompt-injection that makes it read your SSH keys, or the tool quietly phoning home. runclave takes the agent, drops it in a disposable container that has a fresh clone of your repo (including your uncommitted changes), and puts a default-deny proxy in front of its network so the only things it can reach are the hosts you list. When you're done you throw the box away and your real working tree was never touched.

It's meant to be neutral. It doesn't care which agent you run, and it isn't tied to any one vendor.

## Contents

- [Status](#status)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Commands and flags](#commands-and-flags)
- [How it works](#how-it-works)
- [Giving the agent its login](#giving-the-agent-its-login)
- [The git credential broker](#the-git-credential-broker)
- [Policy packs](#policy-packs)
- [What's enforced](#whats-enforced)
- [What it does not protect against](#what-it-does-not-protect-against)
- [Contributing](#contributing)
- [License](#license)

## Status

Early, but the core works. The Docker path runs end to end today: `runclave .` in a repo will build a box, clone the repo inside it (history plus your staged, unstaged and untracked changes), stand up the egress proxy, and give the box a network with no route to the internet except through that proxy. It's tested against a live daemon, and the box genuinely cannot reach anything off the allowlist.

What's built and tested:

- the one-command `runclave .` flow on Docker or Colima, headless or `--shell` interactive
- the internal-network plus gateway-proxy egress boundary, with a pre-flight check that refuses to run if the boundary isn't intact
- the two-payload workspace seed, so the box's `git status` matches your laptop
- three agents so far, Claude Code, the Gemini CLI, and the OpenAI Codex CLI, each a policy pack plus a box image (`--agent` picks one); adding one is a pack and a Dockerfile, no core change
- passing the agent's auth token into the box by name (never on an argv)
- the opt-in `--login` mount that reuses your existing host login
- the git credential broker daemon and its in-box helper, auto-started by `runclave .` on a per-session socket

What's still in progress, stated honestly rather than glossed:

- verifying the broker socket bind-mount end to end on the macOS Docker VM (it works on native Linux docker; the path resolution is settled on both)
- more agent packs (Copilot, Cursor, Aider); the model is proven with three, the rest is catalog work
- the Apple `container` backend on macOS and the bubblewrap backend on Linux
- reading real allow and deny counts out of the gateway log (the receipt records them as unknown until then)

## Requirements

- Go 1.26 or newer, to build the binary
- Docker, or Colima on macOS. The lifecycle is docker-family for now.
- The only external Go dependency is `gopkg.in/yaml.v3`. Everything else is the standard library.

## Install

```sh
git clone https://github.com/saimeda32/runclave
cd runclave
make build     # builds the ./runclave binary
make images    # builds the container images: base, gateway, and the per-agent images
```

`make images` builds:

- `runclave/base` is the workspace base (git plus the runclave binary, non-root).
- `runclave/gateway` runs the allowlist proxy.
- `runclave/claude-code` and `runclave/gemini-cli` are the base plus one agent CLI each, so the box needs no network to install the agent.

You only need to run `make images` once per machine, or again after you change a Dockerfile.

Images are per-agent by default, which keeps each box's contents to the one agent you're running. If you would rather have a single image that carries every agent CLI and switch between them, build the combined image and point `--image` at it:

```sh
make all-image                                          # builds runclave/all with every agent CLI
runclave . --agent gemini-cli --image runclave/all:latest
```

The combined image is purely a convenience: the egress allowlist and the isolation come from the selected agent's policy, not the image, so running Claude in the combined image still only reaches Anthropic's hosts. The trade-off is that a box booted from it carries every agent's dependencies, even the ones you are not using, which is why the slim per-agent images are the default.

## Quick start

From inside any git repo:

```sh
runclave .
```

That's the whole thing. It seeds a box with your repo, brings up the egress boundary, checks the isolation invariants, and runs the agent. If you have the agent's token in your environment it starts logged in; if not, it tells you.

If you'd rather see the plan before anything runs:

```sh
runclave . --dry-run
```

This prints the exact sequence of commands runclave would run, including the network setup, the seed transfer, and the agent exec, without touching Docker.

## Commands and flags

```
runclave .                 provision a box for the current repo and run the agent
runclave run <agent>       run a named agent headless
runclave backends          list detected isolation backends, strongest first
runclave policy <agent>    validate and print an agent policy pack
runclave destroy <box>     tear a box down
runclave verify <receipt>  check a signed receipt (.dsse.json) offline; fails on tamper
runclave brokerd           host-side git credential daemon (see the broker section)
runclave credential <op>   in-box git credential helper (runclave runs this for you)
```

Flags for `runclave .`:

```
--backend <name>   force a backend (docker today); default is the strongest available
--clean            clone HEAD only, without your uncommitted working-tree changes
--shell            drop into an interactive shell in the box instead of running the
                   agent. Same clone, same egress boundary, same login. Type exit to
                   leave; the box persists.
--login            mount this agent's existing host login read-only so it starts
                   logged in. Off by default. Shares a long-lived credential, so it
                   warns and records it on the receipt.
--dry-run          print the verified plan without executing it
--policies <dir>   use on-disk policy packs from <dir> instead of the trusted
                   built-in packs. Opt-in, and it warns you that you're off the
                   trusted set.
```

## How it works

The short version:

- A fresh clone goes into the box. runclave never bind-mounts your working tree, so the agent has no path back to your real disk. Work comes back out through git.
- The box sits on a Docker network created with `--internal`, so it has no route to the internet on its own.
- A small gateway container runs a CONNECT proxy with an allowlist and straddles two networks: the internal one, to receive the box's traffic, and a normal one, to actually reach the internet. The box's only way out is through that proxy.
- Every run writes a receipt: which policy was active, which egress the proxy allowed or denied, whether a login was shared, and how the box was disposed of.

The thing that makes the seed a bit fiddly is that git has two separate piles of state. Committed history moves with a bundle. Your uncommitted work does not, and untracked files aren't in any git object at all. runclave carries all three (a full bundle, a stash-commit bundle, and a tar of untracked files) so the box's `git status` matches what you had on your laptop. Untracked files are captured without a shell and without following symlinks, so a file with an odd name or a symlink pointing outside the repo can't pull host files into the box.

## Giving the agent its login

An agent in the box needs to authenticate to its provider, and it needs to push and pull code. Those are two different secrets, and runclave treats them differently.

Git credentials are brokered. See the next section.

The agent's own login (Claude Code talking to Anthropic, and so on) can't be brokered the same way, because those CLIs read a token straight from an environment variable at startup rather than asking anyone for it per request. There's no interception point. So you have three options, best to worst:

1. Export the token the pack names. runclave passes it into the box by name only, meaning the value is read from runclave's own environment at exec time and never appears on an argv, in `ps`, or in a printed plan. For Claude Code:

   ```sh
   export CLAUDE_CODE_OAUTH_TOKEN=...   # from: claude setup-token
   runclave .
   ```

   The token does still enter the box's process environment, because the agent needs it to authenticate. That's fine here: the box is single use and disposable. If the variable isn't set, runclave says so and the agent starts logged out.

2. Reuse your existing host login with `--login`:

   ```sh
   runclave . --login
   ```

   runclave mounts that agent's login files from your machine into the box, read only, so it starts already authenticated. This is the easy path when you're already logged in on your laptop. It's also weaker: it shares a long-lived, unscoped credential with the box, so runclave prints a warning and records the shared paths on the receipt. Only the exact files the pack declares get mounted (for Claude Code that's `~/.claude` and `~/.claude.json`), nothing else from your home directory, and the mount is read only so the box can't rewrite your host login. runclave refuses any login path that resolves outside your home directory.

3. Mounting your whole home or config directory yourself. Don't. It hands the box far more than the login, and it defeats the isolation that's the reason to use runclave at all.

The ranking matters: option 1 keeps the credential off every visible surface, option 2 trades some of that for zero setup, option 3 throws the isolation away. Pick the strongest one that fits how you work.

## The git credential broker

When the agent runs `git push` or `git pull`, it needs a credential, and you don't want a long-lived token sitting in a box you don't fully trust. The broker solves that.

A daemon on your host, `runclave brokerd`, holds the real secret (a GitHub App private key) and hands the box a short-lived, single-repo token over a per-session unix socket. Inside the box, git is pointed at `runclave credential` as its helper, which just relays the request over the socket. The box never holds a long-lived secret.

Authorization is decided on the host. The daemon mints a token only for the repo the session was created for, and it ignores whatever repo the box asks for in the request, logging any mismatch. A compromised box can't talk the daemon into credentials for a different repo, because the box's claimed identity is never trusted for the decision.

To use it, configure a GitHub App and export its three settings:

```sh
export RUNCLAVE_GH_APP_ID=...
export RUNCLAVE_GH_INSTALLATION_ID=...
export RUNCLAVE_GH_PRIVATE_KEY=/path/to/app-private-key.pem
runclave .
```

With those set and a `github.com` origin on the repo, `runclave .` starts the daemon for you: it derives the repo from the origin, creates a per-session socket in a runclave-owned, owner-only directory under your runtime or cache dir (`$XDG_RUNTIME_DIR/runclave/...` on Linux, `~/Library/Caches/runclave/...` on macOS, no root and no `/run` needed), mounts it read-only into the box, and stops the daemon and removes the socket when the run ends. If the App isn't configured, or the repo has no github origin, the run just proceeds without brokered git and says so.

You can also run the daemon yourself, for example to serve a longer-lived box:

```sh
runclave brokerd --socket "$XDG_RUNTIME_DIR/runclave/mybox/broker.sock" --repo github.com/you/yourrepo
```

The daemon creates the socket owner-only, refuses to touch a path that isn't a socket, and fails closed: if the App isn't configured, it mints nothing rather than falling back to a long-lived secret. The tokens it mints carry an expiry, so git rotates them on its own.

Two honest limits. First, the auto-started daemon lives for the duration of the run: it serves the agent's git while the run is active and stops on return, so a box you re-enter later is not brokered until you go through `runclave` again. Second, the socket location is settled for both operating systems, but bind-mounting a host unix socket into the box on the macOS Docker VM crosses the VM's file-sharing layer and isn't verified here; on native Linux docker it works. So treat macOS end-to-end brokering as unproven for now, not as a promise.

## Policy packs

Each agent is described by a small YAML file, not code. A pack lists the egress the agent needs, where it keeps its config and auth, and how it's meant to run. Adding support for a new agent is a one-file change, which is the whole point.

A pack looks roughly like this:

```yaml
agent: claude-code
type: cli-headless
run:
  image: runclave/claude-code:latest
  command: claude
  headlessFlags: ["-p"]
egress:
  model: [api.anthropic.com, claude.ai]
  infra: [registry.npmjs.org]
auth:
  method: env-token
  envVar: CLAUDE_CODE_OAUTH_TOKEN
  loginPaths:            # only used by --login, mounted read-only
    - "~/.claude"
    - "~/.claude.json"
```

- `egress` is grouped by class (the model API, and supporting infrastructure like a package registry). The gateway allowlist is the union of these.
- `auth.envVar` is the token variable runclave passes in by name.
- `auth.loginPaths` are the host files `--login` may mount, and nothing else.
- `run.image` lets a pack pick its own box image; packs without one fall back to the base.

The trusted packs are baked into the binary. runclave will not pick up a `./policies` directory from the repo you're pointing it at, because that repo is exactly the thing you don't trust yet. If you want to use your own packs from disk, pass `--policies <dir>` and you'll get a warning that you're off the trusted set. That warning is real: an on-disk pack can widen the egress allowlist and name its own box image, so only use packs you trust.

If you genuinely want an unrestricted box, put `"*"` in the pack's egress list. You'll get it, and you'll also get a loud line in the log and a note on the receipt saying this box is not egress-sandboxed. The tool won't stop you, it just won't let a wide-open box look like a locked-down one.

## What's enforced

The isolation isn't a vibe, it's checked before anything runs. `runclave .` builds the plan, verifies a set of invariants, and refuses to execute if any of them fail:

- the box only ever joins the internal, no-egress network
- the gateway is the only container allowed to reach the outbound network
- neither container keeps `NET_ADMIN`, so a box can't reroute itself around the proxy
- the gateway is actually running the allowlist proxy, with exactly the allowlist from the trusted pack
- no step hands the box a path to the host disk

The last one has two sanctioned exceptions, and only two: the broker's unix socket (an IPC endpoint, not a filesystem tree) and, when you pass `--login`, the exact login files the pack declares, read only. Both are stripped from the check by an exact match, so any other mount, any mount to a different path, or any attempt to widen either exception is still caught.

## Receipts

Every run writes a receipt (which agent, the policy hash, the box image that booted, the egress allow/deny counts, and how the box was disposed of), and signs it. The signature is Ed25519 over a DSSE-style pre-authentication encoding, and the signed envelope carries the public key that made it, so it verifies offline with no key server:

```sh
runclave verify /tmp/runclave-<box>-receipt.dsse.json
```

The private key is generated once and kept owner-only in your config dir; only the public key ever travels. Verification is fail-closed: any change to the receipt, the payload type, or the key makes it fail. Be clear on what a passing check means: it proves the receipt is intact and shows you the signer's fingerprint, but a valid signature is not by itself proof of authenticity. Anyone can sign a receipt with their own key. It is trustworthy only when the fingerprint is one you trust, which is why `runclave verify` calls out when the signer is this machine's own key.

## What it does not protect against

Being straight about the edges:

- It is not a kernel sandbox. On Docker the box is a container; a kernel-level container escape is out of scope for this layer. The Apple `container` backend (a real VM) is the stronger option and is planned.
- The allowlist is by hostname. If a host you allow can itself be used to reach somewhere else (an open redirect, a proxy, a shared CDN), the agent can ride that. Keep the allowlist tight.
- With `--login`, or with a token in the environment, the credential is inside the box for the agent to use. runclave keeps it off visible surfaces and, for git, replaces it with a short-lived brokered token, but a live credential the agent can use is a credential a compromised agent can use. Rotate if you have any doubt.
- Egress accounting isn't wired to the gateway log yet, so the allow and deny counts on the receipt read as unknown for now.

None of this is hidden in the code either. Where something is advisory rather than enforced, the comments say so.

## Contributing

Issues and pull requests are welcome. The most useful contributions right now are policy packs for agents that aren't covered yet, and testing the Docker path on setups other than macOS. See CONTRIBUTING.md.

## License

MIT. See LICENSE.
