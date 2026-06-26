# runclave

Run a coding agent inside a throwaway box that can't touch your real files and can only reach the network you allow.

A lot of people want to use tools like Claude Code, Copilot, Cursor, Codex and friends, but are nervous about running them straight on their laptop. The worry is usually some mix of: a bad dependency the agent pulls in, a prompt-injection that makes it read your SSH keys, or the tool quietly phoning home. runclave takes the agent, drops it in a disposable container that has a fresh clone of your repo (including your uncommitted changes), and puts a default-deny proxy in front of its network so the only things it can reach are the hosts you list. When you're done you throw the box away and your real working tree was never touched.

It's meant to be neutral. It doesn't care which agent you run, and it isn't tied to any one vendor.

## Status

Early. The Docker path works end to end today: `runclave .` in a repo will build a box, clone the repo inside it (history plus staged, unstaged and untracked changes), stand up the egress proxy, and hand the box a network with no route to the internet except through that proxy. It's tested against a live daemon.

Still in progress: installing the agent CLI into the box image per policy pack, the credential broker that lends git tokens without them landing in the box, and the Apple `container` and Linux/bubblewrap backends. I'd rather be honest about the edges than oversell it.

## How it works

The short version:

- A fresh clone goes into the box. runclave never bind-mounts your working tree, so the agent has no path back to your real disk. Work comes back out through git.
- The box sits on a Docker network created with `--internal`, so it has no route to the internet on its own.
- A small gateway container runs a CONNECT proxy with an allowlist and straddles two networks: the internal one, to receive the box's traffic, and a normal one, to actually reach the internet. The box's only way out is through that proxy.
- Every run writes a receipt: which policy was active, which egress the proxy allowed or denied, and how the box was disposed of.

The thing that makes the seed a bit fiddly is that git has two separate piles of state. Committed history moves with a bundle. Your uncommitted work does not, and untracked files aren't in any git object at all. runclave carries all three (a full bundle, a stash-commit bundle, and a tar of untracked files) so the box's `git status` matches what you had on your laptop.

## Getting started

You'll need Go 1.26 or newer and Docker (or Colima).

```sh
git clone https://github.com/saimeda32/runclave
cd runclave
make build          # builds the ./runclave binary
make images         # builds the box and gateway container images
```

Then, from inside any git repo:

```sh
runclave .              # bring up a box seeded with this repo
runclave . --dry-run    # print the plan without running anything
runclave . --clean      # clone HEAD only, skip uncommitted changes
runclave backends       # show which isolation backends are available
runclave policy claude-code   # print and validate a policy pack
runclave destroy <box>  # tear a box down
```

## Policy packs

Each agent is described by a small YAML file, not code. A pack lists the egress the agent needs, where it keeps its config and auth, and how it's meant to run. Adding support for a new agent is a one file change, which is the whole point.

The trusted packs are baked into the binary. runclave will not pick up a `./policies` directory from the repo you're pointing it at, because that repo is exactly the thing you don't trust yet. If you want to use your own packs from disk, pass `--policies <dir>` and you'll get a warning that you're off the trusted set.

If you genuinely want an unrestricted box, put `"*"` in the pack's egress list. You'll get it, and you'll also get a loud line in the log and a note on the receipt saying this box is not egress-sandboxed. The tool won't stop you, it just won't let a wide-open box look like a locked-down one.

## What's checked

The isolation isn't a vibe, it's enforced before anything runs. `runclave .` builds the plan, checks a set of invariants, and refuses to execute if any of them fail:

- the box only ever joins the internal, no-egress network
- the gateway is the only container allowed to reach the outbound network
- neither container keeps `NET_ADMIN`, so a box can't reroute itself around the proxy
- the gateway is actually running the allowlist proxy, with exactly the allowlist from the trusted pack
- no step hands the box a path to the host disk

## Contributing

Issues and pull requests are welcome. The most useful contributions right now are policy packs for agents that aren't covered yet, and testing the Docker path on setups other than macOS. See CONTRIBUTING.md.

## License

MIT. See LICENSE.
