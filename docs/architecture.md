# Architecture

A quick tour of the packages, roughly in the order a run touches them.

## The flow of `runclave .`

1. `internal/cli` figures out you're in a git repo, picks a backend, and loads the policy pack for the agent.
2. `internal/workspace` creates the seed on the host: a full history bundle, a bundle of the stash-create commit for tracked changes, and a tar of untracked files. Only the payloads that exist are created.
3. `internal/box` builds the lifecycle plan: create the internal network, provision the gateway and the box on it, copy the seed in, reconstruct the working tree, and exec the agent. The plan is data, so it can be checked and printed before anything runs.
4. Before executing, the plan's egress and host-access invariants are verified. If any fail, the run is refused.
5. `internal/egress` is the proxy the gateway runs. `internal/ledger` writes the run receipt.

## Packages

- `internal/policy` loads and validates policy packs. Packs are embedded in the binary; a repo-local `./policies` is never picked up unless you opt in.
- `internal/egress` is a CONNECT proxy with a domain allowlist. It filters on the connect target and validates the hostname; it does not terminate TLS, so it passes HTTP/2 straight through.
- `internal/ledger` is a hash-chained record of what happened during a run, plus the receipt.
- `internal/backend` detects and describes the isolation backends. Today that's Docker; Apple `container` detection is there but its lifecycle isn't built.
- `internal/workspace` is the seed logic and the host-escape guard that keeps the box off your real disk.
- `internal/session` ties the proxy and ledger together for a run.
- `internal/box` is the container lifecycle and the invariant checker.
- `internal/fleet` is an optional, opt-in layer for a team that wants to sign and distribute packs and collect receipts. The standalone tool works without it.

## Why the box is provisioned the way it is

An early version created the box with `--network none` and then tried to attach it to the internal network. Docker refuses to connect a container that was created in `none` mode to another network, so that never actually worked. The box and gateway are now created directly on the internal network. The gateway is then also attached to the outbound network, which is allowed because it's already on a normal network. The box never gets a second attachment, so its only path out is the gateway.
