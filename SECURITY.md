# Security

runclave's whole job is isolation, so bugs that break it matter more than most.

## Reporting

If you find a way for a box to reach the host filesystem, escape the egress allowlist, or run a command on the host during provisioning, email mskmeda4@gmail.com rather than opening a public issue. I'll get back to you as soon as I can.

## What runclave is trying to protect

- The agent in the box cannot read or write your real working tree. It gets a clone, not a mount.
- The box has no network route except through the allowlist proxy.
- Long-lived secrets are not meant to end up in the box.

## What it does not protect against, today

- A box you deliberately mark unrestricted (egress `"*"`) is not sandboxed on the network. That's your call, and it's recorded.
- The receipt is a record of what a host attested, not proof of the isolation it actually ran. A compromised or lying signer is out of scope.
- The Docker path relies on Docker's own network and capability enforcement. On Windows the same-user story is weaker than a VM, which is why the plan is to lean on WSL2 there.

The comments in `internal/box` and `internal/egress` spell out the boundaries in more detail, including the parts that are enforced versus the parts that are still defence in depth.
