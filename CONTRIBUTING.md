# Contributing

Thanks for looking. This is a young project and the code moves around, so it's worth opening an issue before a large change.

## Building and testing

```sh
make build
make test
go vet ./...
```

Everything under `internal/` has unit tests and they should stay green. The lifecycle and backend code is written so the security-relevant behaviour is testable without a running Docker daemon: the plan is built as data and checked, and only the parts that genuinely need a daemon are guarded behind a check.

## Good first contributions

- Policy packs. Each agent is a single YAML file under `internal/policy/packs`. If you use an agent that isn't covered, adding a pack is mostly research: what hosts it needs to reach, where it stores auth, how to run it headless. Look at `claude-code.yaml` for the shape.
- Running the Docker path on Linux and Windows/WSL2 and reporting what breaks. It's been exercised most on macOS with Docker Desktop and Colima.

## Style

Plain Go. Run `gofmt`. Keep comments about why something is done, not what the next line does. If a change relaxes an isolation guarantee, say so clearly in the comment and the PR.

## Security

If you find a way for the agent to reach the host filesystem or escape the egress allowlist, please don't open a public issue. See SECURITY.md.
