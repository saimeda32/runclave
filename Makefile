.PHONY: build test vet images gateway-image base-image claude-image gemini-image codex-image all-image

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o runclave ./cmd/runclave

test:
	go test ./...

vet:
	go vet ./...

# Build the container images the lifecycle plan references. Run once before the
# first real `runclave .` on a machine (the plan uses runclave/base + runclave/gateway).
images: base-image gateway-image claude-image gemini-image codex-image

base-image:
	docker build -f docker/Dockerfile.base -t runclave/base:latest .

gateway-image:
	docker build -f docker/Dockerfile.gateway -t runclave/gateway:latest .

# The claude-code pack's box image (base plus the Claude Code CLI).
claude-image:
	docker build -f docker/Dockerfile.claude-code -t runclave/claude-code:latest .

# The gemini-cli pack's box image (base plus the Gemini CLI).
gemini-image:
	docker build -f docker/Dockerfile.gemini-cli -t runclave/gemini-cli:latest .

# The codex pack's box image (base plus the OpenAI Codex CLI).
codex-image:
	docker build -f docker/Dockerfile.codex -t runclave/codex:latest .

# Opt-in combined image: every agent CLI in one box (runclave . --image runclave/all).
# NOT part of `make images` - the default stays minimal per-agent.
all-image:
	docker build -f docker/Dockerfile.all -t runclave/all:latest .
