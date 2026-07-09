.PHONY: build test vet smoke release images gateway-image base-image claude-image gemini-image codex-image copilot-image all-image

# Version stamped into the binary. A tag if we're on one, else the short commit,
# with -dirty when the tree has uncommitted changes; "dev" outside a git checkout.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X github.com/saimeda/runclave/internal/cli.Version=$(VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o runclave ./cmd/runclave

test:
	go test ./...

vet:
	go vet ./...

# Build the container images the lifecycle plan references. Run once before the
# first real `runclave .` on a machine (the plan uses runclave/base + runclave/gateway).
images: base-image gateway-image claude-image gemini-image codex-image copilot-image

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

# The copilot pack box image (base plus the GitHub Copilot CLI).
copilot-image:
	docker build -f docker/Dockerfile.copilot -t runclave/copilot:latest .

# Opt-in combined image: every agent CLI in one box (runclave . --image runclave/all).
# NOT part of `make images` - the default stays minimal per-agent.
all-image:
	docker build -f docker/Dockerfile.all -t runclave/all:latest .

# Real-path integration smoke test (needs `make images` + a docker daemon).
smoke:
	go test -tags integration -run TestIntegration -v ./internal/box/

# Reproducible, versioned release binaries for the supported OS/arch, plus checksums.
# Signing (cosign, keyless) and SBOM (syft) are printed as next steps: they need a
# pushed tag and those tools, so the Makefile does not fake them.
DIST ?= dist
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

release: test vet
	rm -rf $(DIST) && mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; \
	  out=$(DIST)/runclave-$(VERSION)-$$os-$$arch; \
	  echo "  building $$out"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" -o $$out ./cmd/runclave || exit 1; \
	done
	@cd $(DIST) && (shasum -a 256 runclave-* 2>/dev/null || sha256sum runclave-*) > SHA256SUMS
	@echo "release $(VERSION): $(DIST)/ (binaries + SHA256SUMS)"
	@echo "  sign (keyless, needs cosign + a pushed tag):  cosign sign-blob --yes $(DIST)/SHA256SUMS > $(DIST)/SHA256SUMS.sig"
	@echo "  SBOM (needs syft):                            syft dir:. -o spdx-json > $(DIST)/sbom.spdx.json"
