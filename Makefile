.PHONY: build test vet images gateway-image base-image

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o runclave ./cmd/runclave

test:
	go test ./...

vet:
	go vet ./...

# Build the container images the lifecycle plan references. Run once before the
# first real `runclave .` on a machine (the plan uses runclave/base + runclave/gateway).
images: base-image gateway-image

base-image:
	docker build -f docker/Dockerfile.base -t runclave/base:latest .

gateway-image:
	docker build -f docker/Dockerfile.gateway -t runclave/gateway:latest .
