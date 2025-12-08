.PHONY: build run clean test docker-build docker-run docker-push help

# Variables
CARGO = cargo
DOCKER = docker
IMAGE_NAME = syslog_sniffer
IMAGE_TAG = latest
REGISTRY ?= # Set your registry here, e.g., docker.io/username

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the Rust project
	$(CARGO) build --release

run: ## Run the application
	$(CARGO) run

clean: ## Clean build artifacts
	$(CARGO) clean
	rm -rf target/

test: ## Run tests
	$(CARGO) test

check: ## Check code without building
	$(CARGO) check

fmt: ## Format code
	$(CARGO) fmt

format: ## Format code and fix lints
	$(CARGO) fmt
	$(CARGO) clippy --fix --allow-dirty --allow-staged

clippy: ## Run clippy linter
	$(CARGO) clippy -- -D warnings

coverage: ## Generate coverage report
	$(CARGO) tarpaulin --out Xml --out Html

docker-build: ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-run: ## Run Docker container
	$(DOCKER) run --rm -it \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network host \
		$(IMAGE_NAME):$(IMAGE_TAG) $(ARGS)

docker-run-interactive: ## Run Docker container interactively with shell
	$(DOCKER) run --rm -it \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network host \
		--entrypoint /bin/sh \
		$(IMAGE_NAME):$(IMAGE_TAG)

docker-tag: ## Tag image for registry
ifdef REGISTRY
	$(DOCKER) tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
else
	@echo "Error: REGISTRY variable not set. Usage: make docker-tag REGISTRY=docker.io/username"
	@exit 1
endif

docker-push: docker-tag ## Push Docker image to registry
ifdef REGISTRY
	$(DOCKER) push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
else
	@echo "Error: REGISTRY variable not set. Usage: make docker-push REGISTRY=docker.io/username"
	@exit 1
endif

docker-clean: ## Remove Docker images
	$(DOCKER) rmi $(IMAGE_NAME):$(IMAGE_TAG) || true
ifdef REGISTRY
	$(DOCKER) rmi $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) || true
endif

all: clean build test docker-build ## Clean, build, test, and create Docker image
# ============================================================================
# Alpine Docker Build Targets
# ============================================================================

# Variables for Alpine builds
IMAGE_NAME_ALPINE ?= rust_syslog_sniffer
ALPINE_TAG ?= alpine-latest
PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7

.PHONY: docker-build-alpine docker-buildx-alpine docker-run-alpine docker-push-alpine help-alpine

# Single-platform Alpine build
docker-build-alpine:
	docker build -f Dockerfile.alpine -t $(IMAGE_NAME_ALPINE):$(ALPINE_TAG) .

# Multi-architecture build using buildx
docker-buildx-alpine:
	docker buildx create --name alpine-builder --use || true
	docker buildx build \
		--platform $(PLATFORMS) \
		-f Dockerfile.alpine \
		-t $(REGISTRY)/$(IMAGE_NAME_ALPINE):$(ALPINE_TAG) \
		--push \
		.
	docker buildx rm alpine-builder

# Build and load for local testing (single arch)
docker-build-alpine-local:
	docker buildx build \
		--platform linux/amd64 \
		-f Dockerfile.alpine \
		-t $(IMAGE_NAME_ALPINE):$(ALPINE_TAG) \
		--load \
		.

# Build specific architectures
docker-build-alpine-amd64:
	docker buildx build \
		--platform linux/amd64 \
		-f Dockerfile.alpine \
		-t $(IMAGE_NAME_ALPINE):alpine-amd64 \
		--load \
		.

docker-build-alpine-arm64:
	docker buildx build \
		--platform linux/arm64 \
		-f Dockerfile.alpine \
		-t $(IMAGE_NAME_ALPINE):alpine-arm64 \
		--load \
		.

docker-build-alpine-armv7:
	docker buildx build \
		--platform linux/arm/v7 \
		-f Dockerfile.alpine \
		-t $(IMAGE_NAME_ALPINE):alpine-armv7 \
		--load \
		.

# Run Alpine container
docker-run-alpine:
	docker run --rm \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network host \
		$(IMAGE_NAME_ALPINE):$(ALPINE_TAG) \
		$(ARGS)

# Run Alpine container interactively
docker-run-alpine-interactive:
	docker run -it --rm \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network host \
		--entrypoint /bin/sh \
		$(IMAGE_NAME_ALPINE):$(ALPINE_TAG)

# Push Alpine image
docker-push-alpine:
	docker tag $(IMAGE_NAME_ALPINE):$(ALPINE_TAG) $(REGISTRY)/$(IMAGE_NAME_ALPINE):$(ALPINE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME_ALPINE):$(ALPINE_TAG)

# Clean Alpine images
docker-clean-alpine:
	docker rmi $(IMAGE_NAME_ALPINE):$(ALPINE_TAG) 2>/dev/null || true
	docker rmi $(REGISTRY)/$(IMAGE_NAME_ALPINE):$(ALPINE_TAG) 2>/dev/null || true

# Help target for Alpine commands
help-alpine:
	@echo "Alpine Docker Targets:"
	@echo "  docker-build-alpine        - Build Alpine image (local architecture)"
	@echo "  docker-buildx-alpine       - Build and push multi-arch Alpine images"
	@echo "  docker-build-alpine-local  - Build Alpine for local testing (amd64)"
	@echo "  docker-build-alpine-amd64  - Build Alpine for amd64"
	@echo "  docker-build-alpine-arm64  - Build Alpine for arm64"
	@echo "  docker-build-alpine-armv7  - Build Alpine for armv7"
	@echo "  docker-run-alpine          - Run Alpine container"
	@echo "  docker-run-alpine-interactive - Run Alpine container with shell"
	@echo "  docker-push-alpine         - Push Alpine image to registry"
	@echo "  docker-clean-alpine        - Remove Alpine images"

# ============================================================================
# Alpine Docker Build Targets
# ============================================================================

IMAGE_NAME_ALPINE ?= rust_syslog_sniffer
ALPINE_TAG ?= alpine-latest
PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7

.PHONY: docker-build-alpine docker-buildx-alpine docker-run-alpine help-alpine

# Simple single-architecture Alpine build (recommended for local use)
docker-build-alpine:
	docker build -f Dockerfile.alpine -t $(IMAGE_NAME_ALPINE):$(ALPINE_TAG) .

# Multi-architecture build using buildx (for production)
docker-buildx-alpine:
	docker buildx create --name alpine-builder --use || true
	docker buildx build \
		--platform $(PLATFORMS) \
		-f Dockerfile.alpine.multiarch \
		-t $(REGISTRY)/$(IMAGE_NAME_ALPINE):$(ALPINE_TAG) \
		--push \
		.
	docker buildx rm alpine-builder

# Build and load for local testing
docker-build-alpine-local:
	docker buildx build \
		--platform linux/amd64 \
		-f Dockerfile.alpine.multiarch \
		-t $(IMAGE_NAME_ALPINE):$(ALPINE_TAG) \
		--load \
		.

# Run Alpine container
docker-run-alpine:
	docker run --rm \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network host \
		$(IMAGE_NAME_ALPINE):$(ALPINE_TAG) \
		$(ARGS)

# Run Alpine container interactively
docker-run-alpine-interactive:
	docker run -it --rm \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network host \
		--entrypoint /bin/sh \
		$(IMAGE_NAME_ALPINE):$(ALPINE_TAG)

# Push Alpine image
docker-push-alpine:
	docker tag $(IMAGE_NAME_ALPINE):$(ALPINE_TAG) $(REGISTRY)/$(IMAGE_NAME_ALPINE):$(ALPINE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME_ALPINE):$(ALPINE_TAG)

# Clean Alpine images
docker-clean-alpine:
	docker rmi $(IMAGE_NAME_ALPINE):$(ALPINE_TAG) 2>/dev/null || true
	docker rmi $(REGISTRY)/$(IMAGE_NAME_ALPINE):$(ALPINE_TAG) 2>/dev/null || true

# Help for Alpine targets
help-alpine:
	@echo "Alpine Docker Targets:"
	@echo "  docker-build-alpine            - Build Alpine image (single arch, local)"
	@echo "  docker-buildx-alpine           - Build multi-arch Alpine and push"
	@echo "  docker-build-alpine-local      - Build multi-arch for local testing"
	@echo "  docker-run-alpine              - Run Alpine container"
	@echo "  docker-run-alpine-interactive  - Run Alpine container with shell"
	@echo "  docker-push-alpine             - Push Alpine image to registry"
	@echo "  docker-clean-alpine            - Remove Alpine images"
