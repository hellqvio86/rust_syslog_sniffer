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
# Trixie Docker Build Targets
# ============================================================================

# Variables for Trixie builds
IMAGE_NAME_TRIXIE ?= rust_syslog_sniffer
TRIXIE_TAG ?= trixie-latest
PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7

.PHONY: docker-build-trixie docker-buildx-trixie docker-run-trixie docker-push-trixie help-trixie

# Single-platform Trixie build
docker-build-trixie:
	docker build -f Dockerfile -t $(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG) .

# Multi-architecture build using buildx
docker-buildx-trixie:
	docker buildx create --name trixie-builder --use || true
	docker buildx build \
		--platform $(PLATFORMS) \
		-f Dockerfile.trixie.multiarch \
		-t $(REGISTRY)/$(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG) \
		--push \
		.
	docker buildx rm trixie-builder

# Build and load for local testing (single arch)
docker-build-trixie-local:
	docker buildx build \
		--platform linux/amd64 \
		-f Dockerfile.trixie.multiarch \
		-t $(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG) \
		--load \
		.

# Run Trixie container
docker-run-trixie:
	docker run --rm \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network host \
		$(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG) \
		$(ARGS)

# Run Trixie container interactively
docker-run-trixie-interactive:
	docker run -it --rm \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network host \
		--entrypoint /bin/sh \
		$(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG)

# Push Trixie image
docker-push-trixie:
	docker tag $(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG) $(REGISTRY)/$(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG)

# Clean Trixie images
docker-clean-trixie:
	docker rmi $(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG) 2>/dev/null || true
	docker rmi $(REGISTRY)/$(IMAGE_NAME_TRIXIE):$(TRIXIE_TAG) 2>/dev/null || true

# Help target for Trixie commands
help-trixie:
	@echo "Trixie Docker Targets:"
	@echo "  docker-build-trixie        - Build Trixie image (local architecture)"
	@echo "  docker-buildx-trixie       - Build and push multi-arch Trixie images"
	@echo "  docker-build-trixie-local  - Build multi-arch for local testing"
	@echo "  docker-run-trixie          - Run Trixie container"
	@echo "  docker-run-trixie-interactive - Run Trixie container with shell"
	@echo "  docker-push-trixie         - Push Trixie image to registry"
	@echo "  docker-clean-trixie        - Remove Trixie images"


