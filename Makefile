.PHONY: build run clean test docker-build docker-run docker-push help renovate renovate-summary fmt-check clippy lint secrets trivy hooks

# Variables
CARGO = cargo
CARGO_AUDITABLE = $(CARGO) auditable
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
	@if command -v cargo-auditable >/dev/null 2>&1; then \
		$(CARGO_AUDITABLE) build --release; \
	else \
		$(CARGO) build --release; \
	fi

sbom: ## Generate SBOM in CycloneDX format
	@if ! command -v cargo-cyclonedx >/dev/null 2>&1; then \
		echo "Installing cargo-cyclonedx..."; \
		$(CARGO) install cargo-cyclonedx; \
	fi
	$(CARGO) cyclonedx --format json --override-filename "sbom"

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

fmt-check: ## Check code formatting
	$(CARGO) fmt -- --check

format: ## Format code and fix lints
	$(CARGO) fmt
	$(CARGO) clippy --fix --allow-dirty --allow-staged

clippy: ## Run clippy linter
	$(CARGO) clippy --all-targets -- -D warnings

lint: fmt-check clippy ## Run fmt check and clippy linter

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

all: clean build test sbom docker-build ## Clean, build, test, and create Docker image

renovate: ## Run Renovate locally in dry-run mode
	@./bin/renovate/run.sh

renovate-summary: ## Run Renovate locally and show summary of branches/updates
	@./bin/renovate/run.sh --summary


hooks: ## Install git pre-commit hook
	@chmod +x .githooks/pre-commit 2>/dev/null || true
	@git config core.hooksPath .githooks
	@echo "Git pre-commit hook installed and core.hooksPath set to .githooks."

secrets: ## Run TruffleHog secret scanning
	@echo "Running TruffleHog secret scan..."
	@if command -v trufflehog >/dev/null 2>&1; then \
		trufflehog --no-update git file://$$(pwd) --only-verified --fail; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v $$(pwd):/src -w /src trufflesecurity/trufflehog:latest git file:///src --only-verified --fail; \
	else \
		echo "ERROR: trufflehog or docker is required!" >&2 && exit 1; \
	fi

trivy: ## Run Trivy vulnerability scanning
	@echo "Running Trivy vulnerability scan..."
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --severity HIGH,CRITICAL --exit-code 1 .; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v $$(pwd):/src -v trivy-cache:/root/.cache -w /src aquasec/trivy:latest fs --severity HIGH,CRITICAL --exit-code 1 .; \
	else \
		echo "ERROR: trivy or docker is required!" >&2 && exit 1; \
	fi

