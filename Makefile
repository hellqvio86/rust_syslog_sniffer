.PHONY: all build run clean test check fmt fmt-check format clippy lint coverage sbom docker-build docker-run docker-run-interactive docker-tag docker-push docker-clean renovate renovate-summary help hooks secrets trivy

# Variables
CARGO = cargo
CARGO_AUDITABLE = $(CARGO) auditable
DOCKER = docker
IMAGE_NAME = syslog_sniffer
IMAGE_TAG = latest
REGISTRY ?= # Set your registry here, e.g., docker.io/username
DOCKER_OPTS ?=
ARGS ?=

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the Rust project
	@if command -v cargo-auditable >/dev/null 2>&1; then \
		$(CARGO_AUDITABLE) build --release --locked; \
	else \
		$(CARGO) build --release --locked; \
	fi

sbom: ## Generate SBOM in CycloneDX format
	@if ! command -v cargo-cyclonedx >/dev/null 2>&1; then \
		echo "Installing cargo-cyclonedx..."; \
		$(CARGO) install --locked cargo-cyclonedx; \
	fi
	$(CARGO) cyclonedx --format json --override-filename "sbom"

run: ## Run the application (pass arguments via ARGS="--interface lo ...")
	$(CARGO) run --locked -- $(ARGS)

clean: ## Clean build artifacts
	$(CARGO) clean
	rm -rf target/

test: ## Run tests
	$(CARGO) test --locked

check: ## Check code without building
	$(CARGO) check --locked

fmt: ## Format code
	$(CARGO) fmt

fmt-check: ## Check code formatting
	$(CARGO) fmt -- --check

format: ## Format code and fix lints
	$(CARGO) fmt
	$(CARGO) clippy --locked --fix --allow-dirty --allow-staged

clippy: ## Run clippy linter
	$(CARGO) clippy --locked --all-targets -- -D warnings

doc: ## Check documentation
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --locked --no-deps

lint: fmt-check clippy doc ## Run fmt check, clippy, and doc linter

coverage: ## Generate coverage report (enforces >= 80% coverage)
	$(CARGO) tarpaulin --fail-under 80 --follow-exec --out Xml --out Html

docker-build: ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-run: ## Run Docker container
	$(DOCKER) run --rm \
		--cap-drop=ALL \
		--cap-add=NET_RAW \
		--network host \
		$(DOCKER_OPTS) \
		$(IMAGE_NAME):$(IMAGE_TAG) $(ARGS)

docker-run-interactive: ## Run Docker container interactively with shell
	$(DOCKER) run --rm -it \
		--cap-drop=ALL \
		--cap-add=NET_RAW \
		--network host \
		$(DOCKER_OPTS) \
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

renovate: ## Run Renovate locally in dry-run mode
	@./bin/renovate/run.sh

renovate-summary: ## Run Renovate locally and show summary of branches/updates
	@./bin/renovate/run.sh --summary

TRUFFLEHOG_IMAGE ?= trufflesecurity/trufflehog:3.99.8
TRIVY_IMAGE ?= aquasec/trivy:0.69.2

hooks: ## Install git pre-commit and pre-push hooks
	@chmod +x .githooks/pre-commit .githooks/pre-push 2>/dev/null || true
	@git config core.hooksPath .githooks
	@echo "Git pre-commit and pre-push hooks installed and core.hooksPath set to .githooks."

secrets: ## Run TruffleHog secret scanning
	@echo "Running TruffleHog secret scan..."
	@if command -v trufflehog >/dev/null 2>&1; then \
		trufflehog --no-update git file://$$(pwd) --only-verified --fail; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v $$(pwd):/src -w /src $(TRUFFLEHOG_IMAGE) git file:///src --only-verified --fail; \
	else \
		echo "ERROR: trufflehog or docker is required!" >&2 && exit 1; \
	fi

trivy: ## Run Trivy vulnerability scanning
	@echo "Running Trivy vulnerability scan..."
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --severity HIGH,CRITICAL --exit-code 1 .; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v $$(pwd):/src -v trivy-cache:/root/.cache -w /src $(TRIVY_IMAGE) fs --severity HIGH,CRITICAL --exit-code 1 .; \
	else \
		echo "ERROR: trivy or docker is required!" >&2 && exit 1; \
	fi
