# YRLint Makefile - Manages all project operations

# Default shell
SHELL := /bin/bash

# Directories
SRC_DIR := $(CURDIR)/src
TESTS_DIR := $(CURDIR)/tests
EXAMPLES_DIR := $(CURDIR)/examples
DOCKER_DIR := $(CURDIR)/docker

# Binary paths
DEBUG_BIN := $(CURDIR)/target/debug/yrlint
RELEASE_BIN := $(CURDIR)/target/release/yrlint

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# Check if docker is running
DOCKER_RUNNING := $(shell docker info > /dev/null 2>&1 && echo 1 || echo 0)

.PHONY: all build build-debug build-release clean test test-unit test-integration \
        lint format check docker-build docker-run docker-stop install uninstall \
        help update-rust setup generate-config

all: build test

# Setup commands
setup:
	@echo -e "$(YELLOW)Setting up YRLint environment...$(NC)"
	@mkdir -p $(DOCKER_DIR)
	@echo -e "$(GREEN)Setup completed successfully$(NC)"

update-rust:
	@echo -e "$(YELLOW)Updating Rust to the latest stable version...$(NC)"
	@rustup update stable
	@echo -e "$(GREEN)Rust updated successfully$(NC)"

generate-config:
	@echo -e "$(YELLOW)Generating default config file...$(NC)"
	@cargo run -- --generate-config .yrlint.yml
	@echo -e "$(GREEN)Default config file generated at .yrlint.yml$(NC)"

# Build commands
build: build-debug
	@echo -e "$(GREEN)YRLint built successfully in debug mode$(NC)"

build-debug:
	@echo -e "$(YELLOW)Building YRLint in debug mode...$(NC)"
	@cargo build
	@echo -e "$(GREEN)YRLint built successfully in debug mode$(NC)"

build-release:
	@echo -e "$(YELLOW)Building YRLint in release mode...$(NC)"
	@cargo build --release
	@echo -e "$(GREEN)YRLint built successfully in release mode$(NC)"

# Test commands
test: test-unit
	@echo -e "$(GREEN)All tests passed$(NC)"

test-unit:
	@echo -e "$(YELLOW)Running unit tests...$(NC)"
	@cargo test
	@echo -e "$(GREEN)Unit tests passed$(NC)"

test-integration:
	@echo -e "$(YELLOW)Building for integration tests...$(NC)"
	@cargo build
	@echo -e "$(YELLOW)Running integration tests...$(NC)"
	@RUN_INTEGRATION_TESTS=1 cargo test -- --ignored
	@echo -e "$(GREEN)Integration tests passed$(NC)"

test-examples:
	@echo -e "$(YELLOW)Testing with example YARA rules...$(NC)"
	@cargo run -- $(EXAMPLES_DIR)/good_rule.yar
	@cargo run -- $(EXAMPLES_DIR)/bad_rule.yar || echo -e "$(GREEN)Successfully detected issues in bad_rule.yar$(NC)"
	@cargo run -- $(EXAMPLES_DIR)/complex_rule.yar
	@echo -e "$(GREEN)Example tests completed$(NC)"

# Lint commands
lint:
	@echo -e "$(YELLOW)Linting code...$(NC)"
	@cargo clippy -- -D warnings
	@echo -e "$(GREEN)Linting passed$(NC)"

# Format code
format:
	@echo -e "$(YELLOW)Formatting code...$(NC)"
	@cargo fmt
	@echo -e "$(GREEN)Code formatting completed$(NC)"

# Type checking
check:
	@echo -e "$(YELLOW)Type checking code...$(NC)"
	@cargo check
	@echo -e "$(GREEN)Type checking completed$(NC)"

# Docker commands
docker-build:
ifeq ($(DOCKER_RUNNING), 0)
	@echo -e "$(RED)Docker is not running. Please start Docker and try again.$(NC)"
	@exit 1
endif
	@echo -e "$(YELLOW)Building Docker image...$(NC)"
	@mkdir -p $(DOCKER_DIR)
	@echo 'FROM rust:slim-bullseye' > $(DOCKER_DIR)/Dockerfile
	@echo 'WORKDIR /app' >> $(DOCKER_DIR)/Dockerfile
	@echo 'COPY . .' >> $(DOCKER_DIR)/Dockerfile
	@echo 'RUN cargo build --release' >> $(DOCKER_DIR)/Dockerfile
	@echo 'ENTRYPOINT ["/app/target/release/yrlint"]' >> $(DOCKER_DIR)/Dockerfile
	@docker build -t yrlint -f $(DOCKER_DIR)/Dockerfile .
	@echo -e "$(GREEN)Docker image built successfully$(NC)"

docker-run:
ifeq ($(DOCKER_RUNNING), 0)
	@echo -e "$(RED)Docker is not running. Please start Docker and try again.$(NC)"
	@exit 1
endif
	@echo -e "$(YELLOW)Running YRLint in Docker...$(NC)"
	@docker run --rm -v $(CURDIR):/data -w /data yrlint $(ARGS)

docker-stop:
ifeq ($(DOCKER_RUNNING), 0)
	@echo -e "$(RED)Docker is not running. Please start Docker and try again.$(NC)"
	@exit 1
endif
	@echo -e "$(YELLOW)Stopping YRLint Docker containers...$(NC)"
	@docker ps -q --filter "ancestor=yrlint" | xargs -r docker stop
	@echo -e "$(GREEN)Docker containers stopped successfully$(NC)"

# Install/Uninstall commands
install: build-release
	@echo -e "$(YELLOW)Installing YRLint...$(NC)"
	@cargo install --path .
	@echo -e "$(GREEN)YRLint installed successfully$(NC)"

uninstall:
	@echo -e "$(YELLOW)Uninstalling YRLint...$(NC)"
	@cargo uninstall yrlint || true
	@echo -e "$(GREEN)YRLint uninstalled successfully$(NC)"

# Github Actions CI test
ci: format-check lint test
	@echo -e "$(GREEN)CI checks passed$(NC)"

format-check:
	@echo -e "$(YELLOW)Checking code formatting...$(NC)"
	@cargo fmt -- --check
	@echo -e "$(GREEN)Format check passed$(NC)"

# Clean up
clean:
	@echo -e "$(YELLOW)Cleaning build artifacts...$(NC)"
	@cargo clean
	@echo -e "$(GREEN)Clean up completed$(NC)"

# Help command
help:
	@echo -e "$(GREEN)YRLint Makefile Commands:$(NC)"
	@echo -e "  $(YELLOW)make setup$(NC)             - Prepare environment"
	@echo -e "  $(YELLOW)make update-rust$(NC)       - Update Rust to the latest stable version"
	@echo -e "  $(YELLOW)make generate-config$(NC)   - Generate default config file"
	@echo -e "  $(YELLOW)make build$(NC)             - Build YRLint in debug mode"
	@echo -e "  $(YELLOW)make build-release$(NC)     - Build YRLint in release mode"
	@echo -e "  $(YELLOW)make test$(NC)              - Run unit tests"
	@echo -e "  $(YELLOW)make test-integration$(NC)  - Run integration tests"
	@echo -e "  $(YELLOW)make test-examples$(NC)     - Test with example YARA rules"
	@echo -e "  $(YELLOW)make lint$(NC)              - Run clippy linter"
	@echo -e "  $(YELLOW)make format$(NC)            - Format code with rustfmt"
	@echo -e "  $(YELLOW)make format-check$(NC)      - Check if code is properly formatted"
	@echo -e "  $(YELLOW)make check$(NC)             - Type check without building"
	@echo -e "  $(YELLOW)make ci$(NC)                - Run CI checks (format, lint, test)"
	@echo -e "  $(YELLOW)make docker-build$(NC)      - Build Docker image"
	@echo -e "  $(YELLOW)make docker-run$(NC)        - Run YRLint in Docker (use ARGS='file.yar' to pass arguments)"
	@echo -e "  $(YELLOW)make docker-stop$(NC)       - Stop YRLint Docker containers"
	@echo -e "  $(YELLOW)make install$(NC)           - Install YRLint globally"
	@echo -e "  $(YELLOW)make uninstall$(NC)         - Uninstall YRLint"
	@echo -e "  $(YELLOW)make clean$(NC)             - Clean build artifacts"
	@echo -e "  $(YELLOW)make help$(NC)              - Show this help message"
	@echo -e "\nExamples:"
	@echo -e "  $(YELLOW)make docker-run ARGS='examples/good_rule.yar'$(NC)"
	@echo -e "  $(YELLOW)make docker-run ARGS='-c custom-config.yml rules/'$(NC)"

# Default target
.DEFAULT_GOAL := help
