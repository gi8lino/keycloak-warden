
.DEFAULT_GOAL := help

## Tool Versions

# renovate: datasource=github-releases depName=golangci/golangci-lint
GOLANGCI_LINT_VERSION ?= v2.15.0

# renovate: datasource=github-releases depName=gi8lino/dev-tools
DEV_TOOLS_VERSION ?= v0.9.0

# renovate: datasource=github-releases depName=kumbuka-me/cli
KUMBUKA_CLI_VERSION ?= v0.14.2
KUMBUKA_CLI := bin/.kumbuka/$(KUMBUKA_CLI_VERSION)/kumbuka-cli
KUMBUKA_CLI_ASSET ?= kumbuka-cli_{version}_{os}_{arch}.tar.gz

# renovate: datasource=github-releases depName=gi8lino/keycloak-snitch
SNITCH_VERSION ?= v1.0.0
SNITCH_RELEASE := $(patsubst v%,%,$(SNITCH_VERSION))
SNITCH_JAR := test/e2e/snitch/keycloak-snitch-$(SNITCH_RELEASE).jar
SNITCH_URL := https://github.com/gi8lino/keycloak-snitch/releases/download/$(SNITCH_VERSION)/keycloak-snitch-$(SNITCH_RELEASE).jar

##@ Assets
DEV_TOOLS_BIN = bin
FAVICON_GENERATE := $(DEV_TOOLS_BIN)/favicon-generate
FAVICON_SOURCE ?= docs/assets/warden.svg
FAVICON_SIZES ?= 16x16 32x32
SVG_TO_PNG := $(DEV_TOOLS_BIN)/svg-to-png
LOGO_SOURCE ?= docs/assets/warden.svg
LOGO_PNG ?= docs/assets/favicon.png
LOGO_PNG_WIDTH ?= 1200


$(FAVICON_GENERATE): | $(DEV_TOOLS_BIN)
	$(call download-dev-tool,favicon-generate,$@)

.PHONY: logo-png
logo-png: $(SVG_TO_PNG) $(LOGO_SOURCE) ## Generate a PNG version of the logo.
	$(call run-tool,$(SVG_TO_PNG),--width "$(LOGO_PNG_WIDTH)" "$(LOGO_SOURCE)" "$(LOGO_PNG)")

.PHONY: favicon
favicon: $(FAVICON_GENERATE) $(FAVICON_SOURCE) ## Generate Web UI and documentation favicons from the logo.
	$(call run-tool,$(FAVICON_GENERATE),--apple-touch "$(FAVICON_SOURCE)" "docs/assets" $(FAVICON_SIZES))
	$(call run-tool,$(FAVICON_GENERATE),--apple-touch "$(FAVICON_SOURCE)" "docs/assets" $(FAVICON_SIZES))
	$(call run-tool,$(FAVICON_GENERATE),--apple-touch "$(FAVICON_SOURCE)" "docs/assets" $(FAVICON_SIZES))


## End-to-end Compose Configuration

E2E_PROJECT ?= keycloak-warden-e2e
E2E_KC_PORT ?= 18080
E2E_WARDEN_PORT ?= 18081
E2E_MANAGEMENT_PORT ?= 18082
E2E_RECEIVER_PORT ?= 18090

E2E_KEYCLOAK_REALM_FILE := test/e2e/realm/warden-e2e.json
E2E_KEYCLOAK_REALM := $(shell sed -n 's/^[[:space:]]*"realm"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' $(E2E_KEYCLOAK_REALM_FILE))
E2E_KEYCLOAK_URL := http://127.0.0.1:$(E2E_KC_PORT)/realms/$(E2E_KEYCLOAK_REALM)/account/

E2E_COMPOSE := docker compose -p $(E2E_PROJECT) -f test/e2e/compose.yaml

export SNITCH_VERSION SNITCH_RELEASE
export E2E_PROJECT E2E_KC_PORT E2E_WARDEN_PORT E2E_MANAGEMENT_PORT E2E_RECEIVER_PORT

## Shared Development Tools

include bin/dev-tools.mk
include $(call dev-tools-module,tag)
include $(call dev-tools-module,port)
include $(call dev-tools-module,browser)
include $(call dev-tools-module,help)

## Project-local Tools

GOLANGCI_LINT := bin/golangci-lint

## Build Configuration

BINARY ?= build/warden
COMMAND ?= ./cmd/warden
BUILD_VERSION ?= dev
LDFLAGS ?= -s -w -X main.Version=$(BUILD_VERSION)

## Local Development

CONFIG ?= examples/kubernetes/warden.yaml

WARDEN_ASSIGNED_PORT ?= $(call dev-port,app)
WARDEN_MANAGEMENT_ASSIGNED_PORT ?= $(call dev-port,management)

LISTEN_ADDRESS ?= 127.0.0.1:$(WARDEN_ASSIGNED_PORT)
MANAGEMENT_LISTEN_ADDRESS ?= 127.0.0.1:$(WARDEN_MANAGEMENT_ASSIGNED_PORT)

DATABASE ?= warden.db
RUN_ARGS ?=

## SQLite Migration Consolidation

MIGRATION_DIR := internal/sqlite/migrations
MIGRATION_OUTPUT_DIR := build/migrations
MIGRATION_MERGE := scripts/db/merge_migrations.sh
MIGRATION_CLEANUP := scripts/db/cleanup_migrations.sh
MIGRATION_HELPER := scripts/db/baseline.py

## Site Configuration

SITE_CONFIG ?= docs/site.toml
SITE_PORT = $(call dev-port,site)
SITE_URL = http://127.0.0.1:$(SITE_PORT)/
BUILD_ARGS ?=

##@ Migration

.PHONY: merge-migrations
merge-migrations: $(MIGRATION_MERGE) $(MIGRATION_HELPER) ## Generate and validate the next SQLite baseline without changing source migrations.
	$(MIGRATION_MERGE) --migrations "$(MIGRATION_DIR)" --output-dir "$(MIGRATION_OUTPUT_DIR)"

.PHONY: cleanup-migrations
cleanup-migrations: merge-migrations $(MIGRATION_CLEANUP) ## Replace old SQL migration files with the validated baseline.
	$(MIGRATION_CLEANUP) --migrations "$(MIGRATION_DIR)" --generated-dir "$(MIGRATION_OUTPUT_DIR)"

.PHONY: test-migrations
test-migrations: ## Run SQLite baseline generation and cleanup regression tests.
	python3 -m unittest discover -s scripts/db -p 'test_*.py'

##@ Development

.PHONY: ports
ports: $(DEV_PORT) ## Print the assigned local HTTP ports.
	@$(DEV_PORT) app --port "$(WARDEN_ASSIGNED_PORT)" > /dev/null
	@$(DEV_PORT) management --port "$(WARDEN_MANAGEMENT_ASSIGNED_PORT)" > /dev/null
	@echo "Application: http://127.0.0.1:$(WARDEN_ASSIGNED_PORT)/events"
	@echo "Management: http://127.0.0.1:$(WARDEN_MANAGEMENT_ASSIGNED_PORT)/healthz"

.PHONY: ports-reset
ports-reset: $(DEV_PORT) ## Clear saved ports after stopping local services.
	$(call run-tool,$(DEV_PORT),--reset)

.PHONY: download
download: dev-tools snitch-download ## Download Go modules, development tools, and the Snitch JAR.
	go mod download

.PHONY: build
build: ## Build the Warden binary.
	@mkdir -p "$(dir $(BINARY))"
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o "$(BINARY)" "$(COMMAND)"

.PHONY: serve
serve: ports ## Run Warden with assigned ports and YAML rule/target configuration.
	go run "$(COMMAND)" serve \
		--config="$(CONFIG)" \
		--listen-address="$(LISTEN_ADDRESS)" \
		--management-listen-address="$(MANAGEMENT_LISTEN_ADDRESS)" \
		--database="$(DATABASE)" \
		$(RUN_ARGS)

.PHONY: run
run: ## Run Warden locally.
	$(MAKE) serve RUN_ARGS="$(RUN_ARGS)"

.PHONY: clean
clean: ## Remove built binaries and coverage reports.
	rm -rf build
	rm -f coverage.out coverage.html

##@ Documentation

.PHONY: build-docs
build-docs: cli ## Build the production documentation site.
	$(call run-tool,$(KUMBUKA_CLI),build --config "$(SITE_CONFIG)" $(BUILD_ARGS))

.PHONY: serve-docs
serve-docs: $(DEV_PORT) $(OPEN_BROWSER) cli ## Build, watch, serve, and open the documentation locally.
	@(until curl --fail --silent --output /dev/null "$(SITE_URL)"; do sleep 0.2; done; \
		$(OPEN_BROWSER) "$(SITE_URL)") & \
	browser_pid=$$!; \
	trap 'kill "$$browser_pid" 2>/dev/null || true' EXIT; \
	$(KUMBUKA_CLI) serve \
		--config "$(SITE_CONFIG)" \
		--site-url "$(SITE_URL)" \
		--listen-address "127.0.0.1:$(SITE_PORT)"

##@ End-to-end Compose

.PHONY: snitch-download
snitch-download: $(SNITCH_JAR) ## Download the pinned Keycloak Snitch JAR release.

$(SNITCH_JAR):
	@mkdir -p "$(dir $@)"
	@set -eu; \
	tmp="$@.tmp"; \
	trap 'rm -f "$$tmp"' EXIT HUP INT TERM; \
	curl --fail --location --silent --show-error --retry 3 \
		"$(SNITCH_URL)" --output "$$tmp"; \
	unzip -tq "$$tmp" > /dev/null; \
	mv "$$tmp" "$@"; \
	trap - EXIT HUP INT TERM

.PHONY: e2e-up
e2e-up: snitch-download ## Build and start Keycloak, Snitch, Warden, and Hookglass.
	$(E2E_COMPOSE) up --build --detach
	@echo "Keycloak: $(E2E_KEYCLOAK_URL)"

.PHONY: e2e-logs
e2e-logs: ## Follow the end-to-end stack logs.
	$(E2E_COMPOSE) logs --follow

.PHONY: e2e-down
e2e-down: ## Stop the stack without deleting SQLite data.
	$(E2E_COMPOSE) down --remove-orphans

.PHONY: e2e-reset
e2e-reset: ## Stop the stack and delete its dedicated SQLite volume.
	$(E2E_COMPOSE) down --volumes --remove-orphans

.PHONY: e2e-test
e2e-test: ## Run the real Keycloak -> Snitch -> Warden -> webhook E2E flow.
	$(MAKE) e2e-reset
	$(MAKE) e2e-up
	sh test/e2e/test.sh

##@ Testing

.PHONY: test
test: ## Run Go tests.
	go test -count=1 -timeout=3m ./...

.PHONY: test-race
test-race: ## Run Go tests with the race detector.
	go test -race -count=1 -timeout=3m ./...

.PHONY: cover
cover: ## Generate and view Go test coverage.
	go test -coverprofile=coverage.out -covermode=set -count=1 -timeout=3m ./...
	go tool cover -html=coverage.out

##@ Formatting

.PHONY: fmt
fmt: ## Format Go source code.
	go fmt ./...

.PHONY: check-format
check-format: ## Verify Go source formatting and whitespace.
	@set -e; unformatted="$$(gofmt -l cmd internal)"; \
	if [ -n "$$unformatted" ]; then \
		printf 'Go files need formatting:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi
	git diff --check

##@ Linting

.PHONY: vet
vet: ## Run Go static analysis.
	go vet ./...

.PHONY: lint
lint: lint-go ## Run Go linters.

.PHONY: lint-go
lint-go: golangci-lint ## Run golangci-lint.
	$(call run-tool,$(GOLANGCI_LINT),run)

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint and apply fixes.
	$(call run-tool,$(GOLANGCI_LINT),run --fix)

.PHONY: check
check: check-format vet test-race ## Run local formatting, vet and race checks.

.PHONY: verify
verify: check lint ## Run all local checks.

##@ Dependencies

.PHONY: dev-tools
dev-tools: $(DEV_PORT) $(DEV_TAG) $(OPEN_BROWSER) $(MAKE_HELP) $(GO_INSTALL_TOOL) ## Download the pinned development tools.

.PHONY: golangci-lint
golangci-lint: $(GO_INSTALL_TOOL) ## Download golangci-lint locally if necessary.
	@$(GO_INSTALL_TOOL) \
		--target "$(GOLANGCI_LINT)" \
		--package github.com/golangci/golangci-lint/v2/cmd/golangci-lint \
		--tool-version "$(GOLANGCI_LINT_VERSION)"

$(KUMBUKA_CLI): $(GITHUB_RELEASE_INSTALL)
	@mkdir -p "$(dir $@)"
	@$(GITHUB_RELEASE_INSTALL) \
		--repo kumbuka-me/cli \
		--tag "$(KUMBUKA_CLI_VERSION)" \
		--asset "$(KUMBUKA_CLI_ASSET)" \
		--binary kumbuka-cli \
		--target "$@"

.PHONY: cli
cli: $(KUMBUKA_CLI) ## Install the pinned Kumbuka CLI.

$(SVG_TO_PNG): | $(DEV_TOOLS_BIN)
	$(call download-dev-tool,svg-to-png,$@)

