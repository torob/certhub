SHELL := /usr/bin/env bash

CODEX_TOOLS ?= $(HOME)/.tools
export CODEX_TOOLS
export PATH := $(CODEX_TOOLS)/bin:$(PATH)

LOCAL_GO := $(CODEX_TOOLS)/go/1.26.4/bin/go
LOCAL_GOFMT := $(CODEX_TOOLS)/go/1.26.4/bin/gofmt
LOCAL_NODE_DIR := $(CODEX_TOOLS)/node/24.15.0/bin
LOCAL_NODE := $(LOCAL_NODE_DIR)/node
LOCAL_NPM := $(LOCAL_NODE_DIR)/npm
LOCAL_HELM := $(CODEX_TOOLS)/helm/3.16.2/linux-amd64/helm
TOOLS_NODE := $(CODEX_TOOLS)/bin/node
TOOLS_NPM := $(CODEX_TOOLS)/bin/npm
GO ?= $(if $(wildcard $(LOCAL_GO)),$(LOCAL_GO),go)
GOFMT ?= $(if $(wildcard $(LOCAL_GOFMT)),$(LOCAL_GOFMT),gofmt)
NPM = $(if $(wildcard $(LOCAL_NPM)),$(LOCAL_NPM),$(if $(wildcard $(TOOLS_NPM)),$(TOOLS_NPM),npm))
NODE = $(if $(wildcard $(LOCAL_NODE)),$(LOCAL_NODE),$(if $(wildcard $(TOOLS_NODE)),$(TOOLS_NODE),node))
HELM ?= $(LOCAL_HELM)
export NPM
export NODE
export HELM
GOVULNCHECK_VERSION ?= 1.5.0
HELM_VERSION ?= 3.16.2
DIST_DIR ?= dist
WEB_DIR := web
WEB_DIST_DIR := $(DIST_DIR)/web
WEB_EMBED_DIR := internal/webui/assets
GO_BUILD_ENV := CGO_ENABLED=0 GOCACHE=$$HOME/.cache/go-build GOPATH=$$HOME/go GOMODCACHE=$$HOME/go/pkg/mod GOPROXY=https://proxy.golang.org,direct
GO_READONLY_ENV := $(GO_BUILD_ENV) GOFLAGS=-mod=readonly
GO_BUILD_FLAGS := -trimpath -buildvcs=false -ldflags "-s -w"
GO_PACKAGE_ROOTS := ./cmd/... ./internal/... ./pkg/... ./migrations/... ./test/...

.PHONY: check fmt go-fmt go-test go-lockfile-check build build-go build-server build-cli build-operator web-ci web-install web-typecheck web-build web-build-release web-embed-release release-artifacts dependency-check go-dependency-check go-vulnerability-check go-license-check web-dependency-check web-vulnerability-check web-license-check web-lockfile-check web-asset-check release-scaffold-check contract openapi-validate contract-baseline tools-redocly tools-govulncheck tools-helm clean

check: fmt dependency-check contract web-ci build web-asset-check release-scaffold-check

fmt: go-fmt

go-fmt:
	@unformatted="$$(find . \
		-path './.git' -prune -o \
		-path './certhub-full-e2e-artifacts' -prune -o \
		-path './dist' -prune -o \
		-path './web/dist' -prune -o \
		-path './web/node_modules' -prune -o \
		-name '*.go' -print0 | xargs -0 -r "$(GOFMT)" -l)"; \
	if [ -n "$$unformatted" ]; then \
		echo "Go files need gofmt:" >&2; \
		printf '%s\n' "$$unformatted" >&2; \
		exit 1; \
	fi

go-test:
	@packages="$$( $(GO_READONLY_ENV) $(GO) list $(GO_PACKAGE_ROOTS) )"; \
	$(GO_READONLY_ENV) $(GO) test $$packages

go-lockfile-check:
	$(GO_BUILD_ENV) GO_BIN="$(GO)" ./scripts/check-go-lockfile.sh

build: build-go

build-go: build-server build-cli build-operator go-test go-lockfile-check

build-server: web-build-release
	mkdir -p "$(DIST_DIR)/bin"
	@tmp_dir="$$(mktemp -d)"; \
	cp -a "$(WEB_EMBED_DIR)" "$$tmp_dir/assets"; \
	restore() { find "$(WEB_EMBED_DIR)" -mindepth 1 -maxdepth 1 -exec rm -rf {} +; cp -a "$$tmp_dir/assets"/. "$(WEB_EMBED_DIR)"/; rm -rf "$$tmp_dir"; }; \
	trap restore EXIT; \
	find "$(WEB_EMBED_DIR)" -mindepth 1 -maxdepth 1 -exec rm -rf {} +; \
	cp -a "$(WEB_DIST_DIR)"/. "$(WEB_EMBED_DIR)"/; \
	$(GO_READONLY_ENV) $(GO) build $(GO_BUILD_FLAGS) -o "$(DIST_DIR)/bin/certhub-server" ./cmd/certhub-server

build-cli:
	mkdir -p "$(DIST_DIR)/bin"
	$(GO_READONLY_ENV) $(GO) build $(GO_BUILD_FLAGS) -o "$(DIST_DIR)/bin/certhub-cli" ./cmd/certhub-cli

build-operator:
	mkdir -p "$(DIST_DIR)/bin"
	$(GO_READONLY_ENV) $(GO) build $(GO_BUILD_FLAGS) -o "$(DIST_DIR)/bin/certhub-operator" ./cmd/certhub-operator

web-ci: web-lockfile-check web-install web-typecheck web-build

web-install:
	cd "$(WEB_DIR)" && $(NPM) ci --ignore-scripts --registry https://registry.npmjs.org

web-lockfile-check:
	@tmp_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	cp "$(WEB_DIR)/package.json" "$(WEB_DIR)/package-lock.json" "$$tmp_dir/"; \
	cd "$$tmp_dir" && $(NPM) ci --package-lock-only --ignore-scripts --registry https://registry.npmjs.org --no-audit --no-fund >/dev/null; \
	if ! cmp -s "$(CURDIR)/$(WEB_DIR)/package-lock.json" "$$tmp_dir/package-lock.json"; then \
		echo "$(WEB_DIR)/package-lock.json is out of sync with $(WEB_DIR)/package.json" >&2; \
		diff -u "$(CURDIR)/$(WEB_DIR)/package-lock.json" "$$tmp_dir/package-lock.json" >&2 || true; \
		exit 1; \
	fi

web-typecheck:
	cd "$(WEB_DIR)" && $(NPM) run typecheck

web-build:
	cd "$(WEB_DIR)" && $(NPM) run build

web-build-release: web-install web-typecheck
	cd "$(WEB_DIR)" && $(NPM) run build

web-embed-release: web-build-release
	@echo "web assets are embedded during build-server"

dependency-check: go-dependency-check web-dependency-check

go-dependency-check: go-lockfile-check go-vulnerability-check go-license-check
	$(GO_BUILD_ENV) GO_BIN="$(GO)" ./scripts/check-go-dependencies.sh

go-vulnerability-check: tools-govulncheck
	$(GO_BUILD_ENV) GO_BIN="$(GO)" ./scripts/check-go-vulnerabilities.sh

go-license-check:
	$(GO_BUILD_ENV) GO_BIN="$(GO)" ./scripts/check-go-licenses.sh

web-dependency-check: web-vulnerability-check web-license-check
	$(NODE) scripts/check-web-dependencies.mjs

web-vulnerability-check:
	$(NODE) scripts/check-web-audit.mjs

web-license-check:
	$(NODE) scripts/check-web-licenses.mjs

web-asset-check:
	$(NODE) scripts/check-web-assets.mjs web/index.html web/src web/public "$(WEB_DIST_DIR)"

release-artifacts: build
	GO_BIN="$(GO)" ./scripts/build-release-artifacts.sh

release-scaffold-check: tools-helm release-artifacts
	HELM_BIN="$(HELM)" NODE_BIN="$(NODE)" ./scripts/check-release-scaffold.sh

contract: openapi-validate contract-baseline

openapi-validate: tools-redocly
	./scripts/check-contract.sh openapi

contract-baseline: tools-redocly
	./scripts/check-contract.sh baseline

tools-redocly:
	./scripts/install-redocly.sh >/dev/null

tools-govulncheck:
	$(GO_BUILD_ENV) GO_BIN="$(GO)" GOVULNCHECK_VERSION="$(GOVULNCHECK_VERSION)" ./scripts/install-govulncheck.sh >/dev/null

tools-helm:
	HELM_VERSION="$(HELM_VERSION)" ./scripts/install-helm.sh >/dev/null

clean:
	rm -rf "$(DIST_DIR)" "$(WEB_DIR)/dist" "$(WEB_DIR)/node_modules"
