BINARY       := sshepherd
IMAGE        := sshepherd:dev
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COVERPROFILE := coverage.out
COVERAGE_MIN := 80
PKG          := ./...
GO           := go

# Pinned dev-tool versions (keep in sync with CLAUDE.md). Exact releases only —
# never @latest — so a new upstream rule or a broken/compromised release can't
# flip the gate without a change in this repo. Bump deliberately.
GOLANGCI_VERSION := v2.12.2
GOSEC_VERSION    := v2.29.0
GOVULN_VERSION   := v1.8.0
GITLEAKS_VERSION := v8.30.1
DEADCODE_VERSION := v0.51.0

# Tools are compiled from source by the active toolchain (`go install`). A
# linter built by an older Go than the one on PATH fails to type-check the
# newer stdlib (e.g. math/rand/v2), so `lint` refuses a mismatched binary and
# points at `make tools`. GOTOOLCHAIN=local keeps `go install` from silently
# fetching a different toolchain for a tool whose go.mod asks for a newer Go.
GO_VERSION   = $(shell $(GO) env GOVERSION)
TOOLS_ENV   := GOTOOLCHAIN=local

.PHONY: all check build fmt vet lint lint-toolchain deadcode security gosec vuln secrets test \
        coverage integration fuzz bench tidy docker docker-lint docker-scan smoke tools hooks clean

## all: default target — run the full gate
all: check

## check: full quality gate (the same command CI runs) — includes the coverage minimum
check: tidy fmt vet lint deadcode security coverage

## build: reproducible static binary into ./bin
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/$(BINARY) ./cmd/$(BINARY)

## fmt: fail if any file is not gofmt-clean
fmt:
	@files=$$(gofmt -l .); if [ -n "$$files" ]; then echo "gofmt needed:"; echo "$$files"; exit 1; fi

## vet: go vet
vet:
	$(GO) vet $(PKG)

## lint: golangci-lint (v2)
lint: lint-toolchain
	golangci-lint run

# lint-toolchain: fail fast (with the fix) when golangci-lint was built by a
# different Go than the active toolchain.
lint-toolchain:
	@have=$$(golangci-lint version 2>/dev/null | sed -n 's/.* built with \(go[^ ]*\) .*/\1/p'); \
	if [ "$$have" != "$(GO_VERSION)" ]; then \
	  echo "golangci-lint was built with $${have:-an unknown Go} but the active toolchain is $(GO_VERSION);"; \
	  echo "rebuild it with: make tools"; exit 1; \
	fi

## deadcode: whole-program reachability — fail on functions unreachable from main
deadcode:
	@out=$$(deadcode ./cmd/$(BINARY)); if [ -n "$$out" ]; then \
	  echo "$$out"; echo "FAIL: dead code found"; exit 1; \
	fi

## security: SAST + vulnerabilities + secret scan
security: gosec vuln secrets

gosec:
	gosec -quiet ./...

vuln:
	govulncheck ./...

secrets:
	gitleaks dir --redact .

## test: race detector + atomic coverage profile
test:
	$(GO) test -race -covermode=atomic -coverprofile=$(COVERPROFILE) $(PKG)

## integration: run integration tests against a throwaway sshd container
integration:
	./scripts/integration.sh

## coverage: report coverage and fail below COVERAGE_MIN%
coverage: test
	$(GO) tool cover -func=$(COVERPROFILE)
	$(GO) tool cover -html=$(COVERPROFILE) -o coverage.html
	@total=$$($(GO) tool cover -func=$(COVERPROFILE) | awk '/^total:/ {print $$3}' | tr -d '%'); \
	if awk -v t="$$total" -v m="$(COVERAGE_MIN)" 'BEGIN { exit !(t+0 >= m+0) }'; then \
	  printf 'coverage %s%% meets the %s%% minimum\n' "$$total" "$(COVERAGE_MIN)"; \
	else \
	  printf 'FAIL: coverage %s%% is below the %s%% minimum\n' "$$total" "$(COVERAGE_MIN)"; exit 1; \
	fi

## fuzz: short fuzz run of all parsers
fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzParseLine -fuzztime=15s ./internal/authkeys
	$(GO) test -run='^$$' -fuzz=FuzzParseFile -fuzztime=15s ./internal/authkeys
	$(GO) test -run='^$$' -fuzz=FuzzRenderRoundTrip -fuzztime=15s ./internal/authkeys
	$(GO) test -run='^$$' -fuzz=FuzzSanitizeName -fuzztime=15s ./internal/adopt
	$(GO) test -run='^$$' -fuzz=FuzzParse -fuzztime=15s ./internal/sshcfg
	$(GO) test -run='^$$' -fuzz=FuzzMatchGlob -fuzztime=15s ./internal/sshcfg
	$(GO) test -run='^$$' -fuzz=FuzzExpand -fuzztime=15s ./internal/identity
	$(GO) test -run='^$$' -fuzz=FuzzSanitize -fuzztime=15s ./internal/clog
	$(GO) test -run='^$$' -fuzz=FuzzShQuote -fuzztime=15s ./internal/sshconn
	$(GO) test -run='^$$' -fuzz=FuzzWriteCmds -fuzztime=15s ./internal/sshwrite
	$(GO) test -run='^$$' -fuzz=FuzzMergeRoundTrip -fuzztime=15s ./internal/manifest
	$(GO) test -run='^$$' -fuzz=FuzzLoad -fuzztime=15s ./internal/config
	$(GO) test -run='^$$' -fuzz=FuzzClassify -fuzztime=15s ./internal/keyfile
	$(GO) test -run='^$$' -fuzz=FuzzDecrypt -fuzztime=15s ./internal/keyfile

## bench: run benchmarks
bench:
	$(GO) test -run='^$$' -bench=. -benchmem $(PKG)

## tidy: fail if go.mod/go.sum are not tidy; verify module checksums
## (`-diff` never rewrites the files: it prints the needed change and exits non-zero)
tidy:
	@$(GO) mod tidy -diff || { echo "FAIL: go.mod/go.sum are not tidy — run 'go mod tidy'"; exit 1; }
	$(GO) mod verify

## docker: build the container image
docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

## docker-lint: lint the Dockerfile and the built image
docker-lint:
	hadolint Dockerfile
	# CIS-DI-0006 (HEALTHCHECK) waived: sshepherd is a CLI, not a service.
	dockle --exit-code 1 -i CIS-DI-0006 $(IMAGE)

## docker-scan: scan the image + config for CVEs/misconfig
docker-scan:
	trivy image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed $(IMAGE)
	trivy config --exit-code 1 .

## smoke: the image runs, reports its version and help, stays under the size
## budget, and does not run as root (the same gates CI applies)
smoke:
	IMAGE=$(IMAGE) ./scripts/docker-gates.sh

## tools: install pinned dev tooling into GOPATH/bin
## (re-run after upgrading Go: tools are built by, and must match, the active toolchain)
tools:
	$(TOOLS_ENV) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	$(TOOLS_ENV) $(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	$(TOOLS_ENV) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULN_VERSION)
	$(TOOLS_ENV) $(GO) install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)
	$(TOOLS_ENV) $(GO) install golang.org/x/tools/cmd/deadcode@$(DEADCODE_VERSION)

## hooks: install git pre-commit/pre-push hooks (lefthook)
hooks:
	lefthook install

## clean: remove build and coverage artifacts
clean:
	rm -rf bin $(COVERPROFILE) coverage.html
