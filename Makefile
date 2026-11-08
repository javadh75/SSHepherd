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
GOLANGCI_VERSION := v2.15.0
GOSEC_VERSION    := v2.30.0
GOVULN_VERSION   := v1.8.0
GITLEAKS_VERSION := v8.30.1
DEADCODE_VERSION := v0.51.0
GOLICENSES_VERSION := v2.0.1
ACTIONLINT_VERSION := v1.7.12
# benchstat is not installed by `make tools`: CI's informational bench job runs
# it with `go run` at this pin.
BENCHSTAT_VERSION  := v0.0.0-20261009192801-be2c69fb417e

# print-VAR: print a Makefile variable, so a workflow reads a tool pin instead
# of repeating it (e.g. `make -s print-GOVULN_VERSION`).
print-%: ; @echo $($*)

# Tools are compiled from source by the active toolchain (`go install`). A
# linter built by an older Go than the one on PATH fails to type-check the
# newer stdlib (e.g. math/rand/v2), so `lint` refuses a mismatched binary and
# points at `make tools`. GOTOOLCHAIN=local keeps `go install` from silently
# fetching a different toolchain for a tool whose go.mod asks for a newer Go.
#
# Supported Go line. The pinned linters cannot read a newer Go's export data
# ("unsupported export data version"), so when the go on PATH is from another
# minor line (e.g. Homebrew's newest), every target runs under GO_PIN instead —
# the go command downloads it once — and local runs match CI (Go 1.27). An
# explicit GOTOOLCHAIN (environment or `make GOTOOLCHAIN=…`) always wins.
GO_LINE := go1.27
GO_PIN  := go1.27.3
ifeq ($(origin GOTOOLCHAIN),undefined)
  ifneq ($(GO_LINE),$(shell $(GO) env GOVERSION | cut -d. -f1-2))
    export GOTOOLCHAIN := $(GO_PIN)
  endif
endif
TOOLS_ENV   := GOTOOLCHAIN=$(or $(GOTOOLCHAIN),local)

.PHONY: all check build dist fmt vet lint lint-toolchain layering deadcode security gosec vuln secrets \
        secrets-history licenses actionlint test coverage integration fuzz fuzz-list bench tidy \
        docker docker-lint docker-scan smoke tools hooks clean

## all: default target — run the full gate
all: check

## check: full quality gate (the same command CI runs) — includes the coverage minimum
check: tidy fmt vet lint layering deadcode security licenses coverage

# LDFLAGS stamps VERSION into main.version, so --version reports it; a plain
# `go install …@vX.Y.Z` falls back to the module version instead.
LDFLAGS := -s -w -X main.version=$(VERSION)

## build: reproducible static binary into ./bin
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/$(BINARY)

## dist: release binary for GOOS/GOARCH into ./dist (used by release.yml)
dist:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags="$(LDFLAGS)" \
	  -o dist/$(BINARY)_$(VERSION)_$(GOOS)_$(GOARCH) ./cmd/$(BINARY)

## fmt: fail if any file is not gofmt-clean
fmt:
	@files=$$(gofmt -l .); if [ -n "$$files" ]; then echo "gofmt needed:"; echo "$$files"; exit 1; fi

## vet: go vet, plain and with the integration build tag
vet:
	$(GO) vet $(PKG)
	$(GO) vet -tags=integration $(PKG)

## lint: golangci-lint (v2)
lint: lint-toolchain
	golangci-lint run

# lint-toolchain: fail fast (with the fix) when golangci-lint was built by a
# different Go than the active toolchain.
lint-toolchain:
	@have=$$(golangci-lint version 2>/dev/null | sed -n 's/.* built with \(go[^ ]*\) .*/\1/p'); \
	want=$$($(GO) env GOVERSION); \
	if [ "$$have" != "$$want" ]; then \
	  echo "golangci-lint was built with $${have:-an unknown Go} but the active toolchain is $$want;"; \
	  echo "rebuild it with: make tools"; exit 1; \
	fi

# Transitive import assertions depguard cannot express (it checks direct
# imports only): apply/workflow/fleet never pull in the transport, the
# terminal or the CLI, and the transport never pulls in the domain.
LAYER_DOMAIN_BAN := SSHepherd/internal/(sshconn|sshread|sshwrite|keyfile)$$|golang.org/x/term$$|golang.org/x/crypto/ssh/(agent|knownhosts)$$|spf13/cobra$$
LAYER_TRANSPORT_BAN := SSHepherd/internal/(audit|apply|adopt|workflow)$$

## layering: fail when the import graph breaks the documented package layers
layering:
	@bad=$$($(GO) list -deps ./internal/apply ./internal/workflow ./internal/fleet | grep -E '$(LAYER_DOMAIN_BAN)'); \
	bad2=$$($(GO) list -deps ./internal/sshconn ./internal/sshread ./internal/sshwrite | grep -E '$(LAYER_TRANSPORT_BAN)'); \
	if [ -n "$$bad$$bad2" ]; then printf '%s\n%s\n' "$$bad" "$$bad2"; echo "FAIL: layering"; exit 1; fi

## deadcode: whole-program reachability — fail on functions unreachable from main
deadcode:
	@out=$$(deadcode ./cmd/$(BINARY)); if [ -n "$$out" ]; then \
	  echo "$$out"; echo "FAIL: dead code found"; exit 1; \
	fi

## security: SAST + vulnerabilities + secret scan
security: gosec vuln secrets

## gosec: SAST. Standalone gosec scans the non-test code (it skips every
## _test.go file). golangci-lint's gosec scans the //go:build integration test
## files, which are scoped and triaged in .golangci.yml. The target fails when
## gosec cannot type-check the code, because then only its syntax rules run.
## .claude/ holds agent git worktrees (other checkouts of this module), which
## gosec's own ./... walk would otherwise type-check too.
gosec: lint-toolchain
	@out=$$(gosec -fmt=text -tags=integration -exclude-dir=.claude ./... 2>&1); rc=$$?; \
	if printf '%s\n' "$$out" | grep -q 'Golang errors'; then \
	  printf '%s\n' "$$out" | grep -m3 -A2 'Golang errors'; \
	  echo "FAIL: gosec could not type-check the code; rebuild it with: make tools"; exit 1; \
	fi; \
	if [ $$rc -ne 0 ]; then printf '%s\n' "$$out" | grep -v '^\[gosec\]'; exit $$rc; fi
	@bad=$$(grep -rl --include='*_test.go' '^//go:build integration' cmd internal | grep -Ev '(integration|e2e)_test\.go$$'); \
	if [ -n "$$bad" ]; then \
	  echo "$$bad"; echo "FAIL: name //go:build integration test files *integration_test.go or *e2e_test.go (the gosec scope in .golangci.yml)"; exit 1; \
	fi
	golangci-lint run --enable-only=gosec

vuln:
	govulncheck ./...

## secrets: scan the working tree (also files not yet committed)
secrets:
	gitleaks dir --redact .

## secrets-history: scan commits BASE..HEAD for secrets (the whole history when
## BASE is unset, all-zero, or unknown, e.g. a new branch or workflow_dispatch)
secrets-history:
	@if [ -z "$(BASE)" ] || [ "$(BASE)" = 0000000000000000000000000000000000000000 ] \
	    || ! git cat-file -e "$(BASE)^{commit}" 2>/dev/null; then \
	  gitleaks git --redact --verbose .; \
	else \
	  gitleaks git --redact --verbose --log-opts="$(BASE)..HEAD" .; \
	fi

## licenses: the shipped binary's dependency licenses stay Apache-2.0-compatible
licenses:
	go-licenses check --disallowed_types=forbidden,restricted,unknown ./cmd/$(BINARY)

## actionlint: lint the GitHub workflows. Not part of check (no finding asks for
## it); shellcheck is disabled so the result never depends on what is installed.
actionlint:
	actionlint -shellcheck=""

## test: race detector + atomic coverage profile
test:
	$(GO) test -race -covermode=atomic -coverprofile=$(COVERPROFILE) $(PKG)

## integration: run integration tests against two throwaway sshd containers
## built from ci/images/sshd-$(IT_DISTRO).Dockerfile (alpine | debian | rocky)
IT_DISTRO ?= alpine
integration:
	./scripts/integration.sh "$(IT_DISTRO)"

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

FUZZTIME ?= 15s

## fuzz-list: every Fuzz* target as "importpath Target" (discovered, never hand-listed).
## Fails, rather than dropping a package, when `go list` or a package's
## `go test -list` fails (tests that do not build), or when the targets listed
## differ in number from the `func Fuzz…` declarations in its test files.
fuzz-list:
	@pkgs=$$($(GO) list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' $(PKG)) || \
	  { echo "FAIL: go list $(PKG)" >&2; exit 1; }; \
	for pkg in $$pkgs; do \
	  out=$$($(GO) test -list '^Fuzz' $$pkg) || \
	    { echo "FAIL: go test -list $$pkg (its tests must build for its Fuzz* targets to run)" >&2; exit 1; }; \
	  got=$$(printf '%s\n' "$$out" | sed -n "s|^\(Fuzz[A-Za-z0-9_]*\)$$|$$pkg \1|p"); \
	  info=$$($(GO) list -f '{{.Dir}}{{range .TestGoFiles}} {{.}}{{end}}{{range .XTestGoFiles}} {{.}}{{end}}' $$pkg) || exit 1; \
	  set -- $$info; dir=$$1; shift; \
	  want=$$(cd "$$dir" && cat "$$@" | grep -c '^func Fuzz[^a-z]'); \
	  n=$$(printf '%s' "$$got" | grep -c .); \
	  [ "$$n" = "$$want" ] || \
	    { echo "FAIL: $$pkg: go test -list found $$n Fuzz* targets, its test files declare $$want" >&2; exit 1; }; \
	  [ -z "$$got" ] || printf '%s\n' "$$got"; \
	done

## fuzz: fuzz every target for FUZZTIME each (default 15s); runs all, fails if any failed
fuzz:
	@fail=0; $(MAKE) -s fuzz-list > .fuzz-targets || { rm -f .fuzz-targets; exit 1; }; \
	while read -r pkg t; do \
	  echo "== $$t ($$pkg)"; \
	  $(GO) test -run='^$$' -fuzz="^$$t\$$" -fuzztime=$(FUZZTIME) $$pkg || fail=1; \
	done < .fuzz-targets; rm -f .fuzz-targets; exit $$fail

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
	trivy config --exit-code 1 --skip-dirs ci/images .

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
	$(TOOLS_ENV) $(GO) install github.com/google/go-licenses/v2@$(GOLICENSES_VERSION)
	$(TOOLS_ENV) $(GO) install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

## hooks: install git pre-commit/pre-push hooks (lefthook)
hooks:
	lefthook install

## clean: remove build and coverage artifacts
clean:
	rm -rf bin dist $(COVERPROFILE) coverage.html .fuzz-targets
