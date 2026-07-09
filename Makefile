BINARY       := sshepherd
IMAGE        := sshepherd:dev
COVERPROFILE := coverage.out
COVERAGE_MIN := 80
PKG          := ./...
GO           := go

# Pinned dev-tool versions (keep in sync with CLAUDE.md).
GOLANGCI_VERSION := v2.12.2
GOSEC_VERSION    := latest
GOVULN_VERSION   := latest
GITLEAKS_VERSION := latest

.PHONY: all check build fmt vet lint security gosec vuln secrets test coverage \
        integration fuzz bench tidy docker docker-lint docker-scan smoke tools hooks clean

## all: default target — run the full gate
all: check

## check: full quality gate (the same command CI runs)
check: tidy fmt vet lint security test

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
lint:
	golangci-lint run

## security: SAST + vulnerabilities + secret scan
security: gosec vuln secrets

gosec:
	gosec -quiet ./...

vuln:
	govulncheck ./...

secrets:
	gitleaks detect --no-git --redact

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

## fuzz: short fuzz run of the authorized_keys parsers
fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzParseLine -fuzztime=15s ./internal/authkeys
	$(GO) test -run='^$$' -fuzz=FuzzParseFile -fuzztime=15s ./internal/authkeys

## bench: run benchmarks
bench:
	$(GO) test -run='^$$' -bench=. -benchmem $(PKG)

## tidy: ensure go.mod/go.sum are tidy and verified
tidy:
	$(GO) mod tidy
	$(GO) mod verify

## docker: build the container image
docker:
	docker build -t $(IMAGE) .

## docker-lint: lint the Dockerfile and the built image
docker-lint:
	hadolint Dockerfile
	# CIS-DI-0006 (HEALTHCHECK) waived: sshepherd is a CLI, not a service.
	dockle --exit-code 1 -i CIS-DI-0006 $(IMAGE)

## docker-scan: scan the image + config for CVEs/misconfig
docker-scan:
	trivy image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed $(IMAGE)
	trivy config --exit-code 1 .

## smoke: the image runs and reports its version
smoke:
	docker run --rm $(IMAGE) --version

## tools: install pinned dev tooling into GOPATH/bin
tools:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULN_VERSION)
	$(GO) install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

## hooks: install git pre-commit/pre-push hooks (lefthook)
hooks:
	lefthook install

## clean: remove build and coverage artifacts
clean:
	rm -rf bin $(COVERPROFILE) coverage.html
