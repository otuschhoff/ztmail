.PHONY: build build-one test

BUILD_TIME ?= $(shell date -u +%Y%m%d-%H%M%S)
COMMIT_SHA ?= $(shell git rev-parse HEAD | cut -c1-7)
TARGET_OS ?= linux
TARGET_ARCH ?= amd64
OUTPUT ?= dist/ztmail-$(TARGET_OS)-$(TARGET_ARCH)$(if $(filter windows,$(TARGET_OS)),.exe)
LDFLAGS = -X main.buildTime=$(BUILD_TIME) -X main.commitSHA=$(COMMIT_SHA)

build:
	@set -eu; \
	for os in linux windows darwin; do \
		for arch in amd64 arm64; do \
			$(MAKE) --no-print-directory build-one TARGET_OS=$$os TARGET_ARCH=$$arch \
				BUILD_TIME="$(BUILD_TIME)" COMMIT_SHA="$(COMMIT_SHA)"; \
		done; \
	done

build-one:
	@test -n "$(BUILD_TIME)" && test -n "$(COMMIT_SHA)" || { echo "Build time and commit SHA are required" >&2; exit 1; }
	mkdir -p "$(dir $(OUTPUT))"
	CGO_ENABLED=0 GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) go build ./...
	CGO_ENABLED=0 GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) go build -trimpath -ldflags "$(LDFLAGS)" -o "$(OUTPUT)" ./cmd/ztmail

test:
	bash .github/scripts/release-notes-test.sh
	go test -race ./...
	go vet ./...
