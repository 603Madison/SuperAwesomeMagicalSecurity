VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS = -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
PKG := ./cmd/sams-agent

TARGETS := linux-amd64 linux-arm64 darwin-arm64 windows-amd64

PKG_VERSION ?= 0.1.0
NFPM ?= nfpm

.PHONY: all build test vet clean packages $(TARGETS)

all: test $(TARGETS)

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/sams-agent $(PKG)

linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/sams-agent-linux-amd64 $(PKG)

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/sams-agent-linux-arm64 $(PKG)

darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/sams-agent-darwin-arm64 $(PKG)

windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/sams-agent-windows-amd64.exe $(PKG)

vet:
	go vet ./...
	GOOS=windows go vet ./...
	GOOS=darwin go vet ./...

test: vet
	go test ./...

# Linux .deb and .rpm for amd64 + arm64 (binary in /usr/bin, unit in /usr/lib/systemd/system)
packages: VERSION = $(PKG_VERSION)
packages: linux-amd64 linux-arm64
	mkdir -p dist
	for arch in amd64 arm64; do \
	  mkdir -p bin/.pkg && cp bin/sams-agent-linux-$$arch bin/.pkg/sams-agent || exit 1; \
	  for fmt in deb rpm; do \
	    PKG_ARCH=$$arch PKG_VERSION=$(PKG_VERSION) $(NFPM) package --config packaging/nfpm.yaml --packager $$fmt --target dist/ || exit 1; \
	  done; \
	done

clean:
	rm -rf bin dist
