BINARY := boarnet
PKG    := ./cmd/boarnet
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build release release-clean run fmt vet test tidy clean build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64

build:
	go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-linux-amd64 $(PKG)

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-linux-arm64 $(PKG)

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-darwin-amd64 $(PKG)

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY)-darwin-arm64 $(PKG)

# release: build all four platforms + emit SHA-256 checksums.
# Run on a clean checkout of a tagged commit so VERSION comes out pretty.
release: release-clean build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64
	cd bin && sha256sum $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 $(BINARY)-darwin-amd64 $(BINARY)-darwin-arm64 > SHA256SUMS
	@echo
	@echo "Release artifacts in ./bin:"
	@ls -la bin/

release-clean:
	rm -rf bin/
	mkdir -p bin

run:
	go run $(PKG) \
		--ssh-port 2222 \
		--tls-port 8443 \
		--ingest-url http://localhost:3000/v1/events \
		--sensor-id dev-local \
		--data-dir ./.boarnet

fmt:
	go fmt ./...

vet:
	go vet ./...

test:
	go test -race ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/ .boarnet/
