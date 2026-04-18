BINARY := boarnet
PKG    := ./cmd/boarnet
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: build run fmt vet test tidy clean

build:
	go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY) $(PKG)

build-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY)-linux-arm64 $(PKG)

build-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY)-linux-amd64 $(PKG)

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
