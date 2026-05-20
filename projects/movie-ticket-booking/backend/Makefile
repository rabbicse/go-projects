.PHONY: run build test test-unit test-integration lint tidy

BINARY := bin/api
PKG    := ./cmd/api/...

run:
	go run $(PKG)

build:
	go build -o $(BINARY) $(PKG)

tidy:
	go mod tidy

lint:
	golangci-lint run ./...

# Unit tests only (fast, no containers)
test-unit:
	go test -v -race -count=1 ./internal/... -short

# Integration tests (requires Docker)
test-integration:
	go test -v -race -count=1 -timeout 120s ./tests/integration/...

test: test-unit test-integration

# Run with race detector
run-race:
	go run -race $(PKG)

# Sync swagger.json from internal/docs to top-level docs/
sync-swagger:
	cp internal/docs/swagger.json docs/swagger.json
	@echo "Swagger spec synced. Open http://localhost:8080/api/v1/docs to view."
