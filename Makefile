GO ?= go

.PHONY: build test test-cover vet fmt tidy check

build:
	@mkdir -p bin
	$(GO) build -o bin/ ./cmd/...

test:
	$(GO) test ./...

test-cover:
	$(GO) test -cover ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

tidy:
	$(GO) mod tidy

check: fmt vet test
