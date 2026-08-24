.PHONY: build test vet bench fmt

GOCACHE ?= $(CURDIR)/.gocache
GOTMPDIR ?= $(CURDIR)/.gotmp
export GOCACHE GOTMPDIR GOTELEMETRY=off

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

bench:
	go test -bench=Benchmark -benchmem ./internal/...

fmt:
	gofmt -w .