# GNU make targets. On Windows without make, use: powershell -File .\dev.ps1 <target>
# CGO is disabled; this pass is pure-Go.

CGO_ENABLED ?= 0
export CGO_ENABLED

.PHONY: gencerts run-relay run-agent test vet build

build:
	go build -o bin/agent ./cmd/agent
	go build -o bin/relay-stub ./cmd/relay-stub

gencerts:
	go run ./cmd/gencerts

run-relay:
	go run ./cmd/relay-stub

run-agent:
	go run ./cmd/agent

test:
	go test ./...

vet:
	go vet ./...
