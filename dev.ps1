# Windows stand-in for Makefile targets: gencerts, run-relay, run-agent, test, vet
param(
    [Parameter(Position = 0)]
    [ValidateSet("gencerts", "run-relay", "run-agent", "test", "vet")]
    [string]$Target = "test"
)

$ErrorActionPreference = "Stop"
$env:CGO_ENABLED = "0"

switch ($Target) {
    "gencerts" { go run ./cmd/gencerts; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
    "run-relay" { go run ./cmd/relay-stub; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
    "run-agent" { go run ./cmd/agent; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
    "test" { go test ./...; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
    "vet" { go vet ./...; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
}
