# Windows stand-in for Makefile targets: gencerts, run-relay, run-agent, test, vet, build
param(
    [Parameter(Position = 0)]
    [ValidateSet("gencerts", "run-relay", "run-agent", "test", "vet", "build")]
    [string]$Target = "test",
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"
$env:CGO_ENABLED = "0"
$ldflags = "-X github.com/hookdeploy/hookdeployed/internal/version.Version=$Version"

switch ($Target) {
    "gencerts" { go run ./cmd/gencerts; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
    "run-relay" { go run ./cmd/relay-stub; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
    "run-agent" { go run -ldflags $ldflags ./cmd/agent; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
    "build" {
        New-Item -ItemType Directory -Force -Path bin | Out-Null
        go build -ldflags $ldflags -o bin/agent.exe ./cmd/agent
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        go build -o bin/relay-stub.exe ./cmd/relay-stub
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    "test" { go test ./...; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
    "vet" { go vet ./...; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }
}
