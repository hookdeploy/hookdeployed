# hookdeployed

HookDeploy delivery agent.

Status: pre-alpha, under active development.

## Version

Local / unset builds report `dev`. Release builds set:

```
go build -ldflags "-X github.com/hookdeploy/hookdeployed/internal/version.Version=0.1.0" -o bin/agent ./cmd/agent
```

Or `make build VERSION=0.1.0` / `powershell -File .\dev.ps1 build -Version 0.1.0`.

There is no CI distribution build yet — wire the same `-ldflags` when that is added.
