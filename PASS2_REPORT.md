# HookDeployed Pass 2 Report

**Date:** 2026-08-15  
**Status:** Isolated mTLS handshake proven. Local commit only. No push. Other five repos untouched.

## Audit

### `go version`

```
go version go1.26.6 windows/amd64
```

`where.exe go`:

```
C:\Program Files\Go\bin\go.exe
```

`go env` (relevant):

```
GOVERSION=go1.26.6
CGO_ENABLED=0
GOOS=windows
GOARCH=amd64
```

### Directory / module path

`c:\hookdeploy\hookdeployed\` **existed** from the previous stop (only `PASS2_REPORT.md`, no `.git`). It was not a foreign project. Proceeded in that directory.

Module path `github.com/hookdeploy/hookdeployed` was free (no existing `go.mod`).

`git init` created an independent repo at `c:\hookdeploy\hookdeployed\.git` (not a submodule of any sibling clone). Default branch `master` was renamed to `main` with `git branch -m main` (no `git config` changes).

## Cert method

**Go `crypto/x509` via `cmd/gencerts`** (preferred in the prompt). ECDSA P-256. No openssl. No cgo. No SQLite.

Throwaway identities:

| Role | Subject |
|---|---|
| Test CA | CN=`hookdeployed-test-ca` (self-signed) |
| Server | CN=`localhost`, SAN DNS=`localhost`, IP=`127.0.0.1` |
| Client | CN=`agent-test-001`, OU=`org-test-aaa` |

PEMs written to gitignored `certs/` (`ca.crt`/`ca.key`, `server.crt`/`server.key`, `client.crt`/`client.key`).

## What was created (file tree)

Committed / source tree (certs/ is gitignored and not listed as source):

```
hookdeployed/
  .gitignore
  LICENSE                          Apache-2.0, copyright SnapStack Technologies Inc.
  Makefile                         gencerts, run-relay, run-agent, test, vet
  README.md
  PASS2_REPORT.md
  dev.ps1                          Windows stand-in for Makefile targets
  go.mod                           module github.com/hookdeploy/hookdeployed, go 1.26.6
  cmd/agent/main.go
  cmd/gencerts/main.go
  cmd/relay-stub/main.go
  internal/mtls/pki.go
  internal/mtls/tls.go
  internal/mtls/tls_test.go
```

Local only (gitignored):

```
certs/ca.crt
certs/ca.key
certs/server.crt
certs/server.key
certs/client.crt
certs/client.key
```

## Handshake proof (pasted command output)

### Generate certs

```
PS> $env:CGO_ENABLED = "0"; powershell -File .\dev.ps1 gencerts
2026/08/15 10:17:01 wrote test PKI to certs (CA, server SAN=localhost, client CN=agent-test-001 OU=org-test-aaa)
```

```
ca.crt
ca.key
client.crt
client.key
server.crt
server.key
```

### Server log (CN/OU extracted)

`go run ./cmd/relay-stub` listening on `127.0.0.1:8443`:

```
2026/08/15 10:17:06 relay-stub: relay-stub listening on 127.0.0.1:8443 (mTLS required)
2026/08/15 10:17:10 relay-stub: client identity CN=agent-test-001 OU=org-test-aaa
2026/08/15 10:17:10 relay-stub: received: "hello-from-agent\n"
2026/08/15 10:17:10 relay-stub: echoed; holding connection open
```

### Client log (echo + exit 0)

```
PS> $env:CGO_ENABLED = "0"; go run ./cmd/agent; Write-Host "agent exit: $LASTEXITCODE"
2026/08/15 10:17:10 agent: sent: "hello-from-agent\n"
2026/08/15 10:17:10 agent: echo: "hello-from-agent\n"
2026/08/15 10:17:10 agent: mTLS echo ok
agent exit: 0
```

### `go vet ./...`

```
PS> $env:CGO_ENABLED = "0"; go vet ./...; Write-Host "vet exit: $LASTEXITCODE"
vet exit: 0
```

## No-client-cert rejection test (pasted output)

`internal/mtls/tls_test.go` starts an in-process TLS listener using `tls.RequireAndVerifyClientCert`, then dials with CA trust and **no** client certificate.

```
PS> $env:CGO_ENABLED = "0"; go test ./... -v
?   	github.com/hookdeploy/hookdeployed/cmd/agent	[no test files]
?   	github.com/hookdeploy/hookdeployed/cmd/gencerts	[no test files]
?   	github.com/hookdeploy/hookdeployed/cmd/relay-stub	[no test files]
=== RUN   TestRejectsConnectionWithoutClientCert
    tls_test.go:55: client rejected at read: remote error: tls: certificate required
    tls_test.go:65: server rejected as expected: tls: client didn't provide a certificate
--- PASS: TestRejectsConnectionWithoutClientCert (0.00s)
PASS
ok  	github.com/hookdeploy/hookdeployed/internal/mtls	(cached)
```

Mutual auth is enforced. A client that only verifies the server is rejected with `tls: certificate required`.

## Deviations from the prompt

1. **Directory was not empty at start of this pass.** It contained only the previous STOP `PASS2_REPORT.md`. No foreign module. Did not stop.
2. **`make` is not installed** on this Windows machine. Added a `Makefile` (for later/CI) and `dev.ps1` with the same targets (`gencerts`, `run-relay`, `run-agent`, `test`, plus `vet`). Handshake and tests were run via `go run` / `dev.ps1`, not `make`.
3. **Added `internal/mtls`** (not named in the prompt) so `gencerts`, the two cmds, and the rejection test share one PKI/TLS implementation. Cmd paths match the prompt.
4. **TLS 1.3:** `tls.Dial` without a client cert can return success; the server then aborts. The test treats first-I/O `remote error: tls: certificate required` plus server `tls: client didn't provide a certificate` as rejection. It does not require Dial itself to fail.
5. **`git init` defaulted to `master`.** Renamed to `main` with `git branch -m main`. Did not change git config.
6. **Previous session stopped** because Go was missing. This session used the now-installed `go1.26.6` toolchain. `go.mod` is pinned to `1.26.6`.

## Other repos

No files modified, staged, or committed in `platform/`, `relay/`, `supabase/`, `marketing/`, or `n8n/`. No deploy, publish, wrangler, or `git push`.
