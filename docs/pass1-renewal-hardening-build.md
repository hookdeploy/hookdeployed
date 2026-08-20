# Pass 1 — agent renewal hardening (when, not what)

**Repo:** `hookdeployed` only. **No deploy. No commit. No PR.**

This pass changes **when** `MaybeRenew` is attempted. It does not change the halfway predicate, the renew POST, or `WriteBundle`. It does **not** introduce a renewal token.

**Explicit statement:** this pass does not fix the expired-beyond-grace case. An agent asleep past its cert’s expiry + the Worker’s ±1h grace still cannot renew and still needs re-enrollment. That is passes 2–3 (the 30-day renewal token).

---

## PART 0 — read-only confirm (pre-edit)

### Base state

| Command | Output |
| --- | --- |
| `git rev-parse HEAD` | `925f5de963f8c2be10942621305f31cf0af54795` |
| `git rev-parse --abbrev-ref HEAD` | `feat/enrollment` |
| `git status --short` (start of this pass) | see below |

Pre-existing dirty tree (untouched by this pass; **do not mix in**):

```
 M cmd/agent/main.go
 M internal/mtls/client.go
?? internal/connect/
?? internal/mtls/client_test.go
```

`internal/connect/` was already untracked relative to HEAD. This pass edits that working-tree package. `internal/enroll/run.go` was clean at HEAD and is the only tracked file this pass changes.

### `MaybeRenew` call sites (audit match)

`Get-ChildItem -Recurse -Filter *.go | Select-String -Pattern 'MaybeRenew'` **before** this pass, matching the two-credential audit:

| File | Role |
| --- | --- |
| `internal/connect/connect.go:64-66` | once, at `Run` start, before the reconnect loop |
| `cmd/agent/main.go:114` | echo/stub path only (not the `connect` subcommand) |
| `internal/enroll/run.go:95` | definition |

No call in the reconnect loop (`73-91`) or `dialAndHeartbeat` (`94-151`). Agrees with the audit. Proceeded.

After this pass the definition moved to `run.go:98` (import lines). The start-of-`Run` call was **moved into the reconnect loop** via `attemptRenew` (defaults to `enroll.MaybeRenew`). `cmd/agent/main.go:114` is unchanged.

### Full pre-edit `internal/connect/connect.go` (180 lines)

Quoted as it existed on disk immediately before this pass (reconstructed from the connect-package write + the two follow-up `StrReplace`s that introduced the shared `bufio.Reader` and the PING/PONG log invariant). Line numbers match the audit (`MaybeRenew` at 64–66, loop 73–91, `dialAndHeartbeat` 94–151, ticker 135, `time.After` 86).

```go
package connect

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hookdeploy/hookdeployed/internal/enroll"
	"github.com/hookdeploy/hookdeployed/internal/store"
)

const (
	DefaultPort         = "9443"
	DefaultPingInterval = 10 * time.Second
	maxBackoff          = 30 * time.Second
	minBackoff          = time.Second
)

type Config struct {
	Relay        string
	CertsDir     string
	EnrollURL    string
	PingInterval time.Duration
}

func ParseRelay(relay string) (host, addr string, err error) {
	if relay == "" {
		return "", "", fmt.Errorf("--relay is required")
	}
	if h, p, splitErr := net.SplitHostPort(relay); splitErr == nil {
		if h == "" {
			return "", "", fmt.Errorf("--relay host is empty")
		}
		return h, net.JoinHostPort(h, p), nil
	}
	return relay, net.JoinHostPort(relay, DefaultPort), nil
}

func NextBackoff(prev time.Duration) time.Duration {
	if prev < minBackoff {
		return minBackoff
	}
	next := prev * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = DefaultPingInterval
	}
	host, addr, err := ParseRelay(cfg.Relay)
	if err != nil {
		return err
	}

	if err := enroll.MaybeRenew(cfg.EnrollURL, cfg.CertsDir); err != nil {
		log.Printf("renew skipped/failed: %v", err)
	}

	if _, err := store.Load(cfg.CertsDir); err != nil {
		return fmt.Errorf("no enrolled cert in %s — run `agent enroll` first", cfg.CertsDir)
	}

	backoff := time.Duration(0)
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := dialAndHeartbeat(ctx, cfg, host, addr); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			backoff = NextBackoff(backoff)
			log.Printf("disconnected relay=%s; retry in %s", host, backoff)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			continue
		}
		return nil
	}
}

func dialAndHeartbeat(ctx context.Context, cfg Config, host, addr string) error {
	material, err := store.Load(cfg.CertsDir)
	if err != nil {
		return fmt.Errorf("reload certs: %w", err)
	}
	tlsCfg, err := material.ClientTLSConfigFor(host)
	if err != nil {
		return err
	}

	dialer := &tls.Dialer{Config: tlsCfg}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("dial relay=%s: %v", host, err)
		return err
	}
	defer conn.Close()
	log.Printf("connected relay=%s remote=%s", host, conn.RemoteAddr())

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	reader := bufio.NewReader(conn)
	if err := pingOnce(conn, reader, cfg.PingInterval); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("heartbeat dropped relay=%s", host)
		return err
	}

	ticker := time.NewTicker(cfg.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := pingOnce(conn, reader, cfg.PingInterval); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				log.Printf("heartbeat dropped relay=%s", host)
				return err
			}
		}
	}
}

func pingOnce(conn net.Conn, reader *bufio.Reader, interval time.Duration) error {
	if _, err := io.WriteString(conn, "PING\n"); err != nil {
		return err
	}
	slack := 2 * time.Second
	if interval > slack {
		slack = interval
	}
	_ = conn.SetReadDeadline(time.Now().Add(interval + slack))
	line, err := reader.ReadString('\n')
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	// INVARIANT: never log the line, its length, or a hash. PING/PONG are
	// control; when this loop forwards webhooks the same rule applies.
	if trimHeartbeat(line) != "PONG" {
		return fmt.Errorf("heartbeat: expected PONG")
	}
	return nil
}

func trimHeartbeat(line string) string {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}
```

### `MaybeRenew` at HEAD (unchanged behavior; this pass only adds a success log after `WriteBundle`)

Signature: `func MaybeRenew(baseURL, certDir string) error`.

Behavior (confirmed, not re-derived):

1. `store.Load(certDir)`.
2. Halfway = `NotBefore + (NotAfter-NotBefore)/2`.
3. If `time.Now().Before(halfway)` → `return nil` (no network, silent).
4. Else CSR + POST `/v1/enroll/renew` via `client.Renew(certPEM, nil, rootPEM, csrPEM)`.
5. On success: `store.WriteBundle(...)` (overwrites the same three files). Previously **no success log**; failures return `error` and the caller prints `renew skipped/failed`.

Quoted from `git show HEAD:internal/enroll/run.go`:

```go
func MaybeRenew(baseURL, certDir string) error {
	material, err := store.Load(certDir)
	if err != nil {
		return err
	}
	life := material.ClientCert.NotAfter.Sub(material.ClientCert.NotBefore)
	halfway := material.ClientCert.NotBefore.Add(life / 2)
	if time.Now().Before(halfway) {
		return nil
	}
	csrPEM, err := CSRFromKey(material.ClientKey, material.ClientCert.Subject.CommonName)
	if err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(filepath.Join(certDir, "client.crt"))
	if err != nil {
		return err
	}
	client := NewClient(baseURL)
	out, err := client.Renew(certPEM, nil, rootPEM, csrPEM)
	if err != nil {
		return err
	}
	keyPEM, err := EncodeKey(material.ClientKey)
	if err != nil {
		return err
	}
	return store.WriteBundle(certDir, []byte(out.Root), []byte(out.CertChain), []byte(out.Certificate), []byte(out.CA), keyPEM)
}
```

Halfway predicate, CSR, POST, and `WriteBundle` are **not** changed. Only a success log after a successful write (PART 4).

---

## PART 1 — renew before each reconnect

`attemptRenew(cfg)` now runs at the **top of every loop iteration**, including the first. The old one-shot call before the loop is gone; launch is the first iteration.

On failure: log `renew skipped/failed` and **continue to `dialAndHeartbeat`**. A failed renew never returns from `Run` and never skips the dial.

### Backoff progression (quoted)

`NextBackoff` / constants, unchanged, already covered by `TestNextBackoff`:

```go
minBackoff = time.Second
maxBackoff = 30 * time.Second
// NextBackoff: if prev < min → min; else prev*2 capped at max
```

Progression: **1s, 2s, 4s, 8s, 16s, 30s, 30s, …**

### Damper decision: **not added**

`MaybeRenew` already self-gates the **network** call on the halfway predicate. The reconnect-loop cost is a disk `Load` of `client.crt` (and friends) every backoff tick.

That is cheap at this backoff: a few reads during the 1→16s ramp, then one read every 30s while the relay is down. The relay’s Pass 1 damper (`DueForRenewalAttempt`, `DefaultRenewMinGap = 10 * time.Minute`) exists to stop **retrying a failing enrollment POST every minute** for ~12h of remaining leaf life. It is a network damper sitting on top of a 1-minute disk ticker, not a disk-read damper.

Mirroring that here would be the wrong polarity: the important reconnect case is **wake from sleep, then redial**. A 10-minute gap would delay the first post-wake `MaybeRenew` until after several TLS failures. Disk I/O at 1–30s does not justify that delay.

No `DueForRenewalAttempt` equivalent in the agent reconnect path. PART 5 item 10 (damper unit test) is therefore N/A.

---

## PART 2 — periodic re-check while connected

Interval: **`DefaultRenewInterval = 5 * time.Minute`**.

Why not the relay’s 1 minute: the relay is infrastructure that must pick up a new on-disk leaf for the next handshake (`GetCertificate`). The agent is a client; halfway of a 24h leaf is ~12h; a 5-minute check is frequent enough that a long-lived process will renew during the second half of the leaf without waiting for a disconnect. Wake detection (PART 3) samples the **10s ping ticker**, so suspend is noticed far sooner than 5 minutes.

Lifecycle: `renewTicker := time.NewTicker(cfg.RenewInterval)` inside `dialAndHeartbeat`, `defer renewTicker.Stop()`, and the same `select` exits on `ctx.Done()` as the ping ticker. `Config.RenewInterval <= 0` falls back to the default (tests can override).

### Forced reconnect after renewal: **no**

A successful `MaybeRenew` writes new files while the TLS conn is live. Go keeps using the handshake certs for that conn. The next `dialAndHeartbeat` does `store.Load` and picks up the new leaf.

Forcing a reconnect would drop a working session to adopt a cert that still has ~12h of validity at halfway. Make-before-break, same reasoning as the relay: write the new bundle, leave the live conn alone.

---

## PART 3 — wake / clock-jump detection

Predicate (exported for tests):

```go
func IsWakeEvent(last, now time.Time, sampleInterval time.Duration) bool {
	if sampleInterval <= 0 || last.IsZero() {
		return false
	}
	gap := now.Round(0).Sub(last.Round(0))
	return gap > 2*sampleInterval
}
```

Sampled on the **ping ticker** (`DefaultPingInterval = 10s`), not only on the 5-minute renew ticker, so a laptop that slept 10 hours notices within one ping period after timers resume.

### Monotonic vs wall — verified from Go’s contract, not assumed

Go `time.Time` carries an optional monotonic reading. `Sub` / `Since` / `Until` **use the monotonic clock when both values have one** ([`time` package, Monotonic Clocks](https://pkg.go.dev/time#hdr-Monotonic_Clocks)):

> On some systems the monotonic clock will stop if the computer goes to sleep. On such systems, times of events spanning a sleep will measure the elapsed time in which the computer was running, not the wall-clock time that elapsed.

Platform clocks Go actually uses:

| OS | Monotonic source | Includes suspend? | Wall source |
| --- | --- | --- | --- |
| Linux | `CLOCK_MONOTONIC` (not `CLOCK_BOOTTIME`) | no | `CLOCK_REALTIME` |
| macOS | `mach_absolute_time` | no | `gettimeofday` |
| Windows | `QueryPerformanceCounter` | no | `GetSystemTimeAsFileTime` |

So `time.Since(lastTick)` after a 10-hour sleep is typically ~one tick of **run** time, not 10 hours. Wall clock **does** jump.

`t.Round(0)` strips the monotonic reading (same docs). `now.Round(0).Sub(last.Round(0))` is therefore wall elapsed. Threshold `> 2× sampleInterval` treats a 10s ping with a >20s wall gap as a wake.

A live OS-suspend test was not run here (CI cannot sleep the host). Isolation tests inject `time.Unix` values (no monotonic) and assert the predicate. That is the same arithmetic the production path uses after `Round(0)`.

On wake, `attemptRenew` runs immediately; the live conn is still not dropped (PART 2). If the leaf is already dead the next ping/dial fails, the reconnect loop runs `attemptRenew` again before the next dial.

---

## PART 4 — logging

**Decision: success log lives inside `MaybeRenew`**, not at each connect call site.

Justification: `cmd/agent/main.go:114` (echo/stub) also calls `MaybeRenew`. One line after `WriteBundle` covers every caller. This pass otherwise does not change renewal logic in `run.go`.

| Outcome | Log |
| --- | --- |
| Checked, not due (`now < halfway`) | **silent** (existing `return nil`) |
| Renewed and persisted | `renewed leaf not_after=<RFC3339 UTC>` — always |
| Parse of the new leaf PEM fails (should not happen after a Worker 200) | `renewed leaf` without `not_after` |
| Attempted and failed | callers already log `renew skipped/failed: %v` — always |

Never logs cert PEM, key, or CSR. `logRenewedLeaf` parses the first PEM block of `out.Certificate` and prints only `NotAfter`.

---

## PART 5 — tests

| Item | Result |
| --- | --- |
| 9. `IsWakeEvent` isolation | `TestIsWakeEvent` + `TestIsWakeEventUsesWallNotMonotonic` |
| 10. reconnect damper | **N/A** — no damper added |
| 11. failed renew still dials | `TestFailedRenewDoesNotBlockDial` (inject `Config.Renew` error; still gets ≥2 PINGs) |
| 12. `go build ./...` / `go test ./...` | all pass (output below) |

Existing `TestConnectHandshakeAndTwoPings`, `TestNextBackoff`, `TestParseRelay`, `TestRunMissingCertDir`, and `internal/enroll` tests still pass. Test PKI leaves are `now-1h` / `now+24h` (halfway ~11.5h out), so the real `MaybeRenew` on the handshake test is a disk check + silent return.

### Test results

```
go build ./...
go test ./...

?   	github.com/hookdeploy/hookdeployed/cmd/agent	[no test files]
?   	github.com/hookdeploy/hookdeployed/cmd/gencerts	[no test files]
?   	github.com/hookdeploy/hookdeployed/cmd/relay-stub	[no test files]
ok  	github.com/hookdeploy/hookdeployed/internal/connect	0.683s
ok  	github.com/hookdeploy/hookdeployed/internal/enroll	0.368s
ok  	github.com/hookdeploy/hookdeployed/internal/mtls	(cached)
?   	github.com/hookdeploy/hookdeployed/internal/store	[no test files]
```

Re-run `-count=1` of the packages this pass touched:

```
ok  	github.com/hookdeploy/hookdeployed/internal/connect	0.712s
ok  	github.com/hookdeploy/hookdeployed/internal/enroll	0.390s
```

---

## Files this pass changed

| File | Change |
| --- | --- |
| `internal/connect/connect.go` | reconnect `MaybeRenew`, 5m ticker, wake predicate |
| `internal/connect/connect_test.go` | wake tests + failed-renew-still-dials |
| `internal/enroll/run.go` | success log only |
| `docs/pass1-renewal-hardening-build.md` | this report |

Not touched: `cmd/agent/main.go`, `internal/mtls/client.go`, credential model, Worker, relay.

---

## Full diff

Tracked file (`git diff internal/enroll/run.go`):

```diff
diff --git a/internal/enroll/run.go b/internal/enroll/run.go
index b551fee..d049f0c 100644
--- a/internal/enroll/run.go
+++ b/internal/enroll/run.go
@@ -1,7 +1,10 @@
 package enroll
 
 import (
+	"crypto/x509"
+	"encoding/pem"
 	"fmt"
+	"log"
 	"os"
 	"path/filepath"
 	"time"
@@ -123,5 +126,23 @@ func MaybeRenew(baseURL, certDir string) error {
 	if err != nil {
 		return err
 	}
-	return store.WriteBundle(certDir, []byte(out.Root), []byte(out.CertChain), []byte(out.Certificate), []byte(out.CA), keyPEM)
+	if err := store.WriteBundle(certDir, []byte(out.Root), []byte(out.CertChain), []byte(out.Certificate), []byte(out.CA), keyPEM); err != nil {
+		return err
+	}
+	logRenewedLeaf(out.Certificate)
+	return nil
+}
+
+func logRenewedLeaf(certPEM string) {
+	block, _ := pem.Decode([]byte(certPEM))
+	if block == nil {
+		log.Printf("renewed leaf")
+		return
+	}
+	cert, err := x509.ParseCertificate(block.Bytes)
+	if err != nil {
+		log.Printf("renewed leaf")
+		return
+	}
+	log.Printf("renewed leaf not_after=%s", cert.NotAfter.UTC().Format(time.RFC3339))
 }
```

Untracked package vs pre-edit working tree:

```diff
--- a/internal/connect/connect.go
+++ b/internal/connect/connect.go
@@ -17,15 +17,23 @@
 const (
 	DefaultPort         = "9443"
 	DefaultPingInterval = 10 * time.Second
-	maxBackoff          = 30 * time.Second
-	minBackoff          = time.Second
+	// DefaultRenewInterval is how often a live connection re-runs MaybeRenew.
+	// Halfway of a 24h leaf is ~12h; 5m is frequent enough for a client without
+	// the 1m cadence the relay uses as infrastructure. Wake detection uses the
+	// ping ticker (10s), so suspend is noticed well before this fires.
+	DefaultRenewInterval = 5 * time.Minute
+	maxBackoff           = 30 * time.Second
+	minBackoff           = time.Second
 )
 
 type Config struct {
-	Relay        string
-	CertsDir     string
-	EnrollURL    string
-	PingInterval time.Duration
+	Relay         string
+	CertsDir      string
+	EnrollURL     string
+	PingInterval  time.Duration
+	RenewInterval time.Duration
+	// Renew overrides enroll.MaybeRenew (tests). Nil uses the real function.
+	Renew func(enrollURL, certDir string) error
 }
 
 func ParseRelay(relay string) (host, addr string, err error) {
@@ -52,17 +60,38 @@
 	return next
 }
 
+// IsWakeEvent reports a wall-clock gap much larger than sampleInterval,
+// which typically means the process was suspended. Monotonic readings are
+// stripped with Round(0): time.Since uses the monotonic clock and does not
+// advance during OS sleep on Windows, macOS, and Linux.
+func IsWakeEvent(last, now time.Time, sampleInterval time.Duration) bool {
+	if sampleInterval <= 0 || last.IsZero() {
+		return false
+	}
+	gap := now.Round(0).Sub(last.Round(0))
+	return gap > 2*sampleInterval
+}
+
+func attemptRenew(cfg Config) {
+	fn := cfg.Renew
+	if fn == nil {
+		fn = enroll.MaybeRenew
+	}
+	if err := fn(cfg.EnrollURL, cfg.CertsDir); err != nil {
+		log.Printf("renew skipped/failed: %v", err)
+	}
+}
+
 func Run(ctx context.Context, cfg Config) error {
 	if cfg.PingInterval <= 0 {
 		cfg.PingInterval = DefaultPingInterval
 	}
+	if cfg.RenewInterval <= 0 {
+		cfg.RenewInterval = DefaultRenewInterval
+	}
 	host, addr, err := ParseRelay(cfg.Relay)
 	if err != nil {
 		return err
 	}
-
-	if err := enroll.MaybeRenew(cfg.EnrollURL, cfg.CertsDir); err != nil {
-		log.Printf("renew skipped/failed: %v", err)
-	}
 
 	if _, err := store.Load(cfg.CertsDir); err != nil {
 		return fmt.Errorf("no enrolled cert in %s — run `agent enroll` first", cfg.CertsDir)
@@ -74,6 +103,7 @@
 		if err := ctx.Err(); err != nil {
 			return nil
 		}
+		attemptRenew(cfg)
 		if err := dialAndHeartbeat(ctx, cfg, host, addr); err != nil {
 			if ctx.Err() != nil {
 				return nil
@@ -132,13 +162,22 @@
 		return err
 	}
 
-	ticker := time.NewTicker(cfg.PingInterval)
-	defer ticker.Stop()
+	pingTicker := time.NewTicker(cfg.PingInterval)
+	defer pingTicker.Stop()
+	renewTicker := time.NewTicker(cfg.RenewInterval)
+	defer renewTicker.Stop()
+	lastWall := time.Now()
+
 	for {
 		select {
 		case <-ctx.Done():
 			return nil
-		case <-ticker.C:
+		case <-pingTicker.C:
+			now := time.Now()
+			if IsWakeEvent(lastWall, now, cfg.PingInterval) {
+				attemptRenew(cfg)
+			}
+			lastWall = now
 			if err := pingOnce(conn, reader, cfg.PingInterval); err != nil {
 				if ctx.Err() != nil {
 					return ctx.Err()
@@ -146,6 +185,9 @@
 				log.Printf("heartbeat dropped relay=%s", host)
 				return err
 			}
+		case <-renewTicker.C:
+			lastWall = time.Now()
+			attemptRenew(cfg)
 		}
 	}
 }
```

```diff
--- a/internal/connect/connect_test.go
+++ b/internal/connect/connect_test.go
@@ -5,6 +5,7 @@
 	"context"
 	"crypto/tls"
 	"encoding/pem"
+	"fmt"
 	"io"
 	"net"
 	"path/filepath"
@@ -57,6 +58,45 @@
 		if got[i] != want[i] {
 			t.Fatalf("backoff[%d]=%s want %s (all=%v)", i, got[i], want[i], got)
 		}
+	}
+}
+
+func TestIsWakeEvent(t *testing.T) {
+	interval := 10 * time.Second
+	base := time.Unix(1_700_000_000, 0) // wall time, no monotonic
+	cases := []struct {
+		name string
+		last time.Time
+		now  time.Time
+		want bool
+	}{
+		{name: "zero last", last: time.Time{}, now: base, want: false},
+		{name: "same instant", last: base, now: base, want: false},
+		{name: "one interval", last: base, now: base.Add(interval), want: false},
+		{name: "exactly 2x", last: base, now: base.Add(2 * interval), want: false},
+		{name: "just over 2x", last: base, now: base.Add(2*interval + time.Nanosecond), want: true},
+		{name: "hours of sleep", last: base, now: base.Add(10 * time.Hour), want: true},
+	}
+	for _, tc := range cases {
+		t.Run(tc.name, func(t *testing.T) {
+			got := IsWakeEvent(tc.last, tc.now, interval)
+			if got != tc.want {
+				t.Fatalf("IsWakeEvent(%s, %s, %s)=%v want %v", tc.last, tc.now, interval, got, tc.want)
+			}
+		})
+	}
+	if IsWakeEvent(base, base.Add(time.Hour), 0) {
+		t.Fatal("zero interval must not be a wake")
+	}
+}
+
+func TestIsWakeEventUsesWallNotMonotonic(t *testing.T) {
+	interval := 10 * time.Second
+	last := time.Unix(1_000, 0)
+	now := time.Unix(1_000, 0).Add(time.Hour)
+	if !IsWakeEvent(last, now, interval) {
+		t.Fatal("wall-clock hour gap should be a wake even if constructed as Unix times")
+	}
 }
 
 func TestRunMissingCertDir(t *testing.T) {
@@ -131,6 +171,68 @@
 	}
 }
 
+func TestFailedRenewDoesNotBlockDial(t *testing.T) {
+	pki, err := mtls.GenerateTestPKI()
+	if err != nil {
+		t.Fatal(err)
+	}
+	dir := t.TempDir()
+	if err := writeEnrolled(dir, pki); err != nil {
+		t.Fatal(err)
+	}
+
+	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer ln.Close()
+
+	var pings atomic.Int32
+	gotTwo := make(chan struct{})
+	go servePings(ln, &pings, gotTwo)
+
+	var renews atomic.Int32
+	ctx, cancel := context.WithCancel(context.Background())
+	defer cancel()
+	errCh := make(chan error, 1)
+	go func() {
+		errCh <- Run(ctx, Config{
+			Relay:         ln.Addr().String(),
+			CertsDir:      dir,
+			EnrollURL:     "http://127.0.0.1:1",
+			PingInterval:  40 * time.Millisecond,
+			RenewInterval: time.Hour,
+			Renew: func(enrollURL, certDir string) error {
+				renews.Add(1)
+				return fmt.Errorf("forced renew failure")
+			},
+		})
+	}()
+
+	select {
+	case <-gotTwo:
+	case err := <-errCh:
+		t.Fatalf("connect exited before 2 PINGs: %v", err)
+	case <-time.After(3 * time.Second):
+		t.Fatalf("timed out waiting for 2 PINGs; saw %d", pings.Load())
+	}
+	cancel()
+	select {
+	case err := <-errCh:
+		if err != nil {
+			t.Fatalf("clean shutdown: %v", err)
+		}
+	case <-time.After(2 * time.Second):
+		t.Fatal("connect did not exit after cancel")
+	}
+	if renews.Load() < 1 {
+		t.Fatal("expected MaybeRenew to be attempted before dial")
+	}
+	if pings.Load() < 2 {
+		t.Fatalf("pings=%d want >= 2 (failed renew must not block dial)", pings.Load())
+	}
+}
+
 func servePings(ln net.Listener, pings *atomic.Int32, gotTwo chan struct{}) {
 	conn, err := ln.Accept()
 	if err != nil {
```

STOP.
