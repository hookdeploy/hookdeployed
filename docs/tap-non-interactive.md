# `tap` — non-interactive mode for GUI / subprocess supervision

**Repo:** `hookdeployed`
**Branch:** `feat/apt-install-sh`
**HEAD (unchanged):** `19b2e0b60f03c3d5d0a317aa208b8aee69793030`
**Mode:** implementation + this report. **No commit.**

**Date:** 2026-08-29

**Why:** `tap <endpoint-id> …` required a TTY and only stopped on Ctrl+C /
`signal.NotifyContext`. A tray app that redirects stdio cannot fake a console
cleanly, and Windows cannot deliver a POSIX SIGTERM to a child. This pass adds
an explicit headless mode whose graceful stop is **stdin EOF**, which works on
Windows and POSIX.

---

## PART 0 — read-only confirm (as found)

### 0.1 TTY check and wait / Ctrl+C (before this pass)

`NeedsTTY` and the create-time refusal (`internal/tap/tap.go`, pre-change):

```
NeedsTTY = "not a TTY; agent tap blocks until Ctrl+C. Run it in a terminal."
```

```
if !cfg.TTY {
    return fmt.Errorf("%s", NeedsTTY)
}
```

`cfg.TTY` is set in `runTapStart` from `enroll.RequireInteractiveFile(os.Stdin) == nil`
(`cmd/agent/main.go` 223). That is the same char-device check enroll/switch use
(`internal/enroll/run.go` 152–163: `info.Mode()&os.ModeCharDevice == 0`).

Wait + stop after create (pre-change):

```
fmt.Fprint(cfg.out(), FormatCreated(opts, created))
fmt.Fprintln(cfg.out(), ConnectHint)
fmt.Fprintln(cfg.out(), "Ctrl+C stops the tap.")

wait := cfg.Wait
if wait == nil {
    wait = func(waitCtx context.Context) error {
        <-waitCtx.Done()
        return nil
    }
}
_ = wait(ctx)
// then stopFn → "Stopped tap %s.\n" or failedStopError
```

Signal wiring is **not** in `tap.go`. It is in `runTapStart`
(`cmd/agent/main.go` 224–225, unchanged this pass):

```
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()
return tap.Start(ctx, tap.Config{ … }, opts)
```

The default wait only observed `ctx.Done()`. On a TTY, that is Ctrl+C
(`os.Interrupt`). There was no stdin-EOF path.

### 0.2 `connect` — the pattern to match (signals only)

`runConnect` (`cmd/agent/main.go` 112–114):

```
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()
return connect.Run(ctx, connect.Config{ … })
```

`connect.Run` returns `nil` when `ctx.Err() != nil` and closes the TLS conn on
`ctx.Done()` (`internal/connect/connect.go` 373–375, 482–489). `tap` already
used the **same** `NotifyContext` pair. This pass does **not** invent a second
signal mechanism. It keeps that ctx and adds stdin EOF as a **second** wait
wake-up for `-no-tty`, because signals are not a reliable parent→child stop on
Windows (0.3).

### 0.3 Windows signal delivery — what actually works

Cited from this machine’s Go toolchain (`go env GOROOT` = `C:\Program Files\Go`)
and `pkg.go.dev/os/signal`.

#### Receiving (child already running, user or OS)

Official `os/signal` Windows section:

> On Windows a ^C or ^BREAK normally cause the program to exit. If Notify is
> called for `os.Interrupt`, ^C or ^BREAK will cause `os.Interrupt` to be sent
> on the channel. **`os.Interrupt` is the only signal that can be used on
> Windows.**
>
> Additionally, if Notify is called, and Windows sends `CTRL_CLOSE_EVENT`,
> `CTRL_LOGOFF_EVENT` or `CTRL_SHUTDOWN_EVENT`, Notify will return
> `syscall.SIGTERM`. Unlike Control-C, those events still terminate the
> process; SIGTERM only gives a chance to clean up.

So `signal.NotifyContext(..., os.Interrupt, syscall.SIGTERM)` **does** fire in
a real console on Ctrl+C, and on logoff/shutdown it may see `SIGTERM` shortly
before the OS kills the process. That is **receive** path, not **parent send**.

#### Sending (parent wants child to stop gracefully)

`os.(*Process).signal` on Windows (`GOROOT/src/os/exec_windows.go` 55–78):

```
func (p *Process) signal(sig Signal) error {
    …
    if sig == Kill {
        // DuplicateHandle + TerminateProcess(..., 1)
        e = syscall.TerminateProcess(...)
        return NewSyscallError("TerminateProcess", e)
    }
    // TODO(rsc): Handle Interrupt too?
    return syscall.Errno(syscall.EWINDOWS)
}
```

**`Process.Signal(os.Interrupt)` and `Process.Signal(syscall.SIGTERM)` return
`EWINDOWS`.** They do not reach the child’s `NotifyContext`. The only
implemented send is `Kill` → `TerminateProcess`, which **does not run deferred
cleanup** and would skip the stop POST — the tap lingers server-side, same as
today’s `failedStopError` case.

Other Windows options, and why they lose for a GUI tray:

| Mechanism | Graceful? | Works for a GUI-spawned, no-console child? |
| --- | --- | --- |
| `os.Process.Signal(Interrupt)` / `SIGTERM` | would be | **No** — `EWINDOWS` |
| `GenerateConsoleCtrlEvent(CTRL_C/BREAK)` | yes, if the child has a console | **No** for `CREATE_NO_WINDOW` / redirected stdio. Also broadcasts to the console group and can kill the parent. |
| `taskkill` (no `/F`) | sometimes WM_CLOSE | Console child has no window. Unreliable. |
| `taskkill /F` / `Process.Kill` | no | Abrupt. Skip stop POST. |
| Job object `TerminateJobObject` | no | Same as Kill, tree-wide. |
| **Close the stdin pipe** | **yes** | **Yes.** Parent holds the write end; close it; child `Read`/`io.Copy` gets EOF. Identical on Windows, Linux, macOS. |

A tray that already redirects stdin (the whole point of “no hidden console”)
**already has** the pipe. Closing it is the natural stop.

### 0.4 Decision

**Trigger: explicit `-no-tty` flag, not auto-detect.**

The TTY check exists as a safety rail (`NeedsTTY` comment; `docs/taps-p3.md`:
a script must not leave a live tap with nobody watching). Auto-detect
(“stdin is not a TTY → allow create”) would turn `hookdeployed tap … < file`
or a long-lived pipe into an unattended tap. `-no-tty` is opt-in, same idea as
`unenroll -yes`. Accidental headless misuse still hits `NeedsTTY`.

**Stop: stdin EOF is the GUI trigger. Signals stay as they are.**

- `-no-tty` wait = `ctx.Done()` **or** stdin EOF (`waitUntilStop`).
- Interactive wait = `ctx.Done()` only (unchanged).
- `runTapStart` still uses the same `NotifyContext(Interrupt, SIGTERM)` as
  `connect`. On Linux/macOS a supervisor can SIGTERM. On Windows a supervisor
  **must close stdin** (or the user hits Ctrl+C if there is a console).
- `TerminateProcess` / `Kill` is documented as the wrong stop: it skips the
  stop POST.

No `-yes` flag. `tap` never prompted before create (`unenroll` is the only
confirm). This is TTY-requirement removal, not a confirmation skip.

---

## Implementation

| Piece | Behavior |
| --- | --- |
| `-no-tty` | Bool flag via `ParseStartFlags`. `assignFlagsAnywhere` now treats `IsBoolFlag()` values as `-name` ⇒ true so `-no-tty` does not steal the next token. |
| TTY check | `if !opts.NoTTY && !cfg.TTY { return NeedsTTY }` |
| Success stdout | Same `FormatCreated` + `ConnectHint`. Instructional line is `HeadlessHint` instead of `StopHint`. |
| Stop stdout / error | Same `Stopped tap %s.\n` and `failedStopError`. |
| Wait | `waitUntilStop`: `io.Copy(Discard, stdin)` in a goroutine; select vs `ctx.Done()`. |
| `main` | Passes `Stdin: os.Stdin`. Signal ctx unchanged. |

Supervisor recipe (Windows tray):

```
cmd := exec.Command("hookdeployed", "tap", endpointID, "-port", p, "-path", path, "-no-tty")
stdin, _ := cmd.StdinPipe()
cmd.Stdout = …  // parse "Tapping … → 127.0.0.1:…"
cmd.Start()
// later:
stdin.Close()   // graceful: stop POST runs
cmd.Wait()
```

Do **not** `cmd.Process.Kill()` if the stop POST must run.

---

## Message strings (shared vs different)

| Line | Interactive | `-no-tty` |
| --- | --- | --- |
| `Tapping %s / %s → 127.0.0.1:%d%s\nExpires %s\n` | `FormatCreated` | **same function** |
| `Deliveries land only while \`agent connect\` is running on this machine.` | `ConnectHint` | **same const** |
| Wait hint | `Ctrl+C stops the tap.` (`StopHint`) | `Closing stdin stops the tap.` (`HeadlessHint`) |
| `Stopped tap %s.\n` | same `Fprintf` | **same** |
| linger error | `failedStopError` | **same** |

A tray parser that keys on `Tapping ` / `Stopped tap ` does not special-case
modes. Only the instructional third line differs (and is not a parse target).

`-yes` was not added.

---

## Tests

`go test ./internal/tap/` on this Windows host: **ok** (0.828s). Existing
interactive tests (`TestNonTTYRefusesBeforeCreate`, `TestCtrlCCallsStop`,
`TestCreateSendsIdsPortPathAndToken`, parse-anywhere, etc.) still pass.

| New test | What it covers |
| --- | --- |
| `TestNoTTYStartsWithoutTTY` | `TTY: false` + `NoTTY: true` creates; stdout contains the same `FormatCreated` + `ConnectHint` + `Stopped tap …`; no `NeedsTTY` |
| `TestNoTTYStdinCloseStops` | default `Wait` (nil); `os.Pipe`; close write end; stop POST + `Stopped tap tap-eof.` |
| `TestParseStartFlagsNoTTY` | trailing `-no-tty`; `-no-tty` before positionals does not consume the UUID |

`TestNonTTYRefusesBeforeCreate` still refuses when `-no-tty` is off.

### What this environment did and did not test

This is Windows (`win32`). Stdin-close (the GUI stop) **was** tested here via
`os.Pipe` in `TestNoTTYStdinCloseStops`.

**Not tested (manual, if a human wants belt-and-suspenders):**

1. Real `hookdeployed.exe tap … -no-tty` spawned from a Win32 parent with
   `StdinPipe()` + `CREATE_NO_WINDOW`, then `Close()` — same mechanism as the
   unit test, but through `os/exec`.
2. POSIX `kill -TERM` on a `-no-tty` child (Linux/macOS). Code path is the
   existing `NotifyContext`; not exercised on this host as a cross-process
   SIGTERM.
3. `Process.Signal(os.Interrupt)` from a Go parent on Windows — expected to
   return `EWINDOWS` per `exec_windows.go`; **do not rely on it**.
4. `GenerateConsoleCtrlEvent` — out of scope; we did not implement it.

Human verify before shipping a tray: spawn with a held stdin pipe, confirm the
`Tapping` line, close the pipe, confirm `Stopped tap` and that the server tap
is actually ended (or run `tap list`).

---

## Full diff (source; uncommitted)

```
diff --git a/cmd/agent/main.go b/cmd/agent/main.go
index b1187af..99f1262 100644
--- a/cmd/agent/main.go
+++ b/cmd/agent/main.go
@@ -227,6 +227,7 @@ func runTapStart() error {
 		Root:      *dir,
 		EnrollURL: *enrollURL,
 		TTY:       tty,
+		Stdin:     os.Stdin,
 		Stdout:    os.Stdout,
 	}, opts)
 }
diff --git a/internal/tap/tap.go b/internal/tap/tap.go
index 8b2b1c3..4e2a9a3 100644
--- a/internal/tap/tap.go
+++ b/internal/tap/tap.go
@@ -20,17 +20,23 @@ const (
 	ListPath    = "/v1/agents/taps/list"
 	StopPath    = "/v1/agents/taps/stop"
 
-	// NeedsTTY is the non-TTY refusal for the blocking create command.
-	// Same discipline as switch and enroll: a script must not hold a tap
-	// open with nobody watching.
+	// NeedsTTY is the non-TTY refusal for the blocking create command
+	// when -no-tty is not set. Same discipline as switch and enroll:
+	// a script must not hold a tap open with nobody watching.
 	NeedsTTY = "not a TTY; agent tap blocks until Ctrl+C. Run it in a terminal."
 
 	// ConnectHint is printed after a tap is created. The CLI cannot see
 	// whether connect is running; deliveries are silent without it.
 	ConnectHint = "Deliveries land only while `agent connect` is running on this machine."
 
+	// StopHint is the interactive wait line. HeadlessHint is the -no-tty
+	// equivalent. Create/stop confirmation strings are shared; only this
+	// instructional line differs.
+	StopHint     = "Ctrl+C stops the tap."
+	HeadlessHint = "Closing stdin stops the tap."
+
 	Usage = `usage: agent tap list
-       agent tap <endpoint-id> [<destination-id>] -port PORT -path PATH [-duration DUR]
+       agent tap <endpoint-id> [<destination-id>] -port PORT -path PATH [-duration DUR] [-no-tty]
        agent tap stop [id]`
 
 	ErrNotUUID = "doesn't look like a valid id"
@@ -68,8 +74,13 @@ type Config struct {
 	EnrollURL string
 	TTY       bool
 	Stdout    io.Writer
-	Client    *enroll.Client
-	// Wait holds the blocking tap open. Tests replace it. Nil waits on ctx.
+	// Stdin is watched for EOF when StartOpts.NoTTY is set and Wait is
+	// nil. A supervising parent stops the tap by closing its write end.
+	// Production passes os.Stdin. Tests pass a pipe.
+	Stdin  io.Reader
+	Client *enroll.Client
+	// Wait holds the blocking tap open. Tests replace it. Nil waits on
+	// ctx, and also on stdin EOF when NoTTY is set.
 	Wait func(ctx context.Context) error
 	// Stop overrides Client stop (tests). Nil uses the real call.
 	Stop func(token, tapID string) error
@@ -260,6 +271,10 @@ type StartOpts struct {
 	Port          int
 	Path          string
 	Duration      time.Duration
+	// NoTTY skips the interactive-TTY requirement. The tap stays up
+	// until stdin hits EOF or the wait context is cancelled (SIGINT /
+	// SIGTERM on platforms that deliver them).
+	NoTTY bool
 }
 
 func Start(ctx context.Context, cfg Config, opts StartOpts) error {
@@ -285,7 +300,7 @@ func Start(ctx context.Context, cfg Config, opts StartOpts) error {
 			return err
 		}
 	}
-	if !cfg.TTY {
+	if !opts.NoTTY && !cfg.TTY {
 		return fmt.Errorf("%s", NeedsTTY)
 	}
 
@@ -308,13 +323,16 @@ func Start(ctx context.Context, cfg Config, opts StartOpts) error {
 
 	fmt.Fprint(cfg.out(), FormatCreated(opts, created))
 	fmt.Fprintln(cfg.out(), ConnectHint)
-	fmt.Fprintln(cfg.out(), "Ctrl+C stops the tap.")
+	if opts.NoTTY {
+		fmt.Fprintln(cfg.out(), HeadlessHint)
+	} else {
+		fmt.Fprintln(cfg.out(), StopHint)
+	}
 
 	wait := cfg.Wait
 	if wait == nil {
 		wait = func(waitCtx context.Context) error {
-			<-waitCtx.Done()
-			return nil
+			return waitUntilStop(waitCtx, opts.NoTTY, cfg.Stdin)
 		}
 	}
 	_ = wait(ctx)
@@ -346,10 +364,28 @@ func failedStopError(created Tap, err error) error {
 	return fmt.Errorf("could not stop tap %s: %s\nThe tap is still live and will linger until it expires (%s) or this agent disconnects.", created.ID, msg, expires)
 }
 
+func waitUntilStop(ctx context.Context, watchStdin bool, stdin io.Reader) error {
+	if !watchStdin || stdin == nil {
+		<-ctx.Done()
+		return nil
+	}
+	eof := make(chan struct{})
+	go func() {
+		defer close(eof)
+		_, _ = io.Copy(io.Discard, stdin)
+	}()
+	select {
+	case <-ctx.Done():
+	case <-eof:
+	}
+	return nil
+}
+
 func ParseStartFlags(fs *flag.FlagSet, args []string) (StartOpts, error) {
 	port := fs.Int("port", 0, "local port that receives the tapped delivery")
 	path := fs.String("path", "", "local path (must start with /)")
 	duration := fs.Duration("duration", 0, "how long the tap stays live (server clamps at 8h)")
+	noTTY := fs.Bool("no-tty", false, "run without a TTY; stop when stdin closes")
 	positionals, err := assignFlagsAnywhere(fs, args)
 	if err != nil {
 		return StartOpts{}, err
@@ -358,6 +394,7 @@ func ParseStartFlags(fs *flag.FlagSet, args []string) (StartOpts, error) {
 		Port:     *port,
 		Path:     *path,
 		Duration: *duration,
+		NoTTY:    *noTTY,
 	}
 	if len(positionals) >= 1 {
 		opts.EndpointID = positionals[0]
@@ -392,6 +429,12 @@ func assignFlagsAnywhere(fs *flag.FlagSet, args []string) (positionals []string,
 		if fs.Lookup(name) == nil {
 			return nil, fmt.Errorf("flag provided but not defined: -%s", name)
 		}
+		if isBoolFlag(fs, name) {
+			if err := fs.Set(name, "true"); err != nil {
+				return nil, err
+			}
+			continue
+		}
 		if i+1 >= len(args) {
 			return nil, fmt.Errorf("flag needs an argument: -%s", name)
 		}
@@ -402,3 +445,12 @@ func assignFlagsAnywhere(fs *flag.FlagSet, args []string) (positionals []string,
 	}
 	return positionals, nil
 }
+
+func isBoolFlag(fs *flag.FlagSet, name string) bool {
+	f := fs.Lookup(name)
+	if f == nil {
+		return false
+	}
+	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
+	return ok && bf.IsBoolFlag()
+}
```

`internal/tap/tap_test.go` adds `TestNoTTYStartsWithoutTTY`,
`TestNoTTYStdinCloseStops`, and `TestParseStartFlagsNoTTY` (see git working
tree). Not repeated here in full.

Untracked: this file (`docs/tap-non-interactive.md`).

---

Stopped. No commit.
