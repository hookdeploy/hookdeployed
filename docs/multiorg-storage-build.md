# Multi-org agent storage — build (pass 2 of 2)

**Repo:** `hookdeployed` only. **No deploy, no commit, no PR.**

| | |
| --- | --- |
| Branch | `feat/agent-browser-issued-enroll` |
| HEAD (unchanged) | `450f2f9de6899e3ee6f665acf8a0345f0bc5dd83` |
| Work | uncommitted on the working tree |

Enrollment inversion (pass 1) already ships: org is chosen in the browser; name comes back on poll. This pass is **storage and CLI only**.

One active org at a time. Simultaneous multi-org connections are out of scope.

**Caveat:** renewal of enrolled orgs only runs while `agent connect` is running. An org whose laptop never runs the agent will still lose its 30-day renewal token. Noted; not solved here.

---

## PART 0 — blast radius

### HEAD / status at start

`feat/agent-browser-issued-enroll` @ `450f2f9`. Clean of this work; pass 1 enroll + `org.json` already on the branch.

### Flat store today

`-certs` / `store.DefaultDir()` = `{UserConfigDir}/hookdeploy/certs` (or `HOOKDEPLOY_CERT_DIR`).

Files **inside** that directory:

| File | Mode | Role |
| --- | --- | --- |
| `ca.crt` | 0600 | HookDeploy root |
| `client.crt` | 0600 | leaf + intermediate |
| `client.key` | 0600 | private key |
| `renewal.token` | 0600 | rotating 30-day secret |
| `org.json` | 0644 | `{id,name,slug}` from pass 1 |

`system-info.json` lived **beside** the cert dir: `{UserConfigDir}/hookdeploy/system-info.json` (`sysinfo.StatePath` = `filepath.Dir(certsDir) + system-info.json`).

### Every `-certs` / store-path construction (complete list)

| Site | What it did |
| --- | --- |
| `cmd/agent/main.go` `runEnroll` | `-certs` default `store.DefaultDir()` → `RunToken` / `RunDevice` → `confirmStore` |
| `cmd/agent/main.go` `runConnect` | `-certs` → `connect.Config.CertsDir` |
| `cmd/agent/main.go` `runEcho` | `-certs` default `"certs"` → `mtls.LoadClientDir` / `MaybeRenew` (dev echo, **not** the production store) |
| `internal/enroll/run.go` `RunDevice` / `runDevice` | `WriteBundle(certDir)` + `WriteOrgMeta(certDir)` |
| `internal/enroll/run.go` `RunToken` | same write pair |
| `internal/enroll/run.go` `MaybeRenew` | `store.Load(certDir)`; reads `ca.crt` / `client.crt` in that dir; `WriteBundle` back |
| `internal/connect/connect.go` `Run` | `store.Load(cfg.CertsDir)` as “am I enrolled” |
| `internal/connect/connect.go` `attemptRenew` | `MaybeRenew(EnrollURL, CertsDir)` — **active only** |
| `internal/connect/connect.go` `attemptReport` | `MaybeReport(EnrollURL, CertsDir)` |
| `internal/connect/connect.go` `dialAndHeartbeat` | `store.Load(cfg.CertsDir)` |
| `internal/connect/connect.go` `settleRejection` | `store.ClearEnrollment(cfg.CertsDir)` + `sysinfo.ClearState(cfg.CertsDir)` — wiped the **whole** store |
| `internal/store/store.go` | `WriteBundle` / `Write` / `Load` / `ClearEnrollment` / `WriteOrgMeta` — operate on the dir they are given |
| `internal/mtls/client.go` | `LoadClientDir` / `WriteClientDir` — four files in `dir` |
| `internal/sysinfo/report.go` | `store.Load(certDir)` + `StatePath(certDir)` (sibling) |

### Call-site changes after this pass

| Site | After |
| --- | --- |
| `Run` / `dialAndHeartbeat` | `EnsureLayout` + `ResolveActiveDir` + `Load(orgDir)` |
| `attemptRenew` | `ListOrgDirs` → `MaybeRenew` **each** org dir; one failure does not stop the rest |
| `attemptReport` | **active org dir only** |
| `settleRejection` | `RemoveOrg(root, activeID)` only; clear `active`; other orgs survive |
| `RunDevice` / `RunToken` | `persistEnrollment` → `<root>/<org_id>/` + `WriteActive` |
| `confirmStore` | loads the active org dir |
| `runEcho` | unchanged (still a raw cert directory) |
| `MaybeRenew` | unchanged signature; callers now pass an **org dir** |
| `StatePath` | **inside** the org dir |

---

## PART 1 — layout

```
<store-root>/                  -certs, still the root
  active                       one line: active org id, 0644
  <org_id>/                    0700
    ca.crt client.crt client.key renewal.token    0600
    system-info.json           0644
    org.json                   0644  {"id","name","slug"}
```

`active` is read with `ReadActive` (trim, missing → empty). Written with `WriteActive` (`0644`, trailing newline). If `active` names a directory that is gone or not loadable, `ResolveActiveDir` **clears the pointer** and returns `ErrNotEnrolled`. Not fatal; `list` still shows remaining orgs.

### Migration

On first `EnsureLayout` of a flat store (`client.key` still at the root), or if `.migrating` is present:

1. Write `.migrating` **first**. `LooksEnrolled` is false whenever that file exists.
2. Read org id from `client.crt` OU (no guessing). Interrupted retries can also discover a single dest dir that already has a cert.
3. `mkdir <org_id>` `0700`.
4. **Move `client.key` first** — the root can no longer `Load`.
5. Move `client.crt`, `renewal.token`, `ca.crt`, `org.json`, `system-info.json`.
6. Move the **legacy sibling** `{parent}/system-info.json` into the org dir.
7. If `org.json` is missing (pre-pass-1 enrollments), write `{id: <ou>, name: "", slug: ""}`.
8. Write `active`, then remove `.migrating`.

**Interrupted-state guarantee.** `LooksEnrolled` requires: no `.migrating`, a readable `active`, and `Load(orgDir)` success. A half-moved store (key in dest, rest at root, marker present) does **not** look enrolled — root has no key, dest is incomplete, marker blocks the active check. `EnsureLayout` can finish the move on the next run.

### `org.json` for a migrated store

Id = cert OU. Name and slug are empty (`—` in `agent list`). Pass 1 never wrote names for those enrollments; we do not invent them.

### Permissions

| Path | Mode |
| --- | --- |
| credentials (`ca.crt`, `client.crt`, `client.key`, `renewal.token`) | **0600** (unchanged `WriteClientDir`) |
| `<org_id>/` | **0700** |
| store root | **0755** |
| `active`, `org.json`, `system-info.json`, `.migrating` | **0644** — not secret |

---

## PART 2 — operating on the active set

`connect` resolves the active org and loads that directory for the relay dial.

**Renew all.** On connect and on the 5-minute ticker (and wake-from-sleep), `attemptRenew` lists every org directory and calls `MaybeRenew` for each. Isolation: errors are logged `renew skipped/failed org=<id>: …` and the loop continues. Inactive orgs do **not** need a relay connection — renewal is a Worker HTTP call (`enroll.MaybeRenew`). Logging: `MaybeRenew` is silent when the leaf is before halfway; we only log a real renew (`renewed leaf not_after=…`) or a failure. Checking several orgs that are not due produces no noise.

**`attemptReport` is active-only.** Each org has a distinct agent id; reporting as an org you are not connected as would be wrong. Confirmed: `ResolveActiveDir` then `MaybeReport(enrollURL, activeOrgDir)`.

### Terminal rejection

Deletes **only** the revoked org’s directory (`ClearOrgDir` is still `client.key` first, then the other enrollment files, then `org.json` + `system-info.json`, then `RemoveAll`).

**Active-org-revoked decision: clear `active`, do not silently switch.** The user is told to `agent switch` or re-enroll. Switching them onto another org’s traffic without asking would be wrong.

Messages:

- No other orgs left: existing `RevokedUserMessage` (“Local credentials were removed. Run `agent enroll`…”).
- Others remain: `RevokedOrgMessage` — “this organization's credentials were removed. Other organizations are still enrolled. Run `agent switch` to pick one, or `agent enroll` to re-enroll this org.”

---

## PART 3 — CLI

```
agent list [-certs DIR]
agent switch [-certs DIR]                 # TTY: numbered picker
agent switch [-certs DIR] <name|slug|id>  # direct
```

### `list` format

Sorted by name, then id. Active marked `*`. Empty name/slug render as `—`.

```
  org-a  Alpha  alpha
* org-b  Beta   beta
```

### `switch` matching

Trim the query. A hit is: id equal (or case-fold), or `EqualFold` on name, or `EqualFold` on slug. If several hit, a **unique id hit wins**. Otherwise one hit wins; more than one is `ambiguous organization "Acme": id-1, id-2`. Zero hits: `no enrolled organization matches`.

### Non-TTY

No-argument `switch` prints the list and exits non-zero with `not a TTY; specify an organization: agent switch <name-or-slug-or-id>`. It does not read stdin. Confirmed by `TestRunSwitchNoArgNonTTYPrintsListAndErrors` (a dummy line in the reader is ignored; `active` is unchanged).

### `--org` on `connect`

**Recommend no.** `switch` then `connect` is sufficient. `--org` would bypass the `active` pointer and make `list` / the next unadorned `connect` disagree with what just ran. Scripting: `agent switch <id> && agent connect --relay …`.

### `enroll`

Writes into `<org_id>/` (id from poll, else leaf OU) and sets `active` to that org. **Re-enrolling an org already on disk replaces it in place** — same directory, overwrite bundle + `org.json`, set active. That is how a revoked org is recovered. It does not error.

---

## PART 4 — tests

```
go test ./...
?   	github.com/hookdeploy/hookdeployed/cmd/agent	[no test files]
?   	github.com/hookdeploy/hookdeployed/cmd/gencerts	[no test files]
?   	github.com/hookdeploy/hookdeployed/cmd/relay-stub	[no test files]
ok  	github.com/hookdeploy/hookdeployed/internal/connect	2.254s
ok  	github.com/hookdeploy/hookdeployed/internal/enroll	(cached)
ok  	github.com/hookdeploy/hookdeployed/internal/mtls	(cached)
ok  	github.com/hookdeploy/hookdeployed/internal/store	(cached)
ok  	github.com/hookdeploy/hookdeployed/internal/sysinfo	(cached)
?   	github.com/hookdeploy/hookdeployed/internal/version	[no test files]
```

Coverage vs the brief:

| # | Case | Test |
| --- | --- | --- |
| 19 | Flat → per-org, `active` set; interrupted does not look enrolled; retry finishes | `TestMigrateFlatStoreSetsActiveAndLooksEnrolled`, `TestInterruptedMigrationDoesNotLookEnrolled` |
| 20 | Stale `active` not fatal, pointer cleared | `TestStaleActiveIsNotFatal` |
| 21 | Renew-all: one org fails, the other is still called | `TestRenewAllContinuesAfterOneFailure` |
| 22 | Revoke removes only that org; others intact; active cleared | `TestRevokedRemovesOnlyThatOrgAndClearsActive` |
| 23 | Match / ambiguity / non-TTY | `TestMatchAndAmbiguity`, `TestRunSwitchDirectAndList`, `TestRunSwitchNoArgNonTTYPrintsListAndErrors`, `TestRunSwitchAmbiguous` |
| 24 | `list` output | `TestFormatListMarksActive` |
| 25 | Full suite + `GOOS=linux,darwin,windows` `go build ./cmd/agent` | all ok |

---

## Full diff

See the working tree. New files: `internal/store/layout.go`, `layout_test.go`, `switch.go`, `switch_test.go`. Modified: `cmd/agent/main.go`, `internal/connect/connect.go` + `_test.go`, `internal/enroll/run.go` + `_test.go`, `internal/store/store.go`, `internal/sysinfo/persist.go` + `sysinfo_test.go`.

Stat: 8 modified (+298/−55) plus the four new files.

No deploy. No commit. No PR.

---

### Patch (modified files)

```diff
diff --git a/cmd/agent/main.go b/cmd/agent/main.go
index 886385a..027b96a 100644
--- a/cmd/agent/main.go
+++ b/cmd/agent/main.go
@@ -37,6 +37,20 @@ func main() {
 		}
 		return
 	}
+	if len(os.Args) > 1 && os.Args[1] == "list" {
+		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
+		if err := runList(); err != nil {
+			log.Fatal(err)
+		}
+		return
+	}
+	if len(os.Args) > 1 && os.Args[1] == "switch" {
+		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
+		if err := runSwitch(); err != nil {
+			log.Fatal(err)
+		}
+		return
+	}
 	runEcho()
 }
 
@@ -82,8 +96,39 @@ func runConnect() error {
 	})
 }
 
+func runList() error {
+	fs := flag.NewFlagSet("list", flag.ExitOnError)
+	dir := fs.String("certs", store.DefaultDir(), "cert store directory")
+	if err := fs.Parse(os.Args[1:]); err != nil {
+		return err
+	}
+	orgs, err := store.List(*dir)
+	if err != nil {
+		return err
+	}
+	if len(orgs) == 0 {
+		return fmt.Errorf("no enrolled organizations G�� run `agent enroll`")
+	}
+	fmt.Print(store.FormatList(orgs))
+	return nil
+}
+
+func runSwitch() error {
+	fs := flag.NewFlagSet("switch", flag.ExitOnError)
+	dir := fs.String("certs", store.DefaultDir(), "cert store directory")
+	if err := fs.Parse(os.Args[1:]); err != nil {
+		return err
+	}
+	tty := enroll.RequireInteractiveFile(os.Stdin) == nil
+	return store.RunSwitch(*dir, fs.Args(), os.Stdin, os.Stdout, tty)
+}
+
 func confirmStore(dir string) error {
-	material, err := store.Load(dir)
+	orgDir, err := store.ResolveActiveDir(dir)
+	if err != nil {
+		return err
+	}
+	material, err := store.Load(orgDir)
 	if err != nil {
 		return err
 	}
@@ -92,10 +137,10 @@ func confirmStore(dir string) error {
 	if len(material.ClientCert.Subject.OrganizationalUnit) > 0 {
 		ou = material.ClientCert.Subject.OrganizationalUnit[0]
 	}
-	if meta, err := store.LoadOrgMeta(dir); err == nil && meta.Name != "" {
-		log.Printf("stored cert in %s org=%s CN=%s OU=%s", dir, meta.Name, cn, ou)
+	if meta, err := store.LoadOrgMeta(orgDir); err == nil && meta.Name != "" {
+		log.Printf("stored cert in %s org=%s CN=%s OU=%s", orgDir, meta.Name, cn, ou)
 	} else {
-		log.Printf("stored cert in %s CN=%s OU=%s", dir, cn, ou)
+		log.Printf("stored cert in %s CN=%s OU=%s", orgDir, cn, ou)
 	}
 	if cn == "" || ou == "" {
 		return fmt.Errorf("enrolled cert missing CN or OU G�� relay will reject")
diff --git a/internal/connect/connect.go b/internal/connect/connect.go
index 4c80ecf..7760a24 100644
--- a/internal/connect/connect.go
+++ b/internal/connect/connect.go
@@ -10,6 +10,7 @@ import (
 	"io"
 	"log"
 	"net"
+	"path/filepath"
 	"time"
 
 	"github.com/hookdeploy/hookdeployed/internal/enroll"
@@ -32,9 +33,13 @@ const (
 	drainRejectDeadline = 200 * time.Millisecond
 )
 
-// RevokedUserMessage is the jargon-free line logged on reason=revoked.
+// RevokedUserMessage is the jargon-free line logged on reason=revoked
+// when no other orgs remain enrolled.
 const RevokedUserMessage = "this agent was revoked and can no longer connect. Local credentials were removed. Run `agent enroll`, then `agent connect`."
 
+// RevokedOrgMessage is logged when the revoked org was one of several.
+const RevokedOrgMessage = "this organization's credentials were removed. Other organizations are still enrolled. Run `agent switch` to pick one, or `agent enroll` to re-enroll this org."
+
 // Rejection is a terminal serverG��agent frame. Reason "revoked" deletes
 // credentials; any other reason stops retry without deleting.
 type Rejection struct {
@@ -101,8 +106,21 @@ func attemptRenew(cfg Config) {
 	if fn == nil {
 		fn = enroll.MaybeRenew
 	}
-	if err := fn(cfg.EnrollURL, cfg.CertsDir); err != nil {
+	dirs, err := store.ListOrgDirs(cfg.CertsDir)
+	if err != nil {
 		log.Printf("renew skipped/failed: %v", err)
+		return
+	}
+	if len(dirs) == 0 {
+		if err := fn(cfg.EnrollURL, cfg.CertsDir); err != nil {
+			log.Printf("renew skipped/failed: %v", err)
+		}
+		return
+	}
+	for _, dir := range dirs {
+		if err := fn(cfg.EnrollURL, dir); err != nil {
+			log.Printf("renew skipped/failed org=%s: %v", filepath.Base(dir), err)
+		}
 	}
 }
 
@@ -111,7 +129,11 @@ func attemptReport(cfg Config) {
 	if fn == nil {
 		fn = sysinfo.MaybeReport
 	}
-	if err := fn(cfg.EnrollURL, cfg.CertsDir); err != nil {
+	dir, err := store.ResolveActiveDir(cfg.CertsDir)
+	if err != nil {
+		return
+	}
+	if err := fn(cfg.EnrollURL, dir); err != nil {
 		// Non-fatal. Do not log cfg contents G�� the token lives in the cert dir.
 		log.Printf("system-info report failed: %v", err)
 	}
@@ -129,7 +151,7 @@ func Run(ctx context.Context, cfg Config) error {
 		return err
 	}
 
-	if _, err := store.Load(cfg.CertsDir); err != nil {
+	if _, err := store.ResolveActiveDir(cfg.CertsDir); err != nil {
 		return fmt.Errorf("no enrolled cert in %s G�� run `agent enroll` first", cfg.CertsDir)
 	}
 
@@ -166,7 +188,11 @@ func Run(ctx context.Context, cfg Config) error {
 }
 
 func dialAndHeartbeat(ctx context.Context, cfg Config, host, addr string) error {
-	material, err := store.Load(cfg.CertsDir)
+	orgDir, err := store.ResolveActiveDir(cfg.CertsDir)
+	if err != nil {
+		return fmt.Errorf("reload certs: %w", err)
+	}
+	material, err := store.Load(orgDir)
 	if err != nil {
 		return fmt.Errorf("reload certs: %w", err)
 	}
@@ -298,12 +324,36 @@ func parseReject(line string) (reason string, ok bool) {
 
 func settleRejection(ctx context.Context, cfg Config, rej Rejection) error {
 	if rej.Reason == "revoked" {
-		log.Print(RevokedUserMessage)
-		if err := store.ClearEnrollment(cfg.CertsDir); err != nil {
-			log.Printf("could not finish removing credentials: %v", err)
+		orgID, _ := store.ReadActive(cfg.CertsDir)
+		if orgID == "" {
+			if dir, err := store.ResolveActiveDir(cfg.CertsDir); err == nil {
+				orgID = filepath.Base(dir)
+			}
+		}
+		others := 0
+		if orgs, err := store.List(cfg.CertsDir); err == nil {
+			for _, o := range orgs {
+				if filepath.Base(o.Dir) != orgID && o.ID != orgID {
+					others++
+				}
+			}
+		}
+		if orgID != "" {
+			if err := store.RemoveOrg(cfg.CertsDir, orgID); err != nil {
+				log.Printf("could not finish removing credentials: %v", err)
+			}
+		} else {
+			if err := store.ClearEnrollment(cfg.CertsDir); err != nil {
+				log.Printf("could not finish removing credentials: %v", err)
+			}
+			if err := sysinfo.ClearState(cfg.CertsDir); err != nil {
+				log.Printf("could not clear system-info state: %v", err)
+			}
 		}
-		if err := sysinfo.ClearState(cfg.CertsDir); err != nil {
-			log.Printf("could not clear system-info state: %v", err)
+		if others > 0 {
+			log.Print(RevokedOrgMessage)
+		} else {
+			log.Print(RevokedUserMessage)
 		}
 	} else {
 		log.Printf("this connection was ended (%s). Not retrying. Credentials were kept.", rej.Reason)
diff --git a/internal/connect/connect_test.go b/internal/connect/connect_test.go
index d5fe77c..75ff47b 100644
--- a/internal/connect/connect_test.go
+++ b/internal/connect/connect_test.go
@@ -441,18 +441,16 @@ func TestRevokedDeletesFilesLogsAndStopsRetrying(t *testing.T) {
 	}()
 
 	waitUntil(t, 3*time.Second, func() bool {
-		_, err := store.Load(dir)
-		return err != nil
+		return strings.Contains(logs.String(), RevokedUserMessage)
 	})
-	if !strings.Contains(logs.String(), RevokedUserMessage) {
-		t.Fatalf("missing user message:\n%s", logs.String())
+	if store.LooksEnrolled(dir) {
+		t.Fatal("store still looks enrolled after revoke")
 	}
-	for _, name := range store.EnrollmentFiles {
-		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
-			t.Fatalf("%s still present", name)
-		}
+	orgDir := store.OrgDir(dir, mtls.TestClientOU)
+	if _, err := os.Stat(orgDir); !os.IsNotExist(err) {
+		t.Fatal("revoked org dir still present")
 	}
-	if _, err := os.Stat(sysinfo.StatePath(dir)); !os.IsNotExist(err) {
+	if _, err := os.Stat(sysinfo.StatePath(orgDir)); !os.IsNotExist(err) {
 		t.Fatal("system-info.json still present")
 	}
 	time.Sleep(150 * time.Millisecond)
@@ -483,6 +481,139 @@ func TestRevokedDeletesFilesLogsAndStopsRetrying(t *testing.T) {
 	}
 }
 
+func TestRenewAllContinuesAfterOneFailure(t *testing.T) {
+	pki, err := mtls.GenerateTestPKI()
+	if err != nil {
+		t.Fatal(err)
+	}
+	root := t.TempDir()
+	if err := writeEnrolled(store.OrgDir(root, "org-ok"), pki); err != nil {
+		t.Fatal(err)
+	}
+	if err := writeEnrolled(store.OrgDir(root, "org-bad"), pki); err != nil {
+		t.Fatal(err)
+	}
+	if err := store.WriteActive(root, "org-ok"); err != nil {
+		t.Fatal(err)
+	}
+
+	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer ln.Close()
+	var pings atomic.Int32
+	gotTwo := make(chan struct{})
+	go servePings(ln, &pings, gotTwo)
+
+	var mu sync.Mutex
+	seen := map[string]int{}
+	ctx, cancel := context.WithCancel(context.Background())
+	defer cancel()
+	errCh := make(chan error, 1)
+	go func() {
+		errCh <- Run(ctx, Config{
+			Relay:         ln.Addr().String(),
+			CertsDir:      root,
+			EnrollURL:     "http://127.0.0.1:1",
+			PingInterval:  40 * time.Millisecond,
+			RenewInterval: time.Hour,
+			Renew: func(enrollURL, certDir string) error {
+				mu.Lock()
+				seen[filepath.Base(certDir)]++
+				mu.Unlock()
+				if filepath.Base(certDir) == "org-bad" {
+					return fmt.Errorf("forced org-bad failure")
+				}
+				return nil
+			},
+		})
+	}()
+
+	select {
+	case <-gotTwo:
+	case err := <-errCh:
+		t.Fatalf("connect exited: %v", err)
+	case <-time.After(3 * time.Second):
+		t.Fatal("timed out")
+	}
+	cancel()
+	<-errCh
+	mu.Lock()
+	defer mu.Unlock()
+	if seen["org-ok"] < 1 || seen["org-bad"] < 1 {
+		t.Fatalf("renew calls=%v; both orgs must be attempted", seen)
+	}
+}
+
+func TestRevokedRemovesOnlyThatOrgAndClearsActive(t *testing.T) {
+	pki, err := mtls.GenerateTestPKI()
+	if err != nil {
+		t.Fatal(err)
+	}
+	root := t.TempDir()
+	if err := writeEnrolled(store.OrgDir(root, "org-a"), pki); err != nil {
+		t.Fatal(err)
+	}
+	if err := writeEnrolled(store.OrgDir(root, "org-b"), pki); err != nil {
+		t.Fatal(err)
+	}
+	if err := store.WriteActive(root, "org-a"); err != nil {
+		t.Fatal(err)
+	}
+
+	ln, err := tls.Listen("tcp", "127.0.0.1:0", pki.ServerTLSConfig())
+	if err != nil {
+		t.Fatal(err)
+	}
+	defer ln.Close()
+	var accepts atomic.Int32
+	go serveFrames(ln, `{"type":"reject","reason":"revoked"}`+"\n", &accepts)
+
+	var logs bytes.Buffer
+	log.SetOutput(&logs)
+	defer log.SetOutput(os.Stderr)
+
+	ctx, cancel := context.WithCancel(context.Background())
+	defer cancel()
+	errCh := make(chan error, 1)
+	go func() {
+		errCh <- Run(ctx, Config{
+			Relay:        ln.Addr().String(),
+			CertsDir:     root,
+			EnrollURL:    "http://127.0.0.1:1",
+			PingInterval: 40 * time.Millisecond,
+		})
+	}()
+
+	waitUntil(t, 3*time.Second, func() bool {
+		_, err := os.Stat(store.OrgDir(root, "org-a"))
+		return os.IsNotExist(err)
+	})
+	if !strings.Contains(logs.String(), RevokedOrgMessage) {
+		t.Fatalf("missing remaining-orgs message:\n%s", logs.String())
+	}
+	if strings.Contains(logs.String(), RevokedUserMessage) {
+		t.Fatalf("must not claim wholly unenrolled:\n%s", logs.String())
+	}
+	if _, err := store.Load(store.OrgDir(root, "org-b")); err != nil {
+		t.Fatalf("other org must survive: %v", err)
+	}
+	active, err := store.ReadActive(root)
+	if err != nil || active != "" {
+		t.Fatalf("active should be cleared, got %q err=%v", active, err)
+	}
+	cancel()
+	select {
+	case err := <-errCh:
+		if err != nil {
+			t.Fatalf("dormant cancel: %v", err)
+		}
+	case <-time.After(2 * time.Second):
+		t.Fatal("Run did not return")
+	}
+}
+
 func TestUnknownReasonIsTerminalWithoutDelete(t *testing.T) {
 	pki, err := mtls.GenerateTestPKI()
 	if err != nil {
@@ -518,8 +649,10 @@ func TestUnknownReasonIsTerminalWithoutDelete(t *testing.T) {
 	waitUntil(t, 3*time.Second, func() bool {
 		return strings.Contains(logs.String(), "Credentials were kept")
 	})
-	if _, err := store.Load(dir); err != nil {
-		t.Fatalf("unknown reason must keep credentials: %v", err)
+	if !store.LooksEnrolled(dir) {
+		if _, err := store.ResolveActiveDir(dir); err != nil {
+			t.Fatalf("unknown reason must keep credentials: %v", err)
+		}
 	}
 	time.Sleep(150 * time.Millisecond)
 	if accepts.Load() != 1 {
@@ -567,8 +700,8 @@ func TestUnknownTypeStillRetries(t *testing.T) {
 	}()
 
 	waitUntil(t, 3*time.Second, func() bool { return accepts.Load() >= 2 })
-	if _, err := store.Load(dir); err != nil {
-		t.Fatalf("unknown type must not delete: %v", err)
+	if !store.LooksEnrolled(dir) {
+		t.Fatal("unknown type must not delete")
 	}
 	cancel()
 	select {
diff --git a/internal/enroll/run.go b/internal/enroll/run.go
index 2f4836c..dc8ed8c 100644
--- a/internal/enroll/run.go
+++ b/internal/enroll/run.go
@@ -116,11 +116,8 @@ func runDevice(baseURL, certDir string, io deviceIO) error {
 				agentID = poll.AgentID
 				continue
 			}
-			if err := store.WriteBundle(certDir, []byte(poll.Root), []byte(poll.CertChain), []byte(poll.Certificate), []byte(poll.CA), keyPEM, []byte(poll.RenewalToken)); err != nil {
-				return err
-			}
 			orgName := firstNonEmpty(poll.OrgName, poll.Minted.OrgName)
-			if err := store.WriteOrgMeta(certDir, store.OrgMeta{
+			if err := persistEnrollment(certDir, []byte(poll.Root), []byte(poll.CertChain), []byte(poll.Certificate), []byte(poll.CA), keyPEM, []byte(poll.RenewalToken), store.OrgMeta{
 				ID:   firstNonEmpty(poll.OrgID, poll.Minted.OrgID),
 				Name: orgName,
 				Slug: firstNonEmpty(poll.OrgSlug, poll.Minted.OrgSlug),
@@ -218,16 +215,35 @@ func RunToken(baseURL, token, certDir string) error {
 	if err != nil {
 		return err
 	}
-	if err := store.WriteBundle(certDir, []byte(out.Root), []byte(out.CertChain), []byte(out.Certificate), []byte(out.CA), keyPEM, []byte(out.RenewalToken)); err != nil {
-		return err
-	}
-	return store.WriteOrgMeta(certDir, store.OrgMeta{
+	return persistEnrollment(certDir, []byte(out.Root), []byte(out.CertChain), []byte(out.Certificate), []byte(out.CA), keyPEM, []byte(out.RenewalToken), store.OrgMeta{
 		ID:   out.OrgID,
 		Name: out.OrgName,
 		Slug: out.OrgSlug,
 	})
 }
 
+func persistEnrollment(root string, rootPEM, certChain, leafPEM, intermediatePEM, keyPEM, renewalToken []byte, meta store.OrgMeta) error {
+	if strings.TrimSpace(meta.ID) == "" {
+		if id, err := store.OrgIDFromCertPEM(leafPEM); err == nil {
+			meta.ID = id
+		}
+	}
+	if strings.TrimSpace(meta.ID) == "" {
+		return fmt.Errorf("enrollment missing org id")
+	}
+	if err := store.EnsureLayout(root); err != nil {
+		return err
+	}
+	orgDir := store.OrgDir(root, meta.ID)
+	if err := store.WriteBundle(orgDir, rootPEM, certChain, leafPEM, intermediatePEM, keyPEM, renewalToken); err != nil {
+		return err
+	}
+	if err := store.WriteOrgMeta(orgDir, meta); err != nil {
+		return err
+	}
+	return store.WriteActive(root, meta.ID)
+}
+
 func localHostname() string {
 	host, err := os.Hostname()
 	if err != nil {
diff --git a/internal/enroll/run_test.go b/internal/enroll/run_test.go
index d7bf596..28c5672 100644
--- a/internal/enroll/run_test.go
+++ b/internal/enroll/run_test.go
@@ -332,11 +332,19 @@ func TestRunDevicePrintsURLStoresOrgNameAndSucceeds(t *testing.T) {
 	if opened != "https://app.hookdeploy.dev/app/cli-auth/s1" {
 		t.Fatalf("opened=%q", opened)
 	}
-	meta, err := store.LoadOrgMeta(dir)
+	orgDir := store.OrgDir(dir, "org-1")
+	meta, err := store.LoadOrgMeta(orgDir)
 	if err != nil {
 		t.Fatal(err)
 	}
 	if meta.Name != "Acme Corp" || meta.ID != "org-1" {
 		t.Fatalf("meta=%#v", meta)
 	}
+	if _, err := store.Load(orgDir); err != nil {
+		t.Fatalf("org dir: %v", err)
+	}
+	active, err := store.ReadActive(dir)
+	if err != nil || active != "org-1" {
+		t.Fatalf("active=%q err=%v", active, err)
+	}
 }
diff --git a/internal/store/store.go b/internal/store/store.go
index dd63d54..ea052c4 100644
--- a/internal/store/store.go
+++ b/internal/store/store.go
@@ -11,9 +11,8 @@ import (
 
 const OrgMetaFile = "org.json"
 
-// OrgMeta is the display name of the org this store is enrolled into.
-// Not secret G�� 0644, beside the 0600 cert files. Pass 2 will relocate
-// the whole directory per org.
+// OrgMeta is the display name of the org one per-org directory is enrolled into.
+// Not secret G�� 0644, beside the 0600 cert files.
 type OrgMeta struct {
 	ID   string `json:"id"`
 	Name string `json:"name"`
diff --git a/internal/sysinfo/persist.go b/internal/sysinfo/persist.go
index 517c81b..6ae2591 100644
--- a/internal/sysinfo/persist.go
+++ b/internal/sysinfo/persist.go
@@ -18,14 +18,10 @@ type snapshot struct {
 	LastAttemptUnix int64  `json:"last_attempt_unix,omitempty"`
 }
 
-// StatePath is the non-secret change-detection file. It lives next to the
-// cert directory, not inside it: the cert store is 0700/0600 PKI material
-// (ca.crt, client.crt, client.key, renewal.token). Default layout:
-//
-//	{UserConfigDir}/hookdeploy/certs          G�� cert store
-//	{UserConfigDir}/hookdeploy/system-info.json
+// StatePath is the non-secret change-detection file. It lives inside the
+// per-org directory next to org.json (0644), not beside the store root.
 func StatePath(certsDir string) string {
-	return filepath.Join(filepath.Dir(certsDir), "system-info.json")
+	return filepath.Join(certsDir, "system-info.json")
 }
 
 // ClearState removes the change-detection file. Missing is not an error.
diff --git a/internal/sysinfo/sysinfo_test.go b/internal/sysinfo/sysinfo_test.go
index 7abcb54..bcce255 100644
--- a/internal/sysinfo/sysinfo_test.go
+++ b/internal/sysinfo/sysinfo_test.go
@@ -4,7 +4,6 @@ import (
 	"os"
 	"path/filepath"
 	"runtime"
-	"strings"
 	"testing"
 	"time"
 
@@ -97,7 +96,7 @@ func TestCollectSane(t *testing.T) {
 	}
 }
 
-func TestClearStateRemovesSiblingFile(t *testing.T) {
+func TestClearStateRemovesFileInOrgDir(t *testing.T) {
 	certs := filepath.Join(t.TempDir(), "certs")
 	if err := os.MkdirAll(certs, 0o700); err != nil {
 		t.Fatal(err)
@@ -117,17 +116,14 @@ func TestClearStateRemovesSiblingFile(t *testing.T) {
 	}
 }
 
-func TestStatePathOutsideCertStore(t *testing.T) {
-	certs := filepath.Join(t.TempDir(), "hookdeploy", "certs")
+func TestStatePathInsideOrgDir(t *testing.T) {
+	certs := filepath.Join(t.TempDir(), "hookdeploy", "certs", "org-1")
 	got := StatePath(certs)
 	if filepath.Base(got) != "system-info.json" {
 		t.Fatalf("base=%q", got)
 	}
-	if filepath.Dir(got) != filepath.Dir(certs) {
-		t.Fatalf("state=%q should be sibling of certs=%q", got, certs)
-	}
-	if strings.Contains(got, string(filepath.Separator)+"certs"+string(filepath.Separator)) {
-		t.Fatalf("state must not live inside the cert store: %q", got)
+	if filepath.Dir(got) != certs {
+		t.Fatalf("state=%q should live inside org dir=%q", got, certs)
 	}
 }
 
```

### New file `internal/store/layout.go`

```go
package store

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	ActiveFile     = "active"
	MigratingFile  = ".migrating"
	SystemInfoFile = "system-info.json"
)

// ErrNotEnrolled means the store has no usable active org.
var ErrNotEnrolled = errors.New("no enrolled organization")

// Enrollment is one per-org directory under the store root.
type Enrollment struct {
	ID     string
	Name   string
	Slug   string
	Dir    string
	Active bool
}

func OrgDir(root, orgID string) string {
	return filepath.Join(root, orgID)
}

func ActivePath(root string) string {
	return filepath.Join(root, ActiveFile)
}

func migratingPath(root string) string {
	return filepath.Join(root, MigratingFile)
}

func HasMigrating(root string) bool {
	_, err := os.Stat(migratingPath(root))
	return err == nil
}

func IsFlatStore(root string) bool {
	_, err := os.Stat(filepath.Join(root, "client.key"))
	return err == nil
}

// LooksEnrolled reports a usable active org. A half-migrated store
// (.migrating present) is never enrolled, even if files already sit
// under <org_id>/. Does not repair the layout.
func LooksEnrolled(root string) bool {
	if HasMigrating(root) {
		return false
	}
	id, err := ReadActive(root)
	if err != nil || id == "" {
		return false
	}
	_, err = Load(OrgDir(root, id))
	return err == nil
}

func ReadActive(root string) (string, error) {
	raw, err := os.ReadFile(ActivePath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func WriteActive(root, orgID string) error {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return fmt.Errorf("active org id is empty")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	return os.WriteFile(ActivePath(root), []byte(orgID+"\n"), 0o644)
}

func ClearActive(root string) error {
	err := os.Remove(ActivePath(root))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// EnsureLayout migrates a flat store into <org_id>/ and writes active.
// Already-migrated stores are a no-op. A missing root is a no-op.
func EnsureLayout(root string) error {
	if HasMigrating(root) || IsFlatStore(root) {
		return migrateFlat(root)
	}
	return nil
}

func migrateFlat(root string) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(migratingPath(root), []byte("1\n"), 0o644); err != nil {
		return err
	}

	orgID, err := discoverMigrationOrgID(root)
	if err != nil {
		return err
	}
	dest := OrgDir(root, orgID)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}

	// client.key first: the root immediately stops looking enrolled.
	if err := moveIfExists(filepath.Join(root, "client.key"), filepath.Join(dest, "client.key")); err != nil {
		return err
	}
	for _, name := range []string{"client.crt", "renewal.token", "ca.crt", OrgMetaFile, SystemInfoFile} {
		if err := moveIfExists(filepath.Join(root, name), filepath.Join(dest, name)); err != nil {
			return err
		}
	}
	legacy := filepath.Join(filepath.Dir(root), SystemInfoFile)
	if err := moveIfExists(legacy, filepath.Join(dest, SystemInfoFile)); err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Join(dest, OrgMetaFile)); os.IsNotExist(err) {
		if err := WriteOrgMeta(dest, OrgMeta{ID: orgID}); err != nil {
			return err
		}
	}

	if err := WriteActive(root, orgID); err != nil {
		return err
	}
	return os.Remove(migratingPath(root))
}

func discoverMigrationOrgID(root string) (string, error) {
	if id, err := orgIDFromCertFile(filepath.Join(root, "client.crt")); err == nil && id != "" {
		return id, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("migrate store: cannot read org id: %w", err)
	}
	var found string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		id, idErr := orgIDFromCertFile(filepath.Join(root, e.Name(), "client.crt"))
		if idErr != nil || id == "" {
			continue
		}
		if found != "" && found != id {
			return "", fmt.Errorf("migrate store: interrupted and ambiguous org directories")
		}
		found = id
	}
	if found == "" {
		return "", fmt.Errorf("migrate store: client cert has no OU")
	}
	return found, nil
}

func orgIDFromCertFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return OrgIDFromCertPEM(raw)
}

// OrgIDFromCertPEM reads the leaf OU (organization id).
func OrgIDFromCertPEM(pemBytes []byte) (string, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		if len(cert.Subject.OrganizationalUnit) == 0 {
			return "", fmt.Errorf("client cert has no OU")
		}
		id := strings.TrimSpace(cert.Subject.OrganizationalUnit[0])
		if id == "" {
			return "", fmt.Errorf("client cert has no OU")
		}
		return id, nil
	}
	return "", fmt.Errorf("client cert has no OU")
}

func moveIfExists(src, dest string) error {
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.Rename(src, dest); err == nil {
		return nil
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, raw, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Remove(src)
}

// ResolveActiveDir runs EnsureLayout, then returns the active org directory.
// A stale active pointer (directory gone) is cleared and treated as not enrolled.
func ResolveActiveDir(root string) (string, error) {
	if err := EnsureLayout(root); err != nil {
		return "", err
	}
	if HasMigrating(root) {
		return "", ErrNotEnrolled
	}
	id, err := ReadActive(root)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", ErrNotEnrolled
	}
	dir := OrgDir(root, id)
	if _, err := Load(dir); err != nil {
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			_ = ClearActive(root)
		}
		return "", ErrNotEnrolled
	}
	return dir, nil
}

func ListOrgDirs(root string) ([]string, error) {
	orgs, err := List(root)
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(orgs))
	for _, o := range orgs {
		dirs = append(dirs, o.Dir)
	}
	return dirs, nil
}

func List(root string) ([]Enrollment, error) {
	if err := EnsureLayout(root); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	active, _ := ReadActive(root)
	var out []Enrollment
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		dir := OrgDir(root, e.Name())
		if _, err := Load(dir); err != nil {
			continue
		}
		meta, _ := LoadOrgMeta(dir)
		id := e.Name()
		if meta.ID != "" {
			id = meta.ID
		}
		out = append(out, Enrollment{
			ID:     id,
			Name:   meta.Name,
			Slug:   meta.Slug,
			Dir:    dir,
			Active: active == e.Name() || active == id,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ClearOrgDir deletes enrollment files key-first, then org.json and
// system-info.json. Missing names are ignored.
func ClearOrgDir(dir string) error {
	var first error
	for _, name := range EnrollmentFiles {
		err := os.Remove(filepath.Join(dir, name))
		if err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	for _, name := range []string{OrgMetaFile, SystemInfoFile} {
		err := os.Remove(filepath.Join(dir, name))
		if err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}

// RemoveOrg wipes one org directory (key first) and removes the folder.
// If it was active, active is cleared — we do not silently switch.
func RemoveOrg(root, orgID string) error {
	dir := OrgDir(root, orgID)
	first := ClearOrgDir(dir)
	if err := os.RemoveAll(dir); err != nil && first == nil {
		first = err
	}
	active, _ := ReadActive(root)
	if active == orgID {
		if err := ClearActive(root); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func FormatList(orgs []Enrollment) string {
	var b strings.Builder
	for _, o := range orgs {
		mark := " "
		if o.Active {
			mark = "*"
		}
		name := o.Name
		if strings.TrimSpace(name) == "" {
			name = "—"
		}
		slug := o.Slug
		if strings.TrimSpace(slug) == "" {
			slug = "—"
		}
		fmt.Fprintf(&b, "%s %s  %s  %s\n", mark, o.ID, name, slug)
	}
	return b.String()
}

func Match(orgs []Enrollment, query string) (Enrollment, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return Enrollment{}, fmt.Errorf("organization is required")
	}
	var hits []Enrollment
	for _, o := range orgs {
		if o.ID == q || strings.EqualFold(o.ID, q) || strings.EqualFold(o.Name, q) || strings.EqualFold(o.Slug, q) {
			hits = append(hits, o)
		}
	}
	if len(hits) == 0 {
		return Enrollment{}, fmt.Errorf("no enrolled organization matches %q", q)
	}
	var idHits []Enrollment
	for _, o := range hits {
		if o.ID == q || strings.EqualFold(o.ID, q) {
			idHits = append(idHits, o)
		}
	}
	if len(idHits) == 1 {
		return idHits[0], nil
	}
	if len(hits) == 1 {
		return hits[0], nil
	}
	ids := make([]string, 0, len(hits))
	for _, o := range hits {
		ids = append(ids, o.ID)
	}
	return Enrollment{}, fmt.Errorf("ambiguous organization %q: %s", q, strings.Join(ids, ", "))
}

func SwitchTo(root, query string) (Enrollment, error) {
	orgs, err := List(root)
	if err != nil {
		return Enrollment{}, err
	}
	if len(orgs) == 0 {
		return Enrollment{}, fmt.Errorf("no enrolled organizations — run `agent enroll`")
	}
	got, err := Match(orgs, query)
	if err != nil {
		return Enrollment{}, err
	}
	if err := WriteActive(root, filepath.Base(got.Dir)); err != nil {
		return Enrollment{}, err
	}
	got.Active = true
	return got, nil
}
```

### New file `internal/store/layout_test.go`

```go
package store

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

func writeFlat(t *testing.T, root string) {
	t.Helper()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(root, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateFlatStoreSetsActiveAndLooksEnrolled(t *testing.T) {
	root := t.TempDir()
	writeFlat(t, root)
	legacy := filepath.Join(filepath.Dir(root), SystemInfoFile)
	if err := os.WriteFile(legacy, []byte(`{"agent_id":"old"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := EnsureLayout(root); err != nil {
		t.Fatal(err)
	}
	if IsFlatStore(root) {
		t.Fatal("root still looks flat")
	}
	if HasMigrating(root) {
		t.Fatal(".migrating should be gone")
	}
	active, err := ReadActive(root)
	if err != nil {
		t.Fatal(err)
	}
	if active != mtls.TestClientOU {
		t.Fatalf("active=%q want %q", active, mtls.TestClientOU)
	}
	if !LooksEnrolled(root) {
		t.Fatal("migrated store should look enrolled")
	}
	dir := OrgDir(root, active)
	if _, err := Load(dir); err != nil {
		t.Fatalf("load org dir: %v", err)
	}
	meta, err := LoadOrgMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ID != mtls.TestClientOU {
		t.Fatalf("org.json id=%q", meta.ID)
	}
	if meta.Name != "" || meta.Slug != "" {
		t.Fatalf("migrated org.json should have id only, got %#v", meta)
	}
	if _, err := os.Stat(filepath.Join(dir, SystemInfoFile)); err != nil {
		t.Fatalf("legacy system-info should move into org dir: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy sibling system-info.json still present")
	}
	info, err := os.Stat(ActivePath(root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o400 == 0 {
		t.Fatalf("active missing read bit: %o", info.Mode().Perm())
	}
}

func TestInterruptedMigrationDoesNotLookEnrolled(t *testing.T) {
	root := t.TempDir()
	writeFlat(t, root)
	dest := OrgDir(root, mtls.TestClientOU)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "client.key"), filepath.Join(dest, "client.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(migratingPath(root), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if LooksEnrolled(root) {
		t.Fatal("half-migrated store must not look enrolled")
	}
	if _, err := Load(root); err == nil {
		t.Fatal("root Load must fail without client.key")
	}
	if _, err := Load(dest); err == nil {
		t.Fatal("partial dest must not Load")
	}

	if err := EnsureLayout(root); err != nil {
		t.Fatal(err)
	}
	if !LooksEnrolled(root) {
		t.Fatal("retry should finish migration")
	}
}

func TestStaleActiveIsNotFatal(t *testing.T) {
	root := t.TempDir()
	if err := WriteActive(root, "missing-org"); err != nil {
		t.Fatal(err)
	}
	dir, err := ResolveActiveDir(root)
	if dir != "" || err != ErrNotEnrolled {
		t.Fatalf("stale active: dir=%q err=%v", dir, err)
	}
	active, err := ReadActive(root)
	if err != nil {
		t.Fatal(err)
	}
	if active != "" {
		t.Fatalf("stale active should be cleared, got %q", active)
	}
}

func TestRemoveOrgLeavesOthersAndClearsActive(t *testing.T) {
	root := t.TempDir()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	a := OrgDir(root, "org-a")
	b := OrgDir(root, "org-b")
	if err := Write(a, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
	if err := Write(b, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(a, OrgMeta{ID: "org-a", Name: "A", Slug: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(b, OrgMeta{ID: "org-b", Name: "B", Slug: "b"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a, SystemInfoFile), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}

	if err := RemoveOrg(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a); !os.IsNotExist(err) {
		t.Fatal("revoked org dir should be gone")
	}
	if _, err := Load(b); err != nil {
		t.Fatalf("other org must survive: %v", err)
	}
	active, err := ReadActive(root)
	if err != nil {
		t.Fatal(err)
	}
	if active != "" {
		t.Fatalf("active should be cleared, not switched, got %q", active)
	}
}

func TestMatchAndAmbiguity(t *testing.T) {
	orgs := []Enrollment{
		{ID: "id-1", Name: "Acme", Slug: "acme"},
		{ID: "id-2", Name: "Acme", Slug: "acme-eu"},
		{ID: "id-3", Name: "Beta", Slug: "beta"},
	}
	got, err := Match(orgs, "beta")
	if err != nil || got.ID != "id-3" {
		t.Fatalf("slug match: %#v err=%v", got, err)
	}
	got, err = Match(orgs, "ID-3")
	if err != nil || got.ID != "id-3" {
		t.Fatalf("id fold: %#v err=%v", got, err)
	}
	if _, err := Match(orgs, "Acme"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("name clash should be ambiguous: %v", err)
	}
	if _, err := Match(orgs, "nope"); err == nil {
		t.Fatal("unknown should error")
	}
}

func TestFormatListMarksActive(t *testing.T) {
	text := FormatList([]Enrollment{
		{ID: "id-1", Name: "Acme", Slug: "acme", Active: false},
		{ID: "id-2", Name: "", Slug: "", Active: true},
	})
	if !strings.Contains(text, "* id-2") {
		t.Fatalf("active mark:\n%s", text)
	}
	if !strings.Contains(text, "  id-1  Acme  acme") {
		t.Fatalf("inactive row:\n%s", text)
	}
	if !strings.Contains(text, "—") {
		t.Fatalf("empty name/slug should be em dash:\n%s", text)
	}
}

func encodeDERCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeECKey(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
```

### New file `internal/store/switch.go`

```go
package store

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
)

const SwitchNeedsTTY = "not a TTY; specify an organization: agent switch <name-or-slug-or-id>"

// RunSwitch implements `agent switch`. No argument on a TTY is a
// numbered picker. No argument without a TTY prints the list and
// returns an error — it never blocks on stdin.
func RunSwitch(root string, args []string, in io.Reader, out io.Writer, tty bool) error {
	orgs, err := List(root)
	if err != nil {
		return err
	}
	if len(orgs) == 0 {
		return fmt.Errorf("no enrolled organizations — run `agent enroll`")
	}

	if len(args) == 0 {
		fmt.Fprint(out, FormatList(orgs))
		if !tty {
			return fmt.Errorf("%s", SwitchNeedsTTY)
		}
		fmt.Fprintf(out, "Select organization [1-%d]: ", len(orgs))
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil {
			return fmt.Errorf("switch: read selection: %w", err)
		}
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil || n < 1 || n > len(orgs) {
			return fmt.Errorf("switch: invalid selection")
		}
		return writeSwitch(root, orgs[n-1], out)
	}

	got, err := Match(orgs, strings.Join(args, " "))
	if err != nil {
		return err
	}
	return writeSwitch(root, got, out)
}

func writeSwitch(root string, got Enrollment, out io.Writer) error {
	if err := WriteActive(root, filepath.Base(got.Dir)); err != nil {
		return err
	}
	label := got.Name
	if strings.TrimSpace(label) == "" {
		label = got.ID
	}
	fmt.Fprintf(out, "active: %s\n", label)
	return nil
}
```

### New file `internal/store/switch_test.go`

```go
package store

import (
	"bytes"
	"strings"
	"testing"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
)

func seedTwoOrgs(t *testing.T, root string) {
	t.Helper()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	a := OrgDir(root, "org-a")
	b := OrgDir(root, "org-b")
	if err := Write(a, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
	if err := Write(b, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(a, OrgMeta{ID: "org-a", Name: "Alpha", Slug: "alpha"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(b, OrgMeta{ID: "org-b", Name: "Beta", Slug: "beta"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
}

func TestRunSwitchDirectAndList(t *testing.T) {
	root := t.TempDir()
	seedTwoOrgs(t, root)

	var out bytes.Buffer
	if err := RunSwitch(root, []string{"beta"}, nil, &out, false); err != nil {
		t.Fatal(err)
	}
	active, err := ReadActive(root)
	if err != nil || active != "org-b" {
		t.Fatalf("active=%q err=%v", active, err)
	}
	if !strings.Contains(out.String(), "Beta") {
		t.Fatalf("switch output: %q", out.String())
	}

	orgs, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	text := FormatList(orgs)
	if !strings.Contains(text, "* org-b") {
		t.Fatalf("list after switch:\n%s", text)
	}
}

func TestRunSwitchNoArgNonTTYPrintsListAndErrors(t *testing.T) {
	root := t.TempDir()
	seedTwoOrgs(t, root)

	var out bytes.Buffer
	err := RunSwitch(root, nil, strings.NewReader("this would hang\n"), &out, false)
	if err == nil || !strings.Contains(err.Error(), SwitchNeedsTTY) {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(out.String(), "org-a") || !strings.Contains(out.String(), "org-b") {
		t.Fatalf("list not printed:\n%s", out.String())
	}
	active, _ := ReadActive(root)
	if active != "org-a" {
		t.Fatalf("non-TTY switch must not change active, got %q", active)
	}
}

func TestRunSwitchInteractivePicker(t *testing.T) {
	root := t.TempDir()
	seedTwoOrgs(t, root)

	var out bytes.Buffer
	if err := RunSwitch(root, nil, strings.NewReader("2\n"), &out, true); err != nil {
		t.Fatal(err)
	}
	active, err := ReadActive(root)
	if err != nil || active != "org-b" {
		t.Fatalf("active=%q err=%v", active, err)
	}
}

func TestRunSwitchAmbiguous(t *testing.T) {
	root := t.TempDir()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	a := OrgDir(root, "org-a")
	b := OrgDir(root, "org-b")
	if err := Write(a, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
	if err := Write(b, encodeDERCert(pki.CACert.Raw), encodeDERCert(pki.ClientCert.Raw), encodeECKey(pki.ClientKey)); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(a, OrgMeta{ID: "org-a", Name: "Acme", Slug: "acme"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteOrgMeta(b, OrgMeta{ID: "org-b", Name: "Acme", Slug: "acme-eu"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	err = RunSwitch(root, []string{"Acme"}, nil, ioDiscard{}, false)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("err=%v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
```
