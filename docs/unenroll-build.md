# `agent unenroll` — build

**No deploy, no commit, no PR.**

| Tree | Branch | HEAD at start of this pass |
| --- | --- | --- |
| `hookdeployed` | `feat/agent-unenroll` off `origin/main` | `c4bad2b` (PR #7 multi-org **is** on `origin/main`) |
| `platform` / enrollment-worker | `feat/enrollment-self-revoke` off `origin/main` | `0e8cb31` |

**Deploy order (human):** enrollment worker first (`POST /v1/agents/self-revoke` must exist), then rebuild the agent.

---

## PART 0 — findings

### Multi-org on main

Confirmed. `origin/main` @ `c4bad2b` is `Merge pull request #7`. `internal/store/layout.go` is on that tree.

### `revoke_agent` cannot be called from the agent

```
if auth.uid() is null then raise 'Authentication required';
if not user_has_permission(org_id, 'agents.manage') then raise ...
```

The agent has a **renewal token**, not a user JWT. `POST /v1/agents/:id/revoke` forwards the dashboard JWT via `supabaseRpcAsUser`. That path stays the “machine may be compromised” button.

**Options for token-authenticated revoke:**

1. **New SQL RPC** (`revoke_agent_by_token(p_token_hash)` SECURITY DEFINER, `service_role` only). One transaction, same writes. Needs a supabase migration — **out of scope** for this pass (repos are hookdeployed + enrollment-worker only).
2. **Service-role REST after a token lookup** — same `lookupRenewalCredential` as system-info, then PATCH `agent_renewal_credentials` (`revoked_at`) and PATCH `agents` (`status='revoked'`, `revoked_at`). Reuse `notifyRevocation`.

**Recommended and implemented: option 2.** No schema change. The worker never calls `revoke_agent`. Writes match that function: credentials first (including the authenticating row), then the agent row if not already revoked.

### Rate limiting

No rate limit exists on agent-facing enrollment-worker routes (`system-info`, `renew`, device). Self-revoke is a one-shot. **No new guard.**

### Security note

This grants revocation to whoever holds the renewal token. That is a self-inflicted DoS at worst — an attacker with the token can already impersonate the agent, which is strictly worse. Blast radius is one agent, recoverable by re-enrolling.

---

## PART 1 — worker

**Route:** `POST /v1/agents/self-revoke`

**Auth:** JSON `{ "renewal_token": "hd_agentrenew_{region}_…" }`. Region from the prefix. Hash lookup via `lookupRenewalCredential`. Reject 401 if not found, rotated (`renewal token reused`), expired, or revoked **unless** the agent is already revoked (idempotent 200, no writes, no fan-out).

**No rotation.** `self-revoke.ts` does not import `rotateRenewalCredential`, `mintRenewalToken`, or `issueRenewalCredential`. Tests assert the rotate RPC is never hit and the source never names those helpers.

**Writes (service role):**

1. `PATCH agent_renewal_credentials?agent_id=eq.<id>&revoked_at=is.null` → `{ revoked_at }`
2. If `agents.status !== 'revoked'`: `PATCH agents?id=eq.<id>` → `{ status: 'revoked', revoked_at }`

**Fan-out:** `notifyRevocation(env, agentId)` — the same `RELAY_MANAGER` POST to `http://relay-manager/internal/revocations` used by dashboard revoke. Fail-open. Without this, a self-unenrolled agent stays connectable until the leaf expires.

**Idempotent:** token already revoked + agent already revoked → 200.

---

## PART 2 — agent

```
agent unenroll [-certs DIR] [--enroll-url URL] [--local-only] [--yes] [<name-or-slug-or-id>]
```

**Resolution:** no argument → `ResolveActiveDir` / `ExplainResolve` (zero orgs → enroll; orgs but no active → switch + list). Argument → `store.Match` (same rules as `switch`).

**Confirmation (TTY):**

```
This will delete local credentials for <name> and revoke the agent on the server.
This cannot be undone without re-enrolling.
Continue? [y/N]
```

`--yes` skips. **Non-TTY without `--yes`:** `not a TTY; pass --yes to unenroll without a prompt` — does not read stdin.

**Order: server-first.** A failed server call keeps local files and says so, suggesting `--local-only`. A failed local delete after a successful revoke self-heals on next connect (terminal rejection). The reverse (local-first) is the orphan this command exists to prevent.

**Local delete:** `store.RemoveOrg` — `client.key` first, whole org dir including `org.json` and `system-info.json`. If it was active, `active` is **cleared**, not switched.

Messages:

- Others remain: `unenrolled <name>. Other organizations are still enrolled. Run \`agent switch\`…`
- None remain: `unenrolled <name>. Local credentials were removed. Run \`agent enroll\`…`
- `--local-only`: `removed local credentials for <name>. The agent record was not revoked (--local-only).`

No token on disk (and not `--local-only`): error, suggest `--local-only`. Do not delete.

---

## PART 3 — tests

### enrollment-worker

`npm test`: **118 pass, 1 skip** (live mint). Includes self-revoke: valid token + fan-out, 401 cases, idempotent, no rotate.

`npx tsc --noEmit`: exit 0.

### hookdeployed

```
go test ./...
ok  	internal/connect	2.326s
ok  	internal/enroll	0.912s
ok  	internal/mtls	(cached)
ok  	internal/store	0.513s
ok  	internal/sysinfo	0.812s
```

`GOOS=linux,darwin,windows` `go build ./cmd/agent`: exit 0.

Agent cases: active default; argument matching; TTY cancel; `--yes`; non-TTY without `--yes`; server failure keeps files; `--local-only` skips the call; active cleared; other orgs untouched; no-active uses `ExplainResolve`.

---

## Full diffs (separated by repo)

See the working trees. Files:

**platform / enrollment-worker**

- `src/routes/self-revoke.ts` (new)
- `src/self-revoke.test.ts` (new)
- `src/index.ts`
- `src/lib/agents.ts` (`findAgentInRegion`)
- `package.json` (test script)

**hookdeployed**

- `internal/enroll/unenroll.go` (new)
- `internal/enroll/unenroll_test.go` (new)
- `internal/enroll/client.go` (`SelfRevoke`)
- `cmd/agent/main.go`
- `docs/unenroll-build.md` (this file)

No deploy. No commit. No PR.

---

### hookdeployed patch

```diff
diff --git a/cmd/agent/main.go b/cmd/agent/main.go
index 333bcda..b89d6f4 100644
--- a/cmd/agent/main.go
+++ b/cmd/agent/main.go
@@ -9,6 +9,7 @@ import (
 	"log"
 	"os"
 	"os/signal"
+	"strings"
 	"syscall"
 
 	"github.com/hookdeploy/hookdeployed/internal/connect"
@@ -51,6 +52,13 @@ func main() {
 		}
 		return
 	}
+	if len(os.Args) > 1 && os.Args[1] == "unenroll" {
+		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
+		if err := runUnenroll(); err != nil {
+			log.Fatal(err)
+		}
+		return
+	}
 	runEcho()
 }
 
@@ -113,6 +121,26 @@ func runList() error {
 	return nil
 }
 
+func runUnenroll() error {
+	fs := flag.NewFlagSet("unenroll", flag.ExitOnError)
+	dir := fs.String("certs", store.DefaultDir(), "cert store directory")
+	enrollURL := fs.String("enroll-url", "https://enroll.hookdeploy.dev", "enrollment worker for self-revoke")
+	localOnly := fs.Bool("local-only", false, "delete local credentials without revoking the agent")
+	yes := fs.Bool("yes", false, "skip the confirmation prompt")
+	if err := fs.Parse(os.Args[1:]); err != nil {
+		return err
+	}
+	tty := enroll.RequireInteractiveFile(os.Stdin) == nil
+	query := strings.Join(fs.Args(), " ")
+	return enroll.Unenroll(enroll.UnenrollConfig{
+		Root:      *dir,
+		EnrollURL: *enrollURL,
+		LocalOnly: *localOnly,
+		Yes:       *yes,
+		Query:     query,
+	}, os.Stdin, os.Stdout, tty)
+}
+
 func runSwitch() error {
 	fs := flag.NewFlagSet("switch", flag.ExitOnError)
 	dir := fs.String("certs", store.DefaultDir(), "cert store directory")
diff --git a/internal/enroll/client.go b/internal/enroll/client.go
index 9272ed5..d2736c9 100644
--- a/internal/enroll/client.go
+++ b/internal/enroll/client.go
@@ -143,6 +143,16 @@ func (c *Client) Renew(certificatePEM, intermediatePEM, rootPEM, csrPEM []byte)
 	return &out, nil
 }
 
+func (c *Client) SelfRevoke(renewalToken string) error {
+	var out struct {
+		OK      bool   `json:"ok"`
+		AgentID string `json:"agent_id"`
+	}
+	return c.post("/v1/agents/self-revoke", map[string]string{
+		"renewal_token": renewalToken,
+	}, &out)
+}
+
 func (c *Client) RenewWithToken(renewalToken string, csrPEM []byte) (*TokenResponse, error) {
 	var out TokenResponse
 	if err := c.post("/v1/enroll/renew", map[string]string{
```

### New `internal/enroll/unenroll.go`

```go
package enroll

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/hookdeploy/hookdeployed/internal/store"
)

const (
	UnenrollNeedsYes = "not a TTY; pass --yes to unenroll without a prompt"

	UnenrollConfirmPrefix = "This will delete local credentials for"
	UnenrollConfirmSuffix = "and revoke the agent on the server.\nThis cannot be undone without re-enrolling.\nContinue? [y/N] "
)

type UnenrollConfig struct {
	Root      string
	EnrollURL string
	LocalOnly bool
	Yes       bool
	Query     string
	// Revoke overrides Client.SelfRevoke (tests). Nil uses the real call.
	Revoke func(enrollURL, token string) error
}

func Unenroll(cfg UnenrollConfig, in io.Reader, out io.Writer, tty bool) error {
	orgs, err := store.List(cfg.Root)
	if err != nil {
		return err
	}

	target, err := resolveUnenrollTarget(cfg.Root, orgs, cfg.Query)
	if err != nil {
		return err
	}
	label := target.Name
	if strings.TrimSpace(label) == "" {
		label = target.ID
	}

	if !cfg.Yes {
		if !tty {
			return fmt.Errorf("%s", UnenrollNeedsYes)
		}
		fmt.Fprintf(out, "%s %s %s", UnenrollConfirmPrefix, label, UnenrollConfirmSuffix)
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil {
			return fmt.Errorf("unenroll: read confirmation: %w", err)
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		if answer != "y" && answer != "yes" {
			return fmt.Errorf("unenroll cancelled")
		}
	}

	orgID := filepath.Base(target.Dir)
	others := 0
	for _, o := range orgs {
		if filepath.Base(o.Dir) != orgID && o.ID != orgID {
			others++
		}
	}

	if !cfg.LocalOnly {
		material, err := store.Load(target.Dir)
		if err != nil {
			return err
		}
		token := strings.TrimSpace(material.RenewalToken)
		if token == "" {
			return fmt.Errorf("no renewal token on disk — cannot revoke on the server. Pass --local-only to delete credentials and leave the dashboard record")
		}
		revoke := cfg.Revoke
		if revoke == nil {
			revoke = func(enrollURL, tok string) error {
				return NewClient(enrollURL).SelfRevoke(tok)
			}
		}
		if err := revoke(cfg.EnrollURL, token); err != nil {
			return fmt.Errorf("could not revoke the agent on the server: %w\nLocal credentials were kept. Re-run when online, or pass --local-only to delete them and leave the dashboard record", err)
		}
	}

	if err := store.RemoveOrg(cfg.Root, orgID); err != nil {
		return err
	}

	if cfg.LocalOnly {
		fmt.Fprintf(out, "removed local credentials for %s. The agent record was not revoked (--local-only).\n", label)
		if others > 0 {
			fmt.Fprintf(out, "Other organizations are still enrolled. Run `agent switch` to pick one.\n")
		}
		return nil
	}
	if others > 0 {
		fmt.Fprintf(out, "unenrolled %s. Other organizations are still enrolled. Run `agent switch` to pick one.\n", label)
		return nil
	}
	fmt.Fprintf(out, "unenrolled %s. Local credentials were removed. Run `agent enroll` to enroll again.\n", label)
	return nil
}

func resolveUnenrollTarget(root string, orgs []store.Enrollment, query string) (store.Enrollment, error) {
	if strings.TrimSpace(query) != "" {
		if len(orgs) == 0 {
			return store.Enrollment{}, store.ExplainResolve(root, store.ErrNotEnrolled)
		}
		return store.Match(orgs, query)
	}
	dir, err := store.ResolveActiveDir(root)
	if err != nil {
		return store.Enrollment{}, store.ExplainResolve(root, err)
	}
	for _, o := range orgs {
		if o.Dir == dir || filepath.Base(o.Dir) == filepath.Base(dir) {
			return o, nil
		}
	}
	return store.Enrollment{}, store.ExplainResolve(root, store.ErrNotEnrolled)
}
```

### New `internal/enroll/unenroll_test.go`

```go
package enroll

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hookdeploy/hookdeployed/internal/mtls"
	"github.com/hookdeploy/hookdeployed/internal/store"
)

const testRenewToken = "hd_agentrenew_us_unenrollfixture"

func seedOrg(t *testing.T, root, id, name, slug, token string) {
	t.Helper()
	pki, err := mtls.GenerateTestPKI()
	if err != nil {
		t.Fatal(err)
	}
	dir := store.OrgDir(root, id)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.CACert.Raw})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.ClientCert.Raw})
	keyDER, err := x509.MarshalECPrivateKey(pki.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := store.Write(dir, caPEM, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if token != "" {
		if err := os.WriteFile(filepath.Join(dir, "renewal.token"), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WriteOrgMeta(dir, store.OrgMeta{ID: id, Name: name, Slug: slug}); err != nil {
		t.Fatal(err)
	}
}

func TestUnenrollActiveDefaultServerThenDelete(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	seedOrg(t, root, "org-b", "Beta", "beta", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}

	var called int
	var out bytes.Buffer
	err := Unenroll(UnenrollConfig{
		Root:      root,
		EnrollURL: "http://example.invalid",
		Yes:       true,
		Revoke: func(enrollURL, token string) error {
			called++
			if token != testRenewToken {
				t.Fatalf("token=%q", token)
			}
			return nil
		},
	}, strings.NewReader(""), &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("revoke calls=%d", called)
	}
	if _, err := os.Stat(store.OrgDir(root, "org-a")); !os.IsNotExist(err) {
		t.Fatal("active org should be gone")
	}
	if _, err := store.Load(store.OrgDir(root, "org-b")); err != nil {
		t.Fatalf("other org must survive: %v", err)
	}
	active, _ := store.ReadActive(root)
	if active != "" {
		t.Fatalf("active should be cleared, got %q", active)
	}
	if !strings.Contains(out.String(), "unenrolled Alpha") || !strings.Contains(out.String(), "agent switch") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestUnenrollArgumentMatching(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	seedOrg(t, root, "org-b", "Beta", "beta", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := Unenroll(UnenrollConfig{
		Root:  root,
		Yes:   true,
		Query: "beta",
		Revoke: func(enrollURL, token string) error {
			return nil
		},
	}, nil, &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.OrgDir(root, "org-b")); !os.IsNotExist(err) {
		t.Fatal("matched org should be gone")
	}
	if _, err := store.Load(store.OrgDir(root, "org-a")); err != nil {
		t.Fatal(err)
	}
	active, _ := store.ReadActive(root)
	if active != "org-a" {
		t.Fatalf("unenrolling a non-active org must not clear active, got %q", active)
	}
}

func TestUnenrollTTYConfirmationRequiredAndYesSkips(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := Unenroll(UnenrollConfig{
		Root: root,
		Revoke: func(enrollURL, token string) error {
			t.Fatal("should not revoke before confirm")
			return nil
		},
	}, strings.NewReader("n\n"), &out, true)
	if err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(out.String(), UnenrollConfirmPrefix) {
		t.Fatalf("prompt=%q", out.String())
	}
	if _, err := store.Load(store.OrgDir(root, "org-a")); err != nil {
		t.Fatal("declined confirm must keep files")
	}

	out.Reset()
	if err := Unenroll(UnenrollConfig{
		Root:   root,
		Yes:    true,
		Revoke: func(enrollURL, token string) error { return nil },
	}, strings.NewReader(""), &out, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.OrgDir(root, "org-a")); !os.IsNotExist(err) {
		t.Fatal("yes should delete")
	}
}

func TestUnenrollNonTTYWithoutYesErrors(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	err := Unenroll(UnenrollConfig{
		Root: root,
		Revoke: func(enrollURL, token string) error {
			t.Fatal("must not revoke")
			return nil
		},
	}, strings.NewReader("yes\n"), ioDiscard{}, false)
	if err == nil || !strings.Contains(err.Error(), UnenrollNeedsYes) {
		t.Fatalf("err=%v", err)
	}
	if _, err := store.Load(store.OrgDir(root, "org-a")); err != nil {
		t.Fatal("must keep files")
	}
}

func TestUnenrollServerFailureKeepsLocal(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	err := Unenroll(UnenrollConfig{
		Root: root,
		Yes:  true,
		Revoke: func(enrollURL, token string) error {
			return fmtUnenroll("worker down")
		},
	}, nil, ioDiscard{}, false)
	if err == nil || !strings.Contains(err.Error(), "could not revoke") {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(err.Error(), "--local-only") {
		t.Fatalf("should suggest --local-only: %v", err)
	}
	if _, err := store.Load(store.OrgDir(root, "org-a")); err != nil {
		t.Fatal("server failure must not delete locally")
	}
}

func TestUnenrollLocalOnlySkipsServer(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	if err := store.WriteActive(root, "org-a"); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := Unenroll(UnenrollConfig{
		Root:      root,
		LocalOnly: true,
		Yes:       true,
		Revoke: func(enrollURL, token string) error {
			t.Fatal("local-only must not call the server")
			return nil
		},
	}, nil, &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.OrgDir(root, "org-a")); !os.IsNotExist(err) {
		t.Fatal("local-only should delete")
	}
	if !strings.Contains(out.String(), "--local-only") {
		t.Fatalf("output must say the record remains: %q", out.String())
	}
}

func TestUnenrollNoActiveUsesExplainResolve(t *testing.T) {
	root := t.TempDir()
	seedOrg(t, root, "org-a", "Alpha", "alpha", testRenewToken)
	err := Unenroll(UnenrollConfig{Root: root, Yes: true}, nil, ioDiscard{}, false)
	if err == nil || !strings.Contains(err.Error(), "agent switch") {
		t.Fatalf("err=%v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func fmtUnenroll(msg string) error { return unenrollErr(msg) }

type unenrollErr string

func (e unenrollErr) Error() string { return string(e) }
```

---

### enrollment-worker patch

```diff
diff --git a/enrollment-worker/package.json b/enrollment-worker/package.json
index 120da60..8b1cc5e 100644
--- a/enrollment-worker/package.json
+++ b/enrollment-worker/package.json
@@ -7,7 +7,7 @@
     "dev": "wrangler dev",
     "deploy": "wrangler deploy",
     "typecheck": "tsc --noEmit",
-    "test": "node --experimental-strip-types --test src/ott.test.ts src/mint-shape.test.ts src/mint-live.test.ts src/renew-chain.test.ts src/cert-dates.test.ts src/csr.test.ts src/http.test.ts src/relay-enroll.test.ts src/relay-renew.test.ts src/renewal-credential.test.ts src/renew-token.test.ts src/revoke.test.ts src/system-info.test.ts src/hostname-field.test.ts src/invert.test.ts"
+    "test": "node --experimental-strip-types --test src/ott.test.ts src/mint-shape.test.ts src/mint-live.test.ts src/renew-chain.test.ts src/cert-dates.test.ts src/csr.test.ts src/http.test.ts src/relay-enroll.test.ts src/relay-renew.test.ts src/renewal-credential.test.ts src/renew-token.test.ts src/revoke.test.ts src/system-info.test.ts src/self-revoke.test.ts src/hostname-field.test.ts src/invert.test.ts"
   },
   "dependencies": {
     "jose": "^6.1.0"
diff --git a/enrollment-worker/src/index.ts b/enrollment-worker/src/index.ts
index b0671a9..c0289df 100644
--- a/enrollment-worker/src/index.ts
+++ b/enrollment-worker/src/index.ts
@@ -15,6 +15,7 @@ import {
   matchRevokePath,
   revokeResponse,
 } from './routes/revoke.ts'
+import { handleSelfRevoke, SELF_REVOKE_PATH } from './routes/self-revoke.ts'
 import { handleSystemInfo } from './routes/system-info.ts'
 import { handleTokenEnroll } from './routes/token.ts'
 import type { EnrollmentEnv } from './types.ts'
@@ -90,6 +91,9 @@ export default {
       if (pathname === '/v1/agents/system-info' && request.method === 'POST') {
         return await handleSystemInfo(request, env)
       }
+      if (pathname === SELF_REVOKE_PATH && request.method === 'POST') {
+        return await handleSelfRevoke(request, env)
+      }
 
       return jsonResponse({ error: 'not_found' }, 404)
     } catch (err) {
diff --git a/enrollment-worker/src/lib/agents.ts b/enrollment-worker/src/lib/agents.ts
index d50325c..143e33d 100644
--- a/enrollment-worker/src/lib/agents.ts
+++ b/enrollment-worker/src/lib/agents.ts
@@ -8,6 +8,20 @@ export type AgentRow = {
   status: string
 }
 
+/** Agent by id in a known region (any status). Used by self-revoke. */
+export async function findAgentInRegion(
+  env: EnrollmentEnv,
+  region: RegionKey,
+  agentId: string,
+): Promise<AgentRow | null> {
+  const rows = await supabaseRest<AgentRow[]>(
+    env,
+    region,
+    `agents?id=eq.${agentId}&select=id,org_id,status&limit=1`,
+  )
+  return rows[0] ?? null
+}
+
 /** Active agent in a known region. Shared by renew and system-info. */
 export async function findActiveAgentInRegion(
   env: EnrollmentEnv,
```

### New `enrollment-worker/src/routes/self-revoke.ts`

```ts
import { findAgentInRegion } from '../lib/agents.ts'
import { HttpError, jsonResponse, readJson } from '../lib/http.ts'
import { notifyRevocation } from '../lib/notify-revocation.ts'
import {
  lookupRenewalCredential,
  parseRenewalTokenRegion,
} from '../lib/renewal-credential.ts'
import { sha256Hex } from '../lib/rest.ts'
import { supabaseRest } from '../lib/supabase.ts'
import type { EnrollmentEnv } from '../types.ts'

export const SELF_REVOKE_PATH = '/v1/agents/self-revoke'

type SelfRevokeBody = {
  renewal_token?: unknown
}

/**
 * POST /v1/agents/self-revoke
 *
 * Auth is a *read* of the renewal token (hash lookup), same as system-info.
 * This file must never import rotate / mint / issue helpers.
 *
 * After the token is accepted, service-role REST applies the same writes as
 * revoke_agent (credentials first, then agents.status). The agent has no
 * user JWT, so revoke_agent cannot be called from this path.
 */
export async function handleSelfRevoke(
  request: Request,
  env: EnrollmentEnv,
): Promise<Response> {
  const body = await readJson<SelfRevokeBody>(request)
  const token = requireToken(body.renewal_token)
  const region = parseRenewalTokenRegion(token)
  if (!region) {
    throw new HttpError(401, 'unauthorized', 'invalid renewal token')
  }

  const presentedHash = await sha256Hex(token)
  const row = await lookupRenewalCredential(env, region, presentedHash)
  if (!row) {
    throw new HttpError(401, 'unauthorized', 'invalid renewal token')
  }
  if (row.rotated_at) {
    throw new HttpError(401, 'unauthorized', 'renewal token reused')
  }
  if (new Date(row.expires_at) <= new Date()) {
    throw new HttpError(401, 'unauthorized', 'renewal token expired')
  }

  const agent = await findAgentInRegion(env, region, row.agent_id)
  if (!agent) {
    throw new HttpError(401, 'unauthorized', 'agent not found or revoked')
  }

  if (row.revoked_at) {
    if (agent.status === 'revoked') {
      return jsonResponse({ ok: true, agent_id: agent.id })
    }
    throw new HttpError(401, 'unauthorized', 'renewal token revoked')
  }

  const now = new Date().toISOString()
  await supabaseRest(
    env,
    region,
    `agent_renewal_credentials?agent_id=eq.${agent.id}&revoked_at=is.null`,
    {
      method: 'PATCH',
      body: JSON.stringify({ revoked_at: now }),
    },
  )
  if (agent.status !== 'revoked') {
    await supabaseRest(env, region, `agents?id=eq.${agent.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: 'revoked', revoked_at: now }),
    })
  }

  await notifyRevocation(env, agent.id)
  return jsonResponse({ ok: true, agent_id: agent.id })
}

function requireToken(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new HttpError(400, 'bad_request', 'renewal_token is required')
  }
  return value.trim()
}
```

### New `enrollment-worker/src/self-revoke.test.ts`

```ts
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { handleSelfRevoke, SELF_REVOKE_PATH } from './routes/self-revoke.ts'
import type { EnrollmentEnv } from './types.ts'

const URL = `https://enroll.hookdeploy.dev${SELF_REVOKE_PATH}`
const US_URL = 'https://us.example.supabase.co'
const AGENT_ID = '62e2bc2f-aaaa-4bbb-8ccc-ddddeeeeffff'
const HEX32 = 'ab'.repeat(32)
const TOKEN = `hd_agentrenew_us_${HEX32}`

function postJson(body: unknown): Request {
  return new Request(URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

function env(managerHits?: Array<{ url: string; method: string; body: string }>): EnrollmentEnv {
  return {
    HOOKDEPLOY_CA: { fetch: async () => new Response('unused') } as Fetcher,
    HOOKDEPLOY_CA_JWK: '',
    HOOKDEPLOY_RELAYS_JWK: '',
    SUPABASE_URL_US: US_URL,
    SUPABASE_SERVICE_ROLE_KEY_US: 'us-service-role',
    SUPABASE_URL_EU: '',
    SUPABASE_SERVICE_ROLE_KEY_EU: '',
    SUPABASE_URL_APAC: '',
    SUPABASE_SERVICE_ROLE_KEY_APAC: '',
    SUPABASE_URL_AU: '',
    SUPABASE_SERVICE_ROLE_KEY_AU: '',
    SUPABASE_URL_ADMIN: '',
    SUPABASE_SERVICE_ROLE_KEY_ADMIN: '',
    CA_ROOT_FINGERPRINT: 'x',
    CA_SIGN_URL: 'https://ca.example/sign',
    CA_PROVISIONER: 'hookdeploy-agents',
    CA_JWK_KID: 'unused',
    APP_ORIGIN: 'https://app.hookdeploy.dev',
    RELAY_MANAGER_SECRET: 'manager-secret',
    RELAY_MANAGER: {
      fetch: async (input, init) => {
        managerHits?.push({
          url: String(input),
          method: (init?.method ?? 'GET').toUpperCase(),
          body: typeof init?.body === 'string' ? init.body : '',
        })
        return new Response(JSON.stringify({ ok: true }), { status: 200 })
      },
    } as Fetcher,
  }
}

type CredRow = {
  agent_id: string
  rotated_at: string | null
  revoked_at: string | null
  expires_at: string
}

type FetchLog = { url: string; method: string; body: string }

function liveCred(overrides?: Partial<CredRow>): CredRow {
  return {
    agent_id: AGENT_ID,
    rotated_at: null,
    revoked_at: null,
    expires_at: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
    ...overrides,
  }
}

function installFetch(state: {
  cred: CredRow | null
  agent: { id: string; org_id: string; status: string } | null
  log: FetchLog[]
}): typeof fetch {
  const previous = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = typeof init?.body === 'string' ? init.body : ''
    state.log.push({ url, method, body })

    if (!url.startsWith(`${US_URL}/rest/v1/`)) {
      return new Response('unexpected url', { status: 500 })
    }
    if (url.includes('rpc/rotate_agent_renewal_credential')) {
      return Response.json({ ok: true, agent_id: AGENT_ID, org_id: 'org' })
    }
    if (url.includes('rpc/revoke_agent')) {
      return new Response('revoke_agent must not be called', { status: 500 })
    }
    if (url.includes('agent_renewal_credentials') && method === 'GET') {
      return Response.json(state.cred ? [state.cred] : [])
    }
    if (url.includes('agent_renewal_credentials') && method === 'PATCH') {
      return new Response(null, { status: 204 })
    }
    if (url.includes('agents?') && method === 'GET') {
      return Response.json(state.agent ? [state.agent] : [])
    }
    if (url.includes('agents?') && method === 'PATCH') {
      return new Response(null, { status: 204 })
    }
    return new Response(`unhandled ${method} ${url}`, { status: 500 })
  }) as typeof fetch
  return previous
}

test('valid token revokes credentials then agent and notifies fan-out', async () => {
  const log: FetchLog[] = []
  const managerHits: Array<{ url: string; method: string; body: string }> = []
  const previous = installFetch({
    cred: liveCred(),
    agent: { id: AGENT_ID, org_id: 'org-1', status: 'active' },
    log,
  })
  try {
    const response = await handleSelfRevoke(postJson({ renewal_token: TOKEN }), env(managerHits))
    assert.equal(response.status, 200)
    const body = (await response.json()) as { ok: boolean; agent_id: string }
    assert.equal(body.ok, true)
    assert.equal(body.agent_id, AGENT_ID)

    const credPatch = log.find(
      (e) => e.method === 'PATCH' && e.url.includes('agent_renewal_credentials'),
    )
    assert.ok(credPatch, 'expected credentials PATCH')
    assert.equal(credPatch.url.includes('revoked_at=is.null'), true)
    const credBody = JSON.parse(credPatch.body) as { revoked_at?: string }
    assert.equal(typeof credBody.revoked_at, 'string')

    const agentPatch = log.find((e) => e.method === 'PATCH' && e.url.includes('agents?'))
    assert.ok(agentPatch, 'expected agents PATCH')
    const agentBody = JSON.parse(agentPatch.body) as { status?: string; revoked_at?: string }
    assert.equal(agentBody.status, 'revoked')
    assert.equal(typeof agentBody.revoked_at, 'string')

    const credIdx = log.indexOf(credPatch)
    const agentIdx = log.indexOf(agentPatch)
    assert.ok(credIdx < agentIdx, 'credentials must be revoked before the agent row')

    assert.equal(
      log.some((e) => e.url.includes('rpc/rotate_agent_renewal_credential')),
      false,
      'self-revoke must not rotate',
    )
    assert.equal(
      log.some((e) => e.url.includes('rpc/revoke_agent')),
      false,
      'self-revoke must not call revoke_agent (no user JWT)',
    )

    assert.equal(managerHits.length, 1)
    assert.equal(managerHits[0]?.url, 'http://relay-manager/internal/revocations')
    assert.equal(JSON.parse(managerHits[0]!.body).agent_id, AGENT_ID)
  } finally {
    globalThis.fetch = previous
  }
})

test('revoked / rotated / expired / missing token → 401 and no writes', async () => {
  const cases = [
    { name: 'missing', cred: null, message: 'invalid renewal token' },
    {
      name: 'rotated',
      cred: liveCred({ rotated_at: new Date().toISOString() }),
      message: 'renewal token reused',
    },
    {
      name: 'revoked-live-agent',
      cred: liveCred({ revoked_at: new Date().toISOString() }),
      agent: { id: AGENT_ID, org_id: 'org-1', status: 'active' },
      message: 'renewal token revoked',
    },
    {
      name: 'expired',
      cred: liveCred({ expires_at: new Date(Date.now() - 1000).toISOString() }),
      message: 'renewal token expired',
    },
  ] as const

  for (const c of cases) {
    const log: FetchLog[] = []
    const previous = installFetch({
      cred: c.cred,
      agent: 'agent' in c ? c.agent : { id: AGENT_ID, org_id: 'org-1', status: 'active' },
      log,
    })
    try {
      await handleSelfRevoke(postJson({ renewal_token: TOKEN }), env()).then(
        () => {
          throw new Error(`${c.name}: expected throw`)
        },
        (err: { status?: number; message?: string }) => {
          assert.equal(err.status, 401, c.name)
          assert.equal(err.message, c.message, c.name)
        },
      )
      assert.equal(
        log.some((e) => e.method === 'PATCH'),
        false,
        `${c.name}: no PATCH`,
      )
    } finally {
      globalThis.fetch = previous
    }
  }
})

test('already-revoked agent with revoked token is idempotent 200', async () => {
  const log: FetchLog[] = []
  const managerHits: Array<{ url: string; method: string; body: string }> = []
  const previous = installFetch({
    cred: liveCred({ revoked_at: new Date().toISOString() }),
    agent: { id: AGENT_ID, org_id: 'org-1', status: 'revoked' },
    log,
  })
  try {
    const response = await handleSelfRevoke(postJson({ renewal_token: TOKEN }), env(managerHits))
    assert.equal(response.status, 200)
    assert.equal(log.some((e) => e.method === 'PATCH'), false)
    assert.equal(managerHits.length, 0)
  } finally {
    globalThis.fetch = previous
  }
})

test('self-revoke source never imports rotate helpers', () => {
  const src = readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), 'routes', 'self-revoke.ts'),
    'utf8',
  )
  assert.equal(src.includes('rotateRenewalCredential'), false)
  assert.equal(src.includes('mintRenewalToken'), false)
  assert.equal(src.includes('issueRenewalCredential'), false)
  assert.equal(src.includes('SELF_REVOKE_PATH'), true)
})
```
