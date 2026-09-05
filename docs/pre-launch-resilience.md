# Pre-launch resilience: auth loops, false errors, edge cases

**Date:** 2026-09-05  
**Repos audited:** `hookdeployed` (Go agent / `cmd/agent`), `hookdeploy-tray` (Tauri UI supervising the agent), `platform/enrollment-worker`  
**Scope note:** There is no separate `hookdeploy-agent` repo — the agent binary lives in `hookdeployed/cmd/agent`.  
**Method:** Code audit + fixture tests. Part D live chaos was **not executed** against production infra in this pass (checklist + expected behavior from code included for a human run).

**Policy for this pass:** Report findings; do not ship product fixes here. Fixture tests lock current behavior (including known gaps).

---

## Prioritized list

### Pre-launch blockers

| # | Finding | Why it matters |
| --- | --- | --- |
| B1 | Tray `summarize_enroll_failure` collapses **already-consumed / expired / invalid token**, **enrollment expired/denied**, and many **rate-limit** messages into **"Enrollment failed. Check your connection and try again."** | Exact failure class that already burned time this session; HN users will report “broken credentials” / “network down” for auth bugs. |
| B2 | Dead renewal token (expired / revoked / reused) does **not** terminate `connect.Run` — placement/reconnect retries **forever** at ≤30s backoff | Agent looks “stuck reconnecting”; hammers placement; never prompts re-enroll. |
| B3 | Clock-skew / TLS cert validity dial failures are **opaque** (`dial relay=…: …`) and also fall into the same **infinite reconnect** path | VM/wrong-clock users get a generic reconnect loop, indistinguishable from relay outage or revoked-looking failures until they dig logs. |

### Rough edges (fix eventually, not launch-blocking if documented)

| # | Finding |
| --- | --- |
| R1 | Cert store has **no file locking** — concurrent tray `connect` + CLI `connect`/`enroll`/`renew` can interleave writes (token-before-cert ordering helps crash recovery, not concurrency). |
| R2 | Tray Connect/Disconnect and Quit discard `start_connect` / `stop_connect` / `shutdown_all` errors (`let _ = …`) — silent no-op from the user’s perspective. |
| R3 | `confirm_server_tap_stop` maps **any** sidecar failure to one fixed unconfirmed string (loses worker 404 vs network). |
| R4 | `list_orgs` / `refreshOrgs` empty-catch can show the “not enrolled” gate on a transient list failure. |
| R5 | Orphan risk: tray `create_tap` can fail after spawn without always killing the child (supervisor path). |
| R6 | Worker 429 has **no `Retry-After`** header (status/code are still distinct). |
| R7 | Enrollment OTT paths all use HTTP **401 `unauthorized`** — distinction is only in `message` (fine for CLI; tray summarizer erases it — see B1). |

### Already fine

| # | Finding |
| --- | --- |
| OK1 | **Revocation** stops reconnect: deletes credentials, logs clear copy, blocks on `ctx.Done()` (no reconnect hammer). Covered by existing + reconnect tests. |
| OK2 | Device-code enroll has a **finite deadline** (`expires_in`, default 10m) and maps poll `expired`/`denied` to clear errors. |
| OK3 | Token enroll is **single-shot** — consumed token returns once as `token already consumed` (CLI). |
| OK4 | Worker **20/min** tap + placement limits return **429 `rate_limited`** — not the same status/code as auth. |
| OK5 | Tap create does not half-write local “running” state; stop failure surfaces an explicit linger message on CLI. |
| OK6 | Dial/placement backoff has a **30s delay ceiling** (attempts are unbounded for non-terminal errors — intentional for flaps, problematic for auth death — B2). |

---

## Part A — retry / reconnect termination

### 1. `connect.Run` after revocation — **SAFE**

Revocation is terminal for reconnect:

```518:559:hookdeployed/internal/connect/connect.go
func settleRejection(ctx context.Context, cfg Config, rej Rejection) error {
	// ...
	if rej.Reason == "revoked" {
		// RemoveOrg / ClearEnrollment ...
		log.Print(RevokedUserMessage) // or RevokedOrgMessage
	} else {
		log.Printf("this connection was ended (%s). Not retrying. Credentials were kept.", rej.Reason)
	}
	<-ctx.Done()
	return nil
}
```

Non-revoked dial/session failures retry forever with `NextBackoff` capped at **30s** (`minBackoff=1s`). Tray only reflects phases; it does not add its own reconnect loop.

**Verdict:** Revoked agents do **not** hammer the relay. Other failures back off sanely but never stop until process cancel.

### 2. Renewal-token refresh when token is dead — **NEEDS-FIXING**

`MaybeRenew` returns the API error once (no internal retry). `attemptRenew` **logs and continues**. Live `renewLoop` (5m + wake) does the same. Auto-placement then fails with the same 401 and `Run` retries placement forever (fixture: `TestUnauthorizedPlacementRetriesWithBackoffCeiling`).

There is **no** path that classifies `renewal token expired|revoked|reused` / `agent not found or revoked` as terminal the way `reason=revoked` is.

**Verdict:** Per-call renew fails cleanly; session orchestration does **not** prompt re-enroll / stop.

### 3. Device-code enrollment expiry — **SAFE**

```74:123:hookdeployed/internal/enroll/run.go
deadline := time.Now().Add(time.Duration(start.ExpiresIn) * time.Second)
// ...
if time.Now().After(deadline) {
    return fmt.Errorf("enrollment expired")
}
// poll status "denied" | "expired" → fmt.Errorf("enrollment %s", ...)
```

HTTP client timeout 30s/call. Fixture tests cover poll `expired`/`denied` and wall-clock deadline.

**Caveat:** Tray summarizer maps `"enrollment expired"` → generic “check your connection” (B1).

### 4. Token-based enrollment, already consumed — **SAFE** (CLI) / **NEEDS-FIXING** (tray UX)

`RunToken` → `TokenStart` then `TokenComplete`, no retry. Worker:

`401 { "error": "unauthorized", "message": "token already consumed" }`

CLI surfaces `token already consumed` via `APIError.Error()`. Tray leak filter drops any line containing `"token"` → generic connection message.

### 5. Concurrent cert store access — **NEEDS-FIXING**

`store` / `mtls.WriteClientDir` use plain `os.WriteFile`. **No** flock, mutex, or PID lock. Token-before-cert write order is crash-safe for rotation recovery, not concurrent writers.

**Likely failure mode:** interleaved PEMs / token vs cert mismatch; not a clear “already in use” error. Worst case silent overwrite of one writer’s files.

### 6. Clock skew — **NEEDS-FIXING** (messaging + termination)

- Client `ShouldRenew`: not-yet-valid **or** expired → attempt renew (good for vacation/skew).
- Worker leaf renew: **1h grace** both sides; messages `certificate not yet valid` / `certificate expired` (401 unauthorized).
- mTLS dial does **not** map skew to those strings; users see raw TLS dial errors, then infinite reconnect.

**Not distinguishable** from generic connectivity problems in the tray; CLI at least shows crypto/tls text in logs.

### 7. Rate limiting (20/min) — **SAFE** at wire level; **NEEDS-FIXING** in tray enroll summary

Applies to **taps** and **placement** (KV, per agent, 60s bucket) — **not** to enrollment OTT mint/consume.

Client sees:

- `429` / `error: "rate_limited"` / `message: "… rate limit exceeded (20/minute)"`
- Distinct from `401 unauthorized`

CLI tap path preserves the message (`TestEveryP1ErrorRendersItsMessage`). Tray enroll summarizer does **not** allowlist “rate” → collapses to generic (if that string ever appears in enroll output). Placement 429 during connect logs `placement failed: …; retry in Ns` and retries (same infinite loop class as B2, but recoverable after the minute window).

### 8. Tap create/stop under partial failure — **SAFE** (CLI) / mixed (tray)

CLI `tap.Start`: create remote → wait → stop; create failure returns immediately; stop failure returns explicit linger copy. No local “running” inventing a tap.

Tray: pending “Starting…” row cleared on create error; stop button re-enabled on error. Server-stop confirmation failure always becomes one fixed unconfirmed string (R3). Abrupt tray kill relies on server tap expiry + agent disconnect (Part D #17).

---

## Part B — generic / misleading errors

### 9. User-facing error → causes table

#### Agent CLI (`hookdeployed`) — high-signal messages

| Message shown | Distinct causes that produce it | Collapsed? |
| --- | --- | --- |
| `token already consumed` | OTT already used | No |
| `token expired` | OTT past `expires_at` | No |
| `invalid token` | Bad prefix / unknown hash | No |
| `renewal token expired` / `revoked` / `reused` / `invalid renewal token` | Matching renew/auth failures | No (distinct messages; same HTTP code) |
| `certificate not yet valid` / `certificate expired` | Leaf renew outside 1h grace | No |
| `enrollment expired` | Device deadline **or** poll status `expired` | Mild collapse (two expiry paths, same copy) |
| `enrollment denied` | Poll `denied` | No |
| `wrong code — try again` | `invalid_code` (includes attempt-cap from worker) | Mild — attempt-cap looks like typo |
| `placement rate limit exceeded (20/minute)` | Placement 429 | No |
| `tap rate limit exceeded (20/minute)` | Tap 429 | No |
| `this agent was revoked…` / org variant | Relay control `reason=revoked` | No |
| `this relay is draining…` | `reason=draining` | No |
| `placement failed: %v; retry in %s` | **Any** placement error (auth, 429, no relay, network) | **Yes** — same log shape; only `%v` differs |
| `dial relay=%s: %v` | Network, TLS, cert skew, refused | **Yes** — raw `%v` |
| `could not stop tap %s: %s` + linger | Any stop API/network failure | Message preserves cause; linger is clear |
| `Enrollment failed. Check your connection…` | *(tray only — see below)* | — |

#### Tray (`hookdeploy-tray`) — enroll / connect

| Message shown | Underlying causes | Collapsed? |
| --- | --- | --- |
| **`Enrollment failed. Check your connection and try again.`** | Empty buffer / spawn error; lines with `token`; `enrollment expired`/`denied`; bare `rate_limited`; many 5xx/raw HTTP lines; anything not on the allowlist | **YES — critical** |
| Allowlisted passthrough (e.g. `could not reach…`, `connection refused`, `unauthorized` without `token`) | Matching CLI line | Partial |
| `Wrong code — try again.` | `wrong code` line / `WrongCode` phase | Includes attempt-cap |
| `timed out waiting for enroll result` | Submit wait 90s | No |
| `Tap process stopped locally, but couldn't confirm…` | **Any** `tap stop` sidecar failure | **Yes** |
| `Something went wrong.` | Unclassified invoke error | Catch-all |
| Connect phase labels only (`Reconnecting`, `Revoked`, …) | Parsed from agent logs; **detail often unused** in webview chrome | Detail underused |
| Offline copy (`No Internet Connection`) | OS online detector | Separate path |

### 10. `EnrollPhase::Failed` summarization — **collapses; needs fix**

```603:655:hookdeploy-tray/src-tauri/src/parse.rs
const ENROLL_FAIL_GENERIC: &str = "Enrollment failed. Check your connection and try again.";
// enroll_line_looks_leaky: any line containing "token" is dropped
// allowlist: wrong code, timeout*, connection refused, failed to connect,
//   could not, unable to, unreachable, unauthorized, forbidden, not enrolled,
//   invalid, error:
// _exit_code is unused
```

| Needed distinction | Current result |
| --- | --- |
| Network unreachable | Often preserved (`could not` / `unreachable` / `refused`) |
| Invalid / expired / consumed token | **All generic** (leaky `token`) |
| Rate limited | **Generic** (no `rate` allowlist; worker copy has no “could not”) |
| Genuine server error | Often **generic** unless wording hits allowlist |
| Device `enrollment expired` | **Generic** (`expired` not allowlisted) |

**Proposed fix (report only — do not implement in this pass):**

1. Keep leak filter for paths, PEM, `CN=`, `stored cert`, raw renewal token **values**.
2. Add a small **classifier** (substring or structured) that maps known agent/worker phrases to **fixed safe copy**, e.g.:
   - consumed → `This enrollment token was already used. Create a new one.`
   - expired token / enrollment expired → `This enrollment code or token expired. Start again.`
   - invalid token → `That enrollment token is invalid.`
   - rate_limited / `rate limit exceeded` → `Too many attempts. Wait a minute and try again.`
   - connection/refused/unreachable/timeout → keep network-ish copy
   - else → generic (still no raw log dump)
3. Optionally pass exit code / a machine-readable `enroll: error=<code>` line from the agent later.

Fixture test `enroll_failure_resilience_distinctions` in `parse.rs` documents today’s collapse so a fix can flip assertions.

### 11. Discarded Results on auth / connection paths

#### `hookdeployed`

| Location | Discard | Risk |
| --- | --- | --- |
| `settleRejection`: `orgID, _ := store.ReadActive` | IO error ignored | Usually falls through cleanup |
| `handleControl`: `_ = json.Decode` | Bad body → empty reason | Still terminal “Not retrying” |
| `attemptRenew` / `attemptReport` | Errors logged or silent skip | Renew auth death not terminal (B2) |
| `tryOpenURL`: `_ = cmd.Start()` | Browser open | Non-auth |
| `tap.Start`: `_ = wait(ctx)` | Wait error ignored | Stop still attempted |

#### `hookdeploy-tray`

| Location | Discard | Risk |
| --- | --- | --- |
| Tray Connect/Disconnect: `let _ = start_connect/stop_connect` | Errors dropped | Silent connect failure |
| Quit: `let _ = shutdown_all` | Errors dropped | Taps/connect may linger |
| `confirm_server_tap_stop`: `Err(_)` → fixed string | Real cause lost | R3 |
| Unenroll path: list failure → `Ok(vec![])` | Looks like success/empty | Confusing post-unenroll UI |
| Connect watch `CommandEvent::Error` | Empty arm | Silent |
| `main.ts` `refreshOrgs` `catch { orgs=[]; setAuthed(false) }` | List failure → enroll gate | False “not enrolled” |
| Emit / kill / channel sends | Fire-and-forget | Lower |

---

## Part C — fixture-based tests added

### New / extended tests

| Test | Package | Asserts |
| --- | --- | --- |
| `TestTokenAlreadyConsumedFailsOnceDistinctly` | `enroll` | 401 message; **exactly one** HTTP hit |
| `TestTokenExpiredFailsOnceDistinctly` | `enroll` | Distinct from consumed |
| `TestTokenInvalidFailsOnceDistinctly` | `enroll` | Distinct message |
| `TestRenewalTokenExpiredSurfacesMessage` | `enroll` | Renew 401 message |
| `TestRenewalTokenRevokedSurfacesMessage` | `enroll` | Renew 401 message |
| `TestPlacementRateLimitedDistinctFromAuth` | `enroll` | 429 `rate_limited` ≠ unauthorized |
| `TestCertNotYetValidDistinctFromExpired` | `enroll` | Two leaf-renew messages |
| `TestDevicePollExpiredStatusFailsCleanly` | `enroll` | `enrollment expired`; one poll |
| `TestDevicePollDeniedFailsCleanly` | `enroll` | `enrollment denied` |
| `TestDeviceEnrollmentDeadlineExpiresWithoutIndefiniteHang` | `enroll` | Deadline &lt;5s; no hang |
| `TestNetworkUnreachableIsNotAPIError` | `enroll` | Dial error ≠ APIError |
| `TestShouldRenewTreatsNotYetValidAsRenewNeeded` | `enroll` | Skew renew trigger |
| `TestUnauthorizedPlacementRetriesWithBackoffCeiling` | `connect` | Dead renew → **≥3** placement retries + backoff logs (**documents B2**) |
| `TestNextBackoffCapsAtThirtySeconds` | `connect` | Cap math |
| `enroll_failure_resilience_distinctions` | tray `parse.rs` | Documents tray collapse (**B1**) |

**Already covered (pre-existing):** revoked no-retry (`reconnect_test` / `connect_test`); tap 429 message preserve (`TestEveryP1ErrorRendersItsMessage`); failed renew does not block dial (`TestFailedRenewDoesNotBlockDial`).

### Results (this machine)

```
go test ./internal/enroll/ ./internal/connect/ -run '…resilience fixtures…'
ok  enroll
ok  connect
```

Tray: `enroll_failure_resilience_distinctions` added in `parse.rs`. **`cargo` was not available on this Windows PATH**, so tray tests were not executed here — run `cargo test enroll_failure` in `hookdeploy-tray/src-tauri` before merge.

---

## Part D — live chaos checklist (manual)

**Status: NOT RUN against live infra in this audit pass.**  
Expected behavior below is from code; fill “Actual” when executing.

| # | Scenario | Expected (from code) | Actual |
| --- | --- | --- | --- |
| 13 | Enroll, revoke from dashboard while `connect` running | Agent gets control `revoked`, deletes creds, logs revoke message, **stops reconnecting**; tray → Revoked | *pending* |
| 14 | Wi-Fi drop mid-tap, then reconnect | Connect: disconnect → reconnect with backoff/immediate rules; tap traffic may fail locally until up; server tap may linger until expiry if agent gone long enough | *pending* |
| 15 | Sleep extended, then wake | `IsWakeEvent` triggers renew; if renewal still valid → reconnect; if renewal expired during sleep → **B2** (retry forever / no re-enroll prompt) | *pending* — watch for B2 |
| 16 | Double enroll same OTT | Second: CLI `token already consumed`; tray likely **generic check your connection** (B1) | *pending* |
| 17 | Force-quit tray while tap active | Local tap process dies with tray/sidecar; server tap until **expiry (configured duration, often up to 8h)** or agent disconnect detection — measure wall clock | *pending* — record observed window |
| 18 | Uninstall/reinstall without clearing creds | Agent/tray should find existing cert dir and reconnect if still valid; if paths differ by installer → may look unenrolled | *pending* |

---

## Suggested fix order (for a follow-up session)

1. **Tray enroll classifier** (B1) — highest user-visible payoff, small surface.
2. **Terminal renew/placement auth death in `connect.Run`** (B2) — stop + clear message to re-enroll; treat 401 renew messages like revoke for loop purposes (but keep credentials policy explicit).
3. **Map TLS not-yet-valid / expired dial errors** to distinct copy + consider terminal or slow-backoff (B3).
4. Cert-dir lock or single-writer rule (R1).
5. Surface discarded tray connect/stop errors (R2).

Do not batch all of these into the same PR as this report.
