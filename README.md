# hookdeployed

**The HookDeploy agent.** A small, single-binary client that receives your production webhooks on
your own machine — your laptop, a staging box, a server behind a firewall — without opening a single
inbound port.

```
curl -fsSL https://raw.githubusercontent.com/hookdeploy/hookdeployed/main/install.sh | sudo bash -s -- --token <your-token>
```

That's it. Get a token from your [HookDeploy dashboard](https://app.hookdeploy.dev), run the command
above on any Linux box, and webhooks configured to hit that agent start arriving locally — instantly,
securely, with nothing to expose.

---

## Why this exists

Webhooks are usually a pain to develop against. You either expose your laptop to the internet with a
tunnel tool, or you deploy just to test a callback, or you wire up ngrok and hope the URL doesn't
change mid-demo. In production it's worse: you often *can't* expose an internal service just to
receive a webhook, so you end up building a public-facing receiver you didn't really want.

`hookdeployed` solves this differently. It dials **out** to HookDeploy's relay network over a mutually
authenticated TLS connection and holds that connection open. Your machine never listens on a public
port. Webhooks captured at the edge get streamed down that same connection and delivered to a local
port you choose. From the outside, your machine is invisible — there's nothing to scan, nothing to
attack, nothing to firewall.

This repo is the client. It's small on purpose: enroll, connect, stay connected, deliver. Everything
else — capture, transformation, routing, retries — happens on HookDeploy's infrastructure and isn't
part of what runs on your machine.

## How it works, briefly

1. **Enroll** — the agent authenticates to HookDeploy and receives a short-lived certificate plus a
   long-lived renewal credential, scoped to your organization.
2. **Connect** — it dials a relay over mTLS, gets assigned to the nearest healthy one automatically
   (or a specific region/relay if you ask), and holds the connection open.
3. **Renew** — certificates rotate automatically, well before expiry, without dropping the
   connection.
4. **Receive** — a webhook destined for this agent arrives over the open connection and is forwarded
   to `127.0.0.1:<port>` on your machine, exactly as it was received (or after your configured
   transformation, if you're tapping a real destination rather than receiving raw).

If your machine goes offline, the connection drops and reconnects automatically the moment it's back
— no manual re-authentication, no babysitting.

## Install

### Non-interactive (servers, CI, provisioning scripts)

Generate a one-time enrollment token from the dashboard, then:

```bash
curl -fsSL https://raw.githubusercontent.com/hookdeploy/hookdeployed/main/install.sh \
  | sudo bash -s -- --token hd_enroll_...
```

This installs the binary, creates a dedicated non-root `hookdeployed` system user, sets up and
enables a systemd service, enrolls, and starts the agent — fully unattended.

### Interactive (your own machine)

```bash
curl -fsSL https://raw.githubusercontent.com/hookdeploy/hookdeployed/main/install.sh | sudo bash
```

With no token, the installer sets up the binary and service but doesn't start it yet. Run:

```bash
sudo hookdeployed enroll
```

and follow the printed URL to approve the agent in your browser (this needs a real terminal — it
won't work piped through `curl`). Then:

```bash
sudo systemctl enable --now hookdeployed
```

### Manual / other platforms

Grab a binary directly from [Releases](../../releases) — Linux (amd64/arm64), macOS
(amd64/arm64), and Windows (amd64) are all built on every release. `install.sh` currently automates
Linux only; on macOS or Windows, download the binary and run `hookdeployed enroll` / `hookdeployed
connect` directly.

## Usage

```
hookdeployed enroll                          interactive enrollment (device-code, opens a browser)
hookdeployed enroll --token <token>          non-interactive enrollment
hookdeployed connect                         connect and stay connected, auto-assigned relay
hookdeployed connect --region us-east        prefer a specific region
hookdeployed connect --relay <host:port>     pin a specific relay
hookdeployed list                            show enrolled organizations
hookdeployed switch                          switch the active organization
hookdeployed unenroll                        remove this machine from an organization
hookdeployed tap <endpoint-id> [<dest-id>] --port N --path /p   mirror live traffic locally
hookdeployed tap list                        show what's available to tap, and active taps
hookdeployed tap stop [id]                   end a tap early
```

Run any command with no arguments, or `--help`, for the current flag set and usage text — this
README describes the shape of the CLI, but the binary itself is the source of truth for exact syntax.

### Taps

`tap` is a debugging tool: point a live production endpoint or destination at your local machine
*temporarily*, without touching the real configuration. You see exactly what a real destination
receives — or the raw, untransformed payload, if you tap the endpoint directly — while production
delivery continues completely unaffected. Taps expire automatically (max 8 hours) and end the moment
your agent disconnects.

## Multi-organization support

One agent, multiple organizations. If you work across several HookDeploy orgs, enroll into each —
credentials are stored separately — and use `hookdeployed switch` to change which one is active.
Only the active organization's traffic is delivered at a time.

## Security model

- **No inbound ports, ever.** The agent only ever makes outbound connections. There is nothing to
  scan, port-forward, or expose.
- **Mutual TLS**, not a shared secret or API key sitting in a config file. The agent's identity is a
  certificate, rotated automatically well before it would ever expire.
- **Short-lived certificates, long-lived renewal credential.** If a laptop is lost or an old
  credential leaks, the exposure window for the actual connecting credential is small; the renewal
  credential itself is scoped and revocable from the dashboard, and revocation takes effect within
  seconds — connected sessions are actively terminated, not just left to expire.
- **You choose the destination port and path.** The agent never picks where traffic lands on your
  machine, and it only ever talks to `127.0.0.1` — it cannot be instructed to forward anywhere else
  on your network.
- **Fully open to inspection.** This entire client — everything that runs on your machine — is in
  this repository. Nothing about how it authenticates, connects, or delivers traffic is hidden.

Found a security issue? Please report it to **security@hookdeploy.dev** rather than opening a public
issue.

## Building from source

Requires Go 1.26+.

```bash
git clone https://github.com/hookdeploy/hookdeployed.git
cd hookdeployed
go build -o hookdeployed ./cmd/agent
```

Cross-compiling follows normal `GOOS`/`GOARCH` conventions — `CGO_ENABLED=0` and no cgo
dependencies, so it builds cleanly for Linux, macOS, and Windows from any of them.

## License

`hookdeployed` is source-available under the [Business Source License 1.1](./LICENSE).

In plain terms: you can read it, build it, modify it, self-host it, and use it for anything —
including running it in production for your own business — for free. The one thing it restricts is
offering this code, or a modified version of it, to third parties as a **competing hosted webhook
service**. On **2030-08-28**, this license automatically converts to Apache 2.0 for the version
released on that date, and every version becomes fully open source four years after its own release.

This isn't a trick to look open while staying closed — it's the same model used by HashiCorp,
Sentry, CockroachDB, and others for exactly this reason: you get real, inspectable source, and we get
to keep building the company that maintains it.

Questions about licensing or alternative arrangements: **support@hookdeploy.dev**

## Support

- Docs: [hookdeploy.dev/docs](https://hookdeploy.dev/docs)
- Dashboard: [app.hookdeploy.dev](https://app.hookdeploy.dev)
- Email: support@hookdeploy.dev
