# APT repository — build infrastructure (manual-first)

**Date:** 2026-08-29

**Mode:** files written; **nothing deployed, uploaded, signed in CI, or executed
as a publish step.** No GitHub Actions changes. No signing-key material appears
in any file this pass created.

| | `hookdeployed` | `platform` |
| --- | --- | --- |
| This pass | packaging + `install.sh` refactor | new `apt-worker/` |
| Not done | `build-apt-repo.sh` not run | no `wrangler deploy`, no bucket create |

Prior design: `docs/apt-repo-design.md`.

---

## Part 1 — `platform/apt-worker`

Directory name matches siblings `api-worker/`, `enrollment-worker/`,
`cron-worker/` (not `relay-manager`, which is the one hyphenated service
name without `-worker`). Worker script name is `hookdeploy-apt`, same
`hookdeploy-<role>` scheme as `hookdeploy-mcp` / `hookdeploy-enrollment`.

### `wrangler.toml` (full)

```
name = "hookdeploy-apt"
main = "src/index.ts"
compatibility_date = "2026-08-29"
compatibility_flags = ["nodejs_compat"]
logpush = true

[observability]
enabled = true

# Public APT repo objects. Do not bind payload, audit-log, or
# email-signature buckets here.
[[r2_buckets]]
binding = "APT"
bucket_name = "hookdeploy-apt"

[[routes]]
pattern = "apt.hookdeploy.dev/*"
zone_name = "hookdeploy.dev"

# DNS: Add CNAME apt.hookdeploy.dev -> hookdeploy.dev (proxied ON)
# Public package repository (InRelease, Packages, .deb).
```

House-pattern check against `relay-manager/wrangler.toml`:

| Field | relay-manager | apt-worker |
| --- | --- | --- |
| `name` / `main` / `compatibility_flags` / `logpush` | yes | yes |
| `[observability] enabled = true` | yes (top) | yes (top) |
| `[[routes]]` `pattern` + `zone_name = "hookdeploy.dev"` | `relay-manager.hookdeploy.dev/*` | `apt.hookdeploy.dev/*` |
| `# DNS: Add CNAME … -> hookdeploy.dev (proxied ON)` | line 67 | same comment |
| Extra bindings | DOs, VPC, KV | **only** `[[r2_buckets]]` `APT` → `hookdeploy-apt` |

`compatibility_date` is today (`2026-08-29`) because this is a new Worker;
relay-manager still has `2024-09-23`. Structure is the same TOML shape, not
the SPA `wrangler.jsonc` + `assets.not_found_handling` pattern.

**Not run:** `wrangler deploy`.

### Worker (`src/index.ts`)

Thin R2 object server: pathname → `env.APT.get(key)`,
`writeHttpMetadata` + etag, stream `object.body`, 404 on miss / bad path.
GET and HEAD only (APT clients HEAD). No SPA fallback, no directory listing,
no `/health`. `..` and `\` rejected. Empty path (`/`) is 404.

### Manual steps the human still runs (not this pass)

**1. Create the bucket** (do not reuse payload / audit / email-signature):

```
npx wrangler r2 bucket create hookdeploy-apt
```

Run from `platform/apt-worker/` after `npm install` (or from any dir with
wrangler, with `CLOUDFLARE_API_TOKEN` / account pointing at prod).

**2. DNS in the Cloudflare dashboard** (zone `hookdeploy.dev`), same comment
as relay-manager — wrangler `[[routes]]` does **not** create this record by
itself:

| Type | Name | Target | Proxy |
| --- | --- | --- | --- |
| CNAME | `apt` | `hookdeploy.dev` | Proxied (orange cloud) ON |

Full name: `apt.hookdeploy.dev` → `hookdeploy.dev`.

**3. Deploy the Worker** (after reviewing this tree):

```
cd platform/apt-worker
npm install
npx wrangler deploy
```

(`package.json` `"deploy": "wrangler deploy"` exists so this matches other
workers; **not invoked here**.)

**4. Optional:** `npx wrangler types` in that directory to replace the
hand-written `Env` with a generated one (house Workers often hand-write
`Env`; skill preference is generated types).

---

## Part 2 — shared install logic

### `packaging/lib/install-common.sh`

Canonical helpers (sourced by `install.sh` from a checkout and by the
`.deb` `postinst` from `/usr/share/hookdeployed/install-common.sh`):

| Symbol | Role |
| --- | --- |
| `SERVICE_USER`, `CERT_DIR`, `STATE_DIR` | defaults match old `install.sh` |
| `ensure_user` | same `useradd --system --no-create-home --home-dir … --shell <nologin>` |
| `ensure_state_dirs` | `mkdir -p` certs; `chown` / `chmod 0755` / `0700`; dry-run log unchanged |
| `already_enrolled` | `active` + `client.key` |
| `enroll_with_token <bin> <token>` | enroll as service user; enable `--now` + restart |
| `print_no_token_instructions <bin> [hint]` | same four log/cat lines; `<bin>` is the path printed |

`log` / `die` / `run` are only defined if the caller did not already define
them. `install.sh` keeps `hookdeployed-install:` prefixes.

### `curl | bash` fallback

A piped install has no `packaging/lib/` on disk. `install.sh` sources the
file when `BASH_SOURCE` resolves to a checkout; otherwise it sources an
inlined copy via a heredoc attached to `. /dev/stdin` (does **not** steal
the `curl` pipe).

Checked this pass: the heredoc body is **byte-identical** to
`packaging/lib/install-common.sh` (CR-normalized compare; both 3821 bytes).
Keep them in sync if either changes.

### `install.sh` behavior — unchanged for the supported paths

Unchanged:

| Item | Value |
| --- | --- |
| Binary | `/usr/local/bin/hookdeployed` |
| Unit dest | `/etc/systemd/system/hookdeployed.service` |
| Unit contents | still `ExecStart=/usr/local/bin/hookdeployed connect` |
| Flags / env | `--token`, `--version`, `--dry-run`, `HOOKDEPLOYED_*` |
| Help text | same `usage()` heredoc |
| Download / checksum / `install -m 0755` | same |
| No-token last line | `… re-run with --token.` (default hint) |
| Token success last line | `installed ${INSTALL_PATH} and started hookdeployed.service` |
| Exit 0 after token path | same |
| Root check, Linux-only, arch map | same |

Control flow after the binary is in place:

```
ensure_user
ensure_state_dirs          # was inline mkdir/chown/chmod
write_unit …
daemon-reload
if token: enroll_with_token /usr/local/bin/hookdeployed "$TOKEN"
           log installed … started; exit 0
else:     log installed PATH and UNIT_PATH
          print_no_token_instructions /usr/local/bin/hookdeployed
```

Dry-run enroll still prints `run sudo -u hookdeployed env HOOKDEPLOY_CERT_DIR=… enroll -token …`.
Live enroll still runs `sudo -u …` when `sudo` exists (always true for
`sudo bash` / `sudo ./install.sh`).

**Only intentional delta:** if `sudo` is **missing**, live enroll now tries
`runuser` then `su` so Debian `postinst` works on a sudo-less root. That
branch is not the curl-install path.

`bash -n` was **not run** — this host has no working bash (WSL `execvpe(bash)`
failed; Git Bash not installed), same constraint as
`docs/linux-distribution-build.md`.

---

## Part 3 — `packaging/debian/` (file by file)

Not a dh/debhelper source package. `packaging/build-apt-repo.sh` copies these
into a `DEBIAN/` + `usr/` tree and runs `dpkg-deb --build`.

### `control` (template)

Placeholders substituted per architecture at build time:

- `__VERSION__` → `0.1.0-1` (`--version` + `--revision`)
- `__ARCH__` → `amd64` or `arm64` (Debian names; same as Go `GOARCH`)
- `__INSTALLED_SIZE__` → `du -sk usr`

One template, two `.deb`s. No second control file.

`Depends: adduser, debconf (>= 0.5)`. `Recommends: ca-certificates`.
No `${misc:Depends}` (we are not running debhelper). No hard `Depends:
systemd`.

### `hookdeployed.service`

Same unit body as `packaging/hookdeployed.service` except:

```
ExecStart=/usr/bin/hookdeployed connect
```

**Installed by `dpkg`** at `/usr/lib/systemd/system/hookdeployed.service`
(data tarball). `postinst` does **not** rewrite it — that is the correct
package-managed path. (`install.sh` still writes
`/etc/systemd/system/` + `/usr/local/bin`.)

### `hookdeployed.templates` + `hookdeployed.config`

`Type: string`, empty default. Config does
`db_get` first and only `db_input medium` when the value is empty, so a
preseeded token is never sent through a frontend widget. A normal
`apt install` (priority **high**) **does not prompt**. `string` rather
than `password`: real tokens are 77–79 characters (`hd_enroll_<region>_`
+ 64 hex) and password-type fields/widgets have historically truncated
or rewritten values; this field is meant for unattended preseed, not
interactive secret entry (`dpkg-reconfigure` will echo the token).

### `postinst`

Sources `/usr/share/hookdeployed/install-common.sh` (shipped in the
`.deb`). Never downloads. On `configure`:

1. `ensure_user` + `ensure_state_dirs`
2. `systemctl daemon-reload`
3. Token from `HOOKDEPLOYED_TOKEN` or debconf `hookdeployed/enroll_token`
4. Token present → `enroll_with_token /usr/bin/hookdeployed`. Success
   clears the debconf value. Failure is logged and falls through to
   manual-enroll instructions — **never a dpkg error**.
5. Else if already enrolled **and** unit enabled → `restart` (upgrade)
6. Else → `print_no_token_instructions /usr/bin/hookdeployed` with an
   apt-specific unattended hint (preseed / `HOOKDEPLOYED_TOKEN`)

Default `apt install hookdeployed` hits branch 6: **no start**.

### `prerm`

Stop on `remove|upgrade|deconfigure`. Needed because `postrm` runs
**after** the unit file is gone. (Extra vs the request’s postrm-only
list; stop-on-remove does not work reliably without it.)

### `postrm`

- `remove`: stop/disable, **keep** `/var/lib/hookdeployed`
- `purge`: disable, `rm -rf /var/lib/hookdeployed`, `userdel` if present,
  `db_purge`

---

## Part 4 — architecture-specific `.deb` build

`packaging/build-apt-repo.sh` (not run this pass):

1. Expects `dist/build/linux-amd64/hookdeployed` and
   `dist/build/linux-arm64/hookdeployed` (same layout as
   `.github/workflows/release.yml` `dist/build/${goos}-${goarch}`).
2. For each arch `amd64` / `arm64`:
   - stage `usr/bin/hookdeployed` from `linux-${arch}/hookdeployed`
   - stage unit, `install-common.sh`, maintainer scripts
   - `sed` the single `control` template
   - `dpkg-deb --root-owner-group --build` →
     `pool/main/h/hookdeployed/hookdeployed_${VER}_${arch}.deb`
3. `dpkg-scanpackages -a ${arch} pool /dev/null` so each
   `binary-<arch>/Packages` lists only that arch
4. `apt-ftparchive -c packaging/apt-ftparchive.conf release` in
   `dists/stable/`
5. `gpg --clearsign --local-user "$KEY"` → `InRelease`
   and `gpg --detach-sign --armor --local-user "$KEY"` → `Release.gpg`
6. Print `wrangler r2 object put` lines — **does not execute them**

`--key` is a fingerprint or email already in the **invoking user’s**
GPG keyring. The script never writes a key file, never asks for a
private key to be pasted, never embeds key material.

### Output tree (minimal valid APT repo)

```
dist/apt-repo/
  dists/stable/Release
  dists/stable/InRelease
  dists/stable/Release.gpg
  dists/stable/main/binary-amd64/Packages
  dists/stable/main/binary-amd64/Packages.gz
  dists/stable/main/binary-arm64/Packages
  dists/stable/main/binary-arm64/Packages.gz
  pool/main/h/hookdeployed/hookdeployed_<ver>_amd64.deb
  pool/main/h/hookdeployed/hookdeployed_<ver>_arm64.deb
```

This is the `dists/stable` + `pool/main/h/hookdeployed` shape from the
design (not a flat `[trusted=yes]` dump). `apt` accepts it with:

```
deb [signed-by=/usr/share/keyrings/hookdeployed.gpg] https://apt.hookdeploy.dev stable main
```

### `build-apt-repo.sh` in full

The committed script is `packaging/build-apt-repo.sh` (253 lines). It is
not duplicated here to avoid a second copy that can drift; read that
file. Behavior in order:

1. Require `--version` and `--key` (keyring id only).
2. Resolve `dist/build/linux-{amd64,arm64}/hookdeployed`.
3. `build_deb` for each arch → `pool/main/h/hookdeployed/*.deb`.
4. `dpkg-scanpackages -a` + `gzip` per arch.
5. `apt-ftparchive release` → `Release`.
6. `gpg --clearsign --local-user "$KEY"` → `InRelease`;
   `gpg --detach-sign --armor --local-user "$KEY"` → `Release.gpg`.
7. Print `npx wrangler r2 object put hookdeploy-apt/<path> …` for every
   file. **Does not run them.**
8. Print commented public-key export/upload lines (you run `gpg --export`;
   the script does not).

---

## Manual sequence (human, after review)

```
# 0. Binaries (local or unpacked release tarballs)
mkdir -p dist/build/linux-amd64 dist/build/linux-arm64
# either:
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X github.com/hookdeploy/hookdeployed/internal/version.Version=0.1.0" -o dist/build/linux-amd64/hookdeployed ./cmd/agent
#   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "…" -o dist/build/linux-arm64/hookdeployed ./cmd/agent
# or extract hookdeployed from hookdeployed_v0.1.0_linux_{amd64,arm64}.tar.gz

# 1. Sign + package (uses YOUR local keyring; replace the id)
#    Do this on Linux/WSL with dpkg-dev, apt-utils, gnupg.
packaging/build-apt-repo.sh --version 0.1.0 --key security@hookdeploy.dev

# 2. Review dist/apt-repo/{dists,pool}

# 3. Upload objects with the printed `npx wrangler r2 object put …` lines
#    plus the public-key command the script prints (you export; it does not).

# 4. Fresh Debian/Ubuntu VM:
#    curl -fsSL https://apt.hookdeploy.dev/hookdeployed.gpg | sudo gpg --dearmor -o /usr/share/keyrings/hookdeployed.gpg
#    echo "deb [signed-by=/usr/share/keyrings/hookdeployed.gpg] https://apt.hookdeploy.dev stable main" | sudo tee /etc/apt/sources.list.d/hookdeployed.list
#    sudo apt update && sudo apt install hookdeployed
#    # expect: installed, service NOT started
#    # then enroll / enable, and separately test preseed + remove vs purge
```

---

## Final checklist (none of this pass)

| # | Action | Who |
| --- | --- | --- |
| 1 | Review Worker + packaging diffs | human |
| 2 | `npx wrangler r2 bucket create hookdeploy-apt` | human |
| 3 | DNS: CNAME `apt.hookdeploy.dev` → `hookdeploy.dev`, proxied ON | human (dashboard) |
| 4 | `cd platform/apt-worker && npm install && npx wrangler deploy` | human |
| 5 | Export **public** key; upload `hookdeploy-apt/hookdeployed.gpg` | human |
| 6 | Build linux amd64 + arm64 binaries | human |
| 7 | `packaging/build-apt-repo.sh --version … --key <id>` | human (local GPG) |
| 8 | Review `dist/apt-repo/` | human |
| 9 | Run the printed `wrangler r2 object put` commands | human |
| 10 | VM: `apt update && apt install hookdeployed` (no token, no start); enroll; preseed; `remove` vs `purge` | human |

**Not this pass:** CI secrets, `release.yml` changes, key generation, deploy,
bucket create, upload, VM test.

---

## Diff summary

### `platform` (new)

```
apt-worker/wrangler.toml
apt-worker/src/index.ts
apt-worker/package.json
apt-worker/tsconfig.json
```

No other `platform` files were modified for this work. (`deploy-production.yml`
was **not** updated — deploy stays manual.)

### `hookdeployed` (modified)

```
.gitattributes          # LF for packaging/**/*.sh and packaging/debian/*
install.sh              # source install-common.sh; paths unchanged
```

### `hookdeployed` (new)

```
packaging/lib/install-common.sh
packaging/debian/control
packaging/debian/postinst
packaging/debian/prerm
packaging/debian/postrm
packaging/debian/hookdeployed.config
packaging/debian/hookdeployed.templates
packaging/debian/hookdeployed.service
packaging/apt-ftparchive.conf
packaging/build-apt-repo.sh
docs/apt-repo-build.md          # this file
```

`install.sh` diff shape: constants `SERVICE_USER`/`CERT_DIR`/`STATE_DIR`
moved into the lib (same values); inline `ensure_user` / `already_enrolled` /
mkdir-chown / token enroll / no-token `cat` replaced by calls to the lib.
Download, unit embed, `/usr/local/bin`, `/etc/systemd/system` untouched.

STOP. No deploy, no upload, no key material, no workflow changes.
