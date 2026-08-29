#!/usr/bin/env bash
# Behavior tests for packaging/apt-install.sh. No network, no real apt.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SCRIPT="${ROOT}/packaging/apt-install.sh"
[ -f "${SCRIPT}" ] || { printf 'missing %s\n' "${SCRIPT}" >&2; exit 1; }

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

run_wrapper() {
  local tmp="$1"
  shift
  HOOKDEPLOYED_APT_DRY_RUN=1 \
    HOOKDEPLOYED_KEYRING="${tmp}/hookdeployed.gpg" \
    HOOKDEPLOYED_SOURCES_LIST="${tmp}/hookdeployed.list" \
    HOOKDEPLOYED_PRESEED_LOG="${tmp}/preseed" \
    HOOKDEPLOYED_APT_BASE="https://apt.hookdeploy.dev" \
    bash "${SCRIPT}" "$@"
}

# --- flag wins over env (same as repo-root install.sh) ---
tmp="$(mktemp -d)"
HOOKDEPLOYED_TOKEN="from-env" run_wrapper "${tmp}" --token "from-flag" >/dev/null
grep -q 'string from-flag$' "${tmp}/preseed" || fail "flag should win over HOOKDEPLOYED_TOKEN"
grep -q 'from-env' "${tmp}/preseed" && fail "env token leaked when --token set"
rm -rf "${tmp}"

# --- env alone ---
tmp="$(mktemp -d)"
HOOKDEPLOYED_TOKEN="from-env-only" run_wrapper "${tmp}" >/dev/null
grep -q 'string from-env-only$' "${tmp}/preseed" || fail "HOOKDEPLOYED_TOKEN should preseed"
rm -rf "${tmp}"

# --- --token= form ---
tmp="$(mktemp -d)"
run_wrapper "${tmp}" --token="equals-form" >/dev/null
grep -q 'string equals-form$' "${tmp}/preseed" || fail "--token= should work"
rm -rf "${tmp}"

# --- trailing CR stripped before preseed ---
tmp="$(mktemp -d)"
cr=$'hd_enroll_us_abc\r'
run_wrapper "${tmp}" --token "${cr}" >/dev/null
got="$(cat "${tmp}/preseed")"
printf '%s\n' "${got}" | grep -q $'\r' && fail "CR should be stripped from preseed line"
printf '%s\n' "${got}" | grep -q 'string hd_enroll_us_abc$' || fail "stripped token missing from preseed"
rm -rf "${tmp}"

# --- no token, non-TTY: must not read stdin, must not hang, no preseed ---
tmp="$(mktemp -d)"
printf 'SHOULD_NOT_BE_READ\n' > "${tmp}/stdin"
out="$(HOOKDEPLOYED_FORCE_TTY=0 run_wrapper "${tmp}" < "${tmp}/stdin")"
[ ! -f "${tmp}/preseed" ] || fail "non-TTY no-token must not preseed"
printf '%s\n' "${out}" | grep -q "no token given" || fail "non-TTY should print instructions"
printf '%s\n' "${out}" | grep -q "dry-run: apt install" || fail "non-TTY should still install"
rm -rf "${tmp}"

# --- no token, TTY, empty input → no-token path ---
tmp="$(mktemp -d)"
out="$(printf '\n' | HOOKDEPLOYED_FORCE_TTY=1 run_wrapper "${tmp}" 2>&1)"
[ ! -f "${tmp}/preseed" ] || fail "empty TTY input must not preseed"
printf '%s\n' "${out}" | grep -q "Enter your HookDeploy enrollment token" || fail "TTY should prompt"
printf '%s\n' "${out}" | grep -q "dry-run: apt install" || fail "empty TTY skip should still install"
rm -rf "${tmp}"

# --- TTY + typed token ---
tmp="$(mktemp -d)"
out="$(printf 'typed-token\n' | HOOKDEPLOYED_FORCE_TTY=1 run_wrapper "${tmp}" 2>&1)"
grep -q 'string typed-token$' "${tmp}/preseed" || fail "TTY prompt token should preseed"
rm -rf "${tmp}"

# --- sources.list overwrite is a single line (idempotent) ---
tmp="$(mktemp -d)"
run_wrapper "${tmp}" >/dev/null
run_wrapper "${tmp}" >/dev/null
lines="$(grep -c '^deb ' "${tmp}/hookdeployed.list" || true)"
[ "${lines}" = 1 ] || fail "second run must not duplicate sources (got ${lines} deb lines)"
rm -rf "${tmp}"

# --- independence: this file must not source or embed the tarball installer ---
if grep -q 'install-common.sh' "${SCRIPT}"; then
  fail "apt-install.sh must not source install-common.sh"
fi
if grep -q 'api.github.com/repos' "${SCRIPT}"; then
  fail "apt-install.sh must not use the GitHub releases installer path"
fi
if grep -q '/usr/local/bin' "${SCRIPT}"; then
  fail "apt-install.sh must not install to /usr/local/bin (that is the tarball path)"
fi

printf 'ok\n'
