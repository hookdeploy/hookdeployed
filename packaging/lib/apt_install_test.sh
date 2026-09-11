#!/usr/bin/env bash
# Behavior tests for packaging/apt-install.sh. No network, no real apt.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
SCRIPT="${ROOT}/packaging/apt-install.sh"
FIXTURE="${ROOT}/packaging/fixtures/apt-r2-layout.json"
[ -f "${SCRIPT}" ] || { printf 'missing %s\n' "${SCRIPT}" >&2; exit 1; }

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

[ -f "${FIXTURE}" ] || fail "missing cross-repo fixture ${FIXTURE}"

# Paths packaging/apt-install.sh fetches over HTTP (${APT_BASE}/… in curl / dry-run logs).
extract_installer_http_paths() {
  grep -oE '\$\{APT_BASE\}/[^" |]+' "${SCRIPT}" \
    | sed 's/\${APT_BASE}\///' \
    | sort -u
}

run_wrapper() {
  local tmp="$1"
  shift
  HOOKDEPLOYED_APT_DRY_RUN=1 \
    HOOKDEPLOYED_KEYRING="${tmp}/hookdeployed.gpg" \
    HOOKDEPLOYED_SOURCES_LIST="${tmp}/hookdeployed.list" \
    HOOKDEPLOYED_PRESEED_LOG="${tmp}/preseed" \
    HOOKDEPLOYED_APT_BASE="https://apt.hookdeploy.dev" \
    HOOKDEPLOYED_FORCE_TTY="${HOOKDEPLOYED_FORCE_TTY:-}" \
    bash "${SCRIPT}" "$@"
}

# --- flag wins over env (same as repo-root install.sh) ---
tmp="$(mktemp -d)"
HOOKDEPLOYED_TOKEN="from-env" run_wrapper "${tmp}" --token "from-flag" >/dev/null
grep -q 'string from-flag$' "${tmp}/preseed" || fail "flag should win over HOOKDEPLOYED_TOKEN"
if grep -q 'from-env' "${tmp}/preseed"; then
  fail "env token leaked when --token set"
fi
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
if printf '%s\n' "${got}" | grep -q $'\r'; then
  fail "CR should be stripped from preseed line"
fi
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
# bash `read -p` only displays the prompt when stdin is a real terminal, so a
# piped FORCE_TTY=1 run still takes the read path but will not emit the prompt
# text. Assert the skip/install behavior instead.
tmp="$(mktemp -d)"
out="$(printf '\n' | HOOKDEPLOYED_FORCE_TTY=1 run_wrapper "${tmp}" 2>&1)"
[ ! -f "${tmp}/preseed" ] || fail "empty TTY input must not preseed"
printf '%s\n' "${out}" | grep -q "no token given" || fail "empty TTY skip should print instructions"
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

# --- cross-repo R2 layout contract (mirror: platform/apt-worker/fixtures/apt-r2-layout.json) ---
command -v jq >/dev/null 2>&1 || fail "jq required for apt-r2-layout fixture contract tests"

fixture_paths="$(jq -r '.installerHttpPaths[]' "${FIXTURE}" | sort)"
script_paths="$(extract_installer_http_paths)"
if [ "$(printf '%s\n' "${fixture_paths}" | sed '/^$/d' | wc -l)" \
  -ne "$(printf '%s\n' "${script_paths}" | sed '/^$/d' | wc -l)" ]; then
  fail "installer HTTP path count mismatch between apt-install.sh and fixture"
fi
while IFS= read -r path; do
  [ -n "${path}" ] || continue
  printf '%s\n' "${script_paths}" | grep -qx "${path}" \
    || fail "apt-install.sh missing fixture installer path: ${path}"
done <<EOF
${fixture_paths}
EOF
while IFS= read -r path; do
  [ -n "${path}" ] || continue
  printf '%s\n' "${fixture_paths}" | grep -qx "${path}" \
    || fail "fixture missing apt-install.sh installer path: ${path}"
done <<EOF
${script_paths}
EOF

tmp="$(mktemp -d)"
out="$(run_wrapper "${tmp}")"
while IFS= read -r path; do
  [ -n "${path}" ] || continue
  printf '%s\n' "${out}" | grep -q "dry-run: curl -fsSL https://apt.hookdeploy.dev/${path}" \
    || fail "dry-run missing curl URL for ${path}"
done <<EOF
${fixture_paths}
EOF

suite="$(jq -r '.aptSuite' "${FIXTURE}")"
component="$(jq -r '.aptComponent' "${FIXTURE}")"
grep -q "deb \\[signed-by=.*\\] https://apt.hookdeploy.dev ${suite} ${component}\$" "${tmp}/hookdeployed.list" \
  || fail "sources.list must use fixture suite/component (${suite} ${component})"

while IFS= read -r path; do
  [ -n "${path}" ] || continue
  jq -e --arg p "${path}" '.objects | has($p)' "${FIXTURE}" >/dev/null \
    || fail "installer path ${path} missing from fixture objects"
done <<EOF
${fixture_paths}
EOF
rm -rf "${tmp}"

printf 'ok\n'
