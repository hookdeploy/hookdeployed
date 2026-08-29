#!/bin/sh
# Behavior tests for enroll_with_token + the postinst configure wrapper.
# Sourced helpers only — does not call the real binary or sudo.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
COMMON="${ROOT}/packaging/lib/install-common.sh"
# shellcheck source=install-common.sh
. "${COMMON}"

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

CERT_DIR="${TMP}/certs"
STATE_DIR="${TMP}/state"
mkdir -p "${CERT_DIR}" "${STATE_DIR}"
TOKEN_OUT="${TMP}/token.out"
ARGV_OUT="${TMP}/argv.out"

# Production tokens: hd_enroll_<region>_<64 hex>. apac is the longest prefix (79).
HEX64="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
FULL_TOKEN="hd_enroll_apac_${HEX64}"
# 64-char password-widget truncation of that token (historical dialog/newt limit).
TRUNCATED="$(printf '%s' "${FULL_TOKEN}" | cut -c1-64)"

already_enrolled() { return 1; }

_enroll_as_service_user() {
  # Record exact argv the way _enroll_as_service_user passes -token.
  printf '%s' "$2" > "${TOKEN_OUT}"
  printf '%s\n' "$@" > "${ARGV_OUT}"
  return "${ENROLL_EC:-0}"
}

# A dummy systemctl so a successful enroll does not touch the host.
mkdir -p "${TMP}/bin"
printf '#!/bin/sh\nexit 0\n' > "${TMP}/bin/systemctl"
chmod +x "${TMP}/bin/systemctl"
PATH="${TMP}/bin:${PATH}"
export PATH

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

# --- Full token is one argument, untruncated ---
ENROLL_EC=0
enroll_with_token /usr/bin/hookdeployed "${FULL_TOKEN}" || fail "full token enroll should succeed"
got="$(cat "${TOKEN_OUT}")"
[ "${got}" = "${FULL_TOKEN}" ] || fail "expected full token (${#FULL_TOKEN} chars), got ${#got} chars: ${got}"
[ "${#got}" -eq 79 ] || fail "apac token should be 79 chars, got ${#got}"
[ "${got}" != "${TRUNCATED}" ] || fail "token was truncated to 64 chars"

# --- Trailing CR is stripped (debconf / Windows preseed) ---
ENROLL_EC=0
cr_token=$(printf '%s\r' "${FULL_TOKEN}")
enroll_with_token /usr/bin/hookdeployed "${cr_token}" || fail "CR token enroll should succeed after trim"
got="$(cat "${TOKEN_OUT}")"
[ "${got}" = "${FULL_TOKEN}" ] || fail "CR should be stripped; got [${got}]"

# --- Invalid token: return 1, do not exit the shell ---
ENROLL_EC=1
set +e
enroll_with_token /usr/bin/hookdeployed "not-a-real-token"
ec=$?
set -e
[ "${ec}" -eq 1 ] || fail "enroll_with_token should return 1, got ${ec}"

# --- postinst-shaped wrapper: enroll failure → instructions, exit 0 ---
UNATTENDED_HINT="For unattended install, preseed hookdeployed/enroll_token or set HOOKDEPLOYED_TOKEN."
postinst_configure_with_token() {
  set -e
  TOKEN="$1"
  if [ -n "${TOKEN}" ]; then
    if enroll_with_token /usr/bin/hookdeployed "${TOKEN}"; then
      :
    else
      log "enrollment did not succeed — package is installed; enroll manually:"
      print_no_token_instructions /usr/bin/hookdeployed "${UNATTENDED_HINT}"
    fi
  else
    print_no_token_instructions /usr/bin/hookdeployed "${UNATTENDED_HINT}"
  fi
  exit 0
}

ENROLL_EC=1
out="$(postinst_configure_with_token "hd_enroll_us_deadbeef" 2>&1)" || fail "wrapper must exit 0, got $?"
printf '%s\n' "${out}" | grep -q "enrollment did not succeed" || fail "expected failure log"
printf '%s\n' "${out}" | grep -q "no token given" || fail "expected manual instructions"

# --- install.sh --token still fails the process (set -e) ---
install_sh_token_path() {
  set -euo pipefail
  TOKEN="$1"
  enroll_with_token /usr/local/bin/hookdeployed "${TOKEN}"
  echo "should-not-reach"
}
ENROLL_EC=1
set +e
install_out="$(install_sh_token_path "hd_enroll_us_deadbeef" 2>&1)"
install_ec=$?
set -e
[ "${install_ec}" -ne 0 ] || fail "install.sh --token path must still exit nonzero on enroll failure"
printf '%s\n' "${install_out}" | grep -q "should-not-reach" && fail "install.sh must not continue after enroll failure"

printf 'ok\n'
