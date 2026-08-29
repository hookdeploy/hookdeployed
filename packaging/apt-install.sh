#!/usr/bin/env bash
# APT-repo setup wrapper for hookdeployed.
#   curl -fsSL https://apt.hookdeploy.dev/install.sh | sudo bash -s -- --token TOKEN
#   curl -fsSL https://apt.hookdeploy.dev/install.sh | sudo bash
#   sudo bash install.sh
#
# This is not the GitHub-releases tarball installer (repo-root install.sh).
# It only adds the signed APT source and runs apt install; upgrades/removals
# after that are ordinary apt upgrade / apt remove.
set -euo pipefail

APT_BASE="${HOOKDEPLOYED_APT_BASE:-https://apt.hookdeploy.dev}"
KEYRING="${HOOKDEPLOYED_KEYRING:-/usr/share/keyrings/hookdeployed.gpg}"
SOURCES_LIST="${HOOKDEPLOYED_SOURCES_LIST:-/etc/apt/sources.list.d/hookdeployed.list}"
DRY_RUN="${HOOKDEPLOYED_APT_DRY_RUN:-0}"

TOKEN="${HOOKDEPLOYED_TOKEN:-}"

usage() {
  cat <<'EOF'
install.sh — add the HookDeploy APT repo and apt install hookdeployed

Usage:
  curl -fsSL https://apt.hookdeploy.dev/install.sh | sudo bash -s -- --token TOKEN
  curl -fsSL https://apt.hookdeploy.dev/install.sh | sudo bash
  sudo bash install.sh [--token TOKEN]
  sudo HOOKDEPLOYED_TOKEN=TOKEN bash install.sh

  --token TOKEN     One-time enrollment token (or HOOKDEPLOYED_TOKEN).
                    Preseeded into debconf as a string, then apt install
                    enrolls via the package postinst.
  -h, --help        Show this help.

Without --token: still installs the package. Piped (curl | bash) prints
enroll instructions and does not read stdin. A real TTY can prompt, or
leave the token blank to enroll later.
EOF
}

log() { printf 'hookdeployed-apt-install: %s\n' "$*"; }
die() { printf 'hookdeployed-apt-install: %s\n' "$*" >&2; exit 1; }

is_stdin_tty() {
  case "${HOOKDEPLOYED_FORCE_TTY:-}" in
    1) return 0 ;;
    0) return 1 ;;
  esac
  [ -t 0 ]
}

trim_token() {
  printf '%s' "$1" | tr -d '\r\n'
}

print_no_token_instructions() {
  log "no token given — installing the package only (service will not start)."
  log "In a real terminal after install, enroll then start:"
  cat <<'EOF'
  sudo -u hookdeployed env HOOKDEPLOY_CERT_DIR=/var/lib/hookdeployed/certs \
    /usr/bin/hookdeployed enroll
  sudo systemctl enable --now hookdeployed
EOF
  log "Do not pipe that enroll command: device-code needs a TTY. For unattended enroll, re-run with --token."
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --token)
        [ $# -ge 2 ] || die "--token requires a value"
        TOKEN="$2"
        shift 2
        ;;
      --token=*)
        TOKEN="${1#--token=}"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done
}

maybe_prompt_for_token() {
  [ -n "${TOKEN}" ] && return 0
  if is_stdin_tty; then
    # Interactive only. Never call read on a pipe (curl | bash hangs).
    read -rp "Enter your HookDeploy enrollment token (or press Enter to skip and enroll later): " TOKEN || true
  fi
  TOKEN="$(trim_token "${TOKEN}")"
  if [ -z "${TOKEN}" ]; then
    print_no_token_instructions
  fi
}

install_apt_source() {
  mkdir -p "$(dirname "${KEYRING}")" "$(dirname "${SOURCES_LIST}")"
  if [ "${DRY_RUN}" = 1 ]; then
    log "dry-run: curl -fsSL ${APT_BASE}/hookdeployed.gpg | gpg --batch --yes --dearmor -o ${KEYRING}"
    log "dry-run: write ${SOURCES_LIST}"
  else
    # --batch --yes: overwrite an existing keyring (second run; one file, not a duplicate).
    local tmp
    tmp="$(mktemp)"
    curl -fsSL "${APT_BASE}/hookdeployed.gpg" | gpg --batch --yes --dearmor -o "${tmp}"
    mv -f "${tmp}" "${KEYRING}"
    chmod 644 "${KEYRING}"
  fi
  # Single-line overwrite. A second run replaces the same file; apt does not
  # grow a second source entry.
  printf 'deb [signed-by=%s] %s stable main\n' "${KEYRING}" "${APT_BASE}" > "${SOURCES_LIST}"
}

preseed_token() {
  TOKEN="$(trim_token "${TOKEN}")"
  [ -n "${TOKEN}" ] || return 0
  local line
  line="hookdeployed hookdeployed/enroll_token string ${TOKEN}"
  if [ -n "${HOOKDEPLOYED_PRESEED_LOG:-}" ]; then
    printf '%s\n' "${line}" > "${HOOKDEPLOYED_PRESEED_LOG}"
  fi
  if [ "${DRY_RUN}" = 1 ]; then
    log "dry-run: debconf-set-selections (string, token len=${#TOKEN})"
    return 0
  fi
  command -v debconf-set-selections >/dev/null 2>&1 || die "missing debconf-set-selections (install debconf)"
  printf '%s\n' "${line}" | debconf-set-selections
}

run_apt() {
  if [ "${DRY_RUN}" = 1 ]; then
    log "dry-run: apt update"
    log "dry-run: apt install -y hookdeployed"
    return 0
  fi
  # Failures print apt's own output; this wrapper does not hide them.
  DEBIAN_FRONTEND=noninteractive apt update
  DEBIAN_FRONTEND=noninteractive apt install -y hookdeployed
}

main() {
  parse_args "$@"

  if [ "${DRY_RUN}" != 1 ]; then
    local os
    os="$(uname -s)"
    if [ "${os}" != "Linux" ]; then
      die "this installer is Linux-only (uname -s=${os})"
    fi
    if [ "$(id -u)" -ne 0 ]; then
      die "must run as root (sudo) to write the APT source and install the package"
    fi
    for cmd in curl gpg apt; do
      command -v "${cmd}" >/dev/null 2>&1 || die "missing required command: ${cmd}"
    done
  fi

  maybe_prompt_for_token
  TOKEN="$(trim_token "${TOKEN}")"

  install_apt_source
  preseed_token
  run_apt
  # Package postinst already prints success or manual-enroll instructions.
}

if [ "${HOOKDEPLOYED_APT_INSTALL_LIB:-0}" != 1 ]; then
  main "$@"
fi
