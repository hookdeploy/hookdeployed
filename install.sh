#!/usr/bin/env bash
# HookDeploy Linux installer.
#   curl -fsSL https://raw.githubusercontent.com/hookdeploy/hookdeployed/main/install.sh \
#     | sudo bash -s -- --token "$TOKEN"
# Piped stdin is not a TTY — this script never runs device-code enroll.
set -euo pipefail

REPO="${HOOKDEPLOYED_REPO:-hookdeploy/hookdeployed}"
BIN_NAME="hookdeployed"
INSTALL_PATH="/usr/local/bin/${BIN_NAME}"
UNIT_PATH="/etc/systemd/system/hookdeployed.service"
RELEASES_API="https://api.github.com/repos/${REPO}/releases"

TOKEN="${HOOKDEPLOYED_TOKEN:-}"
VERSION="${HOOKDEPLOYED_VERSION:-}"
DRY_RUN=0

usage() {
  cat <<'EOF'
install.sh — install hookdeployed on Linux (amd64 / arm64)

Usage:
  sudo ./install.sh [--token TOKEN] [--version vX.Y.Z] [--dry-run]
  sudo HOOKDEPLOYED_TOKEN=TOKEN ./install.sh
  curl -fsSL https://raw.githubusercontent.com/hookdeploy/hookdeployed/main/install.sh \
    | sudo bash -s -- --token TOKEN

  --token TOKEN     One-time enrollment token (or HOOKDEPLOYED_TOKEN).
                    Required for unattended enroll + start. Device-code
                    enroll is not run from this script (needs a real TTY).
  --version TAG     Release tag (default: latest). Example: v0.1.0
                    Also accepted as HOOKDEPLOYED_VERSION.
  --dry-run         Print actions; do not write, download, or enroll.
  -h, --help        Show this help.

Without --token: installs the binary and unit only, then prints the
commands to run enroll in a terminal and enable the service.
EOF
}

log() { printf 'hookdeployed-install: %s\n' "$*"; }
die() { printf 'hookdeployed-install: %s\n' "$*" >&2; exit 1; }

run() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf 'hookdeployed-install: dry-run:' >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    return 0
  fi
  "$@"
}

# Shared user/certs/enroll helpers. Checkout → source the file. curl | bash
# has no sibling tree, so the same file is inlined below. Keep the two copies
# identical to packaging/lib/install-common.sh.
_load_install_common() {
  if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    local dir
    dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "${dir}/packaging/lib/install-common.sh" ]; then
      # shellcheck source=packaging/lib/install-common.sh
      . "${dir}/packaging/lib/install-common.sh"
      return
    fi
  fi
  # Fallback for piped install (curl | bash). Heredoc is attached to this
  # command — it does not consume the script's stdin pipe.
  # BEGIN packaging/lib/install-common.sh
  . /dev/stdin <<'INSTALL_COMMON'
# Shared install helpers for install.sh and the Debian postinst.
# Do not run this file directly — source it.
#
# Caller may define log, die, run, DRY_RUN before sourcing. If those are
# missing, this file provides defaults (run is a passthrough; DRY_RUN=0).

SERVICE_USER="${SERVICE_USER:-hookdeployed}"
CERT_DIR="${CERT_DIR:-/var/lib/hookdeployed/certs}"
STATE_DIR="${STATE_DIR:-/var/lib/hookdeployed}"

if ! type log >/dev/null 2>&1; then
  log() { printf 'hookdeployed: %s\n' "$*"; }
fi
if ! type die >/dev/null 2>&1; then
  die() { printf 'hookdeployed: %s\n' "$*" >&2; exit 1; }
fi
if ! type run >/dev/null 2>&1; then
  run() { "$@"; }
fi

ensure_user() {
  if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    log "user ${SERVICE_USER} already exists"
    return
  fi
  local shell=""
  for cand in /usr/sbin/nologin /sbin/nologin /bin/false; do
    if [ -x "${cand}" ]; then
      shell="${cand}"
      break
    fi
  done
  [ -n "${shell}" ] || die "no nologin/false shell found"
  run useradd --system --no-create-home --home-dir "${STATE_DIR}" --shell "${shell}" "${SERVICE_USER}"
}

ensure_state_dirs() {
  run mkdir -p "${CERT_DIR}"
  if [ "${DRY_RUN:-0}" -eq 0 ]; then
    chown "${SERVICE_USER}:${SERVICE_USER}" "${STATE_DIR}" "${CERT_DIR}"
    chmod 0755 "${STATE_DIR}"
    chmod 0700 "${CERT_DIR}"
  else
    log "dry-run: chown ${SERVICE_USER} ${STATE_DIR} ${CERT_DIR}; chmod 0755/0700"
  fi
}

already_enrolled() {
  local active key
  [ -f "${CERT_DIR}/active" ] || return 1
  active="$(tr -d '[:space:]' < "${CERT_DIR}/active")"
  [ -n "${active}" ] || return 1
  key="${CERT_DIR}/${active}/client.key"
  [ -f "${key}" ]
}

# Run enroll as SERVICE_USER. Prefers sudo -u (install.sh path) so the
# exact command is unchanged; runuser/su are for maintainer scripts.
_enroll_as_service_user() {
  local bin_path="$1"
  local token="$2"
  if command -v sudo >/dev/null 2>&1; then
    sudo -u "${SERVICE_USER}" env HOOKDEPLOY_CERT_DIR="${CERT_DIR}" "${bin_path}" enroll -token "${token}"
  elif command -v runuser >/dev/null 2>&1; then
    runuser -u "${SERVICE_USER}" -- env HOOKDEPLOY_CERT_DIR="${CERT_DIR}" "${bin_path}" enroll -token "${token}"
  else
    su -s /bin/sh "${SERVICE_USER}" -c "env HOOKDEPLOY_CERT_DIR=${CERT_DIR} ${bin_path} enroll -token ${token}"
  fi
}

enroll_with_token() {
  local bin_path="$1"
  # Strip CR/LF. Debconf retrieval and Windows-copied preseeds can leave a
  # trailing CR; the worker hashes the raw string, so that is "invalid token"
  # even though the hd_enroll_<region>_ prefix still matches.
  local token
  token=$(printf '%s' "$2" | tr -d '\r\n')
  local enroll_ec
  log "enrolling as ${SERVICE_USER} (HOOKDEPLOY_CERT_DIR=${CERT_DIR})"
  set +e
  if [ "${DRY_RUN:-0}" -eq 1 ]; then
    run sudo -u "${SERVICE_USER}" env HOOKDEPLOY_CERT_DIR="${CERT_DIR}" "${bin_path}" enroll -token "${token}"
    enroll_ec=0
  else
    _enroll_as_service_user "${bin_path}" "${token}"
    enroll_ec=$?
  fi
  set -e
  if [ "${enroll_ec}" -ne 0 ]; then
    if already_enrolled; then
      log "enroll failed (exit ${enroll_ec}); existing credentials kept — same token is one-time and cannot be reused"
    else
      # Do not die() — postinst sources this file and die() is exit 1, which
      # would fail dpkg configure. install.sh has set -e and still exits 1.
      log "enroll failed (exit ${enroll_ec}) and no usable credentials in ${CERT_DIR}" >&2
      return 1
    fi
  fi
  if command -v systemctl >/dev/null 2>&1; then
    run systemctl enable --now hookdeployed
    # Pick up creds if the unit was already running from a prior install.
    run systemctl restart hookdeployed
  fi
}

# $1 = binary path printed in the enroll command
# $2 = optional unattended-hint sentence (default matches install.sh)
print_no_token_instructions() {
  local bin_path="$1"
  local unattended_hint="${2:-For unattended install, re-run with --token.}"
  log "no token given — service is not enabled (connect needs credentials)."
  log "In a real terminal, enroll then start:"
  cat <<EOF
  sudo -u ${SERVICE_USER} env HOOKDEPLOY_CERT_DIR=${CERT_DIR} ${bin_path} enroll
  sudo systemctl enable --now hookdeployed
EOF
  log "Do not pipe that enroll command: device-code needs a TTY. ${unattended_hint}"
}
INSTALL_COMMON
  # END packaging/lib/install-common.sh
}

_load_install_common

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
    --version)
      [ $# -ge 2 ] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#--version=}"
      shift
      ;;
    --dry-run)
      DRY_RUN=1
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

os="$(uname -s)"
if [ "${os}" != "Linux" ]; then
  die "this installer is Linux-only (uname -s=${os}). Download a release asset for ${os} from https://github.com/${REPO}/releases"
fi

arch_raw="$(uname -m)"
case "${arch_raw}" in
  x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "unsupported architecture ${arch_raw} (need x86_64 or aarch64/arm64)" ;;
esac

if [ "${DRY_RUN}" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  die "must run as root (sudo) to install into ${INSTALL_PATH} and systemd"
fi

for cmd in curl tar sha256sum; do
  command -v "${cmd}" >/dev/null 2>&1 || die "missing required command: ${cmd}"
done

resolve_tag() {
  if [ -n "${VERSION}" ]; then
    printf '%s\n' "${VERSION}"
    return
  fi
  local body
  body="$(curl -fsSL "${RELEASES_API}/latest")" || die "failed to fetch ${RELEASES_API}/latest"
  local tag=""
  if command -v python3 >/dev/null 2>&1; then
    tag="$(printf '%s' "${body}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
  else
    tag="$(printf '%s' "${body}" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  fi
  [ -n "${tag}" ] || die "could not parse tag_name from latest release"
  printf '%s\n' "${tag}"
}

write_unit() {
  local dest="$1"
  local src=""
  if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    local dir
    dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "${dir}/packaging/hookdeployed.service" ]; then
      src="${dir}/packaging/hookdeployed.service"
    fi
  fi
  if [ -n "${src}" ]; then
    run cp "${src}" "${dest}"
    return
  fi
  if [ "${DRY_RUN}" -eq 1 ]; then
    log "dry-run: write ${dest} (embedded unit)"
    return
  fi
  cat > "${dest}" <<'UNIT'
[Unit]
Description=HookDeploy delivery agent
Documentation=https://github.com/hookdeploy/hookdeployed
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hookdeployed
Group=hookdeployed
Environment=HOOKDEPLOY_CERT_DIR=/var/lib/hookdeployed/certs
ExecStart=/usr/local/bin/hookdeployed connect
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=30
StartLimitBurst=5
# In-process reconnect already covers network blips. Restart only if
# the process actually exits (crash, fatal enroll/cert error).
# Restart=always would relaunch a clean exit after revoke.

[Install]
WantedBy=multi-user.target
UNIT
}

TAG="$(resolve_tag)"
ASSET="hookdeployed_${TAG}_linux_${GOARCH}.tar.gz"
DOWNLOAD_BASE="https://github.com/${REPO}/releases/download/${TAG}"

log "version=${TAG} os=linux arch=${GOARCH} asset=${ASSET}"

WORKDIR=""
cleanup() {
  if [ -n "${WORKDIR}" ] && [ -d "${WORKDIR}" ]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

if [ "${DRY_RUN}" -eq 1 ]; then
  WORKDIR="/tmp/hookdeployed-install-dry-run"
  log "dry-run: would download ${DOWNLOAD_BASE}/${ASSET}"
  log "dry-run: would verify ${ASSET} against SHA256SUMS"
  log "dry-run: would install ${BIN_NAME} -> ${INSTALL_PATH} (0755)"
else
  WORKDIR="$(mktemp -d)"
  cd "${WORKDIR}"
  curl -fsSL -o SHA256SUMS "${DOWNLOAD_BASE}/SHA256SUMS" \
    || die "failed to download SHA256SUMS for ${TAG}"
  curl -fsSL -o "${ASSET}" "${DOWNLOAD_BASE}/${ASSET}" \
    || die "failed to download ${ASSET}"
  if ! grep -F -e "${ASSET}" SHA256SUMS > check.sha; then
    die "${ASSET} is not listed in SHA256SUMS"
  fi
  sha256sum -c check.sha || die "checksum mismatch for ${ASSET} — aborting, binary not installed"
  tar -xzf "${ASSET}"
  [ -f "${BIN_NAME}" ] || die "archive ${ASSET} did not contain ${BIN_NAME}"
  run install -m 0755 "${BIN_NAME}" "${INSTALL_PATH}"
fi

ensure_user
ensure_state_dirs

write_unit "${UNIT_PATH}"
if command -v systemctl >/dev/null 2>&1; then
  run systemctl daemon-reload
else
  log "systemctl not found — wrote ${UNIT_PATH}; enable it after systemd is available"
fi

if [ -n "${TOKEN}" ]; then
  enroll_with_token "${INSTALL_PATH}" "${TOKEN}"
  log "installed ${INSTALL_PATH} and started hookdeployed.service"
  exit 0
fi

log "installed ${INSTALL_PATH} and ${UNIT_PATH}"
print_no_token_instructions "${INSTALL_PATH}"
