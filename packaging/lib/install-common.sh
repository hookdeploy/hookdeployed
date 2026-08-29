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
