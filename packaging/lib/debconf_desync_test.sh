#!/bin/sh
# Model the debconf 1:1 command/reply pairing that postinst hits when dpkg
# runs it under a frontend. No real debconf. No network.
#
# Each line written to the protocol gets one reply. db_get reads one reply.
# A log line written to stdout (the protocol, before confmodule redirects it)
# therefore steals the reply that db_get was supposed to get.
set -eu

GOOD_TOKEN="hd_enroll_us_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# Frontend: GET → 0 <token>. Anything else → 20 not-a-command.
frontend_reply() {
  case "$1" in
    GET*)
      printf '0 %s\n' "${GOOD_TOKEN}"
      ;;
    *)
      printf '20 not-a-command\n'
      ;;
  esac
}

# Same strip as Debian confmodule: drop one non-space + one space.
strip_status() {
  _line="$1"
  printf '%s\n' "${_line#[! ][ ]}"
}

# Buggy postinst order: printf/log to stdout (protocol), then db_get.
buggy_db_get() {
  # 1) ensure_user's log — goes to the protocol before confmodule is sourced.
  _r1=$(frontend_reply "hookdeployed: user hookdeployed already exists")
  # 2) db_get writes GET and reads the next (but really: the first) reply.
  #    In a real pipe the 20 is already sitting on stdin; read consumes it.
  #    The GET reply is left unread. RET is the error, not the token.
  _stolen=$(strip_status "${_r1}")
  _r2=$(frontend_reply "GET hookdeployed/enroll_token")
  # What db_get actually assigned: the stolen first reply.
  printf '%s\n' "${_stolen}"
  # Keep _r2 unused — that is the unread GET response sitting on the pipe.
  : "${_r2}"
}

# Fixed order: confmodule sourced first (stdout → stderr), log is not protocol.
fixed_db_get() {
  _r1=$(frontend_reply "GET hookdeployed/enroll_token")
  strip_status "${_r1}"
}

buggy_ret=$(buggy_db_get)
fixed_ret=$(fixed_db_get)

printf 'buggy_ret=[%s]\n' "${buggy_ret}"
printf 'fixed_ret=[%s]\n' "${fixed_ret}"

[ "${buggy_ret}" != "${GOOD_TOKEN}" ] || {
  printf 'FAIL: polluted protocol still yielded the real token\n' >&2
  exit 1
}
[ "${fixed_ret}" = "${GOOD_TOKEN}" ] || {
  printf 'FAIL: clean protocol did not yield the real token (got [%s])\n' "${fixed_ret}" >&2
  exit 1
}
# Stolen RET is not an hd_enroll_* string — worker parseTokenRegion fails
# and returns the same "invalid token" the live postinst printed.
case "${buggy_ret}" in
  hd_enroll_*)
    printf 'FAIL: stolen RET still looks like a token: [%s]\n' "${buggy_ret}" >&2
    exit 1
    ;;
esac

printf 'ok\n'
