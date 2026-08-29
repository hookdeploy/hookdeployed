#!/usr/bin/env bash
# Build .deb packages and a signed APT repo tree locally.
# Does not upload, deploy, or generate signing keys.
#
# Usage:
#   packaging/build-apt-repo.sh --version 0.1.0 --key <fingerprint-or-email>
#
# Expects pre-built binaries (release.yml layout):
#   dist/build/linux-amd64/hookdeployed
#   dist/build/linux-arm64/hookdeployed
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)"
DEBIAN_DIR="${SCRIPT_DIR}/debian"
COMMON_SH="${SCRIPT_DIR}/lib/install-common.sh"
FTPARCHIVE_CONF="${SCRIPT_DIR}/apt-ftparchive.conf"

VERSION=""
REVISION="1"
KEY=""
BIN_DIR="${REPO_ROOT}/dist/build"
OUT_DIR="${REPO_ROOT}/dist/apt-repo"
BUCKET="hookdeploy-apt"

usage() {
  cat <<'EOF'
build-apt-repo.sh — package linux binaries into a signed APT repo tree

Usage:
  packaging/build-apt-repo.sh --version 0.1.0 --key <fingerprint-or-email>
                              [--revision 1]
                              [--bin-dir dist/build]
                              [--out dist/apt-repo]

  --version X.Y.Z   Upstream version (leading v is stripped). Required.
  --key ID          GPG key already in the invoking user's keyring
                    (fingerprint or email). Used only as gpg --local-user.
                    This script never reads or writes key material files.
  --revision N      Debian revision (default: 1) → Version X.Y.Z-N
  --bin-dir DIR     Directory containing linux-amd64/ and linux-arm64/
                    (default: <repo>/dist/build)
  --out DIR         Output repo root (default: <repo>/dist/apt-repo)

This script prints wrangler r2 object put commands. It does not run them.
EOF
}

die() { printf 'build-apt-repo: %s\n' "$*" >&2; exit 1; }
log() { printf 'build-apt-repo: %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      [ $# -ge 2 ] || die "--version requires a value"
      VERSION="$2"
      shift 2
      ;;
    --version=*)
      VERSION="${1#--version=}"
      shift
      ;;
    --key)
      [ $# -ge 2 ] || die "--key requires a value"
      KEY="$2"
      shift 2
      ;;
    --key=*)
      KEY="${1#--key=}"
      shift
      ;;
    --revision)
      [ $# -ge 2 ] || die "--revision requires a value"
      REVISION="$2"
      shift 2
      ;;
    --revision=*)
      REVISION="${1#--revision=}"
      shift
      ;;
    --bin-dir)
      [ $# -ge 2 ] || die "--bin-dir requires a value"
      BIN_DIR="$2"
      shift 2
      ;;
    --bin-dir=*)
      BIN_DIR="${1#--bin-dir=}"
      shift
      ;;
    --out)
      [ $# -ge 2 ] || die "--out requires a value"
      OUT_DIR="$2"
      shift 2
      ;;
    --out=*)
      OUT_DIR="${1#--out=}"
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

[ -n "${VERSION}" ] || die "--version is required"
[ -n "${KEY}" ] || die "--key is required (fingerprint or email of a key already in your GPG keyring)"
VERSION="${VERSION#v}"
case "${VERSION}" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) die "--version must be MAJOR.MINOR.PATCH (got ${VERSION})" ;;
esac
DEB_VERSION="${VERSION}-${REVISION}"

[ -f "${COMMON_SH}" ] || die "missing ${COMMON_SH}"
[ -f "${DEBIAN_DIR}/control" ] || die "missing ${DEBIAN_DIR}/control"
[ -f "${FTPARCHIVE_CONF}" ] || die "missing ${FTPARCHIVE_CONF}"

for cmd in dpkg-deb dpkg-scanpackages apt-ftparchive gzip gpg; do
  command -v "${cmd}" >/dev/null 2>&1 || die "missing required command: ${cmd}"
done

# Resolve bin dir (allow relative to cwd or repo root).
if [ ! -d "${BIN_DIR}" ]; then
  if [ -d "${REPO_ROOT}/${BIN_DIR}" ]; then
    BIN_DIR="${REPO_ROOT}/${BIN_DIR}"
  else
    die "bin dir not found: ${BIN_DIR}"
  fi
fi
if [ "${OUT_DIR#/}" = "${OUT_DIR}" ]; then
  OUT_DIR="${REPO_ROOT}/${OUT_DIR}"
fi

for spec in linux-amd64 linux-arm64; do
  [ -f "${BIN_DIR}/${spec}/hookdeployed" ] \
    || die "missing binary ${BIN_DIR}/${spec}/hookdeployed"
done

log "version=${DEB_VERSION} key=${KEY} bin-dir=${BIN_DIR} out=${OUT_DIR}"

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}/pool/main/h/hookdeployed"
mkdir -p "${OUT_DIR}/dists/stable/main/binary-amd64"
mkdir -p "${OUT_DIR}/dists/stable/main/binary-arm64"

build_deb() {
  local arch="$1"
  local bin="${BIN_DIR}/linux-${arch}/hookdeployed"
  local pkg
  pkg="$(mktemp -d "${TMPDIR:-/tmp}/hookdeployed-deb.XXXXXX")"
  mkdir -p \
    "${pkg}/DEBIAN" \
    "${pkg}/usr/bin" \
    "${pkg}/usr/lib/systemd/system" \
    "${pkg}/usr/share/hookdeployed"

  install -m 0755 "${bin}" "${pkg}/usr/bin/hookdeployed"
  install -m 0644 "${DEBIAN_DIR}/hookdeployed.service" \
    "${pkg}/usr/lib/systemd/system/hookdeployed.service"
  install -m 0644 "${COMMON_SH}" "${pkg}/usr/share/hookdeployed/install-common.sh"
  install -m 0755 "${DEBIAN_DIR}/postinst" "${pkg}/DEBIAN/postinst"
  install -m 0755 "${DEBIAN_DIR}/prerm" "${pkg}/DEBIAN/prerm"
  install -m 0755 "${DEBIAN_DIR}/postrm" "${pkg}/DEBIAN/postrm"
  install -m 0755 "${DEBIAN_DIR}/hookdeployed.config" "${pkg}/DEBIAN/config"
  install -m 0644 "${DEBIAN_DIR}/hookdeployed.templates" "${pkg}/DEBIAN/templates"

  local size
  size="$(du -sk "${pkg}/usr" | awk '{print $1}')"
  sed \
    -e "s/__VERSION__/${DEB_VERSION}/g" \
    -e "s/__ARCH__/${arch}/g" \
    -e "s/__INSTALLED_SIZE__/${size}/g" \
    "${DEBIAN_DIR}/control" > "${pkg}/DEBIAN/control"

  local deb="hookdeployed_${DEB_VERSION}_${arch}.deb"
  dpkg-deb --root-owner-group --build "${pkg}" "${OUT_DIR}/pool/main/h/hookdeployed/${deb}"
  rm -rf "${pkg}"
  log "built ${deb}"
}

build_deb amd64
build_deb arm64

# One Packages file per architecture. -a keeps the other arch's .deb out.
for arch in amd64 arm64; do
  (
    cd "${OUT_DIR}"
    dpkg-scanpackages -a "${arch}" pool /dev/null \
      > "dists/stable/main/binary-${arch}/Packages"
    gzip -9c "dists/stable/main/binary-${arch}/Packages" \
      > "dists/stable/main/binary-${arch}/Packages.gz"
  )
  log "wrote dists/stable/main/binary-${arch}/Packages"
done

# Release hashes are relative to dists/stable/.
(
  cd "${OUT_DIR}/dists/stable"
  apt-ftparchive -c "${FTPARCHIVE_CONF}" release . > Release.tmp
  mv Release.tmp Release
  # Sign with the caller's keyring entry only. No key files are created here.
  gpg --batch --yes --clearsign --local-user "${KEY}" \
    --output InRelease Release
  gpg --batch --yes --detach-sign --armor --local-user "${KEY}" \
    --output Release.gpg Release
)
log "signed dists/stable/InRelease and dists/stable/Release.gpg"

content_type_for() {
  local rel="$1"
  case "${rel}" in
    *.deb) printf '%s\n' "application/vnd.debian.binary-package" ;;
    *.gz) printf '%s\n' "application/gzip" ;;
    *.gpg) printf '%s\n' "application/pgp-signature" ;;
    *) printf '%s\n' "text/plain; charset=utf-8" ;;
  esac
}

log "repo tree:"
if command -v find >/dev/null 2>&1; then
  (cd "${OUT_DIR}" && find dists pool -type f | sort)
fi

cat <<EOF

--- upload (not run by this script) ---
# Review the tree above, then upload each object to R2:
EOF

(
  cd "${OUT_DIR}"
  find dists pool -type f | sort | while IFS= read -r rel; do
    ct="$(content_type_for "${rel}")"
    printf 'npx wrangler r2 object put %s/%s --file %s --remote --content-type %q\n' \
      "${BUCKET}" "${rel}" "${OUT_DIR}/${rel}" "${ct}"
  done
)

cat <<EOF

# Public key — export from YOUR keyring and upload separately.
# This script does not export or write key material.
#   gpg --export --armor --output /tmp/hookdeployed.asc ${KEY}
#   npx wrangler r2 object put ${BUCKET}/hookdeployed.gpg --file /tmp/hookdeployed.asc --remote --content-type application/pgp-keys
#   shred -u /tmp/hookdeployed.asc   # optional; the file is the public key
#
# Worker + DNS + bucket creation are not done here. See docs/apt-repo-build.md.
EOF
