#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist/packages}"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cd "$ROOT_DIR"
export GOTOOLCHAIN=go1.26.10
if [[ "$(go version)" != go\ version\ go1.26.10\ * ]]; then
  echo "ERROR: release build requires Go 1.26.10" >&2
  exit 1
fi

version_line="$(rg -n 'const Version = ' main.go | head -n 1 || true)"
if [[ -z "$version_line" ]]; then
  echo "ERROR: could not find Version constant in main.go" >&2
  exit 1
fi

VERSION_RAW="$(printf '%s' "$version_line" | sed -E 's/.*const Version = "([^"]+)".*/\1/')"
VERSION="${VERSION_RAW#v}"
RPM_VERSION="$(printf '%s' "$VERSION" | sed 's/-.*$//')"
RPM_RELEASE_SUFFIX="$(printf '%s' "$VERSION" | sed -n 's/^[^-]*-\(.*\)$/\1/p' | tr '-' '_' )"
if [[ -n "$RPM_RELEASE_SUFFIX" ]]; then
  RPM_RELEASE="1.${RPM_RELEASE_SUFFIX}"
else
  RPM_RELEASE="1"
fi
if [[ -z "$VERSION" ]]; then
  echo "ERROR: resolved version is empty" >&2
  exit 1
fi

mkdir -p "$DIST_DIR"

OUTDIR="$ROOT_DIR/dist" "$ROOT_DIR/tools/build-ebpf-src-tar.sh" >/dev/null
EBPF_SRC="$ROOT_DIR/dist/honeymesh-ebpf-src-${VERSION_RAW}.tar.gz"
if [[ ! -f "$EBPF_SRC" ]]; then
  echo "ERROR: expected eBPF archive not found: $EBPF_SRC" >&2
  exit 1
fi

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

build_one() {
  local goarch="$1"
  local debarch="$2"
  local rpmarch="$3"
  local bin="$TMP_DIR/honeymesh_${goarch}"
  local stage="$TMP_DIR/stage_${goarch}"
  local root_name="honeymesh-${VERSION}-linux-${goarch}"
  local deb_out="$DIST_DIR/honeymesh_${VERSION}_${debarch}.deb"
  local tar_out="$DIST_DIR/${root_name}.tar.gz"

  echo "[build] linux/${goarch} binary"
  GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -o "$bin" ./

  rm -rf "$stage"
  mkdir -p \
    "$stage/DEBIAN" \
    "$stage/usr/bin" \
    "$stage/usr/lib/systemd/system" \
    "$stage/usr/share/honeymesh" \
    "$stage/usr/share/honeymesh/web" \
    "$stage/usr/share/honeymesh/licenses" \
    "$stage/etc/honeymesh/certs" \
    "$stage/var/lib/honeymesh"

  install -m 0755 "$bin" "$stage/usr/bin/honeymesh"
  install -m 0644 "$EBPF_SRC" "$stage/usr/share/honeymesh/ebpf-src.tar.gz"

  if [[ -d "$ROOT_DIR/web" ]]; then
    cp -a "$ROOT_DIR/web/." "$stage/usr/share/honeymesh/web/"
  fi

  if [[ -d "$ROOT_DIR/LICENSES" ]]; then
    cp -a "$ROOT_DIR/LICENSES/." "$stage/usr/share/honeymesh/licenses/"
  fi

  if [[ -f "$ROOT_DIR/LICENSE" ]]; then
    cp "$ROOT_DIR/LICENSE" "$stage/usr/share/honeymesh/licenses/PROJECT-LICENSE"
  fi

  # Never package the operator's live config, admin token, mesh secret or TLS keys.
  install -m 0640 "$ROOT_DIR/packaging/honeymesh.community.json" "$stage/etc/honeymesh/honeymesh.json"
  install -m 0755 "$ROOT_DIR/packaging/init-local-certs.sh" "$stage/usr/share/honeymesh/init-local-certs.sh"
  install -m 0755 "$ROOT_DIR/packaging/rotate-soc-leaf-ecdsa.sh" "$stage/usr/share/honeymesh/rotate-soc-leaf-ecdsa.sh"
  install -m 0755 "$ROOT_DIR/packaging/setup-service-state.sh" "$stage/usr/share/honeymesh/setup-service-state.sh"
  install -m 0755 "$ROOT_DIR/packaging/activate-service.sh" "$stage/usr/share/honeymesh/activate-service.sh"
  install -m 0644 "$ROOT_DIR/packaging/honeymesh.service" "$stage/usr/lib/systemd/system/honeymesh.service"

  cat > "$stage/DEBIAN/control" <<CONTROL
Package: honeymesh
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${debarch}
Depends: ca-certificates, iproute2, openssl, passwd, util-linux, procps
Maintainer: HoneyMesh <support@network-decode.com>
Description: HoneyMesh distributed cyber defense platform
CONTROL

  cat > "$stage/DEBIAN/preinst" <<'PREINST'
#!/bin/sh
set -e

fail() {
  echo "[HONEYMESH PREINST] $1" >&2
  exit 1
}

KVER=$(uname -r | awk -F- '{print $1}')
REQ="5.8.0"

ver_ge() {
  [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

if ! ver_ge "$KVER" "$REQ"; then
  fail "Kernel $KVER is too old. Require >= $REQ. Upgrade kernel and reboot."
fi

if [ ! -d /sys/fs/bpf ]; then
  fail "/sys/fs/bpf missing. Mount it: sudo mount -t bpf bpf /sys/fs/bpf"
fi

if ! mountpoint -q /sys/fs/bpf; then
  fail "/sys/fs/bpf not mounted. Mount it: sudo mount -t bpf bpf /sys/fs/bpf"
fi

if [ ! -c /dev/bpf ] && [ ! -d /sys/fs/bpf ]; then
  fail "BPF filesystem not available. Ensure kernel supports eBPF and mount /sys/fs/bpf"
fi

if ! sysctl -n kernel.unprivileged_bpf_disabled >/dev/null 2>&1; then
  echo "[HONEYMESH PREINST] Warning: cannot read kernel.unprivileged_bpf_disabled"
fi

exit 0
PREINST

  chmod 0755 "$stage/DEBIAN/preinst"

  echo '/etc/honeymesh/honeymesh.json' > "$stage/DEBIAN/conffiles"
  cat > "$stage/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
  /usr/share/honeymesh/init-local-certs.sh /etc/honeymesh/certs
  /usr/share/honeymesh/setup-service-state.sh
  runuser -u honeymesh -- /usr/bin/honeymesh -config /etc/honeymesh/honeymesh.json -state-dir /var/lib/honeymesh -migrate-state
  /usr/share/honeymesh/activate-service.sh
fi
POSTINST
  chmod 0755 "$stage/DEBIAN/postinst"

  cat > "$stage/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = deconfigure ]; then
  if [ -d /run/systemd/system ]; then
    if systemctl is-active --quiet honeymesh.service; then
      systemctl stop honeymesh.service
    fi
    systemctl disable honeymesh.service >/dev/null 2>&1 || true
  fi
  if pgrep -x honeymesh >/dev/null 2>&1; then
    echo 'HoneyMesh is still running; stop the manual process before removing its binary.' >&2
    exit 1
  fi
fi
PRERM
  chmod 0755 "$stage/DEBIAN/prerm"

  cat > "$stage/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi
POSTRM
  chmod 0755 "$stage/DEBIAN/postrm"

  if has_cmd dpkg-deb; then
    echo "[pack] $deb_out"
    dpkg-deb --root-owner-group --build "$stage" "$deb_out" >/dev/null
    if dpkg-deb -c "$deb_out" | awk '$2 != "root/root" { bad = 1 } END { exit !bad }'; then
      echo "ERROR: Debian package contains a non-root-owned entry" >&2
      exit 1
    fi
  else
    echo "[skip] dpkg-deb not found, skipping .deb for $goarch"
  fi

  local tar_stage="$TMP_DIR/$root_name"
  rm -rf "$tar_stage"
  mkdir -p "$tar_stage"
  cp -a "$stage/usr" "$tar_stage/"
  cp -a "$stage/etc" "$tar_stage/"
  cp -a "$stage/var" "$tar_stage/"

  cat > "$tar_stage/install.sh" <<INSTALL
#!/usr/bin/env bash
set -euo pipefail

if [[ "\${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./install.sh" >&2
  exit 1
fi

KVER=\$(uname -r | awk -F- '{print \$1}')
if [[ "\$(printf '%s\n' "\$KVER" '5.8.0' | sort -V | head -n1)" != '5.8.0' ]]; then
  echo "Kernel \$KVER is too old. Require >= 5.8.0 for CAP_BPF and CAP_PERFMON." >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet honeymesh.service; then
  systemctl stop honeymesh.service
fi

cp -a usr/. /usr/
mkdir -p /etc/honeymesh
if [[ ! -e /etc/honeymesh/honeymesh.json ]]; then
  install -m 0600 etc/honeymesh/honeymesh.json /etc/honeymesh/honeymesh.json
fi
/usr/share/honeymesh/init-local-certs.sh /etc/honeymesh/certs
cp -a var/. /var/
mkdir -p /var/lib/honeymesh
/usr/share/honeymesh/setup-service-state.sh
runuser -u honeymesh -- /usr/bin/honeymesh -config /etc/honeymesh/honeymesh.json -state-dir /var/lib/honeymesh -migrate-state
/usr/share/honeymesh/activate-service.sh

echo "HoneyMesh ${VERSION_RAW} installed."
INSTALL

  chmod 0755 "$tar_stage/install.sh"

  echo "[pack] $tar_out"
  (cd "$TMP_DIR" && tar --owner=0 --group=0 --numeric-owner -czf "$tar_out" "$root_name")
  if tar --numeric-owner -tvf "$tar_out" | awk '$2 != "0/0" { bad = 1 } END { exit !bad }'; then
    echo "ERROR: tar package contains a non-root-owned entry" >&2
    exit 1
  fi

  if has_cmd rpmbuild; then
    local rpm_root="$TMP_DIR/rpmbuild_${goarch}"
    local rpm_top="$rpm_root/top"
    local rpm_out="$DIST_DIR"
    local spec="$rpm_root/honeymesh.spec"
    local pre="$rpm_root/pre.sh"

    mkdir -p "$rpm_top/BUILD" "$rpm_top/BUILDROOT" "$rpm_top/RPMS" "$rpm_top/SOURCES" "$rpm_top/SPECS" "$rpm_top/SRPMS"

    cat > "$pre" <<'PRESCRIPT'
#!/bin/sh
set -e

fail() {
  echo "[HONEYMESH PREINST] $1" >&2
  exit 1
}

KVER=$(uname -r | awk -F- '{print $1}')
REQ="5.8.0"

ver_ge() {
  [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

if ! ver_ge "$KVER" "$REQ"; then
  fail "Kernel $KVER is too old. Require >= $REQ. Upgrade kernel and reboot."
fi

if [ ! -d /sys/fs/bpf ]; then
  fail "/sys/fs/bpf missing. Mount it: sudo mount -t bpf bpf /sys/fs/bpf"
fi

if ! mountpoint -q /sys/fs/bpf; then
  fail "/sys/fs/bpf not mounted. Mount it: sudo mount -t bpf bpf /sys/fs/bpf"
fi

if [ ! -c /dev/bpf ] && [ ! -d /sys/fs/bpf ]; then
  fail "BPF filesystem not available. Ensure kernel supports eBPF and mount /sys/fs/bpf"
fi

if ! sysctl -n kernel.unprivileged_bpf_disabled >/dev/null 2>&1; then
  echo "[HONEYMESH PREINST] Warning: cannot read kernel.unprivileged_bpf_disabled"
fi

exit 0
PRESCRIPT

    chmod 0755 "$pre"

    cat > "$spec" <<SPEC
Name: honeymesh
Version: ${RPM_VERSION}
Release: ${RPM_RELEASE}
Summary: HoneyMesh distributed cyber defense platform
License: Apache-2.0 AND (BSD-2-Clause OR GPL-2.0-only) AND CC-BY-4.0
URL: https://network-decode.com
Requires: ca-certificates, iproute, openssl, shadow-utils, util-linux, procps-ng

%description
HoneyMesh distributed cyber defense platform

%prep

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a ${stage}/usr %{buildroot}/
cp -a ${stage}/etc %{buildroot}/
cp -a ${stage}/var %{buildroot}/

%pre -p /bin/sh
$(cat "$pre")

%post -p /bin/sh
/usr/share/honeymesh/init-local-certs.sh /etc/honeymesh/certs
/usr/share/honeymesh/setup-service-state.sh
runuser -u honeymesh -- /usr/bin/honeymesh -config /etc/honeymesh/honeymesh.json -state-dir /var/lib/honeymesh -migrate-state
/usr/share/honeymesh/activate-service.sh

%preun -p /bin/sh
if [ "\$1" -eq 0 ]; then
  if [ -d /run/systemd/system ]; then
    if systemctl is-active --quiet honeymesh.service; then
      systemctl stop honeymesh.service || exit 1
    fi
    systemctl disable honeymesh.service >/dev/null 2>&1 || true
  fi
  if pgrep -x honeymesh >/dev/null 2>&1; then
    echo 'HoneyMesh is still running; stop the manual process before removing its binary.' >&2
    exit 1
  fi
fi

%postun -p /bin/sh
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi

%files
/usr/bin/honeymesh
/usr/share/honeymesh
/usr/lib/systemd/system/honeymesh.service
%dir /etc/honeymesh
%dir /etc/honeymesh/certs
%config(noreplace) /etc/honeymesh/honeymesh.json
/var/lib/honeymesh
SPEC

    echo "[pack] $DIST_DIR/honeymesh-${RPM_VERSION}-${RPM_RELEASE}.${rpmarch}.rpm"
    rpmbuild \
      --define "_topdir $rpm_top" \
      --define "_rpmdir $rpm_out" \
      --define "__strip /bin/true" \
      --define "__objdump /bin/true" \
      --target "$rpmarch" \
      -bb "$spec" >/dev/null
  else
    echo "[skip] rpmbuild not found, skipping .rpm for $goarch"
  fi
}

case "${HM_BUILD_ARCHES:-all}" in
  all)
    build_one amd64 amd64 x86_64
    build_one arm64 arm64 aarch64
    ;;
  amd64)
    build_one amd64 amd64 x86_64
    ;;
  arm64)
    build_one arm64 arm64 aarch64
    ;;
  *)
    echo "ERROR: HM_BUILD_ARCHES must be all, amd64, or arm64" >&2
    exit 1
    ;;
esac

echo "Done. Packages written to: $DIST_DIR"
