#!/usr/bin/env bash
# Run only in a disposable root-owned package test container.
set -euo pipefail
[[ "$#" -eq 1 && -f "$1" ]]
artifact="$1"
[[ ! -e /etc/harboros/service-auth && ! -e /var/lib/harboros-im-gate ]]
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"' EXIT
install -d "$fixture/ffmpeg/DEBIAN" "$fixture/ffmpeg/usr/bin"
cat > "$fixture/ffmpeg/DEBIAN/control" <<'EOF'
Package: harboros-ffmpeg
Version: 1.0.0
Architecture: all
Maintainer: Harbor package test
Description: Dependency-only fixture; live ffmpeg acceptance is tested separately
EOF
printf '#!/bin/sh\nexit 0\n' > "$fixture/ffmpeg/usr/bin/ffmpeg"
chmod 0755 "$fixture/ffmpeg/usr/bin/ffmpeg"
dpkg-deb --build --root-owner-group "$fixture/ffmpeg" "$fixture/harboros-ffmpeg.deb" >/dev/null
dpkg --install "$fixture/harboros-ffmpeg.deb"
SYSTEMD_OFFLINE=1 dpkg --install "$artifact"
test ! -e /etc/harboros/service-auth
grep -Fxq 'ExecStartPre=/usr/lib/harboros-im-gate/ensure-harborbeacon-token-env prepare' /usr/lib/systemd/system/harboros-service-auth-recovery.service
# Execute the real first-boot pair in this disposable root filesystem.
/usr/lib/harboros-im-gate/ensure-harborbeacon-token-env prepare
/usr/lib/harboros-im-gate/ensure-harborbeacon-token-env recover
for name in gate-to-beacon.send gate-to-beacon.accept-current gate-to-beacon.accept-previous beacon-to-gate.send beacon-to-gate.accept-current beacon-to-gate.accept-previous; do
  test "$(stat -c '%u:%g:%a' "/etc/harboros/service-auth/$name")" = 0:0:600
done
cmp /etc/harboros/service-auth/gate-to-beacon.send /etc/harboros/service-auth/gate-to-beacon.accept-current
cmp /etc/harboros/service-auth/beacon-to-gate.send /etc/harboros/service-auth/beacon-to-gate.accept-current
! cmp -s /etc/harboros/service-auth/gate-to-beacon.send /etc/harboros/service-auth/beacon-to-gate.send
test "$(stat -c '%a' /var/lib/harboros-im-gate)" = 700
test "$(stat -c '%a' /var/lib/harboros-im-gate/sessions)" = 700
test "$(stat -c '%u:%g:%a' /etc/harboros/service-auth)" = 0:0:700
test -f /usr/lib/systemd/system/harboros-service-auth-recovery.service
cp -a /etc/harboros/service-auth "$fixture/auth-before"
cp /usr/lib/systemd/system/harboros-im-gate.service "$fixture/unit-before"
dpkg --install "$artifact"
diff --recursive "$fixture/auth-before" /etc/harboros/service-auth
cmp "$fixture/unit-before" /usr/lib/systemd/system/harboros-im-gate.service
dpkg --remove harboros-im-gate
test ! -e /usr/bin/harboros-im-gate
test -d /var/lib/harboros-im-gate
dpkg --remove harboros-ffmpeg
