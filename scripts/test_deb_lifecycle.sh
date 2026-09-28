#!/usr/bin/env bash
set -euo pipefail

[[ "$#" -eq 1 ]] || { echo "usage: $0 PACKAGE.deb" >&2; exit 2; }
artifact="$1"
[[ -f "$artifact" ]] || { echo "error: package not found: $artifact" >&2; exit 2; }

depends="$(dpkg-deb --field "$artifact" Depends)"
grep -Eq '(^|, )harboros-system(,|$)' <<<"$depends"
! grep -Eq 'harboros-system[[:space:]]*\(' <<<"$depends"

[[ ! -e /etc/harboros/service-auth ]] || {
  echo "error: lifecycle fixture requires a disposable container without service credentials" >&2
  exit 2
}
[[ ! -e /run/harboros/home.env ]] || {
  echo "error: lifecycle fixture requires a disposable container without a Home environment" >&2
  exit 2
}
fixture="$(mktemp -d)"
trap 'rm -rf -- "$fixture"; rm -f -- /run/harboros/home.env' EXIT
install -d "$fixture/system/DEBIAN" "$fixture/system/usr/lib/systemd/system"
cat > "$fixture/system/DEBIAN/control" <<'EOF'
Package: harboros-system
Version: 1.0.0+ci
Architecture: all
Maintainer: Harbor package test
Description: Test-only dependency fixture for HarborGate lifecycle CI
EOF
cat > "$fixture/system/usr/lib/systemd/system/harboros-bootstrap.service" <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/true
EOF
dpkg-deb --build --root-owner-group "$fixture/system" "$fixture/harboros-system.deb" >/dev/null
dpkg --unpack "$fixture/harboros-system.deb"
dpkg --configure harboros-system
install -d -m 0755 /run/harboros
printf 'HARBOR_WORKSPACE_ID=home-ci\n' > /run/harboros/home.env
chmod 0644 /run/harboros/home.env

dpkg --unpack "$artifact"
dpkg --configure harboros-im-gate
test -x /usr/bin/harboros-im-gate
test -f /usr/lib/systemd/system/harboros-im-gate.service
test -x /usr/lib/harborgate/ensure-data-layout
test -x /usr/lib/harboros-im-gate/ensure-harborbeacon-token-env
test -f /usr/lib/systemd/system/harboros-service-auth-recovery.service
test "$(dpkg-deb --field "$artifact" Provides)" = 'harboros-service-auth-abi (= 1)'
test "$(stat -c '%u:%g:%a' /etc/harboros/service-auth)" = '0:0:700'
for name in gate-to-beacon.send gate-to-beacon.accept-current gate-to-beacon.accept-previous beacon-to-gate.send beacon-to-gate.accept-current beacon-to-gate.accept-previous; do
  test "$(stat -c '%u:%g:%a' "/etc/harboros/service-auth/$name")" = '0:0:600'
done
cmp /etc/harboros/service-auth/gate-to-beacon.send /etc/harboros/service-auth/gate-to-beacon.accept-current
cmp /etc/harboros/service-auth/beacon-to-gate.send /etc/harboros/service-auth/beacon-to-gate.accept-current
! cmp -s /etc/harboros/service-auth/gate-to-beacon.send /etc/harboros/service-auth/beacon-to-gate.send
cp -a /etc/harboros/service-auth "$fixture/auth-before"
test -f /usr/share/harboros/component-contracts/harboros-im-gate.json
test -f /usr/share/doc/harboros-im-gate/k3-runtime-evidence-required.json
test -f /usr/share/doc/harboros-im-gate/first-party-rights-approval.json
test -f /usr/share/doc/harboros-im-gate/third-party-licenses.json
test "$(stat -c '%a' /data/harborgate)" = "700"
test "$(stat -c '%a' /data/harborgate/device-sessions)" = "700"
grep -Fq 'Environment=IM_AGENT_HOST=127.0.0.1' \
  /usr/lib/systemd/system/harboros-im-gate.service
grep -Fq 'Environment=HARBORGATE_DEVICE_SESSION_STATE_DIR=/data/harborgate/device-sessions' \
  /usr/lib/systemd/system/harboros-im-gate.service
grep -Fq 'Requires=harboros-bootstrap.service' \
  /usr/lib/systemd/system/harboros-im-gate.service
grep -Fxq 'EnvironmentFile=/run/harboros/home.env' \
  /usr/lib/systemd/system/harboros-im-gate.service
grep -Fxq 'HARBOR_WORKSPACE_ID=home-ci' /run/harboros/home.env
grep -Fq 'LoadCredential=gate-to-beacon-send:/etc/harboros/service-auth/gate-to-beacon.send' \
  /usr/lib/systemd/system/harboros-im-gate.service
! grep -Fq '/etc/default/harboros-im-gate' \
  /usr/lib/systemd/system/harboros-im-gate.service
! grep -Fq '/etc/default/harboros-beacon-gate' \
  /usr/lib/systemd/system/harboros-im-gate.service
python3 -m json.tool /usr/share/harboros/component-contracts/harboros-im-gate.json >/dev/null
python3 -m json.tool /usr/share/doc/harboros-im-gate/k3-runtime-evidence-required.json >/dev/null
python3 -m json.tool /usr/share/doc/harboros-im-gate/first-party-rights-approval.json >/dev/null
python3 -m json.tool /usr/share/doc/harboros-im-gate/third-party-licenses.json >/dev/null
HARBOR_WORKSPACE_ID=home-ci bash ./scripts/test_runtime_smoke.sh

# Reinstalling the exact release exercises the package upgrade path without
# inventing a second package version outside the frozen EVT package set.
dpkg --unpack "$artifact"
dpkg --configure harboros-im-gate
diff --recursive "$fixture/auth-before" /etc/harboros/service-auth
dpkg --remove harboros-im-gate
test ! -e /usr/bin/harboros-im-gate
test -d /data/harborgate
dpkg --remove harboros-system
