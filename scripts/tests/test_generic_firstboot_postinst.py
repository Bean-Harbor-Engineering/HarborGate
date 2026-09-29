from pathlib import Path
import os
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.name != 'posix' or not hasattr(os, 'geteuid')
                              or os.geteuid() != 0, reason='Linux root maintainer fixture')
CURRENT = [f'{direction}.{suffix}' for direction in ('gate-to-beacon', 'beacon-to-gate')
           for suffix in ('send', 'accept-current')]


@pytest.fixture
def image(tmp_path):
    etc = tmp_path / 'etc/harboros'
    auth = etc / 'service-auth'
    auth.mkdir(parents=True, mode=0o700)
    marker = etc / 'engineering-zigbee-firstboot'
    marker.touch(mode=0o644)
    for name in ('gate-to-beacon.accept-previous', 'beacon-to-gate.accept-previous'):
        path = auth / name
        path.write_bytes(b'\n')
        path.chmod(0o600)
    lock = auth / '.credential-writer.lock'
    lock.touch(mode=0o600)
    helper = ROOT / 'debian/ensure-harborbeacon-token-env'
    script = (ROOT / 'debian/harbornavi-k3/postinst').read_text()
    script = script.replace('/usr/lib/harborgate/ensure-data-layout', '/bin/true')
    script = script.replace('/usr/lib/harboros-im-gate/ensure-harborbeacon-token-env',
                            '/bin/bash ' + str(helper))
    for prefix in ('/etc/harboros/', '/etc/harborlink/', '/data/harboros/'):
        script = script.replace(prefix, str(tmp_path) + prefix)
    # No host systemd side effects: only package/runtime plumbing is stubbed.
    script = script.replace('if command -v deb-systemd-helper', 'if false && command -v deb-systemd-helper')
    script = script.replace('if command -v systemctl', 'if false && command -v systemctl')
    postinst = tmp_path / 'postinst'
    postinst.write_text(script)
    env = dict(os.environ, SYSTEMD_OFFLINE='1', HARBOR_SERVICE_AUTH_DIR=str(auth),
               HARBOR_LEGACY_SHARED_ENV_FILE=str(tmp_path / 'missing-legacy'))
    return tmp_path, auth, helper, postinst, env


def run_postinst(image):
    return subprocess.run(['/bin/sh', str(image[3]), 'configure'], env=image[4],
                          capture_output=True, text=True)


def test_prepared_generic_installs_idempotently_without_generating_shared_keys(image):
    _, auth, _, _, _ = image
    before = {p.name: p.read_bytes() for p in auth.iterdir()}
    for _ in range(2):
        result = run_postinst(image)
        assert result.returncode == 0, result.stderr
        assert 'Deferring per-device' in result.stdout
        assert {p.name: p.read_bytes() for p in auth.iterdir()} == before
        assert not any((auth / name).exists() for name in CURRENT)


def test_initialized_valid_image_preserves_credentials_during_upgrade(image):
    root, auth, helper, _, env = image
    for name in ('gate-to-beacon.accept-previous', 'beacon-to-gate.accept-previous'):
        (auth / name).unlink()
    subprocess.run(['/bin/bash', str(helper), 'prepare'], env=env, check=True,
                   capture_output=True, text=True)
    (root / 'etc/harboros/engineering-setup.json').write_text('{}')
    before = {p.name: p.read_bytes() for p in auth.iterdir()}
    result = run_postinst(image)
    assert result.returncode == 0, result.stderr
    assert 'Deferring per-device' not in result.stdout
    assert {p.name: p.read_bytes() for p in auth.iterdir()} == before


@pytest.mark.parametrize('state', ['initialized', 'online', 'missing_marker', 'partial_key', 'symlink_profile'])
def test_incomplete_credentials_do_not_bypass_normal_validation(image, state):
    root, auth, _, _, env = image
    if state == 'initialized':
        (root / 'etc/harboros/engineering-setup.json').write_text('{}')
    elif state == 'online':
        env.pop('SYSTEMD_OFFLINE')
    elif state == 'missing_marker':
        (root / 'etc/harboros/engineering-zigbee-firstboot').unlink()
    elif state == 'partial_key':
        key = auth / CURRENT[0]
        key.write_text('a' * 64 + '\n')
        key.chmod(0o600)
    elif state == 'symlink_profile':
        (root / 'etc/harboros/engineering-setup.json').symlink_to(root / 'missing')
    result = run_postinst(image)
    assert result.returncode == 67, result.stderr
    assert 'incomplete service-auth credential set' in result.stderr
    assert 'Deferring per-device' not in result.stdout
