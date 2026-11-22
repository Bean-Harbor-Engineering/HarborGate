#!/usr/bin/env python3
"""Start the packaged NAS edge from the running Beacon's real configuration.

No shared Gate credential is generated or overwritten. On first boot/package
ordering races systemd retries this entry point until Beacon has a real active
workspace and effective Gate credential. Native N2 does not use this transport.
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

from edge_proxy import Config

PACKAGE_ROOT = Path('/usr/lib/harboros-im-gate')
ENVIRONMENT_FILE = Path('/etc/default/harbor-gate-webui-edge')
EDGE_CREDENTIAL_FILE = Path('/run/harbor-gate-webui-edge/gate-to-beacon')


def effective_gate_token(environment):
    # Match Beacon's service_auth.rs precedence: systemd credential, explicit
    # file, current environment, then the legacy environment alias.
    credentials_directory = environment.get('CREDENTIALS_DIRECTORY', '').strip()
    if credentials_directory:
        inferred = Path(credentials_directory) / 'gate-to-beacon-accept-current'
        if inferred.exists():
            return read_credential(inferred)
    configured_file = environment.get('HARBOR_GATE_TO_BEACON_TOKEN_FILE', '').strip()
    if configured_file:
        return read_credential(Path(configured_file))
    return (environment.get('HARBOR_GATE_TO_BEACON_TOKEN')
            or environment.get('HARBORBEACON_WEB_API_TOKEN') or '').strip()


def read_credential(path):
    if path.stat().st_size > 4096:
        raise ValueError('Beacon Gate credential exceeds the supported size')
    return path.read_text(encoding='utf-8').strip()


def beacon_context(pid, proc_root=Path('/proc')):
    process = proc_root / str(pid)
    environment = dict(item.split('=', 1) for item in (process / 'environ').read_bytes().decode().split('\0')
                       if '=' in item)
    arguments = (process / 'cmdline').read_bytes().decode().rstrip('\0').split('\0')
    admin_state = None
    for index, value in enumerate(arguments):
        if value == '--admin-state' and index + 1 < len(arguments):
            admin_state = arguments[index + 1]
        elif value.startswith('--admin-state='):
            admin_state = value.split('=', 1)[1]
    if not admin_state or not Path(admin_state).is_absolute():
        raise ValueError('Running Beacon must declare its real admin state path')
    state = json.loads(Path(admin_state).read_text(encoding='utf-8'))
    workspace = next((item.get('workspace_id') for item in state.get('platform', {}).get('workspaces', [])
                      if item.get('status') == 'active'), None)
    # Config validates the real workspace/token; there is no guessed home-1 fallback.
    return Config(service_token=effective_gate_token(environment), workspace_id=workspace or '')


def atomic_private_file(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.next')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            output.write(content)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_edge_configuration(config, environment_file=ENVIRONMENT_FILE, credential_file=EDGE_CREDENTIAL_FILE):
    credential_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    credential_file.parent.chmod(0o700)
    atomic_private_file(credential_file, config.service_token + '\n')
    values = {'HARBOR_GATE_TO_BEACON_TOKEN_FILE': str(credential_file),
              'HARBOR_EDGE_WORKSPACE_ID': config.workspace_id}
    atomic_private_file(environment_file, ''.join(key + '=' + shlex.quote(value) + '\n'
                                                for key, value in values.items()))
    return values


def main():
    try:
        result = subprocess.run(['systemctl', 'show', '--property=MainPID', '--value', 'harboros-beacon.service'],
                                check=True, capture_output=True, text=True)
        pid = int(result.stdout.strip())
        if pid <= 0:
            raise ValueError('Beacon has not started')
        config = beacon_context(pid)
        environment = dict(os.environ)
        environment.update(write_edge_configuration(config))
        # Execute the same packaged transport; business URLs and JSON are unchanged.
        os.execve('/usr/bin/python3', ['/usr/bin/python3', str(PACKAGE_ROOT / 'edge_proxy.py')], environment)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError):
        print('HarborGate WebUI edge is waiting for Beacon credentials and an active workspace.', file=sys.stderr)
        return 75


if __name__ == '__main__':
    sys.exit(main())
