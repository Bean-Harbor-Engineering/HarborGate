import json
import os
from pathlib import Path
import tempfile
import unittest

import edge_bootstrap


class NativeBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.proc = self.root / 'proc'
        self.process = self.proc / '42'
        self.process.mkdir(parents=True)
        self.state = self.root / 'real-beacon-state.json'
        self.state.write_text(json.dumps({'platform': {'workspaces': [
            {'workspace_id': 'inactive-workspace', 'status': 'suspended'},
            {'workspace_id': 'real-active-workspace', 'status': 'active'},
        ]}}), encoding='utf-8')
        self.original_token = self.root / 'original-gate-token'
        self.original_token.write_text('real-file-token', encoding='utf-8')
        self.write_process({'HARBOR_GATE_TO_BEACON_TOKEN_FILE': str(self.original_token),
                            'HARBOR_GATE_TO_BEACON_TOKEN': 'stale-env-token'})

    def tearDown(self):
        self.directory.cleanup()

    def write_process(self, environment, arguments=None):
        self.process.joinpath('environ').write_bytes(('\0'.join(key + '=' + value for key, value in environment.items())
                                                    + '\0').encode())
        self.process.joinpath('cmdline').write_bytes(('\0'.join(arguments or [
            '/usr/bin/harboros-beacon', '--admin-state', str(self.state)]) + '\0').encode())

    def test_real_process_state_and_file_credential_define_configuration(self):
        config = edge_bootstrap.beacon_context(42, self.proc)
        self.assertEqual(config.workspace_id, 'real-active-workspace')
        self.assertEqual(config.service_token, 'real-file-token')
        self.assertEqual(self.original_token.read_text(encoding='utf-8'), 'real-file-token')

    def test_systemd_credential_precedes_explicit_file_and_environment(self):
        credentials = self.root / 'systemd-credentials'
        credentials.mkdir()
        (credentials / 'gate-to-beacon-accept-current').write_text('systemd-current-token', encoding='utf-8')
        self.write_process({'CREDENTIALS_DIRECTORY': str(credentials),
                            'HARBOR_GATE_TO_BEACON_TOKEN_FILE': str(self.original_token),
                            'HARBOR_GATE_TO_BEACON_TOKEN': 'stale-env-token'})
        self.assertEqual(edge_bootstrap.beacon_context(42, self.proc).service_token, 'systemd-current-token')

    def test_missing_state_workspace_or_configured_credential_never_guesses_defaults(self):
        self.state.write_text(json.dumps({'platform': {'workspaces': [
            {'workspace_id': 'home-1', 'status': 'suspended'},
        ]}}), encoding='utf-8')
        with self.assertRaises(ValueError):
            edge_bootstrap.beacon_context(42, self.proc)
        self.write_process({'HARBOR_GATE_TO_BEACON_TOKEN_FILE': str(self.root / 'missing-token'),
                            'HARBOR_GATE_TO_BEACON_TOKEN': 'must-not-fall-back'})
        with self.assertRaises(FileNotFoundError):
            edge_bootstrap.beacon_context(42, self.proc)
        with self.assertRaises(FileNotFoundError):
            edge_bootstrap.beacon_context(999, self.proc)

    def test_admin_state_must_come_from_actual_process_command_line(self):
        self.write_process({'HARBOR_GATE_TO_BEACON_TOKEN': 'valid-token'}, ['/usr/bin/harboros-beacon'])
        with self.assertRaises(ValueError):
            edge_bootstrap.beacon_context(42, self.proc)
        self.write_process({'HARBOR_GATE_TO_BEACON_TOKEN': 'valid-token'}, [
            '/usr/bin/harboros-beacon', '--admin-state=' + str(self.state)])
        self.assertEqual(edge_bootstrap.beacon_context(42, self.proc).workspace_id, 'real-active-workspace')

    def test_configuration_writes_only_edge_copy_and_references_the_real_workspace(self):
        config = edge_bootstrap.beacon_context(42, self.proc)
        environment = self.root / 'edge-defaults'
        credential = self.root / 'edge-runtime' / 'gate-token'
        result = edge_bootstrap.write_edge_configuration(config, environment, credential)
        self.assertEqual(result['HARBOR_EDGE_WORKSPACE_ID'], 'real-active-workspace')
        self.assertEqual(result['HARBOR_GATE_TO_BEACON_TOKEN_FILE'], str(credential))
        self.assertEqual(credential.read_text(encoding='utf-8').strip(), 'real-file-token')
        self.assertNotIn('real-file-token', environment.read_text(encoding='utf-8'))
        self.assertEqual(self.original_token.read_text(encoding='utf-8'), 'real-file-token')
        if os.name != 'nt':
            self.assertEqual(credential.stat().st_mode & 0o777, 0o600)
            self.assertEqual(credential.parent.stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main()
