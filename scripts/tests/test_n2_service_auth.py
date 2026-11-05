"""Run the production root-only writer against disposable N2 filesystem roots."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
A, B, C = 'a'*64, 'b'*64, 'c'*64
NAMES = ('gate-to-beacon.send','gate-to-beacon.accept-current','gate-to-beacon.accept-previous',
         'beacon-to-gate.send','beacon-to-gate.accept-current','beacon-to-gate.accept-previous')

@unittest.skipUnless(hasattr(os,'geteuid') and os.geteuid()==0 and shutil.which('bash'), 'requires disposable root Linux')
class N2MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.auth=self.root/'auth';self.legacy=self.root/'beacon-gate.env'
    def tearDown(self):self.temp.cleanup()
    def write(self,path,text):
        path.write_text(text);path.chmod(0o600)
    def legacy_pair(self,a=A,b=B):
        self.write(self.legacy,f'HARBORGATE_BEARER_TOKEN={b}\nIM_AGENT_SERVICE_TOKEN={b}\nHARBORBEACON_WEB_API_TOKEN={a}\n')
    def four(self):
        self.auth.mkdir(mode=0o700)
        for name,value in zip(NAMES,(A,A,'',B,B,'')):
            if not name.endswith('previous'):self.write(self.auth/name,value+'\n')
    def run_writer(self,mode='migrate-n2',failpoint=None):
        env=dict(os.environ,HARBOR_SERVICE_AUTH_DIR=str(self.auth),HARBOR_LEGACY_SHARED_ENV_FILE=str(self.legacy))
        if failpoint:env['HARBOR_SERVICE_AUTH_FAILPOINT']=failpoint
        result=subprocess.run(['bash',str(ROOT/'debian/ensure-harborbeacon-token-env'),mode],env=env,capture_output=True,text=True)
        for secret in (A,B,C):
            self.assertNotIn(secret,result.stdout+result.stderr)
        return result
    def snapshot(self):return {n:(self.auth/n).read_bytes() for n in NAMES if (self.auth/n).exists()}
    def test_first_boot_mints_directional_private_six_and_reprepare_preserves(self):
        self.assertEqual(self.run_writer().returncode,0)
        before=self.snapshot();self.assertEqual(len(before),6)
        self.assertNotEqual(before[NAMES[0]],before[NAMES[3]])
        for name in NAMES:self.assertEqual((self.auth/name).stat().st_mode&0o777,0o600)
        self.assertEqual(self.run_writer().returncode,0);self.assertEqual(before,self.snapshot())
    def test_generic_empty_previous_slots_initialize_and_journal_crash_recovers(self):
        self.auth.mkdir(mode=0o700)
        for name in (NAMES[2],NAMES[5]):self.write(self.auth/name,'\n')
        self.assertEqual(self.run_writer(failpoint='after_rename_3_sigkill').returncode,-9)
        self.assertEqual(self.run_writer().returncode,0)
        self.assertEqual(len(self.snapshot()),6)
        before=self.snapshot();self.assertEqual(self.run_writer().returncode,0)
        self.assertEqual(before,self.snapshot())
    def test_nonempty_previous_only_snapshot_fails_without_generating_tokens(self):
        self.auth.mkdir(mode=0o700)
        for name in (NAMES[2],NAMES[5]):self.write(self.auth/name,A+'\n')
        before=self.snapshot();self.assertNotEqual(self.run_writer().returncode,0)
        self.assertEqual(before,self.snapshot())
    def test_legacy_only_import_preserves_exact_tokens(self):
        self.legacy_pair();before=self.legacy.read_bytes()
        self.assertEqual(self.run_writer().returncode,0)
        self.assertEqual((self.auth/NAMES[0]).read_text(),A+'\n')
        self.assertEqual((self.auth/NAMES[3]).read_text(),B+'\n')
        self.assertEqual(before,self.legacy.read_bytes())
    def test_four_files_matching_legacy_only_add_empty_previous(self):
        self.four();self.legacy_pair();before=self.snapshot()
        self.assertEqual(self.run_writer().returncode,0)
        after=self.snapshot();self.assertEqual({n:after[n] for n in before},before)
        self.assertEqual(after[NAMES[2]],b'\n');self.assertEqual(after[NAMES[5]],b'\n')
        self.assertEqual(self.run_writer('recover').returncode,0)
    def test_four_files_without_legacy_preserved(self):
        self.four();self.assertEqual(self.run_writer().returncode,0)
        self.assertEqual((self.auth/NAMES[0]).read_text(),A+'\n')
    def test_four_and_six_legacy_mismatch_fail_without_token_writes(self):
        for complete in (False,True):
            if not self.auth.exists():self.four()
            if complete:
                self.legacy.unlink();self.assertEqual(self.run_writer().returncode,0)
            self.legacy_pair(C,B);before=self.snapshot()
            self.assertNotEqual(self.run_writer().returncode,0);self.assertEqual(before,self.snapshot())
    def test_interrupted_previous_publish_resumes_without_replacing_four(self):
        self.four();self.legacy_pair();before=self.snapshot()
        self.assertEqual(self.run_writer(failpoint='after_n2_previous_1_sigkill').returncode,-9)
        self.assertEqual(len(self.snapshot()),5)
        self.assertEqual(self.run_writer().returncode,0)
        self.assertEqual({n:self.snapshot()[n] for n in before},before)
    def test_unsafe_or_executable_legacy_is_data_and_fails_closed(self):
        for value in (f'HARBORGATE_BEARER_TOKEN=$(touch {self.root}/executed)\n',
                      f'HARBORGATE_BEARER_TOKEN={A}\nIM_AGENT_SERVICE_TOKEN={C}\nHARBORBEACON_WEB_API_TOKEN={B}\n'):
            self.write(self.legacy,value)
            self.assertNotEqual(self.run_writer().returncode,0)
            self.assertEqual(self.snapshot(),{});self.assertFalse((self.root/'executed').exists())
    def test_binary_legacy_is_rejected_before_any_canonical_token_write(self):
        self.legacy_pair();payload=self.legacy.read_bytes().replace(b'a',b'a\x00',1).rstrip(b'\n')
        self.legacy.write_bytes(payload)
        self.assertNotEqual(self.run_writer().returncode,0);self.assertEqual(self.snapshot(),{})
    def test_partial_missing_sender_and_symlink_previous_rejected(self):
        self.four();(self.auth/NAMES[0]).unlink();before=self.snapshot()
        self.assertNotEqual(self.run_writer().returncode,0);self.assertEqual(before,self.snapshot())
        self.write(self.auth/NAMES[0],A+'\n');(self.auth/NAMES[2]).symlink_to(self.legacy)
        self.assertNotEqual(self.run_writer().returncode,0)
    def test_legacy_prepare_still_refuses_four_files(self):
        self.four();before=self.snapshot();self.assertNotEqual(self.run_writer('prepare').returncode,0)
        self.assertEqual(before,self.snapshot())

if __name__=='__main__':unittest.main()
