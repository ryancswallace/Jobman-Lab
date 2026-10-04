#!/usr/bin/env python3
"""Offline fixed-scope, exact-byte and receipt tests; no Lab access."""
import base64
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
def load(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
c=load('dashboard-scale-identities-common');g=load('dashboard-scale-directory-guest');g.c=c


class DirectoryTests(unittest.TestCase):
    def fixture(self):
        spec=dict(g.SPECS['primary']);before=('User='+spec['user']+'\nExecStart='+spec['old']+' '+' '.join(spec['args'])+'\n').encode();spec['unitSHA256']=c.sha(before)
        snapshot={'version':1,'profile':'primary','epoch':0,'process':{'ExecMainStartTimestampMonotonic':'100'},'preserved':{'same':True},'before':base64.b64encode(before).decode(),'afterSHA256':c.sha(g.transformed(before,spec)),'binarySHA256':g.BINARY_SHA}
        p={'profile':'primary','snapshot':snapshot,'snapshotSHA256':c.sha(c.encoded(snapshot)),'apply':True}
        return spec,before,p

    def test_exact_binary_only_transform_preserves_arguments(self):
        spec,before,_=self.fixture();after=g.transformed(before,spec)
        self.assertEqual(after.replace(str(g.BINARY).encode(),spec['old'].encode()),before)
        for changed in (before+b'\n',before.replace(b'--root',b'--config')):
            with self.assertRaises(c.Failure):g.transformed(changed,spec)
        duplicate=before+b'ExecStart='+spec['old'].encode()+b'\n';spec['unitSHA256']=c.sha(duplicate)
        with self.assertRaisesRegex(c.Failure,'original_unit_command'):g.transformed(duplicate,spec)

    def test_fixed_source_roles_and_helper(self):
        self.assertEqual(set(g.SPECS),{'primary','secondary'})
        self.assertEqual(g.SPECS['primary']['uid'],21902);self.assertEqual(g.SPECS['secondary']['uid'],21908)
        self.assertEqual(g.SPECS['secondary']['args'],['directory','--profile','secondary-v1','--root','/etc/jobman-dashboard-secondary/directory'])
        self.assertEqual(g.BINARY_SHA,'6f511e91434dac2499d464f0b424607fe0b099b966148c992499e5371a333f65')

    def test_private_snapshot_digest_and_preserved_source_drift(self):
        spec,_,p=self.fixture();p['phase']='stage'
        with patch.object(g.os,'geteuid',return_value=0),patch.object(g.os,'uname') as host,patch.dict(g.SPECS,{'primary':spec}),patch.object(g,'preserved',return_value={'different':True}):
            host.return_value.nodename='control01'
            with self.assertRaisesRegex(c.Failure,'preserved_source_drift'):g.execute(p)
            p['snapshotSHA256']='a'*64
            with self.assertRaisesRegex(c.Failure,'snapshot_binding'):g.execute(p)

    def test_mutations_require_explicit_apply_before_writes(self):
        spec,_,p=self.fixture();p.update(phase='swap',apply=False)
        with patch.object(g.os,'geteuid',return_value=0),patch.object(g.os,'uname') as host,patch.dict(g.SPECS,{'primary':spec}),patch.object(g,'preserved',return_value=p['snapshot']['preserved']),patch.object(g,'root_directory'),patch.object(c,'read',return_value=b'binary'),patch.object(c,'sha',side_effect=lambda raw:g.BINARY_SHA if raw==b'binary' else __import__('hashlib').sha256(raw).hexdigest()),patch.object(c,'mkdir') as mkdir:
            host.return_value.nodename='control01'
            with self.assertRaisesRegex(c.Failure,'explicit_apply_required'):g.execute(p)
            mkdir.assert_not_called()

    def test_exclusive_files_reject_drift_and_symlink(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();path=root/'unit'
            with patch.object(g.os,'fchown'):g.write_mode(path,b'reviewed',0o644)
            with patch.object(c,'read',return_value=b'reviewed'):g.write_mode(path,b'reviewed',0o644)
            with patch.object(c,'read',return_value=b'changed'):
                with self.assertRaisesRegex(c.Failure,'retained_file_differs'):g.write_mode(path,b'reviewed',0o644)
            link=root/'link';link.symlink_to(path)
            with self.assertRaises(OSError):c.read(link,mode=0o644)

    def test_restart_verifies_new_process_and_never_requeues_completed(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();spec,_,p=self.fixture();snapshot=p['snapshot'];binding={'proof':'same'}
            after={'ExecMainStartTimestampMonotonic':'200'}
            with patch.object(g,'identity',side_effect=[snapshot['process'],after,after]),patch.object(g,'tls_ready') as tls,patch.object(g,'command') as command:
                g.restart(spec,snapshot,root,binding,'restart')
                self.assertEqual(command.call_count,2)
                g.restart(spec,snapshot,root,binding,'restart')
                self.assertEqual(command.call_count,2);self.assertEqual(tls.call_count,2)
            self.assertEqual(c.decode(c.read(root/'restart.json')),dict(binding,process=after))

    def test_lost_reply_observes_ready_process_without_second_restart(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();spec,_,p=self.fixture();binding={'proof':'same'}
            c.put(root/'restart.pending.json',c.encoded(binding))
            with patch.object(g,'identity',return_value={'ExecMainStartTimestampMonotonic':'200'}),patch.object(g,'tls_ready'),patch.object(g,'command') as command:
                g.restart(spec,p['snapshot'],root,binding,'restart');command.assert_not_called()

    def test_completed_restart_rejects_an_unrelated_later_restart(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();spec,_,p=self.fixture();binding={'proof':'same'}
            c.put(root/'restart.pending.json',c.encoded(binding));c.put(root/'restart.json',c.encoded(dict(binding,process={'ExecMainStartTimestampMonotonic':'200'})))
            with patch.object(g,'identity',return_value={'ExecMainStartTimestampMonotonic':'300'}),patch.object(g,'command') as command:
                with self.assertRaisesRegex(c.Failure,'completed_restart_identity'):g.restart(spec,p['snapshot'],root,binding,'verify')
                command.assert_not_called()

    def test_uncertain_restart_retains_pending_and_refuses_same_process(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();spec,_,p=self.fixture();binding={'proof':'same'};c.put(root/'restart.pending.json',c.encoded(binding))
            with patch.object(g,'identity',return_value=p['snapshot']['process']),patch.object(g,'command') as command,patch.object(g.time,'monotonic',side_effect=[0,41]):
                with self.assertRaisesRegex(c.Failure,'ldap_restart_not_ready'):g.restart(spec,p['snapshot'],root,binding,'restart')
                command.assert_not_called()
            self.assertTrue((root/'restart.pending.json').exists());self.assertFalse((root/'restart.json').exists())

    def test_deadline_caps_each_readiness_command(self):
        with patch.object(g.time,'monotonic',return_value=8):
            self.assertEqual(g.remaining(10,5),2)
            with self.assertRaisesRegex(c.Failure,'verification_deadline'):g.remaining(7,5)


if __name__=='__main__':unittest.main()
