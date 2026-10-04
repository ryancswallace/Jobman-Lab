#!/usr/bin/env python3
"""Offline safety checks for separate Slurm staging; no guest or workload calls."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(filename));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


plan=load('slurm_plan_test','dashboard-slurm-plan.py')
prepare=load('slurm_prepare_test','prepare-dashboard-slurm.py')
observe=load('slurm_observe_test','observe-dashboard-slurm.py')


class SlurmPlanTests(unittest.TestCase):
    def setUp(self):
        self.instance='80000000-0000-4000-8000-000000000001';self.namespace='80000000-0000-4000-8000-000000000002';self.generation='80000000-0000-4000-8000-000000000003'
        self.fixture={'synthetic':True,'endpoint':'https://10.77.0.21:18443','instanceId':self.instance,'namespaces':[{'name':'dashboard-operations','id':self.namespace}]}
        self.receipt={'synthetic':True,'mode':'actual-slurm-execution','deploymentId':plan.base.DEPLOYMENT,'controlInstanceId':self.instance,'namespaceId':self.namespace,'namespace':plan.base.NAMESPACE,'targetGenerationId':self.generation,'targetName':plan.TARGET,'storeRoot':plan.STORE_ROOT}
        self.config={'configurationRevision':7,'controls':[{'id':plan.base.DEPLOYMENT,'expectedInstanceId':self.instance,'origin':'https://10.77.0.21:18443','namespaceIds':[self.namespace]}],'logBrokers':[{'id':'control01-nfs','deploymentId':plan.base.DEPLOYMENT,'origin':'https://10.77.0.21:19443','namespaceIds':[self.namespace]}],'logRoots':[{'preserved':'existing'}],'logMappings':[{'preserved':'existing'}],'unrelated':{'mode':'worker','keys':['private-file-reference']}}

    def test_exact_clean_runner_private_bundles_and_bounded_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);raw=bytearray(32);raw[:6]=b'\x7fELF\x02\x01';raw[18:20]=b'\xb7\x00'
            (root/'jobman-agent').write_bytes(raw);digest=hashlib.sha256(raw).hexdigest()
            (root/'build.json').write_text(json.dumps({'revision':plan.base.REVISION,'platform':'linux/arm64','toolchain':'go1.26.6','sha256':{'jobman-agent':digest}}))
            value=plan.make_plan(root,self.fixture,'a'*40);unit=plan.unit_text(digest)
            self.assertEqual(value['targetRequest']['spec']['executionBackend'],'slurm');self.assertEqual(value['maximumRunSeconds'],30);self.assertEqual(value['maximumRuns'],1)
            self.assertNotEqual(value['bundleRoot'],value['storeRoot']);self.assertIn('--slurm-root '+plan.BUNDLE_ROOT,unit);self.assertIn('--slurm-runner '+value['runner'],unit)
            self.assertEqual(value['runnerCopies'],['submit01','compute01']);self.assertEqual(value['runnerLayout'],'identical-root-owned-local');self.assertNotIn('/shared/apps/',unit);self.assertNotIn('/var/lib/jobman-agent/',unit)
            (root/'jobman-agent').write_bytes(b'changed')
            with self.assertRaises(ValueError):plan.make_plan(root,self.fixture,'a'*40)

    def test_mapping_preserves_everything_and_exact_retry_is_noop(self):
        for role in ['api','reports','broker']:
            original=copy.deepcopy(self.config);changed=plan.mapping_patch(original,self.receipt,role,7)
            key='logRoots' if role=='broker' else 'logMappings'
            self.assertEqual(changed['configurationRevision'],8);self.assertEqual(changed[key][0],{'preserved':'existing'})
            self.assertEqual(changed['unrelated'],original['unrelated']);self.assertEqual(original,self.config)
            self.assertEqual(plan.mapping_patch(changed,self.receipt,role,8),changed)
            if role=='broker':self.assertEqual(changed[key][1]['root'],plan.STORE_ROOT)

    def test_scope_revision_and_existing_destination_fail_closed(self):
        for field,value in [('mode','actual-subprocess-execution'),('controlInstanceId','wrong'),('namespaceId','wrong'),('targetName','onprem-slurm'),('storeRoot','/data/jobman/alice')]:
            bad=dict(self.receipt,**{field:value})
            with self.assertRaises(ValueError):plan.mapping_patch(self.config,bad,'broker',7)
        with self.assertRaises(ValueError):plan.mapping_patch(self.config,self.receipt,'api',6)
        changed=plan.mapping_patch(self.config,self.receipt,'broker',7);changed['logRoots'][-1]['root']='/data/jobman/alice'
        with self.assertRaises(ValueError):plan.mapping_patch(changed,self.receipt,'broker',8)

    def test_remote_programs_compile_and_keep_acl_roles_separate(self):
        for name in ['RUNNER','USER_STORAGE','SUBMIT','ENROLL']:compile(getattr(prepare,name),'<'+name+'>','exec')
        # Execution of filesystem-only submit helpers catches inherited umask
        # changes without touching any real service or root-owned directory.
        source=prepare.SUBMIT;helpers=source[source.index('def directory('):source.index('runner=Path(')]
        import os,stat
        namespace={'os':os,'stat':stat};exec(helpers,namespace)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);old=os.umask(0o077)
            try:namespace['directory'](root/'new',0o755,os.getuid(),os.getgid())
            finally:os.umask(old)
            self.assertEqual(stat.S_IMODE((root/'new').stat().st_mode),0o755)
            (root/'existing').mkdir(mode=0o700)
            with self.assertRaises(AssertionError):namespace['directory'](root/'existing',0o755,os.getuid(),os.getgid())
            self.assertEqual(stat.S_IMODE((root/'existing').stat().st_mode),0o700)



    def test_observation_scope_and_literal_array_indices(self):
        request={'operation':'accounting','parentId':'123','collectionId':self.instance}
        self.assertEqual(observe.validate(request),request)
        lines=[]
        for index in range(5):
            lines.append(f'{123+index}|123_{index}|COMPLETED|0:0|compute01|jobman-array-{self.instance}|2026-10-04T01:00:00|2026-10-04T01:00:03')
        value=observe.accounting('\n'.join(lines),request)
        self.assertEqual([x['jobId'] for x in value['rows']],['123_0','123_1','123_2','123_3','123_4'])
        for bad in [dict(request,parentId='123,456'),dict(request,collectionId='not-a-uuid'),dict(request,operation='cancel'),dict(request,extra='secret')]:
            with self.assertRaises(ValueError):observe.validate(bad)
        for bad in [lines[:4],lines+[lines[0]],lines[:4]+[lines[0]], [lines[0].replace('123_0','123_[0-4]')]+lines[1:], [lines[0].replace('jobman-array-'+self.instance,'unrelated')]+lines[1:]]:
            with self.assertRaises(ValueError):observe.accounting('\n'.join(bad),request)
        compile(observe.REMOTE,'<read-only-slurm>','exec')


if __name__=='__main__':unittest.main()
