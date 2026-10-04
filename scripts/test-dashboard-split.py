#!/usr/bin/env python3
"""Offline split plan regressions. No guests, real keys, role or SQL access."""
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('split', Path(__file__).with_name('dashboard-split-plan.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
spec = importlib.util.spec_from_file_location('split_files', Path(__file__).with_name('dashboard-split-files.py'))
objects = importlib.util.module_from_spec(spec)
spec.loader.exec_module(objects)
spec = importlib.util.spec_from_file_location('split_prepare', Path(__file__).with_name('prepare-dashboard-split.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
spec = importlib.util.spec_from_file_location('split_apply', Path(__file__).with_name('apply-dashboard-split.py'))
apply = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apply)
spec = importlib.util.spec_from_file_location('split_guest', Path(__file__).with_name('dashboard-split-guest.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)
ID = '11111111-1111-4111-8111-111111111111'
NS = ['22222222-2222-4222-8222-222222222222', '33333333-3333-4333-8333-333333333333']


def inputs():
    control = {'id': p.DEPLOYMENT, 'expectedInstanceId': ID, 'origin': 'https://10.77.0.21:18443', 'namespaceIds': NS,
               'trustRootsFile': p.LEGACY + '/control-ca.crt', 'audience': 'urn:jobman:dashboard-lab:control'}
    mapping = {'deploymentId': p.DEPLOYMENT, 'targetGenerationId': ID, 'storeName': 'lab-nfs', 'storeVersion': '1'}
    app = {'configurationRevision': 4, 'publicOrigin': 'https://dashboard.lab.test:8443', 'listen': '10.77.0.10:8443',
           'databaseURLFile': p.LEGACY + '/database-url', 'encryption': {'keyId': 'legacy', 'keyFile': p.LEGACY + '/encryption-key'},
           'serverTLS': {'certificateFile': p.LEGACY + '/server.crt', 'keyFile': p.LEGACY + '/server.key'},
           'oidc': {'issuer': 'https://oidc.lab.test:8443/realms/jobman-lab', 'webClientSecretFile': p.LEGACY + '/web-client-secret'},
           'reports': {'objectRoot': p.REPORT_OLD, 'redactionFile': p.LEGACY + '/redaction.json'},
           'events': {'enabled': True, 'deliveryHold': False}, 'controls': [control],
           'logBrokers': [{'id': 'control01-nfs', 'audience': 'broker-audience', 'privateExtension': 'preserved'}],
           'logMappings': [dict(mapping, brokerId='control01-nfs')],
           'notifications': {'deviceTopics': [{'topic': 'org.jobman.dashboard', 'environment': 'sandbox'}],
                             'previousTokenKeys': [{'keyId': 'old-key', 'keyFile': p.LEGACY + '/old-key'}]}}
    broker = {'configurationRevision': 3, 'publicOrigin': 'https://10.77.0.21:19443', 'listen': '10.77.0.21:19443',
              'stateDirectory': '/var/lib/jobman-dashboard-broker-lab', 'controls': [dict(control, delegationKeyFile=p.BROKER + '/unchanged-key')],
              'services': [{'serviceId': 'old-retained'}], 'logRoots': [dict(mapping, root='/data/jobman/alice/dashboard-execution')],
              'readerConcurrency': 4}
    fixture = {'synthetic': True, 'endpoint': control['origin'], 'instanceId': ID, 'namespaces': [{'id': n} for n in NS]}
    return app, broker, fixture


class SplitTests(unittest.TestCase):
    def test_dynamic_mappings_preserved_and_credentials_separated(self):
        app, broker, fixture = inputs()
        original = copy.deepcopy((app, broker, fixture))
        result = p.configs(app, broker, fixture, 5, '/opt/jobman-dashboard-lab/releases/' + 'a' * 40)
        self.assertEqual((app, broker, fixture), original)
        api, worker = result['api'], result['worker']
        self.assertEqual(api['logMappings'], app['logMappings'])
        self.assertEqual(worker['logMappings'], app['logMappings'])
        self.assertEqual(result['broker']['logRoots'], broker['logRoots'])
        self.assertEqual(result['broker']['controls'], broker['controls'])
        self.assertEqual(result['broker']['services'][0], broker['services'][0])
        self.assertEqual(len(result['broker']['services']), 3)
        self.assertEqual(api['notifications']['tokenEncryption']['previous'][0]['keyId'], 'old-key')
        self.assertTrue(api['events']['deliveryHold'])
        self.assertTrue(worker['deliveryHold'])
        for forbidden in ('oidc', 'encryption', 'serverTLS', 'webRoot', 'listen', 'publicOrigin'):
            self.assertNotIn(forbidden, worker)
        for forbidden in ('tokenEncryption', 'previousTokenKeys', 'apns'):
            self.assertNotIn(forbidden, worker['notifications'])
        self.assertNotIn('delivery', worker['components'])
        self.assertNotEqual(api['controls'][0]['serviceId'], worker['controls'][0]['serviceId'])
        self.assertEqual(result['rollback']['configurationRevision'], 6)
        self.assertEqual(result['rollback']['reports']['objectRoot'], p.REPORT_OLD)
        self.assertNotIn('objectAccess', result['rollback']['reports'])
        self.assertEqual(result['recovery']['controls'],worker['controls'])
        self.assertEqual(result['recovery']['databaseURLFile'],p.LEGACY+'/database-url')
        self.assertIn('/run/jobman-dashboard-broker-lab/',result['broker']['observability']['socketPath'])

    def test_stale_or_rebound_source_and_mapping_fail_closed(self):
        for mutate in [lambda a,b,f: a.update(configurationRevision=6),
                       lambda a,b,f: a['controls'][0].update(expectedInstanceId=NS[0]),
                       lambda a,b,f: b['logRoots'].clear(),
                       lambda a,b,f: b['logRoots'][0].update(root='/unrelated'),
                       lambda a,b,f: a['notifications'].update(apns=[{'privateKeyFile': '/bad'}]),
                       lambda a,b,f: a['reports'].update(objectAccess={'mode': 'shared_group'})]:
            with self.subTest(mutate=mutate):
                a,b,f=inputs();mutate(a,b,f)
                with self.assertRaises(ValueError):
                    p.configs(a,b,f,5,'/opt/jobman-dashboard-lab/releases/'+'a'*40)

    def test_units_enforce_private_surfaces_and_report_access(self):
        for role in ('api', 'worker'):
            unit = p.unit(role, '/opt/jobman-dashboard-lab/releases/' + 'a' * 40)
            self.assertIn('--mode ' + role, unit)
            self.assertIn('RuntimeDirectoryMode=0700', unit)
            self.assertIn('NoNewPrivileges=true', unit)
            self.assertIn('TimeoutStopSec=90s', unit)
            self.assertIn('InaccessiblePaths=', unit)
            self.assertIn(('ReadOnlyPaths=' if role == 'api' else 'ReadWritePaths=') + p.REPORT_NEW, unit)

    def test_duplicate_json_and_linked_private_input_rejected(self):
        with self.assertRaises(ValueError):
            p.decode(b'{"a":1,"a":2}')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'real').write_bytes(b'{}');(root/'link').symlink_to(root/'real')
            with self.assertRaises(OSError):p.read(root/'link',100)
            (root/'real').chmod(0o644)
            with self.assertRaises(ValueError):p.read(root/'real',100,private=True)

    def test_candidate_requires_exact_digest_full_checksums_and_arm64(self):
        metadata={'formatVersion':1,'releaseState':'candidate','os':'linux','architecture':'arm64','isa':'v8.0',
                  'revision':'a'*40,'version':'v0.1.0-rc.1','toolchains':{'go':'go1.26.6'}}
        binary=b'\x7fELF\x02\x01'+bytes(12)+b'\xb7\x00'+bytes(20)
        files={'build.json':p.encoded(metadata),'bin/jobman-dashboard':binary,'bin/jobman-log-broker':binary,'web/index.html':b'<html/>',
               'deploy/postgres/grants.py':b'# synthetic\n','deploy/postgres/grants.json':p.encoded({'schemaMigration':'000018_runtime_lock_privileges.sql'})}
        files['SHA256SUMS']=''.join(p.sha(raw)+'  '+name+'\n' for name,raw in files.items()).encode()
        def archive(path,values,extra=None):
            with tarfile.open(path,'w:gz') as tar:
                for name,raw in values.items():
                    info=tarfile.TarInfo('jobman-dashboard_v0.1.0-rc.1_linux_arm64/'+name);info.size=len(raw);tar.addfile(info,io.BytesIO(raw))
                if extra:tar.addfile(extra)
            return p.sha(path.read_bytes())
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'candidate.tgz';digest=archive(path,files)
            self.assertEqual(p.candidate_files(path,digest)[0],metadata)
            with self.assertRaises(ValueError):p.candidate_files(path,'0'*64)
            changed=dict(files);changed['web/index.html']=b'changed';digest=archive(path,changed)
            with self.assertRaises(ValueError):p.candidate_files(path,digest)
            link=tarfile.TarInfo('jobman-dashboard_v0.1.0-rc.1_linux_arm64/link');link.type=tarfile.SYMTYPE;link.linkname='/etc/passwd'
            digest=archive(path,files,link)
            with self.assertRaises(ValueError):p.candidate_files(path,digest)

    def test_exact_report_backup_conversion_and_resume_preserve_bytes(self):
        # Linux ACL absence is an apply preflight/runtime check, not a portable
        # macOS unit-test claim. Everything else operates on actual local files.
        import os
        with tempfile.TemporaryDirectory() as temp, patch.object(objects,'no_acl'):
            root=Path(temp);old=root/'old';new=root/'new';old.mkdir(mode=0o700)
            name=ID+'.json';(old/name).write_bytes(b'synthetic sealed object bytes');(old/name).chmod(0o600)
            before=(os.getuid(),os.getgid(),0o700,0o600);after=(os.getuid(),os.getgid(),0o750,0o640)
            inventory=objects.inventory(old,[before])
            objects.backup(old,root/'backup',inventory,before)
            receipt=root/'convert.json'
            objects.write(receipt,objects.canonical({'source':str(old),'destination':str(new),'before':list(before),'after':list(after),'inventory':inventory}))
            objects.convert(old,new,receipt,before,after,allowed_paths=(str(old),str(new)))
            self.assertFalse(old.exists());self.assertTrue(new.exists())
            self.assertEqual(objects.inventory(new,[after]),inventory)
            self.assertEqual((new/name).read_bytes(),(root/'backup'/name).read_bytes())
            objects.convert(old,new,receipt,before,after,allowed_paths=(str(old),str(new)))
            self.assertTrue(Path(str(receipt)+'.complete').exists())
            (new/name).write_bytes(b'unexpected mutation')
            with self.assertRaises(ValueError):objects.convert(old,new,receipt,before,after,allowed_paths=(str(old),str(new)))

    def test_report_unknown_entries_links_and_bound_fail_closed(self):
        import os
        with tempfile.TemporaryDirectory() as temp, patch.object(objects,'no_acl'):
            root=Path(temp);profile=(os.getuid(),os.getgid(),0o700,0o600)
            bad=root/'.temporary';bad.write_bytes(b'partial')
            with self.assertRaises(ValueError):objects.inventory(root,[profile])
            bad.unlink();linked=root/(ID+'.json');linked.symlink_to('/etc/passwd')
            with self.assertRaises(OSError):objects.inventory(root,[profile])
            linked.unlink();linked.write_bytes(b'ab');linked.chmod(0o600)
            with patch.object(objects,'MAXIMUM_BYTES',1):
                with self.assertRaises(ValueError):objects.inventory(root,[profile])

    def test_preparation_is_private_complete_last_and_never_overwrites(self):
        import os
        metadata={'revision':'a'*40,'version':'v0.1.0-rc.1'}
        # Candidate integrity is covered above. This tiny renderer deliberately
        # emits harmless SQL text; neither the test nor preparer connects to PG.
        files={'deploy/postgres/grants.py':b'print("BEGIN; COMMIT;")\n','bin/jobman-dashboard':b'synthetic'}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);a,b,f=inputs()
            paths=[]
            for name,value in [('app',a),('broker',b),('fixture',f)]:
                path=root/(name+'.json');p.write_new(path,p.encoded(value));paths.append(path)
            def fake_keys(directory,role):
                p.write_new(directory/(role+'-test.key'),b'synthetic-private-value')
            with patch.object(prepare.plan,'candidate_files',return_value=(metadata,files)),patch.object(prepare,'key_material',side_effect=fake_keys):
                receipt=prepare.prepare(root/'candidate.tar.gz','a'*64,*paths,root/'ready')
                self.assertTrue((root/'ready/plan.json').exists())
                self.assertFalse(receipt['applies'])
                self.assertTrue(receipt['hold']['required'])
                self.assertFalse(receipt['hold']['automaticResume'])
                for path in (root/'ready').rglob('*'):
                    self.assertEqual(path.stat().st_mode&0o077,0)
                self.assertNotIn('synthetic-private-value',(root/'ready/plan.json').read_text())
                with self.assertRaises(ValueError):prepare.prepare(root/'candidate.tar.gz','a'*64,*paths,root/'ready')
            with patch.object(prepare.plan,'candidate_files',return_value=(metadata,files)),patch.object(prepare,'key_material',side_effect=ValueError('synthetic failure')):
                with self.assertRaises(ValueError):prepare.prepare(root/'candidate.tar.gz','a'*64,*paths,root/'partial')
                self.assertTrue((root/'partial').is_dir())
                self.assertFalse((root/'partial/plan.json').exists())

    def test_source_and_broker_key_material_is_distinct_and_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for role in ('api','worker'):
                prepare.key_material(root,role)
            keys=[]
            for role in ('api','worker'):
                for kind in ('control','broker'):
                    prefix=root/(role+'-'+kind)
                    prepare.run(['openssl','req','-in',str(prefix)+'-client.csr','-verify','-noout'])
                    key=Path(str(prefix)+'-signing-key.pem');keys.append(p.sha(key.read_bytes()))
                    self.assertEqual(key.stat().st_mode&0o777,0o600)
                    self.assertNotIn(b'PRIVATE',Path(str(prefix)+'-signing-public.pem').read_bytes())
            self.assertEqual(len(set(keys)),4)

    def test_staging_transfer_has_no_cross_host_private_keys(self):
        names=['material/database-passwords.json','material/api-control-client.key','material/worker-broker-signing-key.pem',
               'material/api-control-client.csr','material/api-control-signing-public.pem','configs/api.json','configs/broker.json',
               'candidate/bin/jobman-log-broker','candidate/bin/jobman-dashboard','grants/api.sql']
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in names:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'synthetic')
            value={'preparedFiles':{n:'irrelevant-here' for n in names}}
            control=apply.selected_files(value,root,'control01')
            self.assertIn('material/api-control-client.csr',control)
            self.assertIn('material/api-control-signing-public.pem',control)
            self.assertNotIn('material/api-control-client.key',control)
            self.assertNotIn('material/worker-broker-signing-key.pem',control)
            self.assertNotIn('material/database-passwords.json',control)
            self.assertNotIn('candidate/bin/jobman-dashboard',control)
            self.assertEqual(set(apply.selected_files(value,root,'pg01')),{'material/database-passwords.json','grants/api.sql'})

    def test_mutating_phase_requires_explicit_apply_before_any_connection(self):
        args=SimpleNamespace(staging=Path('/unused'),expected_plan_sha256='a'*64,phase='cutover',apply=False)
        with patch.object(apply,'verified_staging',return_value={}),patch.object(apply,'ssh_connections') as connections:
            with self.assertRaises(ValueError):apply.execute(args)
            connections.assert_not_called()

    def test_cutover_order_keeps_hold_and_never_skips_to_source_head(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);receipts=root/'apply-receipts';receipts.mkdir(mode=0o700)
            p.write_new(receipts/'preflight.json',p.encoded({'planSHA256':'a'*64,'snapshots':{}}))
            p.write_new(receipts/'material.json',b'{}')
            p.write_new(receipts/'certificates.json',p.encoded({'api-broker':'public','worker-broker':'public'}))
            args=SimpleNamespace(staging=root,expected_plan_sha256='a'*64,phase='cutover',apply=True,lab_root=root)
            actions=[]
            def remote(lab,connections,host,payload):
                actions.append((host,payload['action']))
                if payload['action']=='database-backup':return {'schema':17,'sha256':'b'*64}
                if payload['action']=='schema-state':return {'schema':17}
                return {'complete':True}
            with patch.object(apply,'verified_staging',return_value={}),patch.object(apply,'ssh_connections',return_value={}),patch.object(apply,'remote',side_effect=remote),patch.object(apply,'password',return_value='c'*64):
                result=apply.execute(args)
            self.assertTrue(result['deliveryHeld']);self.assertFalse(result['accepted'])
            ordered=[name for _,name in actions]
            self.assertEqual(ordered,['stop-hold','schema-state','assert-stopped-held','database-backup','objects-keys','database-capacity','migrate','assert-stopped-held','grants','convert','source-activate','activate'])
            self.assertNotIn('resume',ordered)
            self.assertNotIn('events-reset',ordered)

    def test_guest_hash_cas_preserves_prior_bytes_and_rejects_drift(self):
        import os
        # Guest execution requires root; portable unit coverage checks byte/CAS
        # behavior while actual ownership changes remain an explicit Lab gate.
        original_put=guest.put
        def local_put(path,raw,uid=0,gid=0,mode=0o600):original_put(path,raw,os.getuid(),os.getgid(),mode)
        with tempfile.TemporaryDirectory() as temp,patch.object(guest,'put',side_effect=local_put):
            root=Path(temp);live=root/'live';backup=root/'before'
            p.write_new(live,b'original')
            with self.assertRaises(ValueError):guest.replace(live,b'new','0'*64,backup,os.getuid(),os.getgid())
            self.assertFalse(backup.exists());self.assertEqual(live.read_bytes(),b'original')
            guest.replace(live,b'new',p.sha(b'original'),backup,os.getuid(),os.getgid())
            self.assertEqual(backup.read_bytes(),b'original');self.assertEqual(live.read_bytes(),b'new')
            guest.replace(live,b'new',p.sha(b'original'),backup,os.getuid(),os.getgid())

    def test_new_paths_get_exact_modes_with_restrictive_umask_existing_paths_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);old=os.umask(0o077)
            try:
                guest.directory(root/'public',os.getuid(),os.getgid(),0o755)
                guest.put(root/'public'/'binary',b'candidate',os.getuid(),os.getgid(),0o755)
                guest.put(root/'public'/'document',b'runbook',os.getuid(),os.getgid(),0o644)
                guest.put(root/'secret',b'private',os.getuid(),os.getgid())
                self.assertEqual((root/'public').stat().st_mode&0o777,0o755)
                self.assertEqual((root/'public'/'binary').stat().st_mode&0o777,0o755)
                self.assertEqual((root/'public'/'document').stat().st_mode&0o777,0o644)
                self.assertEqual((root/'secret').stat().st_mode&0o777,0o600)
                (root/'public').chmod(0o700)
                with self.assertRaises(ValueError):guest.directory(root/'public',os.getuid(),os.getgid(),0o755)
                self.assertEqual((root/'public').stat().st_mode&0o777,0o700)
                (root/'public'/'document').chmod(0o600)
                with self.assertRaises(ValueError):guest.put(root/'public'/'document',b'runbook',os.getuid(),os.getgid(),0o644)
                self.assertEqual((root/'public'/'document').stat().st_mode&0o777,0o600)
            finally:os.umask(old)

    def test_capacity_rejects_insufficient_space_and_sums_shared_mounts(self):
        policy={'maximumDatabaseBytes':1<<30,'maximumDumpBytes':1<<30,'reserveBytes':256<<20,
                'migrationDatabaseMultiplier':2,'dumpTimeoutSeconds':120}
        with tempfile.TemporaryDirectory() as temp,patch.object(guest.os,'fstatvfs',return_value=SimpleNamespace(f_bavail=10,f_frsize=1024)):
            self.assertEqual(guest.capacity(temp,10240)['availableBytes'],10240)
            with self.assertRaises(ValueError):guest.capacity(temp,10241)
        value={'capacity':policy,'releaseRoot':'/opt/test-release','preparedFiles':{'candidate/bin/jobman-log-broker':'hash','material/extra':'hash'},
               'preparedFileBytes':{'candidate/bin/jobman-log-broker':100,'material/extra':10}}
        requested=[]
        def capacity(path,amount):requested.append(amount);return {'availableBytes':1<<40,'requiredBytes':amount,'device':1}
        with patch.object(guest,'capacity',side_effect=capacity):guest.staging_capacity(value,'storage01',50)
        self.assertEqual(requested[-1],260+(256<<20))
        with patch.object(guest,'sql',return_value=str((1<<30)+1)),patch.object(guest,'run') as command:
            with self.assertRaises(ValueError):guest.database_capacity(value)
            command.assert_not_called()
        with patch.object(guest,'sql',return_value='100'),patch.object(guest,'capacity',side_effect=capacity),patch.object(guest,'run',return_value=b'1:4096'):
            with self.assertRaises(ValueError):guest.database_capacity(value)

    def test_dump_is_bounded_and_failed_partial_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            good=root/'good.partial'
            receipt=guest.bounded_dump([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"ok"*100)'],good,1024,2)
            self.assertEqual(receipt,{'bytes':200,'sha256':p.sha(b'ok'*100)})
            self.assertEqual(guest.file_checksum(good,1024),receipt)
            cases=[('cap','import sys;sys.stdout.buffer.write(b"x"*65536)',1024,2,'byte-cap'),
                   ('exit','import sys;sys.stdout.buffer.write(b"partial");sys.exit(4)',1024,2,'command'),
                   ('timeout','import time;time.sleep(2)',1024,0.05,'timeout')]
            for name,code,maximum,timeout,reason in cases:
                target=root/(name+'.partial')
                with self.assertRaises(ValueError):guest.bounded_dump([sys.executable,'-c',code],target,maximum,timeout)
                self.assertLessEqual(target.stat().st_size,maximum)
                failed=json.loads(Path(str(target)+'.failed.json').read_bytes())
                self.assertFalse(failed['complete']);self.assertEqual(failed['reason'],reason)
                with self.assertRaises(FileExistsError):guest.bounded_dump([sys.executable,'-c','print("not reused")'],target,maximum,timeout)

    def test_database_backup_requires_success_receipt_even_for_readable_partial(self):
        policy={'maximumDatabaseBytes':1<<30,'maximumDumpBytes':1<<30,'reserveBytes':256<<20,
                'migrationDatabaseMultiplier':2,'dumpTimeoutSeconds':120}
        original_put=guest.put
        def local_put(path,raw,uid=0,gid=0,mode=0o600):original_put(path,raw,os.getuid(),os.getgid(),mode)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);partial=root/'dashboard-before.dump.partial'
            p.write_new(partial,b'valid TOC but missing table data')
            payload={'planSHA256':'a'*64}
            with patch.object(guest,'common',return_value=({'capacity':policy},root)),patch.object(guest,'sql',return_value='t'),patch.object(guest,'run') as command,patch.object(guest,'put',side_effect=local_put):
                with self.assertRaises(ValueError):guest.database_backup(payload)
                command.assert_not_called()
                complete=dict(guest.file_checksum(partial,1<<30),schema=17,planSHA256='a'*64)
                p.write_new(root/'database-backup-complete.json',p.encoded(complete))
                self.assertEqual(guest.database_backup(payload),complete)
                self.assertFalse(partial.exists());self.assertTrue((root/'dashboard-before.dump').exists())
                self.assertEqual(guest.database_backup(payload),complete)
                (root/'dashboard-before.dump').write_bytes(b'changed')
                with self.assertRaises(ValueError):guest.database_backup(payload)

    def test_local_phase_lock_serializes_attempts_and_rejects_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with apply.receipt_lock(root):
                with self.assertRaises(BlockingIOError):
                    with apply.receipt_lock(root):self.fail('Concurrent phase admitted')
            with apply.receipt_lock(root):pass
            lock=root/'apply-receipts/.phase.lock';lock.unlink();lock.symlink_to(root/'target')
            with self.assertRaises(OSError):
                with apply.receipt_lock(root):self.fail('Symlink lock admitted')

    def test_schema_probe_uses_full_candidate_check_and_requires_exact_intent(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);candidate=root/'bin/jobman-dashboard';candidate.parent.mkdir();candidate.write_bytes(b'candidate')
            value={'releaseRoot':str(root),'revision':'b'*40,'preparedFiles':{'candidate/bin/jobman-dashboard':p.sha(b'candidate')}}
            payload={'planSHA256':'a'*64};answer=SimpleNamespace(returncode=0,stdout=b'{"held":true,"generation":"2"}')
            with patch.object(guest,'common',return_value=(value,root)),patch.object(guest.subprocess,'run',return_value=answer) as command:
                with self.assertRaises(FileNotFoundError):guest.schema_state(payload)
                p.write_new(root/'migration-started.json',p.encoded({'revision':'b'*40,'planSHA256':'a'*64}))
                self.assertEqual(guest.schema_state(payload),{'schema':18,'held':True,'generation':'2'})
                self.assertEqual(command.call_args.args[0][1:3],['events','hold-status'])
                (root/'migration-started.json').write_bytes(p.encoded({'revision':'c'*40,'planSHA256':'a'*64}))
                with self.assertRaises(ValueError):guest.schema_state(payload)
                command.return_value=SimpleNamespace(returncode=1,stdout=b'')
                with self.assertRaises(ValueError):guest.schema_state(payload)


    def test_verified_schema18_migration_retry_does_not_rerun_sql(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);value={'revision':'b'*40};backup={'schema':17,'planSHA256':'a'*64,'sha256':'c'*64}
            payload={'planSHA256':'a'*64,'backup':backup}
            intent={'revision':'b'*40,'planSHA256':'a'*64,'backupSHA256':'c'*64}
            p.write_new(root/'migration-started.json',p.encoded(intent))
            original_put=guest.put
            def local_put(path,raw,uid=0,gid=0,mode=0o600):original_put(path,raw,os.getuid(),os.getgid(),mode)
            with patch.object(guest,'common',return_value=(value,root)),patch.object(guest,'stopped'),patch.object(guest,'schema_state',return_value={'schema':18}),patch.object(guest,'run') as command,patch.object(guest,'put',side_effect=local_put):
                self.assertEqual(guest.migrate(payload),{'schemaApplied':18})
                command.assert_not_called()
                self.assertEqual(json.loads((root/'schema18-applied.json').read_bytes()),intent)
                payload['backup']['sha256']='d'*64
                with self.assertRaises(ValueError):guest.migrate(payload)


    def test_activation_prepares_private_socket_parents_before_standalone_validation(self):
        directories=[]
        def account(name):
            uid=21904 if name.endswith('-api') else 21905
            return SimpleNamespace(pw_uid=uid,pw_gid=uid)
        with patch.object(guest.pwd,'getpwnam',side_effect=account),patch.object(guest,'directory',side_effect=lambda *v:directories.append(v)):
            guest.prepare_runtime_directories()
        self.assertEqual(directories,[(Path('/run/jobman-dashboard-api-lab'),21904,21904,0o700),(Path('/run/jobman-dashboard-worker-lab'),21905,21905,0o700)])
        actions=[]
        with patch.object(guest,'common',return_value=({'releaseRoot':'/opt/reviewed','revision':'b'*40},Path('/private/receipts'))),patch.object(guest,'stopped'),patch.object(guest,'assert_stopped_held'),patch.object(guest,'prepare_runtime_directories',side_effect=lambda:actions.append('directories')),patch.object(guest,'run',side_effect=lambda args,**kwargs:actions.append(args[0]) or b''),patch.object(guest,'put'),patch.object(guest,'read',return_value=b'unit'),patch.object(guest,'active'):
            self.assertEqual(guest.activate({}),{'splitStarted':True,'held':True})
        self.assertEqual(actions[0],'directories')
        self.assertEqual(actions[1],'runuser')


    def test_final_report_root_check_binds_device_and_inode(self):
        import os
        with tempfile.TemporaryDirectory() as temp,patch.object(objects,'no_acl'):
            root=Path(temp);actual=os.stat(root)
            with patch.object(objects.os,'stat',return_value=SimpleNamespace(st_dev=actual.st_dev+1,st_ino=actual.st_ino)):
                with self.assertRaises(ValueError):objects.inventory(root,[(os.getuid(),os.getgid(),0o700,0o600)])


if __name__ == '__main__':
    unittest.main()
