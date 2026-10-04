#!/usr/bin/env python3
"""Offline regression tests; no SSH, database, identity or service invocation."""
import base64
import copy
from contextlib import ExitStack
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name, injected=None):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);value.__dict__.update(injected or {});spec.loader.exec_module(value);return value
p=load('dashboard-install-plan');g=load('dashboard-install-guest');h=load('install-dashboard-fresh')


def fixture():
    migrations=[{'name':'migrations/%06d_synthetic.sql'%i,'sha256':'a'*64} for i in range(1,18)]
    migrations.append({'name':'migrations/000018_runtime_lock_privileges.sql','sha256':'b'*64})
    candidates={k:{'revision':str(i)*40,'version':'v0.1.0-rc.'+str(i),'archiveSHA256':str(i)*64,
                   'files':{'bin/jobman-dashboard':{'sha256':'a'*64,'bytes':100}},'ledger':copy.deepcopy(migrations),'toolchains':{'go':'go1.26.6'}}
                for i,k in enumerate(('baseline','upgrade'),1)}
    controls=[{'id':'72000000-0000-4000-8000-000000000001','name':'Primary','origin':'https://10.77.0.21:18443',
               'expectedInstanceId':'e633cf92-258d-48ff-965a-fda88d68ef3a','namespaceIds':['73000000-0000-4000-8000-000000000001']}]
    second_control=copy.deepcopy(controls[0]);second_control.update(id='72000000-0000-4000-8000-000000000002',expectedInstanceId='a4f0e2ab-7323-4c90-9510-1f073c660f06',origin='https://10.77.0.21:28443');controls.append(second_control)
    configs={};materials={}
    for role,(root,uid) in p.PRIMARY.items():
        cfg={'configurationRevision':8,'databaseURLFile':root+'/database-url','controls':copy.deepcopy(controls),
             'logBrokers':[],'logMappings':[],'reports':{'objectRoot':'/original/reports','redactionFile':root+'/redaction.json',
             'policyKeyFile':root+'/original-policy.key'},'logCursorKeyFile':root+'/original-cursor.key',
             'notifications':{'deviceTopics':[]}}
        cfg['controls'][0].update({'clientKeyFile':root+'/client.key','clientCertificateFile':root+'/client.crt',
                                   'delegationKeyFile':root+'/sign.key','trustRootsFile':p.CA})
        if role=='api':cfg.update({'publicOrigin':'https://dashboard.lab.test:8443','listen':'10.77.0.10:8443',
            'webRoot':'/original/web','events':{'enabled':True,'deliveryHold':False},'encryption':{'keyFile':root+'/old-auth.key','keyId':'old'},
            'serverTLS':{'certificateFile':root+'/server.crt','keyFile':root+'/server.key'},
            'oidc':{'issuer':p.ISSUER,'webClientId':'jobman-dashboard-web','webClientSecretFile':root+'/old-web-secret'}})
        else:cfg.update({'identityIssuer':p.ISSUER,'components':['ingestion','notifications','reports','retention'],'deliveryHold':False})
        configs[role]=cfg
        for path in p.references(cfg):materials[path]={'uid':0 if path==p.CA else uid,'mode':0o644 if path==p.CA else 0o600,'bytes':32,'sha256':'e'*64}
    database={'databaseOID':'1','hold':{'held':False,'generation':'5','suppressRecordedThrough':None},'schemaSHA256':'a'*64,
              'rolesSHA256':'b'*64,'sources':[{'deploymentId':controls[0]['id'],'controlInstanceId':controls[0]['expectedInstanceId'],
              'recoveryEpoch':'1','namespaceIds':controls[0]['namespaceIds'],'configurationRevision':8,'status':'active',
              'generation':'10','lastPosition':'35','openGaps':0,'unfinishedRecoveries':0}]}
    second=copy.deepcopy(database['sources'][0]);second.update(deploymentId='72000000-0000-4000-8000-000000000002',controlInstanceId='a4f0e2ab-7323-4c90-9510-1f073c660f06');database['sources'].append(second)
    snapshot={'control01':{'identity':{'absent':True}},'storage01':{'unused':True,'configs':configs,'materials':materials,
              'freeBytes':4<<30,'memoryBytes':2<<30},'pg01':{'unused':True,'freeBytes':4<<30,'connections':40,'preserved':{'dashboard':database}}}
    units={key:{role:base64.b64encode(b'[Service]\n').decode() for role in p.USERS} for key in candidates}
    plan=p.make(snapshot,candidates,units,{name:'a'*64 for name in p.FILES},'11000000-0000-4000-8000-000000000001',1,
                {name:format(i,'064x') for i,name in enumerate(g.SECRET_NAMES,1)},dict.fromkeys(('api','worker','operator'),'c'*64))
    return plan



def aborted_fixture():
    plan=fixture()
    proof={'format':1,'scope':'v1','operationId':plan['operationId'],'planSHA256':p.sha(p.encoded(plan)),
           'originalImplementationSHA256':p.sha(p.encoded(plan['implementationSHA256'])),
           **dict.fromkeys(('stopSHA256','retireSHA256','failureSHA256','failureLogSHA256','acceptanceStartedSHA256'),'a'*64),
           'accepted':False,'aborted':True,'states':{host:{'retained':True} for host in ('storage01','control01','pg01')}}
    return {'plan':plan,'abortedReceipt':proof}

def fixture_v2():
    scoped=load('dashboard-install-plan',{'SCOPE':'v2'})
    old=fixture();snap=copy.deepcopy(old['snapshot'])
    for host in snap:snap[host]['previousAttempt']=aborted_fixture()
    value=scoped.make(snap,old['candidates'],old['units'],old['implementationSHA256'],
        '11000000-0000-4000-8000-000000000002',old['createdAt'],old['generatedSHA256'],old['grantSHA256'])
    return scoped,value

class InstallTests(unittest.TestCase):
    def test_finite_v2_scope_has_disjoint_resources_and_retains_v1(self):
        q,plan=fixture_v2();q.validate(plan)
        self.assertEqual(plan['scope'],'v2');self.assertEqual(q.DATABASE,'jobman_install_v2')
        self.assertEqual(q.PORT,49443);self.assertEqual(q.CLIENT,'jobman-dashboard-install-web-v2')
        self.assertEqual([v[1] for v in q.USERS.values()],[21923,21924]);self.assertEqual(q.READER[1],21925)
        for attr in ('ROLES','ROOTS','UNITS'):
            self.assertFalse(set(getattr(p,attr).values()) & set(getattr(q,attr).values()))
        for attr in ('REPORTS','RELEASES','OPERATIONS'):self.assertNotEqual(getattr(p,attr),getattr(q,attr))
        self.assertEqual(plan['configs']['api']['listen'],'10.77.0.10:49443')
        self.assertEqual(plan['configs']['api']['reports']['objectAccess']['workerUid'],21924)
        self.assertTrue(plan['configs']['api']['webRoot'].startswith(q.RELEASES+'/'))
        self.assertNotIn('scope',fixture())
        with self.assertRaises(ValueError):p.validate(plan)
        with self.assertRaises(ValueError):q.validate(fixture())
        with self.assertRaises(ValueError):load('dashboard-install-plan',{'SCOPE':'arbitrary'})

    def test_v2_requires_exact_failed_attempt_proof_on_every_host(self):
        q,plan=fixture_v2()
        for change in (lambda x:x['snapshot']['pg01'].pop('previousAttempt'),
                       lambda x:x['snapshot']['control01']['previousAttempt']['abortedReceipt'].update(accepted=True),
                       lambda x:x['snapshot']['storage01']['previousAttempt']['abortedReceipt'].update(format=True),
                       lambda x:x['snapshot']['storage01']['previousAttempt']['abortedReceipt'].update(extra=1),
                       lambda x:x['snapshot']['pg01']['previousAttempt']['abortedReceipt']['states'].pop('control01'),
                       lambda x:x['snapshot']['pg01']['previousAttempt']['plan'].update(operationId='11000000-0000-4000-8000-000000000003')):
            changed=copy.deepcopy(plan);change(changed)
            with self.assertRaises((ValueError,KeyError)):q.validate(changed)

    def test_v2_guest_preservation_reads_old_scope_and_never_restarts(self):
        q,plan=fixture_v2();prior=plan['snapshot']['storage01']['previousAttempt']
        old=SimpleNamespace(p=p,operation=lambda _:Path('/retained'),tree=lambda _:'a'*64,ROOTS=g.ROOTS,
            stopped=lambda:None,own_configuration=lambda *_:None,verify_release=lambda *_:None)
        guest=load('dashboard-install-guest',{'p':q,'prior_guest':old})
        raw=p.encoded({'completed':True,'stopped':True,'operationId':prior['plan']['operationId']})
        prior['abortedReceipt']['stopSHA256']=p.sha(raw)
        with patch.object(guest.f,'read',return_value=raw),patch.object(guest.f,'properties',return_value={'MainPID':'0'}),             patch.object(guest.f,'run') as run:
            actual=guest.retained_attempt(prior,'storage01',False)
            prior['abortedReceipt']['states']['storage01']=actual
            self.assertEqual(guest.retained_attempt(prior,'storage01'),actual);run.assert_not_called()
            prior['abortedReceipt']['states']['storage01']['operationTreeSHA256']='b'*64
            with self.assertRaisesRegex(ValueError,'previous_attempt_drift'):guest.retained_attempt(prior,'storage01')

    def test_v2_host_prior_hash_and_explicit_scope_are_mandatory(self):
        q,_=fixture_v2();host=load('install-dashboard-fresh',{'p':q})
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            path=Path(name)/'aborted.json';raw=p.encoded(aborted_fixture());path.write_bytes(raw);path.chmod(0o600)
            args=SimpleNamespace(previous_attempt=path,expected_previous_attempt_sha256=p.sha(raw))
            self.assertEqual(host.previous_attempt(args),aborted_fixture())
            args.expected_previous_attempt_sha256='b'*64
            with self.assertRaisesRegex(ValueError,'previous_attempt_changed'):host.previous_attempt(args)
            with self.assertRaisesRegex(ValueError,'unexpected_previous_attempt'):h.previous_attempt(args)
        self.assertIn("'SCOPE':value.get('scope','v1')",host.BOOTSTRAP)
        self.assertIn("'prior_guest':prior_g",host.BOOTSTRAP)

    def test_plan_reconstruction_and_fixed_targets(self):
        plan=fixture();p.validate(plan)
        self.assertEqual(plan['postFixRevision'],'2e8f1b15c58889c52023d49d396fd600b31eecd2')
        self.assertEqual(p.DATABASE,'jobman_install_v1');self.assertEqual(p.ORIGIN,'https://dashboard.lab.test:48443')
        changed=copy.deepcopy(plan);changed['configs']['api']['listen']='10.77.0.10:8443'
        with self.assertRaises(ValueError):p.validate(changed)

    def test_fresh_identity_and_capacity_fail_closed(self):
        plan=fixture()
        for host,key,value in [('storage01','unused',False),('pg01','unused',False),('storage01','memoryBytes',100),('pg01','connections',35)]:
            changed=copy.deepcopy(plan);changed['snapshot'][host][key]=value
            with self.assertRaises(ValueError):p.validate(changed)

    def test_same_schema_and_distinct_candidates_required(self):
        candidates=fixture()['candidates']
        for edit in (lambda c:c['upgrade'].update(revision=c['baseline']['revision']),
                     lambda c:c['upgrade']['ledger'][0].update(sha256='d'*64),
                     lambda c:c['baseline']['ledger'].pop(),
                     lambda c:c['upgrade']['files'].update({'../secret':{'sha256':'a'*64,'bytes':3}})):
            changed=copy.deepcopy(candidates);edit(changed)
            with self.assertRaises(ValueError):p.pair(changed)

    def test_new_keys_and_roles_preserve_source_trust(self):
        plan=fixture();api=plan['configs']['api'];worker=plan['configs']['worker']
        self.assertEqual(api['configurationRevision'],1);self.assertEqual(worker['components'],['ingestion','notifications','reports'])
        self.assertEqual(api['notifications'],{'deviceTopics':[]});self.assertNotIn('encryption',worker)
        self.assertEqual(api['oidc']['webClientId'],p.CLIENT)
        copied={item['source'] for item in plan['copies']}
        self.assertFalse(any('old-auth' in name or 'old-web' in name or 'original-policy' in name or 'original-cursor' in name for name in copied))
        self.assertEqual(api['controls'][0]['namespaceIds'],plan['snapshot']['storage01']['configs']['api']['controls'][0]['namespaceIds'])
        self.assertTrue(all(item['destination'].startswith(p.ROOTS[item['role']]+'/') for item in plan['copies']))

    def test_cross_role_key_copy_rejected(self):
        plan=fixture();plan['snapshot']['storage01']['configs']['api']['controls'][0]['clientKeyFile']=p.PRIMARY['worker'][0]+'/client.key'
        with self.assertRaises(ValueError):p.validate(plan)

    def test_separate_oidc_client_and_exact_callback(self):
        value=p.client_spec('a'*64)
        self.assertEqual(value['redirectUris'],[p.ORIGIN+'/auth/callback']);self.assertNotEqual(value['clientId'],'jobman-dashboard-web')
        self.assertFalse(value['directAccessGrantsEnabled']);self.assertFalse(value['serviceAccountsEnabled'])
        self.assertEqual(value['attributes']['pkce.code.challenge.method'],'S256')
        self.assertEqual(len(value['protocolMappers']),2)

    def test_explicit_mapper_defaults_and_strict_identity_verification(self):
        secret='a'*64;client_id='11000000-0000-4000-8000-000000000001'
        expected=p.client_spec(secret)
        self.assertEqual(expected['protocolMappers'][0]['config']['userinfo.token.claim'],'false')
        class Admin:
            def __init__(self,value):self.value=value;self.secret=secret
            def get(self,path):
                if path.startswith('clients?'):return [{'id':client_id}]
                if path=='clients/'+client_id:return self.value
                if path=='clients/'+client_id+'/client-secret':return {'value':self.secret}
                raise AssertionError(path)
        valid=dict(copy.deepcopy(expected),id=client_id)
        self.assertEqual(g.check_client(Admin(valid),secret),client_id)
        def change(path,value):
            row=copy.deepcopy(valid);cursor=row
            for key in path[:-1]:cursor=cursor[key]
            cursor[path[-1]]=value;return row
        for key,value in [('userinfo.token.claim','true'),('userinfo.token.claim',False),('unknown','false')]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                g.check_client(Admin(change(['protocolMappers',0,'config',key],value)),secret)
        missing=copy.deepcopy(valid);del missing['protocolMappers'][0]['config']['userinfo.token.claim']
        with self.assertRaises(ValueError):g.check_client(Admin(missing),secret)
        for rows in ([valid['protocolMappers'][0],valid['protocolMappers'][0]],valid['protocolMappers']+[valid['protocolMappers'][0]]):
            with self.assertRaises(ValueError):g.check_client(Admin(dict(valid,protocolMappers=rows)),secret)
        for path,value in [(['enabled'],1),(['protocolMappers',0,'consentRequired'],0),(['id'],'other')]:
            with self.assertRaises(ValueError):g.check_client(Admin(change(path,value)),secret)
        admin=Admin(valid);admin.secret='b'*64
        with self.assertRaises(ValueError):g.check_client(admin,secret)
        disabled=dict(valid,enabled=False)
        self.assertEqual(g.check_client(Admin(disabled),secret,retired=True),client_id)
        with self.assertRaises(ValueError):g.check_client(Admin(valid),secret,retired=True)

    def test_unit_uses_actual_packaged_template_and_all_three_sites(self):
        source=Path('/Users/rcw/home/code/jobman-dashboard/deploy/systemd')
        # CI supplies --dashboard-root through the test environment; the checked
        # repository template is preferable to a matching hand-written fixture.
        if os.environ.get('JOBMAN_DASHBOARD_SOURCE'):source=Path(os.environ['JOBMAN_DASHBOARD_SOURCE'])/'deploy/systemd'
        if not source.exists():self.skipTest('Dashboard package template source not present; pure malformed-template test still runs')
        plan=fixture()
        for role in p.USERS:
            raw=(source/('jobman-dashboard-'+role+'.service')).read_bytes();result=p.unit(role,plan['candidates']['baseline'],raw)
            self.assertEqual(result.count(p.release(plan['candidates']['baseline']).encode()),3)
            self.assertIn(b'TimeoutStopSec=90s\nKillMode=control-group',result)
            self.assertIn(p.ROOTS['operator'].encode(),result);self.assertNotIn(b'/opt/jobman-dashboard/current',result)
            with self.assertRaises(ValueError):p.unit(role,plan['candidates']['baseline'],raw.replace(b'KillMode=control-group',b'KillMode=process'))

    def test_malformed_template_rejected(self):
        with self.assertRaises(ValueError):p.unit('api',fixture()['candidates']['baseline'],b'[Service]\nExecStart=/bin/true\n')

    def test_generated_material_pins_and_no_key_reuse(self):
        plan=fixture();values={name:(bytes([i])*32 if name in ('auth','policy','cursor') else format(i,'064x').encode()) for i,name in enumerate(sorted(g.SECRET_NAMES),1)}
        plan['generatedSHA256']={k:p.sha(v) for k,v in values.items()};payload={k:base64.b64encode(v).decode() for k,v in values.items()}
        self.assertEqual(g.verify_secrets(plan,payload),values)
        payload['auth']=payload['cursor']
        with self.assertRaises(ValueError):g.verify_secrets(plan,payload)

    def test_new_file_permissions_under_restrictive_umask(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            root=Path(name);previous=os.umask(0o777)
            try:g.put(root/'value',b'private',os.getuid(),os.getgid());g.directory(root/'dir',os.getuid(),os.getgid(),create=True)
            finally:os.umask(previous)
            self.assertEqual((root/'value').stat().st_mode&0o777,0o600);self.assertEqual((root/'dir').stat().st_mode&0o777,0o700)
            with self.assertRaises(FileExistsError):g.put(root/'value',b'repair',os.getuid(),os.getgid())
            self.assertEqual((root/'value').read_bytes(),b'private')

    def test_tree_rejects_alias_and_does_not_read_link(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            root=Path(name);(root/'value').write_bytes(b'bounded');a=g.tree(root)
            (root/'value').write_bytes(b'changed');self.assertNotEqual(a,g.tree(root))
            (root/'link').symlink_to(root/'value')
            with self.assertRaises(ValueError):g.tree(root)

    def test_hba_scope_and_sql_password_transport(self):
        hba=g.hba_prefix().decode()
        self.assertIn('hostssl jobman_install_v1 jobman_install_ddl,jobman_install_api,jobman_install_worker,jobman_install_operator 10.77.0.10/32',hba)
        self.assertNotIn('jobman_dashboard',hba)
        values={name:b'a'*64 for name in ('ddl','api','worker','operator')};query=g.role_sql(values)
        self.assertIn('CREATE DATABASE jobman_install_v1 OWNER jobman_install_ddl',query)
        self.assertNotIn('DROP',query);self.assertNotIn('SUPERUSER;',query)
        with patch.object(g.f,'run',return_value=b'1') as run:g.sql('SELECT 1;')
        self.assertNotIn('SELECT 1;',run.call_args.args[0]);self.assertEqual(run.call_args.kwargs['data'],b'SELECT 1;')

    def test_api_and_worker_data_permissions_are_distinct(self):
        plan=fixture();self.assertEqual(plan['configs']['api']['reports']['objectAccess'],{'mode':'shared_group','workerUid':21921,'readerGid':21922})
        self.assertNotEqual(p.USERS['api'][1],p.USERS['worker'][1]);self.assertEqual(plan['configs']['operator']['schemaVersion'],1)

    def test_positive_readiness_rejects_late_exact_identity(self):
        plan=fixture()
        with patch.object(g,'process',return_value={'pid':'2'}),patch.object(g.f,'run',return_value=b'{}'),\
             patch.object(g.time,'monotonic',side_effect=[0,0,1,26,26]),patch.object(g.time,'sleep'):
            with self.assertRaises(ValueError):g.ready(plan,'baseline',25)

    def test_observe_never_invokes_mutation(self):
        plan=fixture();receipt={'phase':'database','completed':True,'operationId':plan['operationId'],
                               'planSHA256':p.sha(p.encoded(plan)),'databaseOID':'7'}
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            root=Path(name);(root/'database.pending.json').write_text('{}');(root/'database.json').write_bytes(p.encoded(receipt))
            with patch.object(g,'operation',return_value=root),patch.object(g.f,'read',side_effect=lambda path,**_:Path(path).read_bytes()),\
                 patch.object(g,'sql',return_value='7') as sql,patch.object(g,'database') as mutate:
                self.assertEqual(g.observe(plan,'database',{}),receipt);mutate.assert_not_called()
                self.assertTrue(sql.call_args.args[0].startswith('SELECT'))

    def test_uncompleted_observation_is_not_adopted(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            root=Path(name);(root/'database.pending.json').write_text('{}')
            with patch.object(g,'operation',return_value=root):
                with self.assertRaises(FileNotFoundError):g.observe(fixture(),'database',{})

    def test_existing_intent_never_reexecutes(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            root=Path(name);(root/'upgrade.pending.json').write_text('{}')
            with patch.object(g,'operation',return_value=root),patch.object(g,'marker') as marker:
                with self.assertRaises(ValueError):g.begin(fixture(),'upgrade')
                marker.assert_not_called()

    def test_remote_rejects_unknown_phase_before_ssh(self):
        with patch.object(h.f,'run') as run:
            with self.assertRaises(ValueError):h.remote(Path('/unused'),{'host':'storage01','phase':'drop-database'}, {})
            run.assert_not_called()

    def test_fixed_output_fix_ancestor_is_actually_checked(self):
        with patch.object(h.f,'run',side_effect=p.b.Failure('candidate_predates_output_fix')) as run:
            with self.assertRaises(ValueError):h.schema(Path('/private/tmp'), 'a'*40)
            self.assertEqual(run.call_args.args[0],['git','-C','/private/tmp','merge-base','--is-ancestor',p.FIX,'a'*40])

    def test_operator_dsn_is_pinned_before_migration(self):
        plan=fixture(); secret=b'a'*64; plan['generatedSHA256']['operator']=p.sha(secret);plan['generatedSHA256']['ddl']=p.sha(secret)
        values={str(g.ROOTS['operator']/'config.json'):p.encoded(plan['configs']['operator']),
                str(g.ROOTS['operator']/'ddl-url'):g.dsn('ddl',secret),
                str(g.ROOTS['operator']/'database-url'):g.dsn('operator',secret).replace(b'jobman_install_v1',b'jobman_dashboard')}
        with patch.object(g,'own_identities'),patch.object(g,'verify_release',return_value='/candidate/bin'),\
             patch.object(g,'directory'),patch.object(g.f,'read',side_effect=lambda path,*a,**k:values[str(path)]):
            with self.assertRaisesRegex(ValueError,'operator_dsn_drift'):g.own_configuration(plan,'baseline')

    def test_old_identity_inventory_preserved_around_own_client(self):
        class Admin:
            ours=False
            changed=False
            def get(self,path):
                if path=='clients':return [{'id':'old','clientId':'old-web','redirectUris':['https://old/changed' if self.changed else 'https://old/callback']}]+([{'id':'new','clientId':p.CLIENT}] if self.ours else [])
                if path.startswith('users?'):return [{'id':'alice','username':'synthetic'}]
                if path=='users/profile':return {'attributes':[]}
                raise AssertionError(path)
        admin=Admin();before,_=g.identity_proof(admin,True);admin.ours=True;after,_=g.identity_proof(admin)
        after['absent']=before['absent'];self.assertEqual(after,before)
        admin.changed=True;changed,_=g.identity_proof(admin);changed['absent']=before['absent'];self.assertNotEqual(changed,before)

    def test_preservation_rejects_restore_or_primary_mutation(self):
        plan=fixture();plan['snapshot']['storage01'].update(preserved={'revision':'a'*40,'files':{}},restore={'proof':'unchanged'})
        with patch.object(g.f,'host_snapshot',return_value={'revision':'a'*40,'files':{}}),patch.object(g,'restore_storage',return_value={'proof':'changed'}):
            with self.assertRaisesRegex(ValueError,'restore_storage_changed'):g.preserved(plan,'storage01')
        with patch.object(g.f,'host_snapshot',return_value={'revision':'a'*40,'files':{'primary':'changed'}}):
            with self.assertRaisesRegex(ValueError,'existing_runtime_changed'):g.preserved(plan,'storage01')

    def test_host_phase_records_intent_before_remote_and_blocks_repeat(self):
        plan=fixture()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            root=Path(name);args=SimpleNamespace(phase='baseline',lab_root=Path('/unused'),staging=root,expected_plan_sha256='a'*64,apply=True)
            def remote(*_):
                self.assertTrue((root/'baseline.pending.json').exists());raise ValueError('response_lost')
            with patch.object(h,'load_plan',return_value=(plan,{})),patch.object(h,'authority'),patch.object(h,'receipt'),patch.object(h,'remote',side_effect=remote) as call:
                with self.assertRaisesRegex(ValueError,'response_lost'):h.phase(args)
                with self.assertRaisesRegex(ValueError,'uncertain_mutation_requires_observation'):h.phase(args)
                self.assertEqual(call.call_count,1);self.assertFalse((root/'baseline.json').exists())

    def test_retained_state_must_match_before_acceptance_receipt(self):
        plan=fixture()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            root=Path(name);h.h.save(root/'retained-baseline.json',{'reports':2,'retainedSHA256':'a'*64})
            args=SimpleNamespace(phase='verify',selected='upgrade',staging=root,lab_root=Path('/unused'))
            with patch.object(h,'load_plan',return_value=(plan,{})),patch.object(h,'authority'),patch.object(h,'receipt'),\
                 patch.object(h,'data',return_value={'reports':1,'retainedSHA256':'b'*64}):
                with self.assertRaisesRegex(ValueError,'retained_state_changed'):h.phase(args)
                self.assertFalse((root/'verified-upgrade.json').exists())

    def test_empty_database_rejects_template_data_before_migration(self):
        expected={'relations':0,'extraSchemas':0,'routines':0,'types':0,'extensions':0,'ledgerAbsent':True,'publicOwner':p.ROLES['ddl']}
        with patch.object(g,'sql',return_value=p.encoded(expected)) as call:
            self.assertEqual(g.empty_database(),{'empty':True,'database':p.DATABASE})
            query,database=call.call_args.args
            self.assertEqual(database,p.DATABASE);self.assertIn('BEGIN READ ONLY;',query)
            self.assertIn('pg_class',query);self.assertIn('dashboard_schema_migrations',query)
            self.assertIn('pg_proc',query);self.assertIn('pg_type',query);self.assertIn("extname <> 'plpgsql'",query)
        for key,value in [('relations',1),('extraSchemas',1),('routines',1),('types',1),('extensions',1),('ledgerAbsent',False),('publicOwner','jobman_control')]:
            changed=dict(expected);changed[key]=value
            with patch.object(g,'sql',return_value=p.encoded(changed)):
                with self.assertRaisesRegex(ValueError,'fresh_database_not_empty'):g.empty_database()

    def test_runtime_directory_recreates_only_absent_private_parent(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as name:
            root=Path(name);path=root/'runtime';uid,gid=os.getuid(),os.getgid()
            previous=os.umask(0o077)
            try:g.runtime_directory(path,uid,gid)
            finally:os.umask(previous)
            row=path.lstat();self.assertEqual((row.st_uid,row.st_gid,row.st_mode&0o777),(uid,gid,0o700))
            before=(row.st_ino,row.st_ctime_ns);g.runtime_directory(path,uid,gid)
            row=path.lstat();self.assertEqual((row.st_ino,row.st_ctime_ns),before)
            path.chmod(0o750)
            with self.assertRaisesRegex(ValueError,'directory_identity'):g.runtime_directory(path,uid,gid)
            self.assertEqual(path.stat().st_mode&0o777,0o750)
            alias=root/'alias';alias.symlink_to(path,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'directory_identity'):g.runtime_directory(alias,uid,gid)
            wrong=root/'file';wrong.write_bytes(b'preserved');wrong.chmod(0o700)
            with self.assertRaisesRegex(ValueError,'directory_identity'):g.runtime_directory(wrong,uid,gid)
            self.assertEqual(wrong.read_bytes(),b'preserved')

    def test_runtime_parent_selection_is_exact_for_both_finite_scopes(self):
        for scope in ('v1','v2'):
            q=load('dashboard-install-plan',{'SCOPE':scope});guest=load('dashboard-install-guest',{'p':q})
            with patch.object(guest,'runtime_directory') as call:
                guest.runtime_directories()
                self.assertEqual(call.call_args_list,[unittest.mock.call(Path('/run')/q.UNITS[role],uid,uid) for role,(_,uid) in q.USERS.items()])

    def test_every_activation_prepares_runtime_after_stop_before_validation(self):
        for phase in ('baseline','upgrade','rollback'):
            plan=fixture();seen=[];ready=[False]
            def run(args,code,**kwargs):
                seen.append(code)
                if args[:2]==['systemctl','stop']:ready[0]=False
                if '--mode' in args and 'check-config' in args:
                    self.assertTrue(ready[0]);self.assertIn(code,('install_api_local_validation','install_worker_local_validation'))
                return b'{}'
            def prepare():seen.append('runtime');ready[0]=True
            with ExitStack() as stack:
                for name in ('replace','stopped','process','ready'):
                    stack.enter_context(patch.object(g,name,side_effect=(lambda:seen.append('stopped')) if name=='stopped' else None))
                stack.enter_context(patch.object(g,'begin',return_value=Path('/private/operation')))
                stack.enter_context(patch.object(g,'own_configuration',return_value='/exact/binary'))
                stack.enter_context(patch.object(g,'runtime_directories',side_effect=prepare))
                stack.enter_context(patch.object(g,'tree',return_value='a'*64))
                finish=stack.enter_context(patch.object(g,'finish',return_value={'completed':True}))
                stack.enter_context(patch.object(g.f,'run',side_effect=run))
                self.assertEqual(g.activate(plan,phase),{'completed':True})
                self.assertLess(seen.index('stopped'),seen.index('runtime'))
                self.assertLess(seen.index('runtime'),seen.index('install_api_local_validation'))
                self.assertLess(seen.index('install_worker_local_validation'),seen.index('install_start_api'))
                self.assertEqual(finish.call_count,1)

    def test_runtime_identity_failure_never_starts_service(self):
        plan=fixture();calls=[]
        with ExitStack() as stack:
            for name in ('replace','stopped','process'):stack.enter_context(patch.object(g,name))
            stack.enter_context(patch.object(g,'begin',return_value=Path('/private/operation')))
            stack.enter_context(patch.object(g,'own_configuration',return_value='/exact/binary'))
            stack.enter_context(patch.object(g,'runtime_directories',side_effect=p.b.Failure('directory_identity')))
            stack.enter_context(patch.object(g.f,'run',side_effect=lambda args,*a,**k:calls.append(args) or b'{}'))
            finish=stack.enter_context(patch.object(g,'finish'))
            with self.assertRaisesRegex(ValueError,'directory_identity'):g.activate(plan,'upgrade')
            self.assertFalse(any(args[:2]==['systemctl','start'] for args in calls));finish.assert_not_called()

    def test_bootstrap_compile_only(self):
        compile(h.BOOTSTRAP,'bootstrap','exec')
        self.assertEqual(set(h.REMOTE_NAMES),{'dashboard-split-plan.py','dashboard-dependency-fault-plan.py',
           'dashboard-dependency-fault-guest.py','dashboard-control-upgrade-plan.py','dashboard-control-upgrade-guest.py',
           'dashboard-install-plan.py','dashboard-install-guest.py'})


if __name__=='__main__':unittest.main()
