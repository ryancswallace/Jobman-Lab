#!/usr/bin/env python3
"""Offline guards; no Lab SSH, database, service or product invocation."""
import base64
import copy
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
LAB=Path(os.environ.get('JOBMAN_LAB_SOURCE',str(HERE.parent)))
if not (LAB/'scripts/test-dashboard-install.py').exists():LAB=Path('/Users/rcw/home/code/jobman-lab')

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
p=load('probe_plan',HERE/'dashboard-schema-probe-plan.py')
h=load('probe_host',HERE/'probe-dashboard-schema.py')
t=load('install_test_fixture',LAB/'scripts/test-dashboard-install.py')
g=load('probe_guest',HERE/'dashboard-schema-probe-guest.py');g.p=p;g.g=t.g;g.f=t.g.f;g.u=t.g.u;g.b=t.p.b


def fixture():
    install=t.fixture();snap={'storage01':{'unused':True,'freeBytes':1<<30,'preserved':{}},
        'pg01':{'unused':True,'freeBytes':2<<30,'connections':36,'preserved':{}},'control01':{'preserved':{}}}
    hashes={name:'a'*64 for name in p.FILES+p.INSTALL_FILES};hashes.update(install['implementationSHA256'])
    return p.validate({'format':1,'synthetic':True,'operationId':'91000000-0000-4000-8000-000000000001','createdAt':1,
        'install':install,'installComplete':{'operationId':install['operationId'],'complete':True,'retained':True},
        'selected':'upgrade','snapshot':snap,'configs':p.configs(install,'upgrade'),'implementationSHA256':hashes,
        'secretSHA256':{r:str(i)*64 for i,r in enumerate(p.ROLES,1)},'grantSHA256':{r:'a'*64 for r in p.COMPONENTS}})

class SchemaProbeTests(unittest.TestCase):
    def setUp(self):
        original=g.g.put
        patched=patch.object(g.g,'put',side_effect=lambda path,raw,*args,**kwargs:original(path,raw,os.getuid(),os.getgid()))
        patched.start();self.addCleanup(patched.stop)

    def test_distinct_targets_and_no_delivery_or_source_worker(self):
        plan=fixture();self.assertNotEqual(p.DATABASE,t.p.DATABASE)
        self.assertFalse(set(p.ROLES.values())&set(t.p.ROLES.values()))
        self.assertFalse(set(p.ROOTS.values())&set(t.p.ROOTS.values()))
        self.assertEqual(plan['configs']['worker']['components'],['retention'])
        self.assertEqual(plan['configs']['worker']['controls'],[])
        self.assertNotIn('notifications',plan['configs']['worker'])
        self.assertTrue(all(c['origin']=='https://127.0.0.1:48445' for c in plan['configs']['api']['controls']))
        self.assertEqual(plan['configs']['api']['listen'],'127.0.0.1:48444')
        self.assertNotIn('reports',plan['configs']['api'])

    def test_closed_install_archive_and_capacity_are_mandatory(self):
        for change in (lambda v:v['installComplete'].update(complete=False),
                       lambda v:v['implementationSHA256'].update({'dashboard-install-guest.py':'f'*64}),
                       lambda v:v['snapshot']['pg01'].update(connections=19),
                       lambda v:v['snapshot']['storage01'].update(freeBytes=1),
                       lambda v:v['configs']['api'].update(listen='0.0.0.0:48444')):
            plan=fixture();change(plan)
            with self.assertRaises(ValueError):p.validate(plan)

    def continued(self,plan):
        proof={'adapterSHA256':'1'*64,'originalImplementationSHA256':p.sha(p.encoded(plan['install']['implementationSHA256'])),
               'failureSHA256':'2'*64,'diagnosticSHA256':'3'*64,
               'mapperDifference':{'name':'dashboard-api-audience','config':{'userinfo.token.claim':'false'}}}
        plan['installComplete']['continuation']=proof
        plan['installContinuationSHA256']=p.sha(p.encoded(proof))
        return plan

    def test_explicit_reviewed_completion_preserves_legacy_and_provenance(self):
        self.assertNotIn('installContinuationSHA256',p.validate(fixture()))
        plan=self.continued(fixture());self.assertIs(p.validate(plan),plan)
        for edit in (lambda v:v.pop('installContinuationSHA256'),
                     lambda v:v.update(installContinuationSHA256=None),
                     lambda v:v['installComplete'].update(extra=True),
                     lambda v:v['installComplete'].update(complete=1),
                     lambda v:v['installComplete'].update(operationId='92000000-0000-4000-8000-000000000001'),
                     lambda v:v['installComplete']['continuation'].update(extra='x'),
                     lambda v:v['installComplete']['continuation'].update(adapterSHA256='4'*64),
                     lambda v:v['installComplete']['continuation'].update(failureSHA256='4'*64),
                     lambda v:v['installComplete']['continuation'].update(diagnosticSHA256='4'*64)):
            changed=copy.deepcopy(plan);edit(changed)
            with self.assertRaises(ValueError):p.validate(changed)
        plain=fixture();plain['installContinuationSHA256']='a'*64
        with self.assertRaises(ValueError):p.validate(plain)

    def test_review_hash_cannot_rebind_original_archive_or_expand_mapper_exception(self):
        for edit in (lambda v:v.update(originalImplementationSHA256='4'*64),
                     lambda v:v['mapperDifference']['config'].update({'userinfo.token.claim':False}),
                     lambda v:v['mapperDifference']['config'].update({'access.token.claim':'false'}),
                     lambda v:v['mapperDifference'].update(name='unrelated')):
            plan=self.continued(fixture());edit(plan['installComplete']['continuation'])
            plan['installContinuationSHA256']=p.sha(p.encoded(plan['installComplete']['continuation']))
            with self.assertRaises(ValueError):p.validate(plan)

    def test_actual_host_loader_requires_explicit_continuation_digest(self):
        plan=fixture();install=plan['install']
        install['implementationSHA256']={name:p.sha((LAB/'scripts'/name).read_bytes()) for name in p.INSTALL_FILES}
        self.continued(plan)
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);os.chmod(root,0o700)
            h.save(root/'plan.json',install);h.save(root/'complete.json',plan['installComplete'])
            args=SimpleNamespace(install_staging=root,install_driver=(LAB/'scripts').resolve(),
                expected_install_plan_sha256=p.sha(p.encoded(install)),
                expected_install_complete_sha256=p.sha(p.encoded(plan['installComplete'])))
            with self.assertRaisesRegex(ValueError,'closed_install_required'):h.installation(args)
            args.expected_install_continuation_sha256=plan['installContinuationSHA256']
            _,actual,done,sources=h.installation(args)
            self.assertEqual(actual,install);self.assertEqual(done,plan['installComplete'])
            self.assertEqual(set(sources),set(p.FILES+p.INSTALL_FILES))
            args.expected_install_continuation_sha256='f'*64
            with self.assertRaisesRegex(ValueError,'continuation_provenance_changed'):h.installation(args)

    def test_phase_cannot_drop_reviewed_continuation_binding(self):
        plan=self.continued(fixture())
        args=SimpleNamespace(staging=Path('/unused'),phase='verify',expected_plan_sha256=p.sha(p.encoded(plan)),
            expected_implementation_sha256=p.sha(p.encoded(plan['implementationSHA256'])))
        with patch.object(h,'read',return_value=p.encoded(plan)),patch.object(h,'current') as remote:
            with self.assertRaisesRegex(ValueError,'reviewed_probe_required'):h.run_phase(args,None,plan['install'],{})
            remote.assert_not_called()

    def test_future_is_only_one_unknown_ledger_entry(self):
        self.assertEqual(p.FUTURE['name'],'migrations/999999_lab_schema_probe.sql')
        self.assertRegex(p.FUTURE['sha256'],'^[0-9a-f]{64}$')
        code=(HERE/'dashboard-schema-probe-guest.py').read_text()
        self.assertIn('INSERT INTO dashboard_schema_migrations(name,sha256)',code)
        self.assertNotIn('DROP ',code);self.assertNotIn('DELETE FROM',code)
        self.assertEqual(code.count("'--mode','migrate'"),1)

    def test_refusal_requires_exact_version_error(self):
        raw=('time=2026-10-04T01:00:00Z level=ERROR msg="dashboard stopped" error="'+p.ERROR+'"\n').encode()
        self.assertTrue(p.refusal(1,raw,1)['refused'])
        for code,output,elapsed in ((0,raw,1),(1,raw,16),(1,raw+b'started\n',1),
                (1,raw.replace(p.ERROR.encode(),b'permission denied'),1),(1,b'x'*65537,1)):
            with self.assertRaises(ValueError):p.refusal(code,output,elapsed)

    def test_empty_database_rejects_function_type_and_extension_drift(self):
        value=dict(relations=0,schemas=0,routines=0,types=0,extensions=0,owner=p.ROLES['ddl'])
        with patch.object(g,'sql',return_value=p.encoded(value).decode()) as sql:
            self.assertEqual(g.empty_database(),{'empty':True})
            query=sql.call_args.args[0]
            for catalog in ('pg_class','pg_proc','pg_type','pg_extension','pg_namespace'):self.assertIn(catalog,query)
        for key in ('relations','schemas','routines','types','extensions','owner'):
            bad=dict(value);bad[key]='different' if key=='owner' else 1
            with patch.object(g,'sql',return_value=p.encoded(bad).decode()),self.assertRaises(ValueError):g.empty_database()

    def test_fixed_database_dispatch_and_private_query_transport(self):
        with patch.object(g.f,'run',return_value=b'1') as run:g.sql('SELECT 1;',p.DATABASE)
        self.assertNotIn('SELECT 1;',run.call_args.args[0]);self.assertEqual(run.call_args.kwargs['data'],b'SELECT 1;')
        for database in ('jobman_dashboard','jobman_control','jobman_dashboard_control_secondary'):
            with self.assertRaises(ValueError):g.sql('SELECT 1;',database)

    def test_hba_roles_only_and_tls_only(self):
        text=g.hba_prefix().decode();self.assertIn('hostssl jobman_schema_probe_v1 ',text)
        self.assertIn('10.77.0.10/32 scram-sha-256',text)
        self.assertEqual(text.count(' reject'),2)
        self.assertNotIn('jobman_install_',text);self.assertNotIn('host all all',text)

    def test_no_source_write_in_probe_sql(self):
        plan=fixture();raw=g.dsn('api',b'a'*64).decode()
        self.assertIn('/jobman_schema_probe_v1?',raw);self.assertIn('sslmode=verify-full',raw)
        self.assertIn('connect_timeout=5',raw)
        with self.assertRaises(ValueError):g.dsn('unrelated',b'a'*64)

    def test_database_state_hashes_only_and_scope_is_public(self):
        table={'name':'dashboard_schema_migrations','count':19,'bytes':2500,'digest':'a'*64}
        meta={'oid':'1','objects':'b'*64,'ledger':[p.FUTURE]}
        with patch.object(g,'sql',side_effect=[p.encoded([table['name']]).decode(),p.encoded([table]).decode(),p.encoded(meta).decode()]) as sql:
            result=g.database_state();self.assertEqual(result['rows'],19);self.assertNotIn('tables',result)
            self.assertIn('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY',sql.call_args_list[1].args[0])
        with patch.object(g,'sql',return_value='["other; DROP DATABASE postgres"]'),self.assertRaises(ValueError):g.database_state()

    def test_current_identity_must_be_linux_root_before_any_effect(self):
        with patch.object(g.os,'geteuid',return_value=501),patch.object(g,'snapshot') as called,self.assertRaises(ValueError):
            g.execute({'phase':'snapshot','host':'pg01'})
        called.assert_not_called()

    def test_private_files_exact_mode_and_no_overwrite(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);previous=os.umask(0o777)
            try:h.save(root/'receipt.json',{'ok':True})
            finally:os.umask(previous)
            self.assertEqual((root/'receipt.json').stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):h.save(root/'receipt.json',{'ok':False})
            os.link(root/'receipt.json',root/'alias')
            with self.assertRaises(ValueError):h.read(root/'receipt.json')

    def test_fifo_read_fails_fast(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            path=Path(tmp)/'fifo';os.mkfifo(path,0o600)
            with self.assertRaises(ValueError):h.read(path)

    def test_capture_actual_pipe_success_and_exact_error(self):
        popen=subprocess.Popen
        def local(args,**kw):
            for field in ('user','group','extra_groups'):kw.pop(field,None)
            return popen(args,**kw)
        raw='time=x level=ERROR msg="dashboard stopped" error="'+p.ERROR+'"\n'
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp,patch.object(g.subprocess,'Popen',side_effect=local):
            root=Path(tmp)
            code,out,elapsed=g.captured([sys.executable,'-c','import sys;sys.stderr.write('+repr(raw)+');sys.exit(1)'],os.getuid(),root,'actual')
            self.assertTrue(p.refusal(code,out,elapsed)['refused']);self.assertEqual((root/'actual.log').read_bytes(),out)

    def test_capture_actual_excess_output_is_bounded_and_reaped(self):
        popen=subprocess.Popen;children=[]
        def local(args,**kw):
            for field in ('user','group','extra_groups'):kw.pop(field,None)
            child=popen(args,**kw);children.append(child);return child
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp,patch.object(g.subprocess,'Popen',side_effect=local):
            with self.assertRaisesRegex(ValueError,'process_output_bound'):
                g.captured([sys.executable,'-c','import os;os.write(1,b"x"*100000);__import__("time").sleep(10)'],os.getuid(),Path(tmp),'overflow')
            self.assertLessEqual((Path(tmp)/'overflow.log').stat().st_size,65536);self.assertIsNotNone(children[0].returncode)

    def test_capture_actual_timeout_reaps_only_owned_process(self):
        popen=subprocess.Popen;children=[]
        def local(args,**kw):
            for field in ('user','group','extra_groups'):kw.pop(field,None)
            child=popen(args,**kw);children.append(child);return child
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp,patch.object(g.subprocess,'Popen',side_effect=local):
            with self.assertRaisesRegex(ValueError,'process_timeout'):
                g.captured([sys.executable,'-c','__import__("time").sleep(10)'],os.getuid(),Path(tmp),'timeout',seconds=.1)
            self.assertIsNotNone(children[0].returncode)

    def test_no_completed_receipt_on_refusal_mismatch(self):
        plan=fixture()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp,patch.object(g.g,'verify_release',return_value='/pinned/binary'),\
             patch.object(g,'artifacts',return_value={'safe':'a'*64}),patch.object(g,'captured',return_value=(1,b'wrong error',.1)),\
             patch.object(g.socket,'socket'):
            with self.assertRaises(ValueError):g.product(plan,Path(tmp),'refuse')
            self.assertTrue((Path(tmp)/'refuse-api.pending.json').exists());self.assertFalse((Path(tmp)/'refuse.json').exists())

    def test_runtime_arguments_have_no_ddl_or_secrets(self):
        plan=fixture();raw=('time=x msg="dashboard stopped" error="'+p.ERROR+'"\n').encode()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp,patch.object(g.g,'verify_release',return_value='/pinned/binary'),\
             patch.object(g,'artifacts',return_value={'safe':'a'*64}),patch.object(g,'captured',return_value=(1,raw,.1)) as called,patch.object(g.socket,'socket'):
            result=g.product(plan,Path(tmp),'refuse');self.assertEqual(set(result['processes']),{'api','worker'})
            for call in called.call_args_list:
                argv=call.args[0];self.assertNotIn('--migration-database-url-file',argv)
                self.assertFalse(any('postgres://' in a for a in argv));self.assertIn(call.args[1],(21920,21921))

    def test_guest_bootstrap_loads_exact_independent_modules(self):
        sources={name:(LAB/'scripts'/name).read_text() for name in p.INSTALL_FILES}
        sources.update({name:(HERE/name).read_text() for name in p.FILES})
        payload=p.encoded({'phase':'snapshot','host':'pg01','_sources':sources,'_hashes':{k:p.sha(v.encode()) for k,v in sources.items()}})
        out=io.StringIO()
        with patch.object(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(payload))),patch.object(sys,'stdout',out):
            exec(compile(h.BOOTSTRAP,'actual-bootstrap','exec'),{'__name__':'test'})
        result=p.decode(out.getvalue());self.assertFalse(result['ok']);self.assertEqual(result['code'],'linux_root_required')

    def test_existing_pending_refuses_second_invocation(self):
        plan=fixture()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);h.save(root/'refuse.pending.json',{'preserved':True})
            before=(root/'refuse.pending.json').read_bytes()
            with patch.object(g.os,'geteuid',return_value=0),patch.object(g.sys,'platform','linux'),\
                 patch.object(g.socket,'gethostname',return_value='storage01'),patch.object(g.f,'bounded',return_value=contextlib.nullcontext()),\
                 patch.object(g,'check_preserved'),patch.object(g,'locked',return_value=contextlib.nullcontext()),\
                 patch.object(g,'operation',return_value=root),patch.object(g,'product') as product:
                with self.assertRaisesRegex(ValueError,'uncertain_phase_requires_observation'):
                    g.execute({'phase':'refuse','host':'storage01','plan':plan,'apply':True})
                product.assert_not_called()
            self.assertEqual((root/'refuse.pending.json').read_bytes(),before)

    def test_observe_never_repeats_product(self):
        plan=fixture()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);receipt={'operationId':plan['operationId'],'phase':'refuse','completed':True,'planSHA256':p.sha(p.encoded(plan))}
            h.save(root/'refuse.json',receipt)
            with patch.object(g.os,'geteuid',return_value=0),patch.object(g.sys,'platform','linux'),\
                 patch.object(g.socket,'gethostname',return_value='storage01'),patch.object(g.f,'bounded',return_value=contextlib.nullcontext()),\
                 patch.object(g,'check_preserved'),patch.object(g,'locked',return_value=contextlib.nullcontext()),\
                 patch.object(g,'operation',return_value=root),patch.object(g.f,'read',return_value=p.encoded(receipt)),patch.object(g,'product') as product:
                self.assertEqual(g.execute({'phase':'observe','observedPhase':'refuse','host':'storage01','plan':plan}),receipt)
                product.assert_not_called()

    def test_host_final_database_drift_prevents_completion(self):
        plan=fixture();hashes=plan['implementationSHA256']
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as tmp:
            root=Path(tmp);args=SimpleNamespace(staging=root,phase='verify',expected_plan_sha256=p.sha(p.encoded(plan)),
                expected_implementation_sha256=p.sha(p.encoded(hashes)))
            with patch.object(h,'read',return_value=p.encoded(plan)),patch.object(h.p,'sha',wraps=p.sha),\
                 patch.object(h,'current',side_effect=[{}, {}, {}, {'changed':True}]),\
                 patch.object(h,'receipt',side_effect=[{'complete':True},{'state':{'unchanged':True}}]):
                # Use the real plan/implementation binding while keeping only
                # remote calls mocked; a changed ledger/table proof cannot close.
                sources={name:'' for name in hashes}
                plan['implementationSHA256']={name:p.sha(b'') for name in hashes}
                plan['install']['implementationSHA256']={name:p.sha(b'') for name in p.INSTALL_FILES}
                args.expected_plan_sha256=p.sha(p.encoded(plan));args.expected_implementation_sha256=p.sha(p.encoded(plan['implementationSHA256']))
                with patch.object(h,'read',return_value=p.encoded(plan)),self.assertRaisesRegex(ValueError,'refused_database_changed'):
                    h.run_phase(args,SimpleNamespace(h=SimpleNamespace(HOSTS=('control01','storage01','pg01'))),plan['install'],sources)
            self.assertFalse((root/'complete.json').exists())

    def test_replaced_database_oid_is_rejected(self):
        plan=fixture();row={'completed':True,'phase':'database','operationId':plan['operationId'],
            'planSHA256':p.sha(p.encoded(plan)),'databaseOID':'100'}
        with patch.object(g,'operation',return_value=Path('/fixed')),patch.object(g.f,'read',return_value=p.encoded(row)),patch.object(g,'sql',return_value='101'):
            with self.assertRaisesRegex(ValueError,'probe_database_replaced'):g.database_identity(plan)

    def test_json_duplicate_and_unknown_nonfinite_rejected(self):
        for raw in ('{"a":1,"a":2}','{"a":NaN}'):
            with self.assertRaises(ValueError):p.decode(raw)

if __name__=='__main__':unittest.main()
