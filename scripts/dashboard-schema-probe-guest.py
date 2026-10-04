#!/usr/bin/env python3
"""Fixed disposable schema probe; loaded only with hash-pinned install primitives."""
import base64
import contextlib
import fcntl
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import urllib.parse

# p (probe plan), g (install guest), f (bounded IO), u (source inventory),
# b (source fences) are injected by the reviewed bootstrap, never user imports.

def sql(query,database='postgres',timeout=20):
    p.need(database in ('postgres',p.DATABASE,'jobman_install_v1'),'sql_database')
    return f.run(['podman','exec','-i','--user','postgres','jobman-postgres','psql','-X','-q','-A','-t',
                  '-U','jobman_control','-v','ON_ERROR_STOP=1','-d',database],
                 'schema_probe_sql',data=query.encode(),timeout=timeout,maximum=1<<20).decode().strip()

def ledger():
    return p.decode(sql("BEGIN READ ONLY; SET LOCAL statement_timeout='5000ms'; SELECT json_agg(json_build_object('name',name,'sha256',sha256) ORDER BY name) FROM dashboard_schema_migrations; COMMIT;",p.DATABASE))

def empty_database():
    query="""BEGIN READ ONLY; SET LOCAL statement_timeout='5000ms';
SELECT json_build_object('relations',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),
'schemas',(SELECT count(*) FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname NOT IN ('public','information_schema')),
'routines',(SELECT count(*) FROM pg_proc r JOIN pg_namespace n ON n.oid=r.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),
 'types',(SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),
 'extensions',(SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql'),
 'owner',(SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public')); COMMIT;"""
    value=p.decode(sql(query,p.DATABASE))
    p.need(value==dict(relations=0,schemas=0,routines=0,types=0,extensions=0,owner=p.ROLES['ddl']),'empty_probe_required')
    return {'empty':True}

def database_state():
    # Only the tiny synthetic probe is scanned. Names come from the catalog,
    # are allowlisted before interpolation, and no row payload leaves PostgreSQL.
    names=p.decode(sql("SELECT coalesce(json_agg(c.relname ORDER BY c.relname),'[]') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p');",p.DATABASE))
    p.need(1<=len(names)<=128 and all(p.re.fullmatch('dashboard_[a-z_]{1,80}',n) for n in names),'probe_table_names')
    rows=[]
    for name in names:
        rows.append("SELECT '"+name+"' AS name,count(*) AS count,coalesce(sum(octet_length(to_jsonb(t)::text)),0) AS bytes,encode(sha256(convert_to(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),''),'UTF8')),'hex') AS digest FROM public."+name+' t')
    query="BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms'; SELECT json_agg(row_to_json(x) ORDER BY name) FROM ("+' UNION ALL '.join(rows)+") x; COMMIT;"
    tables=p.decode(sql(query,p.DATABASE))
    p.need(all(row['count']<=100 and row['bytes']<=1<<20 for row in tables) and sum(row['bytes'] for row in tables)<=8<<20,'probe_data_bound')
    meta=p.decode(sql("""BEGIN READ ONLY; SET LOCAL statement_timeout='5000ms'; SELECT json_build_object(
'oid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),
'database',(SELECT encode(sha256(convert_to(json_build_object('owner',datdba,'acl',datacl)::text,'UTF8')),'hex') FROM pg_database WHERE datname=current_database()),
'sequences',(SELECT encode(sha256(convert_to(coalesce(json_agg(row_to_json(s) ORDER BY sequencename)::text,''),'UTF8')),'hex') FROM pg_sequences s WHERE schemaname='public'),
'objects',(SELECT encode(sha256(convert_to(coalesce(json_agg(row_to_json(x) ORDER BY x.relname)::text,''),'UTF8')),'hex') FROM
 (SELECT c.relname,c.relkind,c.relowner,c.relacl,pg_get_userbyid(c.relowner) AS owner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') x),
'definitions',(SELECT encode(sha256(convert_to(json_build_object(
 'columns',(SELECT json_agg(row_to_json(a) ORDER BY a.attrelid,a.attnum) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'defaults',(SELECT json_agg(row_to_json(d) ORDER BY d.oid) FROM pg_attrdef d JOIN pg_class c ON c.oid=d.adrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
 'constraints',(SELECT json_agg(row_to_json(c) ORDER BY c.oid) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='public'),
 'functions',(SELECT json_agg(row_to_json(r) ORDER BY r.oid) FROM pg_proc r JOIN pg_namespace n ON n.oid=r.pronamespace WHERE n.nspname='public'),
 'triggers',(SELECT json_agg(row_to_json(t) ORDER BY t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public')
 )::text,'UTF8')),'hex')),
'ledger',(SELECT json_agg(json_build_object('name',name,'sha256',sha256) ORDER BY name) FROM dashboard_schema_migrations)); COMMIT;""",p.DATABASE))
    return dict(meta,tablesSHA256=p.sha(p.encoded(tables)),tableCount=len(tables),rows=sum(v['count'] for v in tables))

def hba_prefix():
    roles=','.join(p.ROLES.values())
    return (f'# Disposable Dashboard schema refusal v1\nhostssl {p.DATABASE} {roles} 10.77.0.10/32 scram-sha-256\n'
            f'host all {roles} 0.0.0.0/0 reject\nhost all {roles} ::/0 reject\n').encode()

def install_closed(install,host):
    g.p.validate(install);root=g.operation(install)
    phase='stop' if host=='storage01' else 'retire-identity' if host=='control01' else 'grants'
    row=p.decode(f.read(root/(phase+'.json')))
    p.need(row.get('completed') is True and row.get('operationId')==install['operationId'] and
           row.get('planSHA256')==p.sha(p.encoded(install)),'install_completion_required')
    if host=='control01':p.need(row.get('enabled') is False,'install_identity_not_retired')
    if host=='storage01':g.stopped();g.own_configuration(install,'baseline')
    if host=='pg01':p.need(g.install_ledger()==install['candidates']['baseline']['ledger'],'install_schema_changed')

def preserved(install,host):
    install_closed(install,host)
    if host=='control01':
        return {'runtime':f.host_snapshot(host,install['snapshot'][host]['preserved']['revision']),
                'files':u.source_inventory()}
    if host=='storage01':
        paths=[*g.ROOTS.values(),Path(g.p.REPORTS)]
        for selected in ('baseline','upgrade'):g.verify_release(install,selected)
        return {'runtime':f.host_snapshot(host,install['snapshot'][host]['preserved']['revision']),
                'installTrees':{str(path):g.tree(path,maximum=300<<20) for path in paths},'restore':g.restore_storage()}
    return {'databases':u.databases(),'restore':g.restore_database(),'install':g.data_state(install)}

def check_preserved(plan,host):
    before=plan['snapshot'][host]['preserved'];after=preserved(plan['install'],host)
    if host=='pg01':
        b.database_preserved(before['databases']['dashboard'],after['databases']['dashboard'])
        after['databases']['dashboard']=before['databases']['dashboard']
    p.need(after==before,'retained_install_or_runtime_changed')
    if host=='pg01':
        current=g.hba_bytes();original=plan['snapshot'][host]['hbaSHA256']
        p.need(p.sha(current)==original or current.startswith(hba_prefix()) and p.sha(current[len(hba_prefix()):])==original,'unrelated_hba_changed')
    return {'preserved':True,'host':host}

def snapshot(install,host):
    value={'preserved':preserved(install,host)}
    if host=='storage01':
        p.need(all(not os.path.lexists(x) for x in (*p.ROOTS.values(),*p.RUN.values(),p.BASE)),'probe_path_exists')
        with socket.socket() as sock:sock.bind(('127.0.0.1',p.PORT))
        s=os.statvfs('/var/lib');value.update(unused=True,freeBytes=s.f_bavail*s.f_frsize)
    if host=='pg01':
        names=','.join("'"+r+"'" for r in p.ROLES.values())
        p.need(sql("SELECT count(*) FROM pg_database WHERE datname='"+p.DATABASE+"'")=='0' and
               sql('SELECT count(*) FROM pg_roles WHERE rolname IN ('+names+')')=='0' and not os.path.lexists(p.BASE),'probe_database_exists')
        s=os.statvfs('/var/lib/containers');value.update(unused=True,freeBytes=s.f_bavail*s.f_frsize,hbaSHA256=p.sha(g.hba_bytes()),
            connections=int(sql("SELECT current_setting('max_connections')::int-count(*)-current_setting('superuser_reserved_connections')::int FROM pg_stat_activity")))
    return value

@contextlib.contextmanager
def locked(create=False):
    root=Path(p.BASE)
    if create and not root.exists():g.directory(root,create=True)
    g.directory(root);path=root/'.lock'
    try:fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_NONBLOCK,0o600);os.fchmod(fd,0o600)
    except FileExistsError:fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        st=os.fstat(fd);p.need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o600,'probe_lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)

def operation(plan,create=False):
    root=Path(p.BASE)/plan['operationId']
    if create and not root.exists():
        p.need(set(x.name for x in Path(p.BASE).iterdir())=={'.lock'},'probe_already_admitted')
        g.directory(root,create=True);g.marker(root,'plan',plan)
    g.directory(root);p.need(f.read(root/'plan.json',maximum=8<<20)==p.encoded(plan),'probe_plan_changed');return root

def database_identity(plan):
    row=p.decode(f.read(operation(plan)/'database.json'))
    p.need(row.get('completed') is True and row.get('phase')=='database' and row.get('operationId')==plan['operationId'] and
           row.get('planSHA256')==p.sha(p.encoded(plan)),'probe_database_receipt')
    oid=sql("SELECT oid::text FROM pg_database WHERE datname='"+p.DATABASE+"'")
    p.need(oid==row.get('databaseOID') and oid.isdigit() and int(oid)>0,'probe_database_replaced')

def secrets(plan,values):
    p.need(set(values)==set(p.ROLES),'secret_roles');out={}
    for role,value in values.items():
        raw=base64.b64decode(value,validate=True)
        p.need(p.HEX.fullmatch(raw.decode()) and p.sha(raw)==plan['secretSHA256'][role],'secret_pin');out[role]=raw
    return out

def dsn(role,secret):
    p.need(role in p.ROLES and p.HEX.fullmatch(secret.decode()),'dsn_role')
    query=urllib.parse.urlencode({'sslmode':'verify-full','sslrootcert':p.CA,'connect_timeout':'5'})
    return ('postgres://'+p.ROLES[role]+':'+secret.decode()+'@10.77.0.20:5432/'+p.DATABASE+'?'+query+'\n').encode()

def create_database(plan,values,root):
    keys=secrets(plan,values);before=g.hba_bytes()
    p.need(p.sha(before)==plan['snapshot']['pg01']['hbaSHA256'],'hba_drift')
    names=','.join("'"+r+"'" for r in p.ROLES.values())
    p.need(sql("SELECT count(*) FROM pg_database WHERE datname='"+p.DATABASE+"'")=='0' and sql('SELECT count(*) FROM pg_roles WHERE rolname IN ('+names+')')=='0','probe_database_exists')
    lines=["SET statement_timeout='20000ms'; SET lock_timeout='500ms';"]
    for role,name in p.ROLES.items():
        lines.append(f"CREATE ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {16 if role in p.USERS else 2} PASSWORD '{keys[role].decode()}';")
    lines += [f'CREATE DATABASE {p.DATABASE} OWNER {p.ROLES["ddl"]} TEMPLATE template0;',
              f'REVOKE ALL ON DATABASE {p.DATABASE} FROM PUBLIC;',f'GRANT CONNECT ON DATABASE {p.DATABASE} TO '+','.join(p.ROLES[r] for r in p.COMPONENTS)+';',
              '\\connect '+p.DATABASE,'REVOKE ALL ON SCHEMA public FROM PUBLIC;',f'ALTER SCHEMA public OWNER TO {p.ROLES["ddl"]};']
    g.put(root/'hba.before',before);g.put(root/'hba.after',hba_prefix()+before)
    sql('\n'.join(lines)+'\n',timeout=35);empty_database()
    target='/var/lib/postgresql/data/pg_hba.schema-probe-'+plan['operationId']
    command='set -eu; set -C; umask 077; cat > "$1"; chown postgres:postgres "$1"; chmod 0600 "$1"; sync -f "$1"; mv -T "$1" /var/lib/postgresql/data/pg_hba.conf; sync -f /var/lib/postgresql/data'
    p.need(g.hba_bytes()==before,'hba_pre_swap_drift')
    f.run(['podman','exec','-i','--user','root','jobman-postgres','sh','-c',command,'schema-probe-hba',target],
          'probe_hba',data=hba_prefix()+before,timeout=15)
    p.need(sql('SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL')=='0' and sql('SELECT pg_reload_conf()')=='t','hba_reload')
    return {'databaseOID':sql("SELECT oid::text FROM pg_database WHERE datname='"+p.DATABASE+"'"),'hbaSHA256':p.sha(g.hba_bytes())}

def material(plan,values):
    keys=secrets(plan,values)
    for role,path in p.ROOTS.items():
        uid=p.USERS.get(role,0);g.directory(path,uid,uid,create=True)
        g.put(Path(path)/'config.json',p.encoded(plan['configs'][role]),uid,uid)
        g.put(Path(path)/'database-url',dsn(role,keys[role]),uid,uid)
    g.put(Path(p.ROOTS['operator'])/'ddl-url',dsn('ddl',keys['ddl']))
    for role,path in p.RUN.items():g.directory(path,p.USERS[role],p.USERS[role],create=True)
    return {'configSHA256':{r:p.sha(p.encoded(v)) for r,v in plan['configs'].items()}}

def artifacts(plan):
    for role,path in p.ROOTS.items():
        uid=p.USERS.get(role,0);g.directory(path,uid,uid)
        p.need(f.read(Path(path)/'config.json',uid)==p.encoded(plan['configs'][role]),'probe_config_changed')
        parsed=urllib.parse.urlparse(f.read(Path(path)/'database-url',uid).decode().strip())
        p.need(parsed.password is not None and p.sha(parsed.password.encode())==plan['secretSHA256'][role] and
               f.read(Path(path)/'database-url',uid)==dsn(role,parsed.password.encode()),'probe_dsn_changed')
    ddl=f.read(Path(p.ROOTS['operator'])/'ddl-url')
    parsed=urllib.parse.urlparse(ddl.decode().strip())
    p.need(parsed.password is not None and p.sha(parsed.password.encode())==plan['secretSHA256']['ddl'] and
           ddl==dsn('ddl',parsed.password.encode()),'probe_ddl_dsn_changed')
    return {path:g.tree(path) for path in (*p.ROOTS.values(),*p.RUN.values())}

def captured(argv,uid,root,name,seconds=15):
    """Bound actual output through pipes; reap exactly the newly owned process."""
    started=time.monotonic();output=bytearray();child=None;completed=False
    try:
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
             cwd='/',env={'PATH':'/usr/bin:/bin','GOMAXPROCS':'2','GOMEMLIMIT':'256MiB'},
             user=uid,group=uid,extra_groups=([p.READER] if uid else []),umask=0o077,start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout,selectors.EVENT_READ)
            while selector.get_map():
                left=seconds-(time.monotonic()-started);p.need(left>0,'process_timeout')
                for key,_ in selector.select(min(left,.1)):
                    raw=os.read(key.fileobj.fileno(),8192)
                    if not raw:selector.unregister(key.fileobj);continue
                    p.need(len(output)+len(raw)<=65536,'process_output_bound');output.extend(raw)
            left=seconds-(time.monotonic()-started);p.need(left>0,'process_timeout');code=child.wait(timeout=left)
        elapsed=time.monotonic()-started;p.need(elapsed<=seconds,'process_timeout');completed=True
        return code,bytes(output),elapsed
    finally:
        if child is not None:
            if not completed:
                # Do not reap before group cleanup: a retained child PID cannot
                # be reused while an inherited output pipe keeps us waiting.
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait(timeout=3)
            child.stdout.close()
        # Logs belong only to this single admitted invocation. Preserve bounded
        # partial evidence even when timeout/overflow/refusal validation fails.
        g.put(root/(name+'.log'),bytes(output))

def product(plan,root,phase):
    binary=g.verify_release(plan['install'],plan['selected']);before=artifacts(plan)
    if phase=='migrate':
        args=[binary,'--mode','migrate','--config',p.ROOTS['api']+'/config.json','--migration-database-url-file',p.ROOTS['operator']+'/ddl-url']
        code,_,_=captured(args,0,root,'migrate',60);p.need(code==0,'probe_migration_failed');return {'migrated':True}
    if phase=='positive':
        for role,uid in p.USERS.items():
            code,_,_=captured([binary,'--mode','check-config','--check-mode',role,'--config',p.ROOTS[role]+'/config.json'],uid,root,'positive-'+role)
            p.need(code==0,'valid_probe_config_required')
        code,raw,_=captured([binary,'status','--operator-config',p.ROOTS['operator']+'/config.json'],0,root,'positive-status')
        p.need(code==0 and isinstance(p.decode(raw),dict),'compatible_schema_status_required')
        p.need(artifacts(plan)==before,'positive_artifact_changed');return {'compatibleSchema':True,'configsValid':True}
    result={}
    for role,uid in p.USERS.items():
        with socket.socket() as sock:sock.bind(('127.0.0.1',p.PORT))
        p.need(not os.path.lexists(p.RUN[role]+'/observe.sock'),'preexisting_listener')
        g.marker(root,'refuse-'+role+'.pending',{'operationId':plan['operationId'],'role':role})
        code,raw,elapsed=captured([binary,'--mode',role,'--config',p.ROOTS[role]+'/config.json'],uid,root,'refuse-'+role)
        result[role]=p.refusal(code,raw,elapsed)
        p.need(artifacts(plan)==before,'startup_artifact_changed')
        with socket.socket() as sock:sock.bind(('127.0.0.1',p.PORT))
    return {'processes':result,'artifactsSHA256':p.sha(p.encoded(before))}

def execute(payload):
    p.need(os.geteuid()==0 and sys.platform=='linux','linux_root_required')
    host=socket.gethostname().split('.')[0];phase=payload['phase'];p.need(host==payload['host'] and host in ('storage01','pg01','control01'),'fixed_host')
    with f.bounded(120):
        if phase=='snapshot':return snapshot(payload['install'],host)
        plan=p.validate(payload['plan']);g.p.validate(plan['install']);check_preserved(plan,host)
        if phase=='preserved':return {'preserved':True,'host':host}
        if phase=='state':p.need(host=='pg01','state_host');database_identity(plan);return database_state()
        if phase=='empty':p.need(host=='pg01','empty_host');database_identity(plan);return empty_database()
        if phase=='artifacts':p.need(host=='storage01','artifacts_host');return artifacts(plan)
        actual=payload.get('observedPhase') if phase=='observe' else phase
        p.need(actual in p.PHASES and host==p.PHASES[actual],'phase_host')
        with locked(create=phase in ('database','material')):
            if phase=='observe':
                root=operation(plan);row=p.decode(f.read(root/(actual+'.json')))
                p.need(row.get('completed') is True and row.get('phase')==actual and row.get('operationId')==plan['operationId'] and row.get('planSHA256')==p.sha(p.encoded(plan)),'no_durable_completion')
                if host=='pg01':database_identity(plan)
                return row
            p.need(payload.get('apply') is True,'explicit_apply_required');root=operation(plan,create=phase in ('database','material'))
            p.need(not (root/(phase+'.pending.json')).exists(),'uncertain_phase_requires_observation')
            g.marker(root,phase+'.pending',{'phase':phase,'planSHA256':p.sha(p.encoded(plan))})
            if phase=='database':result=create_database(plan,payload['secrets'],root)
            elif phase=='material':result=material(plan,payload['secrets'])
            elif phase in ('migrate','positive','refuse'):result=product(plan,root,phase)
            elif phase=='grants':
                database_identity(plan)
                p.need(ledger()==plan['install']['candidates'][plan['selected']]['ledger'],'exact_probe_ledger')
                p.need(set(payload['grants'])==set(p.COMPONENTS),'grant_roles')
                for role,value in payload['grants'].items():
                    raw=base64.b64decode(value,validate=True);p.need(len(raw)<=256<<10 and p.sha(raw)==plan['grantSHA256'][role],'grant_pin');sql(raw.decode(),p.DATABASE,35)
                result={'granted':True,'state':database_state()}
            else:
                database_identity(plan)
                p.need(ledger()==plan['install']['candidates'][plan['selected']]['ledger'],'future_already_present')
                sql("BEGIN; SET LOCAL statement_timeout='5000ms'; SET LOCAL lock_timeout='500ms'; INSERT INTO dashboard_schema_migrations(name,sha256) VALUES ('"+p.FUTURE['name']+"','"+p.FUTURE['sha256']+"'); COMMIT;",p.DATABASE)
                p.need(ledger()==plan['install']['candidates'][plan['selected']]['ledger']+[p.FUTURE],'future_ledger_mismatch');result={'state':database_state()}
            check_preserved(plan,host)
            row=dict(result,operationId=plan['operationId'],phase=phase,completed=True,planSHA256=p.sha(p.encoded(plan)))
            g.marker(root,phase,row);return row
