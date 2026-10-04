#!/usr/bin/env python3
"""Assemble accepted-scale public inputs from completed private receipts; no network."""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import ssl
import stat

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


a = load('dashboard-scale-activation-common'); c = a.c
i = load('dashboard-scale-identities-common')
FILES = ('dashboard-scale-fixture.py', 'dashboard-scale-activation-common.py',
         'dashboard-scale-source-common.py', 'dashboard-scale-plan.py', 'dashboard-scale-identities-common.py')
DESTINATIONS = ('scale/control-primary-ca.crt', 'scale/control-secondary-ca.crt', 'scale-fixture.json')


def implementation():
    result = {}
    for name in FILES:
        path = HERE / name; mode = stat.S_IMODE(path.lstat().st_mode)
        c.need(not mode & 0o022, 'implementation_permissions')
        result[name] = c.sha(c.read(path, mode=mode))
    return result


def timestamp(value):
    c.need(isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z', value), 'utc_timestamp_required')
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


@contextmanager
def locked(root):
    c.directory(root); path = root / '.scale-fixture.lock'
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchmod(fd, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd); named = path.lstat()
        c.need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and
               (s.st_dev, s.st_ino) == (named.st_dev, named.st_ino), 'private_fixture_lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); yield
    finally:
        os.close(fd)


class Inputs:
    """A private receipt inventory; never read password files or source keys."""
    def __init__(self): self.files = {}

    def read(self, path, public=False):
        path = Path(path); mode = stat.S_IMODE(path.lstat().st_mode) if public else 0o600
        c.need(not public or mode in (0o600, 0o644), 'public_ca_permissions')
        raw = c.read(path, maximum=65536 if public else 1 << 20, mode=mode)
        proof = {'sha256': c.sha(raw), 'mode': mode}
        c.need(str(path) not in self.files or self.files[str(path)] == proof, 'input_changed_during_read')
        self.files[str(path)] = proof; return raw

    def json(self, path): return c.decode(self.read(path))


def identities(inputs, staging, handoff):
    c.directory(staging); c.directory(handoff)
    proof = inputs.json(staging / 'verify.complete.json')
    c.need(proof == inputs.json(staging / 'apply.complete.json'), 'identity_verification_incomplete')
    raw = inputs.read(handoff / 'identities.json'); value = c.decode(raw)
    stage_raw = inputs.read(staging / 'stage.json'); stage = c.decode(stage_raw)
    preflight_raw = inputs.read(staging / 'preflight.json'); preflight = c.decode(preflight_raw)
    c.need(proof == {'stageSHA256': c.sha(stage_raw), 'identitiesSHA256': c.sha(raw)} and inputs.read(staging / 'identities.json') == raw,
           'identity_verified_result_changed')
    c.need(stage['version'] == 1 and stage['issuer'] == c.ISSUER and stage['accounts'] == i.accounts() and
           stage['preflightSHA256'] == c.sha(preflight_raw) and stage['implementationSHA256'] == preflight['implementationSHA256'], 'identity_stage_binding')
    c.need(set(value) == {'version', 'synthetic', 'issuer', 'preservedSHA256', 'users'} and value['version'] == 1 and value['synthetic'] is True and
           value['issuer'] == c.ISSUER and value['preservedSHA256'] == c.sha(c.encoded(preflight['baseline']['preserved'])) and len(value['users']) == 25, 'identity_record_shape')
    subjects = set()
    for user, account in zip(value['users'], i.accounts()):
        subject = user['subject']; c.need(c.UUID.fullmatch(subject) and subject != '00000000-0000-0000-0000-000000000000' and subject not in subjects, 'identity_subject')
        c.need(user == {'username': account['login'], 'keycloakUsername': account['username'], 'directoryId': account['directoryId'], 'subject': subject, 'name': account['name']}, 'identity_account_mapping')
        subjects.add(subject)
    manifest = inputs.json(handoff / 'handoff.json')
    c.need(set(manifest) == {'stageSHA256', 'historyAt', 'files'} and manifest['stageSHA256'] == proof['stageSHA256'] and
           set(manifest['files']) == {'primary-scale-input.json', 'secondary-scale-input.json'}, 'identity_handoff_binding')
    source_inputs = {}
    for profile, spec in c.PROFILES.items():
        name = profile + '-scale-input.json'; raw = inputs.read(handoff / name); source = c.decode(raw)
        c.need(c.sha(raw) == manifest['files'][name] and source == {'instanceId': spec['instance'], 'issuer': c.ISSUER, 'historyAt': manifest['historyAt'],
               'users': [{key: row[key] for key in ('directoryId', 'subject', 'name')} for row in value['users']]}, 'identity_source_input')
        source_inputs[profile] = source
    timestamp(manifest['historyAt'])
    return value, source_inputs, c.sha(c.encoded(manifest))


def source_handoff(inputs, directory, profile, expected_input, identity_handoff_sha):
    c.directory(directory); p = c.PROFILES[profile]
    names = ('seed.json', 'directory.after.json', 'directory-state.after.json', 'receipt.json', 'driver-receipt.json')
    handoff = {name: a.encoded_file(inputs.read(directory / name)) for name in names}
    driver = a.document(handoff['driver-receipt.json']); helper = a.document(handoff['receipt.json'])
    preflight_raw = inputs.read(directory.parent / 'preflight.json'); preflight = c.decode(preflight_raw)
    verify_raw = inputs.read(directory.parent / 'verify.complete.json'); verify = c.decode(verify_raw)
    c.need(preflight['implementationSHA256'] == a.SOURCE_IMPLEMENTATION_SHA and preflight['profile'] == profile and preflight['input'] == expected_input and preflight['identityHandoffSHA256'] == identity_handoff_sha and
           c.sha(preflight_raw) == driver['executionId'] and verify['receipt'] == driver and helper['inputSHA256'] == c.sha(c.encoded(expected_input)), 'source_verified_input_binding')
    c.need(inputs.json(directory.parent / 'seed.complete.json') == driver, 'source_seed_completion')
    db = verify['database']; before = preflight['database']
    c.need(db['database'] == p['database'] and db['instance'] == p['instance'] and db['epoch'] == '1' and db['migrations'] == 21, 'source_verified_identity')
    for key in ('database', 'instance', 'epoch', 'ledgerSHA256', 'migrations', 'namespaceIds', 'namespaceSHA256', 'jobs'):
        c.need(db[key] == before[key], 'source_original_history_changed')
    c.need(db['scaleNamespaces'] == p['count'] and db['scalePrincipals'] == 25 and db['namespaceTotal'] == before['namespaceTotal'] + p['count'], 'source_verified_counts')
    counts = [{'name': name, 'total': 10050, 'active': 50, 'imported': 10000, 'runs': 0, 'executions': 0, 'agents': 0, 'events': 0} for name in c.names(profile)]
    c.need(db['scaleCounts'] == counts, 'captured_seed_execution_counts')
    return handoff, c.sha(verify_raw)


def activation(inputs, directory, handoffs, verification, expected_plan, expected_implementation):
    c.directory(directory)
    snapshot = inputs.json(directory / 'snapshot.json'); plan_raw = inputs.read(directory / 'plan.json'); plan = c.decode(plan_raw)
    c.need(c.HEX.fullmatch(expected_plan or '') and c.HEX.fullmatch(expected_implementation or '') and c.sha(plan_raw) == expected_plan, 'activation_plan_digest')
    c.need(inputs.json(directory / 'handoffs.json') == handoffs and snapshot['seedVerificationSHA256'] == verification, 'activation_seed_handoffs')
    execution = a.binding(snapshot, handoffs, plan, expected_implementation)
    c.need(inputs.json(directory / 'binding.json') == {'implementationSHA256': expected_implementation, 'executionId': execution}, 'activation_implementation_binding')
    hold = inputs.json(directory / 'hold.json'); resume = inputs.json(directory / 'resume.json')
    a.validate_database(snapshot['database'], snapshot, plan, False, 7)
    expected_hold = dict(snapshot['database']['hold'], held=True, generation=int(snapshot['database']['hold']['generation']) + 1)
    c.need(a.same_hold(hold, expected_hold), 'activation_hold_baseline')
    c.need(hold['held'] is True and resume['held'] is False and int(resume['generation']) == int(hold['generation']) + 1 and
           hold.get('restoreRecordedThrough') == resume.get('restoreRecordedThrough'), 'activation_resume_incomplete')
    c.need(inputs.json(directory / 'verify.json') == {host: {'host': host, 'revision': 8, 'verified': True} for host in ('control01', 'storage01')}, 'activation_final_verification')
    for role in ('api', 'worker', 'broker'):
        c.need(inputs.json(directory / ('restart-' + role + '.json')) == {'role': role, 'ready': True, 'revision': 8}, 'activation_runtime_readiness')
    for profile in c.PROFILES:
        original = inputs.json(directory / ('recovery-plan-' + profile + '.json'))
        applied = inputs.json(directory / ('recovery-apply-' + profile + '.json'))
        a.validate_recovery(original, profile, plan); a.validate_recovery(applied, profile, plan)
        c.need(original['id'] == applied['id'] and original['digest'] == applied['digest'] and original['gapId'] == applied['gapId'] and applied['status'] == 'applied', 'activation_recovery_incomplete')
    return snapshot, plan, execution, resume


def public_ca(inputs, path):
    raw = inputs.read(path, public=True)
    c.need(re.fullmatch(rb'\s*-----BEGIN CERTIFICATE-----[\r\n]+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*', raw) is not None, 'single_public_ca_required')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try: context.load_verify_locations(cadata=raw.decode('ascii'))
    except (ValueError, UnicodeError, ssl.SSLError): raise c.Failure('public_ca_invalid') from None
    return raw


def assemble(args):
    inputs = Inputs()
    users, source_inputs, identity_handoff_sha = identities(inputs, args.identity_staging, args.identity_handoff)
    handoffs, verification = {}, {}
    for profile, path in [('primary', args.primary_handoff), ('secondary', args.secondary_handoff)]:
        handoffs[profile], verification[profile] = source_handoff(inputs, path, profile, source_inputs[profile], identity_handoff_sha)
    snapshot, plan, execution, resumed = activation(inputs, args.activation_staging, handoffs, verification, args.activation_plan_sha256, args.activation_implementation_sha256)
    sources, prepared, certificates = [], [], {}
    for profile, ca_path in [('primary', args.primary_ca), ('secondary', args.secondary_ca)]:
        p = c.PROFILES[profile]; seed = a.validate_handoff(profile, handoffs[profile], snapshot['sources'][profile]); source = source_inputs[profile]
        c.need(set(seed) == {'version', 'synthetic', 'mode', 'deploymentId', 'instanceId', 'recoveryEpoch', 'preparedAt', 'historyAt', 'identities', 'namespaces'} and
               seed['version'] == 1 and seed['synthetic'] is True and seed['mode'] == 'imported-history-no-execution' and seed['recoveryEpoch'] == '1' and
               seed['historyAt'] == source['historyAt'], 'source_fixture_shape')
        c.need(timestamp(seed['historyAt']) < timestamp(seed['preparedAt']) <= datetime.now(timezone.utc), 'source_preparation_time')
        for row in seed['namespaces']:
            c.need(set(row) == {'id', 'name', 'activeJobId', 'importedJobId', 'activeJobs', 'importedHistory'} and type(row['activeJobs']) is int and type(row['importedHistory']) is int, 'public_namespace_fields')
        for actual, expected in zip(seed['identities'], source['users']):
            c.need(actual['directoryId'] == expected['directoryId'] and actual['subject'] == expected['subject'] and actual['displayName'] == expected['name'] and actual['issuer'] == c.ISSUER, 'source_subject_drift')
        raw = public_ca(inputs, ca_path); digest = c.sha(raw)
        for role in ('api', 'worker'):
            controls = a.document(plan['runtime'][role])['controls']; selected = [row for row in controls if row['id'] == p['deployment']]
            c.need(len(selected) == 1 and selected[0]['expectedInstanceId'] == p['instance'], 'source_configuration_identity')
            trust = selected[0]['trustRootsFile']; proof = snapshot['hosts']['storage01']['materials'][role][trust]
            c.need(proof['sha256'] == digest and proof['mode'] in (0o600, 0o644), 'configured_public_ca_drift')
        certificates['scale/control-' + profile + '-ca.crt'] = raw
        prepared.append(seed['preparedAt'])
        sources.append({'deploymentId': p['deployment'], 'instanceId': p['instance'], 'recoveryEpoch': seed['recoveryEpoch'], 'caSHA256': digest, 'namespaces': seed['namespaces']})
    c.need(sources[0]['caSHA256'] != sources[1]['caSHA256'], 'independent_source_trust_required')
    fixture = {'version': 1, 'synthetic': True, 'mode': 'imported-history-no-execution', 'preparedAt': max(prepared, key=timestamp),
               'historyAt': source_inputs['primary']['historyAt'], 'users': [{key: user[key] for key in ('username', 'directoryId', 'subject')} for user in users['users']], 'sources': sources}
    c.need(source_inputs['primary']['historyAt'] == source_inputs['secondary']['historyAt'], 'shared_history_window')
    certificates['scale-fixture.json'] = c.encoded(fixture)
    return {'version': 1, 'synthetic': True, 'activationExecutionId': execution, 'activationPlanSHA256': args.activation_plan_sha256,
            'activationImplementationSHA256': args.activation_implementation_sha256, 'resumedHold': resumed, 'inputs': inputs.files,
            'implementation': implementation(), 'outputs': {name: {'sha256': c.sha(raw), 'bytesBase64': a.encoded_file(raw)} for name, raw in certificates.items()}}


def validate_stage(value):
    c.need(value['version'] == 1 and value['synthetic'] is True and value['implementation'] == implementation() and set(value['outputs']) == set(DESTINATIONS), 'fixture_stage_identity')
    c.need(1 <= len(value['inputs']) <= 100, 'fixture_input_bound')
    for path, proof in value['inputs'].items():
        c.need(proof['mode'] in (0o600, 0o644) and c.sha(c.read(Path(path), mode=proof['mode'])) == proof['sha256'], 'fixture_input_drift')
    for record in value['outputs'].values(): c.need(c.sha(a.raw(record['bytesBase64'])) == record['sha256'], 'fixture_output_digest')


def publish(args, value):
    c.need(args.apply, 'explicit_local_publish_required'); validate_stage(value)
    root = args.lab_root / '.lab/dashboard'; c.directory(root)
    receipt = {'stageSHA256': args.stage_sha256, 'activationExecutionId': value['activationExecutionId'],
               'activationPlanSHA256': value['activationPlanSHA256'], 'sourceHelperCommit': c.COMMIT, 'sourceDriverManifestSHA256': a.SOURCE_MANIFEST_SHA,
               'files': {name: record['sha256'] for name, record in value['outputs'].items()}}
    with locked(root):
        validate_stage(value)
        pending, complete = root / 'scale-fixture.pending.json', root / 'scale-fixture.complete.json'
        if pending.exists(): c.need(c.read(pending) == c.encoded(receipt), 'different_fixture_publication_pending')
        else:
            c.need(not complete.exists() and not any((root / name).exists() or (root / name).is_symlink() for name in DESTINATIONS), 'existing_fixture_not_adopted')
            c.put(pending, c.encoded(receipt))
        c.directory(root / 'scale', create=True)
        for name in DESTINATIONS:
            path = root / name; raw = a.raw(value['outputs'][name]['bytesBase64'])
            if path.exists() or path.is_symlink(): c.need(c.read(path, mode=0o644) == raw, 'existing_fixture_bytes_changed')
            else: c.put(path, raw, mode=0o644)
        c.retain(complete, c.encoded(receipt))
    c.retain(args.staging / 'publish.complete.json', c.encoded(receipt))
    return {'published': True, 'fixtureSHA256': receipt['files']['scale-fixture.json'], 'accounts': 25, 'sources': 2, 'guestChanges': False}


def execute(args):
    c.need(args.lab_root.is_absolute() and args.lab_root.resolve() == args.lab_root, 'lab_root_alias')
    c.need(args.staging.is_absolute() and args.staging.parent.resolve() == args.staging.parent, 'fixture_staging_path')
    c.need(not args.staging.is_relative_to(args.lab_root / '.lab/dashboard'), 'fixture_staging_output_overlap')
    if args.phase == 'prepare': c.directory(args.staging, create=True)
    c.directory(args.staging)
    with locked(args.staging):
        if args.phase == 'prepare':
            c.need(not (args.staging / 'stage.json').exists(), 'fixture_stage_already_exists')
            value = assemble(args); c.put(args.staging / 'stage.json', c.encoded(value))
            return {'stageSHA256': c.sha(c.encoded(value)), 'accounts': 25, 'sources': 2, 'guestChanges': False, 'published': False}
        c.need(args.phase == 'publish' and c.HEX.fullmatch(args.stage_sha256 or ''), 'reviewed_fixture_stage_required')
        raw = c.read(args.staging / 'stage.json'); c.need(c.sha(raw) == args.stage_sha256, 'fixture_stage_digest')
        return publish(args, c.decode(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=('prepare', 'publish'), required=True)
    for key in ('lab-root', 'staging', 'identity-staging', 'identity-handoff', 'primary-handoff', 'secondary-handoff', 'activation-staging', 'primary-ca', 'secondary-ca'):
        parser.add_argument('--' + key, type=Path, required=key in ('lab-root', 'staging'))
    for key in ('activation-plan-sha256', 'activation-implementation-sha256', 'stage-sha256'): parser.add_argument('--' + key)
    parser.add_argument('--apply', action='store_true')
    try: print(c.encoded(execute(parser.parse_args())).decode(), end='')
    except Exception as error:
        code = getattr(error, 'code', 'fixture_preparation_failed')
        raise SystemExit('Scale fixture failed (' + code + '); preserve staging and partial publication receipts.') from None


if __name__ == '__main__': main()
