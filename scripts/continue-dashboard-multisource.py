#!/usr/bin/env python3
"""One reviewed continuation for an inactive recovery draft; inspect by default."""
import argparse
import base64
import importlib.util
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('multisource_host', HERE / 'apply-dashboard-multisource.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
r = h.r


def prepared(args):
    old = h.plan.decode(h.read(args.previous_invocation))
    r.need(old['implementationSHA256'] == h.PRIOR_IMPLEMENTATION and old['labRoot'] == str(args.lab_root), 'continuation_invocation')
    previous_scripts = Path(old['script']).parent
    previous_hashes = {name: r.sha(h.read(previous_scripts / name)) for name in h.FILES if name != 'continue-dashboard-multisource.py'}
    r.need(r.sha(r.encoded(previous_hashes)) == h.PRIOR_IMPLEMENTATION, 'continuation_prior_archive')
    current = argparse.Namespace(lab_root=args.lab_root, staging=Path(old['staging']), secondary_prepare_receipt=Path(old['secondaryPrepareReceipt']), secondary_fixture=Path(old['secondaryFixture']), expected_prepare_sha256=old['prepareSHA256'], expected_review_sha256=old['reviewSHA256'], expected_implementation_sha256=args.expected_implementation_sha256, continue_from_implementation=h.PRIOR_IMPLEMENTATION)
    p, hashes = h.prepared(current)
    receipts = current.staging / ('apply-' + p['executionId'])
    h.private_directory(receipts)
    r.need(h.plan.decode(h.read(receipts / 'implementation.json')) == previous_hashes, 'continuation_prior_receipt')
    p['baseline'] = h.plan.decode(h.read(receipts / 'preflight.json'))
    materials = h.plan.decode(h.read(receipts / 'private-materials.json'))
    p['materialHashes'] = {role: {name: r.sha(base64.b64decode(raw, validate=True)) for name, raw in files.items()} for role, files in materials.items()}
    # No private key bytes are needed for this read/one-draft continuation.
    for role in h.ROLES:
        for suffix in ('apply-' + role + '.json', 'restart-' + role + '.json'):
            r.need(not (receipts / suffix).exists() and not (receipts / suffix).is_symlink(), 'continuation_host_swap_started')
    return current, p, hashes, receipts


def database_check(p, args):
    current = h.remote(args.lab_root, h.phase_payload(p, 'pg01', 'database', False))
    namespaces = {entry['id']: entry['namespaceIds'] for entry in h.plan.decode(base64.b64decode(p['after']['worker']))['controls']}
    h.db_validate(current, namespace_sets=namespaces, now=time.time())
    before = p['baseline']['database']
    r.need(current['hold'] == before['hold'] and current['bindingCount'] == before['bindingCount'] and current['bindingSHA256'] == before['bindingSHA256'], 'continuation_durable_state_changed')
    old, new = before['feeds'][0], current['feeds'][0]
    r.need(old['deploymentId'] == new['deploymentId'] and old['namespaces'] == new['namespaces'] and new['generation'] >= old['generation'] and new['lastPosition'] >= old['lastPosition'], 'continuation_feed_changed')
    return current


def execute(args):
    r.need(args.phase in ('inspect', 'apply') and (args.phase == 'inspect' or args.apply), 'explicit_continuation_apply_required')
    current, p, hashes, receipts = prepared(args)
    with h.locked(current.staging):
        identity = h.continuation_identity(p)
        if args.phase == 'inspect':
            r.need(not (receipts / 'continuation-plan.json').exists(), 'continuation_plan_already_recorded')
            state = {host: h.remote(args.lab_root, h.phase_payload(p, host, 'continuation_check', False)) for host in ('control01', 'storage01')}
            r.need(all(row['identity'] == identity and row['complete'] is False for row in state.values()), 'continuation_guest_binding')
            database = database_check(p, args)
            review = {'identity': identity, 'hosts': state, 'database': database, 'checkedAt': int(time.time()), 'implementation': hashes}
            h.receipt(receipts / 'continuation-plan.json', review)
            return {'phase': 'inspect', 'readOnly': True, 'executionId': p['executionId'], 'continuationSHA256': r.sha(r.encoded(review))}
        raw = h.read(receipts / 'continuation-plan.json'); review = h.plan.decode(raw)
        r.need(args.expected_continuation_sha256 == r.sha(raw) and review['identity'] == identity and review['implementation'] == hashes and 0 <= time.time() - review['checkedAt'] <= 900, 'continuation_review_or_freshness')
        database_check(p, args)
        p['continuationProcesses'] = {host: row['processes'] for host, row in review['hosts'].items()}
        # Persist the precise operator-reviewed transition before either guest write.
        h.receipt(receipts / 'continuation.pending.json', {'identity': identity, 'continuationSHA256': args.expected_continuation_sha256})
        state = {}
        for host in ('control01', 'storage01'):
            state[host] = h.remote(args.lab_root, h.phase_payload(p, host, 'continuation_apply', True))
            r.need(state[host]['identity'] == identity and state[host]['complete'] is True and state[host]['processes'] == p['continuationProcesses'][host], 'continuation_completion_mismatch')
            h.receipt(receipts / ('continuation-' + host + '.json'), state[host])
        completed = receipts / 'continuation.complete.json'
        if completed.exists():
            old = h.plan.decode(h.read(completed)); r.need(old['identity'] == identity and old['hosts'] == state, 'continuation_completed_changed')
        else: h.receipt(completed, {'identity': identity, 'hosts': state, 'completedAt': int(time.time())})
        h.receipt(receipts / 'implementation-current.json', hashes)
        return {'phase': 'apply', 'complete': True, 'executionId': p['executionId'], 'activeConfigurationRevision': 6, 'serviceRestarted': False, 'keysRegenerated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-root', required=True, type=Path)
    parser.add_argument('--previous-invocation', required=True, type=Path)
    parser.add_argument('--expected-implementation-sha256', required=True)
    parser.add_argument('--expected-continuation-sha256')
    parser.add_argument('--phase', choices=('inspect', 'apply'), default='inspect')
    parser.add_argument('--apply', action='store_true')
    print(r.encoded(execute(parser.parse_args())).decode(), end='')

if __name__ == '__main__':
    try: main()
    except r.Failure as error: raise SystemExit('Multi-source continuation stopped: ' + error.code + '. Preserve receipts.') from None
    except Exception: raise SystemExit('Multi-source continuation stopped: host_continuation_failed. Preserve receipts.') from None
