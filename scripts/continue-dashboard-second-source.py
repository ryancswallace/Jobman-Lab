#!/usr/bin/env python3
"""Read-only guest inspection and explicit host continuation of one failed prepare.

Only the known overlength-name failure is eligible. Original pending evidence and
completed database stay untouched; this never retries a guest mutation.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('secondary_driver', HERE / 'apply-dashboard-second-source.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
plan = driver.plan
PRIOR_EXECUTION = 'd87f4b43ba6cb4d503f09e3cf4738795f52550c04623bfeeb8c4bce2f5f93331'
PRIOR_PLAN_SHA256 = 'ae19480a6f6e79bc2fa144b1a383af0087df353ea86ad001a7ffcedde1f2cc2d'


def prior_record(staging):
    info = staging.lstat()
    plan.require(staging.is_absolute() and staging.resolve() == staging and stat.S_ISDIR(info.st_mode) and
                 info.st_uid == driver.os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'Prior private staging required')
    raw = driver.private_read(staging / 'plan.json')
    plan.require(hashlib.sha256(raw).hexdigest() == PRIOR_PLAN_SHA256, 'This continuation only handles the reviewed failed plan')
    receipts = staging / ('apply-' + PRIOR_EXECUTION)
    plan.require(not any((receipts / name).exists() for name in ('prepare.json', 'start.json', 'verify.json')), 'Prior preparation already completed')
    prior = {'priorExecutionId': PRIOR_EXECUTION, 'priorPlanSHA256': PRIOR_PLAN_SHA256,
             'priorPreflight': plan.json_value(driver.private_read(receipts / 'preflight.json')),
             'priorDatabase': plan.json_value(driver.private_read(receipts / 'database.json'))}
    plan.require(set(prior['priorPreflight']) == {'pg01', 'control01'} and
                 prior['priorDatabase']['database'] == 'jobman_dashboard_control_secondary' and
                 prior['priorDatabase']['originalsPreserved'] is True and
                 plan.re.fullmatch('[0-9a-f]{64}', prior['priorDatabase']['hbaSHA256']), 'Prior completed database receipt differs')
    return prior


def prepare(args):
    plan.require(args.prior_staging != args.staging, 'Continuation needs a new staged plan')
    for root in (args.prior_staging, args.staging):
        info = root.lstat()
        plan.require(root.is_absolute() and root.resolve() == root and stat.S_ISDIR(info.st_mode) and
                     info.st_uid == driver.os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'Private real staging required before locking')
    with driver.receipt_lock(args.prior_staging), driver.receipt_lock(args.staging):
        prior = prior_record(args.prior_staging)
        driver.verify_stage(args)
        plan.require(not (args.staging / 'continuation.json').exists(), 'Continuation already recorded; inspect it before proceeding')
        payload, _ = driver.verify_stage(args, continuation=prior)
        secret = driver.password(args.lab_root)
        driver.verify_database(secret, args.lab_root)
        snapshots = {host: driver.remote(host, dict(payload, phase='continuation_preflight'), args.lab_root)
                     for host in ('pg01', 'control01')}
        plan.require(all(abs(value['epoch'] - int(driver.time.time())) <= 10 for value in snapshots.values()), 'Lab clocks differ')
        receipt = args.staging / ('apply-' + payload['executionId'])
        receipt.mkdir(mode=0o700)
        receipt.chmod(0o700)
        driver.save(receipt / 'preflight.json', snapshots)
        driver.save(receipt / 'database.json', prior['priorDatabase'])
        # Completion is recorded last. No guest pending/completion record is
        # removed or copied over; the old execution remains evidence of failure.
        driver.save(args.staging / 'continuation.json', prior)
        return {'executionId': payload['executionId'], 'priorExecutionId': PRIOR_EXECUTION,
                'guestMutations': False, 'databaseReused': True, 'nextPhase': 'prepare'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-root', required=True, type=Path)
    parser.add_argument('--prior-staging', required=True, type=Path)
    parser.add_argument('--staging', required=True, type=Path)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--control-build', required=True, type=Path)
    parser.add_argument('--helper-build', required=True, type=Path)
    parser.add_argument('--helper-revision', required=True)
    print(json.dumps(prepare(parser.parse_args()), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Secondary continuation checks failed; retain all original and new evidence. No guest mutation was attempted.', file=sys.stderr)
        sys.exit(1)
