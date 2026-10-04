# Activate synthetic scale directory and monitoring scopes

This reviewed, explicit workflow connects the separately prepared scale metadata
to the existing two-source Dashboard. It preserves source binaries, instance IDs,
recovery epoch1, schema21, keys, original namespaces, existing users and stored
notification/device bindings. The Dashboard schema remains18. It changes only
ordinary directory mappings/state, three matching Control service registrations
per source, matching broker caller scopes, and API/worker/broker configuration
revision7 to8. The dedicated read-only operator configuration stays unchanged.

The helper does not seed data, create identities, upgrade LDAP helpers, execute
workloads, migrate databases, reset feeds, issue SQL grants, restore databases,
rotate keys, or configure Apple delivery. Its SQL is fixed, read-only and bounded.
Synthetic imported history and admitted jobs are not evidence of execution.
Performance and isolation acceptance follow separately after activation.

## Prerequisites and review boundary

Finish any restore, deployment, directory or workload operation first. Coordinate
an exclusive runtime configuration window. The reviewed source seeder must have
completed and verified both source profiles; the two running synthetic LDAP
services must already use helper367006818e72315b01860f56f971004e17c24886 with the
32-identity bounds. See [source preparation](DASHBOARD_SCALE_SOURCE.md) and
[directory helper upgrade](DASHBOARD_SCALE_DIRECTORY.md).

This activation pins source-driver manifest
`08bda5657bf052db70cfce15185f51d57d58fe37f13fe45189416f79a7a2bb23` and its three-script
implementation digest
`c788ff6f7f1301de573887092aaa578d24853088bfe643bbbe01d4ab56dad2bc`.
Each private source handoff contains `seed.json`, `directory.after.json`,
`directory-state.after.json`, `receipt.json` and `driver-receipt.json`; its parent
contains the exact `preflight.json` and `verify.complete.json`. Host and guest
checks bind these receipts, immutable output hashes, exact source instance,
helper binary and input. Unverified drafts cannot authorize activation.

Keep the following six implementation scripts together in a private, reviewed
archive; the digest covers their exact bytes:

- `dashboard-scale-activation.py`
- `dashboard-scale-activation-common.py`
- `dashboard-scale-activation-guest.py`
- `dashboard-scale-plan.py`
- `dashboard-scale-source-common.py`
- `dashboard-multisource-runtime.py`

Also retain the offline test and this runbook with the review manifest. Every
invocation supplies `--lab-root`; execution from an archive does not infer the
Lab directory from the script path. Only the existing pinned SSH inventory and
known-hosts file are used. Tokens, private file bytes and SQL errors are never
printed. Staging and guest receipts remain mode0700 directories with mode0600
files. Private configuration snapshots contain secret file paths, so do not
publish the staging tree.

## Snapshot and concrete plan

Run `--phase digest` against the archived implementation to obtain
`implementationSHA256`. Choose a fresh absolute private staging directory and the
exact reviewed running Dashboard revision. This can be the corrected RC2 build;
the old immutable b8 release is retained. The inactive recovery configuration may
retain only that exact b8 static-root path while API `webRoot` points at RC2; all
other authority and configuration fields must match.

```sh
python3 /absolute/reviewed/dashboard-scale-activation.py \
  --phase digest --lab-root /absolute/jobman-lab

python3 /absolute/reviewed/dashboard-scale-activation.py \
  --phase snapshot --lab-root /absolute/jobman-lab \
  --staging /absolute/private/scale-activation \
  --implementation-sha256 REVIEWED_IMPLEMENTATION_SHA256 \
  --candidate-revision EXACT_RUNNING_DASHBOARD_COMMIT \
  --primary-handoff /absolute/private/primary/handoff \
  --secondary-handoff /absolute/private/secondary/handoff
```

Snapshot is read-only on guests. It requires both source feeds active on their
original two namespaces, no open recovery/gap, delivery unheld, current schema
and source registry, matching API/worker/broker revision7 readiness, pinned
processes, unchanged original Control/Keycloak and independently upgraded LDAP
processes. It captures configured material hashes, original direct-grant
projections and the current device-binding digest. Ordinary feed generation and
position may advance; they may not decrease. No credentials are generated.

Independently review the resulting private `plan.json`, snapshot, source
handoffs and emitted plan digest. The planner reconstructs the exact additive
25-identity/direct-viewer transform and the previously reviewed namespace-scope
patch. It rejects other directory changes, removed scopes, source/key changes,
legacy caller changes, and a different privileged database URL file. The new
root-private recovery configuration uses the worker Control identities with the
existing privileged DSN at `/etc/jobman-dashboard-app-lab/database-url`; it does
not reuse a restricted runtime or read-only operator DB role.

## Ordered application

Every effect requires `--apply` and the same reviewed implementation and plan
SHA-256. The common arguments below are repeated explicitly; substitute only
reviewed paths/digests. Establish the hold within15minutes of the snapshot.

```sh
python3 /absolute/reviewed/dashboard-scale-activation.py \
  --phase hold --apply --lab-root /absolute/jobman-lab \
  --staging /absolute/private/scale-activation \
  --implementation-sha256 REVIEWED_IMPLEMENTATION_SHA256 \
  --plan-sha256 REVIEWED_PLAN_SHA256
```

Run the same command with each following phase, in this order:

1. `stop-worker`
2. `directory-primary`
3. `directory-secondary`
4. `trust-primary`
5. `trust-secondary`
6. `runtime-storage`
7. `runtime-broker`
8. `restart-broker`
9. `restart-api`
10. `restart-worker`

The ordinary hold advances its generation without changing the restore cutoff.
It remains held until the separate resume phase. Directory phases replace only
exact original bytes, retain backups, and restart only the corresponding isolated
Control so normal `ConfigureDirectory` and LDAPS reconciliation take effect.
LDAP processes, source binaries, original Control and Keycloak are not restarted.

Before any trust expansion, fresh source proofs must show all27 enabled accounts,
12 primary or7 secondary managed namespaces, exact canonical aliases, and all
25 scale accounts with only the viewer role in the10 or5 new namespaces. Their
other grants must be empty, and original namespace grants must match the
snapshot. Both mappings and proof freshness are checked again before subsequent
runtime/recovery phases. The bounded wait is50seconds; a failure leaves the hold
and receipts intact for inspection rather than bypassing reconciliation.

Trust phases extend only the matched API, worker and broker service entries,
preserving operations, keys and historical registrations. Runtime phases install
only the reviewed revision8 drafts, validate them as the respective service
identities, and create `/etc/jobman-dashboard-operator-lab/scale-recovery.json`
without modifying the previous recovery configuration. Restarts verify process
identity, private readiness endpoints and revision8 metrics within a bounded
wait. Worker ingestion then opens the normal scope-change gap on each feed.

## Explicit recovery and coverage review

For each profile, use the same common arguments plus `--profile primary` or
`--profile secondary` and `--apply`:

1. `--phase recovery-plan` records the actual scope gap and immutable retained
   replay plan. It requires only additions and the exact source/revision8 scope.
2. `--phase recovery-step` advances at most50 pages. Repeat explicitly until the
   returned state is `ready`. This wrapper caps each step at the remaining budget through500 total pages; inspect
   unexpectedly larger work rather than increasing limits or resetting a feed.
3. `--phase recovery-reconcile` records current-state coverage and prints its
   `coverageSHA256`. This scan does not prove complete historical delivery.

Review the private coverage file. It contains the ready recovery revision, exact
namespace list and each namespace's complete/partial/unavailable/inaccessible
state. Apply the separately reviewed coverage digest:

```sh
python3 /absolute/reviewed/dashboard-scale-activation.py \
  --phase recovery-apply --profile primary --apply --acknowledge-gap \
  --coverage-sha256 REVIEWED_PRIMARY_COVERAGE_SHA256 \
  --lab-root /absolute/jobman-lab --staging /absolute/private/scale-activation \
  --implementation-sha256 REVIEWED_IMPLEMENTATION_SHA256 \
  --plan-sha256 REVIEWED_PLAN_SHA256
```

Use `--allow-incomplete` only after explicitly reviewing incomplete coverage. The
underlying operator command independently performs fresh reconciliation and
source checks at apply; the earlier coverage is an approval record, not reusable
authorization. Repeat for the secondary profile. The workflow never uses
`--dashboard-restored`, suppress-all policy, or a new restore cutoff for this
ordinary scope expansion.

After both recoveries are applied and both feeds are active on the exact expanded
scopes with no open recovery/gap, separately run `--phase resume --apply` with
the common arguments. It checks the held generation, current source identity and
coverage boundary before normal delivery resumes. Then run `--phase verify`
without `--apply`. Verification confirms current mappings/trust, exact processes,
revision8 readiness, the exact resumed unheld generation/cutoff before and after
readiness checks, unchanged protected material and preserved original services.

## Interruption and retained evidence

Host and guest locks serialize one staging operation. Each mutation has a
matching immutable pending receipt before the effect, and exact after-bytes or
process evidence before completion. Repeating the same explicit phase may verify
an already completed effect or finish an exactly bound interrupted effect. It
never regenerates keys, overwrites changed configuration, silently repeats an
unexplained restart or converts a prior completed restart into permission for a
new process. A changed baseline, missing receipt or unrelated restart fails
closed. Preserve all receipts, backups, original source output and the hold.

A lost `recovery-plan` reply is intentionally not guessed from a current feed.
The recorded command intent requires inspection and a separately reviewed
continuation. Similarly, a process that remains stopped/unready after its
recorded start intent requires diagnosis; the helper does not issue repeated
unrecorded restarts. There is no automatic rollback or resume. Forward directory
revisions and recovery history must not be undone by restoring old JSON files.

The source seeds are synthetic data, and this document makes no live activation
or performance claim. After the final verification, run the separately reviewed
real-authentication scale/mixed-load harnesses, original Alice/Bob isolation,
source-qualified aggregate/partial-state checks and notification acceptance.

## Offline regression checks

```sh
python3 scripts/test-dashboard-scale-activation.py
python3 scripts/test-dashboard-scale-plan.py
```

These tests use only disposable local files and mocks. They never read Lab
credentials, invoke SSH, access a guest/database, or install configuration. They
cover additive identity/scope preservation, reviewed source receipt bindings,
current viewer authority, exact process-restart receipts, before/after CAS,
restrictive umask handling, monotonic feed versions, recovery coverage revision
and unavailable-state semantics, and the separate phase/resume boundaries.
