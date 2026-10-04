# Two-Control binary-only query upgrade

This procedure is scoped to the two isolated Dashboard Lab Controls. It replaces
only one selected source unit's `ExecStart` binary path per reviewed operation.
It does not upgrade the original Lab Control service, migrate either database,
change a source helper pin, change Dashboard configuration, or alter keys, source
identity/epoch, directory grants, event cursors or delivery hold.

The reviewed input is Control `04bd83db28bc24155c87e0ceea61c047320fca07`, containing
summary/list query improvements over deployed
`d332a2b569333ae8aed9c2fc9ebc648d8eb5ba4e`. Both commits have the same 21 migration
files and checksums. The Linux arm64 application was built twice identically with
Go 1.26.6; the approved artifact is
`7faac82263dfa281d2fec7c3e8a52a55a121294e39e7e2d1706115751d4a2123`.
The original binary hash is
`38d5d71cadfbde8147d95ca89aa65a5c8783d983c0b5011055d9b08a0e927e7e`.
Check exact-head CI and independent source review before using this procedure.
No live upgrade outcome is implied by offline tests.

## Preconditions and preservation

Run after any current fault/notification operation has finished and been closed.
No concurrent source submissions, cancellations, directory changes, configuration
changes, recovery actions or guest deployments are allowed during snapshot and
upgrade. Root coordinates all live calls. Notification acceptance remains an
independent release gate; it does not block this query-only, same-schema upgrade.
Preserve all previous failed/passing notification evidence. The existing notification
scenario wrapper pins the old source executable through `SOURCE_SHA`, so its
prepare/complete actions will refuse the upgraded source until a separate reviewed
pin/compatibility update. The upgrade preserves the installed helper and changes no
event or authentication contract. Do not weaken that guard or infer notification
acceptance from a successful binary replacement.

The fixed profiles are:

| Profile | Unit on control01 | UID | Database on pg01 | Namespaces |
| --- | --- | --- | --- | --- |
| primary | jobman-dashboard-lab-control | 21902 | jobman_dashboard_control | 12 |
| secondary | jobman-dashboard-lab-control-secondary | 21907 | jobman_dashboard_control_secondary | 7 |

Read-only snapshots pin both source instance IDs and epoch 1, exact schema ledger,
namespace identities, 10/5 scale namespaces with 10,000 imported history rows and
50 accepted jobs each, and bounded hashes/counts of original job, run, execution
and terminal-event identities. Imported history remains explicitly imported; no
workload execution is inferred. Identity/grant/delegation rows are bounded and
hashed, excluding naturally refreshed directory verification timestamps. Actual
SQL uses a read-only repeatable-read transaction, 15-second statement limit and
500-millisecond lock limit. Secrets and raw records are not printed or persisted.

Pin all Dashboard API/worker/broker and unrelated source/directory processes,
configuration/key bytes, service unit hashes, UID, boot/start/PID, Dashboard schema,
roles and delivery hold. Ordinary Dashboard feed generation/position and source
feed-head advancement are permitted monotonically; other data/authority changes
stop the operation. There is no event replay, migration, hold edit or cursor reset.
The existing synthetic source helper remains byte-identical.

Snapshot/prepare make no guest changes. Every mutating phase requires the reviewed
plan/implementation hashes and `--apply`, within one hour of preparation. Source
configuration still has migration-on-start disabled and directory enforcement
unchanged. Both services must use their existing 90-second stop limit and
`KillMode=control-group`, with no drop-ins. Root-owned private receipt directories
and local/guest exclusive locks serialize the two source upgrades.

## Reviewed phases

Archive these five files plus the three unchanged dependency-fault driver modules
listed in `implementationSHA256`. Always execute from that immutable archive.
The planner verifies both committed migration trees; it does not read or adopt
uncommitted Control files. The build directory must contain the exact
`build-receipt.json`, `jobman-control-1` and `jobman-control-2` outputs from the
reviewed double build.

```sh
python3 scripts/test-dashboard-control-upgrade.py
python3 scripts/upgrade-dashboard-controls.py snapshot \
  --lab-root /absolute/jobman-lab --profile primary \
  --dashboard-revision EXACT_RUNNING_DASHBOARD_COMMIT \
  --output /absolute/new-private-primary-snapshot.json
python3 scripts/upgrade-dashboard-controls.py prepare \
  --lab-root /absolute/jobman-lab --profile primary \
  --snapshot /absolute/new-private-primary-snapshot.json \
  --staging /absolute/new-primary-plan \
  --build /absolute/reviewed-double-build \
  --control-root /absolute/jobman-control \
  --go /absolute/pinned-go1.26.6/bin/go
```

Root reviews the exact generated plan and unit delta before any stage. Run each
following command separately with the same reviewed plan and implementation hashes;
inspect its receipt before proceeding to the next phase:

```sh
python3 scripts/upgrade-dashboard-controls.py stage --apply \
  --lab-root /absolute/jobman-lab --staging /absolute/new-primary-plan \
  --expected-plan-sha256 REVIEWED_PLAN_SHA256 \
  --expected-implementation-sha256 REVIEWED_IMPLEMENTATION_SHA256
# Repeat the command with phase apply, then restart (both require --apply).
# Finally use phase verify without --apply.
```

`stage` validates preserved authority before storing the full immutable candidate
under `/usr/local/libexec/jobman-dashboard-control-upgrades/<sha256>/jobman-control`.
The binary is root-owned 0755; its ancestors cannot be writable by the service.
New directories/files receive explicit modes. Existing candidate trees are
validation-only; partial trees are never repaired or adopted silently. Verify the
binary checksum, architecture, linked version/commit and unprivileged `--version`.
Keep the original executable for evidence; it is never overwritten or removed.

`apply` requires the exact prior unit bytes and immutable staged receipt. Persist a
private original-unit backup and intent, replace only the single reviewed
`ExecStart` path via atomic rename and directory fsync, and reload systemd once.
Verify the loaded command, unchanged old running process, source configuration and
all unrelated processes. No environment file, directory/helper file or secret is
rewritten.

`restart` admits one bounded `systemctl restart --no-block` request after durable
intent. The original stop policy is preserved. Await the exact new process and
positive TLS source capabilities within 120 seconds, preserving all source IDs and
epochs. Intermediate Type=simple process images are not accepted. Use the same
validated process observation in the completion receipt, with no unverified later
PID read. Ordinary source unavailability during that restart is expected; authority
checks must recover before success. No automatic second restart or rollback occurs.

`verify` repeats exact application/process/source, database and unrelated-host
proofs and writes final receipts. Only a fully verified first operation permits the
next source. Then capture a **new** secondary snapshot and review a **new** secondary
plan; it pins the already-upgraded primary process and all current authority.
Never reuse the primary snapshot or expect the primary to remain at the old binary.

## Uncertain replies and failures

Any unexpected failure stops the sequence. Keep host and guest intents, old unit
backup, candidate files, original binaries and test logs. Never change a plan,
create replacement operation IDs to bypass pending state, repeat a mutation, or
roll back automatically. A lost stage/apply/restart response has a proof-only path:

```sh
python3 scripts/upgrade-dashboard-controls.py observe \
  --lab-root /absolute/jobman-lab --staging /absolute/existing-plan \
  --expected-plan-sha256 REVIEWED_PLAN_SHA256 \
  --expected-implementation-sha256 REVIEWED_IMPLEMENTATION_SHA256
```

Observation cannot install files, reload systemd, start or restart a service. It
can return only an already-completed stage or currently proven applied/restarted
state. An incomplete install, unapplied unit, missing daemon reload, unconfirmed
restart or drift remains blocked for separate reviewed recovery. No failure is
converted to a successful upgrade by weakening source or identity checks.

After both verified upgrades, run the separately reviewed source/dashboard
functional, two-source aggregate, pagination and scale checks. Those test outcomes
are additional evidence, not supplied by the binary replacement receipts.
