# Primary restore-watchdog intervention acceptance

This is a separate, opt-in outage exercise. It tests the **actual existing
150-second restore watchdog** by stopping the isolated Dashboard API and worker
once and deliberately omitting the host restart. It creates no clone, dump,
restore, source job, rule, or delivery. The original Control, both isolated
Controls, directories, Keycloak, broker, PostgreSQL, configuration, keys, schema,
feed authority, delivery hold and retained data must remain unchanged.

The normal coordinated restore acceptance already proves an early host restart.
That evidence does not prove timer intervention. This additional exercise is
pending until a reviewed, exact plan and its live receipt pass.

## Code and evidence boundary

The plan binds seven Python implementation files, including the complete,
unchanged `dashboard-restore-guest.py`. The self-contained systemd executable
loads that exact module and substitutes **only** `execution_root`: a strict
watchdog-only operation adapter under
`/var/lib/jobman-dashboard-watchdog-acceptance/<64-hex-operation>`. It calls the
original `arm_backup`, `stop_primary`, `backup_window`, `restart_lock` and
`restart_primary`. The original 150-second timer, 125-second pre-stop reserve,
90-second effective service stop policy, 25-second restart budget, shared lock,
boot checks, private receipts and exact primary process/configuration pins
remain intact. Its original safety receipts keep their names; none are described
as evidence of a backup. No `backup-complete.json` is produced.

Only the exact systemd watchdog service may invoke `restart_primary(fired=True)`.
The executable validates its private file, operation payload, invocation ID and
its own systemd cgroup. The host exposes no restart, recover, restore, resume,
SQL-write, source-mutation or hold action. A completed acceptance requires both
original timer `fired.json` and `disarmed.json`, elapsed time from 150 through
180 seconds, and both expected API/worker PID/start identities advanced. A timer
that starts processes but fails its exact completion checks is an acceptance
failure; later observations never synthesize the missing completion receipt.

The current original restart implementation checks process identity immediately
after its one start command. A transient or unavailable identity can therefore
leave a failed completion even if services subsequently recover. The harness
preserves that evidence and does not retry the restart or relax the receipt.

## Preconditions and fresh preparation

The operator must establish a quiet window with no other live Lab operations.
Snapshot, prepare and stage happen before the harness. Only the root operator
runs guest phases after independent plan review. New snapshots are mandatory:
API authentication-key rotations and later candidate changes invalidate earlier
configuration and process pins.

Use an immutable implementation directory containing the seven Python files
listed by `dashboard-watchdog-plan.py`, the reviewed test and this runbook. Use a
new canonical owner-only `0700` directory beneath `/private/tmp` for all host
receipts. Never use the Lab checkout as the receipt directory. Preserve old
operations and evidence; no automatic cleanup or database restore is available.

```sh
python3 /ABSOLUTE/ARCHIVE/scripts/dashboard-watchdog.py snapshot \
  --lab-root /Users/rcw/home/code/jobman-lab \
  --revision EXACT_INSTALLED_DASHBOARD_COMMIT \
  --binary-sha256 EXACT_INSTALLED_DASHBOARD_SHA256 \
  --output /private/tmp/NEW-PRIVATE-PACKET/snapshot.json
python3 /ABSOLUTE/ARCHIVE/scripts/dashboard-watchdog.py prepare \
  --lab-root /Users/rcw/home/code/jobman-lab \
  --revision EXACT_INSTALLED_DASHBOARD_COMMIT \
  --binary-sha256 EXACT_INSTALLED_DASHBOARD_SHA256 \
  --snapshot /private/tmp/NEW-PRIVATE-PACKET/snapshot.json \
  --staging /private/tmp/NEW-PRIVATE-PACKET/prepared
```

Review the exact plan, implementation hashes and fresh baseline. Snapshots and
begin are limited to a 15-minute age; source identities and all scopes are taken
from both live feeds. The database must have no pending report/evaluation/fanout/
delivery work or enabled notification rule. Another active restore/fault timer
or incomplete host fault operation refuses admission. Existing report objects
are bounded to 10,000 canonical single-link JSON files, 8 MiB each and 256 MiB
combined, with exact shared-owner permissions. Larger installations require a
separately reviewed bound; nothing is silently omitted.

```sh
python3 /ABSOLUTE/ARCHIVE/scripts/dashboard-watchdog.py stage \
  --lab-root /Users/rcw/home/code/jobman-lab \
  --staging /private/tmp/NEW-PRIVATE-PACKET/prepared \
  --expected-plan-sha256 REVIEWED_PLAN_SHA256 \
  --expected-implementation-sha256 REVIEWED_IMPLEMENTATION_SHA256 --apply
```

The staged operation is single-use. A partial stage or uncertain begin is not
replayed. The guest retains its private intent, original timer executable and
all receipts. An uncertain response is followed only by read-only `status` or
operator inspection. A failed acceptance deliberately has no host restart in
cleanup: preserve the independent timer and assess actual state before any
separately reviewed recovery.

## Same-credential HTTP acceptance

The Dashboard integration harness signs in synthetic Alice and Bob before the
stop, saves only public hashes/identities and uses those same bearer credentials
after timer recovery. It creates no additional jobs, reports, rules or inbox
items. Prerequisites are the already accepted current Slurm report receipt and
the original public primary/secondary fixture manifests. Both users must have
an existing inbox item in their respective research namespace.

From an immutable Dashboard source snapshot, build or run exactly
`TestLabRestoreWatchdogIntervention` with a seven-minute test timeout. Set:

- `JOBMAN_DASHBOARD_LAB_RUNTIME=1`
- `JOBMAN_DASHBOARD_LAB_RESTORE_WATCHDOG=1`
- `JOBMAN_DASHBOARD_LAB_ROOT=/Users/rcw/home/code/jobman-lab`
- `JOBMAN_DASHBOARD_LAB_WATCHDOG_DRIVER=/ABSOLUTE/ARCHIVE/scripts/dashboard-watchdog.py`
- `JOBMAN_DASHBOARD_LAB_WATCHDOG_STAGING=/private/tmp/NEW-PRIVATE-PACKET/prepared`
- `JOBMAN_DASHBOARD_LAB_WATCHDOG_PLAN_SHA256` and
  `JOBMAN_DASHBOARD_LAB_WATCHDOG_IMPLEMENTATION_SHA256` from the reviewed packet
- `JOBMAN_DASHBOARD_LAB_WATCHDOG_SLURM_RECEIPT` pointing to the exact accepted
  `929a9e93e83069dc330734b699bd6077432507397e56ec484367c6af954be530` receipt
- `JOBMAN_DASHBOARD_LAB_SECONDARY_FIXTURE` pointing to the retained public
  secondary fixture manifest
- `JOBMAN_DASHBOARD_LAB_WATCHDOG_RESULT=/private/tmp/NEW-PRIVATE-PACKET/prepared/acceptance.json`

```sh
go test -tags integration -race ./internal/auth \
  -run '^TestLabRestoreWatchdogIntervention$' -count=1 -timeout=7m
```

The harness admits exactly one begin, waits for the timer and checks both private
`readyz` sockets. It proves unchanged source-qualified current grants, both
Controls' readable research jobs, exact retained owner inbox items and opposite
owner denial, unchanged accepted run, sealed report/citation, NFS log bytes and
Bob's operations denial. The driver compares all retained event/inbox/delivery/
report IDs, object bytes, schema/roles/hold/source identities and every unrelated
process. Feed generation/position may only advance monotonically. Reports are
read again; none are regenerated. Only sanitized HTTP503 may be retried during a
15-second authorized read recovery window. No sign-in occurs after the outage.

Only after these HTTP checks does `close --apply` write a watchdog acceptance
marker. It cannot start or stop a service. Evidence includes the original timer
receipt and public content hashes, never credentials. This proves bounded
synthetic native-bearer and operator-path recovery, not physical iPhone/APNs,
corporate AD FS, a database restore, or general arbitrary-service recovery.

## Offline validation

```sh
python3 scripts/test-dashboard-watchdog.py
go test -tags integration -race ./internal/auth -run '^TestLabWatchdog' -count=1
```

The Python tests execute the actual hash-bound bootstrap and original watchdog
failure paths with mocked external boundaries. They cover late-stop refusal,
real timer-context requirements, lost-response no-replay, partial completion
without success, changed process/configuration pins, age bounds, quiet SQL and
host phase restrictions. These tests are not live timer timing evidence.

## Staged-only failed attempts

A staged operation that failed during HTTP setup is not a watchdog acceptance.
It continues to block new staging until an independently reviewed, fixed-operation
retirement proves that only its original `plan.json`, `intent.json` and
`staged.json` exist, that no timer is active and that the current services and
retained state remain intact. A failed host stage with no guest directory is
retained as failed evidence; it is never retried to make it appear successful.

The explicit retirement first creates a durable `begin.pending.json` tombstone.
The original archived begin implementation refuses that file, so even an old
operator command cannot arm the retired operation. Only after this fence is
synced does retirement create `aborted.json`, with `accepted:false`, the exact
three original file hashes, the tombstone hash and the reviewed failure/proof
hashes. Original receipts are never overwritten and no `accepted.json` is made.
A lost response or partial retirement remains blocked pending independent
inspection; the host never repeats the mutation automatically.

Future stage accepts only this exact five-file aborted shape, checking every
private original file and receipt. Any arm, stop, timer executable, restart,
acceptance or unknown artifact rejects it. A new operation still needs a fresh
snapshot, new plan and separate stage/begin review; neither retirement nor new
stage changes the original 150-second restore timer or its process checks.
