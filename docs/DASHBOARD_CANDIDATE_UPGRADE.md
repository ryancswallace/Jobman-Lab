# Isolated Dashboard RC2 candidate upgrade

This narrowly scoped operator tool upgrades the synthetic Lab's existing split
runtime from `b8f25afdd90f83b4602f32440a89e74dfa866b6c` to
`42d153b4672aeb5cdb2d7395f052b8c6a095f5e1` (`v0.1.0-rc.2`). Preparing or testing the
tool does not authorize a live phase. Obtain the coordinator's independent review
of the exact implementation manifest and prepared plan, and wait for the restore
freeze and other synthetic workload tests to finish before taking a live snapshot.
No release publication, production deployment, schema migration, source restart,
feed recovery, or identity-policy change is part of this operation.

## Exact change

The reviewed Linux ARM64 archive SHA256 is
`1634cb3c44e9ca1b9321a42783be22fe7254cca8d0c235371de19db593dec85a`.
The full archive, including both binaries, web assets, examples, grants, and
runbooks, is installed on `storage01` and `control01` under a fresh immutable
`/opt/jobman-dashboard-lab/releases/42d153b4672aeb5cdb2d7395f052b8c6a095f5e1`.
The existing b8 release remains available unchanged.

| Role | Guest | UID | Unit | Changed release sites |
| --- | --- | --- | --- | --- |
| API | storage01 | 21904 | jobman-dashboard-lab-api | WorkingDirectory, ExecStartPre, ExecStart |
| Worker | storage01 | 21905 | jobman-dashboard-lab-worker | WorkingDirectory, ExecStartPre, ExecStart |
| Broker | control01 | 21901 | jobman-dashboard-lab-broker | ExecStartPre, ExecStart |

The unit transformer requires exactly those original commands, users, groups,
90-second stop limits, and release-prefix counts. It replaces only the old
release prefix. Effective systemd policy must have no drop-ins and must use
`KillMode=control-group`.

The only JSON configuration change is API `webRoot` from the old release's `/web`
to the new release's `/web`. The API JSON may be reserialized canonically; every
other value is compared structurally. Worker and broker configuration bytes stay
identical. All three retain configuration revision **7**. Keys, credential files,
Control instances, epochs, namespaces, log mappings and broker allowlists remain
unchanged. The inactive privileged `multisource-recovery.json` and read-only
operator configuration remain byte-identical, including the recovery
configuration's deliberately retained b8 static-root path. Later recovery/scale
planning must account for that exact static-path difference explicitly. Only the
recovery configuration may retain `databaseURLFile` pointing at the exact legacy
`/etc/jobman-dashboard-app-lab/database-url`, verified as UID/GID21903 and0600.
No neighboring legacy file or alternate use of that path is permitted.

## Schema and authority proof

Offline preparation reads only the two exact Git commits. Their 18 migration
filenames and SHA256s must match each other and the captured database ledger;
`migrations/000018_runtime_lock_privileges.sql` remains the final ledger name.
Ledger names use the complete `migrations/...` paths emitted by the Go embedded
filesystem; the separate archive grants manifest uses the migration basename. The archive
validator checks its schema18 grants manifest, every internal checksum, Linux
ARM64 executable headers, bounded paths, entry count and expanded size.

Before configuration changes on storage01, the actual new binary runs
`status --operator-config /etc/jobman-dashboard-operator-lab/config.json`. This
command opens the existing read-only operator DSN and calls `CheckSchema` against
the new binary's embedded migrations before reading bounded status. `check-config`
alone is not considered schema compatibility evidence. No `migrate` or grants
command is invoked.

A fixed read-only, repeatable-read PostgreSQL query on pg01 records and rechecks:

- Database OID and all migration checksums.
- Both source instance IDs, recovery epochs, explicit namespaces, configuration
  revisions, active feed generations/positions and absence of unfinished gaps/recoveries.
- Delivery hold, hold generation and restore suppression cutoff.
- The primary roles' attributes, memberships and database/schema/table/column/
  function/default privilege metadata, represented by a digest.

Normal event cursor, lease, count and last-success progress is allowed. Feed
generation and last position must each be at least their captured baseline;
ordinary polling advances generation. Nothing resets or overwrites these values.
A regression or a changed hold, source epoch/scope, role policy or schema stops
the operation. The driver does not issue
SQL that mutates the database. It captures private material **hashes and ownership
metadata only**, never copies or prints private key/DSN values. Configuration
snapshots, plans and receipts are operator-only files because configurations can
still contain private infrastructure metadata.

## Offline preparation and review

Archive these implementation files together, preserving their exact bytes:

- `dashboard-candidate-plan.py`
- `dashboard-candidate-guest.py`
- `upgrade-dashboard-candidate.py`
- Existing read-only dependencies `dashboard-split-plan.py` and
  `dashboard-multisource-runtime.py`

The implementation manifest binds all five files. Also archive this runbook and
`test-dashboard-candidate.py`. Use an explicit original `--lab-root` even when
running an archived driver; it supplies the existing pinned SSH inventory and
known-hosts file. The tool never discovers or accepts a new host key.

Run the offline suite without loading Lab credentials:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-dashboard-candidate.py
```

After independent source review and explicit coordination release, take one
read-only snapshot to a new private path. This command reads guests; it must not
be run during the restore freeze merely to prepare the code.

```sh
python3 /absolute/archive/scripts/upgrade-dashboard-candidate.py snapshot \
  --lab-root /Users/rcw/home/code/jobman-lab \
  --snapshot /absolute/private/candidate-snapshot.json
```

Then prepare entirely offline. The staging directory must not already exist:

```sh
python3 /absolute/archive/scripts/upgrade-dashboard-candidate.py prepare \
  --snapshot /absolute/private/candidate-snapshot.json \
  --candidate /absolute/private/jobman-dashboard_v0.1.0-rc.2_linux_arm64.tar.gz \
  --dashboard-root /Users/rcw/home/code/jobman-dashboard \
  --staging /absolute/private/candidate-prepared
```

Review `plan.json`, its exact SHA256, the implementation SHA256, and `review.json`.
The plan contains each old/new unit and configuration digest, captured process
PID/start/boot identity, material ownership/digests, schema ledger, source proof,
and all 52 candidate file hashes/modes. An offline fixture is never a live plan.
No configuration or service changes happen during snapshot or preparation.

## Explicit phases

Every command below requires the same `--lab-root`, `--staging`,
`--expected-plan-sha256` and `--expected-implementation-sha256`. The driver checks
all of them before remote work. Only a coordinator-reviewed plan may be used.
Invoke one phase/host or phase/role at a time, inspect the result, and stop on an
unexpected failure. Do not batch a blind retry loop.

1. `preflight --host pg01`, then `control01`, then `storage01` (no `--apply`).
   All three record fresh read-only proof; candidate release paths must be absent.
   The original snapshot must be at most one hour old. Re-reading a preflight does
   not extend its original expiry.
2. `stage --host control01 --apply`, then `storage01`. Both immutable full releases
   must be staged before either host's active files may change. New files are
   created exclusively with explicit modes regardless of umask; existing trees
   are never repaired or adopted. Expanded disk headroom is checked first.
3. `apply --host control01 --apply`, then `storage01`. Each file uses exact
   compare-and-swap, a private backup and same-owner temporary file, descriptor
   `fsync`, atomic rename and parent-directory `fsync`. Any partially completed
   apply is preserved for review; it is never automatically rolled back.
4. `restart --role broker --apply`, then `api`, then `worker`. The host performs
   one receipt-bound daemon reload, validates the loaded command paths and then
   requests one bounded service restart. Fresh process identity, exact executable
   bytes, configuration validation, local live/ready endpoints and loaded
   revision7 metrics must all pass. A shared deadline bounds startup checks.
5. `verify --host pg01 --apply`, then `control01`, then `storage01`. Despite the
   explicit phase-authorization flag, pg01 only executes the fixed read-only
   query. Service hosts recheck full immutable candidate inventory, exact active
   config/unit/process identity, original source/key/role/hold proofs and the new
   binary's schema compatibility. Record all three results before claiming the
   upgrade complete.

A global local lock serializes all candidate phases across staging directories.
A global operation receipt prevents different plans from being interleaved. Each
service host also holds a fixed private lock and binds its durable operation
receipt to the same plan and complete implementation manifest. New effects must
begin within one hour of all original preflights. An expired operation requires
review; it does not silently refresh its authority.

## Interrupted operations

Before any remote mutation request, the host writes an exclusive durable pending
receipt. The guest independently writes its intent before touching candidate
files, active files, daemon state or services. A normal invocation encountering a
pending host phase fails without resending that mutation.

After inspecting both sides, an authorized `--observe-only --apply` for the same
phase can prove already completed effects. It cannot extract a partial candidate,
change a file, repeat daemon reload or restart a service. For a lost restart reply,
it requires the original boot identity, a different PID, a strictly later process
start timestamp, the new binary/configuration, and full readiness checks. It then
records proof of the observed effect. If the old process is still running, the
pending phase stays unresolved. No second restart is issued.

A partially applied file set, an incomplete candidate tree, a host reboot,
uncertain effects without proof, or changed authority require a separately
reviewed recovery plan. Preserve all pending markers, backups and old immutable
files. Never remove a marker to manufacture a retry, decrement a revision, reset
an event feed, or switch to an older candidate automatically.

## Evidence limits

Offline tests and a reproducible package prove the helper and artifacts, not a
live upgrade. Keep those results separate from eventual runtime verification and
post-upgrade monitoring/diagnosis/notification acceptance. Simulator iPhone
success does not claim company-managed device distribution, real AD FS or APNs
acceptance; those release gates remain explicit.
