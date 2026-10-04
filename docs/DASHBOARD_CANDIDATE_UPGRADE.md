# Isolated Dashboard candidate upgrades

This narrowly scoped operator tool upgrades the synthetic Lab's existing split
runtime from `b8f25afdd90f83b4602f32440a89e74dfa866b6c` to
`42d153b4672aeb5cdb2d7395f052b8c6a095f5e1` (`v0.1.0-rc.2`). Preparing or testing the
tool does not authorize a live phase. Obtain the coordinator's independent review
of the exact implementation manifest and prepared plan, and wait for the restore
freeze and other synthetic workload tests to finish before taking a live snapshot.
No release publication, production deployment, schema migration, source restart,
feed recovery, or identity-policy change is part of this operation.

## RC7 transition after completed RC6 acceptance

The fixed `rc6-to-rc7` profile uses the exact hosted artifact from passing
candidate CI37229091125. All58 archive files,57 internal checksums, both executable
hashes, bundled docs and the18-migration ledger were verified against committed
source. Missing pins still refuse before reading Lab inputs or calling a guest.
There is no arbitrary-hash/version CLI override.

| Input | SHA256 |
| --- | --- |
| `jobman-dashboard_v0.1.0-rc.7_linux_arm64.tar.gz` | `19b3ded0315e4781f07f3885fdca360371c0ac0d28f19abf9a6c53d0ad7e9956` |
| `bin/jobman-dashboard` | `24ce928be7a9bf0cc69f650039b5faf7af3a814fd5707ba06395760980c116c0` |
| `bin/jobman-log-broker` | `ec6f819c33592bcff4e22d39aef428c7ff03f7f63204b158e9f559ab26eec35c` |

The exact transition is `633b5e3fdc08cc973e9f318faefccc298c713295` to
`d10fb5f813efa3599a0bc5f79b3ca88826210510` (`v0.1.0-rc.7`). The predecessor hashes
are the reviewed RC6 Dashboard `55439501efe320524e0216947cb30f6bfc2764fa73e9fdc0fdb6b766e2c482e7`
and broker `1457a7b9159285e4054d9ef8b850bc377f99e225eec1bccac0a2fda7d05bdbf8`.
The source delta is foreground/interval refresh for web Reports, Alerts and
Inbox, plus acceptance documentation and curated runbooks. Go/native source and
all18 migrations are unchanged; binaries still receive the new build revision,
so their hashes must come from the actual RC7 artifact, never be inferred.

This profile reuses the RC6 preservation and
bounded phase machinery below: configuration8/schema18, two independent
Control636 instances with bounded run catalog, original epoch1/scopes12+7,
released hold with exact current generation/cutoff, rotated API key and all
three recovery drafts. Only the three units' release paths (including
ExecStartPre/ExecStart and API/worker WorkingDirectory) and API webRoot change.
Take a fresh snapshot of the actual current process identities; successful RC6
acceptance is not a substitute for current preflight/CAS.

Use `--transition rc6-to-rc7` on every command after independent source and
concrete-plan review. Separate
`operation-rc6-to-rc7` guest and `.candidate-upgrade.rc6-to-rc7.operation.json`
host receipts use the existing shared locks and retain all legacy operation
markers. No migrations, Control restart, scope/key/hold changes, automatic retry,
rollback, publication or production action is added. All earlier profiles and
the omitted-option default retain their existing behavior.

## RC6 transition after authentication rotation

The candidate source is frozen at `633b5e3fdc08cc973e9f318faefccc298c713295`.
The exact hosted Linux package was independently verified against the GitHub
artifact digest, all 55 archive files, 54 inner checksums, both executable hashes,
and the committed documentation, deployment files and 18 migration checksums.

The additive `rc3-to-rc6` profile upgrades only the three existing split role
binaries/unit release paths and API static root. It accepts only these fixed
reviewed Linux ARM64 digests:

| Input | SHA256 |
| --- | --- |
| `jobman-dashboard_v0.1.0-rc.6_linux_arm64.tar.gz` | `c705c532b7c6261bc191e7cfa5a92dc7c1e1927368a37207245f38292cb8ad3c` |
| `bin/jobman-dashboard` | `55439501efe320524e0216947cb30f6bfc2764fa73e9fdc0fdb6b766e2c482e7` |
| `bin/jobman-log-broker` | `1457a7b9159285e4054d9ef8b850bc377f99e225eec1bccac0a2fda7d05bdbf8` |

There is no CLI argument for arbitrary revisions, artifact digests, role
identities or paths. Missing or malformed pins fail before snapshot or guest
access. Source and artifact verification alone do not establish live acceptance.

The fixed predecessor is `9b1c65e31db8a849ebe2dfa00caf4474bef8e7d2`, including both
recorded RC3 executable hashes. Configuration 8/schema 18, original source instance
IDs, epoch 1, exactly 12/7 namespaces and active feeds without unresolved gaps or
recoveries remain required. Both Controls must now advertise the actual
`bounded-run-catalog` contract. Their separate reviewed binary upgrades happen
before taking this candidate snapshot; this driver never restarts Control.

Snapshot the current released delivery hold, including its generation and restore
cutoff; do not substitute the old scale-activation generation 5. A held baseline
is refused. Every following phase requires exact hold/cutoff continuity, while
normal feed generation/position may only advance. Source scope, role policy,
database identity and every migration checksum remain fixed. No DDL, role change,
rebind, replay, hold/resume operation, quota change or automatic rollback occurs.

The active API must use authentication key ID `lab-auth-rotation-v1` at the exact
role-owned `authentication-rotation-v1.key`, with its 32-byte digest proof. Preserve
all three root-owned recovery drafts byte-for-byte: original multisource, scale,
and `/etc/jobman-dashboard-auth-rotation-lab/recovery.json`. The rotation directory
must remain root-owned 0700 and the draft 0600; its authentication reference and
material proof must equal the active API's rotated key. Old drafts remain
historical evidence and are never overwritten, rekeyed or run. Their retained
old static paths are permitted exactly as captured. All dedicated purpose keys,
source certificates/signers, database material, report objects, sessions and
existing browse records remain untouched.

Use a new private staging directory and a fresh snapshot after all outstanding
operations close. Pass `--transition rc3-to-rc6` on every command. Its separately
named host/guest operation receipts use the same existing global locks, so the
older RC2/RC3 receipts and backups cannot be replaced or replayed. Preserve all
pending evidence on failure; a lost reply permits only the existing bounded
observation path, never a repeated mutation. Ordinary service restart creates
its own RuntimeDirectory before the new active-process/config/readiness checks;
this driver does not manually stop roles or recreate missing runtime paths.

Use the same snapshot, prepare and explicit phased commands below with
`--transition rc3-to-rc6` and the exact RC6 archive. The independently reviewed
implementation and fresh prepared plan must match every phase. No live result
is implied by these offline checks. The candidate remains an engineering prerelease: source/protocol checks do not prove final
upstream tag publication, corporate AD FS, APNs or managed-iPhone acceptance.

## RC3 transition after scale activation

Use explicit `--transition rc2-to-rc3` on **every** command for the approved
`42d153b4672aeb5cdb2d7395f052b8c6a095f5e1` →
`9b1c65e31db8a849ebe2dfa00caf4474bef8e7d2` transition (`v0.1.0-rc.3`).
Omitting the option retains the original `rc1-to-rc2` default described below;
that default cannot operate against configuration8. Both transitions are fixed
allowlisted profiles; the CLI accepts no arbitrary revision or release path.

RC3 requires the completed scale activation: configuration8, identical schema18
ledger in both exact commits, both original source instances at epoch1, exactly
12 primary and7 secondary namespaces with equal configuration/feed sets, active
feeds with no open gaps/recoveries, and delivery hold=false/generation5 with no
restore cutoff. Take the fresh snapshot only after scale resume and verification.
The same requirements fence every subsequent read-only database check.

The approved arm64 archive is
`179af3e6a60002fe3dcd630867e0911971461493b9aea291263d894a3fdaf705`;
Dashboard binary SHA256 is
`e03612c5ab0384e8bac2150ae498fb4e0b6076c7644ec1120d3ae9f0572bf411`,
and broker SHA256 is
`18d77e81fa41662bfd6003a8722f4da2b76afc4e11de164417fa529bb5e0a096`.
The planner validates all three pins and every internal archive checksum.
Only the three unit release paths and API webRoot change to the9b release.
Worker/broker config bytes, configuration8, keys, source registration and all
19 namespace bindings remain unchanged. Both privileged recovery configurations
(`multisource-recovery.json` and `scale-recovery.json`) plus the read-only operator
configuration and their referenced material hashes remain unchanged. The active
scale recovery config may retain its prior RC2 webRoot; this upgrade does not run
recovery commands or alter that file.

Example offline preparation, after an explicitly authorized read-only snapshot:

```sh
python3 /absolute/archive/scripts/upgrade-dashboard-candidate.py snapshot \
  --transition rc2-to-rc3 --lab-root /Users/rcw/home/code/jobman-lab \
  --snapshot /absolute/private/rc3-snapshot.json
python3 /absolute/archive/scripts/upgrade-dashboard-candidate.py prepare \
  --transition rc2-to-rc3 --snapshot /absolute/private/rc3-snapshot.json \
  --candidate /absolute/private/jobman-dashboard_v0.1.0-rc.3_linux_arm64.tar.gz \
  --dashboard-root /Users/rcw/home/code/jobman-dashboard \
  --staging /absolute/private/rc3-prepared
```

The phases and bounded interrupted-operation handling below are unchanged; pass
`--transition rc2-to-rc3` along with all normal plan/implementation arguments.
Readiness must show revision8. RC3 uses separately named operation markers under
the **same global locks**, preserving completed RC2 markers and backups. Marker
selection is part of the selected profile and hashed plan; a second RC3 plan
cannot overwrite the first. Old-profile retries fail the exact release, revision,
scope and hold fences. Nothing removes prior operation evidence or automatically
rolls back. Preparation, unit tests and artifact checks are not live acceptance.

## Original RC2 change (default profile)

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
and all candidate file hashes/modes. An offline fixture is never a live plan.
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
   the profile’s captured configuration revision metrics must all pass. A shared deadline bounds startup checks.
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
