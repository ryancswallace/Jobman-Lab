# Isolated Dashboard backup and restore acceptance

This is a proposed Lab exercise, not a completed restore or a production runbook.
The offline planner and preparer do not connect to guests, read credential files,
stop services, back up data, create roles, restore a database or release a hold.
A separately reviewed execution driver and exact fresh plan are required before
those actions. The original deployment must never be a restore target.

## Fixed isolation and remaining preflight

| Resource | Proposed isolated target |
| --- | --- |
| Host | Existing storage01, no additional VM |
| PostgreSQL | New `jobman_dashboard_restore`, schema `public`, on existing pg01 |
| Owner/recovery login | `jobman_dashboard_restore_ddl`; root-only operator use, never a runtime credential |
| Runtime logins | `jobman_dashboard_restore_api`, `jobman_dashboard_restore_worker` |
| Read-only status login | `jobman_dashboard_restore_operator` |
| API service account | `jobman-dash-restore-api`, UID/GID21909 |
| Worker service account | `jobman-dash-restore-worker`, UID/GID21910 |
| Report reader group | `jobman-dash-restore-readers`, GID21911 |
| HTTPS | `https://dashboard.lab.test:38443`, explicitly dial10.77.0.10:38443 with hostname/certificate verification |
| Config roots | `/etc/jobman-dashboard-restore-{api,worker,operator}-lab` |
| Report root | `/var/lib/jobman-dashboard-restore-reports-lab` |
| Private sockets | `/run/jobman-dashboard-restore-{api,worker}-lab/observe.sock` |
| Units | `jobman-dashboard-restore-{api,worker}-lab.service` |
| Worker components | ingestion, notifications, reports; no delivery or retention component |

Names, IDs, port and paths remain proposals until a fresh read-only preflight
proves them unused. Preserve21901–21908 and every existing database, service,
namespace, key, file and role. Runtime accounts are no-login OS users and restricted
PostgreSQL logins. Use the candidate's reviewed explicit-column grant renderer;
no runtime receives owner/DDL, hold-release, identity-editing or cross-database
privileges. New HBA rules must be TLS-only and restricted to these new roles/database.
Do not replace existing rules or broaden primary grants. Hold/recovery commands
use the new clone's owner/recovery credential in a private root-only config.

The clone uses the exact backed-up, role-specific Control and broker read identities
and their private keys. This deliberately preserves service-bound event cursors.
It does not require any Control/broker registration, source restart, source epoch
change or source permission expansion. API source credentials stay API-only;
worker source credentials stay worker-only. Corresponding API session/token keys,
report policy bytes and log cursor keys are copied from the coordinated backup,
never regenerated or derived from unrelated keys. The worker receives no API
session master, OIDC client secret or device-token key. The clone has **no APNs
provider credentials or delivery component**, even if restored rows contain old
device registrations or deliveries. The planner refuses a provider-configured
primary rather than silently claiming to cover that different recovery scenario.

## Snapshot and source binding

Do not reuse the split revision5 configuration or its preparation plan. Snapshot
the actual API/worker configs after any pending Slurm and secondary-Control mapping
changes have completed. Exact SHA256 bytes, current candidate revision, complete
schema18 ledger digest, global hold generation and current source set become
reviewed inputs. Every retained feed must correspond to a configured source;
every configured source must have a verified current instance/epoch, namespace
set and active feed. A partial/unavailable source blocks this preparation.

An input snapshot has `formatVersion: 1`, `synthetic: true`, database
`jobman_dashboard`, `capturedAt` in UTC, `candidateRevision`, numeric
`configurationRevision`, `apiSHA256`, `workerSHA256`, `schema` containing
`migrationCount: 18` and `ledgerSHA256`, current `hold`, and all `sources`.
Each source carries `deploymentId`, `controlInstanceId`, canonical decimal
`recoveryEpoch`, ordered `namespaceIds`, numeric `configurationRevision` and
`state: active`. It also includes an exact `files` inventory for config-referenced
material: path, SHA256, bytes, UID/GID and four-digit mode. This contains **no file
contents, credential values, opaque source cursors or user tokens**. The privileged
live driver must collect this evidence directly and recheck it before copying.

All source IDs, scopes, role-specific service identities and generation/store
mappings are preserved. Clone configuration keeps the backed-up source registry
revision because only its local database, origin, file locations and startup hold
change. No source policy changes. Independent future primary revisions do not
write the isolated database. Configuration drift during backup or clone staging
fails closed; regenerate and review a fresh plan rather than silently merging.

The API HTTPS origin changes to port38443; the retained Lab certificate must verify
that hostname. Acceptance uses actual signed native bearer tokens with the same
approved API audience and explicit origin/dial binding. No browser redirect/client
registration changes, browser sign-in acceptance, corporate AD FS proof or physical
iPhone claim are implied.

## Bounded coordinated backup

1. Before interruption, provision only the empty isolated database/roles/private
   directories and stage the exact reviewed candidate. Check free space, PostgreSQL
   version/TLS/HBA, clocks, primary process identities and original config hashes.
   Never accept an existing clone target unless an exact completed receipt proves
   it is this execution's resource and the requested phase is safely resumable.
2. Through ordinary authenticated APIs, create fresh test-owned personal rules in
   the existing synthetic research namespace. Use a fresh nonce and prepare two
   of the existing two-job notification scenarios. These are ordinary submissions
   and cancellations, with no raw SQL job/event fabrication. Record the four exact
   owned job IDs; their normal cancellation events are called E1, E2, E3 and cleanup.
3. Activate a namespace-wide cancellation rule, complete E1, and wait for both the
   original Control event and the Dashboard processed-event barrier. Require exactly
   one matching inbox per selected account and record its stable ID. Create or
   reuse approved metadata/log-tail reports using fresh retained idempotency keys;
   record the task/report/evidence IDs, actual source/run identity, policy fingerprint
   and all citations. Do not record bearer tokens or source content in public receipts.
4. Quiesce only primary Dashboard API and worker; leave sources, broker, Keycloak
   and PostgreSQL running. Bound the entire stopped window to180seconds, dump to
  90seconds, and object copying to the remaining budget. Capture the last possible
   pre-stop handoff time outside PostgreSQL, even though this Lab has no provider.
   Verify both processes stopped before copying; no report writer or retention
   process may remain. If quiescence cannot be proved, do not claim a coherent backup.
5. Make a custom-format database dump into a unique exclusive `.partial` file with
   a1GiB output cap, successful-process requirement, fsync, checksum, archive listing
   and receipt. Only then atomically promote it. Copy report/evidence files and all
   required configuration/purpose material with descriptor identity, hash, mode,
   ownership and size checks. No symlinks, hard links, unexpected report filenames,
   broad directory chmod or permission inheritance assumptions. Write the private
   backup completion receipt last, binding dump, files, exact schema and candidate.
6. Restart primary API/worker promptly with unchanged exact configs, units and
   source registry. Verify original hold state, current source readiness and
   correct process UID/executable; restore no database or objects into primary.
   Record actual downtime and bounded source-ingestion delay. The backup is only
   complete if both coherent data receipt and primary-restart verification exist.

Maximum admitted database, dump and report bytes are each1GiB; report files10,000;
config-referenced material128files/32MiB with1MiB per file. Require free PostgreSQL
space of3×current database bytes +1GiB dump +256MiB reserve and storage space of
2×report bytes +1GiB dump +384MiB candidate +material bytes +256MiB reserve. Check
actual filesystem/device capacity immediately before every copy/restore phase.
Do not loosen a bound mid-exercise. Use short-lived clone services (initial24hours
maximum planned operating window), API/worker pool caps and service memory limits
within existing host capacity; actual resource consumption is recorded, not guessed.

## The lost interval and restore cutoff

After backup and primary restart, normally cancel E2. Wait for its exact original
event identity and the primary inbox. E2 must not exist in the dump. Stop only the
owned rules through their owner APIs after the intended primary assertions when
appropriate; retain cloned rule intent from the backup for recovery testing.
Record the conservative external UTC cutoff **after** E2's original recorded time
and last observed primary processing/handoff, plus a stated clock margin. This
external receipt lives outside the backed-up/restored database. A backup timestamp,
stale attempt ledger or old cursor is not evidence for a safe delivery cutoff.
No clock change or Control epoch bump is part of this Dashboard-only exercise.

Restore the verified dump into the exact empty `jobman_dashboard_restore` using
`--no-owner --no-acl` and the dedicated clone DDL owner. Never target any original
DB name; never fall back to a default DSN/database. Verify full restore exit,
exact migration names/checksums via the candidate, all copied report hashes and
role grants. No migration downgrade/reseed or copied primary database credential
is allowed. The API/worker DSNs must independently prove current_database is the
clone over verify-full TLS; cross-database and protected-write probes must fail.

Before either clone process starts, use the trusted clone recovery configuration
to establish `events hold --generation <restored-generation> --restore-through
<external-cutoff>`. Confirm monotonic floor, all retained feeds paused and stale
leases fenced. Clone API/worker startup flags remain true and merely assert this
already durable hold. Ordinary runtime roles cannot establish or release it.

## Acceptance and explicit release of the clone hold

- Verify restored row identity digests and both independent source identities, namespace sets, configuration revisions and exact checkpoint/cursor/position hashes before imposing the restore hold. The bounded database backup receipt records these hashes without opaque cursor bytes. Then verify E1 inbox/read state, task/idempotency
  behavior, exact report/evidence seals, factual source/run identity and citations.
  Resubmit the **same** recorded report key/body under its current authorized
  account: same task identity; changed body with that key must conflict. Validate
  both paired files rather than a report view with missing evidence.
- Fetch fresh current source authority through normal delegation. Known denied
  users must not access restored records. A separately coordinated reversible
  direct-group removal may prove same-token denial on a restored member-owned
  research report/inbox; restore the exact original group state before proceeding.
  The clone's cached database identity never substitutes for current source access.
- For **each** retained source, inspect gap and prepare an explicit restored recovery
  plan pinned to its actual current checkpoint and the persisted floor. Review all
  scope differences and suppression fields. Step at most50pages per command,
  200events per page and1,000total pages for this exercise. Resume committed pages
  after an interruption; never reset a saved feed or silently skip to a new head.
- Require E1's stable event/inbox identities preserved and E2 recovered under its
  original UUID with suppression because it is at/before the floor. If the backup
  caught E2 or the recorded cutoff predates it, the scenario is invalid; start a new
  reviewed scenario instead of editing SQL dates. Old unknown/pending deliveries
  stay held; no provider request can be emitted by this clone.
- Reconcile and review coverage for every namespace/source. Existing synthetic
  roles may provide unavailable current-state coverage outside the owned research
  rule. Record that fact and obtain explicit review before `--allow-incomplete`;
  do not fabricate rules just to improve the coverage label. Apply only the reviewed
  ready revision/digest. Capture identity digests after application and all-source
  active status while the global hold is still set.
- Stage exact clone-only startup hold=false configs with CAS/ownership verification,
  then restart only clone services while retaining the durable hold. Require current
  readyz and bounded metrics. Release only with a separately reviewed `events resume`
  using the current generation and fresh checkpoint verification. Preserve the floor.
- Normally cancel E3 after a verified source time strictly greater than the cutoff
  and clock margin. Require one new matched inbox, no duplicate E1 inbox and no E2
  inbox in the clone. Repeat completion/reads to prove stable original identity and
  idempotent matching. This proves bounded inbox recovery, not exactly-once APNs
  delivery or complete historical notification presentation.

## Failure, recovery and cleanup boundaries

Every mutating phase needs a private pending receipt before effects and a synced
completion receipt last. Host and guest receipts bind exact plan/artifact digests.
Never adopt a failed dump by file existence or readable TOC. Never retry a pending
phase blindly: inspect exact resource identities and partial effects. Lost-response
recovery may reconstitute a host receipt only from a matching completed guest
receipt plus live verification. A partially restored clone is left stopped and
held for inspection; do not drop/recreate it automatically.

If the primary stopped-window budget is exhausted, abort backup work and perform
only the explicitly reviewed restart of the unchanged primary units, recording
that backup attempt as failed. Do not leave primary stopped merely because a dump
or receipt failed, and do not restart against changed schema/config. An unexpected
primary mutation or identity conflict requires operator review; no broader repair,
automatic rollback, destructive restore or implicit hold release is permitted.

Cleanup stops only test-owned personal rules using current ownership/revision
checks, cancels the unused fourth owned job after alert stop, and stops/disables
only the two clone units. Retain private backup, cutoff, receipts and clone data
for review. Removing disposable DB/roles/files is a later explicit, receipt-bound
cleanup action; it must never delete preexisting data or primary objects. Imported
source identities must be removed from retired clone credential directories when
that cleanup is approved, without revoking the primary's live identities.

## Offline preparation

After a separately reviewed read-only snapshot procedure has supplied the private
inputs, run:

```sh
python3 scripts/prepare-dashboard-restore.py \
  --candidate /private/operator/jobman-dashboard_candidate_linux_arm64.tar.gz \
  --candidate-sha256 REVIEWED_ARCHIVE_SHA256 \
  --api-config /private/operator/snapshot/api.json \
  --worker-config /private/operator/snapshot/worker.json \
  --snapshot /private/operator/snapshot/state.json \
  --output-directory /private/operator/new-restore-plan
```

The output must be new under an operator-owned0700 parent. It contains private
config rewrites, source-material inventory, reviewed grant plans and SHA manifest;
it does not contain loaded source key bytes, generated passwords or a dump.
`plan.json` is the completion marker and `applySupported` remains false. The offline
regressions run with `python3 scripts/test-dashboard-restore.py`. Deployment,
backup/restore execution and application acceptance are still outstanding.

## Reviewed-driver staging and phase boundaries

The additional `snapshot-dashboard-restore.py`, `apply-dashboard-restore.py` and
`dashboard-restore-guest.py` implement the proposed fixed-host phases. They remain
unapplied until the exact source hashes and then-current prepared plan have been
independently reviewed. `test-dashboard-restore-apply.py` is entirely offline.
It exercises real bounded subprocess output and failure/deadline handling, file
modes/links, fixed clone SQL and HBA, watchdog coherence, lost responses and startup
hold prerequisites. These tests do not establish successful PostgreSQL restore,
report reuse, source replay or a live downtime bound.

Take read-only snapshots with the exact candidate archive and SHA256. The snapshot
script verifies pinned SSH host keys, actual API/worker process owners and binary
bytes, private config/material identities, source TLS instance/epoch, schema18,
active retained feed set, clock skew, unused clone resources and current capacity.
It writes private snapshots only. Feed positions may advance between this snapshot
and the later coordinated backup; the source identity/scope and config pins must
stay unchanged. Prepare the clone with the existing offline preparer and review
its final `plan.json` SHA256 before initializing an execution.

Every apply command supplies the candidate archive/SHA256, prepared plan/SHA256,
exact guest implementation SHA256, reviewed `dashboard-split-files.py` helper
SHA256, private operation directory and pinned Lab root. `initialize` creates only
local random operation/password material. Passwords never enter command arguments,
public receipts or normal output. `inspect` retrieves only existing private guest
receipts; it does not adopt resources, reset a phase or erase a partial operation.
The supported mutation commands also require `--apply`:

1. `provision` creates only the fixed empty clone database/roles, additive TLS-only
   HBA rules, new OS identities, directories and stopped clone units. API and worker
   database connection limits are16 each, owner/recovery2 and operator2; preflight
   requires36 available PostgreSQL slots. Clone API/worker units use512/768MiB
   `MemoryMax`, `GOMAXPROCS=2` and `TasksMax=256`; require at least1.5GiB guest
   `MemAvailable`. No PostgreSQL server capacity or original privileges change.
2. Run the ordinary E1/rule/report baseline before `backup`. It arms a fixed-unit
   transient watchdog before stopping primary API/worker. The root-owned watchdog
   has a single-use operation ID, exact config/unit/binary pins and independent
  150-second deadline. It can only start the two existing primary units; it cannot
   change their config, restore a database or release a hold. The host always
   attempts an earlier restart in `finally`, including lost-stop/dump replies.
   Stop, completion and restart share one deadline-bounded lock. A stop may start
   only with125 seconds remaining before the watchdog: the exact existing unit
   stop timeout90 seconds, restart budget25 seconds and10 seconds margin. Unexpected
   systemd drop-ins or stop-policy changes fail preflight. The entire locked stop
   section is bounded to40 seconds, and every systemctl check has a deadline.
   A delayed stop therefore cannot follow an already completed watchdog restart.
3. With all primary writers stopped, database and object/key snapshots run on
   separate hosts in parallel. The dump streams to an exclusive `.partial` file
   with a1GiB/90-second limit. The dump phase additionally reserves capacity for
   both the host archive and the PostgreSQL-container restore copy. Successful process exit, fsync, checksum and expected
   TOC precede final promotion. A TOC-readable failed partial is never accepted.
   Report backup allows only the existing bounded UUID files and verifies the
   exact inventory before/after; config/key bytes must still match the fresh plan.
   Both completed receipts must exist before a single storage-host coherence
   receipt is written under the same lock used by the watchdog. If the watchdog
   fires before completion, this backup is rejected and retained for inspection.
   Primary startup is verified before successful return; acceptance requires the
   observed arm-to-restart time at most180 seconds and no watchdog firing.
4. Run E2, establish its source/primary processing barrier, then record the external
   UTC cutoff. `restore-held --external-cutoff ...` accepts only a cutoff after the
   coherent snapshot and within the bounded30-minute exercise window. It restores
   into the exact receipt-bound, empty clone database; public tables, functions,
   types, extra user schemas or extensions all reject an allegedly empty target.
   Only that empty clone's default `public` schema is removed before the dump
   recreates it with the new DDL owner. Original databases are never restore targets.
5. Exact migration ledger, stable source-event/inbox/delivery/report-task identity
   counts and SHA256 digests must match the backup before grants and startup are
   accepted. Identity verification is bounded to100,000 rows per family and emits
   only count/digest receipts. Explicit-column grants come from the exact candidate.
   SQL effective-role negative probes verify worker identity/session/preferences
   denial and universal runtime hold-release denial; these probes are distinct
   from actual TLS login checks through clone runtime readiness/operator status.
6. Private report/material copies and clone-only DSNs are installed with the reviewed
   owners/modes. The trusted clone operator config establishes the persisted restore
   hold/floor before either new unit can start. Every retained source is paused for
   explicit recovery by the product hold command. `verify-held` checks actual process
   identity, config bytes, private readiness/metrics, current hold and operator
   status. Startup issues systemctl start once, then polls only transient process/
   socket/readiness availability within a25-second readiness budget and50-second
   total guest phase. Exact config, process, role, revision and hold drift fails
   immediately; retries never issue another start. No delivery worker, APNs provider, automatic replay, apply or resume is
   implemented by these commands.

Completed guest receipts allow a lost host reply to be inspected and recovered
only against the same operation, plan, material/password identity and live resources.
A crash between a mutation and its completion receipt leaves a pending phase:
stop, preserve the evidence and independently review exact continuation conditions.
Do not erase pending markers or claim success from names, a nonempty database,
a readable archive TOC or an already-running process. The primary watchdog remains
independent of that clone-phase recovery. Backup is single-use; never rerun it
against the same operation after the primary has resumed.

The fixed watchdog bound covers the reviewed ordinary unit/config/binary state.
It deliberately refuses to start a drifted or replaced primary service. An OS,
service-start or network failure is a failed acceptance exercise and must remain
visible; no script can promise successful service recovery under arbitrary host
failure. All private backups, partial output and arm/fired/disarm receipts remain
available for investigation. No automatic destructive cleanup is performed.
